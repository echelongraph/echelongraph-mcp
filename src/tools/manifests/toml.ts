// A TOML reader for the machine-written lockfiles scan_manifest reads (#2835): Cargo.lock and
// poetry.lock. No runtime dependency is added for it (the package ships with provenance and
// three dependencies, #2304), so it is this file: TOML 1.0 (toml.io/en/v1.0.0) as those tools
// write it.
//
// It reads comments; [table] and [[array.of.tables]] headers with bare, quoted and dotted keys;
// key = value with dotted keys; basic and literal strings, single- and multi-line, with escapes;
// integers, floats and booleans; dates and times (kept as their text); arrays across lines with
// comments and a trailing comma; inline tables. What it does not hold to the spec: it does not
// refuse every redefinition TOML forbids, which a lockfile writer does not produce. Anything it
// cannot read throws Unreadable with the line, and the file is reported as not read, never as
// holding no dependencies.
//
// Each table's line (1-based, its header's) is kept in `lines`, so an entry not checked can say
// where it is.
import { Unreadable } from "./common.js";

export type TomlTable = { [k: string]: TomlValue };
export type TomlValue = string | number | boolean | TomlValue[] | TomlTable;

export function readToml(text: string): { root: TomlTable; lines: WeakMap<object, number> } {
  const s = text.replace(/\r\n/g, "\n");
  let i = 0;
  let line = 1;
  const lines = new WeakMap<object, number>();
  const root: TomlTable = {};
  lines.set(root, 1);
  let current: TomlTable = root;

  const fail = (why: string): never => {
    throw new Unreadable(`is not TOML this reader can read: ${why} on line ${line}`);
  };
  const peek = (n = 0) => s[i + n];
  const advance = (n = 1) => {
    for (let k = 0; k < n; k++) if (s[i++] === "\n") line++;
  };
  const skipWs = () => {
    while (peek() === " " || peek() === "\t") advance();
  };
  const skipComment = () => {
    if (peek() === "#") while (i < s.length && peek() !== "\n") advance();
  };
  // Whitespace, newlines and comments (inside an array).
  const skipAll = () => {
    for (;;) {
      skipWs();
      skipComment();
      if (peek() === "\n") advance();
      else break;
    }
  };
  const endOfLine = () => {
    skipWs();
    skipComment();
    if (i < s.length && peek() !== "\n") fail(`unexpected "${peek()}"`);
  };

  const ESC: Record<string, string> = { b: "\b", t: "\t", n: "\n", f: "\f", r: "\r", '"': '"', "\\": "\\", e: "\x1b" };
  const basic = (multi: boolean): string => {
    let out = "";
    advance(multi ? 3 : 1);
    if (multi && peek() === "\n") advance();
    for (;;) {
      if (i >= s.length) fail("an unterminated string");
      // A closing """ may follow up to two quotes of the string's own: """" ends it with one.
      if (multi ? s.startsWith('"""', i) && s[i + 3] !== '"' : peek() === '"') {
        advance(multi ? 3 : 1);
        return out;
      }
      const c = peek();
      if (!multi && c === "\n") fail("a newline in a string");
      if (c === "\\") {
        const n = peek(1);
        if (multi && (n === "\n" || n === " " || n === "\t")) {
          // A line-ending backslash: the newline and the whitespace after it are dropped.
          advance();
          while (peek() === " " || peek() === "\t" || peek() === "\n") advance();
          continue;
        }
        if (n === "u" || n === "U") {
          const len = n === "u" ? 4 : 8;
          const hex = s.slice(i + 2, i + 2 + len);
          if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length !== len) fail("a bad unicode escape");
          out += String.fromCodePoint(parseInt(hex, 16));
          advance(2 + len);
          continue;
        }
        if (ESC[n] === undefined) fail(`an unknown escape \\${n}`);
        out += ESC[n];
        advance(2);
        continue;
      }
      out += c;
      advance();
    }
  };
  const literal = (multi: boolean): string => {
    advance(multi ? 3 : 1);
    if (multi && peek() === "\n") advance();
    const close = multi ? "'''" : "'";
    let end = s.indexOf(close, i);
    if (multi) while (end >= 0 && s[end + 3] === "'") end++;
    if (end < 0) fail("an unterminated string");
    const out = s.slice(i, end);
    if (!multi && out.includes("\n")) fail("a newline in a string");
    advance(end - i + close.length);
    return out;
  };
  const key = (): string => {
    skipWs();
    const c = peek();
    if (c === '"') return basic(false);
    if (c === "'") return literal(false);
    const m = /^[A-Za-z0-9_-]+/.exec(s.slice(i, i + 256));
    if (!m) fail("a missing key");
    advance(m![0].length);
    return m![0];
  };
  const dottedKey = (): string[] => {
    const parts = [key()];
    for (;;) {
      skipWs();
      if (peek() !== ".") return parts;
      advance();
      parts.push(key());
    }
  };
  const value = (): TomlValue => {
    skipWs();
    const c = peek();
    if (s.startsWith('"""', i)) return basic(true);
    if (c === '"') return basic(false);
    if (s.startsWith("'''", i)) return literal(true);
    if (c === "'") return literal(false);
    if (c === "[") {
      advance();
      const arr: TomlValue[] = [];
      for (;;) {
        skipAll();
        if (peek() === "]") {
          advance();
          return arr;
        }
        arr.push(value());
        skipAll();
        if (peek() === ",") advance();
        else if (peek() !== "]") fail("a missing , in an array");
      }
    }
    if (c === "{") {
      advance();
      const t: TomlTable = {};
      lines.set(t, line);
      skipWs();
      if (peek() === "}") {
        advance();
        return t;
      }
      for (;;) {
        const k = dottedKey();
        skipWs();
        if (peek() !== "=") fail("a missing = in an inline table");
        advance();
        setPath(t, k, value());
        skipWs();
        if (peek() === ",") {
          advance();
          continue;
        }
        if (peek() === "}") {
          advance();
          return t;
        }
        fail("a missing , in an inline table");
      }
    }
    // A bare scalar: up to a delimiter.
    const m = /^[^\s,\]}#]+(?: [0-9:.+\-Z]+)?/.exec(s.slice(i, i + 128));
    if (!m) fail("a missing value");
    const raw = m![0];
    advance(raw.length);
    if (raw === "true") return true;
    if (raw === "false") return false;
    const num = raw.replace(/_/g, "");
    if (/^[+-]?(0x[0-9a-fA-F]+|0o[0-7]+|0b[01]+|\d+)$/.test(num)) return Number(num.replace(/^\+/, ""));
    if (/^[+-]?(\d+(\.\d+)?([eE][+-]?\d+)?|inf|nan)$/.test(num)) return Number(num.replace(/^\+/, ""));
    if (/^\d{4}-\d{2}-\d{2}|^\d{2}:\d{2}/.test(raw)) return raw;
    return fail(`an unreadable value "${raw.slice(0, 40)}"`);
  };
  const setPath = (t: TomlTable, path: string[], v: TomlValue) => {
    let at = t;
    for (const k of path.slice(0, -1)) {
      if (at[k] === undefined) {
        at[k] = {};
        lines.set(at[k] as object, line);
      }
      const next = at[k];
      if (typeof next !== "object" || Array.isArray(next)) fail(`the key ${k} is not a table`);
      at = next as TomlTable;
    }
    at[path[path.length - 1]] = v;
  };
  // The table a header names, made as needed; [[x]] appends a new table to the array x.
  const header = (path: string[], array: boolean): TomlTable => {
    let at = root;
    path.forEach((k, n) => {
      const last = n === path.length - 1;
      if (last && array) {
        if (at[k] === undefined) at[k] = [];
        if (!Array.isArray(at[k])) fail(`[[${path.join(".")}]] names a key that is not an array of tables`);
        const t: TomlTable = {};
        lines.set(t, line);
        (at[k] as TomlValue[]).push(t);
        at = t;
        return;
      }
      let next = at[k];
      if (next === undefined) {
        next = {};
        lines.set(next, line);
        at[k] = next;
      }
      // A dotted header through an array of tables goes into its last table.
      if (Array.isArray(next)) next = next[next.length - 1];
      if (typeof next !== "object" || next === null || Array.isArray(next)) fail(`[${path.join(".")}] names a key that is not a table`);
      at = next as TomlTable;
    });
    return at;
  };

  while (i < s.length) {
    skipWs();
    const c = peek();
    if (c === "\n") {
      advance();
      continue;
    }
    if (c === "#") {
      skipComment();
      continue;
    }
    if (i >= s.length) break;
    if (c === "[") {
      const array = peek(1) === "[";
      advance(array ? 2 : 1);
      const path = dottedKey();
      skipWs();
      if (array ? !s.startsWith("]]", i) : peek() !== "]") fail("an unclosed table header");
      advance(array ? 2 : 1);
      current = header(path, array);
      endOfLine();
      continue;
    }
    const k = dottedKey();
    skipWs();
    if (peek() !== "=") fail("a missing =");
    advance();
    setPath(current, k, value());
    endOfLine();
  }
  return { root, lines };
}
