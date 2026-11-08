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
//
// #3434: what it builds is bounded. Each table, array entry and key it makes is taken from the call's MAX_TOML_VALUES
// (`values`, common.ts) as it is made; arrays and inline tables nest at most NEST_MAX deep (value() recurses, and a
// deeper nest would end in the engine's own stack); and a string with many escapes is joined in chunks.
//
// #3460's round-10 review (F1): a key from the file never reaches Object.prototype. Every table it makes has no
// prototype (table()), so a key named constructor or prototype is a key like any other, and each is looked up as the
// table's own (Object.hasOwn); a key named __proto__, which no Cargo or PyPI name can be, makes the file unreadable on
// its line. Through round 10 tables were plain objects: a 30-byte Cargo.lock of `[__proto__]` and `hasOwnProperty = 1`
// wrote that key onto Object.prototype, and every later request to the instance failed (HTTP 500) while /health
// answered 200; `link = true` there made every later caller's package-lock.json entries local_path, not checked.
import { PARSE_BUDGET_BYTES, WEIGHT_TOML_DOT, WEIGHT_TOML_KEY, WEIGHT_TOML_OPEN, WEIGHT_TOML_VALUE, tomlEstimate } from "../../parseBudget.js";
import { Unreadable, callBounds, clip, type Bound } from "./common.js";

export type TomlTable = { [k: string]: TomlValue };
export type TomlValue = string | number | boolean | TomlValue[] | TomlTable;

// #3434: no lockfile nests arrays and inline tables more than a few deep (every Cargo.lock measured 1, a dependencies
// list; every poetry.lock 2, a files list of inline tables).
const NEST_MAX = 64;
// #3434: no lockfile's key or table header has more than a few parts (of 43 measured, every Cargo.lock's 1, a
// poetry.lock's 2: [package.extras]).
const KEY_PARTS_MAX = 64;
// #3434: how many runs and escapes basic() holds before it joins them into one chunk.
const PARTS_MAX = 4_096;

// #3381: what reading it would retain, counted first (parseBudget.ts tomlEstimate); past maxBytes (the bound in force,
// PARSE_BUDGET_BYTES, unless the caller names another) it is not read. #3381's review (F8): and what the reader builds is
// counted as it builds it, so the estimate is a bound whether or not the two agree on where a string is. The estimate
// counts each structure character outside strings and comments ('[' and '{' a table or an array, '=' a key, '.' a
// dotted key's part, ',' and newline a value) and two bytes a character; the reader charges the same weights for the
// same characters as it consumes them as structure (charge, below), from the same two bytes a character. Where the two
// agree on the strings, the reader charges no more than the estimate (it charges a '.' or a '[' only where it makes a
// key part or a table of it; test/parse-budget.test.mjs holds it to that). Where they did not (a quote the estimate
// took to open a string the reader did not), the reader built what the estimate never counted: a 5 MB Cargo.lock
// estimated at 10 MB was read past the heap. Now a reader that charges past its estimate stops there, unread.
// `estimate`: what was reserved for it, tomlEstimate's unless the caller names another (its tests). `cost` in the
// answer: what the reader charged. #3434's `values` bound applies beside it (a call's tables, entries and keys).
export function readToml(
  text: string,
  values: Bound = callBounds().toml,
  maxBytes: number = PARSE_BUDGET_BYTES,
  estimate: number = tomlEstimate(text),
): { root: TomlTable; lines: WeakMap<object, number>; cost: number } {
  if (estimate > maxBytes) {
    throw new Unreadable(`is too dense to read: its tables, keys and values are estimated at ${estimate} bytes read, past the ${maxBytes} bytes a file's read may take`);
  }
  let cost = 2 * text.length;
  const charge = (w: number): void => {
    cost += w;
    if (cost > estimate) throw new Unreadable(`is too dense to read: what reading it built passed the ${estimate} bytes estimated of it before it was read`);
  };
  const s = text.replace(/\r\n/g, "\n");
  let i = 0;
  let line = 1;
  const lines = new WeakMap<object, number>();
  const table = (): TomlTable => Object.create(null) as TomlTable;
  const root: TomlTable = table();
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
      if (peek() === "\n") {
        charge(WEIGHT_TOML_VALUE);
        advance();
      } else break;
    }
  };
  const endOfLine = () => {
    skipWs();
    skipComment();
    if (i < s.length && peek() !== "\n") fail(`unexpected "${peek()}"`);
  };

  // #3434: basic() keeps a string as the runs of the text between its escapes, never appended a character at a time,
  // which V8 kept as a string node per character; and every PARTS_MAX of those it joins into one chunk, so a string of
  // many escapes holds no more than its characters and PARTS_MAX entries at once, not two entries per escape.
  const ESC: Record<string, string> = { b: "\b", t: "\t", n: "\n", f: "\f", r: "\r", '"': '"', "\\": "\\", e: "\x1b" };
  const own = (t: object, k: string): boolean => Object.hasOwn(t, k);
  const basic = (multi: boolean): string => {
    const parts: string[] = [];
    const chunks: string[] = [];
    const add = (x: string): void => {
      parts.push(x);
      if (parts.length < PARTS_MAX) return;
      chunks.push(parts.join(""));
      parts.length = 0;
    };
    advance(multi ? 3 : 1);
    if (multi && peek() === "\n") advance();
    let run = i;
    const flush = (): void => {
      if (i > run) add(s.slice(run, i));
    };
    for (;;) {
      if (i >= s.length) fail("an unterminated string");
      // A closing """ may follow up to two quotes of the string's own: """" ends it with one.
      if (multi ? s.startsWith('"""', i) && s[i + 3] !== '"' : peek() === '"') {
        flush();
        advance(multi ? 3 : 1);
        if (chunks.length === 0) return parts.length === 1 ? parts[0] : parts.join("");
        chunks.push(parts.join(""));
        return chunks.join("");
      }
      const c = peek();
      if (!multi && c === "\n") fail("a newline in a string");
      if (c === "\\") {
        flush();
        const n = peek(1);
        if (multi && (n === "\n" || n === " " || n === "\t")) {
          // A line-ending backslash: the newline and the whitespace after it are dropped.
          advance();
          while (peek() === " " || peek() === "\t" || peek() === "\n") advance();
          run = i;
          continue;
        }
        if (n === "u" || n === "U") {
          const len = n === "u" ? 4 : 8;
          const hex = s.slice(i + 2, i + 2 + len);
          if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length !== len) fail("a bad unicode escape");
          // #3434: TOML escapes a Unicode scalar value only: none past U+10FFFF (String.fromCodePoint throws a
          // RangeError on it), and no surrogate.
          const cp = parseInt(hex, 16);
          if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) fail("a bad unicode escape");
          add(String.fromCodePoint(cp));
          advance(2 + len);
          run = i;
          continue;
        }
        if (!own(ESC, n)) fail(`an unknown escape \\${n}`);
        add(ESC[n]);
        advance(2);
        run = i;
        continue;
      }
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
    const k = c === '"' ? basic(false) : c === "'" ? literal(false) : bare();
    if (k === "__proto__") fail("a key named __proto__, which no lockfile writes");
    return k;
  };
  const bare = (): string => {
    const m = /^[A-Za-z0-9_-]+/.exec(s.slice(i, i + 256));
    if (!m) fail("a missing key");
    advance(m![0].length);
    return m![0];
  };
  // #3434: a key or table header is read part by part, each part after its first taken from `values` as it is read (the
  // first is taken where the key is set or the header's table made), and one of more than KEY_PARTS_MAX parts is
  // refused there, before more of its parts are built.
  const dottedKey = (): string[] => {
    const parts = [key()];
    for (;;) {
      skipWs();
      if (peek() !== ".") return parts;
      if (parts.length === KEY_PARTS_MAX) fail(`a dotted key of more than ${KEY_PARTS_MAX} parts`);
      values.take();
      charge(WEIGHT_TOML_DOT);
      advance();
      parts.push(key());
    }
  };
  // How deep the arrays and inline tables value() is inside are (#3434).
  let nest = 0;
  const value = (): TomlValue => {
    skipWs();
    const c = peek();
    if (s.startsWith('"""', i)) return basic(true);
    if (c === '"') return basic(false);
    if (s.startsWith("'''", i)) return literal(true);
    if (c === "'") return literal(false);
    if ((c === "[" || c === "{") && ++nest > NEST_MAX) fail(`arrays and inline tables nested more than ${NEST_MAX} deep`);
    if (c === "[") {
      charge(WEIGHT_TOML_OPEN);
      advance();
      const arr: TomlValue[] = [];
      for (;;) {
        skipAll();
        if (peek() === "]") {
          advance();
          nest--;
          return arr;
        }
        values.take();
        arr.push(value());
        skipAll();
        if (peek() === ",") {
          charge(WEIGHT_TOML_VALUE);
          advance();
        } else if (peek() !== "]") fail("a missing , in an array");
      }
    }
    if (c === "{") {
      charge(WEIGHT_TOML_OPEN);
      advance();
      const t = table();
      lines.set(t, line);
      skipWs();
      if (peek() === "}") {
        advance();
        nest--;
        return t;
      }
      for (;;) {
        const k = dottedKey();
        skipWs();
        if (peek() !== "=") fail("a missing = in an inline table");
        charge(WEIGHT_TOML_KEY);
        advance();
        setPath(t, k, value());
        skipWs();
        if (peek() === ",") {
          charge(WEIGHT_TOML_VALUE);
          advance();
          continue;
        }
        if (peek() === "}") {
          advance();
          nest--;
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
    // A date, a time or a date-time (kept as its text), whole: #3381's review (F8): a token that only began like one
    // (2024-01-01' and the rest of the line) was taken as one, where tomlEstimate saw a string open.
    if (TOML_DATE_TIME.test(raw)) return raw;
    return fail(`an unreadable value "${raw.slice(0, 40)}"`);
  };
  // #3434: each key set, and each table a dotted key makes, is taken from `values`; a key named in a reason is clip()'d.
  const setPath = (t: TomlTable, path: string[], v: TomlValue) => {
    let at = t;
    for (const k of path.slice(0, -1)) {
      if (!own(at, k)) {
        values.take();
        at[k] = table();
        lines.set(at[k] as object, line);
      }
      const next = at[k];
      if (typeof next !== "object" || Array.isArray(next)) fail(`the key ${clip(k)} is not a table`);
      at = next as TomlTable;
    }
    values.take();
    at[path[path.length - 1]] = v;
  };
  // The table a header names, made as needed; [[x]] appends a new table to the array x. #3434: each table or array it
  // makes is taken from `values`; the header named in a reason is clip()'d.
  const header = (path: string[], array: boolean): TomlTable => {
    let at = root;
    path.forEach((k, n) => {
      const last = n === path.length - 1;
      if (last && array) {
        if (!own(at, k)) {
          values.take();
          at[k] = [];
        }
        if (!Array.isArray(at[k])) fail(`[[${clip(path.join("."))}]] names a key that is not an array of tables`);
        values.take();
        const t = table();
        lines.set(t, line);
        (at[k] as TomlValue[]).push(t);
        at = t;
        return;
      }
      let next = own(at, k) ? at[k] : undefined;
      if (next === undefined) {
        values.take();
        next = table();
        lines.set(next, line);
        at[k] = next;
      }
      // A dotted header through an array of tables goes into its last table.
      if (Array.isArray(next)) next = next[next.length - 1];
      if (typeof next !== "object" || next === null || Array.isArray(next)) fail(`[${clip(path.join("."))}] names a key that is not a table`);
      at = next as TomlTable;
    });
    return at;
  };

  while (i < s.length) {
    skipWs();
    const c = peek();
    if (c === "\n") {
      charge(WEIGHT_TOML_VALUE);
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
      charge(array ? 2 * WEIGHT_TOML_OPEN : WEIGHT_TOML_OPEN);
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
    charge(WEIGHT_TOML_KEY);
    advance();
    setPath(current, k, value());
    endOfLine();
  }
  return { root, lines, cost };
}

// A local date, local time, local date-time or offset date-time, the whole token: "T", "t" or a space between date and
// time (the bare scalar above takes "1979-05-27 07:32:00Z" as one), seconds optional (TOML 1.1).
const TOML_DATE_TIME = /^(?:\d{4}-\d{2}-\d{2}(?:[Tt ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:[Zz]|[+-]\d{2}:\d{2})?)?|\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)$/;
