// go.mod (#2835), read as go.dev/ref/mod#go-mod-file describes it: require, in single-line and
// block form, `// indirect` ones included; then each requirement's replace and exclude applied, as
// the go command applies them in the main module.
//   - replace old [v] => new v: the module checked is new at v (a replace naming old's version
//     applies to that version only, and wins over one that names none); replace old => ./dir (or
//     ../dir, /dir) is a local directory: local_path, not checked.
//   - exclude m v: a require of exactly m v is not what the build uses (the go command moves to the
//     next higher version it can find, which this file does not say): version_unresolved.
// A go directive below 1.17 means the file lists only the main module's direct requirements, not
// every module the build loads (module graph pruning, go.dev/ref/mod#graph-pruning): a note says
// so. go.sum is not read here: it lists every version the module graph mentions, not the one the
// build selects (core-backend's go.sum holds ten golang.org/x/sys versions where its go.mod
// selects one).
import { addNotChecked, callBounds, clip, eachLine, emptyParsed, purlOf, specOf, usableVersion, type Bounds, type Parsed } from "./common.js";

// `over`: the last token of a line read no further, past TOKENS_MAX or LINE_MAX (#3434).
type Tok = { text: string; quoted: boolean; over?: true };

// #3434: how much of one line is read. No directive has more than six tokens (replace old v => new v), nor a module
// path, version or directory anywhere near LINE_MAX characters; a line past either, before its comment, is reported
// (unsupported_line), its rest not read, so what one line builds is bounded whatever it holds.
const TOKENS_MAX = 16;
const LINE_MAX = 65_536;
const OVER: Tok = { text: "", quoted: false, over: true };
// Whitespace is every character \s matches, not only space, tab and CR (#3434): the same set ends a bare token, so
// each character is taken by exactly one branch of tokens().
const WS = /\s/;
const BARE_END = /[\s()"`]/;

// One line's tokens, its comment removed (and whether that comment is `// indirect`). Strings are
// "interpreted" or `raw`, as the grammar allows a module path or file path to be quoted.
function tokens(line: string): { toks: Tok[]; indirect: boolean } {
  const toks: Tok[] = [];
  let indirect = false;
  // From the first token on, LINE_MAX characters at most (#3434).
  const from = line.search(/\S/);
  if (from < 0) return { toks, indirect };
  const t = line.slice(from, from + LINE_MAX);
  let comment = false;
  let i = 0;
  // Each pass consumes at least one character of t, or ends the loop.
  while (i < t.length) {
    const c = t[i];
    if (WS.test(c)) {
      i++;
    } else if (t.startsWith("//", i)) {
      indirect = /^indirect(\s|;|$)/.test(line.slice(from + i + 2).trim());
      comment = true;
      break;
    } else if (toks.length === TOKENS_MAX) {
      toks.push(OVER);
      return { toks, indirect };
    } else if (c === '"' || c === "`") {
      // To the closing quote, an interpreted string's backslash escaping the character after it; the text is taken
      // from slices of the line, never built a character at a time (#3434).
      let j = i + 1;
      while (j < t.length && t[j] !== c) j += c === '"' && t[j] === "\\" && j + 1 < t.length ? 2 : 1;
      const s = t.slice(i + 1, j);
      toks.push({ text: c === '"' && s.includes("\\") ? s.replace(/\\(.)/gs, "$1") : s, quoted: true });
      i = j + 1;
    } else if (c === "(" || c === ")") {
      toks.push({ text: c, quoted: false });
      i++;
    } else {
      // c is none of what the branches above take, so the token holds it: j starts past it.
      let j = i + 1;
      while (j < t.length && !BARE_END.test(t[j]) && !t.startsWith("//", j)) j++;
      toks.push({ text: t.slice(i, j), quoted: false });
      i = j;
    }
  }
  // Cut at LINE_MAX before a comment began: the line runs on past what was read.
  if (!comment && t.length < line.length - from) toks.push(OVER);
  return { toks, indirect };
}

const isLocal = (p: string) => /^(\.{1,2}[\\/]|\.{1,2}$|[\\/]|[A-Za-z]:[\\/])/.test(p);

type Line = { verb: string; args: Tok[]; indirect: boolean; line: number; raw: string };

// Each directive line, a block's lines carrying the block's verb. #3434: one line at a time (eachLine), each that
// holds a token taken from the call's MAX_MANIFEST_LINES (common.ts), so no file builds more than that.
function directives(text: string, bounds: Bounds): Line[] {
  const out: Line[] = [];
  let block: string | null = null;
  eachLine(text, false, (raw, i) => {
    const { toks, indirect } = tokens(raw);
    if (toks.length === 0) return;
    bounds.lines.take();
    // #3434: a line past TOKENS_MAX or LINE_MAX is only reported (readGoMod), so it keeps none of its tokens, only OVER.
    const over = toks[toks.length - 1] === OVER;
    if (block !== null) {
      if (toks.length === 1 && toks[0].text === ")" && !toks[0].quoted) {
        block = null;
        return;
      }
      out.push({ verb: block, args: over ? [OVER] : toks, indirect, line: i + 1, raw });
      return;
    }
    const verb = toks[0].text;
    if (toks.length === 2 && toks[1].text === "(" && !toks[1].quoted) {
      block = verb;
      return;
    }
    out.push({ verb, args: over ? [OVER] : toks.slice(1), indirect, line: i + 1, raw });
  });
  return out;
}

// "1.16" is below 1.17; "1.21.0" and "1.17" are not.
function below117(v: string): boolean {
  const m = /^(\d+)\.(\d+)/.exec(v);
  if (!m) return false;
  return Number(m[1]) < 1 || (Number(m[1]) === 1 && Number(m[2]) < 17);
}

export function readGoMod(text: string, bounds: Bounds = callBounds()): Parsed {
  const p = emptyParsed();
  p.replaced = [];
  const lines = directives(text, bounds);
  const requires: Line[] = [];
  const excluded = new Set<string>();
  // replace, keyed by old path, then by old version ("" for every version). #3434: `to` and `purl`, what every require
  // it applies to is checked as, are built once per replace, not once per require.
  const replaces = new Map<string, Map<string, { path: string; version: string | null; line: number; to?: string; purl?: string }>>();
  let goVersion: string | null = null;
  for (const l of lines) {
    // #3434: a line past TOKENS_MAX tokens or LINE_MAX characters, not read on (tokens).
    if (l.args.some((t) => t.over)) {
      addNotChecked(p, { name: null, spec: specOf(l.raw), reason: "unsupported_line", line: l.line, detail: `more than ${TOKENS_MAX} tokens or ${LINE_MAX} characters before its comment, which no go.mod directive has: not read` });
      continue;
    }
    const a = l.args.map((t) => t.text);
    switch (l.verb) {
      case "go":
        goVersion = a[0] ?? null;
        break;
      case "require":
        requires.push(l);
        break;
      case "exclude":
        if (a.length >= 2) excluded.add(`${a[0]}@${a[1]}`);
        break;
      case "replace": {
        const arrow = a.indexOf("=>");
        if (arrow < 1) break;
        const [oldPath, oldVersion = ""] = a.slice(0, arrow);
        const [newPath, newVersion] = a.slice(arrow + 1);
        if (!newPath) break;
        if (!replaces.has(oldPath)) replaces.set(oldPath, new Map());
        replaces.get(oldPath)!.set(oldVersion, { path: newPath, version: newVersion ?? null, line: l.line });
        break;
      }
      case "module":
      case "toolchain":
      case "godebug":
      case "retract":
      case "tool":
      case "ignore":
        // No dependency version.
        break;
      default:
        // #3434: the verb clip()'d, as a block's lines all carry the block's (clip, not specOf: a quoted verb's own
        // whitespace is kept, as before).
        addNotChecked(p, { name: null, spec: specOf(l.raw), reason: "unsupported_line", line: l.line, detail: `not a go.mod directive (${clip(l.verb)})` });
        break;
    }
  }
  for (const r of requires) {
    const [path, version] = r.args.map((t) => t.text);
    const miss = (reason: "version_unresolved" | "local_path" | "unsupported_line", detail: string) =>
      addNotChecked(p, { name: path === undefined ? null : clip(path), spec: specOf(r.raw), reason, line: r.line, detail });
    if (!path || !usableVersion(version) || r.args.length !== 2) {
      miss("unsupported_line", "not a require line this reader can read (module path, then version)");
      continue;
    }
    const rep = replaces.get(path)?.get(version) ?? replaces.get(path)?.get("");
    if (rep) {
      // #3434: one replace applies to every require of its module, so its path is clip()'d in each detail.
      if (isLocal(rep.path)) {
        miss("local_path", `replaced by the local directory ${clip(rep.path)} (replace on line ${rep.line}), which is not a published module version`);
        continue;
      }
      if (!usableVersion(rep.version)) {
        miss("unsupported_line", `replaced by ${clip(rep.path)} without a version (replace on line ${rep.line}), which this reader cannot resolve`);
        continue;
      }
      rep.to ??= `${rep.path}@${rep.version}`;
      rep.purl ??= purlOf("golang", rep.path, rep.version);
      p.replaced.push({ from: `${path}@${version}`, to: rep.to });
      p.pinned.push({ purl: rep.purl, line: r.line });
      continue;
    }
    if (excluded.has(`${path}@${version}`)) {
      miss("version_unresolved", "this version is excluded by an exclude directive, so the build uses another version, which go.mod does not name");
      continue;
    }
    p.pinned.push({ purl: purlOf("golang", path, version), line: r.line });
  }
  // No go directive is read as go 1.16 (go.dev/ref/mod#go-mod-file-go).
  if (goVersion === null || below117(goVersion)) {
    p.notes.push(
      `${goVersion === null ? "It has no go directive, which the go command reads as go 1.16" : `Its go directive is ${goVersion}`}, below 1.17: such a go.mod lists the main module's own requirements, not every module the build loads, so modules required only by its dependencies are not checked.`,
    );
  }
  return p;
}
