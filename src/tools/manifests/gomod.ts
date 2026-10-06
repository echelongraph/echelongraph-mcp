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
import { emptyParsed, purlOf, specOf, usableVersion, type Parsed } from "./common.js";

type Tok = { text: string; quoted: boolean };

// One line's tokens, its comment removed (and whether that comment is `// indirect`). Strings are
// "interpreted" or `raw`, as the grammar allows a module path or file path to be quoted.
function tokens(line: string): { toks: Tok[]; indirect: boolean } {
  const toks: Tok[] = [];
  let i = 0;
  let indirect = false;
  while (i < line.length) {
    const c = line[i];
    if (c === " " || c === "\t" || c === "\r") {
      i++;
    } else if (line.startsWith("//", i)) {
      indirect = /^indirect(\s|;|$)/.test(line.slice(i + 2).trim());
      break;
    } else if (c === '"' || c === "`") {
      let j = i + 1;
      let s = "";
      while (j < line.length && line[j] !== c) {
        if (c === '"' && line[j] === "\\" && j + 1 < line.length) j++;
        s += line[j++];
      }
      toks.push({ text: s, quoted: true });
      i = j + 1;
    } else if (c === "(" || c === ")") {
      toks.push({ text: c, quoted: false });
      i++;
    } else {
      let j = i;
      while (j < line.length && !/[\s()"`]/.test(line[j]) && !line.startsWith("//", j)) j++;
      toks.push({ text: line.slice(i, j), quoted: false });
      i = j;
    }
  }
  return { toks, indirect };
}

const isLocal = (p: string) => /^(\.{1,2}[\\/]|\.{1,2}$|[\\/]|[A-Za-z]:[\\/])/.test(p);

type Line = { verb: string; args: Tok[]; indirect: boolean; line: number; raw: string };

// Each directive line, a block's lines carrying the block's verb.
function directives(text: string): Line[] {
  const out: Line[] = [];
  let block: string | null = null;
  text.split("\n").forEach((raw, i) => {
    const { toks, indirect } = tokens(raw);
    if (toks.length === 0) return;
    if (block !== null) {
      if (toks.length === 1 && toks[0].text === ")" && !toks[0].quoted) {
        block = null;
        return;
      }
      out.push({ verb: block, args: toks, indirect, line: i + 1, raw });
      return;
    }
    const verb = toks[0].text;
    if (toks.length === 2 && toks[1].text === "(" && !toks[1].quoted) {
      block = verb;
      return;
    }
    out.push({ verb, args: toks.slice(1), indirect, line: i + 1, raw });
  });
  return out;
}

// "1.16" is below 1.17; "1.21.0" and "1.17" are not.
function below117(v: string): boolean {
  const m = /^(\d+)\.(\d+)/.exec(v);
  if (!m) return false;
  return Number(m[1]) < 1 || (Number(m[1]) === 1 && Number(m[2]) < 17);
}

export function readGoMod(text: string): Parsed {
  const p = emptyParsed();
  p.replaced = [];
  const lines = directives(text);
  const requires: Line[] = [];
  const excluded = new Set<string>();
  // replace, keyed by old path, then by old version ("" for every version).
  const replaces = new Map<string, Map<string, { path: string; version: string | null; line: number }>>();
  let goVersion: string | null = null;
  for (const l of lines) {
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
        p.not_checked.push({ name: null, spec: specOf(l.raw), reason: "unsupported_line", line: l.line, detail: `not a go.mod directive (${l.verb})` });
        break;
    }
  }
  for (const r of requires) {
    const [path, version] = r.args.map((t) => t.text);
    const miss = (reason: "version_unresolved" | "local_path" | "unsupported_line", detail: string) =>
      p.not_checked.push({ name: path ?? null, spec: specOf(r.raw), reason, line: r.line, detail });
    if (!path || !usableVersion(version) || r.args.length !== 2) {
      miss("unsupported_line", "not a require line this reader can read (module path, then version)");
      continue;
    }
    const rep = replaces.get(path)?.get(version) ?? replaces.get(path)?.get("");
    if (rep) {
      if (isLocal(rep.path)) {
        miss("local_path", `replaced by the local directory ${rep.path} (replace on line ${rep.line}), which is not a published module version`);
        continue;
      }
      if (!usableVersion(rep.version)) {
        miss("unsupported_line", `replaced by ${rep.path} without a version (replace on line ${rep.line}), which this reader cannot resolve`);
        continue;
      }
      p.replaced.push({ from: `${path}@${version}`, to: `${rep.path}@${rep.version}` });
      p.pinned.push({ purl: purlOf("golang", rep.path, rep.version), line: r.line });
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
