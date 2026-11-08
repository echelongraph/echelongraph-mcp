// package-lock.json and npm-shrinkwrap.json (#2835), lockfileVersion 1, 2 and 3, read as JSON
// (docs.npmjs.com/cli/v10/configuring-npm/package-lock-json).
//
// Version 2 and 3 files hold `packages`, keyed by install path: the package's name is what follows
// the last "node_modules/" in the key, or the entry's own name where it has one (an alias,
// "lodash-latest": "npm:lodash@4.17.21", installs lodash under another folder name). The root
// entry ("") is the project itself and is skipped and counted; a key outside node_modules is a
// workspace member, and a `link: true` entry a symlink to one: local_path. Version 1 files hold
// only `dependencies`, a tree keyed by name; version 2 files hold both, and `packages` is read.
// The same installed tree gives the same purls in all three.
//
// An entry installed from git (resolved git+…, or a v1 version that is a git URL) is vcs_source;
// from a directory or file (file:…) local_path; from a tarball URL unsupported_line; an entry
// without a version version_unresolved. Each is listed, never sent.
import { PARSE_BUDGET_BYTES } from "../../parseBudget.js";
import { LONG_NAME_DETAIL, SPEC_MAX, Unreadable, addNotChecked, callBounds, clip, emptyParsed, isObj, parseLockfileJson, pin, specOf, tooLong, usableVersion, type Bounds, type NotCheckedReason, type Parsed } from "./common.js";

const NM = "node_modules/";
const GIT = /^(git(\+[a-z]+)?:|github:|gitlab:|bitbucket:|gist:)/i;

// Where an entry was installed from, when not the registry.
function source(s: string | undefined): { reason: NotCheckedReason; detail: string } | null {
  if (!s) return null;
  if (GIT.test(s) || /^[\w.-]+\/[\w.-]+(#.*)?$/.test(s)) return { reason: "vcs_source", detail: "installed from a git repository, whose code need not match the npm release of the same version" };
  if (/^(file:|link:|\.{1,2}\/|\/)/.test(s)) return { reason: "local_path", detail: "installed from a local directory or file, not an npm release" };
  if (/^https?:\/\//i.test(s) && !/\/-\/[^/]+\.tgz$/.test(s)) return { reason: "unsupported_line", detail: "installed from a tarball URL that is not a registry release" };
  return null;
}

// A JSON value of the file named in a reason: a string clip()'d to SHOWN_MAX and quoted, a number, boolean or null as
// JSON writes it, an array or object by its type alone (#3460's round-10 review, F2). A number past what a double holds
// (1e400 parses as Infinity, which JSON writes as null) is said to be one (round 11, the round-10 verify's d2 N2).
const SHOWN_MAX = 40;
const shown = (v: unknown): string =>
  typeof v === "number" && !Number.isFinite(v)
    ? "a number past what a double holds"
    : typeof v === "string" ? JSON.stringify(clip(v, SHOWN_MAX)) : v === null || typeof v === "number" || typeof v === "boolean" ? JSON.stringify(v) : Array.isArray(v) ? "an array" : "an object";

export function readNpmLock(text: string, bounds: Bounds = callBounds(), parseBytes: number = PARSE_BUDGET_BYTES): Parsed {
  // #3381: what its parse would retain is estimated before it is parsed (parseLockfileJson's parseBytes).
  const doc = parseLockfileJson(text, bounds, parseBytes);
  if (!isObj(doc)) throw new Unreadable("is not a JSON object");
  const p = emptyParsed();
  const lv = doc.lockfileVersion;
  if (isObj(doc.packages)) {
    // #3434: for...in, not Object.entries, which built a [key, value] array per entry beside the parsed object (the same
    // keys, in the same order, as JSON.parse makes no inherited enumerable key).
    // #3460's round-10 review (F1): own keys only, whatever the prototype holds (JSON.parse makes every key its own).
    const packages = doc.packages;
    for (const key in packages) {
      if (!Object.hasOwn(packages, key)) continue;
      const e = packages[key];
      if (key === "") {
        p.skipped++;
        continue;
      }
      const at = key.lastIndexOf(NM);
      const folder = at >= 0 ? key.slice(at + NM.length) : null;
      const entry = isObj(e) ? e : {};
      const name = typeof entry.name === "string" && entry.name ? entry.name : (folder ?? key);
      const version = typeof entry.version === "string" ? entry.version : undefined;
      const miss = (reason: NotCheckedReason, detail: string) =>
        addNotChecked(p, { name: clip(name), spec: specOf(`${key}${version ? ` ${version}` : ""}`), reason, line: null, detail });
      // #3460: bounded before anything reads into them (common.ts NAME_MAX).
      if (tooLong(name, version)) {
        miss("unsupported_line", LONG_NAME_DETAIL);
        continue;
      }
      if (folder === null) {
        miss("local_path", "a workspace member of this project, not an npm release");
        continue;
      }
      if (entry.link === true) {
        miss("local_path", `a link to ${typeof entry.resolved === "string" ? clip(entry.resolved) : "a local directory"}, not an npm release`);
        continue;
      }
      const src = source(typeof entry.resolved === "string" ? entry.resolved : undefined);
      if (src) {
        miss(src.reason, src.detail);
        continue;
      }
      if (!usableVersion(version) || !name) {
        miss("version_unresolved", "the entry carries no version");
        continue;
      }
      pin(p, null, "npm", name, version, (why) => miss("unsupported_line", why));
    }
    return p;
  }
  // #3460's round-10 review (F2): the value named as JSON writes it, clip()'d first, or by its type: through round 10 it
  // was written whole, and a lockfileVersion of 3,100,000 characters made an answer of 31 MB.
  if (lv !== undefined && lv !== 1) throw new Unreadable(`has lockfileVersion ${shown(lv)} and no packages object`);
  // Version 1: the dependencies tree, each node's own dependencies nested below it. #3434: `at`, the parent's install
  // path, is passed down as its first SPEC_MAX characters, a string of its own (clip's copy, uncut): a spec shows no
  // more of a path (specOf), so each spec is as before, and no entry flattens or keeps a path longer than that.
  const walk = (deps: unknown, at: string, depth: number) => {
    if (!isObj(deps)) return;
    if (depth > 64) throw new Unreadable("nests its dependencies deeper than 64 levels");
    for (const key in deps) {
      if (!Object.hasOwn(deps, key)) continue;
      const e = deps[key];
      const entry = isObj(e) ? e : {};
      const path = `${at}${NM}${key}`;
      let name = key;
      let version = typeof entry.version === "string" ? entry.version : undefined;
      // #3460: bounded before anything reads into them (common.ts NAME_MAX); an alias's name and version are within
      // its own.
      const long = tooLong(key, version);
      // An alias: "npm:real-name@1.2.3".
      const alias = version && !long ? /^npm:((?:@[^/@]+\/)?[^@]+)@(.+)$/.exec(version) : null;
      if (alias) [, name, version] = alias;
      const miss = (reason: NotCheckedReason, detail: string) => addNotChecked(p, { name: clip(name), spec: specOf(`${path}${version ? ` ${version}` : ""}`), reason, line: null, detail });
      const src = long ? null : (source(version) ?? source(typeof entry.resolved === "string" ? entry.resolved : undefined));
      if (long) miss("unsupported_line", LONG_NAME_DETAIL);
      else if (src) miss(src.reason, src.detail);
      else if (!usableVersion(version)) miss("version_unresolved", "the entry carries no version");
      else pin(p, null, "npm", name, version, (why) => miss("unsupported_line", why));
      if (isObj(entry.dependencies)) walk(entry.dependencies, clip(`${path}/`.slice(0, SPEC_MAX), SPEC_MAX), depth + 1);
    }
  };
  if (!isObj(doc.dependencies)) throw new Unreadable("has neither a packages nor a dependencies object");
  walk(doc.dependencies, "", 0);
  return p;
}
