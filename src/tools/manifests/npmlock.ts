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
import { Unreadable, emptyParsed, isObj, purlOf, specOf, usableVersion, type NotCheckedReason, type Parsed } from "./common.js";

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

export function readNpmLock(text: string): Parsed {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    throw new Unreadable("is not JSON");
  }
  if (!isObj(doc)) throw new Unreadable("is not a JSON object");
  const p = emptyParsed();
  const lv = doc.lockfileVersion;
  if (isObj(doc.packages)) {
    for (const [key, e] of Object.entries(doc.packages)) {
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
        p.not_checked.push({ name, spec: specOf(`${key}${version ? ` ${version}` : ""}`), reason, line: null, detail });
      if (folder === null) {
        miss("local_path", "a workspace member of this project, not an npm release");
        continue;
      }
      if (entry.link === true) {
        miss("local_path", `a link to ${typeof entry.resolved === "string" ? entry.resolved : "a local directory"}, not an npm release`);
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
      p.pinned.push({ purl: purlOf("npm", name, version), line: null });
    }
    return p;
  }
  if (lv !== undefined && lv !== 1) throw new Unreadable(`has lockfileVersion ${JSON.stringify(lv)} and no packages object`);
  // Version 1: the dependencies tree, each node's own dependencies nested below it.
  const walk = (deps: unknown, at: string, depth: number) => {
    if (!isObj(deps)) return;
    if (depth > 64) throw new Unreadable("nests its dependencies deeper than 64 levels");
    for (const [key, e] of Object.entries(deps)) {
      const entry = isObj(e) ? e : {};
      const path = `${at}${NM}${key}`;
      let name = key;
      let version = typeof entry.version === "string" ? entry.version : undefined;
      // An alias: "npm:real-name@1.2.3".
      const alias = version ? /^npm:((?:@[^/@]+\/)?[^@]+)@(.+)$/.exec(version) : null;
      if (alias) [, name, version] = alias;
      const miss = (reason: NotCheckedReason, detail: string) => p.not_checked.push({ name, spec: specOf(`${path}${version ? ` ${version}` : ""}`), reason, line: null, detail });
      const src = source(version) ?? source(typeof entry.resolved === "string" ? entry.resolved : undefined);
      if (src) miss(src.reason, src.detail);
      else if (!usableVersion(version)) miss("version_unresolved", "the entry carries no version");
      else p.pinned.push({ purl: purlOf("npm", name, version), line: null });
      walk(entry.dependencies, `${path}/`, depth + 1);
    }
  };
  if (!isObj(doc.dependencies)) throw new Unreadable("has neither a packages nor a dependencies object");
  walk(doc.dependencies, "", 0);
  return p;
}
