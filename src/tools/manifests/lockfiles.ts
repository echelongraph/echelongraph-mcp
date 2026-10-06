// The resolved-version lockfiles of Rust, Python (Poetry), Ruby, PHP and Gradle (#2835). Each
// entry is one package at one version as the tool that wrote the file resolved it; entries from a
// local path or a VCS checkout are listed, not checked.
//
//   Cargo.lock (v1 to v4)  [[package]] tables read as TOML, never by pairing a name line with the
//                          next version line (docs/SBOM_COVERAGE_PROGRAM.md row 46): a source of
//                          the crates.io index (registry+https://github.com/rust-lang/crates.io-index
//                          or sparse+https://index.crates.io/) is checked; no source is a workspace
//                          member or path crate (local_path); git+ is vcs_source; another registry
//                          unsupported_line.
//   poetry.lock            [[package]] tables read as TOML; a [package.source] of type git is
//                          vcs_source, directory or file local_path, url unsupported_line; a legacy
//                          (private index) source is checked as PyPI.
//   Gemfile.lock           Bundler's sections read by indentation: each spec line (four spaces,
//                          name (version)) of a GEM section is checked, its platform suffix
//                          stripped (nokogiri (1.15.4-x86_64-linux) is nokogiri 1.15.4); a PATH
//                          section's specs are local_path and a GIT section's vcs_source.
//   composer.lock          packages and packages-dev, each version's leading v stripped
//                          (v6.4.1 is 6.4.1); a branch version (dev-main, 2.x-dev) is
//                          version_unresolved; a dist of type path local_path.
//   gradle.lockfile        group:artifact:version=configurations lines (and the older
//                          per-configuration lockfiles' group:artifact:version); empty= lists the
//                          configurations with no dependency, and is skipped.
import { Unreadable, emptyParsed, isObj, pep503, purlOf, seg, specOf, usableVersion, type NotCheckedReason, type Parsed } from "./common.js";
import { readToml, type TomlTable } from "./toml.js";

// [[package]] tables of a TOML lockfile, each with its header's line.
function packagesOf(text: string): { t: TomlTable; line: number | null }[] {
  const { root, lines } = readToml(text);
  const pkgs = root.package;
  if (pkgs === undefined) return [];
  if (!Array.isArray(pkgs)) throw new Unreadable("has a package key that is not an array of [[package]] tables");
  return pkgs.filter(isObj).map((t) => ({ t: t as TomlTable, line: lines.get(t as object) ?? null }));
}

const CRATES_IO = new Set(["registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/"]);

export function readCargoLock(text: string): Parsed {
  const p = emptyParsed();
  for (const { t, line } of packagesOf(text)) {
    const name = typeof t.name === "string" ? t.name : null;
    const version = typeof t.version === "string" ? t.version : undefined;
    const src = typeof t.source === "string" ? t.source : undefined;
    const miss = (reason: NotCheckedReason, detail: string) => p.not_checked.push({ name, spec: specOf(`${name ?? "?"} ${version ?? ""}${src ? ` (${src})` : ""}`), reason, line, detail });
    if (!name || !usableVersion(version)) miss("version_unresolved", "the [[package]] table names no package and version");
    else if (src === undefined) miss("local_path", "no source: a workspace member or path dependency, not a crates.io release");
    else if (src.startsWith("git+")) miss("vcs_source", "a git dependency, whose code need not match the crates.io release of the same version");
    else if (!CRATES_IO.has(src)) miss("unsupported_line", "from a registry other than crates.io, whose crates need not be the crates.io crates of the same name");
    else p.pinned.push({ purl: purlOf("cargo", name, version), line });
  }
  return p;
}

export function readPoetryLock(text: string): Parsed {
  const p = emptyParsed();
  for (const { t, line } of packagesOf(text)) {
    const name = typeof t.name === "string" ? t.name : null;
    const version = typeof t.version === "string" ? t.version : undefined;
    const source = isObj(t.source) ? t.source : null;
    const type = source && typeof source.type === "string" ? source.type : null;
    const miss = (reason: NotCheckedReason, detail: string) => p.not_checked.push({ name, spec: specOf(`${name ?? "?"} ${version ?? ""}${type ? ` (source ${type})` : ""}`), reason, line, detail });
    if (!name || !usableVersion(version)) miss("version_unresolved", "the [[package]] table names no package and version");
    else if (type === "git") miss("vcs_source", "a git dependency, whose code need not match the PyPI release of the same version");
    else if (type === "directory" || type === "file") miss("local_path", `a local ${type}, not a PyPI release`);
    else if (type === "url") miss("unsupported_line", "installed from a URL, not a PyPI release");
    else p.pinned.push({ purl: purlOf("pypi", pep503(name), version), line });
  }
  return p;
}

export function readGemfileLock(text: string): Parsed {
  const p = emptyParsed();
  let section: string | null = null;
  let inSpecs = false;
  text.split(/\r?\n/).forEach((raw, i) => {
    const line = i + 1;
    if (raw.trim() === "") return;
    if (!/^\s/.test(raw)) {
      section = raw.trim();
      inSpecs = false;
      return;
    }
    if (/^ {2}specs:\s*$/.test(raw)) {
      inSpecs = true;
      return;
    }
    if (/^ {2}\S/.test(raw)) {
      inSpecs = false;
      return;
    }
    // A spec: four spaces, then name (version). Six spaces is one of its own requirements.
    if (!inSpecs || !/^ {4}\S/.test(raw)) return;
    const m = /^ {4}([^\s(]+) \(([^)]+)\)\s*$/.exec(raw);
    const miss = (name: string | null, reason: NotCheckedReason, detail: string) => p.not_checked.push({ name, spec: specOf(raw), reason, line, detail });
    if (!m) return miss(null, "unsupported_line", "a spec line this reader cannot read (name (version))");
    const [, name, full] = m;
    // RubyGems versions carry no '-': what follows the first one is the platform.
    const version = full.split("-")[0];
    if (section === "PATH") return miss(name, "local_path", "a gem from a local path (PATH section), not a RubyGems release");
    if (section === "GIT") return miss(name, "vcs_source", "a gem from a git repository (GIT section), whose code need not match the RubyGems release of the same version");
    if (section !== "GEM") return miss(name, "unsupported_line", `a gem from a ${section ?? "unnamed"} section, not a RubyGems source`);
    if (!usableVersion(version)) return miss(name, "version_unresolved", "the spec carries no version");
    p.pinned.push({ purl: purlOf("gem", name, version), line });
  });
  return p;
}

export function readComposerLock(text: string): Parsed {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    throw new Unreadable("is not JSON");
  }
  if (!isObj(doc)) throw new Unreadable("is not a JSON object");
  if (!Array.isArray(doc.packages) && !Array.isArray(doc["packages-dev"])) throw new Unreadable("has neither a packages nor a packages-dev list");
  const p = emptyParsed();
  for (const list of ["packages", "packages-dev"]) {
    const pkgs = doc[list];
    if (!Array.isArray(pkgs)) continue;
    for (const e of pkgs) {
      if (!isObj(e)) continue;
      const name = typeof e.name === "string" ? e.name : null;
      const raw = typeof e.version === "string" ? e.version : undefined;
      const miss = (reason: NotCheckedReason, detail: string) => p.not_checked.push({ name, spec: specOf(`${list}: ${name ?? "?"} ${raw ?? ""}`), reason, line: null, detail });
      const dist = isObj(e.dist) ? e.dist : null;
      if (!name || !usableVersion(raw)) miss("version_unresolved", "the entry names no package and version");
      else if (dist && dist.type === "path") miss("local_path", "installed from a local path, not a Packagist release");
      else if (/^dev-|-dev$/.test(raw)) miss("version_unresolved", "a branch, not a released version");
      else p.pinned.push({ purl: purlOf("composer", name, raw.replace(/^v(?=\d)/, "")), line: null });
    }
  }
  return p;
}

export function readGradleLockfile(text: string): Parsed {
  const p = emptyParsed();
  text.split(/\r?\n/).forEach((raw, i) => {
    const l = raw.trim();
    if (l === "" || l.startsWith("#")) return;
    if (/^empty=/.test(l)) return;
    const coords = l.split("=")[0];
    const m = /^([^:\s]+):([^:\s]+):([^:\s]+)$/.exec(coords);
    if (!m) {
      p.not_checked.push({ name: null, spec: specOf(raw), reason: "unsupported_line", line: i + 1, detail: "not a group:artifact:version line" });
      return;
    }
    const [, group, artifact, version] = m;
    // purl-spec maven: the group is the namespace, the artifact the name.
    p.pinned.push({ purl: `pkg:maven/${seg(group)}/${seg(artifact)}@${seg(version)}`, line: i + 1 });
  });
  return p;
}
