// What every manifest reader (#2835) returns, and the purl builders they share.
//
// A reader turns one file's text into the purls it pins (one per dependency entry it can resolve
// to a single registry version) and the entries it cannot check, each with a reason. Nothing is
// guessed: a range is not narrowed to a version, a branch is not resolved to a tag, and an entry
// that names a local path or a VCS checkout is not matched against registry advisories, whose
// versions it need not share. Each such entry is listed, never dropped.
//
// purls follow the purl spec (github.com/package-url/purl-spec, PURL-TYPES.rst), and the shape
// tier1-cloud-scanner/sca/scanner.go purlFor emits: the type, each name segment percent-encoded
// (a scope's '@' as %40), '@', the version as the file states it (Go keeps its leading v). The
// backend reads them with url.PathUnescape (core-backend internal/cve/matchbatch.go
// purlNameVersion) and normalises names on lookup (pkgmatch.go), so the case a file uses is kept.

// Why an entry was not sent to the API. Each is not clean: the entry was not checked at all.
//   version_unpinned    the entry gives a range or a wildcard, not one version (django>=4, ==1.4.*);
//   version_unresolved  the entry names no single registry version: none is given, a branch is
//                       named (composer dev-main), or the version the build selects cannot be read
//                       from this file (a go.mod require of an excluded version);
//   local_path          the dependency is a directory, file or workspace member, not a registry
//                       release (a go.mod replace to ./x, an npm link, a Cargo path crate);
//   vcs_source          the dependency is a VCS checkout (git+, a GIT section), whose code need not
//                       match the registry release of the same version;
//   unsupported_line    a line or entry this reader does not take: another file it includes
//                       (-r, -c), a direct URL, an option, a registry other than the ecosystem's
//                       public one, or text it cannot read.
export const NOT_CHECKED_REASONS = ["version_unpinned", "version_unresolved", "local_path", "vcs_source", "unsupported_line"] as const;
export type NotCheckedReason = (typeof NOT_CHECKED_REASONS)[number];

// One entry not sent: the package name when the entry names one, what the file says for it (the
// line, or the lockfile key and version), the reason, and a sentence on why. line is 1-based, or
// null in a JSON lockfile, whose entries are named by key instead.
export type NotChecked = { name: string | null; spec: string; reason: NotCheckedReason; line: number | null; detail: string };
// One purl read, and where.
export type Pinned = { purl: string; line: number | null };

export type Parsed = {
  pinned: Pinned[];
  not_checked: NotChecked[];
  // Entries left out that are not dependencies: the lockfile's own project (package-lock's root
  // entry), counted so that every entry the file holds is accounted for.
  skipped: number;
  // Sentences on how this file was read that change what its verdicts cover (go.mod before 1.17).
  notes: string[];
  // go.mod replace directives applied: the module required, and the coordinate checked instead.
  replaced?: { from: string; to: string }[];
};

// A file the reader cannot read at all (not JSON, not TOML): the reason, said to the caller.
export class Unreadable extends Error {}

// The most characters of a line or value a not_checked entry repeats.
const SPEC_MAX = 200;
export const specOf = (s: string): string => {
  const t = s.trim();
  return t.length > SPEC_MAX ? `${t.slice(0, SPEC_MAX - 1)}…` : t;
};

// One purl segment, percent-encoded as the purl spec asks; '+' is left as it is (Go's
// +incompatible, a PyPI local version), which url.PathUnescape reads back unchanged.
export const seg = (s: string): string => encodeURIComponent(s).replace(/%2B/g, "+");
// A hierarchical name (a Go module path, an npm @scope/name, a Packagist vendor/name): each
// '/'-separated segment encoded, the separators kept.
export const segPath = (s: string): string => s.split("/").map(seg).join("/");

export const purlOf = (type: string, name: string, version: string): string => `pkg:${type}/${segPath(name)}@${seg(version)}`;

// PEP 503: a PyPI name lowercased, each run of '-', '_' and '.' one '-' (the purl spec's pypi rule).
export const pep503 = (name: string): string => name.toLowerCase().replace(/[-_.]+/g, "-");

// A version a purl can carry: non-empty, no whitespace.
export const usableVersion = (v: unknown): v is string => typeof v === "string" && v.trim() !== "" && !/\s/.test(v.trim());

export const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

export const emptyParsed = (): Parsed => ({ pinned: [], not_checked: [], skipped: 0, notes: [] });
