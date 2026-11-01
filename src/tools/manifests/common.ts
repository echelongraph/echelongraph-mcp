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
  // #3434: the first NOT_CHECKED_MAX entries not sent, in the order read (addNotChecked); `counted` counts every one.
  not_checked: NotChecked[];
  counted: Record<NotCheckedReason, number>;
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
export const SPEC_MAX = 200;
// #3434: every string from the file that a not_checked entry carries (its spec, its name, one its detail names) is a
// short copy of its own, clip()'s or specOf()'s, never a slice of the text: V8 keeps a slice's whole parent alive, and
// a slice of a string it flattened (an npm v1 install path built as `${parent}node_modules/${key}`, trimmed) keeps
// that whole flattened copy. Then an entry costs what it shows, and one long string of the file named in many
// entries (a block's verb, a replace's directory, a Gemfile.lock section) is copied at most SPEC_MAX characters
// into each.
// JSON.parse builds a new flat string of the characters it is given; a lone surrogate round-trips (JSON.stringify
// escapes it).
const fresh = (s: string): string => JSON.parse(JSON.stringify(s)) as string;
// #3434: what one UTF-16 unit of a string at `i` counts toward clip()'s bound, and how many units it takes: six for a
// character JSON.stringify writes as an escape of six (\u00XX: a control character with no short escape; \uXXXX: a lone
// surrogate), two units of one each for a surrogate pair, else one. A quote, a backslash and \b \t \n \f \r, which JSON
// writes as two, count one: so a string of none of the six-character escapes is cut where its length cuts it (a real
// requirement's `; python_version < "3.9"` as before), and any clipped string's JSON is at most twice `max`.
function jsonCost(s: string, i: number): [cost: number, units: number] {
  const c = s.charCodeAt(i);
  if (c < 0x20) return [c === 0x08 || c === 0x09 || c === 0x0a || c === 0x0c || c === 0x0d ? 1 : 6, 1];
  if (c >= 0xd800 && c <= 0xdbff) {
    const d = s.charCodeAt(i + 1);
    return d >= 0xdc00 && d <= 0xdfff ? [2, 2] : [6, 1];
  }
  return [c >= 0xdc00 && c <= 0xdfff ? 6 : 1, 1];
}
/**
 * s as a string of its own, whitespace and all, when it counts at most `max` (jsonCost: its length, a six-character
 * JSON escape six); else its longest start that counts at most `max` - 1, then "…" (never cutting a surrogate pair).
 * #3434: bounded as an answer carries it, not by its length alone: a string of control characters is six times as long
 * in JSON.
 */
export function clip(s: string, max = SPEC_MAX): string {
  let cost = 0;
  let cut = -1;
  for (let i = 0; i < s.length; ) {
    const [c, n] = jsonCost(s, i);
    if (cut < 0 && cost + c > max - 1) cut = i;
    cost += c;
    if (cost > max) return fresh(`${s.slice(0, cut)}…`);
    i += n;
  }
  return fresh(s);
}
/** s trimmed, then clip()'d. */
export const specOf = (s: string): string => clip(s.trim());

// #3434: the most entries not sent a call lists (data.not_checked), and the most go.mod replaces it lists
// (data.manifest.files[].replaced), each in the order read; the rest are counted, never listed. MAX_PURLS's 2,000,
// and more than any real manifest holds (the most measured, a polkadot-sdk Cargo.lock's, 598). So the answer is
// bounded whatever the files hold: each entry is at most a filename of 1,024 characters (no character JSON writes as a
// six-character escape: scan_manifest refuses one) and strings clip()'d.
export const NOT_CHECKED_MAX = 2_000;

/** One entry not sent: kept in p.not_checked while it holds fewer than NOT_CHECKED_MAX, counted in p.counted always. */
export function addNotChecked(p: Parsed, n: NotChecked): void {
  p.counted[n.reason]++;
  if (p.not_checked.length < NOT_CHECKED_MAX) p.not_checked.push(n);
}

// ── What one call's readers may take (#3434) ──
//
// A call's files are read within three bounds, each counted across all the files of the call (up to 20), so that what
// reading them builds is bounded whatever they hold. Past one the call is refused (scan_manifest: invalid_input naming
// the bound and each file's count), nothing more read. Each was measured on calls of real files, 20 files a call where
// a repository has them, and on the costliest shapes at the bound, two calls at once under Dockerfile.http's flags (its
// two large-body slots).
//   MAX_MANIFEST_LINES  lines of go.mod, requirements.txt, Gemfile.lock and gradle.lockfile, counted as they are
//                       read: each line a reader takes (one that holds a token, or a requirement; blank and comment
//                       lines are not counted). A line gives at most one entry (a go.mod require one replace too),
//                       so this bounds the entries as well. Real calls: GitLab's 20 largest Gemfile.locks, 15,535
//                       lines; 16 of those with 4 other repositories' Gemfile.locks, 20,778; the 20 largest of nine
//                       repositories', 23,286 (refused all the same, past MAX_PURLS); DataHub's 20 largest gradle
//                       lockfiles, 12,671 (the largest one file, GitLab's Gemfile.lock, 3,655). At the bound,
//                       two calls at once, the costliest shapes measured (a go.mod require block of 40,000 lines of
//                       16 tokens, or of long module paths) peaked at 40 to 60 MB live, of the image's 104 MB old
//                       space; every other line format at 27 to 35 MB.
//   MAX_JSON_VALUES     objects and arrays of package-lock.json and composer.lock, and the entries in them (an
//                       object's members, an array's elements), counted before each file is parsed (jsonValues). Not
//                       the objects and arrays alone: an object's members that are not objects cost the parse as
//                       much, and each is an entry a reader takes (an npm v1 dependency, say). Real calls: 7
//                       composer.locks, 128,335; Gutenberg's package-lock.json alone, 50,326 in 1.7 MB. At the
//                       densest file measured (OpenMCT's, 11,420 in 278 KB), the 5,000,000 characters a call reads
//                       would hold about 206,000.
//   MAX_TOML_VALUES     tables, array entries and keys of Cargo.lock and poetry.lock, counted as they are read
//                       (toml.ts; a dotted key's parts each). Real calls: 5 poetry.locks, 86,205; polkadot-sdk's
//                       Cargo.lock alone, 28,189 in 708 KB. At the densest file measured (Zed's, 19,819 in 492 KB),
//                       5,000,000 characters would hold about 201,000.
export const MAX_MANIFEST_LINES = 40_000;
export const MAX_JSON_VALUES = 300_000;
export const MAX_TOML_VALUES = 300_000;

/** A call's count of one kind of unit its readers take, refused past `max` (PastBound). */
export class Bound {
  private taken = 0;
  constructor(
    readonly max: number,
    readonly what: string,
    readonly formats: string,
  ) {}
  take(n = 1): void {
    this.taken += n;
    if (this.taken > this.max) throw new PastBound(this);
  }
  /** How many have been taken (past `max` once it is passed). */
  get count(): number {
    return this.taken;
  }
  /** How many more may be taken. */
  get left(): number {
    return Math.max(0, this.max - this.taken);
  }
}
export class PastBound extends Error {
  constructor(readonly bound: Bound) {
    super(`more than ${bound.max} ${bound.what}`);
  }
}
export type Bounds = { lines: Bound; json: Bound; toml: Bound };
/** One call's bounds, none taken yet. */
export const callBounds = (): Bounds => ({
  lines: new Bound(MAX_MANIFEST_LINES, "lines", "go.mod, requirements.txt, Gemfile.lock and gradle.lockfile"),
  json: new Bound(MAX_JSON_VALUES, "objects, arrays and entries", "package-lock.json and composer.lock"),
  toml: new Bound(MAX_TOML_VALUES, "tables, array entries and keys", "Cargo.lock and poetry.lock"),
});

// #3434: a character JSON.stringify writes as an escape of six characters (a control character with no short escape, a
// lone surrogate) or two (a quote), which a filename that every not_checked entry repeats must not hold. A portable path
// holds none (Windows refuses each in a file name). A backslash, which JSON also writes as two, is a path separator (detect reads it as one).
const ESCAPED = /[\u0000-\u001f"]|[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
/** Whether a filename holds a character JSON escapes: a control character, a quote, or a lone surrogate. */
export const jsonEscaped = (s: string): boolean => ESCAPED.test(s);

/**
 * The objects and arrays of a JSON text, and the entries in them (each counted by the comma before it, or as the first
 * of its object or array), outside its strings, counted to `max` + 1 at most, before it is parsed.
 */
export function jsonValues(text: string, max: number): number {
  let n = 0;
  // The last structural character opened an object or array: the next that is not whitespace begins its first entry,
  // or closes it.
  let opened = false;
  for (let i = 0; i < text.length && n <= max; i++) {
    const c = text.charCodeAt(i);
    if (c === 0x20 || c === 0x0a || c === 0x0d || c === 0x09) continue;
    if (opened) {
      opened = false;
      if (c !== 0x7d && c !== 0x5d) n++;
    }
    if (c === 0x22) {
      // A string, to its closing quote, a backslash escaping the character after it.
      for (i++; i < text.length; i++) {
        const d = text.charCodeAt(i);
        if (d === 0x5c) i++;
        else if (d === 0x22) break;
      }
    } else if (c === 0x7b || c === 0x5b) {
      n++;
      opened = true;
    } else if (c === 0x2c) n++;
  }
  return n;
}

/** A JSON lockfile's text parsed, once its objects, arrays and entries are taken from the call's MAX_JSON_VALUES: a
 *  text past it is never parsed. */
export function parseLockfileJson(text: string, bounds: Bounds): unknown {
  bounds.json.take(jsonValues(text, bounds.json.left));
  try {
    return JSON.parse(text);
  } catch {
    throw new Unreadable("is not JSON");
  }
}

/**
 * Each line of `text` as text.split(crlf ? /\r?\n/ : "\n").forEach(fn) gives them (the empty line after a final newline
 * included), one at a time: a file of many lines never holds an array of them all.
 */
export function eachLine(text: string, crlf: boolean, fn: (raw: string, i: number) => void): void {
  let start = 0;
  for (let i = 0; ; i++) {
    const nl = text.indexOf("\n", start);
    const end = nl < 0 ? text.length : nl;
    // A \r ends the line only before its \n, as in split(/\r?\n/): a last line's own \r is its text.
    fn(crlf && nl >= 0 && end > start && text.charCodeAt(end - 1) === 0x0d ? text.slice(start, end - 1) : text.slice(start, end), i);
    if (nl < 0) return;
    start = nl + 1;
  }
}

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

export const emptyParsed = (): Parsed => ({
  pinned: [],
  not_checked: [],
  counted: Object.fromEntries(NOT_CHECKED_REASONS.map((r) => [r, 0])) as Record<NotCheckedReason, number>,
  skipped: 0,
  notes: [],
});
