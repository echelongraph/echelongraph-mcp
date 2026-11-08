// scan_manifest (#2835): a project's lockfiles or pinned manifests checked against EchelonGraph's
// advisory corpus, one verdict per dependency, through the batch route check_sbom uses
// (POST /api/v1/public/cves/match/batch, match_batch.ts's loop).
//
// Where the files are read: HERE, in this MCP server, as check_sbom reads an SBOM (on the caller's
// machine when it runs from npm; on EchelonGraph's hosted endpoint when it is called there, whose
// body cap admits a large body for a tools/call of this tool or check_sbom, or a prompts/get of
// sbom_review, and nothing else (httpPolicy.ts LARGE_BODY_TARGETS, #3149)). The caller
// passes each file's text; this server never reads the caller's filesystem. Each file is read
// into purls by its reader (manifests/), and only the distinct purls are sent, in POST bodies of
// at most MAX_COMPONENTS (never a URL, #1983). Filenames, file contents, comments, hashes and
// the entries not checked never leave this process.
//
// Nothing is guessed. Only an entry that names one registry version is sent; a range, a branch,
// a local path, a VCS checkout or a line a reader does not take is listed in data.not_checked with
// its file, line and reason, counted in coverage.not_checked_by_reason, and named in the note as
// not clean. A manifest of ranges (package.json, pyproject.toml, …) is refused with the lockfile
// to pass instead, and go.sum is refused: it lists versions the build does not select.
//
// No fixed version is derived here: each row's matches carry the API's own fixed_in and
// fixed_in_reason (#2834), relayed as sent.
import type { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod";
import { answering, FULL_ARG, TEXT_BUDGET_DESCRIPTION, type TextCut } from "../textBudget.js";
import { BUDGETS, WEIGHT_MANIFEST_ENTRY, WEIGHT_MANIFEST_ITEM, documentCost, lockfileEntries, nonBlankLines, tomlEstimate, tomlPackages, tooLargeToHold, LOCAL_INSTEAD, type Budgets } from "../parseBudget.js";
import { BUSY_WHY, sbomData, sbomText, type CheckSbomDeps } from "./check_sbom.js";
import { isHttpEntrypoint, parseBudgeted } from "../runtime.js";
import {
  FORMAT_NAMES,
  FORMATS,
  MAX_JSON_VALUES,
  MAX_MANIFEST_LINES,
  MAX_TOML_VALUES,
  NOT_CHECKED_MAX,
  NOT_CHECKED_REASONS,
  PastBound,
  SPEC_MAX,
  callBounds,
  detect,
  jsonEscaped,
  readFile,
  type Bounds,
  type Format,
  type NotChecked,
  type NotCheckedReason,
} from "./manifests/index.js";
import {
  CLEAN_NOTE,
  DISTRO_NOTE,
  FRESHNESS_NOTE,
  MAX_PURLS,
  MEASURED_AT_NOTE,
  METHOD,
  batchDataShape,
  dedupe,
  field,
  plural,
  purlsRefusal,
  reserveAnswers,
  sendBatches,
  sendingCoverage,
  sendingCoverageShape,
  failureSendingCoverageShape,
  sendingSentences,
  verdictSentences,
  type FailureLike,
  type Sending,
  type ToolResult,
} from "./match_batch.js";

export const SCAN_MANIFEST = "scan_manifest";
// At most this many files per call, and this many characters of content in all: check_sbom's
// document cap, so the hosted endpoint's 6 MiB body cap holds a call at this size (httpPolicy.ts).
export const MAX_FILES = 20;
export const MAX_MANIFEST_CHARS = 5_000_000;
// #3434: the longest filename taken, a path in a repository (the inputSchema's maxLength too), and the characters it may
// not hold: any JSON writes as an escape of six characters or a quote (manifests/common.ts jsonEscaped; the
// inputSchema's pattern too, but for a lone surrogate, which a pattern cannot say alike in every validator). Each entry
// of data.not_checked carries its file's name, so this bounds what a call's NOT_CHECKED_MAX entries repeat of it, as an
// answer carries it: at most 1,024 characters, which JSON writes in at most 2,048 (a backslash as two).
export const MAX_FILENAME_CHARS = 1_024;
const FILENAME_PATTERN = /^[^\x00-\x1f"]*$/;
const FILENAME_RULE = "must hold no control character (U+0000 to U+001F), quote or lone surrogate, which a portable path does not hold";
// How many files the note names one by one.
const NOTE_FILES_MAX = 20;
// How many entries of data.not_checked the text keeps once it must be cut.
const TEXT_NOT_CHECKED = 20;

// The order the distinct purls are counted in, for the position of those not sent (#2799).
const READ_ORDER =
  "counted in the order this tool read them (the files in the order given, each file's entries in the order the file lists them, each purl at its first place)";

const NOT_CHECKED_NOTE =
  "not_checked entries are not clean: each names a dependency this tool did not send to the API (its version is a range or unresolved, or it comes from a local path, a VCS checkout or a line this tool does not read), so no verdict was looked up for it.";

// 3.1.0's phase A review: fix C's wording tied "50 seconds a call" to the 429 wait alone, while
// match_batch.ts's TIME_BUDGET_MS bounds the whole call: a slow batch is cut off at its end
// (time_budget), and a 429 refused (rate_limited) or a batch failed (request_failed) after the first
// also answers partial, the rest in not_sent_purls. 3.0.2's "within 50 seconds" said so; the
// description says it again, the room from shorter wording elsewhere (every claim kept).
// #3434: data.not_checked lists a call's first NOT_CHECKED_MAX entries and counts all, and a call past a per-call bound
// or with a filename past MAX_FILENAME_CHARS is refused; the description says both, within its 1,948 characters, the
// room from fixed_in_reason, not_assessed_reason, matched_via and "require" (the outputSchema describes each), the
// format sentence (files' own descriptions say it) and "unchecked" (not_sent_purls are not clean). The refusals come
// before the budget sentence, which test/scan_manifest.test.mjs (#3100) reads with the API's sentence after it. Its
// numbers are literals, as marketing-site's check reads them; test/manifest-lines.test.mjs holds them to the constants.
export const SCAN_MANIFEST_TITLE = "Check a lockfile against the advisory corpus";
export const SCAN_MANIFEST_DESCRIPTION =
  "Check a project's lockfile or pinned manifest against EchelonGraph's advisory corpus, one verdict per dependency. Pass files: 1 to 20 of filename and content, up to 5,000,000 characters in all. Read: requirements.txt (== and === pins only), go.mod, package-lock.json and npm-shrinkwrap.json (v1-v3), Cargo.lock, Gemfile.lock, composer.lock, poetry.lock and gradle.lockfile. package.json, pyproject.toml, Pipfile, Gemfile, Cargo.toml, composer.json and build.gradle hold ranges: refused, naming the lockfile; go.sum is refused: it lists versions the build does not select. The server reads the files into purls; only the purls are sent to the API, in POST bodies of at most 200, never in a URL; filenames and file contents are not sent on. Run from npm, this server is on your machine; over the hosted endpoint (mcp.echelongraph.io) it is EchelonGraph's, and the files are the request body, up to 6 MiB. data.results holds a row per distinct purl: verdict (affected, not_affected, undetermined or not_assessed) and cve_ids; each match carries kev_listed, epss_score and fixed_in. not_affected is the only clean verdict. data.not_checked lists the first 2,000 entries not sent (file, line, reason), counting all; not_checked entries are not clean. Refused: over 40,000 lines or 300,000 JSON/TOML values a call, a filename over 1,024 characters. Hosted, also over 30 MiB with its body. At most 2,000 distinct purls and 50 seconds a call. The API allows 1,200 components a minute per caller; on a 429 it waits out Retry-After within that; a later batch cut off, refused or failed ends the call, the rest in data.not_sent_purls, not clean." +
  " " +
  TEXT_BUDGET_DESCRIPTION +
  " Cut, each row keeps index, purl, verdict, not_assessed_reason and cve_ids at least; not_checked its first 20.";

// The text's cut: check_sbom's rows and levels, and data.not_checked beside them, cut to its
// first TEXT_NOT_CHECKED once the first level does not fit (structuredContent.data keeps it whole).
// #3132's second review: check_sbom's sentence on not_sent_purls says a second call can send them
// without reading the list, from their positions in the input; here those positions index purls
// read from the files, which a client cannot rebuild, so the sentence names full: true instead.
// #3434: `notChecked`, the entries not checked the call counted, of which data.not_checked lists at most
// NOT_CHECKED_MAX.
export function manifestText(sent: number, notChecked?: number): TextCut {
  const sbom = sbomText(sent);
  return {
    ...sbom,
    sides: [
      ...(sbom.sides ?? []).map((side) =>
        side.list === "not_sent_purls"
          ? {
              ...side,
              said: (_inText: number, total: number) =>
                `The ${total} purls not sent are the purls this tool read from position ${sent + 1} on, counted in the order the note gives for them; structuredContent.data.not_sent_purls lists every one with full: true.`,
            }
          : side,
      ),
      {
        list: "not_checked",
        cap: TEXT_NOT_CHECKED,
        said: (inText, total) => `coverage.not_checked_by_reason counts all ${notChecked ?? total} entries not checked, ${inText} of them in the text.`,
      },
    ],
    // #3269's second review: no page sentence, as for check_sbom's text (sbomText says why).
  };
}

// #3013: the structured result's cut, check_sbom's (sbomData: the lists beside the rows, then every
// row thinned, then rows leaving, clean ones first) with not_checked beside not_sent_purls.
// #3269's second review: the sentence promises only what holds (check_sbom.ts sbomPageSaid).
export const manifestPageSaid = (k: number): string =>
  `A call whose files hold the first ${k} of these purls, or fewer, keeps every row in data; a call of other files says in its own note what it leaves out.`;
const MANIFEST_DATA = sbomData(["not_sent_purls", "not_checked"], manifestPageSaid);

// ── Reading the files ──

type FileIn = { filename?: unknown; content?: unknown; format?: unknown };
// One file as data.manifest.files reports it.
type FileRead = {
  filename: string;
  format: Format | null;
  ecosystem: string | null;
  read: boolean;
  refused: string | null;
  purls: number;
  not_checked: number;
  skipped: number;
  notes: string[];
  replaced: { from: string; to: string }[];
};
// #3434: not_checked, the first NOT_CHECKED_MAX entries not sent (counted, all of them, in not_checked_total and
// not_checked_by_reason), and the files' replaced lists the first NOT_CHECKED_MAX replaces applied (replaced_total).
type Read = {
  files: FileRead[];
  purls: string[];
  read_purls: number;
  duplicates_removed: number;
  not_checked: (NotChecked & { file: string })[];
  not_checked_total: number;
  not_checked_by_reason: Record<NotCheckedReason, number>;
  replaced_total: number;
};

// #3434: why a call whose files pass one of the readers' bounds (manifests/common.ts) is refused, naming the bound, and
// what each of its files counted against it, as purlsRefusal lists each file's purls, so a caller can split the call.
// `counted`: each file read so far, the last the one that passed the bound (counted to that point).
function pastBound(e: PastBound, bounds: Bounds, counted: { filename: string; counts: Record<keyof Bounds, number> }[]): string {
  const b = e.bound;
  const key = (Object.keys(bounds) as (keyof Bounds)[]).find((k) => bounds[k] === b) ?? "lines";
  const how = key === "lines" ? " (blank and comment lines are not counted)" : key === "json" ? " (counted before each file is parsed)" : "";
  const each = counted.filter((f) => f.counts[key] > 0).map((f, i, all) => `${f.filename} ${f.counts[key]}${i === all.length - 1 ? " when the bound was passed" : ""}`);
  return `the ${b.formats} files hold more than ${b.max} ${b.what} in all, counted per call${how}: ${each.join(", ")}; at most ${b.max} are read per call, so no file is read: pass these files over more calls, or a lockfile's purls to check_sbom in parts`;
}

// #3381's round-5 review (C1): the hosted endpoint's bound in files, for a too_large refusal of a lockfile to say in
// plain words. Measured 2026-11-01 on 38 real lockfiles of large public repositories (24 package-lock.json, 8
// Cargo.lock, 6 poetry.lock, 67 KB to 1.8 MB: each one read, the costliest 0.40 of what one request may hold), and on
// each scaled by copies of its own packages up to the 5,000,000-character cap: a poetry.lock is refused from about 3 MB
// (3.1 to 3.9 MB, by its shape). A Cargo.lock is refused from 2.4 MB and a package-lock.json from 3.3 to 5 MB, but
// #3381's round-6 verification (R6V-2.2, 2.3) found each of those already holds more than the 2,000 distinct purls a
// call checks (3.1.5 refused them too): only the poetry.lock is a call 3.1.5 answered and this endpoint refuses. A
// package-lock.json whose entries repeat a package at many install paths can stay within 2,000 and pass the bound too
// (test/http-parse-budget-round4.test.mjs F4), hence "usually".
export const HOSTED_READS = "on this endpoint that is about a 3 MB poetry.lock; a Cargo.lock or package-lock.json that large usually already holds more than the 2,000 distinct purls a call checks";
// The formats read a line at a time; the rest (JSON and TOML lockfiles) are parsed whole.
const LINE_FORMATS: ReadonlySet<Format> = new Set<Format>(["requirements.txt", "go.mod", "Gemfile.lock", "gradle.lockfile"]);

// #3381: what reading a call's files may retain, estimated before any is read, which the hosted endpoint reserves in its
// parse budget first (runtime.ts reserveParse): the costliest one file's parse (a JSON lockfile's tree, parseBudget.ts
// scanJson; a TOML lockfile's tables, tomlEstimate; a line format keeps one line at a time), and every entry its readers
// will take, counted as they take them (#3381's review: through round 3 every line and JSON element was counted, so a
// real poetry.lock or package-lock.json of a few MB was reserved far more than it takes, and could never fit beside its
// own body): a package entry of an npm or Composer lockfile (parseBudget.ts lockfileEntries), a [[package]] table of a
// TOML one (tomlPackages), a line of the others (nonBlankLines), each kind at most #3434's bound for it (MAX_MANIFEST_LINES,
// MAX_JSON_VALUES, MAX_TOML_VALUES: past one the readers stop and the call is refused), each entriesCost's. A
// file past PARSE_BUDGET_BYTES is not read (its reader refuses it), so it adds nothing; a call whose files readFiles
// refuses (precheck) adds nothing. `budgets`: the bounds in force (parseBudget.ts BUDGETS, from this process's heap),
// unless the caller names others. #3381's round-4 review (F10): each file counted as its reader will read it, its
// leading byte-order mark dropped (manifests/index.ts readFile): through round 4 one before a lockfile's '{' left the
// count at 0 entries, where its reader took them all.
export function manifestEstimate(a: { files?: unknown }, budgets: Budgets = BUDGETS): number {
  if (precheck(a) !== undefined) return 0;
  let parse = 0;
  let lines = 0;
  let json = 0;
  let toml = 0;
  for (const f of a.files as { filename: string; content: string; format?: Format | null }[]) {
    const d = f.format ? { format: f.format } : detect(f.filename);
    if ("refused" in d) continue;
    const content = f.content.replace(/^\uFEFF/, "");
    let one = 0;
    let entries: number;
    if (d.format === "package-lock.json" || d.format === "composer.lock") {
      one = documentCost(content).bytes;
      entries = one <= budgets.parseBytes ? lockfileEntries(content, d.format === "composer.lock" ? "composer" : "npm") : 0;
    } else if (d.format === "Cargo.lock" || d.format === "poetry.lock") {
      one = tomlEstimate(content);
      entries = one <= budgets.parseBytes ? tomlPackages(content) : 0;
    } else entries = nonBlankLines(content);
    if (one > budgets.parseBytes) continue;
    parse = Math.max(parse, one);
    if (d.format === "package-lock.json" || d.format === "composer.lock") json += entries;
    else if (d.format === "Cargo.lock" || d.format === "poetry.lock") toml += entries;
    else lines += entries;
  }
  // #3434's per-call bounds stop the readers past them (manifests/common.ts), so no more is reserved than they take.
  return parse + entriesCost(Math.min(lines, MAX_MANIFEST_LINES) + Math.min(json, MAX_JSON_VALUES) + Math.min(toml, MAX_TOML_VALUES));
}

// #3381's round-5 review (C1): what `entries` entries a call's readers take hold to the call's end, WEIGHT_MANIFEST_ENTRY
// each, and as many of them as data.not_checked can list (NOT_CHECKED_MAX) WEIGHT_MANIFEST_ITEM more, as the answer
// carries them (parseBudget.ts). `listed`: how many of them are listed, where that is known (after the read); before it,
// as many as may be.
export const entriesCost = (entries: number, listed: number = entries): number =>
  entries * WEIGHT_MANIFEST_ENTRY + Math.min(listed, NOT_CHECKED_MAX) * WEIGHT_MANIFEST_ITEM;

// Why a call's files are not read, from their shape alone (before anything is counted or reserved, #3381's review), or
// undefined.
export function precheck(a: { files?: unknown }): string | undefined {
  if (!Array.isArray(a.files)) return "files must be a list of {filename, content}";
  if (a.files.length === 0) return "files holds no file";
  if (a.files.length > MAX_FILES) return `${a.files.length} files; at most ${MAX_FILES} are read per call`;
  let total = 0;
  for (const [n, f] of (a.files as FileIn[]).entries()) {
    if (f === null || typeof f !== "object" || typeof f.filename !== "string" || typeof f.content !== "string") return `files[${n}] must be {filename, content}, both strings`;
    if (f.filename.length > MAX_FILENAME_CHARS) return `files[${n}].filename is ${f.filename.length} characters; at most ${MAX_FILENAME_CHARS} are taken (a path in a repository)`;
    if (jsonEscaped(f.filename)) return `files[${n}].filename ${FILENAME_RULE}`;
    if (f.format !== undefined && f.format !== null && !(FORMAT_NAMES as string[]).includes(f.format as string)) {
      return `files[${n}].format ${JSON.stringify(f.format)} is not one of ${FORMAT_NAMES.join(", ")}`;
    }
    total += f.content.length;
  }
  if (total > MAX_MANIFEST_CHARS) return `the files are ${total} characters in all; at most ${MAX_MANIFEST_CHARS} are read per call`;
  return undefined;
}

// `budgets`: the bounds in force (parseBudget.ts BUDGETS, from this process's heap), unless the caller names others: each
// file's parse or read is held to its parseBytes (#3381).
export function readFiles(a: { files?: unknown }, budgets: Budgets = BUDGETS): Read | string {
  const refused = precheck(a);
  if (refused) return refused;

  const files: FileRead[] = [];
  const all: string[] = [];
  const notChecked: (NotChecked & { file: string })[] = [];
  const by = Object.fromEntries(NOT_CHECKED_REASONS.map((r) => [r, 0])) as Record<NotCheckedReason, number>;
  let notCheckedTotal = 0;
  let replacedKept = 0;
  let replacedTotal = 0;
  // #3434: one set of bounds for the whole call, every file's reader taking from it, and what each file counted.
  const bounds = callBounds();
  const counted: { filename: string; counts: Record<keyof Bounds, number> }[] = [];
  const counts = (): Record<keyof Bounds, number> => ({ lines: bounds.lines.count, json: bounds.json.count, toml: bounds.toml.count });
  for (const f of a.files as { filename: string; content: string; format?: Format | null }[]) {
    const out: FileRead = { filename: f.filename, format: null, ecosystem: null, read: false, refused: null, purls: 0, not_checked: 0, skipped: 0, notes: [], replaced: [] };
    files.push(out);
    const d: { format: Format } | { refused: string } = f.format ? { format: f.format } : detect(f.filename);
    if ("refused" in d) {
      out.refused = d.refused;
      continue;
    }
    out.format = d.format;
    out.ecosystem = FORMATS[d.format].ecosystem;
    let r: ReturnType<typeof readFile>;
    const before = counts();
    const mine = (): Record<keyof Bounds, number> => {
      const now = counts();
      return { lines: now.lines - before.lines, json: now.json - before.json, toml: now.toml - before.toml };
    };
    try {
      r = readFile(d.format, f.content, bounds, budgets.parseBytes);
    } catch (e) {
      if (e instanceof PastBound) return pastBound(e, bounds, [...counted, { filename: f.filename, counts: mine() }]);
      throw e;
    }
    counted.push({ filename: f.filename, counts: mine() });
    if ("unreadable" in r) {
      out.refused = `read as ${d.format}, ${r.unreadable}`;
      // #3381's round-5 review (C1): past the parse bound on the hosted endpoint, the bound in files and what to do.
      if (isHttpEntrypoint() && r.unreadable.startsWith("it is too dense to read")) out.refused += `; on this endpoint one file's read may take ${budgets.parseBytes} bytes (${Math.floor(budgets.parseBytes / (1024 * 1024))} MiB) of its memory: ${LOCAL_INSTEAD}, or pass the lockfile's purls to check_sbom, in calls of 2,000 or fewer`;
      continue;
    }
    out.read = true;
    out.purls = r.pinned.length;
    out.not_checked = NOT_CHECKED_REASONS.reduce((n, reason) => n + r.counted[reason], 0);
    out.skipped = r.skipped;
    out.notes = r.notes;
    // #3434: the call lists the first NOT_CHECKED_MAX replaces applied, and counts them all.
    const replaced = r.replaced ?? [];
    out.replaced = replaced.length <= NOT_CHECKED_MAX - replacedKept ? replaced : replaced.slice(0, NOT_CHECKED_MAX - replacedKept);
    replacedKept += out.replaced.length;
    replacedTotal += replaced.length;
    // One by one, never push(...list): a 5,000,000-character requirements.txt of unpinned lines
    // is some 170,000 entries, and, spread into push() as that many arguments, they overflowed
    // V8's stack ("Maximum call stack size exceeded", #3013's review): the call crashed.
    for (const p of r.pinned) all.push(p.purl);
    // #3434: the call lists the first NOT_CHECKED_MAX entries not checked, and counts them all.
    notCheckedTotal += out.not_checked;
    for (const reason of NOT_CHECKED_REASONS) by[reason] += r.counted[reason];
    for (const n of r.not_checked) {
      if (notChecked.length >= NOT_CHECKED_MAX) break;
      notChecked.push({ file: f.filename, ...n });
    }
  }
  if (files.every((f) => !f.read)) return `no file could be read: ${files.map((f) => `${f.filename}: ${f.refused}`).join("; ")}`;
  const { purls, removed } = dedupe(all);
  return {
    files,
    purls,
    read_purls: all.length,
    duplicates_removed: removed,
    not_checked: notChecked,
    not_checked_total: notCheckedTotal,
    not_checked_by_reason: by,
    replaced_total: replacedTotal,
  };
}

// ── The answer ──

function noteFor(head: string, x: Read, d: object | null, g: Sending): { note: string; assessed: number } {
  const out: string[] = [head];
  const read = x.files.filter((f) => f.read);
  const shown = read.slice(0, NOTE_FILES_MAX).map((f) => `${f.filename} as ${f.format}: ${plural(f.purls, "entry", "entries")} pinned to one version${f.not_checked ? `, ${f.not_checked} not checked` : ""}${f.skipped ? `, ${f.skipped} skipped (the project's own entry)` : ""}`);
  out.push(`Read ${plural(read.length, "file", "files")}: ${shown.join("; ")}${read.length > NOTE_FILES_MAX ? `; and ${read.length - NOTE_FILES_MAX} more in data.manifest.files` : ""}.`);
  for (const f of x.files.filter((f) => !f.read)) out.push(`NOT READ, so nothing in it is checked: ${f.filename}: ${f.refused}.`);
  for (const f of read) for (const n of f.notes) out.push(`${f.filename}: ${n}`);
  const replaced = x.replaced_total;
  const listed = read.reduce((n, f) => n + f.replaced.length, 0);
  if (replaced) {
    out.push(
      `${plural(replaced, "go.mod replace was", "go.mod replaces were")} applied, each module checked at its replacement (data.manifest.files lists ${listed === replaced ? "them" : `the first ${listed}, as many as a call lists`}).`,
    );
  }
  out.push(
    `${plural(x.purls.length, "distinct purl", "distinct purls")}${x.duplicates_removed ? ` (${plural(x.duplicates_removed, "duplicate was", "duplicates were")} sent once)` : ""}; sent ${g.sent}.`,
  );
  const by = x.not_checked_by_reason;
  const nc = x.not_checked_total;
  if (nc) {
    const parts = NOT_CHECKED_REASONS.filter((r) => by[r] > 0).map((r) => `${r} ${by[r]}`);
    // #3013's review: the note is written before the structured result is cut, and a DATA CUT can
    // cut data.not_checked (it goes before any row), so this says the list is whole with full:
    // true, as the sentence on data.not_sent_purls does (match_batch.ts sendingSentences); the
    // counts above are coverage.not_checked_by_reason's, which no cut touches.
    // #3434: past NOT_CHECKED_MAX, the list is the first entries read, and the rest are counted only.
    const listed = x.not_checked.length;
    out.push(
      listed === nc
        ? `${plural(nc, "entry was", "entries were")} NOT checked and ${nc === 1 ? "is" : "are"} not clean (${parts.join(", ")}): data.not_checked lists each with its file, line and reason, whole with full: true (past the structured result's budget, that list can be cut by default), and none was sent to the API.`
        : `${plural(nc, "entry was", "entries were")} NOT checked and are not clean (${parts.join(", ")}): data.not_checked lists the first ${listed} read, each with its file, line and reason (at most ${NOT_CHECKED_MAX} a call, full: true included; past the structured result's budget, that list can be cut further by default), and the other ${nc - listed} are counted in coverage.not_checked_by_reason and data.manifest.files, not listed; none was sent to the API.`,
    );
  }
  out.push(...sendingSentences(g, x.purls.length, READ_ORDER, "check_sbom with purls set to", false));
  if (d === null) return { note: out.join(" "), assessed: 0 };
  const v = verdictSentences(d, g);
  out.push(...v.sentences);
  return { note: out.join(" "), assessed: v.assessed };
}

// What data.manifest.files and data.not_checked carry, beside the API's answer.
const manifestData = (x: Read) => ({
  manifest: {
    files: x.files.map((f) => ({ ...f })),
  },
  not_checked: x.not_checked,
});

export async function scanManifest<F extends FailureLike>(deps: CheckSbomDeps<F>, a: { files?: unknown }): Promise<ToolResult> {
  const tool = SCAN_MANIFEST;
  try {
    // #3381: on the hosted endpoint, what reading the files may retain is reserved in the instance's parse budget first,
    // once the files' shape is one readFiles reads (#3381's review: a call it refuses for its shape reserves nothing): a
    // reservation the request could never hold is refused at once, one that found no room in the wait is busy.
    const shape = precheck(a);
    if (shape) return deps.badInput(tool, shape);
    let keep: ((bytes: number) => void) | undefined;
    let reserved = 0;
    // #3381's round-6 verification (R6V-2.4): only a call the hosted endpoint serves has a budget (runtime.ts
    // parseBudgeted); on stdio the estimate bounded nothing and was thrown away, every call paying for a scan of its
    // files.
    if (deps.reserve && deps.busy && parseBudgeted()) {
      const bytes = manifestEstimate(a);
      reserved = bytes;
      const r = await deps.reserve(bytes);
      if (r.state === "busy") return deps.busy(tool, BUSY_WHY);
      if (r.state === "too_large") {
        // #3381's round-5 review (C1): a call of one file cannot pass fewer files. Round-6 verification (R6V-2.1): the
        // advice by format: a lockfile's purls to check_sbom, the bound in lockfile sizes; a line format's lines over
        // more calls.
        const files = a.files as { filename: string; format?: Format | null }[];
        const lockfile = files.some((f) => {
          const d = f.format ? { format: f.format } : detect(f.filename);
          return "format" in d && !LINE_FORMATS.has(d.format);
        });
        const one = files.length === 1;
        const instead = one
          ? lockfile ? "pass the lockfile's purls to check_sbom, in calls of 2,000 or fewer" : "pass its lines over more calls"
          : lockfile ? "pass fewer or smaller files per call, or a lockfile's purls to check_sbom in parts" : "pass fewer or smaller files per call, or a file's lines over more calls";
        return deps.badInput(tool, tooLargeToHold(one ? "the file" : "the files", bytes, r.heldBytes, r.maxBytes, instead, lockfile ? HOSTED_READS : undefined));
      }
      keep = r.keep;
    }
    const x = readFiles(a);
    // #3381's review: what parsing the files built is dropped once readFiles returns; for the rest of the call (its API
    // phase) what is held is the entries kept (entriesCost: never more than manifestEstimate reserved for them, so the
    // hold only shrinks, #3381's round-5 review B1).
    // #3381's round-10 review (R10-B1): and at most what was reserved, whatever the two counts come to.
    keep?.(typeof x === "string" ? 0 : Math.min(reserved, entriesCost(x.purls.length + x.not_checked.length, x.not_checked.length)));
    if (typeof x === "string") return deps.badInput(tool, x);
    const refused = purlsRefusal(
      x.purls,
      `pass fewer files per call (${x.files.filter((f) => f.read).map((f) => `${f.filename}: ${f.purls}`).join(", ")}), or pass a lockfile's purls to check_sbom in parts of ${MAX_PURLS} or fewer`,
    );
    if (refused) return deps.badInput(tool, refused);
    const by = x.not_checked_by_reason;
    const fileCoverage = {
      files: x.files.length,
      files_read: x.files.filter((f) => f.read).length,
      files_not_read: x.files.filter((f) => !f.read).length,
      entries_pinned: x.read_purls,
      duplicates_removed: x.duplicates_removed,
      not_checked: x.not_checked_total,
      not_checked_by_reason: by,
    };
    const notes = [NOT_CHECKED_NOTE, CLEAN_NOTE, DISTRO_NOTE, MEASURED_AT_NOTE, FRESHNESS_NOTE];

    // Nothing to send: every entry is a range, a local path, a VCS checkout or unread. The answer
    // says so, entry by entry; no request is made, and nothing is measured.
    if (x.purls.length === 0) {
      const g: Sending = { batches: 0, batches_sent: 0, sent: 0, not_sent_purls: [], not_sent_reason: null, not_sent_detail: null, waits: 0, waited_ms: 0 };
      const head = `${tool} OK: nothing was sent to EchelonGraph, as no entry in the files names one registry version this tool can check, so nothing is measured and nothing is clean.`;
      const { note } = noteFor(head, x, null, g);
      return deps.succeeded({ ...manifestData(x), results: [] }, note, {
        state: "not_assessed",
        measured_at: null,
        method: METHOD,
        coverage: { ...fileCoverage, ...sendingCoverage(g, 0, undefined) },
        freshness: null,
        notes,
      }, manifestText(0, x.not_checked_total));
    }

    // match_batch.ts: one batch at a time, Retry-After waited out within the budget, stopped on
    // cancellation (#2775), exactly as check_sbom sends its purls.
    // #3381's round-4 review: what the API's answers will hold, reserved before the first batch (match_batch.ts).
    const answers = await reserveAnswers(deps, tool, x.purls.length);
    if ("result" in answers) return answers.result;
    const run = await sendBatches(deps, tool, x.purls, answers);
    if (!run.ok) return run.result;
    const { data, status, sending: g } = run;
    Object.assign(data, manifestData(x));
    const { note, assessed } = noteFor(deps.okHead(tool, status), x, data, g);
    return deps.succeeded(data, note, {
      state: assessed > 0 ? "measured" : "not_assessed",
      measured_at: null,
      method: METHOD,
      coverage: { ...fileCoverage, ...sendingCoverage(g, x.purls.length, field(data, "summary")) },
      freshness: null,
      notes,
    }, manifestText(g.sent, x.not_checked_total));
  } catch (e) {
    return deps.crashed(tool, e);
  }
}

// ── Schemas ──

const reasonEnum = z.enum(NOT_CHECKED_REASONS);
// #3434: NOT_CHECKED_MAX as the schema's descriptions say it.
const LISTED = NOT_CHECKED_MAX.toLocaleString("en-US");
const formatEnum = z.enum(FORMAT_NAMES as [Format, ...Format[]]);

export function scanManifestOutput(envelopeSchema: CheckSbomDeps<FailureLike>["envelopeSchema"]): z.ZodType {
  const read = {
    files: z.number().int().describe("Files passed."),
    files_read: z.number().int().describe("Of those, the ones read."),
    files_not_read: z.number().int().describe("The ones refused or unreadable: nothing in them is checked, and none is clean."),
    entries_pinned: z.number().int().describe("Entries pinned to one version across the files, duplicates included."),
    duplicates_removed: z.number().int().describe("Purls read more than once (the same package and version in two places) and sent once."),
    not_checked: z.number().int().describe(`Entries not sent, every one counted (data.not_checked lists the first ${LISTED}): not clean.`),
    not_checked_by_reason: z.strictObject(Object.fromEntries(NOT_CHECKED_REASONS.map((r) => [r, z.number().int()])) as Record<NotCheckedReason, z.ZodNumber>).describe("not_checked, counted by reason."),
  };
  return envelopeSchema({
    data: z.looseObject({
      ...batchDataShape,
      manifest: z
        .object({
          files: z.array(
            z.object({
              filename: z.string(),
              format: formatEnum.nullable().describe("The format the file was read as: set by format, or read from the filename; null when it was not read."),
              ecosystem: z.string().nullable().describe("The OSV ecosystem of the purls read from it."),
              read: z.boolean().describe("false: the file was refused or could not be read, and nothing in it is checked (not clean)."),
              refused: z.string().nullable().describe("Why the file was not read, and the file to pass instead where there is one; null when it was read."),
              purls: z.number().int().describe("Entries pinned to one version, read as purls (duplicates included)."),
              not_checked: z.number().int().describe(`Entries not sent, every one counted; data.not_checked lists the call's first ${LISTED}: not clean.`),
              skipped: z.number().int().describe("Entries that are not dependencies (a package-lock's root entry, the project itself)."),
              notes: z.array(z.string()).describe("How this file was read where that limits what its verdicts cover (a go.mod below go 1.17)."),
              replaced: z
                .array(z.object({ from: z.string(), to: z.string() }))
                .describe(`go.mod replace directives applied: the module required, and the module and version checked instead (a call lists at most ${LISTED}; the note counts them all).`),
            }),
          ),
        })
        .describe("Each file passed, in order, and how it was read. Filenames and contents are not sent to the API."),
      not_checked: z
        .array(
          z.object({
            file: z.string(),
            name: z.string().nullable().describe(`The package's name, as the file gives it (at most ${SPEC_MAX} characters).`),
            spec: z.string().describe("What the file says for the entry: its line, or its lockfile key and version (at most 200 characters)."),
            reason: reasonEnum.describe(
              "version_unpinned: a range or wildcard, not one version; version_unresolved: no single registry version (none given, a branch, or an excluded go.mod version); local_path: a directory, file or workspace member; vcs_source: a VCS checkout; unsupported_line: a line or entry this tool does not read (another file named by -r or -c, a direct URL, another registry).",
            ),
            line: z.number().int().nullable().describe("1-based line; null in a JSON lockfile, whose entries spec names by key."),
            detail: z.string(),
          }),
        )
        .describe(
          `Each entry not sent to the API, with its file, line and reason: not checked, and not clean. A call lists its first ${LISTED} read; coverage.not_checked counts them all.`,
        ),
    }),
    coverage: z.strictObject({ ...read, ...sendingCoverageShape }),
    // #3381's round-10 review (R10-1): the failure branch keeps 3.1.5's not_sent_reason (match_batch.ts).
    failureCoverage: z.strictObject({ ...read, ...failureSendingCoverageShape }),
    freshness: null,
  });
}

// One output schema per process, not per request (3.0.2; index.ts envelopeSchema says why).
const OUTPUTS = new WeakMap<object, z.ZodType>();
// A literal server.registerTool(name, { title, description, … }) call with constant strings:
// marketing-site lib/mcpToolClaims.test.ts reads it here (it follows index.ts's call to this
// function) and holds the /pulse/mcp row to this title and description.
export function registerScanManifest<F extends FailureLike>(server: McpServer, deps: CheckSbomDeps<F>): void {
  const envelope = deps.envelopeSchema as CheckSbomDeps<FailureLike>["envelopeSchema"];
  const output = OUTPUTS.get(envelope) ?? scanManifestOutput(envelope);
  OUTPUTS.set(envelope, output);
  server.registerTool(
    SCAN_MANIFEST,
    {
      title: SCAN_MANIFEST_TITLE,
      description: SCAN_MANIFEST_DESCRIPTION,
      inputSchema: z.object({
        // #3345: at most MAX_FILES, checked before any file is parsed (inputBounds.ts says why).
        files: z
          .array(
            z.object({
              // #3434: bounded, as readFiles bounds it (MAX_FILENAME_CHARS).
              filename: z
                .string()
                .max(MAX_FILENAME_CHARS)
                .regex(FILENAME_PATTERN, FILENAME_RULE)
                .describe("the file's name, e.g. package-lock.json or services/api/go.mod; it picks the format unless format is set"),
              content: z.string().describe("the file's text, as it is on disk"),
              format: formatEnum.optional().describe("the format to read the file as, when its name does not say"),
            }),
          )
          .max(MAX_FILES)
          .describe(
            "1 to 20 files, up to 5,000,000 characters of content in all; read by this MCP server into purls, and only the purls are sent to the API; over the hosted endpoint (mcp.echelongraph.io) the files are the request body",
          ),
        full: FULL_ARG,
      }),
      outputSchema: output as z.ZodObject,
      annotations: deps.annotations,
    },
    async (a: { files?: unknown; full?: boolean }, ctx: { mcpReq: { signal: AbortSignal } }) =>
      answering(a.full, MANIFEST_DATA, async () => {
        const run = scanManifest({ ...deps, signal: ctx.mcpReq.signal }, a);
        return deps.checked(SCAN_MANIFEST, output, await (deps.hold ? deps.hold(run) : run)) as never;
      }),
  );
}
