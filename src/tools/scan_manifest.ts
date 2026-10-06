// scan_manifest (#2835): a project's lockfiles or pinned manifests checked against EchelonGraph's
// advisory corpus, one verdict per dependency, through the batch route check_sbom uses
// (POST /api/v1/public/cves/match/batch, match_batch.ts's loop).
//
// Where the files are read: HERE, in this MCP server, as check_sbom reads an SBOM (on the caller's
// machine when it runs from npm; on EchelonGraph's hosted endpoint when it is called there, whose
// body cap admits a large body for this tool and check_sbom alone, httpPolicy.ts). The caller
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
import { TEXT_BUDGET_DESCRIPTION, type TextCut } from "../textBudget.js";
import { sbomText, type CheckSbomDeps } from "./check_sbom.js";
import { FORMAT_NAMES, FORMATS, NOT_CHECKED_REASONS, detect, readFile, type Format, type NotChecked, type NotCheckedReason } from "./manifests/index.js";
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
  sendBatches,
  sendingCoverage,
  sendingCoverageShape,
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
// How many files the note names one by one.
const NOTE_FILES_MAX = 20;
// How many entries of data.not_checked the text keeps once it must be cut.
const TEXT_NOT_CHECKED = 20;

// The order the distinct purls are counted in, for the position of those not sent (#2799).
const READ_ORDER =
  "counted in the order this tool read them (the files in the order given, each file's entries in the order the file lists them, each purl at its first place)";

const NOT_CHECKED_NOTE =
  "not_checked entries are not clean: each names a dependency this tool did not send to the API (its version is a range or unresolved, or it comes from a local path, a VCS checkout or a line this tool does not read), so no verdict was looked up for it.";

export const SCAN_MANIFEST_TITLE = "Check a lockfile against the advisory corpus";
export const SCAN_MANIFEST_DESCRIPTION =
  "Check a project's lockfile or pinned manifest against EchelonGraph's advisory corpus, one verdict per dependency. Pass files: 1 to 20 of filename and content, up to 5,000,000 characters in all; the filename, or format, gives the format. Read: requirements.txt (== and === pins only), go.mod (require, after replace and exclude), package-lock.json and npm-shrinkwrap.json (v1 to v3), Cargo.lock, Gemfile.lock, composer.lock, poetry.lock and gradle.lockfile. package.json, pyproject.toml, Pipfile, Gemfile, Cargo.toml, composer.json and build.gradle hold ranges and are refused, naming the lockfile to pass; go.sum is refused: it lists versions the build does not select. This server reads the files into purls and only the purls are sent to the API, in POST bodies of at most 200, never in a URL; filenames and file contents are not sent on. Run from npm, this server is on your machine; over the hosted endpoint (mcp.echelongraph.io) it is EchelonGraph's, and the files are the request body, accepted up to 6 MiB. data.results holds one row per distinct purl, with verdict (affected, not_affected, undetermined or not_assessed), not_assessed_reason, cve_ids and matched_via; each match carries kev_listed, epss_score and fixed_in or null with fixed_in_reason. not_affected is the only clean verdict. data.not_checked lists each entry not sent, with file, line and reason: version_unpinned (a range), version_unresolved, local_path, vcs_source or unsupported_line; not_checked entries are not clean. At most 2,000 distinct purls per call, within 50 seconds; data.not_sent_purls lists any not sent, unchecked and not clean." +
  " " +
  TEXT_BUDGET_DESCRIPTION +
  " Cut, each row keeps index, purl, verdict, not_assessed_reason and cve_ids at least; not_checked keeps its first 20.";

// The text's cut: check_sbom's rows and levels, and data.not_checked beside them, cut to its
// first TEXT_NOT_CHECKED once the first level does not fit (structuredContent.data keeps it whole).
export function manifestText(sent: number): TextCut {
  const sbom = sbomText(sent);
  return {
    ...sbom,
    sides: [
      ...(sbom.sides ?? []),
      {
        list: "not_checked",
        cap: TEXT_NOT_CHECKED,
        said: (inText, total) => `coverage.not_checked_by_reason counts all ${total} entries not checked, ${inText} of them in the text.`,
      },
    ],
    page: (shown) => `To read every row in the text, pass files that hold ${shown} or fewer distinct purls per call.`,
  };
}

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
type Read = { files: FileRead[]; purls: string[]; read_purls: number; duplicates_removed: number; not_checked: (NotChecked & { file: string })[] };

export function readFiles(a: { files?: unknown }): Read | string {
  if (!Array.isArray(a.files)) return "files must be a list of {filename, content}";
  if (a.files.length === 0) return "files holds no file";
  if (a.files.length > MAX_FILES) return `${a.files.length} files; at most ${MAX_FILES} are read per call`;
  let total = 0;
  for (const [n, f] of (a.files as FileIn[]).entries()) {
    if (f === null || typeof f !== "object" || typeof f.filename !== "string" || typeof f.content !== "string") return `files[${n}] must be {filename, content}, both strings`;
    if (f.format !== undefined && f.format !== null && !(FORMAT_NAMES as string[]).includes(f.format as string)) {
      return `files[${n}].format ${JSON.stringify(f.format)} is not one of ${FORMAT_NAMES.join(", ")}`;
    }
    total += f.content.length;
  }
  if (total > MAX_MANIFEST_CHARS) return `the files are ${total} characters in all; at most ${MAX_MANIFEST_CHARS} are read per call`;

  const files: FileRead[] = [];
  const all: string[] = [];
  const notChecked: (NotChecked & { file: string })[] = [];
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
    const r = readFile(d.format, f.content);
    if ("unreadable" in r) {
      out.refused = `read as ${d.format}, ${r.unreadable}`;
      continue;
    }
    out.read = true;
    out.purls = r.pinned.length;
    out.not_checked = r.not_checked.length;
    out.skipped = r.skipped;
    out.notes = r.notes;
    out.replaced = r.replaced ?? [];
    all.push(...r.pinned.map((x) => x.purl));
    notChecked.push(...r.not_checked.map((x) => ({ file: f.filename, ...x })));
  }
  if (files.every((f) => !f.read)) return `no file could be read: ${files.map((f) => `${f.filename}: ${f.refused}`).join("; ")}`;
  const { purls, removed } = dedupe(all);
  return { files, purls, read_purls: all.length, duplicates_removed: removed, not_checked: notChecked };
}

// ── The answer ──

const byReason = (rows: { reason: NotCheckedReason }[]): Record<NotCheckedReason, number> => {
  const by = Object.fromEntries(NOT_CHECKED_REASONS.map((r) => [r, 0])) as Record<NotCheckedReason, number>;
  for (const r of rows) by[r.reason]++;
  return by;
};

function noteFor(head: string, x: Read, d: object | null, g: Sending): { note: string; assessed: number } {
  const out: string[] = [head];
  const read = x.files.filter((f) => f.read);
  const shown = read.slice(0, NOTE_FILES_MAX).map((f) => `${f.filename} as ${f.format}: ${plural(f.purls, "entry", "entries")} pinned to one version${f.not_checked ? `, ${f.not_checked} not checked` : ""}${f.skipped ? `, ${f.skipped} skipped (the project's own entry)` : ""}`);
  out.push(`Read ${plural(read.length, "file", "files")}: ${shown.join("; ")}${read.length > NOTE_FILES_MAX ? `; and ${read.length - NOTE_FILES_MAX} more in data.manifest.files` : ""}.`);
  for (const f of x.files.filter((f) => !f.read)) out.push(`NOT READ, so nothing in it is checked: ${f.filename}: ${f.refused}.`);
  for (const f of read) for (const n of f.notes) out.push(`${f.filename}: ${n}`);
  const replaced = read.flatMap((f) => f.replaced);
  if (replaced.length) out.push(`${plural(replaced.length, "go.mod replace was", "go.mod replaces were")} applied, each module checked at its replacement (data.manifest.files lists them).`);
  out.push(
    `${plural(x.purls.length, "distinct purl", "distinct purls")}${x.duplicates_removed ? ` (${plural(x.duplicates_removed, "duplicate was", "duplicates were")} sent once)` : ""}; sent ${g.sent}.`,
  );
  const by = byReason(x.not_checked);
  const nc = x.not_checked.length;
  if (nc) {
    const parts = NOT_CHECKED_REASONS.filter((r) => by[r] > 0).map((r) => `${r} ${by[r]}`);
    out.push(
      `${plural(nc, "entry was", "entries were")} NOT checked and ${nc === 1 ? "is" : "are"} not clean (${parts.join(", ")}): data.not_checked lists each with its file, line and reason, and none was sent to the API.`,
    );
  }
  out.push(...sendingSentences(g, x.purls.length, READ_ORDER, "check_sbom with purls set to"));
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
    const x = readFiles(a);
    if (typeof x === "string") return deps.badInput(tool, x);
    const refused = purlsRefusal(
      x.purls,
      `pass fewer files per call (${x.files.filter((f) => f.read).map((f) => `${f.filename}: ${f.purls}`).join(", ")}), or pass a lockfile's purls to check_sbom in parts of ${MAX_PURLS} or fewer`,
    );
    if (refused) return deps.badInput(tool, refused);
    const by = byReason(x.not_checked);
    const fileCoverage = {
      files: x.files.length,
      files_read: x.files.filter((f) => f.read).length,
      files_not_read: x.files.filter((f) => !f.read).length,
      entries_pinned: x.read_purls,
      duplicates_removed: x.duplicates_removed,
      not_checked: x.not_checked.length,
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
      }, manifestText(0));
    }

    // match_batch.ts: one batch at a time, Retry-After waited out within the budget, stopped on
    // cancellation (#2775), exactly as check_sbom sends its purls.
    const run = await sendBatches(deps, tool, x.purls);
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
    }, manifestText(g.sent));
  } catch (e) {
    return deps.crashed(tool, e);
  }
}

// ── Schemas ──

const reasonEnum = z.enum(NOT_CHECKED_REASONS);
const formatEnum = z.enum(FORMAT_NAMES as [Format, ...Format[]]);

export function scanManifestOutput(envelopeSchema: CheckSbomDeps<FailureLike>["envelopeSchema"]): z.ZodType {
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
              not_checked: z.number().int().describe("Entries not sent, listed in data.not_checked: not clean."),
              skipped: z.number().int().describe("Entries that are not dependencies (a package-lock's root entry, the project itself)."),
              notes: z.array(z.string()).describe("How this file was read where that limits what its verdicts cover (a go.mod below go 1.17)."),
              replaced: z.array(z.object({ from: z.string(), to: z.string() })).describe("go.mod replace directives applied: the module required, and the module and version checked instead."),
            }),
          ),
        })
        .describe("Each file passed, in order, and how it was read. Filenames and contents are not sent to the API."),
      not_checked: z
        .array(
          z.object({
            file: z.string(),
            name: z.string().nullable(),
            spec: z.string().describe("What the file says for the entry: its line, or its lockfile key and version (at most 200 characters)."),
            reason: reasonEnum.describe(
              "version_unpinned: a range or wildcard, not one version; version_unresolved: no single registry version (none given, a branch, or an excluded go.mod version); local_path: a directory, file or workspace member; vcs_source: a VCS checkout; unsupported_line: a line or entry this tool does not read (another file named by -r or -c, a direct URL, another registry).",
            ),
            line: z.number().int().nullable().describe("1-based line; null in a JSON lockfile, whose entries spec names by key."),
            detail: z.string(),
          }),
        )
        .describe("Each entry not sent to the API, with its file, line and reason: not checked, and not clean."),
    }),
    coverage: z.strictObject({
      files: z.number().int().describe("Files passed."),
      files_read: z.number().int().describe("Of those, the ones read."),
      files_not_read: z.number().int().describe("The ones refused or unreadable: nothing in them is checked, and none is clean."),
      entries_pinned: z.number().int().describe("Entries pinned to one version across the files, duplicates included."),
      duplicates_removed: z.number().int().describe("Purls read more than once (the same package and version in two places) and sent once."),
      not_checked: z.number().int().describe("Entries not sent (data.not_checked): not clean."),
      not_checked_by_reason: z.strictObject(Object.fromEntries(NOT_CHECKED_REASONS.map((r) => [r, z.number().int()])) as Record<NotCheckedReason, z.ZodNumber>).describe("not_checked, counted by reason."),
      ...sendingCoverageShape,
    }),
    freshness: null,
  });
}

// A literal server.registerTool(name, { title, description, … }) call with constant strings:
// marketing-site lib/mcpToolClaims.test.ts reads it here (it follows index.ts's call to this
// function) and holds the /pulse/mcp row to this title and description.
export function registerScanManifest<F extends FailureLike>(server: McpServer, deps: CheckSbomDeps<F>): void {
  const output = scanManifestOutput(deps.envelopeSchema as CheckSbomDeps<FailureLike>["envelopeSchema"]);
  server.registerTool(
    SCAN_MANIFEST,
    {
      title: SCAN_MANIFEST_TITLE,
      description: SCAN_MANIFEST_DESCRIPTION,
      inputSchema: z.object({
        files: z
          .array(
            z.object({
              filename: z.string().describe("the file's name, e.g. package-lock.json or services/api/go.mod; it picks the format unless format is set"),
              content: z.string().describe("the file's text, as it is on disk"),
              format: formatEnum.optional().describe("the format to read the file as, when its name does not say"),
            }),
          )
          .describe(
            "1 to 20 files, up to 5,000,000 characters of content in all; read by this MCP server into purls, and only the purls are sent to the API; over the hosted endpoint (mcp.echelongraph.io) the files are the request body",
          ),
      }),
      outputSchema: output as z.ZodObject,
      annotations: deps.annotations,
    },
    async (a: { files?: unknown }, ctx: { mcpReq: { signal: AbortSignal } }) => {
      const run = scanManifest({ ...deps, signal: ctx.mcpReq.signal }, a);
      return deps.checked(SCAN_MANIFEST, output, await (deps.hold ? deps.hold(run) : run)) as never;
    },
  );
}
