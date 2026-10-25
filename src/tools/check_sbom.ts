// check_sbom (#2721): a dependency list checked against EchelonGraph's advisory corpus, one
// verdict per component, through POST /api/v1/public/cves/match/batch.
//
// Where the SBOM is parsed: HERE, in this MCP server — on the caller's machine when it runs from
// npm, on EchelonGraph's hosted endpoint when it is called there (http.ts, whose body cap admits
// a document only for this tool and scan_manifest, #2747, #2835). The backend accepts only a list
// of components ({purl} or {ecosystem, package, version}); a CycloneDX or SPDX document posted to it
// whole is refused. So this tool reads the document, takes each component's purl, and sends only
// those, in a POST body (never a URL, #1983). The document's metadata, licences, hashes and free
// text never leave the machine, and the public route parses nothing but a flat list
// (core-backend internal/cve/matchbatch.go says the same from its side).
//
// What it is not: a ranking. It is not the rejected prioritize_cves (#2304, "Considered and
// rejected"); it relays each component's own verdict, assessed / not_assessed_reason included,
// and orders nothing.
//
// The note never renders not_assessed or undetermined as clean, and always says why a deb, apk or
// rpm purl without a distro release is not assessed.
import type { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod";
import { answering, FULL_ARG, TEXT_BUDGET_DESCRIPTION, type Again, type DataCut, type LeaveLast, type RowKeep, type TextCut, type ThinLevel } from "../textBudget.js";
import { boundedRecord } from "../inputBounds.js";
import {
  CLEAN_NOTE,
  DISTRO_NOTE,
  FRESHNESS_NOTE,
  MAX_PURLS,
  MEASURED_AT_NOTE,
  METHOD,
  affectedSaidOver,
  batchDataShape,
  dedupe,
  field,
  isObj,
  plural,
  purlsRefusal,
  sendBatches,
  sendingCoverage,
  sendingCoverageShape,
  sendingSentences,
  verdictSentences,
  type FailureLike,
  type MatchBatchDeps,
  type Sending,
  type ToolResult,
} from "./match_batch.js";

// #2835: the batch loop, its constants and the row schema moved to match_batch.ts, which
// scan_manifest shares; re-exported here, where the tests and prompts.ts import them.
export { API_COMPONENTS_PER_MINUTE, BATCH_PATH, MAX_COMPONENTS, MAX_PURLS, TIME_BUDGET_MS, mergeAnswers, type ToolResult } from "./match_batch.js";

// What index.ts hands this module, so the tool uses the server's one api(), envelope and failure
// contract instead of a copy (and index.ts stays the only place that defines them). The batch
// loop's part is match_batch.ts's MatchBatchDeps.
export type CheckSbomDeps<F extends FailureLike> = MatchBatchDeps<F> & {
  // #2775: on the hosted endpoint, runtime.ts holdRequest: the request's admission and large-body
  // slot are held until the call has stopped. Absent, the call runs unheld.
  hold?: <T>(p: Promise<T>) => Promise<T>;
  badInput: (tool: string, why: string) => ToolResult;
  crashed: (tool: string, e: unknown) => ToolResult;
  checked: (tool: string, schema: z.ZodType, r: ToolResult) => ToolResult;
  succeeded: (
    data: object,
    note: string,
    env: { state: "measured" | "not_assessed"; measured_at: string | null; method: string; coverage: Record<string, unknown> | null; freshness: null; notes?: string[] },
    cut?: TextCut,
  ) => ToolResult;
  okHead: (tool: string, status?: number) => string;
  envelopeSchema: (o: { data: z.ZodType; coverage: z.ZodType | null; freshness: z.ZodType | null }) => z.ZodType;
  annotations: Record<string, boolean>;
};

export const CHECK_SBOM = "check_sbom";
// The document's size cap, as JSON text. OWASP Juice Shop 11.1.2's full CycloneDX SBOM (840
// components) is 0.74 MB; this leaves room for a much larger one while bounding what this process
// parses.
export const MAX_SBOM_CHARS = 5_000_000;
// #3345: the most top-level members an sbom passed as an object may have, checked before zod
// reads any of them (inputBounds.ts boundedRecord). CycloneDX 1.6 defines 18 ($schema, bomFormat,
// specVersion, serialNumber, version, metadata, components, services, externalReferences,
// dependencies, compositions, properties, vulnerabilities, annotations, formulation, declarations,
// definitions, signature), SPDX 2.3 16 and SPDX 3.0's JSON-LD 2; 64 leaves room for a later
// version's and a generator's own. What a member holds is bounded by the document's character cap
// above and by the arguments' element limit (index.ts MAX_TOOL_INPUT_ELEMENTS).
export const MAX_SBOM_MEMBERS = 64;
// #3345: the most entries purls may hold, repeats included, checked before zod reads any
// (inputBounds.ts). Not MAX_PURLS, the most DISTINCT purls a call checks, counted after trimming
// and dedupe (purlsRefusal): a list may repeat a purl, as a flattened SBOM does once per install
// path, and through 3.1.0 such a list was checked with each purl sent once. Five times MAX_PURLS,
// room for each of 2,000 distinct purls five times over; only a list past it, which 3.1.0 had no
// bound for, is newly refused. It is reached over the hosted endpoint as on stdio (no body cap
// there): a check_sbom call may be a large body (httpPolicy.ts, up to 6 MiB), and 10,000 entries
// of realistic purls (22 to 120 characters, npm to rpm with qualifiers) are a 0.25 to 1.2 MB
// tools/call body, of the longest the backend takes (MAX_PURL_LEN, 512) 5.15 MB
// (test/input-bounds.test.mjs holds that under the cap). Its 10,002 elements are far below the
// arguments' element limit (index.ts MAX_TOOL_INPUT_ELEMENTS), and the answer grows with the
// distinct purls sent, not with this.
export const MAX_PURL_ENTRIES = 10_000;
// CycloneDX nests components; this bounds the walk.
const MAX_DEPTH = 32;
// The order in which extract() reads and counts the distinct purls (#2799 review): purls as listed;
// a CycloneDX document's components depth first, each one's nested components right after it
// (fromCycloneDX); an SPDX document's packages as listed; each purl trimmed and kept at its first
// place (dedupe). The note says it beside the position from which the purls not sent run, so a
// second call can rebuild them from its own input whether or not the text cuts not_sent_purls.
const READ_ORDER =
  "counted in the order this tool read them (the order of purls, or of the document's components or packages, each component's nested components right after it and before its next sibling, each purl at its first place)";

export const CHECK_SBOM_TITLE = "Check an SBOM against the advisory corpus";
// #2846: the routing sentence for the pods-and-images question, inside the description's first
// 2,048 characters (test/prompts-resources.test.mjs holds it there, with a control). The workload
// itself never reaches this tool: the workload_triage prompt has the agent build each image's SBOM
// with its own tools and pass the purls.
export const CHECK_SBOM_ROUTING =
  "For container images and Kubernetes pods, the input is an SBOM of each image, or its purls.";
export const CHECK_SBOM_DESCRIPTION =
  "Check a dependency list against EchelonGraph's advisory corpus, one verdict per component. " +
  CHECK_SBOM_ROUTING +
  " Pass purls (package URLs, up to 2,000 distinct, 10,000 with repeats) or sbom (a CycloneDX or SPDX JSON document, up to 5,000,000 characters). This server reads the document's purls; only they are sent to the API, in POST bodies of at most 200, never in a URL; the document itself is not sent on. Run from npm, this server is on your machine; over the hosted endpoint (mcp.echelongraph.io) it is EchelonGraph's, and the document is the request body, accepted up to 6 MiB. data.results holds one row per component sent, in order, with verdict (affected, not_affected, undetermined or not_assessed), not_assessed_reason, cve_ids, matched_package and matched_via (a deb or apk purl's upstream qualifier matches as its source package); each match carries fixed_in (the next unaffected version) or null with fixed_in_reason. data.summary counts the verdicts. not_affected is the only clean verdict: not_assessed (no verdict, as for a deb, apk or rpm purl without a distro qualifier naming its release, which EchelonGraph does not guess) and undetermined are not, and the note counts both. The API allows 1,200 components a minute per caller; on a 429 the tool waits out Retry-After, up to 50 seconds a call, then answers what it has, the rest in data.not_sent_purls, not clean. Input with more than 2,000 distinct purls is refused, not truncated." +
  " " +
  TEXT_BUDGET_DESCRIPTION +
  " Cut, each row keeps index, purl, verdict, not_assessed_reason and cve_ids at least, each match its fixed_in while kept; not_affected rows leave the text first, then not_assessed ones; not_sent_purls keeps its first 10.";

// #2783: a production row is about 2,200 characters as pretty JSON, most of it its matches, each
// a CVE with its description, so the 50-component Juice Shop document was 112,820 characters of
// text, and 2,000 purls about 1,200,000. Past DATA_TEXT_BUDGET each row in the first text block
// keeps its verdict, counts, cve_ids, matched_package and matched_via (#2836), and each match its
// scores, flags, fixed_in (#2834) and match_reason (the
// advisory interval the version falls inside: "[A, B)" names that interval's fixed bound B, "[A, B]" the last
// affected one, #2830) without the
// description; then the same without match_reason; then only index, purl, verdict,
// not_assessed_reason and cve_ids. When rows must still go, the clean ones (not_affected) leave
// first, then the not_assessed ones, both counted in data.summary and the note, so the affected
// and undetermined rows are the last to leave the text.
// A call that stops early (a 2,000-purl call from a fresh budget answers 1,200 and is refused the
// rest with a 429) lists the purls not sent in data.not_sent_purls: 800 of them are some 20,000
// to 60,000 characters, which the text cannot hold beside the rows. Once the first level does not
// fit with that list whole, the text keeps its first 10 and the note says which they are: the
// input's distinct purls from position `sent` + 1 on, in input order, which is how check_sbom read
// them (x.purls.slice(answers.length * MAX_COMPONENTS)), so a second call can send them without
// reading the list. noteFor gives that order (READ_ORDER) beside the position, so this sentence
// points to it.
// #3269 (the structured cut's rule, kept in the text too): the clean and not_assessed rows left
// the text only once every row was cut to the last level, so an image SBOM's text kept every clean
// row and no affected row's matches: replayed on the production synthetic's rows, 150 purls with 40
// affected kept 150 rows and the matches of none of the 40, on 3.0.0 and 3.0.2 alike. Now, before
// any row is cut to the last level, those rows are cut to it and leave the text, as many as must;
// where even that does not fit, the cut goes on as before.
export function sbomText(sent: number): TextCut {
  const matches = ["cve_id", "severity", "effective_severity", "effective_score", "kev_listed", "ransomware", "epss_score", "score_assessed", "fixed_in", "fixed_in_reason"];
  const row = [
    "index", "purl", "ecosystem", "package", "version", "verdict", "assessed", "not_assessed_reason", "count", "not_affected_count", "undetermined_count", "cve_ids", "matched_package", "matched_via",
  ];
  return {
    rows: "results",
    levels: [
      { keep: [...row, ["matches", [...matches, "match_reason"]]], clip: 200 },
      { keep: [...row, ["matches", matches]], clip: 200 },
      { keep: ["index", "purl", "verdict", "not_assessed_reason", "cve_ids"], clip: 100 },
    ],
    sides: [
      {
        list: "not_sent_purls",
        cap: 10,
        said: (_inText, total) =>
          `The ${total} purls not sent are the input's distinct purls from position ${sent + 1} on, counted in the order the note gives for them, so a second call can send them without reading the list.`,
      },
    ],
    leaveOutFirst: { field: "verdict", values: ["not_affected", "not_assessed"], why: "data.summary counts every verdict" },
    outFirstBefore: 2,
    // #3284: data keeps the rows with a KEV-listed or ransomware match first (SBOM_LEAVE_LAST),
    // while the text left rows from the end in input order, so a KEV-bearing row data kept could
    // leave the text, named in no text block and in no note (the DATA CUT sentence names only rows
    // left out of data): on the reviewer's 36 realistic Debian-12 images a client reading the text
    // alone missed 95 of 413 KEV-bearing rows (linux-libc-dev at index 282, 5 KEV CVEs, among
    // them). Now such rows leave the text last, as #2899's check_affected matches do, and the note
    // names each one that still leaves by its index.
    leaveOutLast: { fields: [], name: "index", why: "", has: hasKev, said: "a KEV-listed or ransomware match", runs: true },
    // check_affected cuts its text too past the budget (#2802): only its structuredContent.data is
    // a component's matches whole, with full: true (#3013).
    whole:
      "check_affected, given a row's ecosystem, package and version, returns that component's matches, whole in its structuredContent.data with full: true, and cve_intel a CVE's affected packages and fixed versions.",
    // #3269's second review: no page sentence. "To read every row in the text, check N or fewer purls
    // per call", N the rows the text kept, was false for a call of the first N purls in 34 of 89
    // mixes (on 3.0.2 too): the clean rows that leave first make N no page size. The sentence on
    // the rows left out says how many left and that structuredContent.data holds them.
  };
}

// #3013: the structured result's cut. A production row is about 1,900 characters of compact JSON
// (its matches, each a CVE with its description), so the 50-component Juice Shop document was 98,682
// characters of structured result and 2,000 purls 3,790,686. The lists beside the rows go first
// (not_sent_purls: the note says from which position of the input they run, and in what order; and,
// for scan_manifest, not_checked, which coverage.not_checked_by_reason counts). Then, before any
// row leaves, every row is thinned to SBOM_ROW_THIN: what a row says of the component and its
// verdict, and per match what a triage reads (a match's description, about 535 characters, is
// get_cve's); the first #3013 cut, before release, kept 3 of Juice Shop's 50 rows whole, all affected, and named the
// other 7 affected components nowhere a client reading structuredContent sees. Only then do rows
// leave, as in the text: the not_affected rows first, then the not_assessed ones (data.summary
// counts every verdict), then the last of the rest, so the affected and undetermined rows are the
// last to go.
// #3013's review: a thinned match kept cve_id, kev_listed, epss_score, fixed_in and
// fixed_in_reason, while the workload_triage prompt reads kev_listed, ransomware, epss_score,
// effective_score, score_assessed and fixed_in from a row's matches (its step 5 and ordering keys),
// so a client reading structuredContent lost ransomware and the score it ranks by. Each field a
// prompt reads from check_sbom's or scan_manifest's matches is kept (test/prompt-fields.test.mjs
// holds every prompt's to this list).
export const SBOM_ROW_THIN: RowKeep = [
  "index",
  "purl",
  "verdict",
  "not_assessed_reason",
  "cve_ids",
  "matched_package",
  "matched_via",
  "matched_version_from",
  "purl_name",
  ["matches", ["cve_id", "kev_listed", "ransomware", "epss_score", "effective_score", "score_assessed", "fixed_in", "fixed_in_reason"]],
];
// #3132: past SBOM_ROW_THIN, each row is cut on its own terms before any row leaves. Through 3.0.0
// SBOM_ROW_THIN was the only level, and it keeps every match object, so one row still large once
// thinned left data, and every row after it with it (rows leave from the end): measured on hosted
// 3.0.0 (2026-10-11), five Debian 12 purls, all affected, kept 1 row (libssl3; linux-libc-dev
// 6.1.55-1's 200 matches are 42,417 characters thinned); Juice Shop 11.1.2 with
// magento/community-edition 2.3.0 inserted at index 2 kept 2 of 51 rows (19 affected); that purl
// alone kept none, and the note said "check 0 or fewer purls per call". Now, in order (since
// #3269, the clean and not-assessed rows leave between 1 and 2: see SBOM_ROW_COMPACT's comment):
//   1. SBOM_ROW_THIN, every row, every match (as before);
//   2. the same, with every row's matches capped at one number m, the most that fit: a row with
//      more than m keeps m (its first in the API's order through 3.0.2; pickMatches's since #3270) and carries
//      matches_truncated, its own total and returned, and the CVE IDs among all its matches that
//      are KEV-listed (kev_listed_cve_ids) or used in ransomware (ransomware_cve_ids), and the
//      distinct fixed_in versions they name (fixed_in_versions), so what a triage ranks by first
//      is still said of the matches cut; rows with m or fewer matches are untouched;
//   3. SBOM_ROW_COMPACT, each match cut to cve_id, kev_listed, ransomware, fixed_in and
//      effective_score (and, since #3270, epss_score and score_assessed), the row keeping
//      matched_package, matched_via and an upstream row's
//      matched_version_from and purl_name, matches capped at one number m as in 2 (any m, 0
//      included), with the same matches_truncated;
//   4. SBOM_ROW_MIN, the text's leanest level (index, purl, verdict, not_assessed_reason and
//      cve_ids), with that matches_truncated on each row that had matches;
//   5. SBOM_ROW_MIN with matches_truncated cut to total and returned;
// and only then do rows leave (clean, then not assessed, then the last of the rest).
// #3132's review: round 1 had no level 3, and level 2 was taken at m = 0. The production
// synthetic's 201-purl probe (synthetic/probes.mjs SBOM_PROBE_PURLS, recorded on hosted 3.0.0 with
// full: true, 2026-10-11: 201 affected rows, 415 matches, 710,724 characters) then came back at
// level 5 with 132 rows, every match, KEV flag and fixed_in gone, and the probe's EXPECT (log4j-core
// 2.14.1's CVE-2021-44228 match, fixed_in 2.15.0; the upstream row's matched_via) failed, where
// 3.0.0 kept 43 rows thinned and passed. So now:
//   - level 2 is taken only at m >= 1 (least): at m = 0 it holds less than level 3;
//   - when not even level 5 keeps every row, rows leave at level 3 with matches capped at
//     SBOM_LEAVING_CAP (leaveAt), not at level 5: a page of the size the note names then comes back
//     with each row's KEV flags and fixed_in, which at level 5 no page size did;
//   - once the cut is settled, the rows kept take back detail in input order while the result fits
//     (giveBack): each the richest level above its own that fits, its matches at the compact level
//     at the most that fit, stopping at the first row that takes back none.
// Measured on that recording (test/check_sbom-large-rows.test.mjs): 54 of 201 rows, each compact
// with every match (none has more than 7), the log4j-core row with its CVE-2021-44228 match and the
// upstream row with matched_via, at 29,959 characters.
// cve_ids is what the API caps at 200 a row, about 3,400 characters, so every row survives level 5
// unless the rows are many (the probe's 201, Juice Shop's full 840 purls).
// #3269's second review (DO-NOT-SHIP on its first): levels 2 and 3 went on below a row's floor,
// to a cap of 1 and then 0, and then to levels 4 and 5, every row kept with one match or none:
// five Debian 12 purls beside an image's 150 (40 affected) kept 45 affected rows, 1 with any match
// (3.0.2: 26, 22 with every match). Now levels 2 and 3 hold each row's floor (matchFloor) whatever
// their cap, taken from a cap of SBOM_LEAVING_CAP; levels 4 and 5 are not taken while a row other
// than a not_affected or not_assessed one has matches; and rows leave whole at level 3 at their
// floor (SBOM_LEAVE_AT), the rows kept chosen those with a KEV-listed or ransomware match first,
// then the others, each in input order, each one that fits (SBOM_LEAVE_LAST, textBudget.ts
// keptByFit), the rest named by index in the note. Where not even one row fits at its floor, the
// row chosen first stays alone below it, its matches the most that fit (belowSaid). Measured on
// the 40 Debian-image mixes of that review: 819 affected rows keep every match or their floor
// (round 1 of it: 462, 744 more under the floor; 3.0.2: 929, 116 more under it, its compact
// matches without epss_score and score_assessed, which #3270 keeps: with those two left out, this
// ladder keeps 1,025). #3269's third review: 820 (1,030 with those two left out), the note naming
// the rows left out with a KEV-listed match apart and how to check them again.
//
// #3269 and #3270, the post-close review of #3132 (3.0.2):
//   - Every row went down these levels together, the clean ones with the affected, and rows left
//     only at the last, so an ordinary image SBOM kept its clean rows by cutting the affected rows'
//     matches: 150 purls, 40 of them affected (test/check_sbom-large-rows.test.mjs's image-shaped
//     mix), kept all 150 rows and the matches of 2 of the 40 affected, where 3.0.0 kept 56 rows and
//     every match of all 40. An affected row's matches are what an SBOM check is for, and the clean
//     rows are counted in data.summary. So now (sbomData's outFirst) the not_affected and
//     not_assessed rows are cut to SBOM_ROW_MIN (a not_assessed row keeps not_assessed_reason),
//     then leave, not_affected first, before any other row is cut below SBOM_ROW_THIN; once the
//     cut is settled, those that left come back, cut so, as many as the room left holds. #3269's
//     review: they leave so only where that keeps every other row's matches whole; where the
//     others must be capped anyway, they stay while the others fit at matchFloor (below).
//   - A capped row kept its first m matches, the API's order (highest effective_score first), so a
//     KEV-listed CVE ranked lower was cut and only matches_truncated named it: magento/community-
//     edition 2.3.0's CVE-2025-54236, at position 21 of its 200, with Juice Shop beside it. A capped
//     row now keeps its KEV-listed and ransomware matches first, then the highest effective_score
//     (pickMatches), in the API's order.
//   - SBOM_ROW_COMPACT dropped epss_score and score_assessed, which workload_triage ranks by: the
//     201-purl probe kept 54 rows and not one match with either. Every level that keeps matches now
//     keeps every field a prompt reads from a match (test/prompt-fields.test.mjs holds each level of
//     SBOM_ROW_LEVELS to them); compact is SBOM_ROW_THIN without fixed_in_reason. 3.1.0's
//     integration (#2834 beside #3269): sbom_review relays a null fixed_in's fixed_in_reason, and
//     keeping it here was measured: it cost the 201-purl probe a row (43 to 42; the DATA CUT
//     sentence naming it is 17 characters longer) and the second review's image mixes affected rows
//     at their floor (16 to 12, 32 to 31, 31 to 30, 23 to 22). So it stays out, and sbom_review
//     reads a null fixed_in without it as a reason the cut left out, never as no fix
//     (test/check_sbom-large-rows.test.mjs pins the probe; prompt-fields the prompt).
export const SBOM_ROW_COMPACT: RowKeep = [
  "index",
  "purl",
  "verdict",
  "not_assessed_reason",
  "cve_ids",
  "matched_package",
  "matched_via",
  "matched_version_from",
  "purl_name",
  ["matches", ["cve_id", "kev_listed", "ransomware", "epss_score", "effective_score", "score_assessed", "fixed_in"]],
];
export const SBOM_ROW_MIN: RowKeep = ["index", "purl", "verdict", "not_assessed_reason", "cve_ids"];
// The most matches a row keeps, compact, when rows leave (pickMatches's); the rest are in its
// cve_ids and matches_truncated.
export const SBOM_LEAVING_CAP = 10;
// #3270: which `cap` of a row's matches a capped level keeps, by their index: those used in
// ransomware, then the other KEV-listed ones, then the highest effective_score (a match without one
// last), the API's order breaking ties; returned in the API's order, which data keeps.
export function pickMatches(ms: readonly unknown[], cap: number): number[] {
  const tier = (m: unknown) => (field(m, "ransomware") === true ? 0 : field(m, "kev_listed") === true ? 1 : 2);
  const score = (m: unknown) => {
    const s = field(m, "effective_score");
    return typeof s === "number" && Number.isFinite(s) ? s : Number.NEGATIVE_INFINITY;
  };
  const by = (a: number, b: number) => tier(ms[a]) - tier(ms[b]) || (score(ms[b]) === score(ms[a]) ? 0 : score(ms[b]) > score(ms[a]) ? 1 : -1) || a - b;
  return ms
    .map((_, i) => i)
    .sort(by)
    .slice(0, Math.max(0, cap))
    .sort((a, b) => a - b);
}
// matches_truncated for a row whose matches data keeps `kept` of (none at levels 3 and 4); with
// `summary`, the three lists drawn from all of the row's matches. Absent on a row with no match
// cut, and on one with no matches.
function matchesTruncated(row: Record<string, unknown>, kept: number, summary: boolean): Record<string, unknown> {
  const ms = Array.isArray(row.matches) ? row.matches.filter(isObj) : [];
  if (ms.length <= kept) return {};
  const ids = (f: string) => [...new Set(ms.filter((m) => m[f] === true && typeof m.cve_id === "string").map((m) => m.cve_id as string))];
  const fixed = [...new Set(ms.map((m) => m.fixed_in).filter((v): v is string => typeof v === "string"))];
  return {
    matches_truncated: {
      total: ms.length,
      returned: Math.min(kept, ms.length),
      ...(summary ? { kev_listed_cve_ids: ids("kev_listed"), ransomware_cve_ids: ids("ransomware"), fixed_in_versions: fixed } : {}),
    },
  };
}
const MATCHES_TRUNCATED_SAID =
  "carrying matches_truncated, which gives its own total and returned, and, of all its matches, the CVE IDs KEV-listed (kev_listed_cve_ids) or used in ransomware (ransomware_cve_ids) and the distinct fixed_in versions (fixed_in_versions)";
const PICK_SAID = "chosen used in ransomware first, then the other KEV-listed ones, then those of highest effective_score, and listed in the API's order";
// #3269's review: the matches kept are chosen in one order and listed in another; round 1's "at
// most m, in the API's order: those KEV-listed or used in ransomware first, then those of highest
// effective_score" read as the order data lists them in. #3269's second review: and a row keeps its
// floor (matchFloor) whatever the cap, which the clause says where it is above the cap for a row.
const cappedSaid = (cap: number, raised?: boolean) =>
  `each row's matches keeping at most ${cap}${raised ? `, or its matches used in ransomware or KEV-listed and ${SBOM_LEAVING_CAP} more where those come to more` : ""}, ${PICK_SAID}; a row with more than that ${MATCHES_TRUNCATED_SAID}`;
// #3269's second review: the one row kept below its floor, where not even it fits at the floor.
const belowSaid = (cap: number) =>
  `the one row kept keeping ${cap} of its matches, fewer than its matches used in ransomware or KEV-listed and ${SBOM_LEAVING_CAP} more, since no more fit beside it, ${PICK_SAID}, and ${MATCHES_TRUNCATED_SAID}`;
// #3269's second review: the two capped levels hold each row's floor (matchFloor) whatever the cap,
// and are taken from a cap of SBOM_LEAVING_CAP (below it every row keeps the same: its floor).
export const SBOM_ROW_LEVELS: readonly ThinLevel[] = [
  SBOM_ROW_THIN,
  { keep: SBOM_ROW_THIN, capped: "matches", least: SBOM_LEAVING_CAP, floor: matchFloor, pick: pickMatches, mark: (row, cap) => matchesTruncated(row, cap, true), said: cappedSaid },
  { keep: SBOM_ROW_COMPACT, capped: "matches", least: SBOM_LEAVING_CAP, floor: matchFloor, pick: pickMatches, mark: (row, cap) => matchesTruncated(row, cap, true), said: cappedSaid, below: belowSaid },
  { keep: SBOM_ROW_MIN, mark: (row) => matchesTruncated(row, 0, true), said: () => `a row that had matches ${MATCHES_TRUNCATED_SAID}` },
  { keep: SBOM_ROW_MIN, mark: (row) => matchesTruncated(row, 0, false), said: () => "a row that had matches carrying matches_truncated with its total and returned 0" },
];
// #3269's second review: rows leave at the compact level at their floor (`floor`: levels 4 and 5
// are not taken while a row other than a not_affected or not_assessed one has matches), and of
// those rows, the ones with a KEV-listed or ransomware match last (SBOM_LEAVE_LAST).
const SBOM_LEAVE_AT = { level: 2, cap: SBOM_LEAVING_CAP, floor: true as const };
const hasKev = (row: unknown): boolean => {
  const ms = field(row, "matches");
  return Array.isArray(ms) && ms.some((m) => field(m, "ransomware") === true || field(m, "kev_listed") === true);
};
export const SBOM_LEAVE_LAST: LeaveLast = {
  has: hasKev,
  said: "a KEV-listed or ransomware match",
  id: "index",
  rest: ["affected or undetermined row", "affected or undetermined rows"],
  chosen: "kept: rows with one first, then the others, in input order, each that fits",
};
// #3269's third review: the most check_sbom calls the prompts make to check again the rows a DATA
// CUT left out (prompts.ts workload_triage's step 6 and sbom_review), and so the calls whose sizes
// the note gives one by one.
export const RECHECK_CALLS = 5;
// check_sbom's sentence on checking again the affected and undetermined rows that left data, in
// the order the note names them (those with a KEV-listed or ransomware match first): the sizes of
// the first RECHECK_CALLS calls, each the most of the rest that fits, then at most `m` a call
// (textBudget.ts PageAt.againFit, counted for those rows, where the page sentence's N holds for
// the first N purls of the call only: re-check calls of N dropped 504 of 2,540 rows on realistic
// Debian images). One size for every call, any m in a row (the review's "calls of at most M"),
// put 201 of 255 KEV-bearing rows of six old unpatched images in view after 5 calls, and the best
// single size, found by real calls, 224, against 228 for round 3's step 6 on the same images with
// their KEV-bearing purls sent first; the first-fit sizes put 238. A row whose floor alone is past
// the budget goes in a call of its own, which keeps it under its floor.
export const sbomAgainSaid = ({ k, sizes, m, alone, aloneCount }: Again): string => {
  const own =
    aloneCount === 0
      ? ""
      : `${aloneCount === 1 ? `The purl at index ${alone} goes` : `Each of the purls at index ${alone} goes`} in a call of its own: its row's matches used in ransomware or KEV-listed and ${SBOM_LEAVING_CAP} more are past the budget even alone, so that call keeps the row with the most of them that fit, and its note says how many.`;
  if (aloneCount === k) return own;
  const these = aloneCount === 0 ? `these ${k} purls` : `the other ${k - aloneCount} of these purls`;
  const calls =
    sizes.length === 1 && m === 0
      ? `Re-check ${these} in one call: it keeps every row in data.`
      : `Re-check ${these} in this order, in calls of ${listedAnd(sizes.map(String))}${m > 0 ? `, then of at most ${m}` : ""}: each such call keeps every row in data.`;
  return own ? `${calls} ${own}` : calls;
};
const listedAnd = (xs: readonly string[]): string => (xs.length < 2 ? xs.join("") : `${xs.slice(0, -1).join(", ")} and ${xs[xs.length - 1]}`);
// #3269's review: the floor of matches an affected row keeps, once the rows must be capped anyway,
// before a clean or not-assessed row leaves for it: every match used in ransomware or KEV-listed,
// and SBOM_LEAVING_CAP more, the highest effective_score (pickMatches keeps them, at a cap of this
// many). SBOM_LEAVING_CAP because it is what the ladder already gives a row when rows leave
// (SBOM_LEAVE_AT): a clean row stays at SBOM_ROW_MIN while every affected row can keep at least
// that, and its KEV-listed matches beside it. Round 1 had no floor: once a row had to be capped, the
// clean rows left so that the cap could rise, and came back only into the room the cap left.
// linux-libc-dev 6.1.55-1 (200 matches) with 100 clean Debian purls kept 1 row of 101, and the page
// sentence said "check 1 or fewer purls per call": 101 calls to read 100 not_affected verdicts.
export function matchFloor(row: unknown): number {
  const ms = field(row, "matches");
  if (!Array.isArray(ms)) return 0;
  const kev = ms.filter((m) => field(m, "ransomware") === true || field(m, "kev_listed") === true).length;
  return Math.min(ms.length, kev + SBOM_LEAVING_CAP);
}
// #3269: the clean and not-assessed rows are cut to SBOM_ROW_MIN, then leave, before any other row
// is cut to SBOM_ROW_LEVELS[1] (its matches capped); see SBOM_ROW_COMPACT's comment. #3269's
// review: where the other rows must be capped even with every one of them gone, they stay while the
// others fit at matchFloor, at SBOM_ROW_LEVELS[1] or [2] (textBudget.ts OutFirst.floor).
const SBOM_OUT_FIRST = { before: 1, level: SBOM_ROW_MIN, floor: { at: 2 } };
// The page sentence (#3132): never "0 or fewer". #3269's review: the number it names is what a
// call of the first that many purls keeps whole (PageAt.firstFit), not the number of rows this
// call's data kept. Round 1 named the rows kept, and the clean rows that leave first made that
// false: Juice Shop 11.1.2 with magento/community-edition 2.3.0 said "check 19 or fewer purls per
// call", and a call of its first 19 purls kept 14 of them (and one of 14 kept 12). firstFit counts
// every first n' up to the number it names, so "or fewer" holds too; a later page is not this
// call's, so its own note says what its data leaves out. When not one row fits, no page size does,
// and the note says where a row is read instead.
// #3132's review: the lists beside the rows go first, scan_manifest's not_checked before
// not_sent_purls, which keeps every purl or none (whole): those purls are the list a client
// retries, and round 1 kept 3 of the rate-limited case's 800. With none kept, the note gives them
// exactly as positions in the input (sendingSentences: coverage.sent + 1 to
// coverage.distinct_purls), and the room the rows leave goes back to not_sent_purls before
// not_checked.
// #3269's third review: `again`, check_sbom's sentence on checking the left-out rows again
// (sbomAgainSaid), with the note's own growth for such a call (match_batch.ts affectedSaidOver);
// scan_manifest's rows are checked again through check_sbom, by purls its note does not give, so it
// names none.
export function sbomData(sides: readonly string[], page: (kept: number) => string, again?: LeaveLast["again"]): DataCut {
  const others = sides.filter((x) => x !== "not_sent_purls");
  const leaveLast: LeaveLast = again ? { ...SBOM_LEAVE_LAST, again, againCalls: RECHECK_CALLS, noteOver: affectedSaidOver } : SBOM_LEAVE_LAST;
  return {
    steps: [
      ...(others.length ? [{ lists: others }] : []),
      ...(sides.includes("not_sent_purls") ? [{ lists: ["not_sent_purls"], whole: true as const }] : []),
      {
        lists: ["results"],
        thin: SBOM_ROW_LEVELS,
        leaveOutFirst: { field: "verdict", values: ["not_affected", "not_assessed"], why: "data.summary counts every verdict" },
        leaveLast,
        outFirst: SBOM_OUT_FIRST,
        leaveAt: SBOM_LEAVE_AT,
        giveBack: true,
      },
    ],
    page: (t, _data, at) => {
      if (!t.results || t.results.returned >= t.results.total) return "";
      if (t.results.returned === 0)
        return `Not one row fits data even cut to ${SBOM_ROW_MIN.join(", ")}, so no number of purls per call does: the same call with full: true returns every row whole.`;
      const k = at.firstFit("results");
      return k > 0 ? page(k) : "Not even a call of the first of these purls is sure to keep its row in data: the same call with full: true returns every row whole.";
    },
  };
}
// #3269's second review: the sentence promises only what holds. Its round-2 opening, "To read every
// row in data, check N or fewer purls per call", read as "page the SBOM in calls of N", and a call
// of a later N purls need not keep every row (it lost rows in 55% of the paged mixes).
export const sbomPageSaid = (k: number): string =>
  `A call of the first ${k} of these purls, or of fewer, keeps every row in data; a call of other purls says in its own note what it leaves out.`;
const SBOM_DATA = sbomData(["not_sent_purls"], sbomPageSaid, sbomAgainSaid);

// ── Reading the input ──

export type Extracted = {
  input: "purls" | "cyclonedx" | "spdx";
  // Components (CycloneDX) or packages (SPDX) in the document; null for a plain purl list.
  components_in_document: number | null;
  with_purl: number;
  without_purl: number;
  duplicates_removed: number;
  purls: string[];
};

// The purls of a CycloneDX JSON document: every components[] entry, nested ones included.
// metadata.component (the subject of the SBOM, not a dependency of it) is not checked.
function fromCycloneDX(doc: Record<string, unknown>): Extracted | string {
  if (doc.components !== undefined && !Array.isArray(doc.components)) return "its components is not an array";
  let total = 0;
  let without = 0;
  const found: string[] = [];
  const walk = (cs: unknown, depth: number): string | null => {
    if (!Array.isArray(cs)) return null;
    if (depth > MAX_DEPTH) return `its components nest deeper than ${MAX_DEPTH} levels`;
    for (const c of cs) {
      if (!isObj(c)) continue;
      total++;
      const p = typeof c.purl === "string" ? c.purl.trim() : "";
      if (p) found.push(p);
      else without++;
      const err = walk(c.components, depth + 1);
      if (err) return err;
    }
    return null;
  };
  const err = walk(doc.components, 0);
  if (err) return err;
  const { purls, removed } = dedupe(found);
  return { input: "cyclonedx", components_in_document: total, with_purl: found.length, without_purl: without, duplicates_removed: removed, purls };
}

// The purls of an SPDX JSON document: each package's externalRefs entry of referenceType purl
// (referenceCategory PACKAGE-MANAGER, spelled PACKAGE_MANAGER by some tools; the type decides).
function fromSPDX(doc: Record<string, unknown>): Extracted | string {
  if (doc.packages !== undefined && !Array.isArray(doc.packages)) return "its packages is not an array";
  const pkgs = Array.isArray(doc.packages) ? doc.packages : [];
  let total = 0;
  let without = 0;
  const found: string[] = [];
  for (const p of pkgs) {
    if (!isObj(p)) continue;
    total++;
    const refs = Array.isArray(p.externalRefs) ? p.externalRefs : [];
    const ref = refs.find((r) => isObj(r) && typeof r.referenceType === "string" && r.referenceType.toLowerCase() === "purl" && typeof r.referenceLocator === "string" && r.referenceLocator.trim());
    if (ref && isObj(ref)) found.push(String(ref.referenceLocator).trim());
    else without++;
  }
  const { purls, removed } = dedupe(found);
  return { input: "spdx", components_in_document: total, with_purl: found.length, without_purl: without, duplicates_removed: removed, purls };
}

// Reads the tool's arguments into the purls to send, or says why it cannot.
export function extract(a: { purls?: unknown; sbom?: unknown }): Extracted | string {
  const hasPurls = a.purls !== undefined;
  const hasSbom = a.sbom !== undefined;
  if (hasPurls === hasSbom) return "pass exactly one of purls (a list of package URLs) or sbom (a CycloneDX JSON or SPDX JSON document)";
  if (hasPurls) {
    if (!Array.isArray(a.purls) || a.purls.some((p) => typeof p !== "string")) return "purls must be a list of strings";
    const trimmed = (a.purls as string[]).map((p) => p.trim()).filter(Boolean);
    const { purls, removed } = dedupe(trimmed);
    return { input: "purls", components_in_document: null, with_purl: trimmed.length, without_purl: (a.purls as string[]).length - trimmed.length, duplicates_removed: removed, purls };
  }
  let doc: unknown = a.sbom;
  if (typeof doc === "string") {
    if (doc.length > MAX_SBOM_CHARS) return `sbom is ${doc.length} characters; at most ${MAX_SBOM_CHARS} are read`;
    try {
      doc = JSON.parse(doc);
    } catch {
      return "sbom is not JSON: pass a CycloneDX JSON or SPDX JSON document (XML and SPDX tag-value are not read)";
    }
  } else {
    let size = 0;
    try {
      size = JSON.stringify(doc)?.length ?? 0;
    } catch {
      return "sbom could not be serialised as JSON";
    }
    if (size > MAX_SBOM_CHARS) return `sbom is ${size} characters as JSON; at most ${MAX_SBOM_CHARS} are read`;
  }
  if (!isObj(doc)) return "sbom must be a JSON object: a CycloneDX JSON or SPDX JSON document";
  if (typeof doc.bomFormat === "string" && doc.bomFormat.toLowerCase() === "cyclonedx") {
    const r = fromCycloneDX(doc);
    return typeof r === "string" ? `the CycloneDX document cannot be read: ${r}` : r;
  }
  if (typeof doc.spdxVersion === "string" && doc.spdxVersion.toUpperCase().startsWith("SPDX-")) {
    const r = fromSPDX(doc);
    return typeof r === "string" ? `the SPDX document cannot be read: ${r}` : r;
  }
  return 'sbom is neither a CycloneDX JSON document (bomFormat "CycloneDX") nor an SPDX JSON document (spdxVersion "SPDX-…")';
}

// ── The answer ──

function noteFor(head: string, x: Extracted, d: object, g: Sending): { note: string; assessed: number } {
  const out: string[] = [head];

  if (x.input === "purls") {
    out.push(`Sent ${plural(g.sent, "purl", "purls")}${x.duplicates_removed ? ` (${plural(x.duplicates_removed, "duplicate was", "duplicates were")} sent once)` : ""}.`);
  } else {
    const kind = x.input === "cyclonedx" ? "CycloneDX" : "SPDX";
    const unit = x.input === "cyclonedx" ? "component" : "package";
    out.push(
      `Read ${plural(x.components_in_document ?? 0, unit, `${unit}s`)} from the ${kind} document: ${x.with_purl} with a purl${x.without_purl ? `, and ${x.without_purl} without one, which ${x.without_purl === 1 ? "was" : "were"} not checked and ${x.without_purl === 1 ? "is" : "are"} not clean` : ""}${x.duplicates_removed ? `; ${plural(x.duplicates_removed, "duplicate purl was", "duplicate purls were")} sent once` : ""}; sent ${g.sent}.`,
    );
  }
  // The batches, the waits and the purls not sent, at their position in READ_ORDER (#2799).
  out.push(...sendingSentences(g, x.purls.length, READ_ORDER, "check_sbom again with purls set to"));
  const v = verdictSentences(d, g);
  out.push(...v.sentences);
  return { note: out.join(" "), assessed: v.assessed };
}

export async function checkSbom<F extends FailureLike>(deps: CheckSbomDeps<F>, a: { purls?: unknown; sbom?: unknown }): Promise<ToolResult> {
  const tool = CHECK_SBOM;
  try {
    const x = extract(a);
    if (typeof x === "string") return deps.badInput(tool, x);
    if (x.purls.length === 0) {
      return deps.badInput(tool, x.input === "purls" ? "purls holds no package URL" : `the document holds ${x.components_in_document ?? 0} components and none carries a purl, so there is nothing to check`);
    }
    const refused = purlsRefusal(x.purls, `split the list into calls of ${MAX_PURLS} or fewer`);
    if (refused) return deps.badInput(tool, refused);

    // match_batch.ts: one batch at a time, Retry-After waited out within the budget (#2734,
    // #2756), stopped on cancellation (#2775).
    const run = await sendBatches(deps, tool, x.purls);
    if (!run.ok) return run.result;
    const { data, status, sending: g } = run;
    const { note, assessed } = noteFor(deps.okHead(tool, status), x, data, g);
    return deps.succeeded(data, note, {
      state: assessed > 0 ? "measured" : "not_assessed",
      measured_at: null,
      method: METHOD,
      coverage: {
        input: x.input,
        components_in_document: x.components_in_document,
        with_purl: x.with_purl,
        without_purl: x.without_purl,
        duplicates_removed: x.duplicates_removed,
        ...sendingCoverage(g, x.purls.length, field(data, "summary")),
      },
      freshness: null,
      notes: [DISTRO_NOTE, CLEAN_NOTE, MEASURED_AT_NOTE, FRESHNESS_NOTE],
    }, sbomText(g.sent));
  } catch (e) {
    return deps.crashed(tool, e);
  }
}

// ── Schemas ──

export function checkSbomOutput(envelopeSchema: CheckSbomDeps<FailureLike>["envelopeSchema"]): z.ZodType {
  return envelopeSchema({
    // match_batch.ts batchDataShape: the batch route's answer, merged over the batches.
    data: z.looseObject(batchDataShape),
    coverage: z.strictObject({
      input: z.enum(["purls", "cyclonedx", "spdx"]).describe("What was passed: a purl list, a CycloneDX JSON document or an SPDX JSON document."),
      components_in_document: z.number().int().nullable().describe("Components (CycloneDX) or packages (SPDX) in the document; null for a purl list."),
      with_purl: z.number().int().describe("Of those, the ones carrying a purl."),
      without_purl: z.number().int().describe("The ones without a purl: not checked, and not clean."),
      duplicates_removed: z.number().int().describe("Purls that appeared more than once and were sent once."),
      ...sendingCoverageShape,
    }),
    freshness: null,
  });
}

// One output schema per process, not per request (3.0.2; index.ts envelopeSchema says why).
const OUTPUTS = new WeakMap<object, z.ZodType>();
// A literal server.registerTool(name, { title, description, … }) call with constant strings:
// marketing-site lib/mcpToolClaims.test.ts reads it here (it follows index.ts's call to this
// function) and holds the /pulse/mcp row to this title and description.
export function registerCheckSbom<F extends FailureLike>(server: McpServer, deps: CheckSbomDeps<F>): void {
  const envelope = deps.envelopeSchema as CheckSbomDeps<FailureLike>["envelopeSchema"];
  const output = OUTPUTS.get(envelope) ?? checkSbomOutput(envelope);
  OUTPUTS.set(envelope, output);
  server.registerTool(
    CHECK_SBOM,
    {
      title: CHECK_SBOM_TITLE,
      description: CHECK_SBOM_DESCRIPTION,
      inputSchema: z.object({
        // #3345: bounded before any element is parsed (inputBounds.ts): MAX_PURL_ENTRIES entries,
        // repeats included (the MAX_PURLS distinct a call checks is checkSbom's own rule, above),
        // and an object document's top level to MAX_SBOM_MEMBERS.
        purls: z
          .array(z.string())
          .max(MAX_PURL_ENTRIES)
          .optional()
          .describe(
            "package URLs to check, e.g. pkg:npm/lodash@4.17.20 or pkg:deb/debian/openssl@3.0.11-1~deb12u1?distro=debian-12 (up to 2,000 distinct, sent in batches of 200), in a list of at most 10,000 entries, repeats included",
          ),
        sbom: z
          .union([z.string(), boundedRecord(z.unknown(), MAX_SBOM_MEMBERS)])
          .optional()
          .describe(
            "a CycloneDX JSON or SPDX JSON document, as JSON text or as an object; its purls are read by this MCP server and only they are sent to the API; over the hosted endpoint (mcp.echelongraph.io) the document is the request body",
          ),
        full: FULL_ARG,
      }),
      outputSchema: output as z.ZodObject,
      annotations: deps.annotations,
    },
    async (a: { purls?: string[]; sbom?: unknown; full?: boolean }, ctx: { mcpReq: { signal: AbortSignal } }) =>
      answering(a.full, SBOM_DATA, async () => {
        const run = checkSbom({ ...deps, signal: ctx.mcpReq.signal }, a);
        return deps.checked(CHECK_SBOM, output, await (deps.hold ? deps.hold(run) : run)) as never;
      }),
  );
}
