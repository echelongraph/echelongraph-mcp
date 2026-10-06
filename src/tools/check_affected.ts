// check_affected (#2716): "am I affected by product X at version Y?", answered by the same
// endpoint as echelongraph.io/am-i-affected, GET /api/v1/public/cves/match (core-backend
// internal/cve/handler.go MatchByProductPublic). Two lookup paths, chosen by the input:
//
//   cpe       {product, version}: the CPE matcher (matchByProductPublic). CVEs whose NVD CPE
//             product field is this token and whose version range includes this version. It
//             matches the product token across vendors; each match names the vendor NVD asserts
//             (cpe_vendor) and whether that vendor was verified (vendor_unknown).
//   registry  {ecosystem, package, version}: the registry matcher (matchByPackage). The OSV
//             advisory records EchelonGraph holds for this package, each decided against this
//             version as affected, not affected, or undetermined.
//
// #1983: every typed value travels in a request header (X-EG-Product, X-EG-Version,
// X-EG-Ecosystem, X-EG-Package; handler.go MatchProductHeader..MatchPackageHeader), percent-
// encoded as the backend's publicMatchParam decodes it, and never in the URL: Cloud Run's request
// log and its trace spans record the URL and no request header. The backend answers a
// header-carried lookup with Cache-Control: private, no-store and varies on the four headers. The
// endpoint reads the CPE vendor from the query string only (handler.go matchByProductPublic), so
// this tool takes no vendor: sending one would put a typed value in the URL.
//
// The verdict is `assessed`, read BEFORE `count` (the endpoint's own contract): assessed false
// means the lookup did not evaluate this component, and count 0 then asserts nothing. So the
// envelope's state is measured only when the answer says assessed true; assessed false, or an
// answer without assessed, is not_assessed, and the note's first sentence after the head says so,
// with the reason. A 500/503 (advisory_lookup_failed) is a failure like any other non-2xx.
//
// The JSON is relayed verbatim as data (#1874): every match keeps kev_listed, ransomware,
// epss_score, effective_score, effective_severity and score_assessed as the API sent them.
import * as z from "zod";
import type { McpServer } from "@modelcontextprotocol/server";
import { GET_CVE_WHOLE, TEXT_BUDGET_DESCRIPTION, type TextCut } from "../textBudget.js";

// What this file needs from index.ts, passed in so it imports nothing from a module that starts
// the stdio server when loaded.
type Text = { type: "text"; text: string };
type ToolResult = { content: Text[]; structuredContent: Record<string, unknown>; isError?: boolean };
type Failure = { ok: false; kind: "network" | "timeout" | "http" | "not_json" | "not_object" | "unexpected_shape"; path: string; status?: number; detail: string };
type ApiResult = { ok: true; status: number; data: object } | Failure;
type Env = {
  state: "measured" | "not_assessed";
  measured_at: string | null;
  method: string | null;
  coverage: Record<string, unknown> | null;
  freshness: Record<string, unknown> | null;
  notes?: string[];
};
export type CheckAffectedKit = {
  api: (path: string, init?: { headers?: Record<string, string>; method?: string; body?: string }) => Promise<ApiResult>;
  succeeded: (data: object, note: string, env: Env, cut?: TextCut) => ToolResult;
  failed: (tool: string, f: Failure) => ToolResult;
  badInput: (tool: string, why: string) => ToolResult;
  crashed: (tool: string, e: unknown) => ToolResult;
  checked: (tool: string, schema: z.ZodType, r: ToolResult) => ToolResult;
  okHead: (tool: string, status?: number) => string;
  envelopeSchema: (o: { data: z.ZodType; coverage: z.ZodType | null; freshness: z.ZodType | null }) => z.ZodType;
  annotations: Record<string, boolean>;
};

const TOOL = "check_affected";
export const MATCH_PATH = "/api/v1/public/cves/match";
// handler.go, the four request headers the endpoint reads before the query string.
export const MATCH_HEADERS = { product: "X-EG-Product", version: "X-EG-Version", ecosystem: "X-EG-Ecosystem", package: "X-EG-Package" } as const;

const CPE_METHOD =
  "EchelonGraph's CPE matcher over its CVE corpus, the matcher behind echelongraph.io/am-i-affected and EchelonGraph's scanner: CVEs whose NVD CPE match criteria name this product token and whose version range includes this version.";
const REGISTRY_METHOD =
  "EchelonGraph's registry matcher, the matcher behind echelongraph.io/am-i-affected for a registry package: the OSV advisory records EchelonGraph holds for this package in this ecosystem, each decided against this version as affected, not affected, or undetermined.";
const NO_TIME = "measured_at is null: a match answer carries no observation time, and each matched CVE is a record of the CVE feed, polled from its sources on a schedule.";
const NO_FRESHNESS = "freshness is null: the match answer carries no time at which the feed's pollers last completed.";

// Why an answer says assessed false (core-backend cve/cpematch.go, cve/pkgmatch.go). One sentence
// each, worded so that none reads as a clean result.
const REASONS: Record<string, string> = {
  product_not_in_cpe_corpus:
    "no CVE in the CPE corpus has this token as its CPE product, so the component was not located, not cleared; the CPE product token can differ from a package name (spring_boot, not spring-boot), and a registry package can be looked up by ecosystem and package instead.",
  package_not_cpe_nameable:
    "the CVEs the CPE corpus holds for this token describe it in a way the CPE lookup cannot decide for this asset (an npm package NVD records only for target_sw node.js is the common case), so a registry lookup by ecosystem and package is the one to use.",
  candidate_load_pending:
    "the product's candidate CVEs were still loading when this request's time ran out (degraded), so nothing was compared; the same lookup can be retried shortly.",
  candidate_window_truncated:
    "the product has more candidate CVEs than one lookup loads (candidates_capped), so the CVEs below the cut were never examined.",
  package_not_in_advisory_corpus:
    "EchelonGraph holds no advisory record for this package in this ecosystem, so the package was not located, not cleared; the ecosystem and package name are worth checking.",
  no_decidable_advisory:
    "EchelonGraph holds advisories for this package, but not one of them could be decided either way at this version (see undetermined).",
  advisory_lookup_failed: "the advisory lookup failed.",
};

// The reasons this version describes, and any other string, which the note names as one it does not.
const REASON = z.union([z.enum(Object.keys(REASONS) as [string, ...string[]]), z.string()]).describe("Why assessed is false; empty or absent when it is true.");
const opt = <T extends z.ZodType>(t: T) => t.nullable().optional();
const Match = z.looseObject({
  cve_id: opt(z.string()),
  description: opt(z.string()),
  severity: opt(z.string()).describe("NVD's own CVSS v3 band, as provenance: it can be NONE for a CVE NVD rated only under CVSS v2. Rank and display on effective_severity."),
  cvss_v3_score: opt(z.number()),
  cvss_v2_score: opt(z.number()),
  cvss_v4_score: opt(z.number()),
  kev_listed: opt(z.boolean()).describe("Listed in CISA-KEV: known to be exploited."),
  ransomware: opt(z.boolean()).describe("CISA-KEV records known use in ransomware campaigns."),
  epss_score: opt(z.number()).describe("EPSS exploitation probability, 0 to 1."),
  echelongraph_score: opt(z.number()).describe("EchelonGraph's 0-10 score: present only when score_assessed is true."),
  echelongraph_severity: opt(z.string()),
  effective_score: opt(z.number()).describe("The best real score held for the CVE (EchelonGraph's, else CVSS), the number the matches are ranked by."),
  effective_severity: opt(z.string()).describe("The band of effective_score; absent or empty when the CVE has no band at all (unrated, not harmless)."),
  score_assessed: opt(z.boolean()).describe("Whether EchelonGraph has scored the CVE. false: NOT YET SCORED, and echelongraph_score is withheld."),
  score_unassessed_reason: opt(z.string()),
  vendor_severity: opt(z.string()),
  matched_criteria: opt(z.string()),
  match_method: opt(z.string()),
  match_confidence: opt(z.number()),
  cpe_vendor: opt(z.string()).describe("The vendor NVD's CPE asserts for this match."),
  vendor_unknown: opt(z.boolean()).describe("true: the vendor was not verified, so the match is real but its attribution to your vendor is not."),
  match_reason: opt(z.string()),
  version_evidence: opt(z.string()),
  // #2834: registry matches only (core-backend cve/pkgmatch_fixedin.go registryFixedIn).
  interval: opt(
    z.looseObject({ introduced: opt(z.string()), fixed: opt(z.string()), last_affected: opt(z.string()) }),
  ).describe("Registry match: the advisory interval that holds this version (fixed is exclusive, last_affected inclusive); absent when no interval holds it."),
  fixed_in: opt(z.string()).describe(
    "Registry match: the fixed bound of the advisory interval that holds this version, always above it. null when that interval records no fix (it ends at last_affected, or has no end) or no interval holds the version, with fixed_in_reason saying which. Absent on a CPE match.",
  ),
  fixed_in_reason: opt(z.string()).describe("Why fixed_in is null; absent when fixed_in is a version."),
});
const Undetermined = z.looseObject({
  cve_id: opt(z.string()),
  package: opt(z.string()),
  ecosystem: opt(z.string()),
  reason: opt(z.string()),
  detail: opt(z.string()),
});
const DATA = z.looseObject({
  product: opt(z.string()),
  version: opt(z.string()),
  vendor: opt(z.string()),
  ecosystem: opt(z.string()),
  ecosystem_recognised: opt(z.boolean()),
  package: opt(z.string()),
  assessed: opt(z.boolean()).describe("count depends on it. true: the lookup evaluated this component. false: it did not, and count 0 says nothing about whether this version is affected."),
  not_assessed_reason: opt(REASON),
  match_layer: opt(z.string()).describe("Which lookup path answered."),
  cve_ids: opt(z.array(z.string())),
  matches: opt(z.array(Match)),
  count: opt(z.number()),
  capped: opt(z.boolean()).describe("true: the match list stopped at its cap."),
  candidates_capped: opt(z.boolean()).describe("true: not every candidate CVE was loaded."),
  candidate_count: opt(z.number()),
  advisories_considered: opt(z.number()),
  excluded_count: opt(z.number()).describe("CPE candidates suppressed by the vendor or platform gate."),
  excluded: z.unknown().optional(),
  undetermined_count: opt(z.number()),
  undetermined: opt(z.array(Undetermined)),
  not_affected_count: opt(z.number()).describe("Advisories decided as not affecting this version."),
  degraded: opt(z.boolean()).describe("true: the lookup ran out of time."),
  undecidable_excluded_count: opt(z.number()),
  undecided_candidate_count: opt(z.number()),
  product_named_count: opt(z.number()),
  vendor_advisory_count: opt(z.number()),
});
const COVERAGE = z.strictObject({
  assessed: z.boolean().nullable().describe("The answer's assessed, first: null when the answer does not say."),
  not_assessed_reason: REASON.nullable(),
  lookup: z.enum(["cpe", "registry"]).describe("Which lookup path this call asked for."),
  match_layer: z.string().nullable(),
  count: z.number().nullable(),
  capped: z.boolean().nullable(),
  candidates_capped: z.boolean().nullable(),
  excluded_count: z.number().nullable(),
  undetermined_count: z.number().nullable(),
  not_affected_count: z.number().nullable(),
  degraded: z.boolean().nullable(),
});

// Constant strings, so marketing-site lib/mcpToolClaims.test.ts can fold them should it read
// this file.
export const CHECK_AFFECTED_TITLE = "Am I affected? (product or package at a version)";
export const CHECK_AFFECTED_DESCRIPTION =
  "Whether a product or package at a given version is affected by known CVEs, from the same matcher as echelongraph.io/am-i-affected. The CPE path takes product (an NVD CPE product token, such as openssl or nginx) and version, and returns the CVEs whose NVD CPE match criteria include that product at that version; each match names the vendor NVD asserts (cpe_vendor) and whether it was verified (vendor_unknown). The registry path takes ecosystem (npm, PyPI, Maven and other OSV ecosystem names), package and version, and decides each OSV advisory EchelonGraph holds for that package as affected, not affected or undetermined. count depends on assessed: assessed false means the lookup did not evaluate this component, not_assessed_reason says why, and a count of 0 there is not a finding of not affected. An advisory undecidable at this version is reported as undetermined (undetermined_count, and up to 50 of them in undetermined), never as safe. Each match carries cve_id, kev_listed, ransomware, epss_score, effective_score, effective_severity and score_assessed (false: not yet scored, so echelongraph_score is withheld). A registry match also carries interval, the advisory interval holding this version, and fixed_in, its fixed bound, or null with fixed_in_reason; a CPE match carries no fixed_in. All four inputs travel in request headers, never in the URL." +
  " " +
  TEXT_BUDGET_DESCRIPTION +
  " Cut, the excluded and undetermined samples keep their first 10 entries, each its cve_id and reason, cve_ids keeps its first 10, and each match keeps cve_id, kev_listed, ransomware, epss_score, effective_score, score_assessed and fixed_in at least. Every CPE match stays in the text; near the cap, a registry list's last matches can leave it, and the note says how many.";

export const CHECK_AFFECTED_INPUT = z.object({
  product: z.string().optional().describe("CPE path: the NVD CPE product token, such as openssl, nginx or linux_kernel. Leave out for the registry path."),
  ecosystem: z.string().optional().describe("Registry path: the package's ecosystem, such as npm, PyPI or Maven. Give with package, not with product."),
  package: z.string().optional().describe("Registry path: the package name in that ecosystem, such as lodash."),
  version: z.string().describe("The version to check, such as 3.0.0."),
});
type Args = z.infer<typeof CHECK_AFFECTED_INPUT>;

const field = (o: unknown, k: string): unknown => (o !== null && typeof o === "object" ? (o as Record<string, unknown>)[k] : undefined);
const num = (o: unknown, k: string): number | null => {
  const v = field(o, k);
  return typeof v === "number" && Number.isFinite(v) ? v : null;
};
const bool = (o: unknown, k: string): boolean | null => {
  const v = field(o, k);
  return typeof v === "boolean" ? v : null;
};
const str = (o: unknown, k: string): string | null => {
  const v = field(o, k);
  return typeof v === "string" && v ? v : null;
};
const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

// The sentences about the matches themselves: how many are KEV-listed, and which are not scored.
function matchesNote(matches: unknown[]): string {
  const kev = matches.filter((m) => field(m, "kev_listed") === true).length;
  const ransomware = matches.filter((m) => field(m, "ransomware") === true).length;
  const unscored = matches.filter((m) => field(m, "score_assessed") === false).map((m, i) => str(m, "cve_id") ?? `matches[${i}]`);
  const unverified = matches.filter((m) => field(m, "vendor_unknown") === true).length;
  let out = "";
  if (unverified > 0) {
    out += ` ${unverified === matches.length ? "Every match has" : `${plural(unverified, "match has", "matches have")}`} vendor_unknown true: matched on the product name, so the vendor NVD asserts (cpe_vendor) is not verified to be the one you run.`;
  }
  if (kev > 0) out += ` ${plural(kev, "of them is", "of them are")} listed in CISA-KEV (kev_listed)${ransomware > 0 ? `, ${ransomware} with known ransomware use` : ""}.`;
  if (unscored.length > 0) {
    const shown = unscored.slice(0, 10).join(", ");
    out += ` NOT YET SCORED (score_assessed: false): ${shown}${unscored.length > 10 ? ` and ${unscored.length - 10} more` : ""}; EchelonGraph has not scored ${unscored.length === 1 ? "it" : "them"}, so an effective_score of zero or an empty effective_severity there means unrated, not harmless.`;
  }
  return out;
}

// #2834: what the registry matches say about a fix. fixed_in is the fixed bound of the interval
// that holds this version (core-backend cve/pkgmatch_fixedin.go), so it is per match: an advisory
// with several branches (Log4Shell: 2.3.1, 2.12.2, 2.15.0) names the one for this version.
function fixedInNote(matches: unknown[]): string {
  const registry = matches.filter((m) => m !== null && typeof m === "object" && "fixed_in" in (m as object));
  if (registry.length === 0) return "";
  const fixed = registry.filter((m) => typeof field(m, "fixed_in") === "string").length;
  const none = registry.length - fixed;
  return ` fixed_in, the fixed bound of the advisory interval that holds this version: ${fixed === registry.length ? `set on every match` : `set on ${fixed} of ${registry.length} matches`}${none > 0 ? `; null on ${none}, where the advisory records no fix for this version (fixed_in_reason says why)` : ""}.`;
}

// #2783: a production match is about 2,100 characters as pretty JSON, most of it the CVE's
// description and match_reason, so openssl 3.0.0 (71 matches) was 156,058 characters of text and
// linux_kernel 5.10.0 (200, the API's cap) 364,408. Past DATA_TEXT_BUDGET each match in the first
// text block keeps its scores, flags, vendor attribution and match_reason (for a registry match,
// the advisory interval its version falls inside: "[A, B)" names the fixed version B, "[A, B]" the
// last affected one, #2830) with the
// description cut to 200 characters; then the same without the description; then only the fields
// the description promises; then, for a list at the cap, without cpe_vendor and vendor_unknown;
// and last without effective_severity, the band of effective_score. kev_listed, ransomware,
// epss_score, effective_score and score_assessed stay in every level (#2799): the am_i_affected
// prompt asks for each match's ransomware and epss_score, and through 2.6.3 the last level left
// them out of every match of a list at the cap (hosted linux_kernel 5.10.0, 200 matches, 1 with
// known ransomware use, named nowhere in the text). 200 matches with effective_severity beside
// them are 33,240 characters, past the budget alone, so the band goes first. The lists beside the
// matches, the excluded sample (up to 50 CPE candidates the vendor or platform gate suppressed,
// each with a sentence of detail, 13,861 characters for flash_player 10.0.0) and the undetermined
// sample (up to 50), keep their first 10 entries, each its cve_id and reason, once the first level
// does not fit with them whole, before any match field that level keeps goes (50 of them beside
// 200 matches left the last level 120 characters past the budget for flash_player 10.0.0, and
// 1,071 for a registry answer at the cap with 50 undetermined); and the registry path's cve_ids,
// which is each match's cve_id in the order of matches (core-backend cve/handler.go), keeps its
// first 10, so that every CPE match stays in the text, 200 at the cap: this tool has no page to
// read more from. A registry list at the cap does not fit even so (#2834): fixed_in, which every
// level keeps, costs about 20 characters a match, and the last level's rows alone, 200 of them at
// about 155 characters each, are some 31,000 characters, past the budget before anything beside
// them. At 200 django matches carrying fixed_in, fixed_in_reason and interval, beside 50
// undetermined, the text keeps 185 (29,863 characters, 2026-10-05), and the last 15 in order, the
// lowest ranked, are in structuredContent.data only; the description says so, and the note names
// how many. No field of the last level can go: the description and the am_i_affected prompt read
// each of them per match. excluded_count and undetermined_count count every entry.
// structuredContent.data keeps every list whole.
const CHECK_AFFECTED_TEXT: TextCut = {
  rows: "matches",
  levels: [
    {
      keep: [
        "cve_id", "severity", "cvss_v3_score", "description", "kev_listed", "ransomware", "epss_score", "echelongraph_score", "echelongraph_severity", "effective_score", "effective_severity",
        "score_assessed", "score_unassessed_reason", "matched_criteria", "cpe_vendor", "vendor_unknown", "match_confidence", "match_reason", "version_evidence", "fixed_in",
        "fixed_in_reason",
      ],
      clip: 200,
    },
    {
      keep: [
        "cve_id", "severity", "cvss_v3_score", "kev_listed", "ransomware", "epss_score", "echelongraph_score", "effective_score", "effective_severity", "score_assessed", "matched_criteria",
        "cpe_vendor", "vendor_unknown", "match_reason", "fixed_in",
      ],
      clip: 200,
    },
    {
      keep: [
        "cve_id", "severity", "cvss_v3_score", "kev_listed", "ransomware", "epss_score", "echelongraph_score", "effective_score", "effective_severity", "score_assessed", "matched_criteria",
        "cpe_vendor", "vendor_unknown", "fixed_in",
      ],
      clip: 100,
    },
    { keep: ["cve_id", "kev_listed", "ransomware", "epss_score", "effective_score", "effective_severity", "score_assessed", "cpe_vendor", "vendor_unknown", "fixed_in"], clip: 100 },
    { keep: ["cve_id", "kev_listed", "ransomware", "epss_score", "effective_score", "effective_severity", "score_assessed", "fixed_in"], clip: 100 },
    { keep: ["cve_id", "kev_listed", "ransomware", "epss_score", "effective_score", "score_assessed", "fixed_in"], clip: 100 },
  ],
  sides: [
    { list: "cve_ids", cap: 10, said: () => "cve_ids lists each match's cve_id, in the order of matches." },
    { list: "excluded", keep: ["cve_id", "reason"], clip: 100, cap: 10 },
    { list: "undetermined", keep: ["cve_id", "reason"], clip: 100, cap: 10 },
  ],
  whole: `${GET_CVE_WHOLE}, and cve_intel a CVE's affected packages and fixed versions.`,
};

async function checkAffected(kit: CheckAffectedKit, a: Args): Promise<ToolResult> {
  const product = (a.product ?? "").trim();
  const ecosystem = (a.ecosystem ?? "").trim();
  const pkg = (a.package ?? "").trim();
  const version = (a.version ?? "").trim();
  if (product && (ecosystem || pkg)) return kit.badInput(TOOL, "give product (the CPE path) or ecosystem and package (the registry path), not both");
  if (!product && !ecosystem && !pkg) return kit.badInput(TOOL, "product, or ecosystem and package, is required");
  if (!product && !ecosystem) return kit.badInput(TOOL, "ecosystem is required with package");
  if (!product && !pkg) return kit.badInput(TOOL, "package is required with ecosystem");
  if (!version) return kit.badInput(TOOL, "version is required");
  const lookup: "cpe" | "registry" = product ? "cpe" : "registry";
  // #1983: percent-encoded, as the backend's publicMatchParam decodes it (url.PathUnescape), so
  // any value is a legal header and a literal + survives.
  const enc = encodeURIComponent;
  const headers: Record<string, string> =
    lookup === "cpe"
      ? { [MATCH_HEADERS.product]: enc(product), [MATCH_HEADERS.version]: enc(version) }
      : { [MATCH_HEADERS.ecosystem]: enc(ecosystem), [MATCH_HEADERS.package]: enc(pkg), [MATCH_HEADERS.version]: enc(version) };
  try {
    const r = await kit.api(MATCH_PATH, { headers });
    if (!r.ok) return kit.failed(TOOL, r);
    const d = r.data;
    const assessed = bool(d, "assessed");
    const reason = str(d, "not_assessed_reason");
    const matches = Array.isArray(field(d, "matches")) ? (field(d, "matches") as unknown[]) : [];
    const count = num(d, "count") ?? (Array.isArray(field(d, "matches")) ? matches.length : null);
    const capped = bool(d, "capped");
    const candidatesCapped = bool(d, "candidates_capped");
    const undetermined = num(d, "undetermined_count");
    const notAffected = num(d, "not_affected_count");
    const excluded = num(d, "excluded_count");
    const degraded = bool(d, "degraded");
    const layer = str(d, "match_layer");
    const what = lookup === "cpe" ? `product ${product} at version ${version}` : `${ecosystem} package ${pkg} at version ${version}`;

    // assessed, first.
    let note = kit.okHead(TOOL, r.status);
    if (assessed === true) {
      note += ` (state: measured) assessed: true, so the lookup evaluated ${what}.`;
    } else if (assessed === false) {
      const why = reason === null ? "the answer gives no not_assessed_reason." : (REASONS[reason] ?? `the answer gives not_assessed_reason ${reason}, which this version of the server does not describe.`);
      note += ` (state: not_assessed) NOT ASSESSED: assessed is false for ${what}${reason === null ? "" : ` (not_assessed_reason ${reason})`}: ${why} A count of 0 here does not mean this version is not affected: do not report it as unaffected or clean.`;
    } else {
      note += ` (state: not_assessed) The answer carries no assessed field (an API older than it sends none), so it does not say whether ${what} was evaluated, and a count of 0 here does not mean this version is not affected.`;
    }
    if (count !== null && count > 0) {
      note += ` AFFECTED: ${plural(count, "CVE matches", "CVEs match")} this version${capped === true ? " (capped: true, so the list stopped at its cap and more may match)" : ""}.${matchesNote(matches)}${fixedInNote(matches)}`;
    } else if (count === 0 && assessed === true) {
      note += ` 0 CVEs match this version, a measured result (we looked and found nothing that matches), not a lookup failure.`;
      if (lookup === "registry" && notAffected !== null) note += ` ${plural(notAffected, "advisory was", "advisories were")} decided not to affect this version (not_affected_count), and only those are cleared.`;
    }
    if (undetermined !== null && undetermined > 0) {
      note += ` UNDETERMINED: ${plural(undetermined, "advisory names", "advisories name")} this package with a version range that could not be decided at this version (undetermined_count, listed in undetermined): report ${undetermined === 1 ? "it" : "them"} as undetermined, never as safe.`;
    }
    if (candidatesCapped === true && reason !== "candidate_window_truncated") note += " candidates_capped is true: not every candidate CVE was loaded, so more CVEs may match than the answer lists.";
    if (excluded !== null && excluded > 0) note += ` ${plural(excluded, "candidate CVE was", "candidate CVEs were")} suppressed by the vendor or platform gate (excluded_count, listed in excluded).`;
    if (degraded === true) note += " degraded is true: the lookup ran out of time before it finished, so this answer is incomplete.";

    return kit.succeeded(d, note, {
      state: assessed === true ? "measured" : "not_assessed",
      measured_at: null,
      method: (layer ?? lookup) === "registry" ? REGISTRY_METHOD : CPE_METHOD,
      coverage: {
        assessed,
        not_assessed_reason: reason,
        lookup,
        match_layer: layer,
        count,
        capped,
        candidates_capped: candidatesCapped,
        excluded_count: excluded,
        undetermined_count: undetermined,
        not_affected_count: notAffected,
        degraded,
      },
      freshness: null,
      notes: [NO_TIME, NO_FRESHNESS],
    }, CHECK_AFFECTED_TEXT);
  } catch (e) {
    return kit.crashed(TOOL, e);
  }
}

export function registerCheckAffected(server: McpServer, kit: CheckAffectedKit): void {
  const output = kit.envelopeSchema({ data: DATA, coverage: COVERAGE, freshness: null });
  server.registerTool(
    TOOL,
    {
      title: CHECK_AFFECTED_TITLE,
      description: CHECK_AFFECTED_DESCRIPTION,
      inputSchema: CHECK_AFFECTED_INPUT,
      outputSchema: output,
      annotations: kit.annotations,
    },
    async (a: Args) => kit.checked(TOOL, output, await checkAffected(kit, a)),
  );
}
