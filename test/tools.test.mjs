// Behavioural tests for the five MCP tools against a stub EchelonGraph API (#1874).
//
// The property under test: an upstream failure — unreachable host, connection refused,
// non-2xx, timeout, or a 200 whose body is not JSON — must come back as an MCP error result
// (isError: true), never as a successful result whose fields are null. A model that is
// handed a well-formed success with empty fields tells its user "no exposure found", so an
// outage must not read as an all-clear.
//
// The control: a genuine empty answer (HTTP 200, zero rows) must stay a SUCCESS whose note
// says so in words — the fix must not over-correct into "every empty answer is an error".
// "We could not look" and "we looked and found nothing" have to stay distinguishable.
//
// Runs against dist/index.js, so build first — `npm test` does. No framework beyond node:test.
// See server-under-test.mjs for running it against an installed tarball instead.
//
// Protocol eras (#2311). The whole suite runs once per era: this file opens every connection
// with the 2026-07-28 server/discover, and tools-legacy.test.mjs imports it to run the same
// tests over a 2025-06-18 initialize. Every behavioural rule below has to hold in both.
//
// Structured results (#2313). Every tool result the suite receives, in every describe block,
// is collected, and the last block validates each one's structuredContent against the tool's
// own advertised outputSchema with a JSON Schema validator (ajv, as the SDK ships it), and
// walks each one for an exposure number that claims to be measured without a date or a method.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import { AjvJsonSchemaValidator } from "@modelcontextprotocol/server/validators/ajv";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { PKG, PKG_DIR, readPkgFile, serverCommand } from "./server-under-test.mjs";
import { BATCH_PATH, CALL_ANSWER, CALL_ANSWER_EMPTY } from "./fixtures/match-batch.mjs";

// The era this run of the suite opens its connections with.
const ERA = globalThis.MCP_TEST_ERA ?? MODERN;
const CVE = "CVE-2023-44487";
// cve_exposure fixtures for the contract of GET /api/v1/public/kev-exposure/cve/:id.
const CVE_UNTRACKED = "CVE-2099-10001"; // tracked:false, 0 hosts
const CVE_OLD_API = "CVE-2099-10002"; // an API older than `tracked`: 0 hosts, Go zero last_seen
const CVE_REJECTED = "CVE-2099-10003"; // the API answers 400 invalid CVE id
const CVE_UNTRACKED_STALE = "CVE-2099-10004"; // tracked:false, but hosts left from earlier scans
// A method sentence with no closing full stop (the note must supply one).
const METHOD = "Shodan banner match on tracked products; up to 100 ip:port services per product query; searched every 12 h when Shodan query credits allow";
// The sentence the backend actually sends: kevexposure.exposureMethod (poller.go), verbatim.
// The note quotes it word for word, so the #2306 guard below must see THIS string, not an
// example. core-backend's TestExposureMethod_IsTheStringTheMCPServerTestsGuard fails until
// this literal is updated whenever that sentence changes.
const BACKEND_METHOD = "Shodan banner match over the radar's 22 tracked product queries, reading at most 100 ip:port services per query (the first results page); a service counts only when its banner version falls in the CVE's vulnerable CPE range and the CVE is CISA-KEV-listed or has EPSS >= 0.50. Searched every 12 h when Shodan query credits allow. last_seen is when EchelonGraph last wrote or refreshed a service's row, not when the service was observed: it is set to the time of the write when a search matches the banner, and again when a re-check finds the port still listed by Shodan InternetDB, without re-reading the banner, so a patched service can stay counted while its port stays open. A service whose row has not been written or refreshed for 21 days is dropped.";
// #2439: production's per-CVE answer for CVE-2026-87902, recorded through probe-prod.sh on
// 2026-09-27 at 22:05Z and replayed here (the method is the backend's current sentence). Its
// last_seen, 21:52:34.976885Z, is the poller's write time, not an observation: the KEV radar's
// last_run_at in the same capture was 21:53:39Z, and the 50 newest /kev-exposure/feed rows all
// carried last_seen between 21:53:07.85Z and 21:53:08.63Z, a 0.78 s batch write (core-backend
// kevexposure store.go Upsert and Touch set last_seen to now()). The answer serves no other time
// but generated_at, when the API built it.
const CVE_PROD_WRITE_STAMPED = "CVE-2026-87902";
const PROD_WRITE_STAMPED = {
  cve_id: CVE_PROD_WRITE_STAMPED,
  exposed_hosts: 229,
  countries: 32,
  kev_listed: true,
  kev_seen_in_observations: true,
  kev_catalog_listed: true,
  tracked: true,
  method: BACKEND_METHOD,
  ransomware: false,
  top_countries: [
    { country: "United States", hosts: 130 },
    { country: "United Kingdom", hosts: 15 },
    { country: "Germany", hosts: 14 },
    { country: "France", hosts: 8 },
    { country: "India", hosts: 7 },
    { country: "Canada", hosts: 6 },
  ],
  top_products: [{ product: "wordpress", hosts: 229 }],
  last_seen: "2026-09-27T21:52:34.976885Z",
  generated_at: "2026-09-27T22:06:13.516192827Z",
};
// Write times from the same capture: the stamp above, the feed's burst, and the KEV radar's
// completed check. Each is a time EchelonGraph wrote something, and none may become measured_at.
const PROD_WRITE_TIMES = ["2026-09-27T21:52:34.976885Z", "2026-09-27T21:53:07.85Z", "2026-09-27T21:53:08.628614Z", "2026-09-27T21:53:39Z"];
// A follower instance's poller block from an API older than fleet freshness: what the
// shadow-AI stats answer carried when the request landed on an instance not running the
// poller (#2307).
const FOLLOWER_POLLER = { running: false, interval_seconds: 3600, last_run_at: "0001-01-01T00:00:00Z", last_new_inserts: 0, skipped_as_follower: 14, source_health: "healthy", consecutive_fails: 0, shodan_enabled: true, shodan_last_new: 0 };
// The same block from the fleet-freshness API (core-backend shadowctlog Poller.Status):
// running and last_run_at describe the fleet, last_run_at is when the leader last COMPLETED a
// crt.sh cycle, running is true only within 30 minutes of that, and both are omitted when
// unknown. Instance fields are sent only by a process that has run a cycle itself.
const FLEET_RUNNING = { running: true, interval_seconds: 60, last_run_at: "2026-09-26T10:00:00Z", shodan_enabled: true };
const FLEET_STOPPED = { running: false, interval_seconds: 60, last_run_at: "2026-09-26T08:15:00Z", shodan_enabled: true };
const FLEET_UNKNOWN = { interval_seconds: 60, shodan_enabled: true };
// Every key the poller block can carry: the json tags of core-backend shadowctlog poller.go
// Status. Any other key is unknown to this version and must be named when left out (#2440).
const SHADOW_AI_POLLER_KNOWN = ["running", "interval_seconds", "last_run_at", "last_new_inserts", "last_error", "skipped_as_follower", "source_health", "consecutive_fails", "shodan_enabled", "shodan_last_new"];
// The shadow-AI stats answer shaped as production sent it on 2026-09-27 (#2307, reopened):
// total 36,222 against 2,000 confirmed exposed (the sum of visible_by_category); top_products
// ranking LiteLLM at 6,813 observations while 1,395 LLM-PROXY services are confirmed exposed;
// last_24h_count 1,569 against 201 confirmed; auth_confirmed 8,065 and auth_undetermined
// 9,307. Every field core-backend shadowctlog store.go Stats sends is here, the rankings and
// the 30-day series included, so the fixture is no kinder than production.
const TREND_30D = Array.from({ length: 30 }, (_, i) => ({
  date: new Date(Date.UTC(2026, 7, 28 + i)).toISOString().slice(0, 10),
  count: 1100 + 7 * i,
}));
const PROD_SHADOW_STATS = {
  total: 36222,
  by_category: { "LLM-PROXY": 14000, "VECTOR-DB": 8000, NOTEBOOK: 6000, "AI-WORKFLOW": 4222, "INFERENCE-SRV": 2500, "MCP-SERVER": 1500 },
  visible_by_category: { "LLM-PROXY": 1395, "VECTOR-DB": 300, NOTEBOOK: 150, "AI-WORKFLOW": 100, "INFERENCE-SRV": 40, "MCP-SERVER": 15 },
  last_observation: "2026-09-26T11:02:00Z",
  last_24h_count: 1569,
  last_24h_visible_count: 201,
  auth_confirmed: 8065,
  auth_undetermined: 9307,
  top_products: [
    { product: "LiteLLM", count: 6813 },
    { product: "Ollama", count: 5210 },
    { product: "Qdrant", count: 3120 },
    { product: "Jupyter Notebook", count: 2704 },
    { product: "n8n", count: 1988 },
  ],
  top_countries: [
    { country: "United States", count: 9800 },
    { country: "China", count: 7400 },
    { country: "Germany", count: 3100 },
  ],
  top_issuers: [
    { issuer: "Let's Encrypt", count: 15800 },
    { issuer: "Tencent Cloud Computing (Beijing) Co., Ltd (China)", count: 3500 },
    { issuer: "Google Trust Services", count: 2900 },
  ],
  trend_30d: TREND_30D,
};
// What exposure_radar must relay for it: the same numbers, grouped by what each one counts.
const PROD_SHADOW_RELAYED = {
  confirmed_exposed: { total: 2000, by_category: PROD_SHADOW_STATS.visible_by_category, last_24h: 201 },
  observed: {
    total: 36222,
    by_category: PROD_SHADOW_STATS.by_category,
    last_24h: 1569,
    trend_30d: TREND_30D,
    top_products: PROD_SHADOW_STATS.top_products,
    top_countries: PROD_SHADOW_STATS.top_countries,
    top_issuers: PROD_SHADOW_STATS.top_issuers,
    last_observation: "2026-09-26T11:02:00Z",
  },
  authentication: { observed: 8065, not_determined: 9307 },
};
// #2313 items 6 and 7: the other three radars' stats answers, shaped field for field by the
// Go structs' json tags at HEAD (core-backend/internal):
//   kev_exposure       kevexposure/store.go Stats, ProductCount, CVECount, CountryCount,
//                      KEVAddition, TrendPoint (omitempty: severity, cvss_v3_score, epss_score,
//                      ransomware, vuln_name, added_date)
//   exposed_databases  exposeddb/store.go Stats, EngineCount, CountryCount
//   leaked_credentials leakedcreds/store.go Stats, ProviderCount, TypeCount
// Each also carries last_run_at since #2335 (`json:"last_run_at,omitempty"`): when that radar
// last COMPLETED a check, read from poller_run_state (pollerlock/published.go). The three are
// distinct and none equals generated_at (when the 60 s stats cache recomputed the totals), so
// a reader that relays one radar's stamp, or generated_at, as another's is caught.
const LAST_RUN = {
  kev_exposure: "2026-09-27T03:12:44Z",
  exposed_databases: "2026-09-27T02:18:06Z",
  leaked_credentials: "2026-09-27T08:41:15Z",
};
// newest_kev is the audit's case: of 15 rows, one CVE the radar tracks with 142 services on
// record (CVE-2026-87902, tracked:true on /kev-exposure/cve/:id), and 14 at exposed_hosts 0,
// every one tracked:false on that endpoint (CVE-2026-65660, -94127, -76460 and -71362 are the
// ids the audit measured; the other ten stand in for the rest). A 0 there is the stats query's
// LEFT JOIN default, COALESCE(e.h, 0), not a measurement.
const KEV_TRACKED = "CVE-2026-87902";
const KEV_UNTRACKED = [
  "CVE-2026-65660", "CVE-2026-94127", "CVE-2026-76460", "CVE-2026-71362", "CVE-2026-60311", "CVE-2026-58002", "CVE-2026-55519",
  "CVE-2026-52870", "CVE-2026-49133", "CVE-2026-47401", "CVE-2026-44018", "CVE-2026-41276", "CVE-2026-39954", "CVE-2026-36087",
];
const NEWEST_KEV = [
  { cve_id: KEV_TRACKED, added_date: "2026-09-25", severity: "CRITICAL", cvss_v3_score: 9.8, epss_score: 0.912, ransomware: true, vuln_name: "Fortinet FortiOS Out-of-Bounds Write", exposed_hosts: 142 },
  ...KEV_UNTRACKED.map((cve_id, i) => ({
    cve_id,
    added_date: `2026-09-${String(24 - i).padStart(2, "0")}`,
    // omitempty: a record with no CVSS v3 score or no severity sends neither (store.go KEVAddition).
    ...(i % 5 === 4 ? {} : { severity: i % 2 ? "HIGH" : "CRITICAL", cvss_v3_score: i % 2 ? 8.1 : 9.1 }),
    epss_score: Number((0.02 + i / 100).toFixed(2)),
    vuln_name: `Vendor ${i + 1} product vulnerability`,
    exposed_hosts: 0,
  })),
];
const KEV_TREND = Array.from({ length: 12 }, (_, i) => ({
  week: new Date(Date.UTC(2026, 6, 6 + 7 * i)).toISOString().slice(0, 10),
  new_exposures: 2400 + 13 * i,
}));
const PROD_KEV_STATS = {
  distinct_hosts: 25113,
  kev_cves_exposed: 54,
  correlations: 31887,
  ransomware_cves: 19,
  ransomware_hosts: 6655,
  top_products: [
    { product: "http_server", hosts: 9120 },
    { product: "exchange_server", hosts: 4410 },
    { product: "fortios", hosts: 2891 },
  ],
  top_cves: [
    { cve_id: CVE, hosts: 6213, severity: "HIGH", cvss_v3_score: 7.5, epss_score: 0.94 },
    { cve_id: "CVE-2021-26855", hosts: 3980, severity: "CRITICAL", cvss_v3_score: 9.8, epss_score: 0.97, ransomware: true },
    { cve_id: "CVE-2024-21762", hosts: 2702, severity: "CRITICAL", cvss_v3_score: 9.8, epss_score: 0.93, ransomware: true },
  ],
  top_countries: [
    { country: "United States", hosts: 7021 },
    { country: "Germany", hosts: 1893 },
    { country: "China", hosts: 1655 },
  ],
  newest_kev: NEWEST_KEV,
  trend: KEV_TREND,
  generated_at: "2026-09-27T09:00:00Z",
  last_run_at: LAST_RUN.kev_exposure,
};
const PROD_EXPOSED_DB_STATS = {
  distinct_hosts: 7380,
  engines: 10,
  pii_likely: 412,
  pci_likely: 37,
  top_engines: [
    { engine: "redis", hosts: 2410 },
    { engine: "elasticsearch", hosts: 1733 },
    { engine: "mongodb", hosts: 1250 },
    { engine: "grafana", hosts: 690 },
  ],
  top_countries: [
    { country: "United States", hosts: 2204 },
    { country: "China", hosts: 1310 },
  ],
  generated_at: "2026-09-27T09:00:00Z",
  last_run_at: LAST_RUN.exposed_databases,
};
const PROD_LEAKED_CREDS_STATS = {
  distinct_repos: 303,
  distinct_secrets: 507,
  total: 531,
  top_providers: [
    { provider: "aws", count: 212 },
    { provider: "github", count: 141 },
    { provider: "slack", count: 77 },
  ],
  top_types: [
    { secret_type: "AWS Access Key ID", count: 188 },
    { secret_type: "GitHub Personal Access Token", count: 139 },
  ],
  generated_at: "2026-09-27T09:00:00Z",
  last_run_at: LAST_RUN.leaked_credentials,
};
// #2315: the ?service=mcp answer (GET /api/v1/public/ai-exposure/stats?service=mcp), key for key
// as the contract gives it (core-backend aiexposure handler.go MCPPublicCounts). The counts are
// made up, not production's; every partition adds up to the count it divides, and window.from,
// window.to, last_run_at and counted_at are four different instants, so a reader that relays one
// as another, or takes one for measured_at, is caught. None of the numbers is one the shadow-AI
// fixture above sends.
const MCP_PATH = "/api/v1/public/ai-exposure/stats?service=mcp";
const MCP_REASONS = {
  identified_no_challenge: 347,
  resource_mismatch: 233,
  cross_origin_pointer: 58,
  bare_challenge_no_prm: 41,
  pointer_unreachable: 11,
  pointer_invalid: 6,
  no_authorization_servers: 4,
  wellknown_unreachable: 9,
  metadata_invalid: 2,
  challenge_unadjudicated: 877,
  no_http_answer: 6120,
  not_identified_as_mcp: 1893,
};
const MCP_STATS = {
  service: "mcp",
  total: 10217,
  protected: 611,
  pending_readjudication: 5,
  not_assessed: 9601,
  not_assessed_by_reason: MCP_REASONS,
  prm_via: { header: 402, wellknown_path: 131, wellknown_root: 78 },
  era: { legacy: 213, dual: 4, modern: 37, unknown: 1402, not_measured: 8561 },
  transport: { streamable_http: 251, legacy_sse: 3, unknown: 1402, not_measured: 8561 },
  window: { from: "2026-09-12T00:04:01Z", to: "2026-09-28T22:51:09Z" },
  own_controls_excluded: 3,
  enabled: true,
  last_run_at: "2026-09-28T23:05:44Z",
  counted_at: "2026-09-28T23:06:00Z",
};
// What exposure_radar must relay for it: every count and timestamp as given, and not `service`,
// the one string in the answer that is not a timestamp.
const { service: _mcpService, ...MCP_RELAYED } = MCP_STATS;
const zeroed = (o) => Object.fromEntries(Object.keys(o).map((k) => [k, 0]));
// A radar that holds no MCP verdict and has never completed a check: every count 0, from and to
// null (the contract's window struct with nothing to span), last_run_at null, enabled false.
const MCP_EMPTY = {
  service: "mcp",
  total: 0,
  protected: 0,
  pending_readjudication: 0,
  not_assessed: 0,
  not_assessed_by_reason: zeroed(MCP_REASONS),
  prm_via: zeroed(MCP_STATS.prm_via),
  era: zeroed(MCP_STATS.era),
  transport: zeroed(MCP_STATS.transport),
  window: { from: null, to: null },
  own_controls_excluded: 0,
  enabled: false,
  last_run_at: null,
  counted_at: "2026-09-28T23:06:00Z",
};
// What exposure_radar must relay for newest_kev: the tracked row with its count, and every
// untracked row marked not_assessed with no count at all.
const NEWEST_KEV_RELAYED = NEWEST_KEV.map(({ exposed_hosts, ...r }) =>
  r.cve_id === KEV_TRACKED ? { ...r, exposure_state: "exposed", exposed_hosts } : { ...r, exposure_state: "not_assessed" },
);
// Shodan's terms ask that materials based on Shodan information "clearly indicate Shodan's
// ownership and copyright" (#2306, reopened). The package's exact sentence, pinned here.
const SHODAN_OWNERSHIP = "Shodan data is owned by Shodan, which holds its copyright (© Shodan).";
// Claims the package's own copy must not make (#2306): the exposure data is Shodan-derived
// and the other radars send active probes (nothing is passive); every figure refreshes on a
// schedule (nothing is live or real-time); others also map CVEs to exposure (not unique).
const REMOVED_CLAIMS = /passive|no other|unique|real-?time|\blive\b|right now/i;
// Every radar count is of distinct ip:port services (the backend keys an observation on
// ip:port, one Shodan banner per port), so a machine answering on two ports counts twice.
// The package's own words must not call that number hosts. Field names such as
// exposed_hosts are not matched: `_` is a word character.
const HOST_UNIT = /\bhosts\b|\bhost\(s\)/i;

// #2719: the vendor-advisory routes (core-backend vendoradv handler.go), shaped as the API sends
// them: the list with search_applied, the per-CVE rows with our_first_seen_at.
const VADV_CVE = "CVE-2024-21412";
const VADV_ID = "RHSA-2024:1234";
const VADV_ROW = {
  advisory_id: "6f1c7d2e-0000-4000-8000-000000000001", vendor: "redhat", vendor_display_name: "Red Hat", vendor_advisory_id: VADV_ID,
  cve_ids: [VADV_CVE], title: "Important: kernel security update", severity: "High", cvss_v3_score: 7.8,
  summary: "An update for kernel is now available.", affected_products: ["Red Hat Enterprise Linux 9"],
  vendor_published_at: "2024-02-13T00:00:00Z", our_first_seen_at: "2024-02-13T06:12:44Z", withdrawn: false,
};
const VADV_DETAIL = {
  ...VADV_ROW, known_cve_ids: [VADV_CVE], description: "An update for kernel is now available.", remediation: "Update the kernel packages.",
  references: [{ url: "https://access.redhat.com/errata/RHSA-2024:1234" }], vendor_modified_at: "2024-02-14T00:00:00Z", withdrawn_at: "", withdrawn_reason: "",
};

// One representative call per tool. Every describe block below exercises all of them.
// check_affected's own cases (every not_assessed_reason, header carriage, both paths) are in
// check_affected.test.mjs; here it goes through every rule the other tools do.
const CALLS = {
  cve_summary: {},
  search_cves: { search: "tomcat", limit: 2 },
  get_cve: { cve_id: CVE },
  cve_exposure: { cve_id: CVE },
  exposure_radar: {},
  // #2718; its own cases are in epss_history.test.mjs.
  epss_history: { cve_id: CVE },
  check_affected: { product: "openssl", version: "3.0.0" },
  // #2721: its own suite is check_sbom.test.mjs; here it meets every cross-tool rule.
  check_sbom: { purls: ["pkg:npm/lodash@4.17.20", "pkg:deb/debian/openssl@3.0.11-1~deb12u1"] },
  // #2719 (fixtures: VADV_* below; the tool-specific tests are in vendor-advisories.test.mjs).
  vendor_advisories_for_cve: { cve_id: VADV_CVE },
  get_vendor_advisory: { vendor: "redhat", advisory_id: VADV_ID },
  search_vendor_advisories: { query: "exchange server", limit: 2 },
};
const TOOLS = Object.keys(CALLS);
// What tools/list answers, in createServer()'s registration order. Tools registered from
// src/tools/ that are not in CALLS have their own suites (kev_recent: kev_recent.test.mjs, #2717).
const PROMPT_NAMES = ["triage_cve", "kev_weekly_brief", "am_i_affected", "sbom_review"];
const LISTED = ["cve_summary", "search_cves", "get_cve", "cve_exposure", "exposure_radar", "kev_recent", "epss_history", "check_affected", "check_sbom", "cve_intel", "get_cwe", "vendor_advisories_for_cve", "get_vendor_advisory", "search_vendor_advisories"];

// #2535: score_assessed. A CVE EchelonGraph has not scored carries score_assessed false, and
// any echelongraph_score it carries is a placeholder, not a rating (core-backend cve/store.go,
// the CVE struct's ScoreAssessed). The API sends the key on every CVE row. Since #1106 and #1949
// it withholds echelongraph_score, echelongraph_severity and echelongraph_risk on an unscored
// row (store.go scanFullCVE) and still sends score_confidence NONE, the scorer's rationale and
// score_unassessed_reason. An API before those sent the placeholders 0, NONE and 0: the shape a
// model reads as "EG score 0", and how CVE-2026-41566 was indexed as "EG 0.0" before it was
// scored. An API before migration 097 sent no score_assessed at all. Synthetic ids, one per shape.
const CVE_UNSCORED_ZERO = "CVE-2099-20001"; // score_assessed false, placeholders sent: 0, NONE, 0
const CVE_UNSCORED = "CVE-2099-20002"; // score_assessed false, placeholders withheld (production's shape)
const CVE_UNSCORED_REJECTED = "CVE-2099-20003"; // score_assessed false, the record rejected
const CVE_SCORE_UNSTATED = "CVE-2099-20004"; // no score_assessed, and a 0 score
// cve/scoring/scorer.go Rule 7, verbatim: the rationale an unscored CVE carries.
const NO_DATA_RATIONALE =
  "No severity assessment is available for this CVE yet. No source has published a CVSS v3.1, v4.0 or v2.0 base score, it is not in CISA KEV, there is no GitHub Security Advisory, and the advisory text does not state a vendor severity we can parse. This is NOT a score of zero and NOT a statement that the CVE is harmless — it means we cannot yet assess it. The EchelonGraph score will populate as soon as any source publishes data.";
const SCORE_ROWS = {
  [CVE_UNSCORED_ZERO]: { cve_id: CVE_UNSCORED_ZERO, echelongraph_score: 0, echelongraph_severity: "NONE", echelongraph_risk: 0, score_confidence: "NONE", score_assessed: false, score_unassessed_reason: "no_signal", epss_score: 0.00041, kev_listed: false },
  [CVE_UNSCORED]: { cve_id: CVE_UNSCORED, score_confidence: "NONE", score_rationale: NO_DATA_RATIONALE, score_assessed: false, score_unassessed_reason: "no_signal", epss_score: 0.00041, kev_listed: false },
  [CVE_UNSCORED_REJECTED]: { cve_id: CVE_UNSCORED_REJECTED, score_confidence: "NONE", score_assessed: false, score_unassessed_reason: "rejected", kev_listed: false },
  [CVE_SCORE_UNSTATED]: { cve_id: CVE_SCORE_UNSTATED, echelongraph_score: 0, echelongraph_severity: "NONE", score_confidence: "NONE", kev_listed: false },
};

// #2641: production's /api/v1/public/cves/summary, read 2026-09-30T10:02:13Z through the
// operator probe, whole: every one of the fourteen summary fields and the eight of the poller
// block (core-backend cve/store.go CVESummary, cve/poller.go Stats), in the order it sent them.
// Through 2.3.3 this fixture was trimmed to the fields the tests asserted on, so it held none of
// nvd_critical, nvd_high, nvd_medium, nvd_low, nvd_none or rejected, and no test could see that
// the tool relayed nvd_none (75,962, 22 times summary.none) with no word about what it counts.
// Both histograms add up to total, as store.go Summary builds them.
const PROD_CVE_SUMMARY = {
  poller: { cves_ingested: 7195, cves_skipped: 51, http_retries: 0, interval: "20m0s", last_poll_at: "2026-09-30T09:46:50Z", last_poll_dur_ms: 1214, poll_count: 4, poll_errors: 0 },
  summary: {
    critical: 42887, high: 151750, medium: 168729, low: 14500, none: 3408, unscored: 3408, total: 381274,
    nvd_critical: 39188, nvd_high: 121655, nvd_medium: 134157, nvd_low: 10312, nvd_none: 75962, rejected: 884,
    last_updated: "2026-09-30T09:56:35.584Z",
  },
};

// Stub bodies shaped like the live API answered on 2026-09-15, trimmed to the fields the
// tests assert on, except cve_summary's, which is production's whole answer (#2641). `ok` is a
// populated answer; `empty` is the genuine-nothing answer. The CVE rows carry score_assessed
// true, as every scored row on the API does (#2535). The summary carries unscored beside none,
// equal to it, as core-backend cve/store.go Summary sends it (#2610).
const BODIES = {
  // #2721: check_sbom's POST (the stub answers by path, whatever the method).
  [BATCH_PATH]: { ok: CALL_ANSWER, empty: CALL_ANSWER_EMPTY },
  "/api/v1/public/cves/summary": {
    ok: PROD_CVE_SUMMARY,
    empty: {
      poller: PROD_CVE_SUMMARY.poller,
      summary: { critical: 0, high: 0, medium: 0, low: 0, none: 0, unscored: 0, total: 0, nvd_critical: 0, nvd_high: 0, nvd_medium: 0, nvd_low: 0, nvd_none: 0, rejected: 0, last_updated: PROD_CVE_SUMMARY.summary.last_updated },
    },
  },
  "/api/v1/public/cves": {
    ok: { cves: [{ cve_id: CVE, severity: "HIGH", cvss_v3_score: 7.5, echelongraph_score: 9, score_assessed: true, kev_listed: true }], limit: 2, offset: 0, total: 1 },
    empty: { cves: [], limit: 2, offset: 0, total: 0 },
  },
  [`/api/v1/public/cves/${CVE}`]: {
    ok: { cve_id: CVE, severity: "HIGH", cvss_v3_score: 7.5, echelongraph_score: 9, score_confidence: "HIGH", score_assessed: true, epss_score: 0.99999, kev_listed: true, kev_ransomware: false },
    // The live API answers an unknown CVE with HTTP 404 and its own JSON message.
    empty: { status: 404, body: { error: `CVE not found: ${CVE}` } },
  },
  // #2718: core-backend cve/epss_history.go's answer. `empty` is a CVE with no recorded change.
  [`/api/v1/public/cves/${CVE}/epss-history`]: {
    ok: {
      cve_id: CVE, series_kind: "change_only", series_starts_at: "2026-05-27T03:00:00Z",
      current: { epss_score: 0.94358, epss_percentile: 0.99911, epss_updated_at: "2026-10-01T03:00:00Z" },
      points: [
        { at: "2026-06-01T03:00:00Z", epss_score: 0.81022, epss_percentile: 0.99012 },
        { at: "2026-10-01T03:00:00Z", epss_score: 0.94358, epss_percentile: 0.99911 },
      ],
      history_rows: 3, points_truncated: false, latest_point_matches_current: true,
    },
    empty: {
      cve_id: CVE, series_kind: "change_only", series_starts_at: "2026-05-27T03:00:00Z",
      current: { epss_score: 0.94358, epss_percentile: 0.99911, epss_updated_at: "2026-05-20T03:00:00Z" },
      points: [], history_rows: 0, points_truncated: false, latest_point_matches_current: null,
    },
  },
  // The contract shape: the old fields plus tracked, kev_catalog_listed,
  // kev_seen_in_observations, method, and last_seen null when there is no observation.
  [`/api/v1/public/kev-exposure/cve/${CVE}`]: {
    ok: { cve_id: CVE, exposed_hosts: 6213, countries: 107, kev_listed: true, kev_seen_in_observations: true, kev_catalog_listed: true, tracked: true, method: BACKEND_METHOD, ransomware: false, top_countries: [{ country: "United States", hosts: 1888 }], top_products: [{ product: "http_server", hosts: 2668 }], last_seen: "2026-09-15T04:02:09Z", generated_at: "2026-09-15T05:00:00Z" },
    empty: { cve_id: CVE, exposed_hosts: 0, countries: 0, kev_listed: false, kev_seen_in_observations: false, kev_catalog_listed: true, tracked: true, method: BACKEND_METHOD, ransomware: false, top_countries: [], top_products: [], last_seen: null, generated_at: "2026-09-15T05:00:00Z" },
  },
  [`/api/v1/public/kev-exposure/cve/${CVE_UNTRACKED}`]: {
    ok: { cve_id: CVE_UNTRACKED, exposed_hosts: 0, countries: 0, kev_listed: false, kev_seen_in_observations: false, kev_catalog_listed: false, tracked: false, method: BACKEND_METHOD, ransomware: false, top_countries: [], top_products: [], last_seen: null, generated_at: "2026-09-15T05:00:00Z" },
  },
  [`/api/v1/public/kev-exposure/cve/${CVE_UNTRACKED_STALE}`]: {
    ok: { cve_id: CVE_UNTRACKED_STALE, exposed_hosts: 3, countries: 2, kev_listed: true, kev_seen_in_observations: true, kev_catalog_listed: true, tracked: false, method: `${METHOD}.`, ransomware: false, top_countries: [], top_products: [], last_seen: "2026-09-01T00:00:00Z", generated_at: "2026-09-15T05:00:00Z" },
  },
  // What the API answered before the contract: no tracked, no method, the Go zero time.
  [`/api/v1/public/kev-exposure/cve/${CVE_OLD_API}`]: {
    ok: { cve_id: CVE_OLD_API, exposed_hosts: 0, countries: 0, kev_listed: false, ransomware: false, top_countries: [], top_products: [], last_seen: "0001-01-01T00:00:00Z", generated_at: "2026-09-15T05:00:00Z" },
  },
  [`/api/v1/public/kev-exposure/cve/${CVE_REJECTED}`]: {
    ok: { status: 400, body: { error: "invalid CVE id", cve_id: CVE_REJECTED } },
  },
  // An empty observation table still answers newest_kev: those rows come from the CVE records,
  // LEFT JOINed to the observations, so every one reads exposed_hosts 0.
  "/api/v1/public/kev-exposure/stats": {
    ok: PROD_KEV_STATS,
    empty: { distinct_hosts: 0, kev_cves_exposed: 0, correlations: 0, ransomware_cves: 0, ransomware_hosts: 0, top_products: [], top_cves: [], top_countries: [], newest_kev: NEWEST_KEV.map((r) => ({ ...r, exposed_hosts: 0 })), trend: [], generated_at: "2026-09-27T09:00:00Z" },
  },
  "/api/v1/public/exposed-databases/stats": {
    ok: PROD_EXPOSED_DB_STATS,
    empty: { distinct_hosts: 0, engines: 0, pii_likely: 0, pci_likely: 0, top_engines: [], top_countries: [], generated_at: "2026-09-27T09:00:00Z" },
  },
  "/api/v1/public/leaked-credentials/stats": {
    ok: PROD_LEAKED_CREDS_STATS,
    empty: { distinct_repos: 0, distinct_secrets: 0, total: 0, top_providers: [], top_types: [], generated_at: "2026-09-27T09:00:00Z" },
  },
  // The per-CVE answers for newest_kev's CVEs, as /kev-exposure/cve/:id gives them: tracked
  // only where the radar holds services (store.go trackedVerdict), tracked:false elsewhere.
  [`/api/v1/public/kev-exposure/cve/${KEV_TRACKED}`]: {
    ok: { cve_id: KEV_TRACKED, exposed_hosts: 142, countries: 17, kev_listed: true, kev_seen_in_observations: true, kev_catalog_listed: true, tracked: true, method: BACKEND_METHOD, ransomware: true, top_countries: [{ country: "United States", hosts: 40 }], top_products: [{ product: "fortios", hosts: 142 }], last_seen: "2026-09-27T03:00:00Z", generated_at: "2026-09-27T09:00:00Z" },
  },
  ...Object.fromEntries(
    KEV_UNTRACKED.map((id) => [
      `/api/v1/public/kev-exposure/cve/${id}`,
      { ok: { cve_id: id, exposed_hosts: 0, countries: 0, kev_listed: false, kev_seen_in_observations: false, kev_catalog_listed: true, tracked: false, method: BACKEND_METHOD, ransomware: false, top_countries: [], top_products: [], last_seen: null, generated_at: "2026-09-27T09:00:00Z" } },
    ]),
  ),
  // stats.total counts every observation; the confirmed-exposed count is the sum of
  // visible_by_category (2,000 here, as on 2026-09-27 against a total of 36,222).
  // Keyed by the whole request URL: a request without ?service=mcp gets the router's 404.
  [MCP_PATH]: { ok: MCP_STATS, empty: MCP_EMPTY },
  // check_affected (#2716): the typed values travel in X-EG-* headers, so the path is the whole
  // URL. ok is an assessed CPE hit, shaped as production answered openssl 3.0.0 on 2026-10-03
  // (trimmed to one match); empty is the not_assessed answer production gives spring-boot.
  "/api/v1/public/cves/match": {
    ok: {
      assessed: true, candidate_count: 319, candidates_capped: false, capped: false, count: 1, excluded: [], excluded_count: 0, match_layer: "cpe", not_assessed_reason: "",
      product: "openssl", product_named_count: 318, undecidable_excluded_count: 0, undecided_candidate_count: 4, vendor: "", vendor_advisory_count: 0, version: "3.0.0",
      matches: [{ cve_id: "CVE-2026-45447", severity: "HIGH", cvss_v3_score: 8.8, description: "A use-after-free during PKCS#7 signature verification.", kev_listed: false, ransomware: false, epss_score: 0.04002, cvss_v2_score: 0, cvss_v4_score: 0, echelongraph_score: 9.8, echelongraph_severity: "CRITICAL", effective_score: 9.8, effective_severity: "CRITICAL", score_assessed: true, matched_criteria: "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", match_method: "product-name heuristic", match_confidence: 0.5, cpe_vendor: "openssl", vendor_unknown: true }],
    },
    empty: { assessed: false, candidate_count: 0, candidates_capped: false, capped: false, count: 0, excluded: [], excluded_count: 0, match_layer: "cpe", matches: [], not_assessed_reason: "product_not_in_cpe_corpus", product: "openssl", product_named_count: 0, undecidable_excluded_count: 0, undecided_candidate_count: 0, vendor: "", vendor_advisory_count: 0, version: "3.0.0" },
  },
  [`/api/v1/public/vendor-advisories/by-cve/${VADV_CVE}`]: {
    ok: { cve_id: VADV_CVE, advisories: [VADV_ROW], total: 1 },
    empty: { cve_id: VADV_CVE, advisories: [], total: 0 },
  },
  [`/api/v1/public/vendor-advisories/redhat/${encodeURIComponent(VADV_ID)}`]: {
    ok: VADV_DETAIL,
    empty: { status: 404, body: { error: "advisory not found" } },
  },
  "/api/v1/public/vendor-advisories": {
    ok: { advisories: [VADV_ROW], total: 1, limit: 2, offset: 0, search_applied: true },
    empty: { advisories: [], total: 0, limit: 2, offset: 0, search_applied: true },
  },
  "/api/v1/public/shadow-ai-radar/stats": {
    ok: { stats: PROD_SHADOW_STATS, poller: FOLLOWER_POLLER },
    empty: { stats: { total: 0, by_category: {}, visible_by_category: {}, last_24h_count: 0, last_24h_visible_count: 0, auth_confirmed: 0, auth_undetermined: 0 }, poller: FOLLOWER_POLLER },
  },
};

// A stub API whose behaviour is switched per describe block. Modes:
//   ok / empty  — HTTP 200 with the matching body above (get_cve's `empty` is the API's 404;
//                 a body with a `status` is answered with that status, and one with a `raw`
//                 string is answered with that string as is). A body is looked up by the whole
//                 request URL first, then by its path.
//   403         — HTTP 403 with an HTML body, the shape an edge block produces
//   html        — HTTP 200 with an HTML body (an SPA shell or a wrong path)
//   null        — HTTP 200 whose JSON body is the literal `null`
//   number      — HTTP 200 whose JSON body is a bare number (#2311)
//   truncated   — HTTP 200 whose body is JSON cut off mid-object (#2311)
//   hang        — accept the request and never answer
async function startStub() {
  // overrides: request URL or pathname -> body, consulted before BODIES in the ok/empty modes.
  const state = { mode: "ok", seen: [], userAgents: [], overrides: {} };
  const pending = new Set();
  const server = http.createServer((req, res) => {
    state.seen.push(req.url);
    state.userAgents.push(req.headers["user-agent"]);
    (state.searchHeaders ??= []).push(req.headers["x-eg-search"]);
    const { pathname } = new URL(req.url, "http://stub");
    switch (state.mode) {
      case "403":
        res.writeHead(403, { "content-type": "text/html" });
        res.end("<html><head><title>Just a moment...</title></head><body>Forbidden</body></html>");
        return;
      case "html":
        res.writeHead(200, { "content-type": "text/html" });
        res.end("<!doctype html><html><body><div id=app></div></body></html>");
        return;
      case "null":
        res.writeHead(200, { "content-type": "application/json" });
        res.end("null");
        return;
      case "number":
        res.writeHead(200, { "content-type": "application/json" });
        res.end("42");
        return;
      case "truncated":
        res.writeHead(200, { "content-type": "application/json" });
        res.end('{"summary": {"critical": 42038, "total": 3735');
        return;
      case "hang":
        pending.add(res);
        req.on("close", () => pending.delete(res));
        return;
      default: {
        const entry = state.overrides[req.url] ?? state.overrides[pathname] ?? BODIES[req.url]?.[state.mode] ?? BODIES[pathname]?.[state.mode];
        if (entry === undefined) {
          // What the Go router does for a path it does not know.
          res.writeHead(404, { "content-type": "text/plain" });
          res.end("404 page not found\n");
          return;
        }
        const status = entry.status ?? 200;
        const body = entry.status ? entry.body : entry;
        res.writeHead(status, { "content-type": "application/json" });
        res.end(typeof entry.raw === "string" ? entry.raw : JSON.stringify(body));
      }
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    state,
    base: `http://127.0.0.1:${server.address().port}`,
    close: () => {
      for (const res of pending) res.destroy();
      server.closeAllConnections();
      return new Promise((resolve) => server.close(resolve));
    },
  };
}

// A port nothing listens on, so a connection to it is refused rather than blocked.
async function refusedPort() {
  const probe = net.createServer();
  await new Promise((resolve) => probe.listen(0, "127.0.0.1", resolve));
  const { port } = probe.address();
  await new Promise((resolve) => probe.close(resolve));
  return port;
}

// Every tool result any test receives: [tool, arguments, result]. The last describe block
// validates all of them (#2313).
const COLLECTED = [];

async function spawnServer(env) {
  const client = await connect({ era: ERA, ...serverCommand(), env: { ...process.env, ...env }, stderr: "inherit" });
  const call = client.callTool.bind(client);
  client.callTool = async (req) => {
    const res = await call(req);
    COLLECTED.push([req.name, req.arguments ?? {}, res]);
    return res;
  };
  return client;
}

async function callAll(client) {
  const out = {};
  for (const name of TOOLS) out[name] = await client.callTool({ name, arguments: CALLS[name] });
  return out;
}

const textOf = (res) => (res.content ?? []).filter((c) => c.type === "text").map((c) => c.text).join("\n");
const textBlocks = (res) => (res.content ?? []).filter((c) => c.type === "text").map((c) => c.text);
// The server's own words: the failure message of an error, the note after the API's JSON
// otherwise. The envelope block after either (#2440) is read by envelopeOf, not here.
const noteOf = (res) => textBlocks(res)[res.isError ? 0 : 1] ?? "";
// #2440: the last text block, which is structuredContent without data, as JSON.
const envelopeOf = (res) => JSON.parse(textBlocks(res).at(-1));
// Every string an envelope carries, one after another: what a model reads in it, for the
// wording guards (they read prose sentence by sentence, and a JSON array of sentences, or a
// method string beside a notes array, is not split the way prose is).
const stringsIn = (v, out = []) => {
  if (typeof v === "string") out.push(v);
  else if (v !== null && typeof v === "object") for (const x of Object.values(v)) stringsIn(x, out);
  return out;
};
const envelopeWords = (res) => stringsIn(envelopeOf(res)).join(" ");
const brief = (res) => JSON.stringify(res).replace(/\s+/g, " ").slice(0, 300);

// The server's own split of a note into notes (index.ts `sentences`): whitespace runs collapsed,
// one sentence per entry, ending in ".", "!" or "?" before whitespace.
const noteSentences = (t) => t.replace(/\s+/g, " ").trim().split(/(?<=[.!?])\s+/).filter(Boolean);
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

// #2440, #2467: a result's text carries its envelope. A success is three text blocks (the API's
// JSON, the note, the envelope) and a failure two (the message, the envelope). The envelope block
// is structuredContent as JSON less what an earlier block already says verbatim, and nothing else
// (#2467: 2.1.0 repeated the whole note in it):
//   - state, measured_at, coverage and freshness are always in it, equal to structuredContent's;
//   - data is not: a success's first block parses to it;
//   - notes holds only the envelope's own sentences: structuredContent's notes are those followed
//     by the sentences of the block just before the envelope (the note, or the message), each
//     found verbatim in that block, and none of the own sentences is one of them. With no own
//     sentence, notes is left out rather than sent empty;
//   - method is in it, equal, unless the block before quotes structuredContent's method verbatim,
//     and then it is left out, since the text already says it.
// So the text, rebuilt from its blocks, is structuredContent exactly: text and structure cannot
// disagree, and nothing structuredContent says is missing from the text. A "(state: …)" or
// "(exposure_state: …)" tag in the note or message names the structured value, never another.
// Returns the envelope block as read.
const TAG = /\((state|exposure_state): ([a-z_]+)\)/g;
function assertEnvelopeInText(where, res) {
  const sc = res.structuredContent;
  const blocks = textBlocks(res);
  const want = res.isError ? 2 : 3;
  assert.equal(blocks.length, want, `${where}: ${blocks.length} text block(s), expected ${want}: ${brief(res)}`);
  let env;
  try {
    env = JSON.parse(blocks.at(-1));
  } catch {
    assert.fail(`${where}: the last text block is not the envelope's JSON: ${blocks.at(-1).slice(0, 200)}`);
  }
  const said = blocks.at(-2);
  const { data, ...withoutData } = sc;
  for (const k of ["state", "measured_at", "coverage", "freshness", ...(has(env, "method") ? ["method"] : [])]) {
    assert.ok(has(env, k), `${where}: the text's envelope has no ${k}`);
    assert.deepEqual(env[k], sc[k], `${where}: the text says ${k} ${JSON.stringify(env[k])}, structuredContent ${JSON.stringify(sc[k])}`);
  }
  assert.ok(!("data" in env), `${where}: the envelope block repeats data, which is the first block`);
  if (!res.isError) assert.deepEqual(JSON.parse(blocks[0]), data, `${where}: the first text block is not data`);
  for (const [, key, value] of noteOf(res).matchAll(TAG)) {
    assert.equal(value, sc[key], `${where}: the text tags (${key}: ${value}) but structuredContent.${key} is ${JSON.stringify(sc[key])}`);
  }
  // method: in the envelope block, or verbatim in the block before it; never both, never neither.
  const quoted = typeof sc.method === "string" && said.includes(sc.method);
  if (has(env, "method")) assert.ok(!quoted, `${where}: the envelope block repeats method, which the block before it quotes verbatim`);
  else assert.ok(quoted, `${where}: the text's envelope has no method, and the block before it does not quote ${JSON.stringify(sc.method)}`);
  // notes: the envelope's own sentences, then the block before's, each verbatim there.
  if (has(env, "notes")) assert.ok(Array.isArray(env.notes) && env.notes.length > 0, `${where}: the envelope block sends notes ${JSON.stringify(env.notes)}; with none of its own it is left out`);
  const own = env.notes ?? [];
  const before = noteSentences(said);
  for (const s of before) assert.ok(said.includes(s), `${where}: the note's sentence is not verbatim in the block before the envelope: "${s}"`);
  const repeated = own.filter((s) => before.includes(s));
  assert.deepEqual(repeated, [], `${where}: the envelope block repeats the block before it`);
  assert.deepEqual(sc.notes, [...own, ...before], `${where}: structuredContent's notes are not the envelope block's notes followed by the sentences of the block before it`);
  // The whole: rebuilt from the blocks, the text is structuredContent without data.
  const rebuilt = { ...env, notes: [...own, ...before], ...(has(env, "method") ? {} : { method: sc.method }) };
  assert.deepEqual(rebuilt, withoutData, `${where}: the text's envelope, rebuilt, is not structuredContent without data`);
  return env;
}

// #2531: the repeat share, as a number. assertEnvelopeInText holds the structure #2467 set; this
// measures what that structure is for. For every text block after the first it counts the block's
// sentences that an earlier block already holds, verbatim, and gives the share: repeated sentences
// over sentences. What a model reads in a block is its sentences: a prose block (the note, a
// failure's message) split as the server splits a note, and a JSON block (the data, the envelope)
// split the same way string by string, so a note repeated inside JSON, as 2.1.0's notes array
// repeated it, is found sentence by sentence. A sentence is prose: words, ending in ".", "!" or
// "?". A value is not one: a timestamp, a state, an id, a radar's name, or a failure's quoted cause
// (error.message, which the message quotes inside its own sentence, #2313). The envelope carries
// such values on purpose, and they are held equal to structuredContent by the check above.
const IS_SENTENCE = /\s.*[.!?]$/;
function readBlock(block) {
  let strings;
  try {
    strings = stringsIn(JSON.parse(block));
  } catch {
    strings = [block];
  }
  const norm = strings.map((s) => s.replace(/\s+/g, " ").trim());
  return { text: norm.join("\n"), sentences: norm.flatMap(noteSentences).filter((s) => IS_SENTENCE.test(s)) };
}
// The repeats a success's note makes on purpose, each a sentence the data block before it (the API's
// JSON verbatim, #1874) also carries: the API's own method, which cve_exposure's note quotes
// ("Method: …", #2306), and Shodan's ownership, which a note on Shodan-derived data states (#2306)
// and such an answer's attribution string can state too (#2353). Only the note of a three-block
// success makes them; the same sentence in any other block, or in a result of any other shape, is a
// repeat like any other.
function quotedOnPurpose(res, i, s) {
  if (res.isError || textBlocks(res).length !== 3 || i !== 1) return false;
  const method = res.structuredContent?.data?.method;
  return s === SHODAN_OWNERSHIP || (typeof method === "string" && noteSentences(method).includes(s));
}
// Per block: its sentences, the ones an earlier block holds verbatim, and of those the ones not
// quoted on purpose. The envelope block is the last. Returns three shares: the envelope block's;
// every block's after the first (all); and the same less the quotes on purpose (other).
function repeatShare(res) {
  const read = textBlocks(res).map(readBlock);
  const blocks = read.map((b, i) => {
    const repeated = b.sentences.filter((s) => read.slice(0, i).some((e) => e.text.includes(s)));
    return { sentences: b.sentences, repeated, other: repeated.filter((s) => !quotedOnPurpose(res, i, s)) };
  });
  const share = (bs, key) => {
    const n = bs.reduce((k, b) => k + b.sentences.length, 0);
    const r = bs.reduce((k, b) => k + b[key].length, 0);
    return { sentences: n, repeated: r, share: n ? r / n : 0 };
  };
  return { blocks, envelope: share(blocks.slice(-1), "repeated"), all: share(blocks.slice(1), "repeated"), other: share(blocks.slice(1), "other") };
}
// The property, as numbers: the envelope block's repeat share is 0, and so is every block's besides
// the quotes on purpose. The test over every result and its control both call this.
function assertNoRepeat(where, res) {
  const r = repeatShare(res);
  assert.equal(r.envelope.share, 0, `${where}: the envelope block's repeat share is ${r.envelope.share}, ${r.envelope.repeated} of its ${r.envelope.sentences} sentences said by an earlier block: ${JSON.stringify(r.blocks.at(-1).repeated)}`);
  assert.equal(r.other.share, 0, `${where}: the repeat share across its blocks is ${r.other.share}, ${r.other.repeated} of ${r.other.sentences} sentences said by an earlier block: ${JSON.stringify(r.blocks.flatMap((b) => b.other))}`);
  return r;
}

// #2307: every numeric field exposure_radar may relay under shadow_ai, by normalised path
// ([] = any array element, * = any key of a category map), mapped to the name the note, the
// description and the README label it by. The group in the name is the label: observed (every
// Certificate Transparency or Shodan observation), confirmed_exposed (liveness active or
// rechecking), authentication (probe outcomes). A numeric field outside this set fails the
// enumeration test, so a field the backend adds later cannot reach a model unlabelled.
const SHADOW_AI_LABELLED = {
  "confirmed_exposed.total": "confirmed_exposed.total",
  "confirmed_exposed.by_category.*": "confirmed_exposed.by_category",
  "confirmed_exposed.last_24h": "confirmed_exposed.last_24h",
  "observed.total": "observed.total",
  "observed.by_category.*": "observed.by_category",
  "observed.last_24h": "observed.last_24h",
  "observed.trend_30d[].count": "observed.trend_30d",
  "observed.top_products[].count": "observed.top_products",
  "observed.top_countries[].count": "observed.top_countries",
  "observed.top_issuers[].count": "observed.top_issuers",
  "authentication.observed": "authentication.observed",
  "authentication.not_determined": "authentication.not_determined",
};
// The objects whose keys are data (category names), not field names.
const SHADOW_AI_MAPS = new Set(["observed.by_category", "confirmed_exposed.by_category"]);
const childPath = (p, k) => (SHADOW_AI_MAPS.has(p) || SHADOW_AI_MAPS.has(p.replace(/^shadow_ai\./, "")) ? `${p}.*` : p ? `${p}.${k}` : k);
// Every path to a number, and every field-name path, under a relayed value.
function numericPaths(v, p = "", out = new Set()) {
  if (typeof v === "number") out.add(p);
  else if (Array.isArray(v)) for (const x of v) numericPaths(x, `${p}[]`, out);
  else if (v !== null && typeof v === "object") for (const [k, x] of Object.entries(v)) numericPaths(x, childPath(p, k), out);
  return out;
}

// #2313 item 7: the same for the whole exposure_radar result, all five radars. Every numeric
// path, normalised as above, mapped to the name the note, the description and the README label
// it by. Each label was checked against the Go source at HEAD (core-backend/internal):
//   kev_exposure.distinct_hosts     kevexposure/store.go:413 COUNT(DISTINCT host), host = "ip:port" (poller.go:355)
//   kev_exposure.kev_cves_exposed   store.go:413 COUNT(DISTINCT cve_id)
//   kev_exposure.correlations       store.go:413 COUNT(*): one row per (host, CVE), obsID(host, cve) store.go:171
//   kev_exposure.ransomware_cves    store.go:414 COUNT(DISTINCT cve_id) FILTER (WHERE ransomware)
//   kev_exposure.ransomware_hosts   store.go:415 COUNT(DISTINCT host) FILTER (WHERE ransomware): services
//   kev_exposure.top_products       store.go:420-421 COUNT(DISTINCT host) per product, LIMIT 12
//   kev_exposure.top_cves           store.go:432-434 COUNT(DISTINCT host), MAX(cvss_v3), MAX(epss_score), LIMIT 12
//   kev_exposure.top_countries      store.go:452-453 COUNT(DISTINCT host) per country, LIMIT 10
//   kev_exposure.newest_kev         store.go:465-474 cves rows LEFT JOIN observation counts, COALESCE(e.h,0), LIMIT 15
//   kev_exposure.trend              store.go:486-489 COUNT(*) per date_trunc('week', first_seen): pairs, 12 weeks
//   exposed_databases.distinct_hosts / .engines   exposeddb/store.go:406-408, host = "ip:port" (poller.go:557)
//   exposed_databases.pii_likely / .pci_likely    exposeddb/store.go:410-419, gate = classify.go:75-112, names only classify.go:8-23
//   exposed_databases.top_engines / .top_countries exposeddb/store.go:421-423, 433-435 (LIMIT 15 / 10)
//   leaked_credentials.total / .distinct_secrets / .distinct_repos   leakedcreds/store.go:205-207,
//                                   one row per (repo, secret) store.go:46-50
//   leaked_credentials.top_providers / .top_types leakedcreds/store.go:209-221 COUNT(*), LIMIT 15
//   none validated                  leakedcreds/detect.go:29-33 ("verified" = structural, never live)
//   mcp_servers.* (#2315)           aiexposure handler.go MCPPublicCounts and the #2315 contract:
//                                   one hostname per row, latest verdict; protected = RFC 9728
//                                   validated (prm.go), each partition adds up to the count it divides
const RADAR_LABELLED = {
  "kev_exposure.distinct_hosts": "kev_exposure.distinct_hosts",
  "kev_exposure.ransomware_hosts": "kev_exposure.ransomware_hosts",
  "kev_exposure.kev_cves_exposed": "kev_exposure.kev_cves_exposed",
  "kev_exposure.ransomware_cves": "kev_exposure.ransomware_cves",
  "kev_exposure.correlations": "kev_exposure.correlations",
  "kev_exposure.top_products[].hosts": "kev_exposure.top_products",
  "kev_exposure.top_countries[].hosts": "kev_exposure.top_countries",
  "kev_exposure.top_cves[].hosts": "kev_exposure.top_cves",
  "kev_exposure.top_cves[].cvss_v3_score": "kev_exposure.top_cves[].cvss_v3_score",
  "kev_exposure.top_cves[].epss_score": "kev_exposure.top_cves[].epss_score",
  "kev_exposure.trend[].new_exposures": "kev_exposure.trend",
  "kev_exposure.newest_kev[].exposed_hosts": "kev_exposure.newest_kev[].exposed_hosts",
  "kev_exposure.newest_kev[].cvss_v3_score": "kev_exposure.newest_kev[].cvss_v3_score",
  "kev_exposure.newest_kev[].epss_score": "kev_exposure.newest_kev[].epss_score",
  "exposed_databases.distinct_hosts": "exposed_databases.distinct_hosts",
  "exposed_databases.engines": "exposed_databases.engines",
  "exposed_databases.pii_likely": "exposed_databases.pii_likely",
  "exposed_databases.pci_likely": "exposed_databases.pci_likely",
  "exposed_databases.top_engines[].hosts": "exposed_databases.top_engines",
  "exposed_databases.top_countries[].hosts": "exposed_databases.top_countries",
  "leaked_credentials.total": "leaked_credentials.total",
  "leaked_credentials.distinct_secrets": "leaked_credentials.distinct_secrets",
  "leaked_credentials.distinct_repos": "leaked_credentials.distinct_repos",
  "leaked_credentials.top_providers[].count": "leaked_credentials.top_providers",
  "leaked_credentials.top_types[].count": "leaked_credentials.top_types",
  ...Object.fromEntries(Object.entries(SHADOW_AI_LABELLED).map(([p, name]) => [`shadow_ai.${p}`, name])),
  // Every mcp_servers number is labelled by its own full path.
  ...Object.fromEntries(
    [
      "total",
      "protected",
      "pending_readjudication",
      "not_assessed",
      "own_controls_excluded",
      ...["not_assessed_by_reason", "prm_via", "era", "transport"].flatMap((p) => Object.keys(MCP_STATS[p]).map((b) => `${p}.${b}`)),
    ].map((k) => [`mcp_servers.${k}`, `mcp_servers.${k}`]),
  ),
};
// The numeric paths of a relayed exposure_radar result that carry no label.
const unlabelledIn = (data) => [...numericPaths(data)].filter((p) => !(p in RADAR_LABELLED)).sort();
function keyPaths(v, p = "", out = new Set()) {
  if (Array.isArray(v)) for (const x of v) keyPaths(x, `${p}[]`, out);
  else if (v !== null && typeof v === "object") {
    for (const [k, x] of Object.entries(v)) {
      const c = childPath(p, k);
      out.add(c);
      keyPaths(x, c, out);
    }
  }
  return out;
}
const numbersUnder = (v) => {
  const out = new Set();
  const walk = (x) => {
    if (typeof x === "number") out.add(x);
    else if (x !== null && typeof x === "object") for (const y of Object.values(x)) walk(y);
  };
  walk(v);
  return out;
};
// A reader's unit of text: a sentence. Field names (observed.total, crt.sh) carry no space
// after their dot, so they do not split one.
const sentencesOf = (t) => t.replace(/\s+/g, " ").split(/(?<=[.!?])\s+/);
// The README read the same way, except that each table row is its own unit.
const readmeUnits = (md) =>
  md.split(/\n\s*\n/).flatMap((block) => {
    const lines = block.split("\n").filter((l) => l.trim());
    return lines.length && lines.every((l) => l.trim().startsWith("|")) ? lines : sentencesOf(block);
  });
// "exposed" said of an observed thing is allowed only as a denial: "not" within the 30
// characters before it ("observed, not exposed", "not a count of exposed services").
const denied = (s, i) => /\bnot\b/.test(s.slice(Math.max(0, i - 30), i));
// Any sentence of `text` carrying a number that exists only under observed or authentication
// (not also a confirmed_exposed number) must not call it exposed. Returns how many such
// numbers it found in the text, so a caller can prove it was not vacuous.
function assertNoObservedNumberCalledExposed(where, text, shadowAI) {
  const confirmed = numbersUnder(shadowAI.confirmed_exposed);
  const observedOnly = [...numbersUnder([shadowAI.observed, shadowAI.authentication])].filter((n) => !confirmed.has(n));
  let checked = 0;
  for (const s of sentencesOf(text)) {
    const carried = observedOnly.filter((n) =>
      new RegExp(`(?<![\\d.,])(?:${n}|${n.toLocaleString("en-US")})(?![\\d]|,\\d)`).test(s),
    );
    if (!carried.length) continue;
    checked += carried.length;
    for (const m of s.matchAll(/exposed/gi)) {
      assert.ok(denied(s, m.index), `${where}: observed number(s) ${carried.join(", ")} called exposed in: "${s}"`);
    }
  }
  return checked;
}
// A sentence that names an observed or authentication field may use "exposed" only as a
// denial or in the name of the other group, confirmed_exposed.
const OBSERVED_FIELD = /\bshadow_ai\.(?:observed|authentication)\b|\bobserved\.[a-z_0-9]+|\bauthentication\.(?:observed|not_determined)\b/;
function assertObservedFieldsNotCalledExposed(where, units) {
  let checked = 0;
  for (const u of units) {
    if (!OBSERVED_FIELD.test(u)) continue;
    checked++;
    for (const m of u.matchAll(/exposed/gi)) {
      if (/confirmed_$/.test(u.slice(0, m.index))) continue;
      assert.ok(denied(u, m.index), `${where}: an observed field called exposed in: "${u}"`);
    }
  }
  return checked;
}

// ── #2311 / #2313: the structured result ──

// What every tool declares: read-only, no side effects, repeatable, and it reaches the open
// internet (the EchelonGraph API). Annotations are hints a client MUST treat as untrusted.
const ANNOTATIONS = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true };
const STATES = ["measured", "not_assessed", "failed", "invalid_input"];
// The tools whose numbers are exposure numbers: every number anywhere in their data.
const EXPOSURE_TOOLS = new Set(["cve_exposure", "exposure_radar"]);
const realInstant = (s) => typeof s === "string" && Date.parse(s) > 0;

// A JSON Schema validator: ajv 8 as the SDK bundles it, dispatching on the schema's $schema
// dialect (2020-12 here). It is what an MCP client runs over structuredContent.
const validator = new AjvJsonSchemaValidator();
function assertValid(where, schema, value) {
  const v = validator.getValidator(schema)(value);
  assert.ok(v.valid, `${where}: structuredContent does not validate against the outputSchema: ${v.errorMessage}\n${JSON.stringify(value).slice(0, 600)}`);
}
const isValid = (schema, value) => validator.getValidator(schema)(value).valid;

// #2313 done-means 5: every exposure number in a result has a non-null measured_at and a
// method, or the result's state is not measured. Walks one structuredContent; returns how many
// exposure numbers it found under a measured state, so a caller can prove it was not vacuous.
function assertExposureNumbersDated(where, tool, sc) {
  if (!EXPOSURE_TOOLS.has(tool)) return 0;
  let n = 0;
  const walk = (v, p) => {
    if (typeof v === "number") {
      if (sc.state !== "measured") return;
      n++;
      assert.ok(realInstant(sc.measured_at), `${where}: ${p} = ${v} is under state measured with measured_at ${JSON.stringify(sc.measured_at)}`);
      assert.ok(typeof sc.method === "string" && sc.method.length > 0, `${where}: ${p} = ${v} is under state measured with no method`);
    } else if (Array.isArray(v)) v.forEach((x, i) => walk(x, `${p}[${i}]`));
    else if (v !== null && typeof v === "object") for (const [k, x] of Object.entries(v)) walk(x, `${p}.${k}`);
  };
  walk(sc.data, "data");
  return n;
}

// Every path to a number the schema allows, normalised as numericPaths does: [] for an array
// element, .* for a map value.
function schemaNumericPaths(s, p = "", out = new Set()) {
  if (s === null || typeof s !== "object") return out;
  const types = [].concat(s.type ?? []);
  if (types.includes("number") || types.includes("integer")) out.add(p);
  for (const k of ["anyOf", "oneOf", "allOf"]) for (const x of s[k] ?? []) schemaNumericPaths(x, p, out);
  if (s.items) schemaNumericPaths(s.items, `${p}[]`, out);
  if (s.properties) for (const [k, x] of Object.entries(s.properties)) schemaNumericPaths(x, p ? `${p}.${k}` : k, out);
  if (s.additionalProperties && typeof s.additionalProperties === "object" && Object.keys(s.additionalProperties).length) {
    schemaNumericPaths(s.additionalProperties, `${p}.*`, out);
  }
  return out;
}
// Every property name and every string enum value a schema holds, at any depth.
function schemaNames(s, out = new Set()) {
  if (s === null || typeof s !== "object") return out;
  if (Array.isArray(s)) {
    for (const x of s) schemaNames(x, out);
    return out;
  }
  for (const e of s.enum ?? []) if (typeof e === "string") out.add(e);
  if (s.properties) for (const k of Object.keys(s.properties)) out.add(k);
  for (const [k, x] of Object.entries(s)) if (k !== "enum" && k !== "description") schemaNames(x, out);
  return out;
}
// Every description string a schema holds, at any depth (a property named `description`, such as
// get_cve's, is a schema, and is walked).
function schemaDescriptions(s, out = []) {
  if (Array.isArray(s)) for (const x of s) schemaDescriptions(x, out);
  else if (s !== null && typeof s === "object") {
    for (const [k, x] of Object.entries(s)) {
      if (k === "description" && typeof x === "string") out.push(x);
      else schemaDescriptions(x, out);
    }
  }
  return out;
}
// #2465: a sentence that denies the numbers in an answer are findings, in any of the ways it has
// been or could be written: 2.1.0's schema said "no number in it is a finding", and its code
// comment "Its numbers are not findings". Scoped to numbers, counts and figures, so a failure's
// "this is not a finding" and "a zero … is not a finding of no exposure" are not matched: those
// are said of an answer that relays no count, or of a zero.
const DENIES_FINDINGS = [
  /\bno (?:number|count|figure)s?\b[^.;]*?\b(?:is|are)\b[^.;]*?\bfindings?\b/i,
  /\bnone of (?:it|its|the|these|those)\b[^.;]*?\b(?:numbers?|counts?|figures?)\b[^.;]*?\bfindings?\b/i,
  /\b(?:numbers|counts|figures)\b[^.;]*?\b(?:is|are) not (?:a )?findings?\b/i,
];
// Returns how many sentences it read, so a caller can prove it was not vacuous.
function assertNoFindingDenied(where, units) {
  for (const u of units) for (const re of DENIES_FINDINGS) assert.doesNotMatch(u, re, `${where}: a sentence denies the numbers are findings: "${u}"`);
  return units.length;
}
// The success and failure branches of an outputSchema, by the states each admits.
const branchOf = (schema, state) => (schema.oneOf ?? []).find((b) => b.properties?.state?.enum?.includes(state));
// A field name as a description or the README writes it: snake_case, one underscore at least.
const FIELD_TOKEN = /\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b/g;
// A sentence naming a re-probe (re-check, re-verification) together with an interval: "every
// 24 h", "a 24-hour re-probe", "daily". The published re-probe interval applies only to hosts
// EchelonGraph does not own, so any sentence that names one must say so. A window ("in the last
// 24 h") is not an interval.
const REPROBE = /\bre-?(?:probe|check|verif)\w*/i;
const INTERVAL =
  /\bevery\s+\d+(?:\.\d+)?\s*(?:h|hrs?|hours?|d|days?|min|minutes?)\b|\b\d+(?:\.\d+)?\s*-?\s*(?:h|hrs?|hours?|days?|minutes?)\s+(?:re-?probe|re-?check|re-?verif|interval|cadence)|\b(?:hourly|daily|weekly)\b/i;
function assertReprobeIntervalsQualified(where, units) {
  let named = 0;
  for (const u of units) {
    if (!REPROBE.test(u) || !INTERVAL.test(u)) continue;
    named++;
    assert.ok(u.includes("for hosts we do not own"), `${where}: a re-probe interval without "for hosts we do not own": "${u}"`);
  }
  return named;
}

// The P1 property. Asserted on its own so a pre-fix run shows exactly which tools answer a
// failure with a success.
function assertErrorResult(name, res) {
  assert.equal(res.isError, true, `${name}: expected isError=true, got ${brief(res)}`);
}

// The wording property: an error must say which tool, what failed, and where it looked.
function assertNames(name, res, base, ...phrases) {
  const t = textOf(res);
  assert.match(t, new RegExp(`\\b${name}\\b`), `${name}: error text does not name the tool: ${t}`);
  assert.ok(t.includes(base), `${name}: error text does not name the base URL ${base}: ${t}`);
  for (const p of phrases) assert.match(t, p, `${name}: error text lacks ${p}: ${t}`);
}

describe(`failure polarity: unreachable base (ECHELONGRAPH_API_BASE=http://127.0.0.1:1) [${ERA}]`, () => {
  const base = "http://127.0.0.1:1";
  let client, results;
  before(async () => {
    client = await spawnServer({ ECHELONGRAPH_API_BASE: base, ECHELONGRAPH_API_TIMEOUT_MS: "2000" });
    results = await callAll(client);
  });
  // A client that never connected (a failed opening) leaves nothing to close.
  after(() => client?.close());
  for (const name of TOOLS) {
    it(`${name} returns an error result, not a success with null fields`, () => assertErrorResult(name, results[name]));
    it(`${name} error text names the tool, the failure and the base URL`, () =>
      assertNames(name, results[name], base, /could not be reached/));
  }
});

describe(`failure polarity: connection refused [${ERA}]`, () => {
  let client, results, base;
  before(async () => {
    base = `http://127.0.0.1:${await refusedPort()}`;
    client = await spawnServer({ ECHELONGRAPH_API_BASE: base, ECHELONGRAPH_API_TIMEOUT_MS: "2000" });
    results = await callAll(client);
  });
  // A client that never connected (a failed opening) leaves nothing to close.
  after(() => client?.close());
  for (const name of TOOLS) {
    it(`${name} returns an error result`, () => assertErrorResult(name, results[name]));
    it(`${name} error text names ECONNREFUSED and the base URL`, () =>
      assertNames(name, results[name], base, /could not be reached/, /ECONNREFUSED/));
  }
});

// Two timeouts, on purpose. The "hangs past the timeout" block needs a short one: it
// asserts the "within 500 ms" wording, and a hanging upstream fails at the timeout however busy
// the machine is. Every other block asserts what the upstream ANSWERED (403, non-JSON, null, 200
// …), and with a 500 ms budget the first request after the server spawns could miss it when
// several test files run in parallel on a busy CPU — measured 3 failing runs in 10 on a 4-core
// box, each "did not answer … within 500 ms" where HTTP 403 was expected. So the answer modes get
// a budget no answer misses (the stub replies at once), and only the hang block runs against a
// server spawned with the 500 ms budget its assertion names.
const ANSWER_TIMEOUT_MS = "10000";
const HANG_TIMEOUT_MS = "500";

describe(`against a stub API [${ERA}]`, () => {
  let stub, client;
  before(async () => {
    stub = await startStub();
    client = await spawnServer({ ECHELONGRAPH_API_BASE: stub.base, ECHELONGRAPH_API_TIMEOUT_MS: ANSWER_TIMEOUT_MS });
  });
  // The stub is closed even when the opening failed: an open listener would keep this file's
  // process alive after its last test, and node --test would wait on it forever.
  after(async () => {
    try {
      await client?.close();
    } finally {
      await stub?.close();
    }
  });

  describe("failure polarity: upstream answers HTTP 403", () => {
    let results;
    before(async () => { stub.state.mode = "403"; results = await callAll(client); });
    for (const name of TOOLS) {
      it(`${name} returns an error result`, () => assertErrorResult(name, results[name]));
      it(`${name} error text names HTTP 403 and the base URL`, () =>
        assertNames(name, results[name], stub.base, /HTTP 403/));
    }
  });

  describe("failure polarity: upstream hangs past the timeout", () => {
    // Its own server, with the short budget the assertion names (see HANG_TIMEOUT_MS above).
    let results, hangClient;
    before(async () => {
      hangClient = await spawnServer({ ECHELONGRAPH_API_BASE: stub.base, ECHELONGRAPH_API_TIMEOUT_MS: HANG_TIMEOUT_MS });
      stub.state.mode = "hang";
      results = await callAll(hangClient);
    });
    after(async () => { await hangClient?.close(); });
    for (const name of TOOLS) {
      it(`${name} returns an error result`, () => assertErrorResult(name, results[name]));
      it(`${name} error text names the timeout and the base URL`, () =>
        assertNames(name, results[name], stub.base, /did not answer/, new RegExp(`within ${HANG_TIMEOUT_MS} ms`)));
    }
  });

  describe("failure polarity: upstream answers 200 with a non-JSON body", () => {
    let results;
    before(async () => { stub.state.mode = "html"; results = await callAll(client); });
    for (const name of TOOLS) {
      it(`${name} returns an error result`, () => assertErrorResult(name, results[name]));
      it(`${name} error text says the body was not JSON`, () =>
        assertNames(name, results[name], stub.base, /was not JSON/));
    }
  });

  describe("failure polarity: upstream answers 200 with JSON null", () => {
    let results;
    before(async () => { stub.state.mode = "null"; results = await callAll(client); });
    for (const name of TOOLS) {
      it(`${name} returns an error result`, () => assertErrorResult(name, results[name]));
      it(`${name} error text says the body was not a JSON object`, () =>
        assertNames(name, results[name], stub.base, /was not a JSON object/));
    }
  });

  describe("success polarity: upstream answers 200 with data", () => {
    let results;
    before(async () => { stub.state.mode = "ok"; stub.state.seen.length = 0; results = await callAll(client); });
    for (const name of TOOLS) {
      it(`${name} is not an error and its first block is the API's JSON`, () => {
        const res = results[name];
        assert.notEqual(res.isError, true, `${name}: unexpected error: ${brief(res)}`);
        assert.doesNotThrow(() => JSON.parse(res.content[0].text), `${name}: first block is not JSON`);
      });
      it(`${name} carries a note that says it succeeded, and where`, () => {
        const t = textOf(results[name]);
        assert.match(t, new RegExp(`\\b${name} OK\\b`), `${name}: no OK note: ${t}`);
        assert.ok(t.includes(stub.base), `${name}: note does not name the base URL: ${t}`);
        assert.doesNotMatch(t, /found nothing/, `${name}: a populated answer must not read as empty: ${t}`);
      });
    }
    it("cve_summary returns the feed totals", () => {
      assert.equal(JSON.parse(results.cve_summary.content[0].text).summary.total, 381274);
    });
    it("search_cves forwards the filters and returns the rows", () => {
      // #1983: the term travels in X-EG-Search, never in the URL (Cloud Run keeps URLs in traces).
      assert.ok(stub.state.seen.includes("/api/v1/public/cves?limit=2"), `seen: ${stub.state.seen}`);
      assert.ok(!stub.state.seen.some((u) => u.includes("tomcat")), `the term is in a URL: ${stub.state.seen}`);
      assert.ok((stub.state.searchHeaders ?? []).includes("tomcat"), "the term did not arrive in X-EG-Search");
      const data = JSON.parse(results.search_cves.content[0].text);
      assert.equal(data.total, 1);
      assert.equal(data.cves[0].cve_id, CVE);
    });
    it("get_cve returns the record", () => {
      const data = JSON.parse(results.get_cve.content[0].text);
      assert.equal(data.cve_id, CVE);
      assert.equal(data.echelongraph_score, 9);
    });
    it("cve_exposure returns the footprint", () => {
      const data = JSON.parse(results.cve_exposure.content[0].text);
      assert.equal(data.exposed_hosts, 6213);
      assert.equal(data.countries, 107);
    });
    it("exposure_radar returns all five radars, none null", () => {
      const data = JSON.parse(results.exposure_radar.content[0].text);
      assert.equal(data.mcp_servers.total, 10217);
      assert.equal(data.mcp_servers.protected, 611);
      assert.equal(data.kev_exposure.distinct_hosts, 25113);
      assert.equal(data.exposed_databases.distinct_hosts, 7380);
      assert.equal(data.leaked_credentials.total, 531);
      assert.equal(data.shadow_ai.observed.total, 36222);
      assert.equal(data.shadow_ai.confirmed_exposed.total, 2000);
    });
  });

  // The control that keeps the fix honest: an empty answer is a measurement, not a failure.
  describe("genuine-empty control: upstream answers 200 with zero rows", () => {
    let results;
    before(async () => { stub.state.mode = "empty"; results = await callAll(client); });
    for (const name of ["cve_summary", "search_cves", "cve_exposure", "exposure_radar"]) {
      it(`${name} is a SUCCESS, not an error`, () => {
        const res = results[name];
        assert.notEqual(res.isError, true, `${name}: an empty answer was rendered as an error: ${brief(res)}`);
        assert.doesNotThrow(() => JSON.parse(res.content[0].text), `${name}: first block is not JSON`);
      });
    }
    for (const name of ["cve_summary", "search_cves", "cve_exposure"]) {
      it(`${name} says in words that it looked and found nothing`, () => {
        const t = textOf(results[name]);
        assert.match(t, new RegExp(`\\b${name} OK\\b`), `${name}: no OK note: ${t}`);
        assert.match(t, /found nothing/, `${name}: empty answer is not worded as such: ${t}`);
        assert.match(t, /not a lookup failure/, `${name}: empty answer does not rule out a failure: ${t}`);
        assert.doesNotMatch(t, /FAILED/, `${name}: empty answer reads as a failure: ${t}`);
      });
    }
    it("search_cves reports zero matches", () => {
      assert.equal(JSON.parse(results.search_cves.content[0].text).total, 0);
    });
    it("cve_exposure reports a measured zero", () => {
      assert.equal(JSON.parse(results.cve_exposure.content[0].text).exposed_hosts, 0);
    });
    // The live API answers an unknown CVE with 404 + its own message. That is not a 200 with
    // zero rows, so it stays an error result — but the API's message must be quoted verbatim
    // so the model sees the backend's own words, not a bare status code.
    it("get_cve on the API's 404 is an error result that quotes the API's message", () => {
      const res = results.get_cve;
      assertErrorResult("get_cve", res);
      assertNames("get_cve", res, stub.base, /HTTP 404/, new RegExp(`CVE not found: ${CVE}`));
    });
  });

  // #2306: the package's own copy makes no claim the data cannot back. Both polarities: the
  // claims are absent from every description, note and packaged text, and what replaces them
  // (the method, the Shodan attribution) is present.
  describe("#2306: no removed claim in any tool text, and the method is named", () => {
    let tools;
    const notes = [];
    // #2440: the envelope block of each of the same results, as the strings it carries, and
    // (#2467) the text block just before it, whose sentences the envelope block no longer repeats.
    const envelopes = [];
    before(async () => {
      ({ tools } = await client.listTools());
      for (const mode of ["ok", "empty", "403"]) {
        stub.state.mode = mode;
        const results = await callAll(client);
        for (const name of TOOLS) {
          notes.push([`${name}/${mode}`, noteOf(results[name])]);
          envelopes.push([`${name}/${mode} envelope block`, envelopeWords(results[name]), textBlocks(results[name]).at(-2)]);
        }
      }
      stub.state.mode = "ok";
      for (const id of [CVE_UNTRACKED, CVE_UNTRACKED_STALE, CVE_OLD_API, CVE_REJECTED, "not-a-cve"]) {
        const res = await client.callTool({ name: "cve_exposure", arguments: { cve_id: id } });
        notes.push([`cve_exposure/${id}`, noteOf(res)]);
        envelopes.push([`cve_exposure/${id} envelope block`, envelopeWords(res), textBlocks(res).at(-2)]);
      }
    });
    it("no tool description or argument description makes a removed claim", () => {
      for (const t of tools) {
        assert.doesNotMatch(t.description, REMOVED_CLAIMS, `${t.name} description: ${t.description}`);
        for (const [arg, schema] of Object.entries(t.inputSchema?.properties ?? {})) {
          assert.doesNotMatch(schema.description ?? "", REMOVED_CLAIMS, `${t.name}.${arg}: ${schema.description}`);
        }
      }
    });
    it("no result note or failure text makes a removed claim", () => {
      assert.ok(notes.length >= 20, `only ${notes.length} notes collected`);
      for (const [where, note] of notes) assert.doesNotMatch(note, REMOVED_CLAIMS, `${where}: ${note}`);
    });
    it("#2440: no envelope block makes a removed claim or calls a count hosts", () => {
      assert.equal(envelopes.length, notes.length, "an envelope block for every note");
      for (const [where, e] of envelopes) {
        assert.doesNotMatch(e, REMOVED_CLAIMS, `${where}: ${e}`);
        assert.doesNotMatch(e, HOST_UNIT, `${where}: ${e}`);
      }
    });
    // The note quotes the API's method sentence verbatim, so the guard above only covers
    // what the API really sends if the notes it read carried that sentence.
    it("the notes checked above include the backend's own method sentence, quoted once", () => {
      const quoting = notes.filter(([, n]) => n.includes(`Method: ${BACKEND_METHOD} Exposure counts`));
      assert.ok(quoting.length >= 3, `only ${quoting.length} notes quote BACKEND_METHOD: ${notes.map(([w]) => w).join(", ")}`);
    });
    it("every count is worded as ip:port services, never as hosts", () => {
      for (const t of tools) assert.doesNotMatch(t.description, HOST_UNIT, `${t.name} description: ${t.description}`);
      for (const [where, note] of notes) assert.doesNotMatch(note, HOST_UNIT, `${where}: ${note}`);
      assert.doesNotMatch(readPkgFile("README.md"), HOST_UNIT);
      assert.doesNotMatch(PKG.description, HOST_UNIT);
      assert.match(tools.find((t) => t.name === "cve_exposure").description, /distinct ip:port/);
      assert.match(tools.find((t) => t.name === "exposure_radar").description, /distinct ip:port/);
    });
    it("README, package.json description and server.json description make no removed claim", () => {
      assert.doesNotMatch(readPkgFile("README.md"), REMOVED_CLAIMS);
      assert.doesNotMatch(PKG.description, REMOVED_CLAIMS);
      assert.doesNotMatch(JSON.parse(readPkgFile("server.json")).description, REMOVED_CLAIMS);
    });
    it("cve_exposure's description names the method and attributes Shodan", () => {
      const d = tools.find((t) => t.name === "cve_exposure").description;
      assert.match(d, /derived from Shodan data/);
      assert.match(d, /up to 100 ip:port services per query/);
      assert.match(d, /Every 12 h/);
      assert.match(d, /NOT ASSESSED/);
    });
    it("every cve_exposure success note names the method and attributes Shodan", () => {
      const successes = notes.filter(([where, n]) => where.startsWith("cve_exposure/") && /\bcve_exposure OK\b/.test(n));
      assert.ok(successes.length >= 4, `only ${successes.length} cve_exposure successes`);
      for (const [where, n] of successes) {
        assert.match(n, /Method: /, `${where}: ${n}`);
        assert.match(n, /Exposure counts are derived from Shodan data\./, `${where}: ${n}`);
      }
    });
    it("README and package.json attribute the exposure data to Shodan", () => {
      assert.match(readPkgFile("README.md"), /derived from Shodan data/);
      assert.match(PKG.description, /derived from Shodan data/);
    });

    // The wording rules below were each checked against the backend's code before they were
    // written; the comment on each names what it holds the text to.
    const flat = (s) => s.replace(/\s+/g, " ");
    // Every package-authored text a user or a model reads, README reflowed onto one line.
    const shipped = () => [
      ...tools.map((t) => [`${t.name} description`, t.description]),
      // #2311: the server instructions every client receives in the opening exchange.
      ["server instructions", client.opening.instructions],
      ...notes,
      ...envelopes,
      ["README.md", flat(readPkgFile("README.md"))],
      ["package.json description", PKG.description],
      ["server.json description", JSON.parse(readPkgFile("server.json")).description],
    ];

    // kevexposure/poller.go runOnce skips the Shodan search when shodan.HasQueryBudget says
    // fewer than SHODAN_MIN_QUERY_BUDGET credits remain, so the cadence is never unconditional.
    it("every statement of the 12 h search cadence says it runs only when Shodan query credits allow", () => {
      let checked = 0;
      for (const [where, t] of shipped()) {
        for (const m of t.matchAll(/every 12 (?:h|hours)\b/gi)) {
          checked++;
          const after = t.slice(m.index + m[0].length, m.index + m[0].length + 40);
          assert.match(after, /^,? when Shodan query credits allow/, `${where}: "${t.slice(m.index, m.index + 80)}"`);
        }
      }
      // The description, the README, and the notes quoting both the backend's method and the
      // fallback one: a guard that matched nothing would pass on nothing.
      assert.ok(checked >= 6, `only ${checked} cadence statements checked`);
    });

    // kevexposure store.go Upsert sets last_seen to now() when a search matches the banner, and
    // poller.go reconcileStale Touches it to now() when InternetDB still lists the PORT, without
    // re-reading the version. So last_seen is EchelonGraph's write or refresh time (#2439): no
    // sighting of the service, no re-sighting of the vulnerable banner, and a patched service
    // can stay counted.
    it("#2439: last_seen is described as a write or refresh time, never as a sighting of the service", () => {
      let checked = 0;
      for (const [where, t] of shipped()) {
        assert.doesNotMatch(t, /re-seen|most recently seen|last seen listening|not seen on its port/i, `${where}: ${t}`);
        if (/last_seen/.test(t)) checked++;
      }
      // The description, the README, and every note and envelope block that quotes the method.
      assert.ok(checked >= 6, `only ${checked} texts naming last_seen checked`);
      const rule = /`?last_seen`? is when EchelonGraph last wrote or refreshed a service's row, not when the service was observed/;
      assert.match(tools.find((t) => t.name === "cve_exposure").description, rule);
      assert.match(flat(readPkgFile("README.md")), rule);
      assert.match(BACKEND_METHOD, rule, "the fixture no longer carries the backend's wording");
      // Still: the re-check reads the port, not the version.
      for (const t of [tools.find((x) => x.name === "cve_exposure").description, flat(readPkgFile("README.md")), BACKEND_METHOD]) {
        assert.match(t, /without re-reading the banner, so a patched service can stay counted while its port stays open/);
      }
    });

    // The KEV fetcher (internal/cve/kev/fetcher.go) only UPDATEs existing cves rows, and the
    // API answers kev_catalog_listed:false when there is no row, so false is not a statement
    // about the CISA catalog.
    it("no note states CISA-KEV catalog membership as fact; it says what EchelonGraph's record holds", () => {
      let checked = 0;
      for (const [where, n] of notes) {
        assert.doesNotMatch(n, /is (?:not )?listed in the CISA-KEV catalog/, `${where}: ${n}`);
        if (/EchelonGraph's CVE (?:record|data) (?:marks|does not mark)/.test(n)) checked++;
      }
      assert.ok(checked >= 3, `only ${checked} notes carry a KEV sentence`);
    });

    // The backend omits `tracked` on purpose when it cannot decide (store.go trackedVerdict),
    // not only on an older API.
    it("the README's absent-tracked row does not blame an older API alone", () => {
      const readme = flat(readPkgFile("README.md"));
      assert.doesNotMatch(readme, /no `tracked` field \(older API\)/);
      assert.match(readme, /no `tracked` field \| The API did not say whether the CVE is in the tracked set: an older API, or the radar cannot decide/);
    });

    // A count over at most 100 Shodan results per product query is not a census, so no text
    // may invite reading it as one.
    it("no text or suggested prompt invites an internet-wide census reading", () => {
      for (const [where, t] of shipped()) {
        assert.doesNotMatch(t, /how exposed is the internet|how much of the internet|internet is exposed/i, `${where}: ${t}`);
      }
      assert.match(flat(readPkgFile("README.md")), /how many exposed services does EchelonGraph's radar have on record for it\?/);
    });

    // #2311: EchelonGraph's published re-probe interval applies only to hosts it does not own, so
    // any sentence naming a re-probe (or re-check) interval must say "for hosts we do not own".
    // The package names none today; the guard keeps a later edit from naming one bare.
    it("no shipped sentence names a re-probe interval without \"for hosts we do not own\"", () => {
      for (const [where, t] of shipped()) assertReprobeIntervalsQualified(where, sentencesOf(t));
      assertReprobeIntervalsQualified("README.md", readmeUnits(readPkgFile("README.md")));
      // The guard can fail: a bare interval is caught, and the qualified one passes.
      assert.throws(() => assertReprobeIntervalsQualified("mutant", ["The radar re-probes every service every 24 h."]), /for hosts we do not own/);
      assert.equal(assertReprobeIntervalsQualified("control", ["The radar re-probes every 24 h for hosts we do not own."]), 1);
      assert.throws(() => assertReprobeIntervalsQualified("mutant", ["Each service gets a 24-hour re-check."]), /for hosts we do not own/);
      assert.throws(() => assertReprobeIntervalsQualified("mutant", ["Exposed services are re-verified daily."]), /for hosts we do not own/);
    });

    // #2306 reopened: Shodan's terms require materials based on Shodan information to
    // "clearly indicate Shodan's ownership and copyright in the applicable Shodan materials".
    // Attribution alone is half of it. Both polarities: the ownership sentence sits beside the
    // attribution, and nothing claims EchelonGraph copyright over Shodan-derived data.
    it("cve_exposure's description indicates Shodan's ownership and copyright beside the attribution", () => {
      const d = tools.find((t) => t.name === "cve_exposure").description;
      assert.ok(d.includes(`exposure counts are derived from Shodan data. ${SHODAN_OWNERSHIP}`), d);
    });
    it("every cve_exposure success note indicates Shodan's ownership and copyright beside the attribution", () => {
      const successes = notes.filter(([where, n]) => where.startsWith("cve_exposure/") && /\bcve_exposure OK\b/.test(n));
      assert.ok(successes.length >= 4, `only ${successes.length} cve_exposure successes`);
      for (const [where, n] of successes) {
        assert.ok(n.includes(`Exposure counts are derived from Shodan data. ${SHODAN_OWNERSHIP}`), `${where}: ${n}`);
      }
    });
    it("README indicates Shodan's ownership and copyright beside the attribution, and in its License section", () => {
      const intro = flat(readPkgFile("README.md").split(/^## Tools$/m)[0]);
      assert.ok(intro.includes(`Exposure counts are derived from Shodan data. ${SHODAN_OWNERSHIP}`), `README intro: ${intro}`);
      const license = flat(readPkgFile("README.md").split(/^## License$/m)[1] ?? "");
      assert.ok(license.includes(`Exposure counts are derived from Shodan data. ${SHODAN_OWNERSHIP}`), `License section: ${license}`);
    });
    it("every shipped text that names Shodan indicates Shodan's ownership and copyright", () => {
      let checked = 0;
      for (const [where, t, before] of shipped()) {
        if (!/Shodan/.test(t)) continue;
        checked++;
        // server.json's description is capped at 100 characters by the registry schema, so
        // it carries the short form; the README it points to carries the sentence.
        if (where === "server.json description") assert.match(t, /Shodan data \(© Shodan\)/, `${where}: ${t}`);
        // #2467: an envelope block no longer repeats the note just before it, which states
        // Shodan's ownership in the same result; the block names Shodan in method or in its own
        // notes (last_seen), and is read after that note. The note is itself one of the texts
        // this loop checks, and structuredContent's notes carry the sentence (the walk at the end).
        else if (before !== undefined) assert.ok(t.includes(SHODAN_OWNERSHIP) || before.includes(SHODAN_OWNERSHIP), `${where}, and the block before it: ${before} ${t}`);
        else assert.ok(t.includes(SHODAN_OWNERSHIP), `${where}: ${t}`);
      }
      // Two tool descriptions, the cve_exposure and exposure_radar success notes, the README,
      // package.json and server.json: a guard that matched nothing would pass on nothing.
      assert.ok(checked >= 12, `only ${checked} texts naming Shodan checked`);
    });
    it("nothing claims EchelonGraph copyright over the data: © EchelonGraph covers only the CVE Pulse compilation", () => {
      const readme = flat(readPkgFile("README.md"));
      assert.doesNotMatch(readme, /Data © EchelonGraph/, "the README still asserts EchelonGraph copyright over all data");
      let owned = 0;
      for (const [where, t] of shipped()) {
        for (const m of t.matchAll(/© EchelonGraph/g)) {
          owned++;
          const lead = t.slice(Math.max(0, m.index - 160), m.index);
          assert.match(lead, /The CVE Pulse compilation \([^)]*\) is $/, `${where}: "${t.slice(Math.max(0, m.index - 160), m.index + 20)}"`);
        }
      }
      assert.equal(owned, 1, "the README's License section names what EchelonGraph owns, once");
      assert.match(readme, /EchelonGraph claims no ownership of it or copyright in it\./);
    });
    it("the MIT licence still covers the code", () => {
      assert.equal(PKG.license, "MIT");
      assert.match(flat(readPkgFile("README.md")), /## License The code is MIT-licensed\./);
    });
  });

  // The contract of GET /api/v1/public/kev-exposure/cve/:id, as the tool must read it.
  describe("cve_exposure: tracked, not assessed, measured zero, and invalid input", () => {
    const call = (cve_id) => client.callTool({ name: "cve_exposure", arguments: { cve_id } });
    before(() => { stub.state.mode = "ok"; });

    it("a malformed id is refused as invalid_input without a request", async () => {
      stub.state.seen.length = 0;
      for (const id of ["not-a-cve", "CVE-2023-123", "2023-44487", "CVE-2023-44487; DROP"]) {
        const res = await call(id);
        assertErrorResult("cve_exposure", res);
        const t = noteOf(res);
        assert.match(t, /invalid_input/, `${id}: ${t}`);
        assert.match(t, /Nothing was looked up/, `${id}: ${t}`);
        assert.doesNotMatch(t, /measured|found nothing/, `${id}: ${t}`);
        // The envelope block beside it says the same: nothing was measured.
        assert.equal(envelopeOf(res).state, "invalid_input", id);
        assert.equal(envelopeOf(res).measured_at, null, id);
      }
      assert.deepEqual(stub.state.seen, [], "a malformed id reached the API");
    });
    it("a lower-case id is accepted and sent in canonical upper case", async () => {
      stub.state.seen.length = 0;
      const res = await call(` ${CVE.toLowerCase()} `);
      assert.notEqual(res.isError, true, brief(res));
      assert.deepEqual(stub.state.seen, [`/api/v1/public/kev-exposure/cve/${CVE}`]);
    });
    it("HTTP 400 from the API is an error tagged invalid_input, never a measured zero", async () => {
      const res = await call(CVE_REJECTED);
      assertErrorResult("cve_exposure", res);
      assertNames("cve_exposure", res, stub.base, /invalid_input/, /HTTP 400/, /invalid CVE id/);
      assert.doesNotMatch(noteOf(res), /measured|found nothing|0 exposed/, noteOf(res));
      assert.doesNotMatch(envelopeWords(res), /measured|found nothing|0 exposed/, envelopeWords(res));
      assert.equal(envelopeOf(res).state, "invalid_input");
    });
    it("tracked:false is NOT ASSESSED: outside the tracked set, and 0 is not a measurement", async () => {
      const res = await call(CVE_UNTRACKED);
      assert.notEqual(res.isError, true, brief(res));
      const n = noteOf(res);
      assert.doesNotMatch(n, /measured zero|found nothing/, n);
      assert.match(n, /NOT ASSESSED/);
      assert.match(n, /outside the radar's tracked set; 0 is not a measurement/);
      assert.match(n, /\bcve_exposure OK\b/);
      assert.match(n, /\(exposure_state: not_assessed\)/);
      // kev_catalog_listed:false is also the answer when EchelonGraph has no cves row (the KEV
      // fetcher only UPDATEs), so it is worded as what EchelonGraph's data says.
      assert.match(n, new RegExp(`EchelonGraph's CVE data does not mark ${CVE_UNTRACKED} as CISA-KEV-listed \\(kev_catalog_listed is false, which it also is when EchelonGraph holds no record of ${CVE_UNTRACKED}\\)`));
      assert.doesNotMatch(n, /listed in the CISA-KEV catalog/, n);
    });
    it("tracked:false with hosts on record is still NOT ASSESSED, not a current count", async () => {
      const n = noteOf(await call(CVE_UNTRACKED_STALE));
      assert.match(n, /NOT ASSESSED/);
      assert.match(n, /3 service\(s\) \(distinct ip:port\) on record are left from earlier scans and are not a current measurement/);
      assert.ok(n.includes(`Method: ${METHOD}. Exposure counts`), `an API method ending in a full stop is quoted once: ${n}`);
    });
    // The radar reads at most the first 100 Shodan results per product query, so even a
    // tracked zero is a zero in that sample, not "the tracked products as Shodan sees them".
    it("tracked:true with 0 hosts is a measured zero in the radar's sample, not an internet-wide zero", async () => {
      stub.state.mode = "empty";
      const res = await call(CVE);
      stub.state.mode = "ok";
      assert.notEqual(res.isError, true, brief(res));
      const n = noteOf(res);
      assert.match(n, /\(exposure_state: measured_zero\)/);
      assert.match(n, /a measured zero in the radar's sample/);
      assert.match(n, /It is a zero in a sample, not an internet-wide zero: the radar reads at most the first 100 Shodan results per tracked-product query/);
      assert.doesNotMatch(n, /as Shodan sees them|among the radar's tracked products/, n);
      assert.match(n, /not a lookup failure/);
      assert.match(n, new RegExp(`EchelonGraph's CVE record marks ${CVE} as CISA-KEV-listed\\.`));
      assert.doesNotMatch(n, /NOT ASSESSED/);
    });
    it("tracked absent (an older API, or one that could not decide) makes no claim that the zero was measured", async () => {
      const res = await call(CVE_OLD_API);
      assert.notEqual(res.isError, true, brief(res));
      const n = noteOf(res);
      assert.doesNotMatch(n, /measured/, n);
      assert.doesNotMatch(n, /found nothing|NOT ASSESSED/, n);
      assert.match(n, /\bcve_exposure OK\b/);
      assert.match(n, /\(exposure_state: tracking_unknown\)/);
      assert.match(n, /does not say whether .* is in the radar's tracked set/);
      // The backend also omits `tracked` on purpose when it cannot decide, so "older API"
      // must not be the only reason given.
      assert.match(n, /an API older than that field, or the radar cannot decide for this CVE/);
      assert.match(n, /not evidence either way/);
      assert.match(n, /kev_listed field reflects the radar's own observations, not the CISA-KEV catalog/);
      assert.doesNotMatch(n, /0001-01-01/);
    });
    it("a populated footprint names its count, the method the API reports, and Shodan", async () => {
      const n = noteOf(await call(CVE));
      assert.match(n, /\(exposure_state: exposed\)/);
      assert.match(n, new RegExp(`6213 internet-facing services \\(distinct ip:port, the exposed_hosts field\\) on record whose banner version maps to ${CVE} across 107 countries`));
      assert.ok(n.includes(`Method: ${BACKEND_METHOD} Exposure counts`), `the API's method, which ends in a full stop, is quoted once: ${n}`);
      // last_seen is EchelonGraph's write time, refreshed on port presence alone (#2439), so it
      // is neither a sighting of the service nor of the vulnerable version, and must not read as
      // either.
      assert.match(n, /Their latest last_seen is 2026-09-15T04:02:09Z: when EchelonGraph last wrote or refreshed one of their rows, not when any of them was observed and not when a vulnerable version was last confirmed\./);
      assert.doesNotMatch(n, /most recently seen|last seen listening/, n);
    });
    // #2440: the note's tag is exposure_state, named as such; the envelope's state is a
    // different field, and the text never tags it with an exposure_state word.
    it("#2440: the note's tag names exposure_state, never state, in every case", async () => {
      for (const id of [CVE, CVE_UNTRACKED, CVE_UNTRACKED_STALE, CVE_OLD_API]) {
        const res = await call(id);
        const n = noteOf(res);
        assert.doesNotMatch(n, /\(state: /, `${id}: ${n}`);
        const [, key, value] = n.match(/\((exposure_state): ([a-z_]+)\)/) ?? [];
        assert.equal(key, "exposure_state", `${id}: no exposure_state tag: ${n}`);
        assert.equal(value, res.structuredContent.exposure_state, id);
        assert.equal(envelopeOf(res).state, "not_assessed", id);
      }
    });
  });

  // #2307: exposure_radar relays shadow-ai-radar/stats, whose total counts every observation.
  describe("#2307: exposure_radar labels shadow AI observed vs confirmed exposed", () => {
    let tools, res, data, note;
    before(async () => {
      stub.state.mode = "ok";
      ({ tools } = await client.listTools());
      res = await client.callTool({ name: "exposure_radar", arguments: {} });
      data = JSON.parse(res.content[0].text);
      note = noteOf(res);
    });
    it("the description no longer calls the total exposed AI services", () => {
      const d = tools.find((t) => t.name === "exposure_radar").description;
      assert.doesNotMatch(d, /exposed AI services/, d);
      assert.match(d, /shadow_ai\.observed counts every Certificate Transparency or Shodan observation on record, whatever its verification state: its numbers are observed, not exposed\./, d);
      assert.match(d, /confirmed_exposed\.total is the sum of confirmed_exposed\.by_category/, d);
      // #2313: the same result now carries kev_exposure and exposed_databases, which do count
      // exposed services, so the rule is scoped to shadow_ai.
      assert.match(d, /Of the shadow_ai numbers, only confirmed_exposed counts exposed services\./, d);
    });
    it("the note calls confirmed_exposed.total (the sum of the API's visible_by_category) confirmed exposed", () => {
      assert.match(note, /Shadow AI confirmed exposed: 2000 \(confirmed_exposed\.total, the sum of confirmed_exposed\.by_category: services EchelonGraph's probes found answering without an authentication gate/, note);
      assert.match(note, /, 201 of them first recorded in the last 24 h \(confirmed_exposed\.last_24h\)\./, note);
      assert.match(note, /Of the shadow_ai numbers, only confirmed_exposed counts exposed services\./, note);
      assert.equal(data.shadow_ai.confirmed_exposed.total, 2000);
    });
    it("the note never calls observed.total exposed", () => {
      assert.match(note, /Shadow AI observed: 36222 \(observed\.total\) counts every Certificate Transparency or Shodan observation on record/, note);
      assert.match(note, /that many observed, not that many exposed/, note);
      assert.doesNotMatch(note, /36,?222 (?:internet-)?exposed|exposed[^.:;]{0,40}\b36,?222\b/, note);
    });
    it("a follower's zero-time poller block is never presented as freshness", () => {
      const all = textOf(res);
      assert.doesNotMatch(all, /0001-01-01/, "a Go zero time reached the result");
      assert.doesNotMatch(all, /"running": false/, "a follower's running:false reached the result");
      assert.equal(data.shadow_ai.poller, undefined);
      assert.equal(data.shadow_ai.observed.total, 36222, "the stats themselves must still be relayed");
      assert.match(note, /Shadow-AI radar freshness is unknown/, note);
      assert.match(note, /Latest shadow-AI observation on record: 2026-09-26T11:02:00Z/, note);
    });

    // #2307 reopened: body item 1 asks that EVERY number be labelled observed vs confirmed,
    // and 1.0.2 relayed eight observation counts under the API's names with no label. What
    // each group counts, from core-backend/internal/shadowctlog:
    //   confirmed_exposed  store.go Stats: visible_by_category and last_24h_visible_count,
    //                      liveness IN ('active','rechecking')
    //   observed           store.go Stats: total, by_category, last_24h_count (no liveness
    //                      filter); TopProducts, TopCountries, TopIssuers, DailyTrend (the same)
    //   authentication     store.go Stats: auth_confirmed = liveness 'authenticated',
    //                      auth_undetermined = liveness 'inconclusive' (verifier.go)
    it("the relayed shadow_ai is regrouped as confirmed_exposed, observed and authentication", () => {
      assert.deepEqual(data.shadow_ai, PROD_SHADOW_RELAYED);
      assert.equal(data.shadow_ai.stats, undefined, "the API's ungrouped stats are not relayed beside the groups");
    });
    it("every numeric field reachable in shadow_ai is a labelled one, and every labelled one is there", () => {
      const found = [...numericPaths(data.shadow_ai)].sort();
      const unlabelled = found.filter((p) => !(p in SHADOW_AI_LABELLED));
      assert.deepEqual(unlabelled, [], `numeric fields relayed with no label: ${unlabelled.join(", ")}`);
      // Not vacuous: the production-shaped answer reaches every labelled field.
      assert.deepEqual(found, Object.keys(SHADOW_AI_LABELLED).sort());
    });
    it("each labelled field is named in the note, the tool description and the README", () => {
      const d = tools.find((t) => t.name === "exposure_radar").description;
      const readme = readPkgFile("README.md");
      for (const name of new Set(Object.values(SHADOW_AI_LABELLED))) {
        assert.ok(note.includes(name), `the note does not label ${name}: ${note}`);
        assert.ok(d.includes(name), `the description does not label ${name}: ${d}`);
        assert.ok(readme.includes(name), `the README does not label ${name}`);
      }
    });
    it("the note labels each observed ranking and series as counts of observations", () => {
      assert.match(note, /Every other number under observed counts the same observations, not exposed services: /, note);
      assert.match(note, /observed\.last_24h \(1569\) counts those first recorded in the last 24 h/, note);
      assert.match(note, /observed\.trend_30d counts them per UTC day over the last 30 days/, note);
      assert.match(note, /observed\.top_products ranks up to ten products by observations \(first: LiteLLM, 6813 observations\)/, note);
      assert.match(note, /observed\.top_countries ranks up to ten countries by observations \(first: United States, 9800 observations\)/, note);
      assert.match(note, /observed\.top_issuers ranks up to ten issuers by observations, an issuer being the certificate's CA for a Certificate Transparency observation and the hosting operator Shodan reports for a Shodan one \(first: Let's Encrypt, 15800 observations\)/, note);
    });
    it("the note labels the authentication counts as probe outcomes, neither exposed nor secured", () => {
      assert.match(note, /authentication\.observed \(8065\) counts observations where a probe observed an authentication gate/, note);
      assert.match(note, /authentication\.not_determined \(9307\) counts observations whose service answered but where no probe could tell/, note);
      assert.match(note, /Neither authentication count is part of confirmed_exposed, and observed\.total minus confirmed_exposed\.total is not a count of secured services/, note);
      assert.doesNotMatch(note, /\bsecured\b(?! services:)/, note);
    });
    // The auditor's mutant added "Headline: 36222 AI services exposed on the internet." to the
    // note and 1.0.2's suite still passed 136/136: its guard knew two word orders. This one
    // reads sentences: any sentence carrying a number from observed or authentication may use
    // "exposed" only as "not … exposed".
    it("no number under observed or authentication is called exposed in the note", () => {
      const checked = assertNoObservedNumberCalledExposed("exposure_radar note", note, data.shadow_ai);
      // 36222, 1569, 6813, 9800, 15800, 8065 and 9307 are each in the note.
      assert.ok(checked >= 7, `only ${checked} observed numbers found in the note`);
    });
    it("the guard above rejects the auditor's two mutants (an in-suite control)", () => {
      for (const mutant of ["Headline: 36222 AI services exposed on the internet.", "Shadow AI has 36222 internet-facing services exposed."]) {
        assert.throws(() => assertNoObservedNumberCalledExposed("mutant", `${note} ${mutant}`, data.shadow_ai), /called exposed/, mutant);
      }
    });
    it("no sentence that names an observed or authentication field calls it exposed: note, description, README", () => {
      const d = tools.find((t) => t.name === "exposure_radar").description;
      const n = assertObservedFieldsNotCalledExposed("note", sentencesOf(note));
      const dn = assertObservedFieldsNotCalledExposed("description", sentencesOf(d));
      const rn = assertObservedFieldsNotCalledExposed("README.md", readmeUnits(readPkgFile("README.md")));
      assert.ok(n >= 4 && dn >= 4 && rn >= 6, `too few sentences checked: note ${n}, description ${dn}, README ${rn}`);
    });
    it("no field name under shadow_ai says exposed, outside confirmed_exposed", () => {
      const named = [...keyPaths(data.shadow_ai)].filter((p) => !p.startsWith("confirmed_exposed"));
      assert.ok(named.length >= 12, `only ${named.length} field names checked`);
      for (const p of named) assert.doesNotMatch(p, /expos/i, p);
    });
    // Every quadrant but leaked credentials is found through Shodan; exposed databases fall
    // back to LeakIX, and that quadrant holds observability UIs as well as data stores.
    it("the description attributes the exposed-databases quadrant to Shodan and LeakIX, and names what it holds", () => {
      const d = tools.find((t) => t.name === "exposure_radar").description;
      assert.doesNotMatch(d, /unauthenticated databases/, d);
      assert.match(d, /unauthenticated data stores and observability UIs, found through Shodan \(LeakIX when Shodan query credits run low\)/, d);
      // Not "read-only": exposeddb names its client on Redis (CLIENT SETNAME) and its ClickHouse
      // SELECT lands in the target's query_log (exposeddb/probewrites_guard_test.go).
      assert.match(d, /confirmed by EchelonGraph's own identified check \(not a pure read/, d);
      assert.doesNotMatch(d, /read-only check/, d);
    });
    it("the note attributes Shodan to every quadrant that uses it, not only KEV-exposure", () => {
      assert.match(note, /KEV-exposure, exposed-database and shadow-AI discovery use Shodan data/, note);
      assert.match(note, /exposed databases fall back to LeakIX when Shodan query credits run low/, note);
      assert.doesNotMatch(note, /KEV-exposure counts are derived from Shodan data/, note);
    });
    // The fleet-freshness block (core-backend shadowctlog Poller.Status). Three cases, and the
    // note must tell them apart: running since a real completion, stopped since one, unknown.
    const SA_PATH = "/api/v1/public/shadow-ai-radar/stats";
    // poller: the block the stub answers with; undefined answers with no poller key at all.
    const radarWith = async (poller) => {
      const { poller: _dropped, ...rest } = BODIES[SA_PATH].ok;
      stub.state.overrides[SA_PATH] = poller === undefined ? rest : { ...rest, poller };
      try {
        const r = await client.callTool({ name: "exposure_radar", arguments: {} });
        assert.notEqual(r.isError, true, brief(r));
        return { relayed: JSON.parse(r.content[0].text).shadow_ai, n: noteOf(r) };
      } finally {
        delete stub.state.overrides[SA_PATH];
      }
    };
    // Freshness is the fleet's, never the answering instance's: the old wording must be gone.
    const noInstanceWording = (n) => assert.doesNotMatch(n, /server instance that answered|last ran the shadow-AI poller/, n);

    it("running:true with a real last_run_at: the radar's leader last completed a cycle at that time; the block is kept", async () => {
      const { relayed, n } = await radarWith(FLEET_RUNNING);
      assert.match(n, /Shadow-AI radar freshness: the radar's leader last completed a Certificate Transparency \(crt\.sh\) discovery cycle at 2026-09-26T10:00:00Z \(poller\.running is true: that was within 30 minutes of the API's answer\)\./, n);
      assert.doesNotMatch(n, /freshness is unknown|has completed since|may be stale/, n);
      noInstanceWording(n);
      // Only the two fleet fields the note explains; interval_seconds and shodan_enabled are the
      // answering instance's own settings (Poller.Status).
      assert.deepEqual(relayed.poller, { running: true, last_run_at: FLEET_RUNNING.last_run_at }, "a fleet block with a real completion time is relayed as running and last_run_at");
    });
    it("running:false with a real last_run_at: no cycle has completed since that time; the block is kept", async () => {
      const { relayed, n } = await radarWith(FLEET_STOPPED);
      assert.match(n, /Shadow-AI radar freshness: no Certificate Transparency \(crt\.sh\) discovery cycle has completed since 2026-09-26T08:15:00Z, when the radar's leader last completed one \(poller\.running is false: that was more than 30 minutes before the API's answer\), so the shadow-AI figures may be stale\./, n);
      assert.doesNotMatch(n, /freshness is unknown|last completed a Certificate Transparency \(crt\.sh\) discovery cycle at/, n);
      noInstanceWording(n);
      assert.deepEqual(relayed.poller, { running: false, last_run_at: FLEET_STOPPED.last_run_at }, "a stopped radar's real completion time is a finding, relayed as running and last_run_at");
    });
    it("last_run_at absent (the API cannot tell): freshness is unknown and the block is left out", async () => {
      const { relayed, n } = await radarWith(FLEET_UNKNOWN);
      assert.match(n, /Shadow-AI radar freshness is unknown: the answer's poller block does not give both a real time at which the radar's leader last completed a cycle \(poller\.last_run_at\) and a running verdict \(poller\.running\), so that block was left out of the data above\./, n);
      assert.doesNotMatch(n, /has completed since|last completed a Certificate Transparency/, n);
      assert.equal(relayed.poller, undefined);
      assert.equal(relayed.observed.total, 36222, "the stats themselves must still be relayed");
    });
    // An older API, or a malformed block: a zero or missing time, or a time without a verdict,
    // is never presented as the radar running or stopped.
    for (const [label, poller] of [
      ["an older API's follower (running:false, zero time)", FOLLOWER_POLLER],
      ["running:true with the zero time", { ...FLEET_RUNNING, last_run_at: "0001-01-01T00:00:00Z" }],
      ["running:true with no last_run_at", { running: true, interval_seconds: 60 }],
      ["a real last_run_at with no running verdict", { interval_seconds: 60, last_run_at: "2026-09-26T10:00:00Z" }],
    ]) {
      it(`${label}: freshness is unknown, and no running flag or zero time is relayed`, async () => {
        const { relayed, n } = await radarWith(poller);
        assert.match(n, /Shadow-AI radar freshness is unknown/, n);
        assert.doesNotMatch(n, /has completed since|last completed a Certificate Transparency|0001-01-01/, n);
        assert.equal(relayed.poller, undefined);
      });
    }
    it("no poller block at all: freshness is unknown, said in words", async () => {
      const { relayed, n } = await radarWith(undefined);
      assert.match(n, /Shadow-AI radar freshness is unknown: the answer carries no poller block\./, n);
      assert.equal(relayed.poller, undefined);
    });
    // #2313 item 7 / #2440: unknown fields are "dropped and named". 2.0.0 checked the top-level
    // and stats keys but not the poller block's, so an injected poller.exposed_now: 99999
    // vanished unmentioned. The known instance fields are still left out by design, unnamed.
    for (const [label, poller] of [
      ["a running fleet's block", FLEET_RUNNING],
      ["a block of unknown freshness", FLEET_UNKNOWN],
      ["an older API's follower block", FOLLOWER_POLLER],
    ]) {
      it(`an unknown key in ${label} is left out and named; its known instance fields are left out unnamed`, async () => {
        const { relayed, n } = await radarWith({ ...poller, exposed_now: 99999, candidate_services: 12, last_new_inserts: 7, last_error: "crt.sh 503", source_health: "degraded" });
        // Exactly the two unknown keys, in the order sent: no known instance field is named.
        assert.match(n, /Left out of shadow_ai because this version of the tool cannot label them: poller\.exposed_now, poller\.candidate_services\./, n);
        assert.doesNotMatch(n, /Left out of shadow_ai because they were not in the expected shape/, n);
        assert.doesNotMatch(JSON.stringify(relayed), /99999|exposed_now|candidate_services/, "an unknown poller field was relayed");
        const found = [...numericPaths(relayed)].filter((p) => !(p in SHADOW_AI_LABELLED));
        assert.deepEqual(found, [], `numeric fields relayed with no label: ${found.join(", ")}`);
        if (poller === FLEET_RUNNING) assert.deepEqual(relayed.poller, { running: true, last_run_at: FLEET_RUNNING.last_run_at });
        else assert.equal(relayed.poller, undefined);
      });
    }
    it("a poller block carrying every field the backend's Status sends names nothing (the control for the test above)", async () => {
      const every = { ...FLEET_RUNNING, last_new_inserts: 7, last_error: "x", skipped_as_follower: 1, source_health: "healthy", consecutive_fails: 0, shodan_last_new: 2 };
      assert.deepEqual(Object.keys(every).sort(), [...SHADOW_AI_POLLER_KNOWN].sort(), "the control must carry every known key");
      const { relayed, n } = await radarWith(every);
      assert.doesNotMatch(n, /Left out of shadow_ai/, n);
      assert.deepEqual(relayed.poller, { running: true, last_run_at: FLEET_RUNNING.last_run_at });
    });
    it("the description says what running and last_run_at mean", () => {
      const d = tools.find((t) => t.name === "exposure_radar").description;
      assert.match(d, /last_run_at is when the radar's leader last completed a Certificate Transparency \(crt\.sh\) cycle, and its running is true only when that was within 30 minutes of the answer/, d);
    });

    // What a later backend may add: a new stats count (one named as if exposed), a new count in
    // a ranked row, a new map, a new top-level block, and a polling instance's own counters in
    // the poller block. None may be relayed, since none is labelled; each top-level one is
    // named in the note, so the omission is visible.
    const radarAnswering = async (body) => {
      stub.state.overrides[SA_PATH] = body;
      try {
        const r = await client.callTool({ name: "exposure_radar", arguments: {} });
        assert.notEqual(r.isError, true, brief(r));
        return { relayed: JSON.parse(r.content[0].text).shadow_ai, n: noteOf(r) };
      } finally {
        delete stub.state.overrides[SA_PATH];
      }
    };
    it("a numeric field the backend adds later is left out, never relayed unlabelled, and the note names it", async () => {
      const { relayed, n } = await radarAnswering({
        stats: {
          ...PROD_SHADOW_STATS,
          exposed_total: 36222,
          new_count: 777,
          visible_by_country: { "United States": 400 },
          top_products: PROD_SHADOW_STATS.top_products.map((r) => ({ ...r, visible: 12 })),
          trend_30d: TREND_30D.map((r) => ({ ...r, visible: 3 })),
        },
        coverage: { probes: 5 },
        poller: { ...FLEET_RUNNING, last_new_inserts: 12, skipped_as_follower: 3, consecutive_fails: 0, shodan_last_new: 4 },
      });
      const found = [...numericPaths(relayed)].sort();
      const unlabelled = found.filter((p) => !(p in SHADOW_AI_LABELLED));
      assert.deepEqual(unlabelled, [], `numeric fields relayed with no label: ${unlabelled.join(", ")}`);
      assert.deepEqual(found, Object.keys(SHADOW_AI_LABELLED).sort(), "the labelled fields are still all relayed");
      assert.deepEqual(relayed.poller, { running: true, last_run_at: FLEET_RUNNING.last_run_at });
      // #2313: a field added inside a ranked row or the daily series is named too.
      assert.match(n, /Left out of shadow_ai because this version of the tool cannot label them: coverage, stats\.exposed_total, stats\.new_count, stats\.visible_by_country, stats\.trend_30d\[\]\.visible, stats\.top_products\[\]\.visible\./, n);
      assert.equal(assertNoObservedNumberCalledExposed("note", n, relayed) >= 7, true);
    });
    it("a count in an unexpected shape is left out whole and named, never relayed partly", async () => {
      const { relayed, n } = await radarAnswering({
        stats: {
          ...PROD_SHADOW_STATS,
          by_category: { ...PROD_SHADOW_STATS.by_category, NOTEBOOK: "6000" },
          top_products: [...PROD_SHADOW_STATS.top_products, { product: "vLLM" }],
          auth_undetermined: "9307",
        },
        poller: FLEET_RUNNING,
      });
      assert.equal(relayed.observed.by_category, undefined, "a partial category map is an undercount that reads as a measurement");
      assert.equal(relayed.observed.top_products, undefined);
      assert.equal(relayed.authentication.not_determined, undefined);
      assert.match(n, /Left out of shadow_ai because they were not in the expected shape: stats\.by_category, stats\.auth_undetermined, stats\.top_products\./, n);
      assert.doesNotMatch(n, /observed\.by_category counts|observed\.top_products ranks|authentication\.not_determined \(/, n);
      const unlabelled = [...numericPaths(relayed)].filter((p) => !(p in SHADOW_AI_LABELLED));
      assert.deepEqual(unlabelled, []);
    });
    it("without visible_by_category nothing is called confirmed exposed, and observed.total is still labelled observed", async () => {
      const { visible_by_category: _v, ...stats } = PROD_SHADOW_STATS;
      const { relayed, n } = await radarAnswering({ stats, poller: FLEET_RUNNING });
      assert.equal(relayed.confirmed_exposed.total, undefined);
      assert.match(n, /Shadow AI: the answer carries no usable stats\.visible_by_category, so it does not say how many services are confirmed exposed; confirmed_exposed\.last_24h \(201\) counts confirmed-exposed services first recorded in the last 24 h\./, n);
      assert.match(n, /Shadow AI observed: 36222 \(observed\.total\)/, n);
      assertNoObservedNumberCalledExposed("note", n, relayed);
    });
  });

  // #2313 items 6 and 7 (added from the #2307 re-close audit): kev_exposure.newest_kev relayed
  // 14 of 15 rows as exposed_hosts 0 for CVEs /kev-exposure/cve/:id calls tracked:false, and
  // 16 numeric paths of the other three radars reached the agent with no label; an injected
  // candidate_hosts: 99999 went through unnamed.
  describe("#2313: exposure_radar labels every number of every radar, and relays no not-assessed zero", () => {
    let tools, res, data, note, description, readme;
    const KEV_PATH = "/api/v1/public/kev-exposure/stats";
    const EDB_PATH = "/api/v1/public/exposed-databases/stats";
    const LC_PATH = "/api/v1/public/leaked-credentials/stats";
    // Calls exposure_radar with some stats answers replaced (path -> body).
    const radarWith = async (overrides) => {
      Object.assign(stub.state.overrides, overrides);
      try {
        const r = await client.callTool({ name: "exposure_radar", arguments: {} });
        assert.notEqual(r.isError, true, brief(r));
        return { relayed: JSON.parse(r.content[0].text), n: noteOf(r) };
      } finally {
        for (const p of Object.keys(overrides)) delete stub.state.overrides[p];
      }
    };
    // The sentences of a note that name a given CVE id.
    const sentencesNaming = (n, id) => sentencesOf(n).filter((s) => s.includes(id));
    before(async () => {
      stub.state.mode = "ok";
      ({ tools } = await client.listTools());
      res = await client.callTool({ name: "exposure_radar", arguments: {} });
      data = JSON.parse(res.content[0].text);
      note = noteOf(res);
      description = tools.find((t) => t.name === "exposure_radar").description;
      readme = readPkgFile("README.md");
    });

    // ── item 7: every numeric path labelled or dropped ──
    it("every numeric path in the whole result, all five radars, is a labelled one, and every labelled one is there", () => {
      assert.deepEqual(unlabelledIn(data), [], `numeric fields relayed with no label: ${unlabelledIn(data).join(", ")}`);
      // Not vacuous: the production-shaped answers reach every labelled path of every radar.
      assert.deepEqual([...numericPaths(data)].sort(), Object.keys(RADAR_LABELLED).sort());
      for (const radar of ["kev_exposure", "exposed_databases", "leaked_credentials", "shadow_ai", "mcp_servers"]) {
        assert.ok([...numericPaths(data)].some((p) => p.startsWith(`${radar}.`)), `no number from ${radar}`);
      }
    });
    it("each label is named in the note, the tool description and the README", () => {
      for (const name of new Set(Object.values(RADAR_LABELLED))) {
        assert.ok(note.includes(name), `the note does not label ${name}: ${note}`);
        assert.ok(description.includes(name), `the description does not label ${name}: ${description}`);
        assert.ok(readme.includes(name), `the README does not label ${name}`);
      }
    });
    it("the relayed radars are the API's answers cut to the labelled fields, nothing else", () => {
      const { newest_kev: _n, ...kevRest } = PROD_KEV_STATS;
      assert.deepEqual(data.kev_exposure, { ...kevRest, newest_kev: NEWEST_KEV_RELAYED });
      assert.deepEqual(data.exposed_databases, PROD_EXPOSED_DB_STATS);
      assert.deepEqual(data.leaked_credentials, PROD_LEAKED_CREDS_STATS);
      assert.deepEqual(data.shadow_ai, PROD_SHADOW_RELAYED);
      assert.deepEqual(data.mcp_servers, MCP_RELAYED);
    });
    // Each label below was checked against the Go source; the comment above RADAR_LABELLED
    // cites the line.
    it("kev_exposure.correlations and kev_exposure.trend are labelled service×CVE pairs, not services", () => {
      for (const [where, t] of [["note", note], ["description", description], ["README", readme.replace(/\s+/g, " ")]]) {
        assert.match(t, /kev_exposure\.correlations(?: \(31887\))?`? (?:\| )?(?:counts )?[Ss]ervice×CVE pairs, not services/, `${where}: correlations`);
        assert.match(t, /kev_exposure\.trend`? (?:\| )?(?:counts )?[Ss]ervice×CVE pairs/, `${where}: trend`);
      }
      assert.match(note, /a service with three KEV CVEs counts three times/);
      assert.match(note, /only pairs still on record are counted, so earlier weeks read low/);
    });
    it("kev_exposure.ransomware_hosts and every ranking count ip:port services, and say so", () => {
      assert.match(note, /kev_exposure\.distinct_hosts \(25113\) counts distinct ip:port services, not machines/);
      assert.match(note, /kev_exposure\.ransomware_hosts \(6655\) counts the services among them with at least one ransomware-linked KEV CVE/);
      assert.match(note, /kev_exposure\.top_products ranks up to 12 products \(first: http_server, 9120 services\), kev_exposure\.top_countries ranks up to 10 countries \(first: United States, 7021 services\) and kev_exposure\.top_cves ranks up to 12 CVEs \(first: CVE-2023-44487, 6213 services\), each by distinct ip:port services/);
      assert.match(note, /exposed_databases\.top_engines ranks up to 15 engines \(first: redis, 2410 services\) and exposed_databases\.top_countries ranks up to 10 countries \(first: United States, 2204 services\), each by those services/);
      assert.match(description, /kev_exposure\.ransomware_hosts those with a ransomware-linked one/);
    });
    it("the CVSS and EPSS numbers are labelled scores, not counts", () => {
      assert.match(note, /kev_exposure\.top_cves\[\]\.cvss_v3_score and kev_exposure\.top_cves\[\]\.epss_score are the highest CVSS v3 base score and EPSS probability \(0 to 1\) recorded on that CVE's observations: scores, not counts\./);
      assert.match(note, /kev_exposure\.newest_kev\[\]\.cvss_v3_score and kev_exposure\.newest_kev\[\]\.epss_score are the CVE record's CVSS v3 base score and EPSS probability \(0 to 1\), absent when the record has none: scores, not counts\./);
    });
    it("leaked_credentials.total is labelled (repository, secret) pairs, not distinct secrets, and nothing is called validated", () => {
      assert.match(note, /leaked_credentials\.total \(531\) counts \(repository, secret\) pairs, not distinct secrets: a secret committed to three repositories counts three times/);
      assert.match(note, /leaked_credentials\.distinct_secrets \(507\) counts each secret once/);
      assert.match(note, /None of these is validated: .*never tested against its provider, so none of them is a count of working credentials\./);
      assert.match(description, /leaked_credentials\.total counts \(repository, secret\) pairs, not distinct secrets/);
      assert.match(description, /None is validated: .*never tested against its provider/);
      assert.match(readme.replace(/\s+/g, " "), /None of them is validated/);
      // "validated", "valid" or "working" said of the credentials only as a denial.
      let denials = 0;
      for (const [where, t] of [["note", note], ["description", description], ["README", readme.replace(/\s+/g, " ")]]) {
        for (const m of t.matchAll(/\b(?:validated|valid|working) (?:credentials|secrets|keys)\b/gi)) {
          denials++;
          assert.match(t.slice(Math.max(0, m.index - 40), m.index), /\b(?:not|none|never|no)\b/i, `${where}: "${t.slice(Math.max(0, m.index - 40), m.index + 30)}"`);
        }
      }
      assert.ok(denials >= 1, "the denial itself is gone");
    });
    it("exposed_databases.pii_likely/pci_likely are labelled a precision-first schema gate, never 'no PII'", () => {
      assert.match(note, /exposed_databases\.pii_likely \(412\) counts services whose schema names pass a high-confidence gate for personal data/);
      assert.match(note, /exposed_databases\.pci_likely \(37\) counts services whose schema names pass a high-confidence gate for payment-card data/);
      assert.match(note, /never record values/);
      assert.match(note, /It is precision-first: a service whose names do not pass it is not counted, whatever it holds, so the other services are not shown to hold no personal or card data\./);
      assert.match(description, /precision-first gate for personal or payment-card data, so a service outside them is not shown to hold no such data/);
      for (const [where, t] of [["note", note], ["description", description], ["README", readme]]) {
        assert.doesNotMatch(t, /\bno (?:PII|personal data|card data)\b|free of (?:PII|personal|card)/i, `${where} reads the gate as an absence`);
      }
    });

    // What a later backend may add, and what a malformed answer may carry: none of it relayed,
    // each named. candidate_hosts: 99999 is the audit's own injection.
    it("an unknown field in any of the three radars, top level or inside a row, is left out and named", async () => {
      const { relayed, n } = await radarWith({
        [KEV_PATH]: { ...PROD_KEV_STATS, candidate_hosts: 99999, top_products: PROD_KEV_STATS.top_products.map((r) => ({ ...r, visible: 3 })), newest_kev: NEWEST_KEV.map((r) => ({ ...r, candidate_hosts: 7 })) },
        [EDB_PATH]: { ...PROD_EXPOSED_DB_STATS, open_now: 55, method: "x", top_engines: PROD_EXPOSED_DB_STATS.top_engines.map((r) => ({ ...r, with_pii: 2 })) },
        // constructor is a key that a naive `k in spec` would find on Object.prototype.
        [LC_PATH]: { ...PROD_LEAKED_CREDS_STATS, validated: 12, top_types: PROD_LEAKED_CREDS_STATS.top_types.map((r) => ({ ...r, repos: 4, constructor: 1 })) },
      });
      assert.deepEqual(unlabelledIn(relayed), [], `numeric fields relayed with no label: ${unlabelledIn(relayed).join(", ")}`);
      assert.deepEqual([...numericPaths(relayed)].sort(), Object.keys(RADAR_LABELLED).sort(), "the labelled fields are still all relayed");
      assert.doesNotMatch(JSON.stringify(relayed), /99999|candidate_hosts|open_now|with_pii|validated|"repos"|"visible"|"constructor"/);
      assert.match(n, /Left out of kev_exposure because this version of the tool cannot label them: candidate_hosts, top_products\[\]\.visible, newest_kev\[\]\.candidate_hosts\./, n);
      assert.match(n, /Left out of exposed_databases because this version of the tool cannot label them: open_now, method, top_engines\[\]\.with_pii\./, n);
      assert.match(n, /Left out of leaked_credentials because this version of the tool cannot label them: validated, top_types\[\]\.repos, top_types\[\]\.constructor\./, n);
    });
    it("a known field in an unexpected shape is left out whole and named, never relayed partly", async () => {
      const { relayed, n } = await radarWith({
        [KEV_PATH]: { ...PROD_KEV_STATS, correlations: "31887", top_cves: [...PROD_KEV_STATS.top_cves, { cve_id: "CVE-2024-3400", severity: "CRITICAL" }], generated_at: 0 },
        [EDB_PATH]: { ...PROD_EXPOSED_DB_STATS, pii_likely: null, top_countries: { "United States": 2204 } },
        [LC_PATH]: { ...PROD_LEAKED_CREDS_STATS, top_providers: [...PROD_LEAKED_CREDS_STATS.top_providers, { provider: "gcp", count: "9" }] },
      });
      assert.equal(relayed.kev_exposure.correlations, undefined);
      assert.equal(relayed.kev_exposure.top_cves, undefined, "a ranking with one malformed row reads as a complete one if relayed partly");
      assert.equal(relayed.exposed_databases.top_countries, undefined);
      assert.equal(relayed.exposed_databases.pii_likely, undefined);
      assert.equal(relayed.leaked_credentials.top_providers, undefined);
      assert.match(n, /Left out of kev_exposure because they were not in the expected shape: correlations, top_cves, generated_at\./, n);
      assert.match(n, /Left out of exposed_databases because they were not in the expected shape: top_countries\./, n);
      assert.match(n, /Left out of leaked_credentials because they were not in the expected shape: top_providers\./, n);
      assert.doesNotMatch(n, /kev_exposure\.correlations \(|kev_exposure\.top_cves ranks|exposed_databases\.pii_likely \(|leaked_credentials\.top_providers ranks/, n);
      assert.deepEqual(unlabelledIn(relayed), []);
    });
    it("the genuine-empty answers still carry only labelled numbers", async () => {
      stub.state.mode = "empty";
      try {
        const r = await client.callTool({ name: "exposure_radar", arguments: {} });
        const relayed = JSON.parse(r.content[0].text);
        assert.deepEqual(unlabelledIn(relayed), []);
        assert.equal(relayed.kev_exposure.distinct_hosts, 0);
        assert.equal(relayed.leaked_credentials.total, 0);
      } finally {
        stub.state.mode = "ok";
      }
    });

    // ── item 6: a newest_kev zero is not a measurement ──
    it("newest_kev: the tracked CVE keeps its count as exposed; every untracked one is not_assessed and carries no count", () => {
      assert.deepEqual(data.kev_exposure.newest_kev, NEWEST_KEV_RELAYED);
      const rows = data.kev_exposure.newest_kev;
      assert.equal(rows.length, 15);
      const tracked = rows.find((r) => r.cve_id === KEV_TRACKED);
      assert.equal(tracked.exposure_state, "exposed");
      assert.equal(tracked.exposed_hosts, 142);
      for (const id of KEV_UNTRACKED) {
        const r = rows.find((x) => x.cve_id === id);
        assert.equal(r.exposure_state, "not_assessed", id);
        assert.ok(!("exposed_hosts" in r), `${id} still carries a count: ${JSON.stringify(r)}`);
      }
      assert.ok(!rows.some((r) => r.exposed_hosts === 0), "a newest_kev zero reached the agent");
    });
    it("newest_kev: the note calls every untracked CVE NOT ASSESSED and never a zero, and gives the tracked one its count", () => {
      assert.match(note, /kev_exposure\.newest_kev lists the 15 CVEs that EchelonGraph's CVE records most recently mark as CISA-KEV-listed \(by added_date\), each with an exposure_state\./);
      assert.match(note, new RegExp(`1 of them is exposed \\(exposure_state exposed\\): kev_exposure\\.newest_kev\\[\\]\\.exposed_hosts counts distinct ip:port services on record with that CVE \\(${KEV_TRACKED}: 142\\)\\.`));
      assert.match(note, new RegExp(`14 are NOT ASSESSED \\(exposure_state not_assessed\\): ${KEV_UNTRACKED.join(", ")}\\. The API answers 0 for each, and that 0 is not a measurement`));
      for (const id of KEV_UNTRACKED) {
        const said = sentencesNaming(note, id);
        assert.ok(said.length >= 1, `the note does not name ${id}`);
        for (const s of said) {
          assert.match(s, /NOT ASSESSED/, s);
          assert.doesNotMatch(s, /\bexposed\b|measured zero|found nothing/, s);
        }
      }
      assert.doesNotMatch(note, /\b0 (?:exposed|services)\b|exposed_hosts:? 0\b/, note);
      assert.match(description, /or not_assessed, where the API's answer holds no measurement for that CVE \(its 0 is not one\) and no count is relayed/);
    });
    // The done-means as written: a row whose CVE reads tracked:false on /kev-exposure/cve/:id
    // reaches the agent as not assessed. Asked of the stub's per-CVE endpoint, row by row.
    it("newest_kev agrees with cve_exposure row by row: tracked:false there is not_assessed here", async () => {
      let untracked = 0;
      for (const row of data.kev_exposure.newest_kev) {
        const n = noteOf(await client.callTool({ name: "cve_exposure", arguments: { cve_id: row.cve_id } }));
        if (/\(exposure_state: not_assessed\)/.test(n)) {
          untracked++;
          assert.equal(row.exposure_state, "not_assessed", `${row.cve_id}: cve_exposure says NOT ASSESSED, exposure_radar says ${row.exposure_state}`);
        } else {
          assert.match(n, /\(exposure_state: exposed\)/, `${row.cve_id}: ${n}`);
          assert.equal(row.exposure_state, "exposed", row.cve_id);
        }
      }
      assert.equal(untracked, 14, "the stub's per-CVE endpoint marks the 14 audit-shaped rows tracked:false");
    });
    it("an all-zero newest_kev (an empty observation table) is all not_assessed, with no zero relayed", async () => {
      stub.state.mode = "empty";
      try {
        const r = await client.callTool({ name: "exposure_radar", arguments: {} });
        const relayed = JSON.parse(r.content[0].text);
        assert.equal(relayed.kev_exposure.newest_kev.length, 15);
        for (const row of relayed.kev_exposure.newest_kev) {
          assert.equal(row.exposure_state, "not_assessed", row.cve_id);
          assert.ok(!("exposed_hosts" in row), row.cve_id);
        }
        assert.match(noteOf(r), /15 are NOT ASSESSED \(exposure_state not_assessed\)/);
        assert.doesNotMatch(noteOf(r), /are exposed \(exposure_state exposed\)/);
      } finally {
        stub.state.mode = "ok";
      }
    });
    // The contract proposed on #2313: the stats answer sends each newest_kev row's `tracked`,
    // decided by the per-CVE endpoint's trackedVerdict. Read the way cve_exposure reads it.
    it("with a per-row tracked (the proposed contract): false is not_assessed whatever the count, true with 0 is a measured zero", async () => {
      const rows = [
        { cve_id: "CVE-2026-11111", added_date: "2026-09-26", exposed_hosts: 0, tracked: false },
        { cve_id: "CVE-2026-22222", added_date: "2026-09-26", exposed_hosts: 3, tracked: false },
        { cve_id: "CVE-2026-33333", added_date: "2026-09-26", exposed_hosts: 0, tracked: true },
        { cve_id: "CVE-2026-44444", added_date: "2026-09-26", exposed_hosts: 0 },
        { cve_id: "CVE-2026-55555", added_date: "2026-09-26", exposed_hosts: 9, tracked: true },
      ];
      const { relayed, n } = await radarWith({ [KEV_PATH]: { ...PROD_KEV_STATS, newest_kev: rows } });
      const byId = Object.fromEntries(relayed.kev_exposure.newest_kev.map((r) => [r.cve_id, r]));
      assert.deepEqual(byId["CVE-2026-11111"], { cve_id: "CVE-2026-11111", added_date: "2026-09-26", exposure_state: "not_assessed" });
      assert.deepEqual(byId["CVE-2026-22222"], { cve_id: "CVE-2026-22222", added_date: "2026-09-26", exposure_state: "not_assessed" });
      assert.deepEqual(byId["CVE-2026-33333"], { cve_id: "CVE-2026-33333", added_date: "2026-09-26", exposure_state: "measured_zero", exposed_hosts: 0 });
      assert.deepEqual(byId["CVE-2026-44444"], { cve_id: "CVE-2026-44444", added_date: "2026-09-26", exposure_state: "not_assessed" });
      assert.deepEqual(byId["CVE-2026-55555"], { cve_id: "CVE-2026-55555", added_date: "2026-09-26", exposure_state: "exposed", exposed_hosts: 9 });
      assert.ok(!JSON.stringify(relayed.kev_exposure.newest_kev).includes('"tracked"'), "tracked is read, not relayed: exposure_state says it");
      assert.match(n, /2 are NOT ASSESSED \(exposure_state not_assessed\) because the API says they are outside the radar's tracked set, so no count is relayed for them: CVE-2026-11111, CVE-2026-22222\./, n);
      assert.match(n, /1 is a measured zero in the radar's sample \(exposure_state measured_zero, exposed_hosts 0\): .*not an internet-wide zero: CVE-2026-33333\./, n);
      assert.match(n, /1 is NOT ASSESSED \(exposure_state not_assessed\): CVE-2026-44444\. The API answers 0 for each/, n);
      assert.match(n, /1 of them is exposed \(exposure_state exposed\): .*\(CVE-2026-55555: 9\)\./, n);
    });
    it("a newest_kev row without a count or a CVE id leaves the list out whole, named", async () => {
      const { relayed, n } = await radarWith({ [KEV_PATH]: { ...PROD_KEV_STATS, newest_kev: [...NEWEST_KEV, { cve_id: "CVE-2026-99999" }] } });
      assert.equal(relayed.kev_exposure.newest_kev, undefined);
      assert.match(n, /Left out of kev_exposure because they were not in the expected shape: newest_kev\./, n);
      assert.doesNotMatch(n, /NOT ASSESSED|newest_kev lists/, n);
    });
  });

  // #2353: core-backend adds a string `attribution` to every answer derived from Shodan data —
  // kev-exposure (stats, cve/:id), exposed-databases/stats, shadow-ai-radar/stats — naming what is
  // Shodan's and ending in Shodan's ownership sentence (internal/shodan Ownership; the strings
  // below are those handlers' own). This version of the tool was published before the field
  // existed, so these tests hold what the published tool does with it: the answer is still a
  // success, no number changes, exposure_radar leaves the field out and names it like any field
  // it cannot label, cve_exposure relays it as data (its data schema admits fields the API adds),
  // and each note still states Shodan's ownership itself.
  describe("#2353: a string `attribution` on the Shodan-derived answers is tolerated", () => {
    const OWN = "Shodan data is owned by Shodan, which holds its copyright (© Shodan). EchelonGraph claims no ownership of it or copyright in it.";
    const KEV_ATTRIBUTION = `The services counted here are derived from Shodan data: Shodan banner matches, re-checked against Shodan InternetDB. ${OWN}`;
    const PATHS = {
      kev_exposure: ["/api/v1/public/kev-exposure/stats", KEV_ATTRIBUTION],
      exposed_databases: ["/api/v1/public/exposed-databases/stats", `The services counted here come from Shodan data, or from LeakIX data when Shodan query credits run low. ${OWN}`],
      shadow_ai: ["/api/v1/public/shadow-ai-radar/stats", `Observations whose source is "shodan", and every count that includes them, are derived from Shodan data. ${OWN}`],
    };
    const CVE_PATH = `/api/v1/public/kev-exposure/cve/${CVE}`;
    const withOverrides = async (overrides, fn) => {
      Object.assign(stub.state.overrides, overrides);
      try {
        return await fn();
      } finally {
        for (const p of Object.keys(overrides)) delete stub.state.overrides[p];
      }
    };
    before(() => { stub.state.mode = "ok"; });

    it("exposure_radar: every number relayed as before, attribution left out and named per radar, ownership still stated", async () => {
      const before = await client.callTool({ name: "exposure_radar", arguments: {} });
      assert.notEqual(before.isError, true, brief(before));
      const overrides = Object.fromEntries(Object.values(PATHS).map(([path, attribution]) => [path, { ...BODIES[path].ok, attribution }]));
      const after = await withOverrides(overrides, () => client.callTool({ name: "exposure_radar", arguments: {} }));
      assert.notEqual(after.isError, true, brief(after));
      assert.deepEqual(JSON.parse(after.content[0].text), JSON.parse(before.content[0].text), "the attribution changed what exposure_radar relays");
      assert.doesNotMatch(after.content[0].text, /attribution/);
      const n = noteOf(after);
      for (const radar of Object.keys(PATHS)) {
        assert.match(n, new RegExp(`Left out of ${radar} because this version of the tool cannot label them: attribution\\.`), n);
      }
      assert.doesNotMatch(n, /Left out of leaked_credentials/, n);
      assert.doesNotMatch(n, /not in the expected shape/, n);
      assert.match(n, /Shodan data is owned by Shodan, which holds its copyright \(© Shodan\)\./, n);
      // Apart from those three sentences, the note is the one the tool gave before.
      const without = n.replace(/ Left out of (?:kev_exposure|exposed_databases|shadow_ai) because this version of the tool cannot label them: attribution\./g, "");
      assert.equal(without, noteOf(before));
    });

    it("cve_exposure: the attribution is relayed as data, and the note and envelope are the ones it gave before", async () => {
      const before = await client.callTool({ name: "cve_exposure", arguments: { cve_id: CVE } });
      assert.notEqual(before.isError, true, brief(before));
      const after = await withOverrides({ [CVE_PATH]: { ...BODIES[CVE_PATH].ok, attribution: KEV_ATTRIBUTION } }, () =>
        client.callTool({ name: "cve_exposure", arguments: { cve_id: CVE } }),
      );
      assert.notEqual(after.isError, true, brief(after));
      const data = JSON.parse(after.content[0].text);
      assert.equal(data.attribution, KEV_ATTRIBUTION);
      const { attribution: _a, ...rest } = data;
      assert.deepEqual(rest, JSON.parse(before.content[0].text), "the attribution changed another relayed field");
      assert.equal(noteOf(after), noteOf(before));
      assert.deepEqual(envelopeOf(after), envelopeOf(before));
      assert.match(noteOf(after), /Shodan data is owned by Shodan, which holds its copyright \(© Shodan\)\./);
    });
  });

  // #2335: kev_exposure, exposed_databases and leaked_credentials each answer last_run_at: when
  // that radar last COMPLETED a check, read from poller_run_state (core-backend
  // pollerlock/published.go), UTC and truncated to the second, omitted when unknown and never
  // the Go zero time. The row moves only at the end of a cycle whose reads succeeded (each
  // radar's poller.go checkCompleted / recordCheck). 1.0.4 as first written could not label it,
  // so it named last_run_at as left out. A timestamp is a string, so the numeric enumerator
  // above does not see it; the tests below enumerate the radars' timestamps instead.
  describe("#2335: exposure_radar relays and labels each radar's last completed check (last_run_at)", () => {
    const FLAT = ["kev_exposure", "exposed_databases", "leaked_credentials"];
    const PATHS = {
      kev_exposure: "/api/v1/public/kev-exposure/stats",
      exposed_databases: "/api/v1/public/exposed-databases/stats",
      leaked_credentials: "/api/v1/public/leaked-credentials/stats",
    };
    const PROD = { kev_exposure: PROD_KEV_STATS, exposed_databases: PROD_EXPOSED_DB_STATS, leaked_credentials: PROD_LEAKED_CREDS_STATS };
    const GENERATED_AT = "2026-09-27T09:00:00Z";
    // What each radar's poller.go counts as a completed check, as the note must word it:
    //   kevexposure  checkCompleted = searched && answered > 0 && staleErr == nil
    //   exposeddb    the same, over Shodan or the LeakIX fallback, && gated.unknown == 0
    //   leakedcreds  fetchErr == nil (the public event stream was read)
    const MEANS = {
      kev_exposure: /its Shodan search answered at least one query \(others may have failed\) and its list of services due for a re-check was read; a cycle that skipped the search for want of Shodan query credits, or whose reads failed, does not move it\./,
      exposed_databases: /its Shodan search, or the LeakIX fallback, answered at least one query \(others may have failed\), its list of services due for a re-check was read, and the scan opt-out register could be consulted; a cycle that searched nothing, or whose reads failed, does not move it\./,
      leaked_credentials: /it read the public GitHub event stream \(fetches of some of the commits it lists may have failed\); a cycle whose read of that stream failed does not move it\./,
    };
    // #2313's timestamp twin of RADAR_LABELLED: every string at the top level of the three flat
    // radars, mapped to the name the description and the README label it by.
    const RADAR_INSTANTS = {
      "kev_exposure.generated_at": "generated_at",
      "kev_exposure.last_run_at": "kev_exposure.last_run_at",
      "exposed_databases.generated_at": "generated_at",
      "exposed_databases.last_run_at": "exposed_databases.last_run_at",
      "leaked_credentials.generated_at": "generated_at",
      "leaked_credentials.last_run_at": "leaked_credentials.last_run_at",
    };
    const topLevelStrings = (relayed) =>
      FLAT.flatMap((r) => Object.entries(relayed[r] ?? {}).filter(([, v]) => typeof v === "string").map(([k]) => `${r}.${k}`)).sort();
    // The note's sentences about one radar's last completed check.
    const lastCheckSaid = (n, radar) => sentencesOf(n).filter((s) => s.includes(`${radar}.last_run_at`) || s.includes(`${radar} last completed check`));
    // Wording that would present the stamp as freshness it is not.
    const NOT_A_STAMP = /\b(?:live|real-?time|currently|up[ -]to[ -]date|as of|right now)\b/i;
    let tools, description, readme, data, note;
    const radarWith = async (overrides) => {
      Object.assign(stub.state.overrides, overrides);
      try {
        const r = await client.callTool({ name: "exposure_radar", arguments: {} });
        assert.notEqual(r.isError, true, brief(r));
        return { relayed: JSON.parse(r.content[0].text), n: noteOf(r) };
      } finally {
        for (const p of Object.keys(overrides)) delete stub.state.overrides[p];
      }
    };
    before(async () => {
      stub.state.mode = "ok";
      ({ tools } = await client.listTools());
      description = tools.find((t) => t.name === "exposure_radar").description;
      readme = readPkgFile("README.md");
      const res = await client.callTool({ name: "exposure_radar", arguments: {} });
      data = JSON.parse(res.content[0].text);
      note = noteOf(res);
    });

    it("each radar's last_run_at is relayed as the API sent it, beside generated_at, and is not a count", () => {
      for (const r of FLAT) {
        assert.equal(data[r].last_run_at, LAST_RUN[r], `${r}.last_run_at`);
        assert.equal(data[r].generated_at, GENERATED_AT, `${r}.generated_at`);
        assert.notEqual(data[r].last_run_at, data[r].generated_at, `${r}: the stamp is not the time the totals were computed`);
      }
      // A string: the numeric enumerator neither sees it nor needs a label for it.
      assert.deepEqual([...numericPaths(data)].filter((p) => /last_run_at|generated_at/.test(p)), []);
      assert.deepEqual(unlabelledIn(data), []);
      assert.doesNotMatch(note, /cannot label them: [^.]*last_run_at/, note);
    });
    it("every timestamp at a radar's top level is a labelled one, and every labelled one is there", () => {
      const found = topLevelStrings(data);
      assert.deepEqual(found.filter((p) => !(p in RADAR_INSTANTS)), [], `timestamps relayed with no label: ${found.join(", ")}`);
      assert.deepEqual(found, Object.keys(RADAR_INSTANTS).sort());
      for (const name of new Set(Object.values(RADAR_INSTANTS))) {
        assert.ok(description.includes(name), `the description does not label ${name}`);
        assert.ok(readme.includes(name), `the README does not label ${name}`);
      }
    });
    it("the note labels each radar's last_run_at as its last completed check: a timestamp, not a count", () => {
      for (const r of FLAT) {
        // Exactly three sentences, each anchored, so a clause added to any of them fails.
        const said = lastCheckSaid(note, r);
        assert.equal(said.length, 3, `${r}: expected three sentences about ${r}.last_run_at: ${said.join(" | ")}`);
        const [stamp, means, notEvery] = said;
        assert.equal(stamp, `${r} last completed check: ${LAST_RUN[r]} (${r}.last_run_at, a timestamp, not a count).`);
        assert.match(means, new RegExp(`^${r}\\.last_run_at is when the radar last finished a cycle whose reads succeeded: ${MEANS[r].source}$`), means);
        // Not the time of every record: the totals cover everything still on record.
        assert.equal(
          notEvery,
          `${r}.last_run_at is not the time of every record the ${r} numbers count, which cover everything still on record, not only what that check found; nor is it ${r}.generated_at, when the API computed those numbers.`,
        );
        for (const s of said) assert.doesNotMatch(s, NOT_A_STAMP, `${r}: ${s}`);
        // The stamp is printed once, in its labelled sentence: no other sentence of the note may
        // carry it (as, say, "every number was measured at …").
        assert.deepEqual(sentencesOf(note).filter((s) => s.includes(LAST_RUN[r])), [stamp], `${r}: the stamp is printed outside its label`);
        // Only this radar's own stamp: never another radar's, never generated_at's time.
        for (const other of [...Object.values(LAST_RUN), GENERATED_AT].filter((t) => t !== LAST_RUN[r])) {
          assert.ok(!said.join(" ").includes(other), `${r}'s sentences print ${other}`);
        }
      }
    });
    it("the description and the README label each last_run_at as a timestamp, not a count, and say what completed means", () => {
      for (const r of FLAT) {
        assert.ok(description.includes(`${r}.last_run_at`), `description: ${r}.last_run_at`);
        assert.ok(readme.includes(`| \`${r}.last_run_at\` | A timestamp, not a count: when the radar last completed a check`), `README row: ${r}.last_run_at`);
      }
      assert.match(description, /kev_exposure\.last_run_at, exposed_databases\.last_run_at and leaked_credentials\.last_run_at are timestamps, not counts: each is when that radar last completed a check, a cycle whose reads succeeded/, description);
      assert.match(description, /A cycle that read nothing does not move it, and it is not the time of every record a radar's numbers count, which cover everything still on record, not only what the last check found\./, description);
      assert.match(description, /A radar whose answer carries no last_run_at has none in the result, and the note says nothing about it\./, description);
      const flatReadme = readme.replace(/\s+/g, " ");
      assert.match(flatReadme, /`last_run_at` is a timestamp, not a count\./);
      assert.match(flatReadme, /It moves only at the end of a cycle whose reads succeeded, so a cycle that read nothing leaves it where it was\./);
      assert.match(flatReadme, /It is not the time of every record a radar's numbers count: those cover everything still on record, not only what the last check found\./);
      for (const [where, t] of [["description", description], ["README", flatReadme]]) {
        for (const s of sentencesOf(t).filter((x) => x.includes("last_run_at") && !x.includes("poller"))) {
          assert.doesNotMatch(s, NOT_A_STAMP, `${where}: ${s}`);
        }
      }
    });

    // Absent means the API could not tell. The result then carries none and the note says
    // nothing at all about it: not "never", not a zero, not "unknown". Proved by difference:
    // the note without the stamp is the note with it, minus that radar's sentences about it.
    // The Go zero time, null, "" and a word that is not a date are read the same way.
    for (const [label, value] of [
      ["omitted (the API's omitempty)", undefined],
      ["the Go zero time", "0001-01-01T00:00:00Z"],
      ["null", null],
      ["an empty string", ""],
      ["a word, not a date", "never"],
    ]) {
      it(`last_run_at ${label}: not relayed, and the note says nothing in its place, radar by radar`, async () => {
        for (const r of FLAT) {
          const { last_run_at: _dropped, ...rest } = PROD[r];
          const body = value === undefined ? rest : { ...rest, last_run_at: value };
          const { relayed, n } = await radarWith({ [PATHS[r]]: body });
          assert.ok(!("last_run_at" in relayed[r]), `${r}: ${JSON.stringify(relayed[r].last_run_at)} was relayed`);
          const { last_run_at: _kept, ...expected } = data[r];
          assert.deepEqual(relayed[r], expected, `${r}: the rest of the answer is relayed as before`);
          for (const other of FLAT.filter((x) => x !== r)) assert.equal(relayed[other].last_run_at, LAST_RUN[other], `${other} lost its stamp`);
          assert.deepEqual(lastCheckSaid(n, r), [], `${r}: the note still speaks of its last completed check: ${n}`);
          const without = sentencesOf(note).filter((s) => !lastCheckSaid(note, r).includes(s));
          assert.deepEqual(sentencesOf(n), without, `${r}: the note says something in place of the missing stamp`);
          assert.doesNotMatch(n, /0001-01-01|never (?:completed|ran|run|checked)|no (?:completed )?check|not yet (?:run|checked)/i, `${r}: ${n}`);
        }
      });
    }
    it("a last_run_at that is not a string is left out and named, never relayed", async () => {
      for (const r of FLAT) {
        const { relayed, n } = await radarWith({ [PATHS[r]]: { ...PROD[r], last_run_at: 0 } });
        assert.ok(!("last_run_at" in relayed[r]), `${r}: ${JSON.stringify(relayed[r])}`);
        assert.match(n, new RegExp(`Left out of ${r} because they were not in the expected shape: last_run_at\\.`), n);
        assert.deepEqual(lastCheckSaid(n, r), [], n);
      }
    });
    it("an API from before #2335 (the empty fixtures send no last_run_at) gets no stamp and no sentence", async () => {
      stub.state.mode = "empty";
      try {
        const r = await client.callTool({ name: "exposure_radar", arguments: {} });
        const relayed = JSON.parse(r.content[0].text);
        const n = noteOf(r);
        for (const radar of FLAT) {
          assert.ok(!("last_run_at" in relayed[radar]), radar);
          assert.deepEqual(lastCheckSaid(n, radar), [], n);
        }
        assert.doesNotMatch(n, /last completed check/, n);
      } finally {
        stub.state.mode = "ok";
      }
    });
  });

  // #2315: exposure_radar's fifth radar, mcp_servers: the adjudicated MCP-server counts of
  // GET /api/v1/public/ai-exposure/stats?service=mcp, inside the #2313 envelope. What the tool must
  // hold to, each from the ticket or the contract:
  //   - counts relayed as given, labelled; protected is RFC 9728 validated, and not_assessed is not
  //     unprotected;
  //   - identified_no_challenge is never called open, exposed or unauthenticated (#2307's mistake,
  //     one bucket over): MCP authorization is optional, and only tools/call, which EchelonGraph
  //     never sends, could tell;
  //   - an answer that is not the MCP-server counts (a 400, an API older than ?service=mcp, a
  //     malformed body, counts that contradict each other) is a failure of that radar, never zeros;
  //   - no string the answer carries but its timestamps reaches the result;
  //   - discovery is EchelonGraph's own Certificate Transparency feed, so no Shodan attribution
  //     covers it.
  describe("#2315: exposure_radar relays the adjudicated MCP-server counts (mcp_servers)", () => {
    let tools, res, data, note, description, readme, instructions;
    // Calls exposure_radar with the ?service=mcp answer replaced by `entry`.
    const withMCP = async (entry) => {
      stub.state.overrides[MCP_PATH] = entry;
      try {
        return await client.callTool({ name: "exposure_radar", arguments: {} });
      } finally {
        delete stub.state.overrides[MCP_PATH];
      }
    };
    const relaying = async (body) => {
      const r = await withMCP(body);
      assert.notEqual(r.isError, true, brief(r));
      return { r, relayed: JSON.parse(r.content[0].text).mcp_servers, n: noteOf(r) };
    };
    // Everything a client holds for a result: every text block and the structured result.
    const everything = (r) => `${textBlocks(r).join("\n")}\n${JSON.stringify(r.structuredContent)}`;
    // A refused mcp_servers answer: a failure naming that radar alone, with no radar's numbers.
    const MCP_NUMBERS = /10217|9601|6120|8561|1893/;
    const assertRefused = (r, kind, status, message) => {
      assertErrorResult("exposure_radar", r);
      const sc = r.structuredContent;
      assert.equal(sc.state, "failed");
      assert.ok(!("data" in sc), "a refused answer reached the structured result as data");
      assert.deepEqual(sc.coverage.failed, ["mcp_servers"]);
      assert.deepEqual(sc.coverage.answered, ["kev_exposure", "exposed_databases", "leaked_credentials", "shadow_ai"]);
      assert.equal(sc.error.kind, "radars");
      assert.equal(sc.error.radars.length, 1, JSON.stringify(sc.error.radars));
      const [f] = sc.error.radars;
      assert.deepEqual({ radar: f.radar, kind: f.kind, path: f.path, status: f.status }, { radar: "mcp_servers", kind, path: MCP_PATH, status });
      assert.match(f.message, message);
      const t = textOf(r);
      assert.match(t, /^exposure_radar FAILED: 1 of 5 radars could not be read from /, t);
      assert.match(t, /this is not a finding: do not report it as zero, none found, absent, or unexposed/, t);
      assert.match(t, /The 4 radar\(s\) that did answer \(kev_exposure, exposed_databases, leaked_credentials, shadow_ai\) are withheld/, t);
      // Never zeros, and no number of any radar.
      assert.doesNotMatch(everything(r), MCP_NUMBERS, "an MCP-server count reached a refused result");
      assert.doesNotMatch(everything(r), /25113|7380|36222/, "a withheld radar's number reached the result");
      return t;
    };
    // What no text may say of identified_no_challenge, or of any mcp_servers number.
    const ACCUSES = /\bopen\b|\bexposed\b|\bunauthenticated\b|\bunauthori[sz]ed\b|\bvulnerable\b|without (?:authentication|credentials|auth)\b/i;
    const NAMES_MCP = /\bmcp_servers\b|identified_no_challenge|That is normal in MCP/;
    function assertMCPNotAccused(where, units) {
      let checked = 0;
      for (const u of units) {
        if (!NAMES_MCP.test(u)) continue;
        checked++;
        assert.doesNotMatch(u, ACCUSES, `${where}: a sentence about mcp_servers calls a server open, exposed or unauthenticated: "${u}"`);
      }
      return checked;
    }
    // The bucket's own words, as the note, the description and the README each give them.
    const NORMAL_IN_MCP = /That is normal in MCP: authorization is optional in the spec, and a server can enforce it at `?tools\/call`? instead, which EchelonGraph never sends[.,] [Ss]o this bucket is not a finding of exposure\./;
    before(async () => {
      stub.state.mode = "ok";
      stub.state.seen.length = 0;
      ({ tools } = await client.listTools());
      instructions = client.opening.instructions;
      res = await client.callTool({ name: "exposure_radar", arguments: {} });
      data = JSON.parse(res.content[0].text);
      note = noteOf(res);
      description = tools.find((t) => t.name === "exposure_radar").description;
      readme = readPkgFile("README.md");
    });

    it("the description names every RFC 9728 reason bucket, in the answer's order, as one constant sentence", () => {
      // The description spells the eight reasons out as a constant (MCP_CHALLENGE_REASON_FIELDS), so the site's
      // tool-claims check can read it statically; this pins that constant to the buckets the answer carries.
      const reasons = Object.keys(MCP_REASONS).filter(
        (k) => !["identified_no_challenge", "challenge_unadjudicated", "no_http_answer", "not_identified_as_mcp"].includes(k),
      );
      assert.equal(reasons.length, 8, reasons.join(", "));
      const named = reasons.map((r) => `mcp_servers.not_assessed_by_reason.${r}`);
      const sentence = `${named.slice(0, -1).join(", ")} and ${named.at(-1)} hold endpoints that asked for credentials`;
      assert.ok(description.includes(sentence), `the description does not name the reasons as the answer carries them: ${sentence}`);
    });
    it("asks for ?service=mcp, never the unparameterised answer (every AI service's counts)", () => {
      assert.ok(stub.state.seen.includes(MCP_PATH), stub.state.seen.join(", "));
      assert.ok(!stub.state.seen.includes("/api/v1/public/ai-exposure/stats"), stub.state.seen.join(", "));
    });
    it("a well-formed answer: every count and timestamp relayed as given, and nothing else", () => {
      assert.deepEqual(data.mcp_servers, MCP_RELAYED);
      assert.ok(!("service" in data.mcp_servers), "service is a string the answer carries, and not a timestamp");
      // No string but a timestamp: the relayed strings are exactly the answer's four instants.
      const strings = [];
      const walk = (v) => (typeof v === "string" ? strings.push(v) : v && typeof v === "object" && Object.values(v).forEach(walk));
      walk(data.mcp_servers);
      assert.deepEqual(strings.sort(), [MCP_STATS.window.from, MCP_STATS.window.to, MCP_STATS.last_run_at, MCP_STATS.counted_at].sort());
      for (const s of strings) assert.ok(realInstant(s), s);
    });
    it("the envelope: not_assessed with measured_at null, never the window's ends, last_run_at or counted_at", () => {
      const sc = res.structuredContent;
      assert.equal(sc.state, "not_assessed");
      assert.equal(sc.measured_at, null);
      assert.deepEqual(sc.freshness.mcp_servers, { last_run_at: MCP_STATS.last_run_at, enabled: true });
      assert.match(sc.notes[0], /mcp_servers dates its verdicts at most by a window \(mcp_servers\.window\), from the oldest check among them to the newest, so no count here is presented as a dated measurement and measured_at is null\./);
      assert.match(sc.notes[1], /freshness\.mcp_servers\.last_run_at with freshness\.mcp_servers\.enabled/);
      assert.match(sc.method, /; mcp_servers, the latest verdict on record per hostname named like an MCP server in EchelonGraph's own Certificate Transparency feed, from EchelonGraph's identified MCP probe \(server\/discover, and initialize only if that is refused; never tools\/call\), where protected means the endpoint's RFC 9728 protected-resource metadata validated\.$/);
      assert.equal(assertEnvelopeInText("exposure_radar with mcp_servers", res).state, "not_assessed");
    });
    it("the note labels every mcp_servers number by what it counts", () => {
      for (const re of [
        /MCP servers: mcp_servers\.total \(10217\) counts hostnames the AI-exposure radar has checked for an MCP server, each once, by its latest verdict on record; each was named like an MCP server in EchelonGraph's own Certificate Transparency feed, and not every one is an MCP server\./,
        /mcp_servers\.protected \(611\) counts hostnames whose \/mcp endpoint asked for credentials \(a 401 or 403\) and whose OAuth protected-resource metadata validated under RFC 9728: a 200 JSON document whose resource is identical to the server's identifier and that names at least one authorization server\./,
        /mcp_servers\.prm_via divides them by where that document was found: mcp_servers\.prm_via\.header \(402\), the same-origin URL the challenge named; mcp_servers\.prm_via\.wellknown_path \(131\), .*; and mcp_servers\.prm_via\.wellknown_root \(78\), that URI at the root\./,
        /mcp_servers\.pending_readjudication \(5\) counts verdicts decided by a rule EchelonGraph has since replaced and not yet re-checked under the current rules; they are in neither mcp_servers\.protected nor mcp_servers\.not_assessed\./,
        /mcp_servers\.not_assessed \(9601\) counts the rest, whose protection the radar could not assess; not assessed does not mean unprotected, and mcp_servers\.not_assessed_by_reason puts each in exactly one bucket\./,
        /Endpoints that asked for credentials \(a 401 or 403\) but whose RFC 9728 metadata did not validate are counted by why: mcp_servers\.not_assessed_by_reason\.resource_mismatch \(233\), the document's resource is absent or not identical to the server's identifier; /,
        /and mcp_servers\.not_assessed_by_reason\.metadata_invalid \(2\), the answer is not a 200 JSON object within the size cap\./,
        /Each of those endpoints asked for credentials, so none of them is shown to lack protection: only its metadata did not validate\./,
        /mcp_servers\.not_assessed_by_reason\.challenge_unadjudicated \(877\) counts endpoints that asked for credentials before EchelonGraph read RFC 9728 metadata, not re-checked since\./,
        /mcp_servers\.not_assessed_by_reason\.no_http_answer \(6120\) counts hostnames that gave no HTTP answer .* and mcp_servers\.not_assessed_by_reason\.not_identified_as_mcp \(1893\) hostnames that answered HTTP with nothing that identified an MCP server .*: neither is a count of MCP servers\./,
        /mcp_servers\.era\.dual \(4\), answered server\/discover and named an initialize-era version too, a lower bound, since a server built on the reference SDK names only modern versions there and is counted modern;/,
        /mcp_servers\.era\.modern \(37\), answered server\/discover and named no initialize-era version, not proven modern-only, since EchelonGraph does not send initialize to tell;/,
        /and mcp_servers\.era\.not_measured \(8561\), a verdict recorded before EchelonGraph's probe began recording the era and not re-checked since\./,
        /mcp_servers\.transport divides them by the transport that identified the server: mcp_servers\.transport\.streamable_http \(251\), a POST to \/mcp; mcp_servers\.transport\.legacy_sse \(3\)/,
        /mcp_servers\.own_controls_excluded \(3\) counts EchelonGraph's own control servers, which are left out of every other mcp_servers number\./,
        /mcp_servers\.window says when the verdicts counted were last checked: the oldest at 2026-09-12T00:04:01Z \(mcp_servers\.window\.from\) and the newest at 2026-09-28T22:51:09Z \(mcp_servers\.window\.to\), so the counts are each hostname's latest verdict, not one sweep at one time\./,
        /mcp_servers last completed check: 2026-09-28T23:05:44Z \(mcp_servers\.last_run_at, a timestamp, not a count\)\./,
        /mcp_servers\.enabled is true: the API reports the AI-exposure radar running, a check having completed within 45 minutes of its answer\./,
        /mcp_servers\.counted_at \(2026-09-28T23:06:00Z\) is when the API read these counts: a timestamp, not a count, and not when any verdict was checked\./,
      ]) {
        assert.match(note, re);
      }
      assert.doesNotMatch(note, /Left out of mcp_servers|left out of mcp_servers/, note);
      // Each stamp is printed in its own labelled sentence only.
      for (const t of [MCP_STATS.last_run_at, MCP_STATS.counted_at]) assert.equal(sentencesOf(note).filter((s) => s.includes(t)).length, 1, t);
    });
    it("identified_no_challenge: said to be normal in MCP and not a finding of exposure, never open, exposed or unauthenticated", () => {
      assert.match(
        note,
        /mcp_servers\.not_assessed_by_reason\.identified_no_challenge \(347\) counts servers that identified themselves as MCP servers \(a DiscoverResult, an InitializeResult, or the endpoint event of the deprecated HTTP\+SSE transport\) and did not ask for credentials at the handshake\. /,
      );
      const flatReadme = readme.replace(/\s+/g, " ");
      for (const [where, t] of [["note", note], ["description", description], ["README", flatReadme]]) {
        assert.match(t, NORMAL_IN_MCP, where);
        assert.match(t, /mcp_servers\.not_assessed_by_reason\.identified_no_challenge`? (?:\| )?(?:\(347\) counts |holds )?[Ss]ervers that identified themselves as MCP servers/, where);
      }
      // Every text a client holds, sentence by sentence (the README's table rows each one unit).
      const units = [
        ...sentencesOf(note),
        ...sentencesOf(description),
        ...sentencesOf(instructions),
        ...res.structuredContent.notes.flatMap(sentencesOf),
        ...sentencesOf(res.structuredContent.method),
        ...readmeUnits(readme),
      ];
      const checked = assertMCPNotAccused("exposure_radar", units);
      assert.ok(checked >= 40, `only ${checked} sentences about mcp_servers checked`);
      // The guard can fail: each way the bucket has been, or could be, mislabelled.
      for (const mutant of [
        "mcp_servers.not_assessed_by_reason.identified_no_challenge (347) counts open MCP servers.",
        "identified_no_challenge: 347 MCP servers exposed on the internet.",
        "mcp_servers.not_assessed_by_reason.identified_no_challenge counts unauthenticated MCP servers.",
        "That is normal in MCP, but these servers answer without authentication.",
        "mcp_servers holds 347 vulnerable servers.",
      ]) {
        assert.throws(() => assertMCPNotAccused("mutant", [mutant]), /calls a server open, exposed or unauthenticated/, mutant);
      }
    });
    it("no Shodan attribution covers mcp_servers: its discovery is EchelonGraph's own Certificate Transparency feed", () => {
      assert.match(note, /MCP-server discovery uses no Shodan data: its hostnames come from EchelonGraph's own Certificate Transparency feed, matched by hostname pattern\./);
      for (const s of sentencesOf(note).filter((x) => x.includes("mcp_servers"))) assert.doesNotMatch(s, /Shodan/, s);
      assert.match(description, /It also gives MCP-server counts: hostnames named like an MCP server in EchelonGraph's own Certificate Transparency feed \(no Shodan data\)/);
      assert.match(instructions, /exposure_radar's mcp_servers counts use no Shodan data: their hostnames come from EchelonGraph's own Certificate Transparency feed\./);
      assert.match(readme.replace(/\s+/g, " "), /Every hostname was named like an MCP server in EchelonGraph's own Certificate Transparency feed, matched by hostname pattern; no Shodan data is used\./);
    });
    it("no re-check interval is stated for mcp_servers", () => {
      const units = [...sentencesOf(note), ...sentencesOf(description), ...readmeUnits(readme)].filter((u) => NAMES_MCP.test(u));
      assert.equal(assertReprobeIntervalsQualified("mcp_servers", units), 0, "a sentence about mcp_servers names a re-check interval");
    });

    // ── what is refused: a failure of that radar, never zeros ──
    it("HTTP 400 (an API that does not serve service=mcp) is a failure entry for mcp_servers, not zeros", async () => {
      const r = await withMCP({ status: 400, body: { error: "unknown service", supported: [] } });
      const t = assertRefused(r, "http", 400, /^unknown service$/);
      assert.match(t, /- mcp_servers: EchelonGraph answered HTTP 400 from .* for GET \/api\/v1\/public\/ai-exposure\/stats\?service=mcp — the API said: unknown service\./, t);
      assert.equal(r.structuredContent.state, "failed", "exposure_radar takes no input, so a radar's 400 is not invalid_input");
    });
    it("a 200 from an API older than ?service=mcp (every AI service's counts, with a protected of their own) is refused, never relayed as MCP-server counts", async () => {
      const r = await withMCP({ open: 70913, protected: 44021, not_assessed: 290061, pending_readjudication: 0, enabled: true, last_run_at: MCP_STATS.last_run_at });
      const t = assertRefused(r, "unexpected_shape", 200, /^the answer carries no service field, so it is not the MCP-server counts: an API older than service=mcp ignores that parameter/);
      assert.match(t, /- mcp_servers: EchelonGraph answered HTTP 200 from .* for GET \/api\/v1\/public\/ai-exposure\/stats\?service=mcp, but the answer carries no service field, so it is not the MCP-server counts/, t);
      assert.doesNotMatch(everything(r), /70913|44021|290061/, "the all-services counts reached the result");
    });
    for (const [label, entry, kind, message] of [
      // A body that is not JSON is quoted, as every tool's not_json failure quotes it (#1874), so
      // this one carries no count.
      ["JSON cut off mid-object", { raw: '{"service":"mcp","total":' }, "not_json", /body starts: \{"service":"mcp","total":$/],
      ["a JSON null", { raw: "null" }, "not_object", /body was null/],
      ["a JSON array", [MCP_STATS], "unexpected_shape", /^the answer is not a JSON object carrying the MCP-server counts$/],
      ["a service other than mcp", { ...MCP_STATS, service: "evil-leak.example.com" }, "unexpected_shape", /^the answer names a service other than mcp, so it is not the MCP-server counts$/],
      ["a count sent as a string", { ...MCP_STATS, protected: "611" }, "unexpected_shape", /^its protected is missing or not a whole number of zero or more, so its counts are not relayed$/],
      ["a count missing", (({ total: _t, ...rest }) => rest)(MCP_STATS), "unexpected_shape", /^its total is missing or not a whole number/],
      ["a negative and a fractional count", { ...MCP_STATS, pending_readjudication: -5, not_assessed: 9601.5 }, "unexpected_shape", /^its pending_readjudication and not_assessed are missing or not a whole number/],
      ["counts that contradict each other (total is not protected + pending_readjudication + not_assessed)", { ...MCP_STATS, total: 10218 }, "unexpected_shape", /^its counts contradict each other \(total is not protected \+ pending_readjudication \+ not_assessed, an answer the API's own integrity check does not serve\), so they are not relayed$/],
    ]) {
      it(`a malformed answer, ${label}, is a failure entry for mcp_servers, not zeros`, async () => {
        const r = await withMCP(entry);
        assertRefused(r, kind, 200, message);
        assert.doesNotMatch(everything(r), /evil-leak/, "a string the answer carried reached the result");
      });
    }

    // ── what is left out: named, never relayed partly ──
    it("a partition whose buckets do not add up to the count it divides is left out whole and named; the rest is relayed", async () => {
      const { relayed, n } = await relaying({
        ...MCP_STATS,
        prm_via: { ...MCP_STATS.prm_via, header: 401 },
        era: { ...MCP_STATS.era, modern: 38 },
      });
      assert.equal(relayed.prm_via, undefined);
      assert.equal(relayed.era, undefined);
      const { prm_via: _p, era: _e, ...rest } = MCP_RELAYED;
      assert.deepEqual(relayed, rest);
      assert.match(n, /Left out of mcp_servers because their buckets do not add up to the count they divide: prm_via, era\./, n);
      assert.doesNotMatch(n, /mcp_servers\.prm_via\.|mcp_servers\.era\./, "a left-out partition's buckets are still labelled in the note");
      assert.match(n, /mcp_servers\.transport divides them/, n);
    });
    it("a partition missing a bucket, carrying one this version cannot label, or with a bucket that is not a count is left out whole and named; the unknown bucket's name is not repeated", async () => {
      const { dual: _dual, ...eraWithoutDual } = MCP_STATS.era;
      const { relayed, n, r } = await relaying({
        ...MCP_STATS,
        era: eraWithoutDual,
        transport: { ...MCP_STATS.transport, "evil-leak.example.com": 0 },
        not_assessed_by_reason: { ...MCP_REASONS, no_http_answer: "6120" },
      });
      for (const p of ["era", "transport", "not_assessed_by_reason"]) assert.equal(relayed[p], undefined, p);
      assert.deepEqual(relayed.prm_via, MCP_STATS.prm_via);
      assert.match(n, /Left out of mcp_servers because they were not in the expected shape: not_assessed_by_reason, era, transport\./, n);
      assert.doesNotMatch(everything(r), /evil-leak/);
      assert.doesNotMatch(n, /identified_no_challenge/, "a left-out partition's buckets are still labelled in the note");
    });
    it("a hostile field the answer should never carry is not relayed and its value never repeated; a field-shaped name is named, any other only counted", async () => {
      const { relayed, n, r } = await relaying({
        ...MCP_STATS,
        host: "evil-leak.example.com",
        hostnames: ["evil-leak.example.com", "203.0.113.7:443"],
        server_name: "EvilLeak MCP",
        version: "evil-leak-1.0",
        "evil-leak.example.com": 1,
        EvilLeak: { count: 9 },
      });
      assert.deepEqual(relayed, MCP_RELAYED, "the counts are relayed as before, and nothing else");
      assert.doesNotMatch(everything(r), /evil-?leak|203\.0\.113\.7/i, "a string the answer carried reached the result");
      assert.match(n, /Left out of mcp_servers because this version of the tool cannot label them: host, hostnames, server_name, version\./, n);
      assert.match(n, /Also left out of mcp_servers: 2 fields whose name is not shaped like a field name, not repeated here, since a name could itself identify a server\./, n);
      assert.deepEqual(unlabelledIn(JSON.parse(r.content[0].text)), []);
    });
    it("a timestamp that is not a time is not relayed, and not repeated; a window without a real span is left out and named", async () => {
      const { relayed, n, r } = await relaying({
        ...MCP_STATS,
        window: { from: "evil-leak.example.com", to: MCP_STATS.window.to },
        last_run_at: "0001-01-01T00:00:00Z",
        counted_at: "evil-leak.example.com",
      });
      for (const k of ["window", "last_run_at", "counted_at"]) assert.ok(!(k in relayed), `${k}: ${JSON.stringify(relayed[k])}`);
      assert.match(n, /Left out of mcp_servers because they were not in the expected shape: window\./, n);
      assert.doesNotMatch(everything(r), /evil-leak|0001-01-01/);
      assert.doesNotMatch(n, /mcp_servers last completed check/, n);
      assert.deepEqual(r.structuredContent.freshness.mcp_servers, { last_run_at: null, enabled: true });
      // A window whose from is after its to, and none at all while rows are counted, are left out too.
      for (const window of [{ from: MCP_STATS.window.to, to: MCP_STATS.window.from }, null, { from: null, to: null }]) {
        const again = await relaying({ ...MCP_STATS, window });
        assert.ok(!("window" in again.relayed), JSON.stringify(window));
        assert.match(again.n, /Left out of mcp_servers because they were not in the expected shape: window\./, JSON.stringify(window));
      }
    });
    it("the genuine-empty answer is relayed as zeros on record, with no window, and a radar not reported running is said in words", async () => {
      for (const window of [MCP_EMPTY.window, null]) {
        const { relayed, n, r } = await relaying({ ...MCP_EMPTY, window });
        const { service: _s, window: _w, last_run_at: _l, ...expected } = MCP_EMPTY;
        assert.deepEqual(relayed, expected);
        assert.match(n, /mcp_servers\.total is 0: the radar holds no verdict on record for a hostname named like an MCP server\./, n);
        assert.match(n, /mcp_servers\.enabled is false: the API does not report the AI-exposure radar running \(no check completed within 45 minutes of its answer\), so these numbers may be stale\./, n);
        assert.doesNotMatch(n, /Left out of mcp_servers|mcp_servers last completed check|mcp_servers\.window says/, n);
        assert.deepEqual(r.structuredContent.freshness.mcp_servers, { last_run_at: null, enabled: false });
      }
    });
    it("the outputSchema admits no mcp_servers string field but the timestamps, and no count but the labelled ones", () => {
      const s = branchOf(tools.find((t) => t.name === "exposure_radar").outputSchema, "not_assessed").properties.data.properties.mcp_servers;
      assert.equal(s.additionalProperties, false);
      const strings = [];
      const walk = (x, p) => {
        if (x?.type === "string") strings.push(p);
        for (const [k, y] of Object.entries(x?.properties ?? {})) walk(y, p ? `${p}.${k}` : k);
      };
      walk(s, "");
      assert.deepEqual(strings.sort(), ["counted_at", "last_run_at", "window.from", "window.to"]);
      assert.deepEqual([...schemaNumericPaths(s, "mcp_servers")].sort(), Object.keys(RADAR_LABELLED).filter((p) => p.startsWith("mcp_servers.")).sort());
    });
  });

  // #2311: every tool carries a title, the four annotations and an outputSchema, and the opening
  // exchange carries the server instructions.
  describe("#2311: tools/list, the opening exchange and the server instructions", () => {
    let tools;
    before(async () => {
      ({ tools } = await client.listTools());
    });
    it("the connection was opened in this run's era", () => {
      assert.equal(client.era, ERA);
      if (ERA === MODERN) {
        assert.ok(client.opening.supportedVersions.includes(MODERN), JSON.stringify(client.opening));
      } else {
        assert.equal(client.opening.protocolVersion, ERA, JSON.stringify(client.opening));
      }
    });
    it("every tool has a title, the four annotations, and an outputSchema", () => {
      assert.deepEqual(tools.map((t) => t.name), LISTED);
      for (const t of tools) {
        assert.equal(typeof t.title, "string", `${t.name}: no title`);
        assert.ok(t.title.trim().length > 0, `${t.name}: empty title`);
        assert.deepEqual(t.annotations, ANNOTATIONS, `${t.name}: annotations`);
        assert.ok(t.outputSchema && typeof t.outputSchema === "object", `${t.name}: no outputSchema`);
      }
      assert.equal(new Set(tools.map((t) => t.title)).size, LISTED.length, "two tools share a title");
    });
    it("every outputSchema is an object schema with a success branch that carries data and a failure branch that carries error", () => {
      for (const t of tools) {
        const s = t.outputSchema;
        assert.equal(s.type, "object", `${t.name}: the outputSchema root is not an object schema, so a 2025-era client would receive {result: ...}`);
        const ok = branchOf(s, "measured") ?? branchOf(s, "not_assessed");
        const bad = branchOf(s, "failed");
        assert.ok(ok && bad, `${t.name}: no success or failure branch`);
        assert.deepEqual(branchOf(s, "not_assessed"), ok, `${t.name}: not_assessed is not in the success branch`);
        assert.deepEqual(branchOf(s, "invalid_input"), bad, `${t.name}: invalid_input is not in the failure branch`);
        for (const k of ["state", "measured_at", "method", "coverage", "freshness", "notes", "data"]) assert.ok(ok.required.includes(k), `${t.name}: success does not require ${k}`);
        for (const k of ["state", "measured_at", "method", "coverage", "freshness", "notes", "error"]) assert.ok(bad.required.includes(k), `${t.name}: failure does not require ${k}`);
        assert.equal(bad.properties.data, undefined, `${t.name}: a failure may carry data`);
        assert.equal(bad.additionalProperties, false, `${t.name}: a failure admits fields the schema does not name`);
        assert.equal(ok.additionalProperties, false, `${t.name}: a success admits envelope fields the schema does not name`);
        assert.deepEqual(bad.properties.measured_at, { type: "null" }, `${t.name}: a failure may carry measured_at`);
        // Every state, and only these four.
        assert.deepEqual([...ok.properties.state.enum, ...bad.properties.state.enum].sort(), [...STATES].sort());
      }
    });
    it("the server instructions say the data is public, what freshness means, that exposure numbers are aggregate, and whose the Shodan data is", () => {
      const i = client.opening.instructions;
      assert.equal(typeof i, "string");
      assert.match(i, /Everything these tools return is public/);
      assert.match(i, /freshness gives the producing radar's last_run_at: when it last completed a check whose reads succeeded\./);
      assert.match(i, /not the time of every record the radar's numbers count/);
      assert.match(i, /Exposure numbers are aggregate/);
      assert.match(i, /not an internet-wide census/);
      assert.ok(i.includes(`Exposure counts are derived from Shodan data. ${SHODAN_OWNERSHIP}`), i);
      assert.match(i, /not_assessed means the answer holds no dated measurement of what was asked/);
      assert.doesNotMatch(i, REMOVED_CLAIMS);
      assert.doesNotMatch(i, HOST_UNIT);
    });
    it("the MCP handshake reports package.json's name and version", () => {
      assert.equal(client.getServerVersion()?.name, PKG.name);
      assert.equal(client.getServerVersion()?.version, PKG.version);
    });
    it("#2313: the exposure_radar outputSchema allows exactly the labelled numeric paths, no more and no fewer", () => {
      const s = tools.find((t) => t.name === "exposure_radar").outputSchema;
      const paths = [...schemaNumericPaths(branchOf(s, "not_assessed").properties.data)].sort();
      assert.deepEqual(paths.filter((p) => !(p in RADAR_LABELLED)), [], "the schema allows a number no label covers");
      assert.deepEqual(paths, Object.keys(RADAR_LABELLED).sort());
    });
    // #1880: descriptions listed fields the tools do not return (CWE on get_cve). A description
    // may name a field only if its own outputSchema holds it.
    it("#1880: every field a tool description names is a field, or a value, of that tool's outputSchema", () => {
      const toolNames = new Set(LISTED);
      for (const t of tools) {
        const names = schemaNames(t.outputSchema);
        const tokens = [...new Set(t.description.match(FIELD_TOKEN) ?? [])];
        assert.ok(tokens.length >= 2, `${t.name}: its description names no fields`);
        const unknown = tokens.filter((x) => !names.has(x) && !toolNames.has(x));
        assert.deepEqual(unknown, [], `${t.name}: the description names fields its outputSchema does not hold`);
      }
      assert.doesNotMatch(tools.find((t) => t.name === "get_cve").description, /\bCWE\b/, "get_cve returns no CWE");
    });
    it("#1880: every field the README names is a field, or a value, of some tool's outputSchema", () => {
      // #2722: the README's Prompts table names the prompts, which prompts-resources.test.mjs holds.
      const names = new Set([...LISTED, ...PROMPT_NAMES, ...tools.flatMap((t) => [...schemaNames(t.outputSchema)])]);
      const readme = readPkgFile("README.md").replace(/\b[\w.-]+\.json\b/g, "");
      const unknown = [...new Set(readme.match(FIELD_TOKEN) ?? [])].filter((x) => !names.has(x));
      assert.deepEqual(unknown, [], "the README names fields no outputSchema holds");
    });
  });

  // #2311 done-means 4: the new failure cases.
  describe("#2311: a bare-number body, truncated JSON, an empty or blank cve_id, a partial radar failure", () => {
    it("a 200 whose body is a bare number is a failure, for every tool: not a JSON object", async () => {
      stub.state.mode = "number";
      try {
        const results = await callAll(client);
        for (const name of TOOLS) {
          assertErrorResult(name, results[name]);
          assertNames(name, results[name], stub.base, /was not a JSON object/, /body was 42/);
          const sc = results[name].structuredContent;
          assert.equal(sc.state, "failed", name);
          assert.ok(!("data" in sc), name);
          // exposure_radar makes five requests, and names each radar's failure.
          if (name === "exposure_radar") assert.deepEqual(sc.error.radars.map((r) => r.kind), ["not_object", "not_object", "not_object", "not_object", "not_object"]);
          else assert.equal(sc.error.kind, "not_object", name);
        }
      } finally {
        stub.state.mode = "ok";
      }
    });
    it("a 200 whose JSON is cut off is a failure, for every tool: not JSON", async () => {
      stub.state.mode = "truncated";
      try {
        const results = await callAll(client);
        for (const name of TOOLS) {
          assertErrorResult(name, results[name]);
          assertNames(name, results[name], stub.base, /was not JSON/, /body starts: \{"summary"/);
          const sc = results[name].structuredContent;
          assert.equal(sc.state, "failed", name);
          assert.ok(!("data" in sc), name);
          if (name === "exposure_radar") assert.deepEqual(sc.error.radars.map((r) => r.kind), ["not_json", "not_json", "not_json", "not_json", "not_json"]);
          else assert.equal(sc.error.kind, "not_json", name);
          assert.doesNotMatch(textOf(results[name]), /found nothing|OK:/, name);
        }
      } finally {
        stub.state.mode = "ok";
      }
    });
    for (const blank of ["", "   ", "\t\n "]) {
      it(`cve_id ${JSON.stringify(blank)} is refused as invalid_input by get_cve and cve_exposure, with no request made`, async () => {
        stub.state.mode = "ok";
        stub.state.seen.length = 0;
        for (const name of ["get_cve", "cve_exposure"]) {
          const res = await client.callTool({ name, arguments: { cve_id: blank } });
          assertErrorResult(name, res);
          const t = noteOf(res);
          assert.match(t, new RegExp(`^${name} FAILED \\(state: invalid_input\\): cve_id is required\\. Nothing was looked up, so this is not a finding\\.$`), t);
          assert.equal(res.structuredContent.state, "invalid_input");
          // #2440: the message and its envelope block, nothing else.
          assert.equal(textBlocks(res).length, 2);
          assert.equal(envelopeOf(res).state, "invalid_input");
          assert.deepEqual(res.structuredContent.error, { kind: "invalid_input", path: null, status: null, message: "cve_id is required" });
        }
        // Before #1880's fix an empty id listed 50 unrelated CVEs as the answer.
        assert.deepEqual(stub.state.seen, [], "a blank cve_id reached the API");
      });
    }
    const LC_PATH = "/api/v1/public/leaked-credentials/stats";
    const SA_PATH = "/api/v1/public/shadow-ai-radar/stats";
    const radarWith = async (overrides) => {
      Object.assign(stub.state.overrides, overrides);
      try {
        return await client.callTool({ name: "exposure_radar", arguments: {} });
      } finally {
        for (const p of Object.keys(overrides)) delete stub.state.overrides[p];
      }
    };
    it("exposure_radar with one radar failing is a failure that names it and withholds the four that answered", async () => {
      stub.state.mode = "ok";
      const res = await radarWith({ [LC_PATH]: { status: 503, body: { error: "leaked-credentials store unavailable" } } });
      assertErrorResult("exposure_radar", res);
      const t = textOf(res);
      assert.match(t, /^exposure_radar FAILED: 1 of 5 radars could not be read from /, t);
      assert.match(t, /- leaked_credentials: EchelonGraph answered HTTP 503 from .* for GET \/api\/v1\/public\/leaked-credentials\/stats — the API said: leaked-credentials store unavailable\./, t);
      assert.match(t, /The 4 radar\(s\) that did answer \(kev_exposure, exposed_databases, shadow_ai, mcp_servers\) are withheld: a partial radar picture would be read as the whole one\./, t);
      assert.match(t, /this is not a finding: do not report it as zero/, t);
      const sc = res.structuredContent;
      assert.equal(sc.state, "failed");
      assert.ok(!("data" in sc), "a partial radar picture reached the structured result");
      assert.deepEqual(sc.coverage, { radars: ["kev_exposure", "exposed_databases", "leaked_credentials", "shadow_ai", "mcp_servers"], answered: ["kev_exposure", "exposed_databases", "shadow_ai", "mcp_servers"], failed: ["leaked_credentials"] });
      assert.deepEqual(sc.error.radars, [{ radar: "leaked_credentials", kind: "http", path: LC_PATH, status: 503, message: "leaked-credentials store unavailable" }]);
      // No number any answering radar sent reaches the result, in any block.
      assert.doesNotMatch(JSON.stringify(res), /25113|7380|36222|31887|10217|9601/);
    });
    it("exposure_radar with two radars failing names both, and the withheld two", async () => {
      stub.state.mode = "ok";
      const res = await radarWith({ [LC_PATH]: { status: 500, body: { error: "boom" } }, [SA_PATH]: { status: 404, body: { error: "no such route" } } });
      assertErrorResult("exposure_radar", res);
      assert.match(textOf(res), /2 of 5 radars could not be read/);
      assert.deepEqual(res.structuredContent.coverage.failed, ["leaked_credentials", "shadow_ai"]);
      assert.deepEqual(res.structuredContent.coverage.answered, ["kev_exposure", "exposed_databases", "mcp_servers"]);
      assert.deepEqual(res.structuredContent.error.radars.map((r) => [r.radar, r.status]), [["leaked_credentials", 500], ["shadow_ai", 404]]);
    });
  });

  // #2313: the envelope each tool returns, case by case.
  describe("#2313: state, measured_at, method, coverage and freshness, from what the API sends", () => {
    const call = (name, args = {}) => client.callTool({ name, arguments: args });
    before(() => {
      stub.state.mode = "ok";
    });
    it("every success carries data equal to content[0], and the note's sentences in notes", async () => {
      const results = await callAll(client);
      for (const name of TOOLS) {
        const res = results[name];
        assert.deepEqual(res.structuredContent.data, JSON.parse(res.content[0].text), name);
        const n = sentencesOf(res.content[1].text);
        assert.deepEqual(res.structuredContent.notes.slice(-n.length), n, `${name}: the note is not in notes`);
      }
    });
    // #2439: last_seen is EchelonGraph's write time, so a count it dates is not a dated
    // measurement. The count is relayed, labelled; state is not_assessed and measured_at null.
    it("#2439: cve_exposure, services on record with a real last_seen: not_assessed, undated, the count labelled, and last_seen named a write time", async () => {
      const res = await call("cve_exposure", { cve_id: CVE });
      const sc = res.structuredContent;
      assert.equal(sc.state, "not_assessed");
      assert.equal(sc.measured_at, null);
      assert.equal(sc.method, BACKEND_METHOD);
      assert.deepEqual(sc.coverage, { in_scope: true });
      assert.equal(sc.exposure_state, "exposed");
      assert.equal(sc.freshness, null);
      assert.equal(sc.data.exposed_hosts, 6213, "the count is still relayed");
      assert.equal(
        sc.notes[0],
        "state is not_assessed: exposed_hosts counts the services the radar has on record for CVE-2023-44487, but the answer does not say when any of them was observed, so that count is relayed as what the radar holds on record, not as a dated measurement, and measured_at is null.",
      );
      assert.equal(
        sc.notes[1],
        "last_seen (2026-09-15T04:02:09Z) is not measured_at: it is when EchelonGraph last wrote or refreshed one of these rows (when a Shodan search matched the banner, or a re-check found the port still listed), not when any service was observed, and Shodan's own banner time is not stored.",
      );
      assert.match(noteOf(res), /\(exposure_state: exposed\) The radar has 6213 internet-facing services \(distinct ip:port, the exposed_hosts field\) on record/);
    });
    // The production-shaped case the post-close review of #2313 replayed: 2.0.0 answered it
    // state measured, measured_at 21:52:34.976885Z, the poller's write time.
    it("#2439: production's answer (last_seen is the cycle's write time) is never measured, and no write time becomes measured_at", async () => {
      const P = `/api/v1/public/kev-exposure/cve/${CVE_PROD_WRITE_STAMPED}`;
      try {
        // The recorded answer, and the same answer stamped at each write time in the capture.
        for (const last_seen of PROD_WRITE_TIMES) {
          stub.state.overrides[P] = { ...PROD_WRITE_STAMPED, last_seen };
          const res = await call("cve_exposure", { cve_id: CVE_PROD_WRITE_STAMPED });
          assert.notEqual(res.isError, true, brief(res));
          const sc = res.structuredContent;
          assert.notEqual(sc.state, "measured", `${last_seen}: a write time made the count measured`);
          assert.equal(sc.state, "not_assessed", last_seen);
          assert.equal(sc.measured_at, null, last_seen);
          for (const t of PROD_WRITE_TIMES) assert.notEqual(sc.measured_at, t, `${last_seen}: measured_at is the write time ${t}`);
          assert.equal(sc.exposure_state, "exposed");
          assert.deepEqual(sc.coverage, { in_scope: true });
          // Relayed, labelled: the count and where it comes from, not dropped.
          assert.equal(sc.data.exposed_hosts, 229);
          assert.equal(sc.data.last_seen, last_seen);
          const n = noteOf(res);
          assert.match(n, /\(exposure_state: exposed\) The radar has 229 internet-facing services \(distinct ip:port, the exposed_hosts field\) on record whose banner version maps to CVE-2026-87902 across 32 countries\./, n);
          assert.ok(n.includes(`Their latest last_seen is ${last_seen}: when EchelonGraph last wrote or refreshed one of their rows, not when any of them was observed`), n);
          assert.ok(sc.notes.some((s) => s.startsWith(`last_seen (${last_seen}) is not measured_at: it is when EchelonGraph last wrote or refreshed one of these rows`)), sc.notes.join(" | "));
          // The text says the same (#2440).
          const env = assertEnvelopeInText(`cve_exposure ${last_seen}`, res);
          assert.equal(env.state, "not_assessed");
          assert.equal(env.measured_at, null);
        }
      } finally {
        delete stub.state.overrides[P];
      }
    });
    // measured returns only through observedAt, which reads no field today. A field the API does
    // not serve (any name a future observation time might take) must not be read into one.
    it("#2439: a time field the API does not serve today is not read as an observation time", async () => {
      const P = `/api/v1/public/kev-exposure/cve/${CVE_PROD_WRITE_STAMPED}`;
      stub.state.overrides[P] = {
        ...PROD_WRITE_STAMPED,
        observed_at: "2026-09-20T00:00:00Z",
        first_seen: "2026-09-10T00:00:00Z",
        banner_timestamp: "2026-09-19T00:00:00Z",
        observed_window: { from: "2026-09-06T00:00:00Z", to: "2026-09-20T00:00:00Z" },
      };
      try {
        const sc = (await call("cve_exposure", { cve_id: CVE_PROD_WRITE_STAMPED })).structuredContent;
        assert.equal(sc.state, "not_assessed");
        assert.equal(sc.measured_at, null);
        // Relayed in data, verbatim, as the API's JSON always is.
        assert.equal(sc.data.observed_at, "2026-09-20T00:00:00Z");
      } finally {
        delete stub.state.overrides[P];
      }
    });
    it("cve_exposure, tracked:false: not_assessed, out of scope, undated", async () => {
      for (const id of [CVE_UNTRACKED, CVE_UNTRACKED_STALE]) {
        const sc = (await call("cve_exposure", { cve_id: id })).structuredContent;
        assert.equal(sc.state, "not_assessed", id);
        assert.equal(sc.measured_at, null, id);
        assert.deepEqual(sc.coverage, { in_scope: false }, id);
        assert.equal(sc.exposure_state, "not_assessed", id);
        assert.match(sc.notes[0], /is outside the radar's tracked set, so no number in data is a measurement of its exposure/, id);
      }
    });
    it("cve_exposure, no tracked field (an older API): not_assessed, in_scope null, never the Go zero time", async () => {
      const res = await call("cve_exposure", { cve_id: CVE_OLD_API });
      const sc = res.structuredContent;
      assert.equal(sc.state, "not_assessed");
      assert.equal(sc.measured_at, null);
      assert.deepEqual(sc.coverage, { in_scope: null });
      assert.equal(sc.exposure_state, "tracking_unknown");
      // The method the API did not send is the package's own statement of it, never absent.
      assert.match(sc.method, /^Shodan banner match on the radar's tracked products/);
      assert.doesNotMatch(JSON.stringify({ ...sc, data: undefined }), /0001-01-01/);
    });
    it("cve_exposure, tracked:true with 0 services: exposure_state measured_zero, but not_assessed: a zero has no observation to date it", async () => {
      stub.state.mode = "empty";
      try {
        const sc = (await call("cve_exposure", { cve_id: CVE })).structuredContent;
        assert.equal(sc.exposure_state, "measured_zero");
        assert.equal(sc.state, "not_assessed");
        assert.equal(sc.measured_at, null);
        assert.deepEqual(sc.coverage, { in_scope: true });
      } finally {
        stub.state.mode = "ok";
      }
    });
    // #2440: 2.0.0's text tagged this case "(state: measured_zero)" while the envelope said
    // not_assessed. The text now tags exposure_state, and carries the envelope itself.
    it("#2440: a tracked zero's text and structured result agree: exposure_state measured_zero in both, state not_assessed in both", async () => {
      stub.state.mode = "empty";
      try {
        const res = await call("cve_exposure", { cve_id: CVE });
        const sc = res.structuredContent;
        const n = noteOf(res);
        assert.match(n, /\(exposure_state: measured_zero\)/, n);
        assert.doesNotMatch(n, /\(state: /, n);
        const env = assertEnvelopeInText("cve_exposure tracked zero", res);
        assert.equal(env.state, "not_assessed");
        assert.equal(env.exposure_state, "measured_zero");
        assert.equal(env.measured_at, null);
        assert.equal(sc.state, env.state);
        assert.equal(sc.exposure_state, env.exposure_state);
        assert.match(env.notes[0], /^state is not_assessed: the API marks CVE-2023-44487 as tracked with 0 services on record, but a zero has no observation to date it/);
      } finally {
        stub.state.mode = "ok";
      }
    });
    it("cve_exposure, services on record but no real last_seen: not presented as measured", async () => {
      const P = `/api/v1/public/kev-exposure/cve/${CVE}`;
      for (const last_seen of [null, "0001-01-01T00:00:00Z", undefined]) {
        const { last_seen: _drop, ...body } = BODIES[P].ok;
        stub.state.overrides[P] = last_seen === undefined ? body : { ...body, last_seen };
        try {
          const sc = (await call("cve_exposure", { cve_id: CVE })).structuredContent;
          assert.equal(sc.exposure_state, "exposed", String(last_seen));
          assert.equal(sc.state, "not_assessed", String(last_seen));
          assert.equal(sc.measured_at, null, String(last_seen));
          // No real last_seen, so no sentence about one, and never the Go zero time.
          assert.ok(!sc.notes.some((s) => s.startsWith("last_seen (")), String(last_seen));
          assert.doesNotMatch(sc.notes.join(" "), /0001-01-01/);
        } finally {
          delete stub.state.overrides[P];
        }
      }
    });
    it("cve_exposure, HTTP 400: invalid_input with the API's status and message", async () => {
      const sc = (await call("cve_exposure", { cve_id: CVE_REJECTED })).structuredContent;
      assert.equal(sc.state, "invalid_input");
      assert.deepEqual(sc.error, { kind: "http", path: `/api/v1/public/kev-exposure/cve/${CVE_REJECTED}`, status: 400, message: "invalid CVE id" });
      assert.equal(sc.method, null);
      assert.equal(sc.measured_at, null);
    });
    it("get_cve, HTTP 404: failed, with the API's own message", async () => {
      stub.state.mode = "empty";
      try {
        const sc = (await call("get_cve", { cve_id: CVE })).structuredContent;
        assert.equal(sc.state, "failed");
        assert.deepEqual(sc.error, { kind: "http", path: `/api/v1/public/cves/${CVE}`, status: 404, message: `CVE not found: ${CVE}` });
      } finally {
        stub.state.mode = "ok";
      }
    });
    it("exposure_radar: not_assessed and undated, with each radar's last_run_at as freshness, and every radar answered", async () => {
      const sc = (await call("exposure_radar")).structuredContent;
      assert.equal(sc.state, "not_assessed");
      assert.equal(sc.measured_at, null);
      // #2315: mcp_servers dates its verdicts by a window, which is not one observation time.
      assert.match(sc.notes[0], /^state is not_assessed: every radar answered, but none gives one time at which what it counts was observed: kev_exposure, exposed_databases, leaked_credentials and shadow_ai give none, and mcp_servers dates its verdicts at most by a window \(mcp_servers\.window\)/);
      assert.deepEqual(sc.freshness, {
        kev_exposure: { last_run_at: LAST_RUN.kev_exposure },
        exposed_databases: { last_run_at: LAST_RUN.exposed_databases },
        leaked_credentials: { last_run_at: LAST_RUN.leaked_credentials },
        // The fixture's poller block is an older API's follower: freshness unknown, so null.
        shadow_ai: { last_run_at: null, running: null },
        mcp_servers: { last_run_at: MCP_STATS.last_run_at, enabled: true },
      });
      const radars = ["kev_exposure", "exposed_databases", "leaked_credentials", "shadow_ai", "mcp_servers"];
      assert.deepEqual(sc.coverage, { radars, answered: radars, failed: [] });
      // generated_at is never presented as freshness or as measured_at.
      assert.doesNotMatch(JSON.stringify({ ...sc, data: undefined, notes: undefined }), /2026-09-27T09:00:00Z/);
    });
    it("exposure_radar: a running fleet's poller block is shadow_ai's freshness; an unreal stamp never is", async () => {
      const SA = "/api/v1/public/shadow-ai-radar/stats";
      const KEV = "/api/v1/public/kev-exposure/stats";
      stub.state.overrides[SA] = { stats: PROD_SHADOW_STATS, poller: FLEET_RUNNING };
      stub.state.overrides[KEV] = { ...PROD_KEV_STATS, last_run_at: "0001-01-01T00:00:00Z" };
      try {
        const sc = (await call("exposure_radar")).structuredContent;
        assert.deepEqual(sc.freshness.shadow_ai, { last_run_at: FLEET_RUNNING.last_run_at, running: true });
        assert.deepEqual(sc.freshness.kev_exposure, { last_run_at: null });
      } finally {
        delete stub.state.overrides[SA];
        delete stub.state.overrides[KEV];
      }
    });
    it("cve_summary: measured, dated by summary.last_updated; get_cve: dated by the record's updated_at when it has one", async () => {
      const s = (await call("cve_summary")).structuredContent;
      assert.equal(s.state, "measured");
      assert.equal(s.measured_at, "2026-09-30T09:56:35.584Z");
      assert.equal(s.freshness, null);
      const g = (await call("get_cve", { cve_id: CVE })).structuredContent;
      assert.equal(g.state, "measured");
      assert.equal(g.measured_at, null, "the fixture record has no updated_at");
      const P = `/api/v1/public/cves/${CVE}`;
      stub.state.overrides[P] = { ...BODIES[P].ok, updated_at: "2026-09-20T01:02:03Z" };
      try {
        assert.equal((await call("get_cve", { cve_id: CVE })).structuredContent.measured_at, "2026-09-20T01:02:03Z");
      } finally {
        delete stub.state.overrides[P];
      }
    });
    // core-backend cve/handler.go ListCVEs: total_counted false means no count is in hand and
    // total means nothing; total_is_lower_bound true means at least total; search_relaxed true
    // means the rows are a superset of a phrase's matches.
    it("search_cves: coverage is the list's own account, and an uncounted total is never called a count", async () => {
      const P = "/api/v1/public/cves";
      const row = BODIES[P].ok.cves[0];
      const cases = [
        [{ cves: [row], total: 0, total_counted: false, total_is_lower_bound: false, search_relaxed: false, limit: 2, offset: 0 }, /The API did not count the matches \(total_counted is false\), so its total is not a count; 1 returned in this page\./, /matched|found nothing/],
        [{ cves: [row], total: 5000, total_counted: true, total_is_lower_bound: true, search_relaxed: false, limit: 2, offset: 0 }, /The query matched at least 5000 CVEs \(total_is_lower_bound is true: the count stopped at that floor\); 1 returned in this page\./, /found nothing/],
        [{ cves: [row], total: 12, total_counted: true, total_is_lower_bound: false, search_relaxed: true, limit: 2, offset: 0 }, /The query matched 12 CVEs; 1 returned in this page\. The API relaxed the search phrase to all of its words \(search_relaxed is true\), so these rows are a superset of the rows that match the phrase itself\./, /found nothing/],
        [{ cves: [], total: 0, total_counted: false, total_is_lower_bound: false, search_relaxed: false, limit: 2, offset: 0 }, /The query returned 0 CVEs — a measured empty result/, /matched \d/],
      ];
      for (const [body, says, never] of cases) {
        stub.state.overrides[P] = body;
        try {
          const res = await call("search_cves", { search: "tomcat", limit: 2 });
          assert.notEqual(res.isError, true, brief(res));
          const n = noteOf(res);
          assert.match(n, says, n);
          assert.doesNotMatch(n, never, n);
          const { cves, ...flags } = body;
          assert.deepEqual(res.structuredContent.coverage, { ...flags, returned: cves.length });
        } finally {
          delete stub.state.overrides[P];
        }
      }
    });
    it("a 2xx whose field does not fit the outputSchema is a failure, worded as one, never relayed", async () => {
      const cases = [
        ["get_cve", { cve_id: CVE }, `/api/v1/public/cves/${CVE}`, { ...BODIES[`/api/v1/public/cves/${CVE}`].ok, cvss_v3_score: "7.5" }, /cvss_v3_score/],
        ["cve_exposure", { cve_id: CVE }, `/api/v1/public/kev-exposure/cve/${CVE}`, { ...BODIES[`/api/v1/public/kev-exposure/cve/${CVE}`].ok, exposed_hosts: "6213" }, /exposed_hosts/],
        ["search_cves", CALLS.search_cves, "/api/v1/public/cves", { ...BODIES["/api/v1/public/cves"].ok, total: "1" }, /total/],
      ];
      for (const [name, args, p, body, field] of cases) {
        stub.state.overrides[p] = body;
        try {
          const res = await call(name, args);
          assertErrorResult(name, res);
          assertNames(name, res, stub.base, /did not match this tool's output schema/, field, /this is not a finding/);
          assert.equal(res.structuredContent.state, "failed");
          assert.equal(res.structuredContent.error.kind, "unexpected_shape");
          assert.ok(!("data" in res.structuredContent));
        } finally {
          delete stub.state.overrides[p];
        }
      }
    });
    it("a field the API adds later is still relayed by the tools that relay the API's JSON verbatim", async () => {
      const P = `/api/v1/public/cves/${CVE}`;
      stub.state.overrides[P] = { ...BODIES[P].ok, cwe_ids: ["CWE-400"], brand_new: { nested: 1 } };
      try {
        const res = await call("get_cve", { cve_id: CVE });
        assert.notEqual(res.isError, true, brief(res));
        assert.deepEqual(res.structuredContent.data.cwe_ids, ["CWE-400"]);
      } finally {
        delete stub.state.overrides[P];
      }
    });
  });

  // #2535: get_cve and search_cves relay echelongraph_score as the API sends it, and the note
  // says what it is: a score only when score_assessed is true. For a CVE whose answer says
  // score_assessed false the note says NOT YET SCORED (NOT SCORED for a rejected record) and
  // never reads a 0 as a score; for one whose answer carries no score_assessed it says the
  // answer does not say; for a scored CVE the note is what it was before #2535, word for word.
  describe("#2535: an EchelonGraph score is a score only when score_assessed is true", () => {
    const call = (name, args) => client.callTool({ name, arguments: args });
    const GET = (id) => `/api/v1/public/cves/${id}`;
    const LIST = "/api/v1/public/cves";
    const SCORED = BODIES[GET(CVE)].ok;
    const SCORED_ROW = BODIES[LIST].ok.cves[0];
    // get_cve, or a one-page search_cves, against a body served for this call only.
    async function served(p, body, name, args) {
      stub.state.mode = "ok";
      stub.state.overrides[p] = body;
      try {
        const res = await call(name, args);
        assert.notEqual(res.isError, true, brief(res));
        return res;
      } finally {
        delete stub.state.overrides[p];
      }
    }
    const getCve = (body) => served(GET(body.cve_id), body, "get_cve", { cve_id: body.cve_id });
    const searchPage = (rows) => served(LIST, { cves: rows, limit: 50, offset: 0, total: rows.length }, "search_cves", { search: "x", limit: 50 });
    // A note that reads a 0 as a score says "0" somewhere: "EG score 0", "EG 0.0",
    // "echelongraph_score: 0", "scored 0". The note's own score sentences write no digit, so once
    // the base URL and the CVE ids are taken out, no 0 may be left in it.
    function assertNoZeroRead(where, note) {
      const bare = note.split(stub.base).join(" ").replace(/CVE-\d{4}-\d{4,}/g, " ").replace(/cves\[\d+\]/g, " ");
      // A 0 or 0.0 standing alone, a sentence's last word included; not the 0 of 10, 200 or 0.5.
      assert.doesNotMatch(bare, /(?<![\w.])0(?:\.0+)?(?!\.?\d|\w)/, `${where}: the note says 0: ${note}`);
    }

    it("the zero check can fail: the ways a note could read a 0 as a score are caught, and a note with none passes", () => {
      const head = `get_cve OK: EchelonGraph answered HTTP 200 from ${stub.base}. Returned the record for ${CVE_UNSCORED_ZERO}.`;
      assertNoZeroRead("control", head);
      assertNoZeroRead("control", `${head} The query matched 10 CVEs, the first with an EPSS of 0.5.`);
      for (const mutant of [" Its EG score is 0.", " EG 0.0.", " echelongraph_score: 0.", ` ${CVE_UNSCORED_ZERO} scored 0 (NONE).`]) {
        assert.throws(() => assertNoZeroRead("mutant", head + mutant), /the note says 0/, mutant);
      }
    });

    it("get_cve, score_assessed false with the placeholders 0, NONE and 0: NOT YET SCORED, each placeholder named, no 0 read as a score, the JSON relayed as sent", async () => {
      const body = SCORE_ROWS[CVE_UNSCORED_ZERO];
      const res = await getCve(body);
      const n = noteOf(res);
      assert.equal(
        n,
        `get_cve OK: EchelonGraph answered HTTP 200 from ${stub.base}. Returned the record for ${CVE_UNSCORED_ZERO}. (score_assessed: false) NOT YET SCORED: EchelonGraph has not yet scored ${CVE_UNSCORED_ZERO}, so the record holds no EchelonGraph score for it, and the absence of one does not mean ${CVE_UNSCORED_ZERO} is harmless. score_unassessed_reason is no_signal: no source has yet published severity data EchelonGraph can score. echelongraph_score, echelongraph_severity and echelongraph_risk are placeholders, not a score: report ${CVE_UNSCORED_ZERO} as not yet scored, and do not repeat those values as its score.`,
      );
      assertNoZeroRead("get_cve", n);
      // Relayed as given: the placeholders stay in the JSON, and the note says what they are.
      assert.deepEqual(JSON.parse(res.content[0].text), body);
      assert.deepEqual(res.structuredContent.data, body);
      assert.equal(res.structuredContent.state, "measured");
      assert.ok(res.structuredContent.notes.includes("(score_assessed: false) NOT YET SCORED: EchelonGraph has not yet scored CVE-2099-20001, so the record holds no EchelonGraph score for it, and the absence of one does not mean CVE-2099-20001 is harmless."), res.structuredContent.notes.join(" | "));
    });

    it("get_cve, score_assessed false with the placeholders withheld (production's shape): NOT YET SCORED, and never a zero", async () => {
      const res = await getCve(SCORE_ROWS[CVE_UNSCORED]);
      const n = noteOf(res);
      assert.equal(
        n,
        `get_cve OK: EchelonGraph answered HTTP 200 from ${stub.base}. Returned the record for ${CVE_UNSCORED}. (score_assessed: false) NOT YET SCORED: EchelonGraph has not yet scored ${CVE_UNSCORED}, so the record holds no EchelonGraph score for it, and the absence of one does not mean ${CVE_UNSCORED} is harmless. score_unassessed_reason is no_signal: no source has yet published severity data EchelonGraph can score. Report ${CVE_UNSCORED} as not yet scored, not as a zero or low score.`,
      );
      assertNoZeroRead("get_cve", n);
      assert.deepEqual(res.structuredContent.data, SCORE_ROWS[CVE_UNSCORED]);
    });

    it("get_cve, score_assessed false for a rejected record: NOT SCORED, never NOT YET SCORED, since it never will be", async () => {
      const n = noteOf(await getCve(SCORE_ROWS[CVE_UNSCORED_REJECTED]));
      assert.match(n, /\(score_assessed: false\) NOT SCORED: the record of CVE-2099-20003 was rejected \(withdrawn\) by its numbering authority \(score_unassessed_reason rejected\), and EchelonGraph does not score a withdrawn record/, n);
      assert.match(n, /Report CVE-2099-20003 as not scored, not as a zero or low score\.$/, n);
      assert.doesNotMatch(n, /NOT YET SCORED|not yet scored/, n);
      assertNoZeroRead("get_cve", n);
    });

    it("get_cve, no score_assessed in the answer: the note says the answer does not say, and never presents the 0 as a score", async () => {
      const res = await getCve(SCORE_ROWS[CVE_SCORE_UNSTATED]);
      const n = noteOf(res);
      assert.equal(
        n,
        `get_cve OK: EchelonGraph answered HTTP 200 from ${stub.base}. Returned the record for ${CVE_SCORE_UNSTATED}. The answer does not say whether EchelonGraph has scored ${CVE_SCORE_UNSTATED}: it carries no score_assessed (an API older than that field sends none). echelongraph_score is EchelonGraph's score only when score_assessed is true, so a zero echelongraph_score there is not a rating: it can be the placeholder a CVE not yet scored carries.`,
      );
      // It does not say NOT YET SCORED either: the answer does not say that.
      assert.doesNotMatch(n, /NOT YET SCORED|NOT SCORED|score_assessed: false/, n);
      assertNoZeroRead("get_cve", n);
      assert.deepEqual(res.structuredContent.data, SCORE_ROWS[CVE_SCORE_UNSTATED]);
    });

    it("get_cve, score_assessed true: the note is unchanged, word for word", async () => {
      const res = await getCve(SCORED);
      assert.equal(noteOf(res), `get_cve OK: EchelonGraph answered HTTP 200 from ${stub.base}. Returned the record for ${CVE}.`);
      assert.equal(res.structuredContent.data.echelongraph_score, 9);
    });

    it("search_cves labels each row by its score_assessed: every unscored row named NOT YET SCORED, the rejected one NOT SCORED, the unstated one as not said, the scored one not at all", async () => {
      const rows = [SCORED_ROW, SCORE_ROWS[CVE_UNSCORED_ZERO], SCORE_ROWS[CVE_UNSCORED], SCORE_ROWS[CVE_UNSCORED_REJECTED], SCORE_ROWS[CVE_SCORE_UNSTATED]];
      const res = await searchPage(rows);
      const n = noteOf(res);
      assert.equal(
        n,
        `search_cves OK: EchelonGraph answered HTTP 200 from ${stub.base}. The query matched 5 CVEs; 5 returned in this page. ` +
          `(score_assessed: false) NOT YET SCORED: 2 of the 5 CVEs in this page are not yet scored by EchelonGraph: ${CVE_UNSCORED_ZERO} and ${CVE_UNSCORED}. For each, echelongraph_score, echelongraph_severity and echelongraph_risk, where its row carries them, are placeholders, not a score, and the absence of a score does not mean the CVE is harmless: report each as not yet scored, not as a zero or low score. ` +
          `(score_assessed: false) NOT SCORED: 1 of the 5 CVEs in this page has a record rejected (withdrawn) by the numbering authority (score_unassessed_reason rejected), which EchelonGraph does not score: ${CVE_UNSCORED_REJECTED}. For each, echelongraph_score, echelongraph_severity and echelongraph_risk, where its row carries them, are placeholders, not a score: report each as not scored. ` +
          `The answer does not say whether EchelonGraph has scored 1 of the 5 CVEs in this page: ${CVE_SCORE_UNSTATED} (no score_assessed in its row; an API older than that field sends none). echelongraph_score is EchelonGraph's score only when score_assessed is true, so a zero echelongraph_score there is not a rating: it can be the placeholder a CVE not yet scored carries.`,
      );
      // The scored row is in no sentence about scores.
      assert.ok(!n.includes(CVE), `the scored row ${CVE} is labelled: ${n}`);
      assertNoZeroRead("search_cves", n);
      assert.deepEqual(res.structuredContent.data.cves, rows);
    });

    it("search_cves, one row and it unscored: the 1 CVE in this page is NOT YET SCORED, by id", async () => {
      const n = noteOf(await searchPage([SCORE_ROWS[CVE_UNSCORED_ZERO]]));
      assert.match(n, /\(score_assessed: false\) NOT YET SCORED: the 1 CVE in this page is not yet scored by EchelonGraph: CVE-2099-20001\./, n);
      assertNoZeroRead("search_cves", n);
    });

    it("search_cves, every row without score_assessed: the answer does not say, for all of them, and no 0 is read as a score", async () => {
      const unstated = [SCORE_ROWS[CVE_SCORE_UNSTATED], { ...SCORE_ROWS[CVE_SCORE_UNSTATED], cve_id: "CVE-2099-20005" }];
      const n = noteOf(await searchPage(unstated));
      assert.match(n, /The answer does not say whether EchelonGraph has scored all 2 CVEs in this page: CVE-2099-20004 and CVE-2099-20005 \(no score_assessed in their rows; an API older than that field sends none\)\./, n);
      assert.doesNotMatch(n, /NOT YET SCORED|NOT SCORED/, n);
      assertNoZeroRead("search_cves", n);
    });

    it("search_cves, every row scored: the note is unchanged, word for word", async () => {
      const n = noteOf(await searchPage([SCORED_ROW]));
      assert.equal(n, `search_cves OK: EchelonGraph answered HTTP 200 from ${stub.base}. The query matched 1 CVEs; 1 returned in this page.`);
    });

    it("both descriptions say the score is a score only when score_assessed is true, and that an unscored CVE is NOT YET SCORED, not scored 0", async () => {
      const { tools } = await client.listTools();
      for (const name of ["search_cves", "get_cve"]) {
        const t = tools.find((x) => x.name === name);
        const d = t.description;
        assert.ok(d.includes("echelongraph_score, echelongraph_severity and echelongraph_risk are EchelonGraph's score only when score_assessed is true."), `${name}: ${d}`);
        assert.ok(d.includes("With score_assessed false the CVE is NOT YET SCORED, not scored 0: any of those three it carries (0, NONE, 0) is a placeholder, not a rating, and does not mean the CVE is harmless;"), `${name}: ${d}`);
        assert.ok(d.includes("An answer with no score_assessed (an API older than that field) does not say whether the CVE was scored, the note says so, and a 0 there is not a rating either."), `${name}: ${d}`);
        // The outputSchema describes the field, and the score fields beside it.
        const data = branchOf(t.outputSchema, "measured").properties.data;
        const rec = name === "get_cve" ? data : data.properties.cves.items;
        assert.match(rec.properties.score_assessed.description, /^Whether EchelonGraph has scored the CVE\. true: echelongraph_score, echelongraph_severity and echelongraph_risk are its score\. false: the CVE is NOT YET SCORED, not scored 0/, name);
        assert.deepEqual(rec.properties.score_assessed.type, ["boolean", "null"], name);
        for (const f of ["echelongraph_score", "echelongraph_severity", "echelongraph_risk"]) {
          assert.match(rec.properties[f].description, /only when score_assessed is true\. With score_assessed false it is a placeholder/, `${name} ${f}`);
        }
        assert.match(rec.properties.score_unassessed_reason.description, /^Why score_assessed is false: no_signal, .*; or rejected, /, name);
      }
    });

    it("a score_assessed that is not a boolean is not relayed: the answer does not fit the outputSchema", async () => {
      stub.state.overrides[GET(CVE)] = { ...SCORED, score_assessed: "false" };
      try {
        const res = await call("get_cve", { cve_id: CVE });
        assertErrorResult("get_cve", res);
        assertNames("get_cve", res, stub.base, /did not match this tool's output schema/, /score_assessed/);
      } finally {
        delete stub.state.overrides[GET(CVE)];
      }
    });
  });

  // cve_summary against a body served for this call only (#2610, #2641).
  async function cveSummaryWith(body) {
    stub.state.mode = "ok";
    stub.state.overrides["/api/v1/public/cves/summary"] = body;
    try {
      const res = await client.callTool({ name: "cve_summary", arguments: {} });
      assert.notEqual(res.isError, true, brief(res));
      return res;
    } finally {
      delete stub.state.overrides["/api/v1/public/cves/summary"];
    }
  }
  // The answer with the named summary fields left out: what an API older than them sends.
  const cveSummaryWithout = (...keys) => {
    const ok = BODIES["/api/v1/public/cves/summary"].ok;
    return { ...ok, summary: Object.fromEntries(Object.entries(ok.summary).filter(([k]) => !keys.includes(k))) };
  };
  const NVD_HISTOGRAM = ["nvd_critical", "nvd_high", "nvd_medium", "nvd_low", "nvd_none"];

  // #2610: cve_summary relays summary.none as the API sends it, and says what it counts. core-backend
  // cve/store.go Summary buckets the active CVEs on effectiveSeverityExpr (the EchelonGraph band,
  // else NVD's, else the CVSS v2 band, else NONE, a NONE or UNKNOWN band counting as none), so
  // summary.none is the CVEs with no severity band from any source, and the store sends it again as
  // summary.unscored ("the residual band-less bucket … numerically identical to None"). It is not a
  // count of CVEs rated severity None. Production answered none 3,381 and unscored 3,381 on
  // 2026-09-30, and a model handed 2.3.1's "counts by severity (… summary.none)" reports 3,381 CVEs
  // rated None: #2535's defect, in aggregate. The note labels a none above zero and names unscored as
  // the same count only when the answer carries it equal; a zero is not labelled.
  describe("#2610: cve_summary says summary.none counts CVEs not yet scored, never CVEs rated None", () => {
    const P = "/api/v1/public/cves/summary";
    const OK = BODIES[P].ok;
    const withSummary = (fields) => ({ ...OK, summary: { ...OK.summary, ...fields } });
    const STAMP = OK.summary.last_updated;
    // The four bands, which with none (and so with unscored) add up to total, as in store.go.
    const BANDED = OK.summary.critical + OK.summary.high + OK.summary.medium + OK.summary.low;
    const summary = cveSummaryWith;
    const label = (none) => `summary.none (${none}) is not a severity rating of None: it counts the active CVEs with no severity band from any source, that is, CVEs not yet scored.`;
    const REPORT = "Report them as not yet scored, not as CVEs rated None.";
    // The property, for a note relaying a summary.none above zero: it says what the count is, and how
    // to report it. The tests and the control below all call this.
    function assertNoneLabelled(where, note, none) {
      assert.ok(note.includes(label(none)), `${where}: the note does not say what summary.none (${none}) counts: ${note}`);
      assert.ok(note.includes(REPORT), `${where}: the note does not say how to report summary.none: ${note}`);
    }

    it("the fixture, production's whole answer (none 3408, unscored 3408): the note labels summary.none, names summary.unscored as the same count, and the JSON is relayed as sent", async () => {
      const res = await summary(OK);
      const n = noteOf(res);
      // The sentences after these are #2641's, pinned word for word in its block below.
      const head = `cve_summary OK: EchelonGraph answered HTTP 200 from ${stub.base}. The feed holds 381274 active CVEs (last updated ${STAMP}). ${label(3408)} summary.unscored (3408) is the same count under its own name. ${REPORT}`;
      assert.ok(n.startsWith(`${head} `), n);
      assertNoneLabelled("cve_summary", n, 3408);
      assert.deepEqual(JSON.parse(res.content[0].text), OK);
      assert.deepEqual(res.structuredContent.data, OK);
      assert.equal(res.structuredContent.state, "measured");
      assert.ok(res.structuredContent.notes.includes(label(3408)), res.structuredContent.notes.join(" | "));
    });

    it("production's answer of 2026-09-30 (none 3381, unscored 3381): labelled, with the equality named", async () => {
      const body = withSummary({ none: 3381, unscored: 3381, total: BANDED + 3381 });
      const res = await summary(body);
      const n = noteOf(res);
      assertNoneLabelled("cve_summary", n, 3381);
      assert.ok(n.includes("summary.unscored (3381) is the same count under its own name."), n);
      assert.deepEqual(res.structuredContent.data, body);
    });

    it("an answer that carries no summary.unscored: labelled, and unscored is not named", async () => {
      const n = noteOf(await summary(cveSummaryWithout("unscored")));
      assertNoneLabelled("cve_summary", n, 3408);
      assert.doesNotMatch(n, /unscored/, n);
    });

    it("an answer whose summary.unscored is not summary.none: labelled, and no equality is claimed", async () => {
      const n = noteOf(await summary(withSummary({ unscored: 3400 })));
      assertNoneLabelled("cve_summary", n, 3408);
      assert.doesNotMatch(n, /unscored/, n);
    });

    // #2641: production's answer carries the NVD histogram and rejected too, which the note labels
    // (the block below). An API older than those fields sends the shape 2.3.1 was written against.
    it("a populated feed whose summary.none is 0, from an API with no NVD histogram and no rejected: the note is 2.3.1's, word for word", async () => {
      const older = cveSummaryWithout(...NVD_HISTOGRAM, "rejected");
      const n = noteOf(await summary({ ...older, summary: { ...older.summary, none: 0, unscored: 0, total: BANDED } }));
      assert.equal(n, `cve_summary OK: EchelonGraph answered HTTP 200 from ${stub.base}. The feed holds ${BANDED} active CVEs (last updated ${STAMP}).`);
    });

    it("the description says what summary.none counts, and the outputSchema describes none and unscored", async () => {
      const { tools } = await client.listTools();
      const t = tools.find((x) => x.name === "cve_summary");
      const d = t.description;
      assert.ok(d.includes("the count with no band (summary.none)"), d);
      assert.ok(d.includes("summary.none is not a severity rating of None: it counts the active CVEs with no severity band from any source, that is, CVEs not yet scored, and the answer may carry the same count again as summary.unscored."), d);
      assert.ok(d.includes("Whenever summary.none is above zero the note says so: report those CVEs as not yet scored, not as CVEs rated None."), d);
      // 2.3.1 listed summary.none among the counts by severity.
      assert.doesNotMatch(d, /by severity[^.]*\(summary\.critical[^)]*summary\.none/, d);
      const s = branchOf(t.outputSchema, "measured").properties.data.properties.summary.properties;
      assert.equal(s.none.description, "The active CVEs with no severity band from any source: CVEs not yet scored, not a severity rating of None.");
      assert.equal(s.unscored.description, "The same count as none, under its own name.");
      assert.deepEqual(s.unscored.type, ["number", "null"]);
    });

    it("the label check can fail: 2.3.1's note, the note with its label removed, and a note that calls the count a rating, are caught", async () => {
      const n = noteOf(await summary(OK));
      assertNoneLabelled("control", n, 3408);
      for (const [what, mutant] of [
        ["2.3.1's note", `cve_summary OK: EchelonGraph answered HTTP 200 from ${stub.base}. The feed holds ${OK.summary.total} active CVEs (last updated ${STAMP}).`],
        ["the label removed", n.replace(` ${label(3408)}`, "")],
        ["the report sentence removed", n.replace(` ${REPORT}`, "")],
        ["the count called a rating", n.replace(label(3408), "summary.none (3408): 3408 CVEs are rated severity None.")],
        ["another count labelled", n.replace(label(3408), label(3407))],
      ]) {
        assert.throws(() => assertNoneLabelled(what, mutant, 3408), /the note does not say/, what);
      }
    });
  });

  // #2641: cve_summary relays the NVD histogram and summary.rejected as the API sends them, and says
  // what they count. core-backend cve/store.go Summary buckets the same active CVEs a second time, on
  // the records' NVD severity label (nvd_critical, nvd_high, nvd_medium, nvd_low and nvd_none;
  // CVESummary: "render it as provenance, never as a rating"), and counts the rejected records apart
  // (rejected, which total leaves out). nvd_none is large by design: 75,962 in production's answer
  // beside summary.none 3,408, and #1107 measured that the feed holds NVD's own CVSS v2 score for
  // 72,359 of them. 2.3.3 relayed all six fields with no word about any, and its fixture carried none
  // of them, so no test could see it: a model reports "75,962 CVEs rated None", or "NVD has no
  // severity for 75,962 CVEs". The note labels nvd_none and rejected above zero, with the answer's own
  // counts; it says the five nvd_ counts add up to summary.total only when the answer's do; and it
  // says nothing of a field the answer does not carry.
  describe("#2641: cve_summary says the nvd_ counts are NVD's label as provenance, what summary.nvd_none counts, and what summary.rejected counts", () => {
    const P = "/api/v1/public/cves/summary";
    const OK = BODIES[P].ok;
    const withSummary = (fields) => ({ ...OK, summary: { ...OK.summary, ...fields } });
    const STAMP = OK.summary.last_updated;
    const summary = cveSummaryWith;
    // #2610's sentences about summary.none on the fixture, which come first.
    const NONE_NOTE = "summary.none (3408) is not a severity rating of None: it counts the active CVEs with no severity band from any source, that is, CVEs not yet scored. summary.unscored (3408) is the same count under its own name. Report them as not yet scored, not as CVEs rated None.";
    const ALL_FIVE = "summary.nvd_critical, summary.nvd_high, summary.nvd_medium, summary.nvd_low and summary.nvd_none";
    const addsUp = (total) => `${ALL_FIVE} add up to summary.total (${total}): the same active CVEs, counted by NVD's severity label as provenance, not by EchelonGraph's severity.`;
    const nvdNoneLabel = (k) =>
      `summary.nvd_none (${k}) is not a count of CVEs rated None, nor of CVEs with no severity: it counts the active CVEs with no Critical, High, Medium or Low CVSS label from NVD (v3.x, else v4.0) or a pre-NVD record, many of them with an NVD CVSS v2 score instead.`;
    const NVD_REPORT = "Report them as CVEs without an NVD severity label, not as CVEs rated None or as CVEs not yet scored.";
    const rejectedLabel = (k) => `summary.rejected (${k}) counts CVE records rejected (withdrawn) by their numbering authority, not active CVEs: report them as withdrawn records, never as vulnerabilities.`;
    // The properties the tests and the control below all call. For a note relaying a summary.nvd_none
    // above zero: it says the nvd_ counts are NVD's label, as provenance, what nvd_none counts with the
    // answer's own count, and how to report it.
    function assertNVDNoneLabelled(where, note, k) {
      assert.match(note, /by NVD's severity label,? as provenance, not by EchelonGraph's severity\./, `${where}: the note does not say the nvd_ counts are NVD's label, as provenance: ${note}`);
      assert.ok(note.includes(nvdNoneLabel(k)), `${where}: the note does not say what summary.nvd_none (${k}) counts: ${note}`);
      assert.ok(note.includes(NVD_REPORT), `${where}: the note does not say how to report summary.nvd_none: ${note}`);
    }
    // For a note relaying a summary.rejected above zero: it says what the count is, with its count.
    function assertRejectedLabelled(where, note, k) {
      assert.ok(note.includes(rejectedLabel(k)), `${where}: the note does not say what summary.rejected (${k}) counts: ${note}`);
    }
    // A note that says the nvd_ counts add up to summary.total says it of an answer whose five do.
    // Returns whether the note says it.
    function assertSumTrue(where, note, s) {
      const m = note.match(/add up to summary\.total \((\d+)\)/);
      if (!m) return false;
      const sum = NVD_HISTOGRAM.reduce((a, k) => a + (typeof s[k] === "number" ? s[k] : NaN), 0);
      assert.ok(sum === s.total && Number(m[1]) === s.total, `${where}: the note says the nvd_ counts add up to summary.total (${m[1]}); the answer's add up to ${sum}, and its total is ${s.total}`);
      return true;
    }

    it("the fixture is production's whole answer, relayed as sent: its fourteen summary fields and eight poller fields, none stripped", async () => {
      const res = await summary(OK);
      const relayed = JSON.parse(res.content[0].text);
      assert.deepEqual(relayed, OK);
      assert.deepEqual(res.structuredContent.data, OK);
      assert.deepEqual(Object.keys(relayed.summary), ["critical", "high", "medium", "low", "none", "unscored", "total", ...NVD_HISTOGRAM, "rejected", "last_updated"]);
      assert.deepEqual(Object.keys(relayed.poller), ["cves_ingested", "cves_skipped", "http_retries", "interval", "last_poll_at", "last_poll_dur_ms", "poll_count", "poll_errors"]);
    });

    it("production's answer: the note says the five nvd_ counts add up to summary.total as NVD's label, labels summary.nvd_none (75962) and summary.rejected (884), word for word", async () => {
      const res = await summary(OK);
      const n = noteOf(res);
      assert.equal(
        n,
        `cve_summary OK: EchelonGraph answered HTTP 200 from ${stub.base}. The feed holds 381274 active CVEs (last updated ${STAMP}). ${NONE_NOTE} ${addsUp(381274)} ${nvdNoneLabel(75962)} ${NVD_REPORT} ${rejectedLabel(884)}`,
      );
      assertNVDNoneLabelled("cve_summary", n, 75962);
      assertRejectedLabelled("cve_summary", n, 884);
      assert.equal(assertSumTrue("cve_summary", n, OK.summary), true);
      for (const sentence of [addsUp(381274), nvdNoneLabel(75962), NVD_REPORT, rejectedLabel(884)]) {
        assert.ok(res.structuredContent.notes.includes(sentence), `${sentence} | ${res.structuredContent.notes.join(" | ")}`);
      }
    });

    it("an answer whose nvd_ counts do not add up to summary.total: labelled, and no sum is claimed", async () => {
      const body = withSummary({ nvd_low: OK.summary.nvd_low + 1 });
      const n = noteOf(await summary(body));
      assertNVDNoneLabelled("cve_summary", n, 75962);
      assert.equal(assertSumTrue("cve_summary", n, body.summary), false, n);
      assert.ok(n.includes(`${ALL_FIVE} count active CVEs by NVD's severity label, as provenance, not by EchelonGraph's severity.`), n);
    });

    it("an answer that lacks an nvd_ band: labelled, the fields it carries named, and no sum claimed", async () => {
      const n = noteOf(await summary(cveSummaryWithout("nvd_low")));
      assertNVDNoneLabelled("cve_summary", n, 75962);
      assert.doesNotMatch(n, /nvd_low|add up to/, n);
      assert.ok(n.includes("summary.nvd_critical, summary.nvd_high, summary.nvd_medium and summary.nvd_none count active CVEs by NVD's severity label, as provenance, not by EchelonGraph's severity."), n);
      const alone = noteOf(await summary(cveSummaryWithout("nvd_critical", "nvd_high", "nvd_medium", "nvd_low")));
      assertNVDNoneLabelled("cve_summary", alone, 75962);
      assert.ok(alone.includes(" summary.nvd_none counts active CVEs by NVD's severity label, as provenance, not by EchelonGraph's severity."), alone);
    });

    it("an API older than the NVD histogram and rejected: the note names neither and invents no count, and is 2.3.2's, word for word", async () => {
      const n = noteOf(await summary(cveSummaryWithout(...NVD_HISTOGRAM, "rejected")));
      assert.equal(n, `cve_summary OK: EchelonGraph answered HTTP 200 from ${stub.base}. The feed holds 381274 active CVEs (last updated ${STAMP}). ${NONE_NOTE}`);
      assert.doesNotMatch(n, /nvd|NVD|rejected|withdrawn/, n);
    });

    it("a zero is not labelled: summary.nvd_none 0 gets no NVD sentence, summary.rejected 0 no rejected one, each apart from the other", async () => {
      const noNVD = noteOf(await summary(withSummary({ nvd_none: 0 })));
      assert.doesNotMatch(noNVD, /nvd_|NVD/, noNVD);
      assertRejectedLabelled("cve_summary", noNVD, 884);
      const noRejected = noteOf(await summary(withSummary({ rejected: 0 })));
      assertNVDNoneLabelled("cve_summary", noRejected, 75962);
      assert.doesNotMatch(noRejected, /rejected|withdrawn/, noRejected);
      const neither = noteOf(await summary(withSummary({ nvd_none: 0, rejected: 0 })));
      assert.equal(neither, `cve_summary OK: EchelonGraph answered HTTP 200 from ${stub.base}. The feed holds 381274 active CVEs (last updated ${STAMP}). ${NONE_NOTE}`);
    });

    it("a summary.none of 0 leaves the NVD and rejected sentences in place", async () => {
      const n = noteOf(await summary(withSummary({ none: 0, unscored: 0 })));
      assert.doesNotMatch(n, /summary\.none \(/, n);
      assertNVDNoneLabelled("cve_summary", n, 75962);
      assertRejectedLabelled("cve_summary", n, 884);
    });

    it("the description says what the nvd_ counts, summary.nvd_none and summary.rejected are, and the outputSchema describes each", async () => {
      const { tools } = await client.listTools();
      const t = tools.find((x) => x.name === "cve_summary");
      const d = t.description;
      assert.ok(
        d.includes(
          `${ALL_FIVE} count the same active CVEs as summary.total by NVD's CVSS severity label (v3.x, else v4.0; before NVD's record arrives, or where it gives none, a pre-NVD label from the CVE.org record or a GitHub advisory can stand in): provenance, never EchelonGraph's severity band.`,
        ),
        d,
      );
      assert.ok(
        d.includes(
          "summary.nvd_none counts the active CVEs with no Critical, High, Medium or Low label there, CVEs NVD never labelled under CVSS v3 among them, and many of those carry an NVD CVSS v2 score instead: it is neither a count of CVEs rated None nor the count of CVEs with no severity, which is summary.none. Whenever summary.nvd_none is above zero the note says what it counts, with its count.",
        ),
        d,
      );
      assert.ok(
        d.includes("summary.rejected counts the CVE records rejected (withdrawn) by their numbering authority, which summary.total and the other counts above leave out: report them as withdrawn records, never as vulnerabilities."),
        d,
      );
      const s = branchOf(t.outputSchema, "measured").properties.data.properties.summary.properties;
      for (const [k, label] of [["nvd_critical", "Critical"], ["nvd_high", "High"], ["nvd_medium", "Medium"], ["nvd_low", "Low"]]) {
        assert.equal(s[k].description, `Of the active CVEs total counts, those whose NVD CVSS severity label is ${label}: NVD's label, as provenance, never EchelonGraph's severity band.`, k);
      }
      assert.equal(
        s.nvd_none.description,
        "Of the active CVEs total counts, those with no Critical, High, Medium or Low NVD CVSS severity label, many of them with an NVD CVSS v2 score instead: neither a count of CVEs rated None nor the count of CVEs with no severity, which is none.",
      );
      assert.equal(s.rejected.description, "The CVE records rejected (withdrawn) by their numbering authority, which total and every other count here leave out: withdrawn records, never vulnerabilities.");
      for (const k of [...NVD_HISTOGRAM, "rejected"]) assert.deepEqual(s[k].type, ["number", "null"], k);
    });

    it("the label checks can fail: 2.3.3's note, each label removed, another count, nvd_none called a rating, rejected called vulnerabilities, and a sum the answer does not add up to, are caught", async () => {
      const n = noteOf(await summary(OK));
      assertNVDNoneLabelled("control", n, 75962);
      assertRejectedLabelled("control", n, 884);
      assert.equal(assertSumTrue("control", n, OK.summary), true);
      const v233 = `cve_summary OK: EchelonGraph answered HTTP 200 from ${stub.base}. The feed holds 381274 active CVEs (last updated ${STAMP}). ${NONE_NOTE}`;
      for (const [what, mutant] of [
        ["2.3.3's note", v233],
        ["the histogram sentence removed", n.replace(` ${addsUp(381274)}`, "")],
        ["the nvd_none label removed", n.replace(` ${nvdNoneLabel(75962)}`, "")],
        ["the nvd_none report sentence removed", n.replace(` ${NVD_REPORT}`, "")],
        ["nvd_none called a rating", n.replace(nvdNoneLabel(75962), "summary.nvd_none (75962): 75962 CVEs are rated severity None.")],
        ["another nvd_none count", n.replace(nvdNoneLabel(75962), nvdNoneLabel(75961))],
      ]) {
        assert.throws(() => assertNVDNoneLabelled(what, mutant, 75962), /the note does not say/, what);
      }
      for (const [what, mutant] of [
        ["2.3.3's note", v233],
        ["the rejected label removed", n.replace(` ${rejectedLabel(884)}`, "")],
        ["rejected called vulnerabilities", n.replace(rejectedLabel(884), "summary.rejected (884) counts 884 rejected vulnerabilities.")],
        ["another rejected count", n.replace(rejectedLabel(884), rejectedLabel(883))],
      ]) {
        assert.throws(() => assertRejectedLabelled(what, mutant, 884), /the note does not say/, what);
      }
      // The sum sentence, said of an answer whose nvd_ counts do not add up to its total.
      const off = { ...OK.summary, nvd_low: OK.summary.nvd_low + 1 };
      assert.throws(() => assertSumTrue("a sum the answer does not add up to", n, off), /add up to/);
    });
  });

  // #2467: what each result costs in the channel a model reads. 2.1.0's envelope block repeated
  // the note before it sentence for sentence (82% of exposure_radar's block on production's
  // answers) and nothing measured it, so the fold was silent. Each case below is one of the
  // fixtures above, production's recorded cve_exposure answer (#2439) among them, and its total
  // text (every text block, with the stub's base URL counted as production's, so the number is
  // what a production client receives for the same answer) must stay within its bound: the size
  // measured when #2467 landed, plus MARGIN. The text is deterministic, so the margin only lets a
  // changed word through; a sentence added to a note (nearly every one is longer than MARGIN), or
  // a repeat creeping back into the envelope block, fails here as a number. Before #2467, on these
  // fixtures: exposure_radar 32,606, cve_exposure 6,165, cve_summary 1,141, search_cves 1,231,
  // get_cve 940, the get_cve failure 910 and the search_cves failure 1,133. Raise a measurement on
  // purpose, to a new measurement, never to make a run pass.
  describe("#2467: every tool's text stays within its measured size", () => {
    const PROD_BASE = "https://app.echelongraph.io";
    const PROD_CVE_PATH = `/api/v1/public/kev-exposure/cve/${CVE_PROD_WRITE_STAMPED}`;
    const MARGIN = 50;
    // [case, tool, arguments, stub mode, overrides, what the case must be, characters of text
    // measured at 2.2.0 (2026-09-28)]. exposure_radar was raised on purpose at 2.3.0 (2026-09-29,
    // #2315), from 22,883 to 30,949: the fifth radar, mcp_servers, adds 8,066 characters, which are
    // its 29 labelled counts and 4 timestamps in data, the note sentence that labels each, and its
    // clause in method and in the envelope's two notes. At 2.3.1 (2026-09-30, #2535) search_cves and
    // get_cve were re-measured on purpose, from 1,085 to 1,115 and from 809 to 835: their fixtures
    // gained score_assessed true, as every scored row on the API carries it, 30 and 26 characters of
    // the first text block; their notes are unchanged. The two not-yet-scored cases are new, measured
    // then. At 2.3.2 (2026-09-30, #2610) cve_summary was re-measured on purpose, from 971 to 1,259:
    // its fixture gained summary.unscored, equal to summary.none, as core-backend's store sends it (22
    // characters of the first text block), and its note the three sentences that say what
    // summary.none counts (266 characters); its envelope block is unchanged at 563. After 2.3.3
    // (2026-09-30, #2641) cve_summary was re-measured on purpose, from 1,259 to 2,338. Its fixture
    // became production's whole answer, read 2026-09-30T10:02:13Z, whose data block is 590 characters
    // where the trimmed fixture's was 275: the five nvd_ counts, rejected, and the seven poller fields
    // it had left out. On that answer 2.3.3's own text measures 1,574 (#2641 measured 1,571 on the
    // answer of 09:45Z), so the bound of 1,259 had never been measured against what a production
    // client receives. The note gains the four sentences that say the nvd_ counts are NVD's label, as
    // provenance, and what summary.nvd_none and summary.rejected count (764 characters, from 421 to
    // 1,185); the envelope block is unchanged at 563. At #2720 (2026-10-04) get_cve was re-measured
    // on purpose, from 835 to 1,063 and, not yet scored, from 1,355 to 1,583: its envelope's own
    // notes gained the sentence saying that an answer without cpe_configurations holds no stored NVD
    // configuration tree, which is not a finding that no product is affected (228 characters, the
    // sentence and its JSON quoting); the note in content[1] is unchanged. The other bounds are
    // unchanged.
    const CASES = [
      ["exposure_radar", "exposure_radar", {}, "ok", {}, { state: "not_assessed" }, 30_949],
      ["cve_exposure, exposed (production's recorded answer)", "cve_exposure", { cve_id: CVE_PROD_WRITE_STAMPED }, "ok", { [PROD_CVE_PATH]: PROD_WRITE_STAMPED }, { state: "not_assessed", exposure_state: "exposed" }, 3_905],
      ["cve_summary", "cve_summary", {}, "ok", {}, { state: "measured" }, 2_338],
      ["search_cves", "search_cves", CALLS.search_cves, "ok", {}, { state: "measured" }, 1_115],
      ["get_cve", "get_cve", CALLS.get_cve, "ok", {}, { state: "measured" }, 1_063],
      ["get_cve, failed (the API's 404)", "get_cve", CALLS.get_cve, "empty", {}, { state: "failed" }, 565],
      ["search_cves, failed (an edge's HTTP 403 page)", "search_cves", CALLS.search_cves, "403", {}, { state: "failed" }, 705],
      ["get_cve, not yet scored (the placeholders 0, NONE and 0)", "get_cve", { cve_id: CVE_UNSCORED_ZERO }, "ok", { [`/api/v1/public/cves/${CVE_UNSCORED_ZERO}`]: SCORE_ROWS[CVE_UNSCORED_ZERO] }, { state: "measured" }, 1_583],
      ["search_cves, a page with one row not yet scored", "search_cves", CALLS.search_cves, "ok", { "/api/v1/public/cves": { ...BODIES["/api/v1/public/cves"].ok, cves: [...BODIES["/api/v1/public/cves"].ok.cves, SCORE_ROWS[CVE_UNSCORED_ZERO]], total: 2 } }, { state: "measured" }, 1_803],
    ];
    // #2531: the check itself, one function, so the control below runs the predicate the cases
    // run. The text is every text block, with the stub's base URL counted as production's.
    const sizeOf = (res) => {
      const blocks = textBlocks(res).map((t) => t.split(stub.base).join(PROD_BASE));
      return { total: blocks.reduce((n, t) => n + t.length, 0), envelope: blocks.at(-1).length };
    };
    function assertWithinBound(label, res, size) {
      const { total } = sizeOf(res);
      const bound = size + MARGIN;
      assert.ok(total <= bound, `${label}: ${total} characters of text, over its bound of ${bound} (${size} measured, plus ${MARGIN})`);
      return total;
    }
    const measured = {};
    before(async () => {
      try {
        for (const [label, name, args, mode, overrides] of CASES) {
          stub.state.mode = mode;
          Object.assign(stub.state.overrides, overrides);
          try {
            measured[label] = await client.callTool({ name, arguments: args });
          } finally {
            for (const p of Object.keys(overrides)) delete stub.state.overrides[p];
          }
        }
      } finally {
        stub.state.mode = "ok";
      }
    });
    for (const [label, , , , , is, size] of CASES) {
      const bound = size + MARGIN;
      it(`${label}: at most ${bound} characters of text (${size} measured, plus ${MARGIN})`, (t) => {
        const res = measured[label];
        // The bound is only about this case if the case is what it says it is.
        for (const [k, v] of Object.entries(is)) assert.equal(res.structuredContent[k], v, `${label}: ${k}`);
        const { total, envelope } = sizeOf(res);
        t.diagnostic(`${label}: ${total} characters of text, ${envelope} of them the envelope block`);
        assertWithinBound(label, res, size);
      });
    }
    // #2531: the bound can fail. The control runs assertWithinBound on cve_summary's measured result:
    // as measured it passes; with its note grown to exactly the bound it still passes, and one
    // character more fails; and at its measured size, one sentence more in the note fails, since a
    // note's sentence is longer than MARGIN. Each oversized note is sized from the bound, not from the
    // note, so a note that shrinks later leaves the control as sharp as it is today.
    it("#2531: the bound can fail: an injected oversized note is over it, by as little as one character", () => {
      const [label, , , , , , size] = CASES.find(([l]) => l === "cve_summary");
      const res = measured[label];
      const [data, note, env] = textBlocks(res);
      const withNote = (n) => ({ ...res, content: [data, n, env].map((t) => ({ type: "text", text: t })) });
      const total = assertWithinBound("control", res, size);
      const pad = (k) => "x".repeat(Math.max(0, k));
      assertWithinBound("control, its note grown to the bound", withNote(note + pad(size + MARGIN - total)), size);
      const sentence = " summary.unscored (3408) is the same count under its own name.";
      assert.ok(sentence.length > MARGIN, `the injected sentence is ${sentence.length} characters, within MARGIN`);
      for (const [what, oversized] of [
        ["one character over", note + pad(size + MARGIN - total + 1)],
        ["one sentence more, at the measured size", note + pad(size - total) + sentence],
      ]) {
        assert.throws(() => assertWithinBound(what, withNote(oversized), size), /over its bound of/, what);
      }
    });
  });

  // 1.0.1: the version is read from package.json, so adoption per release is countable.
  describe("package identity: version, User-Agent, tool order, registry metadata", () => {
    it("the MCP handshake reports package.json's version", () => {
      assert.equal(client.getServerVersion()?.version, PKG.version);
    });
    it("every API request carries a User-Agent naming package.json's version", async () => {
      stub.state.mode = "ok";
      stub.state.userAgents.length = 0;
      await callAll(client);
      assert.ok(stub.state.userAgents.length >= TOOLS.length, "no requests seen");
      for (const ua of stub.state.userAgents) {
        assert.equal(ua, `echelongraph-mcp/${PKG.version} (+https://echelongraph.io/pulse/mcp)`);
      }
    });
    it("tools/list answers every tool in a fixed order", async () => {
      const { tools } = await client.listTools();
      assert.deepEqual(tools.map((t) => t.name), LISTED);
    });
    it("server.json and package.json agree for the MCP registry's npm ownership check", () => {
      const sj = JSON.parse(readPkgFile("server.json"));
      assert.equal(PKG.mcpName, sj.name, "package.json mcpName must equal server.json name");
      assert.match(sj.name, /^io\.echelongraph\/[a-zA-Z0-9._-]+$/);
      assert.equal(sj.version, PKG.version);
      assert.equal(sj.packages.length, 1);
      const [p] = sj.packages;
      assert.equal(p.registryType, "npm");
      assert.equal(p.identifier, PKG.name);
      assert.equal(p.version, PKG.version);
      assert.deepEqual(p.transport, { type: "stdio" });
      assert.ok(sj.description.length <= 100, `server.json description is ${sj.description.length} chars; the schema allows 100`);
    });
    // A repo check: npm never packs package-lock.json, so a run against the extracted tarball
    // has none to read and says so instead of failing.
    const hasLock = fs.existsSync(path.join(PKG_DIR, "package-lock.json"));
    it("package-lock.json's root carries package.json's version", { skip: hasLock ? false : "no package-lock.json here (npm does not pack it)" }, () => {
      const lock = JSON.parse(readPkgFile("package-lock.json"));
      assert.equal(lock.version, PKG.version, "package-lock.json version");
      assert.equal(lock.packages[""].version, PKG.version, 'package-lock.json packages[""].version');
    });
  });
});

// A control on the fix itself: the error path quotes what fetch reported, and fetch quotes
// the URL when it refuses one that carries a credential. Nothing configured into
// ECHELONGRAPH_API_BASE may come back out through a tool result.
describe(`a credential in ECHELONGRAPH_API_BASE never reaches a result [${ERA}]`, () => {
  const base = "http://user:s3cretvalue@127.0.0.1:1";
  let client, results;
  before(async () => {
    client = await spawnServer({ ECHELONGRAPH_API_BASE: base, ECHELONGRAPH_API_TIMEOUT_MS: "2000" });
    results = await callAll(client);
  });
  // A client that never connected (a failed opening) leaves nothing to close.
  after(() => client?.close());
  for (const name of TOOLS) {
    it(`${name} is an error result whose text masks the credential`, () => {
      const res = results[name];
      assertErrorResult(name, res);
      const t = textOf(res);
      assert.doesNotMatch(t, /s3cretvalue/, `${name}: credential leaked into the result: ${t}`);
      assert.ok(t.includes("***@127.0.0.1:1"), `${name}: masked base not shown: ${t}`);
      // #2311: the structured result is masked too, every field of it.
      assert.doesNotMatch(JSON.stringify(res), /s3cretvalue/, `${name}: credential leaked into the structured result: ${JSON.stringify(res.structuredContent)}`);
      assert.equal(res.structuredContent?.state, "failed", `${name}: ${JSON.stringify(res.structuredContent)}`);
    });
  }
});

// #2313 done-means 4 and 5, over every tool result the suite above received, in this era:
// successes, not-assessed answers, failures and refused inputs alike. Runs last, so every
// describe block before it has filled COLLECTED.
describe(`#2313: every structuredContent the suite received validates against its tool's outputSchema, and dates every measured exposure number [${ERA}]`, () => {
  let schemas, descriptions, instructions;
  before(async () => {
    // tools/list reaches no API, so an unreachable base is enough to read the schemas.
    const client = await spawnServer({ ECHELONGRAPH_API_BASE: "http://127.0.0.1:1" });
    try {
      const { tools } = await client.listTools();
      schemas = Object.fromEntries(tools.map((t) => [t.name, t.outputSchema]));
      descriptions = Object.fromEntries(tools.map((t) => [t.name, t.description]));
      instructions = client.opening.instructions;
    } finally {
      await client.close();
    }
  });
  it("the suite collected results from every tool, in every state each tool can answer", () => {
    assert.ok(COLLECTED.length >= 150, `only ${COLLECTED.length} results collected`);
    const seen = {};
    for (const [name, , res] of COLLECTED) (seen[name] ??= new Set()).add(res.structuredContent?.state);
    // Each tool's possible states, all of them seen. cve_exposure cannot be measured while the
    // API serves no observation time (#2439), and exposure_radar cannot be either (#2313).
    const expected = {
      cve_summary: ["measured", "failed"],
      search_cves: ["measured", "failed"],
      get_cve: ["measured", "failed", "invalid_input"],
      cve_exposure: ["not_assessed", "failed", "invalid_input"],
      exposure_radar: ["not_assessed", "failed"],
      // invalid_input is exercised in check_affected.test.mjs.
      check_affected: ["measured", "not_assessed", "failed"],
      vendor_advisories_for_cve: ["measured", "failed"],
      get_vendor_advisory: ["measured", "failed"],
      search_vendor_advisories: ["measured", "failed"],
    };
    for (const [name, states] of Object.entries(expected)) {
      for (const st of states) assert.ok(seen[name]?.has(st), `${name}: no result in state ${st} (seen: ${[...(seen[name] ?? [])].join(", ")})`);
      assert.deepEqual([...(seen[name] ?? [])].filter((st) => !states.includes(st)), [], `${name}: a result in a state it cannot answer`);
    }
  });
  // #2440 done-means 1: for every tool, in this era, every result the suite received (success,
  // not_assessed, failed, invalid_input) carries its envelope in its text: state, measured_at,
  // method, coverage and freshness matching structuredContent. #2467: the envelope block leaves
  // out only what an earlier block says verbatim, so the text rebuilds to structuredContent.
  it("#2440, #2467: every result's text rebuilds to its structuredContent, and its envelope block repeats nothing", () => {
    const seen = {};
    let methodQuoted = 0;
    let methodKept = 0;
    let ownNotes = 0;
    let noOwnNotes = 0;
    for (const [name, args, res] of COLLECTED) {
      const env = assertEnvelopeInText(`${name}(${JSON.stringify(args)})`, res);
      (seen[name] ??= new Set()).add(res.structuredContent.state);
      if (typeof res.structuredContent.method === "string") has(env, "method") ? methodKept++ : methodQuoted++;
      has(env, "notes") ? ownNotes++ : noOwnNotes++;
    }
    // Not vacuous: every tool, and each state it answers in, went through the check above, and
    // both ways each key can go: method kept (the CVE feed, exposure_radar) and left out because
    // the note quotes it (cve_exposure), notes of the envelope's own (every success) and none
    // (every failure, whose notes are all the message's).
    assert.deepEqual(Object.keys(seen).sort(), [...TOOLS].sort());
    for (const st of STATES) assert.ok(Object.values(seen).some((s) => s.has(st)), `no result in state ${st} was checked`);
    assert.ok(methodQuoted >= 10 && methodKept >= 10, `method left out ${methodQuoted} times, kept ${methodKept}`);
    assert.ok(ownNotes >= 10 && noOwnNotes >= 10, `own notes in ${ownNotes} envelope blocks, none in ${noOwnNotes}`);
  });
  it("#2440, #2467: the check above can fail: a result without the envelope block, whose text disagrees with structuredContent, drops something, or repeats the note, is caught", () => {
    const pick = (pred) => COLLECTED.find(([n, , r]) => pred(n, r))[2];
    const ok = pick((n, r) => n === "cve_exposure" && r.structuredContent.state === "not_assessed" && r.structuredContent.exposure_state === "exposed");
    const feed = pick((n, r) => n === "cve_summary" && !r.isError);
    const bad = pick((n, r) => n === "get_cve" && r.isError);
    for (const r of [ok, feed, bad]) assertEnvelopeInText("control", r);
    const withText = (res, blocks) => ({ ...res, content: blocks.map((t) => ({ type: "text", text: t })) });
    const env = (res, change) => JSON.stringify({ ...envelopeOf(res), ...change }, null, 2);
    // 2.1.0's envelope block: structuredContent without data, the note's sentences and all.
    const whole = (res) => JSON.stringify((({ data: _d, ...e }) => e)(res.structuredContent), null, 2);
    const [data, note] = textBlocks(ok);
    const [feedData, feedNote] = textBlocks(feed);
    const without = (res, key) => JSON.stringify((({ [key]: _k, ...e }) => e)(envelopeOf(res)), null, 2);
    for (const [label, res, message] of [
      ["2.0.0's shape: no envelope block", withText(ok, [data, note]), /text block\(s\), expected 3/],
      ["a failure without its envelope block", withText(bad, [textBlocks(bad)[0]]), /text block\(s\), expected 2/],
      ["a text state that disagrees", withText(ok, [data, note, env(ok, { state: "measured" })]), /the text says state/],
      ["a text measured_at that disagrees", withText(ok, [data, note, env(ok, { measured_at: ok.structuredContent.data.last_seen })]), /the text says measured_at/],
      ["a text method that disagrees", withText(ok, [data, note, env(ok, { method: "x" })]), /the text says method/],
      ["a text freshness that disagrees", withText(ok, [data, note, env(ok, { freshness: {} })]), /the text says freshness/],
      ["a text envelope with no freshness", withText(ok, [data, note, without(ok, "freshness")]), /has no freshness/],
      ["2.0.0's tag: (state: exposed) beside state not_assessed", withText(ok, [data, note.replace("(exposure_state: exposed)", "(state: exposed)"), textBlocks(ok)[2]]), /tags \(state: exposed\)/],
      ["an envelope block that is not JSON", withText(ok, [data, note, "state: not_assessed"]), /not the envelope's JSON/],
      // #2467: what 2.1.0 sent, and what a fix could lose.
      ["2.1.0's envelope block, repeating the note and the method it quotes", withText(ok, [data, note, whole(ok)]), /repeats method/],
      ["2.1.0's envelope block, repeating the note", withText(feed, [feedData, feedNote, whole(feed)]), /repeats the block before it/],
      ["2.1.0's failure envelope block, repeating the message", withText(bad, [textBlocks(bad)[0], whole(bad)]), /repeats the block before it/],
      ["an own note the text drops", withText(ok, [data, note, env(ok, { notes: envelopeOf(ok).notes.slice(1) })]), /notes are not the envelope block's notes followed by/],
      ["a method the text drops though the note does not quote it", withText(feed, [feedData, feedNote, without(feed, "method")]), /has no method, and the block before it does not quote/],
      ["a note sentence the note no longer says", withText(ok, [data, note.replace(/ Exposure counts are derived from Shodan data\./, ""), textBlocks(ok)[2]]), /notes are not the envelope block's notes followed by/],
      ["an empty notes array instead of none", withText(bad, [textBlocks(bad)[0], env(bad, { notes: [] })]), /with none of its own it is left out/],
      ["a key structuredContent does not have", withText(ok, [data, note, env(ok, { exposed_hosts: 229 })]), /rebuilt, is not structuredContent without data/],
    ]) {
      assert.throws(() => assertEnvelopeInText(label, res), message, label);
    }
  });
  // #2531: the repeat share, as a number, over every result the suite received: the envelope
  // block's, which is #2467's property (its trip-wire: any repeat between blocks), and every block's
  // after the first. Printed per tool, the way the size test prints sizes, so a change reads from
  // the run as a number. Measured on these fixtures at 2.3.2 (2026-09-30), in each era: 0 of the 562
  // sentences in 244 envelope blocks; across every block after the first, 130 of 5,026, every one of
  // them cve_exposure's note quoting its answer's own method (3 sentences an answer) or, once,
  // Shodan's ownership, which that answer's attribution also says (quotedOnPurpose); 0 besides.
  it("#2531: the repeat share, as a number: 0 in every result's envelope block, and 0 across its blocks besides what a note quotes on purpose", (t) => {
    const per = {};
    for (const [name, args, res] of COLLECTED) {
      const r = assertNoRepeat(`${name}(${JSON.stringify(args)})`, res);
      const o = (per[name] ??= { results: 0, envelope: [0, 0], all: [0, 0], other: [0, 0], highest: 0 });
      o.results++;
      for (const k of ["envelope", "all", "other"]) {
        o[k][0] += r[k].repeated;
        o[k][1] += r[k].sentences;
      }
      o.highest = Math.max(o.highest, r.all.share);
    }
    const share = ([r, n]) => `${r} of ${n} sentences, share ${n ? +(r / n).toFixed(3) : 0}`;
    for (const [name, o] of Object.entries(per)) {
      t.diagnostic(
        `${name}: ${o.results} results; envelope blocks repeat ${share(o.envelope)}; every block after the first repeats ${share(o.all)} (highest in one result ${+o.highest.toFixed(3)}); less a note's quotes on purpose, ${share(o.other)}`,
      );
    }
    // Not vacuous: every tool, envelope blocks that hold sentences, and the on-purpose quote exercised.
    assert.deepEqual(Object.keys(per).sort(), [...TOOLS].sort());
    const envelopeSentences = Object.values(per).reduce((k, o) => k + o.envelope[1], 0);
    assert.ok(envelopeSentences >= 300, `only ${envelopeSentences} envelope-block sentences measured`);
    assert.ok(per.cve_exposure.all[0] > 0, "no note quoted its answer's own method, so the on-purpose exception was never exercised");
  });
  it("#2531: the repeat share can fail: an injected duplicate block, 2.1.0's envelope block, and a quote outside the note are each above 0", () => {
    const pick = (pred) => COLLECTED.find(([n, , r]) => pred(n, r))[2];
    const feed = pick((n, r) => n === "cve_summary" && !r.isError);
    const bad = pick((n, r) => n === "get_cve" && r.isError);
    const exposed = pick((n, r) => n === "cve_exposure" && r.structuredContent.exposure_state === "exposed" && r.structuredContent.data.method === BACKEND_METHOD);
    for (const r of [feed, bad, exposed]) assertNoRepeat("control", r);
    // The exception is bounded: the note's method quote is counted, and is all that is excused.
    const quoted = repeatShare(exposed);
    assert.ok(quoted.all.share > 0 && quoted.other.share === 0, JSON.stringify(quoted.blocks.map((b) => b.repeated)));
    const withText = (res, blocks) => ({ ...res, content: blocks.map((t) => ({ type: "text", text: t })) });
    // 2.1.0's envelope block: structuredContent without data, the note's sentences and all.
    const whole = (res) => JSON.stringify((({ data: _d, ...e }) => e)(res.structuredContent), null, 2);
    const [data, note, env] = textBlocks(feed);
    const [message, badEnv] = textBlocks(bad);
    const [eData, eNote, eEnv] = textBlocks(exposed);
    for (const [label, res, which] of [
      ["the note block injected twice", withText(feed, [data, note, note, env]), "all"],
      ["the envelope block injected twice", withText(feed, [data, note, env, env]), "envelope"],
      ["2.1.0's envelope block, repeating the note", withText(feed, [data, note, whole(feed)]), "envelope"],
      ["a failure's message injected twice", withText(bad, [message, message, badEnv]), "all"],
      ["cve_exposure's data block injected twice, method and all", withText(exposed, [eData, eData, eNote, eEnv]), "all"],
    ]) {
      const r = repeatShare(res);
      assert.ok(r[which].share > 0, `${label}: the ${which} share is ${r[which].share}`);
      assert.throws(() => assertNoRepeat(label, res), /repeat share/, label);
    }
  });
  it("every structuredContent validates against its tool's advertised outputSchema, and isError agrees with its state", () => {
    for (const [name, args, res] of COLLECTED) {
      const at = `${name}(${JSON.stringify(args)})`;
      assert.ok(res.structuredContent && typeof res.structuredContent === "object", `${at}: no structuredContent: ${brief(res)}`);
      assertValid(at, schemas[name], res.structuredContent);
      const failedState = res.structuredContent.state === "failed" || res.structuredContent.state === "invalid_input";
      assert.equal(res.isError === true, failedState, `${at}: isError ${res.isError} with state ${res.structuredContent.state}`);
    }
  });
  it("the validator is not vacuous: it rejects a failure carrying data, a success without data, an unknown state, and an unlabelled radar number", () => {
    const ok = COLLECTED.find(([n, , r]) => n === "exposure_radar" && !r.isError)[2].structuredContent;
    const bad = COLLECTED.find(([n, , r]) => n === "cve_exposure" && r.isError)[2].structuredContent;
    assert.ok(isValid(schemas.exposure_radar, ok) && isValid(schemas.cve_exposure, bad), "the controls' base cases must be valid");
    const { data: _d, ...noData } = ok;
    for (const [label, schema, mutant] of [
      ["a failure carrying data", schemas.cve_exposure, { ...bad, data: { exposed_hosts: 0 } }],
      ["a success without data", schemas.exposure_radar, noData],
      ["an unknown state", schemas.exposure_radar, { ...ok, state: "measured_zero" }],
      ["a failure with a measured_at", schemas.cve_exposure, { ...bad, measured_at: "2026-09-27T00:00:00Z" }],
      ["an unlabelled radar number", schemas.exposure_radar, { ...ok, data: { ...ok.data, kev_exposure: { ...ok.data.kev_exposure, candidate_hosts: 99999 } } }],
      ["a newest_kev row with no exposure_state", schemas.exposure_radar, { ...ok, data: { ...ok.data, kev_exposure: { ...ok.data.kev_exposure, newest_kev: [{ cve_id: "CVE-2026-1", exposed_hosts: 0 }] } } }],
    ]) {
      assert.equal(isValid(schema, mutant), false, `the validator accepted ${label}`);
    }
  });
  it("every measured_at is null or a real instant, never the Go zero time", () => {
    for (const [name, args, res] of COLLECTED) {
      const m = res.structuredContent.measured_at;
      assert.ok(m === null || realInstant(m), `${name}(${JSON.stringify(args)}): measured_at ${JSON.stringify(m)}`);
    }
  });
  // #2313 done-means 5, and #2439: every exposure number in a measured result has a real
  // measured_at and a method, and no measured_at is a time EchelonGraph wrote a row. Neither
  // exposure answer serves a time at which what it counts was observed, so today no exposure
  // result is measured at all: the walk finds no measured exposure number, and the control
  // below proves it would catch one.
  it("#2313 done-means 5: every exposure number in a measured result has a real measured_at and a method; today none is measured", () => {
    let measured = 0;
    let undated = 0;
    let counted = 0;
    for (const [name, args, res] of COLLECTED) {
      measured += assertExposureNumbersDated(`${name}(${JSON.stringify(args)})`, name, res.structuredContent);
      if (EXPOSURE_TOOLS.has(name) && res.structuredContent.state === "not_assessed") {
        undated++;
        if (numbersUnder(res.structuredContent.data).size) counted++;
      }
    }
    assert.equal(measured, 0, "an exposure number was measured, but no exposure answer says when what it counts was observed");
    // Not vacuous: the walk read exposure results whose numbers are relayed, labelled, undated.
    assert.ok(undated >= 10, `only ${undated} not-assessed exposure results walked`);
    assert.ok(counted >= 10, `only ${counted} not-assessed exposure results carrying numbers walked`);
  });
  it("#2439: no cve_exposure result is measured, and none takes its measured_at from last_seen, a write time", () => {
    let withLastSeen = 0;
    for (const [name, args, res] of COLLECTED) {
      if (name !== "cve_exposure" || res.isError) continue;
      const sc = res.structuredContent;
      assert.notEqual(sc.state, "measured", `cve_exposure(${JSON.stringify(args)}): measured`);
      assert.equal(sc.measured_at, null, `cve_exposure(${JSON.stringify(args)}): measured_at ${sc.measured_at}`);
      if (realInstant(sc.data.last_seen)) {
        withLastSeen++;
        assert.notEqual(sc.measured_at, sc.data.last_seen, `cve_exposure(${JSON.stringify(args)}): measured_at is last_seen`);
        assert.ok(sc.notes.some((s) => s.startsWith(`last_seen (${sc.data.last_seen}) is not measured_at`)), `cve_exposure(${JSON.stringify(args)}): last_seen is not labelled a write time`);
      }
    }
    // Not vacuous: the fixtures with services on record, production's among them.
    assert.ok(withLastSeen >= 10, `only ${withLastSeen} cve_exposure results with a real last_seen walked`);
  });
  it("the walk above can fail: a measured exposure number with no measured_at, or no method, is caught", () => {
    const [, , res] = COLLECTED.find(([n, , r]) => n === "cve_exposure" && r.structuredContent.state === "not_assessed" && r.structuredContent.exposure_state === "exposed");
    const sc = { ...res.structuredContent, state: "measured", measured_at: "2026-09-20T00:00:00Z" };
    // The control: dated and with a method, a measured count passes, and the walk counts it.
    assert.ok(assertExposureNumbersDated("control", "cve_exposure", sc) > 0);
    assert.throws(() => assertExposureNumbersDated("mutant", "cve_exposure", { ...sc, measured_at: null }), /under state measured with measured_at null/);
    assert.throws(() => assertExposureNumbersDated("mutant", "cve_exposure", { ...sc, measured_at: "0001-01-01T00:00:00Z" }), /measured_at/);
    assert.throws(() => assertExposureNumbersDated("mutant", "cve_exposure", { ...sc, method: "" }), /no method/);
    const radar = COLLECTED.find(([n, , r]) => n === "exposure_radar" && !r.isError)[2].structuredContent;
    assert.throws(() => assertExposureNumbersDated("mutant", "exposure_radar", { ...radar, state: "measured" }), /under state measured with measured_at null/);
  });
  // #2465: 2.1.0's outputSchema described not_assessed as "no dated measurement of what was
  // asked, and no number in it is a finding", while every cve_exposure answer is not_assessed
  // (#2439), production's 249 services on record for a CISA-KEV-listed CVE among them, and
  // exposure_radar relays its labelled totals under the same state. A client that respects the
  // schema was told those counts are not findings. Every text a client holds for an answer that
  // relays a non-zero count is read here sentence by sentence: every description in its tool's
  // outputSchema, the tool's description, the server instructions, the result's note and
  // envelope block, its structured notes and method, and the README the package ships. None may
  // deny that the numbers in it are findings. The other direction stays as #2439 left it (the
  // walks above): such an answer is never measured, and its measured_at is null.
  it("#2465: no text a client holds for an answer that relays a non-zero count says the numbers in it are not findings", () => {
    const answers = {};
    let exposedUndated = 0;
    let sentences = 0;
    for (const [name, args, res] of COLLECTED) {
      const sc = res.structuredContent;
      if (res.isError || ![...numbersUnder(sc.data)].some((n) => n !== 0)) continue;
      answers[name] = (answers[name] ?? 0) + 1;
      if (name === "cve_exposure" && sc.exposure_state === "exposed" && sc.state === "not_assessed" && sc.data.exposed_hosts > 0) exposedUndated++;
      // The package's own words about this answer: not data, which is the API's JSON.
      const texts = [...schemaDescriptions(schemas[name]), descriptions[name], instructions, ...textBlocks(res).slice(1), ...sc.notes, sc.method];
      sentences += assertNoFindingDenied(`${name}(${JSON.stringify(args)})`, texts.flatMap(sentencesOf));
    }
    sentences += assertNoFindingDenied("README.md", readmeUnits(readPkgFile("README.md")));
    // Not vacuous: answers of every tool that relays counts, among them cve_exposure's exposed
    // answers under not_assessed, which are what #2465 is about, and exposure_radar's totals.
    assert.deepEqual(Object.keys(answers).sort(), [...TOOLS].sort(), JSON.stringify(answers));
    assert.ok(exposedUndated >= 10, `only ${exposedUndated} undated exposed cve_exposure answers read`);
    assert.ok(answers.exposure_radar >= 10, `only ${answers.exposure_radar} exposure_radar answers read`);
    assert.ok(sentences >= 1000, `only ${sentences} sentences read`);
  });
  // What the description says instead, in both directions: a not_assessed answer is no dated
  // measurement and presents no count as one (#2439), and it can still relay a count, as what
  // the source holds on record, undated, which its notes and exposure_state describe (#2465).
  it("#2465: every outputSchema says a not_assessed answer can relay a count on record, undated, and presents none as a dated measurement", () => {
    for (const [name, schema] of Object.entries(schemas)) {
      const d = branchOf(schema, "not_assessed").properties.state.description;
      assert.match(d, /not_assessed: the answer holds no dated measurement of what was asked, so no count in it is presented as one;/, `${name}: ${d}`);
      assert.match(d, /it can still relay a count, as what the source holds on record, undated, and its notes \(and exposure_state, where the result carries it\) say what each count is\./, `${name}: ${d}`);
    }
    assert.match(instructions, /not_assessed means the answer holds no dated measurement of what was asked, so no count in it is presented as one\./);
    assert.match(instructions, /It can still relay a count, as what the source holds on record, undated/);
    // exposure_state, the field that tells a relayed count from nothing to report, says so.
    const es = branchOf(schemas.cve_exposure, "not_assessed").properties.exposure_state.description;
    assert.match(es, /not state, which says whether the answer is a dated measurement\. exposed: data\.exposed_hosts counts the services the radar holds on record for the CVE, above 0\./, es);
  });
  it("#2465: the check above can fail: 2.1.0's state description, and the other ways to say it, are caught", () => {
    const today = branchOf(schemas.cve_exposure, "not_assessed").properties.state.description;
    assert.ok(assertNoFindingDenied("control", sentencesOf(today)) >= 1);
    for (const mutant of [
      "measured: a measurement of what was asked; an exposure count is measured only with measured_at and method. not_assessed: no dated measurement of what was asked, and no number in it is a finding.",
      today.replace(/ It can still relay a count[^]*$| it can still relay a count[^]*$/, " no number in it is a finding."),
      "Its numbers are not findings.",
      "None of its counts is a finding.",
      "No count here is a finding of exposure.",
    ]) {
      assert.throws(() => assertNoFindingDenied("mutant", sentencesOf(mutant)), /denies the numbers are findings/, mutant);
    }
  });
  it("every structured result that names Shodan indicates Shodan's ownership and copyright", () => {
    let checked = 0;
    for (const [name, args, res] of COLLECTED) {
      const all = JSON.stringify(res.structuredContent);
      if (!/Shodan/.test(all)) continue;
      checked++;
      assert.ok(res.structuredContent.notes.some((n) => n.includes(SHODAN_OWNERSHIP)), `${name}(${JSON.stringify(args)}): ${res.structuredContent.notes.join(" | ")}`);
    }
    assert.ok(checked >= 20, `only ${checked} structured results naming Shodan checked`);
  });
  it("no structured result makes a removed claim or calls a count hosts", () => {
    for (const [name, args, res] of COLLECTED) {
      const { data: _d, ...envelope } = res.structuredContent;
      const t = JSON.stringify(envelope);
      assert.doesNotMatch(t, REMOVED_CLAIMS, `${name}(${JSON.stringify(args)}): ${t}`);
      assert.doesNotMatch(t, HOST_UNIT, `${name}(${JSON.stringify(args)}): ${t}`);
    }
  });
});
