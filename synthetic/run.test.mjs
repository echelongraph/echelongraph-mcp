// Tests for the production MCP synthetic (#2724), against a local stub API and this package's
// own dist/ (build first; `npm test` does). Nothing here leaves the machine: the runner is given
// --bin (no npm install) and a loopback API base.
//
// What must hold:
//   - every listed tool is called once per era, judged against its own outputSchema with ajv,
//     and reported success; not_assessed counts as success; the planned tools are reported
//     not_published, never failure; a probed tool, prompt or resource the server does not list
//     although its version is at or past the release probes.mjs SHIPPED_IN gives it is a failure,
//     reason not_listed (#3282), and not_published before that release;
//   - a failing API, a forced unknown tool and a result the schema refuses are failures, with
//     a reason;
//   - one JSON line per tool per era carrying exactly the metric's labels (tool, era, outcome)
//     and a latency, then one completion line;
//   - every API request reaches the API under the synthetic's own user-agent family, whether
//     the package honours ECHELONGRAPH_MCP_UA or the forwarder has to prefix it;
//   - the probe table picks a new tool up: a candidate is sent only if it fits the advertised
//     inputSchema, and a listed tool with no entry is called with {} when that fits.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { connect, MODERN } from "../test/mcp-stdio-client.mjs";
import { connectHttp, modern } from "../test/mcp-http-client.mjs";
import { chooseInput, compareCatalogs, COMPLETE_MESSAGE, DEFAULT_CLIENT_CUT, DRIFT_TOOL, HTTP, judge, judgePrompt, judgeResource, judgeTextCut, LEGACY, loadRequiredText, probeOrder, probeSession, PROBE_MESSAGE, remoteUrlAllowed, runSynthetic, STDIO, TEXT_CUT_MESSAGE, UA_TOKEN } from "./run.mjs";
import { identify, startForwarder, uaFamilyOf } from "./forwarder.mjs";
// #2781: read off the modules rather than imported by name, so a runner without them fails the
// tests that read them, each by name, instead of failing this whole file at import.
import * as runner from "./run.mjs";
import * as forwarderModule from "./forwarder.mjs";
import { PROD_BASE, STRUCTURED_BUDGET, TRIP_WIRE, structuredSize, textSize } from "../test/text-bound.mjs";
import { AFTER, EXPECT, HTTP_EXPECT, HTTP_PROBES, LOG4J_CORE, LOG4J_CORE_PURL, LOG4J_FIXED_IN, PROBES, RESOURCE_PROBE, SBOM_PROBE_DOCUMENT, SBOM_PROBE_PURLS, UPSTREAM_PURL } from "./probes.mjs";
import * as probeTable from "./probes.mjs";
import { BATCH_PATH, batchAnswer, CALL_ANSWER, ROWS } from "../test/fixtures/match-batch.mjs";

const DIST = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "index.js");
// Every tool this package's dist lists, in createServer()'s registration order.
const PUBLISHED = [
  "cve_summary", "search_cves", "get_cve", "cve_exposure", "exposure_radar",
  "kev_recent", "epss_history", "check_affected", "check_sbom", "scan_manifest", "cve_intel", "cve_remediation", "get_cwe",
  "vendor_advisories_for_cve", "get_vendor_advisory", "search_vendor_advisories",
];
// A tool named in the probe table before a release lists it: added to PROBES for this file's
// runs only (every tool probes.mjs names today is published), so the not_published path is held.
const PLANNED = ["planned_tool_not_yet_listed"];
const CVE = "CVE-2021-44228";
const ADVISORY = "RHSA-2021:5128";
const EXPOSURE_CVE = "CVE-2023-44487";
const AT = "2026-10-03T09:00:00Z";
const METHOD = "Shodan banner match over the radar's tracked product queries.";

// Shaped like the live API, trimmed to what the tools need to answer.
const BODIES = {
  // #3276: with nvd_poll, the fleet's last completed NVD poll, as production serves it since #3242
  // (EXPECT.cve_summary holds freshness to it).
  "/api/v1/public/cves/summary": {
    nvd_poll: { interval: "20m0s", last_completed_at: AT, scope: "fleet" },
    poller: { cves_ingested: 1, cves_skipped: 0, http_retries: 0, interval: "20m0s", last_poll_at: AT, last_poll_dur_ms: 1000, poll_count: 1, poll_errors: 0 },
    summary: { critical: 1, high: 1, medium: 1, low: 1, none: 0, unscored: 0, total: 4, nvd_critical: 1, nvd_high: 1, nvd_medium: 1, nvd_low: 1, nvd_none: 0, rejected: 0, last_updated: AT },
  },
  "/api/v1/public/cves": { cves: [{ cve_id: CVE, severity: "CRITICAL", cvss_v3_score: 10, echelongraph_score: 10, score_assessed: true, kev_listed: true }], limit: 2, offset: 0, total: 1 },
  // #2839: with CISA's text, as production serves Log4Shell (EXPECT.get_cve holds kev_required_action).
  [`/api/v1/public/cves/${CVE}`]: {
    cve_id: CVE, severity: "CRITICAL", cvss_v3_score: 10, echelongraph_score: 10, score_confidence: "HIGH", score_assessed: true, epss_score: 0.97, kev_listed: true, kev_ransomware: true,
    kev_required_action: "For all affected software assets for which updates exist, the only acceptable remediation actions are: 1) Apply updates; OR 2) remove affected assets from agency networks.",
    kev_short_description: "Apache Log4j2 contains a vulnerability where JNDI features do not protect against attacker-controlled JNDI-related endpoints, allowing for remote code execution.",
    kev_notes_urls: ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
  },
  [`/api/v1/public/kev-exposure/cve/${EXPOSURE_CVE}`]: { cve_id: EXPOSURE_CVE, exposed_hosts: 12, countries: 3, kev_listed: true, kev_seen_in_observations: true, kev_catalog_listed: true, tracked: true, method: METHOD, ransomware: false, top_countries: [{ country: "Germany", hosts: 5 }], top_products: [{ product: "http_server", hosts: 12 }], last_seen: AT, generated_at: AT },
  "/api/v1/public/kev-exposure/stats": { distinct_hosts: 0, kev_cves_exposed: 0, correlations: 0, ransomware_cves: 0, ransomware_hosts: 0, top_products: [], top_cves: [], top_countries: [], newest_kev: [], trend: [], generated_at: AT },
  "/api/v1/public/exposed-databases/stats": { distinct_hosts: 0, engines: 0, pii_likely: 0, pci_likely: 0, top_engines: [], top_countries: [], generated_at: AT },
  "/api/v1/public/leaked-credentials/stats": { distinct_repos: 0, distinct_secrets: 0, total: 0, top_providers: [], top_types: [], generated_at: AT },
  "/api/v1/public/shadow-ai-radar/stats": {
    stats: { total: 0, by_category: {}, visible_by_category: {}, last_24h_count: 0, last_24h_visible_count: 0, auth_confirmed: 0, auth_undetermined: 0 },
    poller: { running: true, interval_seconds: 60, last_run_at: AT, shodan_enabled: true },
  },
};
// The tools registered after the five (#2716-#2721), shaped as their own suites' fixtures.
const KEV_ROW = { cve_id: CVE, kev_added_date: "2021-12-10", kev_due_date: "2021-12-24", kev_vendor: "Apache", kev_product: "Log4j2", kev_vuln_name: "Apache Log4j2 Remote Code Execution Vulnerability", kev_ransomware: true, severity: "CRITICAL", cvss_v3_score: 10, epss_score: 0.97, epss_percentile: 0.99, eg_kev_tier: 1, our_first_seen_kev: AT };
BODIES["/api/v1/public/kev/recent"] = {
  kev: [KEV_ROW], count: 1, total: 1, kev_listed_total: 1, limit: 5, next_cursor: null, order: "kev_added_date DESC, cve_id ASC",
  filters: { since: null, until: null, ransomware: null, vendor: null },
  catalog: { source: "CISA KEV catalog", feed_url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", last_successful_fetch_at: AT, catalog_version: "2026.10.02", date_released: AT, catalog_count: 1 },
  method: "EchelonGraph polls CISA's known_exploited_vulnerabilities.json every 5 minutes.", notes: [], generated_at: AT,
};
BODIES[`/api/v1/public/cves/${CVE}/epss-history`] = {
  cve_id: CVE, series_kind: "change_only", series_starts_at: "2026-06-01T00:00:00Z",
  current: { epss_score: 0.97, epss_percentile: 0.99, epss_updated_at: AT },
  points: [{ at: AT, epss_score: 0.97, epss_percentile: 0.99 }], history_rows: 1, points_truncated: false, latest_point_matches_current: true,
};
BODIES["/api/v1/public/cves/match"] = {
  assessed: true, candidate_count: 1, candidates_capped: false, capped: false, count: 0, excluded: [], excluded_count: 0, match_layer: "registry", not_assessed_reason: "",
  product: "", product_named_count: 0, undecidable_excluded_count: 0, undecided_candidate_count: 0, vendor: "", vendor_advisory_count: 0, version: "4.17.20", matches: [],
};
// #3135: the matcher-verdict probes, pinned here where they are metric labels and values, and read off
// the module (as PROMPT_PROBES is below) so a probes.mjs without them fails the tests that read them,
// each by name, instead of failing this whole file at import.
const MAYAN_CVE = "CVE-2025-14692";
const MAYAN_FIXED_IN = "4.10.2";
const MAGENTO = "magento/community-edition";
const COSMICSTING_CVE = "CVE-2024-34102";
const SESSIONREAPER_CVE = "CVE-2025-54236";
const MALI_CVE = "CVE-2022-38181";
const VERDICT_LABELS = [
  "verdict:pypi/mayan-edms@4.9.0",
  `verdict:packagist/${MAGENTO}@2.4.4-p13`,
  `verdict:packagist/${MAGENTO}@2.4.5-p2`,
  "verdict:cpe/midgard_gpu_kernel_driver@r20p0",
  // #2834: fixed_in on GET /cves/match's exact-list match.
  "verdict:maven/org.apache.logging.log4j/log4j-core@2.14.1",
];
const VERDICT_PROBES = probeTable.VERDICT_PROBES;
// #3135: a verdict probe whose label is in EXPECT_PENDING is listed and tested but not called; the
// Mali probe was, until #3131 reached production, and has been called since c0f58d5d. The lines a run
// writes are the active labels. These tests follow whichever state probes.mjs is in (held back: no
// Mali line; called: a Mali line, judged), so either is one edit there and a redeploy; a test that
// needs the other state sets it for its own run and puts it back.
const EXPECT_PENDING = probeTable.EXPECT_PENDING ?? {};
const MALI_LABEL = "verdict:cpe/midgard_gpu_kernel_driver@r20p0";
const MALI_PENDING_REASON = "#3131 not yet deployed";
const MALI_PENDING = Boolean(EXPECT_PENDING[MALI_LABEL]);
const activeVerdicts = () => VERDICT_LABELS.filter((l) => !EXPECT_PENDING[l]);
async function withPendingAs(label, reason, fn) {
  const was = EXPECT_PENDING[label];
  if (reason === undefined) delete EXPECT_PENDING[label];
  else EXPECT_PENDING[label] = reason;
  try {
    return await fn();
  } finally {
    if (was === undefined) delete EXPECT_PENDING[label];
    else EXPECT_PENDING[label] = was;
  }
}
const withPendingEnabled = (label, fn) => withPendingAs(label, undefined, fn);
// #3135: GET /cves/match for each VERDICT_PROBES lookup, as production answered it on 2026-10-11
// (the hosted endpoint at 3.0.0), trimmed to what the expects read; the stub picks one by the request
// headers check_affected sends (X-EG-Ecosystem, X-EG-Package, X-EG-Product, X-EG-Version). Its
// `regressed` set answers as the rule before each fix would: fixed_in_rule (#3074: the holding
// interval's own bound, 4.9.7, no detail), comparator (#3101: p13 below p9 and p2 above p14, so
// CosmicSting matches 2.4.4-p13 and SessionReaper misses 2.4.5-p2), cpe_comparator (#3131: r20p0
// outside [r4p0, r31p0], which was production's answer until #3131 was deployed), and, for log4j-core
// 2.14.1 (#2834), fixed_in_exact_list (the GET route's exact-list path with no interval lookup:
// fixed_in null, with its reason) and fixed_in_stored (the bound read from the stored fixed_version,
// 2.3.1).
const registryAnswer = (ecosystem, pkg, version, matches, notAffected) => ({
  assessed: true, ecosystem, ecosystem_recognised: true, package: pkg, version, match_layer: "registry", not_assessed_reason: "",
  count: matches.length, capped: false, candidates_capped: false, degraded: false, undetermined_count: 0, undetermined: [], not_affected_count: notAffected,
  cve_ids: matches.map((m) => m.cve_id), matches,
});
const registryMatch = (cve, extra) => ({
  cve_id: cve, severity: "HIGH", cvss_v3_score: 7.5, kev_listed: false, ransomware: false, epss_score: 0.01, effective_score: 7.5, effective_severity: "HIGH", score_assessed: true,
  match_method: "registry package", match_confidence: 0.95, vendor_unknown: false, version_evidence: "advisory_interval", ...extra,
});
const MAYAN_DETAIL = "fixed_in moved past the overlapping interval [0, 4.10.2) of the same record: the interval that holds this version, [4.9.0, 4.9.7), ends inside it, so its own bound is still affected";
const VERDICT_ANSWERS = {
  "PyPI|mayan-edms|4.9.0": (regressed) =>
    registryAnswer("PyPI", "mayan-edms", "4.9.0", [
      registryMatch(MAYAN_CVE, {
        severity: "MEDIUM", cvss_v3_score: 6.1, effective_score: 6.1, effective_severity: "MEDIUM", matched_criteria: "pkg:pypi/mayan-edms", interval: { introduced: "4.9.0", fixed: "4.9.7" },
        ...(regressed.has("fixed_in_rule") ? { fixed_in: "4.9.7" } : { fixed_in: MAYAN_FIXED_IN, fixed_in_detail: MAYAN_DETAIL }),
      }),
    ], 4),
  [`Packagist|${MAGENTO}|2.4.4-p13`]: (regressed) =>
    registryAnswer("Packagist", MAGENTO, "2.4.4-p13", [
      registryMatch("CVE-2025-54236", { kev_listed: true, fixed_in: null, fixed_in_reason: "the interval that holds this version ends at last_affected 2.4.4-p15; no fixed version is recorded" }),
      ...(regressed.has("comparator") ? [registryMatch(COSMICSTING_CVE, { kev_listed: true, interval: { introduced: "0", fixed: "2.4.4-p9" }, fixed_in: "2.4.4-p9" })] : []),
    ], 327),
  [`Packagist|${MAGENTO}|2.4.5-p2`]: (regressed) =>
    registryAnswer("Packagist", MAGENTO, "2.4.5-p2", [
      registryMatch(COSMICSTING_CVE, { kev_listed: true, interval: { introduced: "2.4.5-p1", fixed: "2.4.5-p8" }, fixed_in: "2.4.5-p8" }),
      ...(regressed.has("comparator") ? [] : [registryMatch(SESSIONREAPER_CVE, { kev_listed: true, fixed_in: null, fixed_in_reason: "the interval that holds this version ends at last_affected 2.4.5-p14; no fixed version is recorded" })]),
    ], 229),
  // #2834, as production answered GET /cves/match on 2026-10-11 (#2834's review: the API, and hosted
  // and stdio check_affected, gave the same answer).
  "Maven|org.apache.logging.log4j:log4j-core|2.14.1": (regressed) =>
    registryAnswer("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1", [
      registryMatch(CVE, {
        severity: "CRITICAL", cvss_v3_score: 10, kev_listed: true, ransomware: true, effective_score: 10, effective_severity: "CRITICAL", matched_criteria: "pkg:maven/org.apache.logging.log4j:log4j-core",
        version_evidence: "exact_version_list", interval: { introduced: "2.13.0", fixed: "2.15.0" },
        ...(regressed.has("fixed_in_exact_list")
          ? { interval: undefined, fixed_in: null, fixed_in_reason: "the version is listed verbatim in the advisory's affected versions, and no advisory interval holding it records a fixed version" }
          : { fixed_in: regressed.has("fixed_in_stored") ? "2.3.1" : "2.15.0" }),
      }),
      registryMatch("CVE-2021-45046", { kev_listed: true, interval: { introduced: "2.13.0", fixed: "2.16.0" }, fixed_in: "2.16.0" }),
    ], 3),
  "|midgard_gpu_kernel_driver|r20p0": (regressed) => {
    const cpe = (cve) => ({ cve_id: cve, severity: "MEDIUM", cvss_v3_score: 5.5, kev_listed: true, ransomware: false, score_assessed: true, cpe_vendor: "arm", vendor_unknown: false, match_method: "cpe", matched_criteria: "cpe:2.3:o:arm:midgard_gpu_kernel_driver:*:*:*:*:*:*:*:*" });
    const matches = [cpe("CVE-2023-4211"), ...(regressed.has("cpe_comparator") ? [] : [cpe(MALI_CVE)])];
    return { assessed: true, product: "midgard_gpu_kernel_driver", version: "r20p0", vendor: "", match_layer: "cpe", not_assessed_reason: "", count: matches.length, capped: false, candidates_capped: false, excluded: [], excluded_count: 0, matches };
  },
};
const verdictAnswerFor = (headers, regressed) => {
  // The tool percent-encodes each value (check_affected.ts), so magento/community-edition arrives as
  // magento%2Fcommunity-edition.
  const h = (n) => decodeURIComponent(headers[n] ?? "");
  const key = headers["x-eg-product"] ? `|${h("x-eg-product")}|${h("x-eg-version")}` : `${h("x-eg-ecosystem")}|${h("x-eg-package")}|${h("x-eg-version")}`;
  return VERDICT_ANSWERS[key]?.(regressed);
};
BODIES[BATCH_PATH] = CALL_ANSWER;
// #2834, #2836: the rows production served for check_sbom's two probe purls on 2026-10-11, trimmed to
// what EXPECT.check_sbom reads. A batch carrying either gets its row after CALL_ANSWER's two, so
// the stub answers the probe the way production does. The stub's `regressed` set answers a row as a
// regression would: fixed_in (the bound read from the stored fixed_version), fixed_in_null (no
// interval found on the exact-list path), upstream (the qualifier ignored).
const LOG4J_MATCH = {
  cve_id: CVE, severity: "CRITICAL", cvss_v3_score: 10, kev_listed: true, ransomware: true, epss_score: 0.99999, score_assessed: true,
  match_reason: "registry package (confidence 0.95): Maven/org.apache.logging.log4j:log4j-core — version 2.14.1 is listed verbatim in the advisory's affected versions",
  version_evidence: "exact_version_list", interval: { introduced: "2.13.0", fixed: "2.15.0" }, fixed_in: "2.15.0",
};
const PROBE_ROWS = {
  [LOG4J_CORE_PURL]: (i, regressed) => {
    const m = { ...LOG4J_MATCH };
    if (regressed.has("fixed_in")) m.fixed_in = "2.3.1";
    if (regressed.has("fixed_in_null")) Object.assign(m, { fixed_in: null, fixed_in_reason: "the version is listed verbatim in the advisory's affected versions, and no advisory interval holding it records a fixed version" });
    return { ...ROWS.affected(i, LOG4J_CORE_PURL, LOG4J_CORE, "2.14.1", [CVE]), ecosystem: "Maven", matched_package: LOG4J_CORE, matched_via: "purl_name", matches: [m] };
  },
  [UPSTREAM_PURL]: (i, regressed) =>
    regressed.has("upstream")
      ? { ...ROWS.unknown(i, UPSTREAM_PURL, "libcrypto3", "3.3.6-r0"), ecosystem: "Alpine:v3.20", ecosystem_recognised: false, matched_package: "libcrypto3", matched_via: "purl_name" }
      : {
          ...ROWS.affected(i, UPSTREAM_PURL, "openssl", "3.3.6-r0", ["CVE-2026-31789", "CVE-2026-28387"]),
          ecosystem: "Alpine:v3.20", ecosystem_recognised: false, matched_package: "openssl", matched_via: "upstream", matched_version_from: "purl", purl_name: "libcrypto3",
        },
};
function batchBodyFor(components, regressed) {
  const base = CALL_ANSWER.results;
  const extra = components.map((c) => c?.purl).filter((p) => PROBE_ROWS[p]);
  return batchAnswer([...base, ...extra.map((p, k) => PROBE_ROWS[p](base.length + k, regressed))]);
}
// A check_sbom structuredContent whose data is the stub's answer to the probe's first batch (both
// probe rows in it, as production serves them, or as `regressed` says), under `over`.
function sbomSc(over = {}, regressed = new Set()) {
  const data = batchBodyFor(SBOM_PROBE_PURLS.slice(0, 200).map((purl) => ({ purl })), regressed);
  return { state: "measured", data, coverage: { batches_sent: 2, not_sent_reason: null }, ...over };
}
// #2841: GET /cves/:id/remediation as core-backend's cve/remediation.go serves Log4Shell.
BODIES[`/api/v1/public/cves/${CVE}/remediation`] = {
  cve_id: CVE, state: "assessed", not_assessed_reason: null,
  cisa: { kev_listed: true, required_action: "Apply updates per vendor instructions.", due_date: "2021-12-24T00:00:00Z", short_description: "Apache Log4j2 contains a vulnerability.", notes_urls: [] },
  fixed_branches: [{ ecosystem: "Maven", package_name: "org.apache.logging.log4j:log4j-core", fixed_version: "2.12.2", fixed_branches: [{ introduced: "2.13.0", fixed: "2.15.0", last_affected: null, source: "osv_bulk", advisory_id: "GHSA-jfh8-c2jp-5v3q" }] }],
  vendor_remediations: [
    { vendor: "redhat", vendor_display_name: "Red Hat", vendor_advisory_id: "RHSA-2021:5129", vendor_published_at: AT, withdrawn: false, remediation_state: "parsed", remediation_kinds: ["vendor_fix"], items_total: 1,
      items: [{ kind: "vendor_fix", source_category: "vendor_fix", source_subcategory: null, text: "For details on how to apply this update, refer to https://access.redhat.com/articles/11258", text_truncated: false, text_chars: 89, url: "https://access.redhat.com/errata/RHSA-2021:5129", fixed_build: null, product_ids: [], product_count: 0 }] },
  ],
  fix_references: [], patches: [],
  coverage: { parsed_vendors: ["redhat", "microsoft", "paloalto"], vendors_not_parsed: [], vendor_advisories_listed: 1, vendor_advisory_limit: 20, item_text_cap: 2000, items_per_advisory_cap: 16 },
  failed_sections: [],
};
BODIES[`/api/v1/public/cves/${CVE}/enrichment`] = {
  vendor_advisories: [], patches: [], fixed_versions: [],
  // #2817: what core-backend serves for log4j-core since #2817, which EXPECT.cve_intel holds.
  affected_packages: [
    {
      ecosystem: "Maven", package_name: "org.apache.logging.log4j:log4j-core", fixed_version: "2.12.2", dependents_count: 0, source: "osv",
      fixed_branches: [
        { introduced: "2.13.0", fixed: "2.15.0", last_affected: null, source: "osv_bulk", advisory_id: "GHSA-jfh8-c2jp-5v3q" },
        { introduced: "2.0-beta9", fixed: "2.3.1", last_affected: null, source: "osv_bulk", advisory_id: "GHSA-jfh8-c2jp-5v3q" },
        { introduced: "2.4", fixed: "2.12.2", last_affected: null, source: "osv_bulk", advisory_id: "GHSA-jfh8-c2jp-5v3q" },
      ],
    },
  ],
  cwes: [{ cwe_id: "CWE-502", name: "Deserialization of Untrusted Data", source: "nvd" }],
  timeline: [], timeline_count_7d: 0, timeline_count_30d: 0, timeline_total: 0,
  ai: { plain_summary: null, risk_narrative: null, remediation_playbook: null },
  trending: { is_trending: false, recent_source_count: 0, kev_recent: false, patch_recent: false }, historical_incidents: [],
  exploits: [{ kind: "metasploit", source_name: "metasploit/0", source_url: "https://example.test/metasploit/0", first_seen_at: AT, verified_status: "verified" }],
  exploits_total: 1, exploits_capped: false, exploits_by_kind: { metasploit: 1 }, exploits_by_status: { verified: 1 }, failed_sections: [],
};
BODIES["/api/v1/public/cwes/CWE-79"] = {
  cwe_id: "CWE-79", name: "Cross-site Scripting", description: "The product does not neutralize or incorrectly neutralizes user-controllable input.", total: 1,
  cves: [{ cve_id: CVE, severity: "CRITICAL", cvss_v3_score: 10, echelongraph_score: 10, echelongraph_severity: "CRITICAL", score_assessed: true, published: AT, description: "d", kev_listed: true }],
  page: 1, page_size: 50, max_page: 200, order: "kev_listed desc, echelongraph_score desc (CVEs not yet scored last), cvss_v3_score desc (nulls last), published desc (nulls last), cve_id", catalog_version: "4.17",
};
const ADVISORY_ROW = {
  advisory_id: "6f1c7d2e-0000-4000-8000-000000000001", vendor: "redhat", vendor_display_name: "Red Hat", vendor_advisory_id: ADVISORY,
  cve_ids: [CVE], title: "Critical: log4j security update", severity: "Critical", cvss_v3_score: 10, summary: "An update for log4j is now available.",
  affected_products: ["Red Hat Enterprise Linux 8"], vendor_published_at: AT, our_first_seen_at: AT, withdrawn: false,
};
BODIES[`/api/v1/public/vendor-advisories/by-cve/${CVE}`] = { cve_id: CVE, advisories: [ADVISORY_ROW], total: 1 };
BODIES[`/api/v1/public/vendor-advisories/redhat/${encodeURIComponent(ADVISORY)}`] = {
  ...ADVISORY_ROW, known_cve_ids: [CVE], description: "An update for log4j is now available.", remediation: "Update the log4j packages.",
  references: [{ url: "https://access.redhat.com/errata/RHSA-2021:5128" }], vendor_modified_at: AT, withdrawn_at: "", withdrawn_reason: "",
};
BODIES["/api/v1/public/vendor-advisories"] = { advisories: [ADVISORY_ROW], total: 1, limit: 2, offset: 0, search_applied: true };

const MCP_REASONS = ["identified_no_challenge", "resource_mismatch", "cross_origin_pointer", "bare_challenge_no_prm", "pointer_unreachable", "pointer_invalid", "no_authorization_servers", "wellknown_unreachable", "metadata_invalid", "challenge_unadjudicated", "no_http_answer"];
BODIES["/api/v1/public/ai-exposure/stats?service=mcp"] = {
  service: "mcp", total: 0, protected: 0, pending_readjudication: 0, not_assessed: 0,
  not_assessed_by_reason: Object.fromEntries(MCP_REASONS.map((r) => [r, 0])),
  prm_via: { header: 0, wellknown_path: 0, wellknown_root: 0 },
  era: { legacy: 0, dual: 0, modern: 0, unknown: 0, not_measured: 0 },
  transport: { streamable_http: 0, legacy_sse: 0, unknown: 0, not_measured: 0 },
  window: { from: null, to: null }, own_controls_excluded: 0, withheld_opted_out: 0, enabled: false,
};

// mode: ok (BODIES, else the router's 404), 500 (every request a 500).
async function startStub() {
  // batches: the component count of each POST to the batch route (#2757). refuseSecondBatch:
  // every second one is answered 429 without Retry-After, as a spent per-minute budget would be, so
  // check_sbom answers partial with one batch sent. batchCap: a batch of more components is refused
  // 400 TOO_MANY_COMPONENTS, as the route answers one over cveBatchMaxComponents (a lowered cap).
  const state = { mode: "ok", userAgents: [], seen: [], batches: [], refuseSecondBatch: false, batchCap: null, regressed: new Set() };
  const server = http.createServer((req, res) => {
    state.userAgents.push(req.headers["user-agent"]);
    state.seen.push({ method: req.method, url: req.url, headers: req.headers });
    if (state.mode === "500") {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "internal error" }));
      return;
    }
    if (state.mode === "echo") {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        res.writeHead(201, { "content-type": "application/json", "x-eg-echo": req.headers["x-eg-product"] ?? "" });
        res.end(JSON.stringify({ method: req.method, url: req.url, body: Buffer.concat(chunks).toString() }));
      });
      return;
    }
    if (req.method === "POST" && req.url === BATCH_PATH) {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        const components = JSON.parse(Buffer.concat(chunks).toString()).components;
        const n = components.length;
        state.batches.push(n);
        if (state.batchCap !== null && n > state.batchCap) {
          res.writeHead(400, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: `${n} components sent; at most ${state.batchCap} per call. Nothing was looked up: split the list`, code: "TOO_MANY_COMPONENTS" }));
          return;
        }
        const refused = state.refuseSecondBatch && state.batches.length % 2 === 0;
        res.writeHead(refused ? 429 : 200, { "content-type": "application/json" });
        res.end(JSON.stringify(refused ? { error: "component budget exceeded", code: "RATE_LIMIT_EXCEEDED" } : batchBodyFor(components, state.regressed)));
      });
      return;
    }
    const { pathname } = new URL(req.url, "http://stub");
    const body = (pathname === "/api/v1/public/cves/match" ? verdictAnswerFor(req.headers, state.regressed) : undefined) ?? BODIES[req.url] ?? BODIES[pathname];
    if (body === undefined) {
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("404 page not found\n");
      return;
    }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    state,
    base: `http://127.0.0.1:${server.address().port}`,
    close: () => {
      server.closeAllConnections();
      return new Promise((resolve) => server.close(resolve));
    },
  };
}

// #3097's review: npm's package at the version the hosted endpoint reports, for the comparison when
// that is not the npm leg's version. Here this checkout's build is "npm's" package of its own version
// (the endpoint under test is the same build); any other version is not published. Never the network.
const releasedHere = async (spec) => {
  const { PKG } = await import("../test/server-under-test.mjs");
  if (spec !== `echelongraph-mcp@${PKG.version}`) throw new Error(`npm error code ETARGET | npm error notarget No matching version found for ${spec}.`);
  return { serverJs: DIST, version: PKG.version };
};
async function run(stub, opts = {}) {
  const lines = [];
  const result = await runSynthetic({ serverJs: DIST, apiBase: stub.base, timeoutMs: 30_000, installPackage: releasedHere, write: (l) => lines.push(JSON.parse(JSON.stringify(l))), ...opts });
  const probes = lines.filter((l) => l.message === PROBE_MESSAGE);
  const complete = lines.filter((l) => l.message === COMPLETE_MESSAGE);
  const of = (tool, era) => probes.find((l) => l.tool === tool && l.era === era);
  return { ...result, lines, probes, complete, of };
}

describe("the synthetic against the stub API", () => {
  let stub;
  before(async () => {
    stub = await startStub();
    for (const t of PLANNED) PROBES[t] = [{}];
  });
  after(() => {
    for (const t of PLANNED) delete PROBES[t];
    return stub.close();
  });

  describe("a healthy API", () => {
    let r;
    before(async () => {
      stub.state.mode = "ok";
      stub.state.userAgents.length = 0;
      stub.state.batches.length = 0;
      r = await run(stub);
    });
    // #2835: scan_manifest's probe, registered right after check_sbom, sends its 20 distinct purls
    // as one batch.
    it("#2757: check_sbom is probed with 201 purls, so each era sends two batches, 200 and 1, and both are answered", () => {
      assert.deepEqual(stub.state.batches, [200, 1, 20, 200, 1, 20]);
      for (const era of [MODERN, LEGACY]) assert.equal(r.of("check_sbom", era).outcome, "success");
    });
    it("calls every published tool once per era and reports each a success", () => {
      for (const era of [MODERN, LEGACY]) {
        for (const tool of PUBLISHED) {
          const l = r.of(tool, era);
          assert.ok(l, `${tool} [${era}]: no line`);
          assert.equal(l.outcome, "success", `${tool} [${era}]: ${JSON.stringify(l)}`);
          assert.ok(["measured", "not_assessed"].includes(l.state), `${tool} [${era}]: state ${l.state}`);
          assert.ok(Number.isInteger(l.latency_ms) && l.latency_ms >= 0, `${tool} [${era}]: latency ${l.latency_ms}`);
          assert.equal(l.input, 0);
        }
      }
      assert.equal(r.exitCode, 0);
    });
    it("counts not_assessed as a success (cve_exposure and exposure_radar answer it today)", () => {
      assert.equal(r.of("cve_exposure", MODERN).state, "not_assessed");
      assert.equal(r.of("exposure_radar", LEGACY).state, "not_assessed");
      assert.equal(r.of("cve_exposure", MODERN).outcome, "success");
    });
    it("reports every planned tool not_published, never a failure", () => {
      for (const era of [MODERN, LEGACY]) {
        for (const tool of PLANNED) assert.equal(r.of(tool, era)?.outcome, "not_published", `${tool} [${era}]`);
      }
    });
    it("writes exactly one line per tool per era, with the metric's labels, then one completion line", () => {
      const keys = r.probes.map((l) => `${l.tool}|${l.era}`);
      assert.equal(new Set(keys).size, keys.length, "a tool/era reported twice");
      assert.equal(r.probes.length, 2 * (PUBLISHED.length + PLANNED.length));
      for (const l of r.probes) {
        assert.equal(l.severity, "INFO");
        for (const k of ["tool", "era", "outcome", "run_id", "package_version"]) assert.equal(typeof l[k], "string", `${k} missing: ${JSON.stringify(l)}`);
        assert.ok(["success", "failure", "not_published"].includes(l.outcome));
      }
      assert.equal(r.complete.length, 1);
      assert.equal(r.lines.at(-1).message, COMPLETE_MESSAGE);
      const c = r.complete[0];
      assert.deepEqual([c.success, c.failure, c.not_published], [2 * PUBLISHED.length, 0, 2 * PLANNED.length]);
      assert.equal(new Set(r.lines.map((l) => l.run_id)).size, 1, "one run id per run");
    });
    it("reports the version the server runs, from its handshake", async () => {
      const { PKG } = await import("../test/server-under-test.mjs");
      for (const l of r.lines) assert.equal(l.package_version, PKG.version);
    });
    it("#2842: one client-cut line per era, judged by the package's own registry: instructions within 2,048 characters and every head holding its sentences", async () => {
      const { PKG } = await import("../test/server-under-test.mjs");
      const cut = r.lines.filter((l) => l.message === TEXT_CUT_MESSAGE);
      assert.deepEqual(cut.map((l) => l.era), [MODERN, LEGACY]);
      for (const l of cut) {
        assert.equal(l.severity, "INFO");
        assert.equal(l.transport, STDIO);
        assert.equal(l.run_id, r.complete[0].run_id);
        assert.ok(Number.isInteger(l.instructions_chars) && l.instructions_chars > 0 && l.instructions_chars <= 2048, `instructions_chars ${l.instructions_chars}`);
        assert.deepEqual(
          [l.outcome, l.cut, l.instructions_head_ok, l.description_heads_ok, l.description_heads_missing, l.tools_without_required_entry, l.tools_listed, l.descriptions_over_cut, l.description_heads_basis, l.required_version],
          ["success", 2048, true, true, 0, 0, PUBLISHED.length, 0, "judged", PKG.version],
          JSON.stringify(l),
        );
        assert.equal(l.detail, undefined);
      }
      // Both eras serve the same instructions.
      assert.equal(cut[0].instructions_chars, cut[1].instructions_chars);
      assert.deepEqual([r.complete[0].text_cut_lines, r.complete[0].text_cut_failures], [2, 0]);
    });
    it("#2834, #2836, #2839: check_sbom's and get_cve's probes met their EXPECTs on both eras", () => {
      for (const era of [MODERN, LEGACY]) {
        for (const tool of ["check_sbom", "get_cve"]) assert.deepEqual([r.of(tool, era).outcome, r.of(tool, era).reason], ["success", undefined], tool);
      }
    });
    it("every API request carries the synthetic's family, and this package names it itself", () => {
      assert.ok(stub.state.userAgents.length >= PUBLISHED.length * 2);
      for (const ua of stub.state.userAgents) {
        assert.equal(uaFamilyOf(ua), "echelongraph-mcp-synthetic", ua);
        assert.match(ua, /^echelongraph-mcp-synthetic\/1\.0 echelongraph-mcp\/\S+ \(\+https:\/\/echelongraph\.io\/pulse\/mcp\)$/);
      }
      const c = r.complete[0];
      assert.equal(c.ua_identified_by_package, c.api_requests);
      assert.equal(c.ua_prefixed_by_forwarder, 0);
    });
  });

  it("a version that ignores ECHELONGRAPH_MCP_UA is still identified, by the forwarder", async () => {
    stub.state.mode = "ok";
    stub.state.userAgents.length = 0;
    // An empty value is what a package that predates the variable effectively sends.
    const r = await run(stub, { eras: [LEGACY], serverEnv: { ECHELONGRAPH_MCP_UA: "" } });
    assert.ok(stub.state.userAgents.length > 0);
    for (const ua of stub.state.userAgents) assert.equal(uaFamilyOf(ua), "echelongraph-mcp-synthetic", ua);
    assert.equal(r.complete[0].ua_prefixed_by_forwarder, r.complete[0].api_requests);
  });

  it("--direct sends the package's own requests, under the synthetic's token from ECHELONGRAPH_MCP_UA", async () => {
    stub.state.mode = "ok";
    stub.state.userAgents.length = 0;
    const r = await run(stub, { eras: [MODERN], direct: true });
    assert.equal(r.complete[0].forwarder, "off");
    for (const ua of stub.state.userAgents) assert.equal(uaFamilyOf(ua), "echelongraph-mcp-synthetic", ua);
  });

  it("an API answering 500 fails every published tool, on both eras, with the state as the reason", async () => {
    stub.state.mode = "500";
    const r = await run(stub);
    stub.state.mode = "ok";
    for (const era of [MODERN, LEGACY]) {
      for (const tool of PUBLISHED) {
        const l = r.of(tool, era);
        assert.equal(l.outcome, "failure", `${tool} [${era}]`);
        // A tool whose input comes from another tool's answer (AFTER) has no input when that one failed.
        const want = AFTER[tool] ? "no_valid_probe_input" : "state_failed";
        assert.equal(l.reason, want, `${tool} [${era}]: ${JSON.stringify(l)}`);
      }
      for (const tool of PLANNED) assert.equal(r.of(tool, era).outcome, "not_published");
    }
    assert.equal(r.exitCode, 2);
    assert.equal(r.complete[0].failure, 2 * PUBLISHED.length);
  });

  it("#2757: an API that refuses check_sbom's second batch fails the probe, expectation_unmet, though the answer fits its schema", async () => {
    stub.state.mode = "ok";
    stub.state.batches.length = 0;
    stub.state.refuseSecondBatch = true;
    let r;
    try {
      r = await run(stub, { eras: [LEGACY] });
    } finally {
      stub.state.refuseSecondBatch = false;
    }
    // #2835: then scan_manifest's one batch of 20, answered.
    assert.deepEqual(stub.state.batches, [200, 1, 20], "control: the second batch was sent, and refused");
    const l = r.of("check_sbom", LEGACY);
    assert.equal(l.outcome, "failure", JSON.stringify(l));
    assert.equal(l.reason, "expectation_unmet");
    assert.equal(l.state, "measured", "the answer itself was a valid partial one");
    assert.equal(l.detail, 'coverage.batches_sent 1, want at least 2 (not_sent_reason "rate_limited")');
    for (const tool of PUBLISHED.filter((t) => t !== "check_sbom")) assert.equal(r.of(tool, LEGACY).outcome, "success", tool);
    assert.equal(r.exitCode, 2);
  });

  it("#2757: a lowered batch cap fails check_sbom's probe as state_invalid_input, not expectation_unmet: its first batch is refused", async () => {
    // What the EXPECT comment (probes.mjs) and the alert's runbook say: expectation_unmet is the
    // SECOND batch going unanswered; a cap below 200 refuses the first, and nothing is answered.
    stub.state.mode = "ok";
    stub.state.batches.length = 0;
    stub.state.batchCap = 100;
    let r;
    try {
      r = await run(stub, { eras: [LEGACY] });
    } finally {
      stub.state.batchCap = null;
    }
    // #2835: scan_manifest's one batch of 20 is under the lowered cap, and answered.
    assert.deepEqual(stub.state.batches, [200, 20], "control: the first batch was sent, refused, and nothing after it");
    const l = r.of("check_sbom", LEGACY);
    assert.equal(l.outcome, "failure", JSON.stringify(l));
    // A 400 is the API refusing the input (index.ts failed()), so the state is invalid_input.
    assert.equal(l.reason, "state_invalid_input", JSON.stringify(l));
    assert.equal(r.exitCode, 2);
  });

  // #2834, #2836: production answering a probe row as a regression would fails check_sbom's
  // probe, expectation_unmet with what it saw, and nothing else.
  for (const [regression, want] of [
    ["fixed_in", /CVE-2021-44228 fixed_in "2\.3\.1" .*; want "2\.15\.0"$/],
    ["fixed_in_null", /CVE-2021-44228 fixed_in null \(fixed_in_reason "the version is listed verbatim/],
    ["upstream", /: verdict "not_assessed", matched_via "purl_name", matched_package "libcrypto3" \(not_assessed_reason "package_not_in_advisory_corpus"\); want affected, upstream, openssl$/],
  ]) {
    it(`#2834/#2836: a probe row answered regressed (${regression}) fails check_sbom's probe, expectation_unmet, and only it`, async () => {
      stub.state.mode = "ok";
      stub.state.regressed = new Set([regression]);
      let r;
      try {
        r = await run(stub, { eras: [LEGACY] });
      } finally {
        stub.state.regressed = new Set();
      }
      const l = r.of("check_sbom", LEGACY);
      assert.deepEqual([l.outcome, l.reason, l.state], ["failure", "expectation_unmet", "measured"], JSON.stringify(l));
      assert.match(l.detail, want);
      for (const tool of PUBLISHED.filter((t) => t !== "check_sbom")) assert.equal(r.of(tool, LEGACY).outcome, "success", tool);
      assert.equal(r.exitCode, 2);
    });
  }

  it("#2839: a Log4Shell record served without CISA's text fails get_cve's probe, expectation_unmet, and only it", async () => {
    stub.state.mode = "ok";
    const key = `/api/v1/public/cves/${CVE}`;
    const kept = BODIES[key];
    const { kev_required_action, ...without } = kept;
    assert.equal(typeof kev_required_action, "string", "control: the healthy body carries the text");
    BODIES[key] = without;
    let r;
    try {
      r = await run(stub, { eras: [LEGACY] });
    } finally {
      BODIES[key] = kept;
    }
    const l = r.of("get_cve", LEGACY);
    assert.deepEqual([l.outcome, l.reason, l.detail], ["failure", "expectation_unmet", `data.kev_required_action absent; want CISA's text for ${CVE}`], JSON.stringify(l));
    for (const tool of PUBLISHED.filter((t) => t !== "get_cve")) assert.equal(r.of(tool, LEGACY).outcome, "success", tool);
    assert.equal(r.exitCode, 2);
  });

  // #2842: a server whose description head lacks a sentence its own registry requires. The server
  // is this package's dist, run through a symlink from a directory whose requiredText.js asks one
  // more get_cve sentence than any description holds: loadRequiredText reads the registry beside
  // the server .js it is given, as it reads an installed package's.
  it("#2842: a description head that lacks a required sentence makes the client-cut line a failure, naming it, and the run exit 2", async () => {
    stub.state.mode = "ok";
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "eg-synthetic-2842-"));
    try {
      fs.symlinkSync(DIST, path.join(dir, "index.js"));
      const real = pathToFileURL(path.join(path.dirname(DIST), "requiredText.js")).href;
      fs.writeFileSync(
        path.join(dir, "requiredText.js"),
        `import * as real from ${JSON.stringify(real)};
export const CLIENT_DESCRIPTION_CUT = real.CLIENT_DESCRIPTION_CUT;
export const SHODAN_OWNERSHIP = real.SHODAN_OWNERSHIP;
export const REQUIRED_IN_INSTRUCTIONS = real.REQUIRED_IN_INSTRUCTIONS;
export const REQUIRED_IN_HEAD = { ...real.REQUIRED_IN_HEAD, get_cve: [...real.REQUIRED_IN_HEAD.get_cve, "a sentence no get_cve description holds"] };
`,
      );
      const r = await run(stub, { serverJs: path.join(dir, "index.js") });
      const cut = r.lines.filter((l) => l.message === TEXT_CUT_MESSAGE);
      assert.equal(cut.length, 2, JSON.stringify(cut));
      for (const l of cut) {
        assert.deepEqual([l.outcome, l.description_heads_ok, l.description_heads_missing, l.instructions_head_ok, l.description_heads_basis], ["failure", false, 1, true, "judged"], JSON.stringify(l));
        assert.equal(l.detail, "get_cve: a sentence no get_cve description holds");
      }
      for (const era of [MODERN, LEGACY]) for (const tool of PUBLISHED) assert.equal(r.of(tool, era).outcome, "success", `${tool} [${era}]`);
      assert.deepEqual([r.complete[0].text_cut_lines, r.complete[0].text_cut_failures, r.exitCode], [2, 2, 2]);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("the deliberate-failure canary: a forced tool name no version lists is a failure on both eras", async () => {
    const r = await run(stub, { force: ["canary_deliberate_failure"] });
    for (const era of [MODERN, LEGACY]) {
      const l = r.of("canary_deliberate_failure", era);
      assert.equal(l.outcome, "failure", JSON.stringify(l));
      assert.ok(["rpc_error", "is_error", "not_listed"].includes(l.reason), l.reason);
      for (const tool of PUBLISHED) assert.equal(r.of(tool, era).outcome, "success");
    }
    assert.equal(r.exitCode, 2);
  });

  it("a forced name that is not a tool-name shape is dropped, so it can never become a metric label", async () => {
    const r = await run(stub, { eras: [LEGACY], force: ["Bad Name; rm -rf", "x".repeat(65)] });
    assert.equal(r.probes.length, PUBLISHED.length + PLANNED.length);
  });

  it("a server that cannot start is a (session) failure for each era, not silence", async () => {
    const r = await run(stub, { serverJs: path.join(path.dirname(DIST), "does-not-exist.js") });
    for (const era of [MODERN, LEGACY]) {
      const l = r.of("(session)", era);
      assert.equal(l?.outcome, "failure", JSON.stringify(r.probes));
      assert.equal(l.step, "open");
    }
    assert.equal(r.complete.length, 1);
    assert.equal(r.exitCode, 2);
  });

  it("an install that fails is an (install) failure for each era, and the run still completes", async () => {
    const r = await runSynthetic({ serverJs: undefined, packageSpec: "not-our-package@1.0.0", apiBase: stub.base, write: () => {} });
    assert.equal(r.summary.failure, 2);
    assert.equal(r.exitCode, 2);
  });
});

describe("#2757: what check_sbom's probe must show", () => {
  it("201 distinct purls: one more than a batch, so two batches", () => {
    const purls = PROBES.check_sbom[0].purls;
    assert.equal(purls.length, 201);
    assert.equal(new Set(purls).size, 201, "a duplicate is sent once, and would leave one batch");
  });
  it("EXPECT holds batches_sent at least 2, and says what it saw otherwise", () => {
    const sc = (batches_sent, not_sent_reason = null) => sbomSc({ coverage: { batches_sent, not_sent_reason } });
    assert.equal(EXPECT.check_sbom(sc(2)), undefined);
    assert.equal(EXPECT.check_sbom(sc(1, "rate_limited")), 'coverage.batches_sent 1, want at least 2 (not_sent_reason "rate_limited")');
    assert.equal(EXPECT.check_sbom({}), "coverage.batches_sent null, want at least 2 (not_sent_reason null)");
  });
  it("judge applies it only to a result that is otherwise a success", () => {
    const tool = { name: "t", inputSchema: { type: "object" }, outputSchema: { type: "object" } };
    const expect = (sc) => (sc.ok ? undefined : "saw not ok");
    assert.deepEqual(judge({ structuredContent: { state: "measured", ok: true } }, tool, expect), { outcome: "success", state: "measured" });
    assert.deepEqual(judge({ structuredContent: { state: "measured" } }, tool, expect), { outcome: "failure", reason: "expectation_unmet", state: "measured", detail: "saw not ok" });
    assert.equal(judge({ isError: true, structuredContent: { state: "failed" } }, tool, expect).reason, "state_failed");
  });
});

// #2834, #2836: the two probe rows EXPECT.check_sbom reads, both polarities, each failure named.
describe("#2834, #2836: what check_sbom's probe rows must show", () => {
  // The same answer with one probe row changed by f (a copy).
  const withRow = (purl, f) => {
    const sc = sbomSc();
    sc.data.results = sc.data.results.map((r) => (r.purl === purl ? f(structuredClone(r)) : r));
    return sc;
  };
  const withMatch = (f) => withRow(LOG4J_CORE_PURL, (r) => ({ ...r, matches: r.matches.map(f) }));
  it("both probe purls are in the first batch of 200, so an answer missing the second batch still holds them", () => {
    for (const p of [LOG4J_CORE_PURL, UPSTREAM_PURL]) {
      const i = SBOM_PROBE_PURLS.indexOf(p);
      assert.ok(i >= 0 && i < 200, `${p} at ${i}`);
    }
    assert.equal(LOG4J_FIXED_IN, "2.15.0");
  });
  it("met: log4j-core 2.14.1's CVE-2021-44228 match carries fixed_in 2.15.0, and libcrypto3 is affected as openssl, by its upstream qualifier", () => {
    assert.equal(EXPECT.check_sbom(sbomSc()), undefined);
  });
  it("#2834 unmet, each named: fixed_in absent (core-backend without #2834), null (no interval on the exact-list path), the stored fixed_version's 2.3.1, no CVE-2021-44228 match, no row", () => {
    assert.equal(
      EXPECT.check_sbom(withMatch(({ fixed_in, ...m }) => m)),
      `${LOG4J_CORE_PURL} ${CVE} fixed_in absent (fixed_in_reason null, interval {"introduced":"2.13.0","fixed":"2.15.0"}); want "2.15.0"`,
    );
    assert.match(EXPECT.check_sbom(withMatch((m) => ({ ...m, fixed_in: null, fixed_in_reason: "no advisory interval holding it records a fixed version" }))), /fixed_in null \(fixed_in_reason "no advisory interval holding it records a fixed version", .*\); want "2\.15\.0"$/);
    assert.match(EXPECT.check_sbom(withMatch((m) => ({ ...m, fixed_in: "2.3.1" }))), /CVE-2021-44228 fixed_in "2\.3\.1" .*; want "2\.15\.0"$/);
    assert.equal(
      EXPECT.check_sbom(withRow(LOG4J_CORE_PURL, (r) => ({ ...r, verdict: "not_affected", matches: [], cve_ids: [] }))),
      `${LOG4J_CORE_PURL}: verdict "not_affected", no ${CVE} match (cve_ids [])`,
    );
    const gone = sbomSc();
    gone.data.results = gone.data.results.filter((r) => r.purl !== LOG4J_CORE_PURL);
    assert.equal(EXPECT.check_sbom(gone), `no row for ${LOG4J_CORE_PURL} among ${gone.data.results.length} results`);
    assert.equal(EXPECT.check_sbom({ coverage: { batches_sent: 2 }, data: {} }), "data.results absent; want a row per purl sent");
  });
  it("#2836 unmet, each named: the upstream qualifier ignored, matched under another name, or no longer affected", () => {
    assert.equal(
      EXPECT.check_sbom(sbomSc({}, new Set(["upstream"]))),
      `${UPSTREAM_PURL}: verdict "not_assessed", matched_via "purl_name", matched_package "libcrypto3" (not_assessed_reason "package_not_in_advisory_corpus"); want affected, upstream, openssl`,
    );
    assert.match(EXPECT.check_sbom(withRow(UPSTREAM_PURL, (r) => ({ ...r, matched_package: "libcrypto3" }))), /matched_package "libcrypto3" .*want affected, upstream, openssl$/);
    assert.match(EXPECT.check_sbom(withRow(UPSTREAM_PURL, (r) => ({ ...r, verdict: "not_affected", count: 0, matches: [] }))), /verdict "not_affected", matched_via "upstream", matched_package "openssl"/);
    const gone = sbomSc();
    gone.data.results = gone.data.results.filter((r) => r.purl !== UPSTREAM_PURL);
    assert.equal(EXPECT.check_sbom(gone), `no row for ${UPSTREAM_PURL} among ${gone.data.results.length} results`);
  });
  it("the batches are held first: a second batch unanswered is said as before, whatever the rows hold", () => {
    assert.equal(EXPECT.check_sbom(sbomSc({ coverage: { batches_sent: 1, not_sent_reason: "time_budget" } }, new Set(["upstream", "fixed_in"]))), 'coverage.batches_sent 1, want at least 2 (not_sent_reason "time_budget")');
  });
});

// #2839: EXPECT.get_cve, both polarities.
describe("#2839: what get_cve's probe must show", () => {
  it("the probe asks for CVE-2021-44228", () => assert.deepEqual(PROBES.get_cve, [{ cve_id: CVE }]));
  it("met: KEV-listed, with CISA's required action", () => {
    assert.equal(EXPECT.get_cve({ state: "measured", data: { kev_listed: true, kev_required_action: "Apply updates per vendor instructions." } }), undefined);
  });
  it("unmet, each named: no text, an empty text, a null, not KEV-listed", () => {
    assert.equal(EXPECT.get_cve({ data: { kev_listed: true } }), `data.kev_required_action absent; want CISA's text for ${CVE}`);
    assert.equal(EXPECT.get_cve({ data: { kev_listed: true, kev_required_action: "  " } }), `data.kev_required_action "  "; want CISA's text for ${CVE}`);
    assert.equal(EXPECT.get_cve({ data: { kev_listed: true, kev_required_action: null } }), `data.kev_required_action null; want CISA's text for ${CVE}`);
    assert.equal(EXPECT.get_cve({ data: { kev_listed: false, kev_required_action: "x" } }), `data.kev_listed false; want true for ${CVE}`);
    assert.equal(EXPECT.get_cve({}), `data.kev_listed null; want true for ${CVE}`);
  });
});

// #3276: EXPECT.cve_summary, both polarities. Where the answer carries nvd_poll, the fleet's last
// completed NVD poll (core-backend #3242), freshness.nvd_poll.last_run_at is its last_completed_at;
// where it carries none, freshness is null. 3.0.2 answered freshness null beside the block.
describe("#3276: what cve_summary's probe must show", () => {
  const POLL = { interval: "20m0s", last_completed_at: "2026-10-17T22:45:09Z", scope: "fleet" };
  const FRESH = { nvd_poll: { last_run_at: POLL.last_completed_at, scope: "fleet", interval: "20m0s" } };
  const sc = (freshness, nvd_poll) => ({ state: "measured", freshness, data: { summary: { total: 1 }, ...(nvd_poll === undefined ? {} : { nvd_poll }) } });
  it("the probe calls it with no arguments", () => assert.deepEqual(PROBES.cve_summary, [{}]));
  it("met: freshness.nvd_poll.last_run_at is data.nvd_poll.last_completed_at; with no block, or a null one, freshness is null", () => {
    assert.equal(EXPECT.cve_summary(sc(FRESH, POLL)), undefined);
    assert.equal(EXPECT.cve_summary(sc(null)), undefined);
    assert.equal(EXPECT.cve_summary(sc(null, null)), undefined);
  });
  it("unmet, each named: 3.0.2's freshness null beside the block, another time, a block without a time, a freshness with no block", () => {
    assert.equal(EXPECT.cve_summary(sc(null, POLL)), 'freshness.nvd_poll.last_run_at null, data.nvd_poll.last_completed_at "2026-10-17T22:45:09Z"; want them equal (freshness null)');
    const other = { nvd_poll: { ...FRESH.nvd_poll, last_run_at: "2026-10-17T22:25:09Z" } };
    assert.equal(EXPECT.cve_summary(sc(other, POLL)), `freshness.nvd_poll.last_run_at "2026-10-17T22:25:09Z", data.nvd_poll.last_completed_at "2026-10-17T22:45:09Z"; want them equal (freshness ${JSON.stringify(other)})`);
    assert.equal(EXPECT.cve_summary(sc(null, { scope: "fleet" })), "freshness.nvd_poll.last_run_at null, data.nvd_poll.last_completed_at null; want them equal (freshness null)");
    assert.equal(EXPECT.cve_summary(sc(FRESH)), `freshness ${JSON.stringify(FRESH)} with no data.nvd_poll; want null`);
  });
  it("judged as a probe line, 3.0.2's answer beside the block is expectation_unmet, and this package's is a success", () => {
    const tool = { name: "cve_summary", outputSchema: { type: "object" } };
    assert.deepEqual(judge({ structuredContent: sc(null, POLL) }, tool, EXPECT.cve_summary), {
      outcome: "failure",
      reason: "expectation_unmet",
      state: "measured",
      detail: 'freshness.nvd_poll.last_run_at null, data.nvd_poll.last_completed_at "2026-10-17T22:45:09Z"; want them equal (freshness null)',
    });
    assert.deepEqual(judge({ structuredContent: sc(FRESH, POLL) }, tool, EXPECT.cve_summary), { outcome: "success", state: "measured" });
  });
});

// #2842: judgeTextCut and loadRequiredText, both polarities, against what this package's dist
// serves and the registry it ships.
describe("#2842: what a client that cuts at 2,048 characters is handed", () => {
  let required, served;
  before(async () => {
    required = await loadRequiredText(DIST);
    const c = await connect({ era: LEGACY, command: process.execPath, args: [DIST], env: { ...process.env, ECHELONGRAPH_API_BASE: "http://127.0.0.1:9" }, stderr: "ignore" });
    try {
      served = { instructions: c.opening.instructions, tools: (await c.listTools()).tools };
    } finally {
      await c.close();
    }
  });
  const withDescription = (name, f) => ({ ...served, tools: served.tools.map((t) => (t.name === name ? { ...t, description: f(t.description) } : t)) });
  const pastCut = (text, sentence) => {
    assert.ok(text.includes(sentence), `re-aim this control: the text no longer holds ${sentence}`);
    return `${text.replace(sentence, "")} ${"x".repeat(2048)} ${sentence}`;
  };
  const KEV = "CISA's own text relayed verbatim (kev_required_action, not EchelonGraph's advice";

  it("loadRequiredText reads the package's registry from beside its server .js, and nothing where there is none, it is malformed or it does not load", async () => {
    assert.equal(required.CLIENT_DESCRIPTION_CUT, DEFAULT_CLIENT_CUT);
    assert.ok(required.REQUIRED_IN_HEAD.get_cve.includes(KEV));
    assert.ok(required.REQUIRED_IN_INSTRUCTIONS.length > 0);
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "eg-synthetic-required-"));
    try {
      const js = path.join(dir, "index.js");
      assert.equal(await loadRequiredText(js), undefined, "a release before #2842 ships no requiredText.js");
      fs.writeFileSync(path.join(dir, "requiredText.js"), "export const CLIENT_DESCRIPTION_CUT = '2048';\n");
      assert.equal(await loadRequiredText(js), undefined, "not the registry's shape");
      fs.writeFileSync(path.join(dir, "requiredText.js"), "throw new Error('does not load');\n");
      assert.equal(await loadRequiredText(js), undefined, "does not load");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
  it("met: this package's instructions and descriptions", () => {
    const j = judgeTextCut(served, required);
    assert.deepEqual(
      [j.outcome, j.instructions_chars, j.instructions_head_ok, j.description_heads_ok, j.description_heads_missing, j.tools_without_required_entry, j.descriptions_over_cut],
      ["success", served.instructions.length, true, true, 0, 0, 0],
    );
    assert.ok(j.instructions_chars <= 2048, `${j.instructions_chars}`);
    assert.equal(j.detail, undefined);
  });
  it("unmet: instructions one character past the cut (2,048 exactly is within it)", () => {
    const grown = (n) => ({ ...served, instructions: served.instructions + "y".repeat(n - served.instructions.length) });
    const j = judgeTextCut(grown(2049), required);
    assert.deepEqual([j.outcome, j.instructions_chars, j.instructions_head_ok, j.description_heads_ok], ["failure", 2049, true, true]);
    assert.equal(judgeTextCut(grown(2048), required).outcome, "success");
  });
  it("unmet: a required sentence moved past the cut, named in detail", () => {
    const j = judgeTextCut(withDescription("get_cve", (d) => pastCut(d, KEV)), required);
    assert.deepEqual([j.outcome, j.description_heads_ok, j.description_heads_missing, j.descriptions_over_cut, j.detail], ["failure", false, 1, 1, `get_cve: ${KEV}`]);
  });
  it("unmet: a head that names Shodan without its ownership sentence", () => {
    const j = judgeTextCut(withDescription("get_cwe", (d) => `Shodan aside: ${d}`), required);
    assert.deepEqual([j.outcome, j.description_heads_ok, j.detail], ["failure", false, "get_cwe: names Shodan without its ownership sentence"]);
  });
  it("unmet: the instructions' head without a REQUIRED_IN_INSTRUCTIONS sentence, or no instructions at all", () => {
    const s = required.REQUIRED_IN_INSTRUCTIONS.at(-1);
    const j = judgeTextCut({ ...served, instructions: served.instructions.replace(s, "") }, required);
    assert.deepEqual([j.outcome, j.instructions_head_ok, j.description_heads_ok, j.detail], ["failure", false, true, `instructions: ${s}`]);
    const none = judgeTextCut({ ...served, instructions: undefined }, required);
    assert.deepEqual([none.outcome, none.instructions_chars, none.instructions_head_ok, none.detail], ["failure", null, false, "instructions: none served"]);
  });
  it("a listed tool with no registry entry is counted, not failed: a hosted release may list a tool the npm one does not", () => {
    const j = judgeTextCut({ ...served, tools: [...served.tools, { name: "brand_new_tool", description: "New." }] }, required);
    assert.deepEqual([j.outcome, j.tools_without_required_entry, j.tools_listed], ["success", 1, served.tools.length + 1]);
  });
  it("without a registry only the lengths are measured: the head checks are null, and instructions past the cut still fail", () => {
    const j = judgeTextCut(withDescription("get_cve", (d) => pastCut(d, KEV)), undefined);
    assert.deepEqual([j.outcome, j.cut, j.instructions_head_ok, j.description_heads_ok, j.description_heads_missing, j.descriptions_over_cut], ["success", 2048, null, null, null, 1]);
    assert.equal(judgeTextCut({ ...served, instructions: "y".repeat(2049) }, undefined).outcome, "failure");
  });
  it("neutralisation: with a cut of 1e9 the moved sentence and long instructions pass, so the cut is what fails them", () => {
    const open = { ...required, CLIENT_DESCRIPTION_CUT: 1e9 };
    assert.equal(judgeTextCut(withDescription("get_cve", (d) => pastCut(d, KEV)), open).outcome, "success");
    assert.equal(judgeTextCut({ ...served, instructions: served.instructions + "y".repeat(3000) }, open).outcome, "success");
  });
});

describe("#2817: what cve_intel's probe must show", () => {
  const row = (fixed_branches, extra = {}) => ({ state: "measured", data: { affected_packages: [{ ecosystem: "Maven", package_name: LOG4J_CORE, fixed_version: "2.12.2", ...(fixed_branches === undefined ? {} : { fixed_branches }), ...extra }] } });
  const GHSA = "GHSA-jfh8-c2jp-5v3q";
  const R = (introduced, fixed, advisory_id = GHSA) => ({ introduced, fixed, last_affected: null, source: advisory_id ? "osv_bulk" : null, advisory_id });
  it("the probe asks for CVE-2021-44228", () => assert.deepEqual(PROBES.cve_intel, [{ cve_id: "CVE-2021-44228" }]));
  // #2835: EXPECT.scan_manifest, both polarities, and the probe's document as the tool reads it.
  it("scan_manifest: the probe is one package-lock past 64 KiB, read as 400 entries and 20 distinct purls; EXPECT holds the read, the sending and an affected component", async () => {
    const { readFiles } = await import(pathToFileURL(path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "tools", "scan_manifest.js")).href);
    const [args] = PROBES.scan_manifest;
    assert.equal(args.files.length, 1);
    assert.ok(args.files[0].content.length > 64 * 1024, `${args.files[0].content.length}`);
    const x = readFiles(args);
    assert.deepEqual([x.read_purls, x.purls.length, x.not_checked.length], [400, 20, 0]);
    assert.equal(x.purls[0], "pkg:npm/lodash@4.17.15");
    const sc = (files_read, entries_pinned, distinct_purls, not_sent, affected) => ({ coverage: { files_read, entries_pinned, distinct_purls, not_sent, not_sent_reason: not_sent ? "rate_limited" : null }, data: { summary: { affected } } });
    assert.equal(EXPECT.scan_manifest(sc(1, 400, 20, 0, 1)), undefined);
    assert.equal(EXPECT.scan_manifest(sc(0, 0, 0, 0, 1)), "coverage.files_read 0, entries_pinned 0, distinct_purls 0; want 1, 400, 20");
    assert.equal(EXPECT.scan_manifest(sc(1, 400, 20, 20, 0)), 'coverage.not_sent 20 (not_sent_reason "rate_limited"); want 0');
    assert.equal(EXPECT.scan_manifest(sc(1, 400, 20, 0, 0)), "data.summary.affected 0; want at least 1 (lodash 4.17.15)");
  });
  // #2841: EXPECT.cve_remediation, both polarities.
  it("cve_remediation: the probe asks for CVE-2021-44228; EXPECT holds CISA's text and every row's remediation_state", () => {
    assert.deepEqual(PROBES.cve_remediation, [{ cve_id: "CVE-2021-44228" }]);
    const ok = { data: { cisa: { required_action: "Apply updates." }, vendor_remediations: [{ remediation_state: "parsed" }, { remediation_state: "not_parsed" }] } };
    assert.equal(EXPECT.cve_remediation(ok), undefined);
    assert.equal(EXPECT.cve_remediation({ data: { cisa: { required_action: null }, vendor_remediations: [] } }), "data.cisa.required_action null; want CISA's text for CVE-2021-44228");
    assert.equal(EXPECT.cve_remediation({ data: { cisa: { required_action: "x" }, vendor_remediations: [{ remediation_state: "parsed" }, {}] } }), "1 of 2 vendor_remediations rows carry no remediation_state");
    assert.equal(EXPECT.cve_remediation({ data: { cisa: { required_action: "x" }, failed_sections: ["vendor_remediations"] } }), 'data.vendor_remediations absent (failed_sections ["vendor_remediations"])');
  });
  it("holds log4j-core's three ranges, one fixed in 2.15.0", () => {
    assert.equal(EXPECT.cve_intel(row([R("2.13.0", "2.15.0"), R("2.0-beta9", "2.3.1"), R("2.4", "2.12.2")])), undefined);
  });
  it("ranges loaded before the OSV backfill rerun (advisory_id null or absent) are met: the rerun is founder-timed, 4c checks it", () => {
    assert.equal(EXPECT.cve_intel(row([R("2.0-beta9", "2.3.1", null), R("2.4", "2.12.2", null), R("2.13.0", "2.15.0", null)])), undefined);
    assert.equal(EXPECT.cve_intel(row([{ introduced: "2.0-beta9", fixed: "2.3.1" }, { introduced: "2.4", fixed: "2.12.2" }, { introduced: "2.13.0", fixed: "2.15.0" }])), undefined);
  });
  it("two ranges, one of them fixed in 2.15.0, are too few", () => {
    assert.equal(
      EXPECT.cve_intel(row([R("2.13.0", "2.15.0"), R("2.4", "2.12.2")])),
      `${LOG4J_CORE} fixed_branches has 2 ranges, fixes ["2.15.0","2.12.2"]; want at least 3, one fixed in 2.15.0`,
    );
  });
  it("three ranges with none fixed in 2.15.0 are unmet", () => {
    assert.match(EXPECT.cve_intel(row([R("2.0-beta9", "2.3.1"), R("2.4", "2.12.2"), R("2.13.0", "2.16.0")])), /has 3 ranges, fixes \["2.3.1","2.12.2","2.16.0"\]/);
  });
  it("says what it saw otherwise: production before #2817, a row never loaded, too few ranges, the row gone", () => {
    assert.equal(EXPECT.cve_intel(row(undefined)), `${LOG4J_CORE} fixed_branches absent (fixed_version "2.12.2"); want at least 3 ranges, one fixed in 2.15.0`);
    assert.equal(EXPECT.cve_intel(row(null)), `${LOG4J_CORE} fixed_branches null (fixed_version "2.12.2"); want at least 3 ranges, one fixed in 2.15.0`);
    assert.equal(EXPECT.cve_intel(row([R("2.4", "2.12.2")])), `${LOG4J_CORE} fixed_branches has 1 ranges, fixes ["2.12.2"]; want at least 3, one fixed in 2.15.0`);
    assert.equal(EXPECT.cve_intel({ data: { affected_packages: [] } }), `no Maven ${LOG4J_CORE} row among 0 affected_packages rows`);
    assert.equal(EXPECT.cve_intel({ data: {} }), `data.affected_packages absent; want the ${LOG4J_CORE} row with fixed_branches`);
  });
});

describe("#2774: what the hosted leg's check_sbom probe sends, and must show", () => {
  const SBOM = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "tools", "check_sbom.js");
  const POLICY = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "httpPolicy.js");
  it("a CycloneDX document of exactly the 201 purls the stdio legs send, so the API budget is unchanged", async () => {
    const { extract } = await import(pathToFileURL(SBOM).href);
    assert.deepEqual(HTTP_PROBES.check_sbom, [{ sbom: SBOM_PROBE_DOCUMENT }]);
    const x = extract({ sbom: SBOM_PROBE_DOCUMENT });
    assert.deepEqual([x.input, x.components_in_document, x.without_purl, x.duplicates_removed], ["cyclonedx", 201, 0, 0]);
    assert.deepEqual(x.purls, SBOM_PROBE_PURLS);
    assert.deepEqual(PROBES.check_sbom, [{ purls: SBOM_PROBE_PURLS }], "the stdio legs' input changed");
  });
  it("as a request body, past the general 64 KiB cap on both eras and far inside the large one", async () => {
    const P = await import(pathToFileURL(POLICY).href);
    const { modernMeta } = await import("../test/mcp-http-client.mjs");
    const params = { name: "check_sbom", arguments: HTTP_PROBES.check_sbom[0] };
    for (const p of [params, { ...params, _meta: modernMeta() }]) {
      const bytes = Buffer.byteLength(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: p }));
      assert.ok(bytes > 2 * P.DEFAULT_MAX_BODY_BYTES && bytes < 200_000, `${bytes} bytes`);
      assert.ok(bytes < P.DEFAULT_MAX_SBOM_BODY_BYTES);
    }
  });
  it("HTTP_EXPECT holds measured, read from the document (cyclonedx, 201 components), and then EXPECT's two batches", () => {
    const sc = (state, input, components_in_document, batches_sent) => sbomSc({ state, coverage: { input, components_in_document, batches_sent, not_sent_reason: null } });
    assert.equal(HTTP_EXPECT.check_sbom(sc("measured", "cyclonedx", 201, 2)), undefined);
    assert.equal(HTTP_EXPECT.check_sbom(sc("measured", "purls", null, 2)), 'state "measured", coverage.input "purls", components_in_document null; want measured, cyclonedx, 201');
    assert.equal(HTTP_EXPECT.check_sbom(sc("not_assessed", "cyclonedx", 201, 2)), 'state "not_assessed", coverage.input "cyclonedx", components_in_document 201; want measured, cyclonedx, 201');
    assert.equal(HTTP_EXPECT.check_sbom(sc("measured", "cyclonedx", 201, 1)), EXPECT.check_sbom(sc("measured", "cyclonedx", 201, 1)));
    assert.notEqual(EXPECT.check_sbom(sc("measured", "cyclonedx", 201, 1)), undefined);
  });
  it("the hosted leg chooses it; the stdio legs keep the purl list", () => {
    const tool = { inputSchema: { type: "object", properties: { purls: { type: "array", items: { type: "string" } }, sbom: { anyOf: [{ type: "string" }, { type: "object" }] } } } };
    assert.deepEqual(chooseInput("check_sbom", tool, {}, { ...PROBES, ...HTTP_PROBES }), { args: { sbom: SBOM_PROBE_DOCUMENT }, index: 0 });
    assert.deepEqual(chooseInput("check_sbom", tool, {}), { args: { purls: SBOM_PROBE_PURLS }, index: 0 });
  });
});

// #3135: VERDICT_PROBES, each expect both polarities, against the stub's production-shaped answers and
// the rule before each fix.
describe("#3135: what the matcher-verdict probes must show", () => {
  const sc = (label, regressed = []) => {
    const p = VERDICT_PROBES.find((v) => v.label === label);
    const a = p.arguments;
    const key = a.product ? `|${a.product}|${a.version}` : `${a.ecosystem}|${a.package}|${a.version}`;
    return { state: "measured", data: VERDICT_ANSWERS[key](new Set(regressed)) };
  };
  const expectOf = (label) => VERDICT_PROBES.find((v) => v.label === label).expect;
  const [MAYAN, P13, P2, MALI, LOG4J] = VERDICT_LABELS;

  it("VERDICT_PROBES is a list of check_affected calls under the five pinned labels, with the arguments verified live", () => {
    assert.ok(Array.isArray(VERDICT_PROBES), `probes.mjs exports no VERDICT_PROBES list (it is ${typeof VERDICT_PROBES})`);
    assert.deepEqual(VERDICT_PROBES.map((v) => v.label), VERDICT_LABELS);
    assert.deepEqual(VERDICT_PROBES.map((v) => [v.tool, v.arguments]), [
      ["check_affected", { ecosystem: "PyPI", package: "mayan-edms", version: "4.9.0" }],
      ["check_affected", { ecosystem: "Packagist", package: MAGENTO, version: "2.4.4-p13" }],
      ["check_affected", { ecosystem: "Packagist", package: MAGENTO, version: "2.4.5-p2" }],
      ["check_affected", { product: "midgard_gpu_kernel_driver", version: "r20p0" }],
      ["check_affected", { ecosystem: "Maven", package: "org.apache.logging.log4j:log4j-core", version: "2.14.1" }],
    ]);
    for (const v of VERDICT_PROBES) assert.equal(typeof v.expect, "function", v.label);
    assert.equal(probeTable.LOG4J_VERDICT_LABEL, LOG4J);
  });
  it("met: production's answers as the fixed rules give them (#3074, #3101, #3131)", () => {
    for (const label of VERDICT_LABELS) assert.equal(expectOf(label)(sc(label)), undefined, label);
  });
  it("#3074 unmet: the per-range rule's fixed_in 4.9.7, a version the same record still holds affected", () => {
    assert.equal(
      expectOf(MAYAN)(sc(MAYAN, ["fixed_in_rule"])),
      `PyPI mayan-edms 4.9.0 ${MAYAN_CVE} fixed_in "4.9.7", fixed_in_detail null (interval {"introduced":"4.9.0","fixed":"4.9.7"}, fixed_in_reason null); want a version above 4.9.7 with fixed_in_detail (#3074)`,
    );
  });
  it("#3135: the mayan probe wants fixed_in above the holding range's 4.9.7 with a detail, not 4.10.2 exactly", () => {
    const s = sc(MAYAN);
    const m = s.data.matches[0];
    const withFix = (fixed_in, extra = {}) => ({ ...s, data: { ...s.data, matches: [{ ...m, fixed_in, ...extra }] } });
    assert.equal(probeTable.MAYAN_HOLDING_FIXED, "4.9.7");
    // A later advisory overlapping [0, 4.10.2) moves the walk past it: no regression, so no page.
    for (const later of ["4.10.2", "4.10.3", "4.11", "5.0.0", "4.9.8", "4.9.7.1"]) assert.equal(expectOf(MAYAN)(withFix(later)), undefined, later);
    // At or below the holding bound, or no version it can order, is unmet.
    for (const bad of ["4.9.7", "4.9.7.0", "4.9.6", "4.9.0", "", "unknown", null]) {
      assert.match(expectOf(MAYAN)(withFix(bad)), /; want a version above 4\.9\.7 with fixed_in_detail \(#3074\)$/, String(bad));
    }
    assert.match(expectOf(MAYAN)({ ...s, data: { ...s.data, matches: [(({ fixed_in, ...rest }) => rest)(m)] } }), /fixed_in absent, /);
  });
  it("#3135: releaseAbove orders the dotted numeric release and refuses what has none", () => {
    const { releaseAbove } = probeTable;
    assert.equal(typeof releaseAbove, "function", "probes.mjs exports no releaseAbove");
    assert.deepEqual(
      [["4.10.2", "4.9.7"], ["4.9.10", "4.9.7"], ["4.9.7", "4.9.7"], ["4.9.7.0", "4.9.7"], ["4.9.7", "4.10.2"], ["v5", "4.9.7"], ["4.9.7.post1", "4.9.7"], ["x", "4.9.7"], [undefined, "4.9.7"]].map(([a, b]) => releaseAbove(a, b)),
      [true, true, false, false, false, true, false, undefined, undefined],
    );
  });
  it("#3074 unmet, each named: 4.10.2 without its detail, the match cut from matches, no match, not assessed", () => {
    const s = sc(MAYAN);
    const m = s.data.matches[0];
    const without = { ...s, data: { ...s.data, matches: [{ ...m, fixed_in_detail: "  " }] } };
    assert.match(expectOf(MAYAN)(without), /fixed_in "4\.10\.2", fixed_in_detail " {2}" .*want a version above 4\.9\.7 with fixed_in_detail/);
    assert.match(expectOf(MAYAN)({ ...s, data: { ...s.data, matches: [] } }), /CVE-2025-14692 is in cve_ids but not in matches/);
    assert.match(expectOf(MAYAN)({ ...s, data: { ...s.data, matches: [], cve_ids: [] } }), /^PyPI mayan-edms 4\.9\.0: CVE-2025-14692 not matched \(assessed true/);
    assert.match(expectOf(MAYAN)({ state: "not_assessed", data: { assessed: false, not_assessed_reason: "package_not_in_advisory_corpus" } }), /not assessed \(assessed false, .*not_assessed_reason "package_not_in_advisory_corpus"\); want CVE-2025-14692 matched$/);
  });
  it("#3101 unmet: text order matches CosmicSting to 2.4.4-p13 and misses SessionReaper at 2.4.5-p2", () => {
    assert.equal(
      expectOf(P13)(sc(P13, ["comparator"])),
      `Packagist ${MAGENTO} 2.4.4-p13: ${COSMICSTING_CVE} matched (fixed_in "2.4.4-p9", interval {"introduced":"0","fixed":"2.4.4-p9"}); want it not affected`,
    );
    assert.match(expectOf(P2)(sc(P2, ["comparator"])), new RegExp(`^Packagist ${MAGENTO} 2\\.4\\.5-p2: ${SESSIONREAPER_CVE} not matched \\(assessed true, match_layer "registry", count 1, .*\\); want it matched$`));
  });
  it("#3101: an absence is read only from an answer that looked at everything; undetermined is not 'not affected'", () => {
    const s = sc(P13);
    for (const [over, why] of [[{ assessed: false }, "assessed false"], [{ capped: true }, "capped true"], [{ candidates_capped: true }, "candidates_capped true"], [{ degraded: true }, "degraded true"]]) {
      assert.match(expectOf(P13)({ ...s, data: { ...s.data, ...over } }), new RegExp(`did not look at every candidate \\(.*${why.replace(" ", " ")}.*\\), so ${COSMICSTING_CVE}'s absence is not a finding$`), why);
    }
    const und = { ...s, data: { ...s.data, undetermined_count: 1, undetermined: [{ cve_id: COSMICSTING_CVE, reason: "version_undecidable" }] } };
    assert.equal(expectOf(P13)(und), `Packagist ${MAGENTO} 2.4.4-p13: ${COSMICSTING_CVE} undetermined ("version_undecidable"); want it not affected`);
    // Matched, though cut from matches: cve_ids names every match.
    const cut = { ...s, data: { ...s.data, cve_ids: [...s.data.cve_ids, COSMICSTING_CVE] } };
    assert.match(expectOf(P13)(cut), /CVE-2024-34102 matched \(fixed_in null, interval null\); want it not affected$/);
  });
  it("#3101: a presence is read from cve_ids too, which names every match when matches is cut", () => {
    const s = sc(P2);
    assert.equal(expectOf(P2)({ ...s, data: { ...s.data, matches: s.data.matches.slice(0, 1) } }), undefined);
  });
  it("#3135: the Mali probe is a separate VERDICT_PROBES entry, held back (not called) only while its label is in EXPECT_PENDING, and called since #3131 was deployed", () => {
    // Called as shipped since c0f58d5d, the table empty; held back, it names only the Mali probe. Either way nothing else is ever pending.
    assert.deepEqual({ ...EXPECT_PENDING }, MALI_PENDING ? { [MALI_LABEL]: MALI_PENDING_REASON } : {}, "EXPECT_PENDING names only the Mali probe, with its reason, or nothing once it is enabled");
    assert.equal(MALI, MALI_LABEL);
    assert.equal(probeTable.MALI_LABEL, MALI_LABEL);
    for (const l of VERDICT_LABELS.filter((x) => x !== MALI_LABEL)) assert.equal(EXPECT_PENDING[l], undefined, `${l} must never be pending`);
  });
  // #2834: the GET route's fixed_in for log4j-core 2.14.1, both polarities, each unmet shape named.
  it("#2834 met: log4j-core 2.14.1's CVE-2021-44228 match carries fixed_in 2.15.0 on GET /cves/match", () => {
    assert.equal(expectOf(LOG4J)(sc(LOG4J)), undefined);
    // Never pending: the answer has been production's since #2834 reached it (2026-10-11).
    assert.equal(EXPECT_PENDING[LOG4J], undefined);
  });
  it("#2834 unmet: fixed_in null on the exact-list path, the stored fixed_version's 2.3.1, absent, the match cut, no match", () => {
    assert.equal(
      expectOf(LOG4J)(sc(LOG4J, ["fixed_in_exact_list"])),
      `Maven log4j-core 2.14.1 ${CVE} fixed_in null (fixed_in_reason "the version is listed verbatim in the advisory's affected versions, and no advisory interval holding it records a fixed version", interval null, version_evidence "exact_version_list"); want "2.15.0" (#2834)`,
    );
    assert.match(expectOf(LOG4J)(sc(LOG4J, ["fixed_in_stored"])), /fixed_in "2\.3\.1" \(fixed_in_reason null, interval \{"introduced":"2\.13\.0","fixed":"2\.15\.0"\}, version_evidence "exact_version_list"\); want "2\.15\.0" \(#2834\)$/);
    const s = sc(LOG4J);
    const [m, ...rest] = s.data.matches;
    assert.match(expectOf(LOG4J)({ ...s, data: { ...s.data, matches: [(({ fixed_in, ...x }) => x)(m), ...rest] } }), /fixed_in absent \(/);
    assert.match(expectOf(LOG4J)({ ...s, data: { ...s.data, matches: rest } }), /CVE-2021-44228 is in cve_ids but not in matches/);
    assert.match(expectOf(LOG4J)({ ...s, data: { ...s.data, matches: rest, cve_ids: rest.map((x) => x.cve_id) } }), /^Maven log4j-core 2\.14\.1: CVE-2021-44228 not matched \(assessed true/);
    assert.match(expectOf(LOG4J)({ state: "not_assessed", data: { assessed: false, not_assessed_reason: "package_not_in_advisory_corpus" } }), /not assessed .*want CVE-2021-44228 matched$/);
  });
  it("#3131 unmet: r20p0 outside [r4p0, r31p0] — production's answer until #3131 was deployed", () => {
    assert.match(expectOf(MALI)(sc(MALI, ["cpe_comparator"])), /^midgard_gpu_kernel_driver r20p0: CVE-2022-38181 not matched \(assessed true, match_layer "cpe", count 1, capped false, candidates_capped false, degraded null, not_assessed_reason null\); want it matched$/);
    assert.equal(MALI_CVE, "CVE-2022-38181");
  });
});

describe("judging one result", () => {
  const schema = {
    type: "object",
    oneOf: [
      { type: "object", properties: { state: { enum: ["measured", "not_assessed"] }, data: { type: "object" } }, required: ["state", "data"] },
      { type: "object", properties: { state: { enum: ["failed", "invalid_input"] }, error: { type: "string" } }, required: ["state", "error"] },
    ],
  };
  const tool = { name: "t", inputSchema: { type: "object" }, outputSchema: schema };
  it("measured and not_assessed are successes", () => {
    assert.equal(judge({ structuredContent: { state: "measured", data: {} } }, tool).outcome, "success");
    assert.equal(judge({ structuredContent: { state: "not_assessed", data: {} } }, tool).outcome, "success");
  });
  it("isError, failed, a schema refusal, no structuredContent and no outputSchema are failures, each named", () => {
    assert.deepEqual(judge({ isError: true, structuredContent: { state: "failed", error: "x" } }, tool), { outcome: "failure", reason: "state_failed", state: "failed" });
    assert.equal(judge({ isError: true, content: [] }, tool).reason, "is_error");
    assert.equal(judge({ structuredContent: { state: "failed", error: "x" } }, tool).reason, "state_failed_without_is_error");
    assert.equal(judge({ structuredContent: { state: "measured" } }, tool).reason, "schema_invalid");
    assert.equal(judge({ structuredContent: { state: "measured_zero", data: {} } }, tool).reason, "schema_invalid");
    assert.equal(judge({ content: [] }, tool).reason, "no_structured_content");
    assert.equal(judge({ structuredContent: { state: "measured", data: {} } }, { ...tool, outputSchema: undefined }).reason, "no_output_schema");
    assert.equal(judge({ structuredContent: { state: "measured", data: {} } }, undefined).reason, "not_listed");
  });
});

describe("the probe table picks up new tools", () => {
  it("names every published tool", () => {
    for (const t of PUBLISHED) assert.ok(PROBES[t], `${t} has no probe entry`);
  });
  it("sends only a candidate that fits the advertised inputSchema", () => {
    const strict = (props, required) => ({ type: "object", properties: props, required, additionalProperties: false });
    const byPackage = { inputSchema: strict({ ecosystem: { type: "string" }, package: { type: "string" }, version: { type: "string" } }, ["ecosystem", "package", "version"]) };
    assert.deepEqual(chooseInput("check_affected", byPackage, {}), { args: PROBES.check_affected[0], index: 0 });
    const byProduct = { inputSchema: strict({ product: { type: "string" }, vendor: { type: "string" }, version: { type: "string" } }, ["product", "version"]) };
    assert.deepEqual(chooseInput("check_affected", byProduct, {}), { args: PROBES.check_affected[1], index: 1 });
    const neither = { inputSchema: strict({ cpe: { type: "string" } }, ["cpe"]) };
    assert.deepEqual(chooseInput("check_affected", neither, {}), { reason: "no_valid_probe_input" });
  });
  it("calls a listed tool with no entry with {} when it needs no argument, and fails it when it does", () => {
    assert.deepEqual(chooseInput("brand_new_tool", { inputSchema: { type: "object", properties: { limit: { type: "integer" } } } }, {}), { args: {}, index: -1 });
    assert.deepEqual(chooseInput("brand_new_tool", { inputSchema: { type: "object", properties: { id: { type: "string" } }, required: ["id"] } }, {}), { reason: "no_probe_input" });
  });
  it("get_vendor_advisory takes its vendor and the vendor's advisory ID from vendor_advisories_for_cve's answer, and runs after it", () => {
    const schema = { type: "object", properties: { vendor: { type: "string" }, advisory_id: { type: "string" } }, required: ["vendor", "advisory_id"], additionalProperties: false };
    // A row's advisory_id is EchelonGraph's internal id; the detail route takes vendor_advisory_id.
    const seen = { vendor_advisories_for_cve: { state: "measured", data: { advisories: [{ advisory_id: "6f1c7d2e-0000-4000-8000-000000000001", vendor: "redhat", vendor_advisory_id: "RHSA-2021:5128" }] } } };
    assert.deepEqual(chooseInput("get_vendor_advisory", { inputSchema: schema }, seen).args, { vendor: "redhat", advisory_id: "RHSA-2021:5128" });
    assert.deepEqual(chooseInput("get_vendor_advisory", { inputSchema: schema }, {}), { reason: "no_valid_probe_input" });
    const order = probeOrder(["get_vendor_advisory", "vendor_advisories_for_cve", "cve_summary"]);
    assert.ok(order.indexOf("get_vendor_advisory") > order.indexOf("vendor_advisories_for_cve"));
    assert.equal(order[0], "vendor_advisories_for_cve", "listed order is kept otherwise");
  });
});

// #3011: the chaining mistake, made on purpose: get_vendor_advisory given a row's advisory_id (the
// internal UUID), judged as #3011 specifies, and only where the endpoint advertises that fix.
describe("#3011: the chain probe", () => {
  const CHAIN_PROBES = probeTable.CHAIN_PROBES;
  const judgeChain = runner.judgeChain;
  const UUID = "a68d033b-5d1e-4537-8190-5e37897a27e8";
  const SEEN = { vendor_advisories_for_cve: { state: "measured", data: { advisories: [{ advisory_id: UUID, vendor: "paloalto", vendor_advisory_id: "CVE-2024-3400" }] } } };
  // get_vendor_advisory as tools/list gives it: 3.0.2's inputSchema, and #3011's.
  const OUTPUT = {
    oneOf: [
      { type: "object", properties: { state: { enum: ["measured", "not_assessed"] }, data: { type: "object" } }, required: ["state"] },
      { type: "object", properties: { state: { enum: ["failed", "invalid_input"] }, error: { type: "object" } }, required: ["state", "error"] },
    ],
  };
  const toolWith = (description) => ({
    name: "get_vendor_advisory",
    inputSchema: { type: "object", properties: { vendor: { type: "string" }, advisory_id: { type: "string", description } }, required: ["vendor", "advisory_id"] },
    outputSchema: OUTPUT,
  });
  const OLD = toolWith("the vendor's advisory ID, e.g. RHSA-2024:1234 or GHSA-xxxx-xxxx-xxxx");
  const NEW = toolWith("the vendor's own advisory ID, a row's vendor_advisory_id, e.g. RHSA-2024:1234; not a row's advisory_id, EchelonGraph's internal UUID");
  const probe = () => CHAIN_PROBES[0];
  const ARGS = { vendor: "paloalto", advisory_id: UUID };
  const refusal = (message, kind = "invalid_input") => ({ content: [{ type: "text", text: "get_vendor_advisory FAILED (state: invalid_input)" }], isError: true, structuredContent: { state: "invalid_input", error: { kind, path: null, status: 404, message } } });

  it("CHAIN_PROBES is one get_vendor_advisory call under its pinned label, its arguments the first row's vendor and advisory_id (the UUID)", () => {
    assert.ok(Array.isArray(CHAIN_PROBES), `probes.mjs exports no CHAIN_PROBES list (it is ${typeof CHAIN_PROBES})`);
    assert.deepEqual(CHAIN_PROBES.map((c) => [c.label, c.tool]), [[CHAIN_LABELS[0], "get_vendor_advisory"]]);
    assert.deepEqual(probe().arguments(SEEN), ARGS);
    assert.deepEqual(chooseInput("get_vendor_advisory", NEW, SEEN, { get_vendor_advisory: [probe().arguments] }).args, ARGS);
    // No row with a UUID advisory_id (or no answer): nothing to send, no_valid_probe_input.
    assert.equal(probe().arguments({ vendor_advisories_for_cve: { data: { advisories: [{ vendor: "paloalto", vendor_advisory_id: "CVE-2024-3400" }] } } }), undefined);
    assert.deepEqual(chooseInput("get_vendor_advisory", NEW, {}, { get_vendor_advisory: [probe().arguments] }), { reason: "no_valid_probe_input" });
  });

  it("published: 3.0.2's inputSchema is not the fix, #3011's is", () => {
    assert.equal(probe().published(OLD), false);
    assert.equal(probe().published(NEW), true);
    assert.equal(probe().published(undefined), false);
  });

  it("judged: invalid_input naming vendor_advisory_id passes; the advisory itself passes; failed (the 404 as no record) fails; a refusal that names no field fails", () => {
    assert.deepEqual(judgeChain(refusal(`advisory_id ${UUID} has the shape of a row's advisory_id; pass the row's vendor_advisory_id as advisory_id`), NEW, probe(), ARGS), { outcome: "success", state: "invalid_input" });
    const measured = { content: [{ type: "text", text: "{}" }], structuredContent: { state: "measured", data: { advisory_id: UUID, vendor_advisory_id: "CVE-2024-3400" } } };
    assert.deepEqual(judgeChain(measured, NEW, probe(), ARGS), { outcome: "success", state: "measured" });
    // 3.0.2's answer to the same call (live 2026-10-10).
    const failed = { content: [{ type: "text", text: "get_vendor_advisory FAILED: EchelonGraph answered HTTP 404 ... The API returned no record for this request" }], isError: true, structuredContent: { state: "failed", error: { kind: "http", path: `/api/v1/public/vendor-advisories/paloalto/${UUID}`, status: 404, message: "advisory not found" } } };
    assert.deepEqual(judgeChain(failed, NEW, probe(), ARGS), { outcome: "failure", reason: "state_failed", state: "failed" });
    const vague = judgeChain(refusal("vendor must be a vendor slug"), NEW, probe(), ARGS);
    assert.deepEqual([vague.outcome, vague.reason], ["failure", "expectation_unmet"]);
    const other = judgeChain({ ...measured, structuredContent: { state: "measured", data: { advisory_id: "6f1c7d2e-0000-4000-8000-000000000009" } } }, NEW, probe(), ARGS);
    assert.deepEqual([other.outcome, other.reason], ["failure", "expectation_unmet"]);
    // A refusal the outputSchema does not accept is not the specified one.
    const bare = judgeChain({ content: [], isError: true, structuredContent: { state: "invalid_input" } }, NEW, probe(), ARGS);
    assert.deepEqual([bare.outcome, bare.reason], ["failure", "schema_invalid"]);
  });

  it("in a session: not_published on an endpoint without the fix (no call made), failure on one that answers failed, success on one that refuses as specified", async () => {
    const session = (tool, answer) => {
      const calls = [];
      const client = {
        getServerVersion: () => ({ name: "echelongraph-mcp", version: "0.0.0-test" }),
        listTools: async () => ({ tools: [{ name: "vendor_advisories_for_cve", inputSchema: { type: "object", properties: { cve_id: { type: "string" } } }, outputSchema: OUTPUT }, tool] }),
        callTool: async ({ name, arguments: args }) => {
          calls.push({ name, args });
          return name === "vendor_advisories_for_cve" ? { content: [], structuredContent: SEEN.vendor_advisories_for_cve } : answer;
        },
        listPrompts: async () => ({ prompts: [] }),
        listResources: async () => ({ resources: [] }),
        close: async () => {},
      };
      return { client, calls };
    };
    const lineOf = async (s) => {
      const lines = [];
      await probeSession({ era: MODERN, open: async () => s.client, force: [], emit: (l) => lines.push(l), extras: true, probes: { vendor_advisories_for_cve: [{ cve_id: "CVE-2024-3400" }], get_vendor_advisory: [{ vendor: "paloalto", advisory_id: "CVE-2024-3400" }] }, expect: {} });
      const of = lines.filter((l) => l.tool === CHAIN_LABELS[0]);
      assert.equal(of.length, 1, JSON.stringify(lines));
      return of[0];
    };
    const old = session(OLD, refusal("unused"));
    assert.equal((await lineOf(old)).outcome, "not_published");
    assert.ok(!old.calls.some((c) => c.name === "get_vendor_advisory" && c.args.advisory_id === UUID), "an endpoint without the fix was sent the UUID");
    const failing = session(NEW, { content: [], isError: true, structuredContent: { state: "failed", error: { kind: "http", path: null, status: 404, message: "advisory not found" } } });
    assert.deepEqual([(await lineOf(failing)).outcome, (await lineOf(failing)).reason], ["failure", "state_failed"]);
    const fixed = session(NEW, refusal("pass the row's vendor_advisory_id as advisory_id"));
    const l = await lineOf(fixed);
    assert.deepEqual([l.outcome, l.state], ["success", "invalid_input"], JSON.stringify(l));
    assert.ok(fixed.calls.some((c) => c.name === "get_vendor_advisory" && c.args.advisory_id === UUID && c.args.vendor === "paloalto"));
  });
});

describe("the forwarder", () => {
  let stub, fwd;
  before(async () => {
    stub = await startStub();
    stub.state.mode = "echo";
    fwd = await startForwarder({ upstream: stub.base, token: UA_TOKEN });
  });
  after(async () => {
    await fwd.close();
    await stub.close();
  });
  it("prefixes the token to a user-agent that lacks it, and passes one that leads with it", () => {
    assert.deepEqual(identify("echelongraph-mcp/2.3.4 (+https://echelongraph.io/pulse/mcp)", UA_TOKEN), {
      ua: "echelongraph-mcp-synthetic/1.0 echelongraph-mcp/2.3.4 (+https://echelongraph.io/pulse/mcp)",
      identified: false,
    });
    const own = "echelongraph-mcp-synthetic/1.0 echelongraph-mcp/2.4.0 (+https://echelongraph.io/pulse/mcp)";
    assert.deepEqual(identify(own, UA_TOKEN), { ua: own, identified: true });
    assert.deepEqual(identify(undefined, UA_TOKEN), { ua: UA_TOKEN, identified: false });
    // A family that merely starts with the token's letters is not the token.
    assert.equal(identify("echelongraph-mcp-synthetic2/1", UA_TOKEN).identified, false);
  });
  it("relays method, path, query, X-EG-* headers, body, status and answer headers unchanged", async () => {
    const res = await fetch(`${fwd.base}/api/v1/public/cves/match/batch?x=1`, {
      method: "POST",
      headers: { "user-agent": "echelongraph-mcp/2.3.4", "x-eg-product": "log4j", "content-type": "application/json" },
      body: JSON.stringify({ purls: ["pkg:npm/lodash@4.17.20"] }),
    });
    assert.equal(res.status, 201);
    assert.equal(res.headers.get("x-eg-echo"), "log4j");
    assert.deepEqual(await res.json(), { method: "POST", url: "/api/v1/public/cves/match/batch?x=1", body: JSON.stringify({ purls: ["pkg:npm/lodash@4.17.20"] }) });
    const sent = stub.state.seen.at(-1);
    assert.equal(sent.headers["x-eg-product"], "log4j");
    assert.equal(sent.headers["user-agent"], "echelongraph-mcp-synthetic/1.0 echelongraph-mcp/2.3.4");
  });
  it("an unreachable upstream is a 502 the package reports as a failed lookup", async () => {
    const dead = await startForwarder({ upstream: "http://127.0.0.1:1", token: UA_TOKEN });
    try {
      const res = await fetch(`${dead.base}/api/v1/public/cves/summary`);
      assert.equal(res.status, 502);
      assert.equal(dead.stats.upstream_errors, 1);
    } finally {
      await dead.close();
    }
  });
});

// ── #2737: the hosted leg, against this package's own dist/http.js on 127.0.0.1 ──────────────
// The endpoint is started the way test/http.test.mjs starts it (an ephemeral port, the stub API
// behind it, a forward token for the stub's host) and the synthetic is pointed at it with
// remoteUrl. What must hold: both eras, every tool judged against the outputSchema the ENDPOINT
// advertises, a prompts/get per prompt probe (triage_cve and, #2846, workload_triage) and one
// resources/read, every line labelled transport "http", the
// endpoint's API calls filed under the synthetic's family, and a broken endpoint or API read as
// failure, never as silence or success.
const HTTP_ENTRY = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "http.js");

async function startHttpEntry(apiBase, extraEnv = {}, entry = HTTP_ENTRY) {
  const env = {
    ...process.env,
    PORT: "0",
    ECHELONGRAPH_API_BASE: apiBase,
    ECHELONGRAPH_API_TIMEOUT_MS: "5000",
    ECHELONGRAPH_FORWARD_TOKEN: "forward-token-for-tests-2737",
    ECHELONGRAPH_FORWARD_HOST: "127.0.0.1",
    MCP_RATE_LIMIT_PER_MIN: "1000",
    ...extraEnv,
  };
  const proc = spawn(process.execPath, [entry], { env, stdio: ["ignore", "pipe", "pipe"] });
  const lines = [];
  let stderr = "";
  proc.stderr.setEncoding("utf8").on("data", (d) => (stderr += d));
  const exited = new Promise((resolve) => proc.once("exit", (code) => resolve(code)));
  const port = await new Promise((resolve, reject) => {
    let buf = "";
    const timer = setTimeout(() => reject(new Error(`http.js did not start: ${stderr}`)), 15_000);
    proc.stdout.setEncoding("utf8").on("data", (d) => {
      buf += d;
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 1);
        lines.push(line);
        try {
          const j = JSON.parse(line);
          if (j.message === "mcp_remote_listening") {
            clearTimeout(timer);
            resolve(j.port);
          }
        } catch {
          // not JSON: kept
        }
      }
    });
    exited.then((code) => {
      clearTimeout(timer);
      reject(new Error(`http.js exited ${code} before listening: ${stderr}`));
    });
  });
  return {
    url: `http://127.0.0.1:${port}/mcp`,
    lines,
    async stop() {
      proc.kill("SIGTERM");
      const t = setTimeout(() => proc.kill("SIGKILL"), 5000);
      await exited;
      clearTimeout(t);
    },
  };
}

// The prompt probes' labels, pinned here, not read from probes.mjs: each is a metric label
// (mcp_tool_probe_total{tool}), so one renamed ends its series and one dropped is no longer
// measured (#2846: workload_triage beside triage_cve). PROMPT_PROBES is read off the module rather
// than imported by name, so a probes.mjs without it fails the tests that read it, each by name,
// instead of failing this whole file at import.
const PROMPT_LABELS = ["prompt:triage_cve", "prompt:workload_triage"];
const PROMPT_PROBES = probeTable.PROMPT_PROBES;
// #3011: the chaining-mistake probe's label, pinned for the same reason (a metric label).
const CHAIN_LABELS = ["chain:get_vendor_advisory@row.advisory_id"];
// #3135: the matcher-verdict lines come first, after the tools and before the prompts; a pending one
// writes none. #3011: the chain probe's after them.
const EXTRAS = [...activeVerdicts(), ...CHAIN_LABELS, ...PROMPT_LABELS, RESOURCE_PROBE.label];

describe("#2737: the hosted leg over Streamable HTTP", () => {
  let stub, srv;
  before(async () => {
    stub = await startStub();
    srv = await startHttpEntry(stub.base);
  });
  after(async () => {
    await srv?.stop();
    await stub?.close();
  });
  const runHttp = (opts = {}) => run(stub, { stdio: false, remoteUrl: srv.url, ...opts });

  describe("a healthy endpoint, run beside the stdio leg", () => {
    let r;
    before(async () => {
      stub.state.mode = "ok";
      stub.state.userAgents.length = 0;
      stub.state.seen.length = 0;
      r = await run(stub, { remoteUrl: srv.url });
    });
    it("#3135: the Mali verdict follows EXPECT_PENDING: pending, it writes no line on either era, so it cannot page; enabled, one http line per era, and it passes", () => {
      const mali = r.probes.filter((l) => l.tool === MALI_LABEL);
      if (MALI_PENDING) assert.equal(mali.length, 0, JSON.stringify(mali));
      else {
        assert.deepEqual(mali.map((l) => [l.transport, l.era, l.outcome]).sort(), [[HTTP, LEGACY, "success"], [HTTP, MODERN, "success"]].sort(), JSON.stringify(mali));
      }
      assert.equal(r.exitCode, 0);
    });
    it("every published tool, the active matcher verdicts (#3135), both prompts and the resource succeed on both eras over http", () => {
      for (const era of [MODERN, LEGACY]) {
        for (const tool of [...PUBLISHED, ...EXTRAS]) {
          const l = r.probes.find((p) => p.transport === HTTP && p.tool === tool && p.era === era);
          assert.ok(l, `${tool} [${era}] http: no line`);
          assert.equal(l.outcome, "success", `${tool} [${era}] http: ${JSON.stringify(l)}`);
          assert.ok(Number.isInteger(l.latency_ms) && l.latency_ms >= 0);
        }
      }
      assert.equal(r.exitCode, 0);
    });
    it("tools are judged against the endpoint's outputSchema: each http tool line carries the state it validated", () => {
      for (const tool of PUBLISHED) {
        const l = r.probes.find((p) => p.transport === HTTP && p.tool === tool && p.era === MODERN);
        assert.ok(["measured", "not_assessed"].includes(l.state), `${tool}: ${l.state}`);
      }
    });
    it("every line names its transport; the stdio leg is unchanged and no (tool, era, transport) repeats", () => {
      for (const l of r.probes) assert.ok([STDIO, HTTP].includes(l.transport), JSON.stringify(l));
      const keys = r.probes.map((l) => `${l.tool}|${l.era}|${l.transport}`);
      assert.equal(new Set(keys).size, keys.length, "a (tool, era, transport) reported twice");
      const stdio = r.probes.filter((l) => l.transport === STDIO);
      assert.equal(stdio.length, 2 * PUBLISHED.length);
      assert.ok(stdio.every((l) => !EXTRAS.includes(l.tool)), "the verdict, prompt and resource probes are the hosted leg's");
      const http = r.probes.filter((l) => l.transport === HTTP);
      for (const x of [...EXTRAS, DRIFT_TOOL]) assert.equal(http.filter((l) => l.tool === x).length, 2, `${x}: want one http line per era`);
      // #3097: one (hosted-vs-npm) line per era beside the probes.
      assert.equal(http.length, 2 * (PUBLISHED.length + EXTRAS.length) + 2);
      const c = r.complete[0];
      assert.deepEqual(c.transports, [STDIO, HTTP]);
      assert.deepEqual([c.success, c.failure], [2 * PUBLISHED.length + 2 * (PUBLISHED.length + EXTRAS.length) + 2, 0]);
    });
    it("#3097: on the npm package's version the endpoint's catalog is compared with it, era by era, and is the same: every tool, prompt and resource", async () => {
      const { PKG } = await import("../test/server-under-test.mjs");
      const drift = r.probes.filter((l) => l.tool === DRIFT_TOOL);
      assert.deepEqual(drift.map((l) => [l.transport, l.era, l.outcome]), [[HTTP, MODERN, "success"], [HTTP, LEGACY, "success"]], JSON.stringify(drift));
      for (const l of drift) {
        assert.deepEqual([l.package_version, l.npm_version, l.reason, l.detail, l.uncompared], [PKG.version, PKG.version, undefined, undefined, undefined], JSON.stringify(l));
        assert.equal(l.compared_tools, PUBLISHED.length, JSON.stringify(l));
        assert.ok(l.compared_prompts >= 2 && l.compared_resources >= 1, `control: the prompts and the resource were compared: ${JSON.stringify(l)}`);
        assert.equal(l.latency_ms, undefined, "not a tools/call: no latency for the latency metric");
      }
      assert.equal(r.complete[0].hosted_vs_npm, "identical");
    });
    it("an http line carries the version the endpoint reports in its handshake", async () => {
      const { PKG } = await import("../test/server-under-test.mjs");
      for (const l of r.probes.filter((p) => p.transport === HTTP)) assert.equal(l.package_version, PKG.version);
      assert.equal(r.complete[0].remote_version, PKG.version);
    });
    it("#2842: a client-cut line per era on each transport; the endpoint, on the npm package's version, is judged by its registry", async () => {
      const { PKG } = await import("../test/server-under-test.mjs");
      const cut = r.lines.filter((l) => l.message === TEXT_CUT_MESSAGE);
      assert.deepEqual(cut.map((l) => `${l.transport} ${l.era}`), [`${STDIO} ${MODERN}`, `${STDIO} ${LEGACY}`, `${HTTP} ${MODERN}`, `${HTTP} ${LEGACY}`]);
      for (const l of cut) {
        assert.deepEqual([l.outcome, l.description_heads_ok, l.instructions_head_ok, l.description_heads_basis, l.required_version, l.package_version], ["success", true, true, "judged", PKG.version, PKG.version], JSON.stringify(l));
        assert.ok(l.instructions_chars > 0 && l.instructions_chars <= 2048);
      }
      assert.equal(new Set(cut.map((l) => l.instructions_chars)).size, 1, "the same instructions on both transports and eras");
      assert.deepEqual([r.complete[0].text_cut_lines, r.complete[0].text_cut_failures], [4, 0]);
    });
    it("the endpoint's API calls for the synthetic carry the synthetic's family, never plain echelongraph-mcp", () => {
      assert.ok(stub.state.userAgents.length >= 4 * PUBLISHED.length, "control: both legs reached the API");
      for (const ua of stub.state.userAgents) assert.equal(uaFamilyOf(ua), "echelongraph-mcp-synthetic", ua);
    });
    it("the endpoint's access log files the synthetic under its own family", () => {
      const access = srv.lines.map((l) => JSON.parse(l)).filter((j) => j.message === "mcp_request" && j.path === "/mcp");
      assert.ok(access.length > 0);
      for (const a of access) {
        assert.equal(a.ua_family, "echelongraph-mcp-synthetic");
        assert.equal(typeof a.client_public, "boolean");
      }
    });
    it("#2774: the hosted check_sbom probe is a body past 64 KiB on each era, served 200 and read as the document", () => {
      const sbom = srv.lines.map((l) => JSON.parse(l)).filter((j) => j.message === "mcp_request" && j.tool === "check_sbom");
      assert.equal(sbom.length, 2, JSON.stringify(sbom));
      for (const a of sbom) {
        assert.ok(a.body_bytes > 64 * 1024, `a ${a.body_bytes}-byte body: under the general cap`);
        assert.equal(a.status, 200);
      }
      for (const era of [MODERN, LEGACY]) {
        const l = r.probes.find((p) => p.transport === HTTP && p.tool === "check_sbom" && p.era === era);
        assert.deepEqual([l.outcome, l.state, l.input], ["success", "measured", 0], JSON.stringify(l));
      }
    });
    it("#2835: the hosted scan_manifest probe is a body past 64 KiB on each era, served 200, and measured", () => {
      const lines = srv.lines.map((l) => JSON.parse(l)).filter((j) => j.message === "mcp_request" && j.tool === "scan_manifest");
      assert.equal(lines.length, 2, JSON.stringify(lines));
      for (const a of lines) {
        assert.ok(a.body_bytes > 64 * 1024, `a ${a.body_bytes}-byte body: under the general cap`);
        assert.equal(a.status, 200);
      }
      for (const era of [MODERN, LEGACY]) {
        const l = r.probes.find((p) => p.transport === HTTP && p.tool === "scan_manifest" && p.era === era);
        assert.deepEqual([l.outcome, l.state, l.input], ["success", "measured", 0], JSON.stringify(l));
      }
      // The endpoint's lines hold nothing from the file.
      for (const line of srv.lines) assert.ok(!line.includes("node_modules/") && !line.includes("minimist"), `a log line carries the lockfile: ${line.slice(0, 300)}`);
    });
  });

  // #2835: scan_manifest's probe is past 64 KiB too, so the canary refuses it as well.
  const LARGE = ["check_sbom", "scan_manifest"];
  it("#2774: on a canary copy whose large-body cap is 64 KiB (MCP_MAX_SBOM_BODY_BYTES=65536), the hosted check_sbom and scan_manifest probes fail, rpc_error -32600, and nothing else does", async () => {
    stub.state.mode = "ok";
    const canary = await startHttpEntry(stub.base, { MCP_MAX_SBOM_BODY_BYTES: "65536" });
    try {
      const r = await run(stub, { stdio: false, remoteUrl: canary.url });
      for (const era of [MODERN, LEGACY]) {
        for (const tool of LARGE) {
          const l = r.of(tool, era);
          assert.equal(l.transport, HTTP);
          assert.deepEqual([l.outcome, l.reason, l.rpc_code], ["failure", "rpc_error", -32600], `${tool}: ${JSON.stringify(l)}`);
        }
        for (const tool of [...PUBLISHED.filter((t) => !LARGE.includes(t)), ...EXTRAS]) assert.equal(r.of(tool, era)?.outcome, "success", `${tool} [${era}]: ${JSON.stringify(r.of(tool, era) ?? "no line")}`);
      }
      assert.equal(r.exitCode, 2);
      const refused = canary.lines.map((l) => JSON.parse(l)).filter((j) => j.message === "mcp_request" && j.status === 413);
      assert.equal(refused.length, 2 * LARGE.length, "the endpoint logged each refusal");
      for (const a of refused) assert.equal(a.refused, "body_size");
    } finally {
      await canary.stop();
    }
  });

  // #2842: an endpoint on another version than the npm package is not held to the npm release's
  // sentences (a wording change between them would read as a failure); its lengths still are.
  it("#2842: an endpoint on another version than the npm package: heads not judged (version_mismatch), instructions measured; hosted only: no registry", async () => {
    stub.state.mode = "ok";
    const r = await run(stub, { remoteUrl: srv.url, version: "0.0.0-mismatch" });
    const cut = r.lines.filter((l) => l.message === TEXT_CUT_MESSAGE);
    for (const l of cut.filter((x) => x.transport === STDIO)) assert.deepEqual([l.description_heads_basis, l.description_heads_ok, l.required_version], ["judged", true, "0.0.0-mismatch"]);
    const http = cut.filter((x) => x.transport === HTTP);
    assert.equal(http.length, 2);
    for (const l of http) {
      assert.deepEqual([l.outcome, l.description_heads_basis, l.description_heads_ok, l.instructions_head_ok, l.required_version], ["success", "version_mismatch", null, null, "0.0.0-mismatch"], JSON.stringify(l));
      assert.ok(l.instructions_chars > 0 && l.instructions_chars <= 2048);
    }
    const alone = (await runHttp({ eras: [LEGACY] })).lines.filter((l) => l.message === TEXT_CUT_MESSAGE);
    assert.deepEqual(alone.map((l) => [l.transport, l.description_heads_basis, l.description_heads_ok, l.required_version]), [[HTTP, "no_required_text", null, null]]);
  });

  it("the hosted leg alone: every API call the endpoint made for it leads with the synthetic's fixed token", async () => {
    stub.state.mode = "ok";
    const before = stub.state.seen.length;
    const r = await runHttp({ eras: [LEGACY] });
    assert.equal(r.exitCode, 0);
    const calls = stub.state.seen.slice(before);
    assert.ok(calls.length >= PUBLISHED.length, `control: the endpoint called the API (${calls.length})`);
    for (const s of calls) assert.match(s.headers["user-agent"], /^echelongraph-mcp-synthetic\/1\.0 echelongraph-mcp\/\S+ \(\+https:\/\/echelongraph\.io\/pulse\/mcp\)$/);
  });

  it("a hosted client that is NOT the synthetic reaches the API under the endpoint's own user-agent; a claimed family adds only the fixed token", async () => {
    stub.state.mode = "ok";
    const before = stub.state.seen.length;
    const r = await modern(srv.url, "tools/call", { name: "cve_summary", arguments: {} }, { headers: { "User-Agent": "SomeAgent/1.0" } });
    assert.equal(r.status, 200, r.text);
    const calls = stub.state.seen.slice(before);
    assert.equal(calls.length, 1);
    assert.equal(uaFamilyOf(calls[0].headers["user-agent"]), "echelongraph-mcp");
    // Nothing the client wrote reaches the API's user-agent: only the fixed token is ever added.
    const spoof = await modern(srv.url, "tools/call", { name: "cve_summary", arguments: {} }, { headers: { "User-Agent": "echelongraph-mcp-synthetic/9.9 injected-text" } });
    assert.equal(spoof.status, 200);
    const sent = stub.state.seen.at(-1).headers["user-agent"];
    assert.match(sent, /^echelongraph-mcp-synthetic\/1\.0 echelongraph-mcp\//);
    assert.ok(!sent.includes("injected") && !sent.includes("9.9"), sent);
  });

  it("an API answering 500 fails every published tool and every matcher verdict (#3135) over http with state_failed; the prompts and the resource make no API call and still pass", async () => {
    stub.state.mode = "500";
    const r = await runHttp();
    stub.state.mode = "ok";
    for (const era of [MODERN, LEGACY]) {
      for (const tool of PUBLISHED) {
        const l = r.of(tool, era);
        assert.equal(l.transport, HTTP);
        assert.equal(l.outcome, "failure", `${tool} [${era}]`);
        assert.equal(l.reason, AFTER[tool] ? "no_valid_probe_input" : "state_failed", `${tool} [${era}]: ${JSON.stringify(l)}`);
      }
      // A verdict is a check_affected call: the API's 500 fails it as it fails the tool's own probe.
      for (const x of activeVerdicts()) assert.deepEqual([r.of(x, era)?.outcome, r.of(x, era)?.reason], ["failure", "state_failed"], `${x} [${era}]: ${JSON.stringify(r.of(x, era) ?? "no line")}`);
      if (MALI_PENDING) assert.equal(r.of(MALI_LABEL, era), undefined, "a pending verdict is never called");
      // #3011: the chain probe reads vendor_advisories_for_cve's answer, which failed: like get_vendor_advisory's own probe.
      for (const x of CHAIN_LABELS) assert.deepEqual([r.of(x, era)?.outcome, r.of(x, era)?.reason], ["failure", "no_valid_probe_input"], `${x} [${era}]: ${JSON.stringify(r.of(x, era) ?? "no line")}`);
      for (const x of EXTRAS.filter((e) => !VERDICT_LABELS.includes(e) && !CHAIN_LABELS.includes(e))) assert.equal(r.of(x, era)?.outcome, "success", `${x} [${era}]: ${JSON.stringify(r.of(x, era) ?? "no line")}`);
    }
    assert.equal(r.exitCode, 2);
    assert.deepEqual(r.complete[0].transports, [HTTP]);
  });

  // #3135: each rule before its fix, answered by the API, fails its own verdicts and nothing else:
  // the answers fit check_affected's outputSchema, so only the expect can tell them apart.
  // The cpe_comparator case runs with the Mali probe enabled (its entry out of EXPECT_PENDING), as it
  // has been since #3131 was deployed.
  for (const [regression, failing, saw] of [
    ["fixed_in_rule", [VERDICT_LABELS[0]], /CVE-2025-14692 fixed_in "4\.9\.7", fixed_in_detail null .*want a version above 4\.9\.7 with fixed_in_detail \(#3074\)$/],
    ["comparator", [VERDICT_LABELS[1], VERDICT_LABELS[2]], /CVE-2024-34102 matched \(fixed_in "2\.4\.4-p9".*want it not affected$|CVE-2025-54236 not matched .*want it matched$/],
    ["cpe_comparator", [VERDICT_LABELS[3]], /midgard_gpu_kernel_driver r20p0: CVE-2022-38181 not matched \(assessed true, match_layer "cpe", count 1,.*want it matched$/],
    ["fixed_in_exact_list", [VERDICT_LABELS[4]], /^Maven log4j-core 2\.14\.1 CVE-2021-44228 fixed_in null \(fixed_in_reason "the version is listed verbatim.*; want "2\.15\.0" \(#2834\)$/],
  ]) {
    it(`#3135: an API with the ${regression} regression fails ${failing.join(" and ")} over http, expectation_unmet, and nothing else`, async () => {
      stub.state.mode = "ok";
      stub.state.regressed = new Set([regression]);
      let r;
      try {
        r = regression === "cpe_comparator" ? await withPendingEnabled(MALI_LABEL, () => runHttp({ eras: [LEGACY] })) : await runHttp({ eras: [LEGACY] });
      } finally {
        stub.state.regressed = new Set();
      }
      for (const label of failing) {
        const l = r.of(label, LEGACY);
        assert.deepEqual([l?.outcome, l?.reason, l?.state, l?.transport], ["failure", "expectation_unmet", "measured", HTTP], JSON.stringify(l ?? "no line"));
        assert.match(l.detail, saw, l.detail);
      }
      for (const x of [...PUBLISHED, ...EXTRAS.filter((e) => !failing.includes(e))]) assert.equal(r.of(x, LEGACY)?.outcome, "success", `${x}: ${JSON.stringify(r.of(x, LEGACY) ?? "no line")}`);
      assert.equal(r.exitCode, 2);
    });
  }

  // Production's answer before #3131 (the cpe_comparator regression), with the Mali probe pending:
  // no Mali line, nothing pages. Run pending whatever probes.mjs says, and again as it says, so the
  // state in force is the one judged: pending pages nothing, enabled fails expectation_unmet.
  const preCpe = async () => {
    stub.state.mode = "ok";
    stub.state.regressed = new Set(["cpe_comparator"]);
    try {
      return await runHttp({ eras: [LEGACY] });
    } finally {
      stub.state.regressed = new Set();
    }
  };
  it("#3135: pending, production's answer before #3131 (the cpe_comparator regression) writes no Mali line and pages nothing", async () => {
    const r = await withPendingAs(MALI_LABEL, MALI_PENDING_REASON, preCpe);
    assert.equal(r.of(MALI_LABEL, LEGACY), undefined, JSON.stringify(r.of(MALI_LABEL, LEGACY)));
    assert.equal(r.exitCode, 0, JSON.stringify(r.probes.filter((l) => l.outcome !== "success")));
    assert.equal(Boolean(EXPECT_PENDING[MALI_LABEL]), MALI_PENDING, "probes.mjs's own state is put back");
  });
  it(`#3135: as probes.mjs ships it (Mali ${MALI_PENDING ? "pending" : "enabled"}), production's answer before #3131 ${MALI_PENDING ? "writes no Mali line and pages nothing" : "fails the Mali line, expectation_unmet"}`, async () => {
    const r = await preCpe();
    const l = r.of(MALI_LABEL, LEGACY);
    if (MALI_PENDING) {
      assert.equal(l, undefined, JSON.stringify(l));
      assert.equal(r.exitCode, 0, JSON.stringify(r.probes.filter((x) => x.outcome !== "success")));
    } else {
      assert.deepEqual([l?.outcome, l?.reason], ["failure", "expectation_unmet"], JSON.stringify(l ?? "no line"));
      assert.equal(r.exitCode, 2);
    }
  });

  it("#3135: enabled (its EXPECT_PENDING entry deleted), the Mali verdict is called on both eras and passes on #3131's answer", async () => {
    stub.state.mode = "ok";
    const r = await withPendingEnabled(MALI_LABEL, () => runHttp());
    for (const era of [MODERN, LEGACY]) assert.equal(r.of(MALI_LABEL, era)?.outcome, "success", `${era}: ${JSON.stringify(r.of(MALI_LABEL, era) ?? "no line")}`);
    assert.equal(Boolean(EXPECT_PENDING[MALI_LABEL]), MALI_PENDING, "probes.mjs's own state is put back");
  });

  it("the deliberate-failure canary fails over http on both eras too", async () => {
    stub.state.mode = "ok";
    const r = await runHttp({ force: ["canary_deliberate_failure"] });
    for (const era of [MODERN, LEGACY]) {
      const l = r.of("canary_deliberate_failure", era);
      assert.equal(l.transport, HTTP);
      assert.equal(l.outcome, "failure", JSON.stringify(l));
      for (const tool of PUBLISHED) assert.equal(r.of(tool, era).outcome, "success");
    }
    assert.equal(r.exitCode, 2);
  });

  it("an endpoint that is down is a (session) failure per era over http, and the run completes", async () => {
    const dead = http.createServer();
    await new Promise((resolve) => dead.listen(0, "127.0.0.1", resolve));
    const url = `http://127.0.0.1:${dead.address().port}/mcp`;
    await new Promise((resolve) => dead.close(resolve));
    const r = await run(stub, { stdio: false, remoteUrl: url });
    for (const era of [MODERN, LEGACY]) {
      const l = r.of("(session)", era);
      assert.equal(l?.outcome, "failure", JSON.stringify(r.probes));
      assert.equal(l.transport, HTTP);
      assert.equal(l.step, "open");
    }
    assert.equal(r.complete.length, 1);
    assert.equal(r.exitCode, 2);
  });

  it("an endpoint answering a platform error page is reason http_status with the status", async () => {
    const broken = http.createServer((req, res) => {
      res.writeHead(503, { "content-type": "text/html" });
      res.end("<html>Service Unavailable</html>");
    });
    await new Promise((resolve) => broken.listen(0, "127.0.0.1", resolve));
    try {
      const r = await run(stub, { stdio: false, remoteUrl: `http://127.0.0.1:${broken.address().port}/mcp` });
      for (const era of [MODERN, LEGACY]) {
        const l = r.of("(session)", era);
        assert.equal(l.reason, "http_status", JSON.stringify(l));
        assert.equal(l.http_status, 503);
      }
      assert.equal(r.exitCode, 2);
    } finally {
      broken.closeAllConnections();
      await new Promise((resolve) => broken.close(resolve));
    }
  });

  it("refuses a remote URL that is not https (or loopback http) before sending anything", async () => {
    assert.equal(remoteUrlAllowed("https://mcp.echelongraph.io/mcp"), true);
    assert.equal(remoteUrlAllowed("http://127.0.0.1:8080/mcp"), true);
    assert.equal(remoteUrlAllowed("http://mcp.echelongraph.io/mcp"), false);
    assert.equal(remoteUrlAllowed("https://user:pw@mcp.echelongraph.io/mcp"), false);
    assert.equal(remoteUrlAllowed("not a url"), false);
    await assert.rejects(runSynthetic({ stdio: false, remoteUrl: "http://example.com/mcp", write: () => {} }), /refusing the remote URL/);
  });
});

describe("#2737: judging a prompt and a resource", () => {
  const text = (t, role = "user") => ({ role, content: { type: "text", text: t } });
  it("a prompt must answer messages whose text names the CVE that was sent", () => {
    assert.deepEqual(judgePrompt({ messages: [text("Triage CVE-2021-44228 using these tools")] }, "CVE-2021-44228"), { outcome: "success" });
    assert.equal(judgePrompt({ messages: [text("Triage the CVE using these tools")] }, "CVE-2021-44228").reason, "prompt_argument_not_applied");
    assert.equal(judgePrompt({ messages: [] }, "CVE-2021-44228").reason, "prompt_no_messages");
    assert.equal(judgePrompt({}, "CVE-2021-44228").reason, "prompt_no_messages");
    assert.equal(judgePrompt({ messages: [{ role: "system", content: { type: "text", text: "CVE-2021-44228" } }] }, "CVE-2021-44228").reason, "prompt_invalid_message");
  });
  it("#2846: workload_triage's answer must name check_sbom: a text that does not is prompt_tool_not_named, a blank one prompt_empty", () => {
    const wt = PROMPT_PROBES?.find?.((p) => p.name === "workload_triage");
    assert.ok(wt, "probes.mjs PROMPT_PROBES has no workload_triage entry");
    assert.deepEqual(judgePrompt({ messages: [text("4. Call check_sbom with purls set to one image's purls")] }, wt.expect, wt.unmet), { outcome: "success" });
    // In any message, by either role.
    assert.deepEqual(judgePrompt({ messages: [text("Triage your workloads."), text("Then call check_sbom.", "assistant")] }, wt.expect, wt.unmet), { outcome: "success" });
    const miss = judgePrompt({ messages: [text("Rank your workloads by CISA-KEV listing, then exposure.")] }, wt.expect, wt.unmet);
    assert.deepEqual([miss.outcome, miss.reason], ["failure", "prompt_tool_not_named"], JSON.stringify(miss));
    assert.match(miss.detail, /check_sbom/);
    for (const blank of ["", "  \n "]) assert.equal(judgePrompt({ messages: [text(blank)] }, wt.expect, wt.unmet).reason, "prompt_empty", JSON.stringify(blank));
    // A message with no text block at all is empty too, not "names no check_sbom".
    assert.equal(judgePrompt({ messages: [{ role: "user", content: { type: "image", data: "", mimeType: "image/png" } }] }, wt.expect, wt.unmet).reason, "prompt_empty");
    // triage_cve keeps its own reason, and a blank answer is prompt_empty for it as well.
    assert.equal(judgePrompt({ messages: [text("")] }, CVE).reason, "prompt_empty");
    // An empty expect would match any text ("".includes("")): refused, never a success.
    assert.equal(judgePrompt({ messages: [text("anything")] }, "", wt.unmet).reason, "prompt_probe_without_expect");
  });
  it("a resource must answer an entry for the URI read, with a non-empty text", () => {
    const uri = RESOURCE_PROBE.uri;
    assert.deepEqual(judgeResource({ contents: [{ uri, mimeType: "text/markdown", text: "# How" }] }, uri), { outcome: "success" });
    assert.equal(judgeResource({ contents: [{ uri: "echelongraph://other", text: "x" }] }, uri).reason, "resource_uri_missing");
    assert.equal(judgeResource({ contents: [{ uri, text: "  " }] }, uri).reason, "resource_empty");
    assert.equal(judgeResource({ contents: [] }, uri).reason, "resource_no_contents");
  });
});

// ── #2846: the prompt probes are a list, each its own line per era ───────────────────────────
// probeSession run against a session object that lists no tools (every PROBES tool reads
// not_published) and the prompts a case gives, so what an endpoint answers for each prompt is the
// case's own: the real endpoint's answers are held in the hosted-leg tests above. Only the
// prompt:* and resource:* lines are read.
describe("#2846: every prompt probe is its own line per era", () => {
  const TRIAGE = "prompt:triage_cve";
  const WORKLOAD = "prompt:workload_triage";
  // What each prompt says by default: text naming what its probe expects.
  const SAYS = {
    triage_cve: (args) => `Triage ${args?.cve_id}: call get_cve, cve_intel and cve_remediation.`,
    workload_triage: (args) => `List the workloads (${args?.source}), make an SBOM of each digest, then call check_sbom with its purls.`,
  };
  function session({ prompts = ["triage_cve", "workload_triage"], says = SAYS, listFails = false, version = "0.0.0-test" } = {}) {
    const calls = { list: 0, get: [] };
    const client = {
      getServerVersion: () => ({ name: "echelongraph-mcp", version }),
      listTools: async () => ({ tools: [] }),
      listPrompts: async () => {
        calls.list += 1;
        if (listFails) throw new Error("no answer within 10 ms");
        return { prompts: prompts.map((name) => ({ name })) };
      },
      getPrompt: async ({ name, arguments: args }) => {
        calls.get.push({ name, args });
        return { messages: [{ role: "user", content: { type: "text", text: says[name](args) } }] };
      },
      listResources: async () => ({ resources: [{ uri: RESOURCE_PROBE.uri }] }),
      readResource: async ({ uri }) => ({ contents: [{ uri, mimeType: "text/markdown", text: "# How EchelonGraph measures" }] }),
      close: async () => {},
    };
    return { client, calls };
  }
  async function probe(s, more = {}) {
    const lines = [];
    await probeSession({ era: MODERN, open: async () => s.client, force: [], emit: (l) => lines.push(l), extras: true, ...more });
    const extras = lines.filter((l) => l.tool.startsWith("prompt:") || l.tool.startsWith("resource:"));
    const one = (label) => {
      const of = extras.filter((l) => l.tool === label);
      assert.equal(of.length, 1, `${label}: ${of.length} lines, want 1: ${JSON.stringify(extras)}`);
      return of[0];
    };
    return { extras, one, lines };
  }

  it("PROMPT_PROBES is a list: triage_cve exactly as it was, then workload_triage with source kubernetes, expecting check_sbom", () => {
    assert.ok(Array.isArray(PROMPT_PROBES), `probes.mjs exports no PROMPT_PROBES list (it is ${typeof PROMPT_PROBES})`);
    assert.deepEqual(PROMPT_PROBES.map((p) => p.label), PROMPT_LABELS);
    assert.deepEqual(PROMPT_PROBES[0], { label: TRIAGE, name: "triage_cve", arguments: { cve_id: CVE }, expect: CVE, unmet: "prompt_argument_not_applied" });
    assert.deepEqual(PROMPT_PROBES[1], { label: WORKLOAD, name: "workload_triage", arguments: { source: "kubernetes" }, expect: "check_sbom", unmet: "prompt_tool_not_named" });
    for (const p of PROMPT_PROBES) {
      assert.equal(p.label, `prompt:${p.name}`, "a label is a fixed string naming its prompt");
      assert.ok(typeof p.expect === "string" && p.expect.trim() !== "", `${p.label}: an empty expect would pass any text`);
      assert.match(p.unmet, /^prompt_[a-z_]+$/, `${p.label}: its unmet reason`);
    }
  });

  it("both prompts listed and answering their text: one success line each, in the table's order, each sent the table's own arguments, from one prompts/list", async () => {
    const s = session();
    const { extras, one } = await probe(s);
    for (const label of PROMPT_LABELS) {
      const l = one(label);
      assert.deepEqual([l.outcome, l.era], ["success", MODERN], `${label}: ${JSON.stringify(l)}`);
      assert.ok(Number.isInteger(l.latency_ms) && l.latency_ms >= 0, `${label}: no latency`);
    }
    assert.deepEqual(extras.map((l) => l.tool), [...PROMPT_LABELS, RESOURCE_PROBE.label]);
    assert.deepEqual(s.calls.get, [{ name: "triage_cve", args: { cve_id: CVE } }, { name: "workload_triage", args: { source: "kubernetes" } }]);
    assert.equal(s.calls.list, 1, "prompts/list once per era, read by every prompt probe");
  });

  it("workload_triage answering a text that names no check_sbom is a failure, prompt_tool_not_named; triage_cve's line is unaffected", async () => {
    const s = session({ says: { ...SAYS, workload_triage: () => "Rank your workloads by CISA-KEV listing, then exposure, then EPSS." } });
    const { one } = await probe(s);
    const l = one(WORKLOAD);
    assert.deepEqual([l.outcome, l.reason], ["failure", "prompt_tool_not_named"], JSON.stringify(l));
    assert.match(l.detail, /check_sbom/);
    assert.equal(one(TRIAGE).outcome, "success");
  });

  it("an endpoint whose version predates workload_triage (0.0.0-test) and does not list it: not_published, never called, never a failure", async () => {
    const s = session({ prompts: ["triage_cve"] });
    const { extras, one } = await probe(s);
    const l = one(WORKLOAD);
    assert.equal(l.outcome, "not_published", JSON.stringify(l));
    assert.equal(l.latency_ms, undefined, "a prompt that was not called carries no latency");
    assert.ok(!s.calls.get.some((c) => c.name === "workload_triage"), "an unlisted prompt was called");
    assert.equal(one(TRIAGE).outcome, "success");
    assert.ok(!extras.some((x) => x.outcome === "failure"), JSON.stringify(extras));
  });

  // #3282: #2846 asked the synthetic to read not_published before the release and fail after it.
  // Through 3.0.2 an endpoint that stopped listing workload_triage (a revision built from a tag
  // before 2.7.0, one deploy over another, a hosted-only registration regression) read
  // not_published on every run and paged nobody. Now a probe the endpoint does not list although
  // the version its handshake reports is at or past the release probes.mjs SHIPPED_IN gives it is
  // a failure, reason not_listed. Control: the gate dropped (no SHIPPED_IN entry), 3.0.2 reads
  // not_published again.
  it("#3282: an endpoint reporting 3.0.2 that does not list workload_triage (shipped in 2.7.0): failure, reason not_listed, never called", async () => {
    assert.equal(probeTable.SHIPPED_IN?.[WORKLOAD], "2.7.0", "probes.mjs gives workload_triage no release");
    const s = session({ prompts: ["triage_cve"], version: "3.0.2" });
    const { one } = await probe(s);
    const l = one(WORKLOAD);
    assert.deepEqual([l.outcome, l.reason, l.shipped_in], ["failure", "not_listed", "2.7.0"], JSON.stringify(l));
    assert.equal(l.latency_ms, undefined);
    assert.ok(!s.calls.get.some((c) => c.name === "workload_triage"), "an unlisted prompt was called");
    assert.equal(one(TRIAGE).outcome, "success");
  });
  it("#3282: one reporting 2.6.5 (before workload_triage shipped) that does not list it: not_published", async () => {
    const { one } = await probe(session({ prompts: ["triage_cve"], version: "2.6.5" }));
    assert.equal(one(WORKLOAD).outcome, "not_published", JSON.stringify(one(WORKLOAD)));
  });
  it("#3282 control: with the gate dropped (no SHIPPED_IN entry for it), the 3.0.2 endpoint reads not_published again", async () => {
    const { [WORKLOAD]: _dropped, ...rest } = probeTable.SHIPPED_IN;
    const { one } = await probe(session({ prompts: ["triage_cve"], version: "3.0.2" }), { shipped: rest });
    assert.equal(one(WORKLOAD).outcome, "not_published", JSON.stringify(one(WORKLOAD)));
  });
  it("#3282: the tool probes are gated the same way: at 3.0.2 every unlisted probed tool is not_listed; at 2.6.5 those of 2.7.0 are not_published; one with no release never fails", async () => {
    const tools = Object.keys(PROBES);
    const at = async (version) => (await probe(session({ version }))).lines.filter((l) => tools.includes(l.tool));
    for (const l of await at("3.0.2")) assert.deepEqual([l.outcome, l.reason, l.shipped_in], ["failure", "not_listed", probeTable.SHIPPED_IN[l.tool]], JSON.stringify(l));
    const old = await at("2.6.5");
    for (const l of old) assert.equal(l.outcome, probeTable.SHIPPED_IN[l.tool] === "2.7.0" ? "not_published" : "failure", JSON.stringify(l));
    assert.deepEqual(old.filter((l) => l.outcome === "not_published").map((l) => l.tool).sort(), ["cve_remediation", "scan_manifest"]);
    // A tool with no release (a planned one) stays not_published at any version: the run tests
    // above add one to PROBES and run it against this package's own version.
    assert.deepEqual(runner.unlisted("planned_tool_not_yet_listed", "99.0.0"), { outcome: "not_published" });
  });

  it("a blank answer is prompt_empty, for each prompt", async () => {
    const { one } = await probe(session({ says: { triage_cve: () => " ", workload_triage: () => "" } }));
    for (const label of PROMPT_LABELS) assert.deepEqual([one(label).outcome, one(label).reason], ["failure", "prompt_empty"], label);
  });

  it("a prompts/list that fails is one failure line per prompt label, step list; the resource is still probed", async () => {
    const s = session({ listFails: true });
    const { one } = await probe(s);
    for (const label of PROMPT_LABELS) {
      const l = one(label);
      assert.deepEqual([l.outcome, l.step, l.reason], ["failure", "list", "timeout"], `${label}: ${JSON.stringify(l)}`);
    }
    assert.equal(s.calls.get.length, 0);
    assert.equal(one(RESOURCE_PROBE.label).outcome, "success");
  });
});

// ── #2724: the probe table covers exactly what the server lists ───────────────────────────────
// PUBLISHED above is a hand-kept list, and every run test is judged against it. So it is held
// here to what this package's own dist answers to tools/list, over stdio and over the hosted entry
// (dist/http.js), on both eras, and to the server.registerTool calls in src/. A tool added to the
// server and not to PUBLISHED and probes.mjs fails this test, by name, before it ships: the
// runner would still call it with {} (or fail it no_probe_input), but only a probes.mjs entry
// gives it a known-good input that fits its inputSchema. And a PROBES, HTTP_PROBES, EXPECT or
// AFTER entry for a tool the server no longer lists fails too: the runner would report it
// not_published on every run, which reads as fine.
describe("#2724: the probe table covers exactly what the server lists", () => {
  const SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "src");
  // A row for get_vendor_advisory's candidate, which reads vendor_advisories_for_cve's answer.
  const SEEN = { vendor_advisories_for_cve: { state: "measured", data: { advisories: [{ vendor: "redhat", vendor_advisory_id: ADVISORY }] } } };
  const listed = {};
  // #2846: what the hosted endpoint answers to prompts/list, per era (only the hosted leg probes prompts).
  const listedPrompts = {};
  let stub, srv;
  before(async () => {
    stub = await startStub();
    srv = await startHttpEntry(stub.base);
    for (const era of [MODERN, LEGACY]) {
      const c = await connect({ era, command: process.execPath, args: [DIST], env: { ...process.env, ECHELONGRAPH_API_BASE: stub.base }, stderr: "ignore" });
      try {
        listed[`stdio ${era}`] = (await c.listTools()).tools;
      } finally {
        await c.close();
      }
      const h = await connectHttp({ era, url: srv.url, userAgent: UA_TOKEN, clientInfo: { name: "coverage-test", version: "1.0.0" } });
      try {
        listed[`http ${era}`] = (await h.listTools()).tools;
        listedPrompts[`http ${era}`] = (await h.listPrompts()).prompts;
      } finally {
        await h.close();
      }
    }
  });
  after(async () => {
    await srv?.stop();
    await stub?.close();
  });

  it("control: tools/list answered on every transport and era", () => {
    assert.deepEqual(Object.keys(listed).sort(), [`http ${LEGACY}`, `http ${MODERN}`, `stdio ${LEGACY}`, `stdio ${MODERN}`]);
    for (const [where, tools] of Object.entries(listed)) assert.ok(tools.length > 0, `${where}: no tools`);
  });
  it("PUBLISHED is exactly what tools/list answers, in its order, everywhere", () => {
    for (const [where, tools] of Object.entries(listed)) assert.deepEqual(tools.map((t) => t.name), PUBLISHED, `${where}: tools/list and PUBLISHED differ`);
  });
  it("every server.registerTool call in src/ is listed: none is registered only under a condition the tests do not meet", () => {
    const calls = [];
    const walk = (dir) => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        const p = path.join(dir, e.name);
        if (e.isDirectory()) walk(p);
        else if (p.endsWith(".ts")) {
          const code = fs.readFileSync(p, "utf8").split("\n").filter((l) => !/^\s*\/\//.test(l)).join("\n");
          for (const m of code.matchAll(/server\.registerTool\(\s*("([a-z0-9_]+)"|[A-Za-z_.]+)/g)) calls.push({ file: path.relative(SRC, p), name: m[2] ?? null });
        }
      }
    };
    walk(SRC);
    assert.equal(calls.length, PUBLISHED.length, `src/ registers ${calls.length} tools, tools/list answers ${PUBLISHED.length}: ${JSON.stringify(calls)}`);
    for (const c of calls) if (c.name) assert.ok(PUBLISHED.includes(c.name), `${c.file} registers ${c.name}, which tools/list does not answer`);
  });
  it("every listed tool has a probes.mjs entry whose candidate fits the inputSchema it advertises, and an outputSchema to judge by, on every transport and era", () => {
    for (const [where, tools] of Object.entries(listed)) {
      const table = where.startsWith("http") ? { ...PROBES, ...HTTP_PROBES } : PROBES;
      for (const tool of tools) {
        assert.ok(Object.hasOwn(PROBES, tool.name), `${tool.name} is listed (${where}) but has no probes.mjs entry`);
        const choice = chooseInput(tool.name, tool, SEEN, table);
        assert.ok(choice.args && choice.index >= 0, `${tool.name} (${where}): no candidate fits its inputSchema: ${JSON.stringify(choice)}`);
        assert.ok(tool.outputSchema && typeof tool.outputSchema === "object", `${tool.name} (${where}): no outputSchema, so its answer cannot be judged`);
      }
    }
  });
  it("probes.mjs names no tool the server does not list: a stale entry would read not_published on every run", () => {
    const names = new Set(PUBLISHED);
    for (const [label, table] of [["PROBES", PROBES], ["HTTP_PROBES", HTTP_PROBES], ["EXPECT", EXPECT], ["HTTP_EXPECT", HTTP_EXPECT], ["AFTER", AFTER]]) {
      for (const k of Object.keys(table)) assert.ok(names.has(k), `${label} names ${k}, which tools/list does not answer`);
    }
    for (const deps of Object.values(AFTER)) for (const d of deps) assert.ok(names.has(d), `AFTER waits on ${d}, which tools/list does not answer`);
  });
  // #3282: every probe has the release it shipped in (a probe without one would read not_published
  // on an endpoint that drops it), none later than this package's version, and SHIPPED_IN names
  // nothing probes.mjs does not probe.
  it("#3282: probes.mjs SHIPPED_IN gives every probed tool, prompt and resource its release, none past this package's", async () => {
    const { PKG } = await import("../test/server-under-test.mjs");
    const { versionAtLeast } = runner;
    const SHIPPED = probeTable.SHIPPED_IN;
    assert.ok(SHIPPED && typeof SHIPPED === "object", "probes.mjs exports no SHIPPED_IN");
    const keys = [...Object.keys(PROBES), ...PROMPT_PROBES.map((p) => p.label), RESOURCE_PROBE.label];
    for (const k of [...keys, ...VERDICT_PROBES.map((v) => v.tool), ...probeTable.CHAIN_PROBES.map((c) => c.tool)]) {
      assert.match(SHIPPED[k] ?? "", /^\d+\.\d+\.\d+$/, `${k}: no release in SHIPPED_IN, so an endpoint that drops it reads not_published`);
      assert.ok(versionAtLeast(PKG.version, SHIPPED[k]), `${k}: SHIPPED_IN ${SHIPPED[k]} is past this package's ${PKG.version}`);
    }
    assert.deepEqual(Object.keys(SHIPPED).filter((k) => !keys.includes(k)), [], "SHIPPED_IN names what nothing probes");
  });
  it("#3011: this package's get_vendor_advisory is detected as carrying the chain probe's fix, on every transport and era, and the probe's arguments fit its inputSchema", () => {
    const CHAIN_PROBES = probeTable.CHAIN_PROBES;
    assert.ok(Array.isArray(CHAIN_PROBES), "probes.mjs exports no CHAIN_PROBES list");
    const seen = { vendor_advisories_for_cve: { state: "measured", data: { advisories: [ADVISORY_ROW] } } };
    for (const [where, tools] of Object.entries(listed)) {
      for (const c of CHAIN_PROBES) {
        const tool = tools.find((t) => t.name === c.tool);
        assert.ok(tool, `${c.label}: ${c.tool} is not listed (${where})`);
        assert.equal(c.published(tool), true, `${c.label} (${where}): the package's own inputSchema is not detected as the fix, so the probe would read not_published on every run`);
        const choice = chooseInput(c.tool, tool, seen, { [c.tool]: [c.arguments] });
        assert.deepEqual(choice.args, { vendor: "redhat", advisory_id: ADVISORY_ROW.advisory_id }, `${c.label} (${where}): ${JSON.stringify(choice)}`);
      }
    }
  });
  it("#3135: every VERDICT_PROBES call is of a tool the hosted endpoint lists on both eras, with arguments its inputSchema accepts", () => {
    assert.ok(Array.isArray(VERDICT_PROBES), "probes.mjs exports no VERDICT_PROBES list");
    for (const era of [MODERN, LEGACY]) {
      const tools = listed[`http ${era}`];
      for (const v of VERDICT_PROBES) {
        const tool = tools.find((t) => t.name === v.tool);
        assert.ok(tool, `${v.label}: ${v.tool} is not listed (http ${era}), so it would read not_published on every run`);
        const choice = chooseInput(v.tool, tool, SEEN, { [v.tool]: [v.arguments] });
        assert.deepEqual([choice.index, choice.args], [0, v.arguments], `${v.label} (http ${era}): its arguments do not fit the inputSchema: ${JSON.stringify(choice)}`);
      }
    }
  });
  it("#2846: every PROMPT_PROBES prompt is listed by the hosted endpoint on both eras, sent only the arguments it declares and every one it requires", async () => {
    assert.ok(Array.isArray(PROMPT_PROBES), "probes.mjs exports no PROMPT_PROBES list");
    assert.deepEqual(Object.keys(listedPrompts).sort(), [`http ${LEGACY}`, `http ${MODERN}`], "control: prompts/list answered on both eras");
    for (const [where, prompts] of Object.entries(listedPrompts)) {
      for (const p of PROMPT_PROBES) {
        const decl = prompts.find((x) => x.name === p.name);
        assert.ok(decl, `${p.name} (${where}) is not listed: its probe would read not_published on every run`);
        const declared = (decl.arguments ?? []).map((a) => a.name);
        for (const k of Object.keys(p.arguments)) assert.ok(declared.includes(k), `${p.name} (${where}) is sent ${k}, which it does not declare (${declared.join(", ")})`);
        for (const a of decl.arguments ?? []) if (a.required) assert.ok(Object.hasOwn(p.arguments, a.name), `${p.name} (${where}) requires ${a.name}, which its probe does not send`);
      }
    }
    // workload_triage's source is an enum prompts/list does not show: held against the server's own.
    const { WORKLOAD_SOURCES } = await import("../dist/prompts.js");
    const wt = PROMPT_PROBES.find((p) => p.name === "workload_triage");
    assert.ok(WORKLOAD_SOURCES.includes(wt?.arguments?.source), `workload_triage's probe sends source ${JSON.stringify(wt?.arguments?.source)}, not one of ${WORKLOAD_SOURCES.join(", ")}`);
  });
});

// ── #2781: what each answer costs a client, on its probe line ───────────────────────────────────
// Production's text size was measured only when someone ran `npm run text-bound:live`, so its
// growth past the record was silent. Every probe line whose call was answered now carries
// text_chars (and a tools/call line structured_chars), the series create-mcp-synthetic-monitoring.sh
// reads. What must hold: the sizes are on every answered line of both legs and eras; they are the
// numbers test/text-bound.mjs measures (textSize, structuredSize), never another count; on the stdio
// leg they are what a client of the API base receives, though the package is pointed at the
// forwarder (forwarder.mjs serves under a path that makes its base as long); and a line carries a
// count, never a character of the answer.

// The stub API under a base of `length` characters (production's https://app.echelongraph.io is
// 27): a loopback server at http://127.0.0.1:<port>/<path> that takes the path off and relays the
// rest, headers and body, to the stub. A forwarder in front of it then needs a path of its own.
async function startLongBaseApi(upstream, length) {
  let prefix = "";
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    if (!req.url.startsWith(`${prefix}/`)) {
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("not under the long base\n");
      return;
    }
    const headers = Object.fromEntries(Object.entries(req.headers).filter(([k]) => !["host", "connection", "content-length", "transfer-encoding", "accept-encoding"].includes(k)));
    const up = await fetch(`${upstream}${req.url.slice(prefix.length)}`, { method: req.method, headers, body: chunks.length && req.method !== "GET" ? Buffer.concat(chunks) : undefined });
    res.writeHead(up.status, { "content-type": up.headers.get("content-type") ?? "application/json" });
    res.end(Buffer.from(await up.arrayBuffer()));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  prefix = `/${"a".repeat(length - origin.length - 1)}`;
  return {
    base: `${origin}${prefix}`,
    close: () => {
      server.closeAllConnections();
      return new Promise((resolve) => server.close(resolve));
    },
  };
}

describe("#2781: each answered probe line says what the answer costs a client (text_chars, structured_chars)", () => {
  let stub, srv, longApi, both, viaForwarder, direct;
  const sizeKeys = (l) => ["text_chars", "structured_chars"].filter((k) => Object.hasOwn(l, k));
  before(async () => {
    stub = await startStub();
    stub.state.mode = "ok";
    srv = await startHttpEntry(stub.base);
    longApi = await startLongBaseApi(stub.base, PROD_BASE.length);
    both = await run(stub, { remoteUrl: srv.url, force: ["canary_deliberate_failure"] });
    viaForwarder = await run(stub, { apiBase: longApi.base, eras: [MODERN] });
    direct = await run(stub, { apiBase: longApi.base, eras: [MODERN], direct: true });
  });
  after(async () => {
    await srv?.stop();
    await longApi?.close();
    await stub?.close();
  });

  it("every tools/call line that was answered carries text_chars and structured_chars, on both legs and eras; a prompt's and the resource's line carries text_chars", () => {
    assert.equal(typeof runner.sizesOf, "function", "run.mjs exports no sizesOf: the probe lines carry no size");
    for (const transport of [STDIO, HTTP]) {
      for (const era of [MODERN, LEGACY]) {
        const calls = [...PUBLISHED, ...(transport === HTTP ? activeVerdicts() : [])];
        for (const tool of calls) {
          const l = both.probes.find((p) => p.transport === transport && p.tool === tool && p.era === era);
          assert.ok(l, `${tool} [${transport} ${era}]: no line`);
          assert.ok(Number.isInteger(l.text_chars) && l.text_chars > 0, `${tool} [${transport} ${era}]: text_chars ${JSON.stringify(l.text_chars)}`);
          assert.ok(Number.isInteger(l.structured_chars) && l.structured_chars > 0, `${tool} [${transport} ${era}]: structured_chars ${JSON.stringify(l.structured_chars)}`);
        }
        if (transport === HTTP) {
          for (const label of [...PROMPT_LABELS, RESOURCE_PROBE.label]) {
            const l = both.probes.find((p) => p.transport === HTTP && p.tool === label && p.era === era);
            assert.ok(l && Number.isInteger(l.text_chars) && l.text_chars > 0, `${label} [${era}]: ${JSON.stringify(l)}`);
            assert.deepEqual(sizeKeys(l), ["text_chars"], `${label} [${era}]: a prompt or resource answer has no structuredContent to size`);
          }
        }
      }
    }
  });

  // #3011's chain probe (merged beside #2781) is a tools/call too: its answer costs a client the same.
  it("a chain:… line whose call was answered carries text_chars and structured_chars, as every other tools/call line does", () => {
    for (const era of [MODERN, LEGACY]) {
      for (const label of CHAIN_LABELS) {
        const l = both.probes.find((p) => p.transport === HTTP && p.tool === label && p.era === era);
        assert.ok(l && Number.isInteger(l.latency_ms), `control: ${label} [${era}] was called and answered: ${JSON.stringify(l)}`);
        assert.ok(Number.isInteger(l.text_chars) && l.text_chars > 0, `${label} [${era}]: text_chars ${JSON.stringify(l.text_chars)}`);
        assert.ok(l.structured_chars === null || (Number.isInteger(l.structured_chars) && l.structured_chars > 0), `${label} [${era}]: structured_chars ${JSON.stringify(l.structured_chars)}`);
        assert.ok(Object.hasOwn(l, "structured_chars"), `${label} [${era}]: no structured_chars`);
      }
    }
  });

  it("a line whose call was not answered carries no size, and one answered with an error carries the error's", () => {
    for (const era of [MODERN, LEGACY]) {
      for (const transport of [STDIO, HTTP]) {
        const l = both.probes.find((p) => p.transport === transport && p.tool === "canary_deliberate_failure" && p.era === era);
        assert.equal(l?.outcome, "failure", JSON.stringify(l));
        if (l.reason === "rpc_error") assert.deepEqual(sizeKeys(l), [], `answered no result, so no size: ${JSON.stringify(l)}`);
        else assert.ok(Number.isInteger(l.text_chars), `answered a result, so it is sized: ${JSON.stringify(l)}`);
      }
    }
  });

  it("each size is the number test/text-bound.mjs measures of the same answer (textSize's total, structuredSize), the stub's base counted as production's", async () => {
    assert.equal(typeof runner.sizesOf, "function", "run.mjs exports no sizesOf");
    const answers = [];
    const lines = [];
    const measure = (res) => {
      answers.push(res);
      return runner.sizesOf(res);
    };
    const emit = (l) => lines.push(l);
    const open = () => connect({ era: MODERN, command: process.execPath, args: [DIST], env: { ...process.env, ECHELONGRAPH_API_BASE: stub.base }, stderr: "ignore" });
    await probeSession({ era: MODERN, open, force: [], emit, measure });
    const openHttp = () => connectHttp({ era: MODERN, url: srv.url, userAgent: UA_TOKEN });
    await probeSession({ era: MODERN, open: openHttp, force: [], emit, measure, extras: true, probes: { ...PROBES, ...HTTP_PROBES }, expect: { ...EXPECT, ...HTTP_EXPECT } });
    const sized = lines.filter((l) => Object.hasOwn(l, "text_chars"));
    assert.equal(sized.length, answers.length, "a line for every answer measured");
    assert.ok(answers.length >= 2 * PUBLISHED.length, `${answers.length} answers measured`);
    let prompts = 0;
    for (const [i, res] of answers.entries()) {
      const l = sized[i];
      if (Array.isArray(res.messages)) {
        prompts++;
        assert.equal(l.text_chars, res.messages.filter((m) => m.content?.type === "text").reduce((n, m) => n + m.content.text.length, 0), l.tool);
        continue;
      }
      assert.equal(l.text_chars, textSize(res).total, `${l.tool}: text_chars is not text-bound.mjs's textSize`);
      if (!res.contents) assert.equal(l.structured_chars, structuredSize(res) ?? null, `${l.tool}: structured_chars is not text-bound.mjs's structuredSize`);
      // With a base counted as production's, as text-bound.mjs counts its stub's.
      const asProd = runner.sizesOf(res, { localBase: stub.base, asBase: PROD_BASE });
      assert.equal(asProd.text_chars, textSize(res, stub.base).total, `${l.tool}: the base, counted as production's`);
      if (!res.contents) assert.equal(asProd.structured_chars, structuredSize(res, stub.base) ?? null, `${l.tool}: the base, counted as production's (structured)`);
    }
    assert.equal(prompts, PROMPT_LABELS.length, "both prompt answers measured");
    // Not vacuous: the package quotes its base (the OK note), so counting it as production's moves the size.
    const summary = answers[lines.findIndex((l) => l.tool === "cve_summary")];
    assert.ok(JSON.stringify(summary.content).includes(stub.base), "the answer does not quote the API base, so the base check above proves nothing");
    assert.ok(runner.sizesOf(summary, { localBase: stub.base, asBase: PROD_BASE }).text_chars > runner.sizesOf(summary).text_chars);
  });

  it("the stdio leg's sizes are what a client of the API base receives: the forwarder's base is as long as that base, so the package answers it as it answers a direct client", async () => {
    // The package's own answers, uncounted (no base taken for another): pointed at a forwarder in
    // front of the long base, and at the long base itself. The package quotes its base, and the cut
    // fills its budget to the character, so only a forwarder base of the same length answers alike.
    const raw = async (base) => {
      const out = {};
      const open = () => connect({ era: MODERN, command: process.execPath, args: [DIST], env: { ...process.env, ECHELONGRAPH_API_BASE: base, ECHELONGRAPH_MCP_UA: UA_TOKEN }, stderr: "ignore" });
      await probeSession({ era: MODERN, open, force: [], emit: (l) => (out[l.tool] = l), measure: (res) => runner.sizesOf(res) });
      return out;
    };
    const fwd = await startForwarder({ upstream: longApi.base, token: UA_TOKEN });
    let via, own;
    try {
      [via, own] = [await raw(fwd.base), await raw(longApi.base)];
    } finally {
      await fwd.close();
    }
    for (const tool of PUBLISHED) {
      assert.ok(Number.isInteger(own[tool]?.text_chars), `${tool}: ${JSON.stringify(own[tool])}`);
      assert.deepEqual([via[tool].text_chars, via[tool].structured_chars], [own[tool].text_chars, own[tool].structured_chars], `${tool}: the package answered the forwarder in other sizes than a client of the API base`);
    }
    for (const tool of PUBLISHED) {
      const f = viaForwarder.of(tool, MODERN);
      const d = direct.of(tool, MODERN);
      assert.equal(f?.outcome, "success", `${tool} via the forwarder: ${JSON.stringify(f)}`);
      assert.equal(d?.outcome, "success", `${tool} direct: ${JSON.stringify(d)}`);
      assert.ok(Number.isInteger(d.text_chars) && Number.isInteger(d.structured_chars), `${tool} direct: no sizes: ${JSON.stringify(d)}`);
      assert.deepEqual([f.text_chars, f.structured_chars], [d.text_chars, d.structured_chars], `${tool}: via the forwarder ${f.text_chars} / ${f.structured_chars}, direct ${d.text_chars} / ${d.structured_chars}`);
    }
    assert.equal(direct.complete[0].forwarder, "off");
    assert.ok(viaForwarder.complete[0].api_requests > 0, "the forwarder relayed nothing, so the comparison proves nothing");
  });

  it("the forwarder serves under a path that makes its base as long as its upstream's, takes it off before relaying, and relays nothing outside it", async () => {
    assert.equal(typeof forwarderModule.prefixFor, "function", "forwarder.mjs exports no prefixFor: its base is the loopback origin's length, not the API's");
    const prod = await startForwarder({ upstream: PROD_BASE, token: UA_TOKEN });
    try {
      assert.equal(prod.base.length, PROD_BASE.length, prod.base);
      assert.match(prod.base, /^http:\/\/127\.0\.0\.1:\d+\/p+$/);
    } finally {
      await prod.close();
    }
    stub.state.mode = "echo";
    const long = await startForwarder({ upstream: `${stub.base}/upstream-path`, token: UA_TOKEN });
    try {
      assert.equal(long.base.length, `${stub.base}/upstream-path`.length);
      const res = await fetch(`${long.base}/api/v1/public/cves/summary?x=1`, { headers: { "user-agent": "echelongraph-mcp/2.3.4" } });
      assert.equal(res.status, 201);
      assert.equal((await res.json()).url, "/upstream-path/api/v1/public/cves/summary?x=1", "the forwarder's own path was relayed, or the upstream's dropped");
      const seen = stub.state.seen.length;
      const outside = await fetch(`${new URL(long.base).origin}/api/v1/public/cves/summary`);
      assert.equal(outside.status, 404);
      assert.equal(stub.state.seen.length, seen, "a request outside the forwarder's base was relayed");
    } finally {
      stub.state.mode = "ok";
      await long.close();
    }
    // An upstream no longer than the loopback origin: no path.
    const same = await startForwarder({ upstream: stub.base, token: UA_TOKEN });
    try {
      assert.equal(new URL(same.base).pathname, "/");
      assert.equal(same.base, new URL(same.base).origin);
    } finally {
      await same.close();
    }
  });

  it("sizes only: text_chars and structured_chars are counts, and the thresholds the monitoring alerts at are the suite's (#2617's 45,000 and #3013's 30,000)", () => {
    for (const l of [...both.probes, ...viaForwarder.probes]) {
      for (const k of sizeKeys(l)) assert.ok(l[k] === null || Number.isInteger(l[k]), `${l.tool}: ${k} is ${JSON.stringify(l[k])}, not a count`);
    }
    assert.equal(TRIP_WIRE, 45_000);
    assert.equal(STRUCTURED_BUDGET, 30_000);
    // Every answer the healthy run sized is under both, so the alert rests at nothing on it.
    for (const l of both.probes.filter((p) => Object.hasOwn(p, "text_chars"))) {
      assert.ok(l.text_chars <= TRIP_WIRE && (l.structured_chars ?? 0) <= STRUCTURED_BUDGET, JSON.stringify(l));
    }
  });
});

// ── #3097: hosted versus npm ─────────────────────────────────────────────────────────────────
// On 2026-10-11 the hosted endpoint and npm both reported 2.7.1 and served different cve_intel
// descriptions, and the synthetic, judging each leg by its own outputSchema, could not see it. A
// copy of this package's dist/ with one tool description changed stands in for a build that is not
// the release: served as the hosted endpoint (the 2026-10-11 case), and run as the npm package (the
// other way). Both must fail the (hosted-vs-npm) line, naming the tool and the field, and nothing
// else; the same build on another version is not compared; the release build passes.
const PKG_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DRIFT_FROM = "How one CVE's EPSS score (FIRST's";
const DRIFT_TO = "How one CVE's EPSS scores (FIRST's";
function driftedCopy() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "eg-mcp-drift-3097-"));
  fs.cpSync(path.join(PKG_DIR, "dist"), path.join(dir, "dist"), { recursive: true });
  fs.copyFileSync(path.join(PKG_DIR, "package.json"), path.join(dir, "package.json"));
  fs.symlinkSync(fs.realpathSync(path.join(PKG_DIR, "node_modules")), path.join(dir, "node_modules"), "dir");
  const f = path.join(dir, "dist", "tools", "epss_history.js");
  const src = fs.readFileSync(f, "utf8");
  assert.equal(src.split(DRIFT_FROM).length, 2, "control: dist/tools/epss_history.js holds the description's opening once (re-aim DRIFT_FROM)");
  fs.writeFileSync(f, src.replace(DRIFT_FROM, DRIFT_TO));
  return dir;
}

describe("#3097: a hosted endpoint serving other code than the npm release it reports", () => {
  let stub, release, drifted, copy;
  before(async () => {
    stub = await startStub();
    copy = driftedCopy();
    release = await startHttpEntry(stub.base);
    drifted = await startHttpEntry(stub.base, {}, path.join(copy, "dist", "http.js"));
  });
  after(async () => {
    await release?.stop();
    await drifted?.stop();
    await stub?.close();
    if (copy) fs.rmSync(copy, { recursive: true, force: true });
  });
  const driftLines = (r) => r.probes.filter((l) => l.tool === DRIFT_TOOL);
  const at = DRIFT_FROM.length - " (FIRST's".length + 1; // the first character that differs, 1-based

  function failsOnlyTheComparison(r, what) {
    const drift = driftLines(r);
    assert.deepEqual(drift.map((l) => [l.transport, l.era, l.outcome, l.reason, l.differences]),
      [[HTTP, MODERN, "failure", "hosted_differs_from_npm", 1], [HTTP, LEGACY, "failure", "hosted_differs_from_npm", 1]], JSON.stringify(drift));
    for (const l of drift) {
      assert.match(l.detail, new RegExp(`^tool epss_history: description differs at character ${at} \\(npm (\\d+) characters, hosted (\\d+)\\)$`), l.detail);
      const [, npm, hosted] = l.detail.match(/npm (\d+) characters, hosted (\d+)/).map(Number);
      assert.equal(hosted - npm, what === "hosted" ? 1 : -1, `the longer description is the ${what} one: ${l.detail}`);
      assert.equal(l.compared_tools, PUBLISHED.length);
    }
    const others = r.probes.filter((l) => l.tool !== DRIFT_TOOL && l.outcome === "failure");
    assert.deepEqual(others, [], "only the comparison fails: each leg alone is healthy, which is why nothing saw 2026-10-11");
    assert.equal(r.exitCode, 2);
    assert.deepEqual([r.complete[0].failure, r.complete[0].hosted_vs_npm], [2, "differs"]);
  }

  it("the hosted endpoint drifted (one description changed, the 2026-10-11 case): (hosted-vs-npm) fails on both eras, naming the tool, the field and where it differs", async () => {
    stub.state.mode = "ok";
    failsOnlyTheComparison(await run(stub, { remoteUrl: drifted.url }), "hosted");
  });
  it("the npm package drifted (the other way): the same failure, the other length", async () => {
    stub.state.mode = "ok";
    failsOnlyTheComparison(await run(stub, { serverJs: path.join(copy, "dist", "index.js"), remoteUrl: release.url }), "npm");
  });
  // #3097's review: on another version than npm's latest (a rollback to an older release, a hand
  // deploy reporting another number), the endpoint is compared with npm's package of the version it
  // reports, installed once per run, instead of nothing being compared.
  it("the drifted endpoint on another version than the npm leg's: compared with npm's package of the version it reports, installed once for both eras, and it fails", async () => {
    stub.state.mode = "ok";
    const { PKG } = await import("../test/server-under-test.mjs");
    const asked = [];
    const r = await run(stub, { remoteUrl: drifted.url, version: "0.0.0-another", installPackage: async (spec, dir) => (asked.push([spec, typeof dir]), releasedHere(spec)) });
    assert.deepEqual(asked, [[`echelongraph-mcp@${PKG.version}`, "string"]], "npm's package of the hosted version, installed once, into a directory of its own");
    const drift = driftLines(r);
    assert.deepEqual(drift.map((l) => [l.era, l.outcome, l.reason, l.npm_version, l.compared_with]),
      [[MODERN, "failure", "hosted_differs_from_npm", PKG.version, "hosted_version"], [LEGACY, "failure", "hosted_differs_from_npm", PKG.version, "hosted_version"]], JSON.stringify(drift));
    for (const l of drift) assert.match(l.detail, /^tool epss_history: description differs at character \d+/);
    assert.deepEqual([r.exitCode, r.complete[0].hosted_vs_npm, r.complete[0].hosted_vs_npm_at], [2, "differs", PKG.version]);
  });
  it("the release build on another version than the npm leg's: compared at its own version, and the same", async () => {
    stub.state.mode = "ok";
    const { PKG } = await import("../test/server-under-test.mjs");
    const r = await run(stub, { remoteUrl: release.url, version: "0.0.0-another" });
    assert.deepEqual(driftLines(r).map((l) => [l.era, l.outcome, l.compared_with, l.npm_version, l.compared_tools]), [[MODERN, "success", "hosted_version", PKG.version, PUBLISHED.length], [LEGACY, "success", "hosted_version", PKG.version, PUBLISHED.length]]);
    assert.deepEqual([r.exitCode, r.complete[0].hosted_vs_npm, r.complete[0].hosted_vs_npm_at], [0, "identical", PKG.version]);
  });
  it("an endpoint reporting a version npm does not serve: fails on both eras (hosted_version_not_on_npm), a build no release has", async () => {
    stub.state.mode = "ok";
    const r = await run(stub, { remoteUrl: release.url, version: "0.0.0-another", installPackage: async (spec) => { throw new Error(`npm error code ETARGET | npm error notarget No matching version found for ${spec}.`); } });
    assert.deepEqual(driftLines(r).map((l) => [l.era, l.outcome, l.reason, l.compared_with]), [[MODERN, "failure", "hosted_version_not_on_npm", "hosted_version"], [LEGACY, "failure", "hosted_version_not_on_npm", "hosted_version"]]);
    for (const l of driftLines(r)) assert.match(l.detail, /No matching version found for echelongraph-mcp@/);
    assert.deepEqual([r.exitCode, r.complete[0].hosted_vs_npm], [2, "hosted_version_not_on_npm"]);
  });
  it("npm's package of the hosted version that cannot be installed otherwise: fails on both eras (hosted_version_install_failed), never read as the same", async () => {
    stub.state.mode = "ok";
    const r = await run(stub, { remoteUrl: release.url, version: "0.0.0-another", installPackage: async () => { throw new Error("npm error code ECONNRESET | npm error network aborted"); } });
    assert.deepEqual(driftLines(r).map((l) => [l.era, l.outcome, l.reason]), [[MODERN, "failure", "hosted_version_install_failed"], [LEGACY, "failure", "hosted_version_install_failed"]]);
    assert.deepEqual([r.exitCode, r.complete[0].hosted_vs_npm], [2, "hosted_version_install_failed"]);
  });
  it("restored to the release build: (hosted-vs-npm) passes on both eras", async () => {
    stub.state.mode = "ok";
    const r = await run(stub, { remoteUrl: release.url });
    assert.deepEqual(driftLines(r).map((l) => [l.era, l.outcome]), [[MODERN, "success"], [LEGACY, "success"]]);
    assert.deepEqual([r.exitCode, r.complete[0].hosted_vs_npm], [0, "identical"]);
  });
  it("one leg alone compares nothing and says so only when both legs ran", async () => {
    stub.state.mode = "ok";
    const hostedOnly = await run(stub, { stdio: false, remoteUrl: drifted.url, eras: [LEGACY] });
    assert.deepEqual([driftLines(hostedOnly), hostedOnly.complete[0].hosted_vs_npm], [[], undefined]);
    const npmOnly = await run(stub, { eras: [LEGACY] });
    assert.deepEqual([driftLines(npmOnly), npmOnly.complete[0].hosted_vs_npm], [[], undefined]);
    const noInstall = await run(stub, { serverJs: undefined, packageSpec: "not a spec", remoteUrl: release.url, eras: [LEGACY] });
    assert.deepEqual([driftLines(noInstall), noInstall.complete[0].hosted_vs_npm], [[], "version_unknown"]);
  });
});

describe("#3097: comparing two catalogs", () => {
  const tool = (over = {}) => ({ name: "a", title: "A", description: "abcde", inputSchema: { type: "object", properties: { x: { type: "string" } }, required: ["x"] }, outputSchema: { type: "object" }, annotations: { readOnlyHint: true }, ...over });
  const cat = (over = {}) => ({ instructions: "use it", tools: [tool(), tool({ name: "b" })], prompts: [{ name: "p", arguments: [{ name: "cve_id", required: true }] }], resources: [{ uri: "echelongraph://m", name: "m", mimeType: "text/markdown" }], ...over });
  const diffs = (npm, hosted) => compareCatalogs(npm, hosted).differences;

  it("the same catalog, keys in another order and tools in another order, is the same", () => {
    const shuffled = cat({ tools: [tool({ name: "b" }), Object.fromEntries(Object.entries(tool()).reverse())] });
    const r = compareCatalogs(cat(), shuffled);
    assert.deepEqual(r, { differences: [], compared: { tools: 2, prompts: 1, resources: 1 }, uncompared: [] });
  });
  it("each field of a tool changed alone is a difference naming the tool and the field", () => {
    assert.deepEqual(diffs(cat(), cat({ tools: [tool({ description: "abXde" }), tool({ name: "b" })] })), ["tool a: description differs at character 3 (npm 5 characters, hosted 5)"]);
    assert.deepEqual(diffs(cat(), cat({ tools: [tool({ title: "A2" }), tool({ name: "b" })] })), ["tool a: title differs at character 2 (npm 1 characters, hosted 2)"]);
    assert.deepEqual(diffs(cat(), cat({ tools: [tool({ inputSchema: { type: "object", properties: { x: { type: "string", maxLength: 9 } }, required: ["x"] } }), tool({ name: "b" })] })), ["tool a: inputSchema differs"]);
    assert.deepEqual(diffs(cat(), cat({ tools: [tool({ outputSchema: undefined }), tool({ name: "b" })] })), ["tool a: outputSchema only on npm"]);
    assert.deepEqual(diffs(cat(), cat({ tools: [tool({ annotations: { readOnlyHint: false } }), tool({ name: "b" })] })), ["tool a: annotations differs"]);
    assert.deepEqual(diffs(cat(), cat({ tools: [tool({ _meta: { x: 1 } }), tool({ name: "b" })] })), ["tool a: _meta only on the hosted endpoint"]);
  });
  it("a tool, a prompt or a resource on one side only is named, both ways", () => {
    assert.deepEqual(diffs(cat(), cat({ tools: [tool(), tool({ name: "b" }), tool({ name: "c" })] })), ["tool c: only on the hosted endpoint"]);
    assert.deepEqual(diffs(cat(), cat({ tools: [tool()] })), ["tool b: only on npm"]);
    assert.deepEqual(diffs(cat(), cat({ prompts: [] })), ["prompt p: only on npm"]);
    assert.deepEqual(diffs(cat({ resources: [] }), cat()), ["resource echelongraph://m: only on the hosted endpoint"]);
  });
  it("a prompt's arguments, a resource's fields and the instructions are compared too", () => {
    assert.deepEqual(diffs(cat(), cat({ prompts: [{ name: "p", arguments: [{ name: "cve_id", required: false }] }] })), ["prompt p: arguments differs"]);
    assert.deepEqual(diffs(cat(), cat({ resources: [{ uri: "echelongraph://m", name: "m", mimeType: "text/plain" }] })), ["resource echelongraph://m: mimeType differs at character 6 (npm 13 characters, hosted 10)"]);
    assert.deepEqual(diffs(cat(), cat({ instructions: "use it well" })), ["the server: instructions differs at character 7 (npm 6 characters, hosted 11)"]);
  });
  it("a list one side could not read is uncompared, not a difference; the same failure on both sides is no difference", () => {
    const r = compareCatalogs(cat(), cat({ prompts: { error: "rpc_error -32601" } }));
    assert.deepEqual([r.differences, r.uncompared, r.compared.prompts], [[], ["prompts/list (npm read it, hosted: rpc_error -32601)"], 0]);
    const both = compareCatalogs(cat({ resources: { error: "rpc_error -32601" } }), cat({ resources: { error: "rpc_error -32601" } }));
    assert.deepEqual([both.differences, both.uncompared], [[], []]);
  });
  it("control: a comparison that reads no field would pass every case above; this one reads every field (each changed alone fails)", () => {
    for (const [field, v] of Object.entries({ name: "z", title: "Z", description: "zzz", inputSchema: {}, outputSchema: {}, annotations: {}, icons: [] })) {
      const hosted = cat({ tools: [tool({ [field]: v }), tool({ name: "b" })] });
      assert.ok(diffs(cat(), hosted).length > 0, `a changed ${field} was not seen`);
    }
  });
});
