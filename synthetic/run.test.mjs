// Tests for the production MCP synthetic (#2724), against a local stub API and this package's
// own dist/ (build first; `npm test` does). Nothing here leaves the machine: the runner is given
// --bin (no npm install) and a loopback API base.
//
// What must hold:
//   - every listed tool is called once per era, judged against its own outputSchema with ajv,
//     and reported success; not_assessed counts as success; the planned tools are reported
//     not_published, never failure;
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
import http from "node:http";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { MODERN } from "../test/mcp-stdio-client.mjs";
import { modern } from "../test/mcp-http-client.mjs";
import { chooseInput, COMPLETE_MESSAGE, HTTP, judge, judgePrompt, judgeResource, LEGACY, probeOrder, PROBE_MESSAGE, remoteUrlAllowed, runSynthetic, STDIO, UA_TOKEN } from "./run.mjs";
import { identify, startForwarder, uaFamilyOf } from "./forwarder.mjs";
import { AFTER, EXPECT, HTTP_EXPECT, HTTP_PROBES, LOG4J_CORE, PROBES, PROMPT_PROBE, RESOURCE_PROBE, SBOM_PROBE_DOCUMENT, SBOM_PROBE_PURLS } from "./probes.mjs";
import { BATCH_PATH, CALL_ANSWER } from "../test/fixtures/match-batch.mjs";

const DIST = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "index.js");
// Every tool this package's dist lists, in createServer()'s registration order.
const PUBLISHED = [
  "cve_summary", "search_cves", "get_cve", "cve_exposure", "exposure_radar",
  "kev_recent", "epss_history", "check_affected", "check_sbom", "cve_intel", "get_cwe",
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
  "/api/v1/public/cves/summary": {
    poller: { cves_ingested: 1, cves_skipped: 0, http_retries: 0, interval: "20m0s", last_poll_at: AT, last_poll_dur_ms: 1000, poll_count: 1, poll_errors: 0 },
    summary: { critical: 1, high: 1, medium: 1, low: 1, none: 0, unscored: 0, total: 4, nvd_critical: 1, nvd_high: 1, nvd_medium: 1, nvd_low: 1, nvd_none: 0, rejected: 0, last_updated: AT },
  },
  "/api/v1/public/cves": { cves: [{ cve_id: CVE, severity: "CRITICAL", cvss_v3_score: 10, echelongraph_score: 10, score_assessed: true, kev_listed: true }], limit: 2, offset: 0, total: 1 },
  [`/api/v1/public/cves/${CVE}`]: { cve_id: CVE, severity: "CRITICAL", cvss_v3_score: 10, echelongraph_score: 10, score_confidence: "HIGH", score_assessed: true, epss_score: 0.97, kev_listed: true, kev_ransomware: true },
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
BODIES[BATCH_PATH] = CALL_ANSWER;
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
  const state = { mode: "ok", userAgents: [], seen: [], batches: [], refuseSecondBatch: false, batchCap: null };
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
        const n = JSON.parse(Buffer.concat(chunks).toString()).components.length;
        state.batches.push(n);
        if (state.batchCap !== null && n > state.batchCap) {
          res.writeHead(400, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: `${n} components sent; at most ${state.batchCap} per call. Nothing was looked up: split the list`, code: "TOO_MANY_COMPONENTS" }));
          return;
        }
        const refused = state.refuseSecondBatch && state.batches.length % 2 === 0;
        res.writeHead(refused ? 429 : 200, { "content-type": "application/json" });
        res.end(JSON.stringify(refused ? { error: "component budget exceeded", code: "RATE_LIMIT_EXCEEDED" } : BODIES[BATCH_PATH]));
      });
      return;
    }
    const { pathname } = new URL(req.url, "http://stub");
    const body = BODIES[req.url] ?? BODIES[pathname];
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

async function run(stub, opts = {}) {
  const lines = [];
  const result = await runSynthetic({ serverJs: DIST, apiBase: stub.base, timeoutMs: 30_000, write: (l) => lines.push(JSON.parse(JSON.stringify(l))), ...opts });
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
    it("#2757: check_sbom is probed with 201 purls, so each era sends two batches, 200 and 1, and both are answered", () => {
      assert.deepEqual(stub.state.batches, [200, 1, 200, 1]);
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
    assert.deepEqual(stub.state.batches, [200, 1], "control: the second batch was sent, and refused");
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
    assert.deepEqual(stub.state.batches, [200], "control: the first batch was sent, refused, and nothing after it");
    const l = r.of("check_sbom", LEGACY);
    assert.equal(l.outcome, "failure", JSON.stringify(l));
    // A 400 is the API refusing the input (index.ts failed()), so the state is invalid_input.
    assert.equal(l.reason, "state_invalid_input", JSON.stringify(l));
    assert.equal(r.exitCode, 2);
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
    const sc = (batches_sent, not_sent_reason = null) => ({ coverage: { batches_sent, not_sent_reason } });
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

describe("#2817: what cve_intel's probe must show", () => {
  const row = (fixed_branches, extra = {}) => ({ state: "measured", data: { affected_packages: [{ ecosystem: "Maven", package_name: LOG4J_CORE, fixed_version: "2.12.2", ...(fixed_branches === undefined ? {} : { fixed_branches }), ...extra }] } });
  const GHSA = "GHSA-jfh8-c2jp-5v3q";
  const R = (introduced, fixed, advisory_id = GHSA) => ({ introduced, fixed, last_affected: null, source: advisory_id ? "osv_bulk" : null, advisory_id });
  it("the probe asks for CVE-2021-44228", () => assert.deepEqual(PROBES.cve_intel, [{ cve_id: "CVE-2021-44228" }]));
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
    const sc = (state, input, components_in_document, batches_sent) => ({ state, coverage: { input, components_in_document, batches_sent, not_sent_reason: null } });
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
// advertises, one prompts/get and one resources/read, every line labelled transport "http", the
// endpoint's API calls filed under the synthetic's family, and a broken endpoint or API read as
// failure, never as silence or success.
const HTTP_ENTRY = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "http.js");

async function startHttpEntry(apiBase, extraEnv = {}) {
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
  const proc = spawn(process.execPath, [HTTP_ENTRY], { env, stdio: ["ignore", "pipe", "pipe"] });
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

const EXTRAS = [PROMPT_PROBE.label, RESOURCE_PROBE.label];

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
    it("every published tool, the prompt and the resource succeed on both eras over http", () => {
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
      assert.ok(stdio.every((l) => !EXTRAS.includes(l.tool)), "the prompt and resource probes are the hosted leg's");
      const http = r.probes.filter((l) => l.transport === HTTP);
      assert.equal(http.length, 2 * (PUBLISHED.length + EXTRAS.length));
      const c = r.complete[0];
      assert.deepEqual(c.transports, [STDIO, HTTP]);
      assert.deepEqual([c.success, c.failure], [2 * PUBLISHED.length + 2 * (PUBLISHED.length + EXTRAS.length), 0]);
    });
    it("an http line carries the version the endpoint reports in its handshake", async () => {
      const { PKG } = await import("../test/server-under-test.mjs");
      for (const l of r.probes.filter((p) => p.transport === HTTP)) assert.equal(l.package_version, PKG.version);
      assert.equal(r.complete[0].remote_version, PKG.version);
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
  });

  it("#2774: on a canary copy whose large-body cap is 64 KiB (MCP_MAX_SBOM_BODY_BYTES=65536), the hosted check_sbom probe fails, rpc_error -32600, and nothing else does", async () => {
    stub.state.mode = "ok";
    const canary = await startHttpEntry(stub.base, { MCP_MAX_SBOM_BODY_BYTES: "65536" });
    try {
      const r = await run(stub, { stdio: false, remoteUrl: canary.url });
      for (const era of [MODERN, LEGACY]) {
        const l = r.of("check_sbom", era);
        assert.equal(l.transport, HTTP);
        assert.deepEqual([l.outcome, l.reason, l.rpc_code], ["failure", "rpc_error", -32600], JSON.stringify(l));
        for (const tool of [...PUBLISHED.filter((t) => t !== "check_sbom"), ...EXTRAS]) assert.equal(r.of(tool, era).outcome, "success", tool);
      }
      assert.equal(r.exitCode, 2);
      const refused = canary.lines.map((l) => JSON.parse(l)).filter((j) => j.message === "mcp_request" && j.status === 413);
      assert.equal(refused.length, 2, "the endpoint logged each refusal");
      for (const a of refused) assert.equal(a.refused, "body_size");
    } finally {
      await canary.stop();
    }
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

  it("an API answering 500 fails every published tool over http with state_failed; the prompt and resource make no API call and still pass", async () => {
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
      for (const x of EXTRAS) assert.equal(r.of(x, era).outcome, "success");
    }
    assert.equal(r.exitCode, 2);
    assert.deepEqual(r.complete[0].transports, [HTTP]);
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
  it("a resource must answer an entry for the URI read, with a non-empty text", () => {
    const uri = RESOURCE_PROBE.uri;
    assert.deepEqual(judgeResource({ contents: [{ uri, mimeType: "text/markdown", text: "# How" }] }, uri), { outcome: "success" });
    assert.equal(judgeResource({ contents: [{ uri: "echelongraph://other", text: "x" }] }, uri).reason, "resource_uri_missing");
    assert.equal(judgeResource({ contents: [{ uri, text: "  " }] }, uri).reason, "resource_empty");
    assert.equal(judgeResource({ contents: [] }, uri).reason, "resource_no_contents");
  });
});
