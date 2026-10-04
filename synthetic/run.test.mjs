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
import { fileURLToPath } from "node:url";
import { MODERN } from "../test/mcp-stdio-client.mjs";
import { chooseInput, COMPLETE_MESSAGE, judge, LEGACY, probeOrder, PROBE_MESSAGE, runSynthetic, UA_TOKEN } from "./run.mjs";
import { identify, startForwarder, uaFamilyOf } from "./forwarder.mjs";
import { AFTER, PROBES } from "./probes.mjs";
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
  vendor_advisories: [], patches: [], fixed_versions: [], affected_packages: [],
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
  window: { from: null, to: null }, own_controls_excluded: 0, enabled: false,
};

// mode: ok (BODIES, else the router's 404), 500 (every request a 500).
async function startStub() {
  const state = { mode: "ok", userAgents: [], seen: [] };
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
      r = await run(stub);
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
