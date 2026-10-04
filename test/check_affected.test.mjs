// check_affected (#2716) against a stub of GET /api/v1/public/cves/match.
//
// What is under test, case by case (the ticket's "Done means" 1):
//   - an assessed hit, on the CPE path and on the registry path;
//   - assessed with 0 matches, which is the only clean shape, and only for not_affected_count;
//   - every not_assessed_reason the endpoint sends (core-backend cve/cpematch.go, cve/pkgmatch.go),
//     an unknown one, and an answer with no assessed at all: each is state not_assessed, and none
//     is worded as not affected;
//   - degraded, capped, candidates_capped and undetermined;
//   - header carriage (#1983): the stub asserts each typed value arrived in its X-EG-* header and
//     that the request URL is the bare path, carrying none of them;
//   - every result validates against the tool's advertised outputSchema with ajv.
// Runs once per era: this file over the 2026-07-28 opening, check_affected-legacy.test.mjs over a
// 2025-06-18 initialize.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { AjvJsonSchemaValidator } from "@modelcontextprotocol/server/validators/ajv";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { serverCommand } from "./server-under-test.mjs";

const ERA = globalThis.MCP_TEST_ERA ?? MODERN;
const TOOL = "check_affected";
const PATH = "/api/v1/public/cves/match";
const H = { product: "x-eg-product", version: "x-eg-version", ecosystem: "x-eg-ecosystem", package: "x-eg-package" };

// One match as production sent it for openssl 3.0.0 on 2026-10-03 (description trimmed).
const OPENSSL_MATCH = {
  cve_id: "CVE-2026-45447", severity: "HIGH", cvss_v3_score: 8.8, description: "A use-after-free during PKCS#7 signature verification.",
  kev_listed: false, ransomware: false, epss_score: 0.04002, cvss_v2_score: 0, cvss_v4_score: 0, echelongraph_score: 9.8, echelongraph_severity: "CRITICAL",
  effective_score: 9.8, effective_severity: "CRITICAL", score_assessed: true, matched_criteria: "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
  match_method: "product-name heuristic", match_confidence: 0.5, cpe_vendor: "openssl", vendor_unknown: true,
};
// A KEV-listed, ransomware-used match, and one EchelonGraph has not scored (echelongraph_score withheld).
const KEV_MATCH = { ...OPENSSL_MATCH, cve_id: "CVE-2099-30001", kev_listed: true, ransomware: true, epss_score: 0.97 };
const UNSCORED_MATCH = { ...OPENSSL_MATCH, cve_id: "CVE-2099-30002", echelongraph_score: undefined, echelongraph_severity: undefined, effective_score: 0, effective_severity: "", score_assessed: false, score_unassessed_reason: "no_signal" };
const cpe = (o) => ({
  assessed: true, candidate_count: 319, candidates_capped: false, capped: false, count: 0, excluded: [], excluded_count: 0, match_layer: "cpe", matches: [], not_assessed_reason: "",
  product: "openssl", product_named_count: 318, undecidable_excluded_count: 0, undecided_candidate_count: 0, vendor: "", vendor_advisory_count: 0, version: "3.0.0",
  ...o,
});
// Production's lodash 4.17.15 answer on 2026-10-03, trimmed to the CVE the ticket names.
const LODASH_MATCH = {
  cve_id: "CVE-2020-8203", severity: "HIGH", cvss_v3_score: 7.4, description: "Prototype pollution in zipObjectDeep.", kev_listed: false, ransomware: false, epss_score: 0.02,
  cvss_v2_score: 5.8, cvss_v4_score: 0, echelongraph_score: 7.4, echelongraph_severity: "HIGH", effective_score: 7.4, effective_severity: "HIGH", score_assessed: true,
  matched_criteria: "pkg:npm/lodash", match_method: "registry package", match_confidence: 0.95, vendor_unknown: false, version_evidence: "interval",
};
const registry = (o) => ({
  advisories_considered: 10, assessed: true, candidates_capped: false, capped: false, count: 0, cve_ids: [], ecosystem: "npm", ecosystem_recognised: true, match_layer: "registry",
  matches: [], not_affected_count: 0, not_assessed_reason: "", package: "lodash", undetermined: [], undetermined_count: 0, version: "4.17.15",
  ...o,
});
const withMatches = (base, matches, extra = {}) => base({ matches, count: matches.length, cve_ids: matches.map((m) => m.cve_id), ...extra });

// Every not_assessed_reason, with the answer shape the backend sends it in.
const REASONS = {
  product_not_in_cpe_corpus: cpe({ assessed: false, not_assessed_reason: "product_not_in_cpe_corpus", candidate_count: 0, product_named_count: 0 }),
  package_not_cpe_nameable: cpe({ assessed: false, not_assessed_reason: "package_not_cpe_nameable", excluded_count: 5, undecidable_excluded_count: 5, undecided_candidate_count: 10 }),
  candidate_load_pending: cpe({ assessed: false, not_assessed_reason: "candidate_load_pending", degraded: true, candidate_count: 0, product_named_count: 0 }),
  candidate_window_truncated: cpe({ assessed: false, not_assessed_reason: "candidate_window_truncated", candidates_capped: true, candidate_count: 2000 }),
  package_not_in_advisory_corpus: registry({ assessed: false, not_assessed_reason: "package_not_in_advisory_corpus", advisories_considered: 0 }),
  no_decidable_advisory: registry({
    assessed: false, not_assessed_reason: "no_decidable_advisory", advisories_considered: 2, undetermined_count: 2,
    undetermined: [{ cve_id: "CVE-2099-30010", package: "lodash", ecosystem: "npm", reason: "no_version_data" }, { cve_id: "CVE-2099-30011", package: "lodash", ecosystem: "npm", reason: "git_range_only" }],
  }),
};
// advisory_lookup_failed comes on a non-2xx (handler.go: 503 on the registry path, 500 on the CPE path).
const LOOKUP_FAILED = { status: 503, body: { error: "advisory lookup failed — this is NOT a clean result", code: "MATCH_ERROR", match_layer: "registry", assessed: false, not_assessed_reason: "advisory_lookup_failed" } };

async function startStub() {
  const state = { answer: cpe({}), requests: [] };
  const server = http.createServer((req, res) => {
    state.requests.push({ url: req.url, headers: { ...req.headers } });
    const a = state.answer;
    const status = a?.status ?? 200;
    res.writeHead(status, { "content-type": "application/json", "cache-control": "private, no-store" });
    res.end(JSON.stringify(a?.status ? a.body : a));
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

const textBlocks = (res) => (res.content ?? []).filter((c) => c.type === "text").map((c) => c.text);
const noteOf = (res) => textBlocks(res)[res.isError ? 0 : 1] ?? "";
const validator = new AjvJsonSchemaValidator();
const COLLECTED = [];

describe(`check_affected against a stub of ${PATH} [${ERA}]`, () => {
  let stub, client, schema, tool;
  const call = async (args, answer) => {
    if (answer !== undefined) stub.state.answer = answer;
    stub.state.requests.length = 0;
    const res = await client.callTool({ name: TOOL, arguments: args });
    COLLECTED.push([args, res]);
    return res;
  };
  // The request the stub saw for one call: exactly one, to the bare path.
  const onlyRequest = () => {
    assert.equal(stub.state.requests.length, 1, `requests: ${JSON.stringify(stub.state.requests.map((r) => r.url))}`);
    return stub.state.requests[0];
  };
  before(async () => {
    stub = await startStub();
    client = await connect({ era: ERA, ...serverCommand(), env: { ...process.env, ECHELONGRAPH_API_BASE: stub.base, ECHELONGRAPH_API_TIMEOUT_MS: "2000" }, stderr: "inherit" });
    const { tools } = await client.listTools();
    tool = tools.find((t) => t.name === TOOL);
    schema = tool?.outputSchema;
  });
  after(async () => {
    try {
      await client?.close();
    } finally {
      await stub?.close();
    }
  });

  it("is listed with a title, the read-only annotations, an object inputSchema and an outputSchema", () => {
    assert.ok(tool, "check_affected is not in tools/list");
    assert.ok(tool.title);
    assert.deepEqual(tool.annotations, { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true });
    assert.equal(tool.inputSchema.type, "object");
    assert.deepEqual(Object.keys(tool.inputSchema.properties).sort(), ["ecosystem", "package", "product", "version"]);
    assert.equal(schema.type, "object");
    // The description says what each path covers, and that undetermined is not safe.
    assert.match(tool.description, /The CPE path takes product/);
    assert.match(tool.description, /The registry path takes ecosystem/);
    assert.match(tool.description, /reported as undetermined \(undetermined_count, and up to 50 of them in undetermined\), never as safe/);
    assert.match(tool.description, /a count of 0 there must never be reported as not affected/);
    assert.match(tool.description, /travel in request headers, never in the URL/);
  });

  describe("header carriage (#1983)", () => {
    it("the CPE path sends product and version in X-EG-Product and X-EG-Version, and the URL carries neither", async () => {
      await call({ product: "openssl", version: "3.0.0" }, withMatches(cpe, [OPENSSL_MATCH]));
      const r = onlyRequest();
      assert.equal(r.url, PATH, "the request URL is not the bare path");
      assert.equal(r.headers[H.product], "openssl");
      assert.equal(r.headers[H.version], "3.0.0");
      assert.equal(r.headers[H.ecosystem], undefined);
      assert.equal(r.headers[H.package], undefined);
      assert.doesNotMatch(r.url, /openssl|3\.0\.0|\?/);
      assert.match(r.headers["user-agent"], /^echelongraph-mcp\//);
    });
    it("the registry path sends ecosystem, package and version in their headers, and the URL carries none of them", async () => {
      await call({ ecosystem: "npm", package: "lodash", version: "4.17.15" }, withMatches(registry, [LODASH_MATCH]));
      const r = onlyRequest();
      assert.equal(r.url, PATH);
      assert.equal(r.headers[H.ecosystem], "npm");
      assert.equal(r.headers[H.package], "lodash");
      assert.equal(r.headers[H.version], "4.17.15");
      assert.equal(r.headers[H.product], undefined);
      assert.doesNotMatch(r.url, /npm|lodash|4\.17\.15|\?/);
    });
    it("values are percent-encoded as the backend decodes them (url.PathUnescape): a scoped package, a + build and non-ASCII survive", async () => {
      const args = { ecosystem: "npm", package: "@scope/pkg", version: "1.0.0+build.5 ü" };
      await call(args, registry({ package: "@scope/pkg", version: "1.0.0+build.5 ü" }));
      const r = onlyRequest();
      assert.equal(r.url, PATH);
      assert.equal(r.headers[H.package], "%40scope%2Fpkg");
      assert.equal(decodeURIComponent(r.headers[H.version]), "1.0.0+build.5 ü");
      assert.equal(decodeURIComponent(r.headers[H.package]), "@scope/pkg");
      assert.doesNotMatch(r.url, /scope|build|%/);
    });
    it("surrounding whitespace is trimmed before it is sent", async () => {
      await call({ product: "  nginx ", version: " 1.20.0\t" }, cpe({ product: "nginx", version: "1.20.0" }));
      const r = onlyRequest();
      assert.equal(r.headers[H.product], "nginx");
      assert.equal(r.headers[H.version], "1.20.0");
    });
  });

  describe("assessed answers", () => {
    it("an assessed CPE hit is measured, AFFECTED, and names the unverified vendor", async () => {
      const res = await call({ product: "openssl", version: "3.0.0" }, withMatches(cpe, [OPENSSL_MATCH]));
      const sc = res.structuredContent;
      assert.notEqual(res.isError, true);
      assert.equal(sc.state, "measured");
      assert.equal(sc.measured_at, null);
      assert.match(sc.method, /CPE matcher/);
      assert.deepEqual(sc.coverage, { assessed: true, not_assessed_reason: null, lookup: "cpe", match_layer: "cpe", count: 1, capped: false, candidates_capped: false, excluded_count: 0, undetermined_count: null, not_affected_count: null, degraded: null });
      assert.deepEqual(Object.keys(sc.coverage).slice(0, 2), ["assessed", "not_assessed_reason"], "assessed and its reason are not first");
      assert.deepEqual(sc.data, JSON.parse(res.content[0].text));
      const n = noteOf(res);
      assert.match(n, /^check_affected OK: EchelonGraph answered HTTP 200 from .* \(state: measured\) assessed: true, so the lookup evaluated product openssl at version 3\.0\.0\. AFFECTED: 1 CVE matches this version\./);
      assert.match(n, /Every match has vendor_unknown true/);
      // Each match keeps what the ticket names, as sent.
      const m = sc.data.matches[0];
      for (const k of ["kev_listed", "ransomware", "epss_score", "effective_score", "effective_severity", "score_assessed"]) assert.deepEqual(m[k], OPENSSL_MATCH[k], k);
    });
    it("KEV-listed and not-yet-scored matches are named in the note", async () => {
      const res = await call({ product: "openssl", version: "3.0.0" }, withMatches(cpe, [KEV_MATCH, UNSCORED_MATCH, OPENSSL_MATCH]));
      const n = noteOf(res);
      assert.match(n, /AFFECTED: 3 CVEs match this version\./);
      assert.match(n, /1 of them is listed in CISA-KEV \(kev_listed\), 1 with known ransomware use\./);
      assert.match(n, /NOT YET SCORED \(score_assessed: false\): CVE-2099-30002; .* means unrated, not harmless\./);
      assert.equal(res.structuredContent.data.matches[1].score_assessed, false);
    });
    it("an assessed registry hit (npm lodash 4.17.15) is measured and returns CVE-2020-8203", async () => {
      const res = await call({ ecosystem: "npm", package: "lodash", version: "4.17.15" }, withMatches(registry, [LODASH_MATCH], { not_affected_count: 4 }));
      const sc = res.structuredContent;
      assert.equal(sc.state, "measured");
      assert.match(sc.method, /registry matcher/);
      assert.equal(sc.coverage.lookup, "registry");
      assert.equal(sc.coverage.match_layer, "registry");
      assert.deepEqual(sc.data.cve_ids, ["CVE-2020-8203"]);
      assert.match(noteOf(res), /evaluated npm package lodash at version 4\.17\.15\. AFFECTED: 1 CVE matches this version\./);
    });
    it("assessed with 0 matches is measured, worded as a measured empty result, and clears only the not_affected advisories", async () => {
      const res = await call({ ecosystem: "npm", package: "lodash", version: "4.17.21" }, registry({ version: "4.17.21", not_affected_count: 10 }));
      const sc = res.structuredContent;
      assert.notEqual(res.isError, true);
      assert.equal(sc.state, "measured");
      assert.equal(sc.coverage.count, 0);
      assert.equal(sc.coverage.not_affected_count, 10);
      const n = noteOf(res);
      assert.match(n, /0 CVEs match this version, a measured result \(we looked and found nothing that matches\), not a lookup failure\./);
      assert.match(n, /10 advisories were decided not to affect this version \(not_affected_count\), and only those are cleared\./);
      assert.doesNotMatch(n, /NOT ASSESSED|AFFECTED:/);
    });
    it("assessed with 0 matches on the CPE path is measured too", async () => {
      const res = await call({ product: "openssl", version: "99.0.0" }, cpe({ version: "99.0.0" }));
      assert.equal(res.structuredContent.state, "measured");
      assert.match(noteOf(res), /0 CVEs match this version, a measured result/);
    });
  });

  describe("not assessed: never clean", () => {
    for (const [reason, answer] of Object.entries(REASONS)) {
      it(`not_assessed_reason ${reason} is state not_assessed, relayed first, and not worded as not affected`, async () => {
        const args = answer.match_layer === "registry" ? { ecosystem: "npm", package: "lodash", version: "4.17.15" } : { product: "openssl", version: "3.0.0" };
        const res = await call(args, answer);
        const sc = res.structuredContent;
        assert.notEqual(res.isError, true, "a lookup that answered is relayed, not failed");
        assert.equal(sc.state, "not_assessed");
        assert.equal(sc.coverage.assessed, false);
        assert.equal(sc.coverage.not_assessed_reason, reason);
        assert.equal(sc.coverage.count, 0);
        const n = noteOf(res);
        assert.match(n, new RegExp(`\\(state: not_assessed\\) NOT ASSESSED: assessed is false for .* \\(not_assessed_reason ${reason}\\): `));
        assert.match(n, /A count of 0 here does not mean this version is not affected: do not report it as unaffected or clean\./);
        assert.doesNotMatch(n, /found nothing|a measured result|are cleared|AFFECTED: \d/);
      });
    }
    it("candidate_load_pending with degraded: true says the answer is incomplete", async () => {
      const res = await call({ product: "openssl", version: "3.0.0" }, REASONS.candidate_load_pending);
      assert.equal(res.structuredContent.coverage.degraded, true);
      assert.match(noteOf(res), /degraded is true: the lookup ran out of time before it finished, so this answer is incomplete\./);
    });
    it("no_decidable_advisory names its undetermined advisories as undetermined, never as safe", async () => {
      const res = await call({ ecosystem: "npm", package: "lodash", version: "4.17.15" }, REASONS.no_decidable_advisory);
      assert.equal(res.structuredContent.coverage.undetermined_count, 2);
      assert.equal(res.structuredContent.data.undetermined.length, 2);
      assert.match(noteOf(res), /UNDETERMINED: 2 advisories name this package .* report them as undetermined, never as safe\./);
    });
    it("a reason this version does not know is still not_assessed, and named", async () => {
      const res = await call({ product: "openssl", version: "3.0.0" }, cpe({ assessed: false, not_assessed_reason: "some_future_reason" }));
      assert.equal(res.structuredContent.state, "not_assessed");
      assert.equal(res.structuredContent.coverage.not_assessed_reason, "some_future_reason");
      assert.match(noteOf(res), /the answer gives not_assessed_reason some_future_reason, which this version of the server does not describe\./);
    });
    it("an answer with no assessed field (an older API) is not_assessed, never measured", async () => {
      const { assessed: _a, not_assessed_reason: _r, ...old } = cpe({});
      const res = await call({ product: "openssl", version: "3.0.0" }, old);
      assert.equal(res.structuredContent.state, "not_assessed");
      assert.equal(res.structuredContent.coverage.assessed, null);
      assert.match(noteOf(res), /carries no assessed field/);
      assert.doesNotMatch(noteOf(res), /found nothing/);
    });
    it("advisory_lookup_failed (HTTP 503) is a failure that says it is not a clean result", async () => {
      const res = await call({ ecosystem: "npm", package: "lodash", version: "4.17.15" }, LOOKUP_FAILED);
      assert.equal(res.isError, true);
      assert.equal(res.structuredContent.state, "failed");
      assert.equal(res.structuredContent.error.status, 503);
      assert.equal(res.structuredContent.error.path, PATH, "the failure quotes a path with a typed value in it");
      assert.match(noteOf(res), /HTTP 503 .* advisory lookup failed — this is NOT a clean result\..*this is not a finding/);
      assert.ok(!("data" in res.structuredContent));
    });
  });

  describe("truncation and undetermined beside matches", () => {
    it("capped: true says the list stopped at its cap", async () => {
      const matches = Array.from({ length: 200 }, (_, i) => ({ ...OPENSSL_MATCH, cve_id: `CVE-2099-${String(40000 + i)}` }));
      const res = await call({ product: "linux_kernel", version: "5.10.0" }, withMatches(cpe, matches, { capped: true, product: "linux_kernel", version: "5.10.0" }));
      assert.equal(res.structuredContent.state, "measured");
      assert.equal(res.structuredContent.coverage.capped, true);
      assert.match(noteOf(res), /AFFECTED: 200 CVEs match this version \(capped: true, so the list stopped at its cap and more may match\)\./);
    });
    it("candidates_capped: true beside matches says more may match than the answer lists", async () => {
      const res = await call({ product: "openssl", version: "3.0.0" }, withMatches(cpe, [OPENSSL_MATCH], { candidates_capped: true, candidate_count: 2000 }));
      assert.equal(res.structuredContent.coverage.candidates_capped, true);
      assert.match(noteOf(res), /candidates_capped is true: not every candidate CVE was loaded, so more CVEs may match than the answer lists\./);
    });
    it("undetermined advisories beside an assessed registry hit are named, not cleared", async () => {
      const res = await call(
        { ecosystem: "npm", package: "lodash", version: "4.17.15" },
        withMatches(registry, [LODASH_MATCH], { undetermined_count: 1, undetermined: [{ cve_id: "CVE-2099-30012", package: "lodash", ecosystem: "npm", reason: "collapsed_fix_boundary" }] }),
      );
      assert.equal(res.structuredContent.state, "measured");
      assert.match(noteOf(res), /UNDETERMINED: 1 advisory names this package .* report it as undetermined, never as safe\./);
    });
    it("excluded_count above 0 is named", async () => {
      const res = await call({ product: "openssl", version: "3.0.0" }, withMatches(cpe, [OPENSSL_MATCH], { excluded_count: 3 }));
      assert.match(noteOf(res), /3 candidate CVEs were suppressed by the vendor or platform gate \(excluded_count, listed in excluded\)\./);
    });
  });

  describe("input refused before any request", () => {
    for (const [args, why] of [
      [{ version: "1.0.0" }, "product, or ecosystem and package, is required"],
      [{ product: "openssl", ecosystem: "npm", version: "1.0.0" }, "give product (the CPE path) or ecosystem and package (the registry path), not both"],
      [{ product: "openssl", package: "lodash", version: "1.0.0" }, "give product (the CPE path) or ecosystem and package (the registry path), not both"],
      [{ package: "lodash", version: "1.0.0" }, "ecosystem is required with package"],
      [{ ecosystem: "npm", version: "1.0.0" }, "package is required with ecosystem"],
      [{ product: "openssl", version: "  " }, "version is required"],
      [{ product: "   ", version: "1.0.0" }, "product, or ecosystem and package, is required"],
    ]) {
      it(`${JSON.stringify(args)} is invalid_input: ${why}`, async () => {
        const res = await call(args);
        assert.equal(res.isError, true);
        assert.equal(res.structuredContent.state, "invalid_input");
        assert.deepEqual(res.structuredContent.error, { kind: "invalid_input", path: null, status: null, message: why });
        assert.deepEqual(stub.state.requests, [], "a refused input reached the API");
      });
    }
    it("the API's 400 is invalid_input, quoting the API's message", async () => {
      const res = await call({ product: "no/slashes", version: "1.0.0" }, { status: 400, body: { error: "product is required (1-64 chars: letters, digits, . _ -). Use the CPE product token, e.g. nginx or linux_kernel.", code: "INVALID_PRODUCT" } });
      assert.equal(res.isError, true);
      assert.equal(res.structuredContent.state, "invalid_input");
      assert.equal(res.structuredContent.error.status, 400);
      assert.match(noteOf(res), /Use the CPE product token/);
      assert.equal(onlyRequest().url, PATH);
    });
  });

  describe("every result validates against the advertised outputSchema (ajv)", () => {
    it("every result this file received validates, and every state was seen", () => {
      const seen = new Set();
      assert.ok(COLLECTED.length >= 25, `only ${COLLECTED.length} results`);
      for (const [args, res] of COLLECTED) {
        const v = validator.getValidator(schema)(res.structuredContent);
        assert.ok(v.valid, `${JSON.stringify(args)}: ${v.errorMessage}\n${JSON.stringify(res.structuredContent).slice(0, 500)}`);
        seen.add(res.structuredContent.state);
        // The text's last block is the envelope less data, so a content-only client sees the state.
        assert.equal(JSON.parse(textBlocks(res).at(-1)).state, res.structuredContent.state);
      }
      assert.deepEqual([...seen].sort(), ["failed", "invalid_input", "measured", "not_assessed"]);
    });
    it("the check can fail: a measured result without data, a not_assessed one with an unknown coverage key, and a bad state are refused", () => {
      const ok = COLLECTED.find(([, r]) => r.structuredContent.state === "measured")[1].structuredContent;
      const na = COLLECTED.find(([, r]) => r.structuredContent.state === "not_assessed")[1].structuredContent;
      const isValid = (v) => validator.getValidator(schema)(v).valid;
      assert.ok(isValid(ok) && isValid(na), "control");
      const { data: _d, ...noData } = ok;
      assert.ok(!isValid(noData));
      assert.ok(!isValid({ ...na, coverage: { ...na.coverage, verdict: "clean" } }));
      assert.ok(!isValid({ ...ok, state: "clean" }));
    });
  });
});
