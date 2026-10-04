// #2719: vendor_advisories_for_cve, get_vendor_advisory and search_vendor_advisories, against
// a stub of core-backend's /api/v1/public/vendor-advisories routes, in both protocol eras.
//
// tools.test.mjs (and tools-legacy.test.mjs) already run the three tools through every shared
// failure and envelope rule (outage, 403, timeout, non-JSON, the envelope text block, ajv over
// every result). This file holds what is specific to them:
//   - the search term travels in X-EG-Advisory-Search ONLY: never in the request URL, and never
//     in a note, an error or the envelope (#1983);
//   - an answer without search_applied true is refused when a term was sent, so an API that
//     ignores the header cannot pass the unsearched list off as the search's matches;
//   - withdrawn, vendor_published_at and our_first_seen_at are relayed, and a withdrawn
//     advisory is named as one;
//   - identifiers that are not identifiers are refused before any request.
// Every structuredContent received is validated against the tool's outputSchema with ajv.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { AjvJsonSchemaValidator } from "@modelcontextprotocol/server/validators/ajv";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { serverCommand } from "./server-under-test.mjs";

const HEADER = "x-eg-advisory-search";
const CVE = "CVE-2024-21412";
const CVE_FULL = "CVE-2024-30000"; // 20 rows: the API's cap
const CVE_NONE = "CVE-2024-30001";
const TERM = "Exchange Server — zz1983term café";
const row = (o = {}) => ({
  advisory_id: "6f1c7d2e-0000-4000-8000-000000000001",
  vendor: "microsoft",
  vendor_display_name: "Microsoft",
  vendor_advisory_id: CVE,
  title: "Internet Shortcut Files Security Feature Bypass Vulnerability",
  severity: "High",
  cvss_v3_score: 8.1,
  vendor_published_at: "2024-02-13T08:00:00Z",
  our_first_seen_at: "2024-02-13T08:41:07Z",
  withdrawn: false,
  ...o,
});
const WITHDRAWN = row({ vendor: "github", vendor_display_name: "GitHub Security Advisories", vendor_advisory_id: "GHSA-aaaa-bbbb-cccc", withdrawn: true });
const DETAIL = {
  ...row({ vendor: "redhat", vendor_display_name: "Red Hat", vendor_advisory_id: "RHSA-2024:1234" }),
  cve_ids: [CVE, "CVE-2024-99999"],
  known_cve_ids: [CVE],
  description: "An update is available.",
  affected_products: ["Red Hat Enterprise Linux 9"],
  remediation: "Update.",
  references: [],
  vendor_modified_at: "",
  withdrawn_at: "",
  withdrawn_reason: "",
};
const DETAIL_WITHDRAWN = { ...DETAIL, vendor_advisory_id: "RHSA-2024:0001", withdrawn: true, withdrawn_at: "2024-03-01T00:00:00Z", withdrawn_reason: "superseded" };

// A stub that records every request's URL and search header, and answers per path.
async function startStub() {
  const state = { seen: [], searchApplied: true };
  const server = http.createServer((req, res) => {
    state.seen.push({ url: req.url, search: req.headers[HEADER] });
    const { pathname, searchParams } = new URL(req.url, "http://stub");
    const send = (status, body) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };
    if (pathname === `/api/v1/public/vendor-advisories/by-cve/${CVE}`) return send(200, { cve_id: CVE, advisories: [row(), WITHDRAWN], total: 2 });
    if (pathname === `/api/v1/public/vendor-advisories/by-cve/${CVE_FULL}`) return send(200, { cve_id: CVE_FULL, advisories: Array.from({ length: 20 }, () => row()), total: 20 });
    if (pathname === `/api/v1/public/vendor-advisories/by-cve/${CVE_NONE}`) return send(200, { cve_id: CVE_NONE, advisories: [], total: 0 });
    if (pathname === "/api/v1/public/vendor-advisories/redhat/RHSA-2024%3A1234") return send(200, DETAIL);
    if (pathname === "/api/v1/public/vendor-advisories/redhat/RHSA-2024%3A0001") return send(200, DETAIL_WITHDRAWN);
    if (pathname === "/api/v1/public/vendor-advisories") {
      const searched = req.headers[HEADER] !== undefined;
      const body = { advisories: [row()], total: 7, limit: Number(searchParams.get("limit")), offset: Number(searchParams.get("offset")) };
      if (state.searchApplied !== undefined) body.search_applied = state.searchApplied === "auto" ? searched : state.searchApplied;
      return send(200, body);
    }
    send(404, { error: "advisory not found" });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { state, base: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((resolve) => server.close(resolve)) };
}

const textOf = (res) => res.content.filter((c) => c.type === "text").map((c) => c.text).join("\n");
const noteOf = (res) => res.content[res.isError ? 0 : 1].text;
const validator = new AjvJsonSchemaValidator();

for (const era of [MODERN, "2025-06-18"]) {
  describe(`#2719 vendor-advisory tools [${era}]`, () => {
    let stub, client, schemas;
    const results = [];
    const call = async (name, args) => {
      const res = await client.callTool({ name, arguments: args });
      results.push([name, args, res]);
      return res;
    };
    before(async () => {
      stub = await startStub();
      client = await connect({ era, ...serverCommand(), env: { ...process.env, ECHELONGRAPH_API_BASE: stub.base, ECHELONGRAPH_API_TIMEOUT_MS: "2000" }, stderr: "inherit" });
      const { tools } = await client.listTools();
      schemas = Object.fromEntries(tools.map((t) => [t.name, t.outputSchema]));
    });
    after(async () => {
      try {
        await client?.close();
      } finally {
        await stub?.close();
      }
    });

    it("tools/list carries the three tools after the five", async () => {
      const { tools } = await client.listTools();
      assert.deepEqual(tools.map((t) => t.name).slice(-3), ["vendor_advisories_for_cve", "get_vendor_advisory", "search_vendor_advisories"]);
    });

    it("search_vendor_advisories sends the term in X-EG-Advisory-Search only, percent-encoded, and never echoes it", async () => {
      stub.state.seen.length = 0;
      stub.state.searchApplied = true;
      const res = await call("search_vendor_advisories", { query: `  ${TERM}  `, vendor: "microsoft", severity: "High", has_cve: true, limit: 5, offset: 10 });
      assert.notEqual(res.isError, true, textOf(res));
      assert.equal(stub.state.seen.length, 1);
      const [{ url, search }] = stub.state.seen;
      assert.equal(url, "/api/v1/public/vendor-advisories?vendor=microsoft&severity=High&has_cve=true&limit=5&offset=10");
      assert.equal(search, encodeURIComponent(TERM), "the header carries the trimmed term, percent-encoded");
      assert.equal(decodeURIComponent(search), TERM);
      for (const piece of ["zz1983term", "Exchange", encodeURIComponent(TERM)]) {
        assert.ok(!url.includes(piece), `the term reached the URL: ${url}`);
        assert.ok(!JSON.stringify(res).includes(piece), `the term was echoed into the result: ${piece}`);
      }
      assert.match(noteOf(res), /^search_vendor_advisories OK: EchelonGraph answered HTTP 200 from .*\. The search matched 7 vendor advisories; 1 returned in this page \(offset 10\)\.$/);
      const sc = res.structuredContent;
      assert.equal(sc.state, "measured");
      assert.equal(sc.measured_at, null);
      assert.deepEqual(sc.coverage, { total: 7, returned: 1, limit: 5, offset: 10, search_applied: true });
      assert.equal(sc.freshness, null);
    });

    it("without a query no search header is sent, and the note says it is the list", async () => {
      stub.state.seen.length = 0;
      stub.state.searchApplied = false;
      for (const query of [undefined, "", "   "]) {
        const res = await call("search_vendor_advisories", query === undefined ? {} : { query });
        assert.notEqual(res.isError, true, textOf(res));
        assert.match(noteOf(res), /The list holds 7 vendor advisories/);
      }
      assert.deepEqual(stub.state.seen.map((s) => s.search), [undefined, undefined, undefined]);
      assert.deepEqual(stub.state.seen.map((s) => s.url), Array(3).fill("/api/v1/public/vendor-advisories?limit=20&offset=0"));
    });

    it("an answer that does not say the search was applied is a failure, and relays none of the list", async () => {
      for (const applied of [false, undefined]) {
        stub.state.searchApplied = applied;
        const res = await call("search_vendor_advisories", { query: TERM });
        assert.equal(res.isError, true, textOf(res));
        assert.equal(res.structuredContent.state, "failed");
        assert.equal(res.structuredContent.error.kind, "unexpected_shape");
        assert.match(textOf(res), /does not say the search was applied/);
        assert.match(textOf(res), /this is not a finding/);
        assert.ok(!("data" in res.structuredContent));
        assert.ok(!JSON.stringify(res).includes("zz1983term"), "the term was echoed into the failure");
      }
      stub.state.searchApplied = true;
    });

    it("refuses a query over the API's 100-byte limit, and a bad vendor slug, with no request made", async () => {
      stub.state.seen.length = 0;
      for (const args of [{ query: "é".repeat(51) }, { vendor: "Micro Soft" }, { vendor: "../x" }]) {
        const res = await call("search_vendor_advisories", args);
        assert.equal(res.isError, true);
        assert.equal(res.structuredContent.state, "invalid_input", JSON.stringify(args));
      }
      assert.deepEqual(stub.state.seen, []);
      // 100 bytes exactly is allowed.
      stub.state.searchApplied = "auto";
      const ok = await call("search_vendor_advisories", { query: "z".repeat(100) });
      assert.notEqual(ok.isError, true, textOf(ok));
      stub.state.searchApplied = true;
    });

    it("vendor_advisories_for_cve relays each row's dates and withdrawn, and names the withdrawn one", async () => {
      const res = await call("vendor_advisories_for_cve", { cve_id: CVE.toLowerCase() });
      assert.notEqual(res.isError, true, textOf(res));
      const data = res.structuredContent.data;
      assert.deepEqual(data, JSON.parse(res.content[0].text));
      assert.equal(data.advisories[0].vendor_published_at, "2024-02-13T08:00:00Z");
      assert.equal(data.advisories[0].our_first_seen_at, "2024-02-13T08:41:07Z");
      assert.equal(data.advisories[1].withdrawn, true);
      const note = noteOf(res);
      assert.match(note, new RegExp(`2 vendor advisories name ${CVE}\\.`));
      assert.match(note, /WITHDRAWN: 1 of these 2 advisories was withdrawn \(rescinded\) by its vendor \(withdrawn true\): github\/GHSA-aaaa-bbbb-cccc\. Report it as withdrawn, not as a current advisory\./);
      assert.deepEqual(res.structuredContent.coverage, { returned: 2, cap: 20, at_cap: false });
      assert.ok(res.structuredContent.notes.some((n) => /our_first_seen_at is when EchelonGraph first recorded it/.test(n)));
    });

    it("vendor_advisories_for_cve says a full answer may not be all, and an empty one is a measured nothing", async () => {
      const full = await call("vendor_advisories_for_cve", { cve_id: CVE_FULL });
      assert.equal(full.structuredContent.coverage.at_cap, true);
      assert.match(noteOf(full), /at most 20 advisories for one CVE, newest first, and this answer is full \(at_cap true\), so there may be more\./);
      const none = await call("vendor_advisories_for_cve", { cve_id: CVE_NONE });
      assert.notEqual(none.isError, true);
      assert.match(noteOf(none), /found nothing/);
      assert.match(noteOf(none), /not a lookup failure/);
      assert.match(noteOf(none), /Only the vendor feeds EchelonGraph polls are covered/);
    });

    it("vendor_advisories_for_cve refuses what is not a CVE ID, with no request made", async () => {
      stub.state.seen.length = 0;
      for (const cve_id of ["", "  ", "exchange server", "CVE-24-1", "CVE-2024-1234/../../x"]) {
        const res = await call("vendor_advisories_for_cve", { cve_id });
        assert.equal(res.structuredContent.state, "invalid_input", cve_id);
      }
      assert.deepEqual(stub.state.seen, []);
    });

    it("get_vendor_advisory: measured_at is our_first_seen_at, the CVE split is named, and a withdrawn advisory is named as one", async () => {
      const res = await call("get_vendor_advisory", { vendor: "redhat", advisory_id: "RHSA-2024:1234" });
      assert.notEqual(res.isError, true, textOf(res));
      const sc = res.structuredContent;
      assert.equal(sc.measured_at, "2024-02-13T08:41:07Z");
      assert.equal(sc.data.vendor_published_at, "2024-02-13T08:00:00Z");
      assert.equal(sc.data.withdrawn, false);
      assert.match(noteOf(res), /Returned the advisory redhat\/RHSA-2024:1234\./);
      assert.match(noteOf(res), /Of the 2 CVE IDs it lists \(cve_ids\), 1 has a record in EchelonGraph's CVE feed \(known_cve_ids\)/);
      assert.doesNotMatch(noteOf(res), /WITHDRAWN/);
      const w = await call("get_vendor_advisory", { vendor: "redhat", advisory_id: "RHSA-2024:0001" });
      assert.match(noteOf(w), /WITHDRAWN: the vendor withdrew \(rescinded\) redhat\/RHSA-2024:0001 \(withdrawn true, withdrawn_at 2024-03-01T00:00:00Z\)\. Report it as withdrawn/);
    });

    it("get_vendor_advisory: the API's 404 is a failure quoting it; bad identifiers are refused before any request", async () => {
      const miss = await call("get_vendor_advisory", { vendor: "redhat", advisory_id: "RHSA-2099:0000" });
      assert.equal(miss.isError, true);
      assert.match(textOf(miss), /HTTP 404.*advisory not found/);
      stub.state.seen.length = 0;
      for (const args of [
        { vendor: "", advisory_id: "x" },
        { vendor: "Red Hat", advisory_id: "x" },
        { vendor: "redhat", advisory_id: "" },
        { vendor: "redhat", advisory_id: "a\nb" },
        { vendor: "redhat", advisory_id: "x".repeat(201) },
      ]) {
        const res = await call("get_vendor_advisory", args);
        assert.equal(res.structuredContent.state, "invalid_input", JSON.stringify(args));
      }
      assert.deepEqual(stub.state.seen, []);
    });

    it("every structuredContent received validates against its tool's outputSchema (ajv)", () => {
      assert.ok(results.length >= 25, `only ${results.length} results`);
      const states = new Set();
      for (const [name, args, res] of results) {
        states.add(res.structuredContent.state);
        const v = validator.getValidator(schemas[name])(res.structuredContent);
        assert.ok(v.valid, `${name}(${JSON.stringify(args)}): ${v.errorMessage}`);
      }
      assert.deepEqual([...states].sort(), ["failed", "invalid_input", "measured"]);
    });
  });
}
