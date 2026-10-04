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
//   - identifiers that are not identifiers are refused before any request;
//   - #2729: each vendor's window (GET /vendor-advisories/coverage) is relayed in coverage, and
//     the note names the vendors whose window starts after the CVE's year began, or whose history
//     is still being read, so no advisory from them is never read as "the vendor published none";
//     windows that cannot be read leave the answer measured, with the windows null and said so;
//   - #2728: a 1- or 2-character search is whole words (search_match word), said in the note and
//     the description, and a capped total is written 1,000+, never as an exact 1000.
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

// #2729: GET /api/v1/public/vendor-advisories/coverage as core-backend's CoverageHandler writes it
// (vendors by slug; "" for a date that does not exist), in production's shape on 2026-10-04 before
// the backfill finished: Palo Alto held only from 2026-09-09, Microsoft's history being read, Cisco
// holding nothing.
const COVERAGE_PATH = "/api/v1/public/vendor-advisories/coverage";
const win = (vendor, vendor_display_name, advisories, earliest, latest, history_backfill, history_units_done = 0) => ({
  vendor, vendor_display_name, advisories, earliest_vendor_published_at: earliest, latest_vendor_published_at: latest, history_backfill, history_units_done, history_completed_at: "",
});
const COVERAGE = {
  vendors: [
    win("cisco", "Cisco", 0, "", "", "not_supported"),
    win("github", "GitHub Security Advisories", 21877, "2017-10-24T00:00:00Z", "2026-10-04T05:00:00Z", "not_supported"),
    win("microsoft", "Microsoft", 1311, "2016-01-12T08:00:00Z", "2026-09-30T07:00:00Z", "in_progress", 112),
    win("paloalto", "Palo Alto Networks", 71, "2026-09-09T16:00:00Z", "2026-10-02T21:00:00Z", "not_started"),
    win("redhat", "Red Hat", 18420, "2001-03-29T00:00:00Z", "2026-10-04T04:00:00Z", "not_supported"),
  ],
};
// What the tools relay for a window: the API's row less the backfill bookkeeping, "" as null.
const relayed = (w) => ({
  vendor: w.vendor,
  vendor_display_name: w.vendor_display_name,
  advisories: w.advisories,
  earliest_vendor_published_at: w.earliest_vendor_published_at || null,
  latest_vendor_published_at: w.latest_vendor_published_at || null,
  history_backfill: w.history_backfill,
});
const CVE_3400 = "CVE-2024-3400"; // KEV; Palo Alto's own advisory is dated 2024-04-12
const CVE_OLD = "CVE-2010-0249"; // older than Microsoft's earliest held advisory

// A stub that records every request's URL and search header, and answers per path.
async function startStub() {
  // coverage: the /coverage answer, or { status, body } for a failure. list: overrides of the list's body.
  const state = { seen: [], searchApplied: true, coverage: COVERAGE, list: {} };
  const server = http.createServer((req, res) => {
    state.seen.push({ url: req.url, search: req.headers[HEADER] });
    const { pathname, searchParams } = new URL(req.url, "http://stub");
    const send = (status, body) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };
    if (pathname === COVERAGE_PATH) return state.coverage.status ? send(state.coverage.status, state.coverage.body) : send(200, state.coverage);
    if (pathname === `/api/v1/public/vendor-advisories/by-cve/${CVE}`) return send(200, { cve_id: CVE, advisories: [row(), WITHDRAWN], total: 2 });
    for (const empty of [CVE_3400, CVE_OLD]) if (pathname === `/api/v1/public/vendor-advisories/by-cve/${empty}`) return send(200, { cve_id: empty, advisories: [], total: 0 });
    if (pathname === `/api/v1/public/vendor-advisories/by-cve/${CVE_FULL}`) return send(200, { cve_id: CVE_FULL, advisories: Array.from({ length: 20 }, () => row()), total: 20 });
    if (pathname === `/api/v1/public/vendor-advisories/by-cve/${CVE_NONE}`) return send(200, { cve_id: CVE_NONE, advisories: [], total: 0 });
    if (pathname === "/api/v1/public/vendor-advisories/redhat/RHSA-2024%3A1234") return send(200, DETAIL);
    if (pathname === "/api/v1/public/vendor-advisories/redhat/RHSA-2024%3A0001") return send(200, DETAIL_WITHDRAWN);
    if (pathname === "/api/v1/public/vendor-advisories") {
      const searched = req.headers[HEADER] !== undefined;
      const body = { advisories: [row()], total: 7, limit: Number(searchParams.get("limit")), offset: Number(searchParams.get("offset")) };
      if (state.searchApplied !== undefined) body.search_applied = state.searchApplied === "auto" ? searched : state.searchApplied;
      return send(200, { ...body, ...state.list });
    }
    send(404, { error: "advisory not found" });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { state, base: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((resolve) => server.close(resolve)) };
}

const textOf = (res) => res.content.filter((c) => c.type === "text").map((c) => c.text).join("\n");
const noteOf = (res) => res.content[res.isError ? 0 : 1].text;
// The requests other than the windows' read, and the windows' reads.
const mainRequests = (seen) => seen.filter((s) => s.url !== COVERAGE_PATH);
const coverageRequests = (seen) => seen.filter((s) => s.url === COVERAGE_PATH);
// The sentence the list and the search add for the fixture's two vendors still being read.
const BACKFILLING_NOTE =
  "The older advisories of 2 vendors are still being read (history_backfill in_progress or not_started): microsoft (held from 2016-01-12 to 2026-09-30; history_backfill in_progress); paloalto (held from 2026-09-09 to 2026-10-02; history_backfill not_started). EchelonGraph does not yet hold all of their older advisories, so none found from them is not a finding that they published none.";
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
      assert.equal(mainRequests(stub.state.seen).length, 1);
      const [{ url, search }] = mainRequests(stub.state.seen);
      // #2729: the windows' read carries nothing typed: a fixed path, no search header.
      assert.deepEqual(coverageRequests(stub.state.seen), [{ url: COVERAGE_PATH, search: undefined }]);
      assert.equal(url, "/api/v1/public/vendor-advisories?vendor=microsoft&severity=High&has_cve=true&limit=5&offset=10");
      assert.equal(search, encodeURIComponent(TERM), "the header carries the trimmed term, percent-encoded");
      assert.equal(decodeURIComponent(search), TERM);
      for (const piece of ["zz1983term", "Exchange", encodeURIComponent(TERM)]) {
        assert.ok(!url.includes(piece), `the term reached the URL: ${url}`);
        assert.ok(!JSON.stringify(res).includes(piece), `the term was echoed into the result: ${piece}`);
      }
      // With a vendor filter, the windows are that vendor's: Microsoft's history is being read.
      const msft = "The older advisories of 1 vendor are still being read (history_backfill in_progress or not_started): microsoft (held from 2016-01-12 to 2026-09-30; history_backfill in_progress). EchelonGraph does not yet hold all of its older advisories, so none found from it is not a finding that it published none.";
      assert.equal(noteOf(res), `search_vendor_advisories OK: EchelonGraph answered HTTP 200 from ${stub.base}. The search matched 7 vendor advisories; 1 returned in this page (offset 10). ${msft}`);
      const sc = res.structuredContent;
      assert.equal(sc.state, "measured");
      assert.equal(sc.measured_at, null);
      assert.deepEqual(sc.coverage, { total: 7, total_capped: null, returned: 1, limit: 5, offset: 10, search_applied: true, search_match: null, vendor_windows: [relayed(COVERAGE.vendors[2])] });
      assert.equal(sc.freshness, null);
    });

    it("without a query no search header is sent, and the note says it is the list", async () => {
      stub.state.seen.length = 0;
      stub.state.searchApplied = false;
      for (const query of [undefined, "", "   "]) {
        const res = await call("search_vendor_advisories", query === undefined ? {} : { query });
        assert.notEqual(res.isError, true, textOf(res));
        assert.match(noteOf(res), /The list holds 7 vendor advisories/);
        // Unfiltered: every vendor's window, and the two being read named.
        assert.deepEqual(res.structuredContent.coverage.vendor_windows, COVERAGE.vendors.map(relayed));
        assert.ok(noteOf(res).endsWith(` ${BACKFILLING_NOTE}`), noteOf(res));
      }
      assert.deepEqual(stub.state.seen.map((s) => s.search), Array(6).fill(undefined));
      assert.deepEqual(mainRequests(stub.state.seen).map((s) => s.url), Array(3).fill("/api/v1/public/vendor-advisories?limit=20&offset=0"));
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
      // #2729: Microsoft and GitHub answered; Cisco holds nothing and Palo Alto only from 2026-09-09.
      assert.deepEqual(res.structuredContent.coverage, {
        returned: 2,
        cap: 20,
        at_cap: false,
        cve_year: 2024,
        vendor_windows: COVERAGE.vendors.map(relayed),
        vendors_not_fully_held: ["cisco", "paloalto"],
      });
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

    // ── #2729: what is held of each vendor ──
    it("#2729: CVE-2024-3400 with Palo Alto held only from 2026-09-09: the empty answer names Palo Alto's window, and none here is not a finding", async () => {
      const res = await call("vendor_advisories_for_cve", { cve_id: CVE_3400 });
      assert.notEqual(res.isError, true, textOf(res));
      const sc = res.structuredContent;
      assert.equal(sc.state, "measured");
      assert.deepEqual(sc.coverage.vendor_windows, COVERAGE.vendors.map(relayed));
      // Cisco holds nothing, Microsoft's history is being read, Palo Alto starts after 2024 began;
      // GitHub (2017) and Red Hat (2001) start before it.
      assert.deepEqual(sc.coverage.vendors_not_fully_held, ["cisco", "microsoft", "paloalto"]);
      const note = noteOf(res);
      assert.match(note, /found nothing/, "still the measured empty result");
      assert.ok(
        note.endsWith(
          ` ${CVE_3400} is a 2024 CVE ID, and EchelonGraph may not hold every advisory 3 vendors published for it (vendors_not_fully_held): cisco (none held); microsoft (held from 2016-01-12 to 2026-09-30; history_backfill in_progress); paloalto (held only from 2026-09-09 to 2026-10-02; history_backfill not_started). An advisory a vendor published before the earliest one EchelonGraph holds is not held, and while history_backfill is in_progress or not_started the vendor's older advisories are still being read, so no advisory here from those vendors is not a finding that they published none.`,
        ),
        note,
      );
    });

    it("#2729: once Palo Alto's history is read back to 2012, CVE-2024-3400 no longer names it, and a 2010 CVE names every vendor that starts after 2010 began", async () => {
      stub.state.coverage = {
        vendors: COVERAGE.vendors.map((w) =>
          w.vendor === "paloalto" ? { ...w, advisories: 573, earliest_vendor_published_at: "2012-04-27T00:00:00Z", history_backfill: "complete" } : w.vendor === "microsoft" ? { ...w, history_backfill: "complete" } : w,
        ),
      };
      try {
        const now = await call("vendor_advisories_for_cve", { cve_id: CVE_3400 });
        assert.deepEqual(now.structuredContent.coverage.vendors_not_fully_held, ["cisco"]);
        assert.doesNotMatch(noteOf(now), /paloalto|microsoft/);
        const old = await call("vendor_advisories_for_cve", { cve_id: CVE_OLD });
        assert.deepEqual(old.structuredContent.coverage.vendors_not_fully_held, ["cisco", "github", "microsoft", "paloalto"]);
        assert.equal(old.structuredContent.coverage.cve_year, 2010);
        assert.ok(noteOf(old).includes("; paloalto (held only from 2012-04-27 to 2026-10-02)."), noteOf(old));
        assert.doesNotMatch(noteOf(old), /redhat/, "Red Hat's held advisories start in 2001");
      } finally {
        stub.state.coverage = COVERAGE;
      }
    });

    it("#2729: windows that cannot be read leave every answer measured, with the windows null and a note that says so", async () => {
      for (const [coverage, why] of [
        [{ status: 404, body: { error: "not found" } }, /\(EchelonGraph answered HTTP 404 from .* for GET \/api\/v1\/public\/vendor-advisories\/coverage — the API said: not found\)/],
        [{ status: 500, body: { error: "coverage query failed" } }, /HTTP 500 .* the API said: coverage query failed\)/],
        [{ windows: [] }, /\(the answer of GET \/api\/v1\/public\/vendor-advisories\/coverage carries no vendors list\)/],
      ]) {
        stub.state.coverage = coverage;
        try {
          const res = await call("vendor_advisories_for_cve", { cve_id: CVE_3400 });
          assert.notEqual(res.isError, true, textOf(res));
          assert.equal(res.structuredContent.state, "measured");
          assert.equal(res.structuredContent.coverage.vendor_windows, null);
          assert.equal(res.structuredContent.coverage.vendors_not_fully_held, null);
          assert.match(noteOf(res), why);
          assert.match(noteOf(res), /The vendors' coverage windows could not be read \(.*\), so this answer cannot say from what date each vendor's advisories are held: no advisory here from a vendor is not a finding that it published none\.$/);
          const s = await call("search_vendor_advisories", {});
          assert.notEqual(s.isError, true, textOf(s));
          assert.equal(s.structuredContent.coverage.vendor_windows, null);
          assert.match(noteOf(s), why);
          const d = await call("get_vendor_advisory", { vendor: "redhat", advisory_id: "RHSA-2024:1234" });
          assert.notEqual(d.isError, true, textOf(d));
          assert.deepEqual(d.structuredContent.coverage, { vendor_window: null });
          assert.match(noteOf(d), why);
        } finally {
          stub.state.coverage = COVERAGE;
        }
      }
    });

    it("#2729: get_vendor_advisory carries its vendor's window, and says when that vendor's history is still being read", async () => {
      const res = await call("get_vendor_advisory", { vendor: "redhat", advisory_id: "RHSA-2024:1234" });
      assert.deepEqual(res.structuredContent.coverage, { vendor_window: relayed(COVERAGE.vendors[4]) });
      assert.doesNotMatch(noteOf(res), /still being read/);
      stub.state.coverage = { vendors: COVERAGE.vendors.map((w) => (w.vendor === "redhat" ? { ...w, history_backfill: "in_progress" } : w)) };
      try {
        const b = await call("get_vendor_advisory", { vendor: "redhat", advisory_id: "RHSA-2024:1234" });
        assert.ok(
          noteOf(b).endsWith(
            " The older advisories of 1 vendor are still being read (history_backfill in_progress or not_started): redhat (held from 2001-03-29 to 2026-10-04; history_backfill in_progress). EchelonGraph does not yet hold all of its older advisories, so none found from it is not a finding that it published none.",
          ),
          noteOf(b),
        );
      } finally {
        stub.state.coverage = COVERAGE;
      }
    });

    it("#2729: a history_backfill value the API adds later is relayed as sent, not refused", async () => {
      stub.state.coverage = { vendors: [win("redhat", "Red Hat", 1, "2001-03-29T00:00:00Z", "2026-10-04T04:00:00Z", "paused")] };
      try {
        const res = await call("get_vendor_advisory", { vendor: "redhat", advisory_id: "RHSA-2024:1234" });
        assert.notEqual(res.isError, true, textOf(res));
        assert.equal(res.structuredContent.coverage.vendor_window.history_backfill, "paused");
      } finally {
        stub.state.coverage = COVERAGE;
      }
    });

    // ── #2728: how a search matched, and its capped total ──
    it("#2728: a 1- or 2-character query: search_match word in coverage, and the note says whole words only, without the query", async () => {
      stub.state.list = { search_match: "word", total_capped: false };
      try {
        const res = await call("search_vendor_advisories", { query: "zq" });
        assert.notEqual(res.isError, true, textOf(res));
        assert.deepEqual([res.structuredContent.coverage.search_match, res.structuredContent.coverage.total_capped], ["word", false]);
        assert.ok(
          noteOf(res).includes(
            "The search matched 7 vendor advisories; 1 returned in this page (offset 0). The query is 1 or 2 characters, so it matched whole words only (search_match word): an advisory matches when the query equals, ignoring case, a whole word (a run of letters and digits) of its title, description, vendor_advisory_id, an affected product, a CVE ID or its vendor's name, never part of a longer word.",
          ),
          noteOf(res),
        );
        assert.ok(!JSON.stringify(res).includes("zq"), "the query was echoed into the result");
        stub.state.list = { search_match: "substring", total_capped: false };
        const long = await call("search_vendor_advisories", { query: "exchange" });
        assert.equal(long.structuredContent.coverage.search_match, "substring");
        assert.doesNotMatch(noteOf(long), /whole word/);
      } finally {
        stub.state.list = {};
      }
    });

    it("#2728: a capped total is written 1,000+, never as an exact 1000", async () => {
      stub.state.list = { total: 1000, total_capped: true, search_match: "substring" };
      try {
        const res = await call("search_vendor_advisories", { query: "CVE-2024" });
        assert.notEqual(res.isError, true, textOf(res));
        const note = noteOf(res);
        assert.ok(
          note.includes(
            "The search matched 1,000+ vendor advisories (total_capped true: the API stops counting a search's matches at 1,000, so total is a lower bound, not the count; paging past it still works); 1 returned in this page (offset 0).",
          ),
          note,
        );
        assert.doesNotMatch(note, /\b1000\b|matched 1,000 vendor/, "the capped total was written as a count");
        assert.deepEqual([res.structuredContent.coverage.total, res.structuredContent.coverage.total_capped], [1000, true]);
        // An uncapped total of the same size is a count, and is written as one.
        stub.state.list = { total: 1000, total_capped: false, search_match: "substring" };
        assert.match(noteOf(await call("search_vendor_advisories", { query: "CVE-2024" })), /The search matched 1000 vendor advisories;/);
      } finally {
        stub.state.list = {};
      }
    });

    it("#2728, #2729: the descriptions state the whole-word rule, the 1,000+ cap and each vendor's window", async () => {
      const { tools } = await client.listTools();
      const d = (n) => tools.find((t) => t.name === n).description;
      assert.ok(d("search_vendor_advisories").includes("A query of 1 or 2 characters matches whole words only (search_match word)"), d("search_vendor_advisories"));
      assert.ok(d("search_vendor_advisories").includes("past that, total is 1000 and total_capped is true, which means 1,000 or more (the note writes 1,000+), never exactly 1,000"));
      for (const n of ["vendor_advisories_for_cve", "search_vendor_advisories", "get_vendor_advisory"]) {
        for (const f of ["earliest_vendor_published_at", "latest_vendor_published_at", "history_backfill", "in_progress", "not_started"]) assert.ok(d(n).includes(f), `${n}: ${f}`);
      }
      assert.ok(d("vendor_advisories_for_cve").includes("vendors_not_fully_held"));
      for (const n of ["vendor_advisories_for_cve", "search_vendor_advisories"]) {
        assert.ok(d(n).includes("An advisory a vendor published before its earliest_vendor_published_at is not held, so no advisory from a vendor is not a finding that it published none."), n);
      }
    });

    it("#2729: the description never reads an empty answer as the vendors having published none", async () => {
      // "an empty answer means none of those names the CVE" was #2729's misreading in the tool's own
      // words: Palo Alto's feed does name CVE-2024-3400; EchelonGraph did not hold that advisory.
      const { tools } = await client.listTools();
      const d = tools.find((t) => t.name === "vendor_advisories_for_cve").description;
      const means = [...d.matchAll(/empty answer means[^.]*\./gi)].map((m) => m[0]);
      assert.ok(means.length >= 1, `the description no longer says what an empty answer means: ${d}`);
      for (const s of means) {
        assert.ok(s.includes("the advisories EchelonGraph holds") && s.includes("not that no vendor published one"), `an empty answer is read as the vendors publishing none: "${s}"`);
      }
      // Every reason a vendor is listed in vendors_not_fully_held, as notFullyHeld() lists it.
      for (const why of ["of which EchelonGraph holds none", "whose earliest held advisory is dated after 1 January of cve_year", "whose history is still being read"]) {
        assert.ok(d.includes(why), `vendors_not_fully_held: ${why}`);
      }
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
