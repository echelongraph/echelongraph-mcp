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
//   - #2803: a window starts at held_since, never at the earliest held advisory: a vendor with no
//     history read (Cisco, Red Hat) holds old advisories it revised lately, years before the date
//     it is held from without a gap, and is still listed in vendors_not_fully_held;
//   - #2728: a 1- or 2-character search is whole words (search_match word), said in the note and
//     the description, and a capped total is written 1,000+, never as an exact 1000.
// Every structuredContent received is validated against the tool's outputSchema with ajv.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
// #3121: answers are validated against the closed success branch (strict-output.mjs).
import { StrictOutputValidator } from "./strict-output.mjs";
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
// #2865: CVE-2026-7936, rejected at CVE.org while MSRC's entry reads as a normal advisory.
const CVE_REJ = "CVE-2026-7936";
const CVE_LIVE = "CVE-2026-7937";
const CVE_UNCHECKED = "CVE-2026-7938";
const REJ_ROW = row({ vendor_advisory_id: CVE_REJ, title: "Chromium: CVE-2026-7936 Object lifecycle issue in V8", rejected_cve_ids: [CVE_REJ] });
// A Red Hat erratum naming the rejected CVE and another rejected one.
const REJ_MULTI = row({ vendor: "redhat", vendor_display_name: "Red Hat", vendor_advisory_id: "RHSA-2026:0099", cve_ids: [CVE_REJ, "CVE-2026-0001", "CVE-2024-21412"], rejected_cve_ids: [CVE_REJ, "CVE-2026-0001"] });
const DETAIL_REJ = {
  ...DETAIL,
  vendor_advisory_id: "RHSA-2026:0100",
  cve_ids: ["CVE-2024-21412", "CVE-2026-0001"],
  known_cve_ids: ["CVE-2024-21412"],
  rejected_cve_ids: ["CVE-2026-0001"],
};

// #2729: GET /api/v1/public/vendor-advisories/coverage as core-backend's CoverageHandler writes it
// (vendors by slug; "" for a date that does not exist), in production's shape on 2026-10-04 before
// the backfill finished: Palo Alto held only from 2026-09-09, Microsoft's history being read, Cisco
// holding nothing. #2803: held_since as coverage.go heldSince derives it: GitHub's and Red Hat's
// first polls read their last 7 days (first seen less 7 days), Microsoft's first poll, Palo Alto's
// whole feed (its earliest held). GitHub's 2017 and Red Hat's 2001 advisories are ones the vendor
// revised after those first polls, not the start of a window.
const COVERAGE_PATH = "/api/v1/public/vendor-advisories/coverage";
const win = (vendor, vendor_display_name, advisories, earliest, latest, history_backfill, history_units_done = 0, held_since = earliest) => ({
  vendor, vendor_display_name, advisories, earliest_vendor_published_at: earliest, latest_vendor_published_at: latest, held_since, history_backfill, history_units_done, history_completed_at: "",
});
const COVERAGE = {
  vendors: [
    win("cisco", "Cisco", 0, "", "", "not_supported"),
    win("github", "GitHub Security Advisories", 21877, "2017-10-24T00:00:00Z", "2026-10-04T05:00:00Z", "not_supported", 0, "2026-05-14T09:00:00Z"),
    win("microsoft", "Microsoft", 1311, "2016-01-12T08:00:00Z", "2026-09-30T07:00:00Z", "in_progress", 112, "2026-05-20T10:00:00Z"),
    win("paloalto", "Palo Alto Networks", 71, "2026-09-09T16:00:00Z", "2026-10-02T21:00:00Z", "not_started"),
    win("redhat", "Red Hat", 18420, "2001-03-29T00:00:00Z", "2026-10-04T04:00:00Z", "not_supported", 0, "2026-05-19T11:00:00Z"),
  ],
};
// What the tools relay for a window: the API's row less the backfill bookkeeping, "" as null.
const relayed = (w) => ({
  vendor: w.vendor,
  vendor_display_name: w.vendor_display_name,
  advisories: w.advisories,
  earliest_vendor_published_at: w.earliest_vendor_published_at || null,
  latest_vendor_published_at: w.latest_vendor_published_at || null,
  held_since: w.held_since || null,
  feed_held_since: w.feed_held_since || null,
  history_backfill: w.history_backfill,
  history_scope: w.history_scope || null,
  // #3464: null where the API's row does not carry them (an API older than the fields).
  last_success_at: w.last_success_at || null,
  collection_state: w.collection_state || null,
  failing_since: w.failing_since || null,
  held_back: w.held_back ?? null,
  held_back_since: w.held_back_since || null,
});
// #2803: production's Cisco and Red Hat on 2026-10-04, as the API served them before held_since:
// Cisco's continuous run starts 2026-02-25, its three earlier advisories revised later (the
// earliest cisco-sa-asaftdvirtual-dos-MuenGnYR, 2024-10-23); Red Hat's earliest held 2009-02-04.
const CVE_20188 = "CVE-2025-20188"; // Cisco published cisco-sa-wlc-file-uplpd-rHZG9UfC on 2025-05-07
const CVE_HEARTBLEED = "CVE-2014-0160";
const CISCO_REVISED = win("cisco", "Cisco PSIRT openVuln", 312, "2024-10-23T16:00:00Z", "2026-10-01T16:00:00Z", "not_supported", 0, "2026-02-25T09:00:00Z");
const REDHAT_REVISED = win("redhat", "Red Hat Product Security", 9120, "2009-02-04T00:00:00Z", "2026-10-04T04:00:00Z", "not_supported", 0, "2026-05-19T11:00:00Z");
const CVE_3400 = "CVE-2024-3400"; // KEV; Palo Alto's own advisory is dated 2024-04-12
// #3011: a row's advisory_id (EchelonGraph's UUID) and the detail of the same advisory by the vendor's
// own ID; and a vendor whose own advisory ID has a UUID's shape, which must still be looked up.
const ROW_UUID = row().advisory_id;
const DETAIL_BY_VENDOR_ID = { ...row(), cve_ids: [CVE], known_cve_ids: [CVE], description: "A security feature bypass.", affected_products: ["Windows 11"], remediation: "Install the update.", references: [] };
const UUID_SHAPED_VENDOR_ID = "0f8fad5b-d9cb-469f-a165-70867728950e";
const DETAIL_UUID_SHAPED = { ...DETAIL, advisory_id: "6f1c7d2e-0000-4000-8000-0000000000aa", vendor: "gitlab", vendor_display_name: "GitLab", vendor_advisory_id: UUID_SHAPED_VENDOR_ID };
const CVE_OLD = "CVE-2010-0249"; // older than Microsoft's earliest held advisory
// #3472: GitHub's row once its reviewed-only history read is done, as production's coverage answered
// it on 2026-11-07 (advisories, the earliest, held_since, history_backfill, history_scope and
// feed_held_since; latest_vendor_published_at and the history bookkeeping are the stub's):
// reviewed advisories held from 2017-10-24, unreviewed ones only from the feed's start, 2026-05-15.
// Beside it, a vendor whose read covers all (history_scope all) and one from an API without the
// two fields, both complete.
const GITHUB_REVIEWED = {
  ...win("github", "GitHub Security Advisories", 99802, "2017-10-24T18:33:35Z", "2026-11-06T22:10:00Z", "complete_reviewed_only", 110, "2017-10-24T18:33:35Z"),
  history_completed_at: "2026-11-05T03:00:00Z",
  feed_held_since: "2026-05-15T08:09:51Z",
  history_scope: "reviewed",
};
const MSFT_ALL = {
  ...win("microsoft", "Microsoft", 1311, "2016-01-12T08:00:00Z", "2026-09-30T07:00:00Z", "complete", 193),
  history_completed_at: "2026-10-04T08:00:00Z",
  feed_held_since: "2026-05-20T10:00:00Z",
  history_scope: "all",
};
const PALOALTO_DONE = { ...win("paloalto", "Palo Alto Networks", 573, "2012-04-27T00:00:00Z", "2026-10-02T21:00:00Z", "complete", 6), history_completed_at: "2026-10-04T09:00:00Z" };
const CVE_2021 = "CVE-2021-30001"; // a 2021 CVE ID no held advisory names (the stub answers none)
const CVE_2026 = "CVE-2026-30001"; // its year begins 2026-01-01, before GitHub's feed_held_since
const CVE_2027 = "CVE-2027-30001"; // its year begins after GitHub's feed_held_since
const DETAIL_GHSA = {
  ...DETAIL,
  advisory_id: "6f1c7d2e-0000-4000-8000-0000000000bb",
  vendor: "github",
  vendor_display_name: "GitHub Security Advisories",
  vendor_advisory_id: "GHSA-jfh8-c2jp-5v3q",
  cve_ids: ["CVE-2021-44228"],
  known_cve_ids: ["CVE-2021-44228"],
};
// The item and the rule the by-CVE note gives for GitHub's row.
const GITHUB_ITEM = "github (reviewed advisories held from 2017-10-24 to 2026-11-06; unreviewed advisories held only from 2026-05-15)";
const PART_RULE =
  "An advisory a vendor published before the date EchelonGraph holds that vendor from (held_since) may not be held, even when an older one is, an advisory outside the part of a vendor's advisories its history read covers (history_scope reviewed) may not be held when published before that vendor's feed_held_since, and while history_backfill is in_progress or not_started the vendor's older advisories are still being read, so no advisory here from that vendor is not a finding that it published none.";

// #3464: each vendor's collection state, as core-backend's CoverageHandler serves it (feed_state.go
// feedState). CISCO_FAILING is docs/api/openapi.yaml's example row: production's Cisco from
// 2026-10-12, every poll refused, while its window read "held to 2026-10-07". The others are Palo
// Alto's complete history (held from 2012) in each state, so it is listed for CVE-2024-3400 only for
// its collection_state.
const collected = (w, collection_state, o = {}) => ({ ...w, last_success_at: "2026-11-08T14:29:54Z", collection_state, failing_since: "", held_back: 0, held_back_since: "", ...o });
const CISCO_FAILING = {
  vendor: "cisco",
  vendor_display_name: "Cisco PSIRT",
  advisories: 189,
  earliest_vendor_published_at: "2024-10-23T16:00:00Z",
  latest_vendor_published_at: "2026-10-07T16:00:00Z",
  held_since: "2026-02-21T21:15:03Z",
  feed_held_since: "2026-02-21T21:15:03Z",
  history_backfill: "not_supported",
  history_scope: "",
  history_units_done: 0,
  history_completed_at: "",
  last_success_at: "2026-10-12T12:22:49Z",
  collection_state: "failing",
  failing_since: "2026-10-12T12:22:49Z",
  held_back: 0,
  held_back_since: "",
};
const PALOALTO_OK = collected(PALOALTO_DONE, "ok");
const PALOALTO_FAILING = collected(PALOALTO_DONE, "failing", { last_success_at: "2026-10-12T12:22:49Z", failing_since: "2026-10-12T12:22:49Z" });
// An API that sends last_success_at and not failing_since for a failing vendor is read the same.
const PALOALTO_FAILING_NO_SINCE = collected(PALOALTO_DONE, "failing", { last_success_at: "2026-10-12T12:22:49Z" });
const PALOALTO_NEVER = collected(PALOALTO_DONE, "failing", { last_success_at: "" });
const PALOALTO_PARTIAL = collected(PALOALTO_DONE, "partial", { held_back: 3, held_back_since: "2026-11-07T01:00:00Z" });
const PALOALTO_PARTIAL_ONE = collected(PALOALTO_DONE, "partial", { held_back: 1, held_back_since: "2026-11-07T01:00:00Z" });
const PALOALTO_DISABLED = collected(PALOALTO_DONE, "disabled", { last_success_at: "2026-10-20T06:00:00Z" });
const PALOALTO_DISABLED_NEVER = collected(PALOALTO_DONE, "disabled", { last_success_at: "" });
const PALOALTO_LATER = collected(PALOALTO_DONE, "paused");
const PALOALTO_UNREAD = collected(PALOALTO_DONE, "Paused: see\nlog");
// The sentences, exactly.
const CISCO_FAILING_SENTENCE =
  "Cisco PSIRT (cisco) collection has failed since 2026-10-12 (collection_state failing; failing_since 2026-10-12T12:22:49Z, its last successful poll); advisories Cisco PSIRT published after that may not be held, whatever its window says.";
const PA = "Palo Alto Networks (paloalto)";
const COLLECTION_SENTENCES = [
  [PALOALTO_FAILING, `${PA} collection has failed since 2026-10-12 (collection_state failing; failing_since 2026-10-12T12:22:49Z, its last successful poll); advisories Palo Alto Networks published after that may not be held, whatever its window says.`],
  [PALOALTO_FAILING_NO_SINCE, `${PA} collection has failed since 2026-10-12 (collection_state failing; last_success_at 2026-10-12T12:22:49Z, its last successful poll); advisories Palo Alto Networks published after that may not be held, whatever its window says.`],
  [PALOALTO_NEVER, `${PA} collection is failing, with no successful poll on record (collection_state failing, last_success_at null); advisories Palo Alto Networks published may not be held, whatever its window says.`],
  [PALOALTO_PARTIAL, `3 ${PA} documents are held back, the oldest since 2026-11-07 (collection_state partial, held_back 3: EchelonGraph could not use them); some Palo Alto Networks advisories may be missing: those advisories, or those revisions, may not be held, and the rest of its feed is.`],
  [PALOALTO_PARTIAL_ONE, `1 ${PA} document is held back since 2026-11-07 (collection_state partial, held_back 1: EchelonGraph could not use it); one Palo Alto Networks advisory may be missing: that advisory, or that revision, may not be held, and the rest of its feed is.`],
  [PALOALTO_DISABLED, `${PA} is not collected in this deployment (collection_state disabled): its window ends at its last successful poll, 2026-10-20 (last_success_at 2026-10-20T06:00:00Z); advisories Palo Alto Networks published after that may not be held.`],
  [PALOALTO_DISABLED_NEVER, `${PA} is not collected in this deployment (collection_state disabled), with no successful poll on record (last_success_at null); advisories Palo Alto Networks published may not be held.`],
  [PALOALTO_LATER, `${PA} has a collection_state this server does not know (paused): whether it is being collected is not known, so advisories Palo Alto Networks published may not be held.`],
  [PALOALTO_UNREAD, `${PA} has a collection_state this server does not know: whether it is being collected is not known, so advisories Palo Alto Networks published may not be held.`],
];
const NOT_A_FINDING_ONE = "So no advisory here from that vendor is not a finding that it published none.";
const NOT_A_FINDING_MANY = "So no advisory here from those vendors is not a finding that they published none.";
// The by-CVE note's last sentence when no vendor is listed (vendor_advisories.ts ONLY_POLLED).
const ONLY_POLLED_TAIL = "Only the vendor feeds EchelonGraph polls are covered, so an advisory a vendor published elsewhere is not in this answer.";
const OLD_FRESHNESS = "freshness is null: these answers carry no time at which the vendor-advisory pollers last completed a poll.";
const PER_VENDOR_FRESHNESS =
  "freshness is null: the answer has no single poll time; each vendor's last successful poll is its window's last_success_at in coverage, and its collection_state says whether it is being collected now, by EchelonGraph's feed-state rule.";
// #3663 review (NIT 10): how often a note says that no advisory from a vendor is not a finding.
const notAFindingCount = (note) => (note.match(/is not a finding that (it|they) published none\./g) ?? []).length;

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
    for (const empty of [CVE_3400, CVE_OLD, CVE_20188, CVE_HEARTBLEED, CVE_2021, CVE_2026, CVE_2027]) if (pathname === `/api/v1/public/vendor-advisories/by-cve/${empty}`) return send(200, { cve_id: empty, advisories: [], total: 0 });
    if (pathname === `/api/v1/public/vendor-advisories/by-cve/${CVE_FULL}`) return send(200, { cve_id: CVE_FULL, advisories: Array.from({ length: 20 }, () => row()), total: 20 });
    // #2865
    if (pathname === `/api/v1/public/vendor-advisories/by-cve/${CVE_REJ}`) return send(200, { cve_id: CVE_REJ, cve_rejected: true, advisories: [REJ_ROW, REJ_MULTI], total: 2 });
    if (pathname === `/api/v1/public/vendor-advisories/by-cve/${CVE_LIVE}`) return send(200, { cve_id: CVE_LIVE, cve_rejected: false, advisories: [row({ vendor_advisory_id: CVE_LIVE, rejected_cve_ids: [] })], total: 1 });
    if (pathname === `/api/v1/public/vendor-advisories/by-cve/${CVE_UNCHECKED}`) return send(200, { cve_id: CVE_UNCHECKED, cve_rejected: null, advisories: [row({ vendor_advisory_id: CVE_UNCHECKED, rejected_cve_ids: null })], total: 1 });
    if (pathname === "/api/v1/public/vendor-advisories/redhat/RHSA-2026%3A0100") return send(200, DETAIL_REJ);
    if (pathname === "/api/v1/public/vendor-advisories/redhat/RHSA-2026%3A0101") return send(200, { ...DETAIL_REJ, vendor_advisory_id: "RHSA-2026:0101", rejected_cve_ids: [] });
    if (pathname === `/api/v1/public/vendor-advisories/by-cve/${CVE_NONE}`) return send(200, { cve_id: CVE_NONE, advisories: [], total: 0 });
    if (pathname === "/api/v1/public/vendor-advisories/redhat/RHSA-2024%3A1234") return send(200, DETAIL);
    // #3011: the vendor's own ID answers; the row's UUID falls through to the 404 below, as the API's does.
    if (pathname === `/api/v1/public/vendor-advisories/microsoft/${CVE}`) return send(200, DETAIL_BY_VENDOR_ID);
    if (pathname === `/api/v1/public/vendor-advisories/gitlab/${UUID_SHAPED_VENDOR_ID}`) return send(200, DETAIL_UUID_SHAPED);
    if (pathname === "/api/v1/public/vendor-advisories/redhat/RHSA-2024%3A0001") return send(200, DETAIL_WITHDRAWN);
    if (pathname === "/api/v1/public/vendor-advisories/github/GHSA-jfh8-c2jp-5v3q") return send(200, DETAIL_GHSA);
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
  "The older advisories of 2 vendors are still being read (history_backfill in_progress or not_started): microsoft (held from 2026-05-20 to 2026-09-30, and before that only in part, the earliest held dated 2016-01-12; history_backfill in_progress); paloalto (held from 2026-09-09 to 2026-10-02; history_backfill not_started). EchelonGraph does not yet hold all of their older advisories, so none found from them is not a finding that they published none.";
const validator = new StrictOutputValidator();

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
      const msft = "The older advisories of 1 vendor are still being read (history_backfill in_progress or not_started): microsoft (held from 2026-05-20 to 2026-09-30, and before that only in part, the earliest held dated 2016-01-12; history_backfill in_progress). EchelonGraph does not yet hold all of its older advisories, so none found from it is not a finding that it published none.";
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
      // #2729: Microsoft and GitHub answered; Cisco holds nothing and Palo Alto only from 2026-09-09;
      // #2803: Red Hat is held without a gap only from 2026-05-19.
      assert.deepEqual(res.structuredContent.coverage, {
        returned: 2,
        cap: 20,
        at_cap: false,
        cve_year: 2024,
        vendor_windows: COVERAGE.vendors.map(relayed),
        vendors_not_fully_held: ["cisco", "paloalto", "redhat"],
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

    // ── #3011: a row's advisory_id is EchelonGraph's UUID; get_vendor_advisory takes vendor_advisory_id ──
    it("#3011: a row's advisory_id passed straight from vendor_advisories_for_cve answers invalid_input naming vendor_advisory_id, never failed or no record", async () => {
      const list = await call("vendor_advisories_for_cve", { cve_id: CVE });
      const r0 = list.structuredContent.data.advisories[0];
      assert.equal(r0.advisory_id, ROW_UUID);
      stub.state.seen.length = 0;
      const res = await call("get_vendor_advisory", { vendor: r0.vendor, advisory_id: r0.advisory_id });
      // The API is still asked (a vendor's own ID could have this shape), once.
      assert.deepEqual(mainRequests(stub.state.seen).map((x) => x.url), [`/api/v1/public/vendor-advisories/microsoft/${ROW_UUID}`]);
      assert.equal(res.isError, true, textOf(res));
      const sc = res.structuredContent;
      assert.equal(sc.state, "invalid_input", textOf(res));
      assert.deepEqual(sc.error, {
        kind: "invalid_input",
        path: `/api/v1/public/vendor-advisories/microsoft/${ROW_UUID}`,
        status: 404,
        message: `advisory_id ${ROW_UUID} has the shape of a row's advisory_id, EchelonGraph's internal ID for an advisory (a UUID), which this tool does not take, and EchelonGraph holds no microsoft advisory whose vendor_advisory_id it is (HTTP 404); pass the row's vendor_advisory_id as advisory_id`,
      });
      assert.equal(
        res.content[0].text,
        `get_vendor_advisory FAILED (state: invalid_input): advisory_id ${ROW_UUID} has the shape of a row's advisory_id, EchelonGraph's internal ID for an advisory (a UUID), which this tool does not take, and EchelonGraph holds no microsoft advisory whose vendor_advisory_id it is (HTTP 404). Call get_vendor_advisory again with the row's vendor and its vendor_advisory_id as advisory_id (e.g. CVE-2024-3400 for Palo Alto Networks, RHSA-2024:1234 for Red Hat). This says nothing about whether the advisory exists, and it is not a finding.`,
      );
      assert.ok(sc.notes.some((n) => n.includes("vendor_advisory_id as advisory_id")), JSON.stringify(sc.notes));
      assert.doesNotMatch(textOf(res), /The API returned no record|advisory not found/);
      assert.ok(!("data" in sc));
      // The same row's vendor and vendor_advisory_id return it, and the detail's advisory_id is the row's.
      const ok = await call("get_vendor_advisory", { vendor: r0.vendor, advisory_id: r0.vendor_advisory_id });
      assert.notEqual(ok.isError, true, textOf(ok));
      assert.equal(ok.structuredContent.state, "measured");
      assert.equal(ok.structuredContent.data.vendor_advisory_id, r0.vendor_advisory_id);
      assert.equal(ok.structuredContent.data.advisory_id, r0.advisory_id);
    });

    it("#3011: a search row's advisory_id answers the same refusal; a vendor's own ID of a UUID's shape is looked up and relayed; any other 404 stays failed, as no record", async () => {
      stub.state.searchApplied = false;
      let s0;
      try {
        s0 = (await call("search_vendor_advisories", {})).structuredContent.data.advisories[0];
      } finally {
        stub.state.searchApplied = true;
      }
      const res = await call("get_vendor_advisory", { vendor: s0.vendor, advisory_id: s0.advisory_id });
      assert.equal(res.structuredContent.state, "invalid_input", textOf(res));
      assert.match(textOf(res), /its vendor_advisory_id as advisory_id/);
      const own = await call("get_vendor_advisory", { vendor: "gitlab", advisory_id: UUID_SHAPED_VENDOR_ID });
      assert.notEqual(own.isError, true, textOf(own));
      assert.equal(own.structuredContent.state, "measured");
      assert.equal(own.structuredContent.data.vendor_advisory_id, UUID_SHAPED_VENDOR_ID);
      const miss = await call("get_vendor_advisory", { vendor: "redhat", advisory_id: "RHSA-2099:0001" });
      assert.equal(miss.structuredContent.state, "failed");
      assert.match(textOf(miss), /HTTP 404.*advisory not found.*The API returned no record for this request/s);
    });

    it("#3011: both list tools' outputSchemas describe a row's advisory_id and vendor_advisory_id; get_vendor_advisory's input and its echoed advisory_id say which to pass", async () => {
      const { tools } = await client.listTools();
      const t = (n) => tools.find((x) => x.name === n);
      // Every object schema in `s` that has an advisory_id property.
      const rowsIn = (s, out = []) => {
        if (Array.isArray(s)) s.forEach((x) => rowsIn(x, out));
        else if (s && typeof s === "object") {
          if (s.properties?.advisory_id && s.properties?.vendor_advisory_id) out.push(s.properties);
          Object.values(s).forEach((x) => rowsIn(x, out));
        }
        return out;
      };
      for (const n of ["vendor_advisories_for_cve", "search_vendor_advisories", "get_vendor_advisory"]) {
        const rows = rowsIn(t(n).outputSchema);
        assert.ok(rows.length >= 1, `${n}: no row schema with advisory_id`);
        for (const p of rows) {
          assert.match(p.advisory_id.description ?? "", /EchelonGraph's internal ID for this advisory, a UUID\. It is not the vendor's advisory ID \(vendor_advisory_id\), and an advisory's detail is not looked up by it/, n);
          assert.match(p.vendor_advisory_id.description ?? "", /With vendor, it is the key an advisory's detail is looked up by, as its advisory_id argument/, n);
        }
      }
      const input = t("get_vendor_advisory").inputSchema.properties.advisory_id.description;
      assert.match(input, /a row's vendor_advisory_id/);
      assert.match(input, /not a row's advisory_id, EchelonGraph's internal UUID/);
      assert.match(t("get_vendor_advisory").description, /vendor_advisory_id of a vendor advisory row, never its advisory_id/);
    });

    it("#3011: triage_cve's step 4 names the field get_vendor_advisory takes, vendor_advisory_id, and warns off the row's advisory_id", async () => {
      const p = await client.getPrompt({ name: "triage_cve", arguments: { cve_id: CVE } });
      const step4 = p.messages[0].content.text.split("\n").find((l) => l.startsWith("4. vendor_advisories_for_cve"));
      assert.ok(step4, p.messages[0].content.text.slice(0, 400));
      assert.match(step4, /Call get_vendor_advisory with a row's vendor and its vendor_advisory_id as advisory_id \(never the row's advisory_id, EchelonGraph's internal ID\)/);
    });

    // ── #2729: what is held of each vendor ──
    it("#2729: CVE-2024-3400 with Palo Alto held only from 2026-09-09: the empty answer names Palo Alto's window, and none here is not a finding", async () => {
      const res = await call("vendor_advisories_for_cve", { cve_id: CVE_3400 });
      assert.notEqual(res.isError, true, textOf(res));
      const sc = res.structuredContent;
      assert.equal(sc.state, "measured");
      assert.deepEqual(sc.coverage.vendor_windows, COVERAGE.vendors.map(relayed));
      // Cisco holds nothing, Microsoft's history is being read, Palo Alto starts after 2024 began;
      // #2803: GitHub and Red Hat are held without a gap only from 2026, whatever their earliest.
      assert.deepEqual(sc.coverage.vendors_not_fully_held, ["cisco", "github", "microsoft", "paloalto", "redhat"]);
      const note = noteOf(res);
      assert.match(note, /found nothing/, "still the measured empty result");
      assert.ok(
        note.endsWith(
          ` ${CVE_3400} is a 2024 CVE ID, and EchelonGraph may not hold every advisory 5 vendors published for it (vendors_not_fully_held): cisco (none held); github (held only from 2026-05-14 to 2026-10-04, and before that only in part, the earliest held dated 2017-10-24); microsoft (held only from 2026-05-20 to 2026-09-30, and before that only in part, the earliest held dated 2016-01-12; history_backfill in_progress); paloalto (held only from 2026-09-09 to 2026-10-02; history_backfill not_started); redhat (held only from 2026-05-19 to 2026-10-04, and before that only in part, the earliest held dated 2001-03-29). An advisory a vendor published before the date EchelonGraph holds that vendor from (held_since) may not be held, even when an older one is, and while history_backfill is in_progress or not_started the vendor's older advisories are still being read, so no advisory here from those vendors is not a finding that they published none.`,
        ),
        note,
      );
    });

    it("#2729: once Palo Alto's history is read back to 2012, CVE-2024-3400 no longer names it, and a 2010 CVE names every vendor that starts after 2010 began", async () => {
      stub.state.coverage = {
        vendors: COVERAGE.vendors.map((w) =>
          w.vendor === "paloalto"
            ? { ...w, advisories: 573, earliest_vendor_published_at: "2012-04-27T00:00:00Z", held_since: "2012-04-27T00:00:00Z", history_backfill: "complete" }
            : w.vendor === "microsoft"
              ? { ...w, held_since: w.earliest_vendor_published_at, history_backfill: "complete" }
              : w,
        ),
      };
      try {
        const now = await call("vendor_advisories_for_cve", { cve_id: CVE_3400 });
        assert.deepEqual(now.structuredContent.coverage.vendors_not_fully_held, ["cisco", "github", "redhat"]);
        assert.doesNotMatch(noteOf(now), /paloalto|microsoft/);
        const old = await call("vendor_advisories_for_cve", { cve_id: CVE_OLD });
        assert.deepEqual(old.structuredContent.coverage.vendors_not_fully_held, ["cisco", "github", "microsoft", "paloalto", "redhat"]);
        assert.equal(old.structuredContent.coverage.cve_year, 2010);
        assert.ok(noteOf(old).includes("; paloalto (held only from 2012-04-27 to 2026-10-02); "), noteOf(old));
        assert.ok(noteOf(old).includes("; microsoft (held only from 2016-01-12 to 2026-09-30); "), noteOf(old));
      } finally {
        stub.state.coverage = COVERAGE;
      }
    });

    // #2803 review: the year rule alone must not be what lists a vendor whose history is being read.
    // Palo Alto is a whole-feed poller in backfillVendors, so while its read is in_progress its
    // held_since is its earliest held advisory, which can already be before the CVE's year; it is
    // still listed. And held_since exactly at 1 January 00:00Z of the year is held from that year.
    it("#2803: a vendor whose history is being read is listed though its held_since is before the CVE's year; one held from 1 January 00:00Z exactly is not", async () => {
      const yearStart = "2024-01-01T00:00:00Z";
      stub.state.coverage = {
        vendors: [
          win("aws", "AWS", 40, yearStart, "2026-10-01T00:00:00Z", "not_supported"),
          win("paloalto", "Palo Alto Networks", 300, "2012-04-27T00:00:00Z", "2026-10-02T21:00:00Z", "in_progress", 40, "2012-04-27T00:00:00Z"),
        ],
      };
      try {
        const res = await call("vendor_advisories_for_cve", { cve_id: CVE_3400 });
        assert.notEqual(res.isError, true, textOf(res));
        assert.deepEqual(res.structuredContent.coverage.vendors_not_fully_held, ["paloalto"]);
        assert.ok(noteOf(res).includes("(vendors_not_fully_held): paloalto (held from 2012-04-27 to 2026-10-02; history_backfill in_progress)."), noteOf(res));
        assert.doesNotMatch(noteOf(res), /aws \(/, "held from 1 January 00:00Z of the CVE's year is held for that year");
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
            " The older advisories of 1 vendor are still being read (history_backfill in_progress or not_started): redhat (held from 2026-05-19 to 2026-10-04, and before that only in part, the earliest held dated 2001-03-29; history_backfill in_progress). EchelonGraph does not yet hold all of its older advisories, so none found from it is not a finding that it published none.",
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
        // #3472: and the two fields of a history read that covers a part of a vendor's advisories.
        for (const f of ["earliest_vendor_published_at", "latest_vendor_published_at", "held_since", "history_backfill", "in_progress", "not_started", "history_scope", "feed_held_since"]) assert.ok(d(n).includes(f), `${n}: ${f}`);
      }
      assert.ok(d("vendor_advisories_for_cve").includes("vendors_not_fully_held"));
      for (const n of ["vendor_advisories_for_cve", "search_vendor_advisories"]) {
        // #2842: the short form within the client cut; the full sentence is the windows' outputSchema description.
        assert.ok(d(n).includes("An advisory published before its vendor's held_since may not be held, so no advisory from a vendor is not a finding that it published none."), n);
        // #2803: no description says the window begins at the earliest held advisory.
        assert.doesNotMatch(d(n), /before its earliest_vendor_published_at is not held|earliest held advisory is dated after/, n);
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
      // #3472: the fourth, a history read of a part, whose rest is held from feed_held_since. #3464: the
      // fifth, a vendor not collected in full now.
      for (const why of [
        "of which EchelonGraph holds none",
        "whose held_since is after 1 January of cve_year or not known (outside history_scope, feed_held_since)",
        "whose history is still being read",
        "or collection_state is not ok",
      ]) {
        assert.ok(d.includes(why), `vendors_not_fully_held: ${why}`);
      }
    });

    // ── #2803: a vendor with no history read is held from held_since, not from its earliest ──
    it("#2803: CVE-2025-20188 lists cisco, though Cisco's earliest held advisory is dated 2024-10-23", async () => {
      stub.state.coverage = { vendors: [CISCO_REVISED, REDHAT_REVISED] };
      try {
        const res = await call("vendor_advisories_for_cve", { cve_id: CVE_20188 });
        assert.notEqual(res.isError, true, textOf(res));
        assert.equal(res.structuredContent.coverage.cve_year, 2025);
        assert.deepEqual(res.structuredContent.coverage.vendor_windows, [CISCO_REVISED, REDHAT_REVISED].map(relayed));
        assert.deepEqual(res.structuredContent.coverage.vendors_not_fully_held, ["cisco", "redhat"]);
        assert.ok(
          noteOf(res).includes(
            "(vendors_not_fully_held): cisco (held only from 2026-02-25 to 2026-10-01, and before that only in part, the earliest held dated 2024-10-23); redhat (",
          ),
          noteOf(res),
        );
      } finally {
        stub.state.coverage = COVERAGE;
      }
    });

    it("#2803: CVE-2014-0160 lists redhat, though Red Hat's earliest held advisory is dated 2009-02-04", async () => {
      stub.state.coverage = { vendors: [CISCO_REVISED, REDHAT_REVISED] };
      try {
        const res = await call("vendor_advisories_for_cve", { cve_id: CVE_HEARTBLEED });
        assert.notEqual(res.isError, true, textOf(res));
        assert.deepEqual(res.structuredContent.coverage.vendors_not_fully_held, ["cisco", "redhat"]);
        assert.ok(noteOf(res).includes("; redhat (held only from 2026-05-19 to 2026-10-04, and before that only in part, the earliest held dated 2009-02-04)."), noteOf(res));
      } finally {
        stub.state.coverage = COVERAGE;
      }
    });

    it("#2803: from an API without held_since, a vendor whose history is not read is listed for any year; one whose history read is complete is held from its earliest", async () => {
      const old = (w) => {
        const { held_since, ...rest } = w;
        return rest;
      };
      const msftDone = { ...win("microsoft", "Microsoft", 1311, "2016-01-12T08:00:00Z", "2026-09-30T07:00:00Z", "complete", 193), history_completed_at: "2026-10-04T08:00:00Z" };
      stub.state.coverage = { vendors: [old(CISCO_REVISED), old(msftDone), old(REDHAT_REVISED)] };
      try {
        const res = await call("vendor_advisories_for_cve", { cve_id: CVE_20188 });
        assert.notEqual(res.isError, true, textOf(res));
        assert.deepEqual(
          res.structuredContent.coverage.vendor_windows.map((w) => [w.vendor, w.held_since]),
          [["cisco", null], ["microsoft", null], ["redhat", null]],
        );
        assert.deepEqual(res.structuredContent.coverage.vendors_not_fully_held, ["cisco", "redhat"]);
        assert.ok(noteOf(res).includes("cisco (held from 2024-10-23 to 2026-10-01, not known to be without a gap); redhat (held from 2009-02-04 to 2026-10-04, not known to be without a gap)."), noteOf(res));
      } finally {
        stub.state.coverage = COVERAGE;
      }
    });

    // ── #3472: a history read that covers only part of a vendor's advisories ──
    it("#3472: a 2021 CVE with no GitHub row lists github in vendors_not_fully_held, with its reviewed and its unreviewed advisories' dates, though its held_since is 2017-10-24", async () => {
      stub.state.coverage = { vendors: [GITHUB_REVIEWED, MSFT_ALL, PALOALTO_DONE] };
      try {
        const res = await call("vendor_advisories_for_cve", { cve_id: CVE_2021 });
        assert.notEqual(res.isError, true, textOf(res));
        const sc = res.structuredContent;
        assert.equal(sc.state, "measured");
        assert.deepEqual(sc.coverage.vendor_windows, [GITHUB_REVIEWED, MSFT_ALL, PALOALTO_DONE].map(relayed));
        assert.deepEqual(
          sc.coverage.vendor_windows.map((w) => [w.vendor, w.history_backfill, w.history_scope, w.feed_held_since]),
          [
            ["github", "complete_reviewed_only", "reviewed", "2026-05-15T08:09:51Z"],
            ["microsoft", "complete", "all", "2026-05-20T10:00:00Z"],
            ["paloalto", "complete", null, null],
          ],
        );
        // Microsoft (history_scope all) and Palo Alto (no history_scope) are held from before 2021, as before.
        assert.deepEqual(sc.coverage.vendors_not_fully_held, ["github"]);
        assert.ok(
          noteOf(res).endsWith(` ${CVE_2021} is a 2021 CVE ID, and EchelonGraph may not hold every advisory 1 vendor published for it (vendors_not_fully_held): ${GITHUB_ITEM}. ${PART_RULE}`),
          noteOf(res),
        );
        assert.doesNotMatch(noteOf(res), /microsoft \(|paloalto \(/);
      } finally {
        stub.state.coverage = COVERAGE;
      }
    });

    // The rule compares feed_held_since with 1 January of the CVE ID's year, never with the CVE's own
    // dates: a CVE-2026 ID's year begins 2026-01-01, before 2026-05-15, so GitHub is still listed for
    // it, even for a CVE published after 2026-05-15. A CVE-2027 ID's year begins after both dates.
    it("#3472: a CVE-2026 ID still lists github (its year begins 2026-01-01, before feed_held_since 2026-05-15); a CVE-2027 ID does not", async () => {
      stub.state.coverage = { vendors: [GITHUB_REVIEWED, MSFT_ALL, PALOALTO_DONE] };
      try {
        const y26 = await call("vendor_advisories_for_cve", { cve_id: CVE_2026 });
        assert.notEqual(y26.isError, true, textOf(y26));
        assert.equal(y26.structuredContent.coverage.cve_year, 2026);
        assert.deepEqual(y26.structuredContent.coverage.vendors_not_fully_held, ["github"]);
        assert.ok(noteOf(y26).includes(`(vendors_not_fully_held): ${GITHUB_ITEM}. `), noteOf(y26));
        const y27 = await call("vendor_advisories_for_cve", { cve_id: CVE_2027 });
        assert.notEqual(y27.isError, true, textOf(y27));
        assert.deepEqual(y27.structuredContent.coverage.vendors_not_fully_held, []);
        assert.doesNotMatch(noteOf(y27), /vendors_not_fully_held|unreviewed/);
      } finally {
        stub.state.coverage = COVERAGE;
      }
    });

    it("#3472 regression: history_backfill complete without history_scope, from an API without either new field, reads exactly as before", async () => {
      // The same windows without the two fields, GitHub's as a complete read (2.6.6 to 3.1.2's API shape).
      const old = (w) => {
        const { feed_held_since, history_scope, ...rest } = w;
        return rest;
      };
      const githubComplete = { ...old(GITHUB_REVIEWED), history_backfill: "complete" };
      stub.state.coverage = { vendors: [githubComplete, old(MSFT_ALL), PALOALTO_DONE] };
      try {
        const res = await call("vendor_advisories_for_cve", { cve_id: CVE_2021 });
        assert.notEqual(res.isError, true, textOf(res));
        assert.deepEqual(res.structuredContent.coverage.vendor_windows.map((w) => [w.vendor, w.history_scope, w.feed_held_since]), [["github", null, null], ["microsoft", null, null], ["paloalto", null, null]]);
        assert.deepEqual(res.structuredContent.coverage.vendors_not_fully_held, []);
        assert.doesNotMatch(noteOf(res), /vendors_not_fully_held|history_scope|unreviewed/);
        // A 2010 CVE lists all three in the wording of #2729 and #2803, with no history_scope clause.
        const y10 = await call("vendor_advisories_for_cve", { cve_id: CVE_OLD });
        assert.deepEqual(y10.structuredContent.coverage.vendors_not_fully_held, ["github", "microsoft", "paloalto"]);
        assert.ok(
          noteOf(y10).endsWith(
            ` ${CVE_OLD} is a 2010 CVE ID, and EchelonGraph may not hold every advisory 3 vendors published for it (vendors_not_fully_held): github (held only from 2017-10-24 to 2026-11-06); microsoft (held only from 2016-01-12 to 2026-09-30); paloalto (held only from 2012-04-27 to 2026-10-02). An advisory a vendor published before the date EchelonGraph holds that vendor from (held_since) may not be held, even when an older one is, and while history_backfill is in_progress or not_started the vendor's older advisories are still being read, so no advisory here from those vendors is not a finding that they published none.`,
          ),
          noteOf(y10),
        );
      } finally {
        stub.state.coverage = COVERAGE;
      }
    });

    it("#3472: history_scope decides, whatever history_backfill says: a later value with history_scope reviewed still lists github", async () => {
      stub.state.coverage = { vendors: [{ ...GITHUB_REVIEWED, history_backfill: "paused" }] };
      try {
        const res = await call("vendor_advisories_for_cve", { cve_id: CVE_2021 });
        assert.notEqual(res.isError, true, textOf(res));
        assert.deepEqual(res.structuredContent.coverage.vendors_not_fully_held, ["github"]);
        assert.ok(noteOf(res).includes(`(vendors_not_fully_held): ${GITHUB_ITEM}. `), noteOf(res));
      } finally {
        stub.state.coverage = COVERAGE;
      }
    });

    it("#3472: complete_reviewed_only without history_scope, feed_held_since or held_since is read as reviewed, its rest held from a date not known, never as complete", async () => {
      const { held_since, feed_held_since, history_scope, ...bare } = GITHUB_REVIEWED;
      stub.state.coverage = { vendors: [bare] };
      try {
        const res = await call("vendor_advisories_for_cve", { cve_id: CVE_2021 });
        assert.notEqual(res.isError, true, textOf(res));
        assert.deepEqual(res.structuredContent.coverage.vendor_windows.map((w) => [w.held_since, w.feed_held_since, w.history_scope]), [[null, null, null]]);
        assert.deepEqual(res.structuredContent.coverage.vendors_not_fully_held, ["github"]);
        // held from its earliest, as a finished read is (heldFrom), and the rest from a date not known.
        assert.ok(
          noteOf(res).includes("(vendors_not_fully_held): github (reviewed advisories held from 2017-10-24 to 2026-11-06; unreviewed advisories held from a date not known). "),
          noteOf(res),
        );
        // Nor is it read as a history still being read.
        assert.doesNotMatch(noteOf(res), /history_backfill complete_reviewed_only/);
      } finally {
        stub.state.coverage = COVERAGE;
      }
    });

    it("#3472: while GitHub's reviewed-only read is in progress, its item says so; the rest is held from the same date as held_since, so the two are not given apart", async () => {
      const reading = { ...GITHUB_REVIEWED, held_since: GITHUB_REVIEWED.feed_held_since, history_backfill: "in_progress", history_completed_at: "" };
      stub.state.coverage = { vendors: [reading] };
      try {
        const res = await call("vendor_advisories_for_cve", { cve_id: CVE_2021 });
        assert.deepEqual(res.structuredContent.coverage.vendors_not_fully_held, ["github"]);
        assert.ok(
          noteOf(res).includes(
            "(vendors_not_fully_held): github (held only from 2026-05-15 to 2026-11-06, and before that only in part, the earliest held dated 2017-10-24; history_backfill in_progress, which reads its reviewed advisories only (history_scope reviewed)). ",
          ),
          noteOf(res),
        );
        const s = await call("search_vendor_advisories", {});
        assert.ok(noteOf(s).includes("are still being read (history_backfill in_progress or not_started): github (held from 2026-05-15 to 2026-11-06, and before that only in part"), noteOf(s));
        assert.doesNotMatch(noteOf(s), /covers only part/, "a vendor still being read is named once");
      } finally {
        stub.state.coverage = COVERAGE;
      }
    });

    it("#3472: search_vendor_advisories and get_vendor_advisory name GitHub's reviewed-only read, which is not a history still being read", async () => {
      stub.state.coverage = { vendors: [GITHUB_REVIEWED, MSFT_ALL, PALOALTO_DONE] };
      stub.state.searchApplied = false;
      const sentence =
        " The history read of 1 vendor covers only part of its advisories (history_scope): github (reviewed advisories held from 2017-10-24 to 2026-11-06; unreviewed advisories held only from 2026-05-15). An advisory outside that part published before its feed_held_since may not be held, so none found from it is not a finding that it published none.";
      try {
        const s = await call("search_vendor_advisories", {});
        assert.notEqual(s.isError, true, textOf(s));
        assert.deepEqual(s.structuredContent.coverage.vendor_windows, [GITHUB_REVIEWED, MSFT_ALL, PALOALTO_DONE].map(relayed));
        assert.ok(noteOf(s).endsWith(sentence), noteOf(s));
        assert.doesNotMatch(noteOf(s), /still being read/);
        // Filtered to a vendor whose read covers all, nothing is said.
        const m = await call("search_vendor_advisories", { vendor: "microsoft" });
        assert.doesNotMatch(noteOf(m), /covers only part|still being read/);
        stub.state.searchApplied = true;
        const d = await call("get_vendor_advisory", { vendor: "github", advisory_id: "GHSA-jfh8-c2jp-5v3q" });
        assert.notEqual(d.isError, true, textOf(d));
        assert.deepEqual(d.structuredContent.coverage, { vendor_window: relayed(GITHUB_REVIEWED) });
        assert.ok(noteOf(d).endsWith(sentence), noteOf(d));
      } finally {
        stub.state.coverage = COVERAGE;
        stub.state.searchApplied = true;
      }
    });

    it("#3472: every outputSchema that carries a vendor window documents history_scope and feed_held_since, and history_backfill lists complete_reviewed_only", async () => {
      const success = (s) => s.oneOf.find((b) => b.properties.state.enum.includes("measured"));
      const nonNull = (n) => n.anyOf?.find((b) => b.type !== "null") ?? n;
      const windowsOf = {
        vendor_advisories_for_cve: (s) => nonNull(nonNull(success(s).properties.coverage).properties.vendor_windows).items,
        search_vendor_advisories: (s) => nonNull(nonNull(success(s).properties.coverage).properties.vendor_windows).items,
        get_vendor_advisory: (s) => nonNull(nonNull(success(s).properties.coverage).properties.vendor_window),
      };
      for (const [name, at] of Object.entries(windowsOf)) {
        const w = at(schemas[name]);
        assert.ok(w?.properties, `${name}: no vendor window schema found: re-aim this check`);
        assert.match(w.properties.history_scope?.description ?? "", /What this vendor's history read covers: all .* or reviewed \(GitHub: its reviewed advisories, not its unreviewed ones, which are held only from feed_held_since\)/, name);
        assert.match(w.properties.feed_held_since?.description ?? "", /an advisory outside it published before feed_held_since may not be held, however early held_since is/, name);
        assert.ok(JSON.stringify(w.properties.history_backfill).includes('"complete_reviewed_only"'), `${name}: history_backfill does not list complete_reviewed_only`);
        assert.match(w.description ?? "", /complete_reviewed_only \(the vendor's reviewed advisories have been read back/, name);
      }
      const listed = nonNull(success(schemas.vendor_advisories_for_cve).properties.coverage).properties.vendors_not_fully_held;
      assert.match(
        listed?.description ?? nonNull(listed ?? {}).description ?? "",
        /a history_scope that is a part of the vendor's advisories \(reviewed\) with feed_held_since after 1 January of cve_year or not known/,
      );
    });

    // ── #3464: whether each vendor is being collected ──
    it("#3464: CVE-2024-3400 with Palo Alto held from 2012 but failing lists paloalto, and the note says since when, plainly; ok does not", async () => {
      stub.state.coverage = { vendors: [PALOALTO_FAILING] };
      try {
        const res = await call("vendor_advisories_for_cve", { cve_id: CVE_3400 });
        assert.notEqual(res.isError, true, textOf(res));
        const sc = res.structuredContent;
        assert.deepEqual(sc.coverage.vendor_windows, [relayed(PALOALTO_FAILING)]);
        assert.deepEqual(
          sc.coverage.vendor_windows.map((w) => [w.last_success_at, w.collection_state, w.failing_since, w.held_back, w.held_back_since]),
          [["2026-10-12T12:22:49Z", "failing", "2026-10-12T12:22:49Z", 0, null]],
        );
        assert.deepEqual(sc.coverage.vendors_not_fully_held, ["paloalto"]);
        const note = noteOf(res);
        assert.ok(note.includes("(vendors_not_fully_held): paloalto (held from 2012-04-27 to 2026-10-02; collection_state failing)."), note);
        // NIT 10: vendors_not_fully_held's sentence already says it of paloalto, so the collection
        // sentence closes the note with no second "not a finding".
        assert.ok(note.endsWith(` ${COLLECTION_SENTENCES[0][1]}`), note);
        assert.equal(notAFindingCount(note), 1, note);
        assert.ok(sc.notes.includes(PER_VENDOR_FRESHNESS), sc.notes.join(" | "));
        assert.ok(!sc.notes.includes(OLD_FRESHNESS));
        // Control: the same window, collected (ok): fully held for 2024, and nothing said of collection.
        stub.state.coverage = { vendors: [PALOALTO_OK] };
        const ok = await call("vendor_advisories_for_cve", { cve_id: CVE_3400 });
        assert.deepEqual(ok.structuredContent.coverage.vendors_not_fully_held, []);
        assert.deepEqual(ok.structuredContent.coverage.vendor_windows, [relayed(PALOALTO_OK)]);
        assert.doesNotMatch(noteOf(ok), /collection|held back|not collected/i);
        assert.ok(noteOf(ok).endsWith(ONLY_POLLED_TAIL), noteOf(ok));
        assert.ok(ok.structuredContent.notes.includes(PER_VENDOR_FRESHNESS));
      } finally {
        stub.state.coverage = COVERAGE;
      }
    });

    it("#3464: each collection_state's sentence, exactly, in search_vendor_advisories' note for that vendor; partial, disabled and a later state are listed for any CVE year", async () => {
      for (const [w, sentence] of COLLECTION_SENTENCES) {
        stub.state.coverage = { vendors: [w, CISCO_FAILING] };
        try {
          const s = await call("search_vendor_advisories", { vendor: "paloalto" });
          assert.notEqual(s.isError, true, textOf(s));
          assert.deepEqual(s.structuredContent.coverage.vendor_windows, [relayed(w)], w.collection_state);
          assert.equal(noteOf(s), `search_vendor_advisories OK: EchelonGraph answered HTTP 200 from ${stub.base}. The list holds 7 vendor advisories; 1 returned in this page (offset 0). ${sentence} ${NOT_A_FINDING_ONE}`);
          // The by-CVE answer lists it whatever the year: its window alone holds it from 2012.
          const c = await call("vendor_advisories_for_cve", { cve_id: CVE_3400 });
          assert.deepEqual(c.structuredContent.coverage.vendors_not_fully_held, ["paloalto", "cisco"], w.collection_state);
          assert.ok(noteOf(c).endsWith(` ${sentence} ${CISCO_FAILING_SENTENCE}`), noteOf(c));
          assert.equal(notAFindingCount(noteOf(c)), 1, noteOf(c));
        } finally {
          stub.state.coverage = COVERAGE;
        }
      }
      // A state this server does not read is relayed as sent, and not echoed into the note.
      const unread = COLLECTION_SENTENCES.at(-1)[0];
      stub.state.coverage = { vendors: [unread] };
      try {
        const c = await call("vendor_advisories_for_cve", { cve_id: CVE_3400 });
        assert.equal(c.structuredContent.coverage.vendor_windows[0].collection_state, "Paused: see\nlog");
        assert.ok(noteOf(c).includes("paloalto (held from 2012-04-27 to 2026-10-02; collection_state of a value this server does not read)."), noteOf(c));
        assert.doesNotMatch(noteOf(c), /Paused|see\s+log/);
      } finally {
        stub.state.coverage = COVERAGE;
      }
    });

    it("#3464: docs/api/openapi.yaml's Cisco example: the by-CVE answer names Cisco's failure for a CVE it answered too, and the search names every vendor not collected in full", async () => {
      // CVE-2024-21412's answer holds Microsoft's and GitHub's rows; Microsoft is failing too.
      const MSFT_FAILING = collected(MSFT_ALL, "failing", { last_success_at: "2026-11-01T00:00:00Z", failing_since: "2026-11-01T00:00:00Z" });
      stub.state.coverage = { vendors: [CISCO_FAILING, MSFT_FAILING, collected(GITHUB_REVIEWED, "ok"), PALOALTO_PARTIAL] };
      try {
        const res = await call("vendor_advisories_for_cve", { cve_id: CVE });
        assert.notEqual(res.isError, true, textOf(res));
        // Microsoft answered, so it is not in vendors_not_fully_held; its failure is still said.
        assert.deepEqual(res.structuredContent.coverage.vendors_not_fully_held, ["cisco", "paloalto"]);
        const msft =
          "Microsoft (microsoft) collection has failed since 2026-11-01 (collection_state failing; failing_since 2026-11-01T00:00:00Z, its last successful poll); advisories Microsoft published after that may not be held, whatever its window says.";
        // NIT 10: cisco and paloalto are in vendors_not_fully_held's sentence; Microsoft, which answered,
        // is not, so the closing sentence names it alone.
        assert.ok(noteOf(res).endsWith(` ${CISCO_FAILING_SENTENCE} ${msft} ${COLLECTION_SENTENCES[3][1]} So no advisory here from Microsoft is not a finding that it published none.`), noteOf(res));
        assert.equal(notAFindingCount(noteOf(res)), 2, noteOf(res));
        const s = await call("search_vendor_advisories", {});
        assert.ok(noteOf(s).endsWith(` ${CISCO_FAILING_SENTENCE} ${msft} ${COLLECTION_SENTENCES[3][1]} ${NOT_A_FINDING_MANY}`), noteOf(s));
        const only = await call("search_vendor_advisories", { vendor: "cisco" });
        assert.equal(noteOf(only), `search_vendor_advisories OK: EchelonGraph answered HTTP 200 from ${stub.base}. The list holds 7 vendor advisories; 1 returned in this page (offset 0). ${CISCO_FAILING_SENTENCE} ${NOT_A_FINDING_ONE}`);
        assert.deepEqual(only.structuredContent.coverage.vendor_windows, [relayed(CISCO_FAILING)]);
      } finally {
        stub.state.coverage = COVERAGE;
      }
    });

    it("#3464: get_vendor_advisory says its vendor's collection is failing, and its freshness note names last_success_at", async () => {
      const REDHAT_FAILING = collected(REDHAT_REVISED, "failing", { last_success_at: "2026-10-30T04:00:00Z", failing_since: "2026-10-30T04:00:00Z" });
      stub.state.coverage = { vendors: [REDHAT_FAILING, CISCO_FAILING] };
      try {
        const d = await call("get_vendor_advisory", { vendor: "redhat", advisory_id: "RHSA-2024:1234" });
        assert.notEqual(d.isError, true, textOf(d));
        assert.deepEqual(d.structuredContent.coverage, { vendor_window: relayed(REDHAT_FAILING) });
        assert.equal(
          noteOf(d),
          `get_vendor_advisory OK: EchelonGraph answered HTTP 200 from ${stub.base}. Returned the advisory redhat/RHSA-2024:1234. Of the 2 CVE IDs it lists (cve_ids), 1 has a record in EchelonGraph's CVE feed (known_cve_ids); the others have no record there yet, which does not mean they are not CVEs. Red Hat Product Security (redhat) collection has failed since 2026-10-30 (collection_state failing; failing_since 2026-10-30T04:00:00Z, its last successful poll); advisories Red Hat Product Security published after that may not be held, whatever its window says. ${NOT_A_FINDING_ONE}`,
        );
        assert.doesNotMatch(noteOf(d), /cisco/i, "only the advisory's vendor is named");
        assert.ok(d.structuredContent.notes.includes(PER_VENDOR_FRESHNESS));
        // Its vendor collected: nothing said.
        stub.state.coverage = { vendors: [collected(REDHAT_REVISED, "ok"), CISCO_FAILING] };
        const ok = await call("get_vendor_advisory", { vendor: "redhat", advisory_id: "RHSA-2024:1234" });
        assert.doesNotMatch(noteOf(ok), /collection|held back|not collected/i);
      } finally {
        stub.state.coverage = COVERAGE;
      }
    });

    it("#3464 backwards compatible: from an API without the five fields, nothing is said of collection, they are relayed null, and the freshness note is as before", async () => {
      // COVERAGE is 2.6.4-era: no last_success_at, collection_state, failing_since, held_back or held_back_since.
      assert.ok(COVERAGE.vendors.every((w) => !("collection_state" in w) && !("last_success_at" in w) && !("held_back" in w)));
      const c = await call("vendor_advisories_for_cve", { cve_id: CVE_3400 });
      const s = await call("search_vendor_advisories", {});
      const d = await call("get_vendor_advisory", { vendor: "redhat", advisory_id: "RHSA-2024:1234" });
      for (const res of [c, s, d]) {
        assert.notEqual(res.isError, true, textOf(res));
        assert.equal(res.structuredContent.state, "measured");
        assert.doesNotMatch(noteOf(res), /collection|held back|not collected/i);
        assert.ok(res.structuredContent.notes.includes(OLD_FRESHNESS), res.structuredContent.notes.join(" | "));
        const windows = res.structuredContent.coverage.vendor_windows ?? [res.structuredContent.coverage.vendor_window];
        for (const w of windows) for (const f of ["last_success_at", "collection_state", "failing_since", "held_back", "held_back_since"]) assert.equal(w[f], null, `${w.vendor}.${f}`);
      }
      // As before #3464 (the #2729 case above): every vendor of the fixture, each for its window.
      assert.deepEqual(c.structuredContent.coverage.vendors_not_fully_held, ["cisco", "github", "microsoft", "paloalto", "redhat"]);
    });

    it("#3464: every outputSchema that carries a vendor window documents the five fields, and the descriptions do not say the answer has no poll time", async () => {
      const success = (s) => s.oneOf.find((b) => b.properties.state.enum.includes("measured"));
      const nonNull = (n) => n.anyOf?.find((b) => b.type !== "null") ?? n;
      const at = {
        vendor_advisories_for_cve: (s) => nonNull(nonNull(success(s).properties.coverage).properties.vendor_windows).items,
        search_vendor_advisories: (s) => nonNull(nonNull(success(s).properties.coverage).properties.vendor_windows).items,
        get_vendor_advisory: (s) => nonNull(nonNull(success(s).properties.coverage).properties.vendor_window),
      };
      for (const [name, of] of Object.entries(at)) {
        const w = of(schemas[name]);
        assert.ok(w?.properties, `${name}: no vendor window schema found: re-aim this check`);
        assert.match(w.properties.last_success_at?.description ?? "", /This vendor's last successful poll/, name);
        const state = w.properties.collection_state ?? {};
        assert.match(state.description ?? "", /Whether this vendor is being collected now, by EchelonGraph's feed-state rule: ok, partial, failing or disabled\./, name);
        // NIT 6: a disabled vendor's held advisories are still served (core-backend feed_state.go: served, not collected).
        assert.match(state.description ?? "", /disabled: this deployment runs no collector for it \(its held advisories are still served\)/, name);
        assert.match(state.description ?? "", /failing: it is not being collected, and an advisory it published after failing_since, its last successful poll, may not be held, whatever the window says/, name);
        assert.match(state.description ?? "", /partial: its polls succeed, but held_back of the documents it lists could not be used/, name);
        assert.match(state.description ?? "", /A value the API adds later is relayed as sent and is not read as ok/, name);
        assert.match(w.properties.failing_since?.description ?? "", /an advisory it published after it may not be held/, name);
        assert.match(w.properties.held_back?.description ?? "", /those advisories, or those revisions, may not be held/, name);
        assert.match(w.properties.held_back_since?.description ?? "", /When the oldest held-back document first failed/, name);
        assert.match(w.description ?? "", /collection_state \(whether the vendor is being collected now, by EchelonGraph's feed-state rule:/, name);
        assert.match(w.description ?? "", /disabled, this deployment runs no collector for it \(its held advisories are still served\)/, name);
      }
      const listed = nonNull(success(schemas.vendor_advisories_for_cve).properties.coverage).properties.vendors_not_fully_held;
      assert.match(listed?.description ?? nonNull(listed ?? {}).description ?? "", /for any cve_year, a collection_state that is not ok \(failing, partial, disabled, or a value the API adds later\)/);
      const { tools } = await client.listTools();
      const d = tools.find((t) => t.name === "get_vendor_advisory").description;
      assert.ok(d.includes("vendor_window.last_success_at is the last successful poll"), d);
      for (const t of tools.filter((x) => /vendor_advis/.test(x.name))) assert.doesNotMatch(t.description, /carries no poll-completion time/, t.name);
    });

    // #2865: an advisory that names a rejected CVE, while its vendor has not withdrawn it.
    it("#2865: vendor_advisories_for_cve on a rejected CVE says so first, keeps the vendor's withdrawn, and names a multi-CVE row's other rejected ID", async () => {
      const res = await call("vendor_advisories_for_cve", { cve_id: CVE_REJ });
      assert.notEqual(res.isError, true, textOf(res));
      const note = noteOf(res);
      assert.ok(
        note.startsWith(
          `vendor_advisories_for_cve OK: EchelonGraph answered HTTP 200 from ${stub.base}. CVE REJECTED: the CVE record of ${CVE_REJ} was rejected (withdrawn) by its numbering authority (cve_rejected true). It is a rejected record, not an active vulnerability: report it that way, even where a vendor advisory below reads as a current one. 2 vendor advisories name ${CVE_REJ}.`,
        ),
        note,
      );
      // The Red Hat row's other rejected CVE is named; the queried one is not repeated per row.
      assert.match(note, /CVE REJECTED: 1 of these 2 advisories, not withdrawn by its vendor, names a CVE ID whose CVE record was rejected \(withdrawn\) by its numbering authority \(rejected_cve_ids\): redhat\/RHSA-2026:0099 \(CVE-2026-0001\)\./);
      assert.doesNotMatch(note, /WITHDRAWN:/, "the vendors did not withdraw these");
      const data = res.structuredContent.data;
      assert.equal(data.cve_rejected, true);
      assert.deepEqual(data.advisories[0].rejected_cve_ids, [CVE_REJ]);
      assert.equal(data.advisories[0].withdrawn, false);
    });

    it("#2865: controls: a CVE that is not rejected, and an API without the fields, add no CVE REJECTED note; an unchecked state is said to be unknown", async () => {
      for (const cve of [CVE_LIVE, CVE]) {
        const res = await call("vendor_advisories_for_cve", { cve_id: cve });
        assert.notEqual(res.isError, true, textOf(res));
        assert.doesNotMatch(noteOf(res), /CVE REJECTED|could not be checked/, `${cve}: ${noteOf(res)}`);
      }
      const res = await call("vendor_advisories_for_cve", { cve_id: CVE_UNCHECKED });
      assert.notEqual(res.isError, true, textOf(res));
      assert.match(noteOf(res), new RegExp(`Whether the CVE record of ${CVE_UNCHECKED} was rejected could not be checked \\(cve_rejected null\\), which is not a finding that it was not\\.`));
      assert.doesNotMatch(noteOf(res), /CVE REJECTED/);
    });

    it("#2865: get_vendor_advisory names the rejected CVE IDs of a live advisory; [] adds nothing", async () => {
      const res = await call("get_vendor_advisory", { vendor: "redhat", advisory_id: "RHSA-2026:0100" });
      assert.notEqual(res.isError, true, textOf(res));
      assert.match(
        noteOf(res),
        /Returned the advisory redhat\/RHSA-2026:0100\. CVE REJECTED: 1 of the CVE IDs it lists was rejected \(withdrawn\) by its numbering authority \(rejected_cve_ids\): CVE-2026-0001\. Report it as a rejected record, not as an active vulnerability, even though the vendor has not withdrawn this advisory and its text reads as a current one\./,
      );
      assert.deepEqual(res.structuredContent.data.rejected_cve_ids, ["CVE-2026-0001"]);
      const none = await call("get_vendor_advisory", { vendor: "redhat", advisory_id: "RHSA-2026:0101" });
      assert.notEqual(none.isError, true, textOf(none));
      assert.doesNotMatch(noteOf(none), /CVE REJECTED|could not be checked/);
    });

    it("#2865: search_vendor_advisories names each listed advisory that names a rejected CVE, and not the others", async () => {
      stub.state.searchApplied = true;
      stub.state.list = { advisories: [REJ_ROW, row({ vendor_advisory_id: CVE_LIVE, rejected_cve_ids: [] }), row({ vendor_advisory_id: "CVE-2026-7939", rejected_cve_ids: null, cve_ids: ["CVE-2026-7939"] })], total: 3 };
      try {
        const res = await call("search_vendor_advisories", { vendor: "microsoft" });
        assert.notEqual(res.isError, true, textOf(res));
        const note = noteOf(res);
        assert.match(note, /The list holds 3 vendor advisories; 3 returned in this page \(offset 0\)\. CVE REJECTED: 1 of these 3 advisories, not withdrawn by its vendor, names a CVE ID whose CVE record was rejected \(withdrawn\) by its numbering authority \(rejected_cve_ids\): microsoft\/CVE-2026-7936 \(CVE-2026-7936\)\./);
        assert.doesNotMatch(note, new RegExp(CVE_LIVE));
        assert.match(note, /For 1 of these advisories rejected_cve_ids is null: whether a CVE ID they name was rejected could not be checked, which is not a finding that none was\./);
      } finally {
        stub.state.list = {};
      }
    });

    it("#2865: the three descriptions state rejected_cve_ids, and vendor_advisories_for_cve states cve_rejected", async () => {
      const { tools } = await client.listTools();
      for (const name of ["vendor_advisories_for_cve", "get_vendor_advisory", "search_vendor_advisories"]) {
        const d = tools.find((t) => t.name === name).description;
        assert.match(d, /rejected_cve_ids: the CVE IDs it names whose CVE record was rejected \(withdrawn\) by its numbering authority/, name);
      }
      assert.match(tools.find((t) => t.name === "vendor_advisories_for_cve").description, /cve_rejected is true when the CVE record of the CVE asked for was rejected/);
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
