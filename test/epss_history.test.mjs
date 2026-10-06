// epss_history (#2718) against a stub of GET /api/v1/public/cves/:id/epss-history, in both
// protocol eras: a CVE with several recorded changes, one with none, one with no EPSS score, an
// unknown CVE (the API's 404), the API's 503, a malformed id (never sent), and answers the tool
// must refuse to relay. Every structuredContent is validated against the tool's advertised
// outputSchema with ajv, as an MCP client does.
//
// The property the ticket asks for above all: the series is CHANGE-ONLY, and the tool never
// interpolates it. So every success here asserts the relayed points are the API's points, the
// same count and the same values, and the texts say change-only and when recording began.
//
// tools.test.mjs (and tools-legacy.test.mjs) also run epss_history through every generic
// failure-polarity, wording and envelope check; this file holds what is particular to it.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { AjvJsonSchemaValidator } from "@modelcontextprotocol/server/validators/ajv";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { readPkgFile, serverCommand } from "./server-under-test.mjs";

const ERAS = [MODERN, "2025-06-18"];
const START = "2026-05-27T03:00:00Z";
// core-backend's epssCompleteSince (#2867): the first row of the atomic write path.
const COMPLETE = "2026-10-04T23:14:54.744709Z";
const PATH = (id) => `/api/v1/public/cves/${id}/epss-history`;

// coverage as core-backend answers it for a record that reaches back before complete_since.
const COVERAGE = {
  recorded_from: START,
  complete_since: COMPLETE,
  series_complete: false,
  points_before_complete_since: 3,
  run_log_since: "2026-10-06T13:40:00Z",
  first_day: "2026-10-06",
  last_day: "2026-10-09",
  days_held: 2,
  days_partial: ["2026-10-07"],
  days_missing: ["2026-10-08"],
  runs_undated: 0,
  refresh_runs_truncated: false,
};

// Several changes, shaped as core-backend cve/epss_history.go answers (TestEPSSHistory_Endpoint).
const SEVERAL = "CVE-2021-44228";
const SEVERAL_BODY = {
  cve_id: SEVERAL,
  series_kind: "change_only",
  series_starts_at: START,
  complete_since: COMPLETE,
  coverage: COVERAGE,
  current: { epss_score: 0.94358, epss_percentile: 0.99911, epss_updated_at: "2026-09-30T03:00:00Z" },
  points: [
    { at: "2026-06-01T03:00:00Z", epss_score: 0.2, epss_percentile: 0.8, score_date: null },
    { at: "2026-07-14T03:00:00Z", epss_score: 0.75, epss_percentile: 0.99, score_date: null },
    { at: "2026-09-30T03:00:00Z", epss_score: 0.94358, epss_percentile: 0.99911, score_date: null },
  ],
  history_rows: 4,
  points_truncated: false,
  latest_point_matches_current: true,
};
// No change recorded, in a record that reaches back before complete_since: "measured" only from it.
const NONE = "CVE-2020-1472";
const NONE_BODY = {
  cve_id: NONE,
  series_kind: "change_only",
  series_starts_at: START,
  complete_since: COMPLETE,
  coverage: { ...COVERAGE, points_before_complete_since: 0 },
  current: { epss_score: 0.5, epss_percentile: 0.9, epss_updated_at: "2026-01-01T03:00:00Z" },
  points: [],
  history_rows: 0,
  points_truncated: false,
  latest_point_matches_current: null,
};
// The other polarity: a record that begins at complete_since, so its empty series is measured.
const NONE_COMPLETE = "CVE-2020-1473";
const NONE_COMPLETE_BODY = {
  ...NONE_BODY,
  cve_id: NONE_COMPLETE,
  series_starts_at: COMPLETE,
  coverage: { ...NONE_BODY.coverage, recorded_from: COMPLETE, series_complete: true },
};
// An API older than #2867: no complete_since, no coverage. Nothing may be called complete.
const LEGACY = "CVE-2020-1474";
const LEGACY_BODY = (({ complete_since: _c, coverage: _v, ...rest }) => ({ ...rest, cve_id: LEGACY }))(NONE_BODY);
// series_complete true with no complete_since to be complete from: not believed.
const CLAIMS_COMPLETE = "CVE-2020-1475";
const CLAIMS_COMPLETE_BODY = (({ complete_since: _c, ...rest }) => ({
  ...rest,
  cve_id: CLAIMS_COMPLETE,
  coverage: { ...COVERAGE, complete_since: null, series_complete: true },
}))(SEVERAL_BODY);
// Many missing days: the note names the first ten and points to coverage for the rest.
const GAPPY = "CVE-2020-1476";
const MANY = Array.from({ length: 14 }, (_, i) => `2026-11-${String(i + 1).padStart(2, "0")}`);
const GAPPY_BODY = { ...SEVERAL_BODY, cve_id: GAPPY, coverage: { ...COVERAGE, last_day: "2026-11-15", days_missing: MANY } };
const NO_EPSS = "CVE-2019-0708";
const NO_EPSS_BODY = {
  cve_id: NO_EPSS,
  series_kind: "change_only",
  series_starts_at: null,
  current: { epss_score: null, epss_percentile: null, epss_updated_at: null },
  points: [],
  history_rows: 0,
  points_truncated: false,
  latest_point_matches_current: null,
};
// A change missing from the series: the newest point is not the current value.
const MISSED = "CVE-2018-0001";
const MISSED_BODY = {
  ...SEVERAL_BODY,
  cve_id: MISSED,
  current: { ...SEVERAL_BODY.current, epss_score: 0.97 },
  latest_point_matches_current: false,
  points_truncated: true,
};
const UNKNOWN = "CVE-2099-99999";
const UNAVAILABLE = "CVE-2017-0144";
// Answers the tool must not relay: a series that says it is daily, and one with no points.
const DAILY = "CVE-2016-0001";
const NO_POINTS = "CVE-2016-0002";

const ANSWERS = {
  [PATH(SEVERAL)]: { status: 200, body: SEVERAL_BODY },
  [PATH(NONE)]: { status: 200, body: NONE_BODY },
  [PATH(NONE_COMPLETE)]: { status: 200, body: NONE_COMPLETE_BODY },
  [PATH(LEGACY)]: { status: 200, body: LEGACY_BODY },
  [PATH(CLAIMS_COMPLETE)]: { status: 200, body: CLAIMS_COMPLETE_BODY },
  [PATH(GAPPY)]: { status: 200, body: GAPPY_BODY },
  [PATH(NO_EPSS)]: { status: 200, body: NO_EPSS_BODY },
  [PATH(MISSED)]: { status: 200, body: MISSED_BODY },
  [PATH(UNKNOWN)]: { status: 404, body: { error: `CVE not found: ${UNKNOWN}` } },
  [PATH(UNAVAILABLE)]: { status: 503, body: { error: "The EPSS history could not be read. This is not an empty history — nothing was evaluated. Retry shortly.", code: "EPSS_HISTORY_UNAVAILABLE" } },
  [PATH(DAILY)]: { status: 200, body: { ...SEVERAL_BODY, cve_id: DAILY, series_kind: "daily" } },
  [PATH(NO_POINTS)]: { status: 200, body: (({ points: _p, ...rest }) => ({ ...rest, cve_id: NO_POINTS }))(SEVERAL_BODY) },
};

const validator = new AjvJsonSchemaValidator();
const isValid = (schema, value) => validator.getValidator(schema)(value).valid;
const textBlocks = (res) => (res.content ?? []).filter((c) => c.type === "text").map((c) => c.text);
const branchOf = (schema, state) => (schema.oneOf ?? []).find((b) => b.properties?.state?.enum?.includes(state));

let stub;
const seen = [];
before(async () => {
  stub = http.createServer((req, res) => {
    seen.push(req.url);
    const a = ANSWERS[new URL(req.url, "http://stub").pathname];
    if (!a) {
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("404 page not found\n");
      return;
    }
    res.writeHead(a.status, { "content-type": "application/json" });
    res.end(JSON.stringify(a.body));
  });
  await new Promise((resolve) => stub.listen(0, "127.0.0.1", resolve));
});
after(() => new Promise((resolve) => stub.close(resolve)));

for (const era of ERAS) {
  describe(`epss_history [${era}]`, () => {
    let client, tool, schema;
    const results = [];
    const call = async (cve_id) => {
      const res = await client.callTool({ name: "epss_history", arguments: { cve_id } });
      results.push([cve_id, res]);
      return res;
    };
    before(async () => {
      const env = { ...process.env, ECHELONGRAPH_API_BASE: `http://127.0.0.1:${stub.address().port}`, ECHELONGRAPH_API_TIMEOUT_MS: "2000" };
      client = await connect({ era, ...serverCommand(), env, stderr: "inherit" });
      tool = (await client.listTools()).tools.find((t) => t.name === "epss_history");
      schema = tool?.outputSchema;
    });
    after(() => client?.close());

    it("is listed, read-only, with an outputSchema whose data requires the series and admits only change_only", () => {
      assert.ok(tool, "epss_history is not in tools/list");
      assert.deepEqual(tool.annotations, { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true });
      const data = branchOf(schema, "measured").properties.data;
      for (const k of ["cve_id", "series_kind", "series_starts_at", "current", "points"]) assert.ok(data.required.includes(k), `data does not require ${k}`);
      assert.deepEqual(data.properties.series_kind.enum, ["change_only"]);
    });

    it("the description says change-only, never a daily series, and what series_starts_at means", () => {
      const d = tool.description;
      assert.match(d, /The series is change-only: a point is a recorded change, and a day without a point is not a recorded value\./);
      assert.match(d, /A daily series interpolated from it holds values EchelonGraph never recorded, so the series is never a daily series\./);
      assert.match(d, /Before series_starts_at nothing was recorded, so a missing point there means not recorded, not unchanged/);
      assert.match(d, /latest_point_matches_current false means a change is missing from the series\./);
      assert.match(d, /Between series_starts_at and complete_since the record misses changes, so a missing point there does not mean unchanged either; only from complete_since on is every change a point\./);
    });

    it("several changes: the API's points relayed exactly, none added, measured with the record's write time", async () => {
      const res = await call(SEVERAL);
      assert.notEqual(res.isError, true, JSON.stringify(res).slice(0, 400));
      const sc = res.structuredContent;
      assert.equal(sc.state, "measured");
      // Never interpolated: the same points, the same count, nothing between them.
      assert.deepEqual(sc.data.points, SEVERAL_BODY.points);
      assert.deepEqual(JSON.parse(textBlocks(res)[0]), SEVERAL_BODY);
      assert.equal(sc.measured_at, SEVERAL_BODY.current.epss_updated_at);
      assert.deepEqual(sc.coverage, {
        series_kind: "change_only",
        series_starts_at: START,
        complete_since: COMPLETE,
        series_complete: false,
        points: 3,
        points_before_complete_since: 3,
        points_truncated: false,
        first_day: "2026-10-06",
        last_day: "2026-10-09",
        days_held: 2,
        days_partial: ["2026-10-07"],
        days_missing: ["2026-10-08"],
      });
      assert.equal(sc.freshness, null);
      assert.ok(sc.notes.some((n) => n.startsWith("series_kind is change_only:") && n.includes("no point here is interpolated")), sc.notes.join(" | "));
      assert.ok(sc.notes.includes("The value in force before a CVE's first point is not in the series."));
      const note = textBlocks(res)[1];
      assert.match(note, /^epss_history OK: EchelonGraph answered HTTP 200 from /);
      assert.match(note, /3 recorded changes, from 0\.2 at 2026-06-01T03:00:00Z to 0\.94358 at 2026-09-30T03:00:00Z\./);
      assert.ok(note.includes(`Recording began at ${START} (series_starts_at): before it a missing point means not recorded, not unchanged.`), note);
      assert.doesNotMatch(note, /is missing from the series/);
      // #2867: the incomplete part is named, with this series' share of it, and never called complete.
      assert.ok(
        note.includes(
          `The record is complete only from ${COMPLETE} (complete_since): from then on every change a refresh applied is a point. Between ${START} and complete_since EchelonGraph's earlier write path missed changes, so there a missing point does not mean unchanged, and this series is not complete. 3 of this series' 3 points fall there.`,
        ),
        note,
      );
      assert.doesNotMatch(note, /The record is complete \(/);
      assert.ok(
        note.includes(
          "FIRST score dates in EchelonGraph's run log (run log since 2026-10-06T13:40:00Z; earlier dates are not listed): 2026-10-06 to 2026-10-09, 2 held; not held: 2026-10-08; held for some CVEs only (a refresh failed part-way): 2026-10-07.",
        ),
        note,
      );
    });

    it("a record that begins at complete_since is complete, and its empty series is measured", async () => {
      const res = await call(NONE_COMPLETE);
      const sc = res.structuredContent;
      assert.equal(sc.coverage.series_complete, true);
      assert.equal(sc.coverage.complete_since, COMPLETE);
      const note = textBlocks(res)[1];
      assert.ok(note.includes(`No EPSS change is recorded for ${NONE_COMPLETE} since recording began at ${COMPLETE}: a measured empty series, not a lookup failure.`), note);
      assert.ok(note.includes(`The record is complete (complete_since ${COMPLETE}): every change a refresh applied since recording began is a point.`), note);
    });

    it("an API without complete_since: nothing is called complete or measured-empty, and coverage says it does not know", async () => {
      const res = await call(LEGACY);
      assert.notEqual(res.isError, true);
      const sc = res.structuredContent;
      assert.equal(sc.coverage.complete_since, null);
      assert.equal(sc.coverage.series_complete, false);
      assert.equal(sc.coverage.points_before_complete_since, null);
      assert.equal(sc.coverage.first_day, null);
      assert.equal(sc.coverage.days_held, null);
      assert.deepEqual(sc.coverage.days_missing, []);
      const note = textBlocks(res)[1];
      assert.doesNotMatch(note, /a measured empty series/);
      assert.ok(note.includes("The answer does not say from when the record is complete, so the empty series is not evidence that the score held still."), note);
      assert.ok(note.includes("The answer does not say from when the record is complete (complete_since is absent), so a missing point anywhere in this series may be a missed change, not an unchanged score."), note);
      assert.doesNotMatch(note, /run log/);
    });

    it("series_complete true without a complete_since to be complete from is not believed", async () => {
      const res = await call(CLAIMS_COMPLETE);
      const sc = res.structuredContent;
      assert.equal(sc.coverage.series_complete, false);
      assert.equal(sc.coverage.complete_since, null);
      assert.doesNotMatch(textBlocks(res)[1], /The record is complete/);
    });

    it("a long list of missing days is named up to ten in the note, all of them in coverage", async () => {
      const res = await call(GAPPY);
      assert.deepEqual(res.structuredContent.coverage.days_missing, MANY);
      const note = textBlocks(res)[1];
      assert.ok(note.includes(`not held: ${MANY.slice(0, 10).join(", ")} and 4 more (coverage.days_missing)`), note);
    });

    it("the latest point equals current.epss_score, as the API states it", async () => {
      const sc = (await call(SEVERAL)).structuredContent;
      assert.equal(sc.data.points.at(-1).epss_score, sc.data.current.epss_score);
      assert.equal(sc.data.latest_point_matches_current, true);
    });

    it("no change recorded in a record that reaches back before complete_since: measured only from complete_since, not a failure", async () => {
      const res = await call(NONE);
      assert.notEqual(res.isError, true);
      const sc = res.structuredContent;
      assert.equal(sc.state, "measured");
      assert.deepEqual(sc.data.points, []);
      assert.equal(sc.coverage.points, 0);
      assert.equal(sc.coverage.series_complete, false);
      const note = textBlocks(res)[1];
      assert.ok(
        note.includes(
          `No EPSS change is recorded for ${NONE} since recording began at ${START}. From complete_since (${COMPLETE}) that is measured: no refresh since then changed it. Before complete_since the record misses changes, so the empty series is not evidence that the score held still from ${START} to ${COMPLETE}.`,
        ),
        note,
      );
      assert.doesNotMatch(note, /a measured empty series/);
    });

    it("no EPSS score and nothing recorded yet: says so, and measured_at is null", async () => {
      const res = await call(NO_EPSS);
      const sc = res.structuredContent;
      assert.equal(sc.state, "measured");
      assert.equal(sc.measured_at, null);
      const note = textBlocks(res)[1];
      assert.match(note, /EchelonGraph's record holds no EPSS score for CVE-2019-0708 \(current\.epss_score is null\)\./);
      assert.match(note, /No EPSS change has been recorded for any CVE yet \(series_starts_at is null\), so this empty series says nothing about how the score moved\./);
    });

    it("a missing change and a truncated series are named, not smoothed over", async () => {
      const note = textBlocks(await call(MISSED))[1];
      assert.match(note, /latest_point_matches_current is false: the newest recorded point is not the record's current value, so at least one change is missing from the series\./);
      assert.match(note, /points_truncated is true: only the newest records were read, so the earliest changes are missing from this series\./);
    });

    it("an unknown CVE is the API's 404, quoted, and a failure, never an empty series", async () => {
      const res = await call(UNKNOWN);
      assert.equal(res.isError, true);
      assert.equal(res.structuredContent.state, "failed");
      assert.equal(res.structuredContent.error.status, 404);
      assert.match(textBlocks(res)[0], /HTTP 404/);
      assert.match(textBlocks(res)[0], new RegExp(`CVE not found: ${UNKNOWN}`));
      assert.ok(!("data" in res.structuredContent));
    });

    it("the API's 503 EPSS_HISTORY_UNAVAILABLE is a failure that is not a finding", async () => {
      const res = await call(UNAVAILABLE);
      assert.equal(res.isError, true);
      assert.equal(res.structuredContent.state, "failed");
      assert.match(textBlocks(res)[0], /HTTP 503/);
      assert.match(textBlocks(res)[0], /this is not a finding/);
    });

    it("a malformed id is refused here and never sent; a lower-case id is sent canonical", async () => {
      const before = seen.length;
      const bad = await call("not-a-cve; DROP");
      assert.equal(bad.isError, true);
      assert.equal(bad.structuredContent.state, "invalid_input");
      assert.equal(seen.length, before, `a request was made: ${seen.slice(before)}`);
      const blank = await call("  ");
      assert.equal(blank.structuredContent.state, "invalid_input");
      const lower = await call(SEVERAL.toLowerCase());
      assert.notEqual(lower.isError, true);
      assert.equal(seen.at(-1), PATH(SEVERAL));
    });

    it("an answer that is not a change-only series is a failure, never relayed: series_kind daily, or no points", async () => {
      for (const id of [DAILY, NO_POINTS]) {
        const res = await call(id);
        assert.equal(res.isError, true, `${id}: ${JSON.stringify(res).slice(0, 300)}`);
        assert.equal(res.structuredContent.state, "failed");
        assert.equal(res.structuredContent.error.kind, "unexpected_shape");
        assert.ok(!("data" in res.structuredContent));
      }
    });

    it("every result validates against the advertised outputSchema (ajv), and the validator is not vacuous", () => {
      assert.ok(results.length >= 12, `only ${results.length} results`);
      for (const [id, res] of results) {
        const v = validator.getValidator(schema)(res.structuredContent);
        assert.ok(v.valid, `${id}: ${v.errorMessage} ${JSON.stringify(res.structuredContent).slice(0, 400)}`);
      }
      const ok = results.find(([id, r]) => id === SEVERAL && !r.isError)[1].structuredContent;
      assert.ok(isValid(schema, ok));
      for (const [label, mutant] of [
        ["a daily series", { ...ok, data: { ...ok.data, series_kind: "daily" } }],
        ["a success without points", { ...ok, data: (({ points: _p, ...rest }) => rest)(ok.data) }],
        ["a point without a score", { ...ok, data: { ...ok.data, points: [{ at: "2026-06-01T03:00:00Z" }] } }],
        ["a success without data", (({ data: _d, ...rest }) => rest)(ok)],
        ["coverage with an unnamed field", { ...ok, coverage: { ...ok.coverage, interpolated: true } }],
      ]) {
        assert.equal(isValid(schema, mutant), false, `the validator accepted ${label}`);
      }
    });
  });
}

it("the README lists epss_history and says it is change-only, never a daily series, and complete only from complete_since", () => {
  const readme = readPkgFile("README.md");
  assert.match(readme, /\| `epss_history` \| [^\n]*`change_only`[^\n]*never a daily series[^\n]*not recorded, not unchanged\. \|/);
  assert.match(readme, /\| `epss_history` \| [^\n]*`complete_since`, from when every change is a point \(before it the record misses changes, so a missing point there does not mean unchanged, and the series is never called complete\)/);
});
