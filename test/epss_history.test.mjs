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
const PATH = (id) => `/api/v1/public/cves/${id}/epss-history`;

// Several changes, shaped as core-backend cve/epss_history.go answers (TestEPSSHistory_Endpoint).
const SEVERAL = "CVE-2021-44228";
const SEVERAL_BODY = {
  cve_id: SEVERAL,
  series_kind: "change_only",
  series_starts_at: START,
  current: { epss_score: 0.94358, epss_percentile: 0.99911, epss_updated_at: "2026-09-30T03:00:00Z" },
  points: [
    { at: "2026-06-01T03:00:00Z", epss_score: 0.2, epss_percentile: 0.8 },
    { at: "2026-07-14T03:00:00Z", epss_score: 0.75, epss_percentile: 0.99 },
    { at: "2026-09-30T03:00:00Z", epss_score: 0.94358, epss_percentile: 0.99911 },
  ],
  history_rows: 4,
  points_truncated: false,
  latest_point_matches_current: true,
};
const NONE = "CVE-2020-1472";
const NONE_BODY = {
  cve_id: NONE,
  series_kind: "change_only",
  series_starts_at: START,
  current: { epss_score: 0.5, epss_percentile: 0.9, epss_updated_at: "2026-01-01T03:00:00Z" },
  points: [],
  history_rows: 0,
  points_truncated: false,
  latest_point_matches_current: null,
};
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

    it("the description says change-only, never interpolate, and what series_starts_at means", () => {
      const d = tool.description;
      assert.match(d, /The series is change-only: a point is a recorded change, and a day without a point is not a recorded value\./);
      assert.match(d, /Never interpolate it into a daily series\./);
      assert.match(d, /Before series_starts_at nothing was recorded, so a missing point there means not recorded, not unchanged/);
      assert.match(d, /latest_point_matches_current false means a change is missing from the series\./);
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
      assert.deepEqual(sc.coverage, { series_kind: "change_only", series_starts_at: START, points: 3, points_truncated: false });
      assert.equal(sc.freshness, null);
      assert.ok(sc.notes.some((n) => n.startsWith("series_kind is change_only:") && n.includes("no point here is interpolated")), sc.notes.join(" | "));
      assert.ok(sc.notes.includes("The value in force before a CVE's first point is not in the series."));
      const note = textBlocks(res)[1];
      assert.match(note, /^epss_history OK: EchelonGraph answered HTTP 200 from /);
      assert.match(note, /3 recorded changes, from 0\.2 at 2026-06-01T03:00:00Z to 0\.94358 at 2026-09-30T03:00:00Z\./);
      assert.ok(note.includes(`Recording began at ${START} (series_starts_at): before it a missing point means not recorded, not unchanged.`), note);
      assert.doesNotMatch(note, /is missing from the series/);
    });

    it("the latest point equals current.epss_score, as the API states it", async () => {
      const sc = (await call(SEVERAL)).structuredContent;
      assert.equal(sc.data.points.at(-1).epss_score, sc.data.current.epss_score);
      assert.equal(sc.data.latest_point_matches_current, true);
    });

    it("no change recorded: a measured empty series, worded as such, not a failure", async () => {
      const res = await call(NONE);
      assert.notEqual(res.isError, true);
      const sc = res.structuredContent;
      assert.equal(sc.state, "measured");
      assert.deepEqual(sc.data.points, []);
      assert.equal(sc.coverage.points, 0);
      assert.ok(textBlocks(res)[1].includes(`No EPSS change is recorded for ${NONE} since recording began at ${START}: a measured empty series, not a lookup failure.`), textBlocks(res)[1]);
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

it("the README lists epss_history and says it is change-only, never a daily series", () => {
  const readme = readPkgFile("README.md");
  assert.match(readme, /\| `epss_history` \| [^\n]*`change_only`[^\n]*never a daily series[^\n]*not recorded, not unchanged\. \|/);
});
