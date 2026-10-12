// #3140: text-bound-live.mjs --hosted replays the API's answer whole, never a 3.0.0 or later
// endpoint's default cut of it.
//
// Through 3.0.0 the --hosted replay called each tool without full: true and served its
// structuredContent.data to this checkout's server as production's answer. Since #3013 that data is
// cut past 30,000 characters, so the replay measured a cut and stayed green whatever happened:
// get_cve CVE-2021-44228's default data on hosted 3.0.0 holds cpe_match 77 of 396 and references 77
// of 103 (read 2026-10-11; with full: true, 396 and 103). These hold the two helpers it now calls
// (text-bound.mjs hostedArgs, hostedReplay) and that it calls them, with a control: 3.0.0's call.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { FULL_SINCE, LIVE_RECORD, SHAPED, extraAnswers, hostedArgs, hostedReplay } from "./text-bound.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LIVE = fs.readFileSync(path.join(HERE, "text-bound-live.mjs"), "utf8");
// A hosted answer shaped as 3.0.0's default get_cve CVE-2021-44228 (its data cut), and as the same
// call with full: true (whole).
const CPE = (n) => Array.from({ length: n }, (_, i) => ({ criteria: `cpe:2.3:a:apache:log4j:2.0:beta${i}:*:*:*:*:*:*`, vulnerable: true }));
const CUT = { structuredContent: { state: "measured", data_truncated: true, truncated: { cpe_match: { total: 396, returned: 77 } }, data: { cve_id: "CVE-2021-44228", cpe_match: CPE(77) } } };
const WHOLE = { structuredContent: { state: "measured", data_truncated: false, data: { cve_id: "CVE-2021-44228", cpe_match: CPE(396) } } };
const ARGS = { cve_id: "CVE-2021-44228" };

describe("#3140: the --hosted replay is the API's answer whole", () => {
  it("a server at 3.0.0 or later is called with full: true; one before it, which has no such argument and never cuts data, as asked", () => {
    assert.deepEqual(FULL_SINCE, [3, 0, 0]);
    for (const v of ["3.0.0", "3.0.1", "3.1.0", "10.0.0", "3.0.1-rc.1"]) assert.deepEqual(hostedArgs(ARGS, v), { ...ARGS, full: true }, v);
    for (const v of ["2.7.2", "2.10.9", "1.0.0"]) assert.deepEqual(hostedArgs(ARGS, v), ARGS, v);
    assert.throws(() => hostedArgs(ARGS, undefined), /reports no version/);
  });

  it("the replay of get_cve CVE-2021-44228 called so is the whole answer: 396 cpe_match entries", () => {
    const asked = hostedArgs(ARGS, "3.0.0");
    assert.equal(hostedReplay(WHOLE, asked, "3.0.0").cpe_match.length, 396);
  });

  it("refused: a 3.0.0 or later server called without full: true (3.0.0's replay), and any answer whose data is cut", () => {
    // Control: what 3.0.0's --hosted did, the call as SHAPED gives it.
    assert.throws(() => hostedReplay(CUT, ARGS, "3.0.0"), /did not say full: true: refusing to replay/);
    assert.throws(() => hostedReplay(WHOLE, { ...ARGS, full: false }, "3.0.1"), /did not say full: true/);
    assert.throws(() => hostedReplay(CUT, { ...ARGS, full: true }, "3.0.0"), /data_truncated true.*refusing/);
    // A server before 3.0.0 is replayed as before.
    assert.equal(hostedReplay(WHOLE, ARGS, "2.7.2").cpe_match.length, 396);
  });

  it("text-bound-live.mjs calls the hosted tool with hostedArgs and replays only through hostedReplay", () => {
    assert.match(LIVE, /const asked = hostedArgs\(args, version\);\s*const there = await remote\.callTool\(\{ name: c\.tool, arguments: asked \}\);/);
    assert.match(LIVE, /serve = \{ kind: "one", body: hostedReplay\(there, asked, version\), extra: extraAnswers\(c\) \};/);
    // #3140: the routes a tool reads beside its own are served from the case's fixture, not with
    // the replayed answer (through the first --hosted --record the vendor tools' /coverage got it).
    assert.match(LIVE, /serve\.kind === "one" \? \(serve\.extra\?\.\[pathname\] \?\? serve\.body\)/);
    // Control: 3.0.0's replay of the default call's data.
    assert.doesNotMatch(LIVE, /body: there\.structuredContent\.data/);
    assert.doesNotMatch(LIVE, /callTool\(\{ name: c\.tool, arguments: args \}\);\s*if \(RELAYS_A_CUT/);
    // The header says the replay is whole, not that a default call's data is the API's answer.
    assert.match(LIVE, /with full: true when the endpoint\s*\n\/\/\s+reports 3\.0\.0 or later/);
  });
});

// #3140's review: the record holds structured for every case text-bound-live.mjs measures (every
// case without `live`), from one --hosted --record on 3.0.0 with full: true; a case it cannot
// measure says why in `live`.
describe("#3140: fixtures/text-bound-live.json has structured for every case not marked live", () => {
  it("each SHAPED case either says why it is not measured (live) or has a recorded structured size", () => {
    const rec = JSON.parse(fs.readFileSync(LIVE_RECORD, "utf8")).cases;
    const missing = SHAPED.filter((c) => !c.live && !c.resource && !(typeof rec[c.label]?.structured === "number")).map((c) => c.label);
    assert.deepEqual(missing, []);
    for (const c of SHAPED.filter((x) => x.live)) assert.ok(typeof c.live === "string" && c.live.length > 20, c.label);
  });
  it("the vendor tools' /coverage is served beside a replayed answer, from the case's fixture", () => {
    const c = SHAPED.find((x) => x.label.startsWith("search_vendor_advisories, default page"));
    assert.deepEqual(Object.keys(extraAnswers(c)), ["/api/v1/public/vendor-advisories/coverage"]);
    assert.deepEqual(extraAnswers(SHAPED.find((x) => x.tool === "get_cve")), {});
  });
});
