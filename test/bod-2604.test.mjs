// #2880: get_cve says what the record's CISA BOD 26-04 timeline is, where the scorer wrote it
// (core-backend/internal/cve/scoring/bod2604.go, algorithm v3.4+): for a publicly exposed system
// and for one that is not, each input with its source, CISA's own default named as CISA's. A
// record scored before v3.4, or a malformed block, gets no sentence. The outputSchema describes
// score_factors.bod_26_04, and echelongraph_ssvc_decision as EchelonGraph's run of CISA's SSVC
// table, never a decision CISA published (#3053).
//
// Runs against dist/index.js, so build first — `npm test` does.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
// #3121: answers are validated against the closed success branch (strict-output.mjs).
import { StrictOutputValidator } from "./strict-output.mjs";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { serverCommand } from "./server-under-test.mjs";

const record = (id, extra = {}) => ({
  cve_id: id,
  description: "test record",
  severity: "CRITICAL",
  cvss_v3_score: 9.8,
  echelongraph_score: 9.8,
  echelongraph_severity: "CRITICAL",
  score_assessed: true,
  published: "2026-09-01T00:00:00Z",
  modified: "2026-09-02T00:00:00Z",
  updated_at: "2026-09-03T00:00:00Z",
  references: [],
  cpe_match: [],
  ...extra,
});
const DEFAULT = { value: "no", source: "cisa_bod_26_04_default" };
const SSVC = {
  tree: "CISA Coordinator v2.0.3 (CISA SSVC Guide, Nov 2022, Table 9)", decision: "Track", decision_mission: "medium",
  by_mission: { low: ["Track"], medium: ["Track"], high: ["Track*"] },
  exploitation: { value: "none", source: "no_exploitation_evidence" }, automatable: DEFAULT, technical_impact: { value: "total", source: "cisa_bod_26_04_default" },
};
const BOD = {
  table: "CISA BOD 26-04 Table 1 (CERT/CC decision table cisa:DT_BOD2604 v1.0.0)",
  kev: { value: "no", source: "cisa_kev" }, automatable: DEFAULT, technical_impact: { value: "total", source: "cisa_bod_26_04_default" },
  if_publicly_exposed: ["14D"], if_not_publicly_exposed: ["FSU"], timelines: { "14D": "14 days", FSU: "Fix on system upgrade" },
};
const UNKNOWN = { value: "unknown", source: "not_supplied" };
const BOD_KEV = {
  ...BOD, kev: { value: "yes", source: "cisa_kev" }, automatable: UNKNOWN, technical_impact: UNKNOWN,
  if_publicly_exposed: ["14D", "3D", "3DF"], if_not_publicly_exposed: ["14D", "3DF"],
};

const ANSWERS = {
  "/api/v1/public/cves/CVE-2099-28800": record("CVE-2099-28800", { echelongraph_ssvc_decision: "Track", score_factors: { algorithm_version: "v3.4", ssvc: SSVC, bod_26_04: BOD } }),
  "/api/v1/public/cves/CVE-2099-28801": record("CVE-2099-28801", { kev_listed: true, echelongraph_ssvc_decision: "Act", score_factors: { algorithm_version: "v3.4", ssvc: SSVC, bod_26_04: BOD_KEV } }),
  // Scored before v3.4: no bod_26_04.
  "/api/v1/public/cves/CVE-2099-28802": record("CVE-2099-28802", { echelongraph_ssvc_decision: "Track", score_factors: { algorithm_version: "v3.2", ssvc: SSVC } }),
  // A malformed block: an outcome CERT/CC's table does not have.
  "/api/v1/public/cves/CVE-2099-28803": record("CVE-2099-28803", { score_factors: { algorithm_version: "v3.4", bod_26_04: { ...BOD, if_publicly_exposed: ["30D"] } } }),
};

let stub;
before(async () => {
  stub = http.createServer((req, res) => {
    const a = ANSWERS[req.url];
    res.writeHead(a ? 200 : 404, { "content-type": "application/json" });
    res.end(JSON.stringify(a ?? { error: "not found" }));
  });
  await new Promise((resolve) => stub.listen(0, "127.0.0.1", resolve));
});
after(() => new Promise((resolve) => stub.close(resolve)));

const validator = new StrictOutputValidator();
const textBlocks = (res) => (res.content ?? []).filter((c) => c.type === "text").map((c) => c.text);

function recordProps(s) {
  if (s === null || typeof s !== "object") return undefined;
  if (s.properties && "cve_id" in s.properties && "kev_listed" in s.properties) return s.properties;
  for (const v of Array.isArray(s) ? s : Object.values(s)) {
    const found = recordProps(v);
    if (found) return found;
  }
  return undefined;
}

describe("#2880 get_cve: the SSVC decision and CISA BOD 26-04's timeline", () => {
  let client;
  let getCve;
  before(async () => {
    client = await connect({
      era: MODERN,
      ...serverCommand(),
      env: { ...process.env, ECHELONGRAPH_API_BASE: `http://127.0.0.1:${stub.address().port}`, ECHELONGRAPH_API_TIMEOUT_MS: "2000" },
      stderr: "ignore",
    });
    const { tools } = await client.listTools();
    getCve = tools.find((t) => t.name === "get_cve");
  });
  after(() => client?.close());
  const call = async (cve_id) => {
    const res = await client.callTool({ name: "get_cve", arguments: { cve_id } });
    const v = validator.getValidator(getCve.outputSchema)(res.structuredContent);
    assert.ok(v.valid, v.errorMessage);
    return { res, note: textBlocks(res)[1] ?? "" };
  };

  it("the outputSchema describes both, and never calls the decision CISA's", () => {
    const props = recordProps(getCve.outputSchema);
    assert.match(props.echelongraph_ssvc_decision.description, /CISA publishes the table and, for some CVEs, its inputs, not a decision for a CVE/);
    assert.match(props.score_factors.description, /bod_26_04/);
    for (const d of [getCve.description, props.echelongraph_ssvc_decision.description, props.score_factors.description]) {
      assert.doesNotMatch(d, /CISA SSVC|CISA['’]s SSVC decision(?! table)/);
      assert.doesNotMatch(d, /60 days[^.]{0,60}default|default[^.]{0,60}60 days/i);
    }
  });

  it("a v3.4 record not in KEV: both exposure answers, each input's source, CISA's default named as CISA's", async () => {
    const { res, note } = await call("CVE-2099-28800");
    assert.deepEqual(res.structuredContent.data.score_factors.bod_26_04, BOD, "relayed whole");
    assert.ok(note.includes("score_factors.bod_26_04 is CISA BOD 26-04's remediation timeline for CVE-2099-28800: 14 days if the affected system is publicly exposed, Fix on system upgrade if it is not;"), note);
    assert.ok(note.includes("Its inputs: in CISA KEV no, automatable no (CISA's BOD 26-04 default for a CVE not in KEV that nobody has assessed), technical impact total (CISA's BOD 26-04 default for a CVE not in KEV that nobody has assessed)."), note);
    assert.doesNotMatch(note, /60 days/);
  });

  it("a KEV-listed record CISA has not yet assessed: unknown inputs, every timeline they allow", async () => {
    const { note } = await call("CVE-2099-28801");
    assert.ok(note.includes("14 days, 3 days or 3 days & forensic triage if the affected system is publicly exposed, 14 days or 3 days & forensic triage if it is not"), note);
    assert.ok(note.includes("automatable unknown (not yet published by CISA, so every timeline it allows is listed)"), note);
  });

  it("a record scored before v3.4, and a malformed block, get no BOD 26-04 sentence", async () => {
    const old = await call("CVE-2099-28802");
    assert.doesNotMatch(old.note, /bod_26_04/, old.note);
    const bad = await call("CVE-2099-28803");
    assert.doesNotMatch(bad.note, /bod_26_04|30D/, bad.note);
    assert.ok(bad.res.structuredContent.data.score_factors.bod_26_04, "the malformed block is still relayed in data");
  });
});
