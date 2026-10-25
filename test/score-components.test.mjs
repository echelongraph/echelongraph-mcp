// #2879: get_cve relays the scorer's three components (core-backend scoring v4.0,
// internal/cve/scoring/components.go), which GET /api/v1/public/cves/:id serves at the top level:
// eg_severity (the CVSS base no exploitation signal raises), eg_likelihood (FIRST's EPSS over 30
// days, confirmed exploitation reported beside it) and eg_priority (the SSVC decision and the BOD
// 26-04 timeline). The outputSchema describes them, the answer passes the strict schema, and the
// note says, where the record carries what it reads, that a KEV-floored or EPSS-lifted score is
// exploitation, not impact, and that a null likelihood is unknown, not low. A record scored before
// v4.0 reads as it did. The fixtures' component objects are scoring.Compute's own output for the
// inputs named beside each (a KEV-listed CVSS 5.4, a KEV-listed CVE with no CVSS, an EPSS 0.60
// uplift over 6.5, a plain NVD 9.8), copied verbatim.
//
// Runs against dist/index.js, so build first — `npm test` does.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { StrictOutputValidator } from "./strict-output.mjs";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { serverCommand } from "./server-under-test.mjs";

const record = (id, extra = {}) => ({
  cve_id: id,
  description: "test record",
  severity: "MEDIUM",
  cvss_v3_score: 5.4,
  score_assessed: true,
  published: "2026-09-01T00:00:00Z",
  modified: "2026-09-02T00:00:00Z",
  updated_at: "2026-09-03T00:00:00Z",
  references: [],
  cpe_match: [],
  ...extra,
});
const UNKNOWN = { source: "not_supplied", value: "unknown" };
const KEV_PRIORITY = {
  bod_26_04: { if_not_publicly_exposed: ["14D", "3DF"], if_publicly_exposed: ["14D", "3D", "3DF"] },
  inputs: { automatable: UNKNOWN, exploitation: { source: "kev", value: "active" }, kev: { source: "cisa_kev", value: "yes" }, technical_impact: UNKNOWN },
  ssvc: { by_mission: { high: ["Attend", "Act"], low: ["Track", "Attend"], medium: ["Track", "Attend", "Act"] }, decision: "Act", mission: "medium" },
};
const DEFAULT_PRIORITY = {
  bod_26_04: { if_not_publicly_exposed: ["FSU"], if_publicly_exposed: ["14D"] },
  inputs: {
    automatable: { source: "cisa_bod_26_04_default", value: "no" },
    exploitation: { source: "no_exploitation_evidence", value: "none" },
    kev: { source: "cisa_kev", value: "no" },
    technical_impact: { source: "cisa_bod_26_04_default", value: "total" },
  },
  ssvc: { by_mission: { high: ["Track*"], low: ["Track"], medium: ["Track"] }, decision: "Track", mission: "medium" },
};
const KEV_NO_EPSS = {
  exploited: true, exploited_sources: ["cisa_kev"], horizon_days: 30, null_reason: "no_epss_on_record", probability: null, source: "first_epss",
  summary: "No FIRST EPSS probability is on record, so the likelihood is unknown, not low. Confirmed exploitation, apart from the probability: CISA KEV.",
};
const sevCVSS = (score, severity) => ({
  assessed: true, cvss_version: "3.x", metric: "cvss_base", provider: "NVD CVSS v3", score, severity, source: "nvd", vector: null,
  summary: `CVSS ${score.toFixed(1)} ${severity} (NVD CVSS v3): impact alone; no CISA KEV listing, EPSS or EG-KEV tier raises it.`,
});
const v4 = (rule, extra) => ({ algorithm_version: "v4.0", rule_triggered: rule, ...extra });

const ANSWERS = {
  // KEV + NVD 5.4 (#2879's fixture): the 9.0 floor over a MEDIUM impact.
  "CVE-2099-28790": record("CVE-2099-28790", {
    kev_listed: true, echelongraph_score: 9.0, echelongraph_severity: "CRITICAL", echelongraph_risk: 79, echelongraph_ssvc_decision: "Act",
    score_factors: v4("kev_exploitation"), eg_severity: sevCVSS(5.4, "MEDIUM"), eg_likelihood: KEV_NO_EPSS, eg_priority: KEV_PRIORITY,
  }),
  // KEV, no CVSS at all.
  "CVE-2099-28791": record("CVE-2099-28791", {
    cvss_v3_score: null, kev_listed: true, echelongraph_score: 9.0, echelongraph_severity: "CRITICAL", echelongraph_risk: 100, echelongraph_ssvc_decision: "Act",
    score_factors: v4("kev_exploitation"),
    eg_severity: { assessed: false, score: null, severity: null, unassessed_reason: "kev_listed_no_cvss", summary: "Exploited; severity not yet published: CISA KEV lists this CVE and no CVSS base score is published for it yet." },
    eg_likelihood: KEV_NO_EPSS, eg_priority: KEV_PRIORITY,
  }),
  // NVD 6.5 lifted to 7.9 by EPSS 0.60.
  "CVE-2099-28792": record("CVE-2099-28792", {
    cvss_v3_score: 6.5, echelongraph_score: 7.9, echelongraph_severity: "HIGH", echelongraph_risk: 53, echelongraph_ssvc_decision: "Track",
    score_factors: v4("epss_uplift"), eg_severity: sevCVSS(6.5, "MEDIUM"),
    eg_likelihood: {
      epss_model_version: "v2026.06.15", epss_percentile: 0.98, epss_score_date: "2026-10-11", exploited: false, exploited_sources: [], horizon_days: 30, probability: 0.6, source: "first_epss",
      summary: "FIRST EPSS: 60% probability of exploitation activity within 30 days (score date 2026-10-11, model v2026.06.15). No confirmed exploitation on record (CISA KEV, EG-KEV Tier 1).",
    },
    eg_priority: DEFAULT_PRIORITY,
  }),
  // NVD 9.8, EPSS 2%: the score is the impact severity; nothing to say.
  "CVE-2099-28793": record("CVE-2099-28793", {
    cvss_v3_score: 9.8, echelongraph_score: 9.8, echelongraph_severity: "CRITICAL", echelongraph_risk: 45, echelongraph_ssvc_decision: "Track",
    score_factors: v4("nvd_cvss"), eg_severity: sevCVSS(9.8, "CRITICAL"),
    eg_likelihood: {
      exploited: false, exploited_sources: [], horizon_days: 30, probability: 0.02, source: "first_epss",
      summary: "FIRST EPSS: 2.0% probability of exploitation activity within 30 days. No confirmed exploitation on record (CISA KEV, EG-KEV Tier 1).",
    },
    eg_priority: DEFAULT_PRIORITY,
  }),
  // #2868 (scorer v4.1): ENISA's EU KEV lists it, CISA's catalog does not; NVD 5.4. Rule 1b's floor
  // (eu_kev_exploitation) over a MEDIUM impact. Components from the golden vector eu_kev/floor_lifts_medium_base's shape.
  "CVE-2099-28795": record("CVE-2099-28795", {
    echelongraph_score: 9.0, echelongraph_severity: "CRITICAL", echelongraph_risk: 64, echelongraph_ssvc_decision: "Attend",
    score_factors: { algorithm_version: "v4.1", rule_triggered: "eu_kev_exploitation" },
    eg_severity: {
      ...sevCVSS(5.4, "MEDIUM"),
      summary: "CVSS 5.4 MEDIUM (NVD CVSS v3): impact alone; no CISA KEV listing, ENISA EU KEV listing (Source: ENISA EUVD), EPSS or EG-KEV tier raises it.",
    },
    eg_likelihood: { ...KEV_NO_EPSS, exploited_sources: ["eu_kev"], summary: "No FIRST EPSS probability is on record, so the likelihood is unknown, not low. Confirmed exploitation, apart from the probability: ENISA EU KEV (Source: ENISA EUVD)." },
    eg_priority: DEFAULT_PRIORITY,
  }),
  // #2868 (scorer v4.1): ENISA's EU KEV only, no CVSS at all (eu_kev/no_cvss).
  "CVE-2099-28796": record("CVE-2099-28796", {
    cvss_v3_score: null, echelongraph_score: 9.0, echelongraph_severity: "CRITICAL", echelongraph_risk: 85, echelongraph_ssvc_decision: "Attend",
    score_factors: { algorithm_version: "v4.1", rule_triggered: "eu_kev_exploitation" },
    eg_severity: { assessed: false, score: null, severity: null, unassessed_reason: "eu_kev_listed_no_cvss", summary: "Exploited; severity not yet published: ENISA's EU Known Exploited Vulnerabilities catalogue lists this CVE (Source: ENISA EUVD) and no CVSS base score is published for it yet." },
    eg_likelihood: { ...KEV_NO_EPSS, exploited_sources: ["eu_kev"], summary: "No FIRST EPSS probability is on record, so the likelihood is unknown, not low. Confirmed exploitation, apart from the probability: ENISA EU KEV (Source: ENISA EUVD)." },
    eg_priority: DEFAULT_PRIORITY,
  }),
  // Scored before v4.0: no components.
  "CVE-2099-28794": record("CVE-2099-28794", {
    kev_listed: true, echelongraph_score: 9.0, echelongraph_severity: "CRITICAL", echelongraph_risk: 96, echelongraph_ssvc_decision: "Act",
    score_factors: { algorithm_version: "v3.6", rule_triggered: "kev_exploitation" },
  }),
};

let stub;
before(async () => {
  stub = http.createServer((req, res) => {
    const id = req.url.split("/").pop();
    const a = req.url.startsWith("/api/v1/public/cves/") ? ANSWERS[id] : undefined;
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

describe("#2879 get_cve: eg_severity, eg_likelihood and eg_priority", () => {
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

  it("the outputSchema documents the three components, and the score and EG Risk for what they now are", () => {
    const props = recordProps(getCve.outputSchema);
    assert.match(props.eg_severity?.description ?? "", /CVSS base score[^.]*which no CISA KEV listing, ENISA EU KEV listing \(scorer v4\.1\), EPSS probability or EG-KEV tier raises/);
    assert.match(props.eg_severity.description, /kev_listed_no_cvss reads exploited, severity not yet published/);
    // #2868 (scorer v4.1): the EU-only reason, and ENISA's listing among confirmed exploitation, attributed.
    assert.match(props.eg_severity.description, /eu_kev_listed_no_cvss \(v4\.1\) the same for a CVE only ENISA's EU KEV lists \(Source: ENISA EUVD\)/);
    assert.match(props.eg_likelihood.description, /ENISA's EU KEV lists it \(scorer v4\.1, exploited_sources eu_kev; Source: ENISA EUVD\)/);
    assert.match(props.eg_likelihood?.description ?? "", /FIRST's EPSS probability of exploitation activity in the next 30 days \(source first_epss/);
    assert.match(props.eg_likelihood.description, /not EchelonGraph's own model/);
    assert.match(props.eg_likelihood.description, /never folded into probability/);
    assert.match(props.eg_likelihood.description, /null, with null_reason no_epss_on_record/);
    assert.match(props.eg_priority?.description ?? "", /ssvc[\s\S]*bod_26_04[\s\S]*inputs/);
    assert.match(props.echelongraph_score.description, /a CISA KEV listing floors it at 9\.0/);
    assert.match(props.echelongraph_risk.description, /fused from impact severity \(eg_severity/);
    assert.doesNotMatch(props.echelongraph_risk.description, /fused from the score,/);
    // The likelihood is FIRST's, never presented as EchelonGraph's.
    assert.doesNotMatch(props.eg_likelihood.description, /EchelonGraph's (?:own )?(?:EPSS|probability|likelihood)/);
  });

  it("KEV + CVSS 5.4: relays the components whole and says the 9.0 is exploitation, not impact", async () => {
    const { res, note } = await call("CVE-2099-28790");
    const d = res.structuredContent.data;
    assert.deepEqual(d.eg_severity, ANSWERS["CVE-2099-28790"].eg_severity, "eg_severity relayed whole");
    assert.deepEqual(d.eg_likelihood, KEV_NO_EPSS, "eg_likelihood relayed whole, its null probability kept");
    assert.deepEqual(d.eg_priority, KEV_PRIORITY, "eg_priority relayed whole");
    assert.ok(
      note.includes(" eg_severity is the impact severity of CVE-2099-28790 alone: CVSS 5.4 MEDIUM (NVD CVSS v3). echelongraph_score 9.0 is higher because a CISA KEV listing floors it at 9.0: that is exploitation, not impact."),
      note,
    );
    assert.ok(note.includes(" eg_likelihood.probability is null: no FIRST EPSS probability is on record for CVE-2099-28790, so report its likelihood as unknown, not low."), note);
  });

  it("KEV with no CVSS: severity not yet published, the 9.0 a floor for exploitation", async () => {
    const { note } = await call("CVE-2099-28791");
    assert.ok(
      note.includes(" eg_severity is not assessed: CVE-2099-28791 is exploited (CISA KEV) and no CVSS severity is published yet, so echelongraph_score 9.0 is the floor for confirmed exploitation, not an impact rating."),
      note,
    );
  });

  it("#2868: Rule 1b's floor is named as ENISA's EU KEV listing, attributed, over the impact severity and with no CVSS", async () => {
    const { note } = await call("CVE-2099-28795");
    assert.ok(
      note.includes(" eg_severity is the impact severity of CVE-2099-28795 alone: CVSS 5.4 MEDIUM (NVD CVSS v3). echelongraph_score 9.0 is higher because an ENISA EU KEV listing floors it at 9.0 (Source: ENISA EUVD): that is exploitation, not impact."),
      note,
    );
    const none = await call("CVE-2099-28796");
    assert.ok(
      none.note.includes(" eg_severity is not assessed: CVE-2099-28796 is exploited (ENISA EU KEV; Source: ENISA EUVD) and no CVSS severity is published yet, so echelongraph_score 9.0 is the floor for confirmed exploitation, not an impact rating."),
      none.note,
    );
    // CONTROL: CISA's wording is not reused for ENISA's listing.
    assert.doesNotMatch(note + none.note, /CISA KEV listing floors it|exploited \(CISA KEV\)/);
  });

  it("an EPSS uplift is named as EPSS's; a likelihood on record gets no null sentence", async () => {
    const { note } = await call("CVE-2099-28792");
    assert.ok(note.includes("CVSS 6.5 MEDIUM (NVD CVSS v3). echelongraph_score 7.9 is higher because EPSS lifts it toward 9.0: that is exploitation, not impact."), note);
    assert.doesNotMatch(note, /eg_likelihood/, note);
  });

  it("a score that is its own impact severity, and a record scored before v4.0, get no component sentence", async () => {
    for (const id of ["CVE-2099-28793", "CVE-2099-28794"]) {
      const { res, note } = await call(id);
      assert.doesNotMatch(note, /eg_severity|eg_likelihood|exploitation, not impact/, `${id}: ${note}`);
      if (id === "CVE-2099-28794") {
        for (const k of ["eg_severity", "eg_likelihood", "eg_priority"]) assert.equal(k in res.structuredContent.data, false, `${id} has no ${k}`);
      }
    }
  });
});
