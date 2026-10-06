// #2839: get_cve relays CISA's own KEV text — kev_required_action, kev_short_description and
// kev_notes_urls — verbatim, as core-backend serves it on the record of a KEV-listed CVE, and labels
// it as CISA's: the note says, in one sentence, that CISA's required action is directed at US federal
// civilian agencies under BOD 22-01 and is not EchelonGraph's advice.
//
// Both polarities: a KEV record carrying the text relays it and the sentence; a non-KEV record, and a
// KEV record from an API older than the fields, carry neither. And at Log4Shell's cut level (its
// production-shaped answer, past the text budget) the first text block still carries the text whole.
//
// Runs against dist/index.js, so build first — `npm test` does.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { AjvJsonSchemaValidator } from "@modelcontextprotocol/server/validators/ajv";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { serverCommand } from "./server-under-test.mjs";
import { LOG4SHELL_KEV_TEXT, SHAPED, shapedAnswers } from "./text-bound.mjs";

const ERAS = [MODERN, "2025-06-18"];
const KEV_FIELDS = ["kev_required_action", "kev_short_description", "kev_notes_urls"];
const SENTENCE =
  "kev_required_action, kev_short_description and kev_notes_urls are CISA's own text from its KEV catalog, relayed verbatim: CISA's required action is directed at US federal civilian agencies under Binding Operational Directive 22-01 and is not EchelonGraph's advice.";

const record = (id, extra = {}) => ({
  cve_id: id,
  description: "test record",
  severity: "HIGH",
  cvss_v3_score: 8.8,
  echelongraph_score: 8.1,
  echelongraph_severity: "HIGH",
  score_assessed: true,
  published: "2026-09-01T00:00:00Z",
  modified: "2026-09-02T00:00:00Z",
  updated_at: "2026-09-03T00:00:00Z",
  references: [],
  cpe_match: [],
  ...extra,
});
const KEV = { kev_listed: true, kev_added_date: "2026-09-02T00:00:00Z", kev_due_date: "2026-09-23T00:00:00Z", kev_ransomware: false };
const TEXT = {
  kev_required_action: "Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.",
  kev_short_description: "Acme Widget contains an authentication bypass vulnerability that allows an unauthenticated attacker to gain administrative access.",
  kev_notes_urls: ["https://acme.example/security/2026-001", "https://nvd.nist.gov/vuln/detail/CVE-2099-28390"],
};
const LOG4SHELL_CASE = SHAPED.find((c) => c.label === "get_cve, CVE-2021-44228");

const ANSWERS = {
  "/api/v1/public/cves/CVE-2099-28390": record("CVE-2099-28390", { ...KEV, ...TEXT }),
  "/api/v1/public/cves/CVE-2099-28391": record("CVE-2099-28391", { kev_listed: false, kev_ransomware: false }),
  "/api/v1/public/cves/CVE-2099-28392": record("CVE-2099-28392", KEV), // an API older than the fields
  ...shapedAnswers(LOG4SHELL_CASE),
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

const validator = new AjvJsonSchemaValidator();
const textBlocks = (res) => (res.content ?? []).filter((c) => c.type === "text").map((c) => c.text);

/** The properties of the CVE record within an outputSchema: the first object schema naming cve_id and kev_listed. */
function recordProps(s) {
  if (s === null || typeof s !== "object") return undefined;
  if (s.properties && "cve_id" in s.properties && "kev_listed" in s.properties) return s.properties;
  for (const v of Array.isArray(s) ? s : Object.values(s)) {
    const found = recordProps(v);
    if (found) return found;
  }
  return undefined;
}

/** The KEV text fields an outputSchema's CVE record does not describe as CISA's. */
function undescribedKEVFields(outputSchema) {
  const props = recordProps(outputSchema) ?? {};
  return KEV_FIELDS.filter((k) => typeof props[k]?.description !== "string" || !/CISA/.test(props[k].description));
}

for (const era of ERAS) {
  describe(`#2839 get_cve relays CISA's KEV text [${era}]`, () => {
    let client;
    let getCve;
    before(async () => {
      client = await connect({
        era,
        ...serverCommand(),
        env: { ...process.env, ECHELONGRAPH_API_BASE: `http://127.0.0.1:${stub.address().port}`, ECHELONGRAPH_API_TIMEOUT_MS: "2000" },
        stderr: "ignore",
      });
      const { tools } = await client.listTools();
      getCve = tools.find((t) => t.name === "get_cve");
    });
    after(() => client?.close());
    const call = (cve_id) => client.callTool({ name: "get_cve", arguments: { cve_id } });
    const valid = (res) => {
      const v = validator.getValidator(getCve.outputSchema)(res.structuredContent);
      assert.ok(v.valid, v.errorMessage);
    };

    it("the description and the outputSchema name the three fields, and kev_due_date, as CISA's", () => {
      for (const k of [...KEV_FIELDS, "kev_due_date"]) assert.match(getCve.description, new RegExp(`\\b${k}\\b`), k);
      assert.match(getCve.description, /CISA's own text relayed verbatim/);
      assert.match(getCve.description, /not EchelonGraph's advice/);
      assert.deepEqual(undescribedKEVFields(getCve.outputSchema), []);
      assert.match(recordProps(getCve.outputSchema).kev_required_action.description, /Binding Operational Directive 22-01/);
    });

    it("control: a CVERecord without the field is caught", () => {
      const stripped = structuredClone(getCve.outputSchema);
      delete recordProps(stripped).kev_required_action;
      assert.deepEqual(undescribedKEVFields(stripped), ["kev_required_action"]);
    });

    it("a KEV record with CISA's text: relayed verbatim in content[0] and structuredContent, labelled CISA's in the note", async () => {
      const res = await call("CVE-2099-28390");
      valid(res);
      const [data, note] = textBlocks(res);
      for (const k of KEV_FIELDS) {
        assert.deepEqual(res.structuredContent.data[k], TEXT[k], k);
        assert.deepEqual(JSON.parse(data)[k], TEXT[k], `content[0] ${k}`);
      }
      assert.ok(note.endsWith(SENTENCE), note);
      assert.equal(note.split(SENTENCE).length, 2, "the sentence once");
      assert.ok(res.structuredContent.notes.includes(SENTENCE), "the envelope's notes end with the note's sentences");
    });

    it("a non-KEV record: none of the fields, and no sentence", async () => {
      const res = await call("CVE-2099-28391");
      valid(res);
      const [data, note] = textBlocks(res);
      for (const k of KEV_FIELDS) {
        assert.ok(!(k in res.structuredContent.data), k);
        assert.ok(!(k in JSON.parse(data)), `content[0] ${k}`);
      }
      assert.doesNotMatch(note, /CISA's own text|Binding Operational Directive/);
    });

    it("a KEV record from an API older than the fields: no sentence about text it does not carry", async () => {
      const res = await call("CVE-2099-28392");
      valid(res);
      assert.doesNotMatch(textBlocks(res)[1], /CISA's own text|Binding Operational Directive/);
    });

    it("Log4Shell at its cut level: the first text block is cut, and still carries CISA's text whole", async () => {
      const res = await call("CVE-2021-44228");
      valid(res);
      const [data, note] = textBlocks(res);
      const shown = JSON.parse(data);
      assert.notDeepEqual(shown, res.structuredContent.data, "precondition: the production-shaped answer is past the text budget, so content[0] is cut");
      assert.match(note, /Every list in it keeps at most its first/, "precondition: the cut level is the list cap");
      for (const k of KEV_FIELDS) assert.deepEqual(shown[k], LOG4SHELL_KEV_TEXT[k], `content[0] ${k} at the cut level`);
      assert.ok(note.includes(SENTENCE), note);
    });
  });
}
