// #3391: a match's fixed_in_dispute and the version_evidence value cna_affected_range, relayed by every tool that
// relays a match, against a stub that serves core-backend's own answers.
//
// core-backend's match answers (the registry match of GET /api/v1/public/cves/match and of each row of POST
// .../match/batch, and GET .../cves/:id/remediation's installed version) carry fixed_in_dispute where the CVE record's
// CNA and the advisory disagree on the range that holds the version, and a match whose version only the CNA's range
// holds says version_evidence cna_affected_range. The answers served here are core-backend's, for each kind of dispute
// (test/fixtures/fixed-in-dispute-wire.json says how they were taken): higher cna or advisory, kind fixed or
// introduced, each bound the advisory can give, a list, a range ending at less_than_or_equal, changes, a span the CNA's
// defaultStatus covers (cna_range_default), a fixed_in null beside a dispute; and a version whose CNA statement states no
// end beside the advisory's fix, answered undetermined (cna_range_open_ended, 95927abe's qs 6.14.1) with no match.
//
// #3381's review found the relay saying what the API's answers contradict: "fixed_in stays the advisory's", while with
// higher cna fixed_in is the CNA's bound (lodash 4.17.15: fixed_in 4.18.1, GHSA's fix 4.18.0), and cve_remediation's "as
// the advisory states it" of a range that is the CNA's. What is under test, per tool (check_affected, check_sbom,
// scan_manifest, cve_remediation) and per case:
//   - structuredContent.data relays fixed_in_dispute and version_evidence as sent, and validates against the tool's
//     outputSchema (strict-output.mjs, as the server checks its own answers);
//   - the text keeps fixed_in_dispute on the match, and the note quotes each note verbatim, naming its match;
//   - no sentence of ours calls a disputed match's fixed_in the advisory's, or gives the advisory's account of it
//     ("no affected interval of the advisory holds") but of a match without a dispute; none rests on the note's wording
//     or on which of the object's fields are set (#3381's round-4 review: the relay does not depend on wording a later
//     #3391 round may change, so nothing here matches core-backend's note but to find it quoted whole);
//   - a dispute without a note is a dispute (F15); values and fields a later API adds (a kind, a higher, a status) are
//     relayed and never fail the call;
//   - the undetermined case is relayed undetermined, its reason as sent, never clean;
//   - #3381's round-5 review (C4): a match core-backend raises with no dispute (a version the CNA lists by itself,
//     version_evidence cna_affected_range; an advisory interval's match whose fix the CNA lists as affected) is
//     relayed with none, and nothing is said of one, nor the advisory's account given of a match the CNA's range raised;
//   - control: the same answer without fixed_in_dispute says nothing of one, and keeps the advisory's account.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { AjvJsonSchemaValidator } from "@modelcontextprotocol/server/validators/ajv";
import { StrictOutputValidator } from "./strict-output.mjs";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { PKG_DIR, serverCommand } from "./server-under-test.mjs";
import { BATCH_PATH, ROWS, batchAnswer } from "./fixtures/match-batch.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SBOM = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "check_sbom.js")).href);
const CA = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "check_affected.js")).href);
const D = await import(pathToFileURL(path.join(PKG_DIR, "dist", "fixedInDispute.js")).href);

const WIRE = JSON.parse(fs.readFileSync(path.join(HERE, "fixtures", "fixed-in-dispute-wire.json"), "utf8")).cases;
// The cases whose answer has matches, each disputed; those whose matches carry no dispute (#3381's round-5 review, C4:
// core-backend raises some with none); and those with none, answered undetermined.
const CASES = Object.entries(WIRE).filter(([, c]) => c.match.matches.length > 0 && c.match.matches.every((m) => m.fixed_in_dispute));
const NO_DISPUTE = Object.entries(WIRE).filter(([, c]) => c.match.matches.length > 0 && c.match.matches.every((m) => !m.fixed_in_dispute));
const UNDETERMINED = Object.entries(WIRE).filter(([, c]) => c.match.matches.length === 0);
const disputesOf = (matches) => matches.filter((m) => m.fixed_in_dispute);
// #3381's round-4 review (F11): the advisory's account of fixed_in, said of a disputed match. Each place a note says
// it, the sentence saying it must be one of a match without a dispute.
const ADVISORY_ACCOUNT = /no affected interval of the (?:advisory|CVE's record) holds/g;
function unqualifiedAdvisoryAccount(text) {
  const out = [];
  for (const m of text.matchAll(ADVISORY_ACCOUNT)) {
    const start = Math.max(text.lastIndexOf(". ", m.index), text.lastIndexOf(": ", m.index), 0);
    const sentence = text.slice(start, text.indexOf(".", m.index) + 1 || undefined);
    if (!/without fixed_in_dispute|except on a match with fixed_in_dispute/.test(sentence)) out.push(sentence);
  }
  return out;
}

// A later API's values and fields, on a real dispute: relayed, never a failed call.
const LATER = (m) => ({
  ...m,
  fixed_in_dispute: {
    ...m.fixed_in_dispute,
    kind: "a_kind_added_later",
    higher: "a_value_added_later",
    cna_range: { ...m.fixed_in_dispute.cna_range, status: "a_status_added_later", changes: [{ at: "9.9.9", status: "a_status_added_later", added_later: 1 }], changes_truncated: true, added_later: [1] },
    cna: { ...m.fixed_in_dispute.cna, added_later: true },
    added_later: { anything: 1 },
  },
});
const withoutDispute = (m) => {
  const { fixed_in_dispute: _, ...rest } = m;
  return rest;
};

const REMEDIATION_BASE = {
  state: "assessed", not_assessed_reason: null,
  fix_status: { state: "available", basis: "patch_evidence_release", unread_inputs: [] },
  cisa: { kev_listed: false, required_action: null, due_date: null, short_description: null, notes_urls: [] },
  fixed_branches: [], vendor_remediations: [], fix_references: [], patches: [],
  coverage: { parsed_vendors: [], vendors_not_parsed: [], vendor_advisories_listed: 0, vendor_advisory_limit: 20, item_text_cap: 2000, items_per_advisory_cap: 16 },
  failed_sections: [],
};
const remediationOf = (c, cve, dispute = true) => {
  const { fixed_in_dispute, installed, ...rest } = c.remediation;
  return {
    cve_id: cve, ...REMEDIATION_BASE, ...rest,
    installed: { ...installed, ecosystem: "npm", ecosystem_recognised: true, package: c.package },
    ...(dispute ? { fixed_in_dispute } : {}),
  };
};

// The stub: GET .../match answers stubState.match whole; a batch row for stubState.purl is that answer, as
// core-backend's matchbatch.go makes a row of it (the single GET's body, its index, input_kind, purl and the verdict its
// batchSummary.add gives), any other purl is not affected; .../remediation answers stubState.remediation.
const verdictOf = (b) =>
  b.assessed && b.count > 0 ? "affected" : (b.assessed && b.undetermined_count > 0) || (!b.assessed && b.not_assessed_reason === "no_decidable_advisory") ? "undetermined" : b.assessed ? "not_affected" : "not_assessed";
const stubState = { match: null, purl: null, remediation: null, record: null };
let stub;
before(async () => {
  stub = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const send = (o) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(o));
      };
      if (req.url === "/api/v1/public/cves/match") return send(stubState.match);
      if (req.url === BATCH_PATH && req.method === "POST") {
        const purls = JSON.parse(body).components.map((c) => c.purl);
        const rows = purls.map((p, i) => {
          if (p !== stubState.purl) return ROWS.notAffected(i, p, p.slice(8).split("@")[0], p.split("@")[1]);
          return { ...stubState.match, index: i, input_kind: "purl", purl: p, verdict: verdictOf(stubState.match) };
        });
        return send(batchAnswer(rows));
      }
      if (stubState.remediation && req.url === `/api/v1/public/cves/${stubState.remediation.cve_id}/remediation`) return send(stubState.remediation);
      if (stubState.record && req.url === `/api/v1/public/cves/${stubState.record.cve_id}`) return send(stubState.record);
      res.writeHead(404, { "content-type": "application/json" });
      res.end('{"error":"not found"}');
    });
  });
  await new Promise((resolve) => stub.listen(0, "127.0.0.1", resolve));
});
after(() => new Promise((resolve) => stub.close(resolve)));

const textBlocks = (res) => (res.content ?? []).filter((c) => c.type === "text").map((c) => c.text);
const noteOf = (res) => textBlocks(res)[res.isError ? 0 : 1] ?? "";
const validator = new StrictOutputValidator();
const lockOf = (pkg, version) =>
  JSON.stringify({ name: "app", lockfileVersion: 3, requires: true, packages: { "": { name: "app", version: "1.0.0" }, [`node_modules/${pkg}`]: { version }, "node_modules/left-pad": { version: "1.3.0" } } });
// Each tool's call for a case, where its answer holds the case's matches, and how the note names them.
const TOOLS = [
  ["check_affected", (c) => ({ ecosystem: "npm", package: c.package, version: c.version }), (d) => d.matches, () => ""],
  ["check_sbom", (c) => ({ purls: [`pkg:npm/${c.package}@${c.version}`, "pkg:npm/left-pad@1.3.0"] }), (d, c) => d.results.find((r) => r.purl === `pkg:npm/${c.package}@${c.version}`).matches, (c) => ` (pkg:npm/${c.package}@${c.version})`],
  ["scan_manifest", (c) => ({ files: [{ filename: "package-lock.json", content: lockOf(c.package, c.version) }] }), (d, c) => d.results.find((r) => r.purl === `pkg:npm/${c.package}@${c.version}`).matches, (c) => ` (pkg:npm/${c.package}@${c.version})`],
];
// What no sentence may say of a disputed answer (#3381's review), and, round 4, no list of the values higher takes.
const FALSE_CLAIMS = /stays the advisory's|neither record settles|still the advisory's|as the advisory states it|\(cna or advisory\)/;
const SAID_OF_DISPUTED = {
  check_affected: "with fixed_in_dispute it follows the source the dispute's higher names.",
  check_sbom: "except on a match with fixed_in_dispute, where it follows the source the dispute's higher names;",
  scan_manifest: "except on a match with fixed_in_dispute, where it follows the source the dispute's higher names;",
};
const DISPUTE_SAID = "the CVE record's CNA and the advisory disagree on the range that holds the version; the API's note on each, verbatim: ";

describe("#3391: core-backend's answers, each kind of dispute, as the fixture holds them", () => {
  it("every case with matches carries a dispute on each, or none on any; the others are answered undetermined; between them, every kind core-backend sends", () => {
    assert.ok(CASES.length >= 14 && UNDETERMINED.length >= 1, `${CASES.length} and ${UNDETERMINED.length}`);
    assert.equal(CASES.length + NO_DISPUTE.length + UNDETERMINED.length, Object.keys(WIRE).length, "a case of matches some disputed and some not");
    // #3381's round-5 review (C4): the two core-backend raises with no dispute, each fixed_in null; the one the CNA's
    // range alone raises says so.
    assert.deepEqual(NO_DISPUTE.map(([n]) => n).sort(), ["advisory_interval_cna_listed_at_fix", "cna_listed_alone_no_dispute"]);
    for (const [name, c] of NO_DISPUTE) {
      for (const m of c.match.matches) assert.equal(m.fixed_in, null, name);
      // Round 11: the wire sends no fixed_in_dispute where there is none (remediation.go omitempty).
      assert.ok(!Object.hasOwn(c.remediation, "fixed_in_dispute"), name);
    }
    assert.equal(WIRE.cna_listed_alone_no_dispute.match.matches[0].version_evidence, "cna_affected_range");
    assert.equal(WIRE.advisory_interval_cna_listed_at_fix.match.matches[0].version_evidence, "advisory_interval");
    const seen = new Set();
    for (const [name, c] of UNDETERMINED) {
      assert.equal(c.match.count, 0, name);
      assert.ok(c.match.undetermined.length >= 1, name);
      for (const u of c.match.undetermined) seen.add(u.reason);
      assert.equal(c.remediation.installed.verdict, "undetermined", name);
    }
    for (const [name, c] of CASES) {
      for (const m of c.match.matches) {
        const d = m.fixed_in_dispute;
        assert.ok(d && typeof d.note === "string" && d.note.length > 0, `${name}: ${m.cve_id}`);
        if (m.fixed_in === null || m.fixed_in === undefined) seen.add("fixed_in null");
        if (d.cna_range_default === true) seen.add("cna_range_default");
        // Exactly one advisory bound, as core-backend's FixedInDispute says.
        assert.equal(["advisory_fixed", "advisory_last_affected", "advisory_introduced"].filter((k) => d[k] !== undefined).length, 1, `${name}: ${JSON.stringify(d)}`);
        seen.add(`${d.higher}/${d.kind}`);
        for (const k of ["advisory_fixed", "advisory_last_affected", "advisory_introduced", "advisory_listed"]) if (d[k] !== undefined) seen.add(k);
        if (d.cna_range.less_than_or_equal) seen.add("less_than_or_equal");
        if (d.cna_range.changes) seen.add("changes");
        if (m.version_evidence === "cna_affected_range") seen.add("cna_affected_range");
      }
      assert.deepEqual(c.remediation.fixed_in_dispute, c.match.matches[0].fixed_in_dispute, `${name}: remediation's dispute is the match's`);
    }
    for (const k of ["cna/fixed", "advisory/fixed", "cna/introduced", "advisory_fixed", "advisory_last_affected", "advisory_introduced", "advisory_listed", "less_than_or_equal", "changes", "cna_affected_range", "cna_range_default", "fixed_in null", "cna_range_open_ended"]) {
      assert.ok(seen.has(k), `no case of ${k}`);
    }
    // #3391's third review (F10): the fixture's about says which of the two leaves fixed_in null; it holds the cases to it.
    const about = JSON.parse(fs.readFileSync(path.join(HERE, "fixtures", "fixed-in-dispute-wire.json"), "utf8")).about;
    assert.match(about, /cna_states_no_status: fixed_in is that range's bound/);
    assert.equal(typeof WIRE.cna_states_no_status.match.matches[0].fixed_in, "string");
    assert.match(about, /cna_affected_no_end: fixed_in null/);
    assert.equal(WIRE.cna_affected_no_end.match.matches[0].fixed_in, null);
  });
});

describe(`#3391: fixed_in_dispute and cna_affected_range relayed [${MODERN}]`, () => {
  let client;
  let tools;
  const schemaOf = (name) => tools.find((t) => t.name === name).outputSchema;
  before(async () => {
    client = await connect({
      era: MODERN,
      ...serverCommand(),
      env: { ...process.env, ECHELONGRAPH_API_BASE: `http://127.0.0.1:${stub.address().port}`, ECHELONGRAPH_API_TIMEOUT_MS: "2000" },
      stderr: "ignore",
    });
    ({ tools } = await client.listTools());
  });
  after(() => client?.close());

  it("tools/list: each relaying tool's outputSchema names every field core-backend sends on fixed_in_dispute, open to fields and values a later API adds; version_evidence names cna_affected_range", () => {
    const ajv = new AjvJsonSchemaValidator();
    const find = (s, key, out = []) => {
      if (s === null || typeof s !== "object") return out;
      if (Array.isArray(s)) {
        for (const x of s) find(x, key, out);
        return out;
      }
      if (s.properties && Object.hasOwn(s.properties, key)) out.push(s.properties);
      for (const x of Object.values(s)) find(x, key, out);
      return out;
    };
    const props = (s) => {
      const o = (s.anyOf ?? [s]).find((x) => x && x.properties);
      return o ? Object.keys(o.properties) : [];
    };
    for (const name of ["check_affected", "check_sbom", "scan_manifest", "cve_remediation"]) {
      const holders = find(schemaOf(name), "fixed_in_dispute");
      assert.ok(holders.length >= 1, `${name}: no fixed_in_dispute in its outputSchema`);
      for (const h of holders) {
        const s = h.fixed_in_dispute;
        const named = props(s);
        for (const k of ["kind", "advisory_id", "advisory_fixed", "advisory_last_affected", "advisory_introduced", "advisory_listed", "cna", "cna_product", "cna_range", "cna_range_default", "higher", "note"]) {
          assert.ok(named.includes(k), `${name}: fixed_in_dispute does not name ${k} (${named})`);
        }
        // #3381's round-4 review (F13, F14): cna_range is not said to be the record's own words where cna_range_default
        // makes it a span no entry writes, and absence is not said to be agreement.
        assert.match(s.description, /cna_range_default/, name);
        assert.doesNotMatch(s.description, /as its record writes it|Absent where the two agree/, name);
        assert.match(s.description, /not a finding that the CNA agrees/, name);
        assert.match(s.description, /a match the CNA's range alone raises may carry none/, name);
        // #3381's round-10 review (d5-3391relay F3): cna_range is the CNA's range in dispute, which on a dispute whose
        // higher is advisory ends below the version: it is not said to be the range that holds it. Control: round 10's.
        const HOLDS = /cna_range \([^)]*\)[^.]*: the CNA's range that holds the version/;
        assert.doesNotMatch(s.description, HOLDS, name);
        // Round 11 (the round-10 verify's d5 N1): where higher is cna, the range is the one past the advisory's bound,
        // which on an advisory_interval match holds the advisory's fix, not the version (lodash 4.17.15 under
        // CVE-2026-2950: [4.17.23, 4.18.1)). Control: round 10's "the one that holds the version".
        assert.match(s.description, /the CNA's range in dispute, as the API reads the record \(where higher is cna, the CNA's range that reaches past the advisory's bound: on a cna_affected_range match it holds the version, and on an advisory_interval or exact_version_list match it holds the advisory's bound past the version \(its fix, or the versions just above its last affected or listed version\), so it may start above the version; where higher is advisory, the CNA's range that ends below it/, name);
        assert.doesNotMatch(s.description, /where higher is cna, the one that holds the version/, name);
        assert.match("cna_range (version, less_than or less_than_or_equal, status, version_type; changes, each {at, status}, where the range's status changes inside it, with changes_truncated where the record held more): the CNA's range that holds the version, as the API reads the record", HOLDS);
        // #3381's round-10 review (d4-release R10-3, d5-3391relay F1): described as what a match carries once
        // EchelonGraph's API serves it, never as served now: no "today". Control: round 10's sentence.
        const TODAY = /\btoday\b/;
        assert.match(s.description, /^Once EchelonGraph's API serves it, /, name);
        assert.doesNotMatch(s.description, TODAY, name);
        assert.match("the API reads a CNA's ranges only where it applies them (today, language-registry packages, not distro packages)", TODAY);
        const range = JSON.stringify(s);
        for (const k of ["less_than_or_equal", "version_type", "changes", "changes_truncated"]) assert.match(range, new RegExp(`"${k}"`), `${name}: cna_range does not name ${k}`);
        assert.doesNotMatch(range, /"additionalProperties":false/, `${name}: fixed_in_dispute closed to fields a later API adds`);
        const v = ajv.getValidator(s);
        for (const [cn, c] of CASES) for (const m of c.match.matches) assert.ok(v(m.fixed_in_dispute).valid, `${name} ${cn}: ${v(m.fixed_in_dispute).errorMessage}`);
        const later = LATER(CASES[0][1].match.matches[0]).fixed_in_dispute;
        assert.ok(v(later).valid, `${name}: a field or value a later API adds fails: ${v(later).errorMessage}`);
        // Control: the validator is not one that admits anything.
        assert.equal(v({ ...later, note: 7 }).valid, false, name);
      }
      const ve = find(schemaOf(name), "version_evidence");
      assert.ok(ve.length >= 1, `${name}: no version_evidence in its outputSchema`);
      // #3381's round-4 review (F12): a match's interval (and match_reason's range) is the CNA's where version_evidence
      // is cna_affected_range; no relaying tool calls it the advisory's alone.
      for (const h of find(schemaOf(name), "interval")) {
        const said = `${h.interval.description ?? ""} ${h.match_reason?.description ?? ""}`;
        assert.doesNotMatch(said, /^The advisory interval|with the advisory interval/, `${name}: ${said}`);
        if (h.version_evidence) assert.match(h.interval.description ?? "", /cna_affected_range/, `${name}: ${h.interval.description}`);
      }
      for (const h of ve) {
        assert.match(JSON.stringify(h.version_evidence), /"cna_affected_range"/, `${name}: version_evidence does not name cna_affected_range`);
        // #3381's round-5 review (C4): a match the CNA's range raises may carry no dispute; neither field says it must.
        assert.match(h.version_evidence.description ?? "", /fixed_in_dispute, where the API publishes one, says how the two differ; such a match may carry none/, `${name}: ${h.version_evidence.description}`);
        // #3381's round-10 review (R10-3): cna_affected_range is a value once EchelonGraph's API serves it.
        assert.match(h.version_evidence.description ?? "", /or, once EchelonGraph's API serves it, cna_affected_range \(/, `${name}: ${h.version_evidence.description}`);
        const v = ajv.getValidator(h.version_evidence);
        assert.ok(v("cna_affected_range").valid && v("advisory_interval").valid && v("a_value_added_later").valid, name);
        assert.equal(v(7).valid, false, name);
      }
    }
  });

  for (const [tool, argsOf, matchesOf, whereOf] of TOOLS) {
    it(`${tool}: every case relayed as sent, kept beside each match in the text, each note quoted verbatim, and nothing said of fixed_in that the case contradicts`, async () => {
      for (const [name, c] of CASES) {
        stubState.match = c.match;
        stubState.purl = `pkg:npm/${c.package}@${c.version}`;
        const res = await client.callTool({ name: tool, arguments: argsOf(c) });
        assert.ok(!res.isError, `${name}: ${noteOf(res)}`);
        const sc = res.structuredContent;
        assert.equal(sc.state, "measured", `${name}: ${noteOf(res)}`);
        const v = validator.getValidator(schemaOf(tool))(sc);
        assert.ok(v.valid, `${name}: ${v.errorMessage}`);
        const ms = matchesOf(sc.data, c);
        assert.deepEqual(ms.map((m) => [m.fixed_in_dispute, m.version_evidence, m.fixed_in ?? null, m.interval]), c.match.matches.map((m) => [m.fixed_in_dispute, m.version_evidence, m.fixed_in ?? null, m.interval]), name);
        const tms = matchesOf(JSON.parse(textBlocks(res)[0]), c);
        assert.deepEqual(tms.map((m) => m.fixed_in_dispute), c.match.matches.map((m) => m.fixed_in_dispute), `${name}: the text does not keep it`);
        const note = noteOf(res);
        for (const m of disputesOf(c.match.matches)) assert.ok(note.includes(`${m.cve_id}${whereOf(c)}: "${m.fixed_in_dispute.note}"`), `${name}: ${note}`);
        assert.ok(note.includes(DISPUTE_SAID), `${name}: ${note}`);
        assert.ok(note.includes(SAID_OF_DISPUTED[tool]), `${name}: ${note}`);
        assert.doesNotMatch(note, FALSE_CLAIMS, name);
        assert.deepEqual(unqualifiedAdvisoryAccount(note), [], name);
      }
    });

    // #3381's round-4 review (F15): a dispute the API sends without a note (absent, null, empty or blank) is a dispute:
    // fixed_in is not called the advisory's, the match is named, and no note is made up for it.
    it(`${tool}: a fixed_in_dispute without a note is a dispute all the same, and one with a higher a later API adds is not said to be cna or advisory`, async () => {
      const c = WIRE.cna_fixed_advisory_interval;
      for (const [label, edit] of [["absent", (d) => { const { note: _, ...rest } = d; return rest; }], ["null", (d) => ({ ...d, note: null })], ["empty", (d) => ({ ...d, note: "" })], ["blank", (d) => ({ ...d, note: "   " })], ["higher both", (d) => ({ ...d, higher: "both" })]]) {
        stubState.match = { ...c.match, matches: c.match.matches.map((m) => ({ ...m, fixed_in_dispute: edit(m.fixed_in_dispute) })) };
        stubState.purl = `pkg:npm/${c.package}@${c.version}`;
        const res = await client.callTool({ name: tool, arguments: argsOf(c) });
        assert.ok(!res.isError, `${label}: ${noteOf(res)}`);
        const note = noteOf(res);
        assert.ok(note.includes(SAID_OF_DISPUTED[tool]), `${label}: ${note}`);
        assert.doesNotMatch(note, FALSE_CLAIMS, label);
        assert.deepEqual(unqualifiedAdvisoryAccount(note), [], label);
        for (const m of c.match.matches) {
          const named = label === "higher both" ? `${m.cve_id}${whereOf(c)}: "${m.fixed_in_dispute.note}"` : `${m.cve_id}${whereOf(c)}: (the API sent no note)`;
          assert.ok(note.includes(named), `${label}: ${note}`);
        }
      }
    });

    it(`${tool}: a version the API answers undetermined (cna_range_open_ended, 95927abe's qs 6.14.1) is relayed undetermined, its reason as sent, never clean`, async () => {
      for (const [name, c] of UNDETERMINED) {
        stubState.match = c.match;
        stubState.purl = `pkg:npm/${c.package}@${c.version}`;
        const res = await client.callTool({ name: tool, arguments: argsOf(c) });
        assert.ok(!res.isError, `${name}: ${noteOf(res)}`);
        const v = validator.getValidator(schemaOf(tool))(res.structuredContent);
        assert.ok(v.valid, `${name}: ${v.errorMessage}`);
        const data = res.structuredContent.data;
        const row = tool === "check_affected" ? data : data.results.find((r) => r.purl === stubState.purl);
        assert.deepEqual(row.undetermined, c.match.undetermined, name);
        if (tool !== "check_affected") assert.equal(row.verdict, "undetermined", name);
        const note = noteOf(res);
        assert.match(note, /undetermined/i, name);
        assert.doesNotMatch(note, /fixed_in_dispute/, name);
        // Every sentence that says clean says not or never.
        for (const sentence of note.split(/(?<=\.)\s+/)) if (/\bclean\b/i.test(sentence)) assert.match(sentence, /\b(not|never)\b/, `${name}: ${sentence}`);
      }
    });

    it(`${tool}: a kind, a higher and a status a later API adds, and fields it adds, are relayed, never a failed call`, async () => {
      const c = CASES[0][1];
      stubState.match = { ...c.match, matches: c.match.matches.map(LATER) };
      stubState.purl = `pkg:npm/${c.package}@${c.version}`;
      const res = await client.callTool({ name: tool, arguments: argsOf(c) });
      assert.ok(!res.isError, noteOf(res));
      assert.equal(res.structuredContent.state, "measured", noteOf(res));
      assert.deepEqual(matchesOf(res.structuredContent.data, c).map((m) => m.fixed_in_dispute), stubState.match.matches.map((m) => m.fixed_in_dispute));
    });

    // #3381's round-5 review (C4): core-backend's matches with no dispute, as it sends them.
    it(`${tool}: a match core-backend raises with no dispute is relayed with none, nothing said of one, and no advisory's account given of a match the CNA's range raised`, async () => {
      for (const [name, c] of NO_DISPUTE) {
        stubState.match = c.match;
        stubState.purl = `pkg:npm/${c.package}@${c.version}`;
        const res = await client.callTool({ name: tool, arguments: argsOf(c) });
        assert.ok(!res.isError, `${name}: ${noteOf(res)}`);
        const sc = res.structuredContent;
        assert.equal(sc.state, "measured", `${name}: ${noteOf(res)}`);
        const v = validator.getValidator(schemaOf(tool))(sc);
        assert.ok(v.valid, `${name}: ${v.errorMessage}`);
        const ms = matchesOf(sc.data, c);
        assert.deepEqual(ms.map((m) => [Object.hasOwn(m, "fixed_in_dispute"), m.version_evidence, m.fixed_in ?? null, m.interval]), c.match.matches.map((m) => [false, m.version_evidence, null, m.interval]), name);
        const note = noteOf(res);
        assert.doesNotMatch(note, /fixed_in_dispute/, `${name}: ${note}`);
        assert.doesNotMatch(textBlocks(res)[0], /fixed_in_dispute/, name);
        assert.doesNotMatch(note, FALSE_CLAIMS, name);
        assert.doesNotMatch(note, /of the advisory holds/, `${name}: ${note}`);
      }
    });

    it(`control, ${tool}: the same answer without fixed_in_dispute says nothing of one, and keeps the advisory's account of fixed_in`, async () => {
      const c = WIRE.cna_fixed_advisory_interval;
      stubState.match = { ...c.match, matches: c.match.matches.map(withoutDispute) };
      stubState.purl = `pkg:npm/${c.package}@${c.version}`;
      const res = await client.callTool({ name: tool, arguments: argsOf(c) });
      assert.ok(!res.isError, noteOf(res));
      for (const m of matchesOf(res.structuredContent.data, c)) assert.ok(!Object.hasOwn(m, "fixed_in_dispute"), JSON.stringify(m));
      assert.doesNotMatch(noteOf(res), /fixed_in_dispute/);
      assert.doesNotMatch(textBlocks(res)[0], /fixed_in_dispute/);
      assert.match(noteOf(res), /first version above (this one|the component's) that no affected interval of the CVE's record holds/);
    });
  }

  it("cve_remediation: every case's installed version and fixed_in_dispute relayed, its note quoted verbatim, fixed_in never called the advisory's; without it, the advisory's account", async () => {
    for (const [name, c] of [...CASES, ...NO_DISPUTE, ...UNDETERMINED]) {
      const cve = (c.match.matches[0] ?? c.match.undetermined[0]).cve_id;
      stubState.remediation = remediationOf(c, cve);
      const args = { cve_id: cve, ecosystem: "npm", package: c.package, version: c.version };
      const res = await client.callTool({ name: "cve_remediation", arguments: args });
      assert.ok(!res.isError, `${name}: ${noteOf(res)}`);
      const v = validator.getValidator(schemaOf("cve_remediation"))(res.structuredContent);
      assert.ok(v.valid, `${name}: ${v.errorMessage}`);
      const data = res.structuredContent.data;
      assert.deepEqual(data.fixed_in_dispute, c.remediation.fixed_in_dispute, name);
      assert.equal(data.installed.version_evidence, c.remediation.installed.version_evidence, name);
      const note = noteOf(res);
      if (c.remediation.fixed_in_dispute) {
        assert.ok(note.includes(`fixed_in_dispute: the CVE record's CNA and the advisory disagree on the range that holds it; the API's note, verbatim: "${c.remediation.fixed_in_dispute.note}"`), `${name}: ${note}`);
        assert.doesNotMatch(note, FALSE_CLAIMS, name);
        if (c.remediation.fixed_in) assert.ok(note.includes(`fixed_in is ${c.remediation.fixed_in}: `) && note.includes("as the API answers it, following the source fixed_in_dispute's higher names"), `${name}: ${note}`);
      } else if (c.match.matches.length > 0) {
        // #3381's round-5 review (C4): a match with no dispute: fixed_in null and its reason as sent, nothing said of a
        // dispute, and fixed_in not called the advisory's where the CNA's range raised the match.
        assert.equal(data.fixed_in ?? null, null, name);
        assert.doesNotMatch(note, /fixed_in_dispute/, `${name}: ${note}`);
        assert.doesNotMatch(note, FALSE_CLAIMS, `${name}: ${note}`);
        assert.ok(note.includes(c.remediation.fixed_in_reason), `${name}: ${note}`);
      } else {
        // The undetermined case: its verdict and fixed_in_reason as sent, nothing said of a dispute.
        assert.equal(data.installed.verdict, "undetermined", name);
        assert.ok(note.includes(`installed.verdict is undetermined and fixed_in is null: ${c.remediation.fixed_in_reason}`), `${name}: ${note}`);
        assert.doesNotMatch(note, /fixed_in_dispute/, name);
      }
    }
    // #3381's round-4 review (F15): without a note, a dispute all the same.
    for (const edit of [(d) => { const { note: _, ...rest } = d; return rest; }, (d) => ({ ...d, note: "" }), (d) => ({ ...d, note: null })]) {
      const c = WIRE.cna_fixed_advisory_interval;
      const cve = c.match.matches[0].cve_id;
      const r = remediationOf(c, cve);
      stubState.remediation = { ...r, fixed_in_dispute: edit(r.fixed_in_dispute) };
      const res = await client.callTool({ name: "cve_remediation", arguments: { cve_id: cve, ecosystem: "npm", package: c.package, version: c.version } });
      assert.ok(!res.isError, noteOf(res));
      const note = noteOf(res);
      assert.ok(note.includes("as the API answers it, following the source fixed_in_dispute's higher names") && note.includes("fixed_in_dispute: the CVE record's CNA and the advisory disagree on the range that holds it; the API sent no note on it"), note);
      assert.doesNotMatch(note, FALSE_CLAIMS);
    }
    // Control: without the dispute, an advisory interval's fixed_in is the advisory's.
    const a = WIRE.cna_fixed_advisory_interval;
    const aCve = a.match.matches[0].cve_id;
    stubState.remediation = remediationOf(a, aCve, false);
    const plain = await client.callTool({ name: "cve_remediation", arguments: { cve_id: aCve, ecosystem: "npm", package: a.package, version: a.version } });
    assert.ok(!plain.isError, noteOf(plain));
    assert.equal(plain.structuredContent.data.installed.version_evidence, "advisory_interval");
    assert.ok(!Object.hasOwn(plain.structuredContent.data, "fixed_in_dispute"));
    assert.doesNotMatch(noteOf(plain), /fixed_in_dispute/);
    assert.match(noteOf(plain), /as the advisory states it/);
    // #3767: and where the range holding the version is the CVE record's CNA range (cna_affected_range), with no dispute,
    // fixed_in is the CNA's, never called the advisory's (through 3.2.2 it was).
    const c = WIRE.cna_fixed_cna_affected_range;
    stubState.remediation = remediationOf(c, "CVE-2026-4800", false);
    const cnaRange = await client.callTool({ name: "cve_remediation", arguments: { cve_id: "CVE-2026-4800", ecosystem: "npm", package: "lodash", version: "4.18.0" } });
    assert.ok(!cnaRange.isError, noteOf(cnaRange));
    assert.doesNotMatch(noteOf(cnaRange), /fixed_in_dispute/);
    assert.doesNotMatch(noteOf(cnaRange), FALSE_CLAIMS);
    assert.match(noteOf(cnaRange), /fixed_in is 4\.18\.1: the fixed bound of the affected range \[4\.0\.0, 4\.18\.1\) that holds it, as the CVE record's CNA states it, not an advisory \(installed\.version_evidence cna_affected_range\);/);
  });

  // Round 11 (the round-10 verify's d5 F5, F6, F7). Controls in round 10: cve_remediation's note quoted a 200,000-character
  // note whole; check_affected's DATA CUT kept no match at all; a malformed fixed_in_dispute failed the call.
  it("round 11: an over-long note is clipped in the note and whole in data, keeps check_affected's matches in a cut, and a malformed fixed_in_dispute is left out, never failing the call", async () => {
    const LONG = `${"x".repeat(199_999)}.`;
    const c = WIRE.cna_fixed_advisory_interval;
    // F5: cve_remediation.
    const cve = c.match.matches[0].cve_id;
    const r = remediationOf(c, cve);
    stubState.remediation = { ...r, fixed_in_dispute: { ...r.fixed_in_dispute, note: LONG } };
    let res = await client.callTool({ name: "cve_remediation", arguments: { cve_id: cve, ecosystem: "npm", package: c.package, version: c.version } });
    assert.ok(!res.isError, noteOf(res));
    assert.ok(noteOf(res).length < 20_000, `the note is ${noteOf(res).length} characters`);
    assert.ok(noteOf(res).includes(`the API's note, verbatim: "${"x".repeat(999)}…"`), "clipped as the other tools clip it");
    assert.equal(res.structuredContent.data.fixed_in_dispute.note, LONG, "whole in data");
    // F6: check_affected's data cut thins its matches before any leaves, the long note out of the leanest level.
    stubState.match = { ...c.match, matches: c.match.matches.map((m, i) => (i === 0 ? { ...m, fixed_in_dispute: { ...m.fixed_in_dispute, note: LONG } } : m)) };
    stubState.purl = `pkg:npm/${c.package}@${c.version}`;
    const caArgs = { ecosystem: "npm", package: c.package, version: c.version };
    res = await client.callTool({ name: "check_affected", arguments: caArgs });
    assert.ok(!res.isError, noteOf(res));
    const ms = res.structuredContent.data.matches;
    assert.equal(ms.length, c.match.matches.length, JSON.stringify(res.structuredContent.data.truncated ?? null));
    for (const [i, m] of ms.entries()) {
      assert.equal(m.cve_id, c.match.matches[i].cve_id);
      assert.equal(m.fixed_in, c.match.matches[i].fixed_in, "fixed_in kept beside its dispute");
      assert.equal(m.fixed_in_dispute?.higher, c.match.matches[i].fixed_in_dispute.higher, "the dispute's source kept");
      assert.deepEqual(m.fixed_in_dispute?.cna_range, c.match.matches[i].fixed_in_dispute.cna_range);
    }
    const v = validator.getValidator(schemaOf("check_affected"))(res.structuredContent);
    assert.ok(v.valid, v.errorMessage);
    // F7: a malformed fixed_in_dispute is left out, the call answered with every match.
    // Round 11's final check (F1-a): and one that carries a readable note, which is not said to be missing.
    for (const bad of ["a string", 5, [], { kind: 5 }, { cna_range: { changes: [null] } }, { kind: 5, higher: "cna", note: "a note the API wrote" }]) {
      stubState.match = { ...c.match, matches: c.match.matches.map((m, i) => (i === 0 ? { ...m, fixed_in_dispute: bad } : m)) };
      res = await client.callTool({ name: "check_affected", arguments: caArgs });
      assert.ok(!res.isError, `${JSON.stringify(bad)}: ${noteOf(res)}`);
      const got = res.structuredContent.data.matches;
      assert.equal(got.length, c.match.matches.length, JSON.stringify(bad));
      // Round 11 review (F1): relayed empty, the match still disputed, named in the note; its fixed_in not called the
      // advisory's.
      assert.deepEqual(got[0].fixed_in_dispute, {}, JSON.stringify(bad));
      assert.deepEqual(got[1].fixed_in_dispute, c.match.matches[1].fixed_in_dispute, "the readable one relayed as sent");
      assert.ok(noteOf(res).includes(`The fixed_in_dispute the API sent on ${c.match.matches[0].cve_id} was not in the shape this server reads, so it is relayed empty ({}): the match is still disputed, and its fixed_in may follow the CVE record's CNA, not the advisory.`), `${JSON.stringify(bad)}: ${noteOf(res)}`);
      assert.doesNotMatch(noteOf(res), /On the match without fixed_in_dispute/, JSON.stringify(bad));
      assert.ok(noteOf(res).includes(`${c.match.matches[0].cve_id}: (its value was not in the shape this server reads)`), `${JSON.stringify(bad)}: ${noteOf(res)}`);
      assert.ok(!noteOf(res).includes(`${c.match.matches[0].cve_id}: (the API sent no note)`), `${JSON.stringify(bad)}: an unread value said to carry no note`);
      stubState.remediation = { ...r, fixed_in_dispute: bad };
      res = await client.callTool({ name: "cve_remediation", arguments: { cve_id: cve, ecosystem: "npm", package: c.package, version: c.version } });
      assert.ok(!res.isError, `cve_remediation ${JSON.stringify(bad)}: ${noteOf(res)}`);
      assert.deepEqual(res.structuredContent.data.fixed_in_dispute, {}, JSON.stringify(bad));
      assert.match(noteOf(res), /not in the shape this server reads, so it is relayed empty/, JSON.stringify(bad));
      assert.doesNotMatch(noteOf(res), /as the advisory states it/, `cve_remediation ${JSON.stringify(bad)}: fixed_in called the advisory's`);
      // F1-a, F1-b, F1-c: the value said unreadable, never noteless; the answer (not a match) still disputed; each clause ends.
      assert.ok(noteOf(res).includes("disagree on the range that holds it; its value was not in the shape this server reads. The fixed_in_dispute the API sent on"), `cve_remediation ${JSON.stringify(bad)}: ${noteOf(res)}`);
      assert.ok(noteOf(res).includes("so it is relayed empty ({}): the answer is still disputed"), `cve_remediation ${JSON.stringify(bad)}: ${noteOf(res)}`);
      assert.doesNotMatch(noteOf(res), /the match is still disputed|the API sent no note/, `cve_remediation ${JSON.stringify(bad)}`);
      if (r.installed && typeof r.installed === "object") {
        stubState.remediation = { ...r, installed: { ...r.installed, fixed_in_dispute: bad } };
        res = await client.callTool({ name: "cve_remediation", arguments: { cve_id: cve, ecosystem: "npm", package: c.package, version: c.version } });
        assert.ok(!res.isError, `cve_remediation installed ${JSON.stringify(bad)}: ${noteOf(res)}`);
        assert.ok(noteOf(res).includes(`The fixed_in_dispute the API sent on the installed version asked (npm ${c.package} ${c.version}) was not in the shape this server reads`), `cve_remediation installed ${JSON.stringify(bad)}: ${noteOf(res)}`);
      }
      // check_sbom: the call answered, its other row (left-pad) kept, the malformed value out of lodash's match.
      stubState.match = { ...c.match, matches: c.match.matches.map((m, i) => (i === 0 ? { ...m, fixed_in_dispute: bad } : m)) };
      stubState.purl = `pkg:npm/${c.package}@${c.version}`;
      res = await client.callTool({ name: "check_sbom", arguments: { purls: [stubState.purl, "pkg:npm/left-pad@1.3.0"] } });
      assert.ok(!res.isError, `check_sbom ${JSON.stringify(bad)}: ${noteOf(res)}`);
      const rows = res.structuredContent.data.results;
      assert.ok(rows.some((r) => r.purl === "pkg:npm/left-pad@1.3.0"), "the other row is kept");
      const lodash = rows.find((r) => r.purl === stubState.purl);
      assert.deepEqual(lodash.matches[0].fixed_in_dispute, {}, JSON.stringify(bad));
      assert.ok(noteOf(res).includes(`The fixed_in_dispute the API sent on ${c.match.matches[0].cve_id} (${stubState.purl}) was not in the shape this server reads`), `check_sbom ${JSON.stringify(bad)}: ${noteOf(res)}`);
    }
  });

  it("get_cve: the record's affected_ranges, as #3391's API writes them (changes, changes_truncated, versions_truncated, stored_form, and its fourth round's collection_url, package_url, dropped_products), named in its outputSchema and relayed as sent, with a field a later API adds", async () => {
    const json = JSON.stringify(schemaOf("get_cve"));
    // #3381's round-5 review (C4): and package_name, the entry's packageName.
    for (const k of ["affected_ranges", "versions_truncated", "stored_form", "changes", "changes_truncated", "default_status", "less_than_or_equal", "collection_url", "package_url", "package_name", "dropped_products", "dropped_products_truncated"]) {
      assert.match(json, new RegExp(`"${k}"`), `get_cve's outputSchema does not name ${k}`);
    }
    // #3381's round-10 review (d5-3391relay F2): the fields #3391's API lane adds are described as what a product carries
    // once EchelonGraph's API serves them, and a product without stored_form as one that may have been cut unflagged.
    // Control: round 10's description, which said each is served.
    const desc = /"description":"(The CVE record's affected ranges[^"]*)"/.exec(json)?.[1] ?? "";
    const SERVED = /^(?:(?!Once EchelonGraph's API serves them).)*\b(package_name|collection_url|package_url|versions_truncated|dropped_products|stored_form)\b/;
    assert.doesNotMatch(desc, SERVED, desc);
    assert.match(desc, /A product without stored_form comes from an API or a writer that sends none of these: its versions or its source's products may have been cut, with no flag saying so\./);
    assert.match("The CVE record's affected ranges, each a product as its CNA (source cna) or CISA's ADP (source cisa-adp) writes it: vendor, product (the product or package the entry names, as the API stores it), package_name (the entry's packageName, where it names one)", SERVED);
    const cna = WIRE.cna_changes.match.matches[0].fixed_in_dispute.cna_range;
    stubState.record = {
      cve_id: "CVE-2099-34203", severity: "HIGH", cvss_v3_score: 7.5, score_assessed: true, echelongraph_score: 7.5, epss_score: 0.01, kev_listed: false,
      cna: { short_name: "openjs", name: "OpenJS Foundation" },
      affected_ranges: [
        { source: "cna", vendor: "OpenJS", product: "pkg", collection_url: "https://www.npmjs.com", package_url: "pkg:npm/pkg", package_name: "pkg", default_status: "unaffected", versions: [cna, { ...cna, version: "5.0.0", changes_truncated: true, added_later: 1 }], versions_truncated: true, dropped_products: ["pkg-cli"], dropped_products_truncated: true, stored_form: 2, added_later: "x" },
        { source: "cisa-adp", product: "pkg", versions: [{ version: "0", status: "affected", less_than_or_equal: "4.18.0", version_type: "semver" }] },
      ],
    };
    const res = await client.callTool({ name: "get_cve", arguments: { cve_id: "CVE-2099-34203" } });
    assert.ok(!res.isError, noteOf(res));
    const v = validator.getValidator(schemaOf("get_cve"))(res.structuredContent);
    assert.ok(v.valid, v.errorMessage);
    assert.deepEqual(res.structuredContent.data.affected_ranges, stubState.record.affected_ranges);
  });

  it("check_affected: a list long enough to be cut keeps fixed_in_dispute on every match both cuts keep", async () => {
    const base = WIRE.cna_through_last_affected.match;
    const matches = Array.from({ length: 60 }, (_, i) => ({ ...base.matches[0], cve_id: `CVE-2099-${41000 + i}`, description: "d".repeat(900) }));
    stubState.match = { ...base, matches, count: 60, cve_ids: matches.map((m) => m.cve_id) };
    const res = await client.callTool({ name: "check_affected", arguments: { ecosystem: "npm", package: "pkg", version: "2.0.0" } });
    assert.ok(!res.isError, noteOf(res));
    const sc = res.structuredContent;
    assert.equal(sc.data_truncated, true, "the answer was not cut: re-aim this test");
    const text = JSON.parse(textBlocks(res)[0]).matches;
    // The text's cut caps a long string where it keeps it (its TEXT CUT note says so), the note among them: kept on
    // every match, whole or as its start marked with an ellipsis; data keeps it whole.
    const real = base.matches[0].fixed_in_dispute;
    const keptOf = (d) => d && d.higher === real.higher && d.kind === real.kind && d.advisory_fixed === real.advisory_fixed && (d.note === real.note || (d.note.endsWith("…") && real.note.startsWith(d.note.slice(0, -1))));
    assert.ok(text.length >= 1 && text.length < 60 && text.every((m) => keptOf(m.fixed_in_dispute)), `the text's cut dropped fixed_in_dispute (${text.length} kept)`);
    assert.ok(sc.data.matches.length >= 1 && sc.data.matches.every((m) => m.fixed_in_dispute?.note === base.matches[0].fixed_in_dispute.note), "the structured cut dropped fixed_in_dispute");
    assert.match(noteOf(res), /fixed_in_dispute on 60 matches/);
  });
});

describe("#3391: the note's dispute sentence is bounded, and the cuts that keep fixed_in keep fixed_in_dispute", () => {
  it("disputesSentence names at most 5 matches, quotes each note whole (core-backend's are far below the clip), and cuts only past 1000 characters; disputedOf counts a dispute without a note, and says it has none", () => {
    const real = WIRE.cna_fixed_advisory_interval.match.matches[0].fixed_in_dispute.note;
    const one = D.disputesSentence(D.disputedOf([{ cve_id: "CVE-2026-4800", fixed_in_dispute: { note: real } }]));
    assert.ok(one.includes(`CVE-2026-4800: "${real}"`), one);
    const long = "n".repeat(1500);
    const found = D.disputedOf(Array.from({ length: 9 }, (_, i) => ({ cve_id: `CVE-2099-${40000 + i}`, fixed_in_dispute: { note: long } })), "pkg:npm/x@1");
    assert.equal(found.length, 9);
    const s = D.disputesSentence(found);
    assert.equal((s.match(/CVE-2099-4000\d/g) ?? []).length, 5);
    assert.match(s, /; and 4 more, each in its match's fixed_in_dispute\.$/);
    assert.ok(s.includes(`"${"n".repeat(999)}…"`) && !s.includes("n".repeat(1000)), "a note past the clip is not cut");
    assert.ok(s.length < 6000, `${s.length}`);
    for (const [, c] of CASES) for (const m of c.match.matches) assert.ok(m.fixed_in_dispute.note.length < 1000);
    const noteless = D.disputedOf([{ cve_id: "A", fixed_in_dispute: { kind: "fixed" } }, { cve_id: "B", fixed_in_dispute: { note: "  " } }, { cve_id: "C" }, { cve_id: "D", fixed_in_dispute: null }, { cve_id: "E", fixed_in_dispute: [] }, null, "x"]);
    assert.deepEqual(noteless, [{ where: "A", note: undefined }, { where: "B", note: undefined }]);
    assert.match(D.disputesSentence(noteless), /verbatim: A: \(the API sent no note\); B: \(the API sent no note\)\.$/);
    assert.equal(D.disputesSentence([]), "");
  });

  const matchFields = (keep) => keep.find((k) => Array.isArray(k) && k[0] === "matches")?.[1] ?? [];
  it("check_sbom's text levels and SBOM_ROW_THIN keep fixed_in_dispute wherever they keep fixed_in_reason", () => {
    for (const level of SBOM.sbomText(2).levels) {
      const ms = matchFields(level.keep);
      if (ms.includes("fixed_in_reason")) assert.ok(ms.includes("fixed_in_dispute"), JSON.stringify(ms));
    }
    assert.ok(matchFields(SBOM.SBOM_ROW_THIN).includes("fixed_in_dispute"));
    // As fixed_in_reason, it stays out of the compact level, measured for #3269 (check_sbom.ts).
    assert.ok(!matchFields(SBOM.SBOM_ROW_COMPACT).includes("fixed_in_reason") && !matchFields(SBOM.SBOM_ROW_COMPACT).includes("fixed_in_dispute"));
  });

  it("check_affected's text levels keep fixed_in_dispute wherever they keep fixed_in_reason, and both of its data cut's thin levels keep it", () => {
    const levels = CA.CHECK_AFFECTED_TEXT.levels;
    assert.equal(levels.length, 6);
    let withReason = 0;
    for (const level of levels) {
      if (level.keep.includes("fixed_in_reason")) {
        withReason++;
        assert.ok(level.keep.includes("fixed_in_dispute"), JSON.stringify(level.keep));
      }
    }
    assert.ok(withReason >= 1, "no level keeps fixed_in_reason: re-aim this test");
    const thin = CA.CHECK_AFFECTED_DATA.steps.find((s) => s.lists.includes("matches")).thin;
    // Round 11 (d5 F6): a third level, the leanest, keeps it to every field but its note; the two above keep it whole.
    assert.equal(thin.length, 3);
    const keeps = (t, f) => t.some((k) => k === f || (Array.isArray(k) && k[0] === f));
    for (const t of thin) assert.ok(keeps(t, "fixed_in_dispute") && t.includes("fixed_in"), JSON.stringify(t));
    assert.ok(thin[0].includes("fixed_in_dispute") && thin[1].includes("fixed_in_dispute"));
    assert.deepEqual(thin[2].find((k) => Array.isArray(k) && k[0] === "fixed_in_dispute")?.[1], D.DISPUTE_THIN);
    assert.ok(!D.DISPUTE_THIN.includes("note") && D.DISPUTE_THIN.includes("higher") && D.DISPUTE_THIN.includes("cna_range"));
  });
});

// Round 11 (the round-10 verify's d5 N1): a dispute whose higher is cna on an advisory_interval match carries the CNA's
// range that holds the advisory's fix, which may start above the version. 95927abe answers lodash 4.17.15 under
// CVE-2026-2950 with cna_range [4.17.23, 4.18.1), a range OpenJS's own record does not hold 4.17.15 in; the description
// says so, and no longer that the range holds the version.
describe("fixed_in_dispute's cna_range where higher is cna on an advisory_interval match", () => {
  it("is the CNA's range past the advisory's fix, which can start above the version, and the description says so", async () => {
    const FD = await import(pathToFileURL(path.join(PKG_DIR, "dist", "fixedInDispute.js")).href);
    const c = WIRE.cna_fixed_advisory_interval;
    const m = c.match.matches.find((x) => x.cve_id === "CVE-2026-2950");
    assert.equal(c.version, "4.17.15");
    assert.equal(m.version_evidence, "advisory_interval");
    assert.equal(m.fixed_in_dispute.higher, "cna");
    assert.equal(m.fixed_in_dispute.cna_range.version, "4.17.23", "the CNA's range starts above the version asked");
    assert.equal(m.fixed_in_dispute.cna_range.less_than, "4.18.1");
    assert.match(FD.FIXED_IN_DISPUTE_FIELD, /on an advisory_interval or exact_version_list match it holds the advisory's bound past the version \(its fix, or the versions just above its last affected or listed version\), so it may start above the version/);
    assert.doesNotMatch(FD.FIXED_IN_DISPUTE_FIELD, /where higher is cna, the one that holds the version/);
  });
});
