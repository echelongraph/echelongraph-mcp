// #2720: cve_intel, get_cwe, and get_cve's cpe_configurations, against a stub EchelonGraph API,
// in both protocol eras (2026-07-28 server/discover and the 2025-06-18 initialize), with every
// structuredContent validated against the tool's advertised outputSchema by ajv, as the SDK
// ships it (the same validator tools.test.mjs uses).
//
// What is under test, per tool:
//   cve_intel  the relayed cut (cwes, exploits and their counts, affected_packages,
//              fixed_versions, timeline), exploits_total past the 10-row cap, a section the API
//              could not read left out and named (never relayed as an empty list), an answer
//              without failed_sections or exploits_total (an API older than #2720) worded as
//              such, an empty exploits list never worded as "no exploit exists", no request but
//              /enrichment (never /blast-radius), and invalid input refused before any request.
//   get_cwe    the API's JSON relayed as sent, the order repeated only when the answer states it,
//              a served page that differs from the asked one, the pageable cap, a measured empty
//              CWE, rows NOT YET SCORED, and input normalised (79 -> CWE-79) or refused.
//   get_cve    cpe_configurations relayed, and its absence said in the envelope as "not stored",
//              not "no product affected".
//
// Runs against dist/index.js (npm test builds first), or an installed bin (server-under-test.mjs).
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { AjvJsonSchemaValidator } from "@modelcontextprotocol/server/validators/ajv";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { serverCommand } from "./server-under-test.mjs";

const ERAS = [MODERN, "2025-06-18"];
const LOG4SHELL = "CVE-2021-44228";
const ENRICH = (id) => `/api/v1/public/cves/${id}/enrichment`;

// Claims the package's copy must not make (tools.test.mjs REMOVED_CLAIMS, HOST_UNIT).
const REMOVED_CLAIMS = /passive|no other|unique|real-?time|\blive\b|right now/i;
const HOST_UNIT = /\bhosts\b|\bhost\(s\)/i;
const FIELD_TOKEN = /\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b/g;

// ── Fixtures: core-backend's wire shapes at #2720 ──
const exploit = (i, kind, status, day) => ({
  kind,
  source_name: `${kind}/${i}`,
  source_url: `https://example.test/${kind}/${i}`,
  first_seen_at: `2021-12-${String(day).padStart(2, "0")}T00:00:00Z`,
  verified_status: status,
});
const TIMELINE = Array.from({ length: 25 }, (_, i) => ({
  enriched_at: new Date(Date.UTC(2026, 8, 30 - i)).toISOString(),
  enrichment_kind: "epss",
  fields_changed: { epss_score: { from: 0.9, to: 0.97 } },
}));
// What handler_enrichment.go serves for a widely-weaponised CVE: two CWEs, 12 references (2
// verified Metasploit modules first, then GitHub PoCs), every section read.
const LOG4SHELL_ENRICHMENT = {
  vendor_advisories: [{ vendor: "apache", advisory_id: "LOG4J2-3201", url: "https://logging.apache.org/log4j/2.x/security.html" }],
  patches: [{ vendor: "apache", patch_url: "https://example.test/patch", source: "nvd" }],
  fixed_versions: [{ ecosystem: "Maven", package_name: "org.apache.logging.log4j:log4j-core", vulnerable_range: ">=2.0-beta9 <2.15.0", fixed_version: "2.15.0", source: "osv" }],
  affected_packages: [{ ecosystem: "Maven", package_name: "org.apache.logging.log4j:log4j-core", version_range: ">=2.0-beta9 <2.15.0", fixed_version: "2.15.0", dependents_count: 7000, source: "ghsa" }],
  cwes: [
    { cwe_id: "CWE-502", name: "Deserialization of Untrusted Data", source: "nvd" },
    { cwe_id: "CWE-917", name: "Improper Neutralization of Special Elements Used in an Expression Language Statement (EL Injection)", source: "nvd" },
  ],
  timeline: TIMELINE,
  timeline_count_7d: 3,
  timeline_count_30d: 9,
  timeline_total: 140,
  ai: { plain_summary: { content_kind: "plain_summary", content_md: "generated text", model: "m", generated_at: "2026-09-01T00:00:00Z" }, risk_narrative: null, remediation_playbook: null },
  trending: { is_trending: false, recent_source_count: 0, kev_recent: false, patch_recent: false },
  historical_incidents: [],
  exploits: [exploit(0, "metasploit", "verified", 14), exploit(1, "metasploit", "verified", 13), ...Array.from({ length: 8 }, (_, i) => exploit(i, "github_poc", "reported", 20 - i))],
  exploits_total: 12,
  exploits_capped: true,
  exploits_by_kind: { metasploit: 2, github_poc: 10 },
  exploits_by_status: { verified: 2, reported: 10 },
  failed_sections: [],
};
const EMPTY_ENRICHMENT = {
  ...LOG4SHELL_ENRICHMENT,
  vendor_advisories: [],
  patches: [],
  fixed_versions: [],
  affected_packages: [],
  cwes: [],
  timeline: [],
  timeline_total: 0,
  timeline_count_7d: 0,
  timeline_count_30d: 0,
  exploits: [],
  exploits_total: 0,
  exploits_capped: false,
  exploits_by_kind: {},
  exploits_by_status: {},
  failed_sections: [],
};
// The same CVE as an API older than #2720 serves it: no counts, no failed_sections, and the
// sections that timed out silently empty.
const { exploits_total: _t, exploits_capped: _c, exploits_by_kind: _k, exploits_by_status: _s, failed_sections: _f, ...OLDER } = LOG4SHELL_ENRICHMENT;
const OLDER_EMPTY = { ...OLDER, cwes: [], exploits: [] };
// Sections the API could not read (#2720): served empty, and named.
const PARTIAL = { ...LOG4SHELL_ENRICHMENT, cwes: [], exploits: [], exploits_total: null, exploits_capped: false, exploits_by_kind: {}, exploits_by_status: {}, failed_sections: ["cwes", "exploits", "exploits_total"] };
const ALL_FAILED = { ...EMPTY_ENRICHMENT, failed_sections: ["affected_packages", "cwes", "exploits", "exploits_total", "fixed_versions", "timeline", "timeline_stats"] };
// #2817: the affected_packages rows core-backend serves since #2817 for CVE-2021-44228: one row per
// package, fixed_version one range's fix (log4j-core's 2.12.2, production's on 2026-10-04), and
// fixed_branches every range of the OSV record (GHSA-jfh8-c2jp-5v3q), in the record's order, each
// naming that record; a last_affected bound kept out of fixed; null for a row never structurally
// loaded; [] beside a fixed_version where no version range is on record (only commit ranges).
const RANGE = (introduced, fixed, last_affected = null) => ({ introduced, fixed, last_affected, source: "osv_bulk", advisory_id: "GHSA-jfh8-c2jp-5v3q" });
const LOG4J_CORE_BRANCHES = [RANGE("2.13.0", "2.15.0"), RANGE("2.0-beta9", "2.3.1"), RANGE("2.4", "2.12.2")];
const BRANCHES = {
  ...LOG4SHELL_ENRICHMENT,
  affected_packages: [
    { ecosystem: "Maven", package_name: "org.apache.logging.log4j:log4j-core", version_range: "2.10.0 ... 2.9.1 (18 versions)", fixed_version: "2.12.2", fixed_branches: LOG4J_CORE_BRANCHES, dependents_count: 0, source: "osv" },
    { ecosystem: "Maven", package_name: "com.guicedee.services:log4j-core", version_range: "1.0.10.0 ... 1.2.1.2-jre17 (362 versions)", fixed_branches: [RANGE("0", null, "1.2.1.2-jre17")], dependents_count: 0, source: "osv" },
    { ecosystem: "Debian:12", package_name: "apache-log4j2", fixed_version: "2.15.0-1", fixed_branches: null, dependents_count: 0, source: "osv_bulk" },
    { ecosystem: "Go", package_name: "example.test/commit-ranges-only", fixed_version: "8a5e1f0d3c2b", fixed_branches: [], dependents_count: 0, source: "osv_bulk" },
  ],
};

const CWE79_ROWS = [
  { cve_id: "CVE-2024-27204", severity: "MEDIUM", cvss_v3_score: 6.1, echelongraph_score: 7.2, echelongraph_severity: "HIGH", score_assessed: true, published: "2024-03-01T00:00:00Z", description: "XSS", kev_listed: true },
  { cve_id: "CVE-2010-27203", severity: "MEDIUM", cvss_v3_score: 6.1, echelongraph_score: 6.0, echelongraph_severity: "MEDIUM", score_assessed: true, published: "2010-03-01T00:00:00Z", description: "XSS", kev_listed: false },
  { cve_id: "CVE-2026-27205", severity: "NONE", score_assessed: false, published: "2026-09-01T00:00:00Z", description: "XSS", kev_listed: false },
];
const CWE79 = {
  cwe_id: "CWE-79",
  name: "Cross-site Scripting",
  description: "The product does not neutralize or incorrectly neutralizes user-controllable input.",
  total: 38512,
  cves: CWE79_ROWS,
  page: 1,
  page_size: 50,
  max_page: 200,
  order: "kev_listed desc, echelongraph_score desc (CVEs not yet scored last), cvss_v3_score desc (nulls last), published desc (nulls last), cve_id",
  catalog_version: "4.17",
};
const { order: _o, max_page: _m, catalog_version: _v, ...CWE79_OLDER } = CWE79;

const CFG = [
  {
    operator: "AND",
    nodes: [
      { operator: "OR", negate: false, cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:o:acme:fw:*:*:*:*:*:*:*:*", versionStartExcluding: "2.0", versionEndExcluding: "2.4.1", matchCriteriaId: "11111111-2222-3333-4444-555555555555" }] },
      { operator: "OR", negate: false, cpeMatch: [{ vulnerable: false, criteria: "cpe:2.3:h:acme:x100:-:*:*:*:*:*:*:*", matchCriteriaId: "66666666-7777-8888-9999-000000000000" }] },
    ],
  },
];
const CVE_RECORD = (id, extra = {}) => ({
  cve_id: id,
  description: "d",
  severity: "HIGH",
  cvss_v3_score: 8.1,
  score_assessed: true,
  echelongraph_score: 8,
  cpe_match: [{ criteria: "cpe:2.3:o:acme:fw:*:*:*:*:*:*:*:*", vulnerable: true }],
  updated_at: "2026-10-01T00:00:00Z",
  ...extra,
});

const ANSWERS = {
  [ENRICH(LOG4SHELL)]: LOG4SHELL_ENRICHMENT,
  [ENRICH("CVE-2099-27300")]: EMPTY_ENRICHMENT,
  [ENRICH("CVE-2099-27301")]: OLDER,
  [ENRICH("CVE-2099-27302")]: OLDER_EMPTY,
  [ENRICH("CVE-2099-27303")]: PARTIAL,
  [ENRICH("CVE-2099-27304")]: ALL_FAILED,
  [ENRICH("CVE-2099-27305")]: { status: 500, body: { error: "boom" } },
  [ENRICH("CVE-2099-28170")]: BRANCHES,
  "/api/v1/public/cwes/CWE-79": CWE79,
  "/api/v1/public/cwes/CWE-79?page=3": { ...CWE79, page: 3 },
  "/api/v1/public/cwes/CWE-79?page=200": { ...CWE79, page: 200, cves: [] },
  "/api/v1/public/cwes/CWE-80": { ...CWE79_OLDER, cwe_id: "CWE-80", name: "Basic XSS", total: 3 },
  "/api/v1/public/cwes/CWE-99999": { cwe_id: "CWE-99999", total: 0, cves: [], page: 1, page_size: 50, max_page: 200, order: CWE79.order },
  // The API clamps a page past its last to the last page it serves.
  "/api/v1/public/cwes/CWE-81?page=7": { ...CWE79, cwe_id: "CWE-81", total: 120, page: 3 },
  "/api/v1/public/cves/CVE-2099-27310": CVE_RECORD("CVE-2099-27310", { cpe_configurations: CFG }),
  "/api/v1/public/cves/CVE-2099-27311": CVE_RECORD("CVE-2099-27311"),
};

let stub;
const seen = [];
before(async () => {
  stub = http.createServer((req, res) => {
    seen.push(req.url);
    const a = ANSWERS[req.url];
    if (a === undefined) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: `not found: ${new URL(req.url, "http://stub").pathname}` }));
      return;
    }
    res.writeHead(a.status ?? 200, { "content-type": "application/json" });
    res.end(JSON.stringify(a.status ? a.body : a));
  });
  await new Promise((resolve) => stub.listen(0, "127.0.0.1", resolve));
});
after(() => new Promise((resolve) => stub.close(resolve)));

const validator = new AjvJsonSchemaValidator();
const textBlocks = (res) => (res.content ?? []).filter((c) => c.type === "text").map((c) => c.text);
const noteOf = (res) => textBlocks(res)[res.isError ? 0 : 1] ?? "";
const sentences = (t) => t.replace(/\s+/g, " ").trim().split(/(?<=[.!?])\s+/).filter(Boolean);
function schemaNames(s, out = new Set()) {
  if (s === null || typeof s !== "object") return out;
  if (Array.isArray(s)) {
    for (const x of s) schemaNames(x, out);
    return out;
  }
  for (const e of s.enum ?? []) if (typeof e === "string") out.add(e);
  if (s.properties) for (const k of Object.keys(s.properties)) out.add(k);
  for (const [k, x] of Object.entries(s)) if (k !== "enum" && k !== "description") schemaNames(x, out);
  return out;
}

for (const era of ERAS) {
  describe(`#2720 cve_intel, get_cwe and get_cve's cpe_configurations [${era}]`, () => {
    let client;
    let tools;
    const results = [];
    const call = async (name, args) => {
      const res = await client.callTool({ name, arguments: args });
      results.push([name, args, res]);
      return res;
    };
    before(async () => {
      client = await connect({
        era,
        ...serverCommand(),
        env: { ...process.env, ECHELONGRAPH_API_BASE: `http://127.0.0.1:${stub.address().port}`, ECHELONGRAPH_API_TIMEOUT_MS: "2000" },
        stderr: "ignore",
      });
      ({ tools } = await client.listTools());
    });
    after(() => client?.close());
    const schemaOf = (name) => tools.find((t) => t.name === name).outputSchema;

    // Every result's text is its structuredContent: data, then the note, then the rest.
    function assertTextIsStructure(where, res) {
      const sc = res.structuredContent;
      const blocks = textBlocks(res);
      assert.equal(blocks.length, res.isError ? 2 : 3, `${where}: text blocks`);
      const env = JSON.parse(blocks.at(-1));
      for (const k of ["state", "measured_at", "coverage", "freshness"]) assert.deepEqual(env[k], sc[k], `${where}: envelope block ${k}`);
      if (!res.isError) assert.deepEqual(JSON.parse(blocks[0]), sc.data, `${where}: data`);
      const said = sentences(blocks.at(-2));
      assert.deepEqual(sc.notes.slice(-said.length), said, `${where}: notes end with the note's sentences`);
    }

    it("tools/list: both tools registered after check_sbom, with titles, annotations and an outputSchema", () => {
      // The full order is tools.test.mjs's LISTED; here, the two together, where createServer registers them.
      const names = tools.map((t) => t.name);
      const at = names.indexOf("check_sbom");
      assert.deepEqual(names.slice(at, at + 3), ["check_sbom", "cve_intel", "get_cwe"]);
      for (const name of ["cve_intel", "get_cwe"]) {
        const t = tools.find((x) => x.name === name);
        assert.ok(t.title, name);
        assert.deepEqual(t.annotations, { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true });
        assert.equal(t.outputSchema.type, "object");
        const ok = t.outputSchema.oneOf.find((b) => b.properties.state.enum.includes("measured"));
        assert.equal(ok.additionalProperties, false);
        for (const k of ["state", "measured_at", "method", "coverage", "freshness", "notes", "data"]) assert.ok(ok.required.includes(k), `${name}: ${k}`);
      }
    });

    it("#1880 rule: every field a description names is in that tool's outputSchema; no removed claim; no hosts", () => {
      for (const name of ["cve_intel", "get_cwe", "get_cve"]) {
        const t = tools.find((x) => x.name === name);
        const names = schemaNames(t.outputSchema);
        const unknown = [...new Set(t.description.match(FIELD_TOKEN) ?? [])].filter((x) => !names.has(x));
        assert.deepEqual(unknown, [], `${name}: description names fields its outputSchema lacks`);
        assert.doesNotMatch(t.description, REMOVED_CLAIMS, name);
        assert.doesNotMatch(t.description, HOST_UNIT, name);
      }
      assert.match(tools.find((t) => t.name === "get_cve").description, /cpe_configurations \(NVD's configurations as NVD sent them, with each AND\/OR operator/);
      assert.doesNotMatch(tools.find((t) => t.name === "get_cve").description, /\bCWE\b/, "get_cve returns no CWE");
    });

    it("cve_intel: Log4Shell-shaped answer — CWE-502 and CWE-917, 12 references past the cap, verified first, a labelled cut", async () => {
      seen.length = 0;
      const res = await call("cve_intel", { cve_id: LOG4SHELL.toLowerCase() });
      assert.ok(!res.isError, noteOf(res));
      assert.deepEqual(seen, [ENRICH(LOG4SHELL)], "only /enrichment, canonical id; never /blast-radius");
      const sc = res.structuredContent;
      assert.equal(sc.state, "measured");
      assert.equal(sc.measured_at, null);
      assert.equal(sc.freshness, null);
      assert.deepEqual(
        Object.keys(sc.data).sort(),
        ["affected_packages", "cve_id", "cwes", "exploits", "exploits_by_kind", "exploits_by_status", "exploits_capped", "exploits_total", "fixed_versions", "timeline", "timeline_count_30d", "timeline_count_7d", "timeline_total"].sort(),
      );
      assert.deepEqual(sc.data.cwes.map((c) => c.cwe_id), ["CWE-502", "CWE-917"]);
      assert.deepEqual(sc.data.exploits, LOG4SHELL_ENRICHMENT.exploits, "exploits relayed as sent");
      assert.equal(sc.data.exploits[0].verified_status, "verified");
      assert.equal(sc.data.exploits_total, 12);
      assert.equal(sc.data.timeline.length, 20);
      assert.deepEqual(sc.data.timeline, TIMELINE.slice(0, 20), "the newest 20, as sent");
      assert.deepEqual(sc.coverage.sections_failed, []);
      assert.deepEqual(sc.coverage.sections_left_out, ["vendor_advisories", "patches", "ai", "trending", "historical_incidents"]);
      assert.deepEqual(sc.coverage.exploits, { returned: 10, api_row_limit: 10 });
      assert.deepEqual(sc.coverage.timeline, { returned: 25, relayed: 20, api_row_limit: 100 });
      const n = noteOf(res);
      assert.match(n, /^cve_intel OK: EchelonGraph answered HTTP 200 from /);
      assert.ok(n.includes("CVE-2021-44228 is classified under CWE-502 (Deserialization of Untrusted Data) and CWE-917 (Improper Neutralization"), n);
      assert.ok(n.includes("EchelonGraph holds 12 public exploit references for CVE-2021-44228 (exploits_total), 2 of them with verified_status verified. exploits_capped is true: exploits lists 10 of the 12, verified first."), n);
      assert.ok(n.includes("timeline relays the 20 newest of the 25 enrichment-history rows the API returned (timeline_total 140)."), n);
      assert.ok(n.includes("Not relayed from the answer: vendor_advisories, patches, ai, trending and historical_incidents."), n);
      assert.doesNotMatch(JSON.stringify(res), /generated text/, "the ai section is not relayed");
      assert.match(sc.method, /metasploit\), Exploit-DB entries \(exploit_db\), nuclei templates \(nuclei_template\), GitHub proof-of-concept repositories \(github_poc\) and vendor proofs of concept \(vendor_poc\)/);
      assert.match(sc.method, /each run only where it is enabled, so which sources are current depends on the deployment/);
      assert.doesNotMatch(sc.method, /\bpolled (daily|every)\b/i, "method claims no source is polled");
      assertTextIsStructure("cve_intel ok", res);
    });

    it("cve_intel: zero references is a counted zero, never 'no exploit exists'", async () => {
      const res = await call("cve_intel", { cve_id: "CVE-2099-27300" });
      const n = noteOf(res);
      assert.ok(n.includes("EchelonGraph holds no public exploit reference for CVE-2099-27300 (exploits_total 0). That is not evidence that no public exploit exists"), n);
      assert.ok(n.includes("No CWE classification is on record for CVE-2099-27300 (cwes is empty)"), n);
      assert.ok(n.includes("which is not a finding that the CVE has no weakness class"), n);
      assert.ok(n.includes("affected_packages is empty"), n);
      assert.doesNotMatch(n, /older than that field/);
      assertTextIsStructure("cve_intel empty", res);
    });

    it("#2817 cve_intel: fixed_branches relayed as sent, every range of log4j-core; the note and description say fixed_version is one range's", async () => {
      const res = await call("cve_intel", { cve_id: "CVE-2099-28170" });
      assert.ok(!res.isError, noteOf(res));
      const rows = res.structuredContent.data.affected_packages;
      assert.deepEqual(rows, BRANCHES.affected_packages, "affected_packages relayed as sent");
      const core = rows.find((r) => r.package_name === "org.apache.logging.log4j:log4j-core");
      assert.deepEqual(core.fixed_branches, LOG4J_CORE_BRANCHES);
      // The range holding 2.14.1 is fixed in 2.15.0; fixed_version alone says 2.12.2.
      assert.equal(core.fixed_branches.find((b) => b.introduced === "2.13.0").fixed, "2.15.0");
      assert.equal(core.fixed_version, "2.12.2");
      // The first text block (what a client without structuredContent shows) carries them whole.
      assert.deepEqual(JSON.parse(textBlocks(res)[0]).affected_packages[0].fixed_branches, LOG4J_CORE_BRANCHES);
      const n = noteOf(res);
      assert.ok(n.includes("1 affected_packages row lists more than one affected range in fixed_branches (org.apache.logging.log4j:log4j-core (Maven)): there, fixed_version is one range's fix, and an installed version's fix is the fixed of the range that holds it."), n);
      assert.ok(n.includes("1 affected_packages row carries fixed_branches null (apache-log4j2 (Debian:12)): its ranges are not on record, so fixed_version, one range's fix, is all the answer holds"), n);
      // [] is "no version range on record", not "no fix": the row's fixed_version is named as such.
      assert.ok(n.includes("1 affected_packages row carries fixed_branches [] and a fixed_version (example.test/commit-ranges-only (Go)): no version range is on record there, which is not a finding that no fix exists"), n);
      // Each range names the OSV record that published it, relayed as sent.
      assert.equal(core.fixed_branches[0].advisory_id, "GHSA-jfh8-c2jp-5v3q");
      assert.equal(core.fixed_branches[0].source, "osv_bulk");
      assertTextIsStructure("cve_intel fixed_branches", res);

      // The description says how to pick the range for an installed version, and what fixed_version is.
      const d = tools.find((t) => t.name === "cve_intel").description;
      assert.match(d, /affected_packages \(ecosystem, package_name, version_range, fixed_version, fixed_branches\)/);
      assert.match(d, /To pick the range for an installed version, compare in the ecosystem's version order/);
      assert.match(d, /at or above introduced \("0" is the first version\) and below fixed, or at or below last_affected; that range's fixed is the fix for it/);
      assert.match(d, /fixed_version is one range's fix, kept for compatibility/);
      assert.match(d, /with advisory_id \(the OSV record that published the range\) and source/);
      assert.match(d, /Ranges with an advisory_id are in the order their record lists them/);
      assert.match(d, /\[\] where no version range is on record \(the advisory gives none, only commit ranges, or more than are stored\), which is not a finding that no fix exists/);
      assert.match(d, /not the fix for every affected range/);
      // #2817 trip-wire: nothing calls fixed_version the version to upgrade to.
      assert.doesNotMatch(d, /fixed_version[^.]*(the version to upgrade to|upgrade to)/i);

      // An answer older than #2817 (no fixed_branches on any row) is worded as such.
      const older = await call("cve_intel", { cve_id: LOG4SHELL });
      assert.ok(noteOf(older).includes("No affected_packages row carries fixed_branches (an API older than that field): each row's fixed_version is one range's fix, which need not be the fix for a given installed version."), noteOf(older));
    });

    it("cve_intel: a section the API could not read is left out of data and named, not relayed as empty", async () => {
      const res = await call("cve_intel", { cve_id: "CVE-2099-27303" });
      const sc = res.structuredContent;
      assert.equal(sc.state, "measured");
      for (const k of ["cwes", "exploits", "exploits_total", "exploits_capped", "exploits_by_kind", "exploits_by_status"]) assert.ok(!(k in sc.data), `${k} relayed though it failed`);
      assert.deepEqual(sc.coverage.sections_failed, ["cwes", "exploits", "exploits_total"]);
      assert.deepEqual(sc.coverage.sections_relayed, ["affected_packages", "fixed_versions", "timeline"]);
      assert.deepEqual(sc.coverage.exploits, { returned: null, api_row_limit: 10 });
      const n = noteOf(res);
      assert.ok(n.includes("The API could not read cwes, exploits and exploits_total (failed_sections): they are left out of data, and the absence is not a finding of none."), n);
      assert.doesNotMatch(n, /No CWE classification|no public exploit reference/, n);
      assertTextIsStructure("cve_intel partial", res);
    });

    it("cve_intel: an API older than #2720 — no exploits_total, no failed_sections — is worded as such", async () => {
      const full = await call("cve_intel", { cve_id: "CVE-2099-27301" });
      assert.equal(full.structuredContent.coverage.sections_failed, null);
      assert.ok(noteOf(full).includes("exploits lists 10 public exploit references for CVE-2099-27301, 2 with verified_status verified; the answer carries no exploits_total, so it does not say how many are on record. The API lists at most 10 references, so there may be more."), noteOf(full));
      const empty = await call("cve_intel", { cve_id: "CVE-2099-27302" });
      const n = noteOf(empty);
      assert.ok(n.includes("exploits is empty and the answer carries no exploits_total"), n);
      assert.ok(n.includes("an empty list is not evidence that no public exploit exists"), n);
      assert.ok(n.includes("The answer carries no failed_sections (an API older than that field), so it does not say whether cwes and exploits were read"), n);
      assertTextIsStructure("cve_intel older", empty);
    });

    it("cve_intel: every relayed section failed — a failure, not an empty success", async () => {
      const res = await call("cve_intel", { cve_id: "CVE-2099-27304" });
      assert.equal(res.isError, true);
      assert.equal(res.structuredContent.state, "failed");
      assert.equal(res.structuredContent.error.kind, "unexpected_shape");
      assert.match(noteOf(res), /could not read any section this tool relays/);
      assert.match(noteOf(res), /this is not a finding/);
      assertTextIsStructure("cve_intel all failed", res);
    });

    it("cve_intel: HTTP 500 and 404 are failures; a malformed or blank id is refused with no request", async () => {
      const r500 = await call("cve_intel", { cve_id: "CVE-2099-27305" });
      assert.equal(r500.structuredContent.state, "failed");
      assert.match(noteOf(r500), /HTTP 500 .* the API said: boom/);
      const r404 = await call("cve_intel", { cve_id: "CVE-2099-27399" });
      assert.equal(r404.structuredContent.state, "failed");
      assert.match(noteOf(r404), /returned no record/);
      seen.length = 0;
      for (const bad of ["", "  ", "log4shell", "CVE-21-1", "../summary"]) {
        const res = await call("cve_intel", { cve_id: bad });
        assert.equal(res.structuredContent.state, "invalid_input", bad);
        assertTextIsStructure(`cve_intel ${JSON.stringify(bad)}`, res);
      }
      assert.deepEqual(seen, [], "an invalid id reached the API");
    });

    it("get_cwe: CWE-79 relayed as sent, the stated order repeated, KEV rows counted, NOT YET SCORED labelled, the pageable cap said", async () => {
      seen.length = 0;
      const res = await call("get_cwe", { cwe_id: "79" });
      assert.deepEqual(seen, ["/api/v1/public/cwes/CWE-79"]);
      const sc = res.structuredContent;
      assert.equal(sc.state, "measured");
      assert.deepEqual(sc.data, CWE79);
      assert.deepEqual(sc.coverage, { total: 38512, returned: 3, page: 1, page_requested: 1, page_size: 50, max_page: 200 });
      const n = noteOf(res);
      assert.ok(n.includes("CWE-79 is Cross-site Scripting in the MITRE CWE catalog (version 4.17)."), n);
      assert.ok(n.includes("EchelonGraph's feed holds 38512 active CVEs classified under CWE-79 (total, rejected and reserved records left out); this page lists 3 (page 1 of at most 200)."), n);
      assert.ok(n.includes("Only the first 10000 of them can be paged to: the API serves no page past max_page 200."), n);
      assert.ok(n.includes(`The rows are sorted by ${CWE79.order}, as the answer states (order); 1 of the 3 on this page are CISA-KEV-listed (kev_listed).`), n);
      assert.match(n, /NOT YET SCORED: 1 of the 3 CVEs in this page is not yet scored by EchelonGraph: CVE-2026-27205\./);
      assertTextIsStructure("get_cwe ok", res);
    });

    it("get_cwe: page passed through; a served page that differs from the asked one is said", async () => {
      seen.length = 0;
      const p3 = await call("get_cwe", { cwe_id: "cwe-79", page: 3 });
      assert.deepEqual(seen, ["/api/v1/public/cwes/CWE-79?page=3"]);
      assert.equal(p3.structuredContent.coverage.page, 3);
      assert.doesNotMatch(noteOf(p3), /was asked for/);
      const clamped = await call("get_cwe", { cwe_id: "CWE-81", page: 7 });
      assert.equal(clamped.structuredContent.coverage.page_requested, 7);
      assert.ok(noteOf(clamped).includes("Page 7 was asked for and the API served page 3."), noteOf(clamped));
    });

    it("get_cwe: an answer without order is not called KEV-first", async () => {
      const res = await call("get_cwe", { cwe_id: "CWE-80" });
      const n = noteOf(res);
      assert.ok(n.includes("The answer does not state how its rows are sorted (no order field; an API older than it sorted them by CVE id), so the first rows are not necessarily the CISA-KEV-listed or highest-scored ones"), n);
      assert.doesNotMatch(n, /\(version /, "no catalog version claimed");
      assert.equal(res.structuredContent.coverage.max_page, null);
      assertTextIsStructure("get_cwe older", res);
    });

    it("get_cwe: total 0 is a measured empty result, scoped to EchelonGraph's feed", async () => {
      const res = await call("get_cwe", { cwe_id: "CWE-99999" });
      const n = noteOf(res);
      assert.ok(n.includes("The answer carries no name for CWE-99999"), n);
      assert.ok(n.includes("No active CVE in EchelonGraph's feed is classified under CWE-99999 (total 0): a measured empty result (we looked and found nothing), which says only that no NVD, GitHub or CVE.org record EchelonGraph holds puts a CVE in this class, not that none exists."), n);
    });

    it("get_cwe: a malformed id is refused with no request", async () => {
      seen.length = 0;
      for (const bad of ["", "XSS", "CWE-", "CWE-79a", "79/../../cves"]) {
        const res = await call("get_cwe", { cwe_id: bad });
        assert.equal(res.structuredContent.state, "invalid_input", bad);
      }
      assert.deepEqual(seen, []);
    });

    it("get_cve: cpe_configurations relayed as sent; its absence said as 'not stored', not 'no product affected'", async () => {
      const withCfg = await call("get_cve", { cve_id: "CVE-2099-27310" });
      assert.deepEqual(withCfg.structuredContent.data.cpe_configurations, CFG);
      assert.ok(withCfg.structuredContent.notes.some((s) => s.startsWith("cpe_configurations is NVD's configurations array as sent (1)")));
      const without = await call("get_cve", { cve_id: "CVE-2099-27311" });
      assert.ok(!("cpe_configurations" in without.structuredContent.data));
      const said = without.structuredContent.notes.find((s) => s.startsWith("No cpe_configurations in the answer"));
      assert.ok(said, JSON.stringify(without.structuredContent.notes));
      assert.match(said, /which does not mean no product is affected/);
      // The note in content[1] is unchanged (tools.test.mjs pins it word for word).
      assert.match(noteOf(without), /^get_cve OK: EchelonGraph answered HTTP 200 from .*\. Returned the record for CVE-2099-27311\.$/);
      assertTextIsStructure("get_cve with", withCfg);
      assertTextIsStructure("get_cve without", without);
    });

    it("every result validates against its tool's outputSchema (ajv), and none makes a removed claim", () => {
      assert.ok(results.length >= 25, `only ${results.length} results`);
      const tried = new Set();
      for (const [name, args, res] of results) {
        tried.add(`${name}:${res.structuredContent.state}`);
        const v = validator.getValidator(schemaOf(name))(res.structuredContent);
        assert.ok(v.valid, `${name} ${JSON.stringify(args)}: ${v.errorMessage}`);
        assert.doesNotMatch(textBlocks(res).slice(1).join(" "), REMOVED_CLAIMS, `${name} ${JSON.stringify(args)}`);
        assert.doesNotMatch(textBlocks(res).slice(1).join(" "), HOST_UNIT, `${name} ${JSON.stringify(args)}`);
      }
      for (const k of ["cve_intel:measured", "cve_intel:failed", "cve_intel:invalid_input", "get_cwe:measured", "get_cwe:invalid_input", "get_cve:measured"]) assert.ok(tried.has(k), `no ${k} result validated`);
    });

    it("control: the validator rejects a cve_intel result that relays a field the schema does not name", () => {
      const [, , res] = results.find(([n, , r]) => n === "cve_intel" && r.structuredContent.state === "measured");
      const bad = { ...res.structuredContent, data: { ...res.structuredContent.data, vendor_advisories: [] } };
      assert.equal(validator.getValidator(schemaOf("cve_intel"))(bad).valid, false);
    });
  });
}
