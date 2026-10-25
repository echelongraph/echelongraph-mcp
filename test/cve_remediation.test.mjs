// #2841 cve_remediation, get_cve's remediation summary, and #2840's remediation fields on the
// vendor-advisory tools, against a stub EchelonGraph API, in both protocol eras, with every
// structuredContent validated against the tool's advertised outputSchema by ajv.
//
// What is under test:
//   cve_remediation  the answer relayed as sent (nothing generated: every vendor text in data is
//                    the API's byte for byte, and no note sentence carries remediation text of
//                    its own), CISA's action attributed and scoped to US federal agencies, the
//                    vendor categories named by vendor, not_parsed and none_in_source never worded
//                    as "no fix", a failed section named, a REJECTED CVE not_assessed, a huge
//                    answer cut within the text budget with kinds, states and URLs kept, failures
//                    as failures, and invalid input refused before any request.
//   get_cve          remediation relayed, and one note sentence about it.
//   vendor tools     remediation_kinds and remediation_state on a by-cve row and remediations[]
//                    on the detail, validated, and named in the note.
//
// The fixtures are core-backend's wire shapes at #2840/#2841 (cve/remediation.go
// RemediationResponse, vendoradv/handler.go Detail and ByCVE).
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
// #3121: answers are validated against the closed success branch (strict-output.mjs).
import { StrictOutputValidator } from "./strict-output.mjs";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { serverCommand } from "./server-under-test.mjs";
import { assertDataCutOf, isThinOf } from "./text-bound.mjs";

const ERAS = [MODERN, "2025-06-18"];
const LOG4SHELL = "CVE-2021-44228";
const REM = (id) => `/api/v1/public/cves/${id}/remediation`;
const FIELD_TOKEN = /\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b/g;
const REMOVED_CLAIMS = /passive|no other|unique|real-?time|\blive\b|right now/i;

// ── Fixtures ──
const RH_FIX =
  "For details on how to apply this update, which includes the changes described in this advisory, refer to:\n\nhttps://access.redhat.com/articles/11258";
const RH_WORKAROUND = "Mitigation for this issue is either not available or the currently available options don't meet the Red Hat Product Security criteria.";
const CISA_ACTION =
  "For all affected software assets for which updates exist, the only acceptable remediation actions are: 1) Apply updates; OR 2) remove affected assets from agency networks. Temporary mitigations using one of the measures provided at https://www.cisa.gov/uscert/ed-22-02-apache-log4j-recommended-mitigation-measures are only acceptable until updates are available.";
const item = (kind, category, text, url, extra = {}) => ({
  kind,
  source_category: category,
  source_subcategory: null,
  text,
  text_truncated: false,
  text_chars: text.length,
  url,
  fixed_build: null,
  product_ids: [],
  product_count: 0,
  ...extra,
});
const adv = (vendor, id, state, items, extra = {}) => ({
  vendor,
  vendor_display_name: vendor,
  vendor_advisory_id: id,
  vendor_published_at: "2021-12-14T00:00:00Z",
  withdrawn: false,
  remediation_state: state,
  remediation_kinds: [...new Set(items.map((i) => i.kind))],
  items,
  items_total: items.length,
  ...extra,
});
const COVERAGE = (notParsed) => ({ parsed_vendors: ["redhat", "microsoft", "paloalto"], vendors_not_parsed: notParsed, vendor_advisories_listed: 3, vendor_advisory_limit: 20, item_text_cap: 2000, items_per_advisory_cap: 16 });
const BRANCH = (introduced, fixed, last_affected = null) => ({ introduced, fixed, last_affected, source: "osv_bulk", advisory_id: "GHSA-jfh8-c2jp-5v3q" });
// #2841: the API's fix-status rule (core-backend cve/fixstatus.go), as served.
const FIX_STATUS = { state: "available", basis: "patch_evidence_release", unread_inputs: [] };
const LOG4SHELL_REMEDIATION = {
  cve_id: LOG4SHELL,
  state: "assessed",
  not_assessed_reason: null,
  fix_status: FIX_STATUS,
  cisa: { kev_listed: true, required_action: CISA_ACTION, due_date: "2021-12-24T00:00:00Z", short_description: "Apache Log4j2 contains a vulnerability.", notes_urls: ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"] },
  fixed_branches: [
    {
      ecosystem: "Maven",
      package_name: "org.apache.logging.log4j:log4j-core",
      fixed_version: "2.12.2",
      dependents_count: 7000,
      source: "osv_bulk",
      fixed_branches: [BRANCH("2.13.0", "2.15.0"), BRANCH("2.4", "2.12.2"), BRANCH("2.0-beta9", "2.3.1")],
    },
  ],
  vendor_remediations: [
    adv("redhat", "RHSA-2021:5129", "parsed", [
      item("vendor_fix", "vendor_fix", RH_FIX, "https://access.redhat.com/errata/RHSA-2021:5129", { product_ids: ["7Server-optional:log4j"], product_count: 1 }),
      item("workaround", "workaround", RH_WORKAROUND, null),
    ]),
    adv("paloalto", "PAN-SA-2021-0007", "none_in_source", []),
    adv("cisco", "cisco-sa-apache-log4j-qRuKNEbd", "not_parsed", []),
  ],
  fix_references: [{ url: "https://logging.apache.org/log4j/2.x/security.html", tags: ["Mitigation"], source: "security@apache.org" }],
  patches: [],
  coverage: COVERAGE(["cisco"]),
  failed_sections: [],
};
const REJECTED = {
  cve_id: "CVE-2099-30001",
  state: "not_assessed",
  not_assessed_reason: "rejected: the CVE record was rejected (withdrawn) by its numbering authority",
  cisa: { kev_listed: false, required_action: null, due_date: null, short_description: null, notes_urls: [] },
  fixed_branches: [],
  vendor_remediations: [],
  fix_references: [],
  patches: [],
  coverage: COVERAGE([]),
  failed_sections: [],
};
const NOTHING = { ...REJECTED, cve_id: "CVE-2099-30002", state: "assessed", not_assessed_reason: null };
const PARTIAL = { ...LOG4SHELL_REMEDIATION, cve_id: "CVE-2099-30003", vendor_remediations: [], failed_sections: ["vendor_remediations"] };
// Past the text budget: 20 advisories of 16 items of 2,000 characters.
const LONG = "W".repeat(2000);
const HUGE = {
  ...LOG4SHELL_REMEDIATION,
  cve_id: "CVE-2099-30004",
  vendor_remediations: Array.from({ length: 20 }, (_, a) =>
    adv(
      "redhat",
      `RHSA-2099:${1000 + a}`,
      "parsed",
      Array.from({ length: 16 }, (_, i) => item(i % 2 ? "workaround" : "vendor_fix", i % 2 ? "workaround" : "vendor_fix", LONG, `https://access.redhat.com/errata/RHSA-2099:${1000 + a}#${i}`, { text_truncated: true, text_chars: 4000 })),
    ),
  ),
};
// #3139: CVE-2023-44487 (KEV-listed) as hosted 3.0.0 answered it with full: true (2026-10-11),
// each advisory item cut to the fields the first thinning level keeps (product_ids dropped). Its
// default answer kept 2 of 20 advisories while fixed_branches (13,581 characters, 50 rows) and
// patches (7,471, 30) stayed whole.
const RAPID_RESET = JSON.parse(fs.readFileSync(new URL("./fixtures/cve_remediation-CVE-2023-44487.json", import.meta.url), "utf8")).data;
// #3285: CVE-2025-48013 as the public API served it (2026-10-18): drupal/quick_node_block listed
// under Packagist:https://packages.drupal.org/8 (fixed 2.0.1) and under Packagist (fixed 2.0.0).
const DRUPAL_48013 = JSON.parse(fs.readFileSync(new URL("./fixtures/cve_remediation-CVE-2025-48013.json", import.meta.url), "utf8")).data;
// The note's fix rule, applied as it reads: an installed version's fix is the first fixed above it
// that no range of its package holds, walked from the range that holds it. Its package is the entry
// of the component's ecosystem and package_name, or, where the note says entries of one
// package_name under Packagist or Maven, bare or with a repository URL, are one package, all of
// those entries. Versions here are plain release numbers.
const ONE_PACKAGE = 'Entries of one package_name under Packagist or Maven, bare or with a repository URL after ":", are one package, its ranges all of theirs together';
const relNum = (a, b) => {
  const [pa, pb] = [a, b].map((v) => v.split(".").map(Number));
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) < (pb[i] ?? 0) ? -1 : 1;
  return 0;
};
const rangeHolds = (r, v) => relNum(v, r.introduced) >= 0 && (r.fixed ? relNum(v, r.fixed) < 0 : r.last_affected ? relNum(v, r.last_affected) <= 0 : true);
function fixByNoteRule(note, fixedBranches, { ecosystem, pkg, installed }) {
  const base = (e) => e.toLowerCase().split(":")[0];
  const grouped = note.includes(ONE_PACKAGE) && ["packagist", "maven"].includes(base(ecosystem));
  const entries = fixedBranches.filter((e) => e.package_name.toLowerCase() === pkg.toLowerCase() && (grouped ? base(e.ecosystem) === base(ecosystem) : e.ecosystem === ecosystem));
  const ranges = entries.flatMap((e) => e.fixed_branches ?? []);
  let r = ranges.find((x) => rangeHolds(x, installed));
  const walked = new Set();
  while (r) {
    if (!r.fixed || walked.has(r)) return null;
    walked.add(r);
    const v = r.fixed;
    r = ranges.find((x) => rangeHolds(x, v));
    if (!r) return v;
  }
  return null;
}
const SUMMARY = {
  fix_status: FIX_STATUS,
  vendor_remediation_kinds: { vendor_fix: 1, workaround: 1 },
  vendor_advisories: 3,
  vendors_not_parsed: ["cisco"],
  kev_required_action: CISA_ACTION,
  fixed_branches_count: 3,
  fixed_versions: [{ ecosystem: "Maven", package_name: "org.apache.logging.log4j:log4j-core", fixed: ["2.15.0", "2.12.2", "2.3.1"], fixed_total: 3 }],
  fix_references: ["https://logging.apache.org/log4j/2.x/security.html"],
  failed_sections: [],
  truncated: false,
  see: "cve_remediation",
};
const CVE_RECORD = { cve_id: LOG4SHELL, description: "Log4Shell", severity: "CRITICAL", kev_listed: true, kev_required_action: CISA_ACTION, score_assessed: true, echelongraph_score: 10, updated_at: "2026-10-01T00:00:00Z", remediation: SUMMARY };
const BY_CVE = {
  cve_id: LOG4SHELL,
  total: 2,
  cve_rejected: false,
  advisories: [
    { advisory_id: "a1", vendor: "redhat", vendor_display_name: "Red Hat", vendor_advisory_id: "RHSA-2021:5129", title: "log4j", severity: "Critical", vendor_published_at: "2021-12-14T00:00:00Z", our_first_seen_at: "2026-05-01T00:00:00Z", withdrawn: false, rejected_cve_ids: [], remediation_kinds: ["vendor_fix", "workaround"], remediation_state: "parsed" },
    { advisory_id: "a2", vendor: "cisco", vendor_display_name: "Cisco", vendor_advisory_id: "cisco-sa-apache-log4j-qRuKNEbd", title: "log4j", severity: "Critical", vendor_published_at: "2021-12-10T00:00:00Z", our_first_seen_at: "2026-05-01T00:00:00Z", withdrawn: false, rejected_cve_ids: [], remediation_kinds: [], remediation_state: "not_parsed" },
  ],
};
const DETAIL = {
  ...BY_CVE.advisories[0],
  cve_ids: [LOG4SHELL],
  known_cve_ids: [LOG4SHELL],
  description: "d",
  affected_products: [],
  remediation: RH_FIX,
  references: [],
  vendor_modified_at: "",
  withdrawn_at: "",
  withdrawn_reason: "",
  remediations: [{ ...item("vendor_fix", "vendor_fix", RH_FIX, "https://access.redhat.com/errata/RHSA-2021:5129"), cve_ids: [LOG4SHELL] }],
  remediation_items_not_stored: 0,
};

// #2841: what the route answers when the X-EG-* installed-version headers are sent (cve/remediation.go).
const INSTALLED_BASE = { ecosystem: "Maven", ecosystem_recognised: true, package: "org.apache.logging.log4j:log4j-core" };
const NOT_AFFECTED_REASON = "the version is outside every affected range on record for this package, so per the ranges on record it is not affected by this CVE and has no fix to name";
const MOVED_PAST = "fixed_in moved past the overlapping interval [2.10.0, 2.15.0) of the same record: the interval that holds this version, [2.4, 2.12.2), ends inside it, so its own bound is still affected";
const WITH_INSTALLED = {
  "2.14.1": {
    ...LOG4SHELL_REMEDIATION,
    installed: { ...INSTALLED_BASE, version: "2.14.1", verdict: "affected", version_evidence: "advisory_interval", interval: { introduced: "2.13.0", fixed: "2.15.0" } },
    fixed_in: "2.15.0",
  },
  "2.17.1": { ...LOG4SHELL_REMEDIATION, installed: { ...INSTALLED_BASE, version: "2.17.1", verdict: "not_affected" }, fixed_in: null, fixed_in_reason: NOT_AFFECTED_REASON },
  // #3074: a holding range whose own bound another range of the record still holds (synthetic
  // ranges, the detail as core-backend's registryFixFor renders it).
  "2.11.0": {
    ...LOG4SHELL_REMEDIATION,
    installed: { ...INSTALLED_BASE, version: "2.11.0", verdict: "affected", version_evidence: "advisory_interval", interval: { introduced: "2.4", fixed: "2.12.2" } },
    fixed_in: "2.15.0",
    fixed_in_detail: MOVED_PAST,
  },
};
// The installed version's request headers (core-backend cve/handler.go MatchEcosystemHeader..).
const INSTALLED_HEADERS = ["x-eg-ecosystem", "x-eg-package", "x-eg-version"];

// #2841: a CNA's lowercase "patch" tag (CVE-2026-69486, MSRC's record, production 2026-10-11),
// which the API's fix_references kept only once it matched the tag in either case.
const CNA_PATCH = {
  ...NOTHING,
  cve_id: "CVE-2026-69486",
  fix_status: { state: "fix_referenced", basis: "patch_evidence_reference_only", unread_inputs: [] },
  fix_references: [{ url: "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69486", tags: ["patch"] }],
};

// #3076, third pass: Cisco's "has released software updates" with no version (cause G,
// CVE-2025-20362's shape).
const VENDOR_RELEASED = {
  ...NOTHING,
  cve_id: "CVE-2025-20362",
  fix_status: {
    state: "available", basis: "vendor_fix_released", unread_inputs: [],
    vendor_released: { statement: "Cisco strongly recommends that all customers upgrade to the fixed software releases that are listed in the Fixed Software [\"#fs\"] section of this advisory." },
  },
};

const ANSWERS = {
  [REM(LOG4SHELL)]: LOG4SHELL_REMEDIATION,
  [REM("CVE-2026-69486")]: CNA_PATCH,
  [REM("CVE-2025-20362")]: VENDOR_RELEASED,
  [REM("CVE-2099-30001")]: REJECTED,
  [REM("CVE-2099-30002")]: NOTHING,
  [REM("CVE-2099-30003")]: PARTIAL,
  [REM("CVE-2099-30004")]: HUGE,
  [REM("CVE-2023-44487")]: RAPID_RESET,
  [REM("CVE-2025-48013")]: DRUPAL_48013,
  [REM("CVE-2099-48014")]: {
    ...DRUPAL_48013,
    cve_id: "CVE-2099-48014",
    fixed_branches: [
      { ecosystem: "Debian:11", package_name: "openssl", fixed_version: "1.1.1", fixed_branches: [BRANCH("0", "1.1.1")] },
      { ecosystem: "Debian:12", package_name: "openssl", fixed_version: "3.0.1", fixed_branches: [BRANCH("0", "3.0.1")] },
      { ecosystem: "Maven:https://repo.spring.io/release", package_name: "org.example:lib", fixed_version: "1.2.0", fixed_branches: [BRANCH("0", "1.2.0")] },
      { ecosystem: "Maven", package_name: "org.example:lib", fixed_version: "1.1.0", fixed_branches: [BRANCH("0", "1.1.0")] },
    ],
  },
  [REM("CVE-2099-44487")]: { ...RAPID_RESET, cve_id: "CVE-2099-44487", fix_references: [] },
  [REM("CVE-2099-30005")]: { status: 500, body: { error: "boom" } },
  [REM("CVE-2099-30006")]: { cve_id: "CVE-2099-30006" },
  [`/api/v1/public/cves/${LOG4SHELL}`]: CVE_RECORD,
  [`/api/v1/public/vendor-advisories/by-cve/${LOG4SHELL}`]: BY_CVE,
  "/api/v1/public/vendor-advisories/redhat/RHSA-2021%3A5129": DETAIL,
};

let stub;
const seen = [];
const seenHeaders = [];
before(async () => {
  stub = http.createServer((req, res) => {
    seen.push(req.url);
    seenHeaders.push(req.headers);
    const asked = req.headers["x-eg-version"];
    const a = asked !== undefined && req.url === REM(LOG4SHELL) ? WITH_INSTALLED[decodeURIComponent(asked)] : ANSWERS[req.url];
    if (a === undefined) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "not found" }));
      return;
    }
    res.writeHead(a.status ?? 200, { "content-type": "application/json" });
    res.end(JSON.stringify(a.status ? a.body : a));
  });
  await new Promise((resolve) => stub.listen(0, "127.0.0.1", resolve));
});
after(() => new Promise((resolve) => stub.close(resolve)));

const validator = new StrictOutputValidator();
const textBlocks = (res) => (res.content ?? []).filter((c) => c.type === "text").map((c) => c.text);
const noteOf = (res) => textBlocks(res)[res.isError ? 0 : 1] ?? "";
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
// Every vendor text in an answer.
const textsOf = (d) => (d.vendor_remediations ?? []).flatMap((a) => (a.items ?? []).map((i) => i.text));

for (const era of ERAS) {
  describe(`#2841 cve_remediation, get_cve's remediation and #2840's vendor fields [${era}]`, () => {
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

    it("tools/list: registered after cve_intel, with a title, annotations and an outputSchema; the description names only fields it holds", () => {
      const names = tools.map((t) => t.name);
      assert.equal(names[names.indexOf("cve_intel") + 1], "cve_remediation");
      const t = tools.find((x) => x.name === "cve_remediation");
      assert.equal(t.title, "How one CVE is fixed");
      assert.deepEqual(t.annotations, { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true });
      assert.deepEqual(t.inputSchema.required, ["cve_id"]);
      // #2841: the installed version, optional, all three or none.
      // #3013: and full, which every tool takes.
      assert.deepEqual(Object.keys(t.inputSchema.properties), ["cve_id", "ecosystem", "package", "version", "full"]);
      for (const k of ["ecosystem", "package", "version"]) assert.match(t.inputSchema.properties[k].description, /Sent in a request header\./, k);
      assert.match(t.description, /ecosystem, package and version \(all three or none, sent in request headers, never in the URL\) add installed/);
      assert.match(t.description, /^How one CVE is fixed[^]*Returns fix_status /);
      const known = schemaNames(t.outputSchema);
      assert.deepEqual([...new Set(t.description.match(FIELD_TOKEN) ?? [])].filter((x) => !known.has(x)), []);
      assert.doesNotMatch(t.description, REMOVED_CLAIMS);
      assert.ok(t.description.length <= 2048, `${t.description.length} characters`);
    });

    it("Log4Shell: relayed as sent; CISA's action attributed; vendor categories by vendor; not_parsed and none_in_source never 'no fix'", async () => {
      seen.length = 0;
      const res = await call("cve_remediation", { cve_id: LOG4SHELL.toLowerCase() });
      assert.ok(!res.isError, noteOf(res));
      assert.deepEqual(seen, [REM(LOG4SHELL)], "one request, canonical id");
      const sc = res.structuredContent;
      assert.equal(sc.state, "measured");
      assert.deepEqual(sc.data, LOG4SHELL_REMEDIATION, "data is the API's JSON whole");
      assert.deepEqual(sc.coverage.vendors_not_parsed, ["cisco"]);
      assert.deepEqual(sc.coverage.sections_failed, []);
      const note = noteOf(res);
      assert.match(note, /cisa\.required_action is CISA's text, verbatim, due 2021-12-24T00:00:00Z: CISA's required_action is directed at US federal civilian agencies \(under BOD 26-04, which replaced BOD 22-01 on 10 June 2026\) and is not EchelonGraph's advice\./);
      assert.match(note, /vendor_fix from redhat RHSA-2021:5129; workaround from redhat RHSA-2021:5129\./);
      assert.match(note, /paloalto PAN-SA-2021-0007 lists no remediation for CVE-2021-44228 \(none_in_source\), which is not a finding that no fix exists\./);
      assert.match(note, /EchelonGraph does not read the remediation of cisco cisco-sa-apache-log4j-qRuKNEbd \(not_parsed\)/);
      assert.match(note, /fixed_branches lists 1 affected package with 3 affected ranges, 3 with a fix on record/);
      assert.match(note, /fix_status for CVE-2021-44228 is available \(basis patch_evidence_release\), the API's fix-status rule\./);
      assert.equal(sc.coverage.installed_asked, null, "no installed version was asked");
      assert.ok(seenHeaders.at(-1) && INSTALLED_HEADERS.every((h) => !(h in seenHeaders.at(-1))), "no installed-version header is sent without one");
      assert.match(note, /Every text is relayed as stated by its source; EchelonGraph has not tested it\./);
      // No generation: the note carries no remediation text of its own, and no vendor text.
      assert.doesNotMatch(note, /upgrade to|deny all|apply (?:the )?patch|we recommend/i);
      for (const t of textsOf(sc.data)) assert.ok(!note.includes(t), "a vendor text is in the note");
      assert.deepEqual(textsOf(sc.data), [RH_FIX, RH_WORKAROUND], "every text is the API's, byte for byte");
    });

    // #3285 item 2: the note's rule read "no range of its package holds", and fixed_branches lists
    // a package once per stored ecosystem string, so read entry by entry it gave a Packagist
    // drupal/quick_node_block 1.0.0 the Packagist entry's 2.0.0, which the Drupal advisory's
    // entry (Packagist:https://packages.drupal.org/8, [0, 2.0.1)) still holds affected. The matcher
    // reads both entries as one package (core-backend registryRecordKey) and answers 2.0.1. The
    // note now says those entries are one package and names them. Control: the note as it read
    // before (no such sentence), applied the same way, gives 2.0.0.
    it("#3285: CVE-2025-48013's two Packagist entries for drupal/quick_node_block are one package to the note's rule: 1.0.0's fix is 2.0.1, not 2.0.0", async () => {
      const res = await call("cve_remediation", { cve_id: "CVE-2025-48013" });
      assert.ok(!res.isError, noteOf(res));
      assert.deepEqual(res.structuredContent.data, DRUPAL_48013, "data is the API's JSON whole");
      const note = noteOf(res);
      const said = "fixed_branches lists 2 entries, 1 affected package, with 2 affected ranges, 2 with a fix on record; an installed version's fix is the first fixed above it that no range of its package holds (the fixed of the range that holds it, or, while another range still holds that version, that range's fixed), compared in the ecosystem's version order.";
      assert.ok(note.includes(said), note);
      assert.ok(note.includes(`${ONE_PACKAGE}: here drupal/quick_node_block (Packagist:https://packages.drupal.org/8 and Packagist).`), note);
      const component = { ecosystem: "Packagist", pkg: "drupal/quick_node_block", installed: "1.0.0" };
      assert.equal(fixByNoteRule(note, DRUPAL_48013.fixed_branches, component), "2.0.1");
      // Control: the note before (the rule alone, each listed entry its own package).
      const before = note
        .replace(said, said.replace("2 entries, 1 affected package,", "2 affected packages"))
        .replace(` ${ONE_PACKAGE}: here drupal/quick_node_block (Packagist:https://packages.drupal.org/8 and Packagist).`, "");
      assert.ok(before.includes("fixed_branches lists 2 affected packages with 2 affected ranges, 2 with a fix on record; an installed version's fix is the first fixed above it that no range of its package holds"), before);
      assert.ok(!before.includes(ONE_PACKAGE));
      assert.equal(fixByNoteRule(before, DRUPAL_48013.fixed_branches, component), "2.0.0");
      // A release suffix is never one package with its base: Debian:11 and Debian:12 stay apart.
      const distro = [
        { ecosystem: "Debian:11", package_name: "openssl", fixed_branches: [{ introduced: "0", fixed: "1.1.1" }] },
        { ecosystem: "Debian:12", package_name: "openssl", fixed_branches: [{ introduced: "0", fixed: "3.0.1" }] },
      ];
      assert.equal(fixByNoteRule(note, distro, { ecosystem: "Debian:12", pkg: "openssl", installed: "1.0.0" }), "3.0.1");
    });

    it("#3285: a release suffix is not folded: Debian:11 and Debian:12 entries of one package stay two packages, while Maven and Maven:<repository URL> are one", async () => {
      const res = await call("cve_remediation", { cve_id: "CVE-2099-48014" });
      assert.ok(!res.isError, noteOf(res));
      const note = noteOf(res);
      assert.match(note, /fixed_branches lists 4 entries, 3 affected packages, with 4 affected ranges, 4 with a fix on record;/);
      assert.ok(note.includes(`${ONE_PACKAGE}: here org.example:lib (Maven:https://repo.spring.io/release and Maven).`), note);
      assert.doesNotMatch(note, /openssl \(Debian/);
    });

    it("#2841: an installed version travels in the X-EG-* headers, never the URL; fixed_in and installed are relayed, and what was asked is echoed", async () => {
      seen.length = 0;
      seenHeaders.length = 0;
      const res = await call("cve_remediation", { cve_id: LOG4SHELL, ecosystem: "Maven", package: "org.apache.logging.log4j:log4j-core", version: " 2.14.1 " });
      assert.ok(!res.isError, noteOf(res));
      assert.deepEqual(seen, [REM(LOG4SHELL)], "the URL is the bare route");
      for (const v of ["Maven", "log4j-core", "2.14.1", "ecosystem", "version"]) assert.ok(!seen[0].includes(v), `${v} is in the URL ${seen[0]}`);
      // Percent-encoded, as the backend's matchHeaderValue decodes them; trimmed.
      assert.deepEqual(INSTALLED_HEADERS.map((h) => seenHeaders[0][h]), ["Maven", "org.apache.logging.log4j%3Alog4j-core", "2.14.1"]);
      const sc = res.structuredContent;
      assert.deepEqual(sc.data, WITH_INSTALLED["2.14.1"], "data is the API's JSON whole");
      assert.deepEqual(sc.coverage.installed_asked, { ecosystem: "Maven", package: "org.apache.logging.log4j:log4j-core", version: "2.14.1" });
      const note = noteOf(res);
      assert.match(note, /For the installed version asked \(Maven org\.apache\.logging\.log4j:log4j-core 2\.14\.1\), installed\.verdict is affected and fixed_in is 2\.15\.0: the fixed bound of the affected range \[2\.13\.0, 2\.15\.0\) that holds it, as the advisory states it; EchelonGraph has not tested it\./);
      assert.doesNotMatch(note, /upgrade to/i);

      const none = await call("cve_remediation", { cve_id: LOG4SHELL, ecosystem: "Maven", package: "org.apache.logging.log4j:log4j-core", version: "2.17.1" });
      assert.equal(none.structuredContent.data.fixed_in, null);
      assert.match(noteOf(none), new RegExp(`installed\\.verdict is not_affected and fixed_in is null: ${NOT_AFFECTED_REASON.replace(/[.()]/g, "\\$&")}\\.`));
    });

    // #3074: when fixed_in moved past an overlapping range, the note does not render the holding
    // range with fixed_in as its bound (that range is not on record): it relays fixed_in_detail.
    it("#3074: fixed_in past an overlapping range is said with fixed_in_detail, never as the holding range's own bound", async () => {
      const res = await call("cve_remediation", { cve_id: LOG4SHELL, ecosystem: "Maven", package: "org.apache.logging.log4j:log4j-core", version: "2.11.0" });
      assert.ok(!res.isError, noteOf(res));
      assert.deepEqual(res.structuredContent.data, WITH_INSTALLED["2.11.0"], "data is the API's JSON whole");
      const note = noteOf(res);
      assert.ok(
        note.includes(`installed.verdict is affected and fixed_in is 2.15.0: the first version above it that no affected range on record holds (${MOVED_PAST}), as the advisory states it; EchelonGraph has not tested it.`),
        note,
      );
      // Control: the sentence for an unmoved fixed_in would name [2.4, 2.15.0), a range no record holds.
      assert.doesNotMatch(note, /\[2\.4, 2\.15\.0\)/);
    });

    it("#2841: a partial installed version is refused with invalid_input naming what is missing, and nothing is sent", async () => {
      for (const [args, missing] of [
        [{ ecosystem: "npm" }, /package and version are missing \(given: ecosystem\)/],
        [{ ecosystem: "npm", package: "lodash" }, /version is missing \(given: ecosystem and package\)/],
        [{ version: "1.0.0" }, /ecosystem and package are missing \(given: version\)/],
        [{ ecosystem: "npm", package: "  ", version: "1.0.0" }, /package is missing \(given: ecosystem and version\)/],
      ]) {
        seen.length = 0;
        const res = await call("cve_remediation", { cve_id: LOG4SHELL, ...args });
        assert.equal(res.structuredContent.state, "invalid_input", JSON.stringify(args));
        assert.match(noteOf(res), /ecosystem, package and version go together, all three or none/);
        assert.match(noteOf(res), missing, JSON.stringify(args));
        assert.deepEqual(seen, [], `${JSON.stringify(args)}: a request was sent`);
      }
    });

    it("#2841: an API that ignores the headers (no fixed_in) is said to have not assessed the installed version", async () => {
      const res = await call("cve_remediation", { cve_id: "CVE-2099-30002", ecosystem: "npm", package: "x", version: "1.0.0" });
      assert.match(noteOf(res), /The answer carries no fixed_in for the installed version asked \(npm x 1\.0\.0\): the API did not assess it, which is not a finding either way\./);
    });

    it("#2841: a reference the CNA tagged lowercase patch is a fix reference, named in either spelling, beside the fix_status it supports", async () => {
      const res = await call("cve_remediation", { cve_id: "CVE-2026-69486" });
      assert.ok(!res.isError, noteOf(res));
      assert.deepEqual(res.structuredContent.data.fix_references, CNA_PATCH.fix_references);
      const note = noteOf(res);
      assert.match(note, /fix_status for CVE-2026-69486 is fix_referenced \(basis patch_evidence_reference_only\), the API's fix-status rule\./);
      assert.match(note, /fix_references lists 1 reference the CVE record tags as a patch or mitigation \(NVD's Patch or Mitigation, or the CNA's patch or mitigation\), each with the tags as written\./);
      assert.doesNotMatch(note, /No reference of the CVE record is tagged/);
    });

    it("#3076 third pass: a vendor's released-fix statement with no version is said for what it is, never a version", async () => {
      const g = await call("cve_remediation", { cve_id: "CVE-2025-20362" });
      assert.ok(!g.isError, noteOf(g));
      assert.deepEqual(g.structuredContent.data.fix_status, VENDOR_RELEASED.fix_status, "fix_status relayed whole, vendor_released kept");
      assert.match(noteOf(g), /fix_status for CVE-2025-20362 is available \(basis vendor_fix_released\), the API's fix-status rule; the vendor states a fix is released, but the CVE record names no fixed version \(vendor_released\), so the fixed release is the vendor advisory's to name\./);
      // Control: a fix_status without vendor_released carries no such qualifier.
      assert.doesNotMatch(noteOf(await call("cve_remediation", { cve_id: "CVE-2026-69486" })), /vendor_released/);
    });

    it("REJECTED: not_assessed, nothing relayed as a fix", async () => {
      const res = await call("cve_remediation", { cve_id: "CVE-2099-30001" });
      assert.ok(!res.isError);
      assert.equal(res.structuredContent.state, "not_assessed");
      assert.match(noteOf(res), /NOT ASSESSED: CVE-2099-30001's remediation is not assessed \(rejected:/);
    });

    it("nothing on record: every list empty, worded 'none on record', never 'no fix'", async () => {
      const res = await call("cve_remediation", { cve_id: "CVE-2099-30002" });
      const note = noteOf(res);
      assert.equal(res.structuredContent.state, "measured");
      assert.match(note, /fixed_branches is empty: no affected package range is on record, which is not a finding that no fix exists\./);
      assert.match(note, /No vendor advisory on record names CVE-2099-30002, which is not a finding that no vendor published a fix\./);
      assert.match(note, /No reference of the CVE record is tagged as a patch or mitigation, in NVD's spelling \(Patch, Mitigation\) or the CNA's \(patch, mitigation\)\./);
      // Every sentence that speaks of "no fix" says it is not a finding.
      for (const u of note.split(/(?<=\.)\s+/)) if (/no fix/i.test(u)) assert.match(u, /not a finding/, u);
      assert.doesNotMatch(note, /\b(unpatched|no fix is available)\b/i);
    });

    it("a failed section is named and left out of the note's findings, never relayed as empty", async () => {
      const res = await call("cve_remediation", { cve_id: "CVE-2099-30003" });
      assert.deepEqual(res.structuredContent.coverage.sections_failed, ["vendor_remediations"]);
      assert.ok(!res.structuredContent.coverage.sections_relayed.includes("vendor_remediations"));
      const note = noteOf(res);
      assert.match(note, /The API could not read vendor_remediations \(failed_sections\): an empty value there is not a finding of none\./);
      assert.doesNotMatch(note, /No vendor advisory on record/);
    });

    it("past the text budget: vendor texts cut first, kinds, states and URLs kept, TEXT CUT said; data whole with full: true, its vendor_remediations cut first by default", async () => {
      const res = await call("cve_remediation", { cve_id: "CVE-2099-30004" });
      const [first] = textBlocks(res);
      assert.ok(first.length <= 30_000, `${first.length} characters`);
      // #3013: with full: true data is the answer whole and the text the same; by default the
      // structured result is held to 30,000 characters, vendor_remediations leaving data from the
      // end first, every field that is not a list (fix_status, fixed_in) the answer's.
      const whole = await call("cve_remediation", { cve_id: "CVE-2099-30004", full: true });
      assert.deepEqual(whole.structuredContent.data, HUGE);
      assert.equal(whole.structuredContent.data_truncated, false);
      assert.equal(textBlocks(whole)[0], first);
      const sc = res.structuredContent;
      assert.ok(JSON.stringify(sc).length <= 30_000, `${JSON.stringify(sc).length} characters of structured result`);
      assert.equal(sc.data_truncated, true);
      const kept = sc.truncated.vendor_remediations.returned;
      assert.ok(kept < 20, JSON.stringify(sc.truncated));
      // #3013 follow-up: each advisory kept is thinned first (product_ids, then the texts, leave).
      assert.equal(sc.truncated.vendor_remediations.thinned, kept > 0 ? true : undefined);
      for (const [i, a] of sc.data.vendor_remediations.entries()) assert.ok(isThinOf(a, HUGE.vendor_remediations[i]), `vendor_remediations[${i}]`);
      for (const [k, v] of Object.entries(HUGE)) if (!Array.isArray(v)) assert.deepEqual(sc.data[k], v, k);
      assert.match(noteOf(res), new RegExp(`DATA CUT: .*vendor_remediations keeps ${kept === 0 ? "none of its 20 entries" : `${kept} of its 20 entries, each cut to `}`));
      // #3139: advisories leave only once patches and fixed_branches are cut, and the note then
      // names the tool that lists every one.
      for (const l of ["patches", "fixed_branches"]) if (HUGE[l].length) assert.ok(sc.truncated[l], `${l} was not cut before advisories left: ${JSON.stringify(sc.truncated)}`);
      assert.ok(noteOf(res).includes(`vendor_advisories_for_cve, given this CVE, lists every vendor advisory naming it, the ${20 - kept} left out of data among them, each with its vendor and vendor_advisory_id.`), noteOf(res));
      const shown = JSON.parse(first);
      assert.equal(shown.vendor_remediations.length, 20, "every advisory kept");
      for (const a of shown.vendor_remediations) {
        assert.ok(a.remediation_state && a.remediation_kinds, "state and kinds kept");
        for (const i of a.items) assert.ok(i.url?.startsWith("https://access.redhat.com/errata/"), "URL kept whole");
      }
      assert.match(noteOf(res), /TEXT CUT/);
    });

    // #3139: patches and fixed_branches are thinned and cut before any advisory leaves.
    // #3139's review: fixed_branches is thinned before any patch row leaves. #3139's second review:
    // fix_references is cut before any patch row leaves too. Round 2 kept 28 of the 30 patches here
    // (29,946 characters) and fix_references whole; now all 30 stay, thinned, and fix_references
    // keeps 17 of its 20 (29,931 characters, measured 2026-10-11 on this fixture).
    it("#3139: CVE-2023-44487 (hosted 3.0.0 kept 2 of 20 advisories): all 20 advisories, all 50 fixed_branches and all 30 patches kept thinned, fix_references cut first, within 30,000 characters", async (t) => {
      const res = await call("cve_remediation", { cve_id: "CVE-2023-44487" });
      const sc = res.structuredContent;
      const size = JSON.stringify(sc).length;
      assert.ok(size <= 30_000, `${size} characters of structured result`);
      assertDataCutOf(sc, RAPID_RESET, "CVE-2023-44487");
      assert.deepEqual(sc.truncated.vendor_remediations, { total: 20, returned: 20, thinned: true });
      assert.deepEqual(
        sc.data.vendor_remediations.map((a) => [a.vendor, a.vendor_advisory_id, a.remediation_state]),
        RAPID_RESET.vendor_remediations.map((a) => [a.vendor, a.vendor_advisory_id, a.remediation_state]),
      );
      assert.deepEqual(sc.truncated.fixed_branches, { total: 50, returned: 50, thinned: true }, JSON.stringify(sc.truncated));
      assert.deepEqual(sc.truncated.patches, { total: 30, returned: 30, thinned: true }, `a patch row left before fix_references was cut: ${JSON.stringify(sc.truncated)}`);
      assert.equal(sc.data.patches.length, 30);
      assert.equal(sc.truncated.fix_references?.total, 20, JSON.stringify(sc.truncated));
      assert.ok(sc.truncated.fix_references.returned < 20, JSON.stringify(sc.truncated));
      t.diagnostic(`${size} characters, ${JSON.stringify(sc.truncated)}`);
      // A thinned fixed_branches row keeps what the sbom_review prompt walks.
      for (const r of sc.data.fixed_branches) assert.deepEqual(Object.keys(r).filter((k) => !["ecosystem", "package_name", "version_range", "fixed_version", "fixed_branches"].includes(k)), []);
      assert.ok(sc.data.fixed_branches.some((r) => r.fixed_branches?.[0] && "introduced" in r.fixed_branches[0] && "fixed" in r.fixed_branches[0]));
      // Every advisory is in data, so the note does not send the model elsewhere for one.
      assert.doesNotMatch(noteOf(res), /vendor_advisories_for_cve/);
      assert.ok(validator.getValidator(tools.find((t) => t.name === "cve_remediation").outputSchema)(sc).valid);
    });

    // #3139's review: the same answer without fix_references. Round 1 (35073f92) cut patches first
    // and kept 11 of 30 beside all 50 fixed_branches rows whole (13,581 characters); fixed_branches
    // thinned first (8,876), every patch stays.
    it("#3139's review: fixed_branches is thinned before a patch row leaves: CVE-2023-44487 without fix_references keeps all 30 patches and all 50 fixed_branches", async () => {
      const res = await call("cve_remediation", { cve_id: "CVE-2099-44487" });
      const sc = res.structuredContent;
      assert.ok(JSON.stringify(sc).length <= 30_000);
      assertDataCutOf(sc, { ...RAPID_RESET, cve_id: "CVE-2099-44487", fix_references: [] }, "CVE-2023-44487 without fix_references");
      assert.deepEqual(sc.truncated.vendor_remediations, { total: 20, returned: 20, thinned: true });
      assert.deepEqual(sc.truncated.fixed_branches, { total: 50, returned: 50, thinned: true }, JSON.stringify(sc.truncated));
      assert.equal(sc.data.patches.length, 30, `patches left while fixed_branches could be thinned: ${JSON.stringify(sc.truncated)}`);
      // No package here has more than one range, so none is capped and the note says no cap.
      assert.ok(sc.data.fixed_branches.every((r) => r.fixed_branches_truncated === undefined));
      assert.doesNotMatch(noteOf(res), /keeping at most its first \d+ ranges/);
    });

    it("#3139's review: a package's ranges are capped, with a count, before a patch row leaves, and take back room once the patches are cut", async () => {
      const fb = RAPID_RESET.fixed_branches.map((r, i) =>
        i === 0 ? { ...r, fixed_branches: Array.from({ length: 120 }, (_, j) => ({ introduced: `${j}.0.0`, fixed: `${j}.0.9`, last_affected: null, source: "osv_bulk", advisory_id: `GHSA-xxxx-xxxx-${String(j).padStart(4, "0")}` })) } : r,
      );
      ANSWERS[REM("CVE-2099-44488")] = { ...RAPID_RESET, cve_id: "CVE-2099-44488", fix_references: [], fixed_branches: fb };
      const res = await call("cve_remediation", { cve_id: "CVE-2099-44488" });
      const sc = res.structuredContent;
      assert.ok(JSON.stringify(sc).length <= 30_000);
      assertDataCutOf(sc, { ...RAPID_RESET, cve_id: "CVE-2099-44488", fix_references: [], fixed_branches: fb }, "120 ranges");
      assert.deepEqual(sc.truncated.fixed_branches, { total: 50, returned: 50, thinned: true });
      const big = sc.data.fixed_branches[0];
      assert.equal(big.fixed_branches_truncated?.total, 120);
      assert.equal(big.fixed_branches.length, big.fixed_branches_truncated.returned);
      // Capped at 1 while the patches were whole; with them thinned, it takes back 25 (2026-10-11).
      assert.ok(big.fixed_branches.length > 1, `${big.fixed_branches.length} ranges kept`);
      assert.equal(sc.data.patches.length, 30, JSON.stringify(sc.truncated));
      assert.match(noteOf(res), /fixed_branches keeps all 50 entries, each cut to ecosystem, package_name, version_range, fixed_version and fixed_branches \(each with introduced, fixed and last_affected\).*; with the room left, 1 of the entries kept take back detail \(by position among those kept, in their order in data\): entry 1 cut to /);
      assert.deepEqual(big.fixed_branches, fb[0].fixed_branches.slice(0, big.fixed_branches.length).map(({ introduced, fixed, last_affected }) => ({ introduced, fixed, last_affected })));
      assert.ok(sc.data.vendor_remediations.length === 20);
    });

    // #3272: the first text block (what a client that passes only `content` reads) was still cut
    // the 3.0.0 way: advisories left it from the end while fixed_branches, patches and
    // fix_references stayed whole beside them. Replayed on 3.0.2 (2026-10-17): the recorded answer
    // kept 19 of its 20 advisories in the text, and with 1, 5, 10 and 16 more fixed_branches packages
    // (real rows copied and renamed) 18, 13, 8 and 2; from 18 more the text fell to the every-list cap
    // and kept 20 again. A substring count reads 20 there (RHEA-2024:0556 is also in a patch_url),
    // so this counts parsed rows. Larger answers then lose fix_references, patches and fixed_branches
    // rows, in that order, before any advisory, as the structured cut does.
    const TEXT_LADDER = [0, 1, 5, 10, 16, 18, 60, 100];
    const ladderAnswer = (more) => ({
      ...RAPID_RESET,
      cve_id: `CVE-2099-${46000 + more}`,
      fixed_branches: [
        ...RAPID_RESET.fixed_branches,
        ...Array.from({ length: more }, (_, i) => {
          const r = RAPID_RESET.fixed_branches[i % RAPID_RESET.fixed_branches.length];
          return { ...r, package_name: `${r.package_name}-copy${i}` };
        }),
      ],
    });
    const textCutOf = (note) => note.slice(note.indexOf("TEXT CUT: "), note.includes("DATA CUT: ") ? note.indexOf("DATA CUT: ") : undefined);
    it("#3272: the first text block keeps every advisory, as parsed rows, on CVE-2023-44487 and with 1, 5, 10, 16, 18, 60 and 100 more packages; beside lists lose rows first, fix_references, then patches, then fixed_branches", async (t) => {
      const seenCounts = [];
      for (const more of TEXT_LADDER) {
        const answer = ladderAnswer(more);
        ANSWERS[REM(answer.cve_id)] = answer;
        const res = await call("cve_remediation", { cve_id: answer.cve_id });
        const [first] = textBlocks(res);
        const note = noteOf(res);
        assert.ok(first.length <= 30_000, `+${more}: ${first.length} characters`);
        const shown = JSON.parse(first);
        const n = (k) => shown[k]?.length ?? 0;
        seenCounts.push(`+${more}: ${n("vendor_remediations")}/20 advisories, ${n("fixed_branches")}/${answer.fixed_branches.length} fixed_branches, ${n("patches")}/30 patches, ${n("fix_references")}/20 fix_references, ${first.length} characters`);
        // Every advisory, each the answer's, in order, with its state and kinds.
        assert.deepEqual(
          shown.vendor_remediations.map((a) => [a.vendor, a.vendor_advisory_id, a.remediation_state, a.remediation_kinds]),
          answer.vendor_remediations.map((a) => [a.vendor, a.vendor_advisory_id, a.remediation_state, a.remediation_kinds]),
          `+${more}: ${seenCounts.at(-1)}`,
        );
        // The order the structured cut leaves lists in: fix_references before any patch row,
        // patches before any fixed_branches row, and no advisory before them.
        if (n("patches") < 30) assert.equal(n("fix_references"), 0, `+${more}: a patch row left the text before fix_references: ${seenCounts.at(-1)}`);
        if (n("fixed_branches") < answer.fixed_branches.length) assert.equal(n("patches"), 0, `+${more}: a fixed_branches row left the text before the patches: ${seenCounts.at(-1)}`);
        // The rows kept are the answer's first, thinned, never another's.
        assert.deepEqual(shown.fixed_branches.map((r) => r.package_name), answer.fixed_branches.slice(0, n("fixed_branches")).map((r) => r.package_name));
        for (const r of shown.fixed_branches) assert.deepEqual(Object.keys(r).filter((k) => !["ecosystem", "package_name", "version_range", "fixed_version", "fixed_branches"].includes(k)), [], `+${more}: a fixed_branches row in the text keeps more than the structured cut's thinned fields`);
        const cut = textCutOf(note);
        assert.match(cut, /^TEXT CUT: /);
        // The patches kept are the answer's first, whole, or each cut to the structured cut's fields
        // once fixed_branches thinned does not make room (the note then says so).
        const patchesThinned = /Each entry of patches in it leaves out /.test(cut);
        assert.deepEqual(shown.patches, answer.patches.slice(0, n("patches")).map((p) => (patchesThinned ? { vendor: p.vendor, patch_url: p.patch_url, published_at: p.published_at } : p)), `+${more}`);
        assert.ok(!patchesThinned || /Each entry of fixed_branches in it leaves out /.test(cut), `+${more}: patches were cut before fixed_branches`);
        if (n("fix_references") < 20) {
          assert.match(cut, /In it, fix_references keeps (none of its 20 entries|its first \d+ of 20 entries)[^.]*, before any row of vendor_remediations is left out\./, `+${more}: ${cut}`);
        }
        assert.doesNotMatch(cut, /Only \d+ of the 20 rows of vendor_remediations are in it/, `+${more}`);
        assert.doesNotMatch(cut, /Every list in it keeps at most its first/, `+${more}: the text fell through to the every-list cap`);
      }
      t.diagnostic(seenCounts.join("; "));
      // The recorded answer and the issue's +16 keep every list whole beside the 20 advisories.
      for (const more of [0, 16]) {
        const res = results.findLast(([n, a]) => n === "cve_remediation" && a.cve_id === `CVE-2099-${46000 + more}`)[2];
        const shown = JSON.parse(textBlocks(res)[0]);
        assert.deepEqual([shown.vendor_remediations.length, shown.fixed_branches.length, shown.patches.length, shown.fix_references.length], [20, 50 + more, 30, 20], `+${more}`);
      }
    });

    // 3.1.0's phase A review (decided 2026-10-18: build the cap): through d42d4697 the text capped no
    // package's ranges and gave no room back to a list emptied before, so one package of N ranges
    // first among CVE-2023-44487's 51 cost the text its fix data from about 150 ranges on: 11 of 20
    // references at 150, no reference at 200, no patch at 250, 25 packages at 300, and from 400 no
    // package, patch or reference in 6,347 characters (3.0.2's every-list cap kept 32 packages, 30
    // patches and 20 references at every size). Now the text caps each package's ranges at the
    // most that fit, as data does, every package, patch and reference kept, the capped package
    // marked fixed_branches_truncated and named in the note. Control: the same TextCut without the
    // cap (d42d4697's) keeps none of the 51 at 600.
    const giantAnswer = (n) => {
      const base = RAPID_RESET.fixed_branches[0];
      const giant = { ...base, package_name: "giant", fixed_branches: Array.from({ length: n }, (_, i) => ({ ...(base.fixed_branches?.[0] ?? {}), introduced: `${i}.0.0`, fixed: `${i}.0.1` })) };
      return { ...RAPID_RESET, cve_id: `CVE-2099-${46000 + n}`, fixed_branches: [giant, ...RAPID_RESET.fixed_branches] };
    };
    it("3.1.0's phase A review: one 600-range package first among 51: the text keeps all 51 packages (the large one's ranges capped and marked), 30 patches and 20 references, and data keeps all 51 capped; d42d4697's cut kept none", async () => {
      const answer = giantAnswer(600);
      ANSWERS[REM(answer.cve_id)] = answer;
      const res = await call("cve_remediation", { cve_id: answer.cve_id });
      const [first] = textBlocks(res);
      assert.ok(first.length <= 30_000, `${first.length} characters`);
      const shown = JSON.parse(first);
      assert.deepEqual([shown.vendor_remediations.length, shown.fixed_branches.length, shown.patches.length, shown.fix_references.length], [20, 51, 30, 20], `${first.length} characters`);
      const [g, ...rest] = shown.fixed_branches;
      const c = g.fixed_branches.length;
      assert.ok(c >= 1 && c < 600, `${c} ranges kept of the large package`);
      assert.deepEqual(g.fixed_branches_truncated, { total: 600, returned: c });
      assert.deepEqual(g.fixed_branches.map((b) => b.introduced), answer.fixed_branches[0].fixed_branches.slice(0, c).map((b) => b.introduced), "the large package keeps its first ranges");
      // Every other package keeps every range, unmarked.
      for (const [i, r] of rest.entries()) {
        assert.equal((r.fixed_branches ?? []).length, (RAPID_RESET.fixed_branches[i].fixed_branches ?? []).length, r.package_name);
        assert.equal(r.fixed_branches_truncated, undefined, r.package_name);
      }
      const cut = textCutOf(noteOf(res));
      assert.ok(cut.includes(`In it, each package's fixed_branches keeps at most its first ${c} ranges: giant (${answer.fixed_branches[0].ecosystem}) has more, carrying fixed_branches_truncated with its total and returned, and structuredContent.data holds every range with full: true.`), cut);
      assert.doesNotMatch(cut, /keeps none of its/, cut);
      const data = res.structuredContent.data;
      assert.equal(data.fixed_branches.length, 51);
      assert.ok(data.fixed_branches[0].fixed_branches_truncated?.total === 600, JSON.stringify(data.fixed_branches[0]).slice(0, 300));
      // Control: d42d4697's TextCut, without the cap, on the same answer.
      const { dataText } = await import(new URL("../dist/textBudget.js", import.meta.url).href);
      const { CVE_REMEDIATION_TEXT_CUT: CUT } = await import(new URL("../dist/tools/cve_remediation.js", import.meta.url).href);
      assert.equal(dataText(answer, CUT).text, first, "the replay is not the server's cut");
      const old = JSON.parse(dataText(answer, { ...CUT, sides: CUT.sides.map(({ capped, ...side }) => side) }).text);
      assert.deepEqual([old.fixed_branches.length, old.patches.length, old.fix_references.length], [0, 0, 0], "the control does not show d42d4697's cut");
    });
    it("3.1.0's phase A review: from 50 to 600 ranges in one package, the text keeps every package, patch and reference, and caps the large package's ranges only past the room", async (t) => {
      const seen = [];
      for (const n of [50, 100, 150, 200, 250, 300, 400, 600]) {
        const answer = giantAnswer(n);
        ANSWERS[REM(answer.cve_id)] = answer;
        const res = await call("cve_remediation", { cve_id: answer.cve_id });
        const [first] = textBlocks(res);
        const shown = JSON.parse(first);
        const g = shown.fixed_branches[0];
        seen.push(`${n}: ${shown.fixed_branches.length} packages, ${g.fixed_branches.length} ranges of the large one, ${shown.patches.length} patches, ${shown.fix_references.length} references, ${first.length} characters`);
        assert.ok(first.length <= 30_000, seen.at(-1));
        assert.deepEqual([shown.vendor_remediations.length, shown.fixed_branches.length, shown.patches.length, shown.fix_references.length], [20, 51, 30, 20], seen.at(-1));
        if (g.fixed_branches.length < n) assert.deepEqual(g.fixed_branches_truncated, { total: n, returned: g.fixed_branches.length }, seen.at(-1));
        else assert.equal(g.fixed_branches_truncated, undefined, seen.at(-1));
      }
      t.diagnostic(seen.join("; "));
    });

    // 3.1.0's phase C review (info, done): neither the text's capped sentence nor data's said that
    // the note's fix walk ("the first fixed above it that no range of its package holds") is unsafe
    // on a capped package: over its kept ranges alone it can name a version a range left out still
    // holds. Shown here on a package whose range j runs from j.0.0 to a fix at (j+1).0.0, so every
    // fix is held by the next range: an installed 0.5.0 walks to c.0.0 over the first c ranges, and
    // to N.0.0 over all N. Both notes now say so, and where to read that package's fix.
    const chainAnswer = (n) => {
      const base = RAPID_RESET.fixed_branches[0];
      const chain = { ...base, package_name: "chain", fixed_branches: Array.from({ length: n }, (_, j) => ({ introduced: `${j}.0.0`, fixed: `${j + 1}.0.0`, last_affected: null, source: "osv_bulk", advisory_id: `GHSA-chain-${j}` })) };
      return { ...RAPID_RESET, cve_id: `CVE-2099-${47000 + n}`, fixed_branches: [chain, ...RAPID_RESET.fixed_branches] };
    };
    // The note's rule over the ranges given: the first fixed above v that no range holds.
    const major = (x) => Number(String(x).split(".")[0]);
    const walk = (ranges, v) => {
      const holds = (x) => ranges.some((b) => major(b.introduced) <= major(x) && (b.fixed === null || major(x) < major(b.fixed)));
      const fixes = ranges.map((b) => b.fixed).filter((f) => f && major(f) > major(v)).sort((a, b) => major(a) - major(b));
      return fixes.find((f) => !holds(f)) ?? null;
    };
    const CAPPED_FIX_TEXT = (full) => `A capped package's fix, walked over its kept ranges alone, can be wrong: read that package's fix ${full ? "with full: true" : "from structuredContent.data"}.`;
    const CAPPED_FIX_DATA = "its fix, walked over its kept ranges alone, can be wrong (read that package's fix with full: true)";
    it("3.1.0's phase C review: a capped package's fix walked over its kept ranges alone can be wrong, and the text's and data's notes say so and where to read it", async () => {
      const answer = chainAnswer(600);
      ANSWERS[REM(answer.cve_id)] = answer;
      const res = await call("cve_remediation", { cve_id: answer.cve_id });
      const shown = JSON.parse(textBlocks(res)[0]);
      const data = res.structuredContent.data;
      const [inText, inData] = [shown.fixed_branches[0], data.fixed_branches[0]];
      assert.ok(inText.fixed_branches_truncated && inData.fixed_branches_truncated, "precondition: the chain package is capped in both");
      // The walk's answer over what each keeps is not the answer over every range.
      assert.equal(walk(answer.fixed_branches[0].fixed_branches, "0.5.0"), "600.0.0");
      assert.equal(walk(inText.fixed_branches, "0.5.0"), `${inText.fixed_branches.length}.0.0`);
      assert.equal(walk(inData.fixed_branches, "0.5.0"), `${inData.fixed_branches.length}.0.0`);
      const note = noteOf(res);
      const cut = textCutOf(note);
      assert.ok(cut.includes(`chain (${answer.fixed_branches[0].ecosystem}) has more, carrying fixed_branches_truncated with its total and returned, and structuredContent.data holds every range with full: true. ${CAPPED_FIX_TEXT(true)}`), cut);
      const dataCut = note.slice(note.indexOf("DATA CUT: "));
      assert.ok(dataCut.includes(`a package with more carrying fixed_branches_truncated with its total and returned, and ${CAPPED_FIX_DATA}`), dataCut);
      assert.ok(res.structuredContent.notes.join(" ").includes(CAPPED_FIX_TEXT(true)) && res.structuredContent.notes.join(" ").includes(CAPPED_FIX_DATA));
      // data's step 2 caps to 1 range here, and says "range", not "1 ranges".
      if (inData.fixed_branches.length === 1) assert.match(dataCut, /keeping at most its first 1 range, a package/);
      // With full: true data holds every range, the text names data as where to read it, and the
      // walk over data's ranges is the whole answer's.
      const whole = await call("cve_remediation", { cve_id: answer.cve_id, full: true });
      assert.equal(walk(whole.structuredContent.data.fixed_branches[0].fixed_branches, "0.5.0"), "600.0.0");
      assert.ok(textCutOf(noteOf(whole)).includes(CAPPED_FIX_TEXT(false)), textCutOf(noteOf(whole)));
    });
    it("#3272: when advisories must leave the text, every list beside them is emptied first, and the TEXT CUT note names vendor_advisories_for_cve for the advisories left out", async () => {
      // Each advisory's 8 items with URLs of 1,800 characters: about 15,000 characters an advisory at
      // the leanest level, so the text holds one.
      const wide = RAPID_RESET.vendor_remediations.map((a, j) => ({
        ...a,
        items: Array.from({ length: 8 }, (_, i) => ({ kind: "vendor_fix", source_category: "vendor_fix", text: "t", url: `https://access.redhat.com/errata/${a.vendor_advisory_id}?${String(j * 8 + i).padStart(4, "0")}${"u".repeat(1800)}` })),
        items_total: 8,
      }));
      const answer = { ...RAPID_RESET, cve_id: "CVE-2099-46999", vendor_remediations: wide };
      ANSWERS[REM(answer.cve_id)] = answer;
      const res = await call("cve_remediation", { cve_id: answer.cve_id });
      const [first] = textBlocks(res);
      assert.ok(first.length <= 30_000, `${first.length} characters`);
      const shown = JSON.parse(first);
      const k = shown.vendor_remediations.length;
      assert.ok(k > 0 && k < 20, `${k} advisories in the text`);
      assert.deepEqual(shown.vendor_remediations.map((a) => a.vendor_advisory_id), wide.slice(0, k).map((a) => a.vendor_advisory_id));
      assert.deepEqual([shown.fix_references, shown.patches, shown.fixed_branches], [[], [], []], "an advisory left the text while a list beside it kept a row");
      const cut = textCutOf(noteOf(res));
      assert.ok(cut.includes("In it, fix_references keeps none of its 20 entries, patches keeps none of its 30 entries and fixed_branches keeps none of its 50 entries, before any row of vendor_remediations is left out."), cut);
      assert.ok(cut.includes(`Only ${k} of the 20 rows of vendor_remediations are in it;`), cut);
      assert.ok(cut.includes(`vendor_advisories_for_cve, given this CVE, lists every vendor advisory naming it, the ${20 - k} left out of the first text block among them, each with its vendor and vendor_advisory_id.`), cut);
    });

    it("HTTP 500 and 404 are failures; an answer without state is a failure; a malformed id is refused with no request", async () => {
      for (const [id, re] of [
        ["CVE-2099-30005", /HTTP 500/],
        ["CVE-2099-39999", /404/],
        ["CVE-2099-30006", /carries no state/],
      ]) {
        const res = await call("cve_remediation", { cve_id: id });
        assert.ok(res.isError, id);
        assert.equal(res.structuredContent.state, "failed", id);
        assert.match(noteOf(res), re, id);
      }
      seen.length = 0;
      const bad = await call("cve_remediation", { cve_id: "log4j" });
      assert.equal(bad.structuredContent.state, "invalid_input");
      assert.deepEqual(seen, []);
    });

    it("get_cve relays remediation and says what it is in one sentence", async () => {
      const res = await call("get_cve", { cve_id: LOG4SHELL });
      assert.deepEqual(res.structuredContent.data.remediation, SUMMARY);
      // #2841: fix_status is the summary's first field, relayed as the API sent it.
      assert.equal(Object.keys(res.structuredContent.data.remediation)[0], "fix_status");
      assert.equal(Object.keys(JSON.parse(textBlocks(res)[0]).remediation)[0], "fix_status", "the first text block keeps fix_status first");
      assert.match(
        noteOf(res),
        /remediation summarises how CVE-2021-44228 is fixed, as its sources state it; cve_remediation returns each vendor's text, CISA's action and every fixed range\. remediation\.fix_status is available \(basis patch_evidence_release\), the API's fix-status rule\. Vendor advisories list vendor_fix \(1\), workaround \(1\), by the vendor's own category\./,
      );
    });

    it("vendor_advisories_for_cve relays remediation_kinds and remediation_state; get_vendor_advisory relays remediations", async () => {
      const rows = await call("vendor_advisories_for_cve", { cve_id: LOG4SHELL });
      assert.ok(!rows.isError, noteOf(rows));
      assert.deepEqual(
        rows.structuredContent.data.advisories.map((a) => [a.vendor, a.remediation_kinds, a.remediation_state]),
        [
          ["redhat", ["vendor_fix", "workaround"], "parsed"],
          ["cisco", [], "not_parsed"],
        ],
      );
      assert.match(noteOf(rows), /By the vendors' own categories, the advisories list for CVE-2021-44228: vendor_fix \(1\), workaround \(1\)/);
      assert.match(noteOf(rows), /EchelonGraph does not read the remediation of 1 \(remediation_state not_parsed\), which is not a finding that it lists none\./);
      const one = await call("get_vendor_advisory", { vendor: "redhat", advisory_id: "RHSA-2021:5129" });
      assert.ok(!one.isError, noteOf(one));
      assert.deepEqual(one.structuredContent.data.remediations, DETAIL.remediations);
    });

    it("every result validates against its tool's outputSchema (ajv)", () => {
      const tried = new Set();
      for (const [name, args, res] of results) {
        tried.add(`${name}:${res.structuredContent.state}`);
        const v = validator.getValidator(schemaOf(name))(res.structuredContent);
        assert.ok(v.valid, `${name} ${JSON.stringify(args)}: ${v.errorMessage}`);
      }
      for (const k of ["cve_remediation:measured", "cve_remediation:not_assessed", "cve_remediation:failed", "cve_remediation:invalid_input", "get_cve:measured", "vendor_advisories_for_cve:measured", "get_vendor_advisory:measured"]) {
        assert.ok(tried.has(k), `no ${k} result validated`);
      }
    });

    it("control: the validator rejects a cve_remediation result whose envelope carries a field the schema does not name", () => {
      const [, , res] = results.find(([n, , r]) => n === "cve_remediation" && r.structuredContent.state === "measured");
      assert.equal(validator.getValidator(schemaOf("cve_remediation"))({ ...res.structuredContent, generated_fix: "deny all;" }).valid, false);
    });
  });
}
