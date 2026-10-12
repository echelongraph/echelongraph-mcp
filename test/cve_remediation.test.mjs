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
