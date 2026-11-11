// #3642: no vendor tool relays Microsoft's advisory text.
//
// EchelonGraph's API (#2885, #3642) withholds Microsoft's text (core-backend internal/cve/vendor_text.go): a Microsoft row carries
// vendor_text_withheld true, a title of EchelonGraph's, and no description, summary, remediation,
// remediation text or withdrawal reason; its severity, CVSS score and vector, CVE IDs, affected
// products, dates and links stay. These tools relay the API's answer as sent (the relay contract
// text-bound.test.mjs holds: with full true, data is the API's answer whole), so the rule is the
// API's, and it reaches every version of this server already installed without a release.
//
// What this file pins, against a stub in the API's #3642 shape, in both protocol eras:
//   - vendor_advisories_for_cve, get_vendor_advisory, search_vendor_advisories and cve_remediation
//     relay none of Microsoft's text, in the text blocks or the structured result, cut or full;
//   - they relay the facts, vendor_text_withheld and cvss_v3_vector;
//   - the outputSchema declares vendor_text_withheld and cvss_v3_vector, with what they mean (the
//     rows are open objects, so an undeclared field would still pass; a client reading the schema
//     would not know what it says), and the strict validator (strict-output.mjs) accepts each answer.
// CONTROL: the same calls against a stub in the API's pre-#3642 shape relay Microsoft's text, and
// the same detector finds it there, so a detector that cannot see relayed text fails here.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { StrictOutputValidator } from "./strict-output.mjs";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { serverCommand } from "./server-under-test.mjs";

const CVE = "CVE-2099-3642"; // answered the #3642 way
const OLD = "CVE-2099-3643"; // answered the pre-#3642 way (the control)
const VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C";
const guide = (cve) => `https://msrc.microsoft.com/update-guide/vulnerability/${cve}`;
const MS_TITLE = "Windows Frobnicator Remote Code Execution Vulnerability";
const MS_DESC = "Use after free in Windows Frobnicator allows an unauthorized attacker to execute code over a network.";
const MS_WORKAROUND = "Disable the Frobnicator listener on port 4242.";
// The CVE record's own description (CVE.org), which the #3642 detail serves in cve_records, attributed.
const CVE_RECORD_TEXT = "The CVE record's own description of the flaw.";
// Every phrase of Microsoft's text the pre-#3642 answers carry.
const MSRC_PROSE = ["Frobnicator", "port 4242", "Remote Code Execution Vulnerability", "unauthorized attacker"];

function noProse(what, served) {
  for (const p of MSRC_PROSE) assert.ok(!served.includes(p), `${what} relays Microsoft's text "${p}"`);
}
function holds(what, served, ...facts) {
  for (const f of facts) assert.ok(served.includes(f), `${what} lacks ${f}`);
}

// One Microsoft advisory, as the API answers it since #3642 (withheld) or before it (old).
function msRow(cve, withheld) {
  return {
    advisory_id: `0b1c3642-0000-4000-8000-00000000${cve.slice(-4)}`,
    vendor: "microsoft",
    vendor_display_name: "Microsoft Security Response Center (MSRC)",
    vendor_advisory_id: cve,
    cve_ids: [cve],
    title: withheld ? `Microsoft security update for ${cve}` : MS_TITLE,
    severity: "Critical",
    cvss_v3_score: 9.8,
    ...(withheld ? { summary: undefined, vendor_text_withheld: true } : { summary: MS_DESC }),
    affected_products: ["Windows Server 2025"],
    vendor_published_at: "2099-03-10T07:00:00Z",
    our_first_seen_at: "2099-03-10T07:30:00Z",
    withdrawn: false,
    rejected_cve_ids: [],
  };
}
const rhRow = (cve) => ({
  advisory_id: `0b1c3642-0000-4000-8000-1000000${cve.slice(-4)}`,
  vendor: "redhat",
  vendor_display_name: "Red Hat",
  vendor_advisory_id: "RHSA-2099:3642",
  cve_ids: [cve],
  title: "Important: kernel security update",
  severity: "High",
  summary: "Red Hat's own words about the kernel flaw.",
  vendor_published_at: "2099-03-11T00:00:00Z",
  our_first_seen_at: "2099-03-11T00:10:00Z",
  withdrawn: false,
  rejected_cve_ids: [],
  vendor_text_withheld: false,
});
const byCVERow = (row, vector) => {
  const { summary: _s, affected_products: _p, ...r } = row;
  return { ...r, cvss_v3_vector: vector, remediation_kinds: ["vendor_fix", "workaround"], remediation_state: "parsed" };
};
const item = (kind, category, text, url, fixed) => ({
  kind, source_category: category, source_subcategory: null, text, text_truncated: false, text_chars: text.length, url, fixed_build: fixed, product_ids: [], product_count: 0,
});
const msItems = (withheld) => [
  item("vendor_fix", "Vendor Fix", withheld ? "" : "5099999", "https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5099999", "10.0.26100.9999"),
  item("workaround", "Workaround", withheld ? "" : MS_WORKAROUND, null, null),
];
function detail(cve, withheld) {
  const { summary: _s, ...row } = msRow(cve, withheld);
  return {
    ...row,
    known_cve_ids: [cve],
    description: withheld ? "" : MS_DESC,
    cvss_v3_vector: VECTOR,
    affected_products: ["Windows Server 2025", "Windows 11 Version 24H2 for x64-based Systems"],
    remediation: withheld ? "" : "KB5099999 (Security Update) — fixed build 10.0.26100.9999",
    remediations: msItems(withheld).map((i) => ({ ...i, cve_ids: [cve] })),
    remediation_kinds: ["vendor_fix", "workaround"],
    remediation_state: "parsed",
    remediation_items_not_stored: 0,
    references: [{ url: guide(cve), type: "advisory" }, { url: "https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5099999", type: "patch" }],
    vendor_modified_at: "",
    withdrawn_at: "",
    withdrawn_reason: "",
    // Where Microsoft's text stood: EchelonGraph's own facts of the CVE.
    ...(withheld
      ? {
          remediations: msItems(true).map((i) => ({ ...i, cve_ids: [cve], ...(i.kind === "vendor_fix" ? { kb_article: "KB5099999" } : {}) })),
          cve_records: [
            {
              cve_id: cve, known: true, vuln_status: "PUBLISHED", description: CVE_RECORD_TEXT, cve_record_url: `https://www.cve.org/CVERecord?id=${cve}`, cna: "Microsoft Corporation",
              echelongraph_score: 9.1, echelongraph_severity: "CRITICAL", score_assessed: true, score_unassessed_reason: null, score_confidence: "high",
              kev_listed: true, kev_added_date: "2099-03-12T00:00:00Z", fix_status: { state: "available", basis: "patch_evidence_release", unread_inputs: [] },
            },
          ],
          cve_records_total: 1,
          cve_records_cap: 5,
          content_changed_at: "2099-03-20T09:30:00Z",
        }
      : {}),
  };
}
function remediation(cve, withheld) {
  return {
    cve_id: cve,
    state: "assessed",
    not_assessed_reason: null,
    fix_status: { state: "available", basis: "patch_evidence_release", unread_inputs: [] },
    cisa: { kev_listed: false, required_action: null, due_date: null, short_description: null, notes_urls: [] },
    fixed_branches: [],
    vendor_remediations: [
      {
        vendor: "microsoft",
        vendor_display_name: "Microsoft Security Response Center (MSRC)",
        vendor_advisory_id: cve,
        vendor_published_at: "2099-03-10T07:00:00Z",
        withdrawn: false,
        remediation_state: "parsed",
        remediation_kinds: ["vendor_fix", "workaround"],
        items: msItems(withheld),
        items_total: 2,
        ...(withheld ? { vendor_text_withheld: true } : {}),
      },
    ],
    fix_references: [],
    patches: [],
    coverage: { parsed_vendors: ["redhat", "microsoft", "paloalto"], vendors_not_parsed: [], vendor_advisories_listed: 1, vendor_advisory_limit: 20, item_text_cap: 2000, items_per_advisory_cap: 16 },
    failed_sections: [],
  };
}

async function startStub() {
  const server = http.createServer((req, res) => {
    const { pathname, searchParams } = new URL(req.url, "http://stub");
    const send = (status, body) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };
    if (pathname === "/api/v1/public/vendor-advisories/coverage") return send(200, { vendors: [] });
    for (const [cve, withheld] of [[CVE, true], [OLD, false]]) {
      if (pathname === `/api/v1/public/vendor-advisories/by-cve/${cve}`) {
        return send(200, { cve_id: cve, cve_rejected: false, advisories: [byCVERow(msRow(cve, withheld), VECTOR), byCVERow(rhRow(cve), null)], total: 2 });
      }
      if (pathname === `/api/v1/public/vendor-advisories/microsoft/${cve}`) return send(200, detail(cve, withheld));
      if (pathname === `/api/v1/public/cves/${cve}/remediation`) return send(200, remediation(cve, withheld));
    }
    if (pathname === "/api/v1/public/vendor-advisories") {
      // The vendor filter picks the answer's shape: microsoft the #3642 one, the rest the old one.
      const withheld = searchParams.get("vendor") === "microsoft";
      const cve = withheld ? CVE : OLD;
      const searched = req.headers["x-eg-advisory-search"] !== undefined;
      return send(200, {
        advisories: [msRow(cve, withheld), rhRow(cve)],
        total: 2,
        limit: Number(searchParams.get("limit")),
        offset: Number(searchParams.get("offset")),
        search_applied: searched,
        total_capped: false,
        search_match: searched ? "substring" : null,
      });
    }
    send(404, { error: "advisory not found" });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { base: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((resolve) => server.close(resolve)) };
}

const validator = new StrictOutputValidator();

for (const era of [MODERN, "2025-06-18"]) {
  describe(`#3642 Microsoft's advisory text is not relayed [${era}]`, () => {
    let stub, client, schemas, descriptions;
    before(async () => {
      stub = await startStub();
      client = await connect({ era, ...serverCommand(), env: { ...process.env, ECHELONGRAPH_API_BASE: stub.base, ECHELONGRAPH_API_TIMEOUT_MS: "2000" }, stderr: "inherit" });
      const { tools } = await client.listTools();
      schemas = Object.fromEntries(tools.map((t) => [t.name, t.outputSchema]));
      descriptions = Object.fromEntries(tools.map((t) => [t.name, t.description]));
    });
    after(async () => {
      try {
        await client?.close();
      } finally {
        await stub?.close();
      }
    });

    // The calls, each for the #3642 answer and its pre-#3642 control.
    const calls = (cve, vendor) => [
      ["vendor_advisories_for_cve", { cve_id: cve }],
      ["vendor_advisories_for_cve", { cve_id: cve, full: true }],
      ["get_vendor_advisory", { vendor: "microsoft", advisory_id: cve }],
      ["get_vendor_advisory", { vendor: "microsoft", advisory_id: cve, full: true }],
      ["search_vendor_advisories", { vendor, query: "frobnicator" }],
      ["search_vendor_advisories", { vendor, full: true }],
      ["cve_remediation", { cve_id: cve }],
      ["cve_remediation", { cve_id: cve, full: true }],
    ];

    it("the outputSchema declares vendor_text_withheld and cvss_v3_vector", () => {
      for (const name of ["vendor_advisories_for_cve", "get_vendor_advisory", "search_vendor_advisories", "cve_remediation"]) {
        holds(`${name}'s outputSchema`, JSON.stringify(schemas[name]), '"vendor_text_withheld"');
      }
      for (const name of ["vendor_advisories_for_cve", "get_vendor_advisory"]) holds(`${name}'s outputSchema`, JSON.stringify(schemas[name]), '"cvss_v3_vector"');
      holds("get_vendor_advisory's outputSchema", JSON.stringify(schemas.get_vendor_advisory), '"cve_records"', '"content_changed_at"', '"kb_article"', '"cna"');
      // #3643: each source's licence, with the licence and the source linked, on the field naming the source.
      for (const name of ["vendor_advisories_for_cve", "get_vendor_advisory", "search_vendor_advisories", "cve_remediation"]) {
        holds(`${name}'s outputSchema`, JSON.stringify(schemas[name]), "licensed CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/; source https://access.redhat.com/security/data)",
          "the GitHub Advisory Database, licensed CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/; source https://github.com/github/advisory-database)");
      }
      holds("get_vendor_advisory's outputSchema", JSON.stringify(schemas.get_vendor_advisory), "https://www.cve.org/Legal/TermsOfUse");
      // #3642 review: for a CVE the vendor assigned, the vendor wrote the CVE record: no schema text may say otherwise.
      assert.doesNotMatch(JSON.stringify(schemas.get_vendor_advisory), /not the vendor'?s text/i, "get_vendor_advisory's schema says the CVE record's text is not the vendor's");
    });

    // #3642: with the server-side switch for such descriptions on (off by default), a cve_records
    // description that repeats the advisory's title is null, with description_withheld_reason; the
    // schema declares it, and
    // accepts the answer in that state. And the link to Microsoft's advisory is promised only
    // where the advisory names a CVE ID (an ADV advisory has none, #3642 review).
    it("the outputSchema declares description_withheld_reason and accepts the switch's on-state; the link is promised only where a CVE ID is named", async () => {
      const schema = JSON.stringify(schemas.get_vendor_advisory);
      holds("get_vendor_advisory's outputSchema", schema, '"description_withheld_reason"', "matches_vendor_title", "with a link to Microsoft's advisory where it names a CVE ID",
        "where the advisory names a CVE ID, references lead with the vendor's own advisory page", "its name in the CVE Program's CNA list, else its short name");
      assert.doesNotMatch(schema, /a link to Microsoft's advisory are served/, "the schema still promises a link to Microsoft's advisory on every advisory");
      const res = await client.callTool({ name: "get_vendor_advisory", arguments: { vendor: "microsoft", advisory_id: CVE } });
      const on = structuredClone(res.structuredContent);
      on.data.cve_records[0].description = null;
      on.data.cve_records[0].description_withheld_reason = "matches_vendor_title";
      const v = validator.getValidator(schemas.get_vendor_advisory)(on);
      assert.ok(v.valid, `the strict schema refuses an answer with the switch on: ${JSON.stringify(v.errors ?? v)}`);
    });

    // #3642 round-3 review: what an agent reads before calling get_vendor_advisory for a Microsoft advisory,
    // within the client cut; and a CVE EchelonGraph holds no record of is named as such, with no cause guessed.
    it("get_vendor_advisory's description says what a withheld vendor's detail carries, within the client cut; known false names no cause", () => {
      const d = descriptions.get_vendor_advisory;
      holds("get_vendor_advisory's description", d, "vendor_text_withheld true (Microsoft): title is EchelonGraph's; description, remediation and item texts are empty; cve_records: its first CVEs, each with its CVE-record description or null.");
      // #3642 re-review N3/N4: a cve_records description is null where the record has none, was
      // rejected, is GitHub's stub, is not held, or the switch withholds it, and only the first
      // cve_records_cap CVEs are read, so no text may say it holds each CVE's description.
      for (const [what, text] of [["get_vendor_advisory's description", d], ["get_vendor_advisory's outputSchema", JSON.stringify(schemas.get_vendor_advisory)], ["vendor_advisories_for_cve's outputSchema", JSON.stringify(schemas.vendor_advisories_for_cve)]]) {
        assert.doesNotMatch(text, /cve_records holds each CVE-record description|gives each CVE's own CVE-record description/, `${what} still says cve_records holds every CVE's description`);
      }
      holds("get_vendor_advisory's outputSchema", JSON.stringify(schemas.get_vendor_advisory), "a detail's cve_records lists the first cve_records_cap CVEs it names, each with the CVE record's description or null",
        "null where the record has none, was rejected or is still the stub a GitHub advisory seeded, where EchelonGraph holds no record (known false), or where description_withheld_reason says it is withheld");
      assert.ok(d.length <= 2048 - 100, `get_vendor_advisory's description is ${d.length} characters, inside #2924's 100-character headroom under the 2048-character client cut`);
      const schema = JSON.stringify(schemas.get_vendor_advisory);
      holds("get_vendor_advisory's outputSchema", schema, "false: EchelonGraph holds no CVE record for it; only cve_id and cve_record_url are set.");
      assert.doesNotMatch(schema, /false: none yet/, "known false still guesses that the record is not yet published");
    });

    it("on the API's #3642 answers: none of Microsoft's text, cut or full; the facts and vendor_text_withheld; the strict schema accepts each", async () => {
      for (const [name, args] of calls(CVE, "microsoft")) {
        const res = await client.callTool({ name, arguments: args });
        const label = `${name} ${JSON.stringify(args)}`;
        assert.notEqual(res.isError, true, `${label}: ${JSON.stringify(res.content)}`);
        const served = JSON.stringify(res);
        noProse(label, served);
        // cve_remediation's rows carry no title or severity (core-backend VendorAdvisoryRemediation).
        if (name !== "cve_remediation") holds(label, served, `Microsoft security update for ${CVE}`, "Critical");
        assert.match(served, /\\?"vendor_text_withheld\\?":\s?true/, `${label} does not relay vendor_text_withheld true`);
        if (name !== "cve_remediation" && name !== "search_vendor_advisories") holds(label, served, VECTOR);
        if (name === "get_vendor_advisory" || name === "cve_remediation") holds(label, served, "10.0.26100.9999");
        if (name === "get_vendor_advisory") {
          holds(label, served, guide(CVE), "Windows 11 Version 24H2 for x64-based Systems", "KB5099999", `https://www.cve.org/CVERecord?id=${CVE}`, "2099-03-20T09:30:00Z");
          const recs = res.structuredContent?.data?.cve_records;
          assert.ok(Array.isArray(recs) && recs[0]?.description === CVE_RECORD_TEXT && recs[0]?.echelongraph_score === 9.1 && recs[0]?.cna === "Microsoft Corporation", `${label} does not relay cve_records as the API sends them: ${JSON.stringify(recs)}`);
        }
        const v = validator.getValidator(schemas[name])(res.structuredContent);
        assert.ok(v.valid, `${label}: the strict schema refuses the #3642 answer: ${JSON.stringify(v.errors ?? v)}`);
      }
    });

    it("control: on the API's pre-#3642 answers the tools relay Microsoft's text as sent, and the detector finds it", async () => {
      for (const [name, args] of calls(OLD, "redhat")) {
        const res = await client.callTool({ name, arguments: args });
        const label = `${name} ${JSON.stringify(args)}`;
        assert.notEqual(res.isError, true, `${label}: ${JSON.stringify(res.content)}`);
        assert.throws(() => noProse(label, JSON.stringify(res)), /relays Microsoft's text/, `${label}: the pre-#3642 answer's text did not reach the result, so the check above proves nothing`);
      }
    });
  });
}
