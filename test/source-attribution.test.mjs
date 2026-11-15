// #3694 (review fix 9): a national authority's row keeps its credit, however the answer is cut.
//
// EchelonGraph's API serves every NCSC-NL row (the Dutch National Cyber Security Centre's CSAF
// advisories, read under its written permission of 2026-11-12) with source_attribution: the credit
// ("Source: NCSC-NL"), the authority's own page, the language the text is in, translated (always
// false) and excerpt. Our letter to NCSC-NL promised that credit "in our API and MCP responses".
// Through 3.2.3 none of the cut levels kept it (cutRow drops every key a level does not name), so
// a large by-cve, search or remediation answer relayed NCSC-NL's Dutch titles with no credit and no
// "not translated", and at the leanest level only the slug ncsc-nl was left.
//
// What this file pins, against a stub in the API's #3694 shape, in both protocol eras:
//   - vendor_advisories_for_cve, search_vendor_advisories and cve_remediation keep each NCSC-NL
//     row's source_attribution whole (its credit, link, language, translated and excerpt) at EVERY
//     text cut level and every structured thinning level (the fixtures are sized so that between
//     them every level is reached, and the test reads which level each answer was cut to), and the
//     vendor rows beside them carry none;
//   - the outputSchema declares source_attribution and ratings, and says ncsc-nl is not a vendor;
//     no description calls every row vendor-published;
//   - cve_remediation's summary says an NCSC-NL row is a national authority's, with its credit;
//   - the strict validator (strict-output.mjs) accepts each answer.
// CONTROL: the fixtures are past the budgets (each answer says TEXT CUT, and the levels drop what
// they drop), so a fixture that no longer reaches a cut fails here instead of passing vacuously.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { StrictOutputValidator } from "./strict-output.mjs";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { serverCommand } from "./server-under-test.mjs";

// Three shapes of answer, each past the budgets in its own way, so that between them every level of
// each cut is reached (the test reads which level each answer was cut to, and requires all of them):
const L1 = "CVE-2099-36941"; // long cve_ids (rows) / long item texts (remediation)
const L2 = "CVE-2099-36942"; // long summaries and product lists / sixteen long items
const L3 = "CVE-2099-36943"; // long product lists alone / long product_ids alone
const CREDIT = "Source: NCSC-NL";
const ATTR = (id) => ({
  text: CREDIT, url: `https://advisories.ncsc.nl/2099/${id.toLowerCase()}.html`, language: "nl", language_name: "Dutch", translated: false, excerpt: true,
});
const cveList = (n) => Array.from({ length: n }, (_, i) => `CVE-2099-${String(100000 + i)}`);
const products = (n) => Array.from({ length: n }, (_, i) => `Product ${i} ${"x".repeat(290)}`);

// One row of the list and by-cve answers; even i an NCSC-NL row, odd i a Red Hat one.
function row(cve, i, big) {
  const ncsc = i % 2 === 0;
  const id = ncsc ? `NCSC-2099-${String(1000 + i)}` : `RHSA-2099:${String(1000 + i)}`;
  return {
    advisory_id: `0b1c3694-0000-4000-8000-${String(i).padStart(12, "0")}`,
    vendor: ncsc ? "ncsc-nl" : "redhat",
    vendor_display_name: ncsc ? "NCSC-NL" : "Red Hat",
    vendor_advisory_id: id,
    cve_ids: big === "l1" ? [cve, ...cveList(100)] : [cve],
    title: ncsc ? `Kwetsbaarheden verholpen in Product ${i}` : `Important: product ${i} security update`,
    severity: "High",
    cvss_v3_score: 7.5,
    ...(big === "l2" ? { summary: "s".repeat(2500), affected_products: products(40) } : {}),
    ...(big === "l3" ? { affected_products: products(40) } : {}),
    vendor_published_at: `2099-03-${String(28 - (i % 27)).padStart(2, "0")}T00:00:00Z`,
    our_first_seen_at: "2099-03-28T00:10:00Z",
    withdrawn: false,
    rejected_cve_ids: [],
    remediation_kinds: ["vendor_fix"],
    remediation_state: "parsed",
    ...(ncsc ? { source_attribution: ATTR(id), ratings: [{ name: "Kans", value: "medium" }, { name: "Schade", value: "high" }] } : {}),
  };
}
const rows = (cve, n, big) => Array.from({ length: n }, (_, i) => row(cve, i, big));

// cve_remediation's vendor_remediations: l1 two long items each, l2 sixteen, l3 short items with
// long product_ids.
function remediation(cve, big) {
  const items = (n, len, ids = 0) => Array.from({ length: n }, (_, k) => ({
    kind: "vendor_fix", source_category: "vendor_fix", source_subcategory: null, text: "t".repeat(len), text_truncated: false, text_chars: len,
    url: `https://example.org/fix/${k}`, fixed_build: null, product_ids: Array.from({ length: ids }, (_, j) => `CSAFPID-${j}-${"p".repeat(300)}`), product_count: ids,
  }));
  return {
    cve_id: cve,
    state: "assessed",
    not_assessed_reason: null,
    fix_status: { state: "available", basis: "vendor_advisory_fix", unread_inputs: [] },
    cisa: { kev_listed: false, required_action: null, due_date: null, short_description: null, notes_urls: [] },
    fixed_branches: [],
    vendor_remediations: rows(cve, 20, null).map((r) => ({
      vendor: r.vendor, vendor_display_name: r.vendor_display_name, vendor_advisory_id: r.vendor_advisory_id, vendor_published_at: r.vendor_published_at,
      withdrawn: false, remediation_state: "parsed", remediation_kinds: ["vendor_fix"],
      items: big === "l1" ? items(2, 1500) : big === "l3" ? items(2, 40, 16) : items(16, 2000), items_total: big === "l2" ? 16 : 2,
      ...(r.source_attribution ? { source_attribution: r.source_attribution } : {}),
    })),
    fix_references: [],
    patches: [],
    coverage: { parsed_vendors: ["redhat", "ncsc-nl"], vendors_not_parsed: [], vendor_advisories_listed: 20, vendor_advisory_limit: 20, item_text_cap: 2000, items_per_advisory_cap: 16 },
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
    for (const [cve, big] of [[L1, "l1"], [L2, "l2"], [L3, "l3"]]) {
      if (pathname === `/api/v1/public/vendor-advisories/by-cve/${cve}`) return send(200, { cve_id: cve, cve_rejected: false, advisories: rows(cve, 20, big), total: 20 });
      if (pathname === `/api/v1/public/cves/${cve}/remediation`) return send(200, remediation(cve, big));
    }
    if (pathname === "/api/v1/public/vendor-advisories") {
      const big = { Critical: "l1", High: "l2", Medium: "l3" }[searchParams.get("severity")];
      return send(200, {
        advisories: rows({ l1: L1, l2: L2, l3: L3 }[big], Math.min(50, Number(searchParams.get("limit")) || 50), big), total: 50, limit: Number(searchParams.get("limit")), offset: Number(searchParams.get("offset")),
        search_applied: false, total_capped: false, search_match: null,
      });
    }
    send(404, { error: "advisory not found" });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { base: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((resolve) => server.close(resolve)) };
}

// The rows of the first text block (its JSON, cut), and of structuredContent.data.
function textRows(res, list) {
  const t = res.content?.[0]?.text ?? "";
  const data = JSON.parse(t);
  return data[list] ?? [];
}
const dataRows = (res, list) => res.structuredContent?.data?.[list] ?? [];
const servedText = (res) => (res.content ?? []).map((c) => c.text ?? "").join("\n");

// Every NCSC-NL row keeps its credit whole, and no vendor row carries one.
function credited(label, rs) {
  const ncsc = rs.filter((r) => r.vendor === "ncsc-nl");
  assert.ok(ncsc.length > 0, `${label}: no NCSC-NL row is kept, so the check proves nothing`);
  for (const r of ncsc) {
    const a = r.source_attribution;
    assert.ok(a && a.text === CREDIT && a.translated === false, `${label}: ${r.vendor_advisory_id} lost its credit: ${JSON.stringify(a)}`);
    assert.ok(/^https:\/\/advisories\.ncsc\.nl\//.test(a.url) && a.language === "nl" && a.excerpt === true, `${label}: ${r.vendor_advisory_id}'s credit lost its link or language: ${JSON.stringify(a)}`);
  }
  for (const r of rs.filter((x) => x.vendor !== "ncsc-nl")) assert.equal(r.source_attribution, undefined, `${label}: a ${r.vendor} row carries a credit`);
}

const validator = new StrictOutputValidator();

for (const era of [MODERN, "2025-06-18"]) {
  describe(`#3694 an NCSC-NL row keeps its credit, cut or whole [${era}]`, () => {
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

    const call = async (name, args) => {
      const res = await client.callTool({ name, arguments: args });
      const label = `${name} ${JSON.stringify(args)}`;
      assert.notEqual(res.isError, true, `${label}: ${JSON.stringify(res.content).slice(0, 600)}`);
      const v = validator.getValidator(schemas[name])(res.structuredContent);
      assert.ok(v.valid, `${label}: the strict schema refuses the answer: ${JSON.stringify(v.errors ?? v).slice(0, 600)}`);
      return { res, label };
    };

    it("the outputSchemas declare source_attribution and ratings, and say ncsc-nl is not a vendor; the descriptions name NCSC-NL's rows", () => {
      for (const name of ["vendor_advisories_for_cve", "get_vendor_advisory", "search_vendor_advisories", "cve_remediation"]) {
        const s = JSON.stringify(schemas[name]);
        assert.ok(s.includes('"source_attribution"') && s.includes("A quote or reuse of the row keeps the credit and the link."), `${name}'s outputSchema does not declare source_attribution`);
        assert.ok(s.includes("ncsc-nl is not a vendor: it is the Dutch National Cyber Security Centre (NCSC-NL), a national authority"), `${name}'s outputSchema calls ncsc-nl a vendor`);
      }
      for (const name of ["vendor_advisories_for_cve", "get_vendor_advisory", "search_vendor_advisories"]) assert.ok(JSON.stringify(schemas[name]).includes('"ratings"'), `${name}: ratings undeclared`);
      // The descriptions call no row a vendor's by default (they are within #2924's headroom, so
      // the credit itself is described in the outputSchema, above).
      for (const name of ["vendor_advisories_for_cve", "get_vendor_advisory", "search_vendor_advisories"]) {
        assert.doesNotMatch(descriptions[name], /vendor-published advisories|^One vendor advisory/, `${name}'s description calls every advisory a vendor's`);
      }
      assert.doesNotMatch(descriptions.cve_remediation, /each vendor advisory naming the CVE/, "cve_remediation's description calls every advisory a vendor's");
    });

    // Which level an answer was cut to. Text: the first level keeps vendor_display_name (rows) or
    // items_total (remediation); the leanest keeps neither. Data: 0 when whole, 1 at the first
    // thinning (rows without affected_products, still with our_first_seen_at; items without
    // product_ids, still with text), 2 at the leanest.
    const textLevel = (rs, tool) => (rs.some((r) => (tool === "cve_remediation" ? "items_total" : "vendor_display_name") in r) ? 1 : 2);
    const dataLevel = (rs, tool) =>
      tool === "cve_remediation"
        ? rs.some((r) => (r.items ?? []).some((i) => "product_ids" in i)) ? 0 : rs.some((r) => (r.items ?? []).some((i) => "text" in i)) ? 1 : 2
        : rs.some((r) => "affected_products" in r) ? 0 : rs.some((r) => "our_first_seen_at" in r) ? 1 : 2;

    for (const [tool, list, calls] of [
      ["vendor_advisories_for_cve", "advisories", [{ cve_id: L1 }, { cve_id: L2 }, { cve_id: L3 }]],
      ["search_vendor_advisories", "advisories", [{ severity: "Critical", limit: 20 }, { severity: "High", limit: 50 }, { severity: "Medium", limit: 30 }]],
      ["cve_remediation", "vendor_remediations", [{ cve_id: L1 }, { cve_id: L2 }, { cve_id: L3 }]],
    ]) {
      it(`${tool}: every NCSC-NL row keeps its credit at each text cut level and each structured thinning level, and whole`, async () => {
        const seen = { text: new Set(), data: new Set() };
        for (const args of calls) {
          const { res, label } = await call(tool, args);
          assert.match(servedText(res), /TEXT CUT/, `${label}: the text is not cut, so the fixture no longer reaches a cut`);
          const t = textRows(res, list);
          const tl = textLevel(t, tool);
          seen.text.add(tl);
          credited(`${label} text (level ${tl})`, t);
          const d = dataRows(res, list);
          const dl = dataLevel(d, tool);
          seen.data.add(dl);
          credited(`${label} data (level ${dl})`, d);
          // With full: true, data is the API's answer whole: every credit as sent.
          const { res: full, label: fullLabel } = await call(tool, { ...args, full: true });
          credited(`${fullLabel} data`, dataRows(full, list));
          if (tool === "cve_remediation") {
            const said = "ncsc-nl NCSC-2099-1000, ncsc-nl NCSC-2099-1002, ncsc-nl NCSC-2099-1004, ncsc-nl NCSC-2099-1006 and 6 more are a national authority's advisories, not a vendor's (Source: NCSC-NL): their text is as the authority published it, never translated; quote it with that credit.";
            assert.ok(servedText(res).includes(said), `${label}: the summary does not say the NCSC-NL rows are a national authority's:\n${servedText(res).slice(-3000)}`);
          }
        }
        // Anti-vacuity: between them the fixtures reach every level of both cuts.
        assert.deepEqual([...seen.text].sort(), [1, 2], `${tool}: text cut levels reached ${[...seen.text]}`);
        assert.deepEqual([...seen.data].sort(), [1, 2], `${tool}: structured thinning levels reached ${[...seen.data]}`);
      });
    }
  });
}
