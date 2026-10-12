// #3132: check_sbom's and scan_manifest's structured cut keeps every row before any row leaves, and
// cuts a large row on its own terms instead of dropping it and every row after it.
//
// Through 3.0.0 the structured cut had one thinning level for a row (SBOM_ROW_THIN), which keeps
// every match object; a row still near or past the budget so thinned left data, and with it every
// row after it, since rows leave from the end once the clean ones have. Measured on hosted 3.0.0
// (2026-10-11): five Debian 12 purls, all affected, kept 1 row (libssl3) at 14,457 characters;
// Juice Shop 11.1.2 with pkg:composer/magento/community-edition@2.3.0 inserted at index 2 kept 2 of
// 51 rows (summary.affected 19); that purl alone kept none, and the note said "To read every row in
// data, check 0 or fewer purls per call." These cases replay those answers, recorded from the hosted
// endpoint with full: true (fixtures/check_sbom-large-rows.json, each match cut to the fields
// SBOM_ROW_THIN keeps), and add a synthetic one large row among small ones; each fails on 3.0.0's
// cut (the control in the report of #3132: SBOM_ROW_LEVELS set back to [SBOM_ROW_THIN]) and passes
// with SBOM_ROW_LEVELS.
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
import { STRUCTURED_BUDGET, assertDataCutOf, isEntryCutOf, prefixFor, unprefixed } from "./text-bound.mjs";
// synthetic/ is the repo's production monitor, not part of the package: npm-publish-mcp.sh copies
// test/ beside the extracted tarball (dist/, docs/, README.md, CHANGELOG.md, server.json) and runs it
// there, where ../synthetic/probes.mjs does not exist. So the probe's cases below load it only when
// it is present and are skipped, saying why, inside the tarball; the repo suite (npm test, which the
// mcp-remote and synthetic deploys run) still runs them in full. b64c822e did the same for #3084.
const PROBES_FILE = fileURLToPath(new URL("../synthetic/probes.mjs", import.meta.url));
const PROBES = fs.existsSync(PROBES_FILE) ? await import(pathToFileURL(PROBES_FILE).href) : null;
const { EXPECT, LOG4J_CORE_PURL, LOG4J_FIXED_IN, SBOM_PROBE_PURLS, UPSTREAM_PURL } = PROBES ?? {};

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REC = JSON.parse(fs.readFileSync(path.join(HERE, "fixtures", "check_sbom-large-rows.json"), "utf8"));
const DEBIAN = REC.debian12;
const JS_MAGENTO = REC.juiceShopMagento;
const MAGENTO = "pkg:composer/magento/community-edition@2.3.0";
const purlsOf = (a) => a.results.map((r) => r.purl);
// The rows the recordings hold, by purl: the stub answers any list of them, reindexed, with the
// summary the route computes (batchAnswer), and a purl it does not hold as not_affected.
const BY_PURL = new Map([...DEBIAN.results, ...JS_MAGENTO.results].map((r) => [r.purl, r]));
const answerFor = (purls) => {
  if (JSON.stringify(purls) === JSON.stringify(purlsOf(DEBIAN))) return DEBIAN;
  if (JSON.stringify(purls) === JSON.stringify(purlsOf(JS_MAGENTO))) return JS_MAGENTO;
  return batchAnswer(purls.map((p, i) => (BY_PURL.has(p) ? { ...BY_PURL.get(p), index: i } : ROWS.notAffected(i, p, "x", "1"))));
};
// One large row among small ones: 300 matches, each with a description of 600 characters (a CVE's,
// as the API sends it), at index 1 of 12; every other row affected by two CVEs.
const LARGE_AT = 1;
const SYNTH_PURLS = Array.from({ length: 12 }, (_, i) => `pkg:npm/row-${String(i).padStart(2, "0")}@1.0.0`);
const SYNTH = batchAnswer(
  SYNTH_PURLS.map((p, i) => {
    const ids = i === LARGE_AT ? Array.from({ length: 300 }, (_, j) => `CVE-2099-${String(10000 + j)}`) : [`CVE-2098-${1000 + 2 * i}`, `CVE-2098-${1001 + 2 * i}`];
    const row = ROWS.affected(i, p, `row-${i}`, "1.0.0", ids);
    return {
      ...row,
      matches: row.matches.map((m, j) => ({ ...m, description: `${m.description} ${"x".repeat(560)}`, kev_listed: j === 7, ransomware: false, fixed_in: j % 3 === 0 ? null : "1.0.1", ...(j % 3 === 0 ? { fixed_in_reason: "no fix on record" } : {}) })),
    };
  }),
);

async function startStub() {
  const state = { answer: undefined, requests: [] };
  let prefix = "";
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const url = unprefixed(req.url, prefix);
      state.requests.push(url);
      if (url !== BATCH_PATH || req.method !== "POST") {
        res.writeHead(404, { "content-type": "text/plain" });
        return res.end("404 page not found\n");
      }
      const purls = JSON.parse(body).components.map((c) => c.purl);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(typeof state.answer === "function" ? state.answer(purls) : (state.answer ?? answerFor(purls))));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const origin = `http://127.0.0.1:${server.address().port}`;
  // #3013: a base as long as production's, so the cut fills the budget as production's would.
  prefix = prefixFor(origin);
  return { state, base: `${origin}${prefix}`, close: () => new Promise((r) => server.close(r)) };
}

const noteOf = (res) => res.structuredContent.notes.join(" ");
const published = new AjvJsonSchemaValidator();
const strict = new StrictOutputValidator();

describe("#3132: a large row is cut on its own terms, and every row stays", () => {
  let stub, client, tools;
  const call = async (name, args) => {
    const res = await client.callTool({ name, arguments: args });
    assert.notEqual(res.isError, true, JSON.stringify(res.content).slice(0, 600));
    return res;
  };
  before(async () => {
    stub = await startStub();
    client = await connect({ era: MODERN, ...serverCommand(), env: { ...process.env, ECHELONGRAPH_API_BASE: stub.base, ECHELONGRAPH_API_TIMEOUT_MS: "5000" }, stderr: "inherit" });
    ({ tools } = await client.listTools());
  });
  after(async () => {
    try {
      await client?.close();
    } finally {
      await stub?.close();
    }
  });

  // What every default answer here holds to: within the budget, data the answer cut as truncated
  // says (each row kept is the answer's, thinned, or cut on its own terms), every row kept, each
  // with its verdict and every cve_id, a valid answer, and no "0 or fewer".
  const holds = (name, res, whole, label) => {
    const sc = res.structuredContent;
    const size = JSON.stringify(sc).length;
    assert.ok(size <= STRUCTURED_BUDGET, `${label}: ${size} characters of structured result`);
    assert.equal(sc.data_truncated, true, label);
    assertDataCutOf(sc, whole, label);
    assert.deepEqual(sc.truncated.results, { total: whole.results.length, returned: whole.results.length, thinned: true }, `${label}: rows left data`);
    assert.deepEqual(
      sc.data.results.map((r) => [r.index, r.purl, r.verdict, r.cve_ids]),
      whole.results.map((r) => [r.index, r.purl, r.verdict, r.cve_ids]),
      `${label}: a row lost its verdict or a cve_id`,
    );
    assert.doesNotMatch(noteOf(res), /\b0 or fewer\b/, label);
    const tool = tools.find((t) => t.name === name);
    const v = strict.getValidator(tool.outputSchema)(sc);
    assert.ok(v.valid, `${label}: ${v.errorMessage}`);
    return sc;
  };

  it("five Debian 12 purls, all affected (hosted 3.0.0 kept 1): all 5 rows, each with every cve_id, within 30,000 characters; linux-libc-dev's 200 matches are cut, not the row", async () => {
    const res = await call("check_sbom", { purls: purlsOf(DEBIAN) });
    const sc = holds("check_sbom", res, DEBIAN, "Debian 12");
    const libc = sc.data.results.find((r) => r.purl.includes("linux-libc-dev"));
    assert.ok(libc.matches_truncated, "linux-libc-dev's row carries no matches_truncated");
    assert.equal(libc.matches_truncated.total, 200);
    assert.ok(Array.isArray(libc.matches_truncated.fixed_in_versions) && libc.matches_truncated.fixed_in_versions.length > 0);
    // Only the rows with more matches than the cap lose any; zlib1g's 3 stay whole (thinned).
    const zlib = sc.data.results.find((r) => r.purl.includes("zlib1g"));
    assert.equal(zlib.matches_truncated, undefined);
    assert.equal(zlib.matches.length, 3);
    assert.match(noteOf(res), /results keeps all 5 entries, each cut to index, purl, verdict, not_assessed_reason, cve_ids, matched_package, matched_via, matched_version_from, purl_name and matches \(each with [^)]*\), each row's matches keeping at most its first \d+ \(the API's order, highest effective_score first\), a row with more than that carrying matches_truncated/);
    // #3121: the answer with a field added later still validates against the published schema,
    // which a client that listed the tools before that field is holding; the suite's copy refuses it.
    const tool = tools.find((t) => t.name === "check_sbom");
    assert.equal(published.getValidator(tool.outputSchema)({ ...sc, a_field_added_later: true }).valid, true);
    assert.equal(strict.getValidator(tool.outputSchema)({ ...sc, a_field_added_later: true }).valid, false);
  });

  it("Juice Shop 11.1.2 with magento/community-edition 2.3.0 at index 2 (hosted 3.0.0 kept 2 of 51): all 51 rows, the 19 affected among them", async () => {
    const res = await call("check_sbom", { purls: purlsOf(JS_MAGENTO) });
    const sc = holds("check_sbom", res, JS_MAGENTO, "Juice Shop + magento");
    assert.equal(sc.data.results.length, 51);
    assert.equal(sc.data.results.filter((r) => r.verdict === "affected").length, JS_MAGENTO.summary.affected);
    assert.equal(JS_MAGENTO.summary.affected, 19);
    const magento = sc.data.results[2];
    assert.equal(magento.purl, MAGENTO);
    assert.ok(magento.matches_truncated && magento.matches_truncated.total === 200);
  });

  it("magento/community-edition 2.3.0 alone (hosted 3.0.0: results [] and \"check 0 or fewer purls\"): its one row, its top matches, and the KEV-listed CVEs among all 200", async () => {
    const res = await call("check_sbom", { purls: [MAGENTO] });
    const whole = answerFor([MAGENTO]);
    const sc = holds("check_sbom", res, whole, "magento alone");
    const [row] = sc.data.results;
    assert.equal(row.matches_truncated.total, 200);
    assert.ok(row.matches.length > 0 && row.matches.length === row.matches_truncated.returned);
    assert.deepEqual(row.matches_truncated.kev_listed_cve_ids, ["CVE-2024-34102", "CVE-2025-54236"]);
    assert.deepEqual(row.matches_truncated.ransomware_cve_ids, []);
  });

  it("one large row among small ones (synthetic): every row stays, only the large one is cut, and the rows after it keep every match", async () => {
    stub.state.answer = SYNTH;
    try {
      const res = await call("check_sbom", { purls: SYNTH_PURLS });
      const sc = holds("check_sbom", res, SYNTH, "synthetic");
      for (const [i, r] of sc.data.results.entries()) {
        if (i === LARGE_AT) {
          assert.equal(r.matches_truncated.total, 300);
          assert.deepEqual(r.matches_truncated.kev_listed_cve_ids, ["CVE-2099-10007"]);
          assert.deepEqual(r.matches_truncated.fixed_in_versions, ["1.0.1"]);
          assert.ok(isEntryCutOf(r, SYNTH.results[i]));
        } else {
          assert.equal(r.matches_truncated, undefined, `row ${i} lost matches beside a larger row`);
          assert.equal(r.matches.length, 2, `row ${i}`);
        }
      }
    } finally {
      stub.state.answer = undefined;
    }
  });

  it("scan_manifest: a composer.lock whose first package is magento/community-edition 2.3.0 keeps every row, that one cut on its own terms", async () => {
    const lock = JSON.stringify({
      packages: [
        { name: "magento/community-edition", version: "2.3.0" },
        ...Array.from({ length: 5 }, (_, i) => ({ name: `acme/small-${i}`, version: `1.0.${i}` })),
      ],
      "packages-dev": [],
    });
    const res = await call("scan_manifest", { files: [{ filename: "composer.lock", content: lock }] });
    const purls = res.structuredContent.data.results.map((r) => r.purl);
    assert.equal(purls[0], MAGENTO);
    const sc = holds("scan_manifest", res, { ...res.structuredContent.data, ...answerFor(purls), results: answerFor(purls).results }, "scan_manifest");
    assert.equal(sc.data.results.length, 6);
    assert.equal(sc.data.results[0].matches_truncated.total, 200);
  });
});

// #3132: the page sentence. 3.0.0 built it from returned alone, so a cut that kept no row told the
// model to check "0 or fewer purls per call".
describe("#3132: the paging sentence never advises 0 or fewer", () => {
  it("returned 0 names full: true instead; returned k names k; nothing cut, nothing said", async () => {
    const { sbomData } = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "check_sbom.js")).href);
    const cut = sbomData(["not_sent_purls"], (k) => `To read every row in data, check ${k} or fewer purls per call.`);
    const at = { keeps: {}, wholeFit: () => 0 };
    const none = cut.page({ results: { total: 1, returned: 0 } }, {}, at);
    assert.doesNotMatch(none, /\b0 or fewer\b/);
    assert.match(none, /full: true returns every row whole/);
    assert.equal(cut.page({ results: { total: 840, returned: 300, thinned: true } }, {}, at), "To read every row in data, check 300 or fewer purls per call.");
    assert.equal(cut.page({ results: { total: 5, returned: 5, thinned: true } }, {}, at), "");
    // Control: 3.0.0's sentence for the same cut.
    const old = (t) => (t.results && t.results.returned < t.results.total ? `To read every row in data, check ${t.results.returned} or fewer purls per call.` : "");
    assert.match(old({ results: { total: 1, returned: 0 } }), /\b0 or fewer\b/);
  });
});

// #3132's review (DO-NOT-SHIP): the production synthetic's check_sbom probe, synthetic/probes.mjs
// SBOM_PROBE_PURLS, 201 purls, every one affected on hosted 3.0.0. Round 1 of 3.0.1 cut each of its
// rows to index, purl, verdict, not_assessed_reason and cve_ids (132 of 201 kept), so the probe's
// EXPECT failed on the log4j-core row ("no CVE-2021-44228 match"), and the upstream row lost
// matched_via; every SBOM of about 100 affected rows or more lost every KEV flag and fixed_in.
// fixtures/check_sbom-probe-201.json is that answer, recorded from hosted 3.0.0 with full: true,
// each match cut to the fields SBOM_ROW_THIN keeps. Control: round 1's build (35073f92) fails the
// first two cases here; this build passes them.
const PROBE = JSON.parse(fs.readFileSync(path.join(HERE, "fixtures", "check_sbom-probe-201.json"), "utf8")).probe201;
const PROBE_BY_PURL = new Map(PROBE.results.map((r) => [r.purl, r]));
const probeAnswer = (purls) => batchAnswer(purls.map((p, i) => ({ ...PROBE_BY_PURL.get(p), index: i })));

describe("#3132's review: the synthetic's 201-purl probe keeps compact matches, not cve_ids alone", { skip: PROBES ? false : "synthetic/probes.mjs is not in the package (the tarball test); the repo suite runs this" }, () => {
  let stub, client, tools;
  const call = async (args) => {
    const res = await client.callTool({ name: "check_sbom", arguments: args });
    assert.notEqual(res.isError, true, JSON.stringify(res.content).slice(0, 600));
    return res.structuredContent;
  };
  before(async () => {
    stub = await startStub();
    stub.state.answer = probeAnswer;
    client = await connect({ era: MODERN, ...serverCommand(), env: { ...process.env, ECHELONGRAPH_API_BASE: stub.base, ECHELONGRAPH_API_TIMEOUT_MS: "5000" }, stderr: "inherit" });
    ({ tools } = await client.listTools());
  });
  after(async () => {
    try {
      await client?.close();
    } finally {
      await stub?.close();
    }
  });

  it("the probe's EXPECT passes on the default answer: log4j-core 2.14.1 keeps CVE-2021-44228 (KEV, fixed_in 2.15.0), the upstream row its matched_via", async () => {
    assert.equal(SBOM_PROBE_PURLS.length, 201);
    assert.deepEqual(PROBE.results.map((r) => r.purl), SBOM_PROBE_PURLS, "the fixture is the probe's answer, row for row");
    const whole = (await call({ purls: SBOM_PROBE_PURLS, full: true })).data;
    const sc = await call({ purls: SBOM_PROBE_PURLS });
    const size = JSON.stringify(sc).length;
    assert.ok(size <= STRUCTURED_BUDGET, `${size} characters of structured result`);
    assertDataCutOf(sc, whole, "probe");
    assert.equal(EXPECT.check_sbom(sc), undefined);
    const rows = sc.data.results;
    const log4j = rows.find((r) => r.purl === LOG4J_CORE_PURL);
    assert.deepEqual(
      log4j.matches.find((m) => m.cve_id === "CVE-2021-44228"),
      { cve_id: "CVE-2021-44228", kev_listed: true, ransomware: true, effective_score: 10, fixed_in: LOG4J_FIXED_IN },
    );
    assert.equal(log4j.matched_via, "purl_name");
    const up = rows.find((r) => r.purl === UPSTREAM_PURL);
    assert.deepEqual([up.matched_via, up.matched_package, up.matched_version_from], ["upstream", "openssl", "purl"]);
    const tool = tools.find((t) => t.name === "check_sbom");
    const v = strict.getValidator(tool.outputSchema)(sc);
    assert.ok(v.valid, v.errorMessage);
  });

  it("rows leave with their compact matches: every row kept keeps each match's kev_listed and fixed_in, and the rows kept are the first, in input order", async () => {
    const sc = await call({ purls: SBOM_PROBE_PURLS });
    const rows = sc.data.results;
    assert.ok(rows.length < 201 && rows.length > 43, `${rows.length} rows kept (3.0.0 kept 43 thinned)`);
    assert.deepEqual(sc.truncated.results, { total: 201, returned: rows.length, thinned: true });
    assert.deepEqual(rows.map((r) => r.index), [...Array(rows.length).keys()]);
    for (const r of rows) {
      const all = PROBE_BY_PURL.get(r.purl).matches;
      const kept = r.matches_truncated ? r.matches_truncated.returned : all.length;
      assert.equal(r.matches?.length, kept, `${r.purl}: ${r.matches?.length} matches, want ${kept}`);
      for (const m of r.matches) assert.ok(Object.hasOwn(m, "kev_listed") && Object.hasOwn(m, "fixed_in"), `${r.purl} ${m.cve_id}`);
    }
    assert.match(sc.notes.join(" "), new RegExp(`results keeps ${rows.length} of its 201 entries, each cut to index, purl, verdict, not_assessed_reason, cve_ids, matched_package, matched_via, matched_version_from, purl_name and matches \\(each with cve_id, kev_listed, ransomware, fixed_in and effective_score\\)`));
  });

  it("the page size the note names holds: a call of that many of the probe's purls keeps every row", async () => {
    const sc = await call({ purls: SBOM_PROBE_PURLS });
    const k = sc.data.results.length;
    assert.match(sc.notes.join(" "), new RegExp(`check ${k} or fewer purls per call`));
    const page = await call({ purls: SBOM_PROBE_PURLS.slice(0, k) });
    assert.equal(page.data.results.length, k);
    assert.ok(JSON.stringify(page).length <= STRUCTURED_BUDGET);
    for (const r of page.data.results) assert.ok(Array.isArray(r.matches), `${r.purl} kept no matches`);
  });
});

// #3132's review (should-fix 6): data.not_sent_purls is the list a client sends again, so the cut
// keeps it whole or leaves it out, never its first entries; round 1 gave it back the first ones
// the room the rows left held (3 of the rate-limited case's 800). This drives check_sbom's DataCut
// directly through cutData, so the control is the cut alone: round 1's build (35073f92) keeps a
// prefix here, and this build keeps 0 or all.
describe("#3132's review: not_sent_purls is kept whole or not at all", () => {
  // Shapes like the rate-limited case's (1,200 rows sent, 800 not sent): how much room the rows
  // leave varies with them, so round 1 kept a different prefix in each (1 to 5 purls here).
  const SHAPES = [1, 2, 3, 5, 7].flatMap((every) => [300, 600, 1200].map((n) => ({ every, n })));
  it("rows past the budget and 800 purls not sent: data keeps none or all 800, in every shape", async () => {
    const { sbomData } = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "check_sbom.js")).href);
    const { cutData } = await import(pathToFileURL(path.join(PKG_DIR, "dist", "textBudget.js")).href);
    const cut = sbomData(["not_sent_purls"], (k) => `To read every row in data, check ${k} or fewer purls per call.`);
    const notSent = Array.from({ length: 800 }, (_, i) => `pkg:npm/ns-${i}@1`);
    const structured = (d, truncated, said) => ({ state: "measured", notes: [`check_sbom OK. ${said}`], data_truncated: truncated !== undefined, ...(truncated ? { truncated } : {}), data: d });
    const prefixes = [];
    for (const { every, n } of SHAPES) {
      const rows = batchAnswer(
        Array.from({ length: n }, (_, i) => {
          const p = `pkg:npm/sent-${String(i).padStart(4, "0")}@1.0.0`;
          return i % every === 0 ? ROWS.affected(i, p, `sent-${i}`, "1.0.0", [`CVE-2097-${10000 + 2 * i}`, `CVE-2097-${10001 + 2 * i}`]) : ROWS.notAffected(i, p, `sent-${i}`, "1.0.0");
        }),
      );
      const data = { ...rows, not_sent_purls: notSent };
      const c = cutData(data, cut, JSON.stringify(structured(data, undefined, "")).length, structured);
      assert.ok(c && JSON.stringify(c.structured).length <= STRUCTURED_BUDGET, `${every}/${n}`);
      assert.ok(c.data.results.length > 0, `${every}/${n}`);
      const kept = c.truncated.not_sent_purls?.returned ?? 800;
      if (kept !== 0 && kept !== 800) prefixes.push(`${every}/${n}: ${kept}`);
      else assert.deepEqual(c.data.not_sent_purls, kept === 0 ? [] : notSent);
    }
    assert.deepEqual(prefixes, [], "data kept the first purls not sent, a list to retry that is not the whole");
  });
});

// #3132's second review (nit 4): give-back passed over nothing. A row kept at the compact level
// that already holds every match (10 or fewer) but cannot move up to the thinned level ended it,
// so a later row capped at 10 of its 30 matches never took any back while room was left. Now give-
// back goes on past such a row. Here row 0 holds 8 matches, each with a 300-character
// fixed_in_reason that only the thinned level keeps (some 2,400 characters to move up), and every
// row after it 30 matches, capped at 10 where rows leave (from 50 rows on, the cve_ids-only
// level cannot keep them all); the shapes vary the purls' length, and with it the room
// the rows that leave leave behind. Control: the build with `if (!took) break` leaves room for more matches
// unclaimed in some shape.
describe("#3132's second review: give-back goes on past a row that cannot move up", () => {
  it("a later capped row takes back matches whenever room for one more is left", async () => {
    const { sbomData } = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "check_sbom.js")).href);
    const { cutData } = await import(pathToFileURL(path.join(PKG_DIR, "dist", "textBudget.js")).href);
    const cut = sbomData(["not_sent_purls"], (k) => `To read every row in data, check ${k} or fewer purls per call.`);
    const structured = (d, truncated, said) => ({ state: "measured", notes: [`check_sbom OK. ${said}`], data_truncated: truncated !== undefined, ...(truncated ? { truncated } : {}), data: d });
    const unclaimed = [];
    let tookBack = 0;
    for (let n = 50; n < 60; n++) {
      const rows = batchAnswer(
        Array.from({ length: n }, (_, i) => {
          const p = `pkg:npm/gb-${"p".repeat(20 * (n - 50))}${String(i).padStart(3, "0")}@1.0.0`;
          const ids = Array.from({ length: i === 0 ? 8 : 30 }, (_, j) => `CVE-2096-${String(i * 100 + j).padStart(5, "0")}`);
          const row = ROWS.affected(i, p, `gb-${i}`, "1.0.0", ids);
          return { ...row, matches: row.matches.map((m) => ({ ...m, kev_listed: false, ransomware: false, effective_score: 7.5, fixed_in: null, fixed_in_reason: i === 0 ? "r".repeat(300) : "none" })) };
        }),
      );
      const c = cutData(rows, cut, JSON.stringify(structured(rows, undefined, "")).length, structured);
      const size = JSON.stringify(c.structured).length;
      assert.ok(size <= STRUCTURED_BUDGET, `${n}: ${size}`);
      assert.ok(c.data.results.length < n && c.data.results.length > 1, `${n}: ${c.data.results.length} rows kept`);
      assert.equal(c.data.results[0].matches.length, 8, `${n}: row 0`);
      assert.ok(!("fixed_in_reason" in c.data.results[0].matches[0]), `${n}: row 0 moved up`);
      const more = c.data.results.slice(1).filter((r) => r.matches.length > 10).length;
      tookBack += more;
      // One more compact match is under 100 characters, and the note's clause on the entries that
      // took back detail some 700 (it names the level and the cap): 1,000 left is room for both.
      if (more === 0 && STRUCTURED_BUDGET - size > 1000) unclaimed.push(`${n} rows: ${STRUCTURED_BUDGET - size} characters left`);
    }
    assert.deepEqual(unclaimed, [], "room for more matches left unclaimed behind row 0");
    assert.ok(tookBack > 0);
  });
});
