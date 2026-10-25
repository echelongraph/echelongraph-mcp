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
import { PKG_DIR, readPkgFile, serverCommand } from "./server-under-test.mjs";
import { BATCH_PATH, ROWS, batchAnswer } from "./fixtures/match-batch.mjs";
import { STRUCTURED_BUDGET, assertDataCutOf, isEntryCutOf, pickedMatches, prefixFor, unprefixed } from "./text-bound.mjs";
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
// #3269's second review: the sentence promises only what holds (round 2 opened "To read every row
// in data, check N or fewer purls per call", which read as "page the SBOM in calls of N").
const PAGE_SAID = /A call of the first (\d+) of these purls, or of fewer, keeps every row in data; a call of other purls says in its own note what it leaves out\./;
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
  // with its verdict and every cve_id, a valid answer, and no "0 or fewer". #3269: with
  // `clean: "may leave"`, every row but the not_affected and not_assessed ones, which leave before
  // an affected row's matches are capped (data.summary counts them).
  const holds = (name, res, whole, label, { clean = "kept" } = {}) => {
    const sc = res.structuredContent;
    const size = JSON.stringify(sc).length;
    assert.ok(size <= STRUCTURED_BUDGET, `${label}: ${size} characters of structured result`);
    assert.equal(sc.data_truncated, true, label);
    assertDataCutOf(sc, whole, label);
    const others = whole.results.filter((r) => clean === "kept" || (r.verdict !== "not_affected" && r.verdict !== "not_assessed"));
    if (clean === "kept") assert.deepEqual(sc.truncated.results, { total: whole.results.length, returned: whole.results.length, thinned: true }, `${label}: rows left data`);
    assert.deepEqual(
      sc.data.results.filter((r) => clean === "kept" || (r.verdict !== "not_affected" && r.verdict !== "not_assessed")).map((r) => [r.index, r.purl, r.verdict, r.cve_ids]),
      others.map((r) => [r.index, r.purl, r.verdict, r.cve_ids]),
      `${label}: a row left data, or lost its verdict or a cve_id`,
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
    assert.match(noteOf(res), /results keeps all 5 entries, each cut to index, purl, verdict, not_assessed_reason, cve_ids, matched_package, matched_via, matched_version_from, purl_name and matches \(each with [^)]*\), each row's matches keeping at most \d+, chosen used in ransomware first, then the other KEV-listed ones, then those of highest effective_score, and listed in the API's order; a row with more than that carrying matches_truncated/);
    // #3121: the answer with a field added later still validates against the published schema,
    // which a client that listed the tools before that field is holding; the suite's copy refuses it.
    const tool = tools.find((t) => t.name === "check_sbom");
    assert.equal(published.getValidator(tool.outputSchema)({ ...sc, a_field_added_later: true }).valid, true);
    assert.equal(strict.getValidator(tool.outputSchema)({ ...sc, a_field_added_later: true }).valid, false);
  });

  // #3269: 3.0.2 kept all 51 rows here, magento's matches capped at 6 to keep the 32 clean and
  // not-assessed ones; they now leave first (data.summary counts them, and the note says which
  // left), and every affected row stays, magento's with more of its matches. #3270: both of
  // magento's KEV-listed CVEs are among its matches kept; 3.0.2 cut CVE-2025-54236 (position 21).
  it("Juice Shop 11.1.2 with magento/community-edition 2.3.0 at index 2 (hosted 3.0.0 kept 2 of 51): every one of the 19 affected rows, magento's with both its KEV-listed matches", async () => {
    const res = await call("check_sbom", { purls: purlsOf(JS_MAGENTO) });
    const sc = holds("check_sbom", res, JS_MAGENTO, "Juice Shop + magento", { clean: "may leave" });
    assert.equal(sc.data.results.filter((r) => r.verdict === "affected").length, JS_MAGENTO.summary.affected);
    assert.equal(JS_MAGENTO.summary.affected, 19);
    const magento = sc.data.results.find((r) => r.purl === MAGENTO);
    assert.equal(magento.index, 2);
    assert.ok(magento.matches_truncated && magento.matches_truncated.total === 200);
    assert.deepEqual(magento.matches.filter((m) => m.kev_listed).map((m) => m.cve_id), ["CVE-2024-34102", "CVE-2025-54236"]);
    const left = sc.truncated.results.total - sc.truncated.results.returned;
    if (left > 0) assert.match(noteOf(res), new RegExp(`the ${left} left out being entries whose verdict is not_affected or not_assessed \\(data\\.summary counts every verdict\\)`));
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
    // #3270: and both are among the matches kept, whatever the cap.
    assert.deepEqual(row.matches.filter((m) => m.kev_listed).map((m) => m.cve_id), ["CVE-2024-34102", "CVE-2025-54236"]);
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
    // #3269: the small packages are affected here (two CVEs each): a clean one now leaves before
    // magento's matches are capped, and this case holds the rows after a large one.
    const small = (purls) =>
      batchAnswer(purls.map((p, i) => (BY_PURL.has(p) ? { ...BY_PURL.get(p), index: i } : ROWS.affected(i, p, p.split("/").pop(), "1.0.0", [`CVE-2095-${1000 + 2 * i}`, `CVE-2095-${1001 + 2 * i}`]))));
    stub.state.answer = small;
    try {
      const res = await call("scan_manifest", { files: [{ filename: "composer.lock", content: lock }] });
      const purls = res.structuredContent.data.results.map((r) => r.purl);
      assert.equal(purls[0], MAGENTO);
      const sc = holds("scan_manifest", res, { ...res.structuredContent.data, ...small(purls), results: small(purls).results }, "scan_manifest");
      assert.equal(sc.data.results.length, 6);
      assert.equal(sc.data.results[0].matches_truncated.total, 200);
    } finally {
      stub.state.answer = undefined;
    }
  });
});

// #3132: the page sentence. 3.0.0 built it from returned alone, so a cut that kept no row told the
// model to check "0 or fewer purls per call". #3269's review: it names what a call of the first that
// many purls keeps whole (PageAt.firstFit), not the rows this call kept (round 1: returned).
describe("#3132: the paging sentence never advises 0 or fewer", () => {
  it("returned 0 names full: true instead; otherwise it names firstFit's number, never 0; nothing cut, nothing said", async () => {
    const { sbomData } = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "check_sbom.js")).href);
    const cut = sbomData(["not_sent_purls"], (k) => `To read every row in data, check ${k} or fewer purls per call.`);
    const at = (fit) => ({ keeps: {}, wholeFit: () => 0, firstFit: () => fit });
    const none = cut.page({ results: { total: 1, returned: 0 } }, {}, at(0));
    assert.doesNotMatch(none, /\b0 or fewer\b/);
    assert.match(none, /full: true returns every row whole/);
    assert.equal(
      cut.page({ results: { total: 840, returned: 300, thinned: true } }, {}, at(120)),
      "To read every row in data, check 120 or fewer purls per call.",
    );
    const zero = cut.page({ results: { total: 840, returned: 300, thinned: true } }, {}, at(0));
    assert.doesNotMatch(zero, /\b0 or fewer\b/);
    assert.match(zero, /full: true returns every row whole/);
    assert.equal(cut.page({ results: { total: 5, returned: 5, thinned: true } }, {}, at(5)), "");
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
    // #3270: with epss_score and score_assessed, which 3.0.2's compact level left out.
    const want = PROBE_BY_PURL.get(LOG4J_CORE_PURL).matches.find((m) => m.cve_id === "CVE-2021-44228");
    assert.deepEqual(
      log4j.matches.find((m) => m.cve_id === "CVE-2021-44228"),
      { cve_id: "CVE-2021-44228", kev_listed: true, ransomware: true, epss_score: want.epss_score, effective_score: 10, score_assessed: want.score_assessed, fixed_in: LOG4J_FIXED_IN },
    );
    assert.equal(log4j.matched_via, "purl_name");
    const up = rows.find((r) => r.purl === UPSTREAM_PURL);
    assert.deepEqual([up.matched_via, up.matched_package, up.matched_version_from], ["upstream", "openssl", "purl"]);
    const tool = tools.find((t) => t.name === "check_sbom");
    const v = strict.getValidator(tool.outputSchema)(sc);
    assert.ok(v.valid, v.errorMessage);
  });

  // #3270: 3.0.2 kept 54 rows here, each match without epss_score or score_assessed; the compact
  // level now keeps both, and 43 rows fit, as on 3.0.0, each with every field a prompt ranks by.
  it("rows leave with their compact matches: every row kept keeps each match's kev_listed and fixed_in, and the rows kept are the first, in input order", async () => {
    const sc = await call({ purls: SBOM_PROBE_PURLS });
    const rows = sc.data.results;
    assert.ok(rows.length < 201 && rows.length >= 43, `${rows.length} rows kept (3.0.0 kept 43 thinned)`);
    assert.deepEqual(sc.truncated.results, { total: 201, returned: rows.length, thinned: true });
    assert.deepEqual(rows.map((r) => r.index), [...Array(rows.length).keys()]);
    for (const r of rows) {
      const all = PROBE_BY_PURL.get(r.purl).matches;
      const kept = r.matches_truncated ? r.matches_truncated.returned : all.length;
      assert.equal(r.matches?.length, kept, `${r.purl}: ${r.matches?.length} matches, want ${kept}`);
      for (const m of r.matches) assert.ok(Object.hasOwn(m, "kev_listed") && Object.hasOwn(m, "fixed_in"), `${r.purl} ${m.cve_id}`);
    }
    assert.match(sc.notes.join(" "), new RegExp(`results keeps ${rows.length} of its 201 entries, each cut to index, purl, verdict, not_assessed_reason, cve_ids, matched_package, matched_via, matched_version_from, purl_name and matches \\(each with cve_id, kev_listed, ransomware, epss_score, effective_score, score_assessed and fixed_in\\)`));
  });

  // #2834 beside #3269 (3.1.0's integration): sbom_review relays a null fixed_in's
  // fixed_in_reason, and SBOM_ROW_COMPACT keeps fixed_in without it. Decided by measurement:
  // with fixed_in_reason added to SBOM_ROW_COMPACT, the probe kept 42 rows, not 43 (no probe match
  // carries one: the DATA CUT sentence, 17 characters longer for naming the field, takes 43 rows
  // past the budget), and the second review's image mixes below kept fewer affected rows at their floor (12
  // under the 16 held there, 31 under 32, 30 under 31, 22 under 23). So the compact level leaves it
  // out, and sbom_review reads a null fixed_in without fixed_in_reason as a reason the cut left
  // out, never as no fix (prompt-fields holds both). This replays the probe's own cut through
  // cutData with the served envelope: control, the replay of SBOM_ROW_LEVELS is the served answer,
  // 43 rows; with fixed_in_reason in the compact level, the same replay keeps 42.
  it("the compact level keeps fixed_in, not fixed_in_reason: kept, the reason costs the probe a row", async () => {
    const S = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "check_sbom.js")).href);
    const { cutData } = await import(pathToFileURL(path.join(PKG_DIR, "dist", "textBudget.js")).href);
    const { sentences } = await import(pathToFileURL(path.join(PKG_DIR, "dist", "index.js")).href);
    const fieldsOf = (keep) => keep.find((k) => Array.isArray(k) && k[0] === "matches")[1];
    assert.ok(fieldsOf(S.SBOM_ROW_THIN).includes("fixed_in_reason"));
    assert.deepEqual(fieldsOf(S.SBOM_ROW_THIN).filter((f) => !fieldsOf(S.SBOM_ROW_COMPACT).includes(f)), ["fixed_in_reason"]);
    const wholeSc = await call({ purls: SBOM_PROBE_PURLS, full: true });
    const sc = await call({ purls: SBOM_PROBE_PURLS });
    const at = sc.notes.findIndex((n) => n.startsWith("DATA CUT:"));
    assert.ok(at > 0, "the served answer has no DATA CUT sentence");
    const { state, measured_at, method, coverage, freshness } = sc;
    const structured = (d, truncated, said) => ({ state, measured_at, method, coverage, freshness, notes: [...sc.notes.slice(0, at), ...sentences(said)], data_truncated: truncated !== undefined, ...(truncated ? { truncated } : {}), data: d });
    const replay = (levels) => {
      const cut = S.sbomData(["not_sent_purls"], S.sbomPageSaid, S.sbomAgainSaid);
      const steps = cut.steps.map((st) => (st.thin === S.SBOM_ROW_LEVELS ? { ...st, thin: levels } : st));
      assert.ok(steps.some((st) => st.thin === levels), "check_sbom's cut no longer thins results by SBOM_ROW_LEVELS: re-aim this replay");
      return cutData(wholeSc.data, { ...cut, steps }, JSON.stringify(wholeSc).length, structured).structured;
    };
    // Control: the replay is the served answer.
    const served = replay(S.SBOM_ROW_LEVELS);
    assert.deepEqual(served, sc);
    assert.equal(served.data.results.length, 43);
    const withReason = S.SBOM_ROW_LEVELS.map((l) => (l.keep === S.SBOM_ROW_COMPACT ? { ...l, keep: S.SBOM_ROW_COMPACT.map((k) => (Array.isArray(k) && k[0] === "matches" ? ["matches", [...k[1], "fixed_in_reason"]] : k)) } : l));
    assert.notDeepEqual(withReason, S.SBOM_ROW_LEVELS);
    const kept = replay(withReason);
    assert.ok(JSON.stringify(kept).length <= STRUCTURED_BUDGET);
    assert.equal(kept.data.results.length, 42, "with fixed_in_reason kept compact the probe keeps as many rows: the measurement behind sbom_review's clause changed, so check it again");
  });

  it("the page size the note names holds: a call of that many of the probe's purls keeps every row", async () => {
    const sc = await call({ purls: SBOM_PROBE_PURLS });
    // #3269's review: the number a call of the first that many keeps whole, at most the rows kept.
    const k = Number(PAGE_SAID.exec(sc.notes.join(" "))?.[1]);
    assert.ok(k > 0 && k <= sc.data.results.length, `the note names ${k}, data kept ${sc.data.results.length}`);
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

// #3269 and #3270, the post-close review of #3132. 3.0.2 took every row down its levels together,
// the clean ones with the affected, so on an ordinary image SBOM (most rows clean) the affected rows
// lost their matches to keep the clean rows: 150 purls, 40 of them affected, kept all 150 rows and
// the matches of 2 of the 40 affected (3.0.0: 56 rows, all 40 with every match). A capped row kept
// its first matches by effective_score, so a KEV-listed CVE ranked lower was cut; and the compact
// level left out epss_score and score_assessed, which workload_triage ranks by. These cases replay
// the probe's recorded rows (fixtures/check_sbom-probe-201.json, no synthetic/ import, so they run
// in the tarball test too). Control: up/development's build (3.0.2) fails each of them; this build
// passes them (the report of #3269 gives the lines).
const SBOM_THIN_MATCH = ["cve_id", "kev_listed", "ransomware", "epss_score", "effective_score", "score_assessed", "fixed_in", "fixed_in_reason"];
const RANKED = ["kev_listed", "ransomware", "epss_score", "effective_score", "score_assessed", "fixed_in"];
const SBOM_ROW_MIN = ["index", "purl", "verdict", "not_assessed_reason", "cve_ids"];
// `total` purls, the probe's first `affected` rows spread evenly among clean ones: the suite's own
// not_affected row (match-batch.mjs ROWS) for a short npm purl, or, with "deb", production's clean
// row (Juice Shop's kind-of 3.2.2) for a Debian 12 binary package, as an image's SBOM lists them.
const CLEAN_DEB = JS_MAGENTO.results.find((r) => r.verdict === "not_affected");
const imageMix = (total, affected, shape = "npm") => {
  const rows = [];
  let a = 0;
  let c = 0;
  for (let i = 0; i < total; i++) {
    if (a < affected && Math.floor((i * affected) / total) >= a) rows.push({ ...PROBE.results[a++], index: i });
    else if (shape === "deb") {
      const p = `pkg:deb/debian/libclean${c}@1.2.3-1?arch=amd64&distro=debian-12`;
      rows.push({ ...CLEAN_DEB, ecosystem: "Debian:12", package: `libclean${c}`, matched_package: `libclean${c++}`, version: "1.2.3-1", purl: p, index: i });
    } else rows.push(ROWS.notAffected(i, `pkg:npm/c${c}@1.0.0`, `c${c++}`, "1.0.0"));
  }
  return batchAnswer(rows);
};

describe("#3269 and #3270: affected rows keep their matches before clean rows stay, KEV matches before the rest, and every ranked field", () => {
  let stub, client;
  const call = async (args) => {
    const res = await client.callTool({ name: "check_sbom", arguments: args });
    assert.notEqual(res.isError, true, JSON.stringify(res.content).slice(0, 600));
    return res.structuredContent;
  };
  before(async () => {
    stub = await startStub();
    client = await connect({ era: MODERN, ...serverCommand(), env: { ...process.env, ECHELONGRAPH_API_BASE: stub.base, ECHELONGRAPH_API_TIMEOUT_MS: "5000" }, stderr: "inherit" });
  });
  after(async () => {
    try {
      await client?.close();
    } finally {
      await stub?.close();
    }
  });

  it("an image-shaped SBOM (150 purls, 40 affected; and 150/30, 150/20, 94/40, Debian-shaped 150/40): every affected row keeps every match at SBOM_ROW_THIN, the clean rows leave or are cut to SBOM_ROW_MIN first", async () => {
    for (const [total, affected, shape] of [[150, 40], [150, 30], [150, 20], [94, 40], [150, 40, "deb"]]) {
      const label = `${total}/${affected}${shape ? ` ${shape}` : ""}`;
      const whole = imageMix(total, affected, shape);
      stub.state.answer = whole;
      const sc = await call({ purls: whole.results.map((r) => r.purl) });
      const size = JSON.stringify(sc).length;
      assert.ok(size <= STRUCTURED_BUDGET, `${label}: ${size} characters of structured result`);
      assertDataCutOf(sc, whole, label);
      const rows = sc.data.results;
      const aff = rows.filter((r) => r.verdict === "affected");
      // Every affected row, with every match the answer gave it, each match keeping every field
      // SBOM_ROW_THIN keeps (3.0.2: 150/40 kept 150 rows and the matches of 2 of the 40 affected).
      const full = aff.filter((r) => {
        const all = whole.results[r.index].matches;
        return !r.matches_truncated && r.matches?.length === all.length && r.matches.every((m, j) => SBOM_THIN_MATCH.every((f) => Object.hasOwn(m, f) || !Object.hasOwn(all[j], f)));
      });
      assert.equal(full.length, affected, `${label}: ${full.length} of ${affected} affected rows keep every match at SBOM_ROW_THIN (${rows.length} rows kept)`);
      // A clean row kept is cut to SBOM_ROW_MIN or kept as SBOM_ROW_THIN keeps it only while every
      // affected row is at SBOM_ROW_THIN, as it is here; the ones that left are named as clean.
      const left = sc.truncated.results.total - sc.truncated.results.returned;
      assert.ok(left > 0, `${label}: no row left, so this case holds nothing`);
      assert.match(sc.notes.join(" "), new RegExp(`the ${left} left out being entries whose verdict is not_affected or not_assessed \\(data\\.summary counts every verdict\\)`), label);
      for (const r of rows.filter((x) => x.verdict === "not_affected")) assert.ok(Object.keys(r).every((k) => SBOM_ROW_MIN.includes(k) || k === "matched_package" || k === "matched_via" || k === "matches"), `${label}: clean row ${r.index} keeps ${Object.keys(r)}`);
    }
    stub.state.answer = undefined;
  });

  // #3269, in the first text block (check_sbom.ts sbomText outFirstBefore): its clean rows left
  // only once every row was cut to index, purl, verdict, not_assessed_reason and cve_ids, so the
  // same mixes' text kept every clean row and no affected row's matches, on 3.0.0 and 3.0.2 alike.
  it("the same mixes' first text block: every affected row keeps every match, the clean rows cut to the leanest level or left out first", async () => {
    for (const [total, affected, shape] of [[150, 40], [150, 30], [150, 20], [94, 40], [150, 40, "deb"]]) {
      const label = `${total}/${affected}${shape ? ` ${shape}` : ""} (text)`;
      const whole = imageMix(total, affected, shape);
      stub.state.answer = whole;
      const res = await client.callTool({ name: "check_sbom", arguments: { purls: whole.results.map((r) => r.purl) } });
      const shown = JSON.parse(res.content[0].text);
      const note = res.structuredContent.notes.join(" ");
      assert.ok(res.content[0].text.length <= STRUCTURED_BUDGET, `${label}: ${res.content[0].text.length} characters of text`);
      const aff = shown.results.filter((r) => r.verdict === "affected");
      const full = aff.filter((r) => r.matches?.length === whole.results[r.index].matches.length && r.matches.every((m) => Object.hasOwn(m, "kev_listed") && Object.hasOwn(m, "fixed_in")));
      assert.equal(full.length, affected, `${label}: ${full.length} of ${affected} affected rows keep every match in the text (${shown.results.length} rows in it)`);
      for (const r of shown.results.filter((x) => x.verdict === "not_affected")) assert.deepEqual(Object.keys(r).filter((k) => !SBOM_ROW_MIN.includes(k)), [], `${label}: clean row ${r.index} keeps more than the leanest level`);
      const left = total - shown.results.length;
      if (left > 0) assert.match(note, new RegExp(`Only ${shown.results.length} of the ${total} rows of results are in it; the other ${left} are left out of it: the ${left} whose verdict is not_affected or not_assessed \\(data\\.summary counts every verdict\\)`), label);
      if (shown.results.some((r) => r.verdict === "not_affected")) assert.match(note, /rows of results in it whose verdict is not_affected or not_assessed leave out .* too\./, label);
    }
    stub.state.answer = undefined;
  });

  it("a capped row whose KEV-listed and ransomware CVEs rank below its cap by effective_score keeps them, in the API's order", async () => {
    // One row of 300 matches, effective_score falling from 9.9 by match, its only KEV-listed CVE at
    // position 250 and its ransomware one at 280 (both far below any cap that fits), among 11 small
    // affected rows. And Juice Shop with magento/community-edition 2.3.0, whose KEV-listed
    // CVE-2025-54236 is at position 21 of its 200 (3.0.2 kept 6 of them, so cut it).
    const purls = Array.from({ length: 12 }, (_, i) => `pkg:npm/kev-${String(i).padStart(2, "0")}@1.0.0`);
    const answer = batchAnswer(
      purls.map((p, i) => {
        const ids = i === 3 ? Array.from({ length: 300 }, (_, j) => `CVE-2094-${String(10000 + j)}`) : [`CVE-2093-${1000 + 2 * i}`, `CVE-2093-${1001 + 2 * i}`];
        const row = ROWS.affected(i, p, `kev-${i}`, "1.0.0", ids);
        return {
          ...row,
          matches: row.matches.map((m, j) => ({
            ...m,
            description: `${m.description} ${"x".repeat(400)}`,
            kev_listed: i === 3 && (j === 250 || j === 280),
            ransomware: i === 3 && j === 280,
            epss_score: 0.01,
            effective_score: i === 3 ? Math.round((9.9 - j * 0.03) * 100) / 100 : 5,
            score_assessed: true,
            fixed_in: "1.0.1",
          })),
        };
      }),
    );
    for (const [label, whole, row, want] of [
      ["synthetic", answer, 3, ["CVE-2094-10250", "CVE-2094-10280"]],
      ["Juice Shop + magento", JS_MAGENTO, 2, ["CVE-2024-34102", "CVE-2025-54236"]],
    ]) {
      stub.state.answer = whole;
      const sc = await call({ purls: whole.results.map((r) => r.purl) });
      const r = sc.data.results.find((x) => x.index === row);
      assert.ok(r.matches_truncated, `${label}: row ${row} is not capped, so this case holds nothing`);
      const kept = r.matches.map((m) => m.cve_id);
      for (const id of want) assert.ok(kept.includes(id), `${label}: ${id} (KEV-listed) is not among the ${kept.length} matches row ${row} keeps; it is only in matches_truncated`);
      // The rest are the highest effective_score, and data keeps them in the API's order.
      const all = whole.results[row].matches;
      assert.deepEqual(kept, pickedMatches(all, kept.length).map((j) => all[j].cve_id), `${label}: the matches kept are not the KEV-listed ones and then the highest effective_score, in the API's order`);
      assertDataCutOf(sc, whole, label);
    }
    stub.state.answer = undefined;
  });

  it("the 201-purl probe, every row affected: each match of every row kept carries kev_listed, ransomware, epss_score, effective_score, score_assessed and fixed_in", async () => {
    stub.state.answer = probeAnswer;
    const purls = PROBE.results.map((r) => r.purl);
    const sc = await call({ purls });
    stub.state.answer = undefined;
    assert.ok(JSON.stringify(sc).length <= STRUCTURED_BUDGET);
    const rows = sc.data.results;
    const lacking = rows.filter((r) => !r.matches?.length || r.matches.some((m) => RANKED.some((f) => !Object.hasOwn(m, f) && Object.hasOwn(PROBE_BY_PURL.get(r.purl).matches.find((x) => x.cve_id === m.cve_id), f))));
    assert.deepEqual(lacking.map((r) => r.purl), [], `${lacking.length} of ${rows.length} rows kept have a match without a field workload_triage ranks by (3.0.2: 54 of 54, epss_score and score_assessed)`);
  });
});

// #3269's review (SHIP-WITH-FIXES on round 1 of the fix above).
//  1. Round 1 sent the clean and not-assessed rows out first even where the affected rows had to be
//     capped anyway, and then raised the cap with them gone, so the cap took the room and they came
//     back only into what was left: linux-libc-dev 6.1.55-1 with 100 clean Debian purls kept 1 row
//     of 101 and said "check 1 or fewer purls per call" (3.0.2 kept all 101). Now they stay while
//     every other row fits at the floor (check_sbom.ts matchFloor: its KEV-listed and ransomware
//     matches and 10 more). And the page sentence named the rows kept, which a call of that many
//     purls need not keep: Juice Shop 11.1.2 with magento/community-edition 2.3.0 said "check 19 or
//     fewer purls per call", and a call of its first 19 kept 14. It now names what a call of the
//     first that many keeps whole (PageAt.firstFit).
//  2. The first text block's clean rows, cut to the leanest level (strings to 100 characters), were
//     clipped without the note saying so.
//  3. The capped level's clause read as the order data lists the matches in.
//  5. not_affected rows leave before not_assessed ones (a not_assessed row says something was not
//     checked), in data and in the text.
// Control: round 1's build (537d7571) fails each of these but the last, which holds there too and
// guards the order workload_triage's step 6 relies on.
const LIBC = DEBIAN.results.find((r) => r.purl.includes("linux-libc-dev"));
const cleanDeb = (c) => {
  const p = `pkg:deb/debian/libclean${c}@1.2.3-1?arch=amd64&distro=debian-12`;
  return { ...CLEAN_DEB, ecosystem: "Debian:12", package: `libclean${c}`, matched_package: `libclean${c}`, version: "1.2.3-1", purl: p };
};
// One row of 200 matches (the API's most a row carries) whose 25 KEV-listed and 2 ransomware ones
// rank last by effective_score.
const KEV_HEAVY = (() => {
  const p = "pkg:npm/kev-heavy@1.0.0";
  const row = ROWS.affected(0, p, "kev-heavy", "1.0.0", Array.from({ length: 200 }, (_, j) => `CVE-2092-${String(10000 + j)}`));
  return {
    ...row,
    matches: row.matches.map((m, j) => ({
      ...m,
      description: `${m.description} ${"x".repeat(400)}`,
      kev_listed: j >= 175 || j === 160 || j === 165,
      ransomware: j === 160 || j === 165,
      epss_score: 0.01,
      effective_score: Math.round((9.9 - j * 0.03) * 100) / 100,
      score_assessed: true,
      fixed_in: "1.0.1",
    })),
  };
})();
// Every row the cases below answer, by purl; the stub answers any list of them, reindexed.
const REVIEW_ROWS = new Map([...DEBIAN.results, ...JS_MAGENTO.results, ...PROBE.results, KEV_HEAVY].map((r) => [r.purl, r]));
for (let c = 0; c < 400; c++) {
  const d = cleanDeb(c);
  REVIEW_ROWS.set(d.purl, d);
  REVIEW_ROWS.set(`pkg:npm/c${c}@1.0.0`, ROWS.notAffected(0, `pkg:npm/c${c}@1.0.0`, `c${c}`, "1.0.0"));
  REVIEW_ROWS.set(`pkg:npm/u${c}@1.0.0`, ROWS.unknown(0, `pkg:npm/u${c}@1.0.0`, `u${c}`, "1.0.0"));
  REVIEW_ROWS.set(`pkg:npm/d${c}@1.0.0`, ROWS.undetermined(0, `pkg:npm/d${c}@1.0.0`, `d${c}`, "1.0.0"));
  const mvn = `pkg:maven/org.example.some.very.long.group.name/artifact-name-that-is-quite-long-${c}@1.2.3?repository_url=https://repo.example.com/maven2&type=jar`;
  REVIEW_ROWS.set(mvn, ROWS.notAffected(0, mvn, `artifact-${c}`, "1.2.3"));
}
const reviewAnswer = (purls) => {
  if (JSON.stringify(purls) === JSON.stringify(purlsOf(DEBIAN))) return DEBIAN;
  if (JSON.stringify(purls) === JSON.stringify(purlsOf(JS_MAGENTO))) return JS_MAGENTO;
  return batchAnswer(purls.map((p, i) => ({ ...(REVIEW_ROWS.get(p) ?? ROWS.notAffected(i, p, "x", "1")), purl: p, index: i })));
};
// A seeded mix of the rows above: probe rows (affected), the recordings' large rows, Juice Shop's,
// clean npm and Debian rows, not-assessed and undetermined ones, in proportions the seed picks.
function randomMix(seed) {
  let x = seed;
  const rnd = () => ((x = (x * 1103515245 + 12345) % 2147483648), x / 2147483648);
  const big = [LIBC.purl, MAGENTO, ...DEBIAN.results.filter((r) => r !== LIBC).map((r) => r.purl), KEV_HEAVY.purl];
  const n = 1 + Math.floor(rnd() * 400);
  const [wA, wB, wC] = [rnd(), rnd() * 0.08, rnd()];
  const out = new Set();
  let c = 0;
  while (out.size < n) {
    const r = rnd();
    if (r < wA * 0.5) out.add(PROBE.results[Math.floor(rnd() * PROBE.results.length)].purl);
    else if (r < wA * 0.5 + wB) out.add(big[Math.floor(rnd() * big.length)]);
    else if (r < 0.6) out.add(wC < 0.5 ? `pkg:npm/c${c++ % 400}@1.0.0` : cleanDeb(c++ % 400).purl);
    else if (r < 0.75) out.add(cleanDeb(c++ % 400).purl);
    else if (r < 0.85) out.add(`pkg:npm/u${c++ % 400}@1.0.0`);
    else if (r < 0.9) out.add(`pkg:npm/d${c++ % 400}@1.0.0`);
    else out.add(JS_MAGENTO.results[Math.floor(rnd() * JS_MAGENTO.results.length)].purl);
  }
  return [...out];
}

describe("#3269's review: clean rows leave to keep matches, not to raise a cap; the page sentence is what a call of that many keeps", () => {
  let stub, client, tools;
  const call = async (purls) => {
    const res = await client.callTool({ name: "check_sbom", arguments: { purls } });
    assert.notEqual(res.isError, true, JSON.stringify(res.content).slice(0, 600));
    return res;
  };
  before(async () => {
    stub = await startStub();
    stub.state.answer = reviewAnswer;
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

  it("linux-libc-dev 6.1.55-1 with 100 clean Debian 12 purls (round 1: 1 row of 101, \"check 1 or fewer\"): all 101 rows, linux-libc-dev with at least its floor of matches", async () => {
    const { matchFloor } = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "check_sbom.js")).href);
    const purls = [LIBC.purl, ...Array.from({ length: 100 }, (_, c) => cleanDeb(c).purl)];
    const res = await call(purls);
    const sc = res.structuredContent;
    assert.ok(JSON.stringify(sc).length <= STRUCTURED_BUDGET);
    assertDataCutOf(sc, reviewAnswer(purls), "linux-libc-dev + 100 clean");
    assert.equal(sc.data.results.length, 101, `${sc.data.results.length} of 101 rows kept`);
    const libc = sc.data.results[0];
    assert.equal(matchFloor(LIBC), 10);
    assert.ok(libc.matches.length >= matchFloor(LIBC), `linux-libc-dev keeps ${libc.matches.length} matches, under its floor of ${matchFloor(LIBC)}`);
    assert.doesNotMatch(sc.notes.join(" "), PAGE_SAID);
  });

  it("a row of 200 matches whose 25 KEV-listed and 2 ransomware ones rank last, beside 60 clean rows: every row stays, and it keeps all 27 and 10 more", async () => {
    const purls = [KEV_HEAVY.purl, ...Array.from({ length: 60 }, (_, c) => cleanDeb(c).purl)];
    const sc = (await call(purls)).structuredContent;
    assert.equal(sc.data.results.length, 61, `${sc.data.results.length} of 61 rows kept`);
    const row = sc.data.results[0];
    const kev = row.matches.filter((m) => m.kev_listed || m.ransomware);
    assert.equal(kev.length, 27, `${kev.length} of its 27 KEV-listed or ransomware matches kept`);
    assert.ok(row.matches.length - kev.length >= 10, `${row.matches.length - kev.length} other matches kept, under the floor's 10`);
    assert.deepEqual(row.matches.map((m) => m.cve_id), pickedMatches(KEV_HEAVY.matches, row.matches.length).map((j) => KEV_HEAVY.matches[j].cve_id));
    assertDataCutOf(sc, reviewAnswer(purls), "KEV-heavy + 60 clean");
  });

  it("the page sentence holds: a call of the first N purls, N as the note names it, keeps all N rows, and so does a call of fewer (the image mixes, the recordings, Juice Shop + magento, linux-libc-dev + 100 clean, five Debian 12 + 200 clean, and 24 seeded mixes)", async () => {
    const cases = [
      ...[[150, 40], [150, 30], [150, 20], [94, 40]].flatMap(([t, a]) => [[`${t}/${a}`, imageMix(t, a)], [`${t}/${a} deb`, imageMix(t, a, "deb")]]).map(([l, w]) => [l, w.results.map((r) => r.purl)]),
      ["probe 201", PROBE.results.map((r) => r.purl)],
      ["Debian 12", purlsOf(DEBIAN)],
      ["Juice Shop + magento", purlsOf(JS_MAGENTO)],
      ["magento alone", [MAGENTO]],
      ["linux-libc-dev + 100 clean", [LIBC.purl, ...Array.from({ length: 100 }, (_, c) => cleanDeb(c).purl)]],
      ["Debian 12 + 200 clean", [...purlsOf(DEBIAN), ...Array.from({ length: 200 }, (_, c) => cleanDeb(c).purl)]],
      ...Array.from({ length: 24 }, (_, i) => [`seed ${i + 1}`, randomMix(i + 1)]),
    ];
    // imageMix's rows by purl, so the stub answers its purls and their prefixes.
    for (const [t, a, shape] of [[150, 40], [150, 30], [150, 20], [94, 40], [150, 40, "deb"], [150, 30, "deb"], [150, 20, "deb"], [94, 40, "deb"]]) for (const r of imageMix(t, a, shape).results) REVIEW_ROWS.set(r.purl, r);
    const wrong = [];
    let paged = 0;
    for (const [label, purls] of cases) {
      const res = await call(purls);
      const note = res.structuredContent.notes.join(" ");
      assert.ok(JSON.stringify(res.structuredContent).length <= STRUCTURED_BUDGET, `${label}: structured result past the budget`);
      assert.ok(res.content[0].text.length <= STRUCTURED_BUDGET, `${label}: text past the budget`);
      assert.doesNotMatch(note, /\b0 or fewer\b/, label);
      const n = Number(PAGE_SAID.exec(note)?.[1] ?? 0);
      if (!n) {
        assert.equal(res.structuredContent.data.results.length, purls.length, `${label}: rows left data and the note names no page size`);
        continue;
      }
      paged++;
      for (const k of [n, Math.max(1, Math.floor(n / 2)), Math.max(1, n - 1)]) {
        const got = (await call(purls.slice(0, k))).structuredContent.data.results.length;
        if (got < k) wrong.push(`${label}: the note says a call of the first ${n} purls keeps every row, and a call of the first ${k} keeps ${got} of ${k} rows`);
      }
    }
    assert.deepEqual(wrong, []);
    assert.ok(paged >= 12, `${paged} cases name a page size, so this holds little`);
  });

  it("the first text block's clean rows, cut to the leanest level, say that their strings keep their first 100 characters (150 purls, 40 affected, the clean ones Maven purls of about 150 characters)", async () => {
    const purls = [];
    let a = 0;
    for (let i = 0; i < 150; i++) {
      if (a < 40 && Math.floor((i * 40) / 150) >= a) purls.push(PROBE.results[a++].purl);
      else purls.push(`pkg:maven/org.example.some.very.long.group.name/artifact-name-that-is-quite-long-${i}@1.2.3?repository_url=https://repo.example.com/maven2&type=jar`);
    }
    const res = await call(purls);
    const shown = JSON.parse(res.content[0].text);
    const clipped = shown.results.filter((r) => r.verdict === "not_affected" && typeof r.purl === "string" && r.purl.endsWith("…"));
    assert.ok(clipped.length > 0, "no clean row's purl is clipped in the text, so this case holds nothing");
    assert.ok(shown.results.filter((r) => r.verdict === "affected").every((r) => !r.purl.endsWith("…")));
    assert.match(
      res.structuredContent.notes.join(" "),
      new RegExp(`The ${shown.results.filter((r) => r.verdict === "not_affected" || r.verdict === "not_assessed").length} rows of results in it whose verdict is not_affected or not_assessed leave out [^.]* too; every string in each of them longer than 100 characters keeps its first 100, ending in "…"\\.`),
    );
  });

  it("the capped level says the matches kept are chosen ransomware first, then KEV-listed, then by effective_score, and listed in the API's order, in the note and in matches_truncated's schema", async () => {
    const sc = (await call(purlsOf(JS_MAGENTO))).structuredContent;
    assert.match(sc.notes.join(" "), /each row's matches keeping at most \d+, chosen used in ransomware first, then the other KEV-listed ones, then those of highest effective_score, and listed in the API's order;/);
    assert.doesNotMatch(sc.notes.join(" "), /in the API's order: those KEV-listed or used in ransomware first/);
    const schema = JSON.stringify(tools.find((t) => t.name === "check_sbom").outputSchema);
    assert.ok(schema.includes("returned, the ones data keeps (chosen used in ransomware first, then the other KEV-listed ones, then highest effective_score, and listed in the API's order)"), "matches_truncated's description");
  });

  // #3269's review (4): the README said the text cuts the clean rows lean and sends them out
  // "before any affected row loses its matches"; where the affected rows cannot keep matches even
  // with every clean row gone (five Debian 12 purls and 200 clean ones), every row is cut to the
  // leanest level and the clean rows stay, as docs/tools.md says.
  it("the README says what the text cut does where the affected rows cannot keep their matches: every row is cut to the leanest level, and the clean rows stay (five Debian 12 purls and 200 clean)", async () => {
    const readme = readPkgFile("README.md");
    assert.doesNotMatch(readme, /leave them out before any affected row loses its matches/);
    assert.doesNotMatch(readme, /rows leave before an affected row's matches are cut/);
    assert.ok(readme.replace(/\s+/g, " ").includes("those two kinds are cut to the leanest level and leave sooner where that lets the other rows keep their matches, and where it does not, every row is cut to that level first"), "README's text-cut clause");
    assert.ok(readPkgFile("docs/tools.md").replace(/\s+/g, " ").includes("only where that cannot fit is every row cut so, and then rows leave, those two kinds first"));
    const purls = [...purlsOf(DEBIAN), ...Array.from({ length: 200 }, (_, c) => cleanDeb(c).purl)];
    const shown = JSON.parse((await call(purls)).content[0].text).results;
    assert.ok(shown.every((r) => !Object.hasOwn(r, "matches")), "a row kept matches in the text");
    assert.ok(shown.filter((r) => r.verdict === "not_affected").length > 100, `${shown.length} rows in the text`);
    assert.equal(shown.filter((r) => r.verdict === "affected").length, 5);
  });

  it("not_affected rows leave before not_assessed ones, in data and in the text (150 purls: 40 affected, 60 not_affected, 50 not_assessed)", async () => {
    const purls = [];
    for (let i = 0; i < 150; i++) purls.push(i % 15 < 4 ? PROBE.results[purls.filter((p) => p.startsWith("pkg:") && PROBE_BY_PURL.has(p)).length].purl : i % 15 < 10 ? `pkg:npm/c${i}@1.0.0` : `pkg:npm/u${i}@1.0.0`);
    const res = await call(purls);
    const whole = reviewAnswer(purls);
    const rows = res.structuredContent.data.results;
    const shown = JSON.parse(res.content[0].text).results;
    for (const [where, kept] of [["data", rows], ["text", shown]]) {
      const keptIdx = new Set(kept.map((r) => r.index));
      const out = whole.results.filter((r) => !keptIdx.has(r.index));
      assert.ok(out.length > 0, `${where}: no row left, so this case holds nothing`);
      const naOut = out.filter((r) => r.verdict === "not_assessed").length;
      const cleanIn = kept.filter((r) => r.verdict === "not_affected").length;
      assert.ok(naOut === 0 || cleanIn === 0, `${where}: ${naOut} not_assessed rows left while ${cleanIn} not_affected rows stayed`);
    }
  });
});

// #3269's second review (DO-NOT-SHIP on round 2).
//  H1. Where the floor did not fit even with every clean row gone, round 2 took the cap below it, to
//      1 at the thinned level and 0 at the compact one, then to the levels that keep no match, so
//      every affected row stayed with 1 match or none: five Debian 12 purls beside an image's 150
//      (40 affected) kept 45 affected rows, 1 with any match. Now a capped row never goes below its
//      floor (its KEV-listed and ransomware matches and 10 more, matchFloor): where the floor does
//      not fit, affected rows leave whole at it, those without a KEV-listed or ransomware match
//      first, each from the end, and the note names them by index; the one row kept where not even
//      it fits at its floor keeps the most of its matches that fit, and the note says so.
//  M2. The page sentence promises only what holds: a call of the first N purls, or of fewer.
//  L1. The text's page sentence ("check N or fewer purls per call", N the rows the text kept) was
//      false for a call of the first N in 34 of 89 mixes; there is none now, and the sentence on the
//      rows left out of the text says how many and that structuredContent.data holds them.
// Control: round 2's build (1074cc51) fails the repro, property and exception cases (each repro
// keeps every affected row under its floor there: 41 of 41 for linux-libc-dev with 150 purls) and
// the sentence cases; this build passes them.
const KEV_ALL = (() => {
  const p = "pkg:npm/kev-all@1.0.0";
  const row = ROWS.affected(0, p, "kev-all", "1.0.0", Array.from({ length: 200 }, (_, j) => `CVE-2091-${String(10000 + j)}`));
  return {
    ...row,
    matches: row.matches.map((m, j) => ({
      ...m,
      description: `${m.description} ${"x".repeat(300)}`,
      kev_listed: true,
      ransomware: j >= 195,
      epss_score: 0.01 + j / 100000,
      effective_score: Math.round((9.9 - j * 0.02) * 100) / 100,
      score_assessed: j % 2 === 0,
      fixed_in: j % 3 ? "1.0.1" : null,
      ...(j % 3 ? {} : { fixed_in_reason: "no fix on record" }),
    })),
  };
})();
REVIEW_ROWS.set(KEV_ALL.purl, KEV_ALL);
const CLEAN_VERDICTS = new Set(["not_affected", "not_assessed"]);
const hasKevMatch = (r) => (r.matches ?? []).some((m) => m.kev_listed || m.ransomware);
// The probe's one row with a KEV-listed match (log4j-core 2.14.1, at index 1), from the fixture.
const LOG4J = PROBE.results.find(hasKevMatch).purl;
// Indices as the note's clause names them ("at index 4, 7 and 10 to 12").
const indicesSaid = (said) => said.split(/, | and /).flatMap((t) => {
  const r = /^(\d+) to (\d+)$/.exec(t);
  return r ? Array.from({ length: Number(r[2]) - Number(r[1]) + 1 }, (_, j) => Number(r[1]) + j) : [Number(t)];
});
// #3269's third review: the clause on the affected and undetermined rows that left data names
// those with a KEV-listed or ransomware match first and apart ("K affected or undetermined rows:
// the K with a KEV-listed or ransomware match at index …; the other K at index …", or ", none
// with …, at index …", or ", all with …, at index …"), and the sentence after it gives the sizes of
// the calls that check them again ("Re-check these K purls in this order, in calls of 7, 5 and 8,
// then of at most 6: each such call keeps every row in data."). Round 3 named them in one list,
// in index order, and counted the KEV-bearing ones: undefined on its note.
const RUNS = String.raw`((?:\d+(?: to \d+)?)(?:(?:, | and )\d+(?: to \d+)?)*)(?:, and (\d+) more past index \d+)?`;
const LEFT_HEAD = String.raw`(?:the (\d+) left out being |(\d+) )affected or undetermined rows?`;
function leftSaid(note) {
  const g = (m) => Number(m[1] ?? m[2]);
  let m = new RegExp(`${LEFT_HEAD}: the (\\d+|one) with a KEV-listed or ransomware match at index ${RUNS}; the other (\\d+) (?:at index ${RUNS}|not named here)`).exec(note);
  if (m) return { g: g(m), kev: indicesSaid(m[4]), kevMore: Number(m[5] ?? 0), other: m[7] ? indicesSaid(m[7]) : [], otherMore: m[7] ? Number(m[8] ?? 0) : Number(m[6]) };
  if ((m = new RegExp(`${LEFT_HEAD}, (?:all with|with) a KEV-listed or ransomware match, at index ${RUNS}`).exec(note))) return { g: g(m), kev: indicesSaid(m[3]), kevMore: Number(m[4] ?? 0), other: [], otherMore: 0 };
  if ((m = new RegExp(`${LEFT_HEAD}, (?:none with|without) a KEV-listed or ransomware match, at index ${RUNS}`).exec(note))) return { g: g(m), kev: [], kevMore: 0, other: indicesSaid(m[3]), otherMore: Number(m[4] ?? 0) };
  return undefined;
}
function againSaid(note) {
  const a = /Re-check (?:these (\d+) purls|the other (\d+) of these purls) (?:in one call: it keeps every row in data\.|in this order, in calls of ([\d, and]+?)(?:, then of at most (\d+))?: each such call keeps every row in data\.)/.exec(note);
  const own = /(?:The purl at index|Each of the purls at index) ([\d, toand]+?) goes in a call of its own: its row's matches used in ransomware or KEV-listed and 10 more are past the budget even alone, so that call keeps the row with the most of them that fit, and its note says how many\./.exec(note);
  if (!a && !own) return undefined;
  const k = a ? Number(a[1] ?? a[2]) : 0;
  return { k, sizes: a ? (a[3] ? a[3].split(/, | and /).map(Number) : [k]) : [], m: a ? Number(a[4] ?? 0) : 0, alone: own ? indicesSaid(own[1]) : [] };
}
// The calls the re-check sentence gives, in order: the purls named (those with a KEV-listed or
// ransomware match first), each that goes alone in a call of its own where the order reaches it.
function againCalls(L, A) {
  const alone = new Set(A.alone);
  const calls = [];
  let chunk = [];
  let sized = 0;
  for (const i of [...L.kev, ...L.other]) {
    if (alone.has(i)) {
      calls.push([i]);
      continue;
    }
    chunk.push(i);
    if (chunk.length === (A.sizes[sized] ?? A.m)) {
      calls.push(chunk);
      chunk = [];
      sized++;
    }
  }
  if (chunk.length) calls.push(chunk);
  return calls;
}

describe("#3269's second review: a capped affected row never goes below its floor; rows leave whole at it, KEV rows last", () => {
  let stub, client;
  let matchFloor;
  const call = async (purls, full) => {
    const res = await client.callTool({ name: "check_sbom", arguments: { purls, ...(full ? { full } : {}) } });
    assert.notEqual(res.isError, true, JSON.stringify(res.content).slice(0, 600));
    return res;
  };
  // The answer whole, as the server merges its batches (a list past 200 purls is several).
  const wholeOf = async (purls) => (await call(purls, true)).structuredContent.data;
  before(async () => {
    ({ matchFloor } = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "check_sbom.js")).href));
    for (const [t, a, shape] of [[150, 40, "deb"], [300, 60, "deb"], [150, 40]]) for (const r of imageMix(t, a, shape).results) REVIEW_ROWS.set(r.purl, r);
    stub = await startStub();
    stub.state.answer = reviewAnswer;
    client = await connect({ era: MODERN, ...serverCommand(), env: { ...process.env, ECHELONGRAPH_API_BASE: stub.base, ECHELONGRAPH_API_TIMEOUT_MS: "5000" }, stderr: "inherit" });
  });
  after(async () => {
    try {
      await client?.close();
    } finally {
      await stub?.close();
    }
  });

  // What every answer here holds to: the floor (but for the one row kept alone below it, which the
  // note names), no clean row kept while a row of the rest left, the rows of the rest that left
  // named by index, exactly, and none with a KEV-listed match while a row without one stayed unless
  // it does not fit beside the KEV rows kept. Returns the counts the cases compare.
  const floorHolds = (label, res, whole) => {
    const sc = res.structuredContent;
    const note = sc.notes.join(" ");
    assert.ok(JSON.stringify(sc).length <= STRUCTURED_BUDGET, `${label}: structured result past the budget`);
    assertDataCutOf(sc, whole, label);
    assert.doesNotMatch(note, /\b0 or fewer\b/, label);
    const rows = sc.data.results;
    const under = rows.filter((r) => !CLEAN_VERDICTS.has(r.verdict) && (r.matches?.length ?? 0) < matchFloor(whole.results[r.index]));
    if (rows.length === 1 && under.length === 1) assert.match(note, new RegExp(`the one row kept keeping ${rows[0].matches?.length ?? 0} of its matches, fewer than its matches used in ransomware or KEV-listed and 10 more, since no more fit beside it`), label);
    else assert.deepEqual(under.map((r) => `${r.index}: ${r.matches?.length ?? 0} < ${matchFloor(whole.results[r.index])}`), [], `${label}: affected rows kept under their floor`);
    const keptIdx = new Set(rows.map((r) => r.index));
    const out = whole.results.filter((r) => !keptIdx.has(r.index));
    const restOut = out.filter((r) => !CLEAN_VERDICTS.has(r.verdict));
    if (restOut.length) assert.deepEqual(rows.filter((r) => CLEAN_VERDICTS.has(r.verdict)).map((r) => r.index), [], `${label}: clean rows stayed while ${restOut.length} affected rows left`);
    const L = leftSaid(note);
    if (restOut.length) {
      assert.ok(L, `${label}: ${restOut.length} affected rows left and the note names none by index`);
      assert.equal(L.g, restOut.length, label);
      // #3269's third review: those with a KEV-listed or ransomware match first and apart, each
      // list ascending; past OTHERS_LEFT_LISTED (100) indices or runs of them in all, the note names
      // the first and counts the rest.
      for (const [which, said, more, want] of [
        ["KEV-bearing", L.kev, L.kevMore, restOut.filter(hasKevMatch)],
        ["other", L.other, L.otherMore, restOut.filter((r) => !hasKevMatch(r))],
      ]) {
        const ids = want.map((r) => r.index).sort((a, b) => a - b);
        assert.deepEqual(said, ids.slice(0, said.length), `${label}: the note's ${which} indices are not the ${which} rows that left`);
        assert.equal(more, ids.length - said.length, `${label}: ${which}`);
      }
      const A = againSaid(note);
      assert.ok(A, `${label}: no sentence says how to check the rows left out again`);
      assert.equal(A.k + A.alone.length, L.kev.length + L.other.length, `${label}: the re-check sentence counts other rows than the note names`);
    } else assert.equal(L, undefined, label);
    const affected = rows.filter((r) => r.verdict === "affected");
    const every = affected.filter((r) => !r.matches_truncated && (r.matches?.length ?? 0) === (whole.results[r.index].matches?.length ?? 0)).length;
    const atFloor = affected.filter((r) => (r.matches?.length ?? 0) >= matchFloor(whole.results[r.index])).length;
    return { rows: rows.length, affected: affected.length, every, atFloor, restOut };
  };

  // 3.0.2 (a5217d8f) kept 26, 41, 40 and 33 affected rows with every match or at least the floor
  // here, at its compact level of five fields a match (cve_id, kev_listed, ransomware, fixed_in and
  // effective_score); #3270 keeps epss_score and score_assessed at every level that keeps matches,
  // which makes each probe row about 22% larger, so fewer fit: 16, 32, 31 and 23. With 3.0.2's five
  // fields this cut keeps 25, 41, 40 and 32 (the rest is the longer note: the indices and the page
  // sentence). Round 2 (1074cc51) kept 45, 41, 61 and 59, each under its floor: 1, 0, 1 and 3
  // of them with every match.
  for (const [label, purls, least] of [
    ["five Debian 12 purls and 150 of an image's (40 affected)", () => [...purlsOf(DEBIAN), ...imageMix(150, 40, "deb").results.map((r) => r.purl)], 16],
    ["linux-libc-dev 6.1.55-1 and 150 of an image's (40 affected)", () => [LIBC.purl, ...imageMix(150, 40, "deb").results.map((r) => r.purl)], 32],
    ["linux-libc-dev 6.1.55-1 and 300 of an image's (60 affected)", () => [LIBC.purl, ...imageMix(300, 60, "deb").results.map((r) => r.purl)], 31],
    ["Juice Shop 11.1.2 with magento/community-edition 2.3.0, and 150 more purls (40 affected)", () => [...purlsOf(JS_MAGENTO), ...imageMix(150, 40).results.map((r) => r.purl)], 23],
  ]) {
    it(`${label}: every affected row kept keeps at least its floor, the rest leave whole, named by index`, async () => {
      const list = purls();
      const res = await call(list);
      const c = floorHolds(label, res, await wholeOf(list));
      assert.ok(c.restOut.length > 0, `${label}: no affected row left, so this case holds nothing`);
      assert.ok(c.atFloor >= least, `${label}: ${c.atFloor} affected rows with every match or at least the floor (${c.every} with every match), under ${least}`);
      assert.equal(c.atFloor, c.affected, label);
      // Rows without a KEV-listed or ransomware match left first: log4j-core 2.14.1 stays.
      assert.ok(res.structuredContent.data.results.some((r) => r.purl === LOG4J), `${label}: log4j-core left`);
    });
  }

  it("the floor holds on 24 seeded mixes, the image mixes and the KEV-heavy rows: no affected row kept under min(its floor, its matches) but the one row kept alone, and no clean row kept beside an affected row left", async () => {
    const cases = [
      ...Array.from({ length: 24 }, (_, i) => [`seed ${i + 1}`, randomMix(i + 1)]),
      ...[[150, 40, "deb"], [300, 60, "deb"], [150, 40]].map(([t, a, shape]) => [`${t}/${a}${shape ? ` ${shape}` : ""}`, imageMix(t, a, shape).results.map((r) => r.purl)]),
      ["KEV-heavy + 150/40", [KEV_HEAVY.purl, ...imageMix(150, 40).results.map((r) => r.purl)]],
      ["KEV-heavy + linux-libc-dev + magento + 100 clean", [KEV_HEAVY.purl, LIBC.purl, MAGENTO, ...Array.from({ length: 100 }, (_, c) => cleanDeb(c).purl)]],
      ["probe 201 + KEV-heavy", [...PROBE.results.map((r) => r.purl), KEV_HEAVY.purl]],
    ];
    let left = 0;
    for (const [label, purls] of cases) {
      const c = floorHolds(label, await call(purls), await wholeOf(purls));
      left += c.restOut.length > 0 ? 1 : 0;
    }
    assert.ok(left >= 8, `${left} cases leave affected rows, so this holds little`);
  });

  it("one row whose floor alone is past the budget (200 matches, every one KEV-listed): it stays alone with the most of them that fit, ransomware first, and the note says so; beside 150 purls of an image it leaves instead, named by index, and the others keep their floor", async () => {
    const alone = (await call([KEV_ALL.purl])).structuredContent;
    const [row] = alone.data.results;
    assert.equal(alone.data.results.length, 1);
    assert.equal(matchFloor(KEV_ALL), 200);
    assert.ok(row.matches.length > 0 && row.matches.length < 200, `${row.matches.length} matches kept`);
    assert.deepEqual(row.matches.map((m) => m.cve_id), pickedMatches(KEV_ALL.matches, row.matches.length).map((j) => KEV_ALL.matches[j].cve_id));
    assert.equal(row.matches.filter((m) => m.ransomware).length, 5, "a ransomware match was cut");
    assert.equal(row.matches_truncated.kev_listed_cve_ids.length, 200);
    floorHolds("KEV-all alone", { structuredContent: alone }, await wholeOf([KEV_ALL.purl]));
    // Beside an image's purls, after them: in the plain leaving order every row without a KEV
    // match left before it, and it could not fit, so 1 row of 151 stayed (7,572 characters).
    const purls = [...imageMix(150, 40).results.map((r) => r.purl), KEV_ALL.purl];
    const res = await call(purls);
    const c = floorHolds("150/40 + KEV-all", res, await wholeOf(purls));
    assert.ok(c.affected >= 30, `${c.affected} affected rows kept`);
    assert.deepEqual(c.restOut.map((r) => r.purl), [KEV_ALL.purl]);
    assert.match(res.structuredContent.notes.join(" "), /and 1 affected or undetermined row, with a KEV-listed or ransomware match, at index 150 \(kept: rows with one first/);
    // #3269's third review: no call of it beside other purls keeps it at its floor, so the note
    // sends it to a call of its own, which keeps it with the most of its matches that fit.
    assert.deepEqual(againSaid(res.structuredContent.notes.join(" ")), { k: 0, sizes: [], m: 0, alone: [150] });
    assert.doesNotMatch(res.structuredContent.notes.join(" "), /Re-check /);
  });

  it("the page sentences promise only what holds (M2), and the text has none (L1)", async () => {
    const list = [LIBC.purl, ...imageMix(300, 60, "deb").results.map((r) => r.purl)];
    const res = await call(list);
    const note = res.structuredContent.notes.join(" ");
    assert.match(note, PAGE_SAID);
    assert.doesNotMatch(note, /To read every row in data/);
    assert.doesNotMatch(note, /To read every row in the text/);
    const shown = JSON.parse(res.content[0].text).results;
    assert.ok(shown.length < list.length, "the text keeps every row, so this case holds nothing");
    assert.match(note, new RegExp(`Only ${shown.length} of the ${list.length} rows of results are in it; the other ${list.length - shown.length} are left out of it: .*?, and structuredContent\\.data holds them with full: true\\.`));
    const { manifestPageSaid } = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "scan_manifest.js")).href);
    assert.equal(manifestPageSaid(12), "A call whose files hold the first 12 of these purls, or fewer, keeps every row in data; a call of other files says in its own note what it leaves out.");
  });
});

// #3269's third review (round 3, 9f97d479):
//  F1. The note named the affected and undetermined rows that left data in one list, in index
//      order, and counted those with a KEV-listed or ransomware match; workload_triage's step 6
//      checked them again in that order and stopped after 5 calls, so on old unpatched Debian
//      images, where those rows come late, 119 of 255 were in view after it.
//  F2. Step 6 sized its calls by the page sentence's N, which holds for the first N purls of the
//      call; the rows left out are the heavy ones, so its calls dropped 504 of 2,540 rows on
//      realistic images.
// Now the note names the rows with a KEV-listed or ransomware match first and apart, and a sentence
// gives the sizes of calls of them, in that order, that keep every row: the first 5 calls each the
// most of those left that fit, then at most M a call (textBudget.ts PageAt.againFit, counted for
// those rows), and the rows that go in a call of their own. An old unpatched image's shape, from
// the recorded Debian 12 matches: 60 light rows first (2 to 5 matches), then rows of 12 to 52
// matches, those with a KEV-listed match among them, and a clean row in every 4.
// Control: on 9f97d479 the note has neither the split nor the sentence (both cases fail at their
// first assertion), and its step 6 (index order, at N, 5 calls) puts 26 and 27 of the 37 and 36
// KEV-bearing rows in view and drops 47 and 45 rows.
function oldImage(seedArg) {
  const pool = DEBIAN.results.flatMap((r) => r.matches);
  const tpl = DEBIAN.results.find((r) => r.matched_via === "upstream") ?? DEBIAN.results[0];
  const clean = JS_MAGENTO.results.find((r) => r.verdict === "not_affected");
  let seed = seedArg;
  const rnd = () => ((seed = (seed * 1103515245 + 12345) % 2147483648), seed / 2147483648);
  const rows = [];
  for (let i = 0; i < 160; i++) {
    if (i % 4 === 3) {
      rows.push({ ...clean, purl: `pkg:deb/debian/clean${seedArg}-${i}@1.0-1?arch=amd64&distro=debian-12`, index: i });
      continue;
    }
    const light = i < 60;
    const n = light ? 2 + Math.floor(rnd() * 4) : 12 + Math.floor(rnd() * rnd() * 40);
    const kev = !light && i >= 50 && rnd() < 0.45;
    const ms = Array.from({ length: n }, (_, j) => ({ ...pool[Math.floor(rnd() * pool.length)], cve_id: `CVE-2095-${10000 + i * 100 + j}`, kev_listed: kev && j % 5 === 0, ransomware: false }));
    rows.push({ ...tpl, index: i, purl: `pkg:deb/debian/old${seedArg}-${i}@1.0-1?arch=amd64&upstream=src${i}&distro=debian-12`, package: `old${seedArg}-${i}`, matched_package: `src${i}`, verdict: "affected", matches: ms, cve_ids: ms.map((m) => m.cve_id), count: n });
  }
  return rows;
}

describe("#3269's third review: the rows left out are named KEV-bearing first, and checked again in calls that keep every row", () => {
  let stub, client, RECHECK_CALLS;
  const rowsBy = new Map();
  const call = async (purls) => {
    const res = await client.callTool({ name: "check_sbom", arguments: { purls } });
    assert.notEqual(res.isError, true, JSON.stringify(res.content).slice(0, 600));
    return res.structuredContent;
  };
  const images = [11, 12].map((seed) => [seed, oldImage(seed)]);
  before(async () => {
    ({ RECHECK_CALLS } = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "check_sbom.js")).href));
    for (const [, rows] of images) for (const r of rows) rowsBy.set(r.purl, r);
    stub = await startStub();
    stub.state.answer = (purls) => batchAnswer(purls.map((p, i) => ({ ...(rowsBy.get(p) ?? REVIEW_ROWS.get(p) ?? ROWS.notAffected(i, p, "x", "1")), purl: p, index: i })));
    client = await connect({ era: MODERN, ...serverCommand(), env: { ...process.env, ECHELONGRAPH_API_BASE: stub.base, ECHELONGRAPH_API_TIMEOUT_MS: "5000" }, stderr: "inherit" });
  });
  after(async () => {
    try {
      await client?.close();
    } finally {
      await stub?.close();
    }
  });
  const kevSeen = (rows) => rows.filter((r) => r.verdict === "affected" && (r.matches ?? []).some((m) => m.kev_listed || m.ransomware)).map((r) => r.purl);

  for (const [seed, rows] of images) {
    it(`F1, old unpatched image ${seed}: the note names the rows left out with a KEV-listed match first and apart, and ${5} calls in its order put every KEV-bearing row in view (round 3's index order at N: fewer)`, async () => {
      const purls = rows.map((r) => r.purl);
      const sc = await call(purls);
      const note = sc.notes.join(" ");
      const L = leftSaid(note);
      assert.ok(L, "the note does not name the rows with a KEV-listed or ransomware match apart");
      const kept = new Set(sc.data.results.map((r) => r.index));
      const out = rows.filter((r) => r.verdict !== "not_affected" && !kept.has(r.index));
      assert.deepEqual(L.kev, out.filter(hasKevMatch).map((r) => r.index), "the KEV-bearing rows left out");
      assert.deepEqual(L.other, out.filter((r) => !hasKevMatch(r)).map((r) => r.index), "the other rows left out");
      assert.ok(L.kev.length >= 20 && L.kev.some((i) => i > L.other[0]), `${L.kev.length} KEV-bearing rows left, so this case holds little`);
      const A = againSaid(note);
      assert.ok(A, "no re-check sentence");
      const all = rows.filter(hasKevMatch).map((r) => r.purl);
      const seen = new Set(kevSeen(sc.data.results));
      for (const chunk of againCalls(L, A).slice(0, RECHECK_CALLS)) for (const p of kevSeen((await call(chunk.map((i) => purls[i]))).data.results)) seen.add(p);
      assert.deepEqual(all.filter((p) => !seen.has(p)), [], `KEV-bearing rows out of view after ${RECHECK_CALLS} calls in the note's order`);
      // Control: round 3's step 6, the same rows in index order, N (the page sentence's) a call.
      const N = Number(PAGE_SAID.exec(note)?.[1]);
      const byIndex = [...L.kev, ...L.other].sort((a, b) => a - b);
      const was = new Set(kevSeen(sc.data.results));
      for (let c = 0; c < RECHECK_CALLS && c * N < byIndex.length; c++) for (const p of kevSeen((await call(byIndex.slice(c * N, c * N + N).map((i) => purls[i]))).data.results)) was.add(p);
      assert.ok(was.size < all.length, `index order at N puts ${was.size} of ${all.length} in view too, so this case holds nothing`);
    });

    it(`F2, old unpatched image ${seed}: every call the re-check sentence gives keeps every row it sends, all of them, within the budget (round 3's N, a size for the call's first purls, drops rows of these)`, async () => {
      const purls = rows.map((r) => r.purl);
      const sc = await call(purls);
      const note = sc.notes.join(" ");
      const L = leftSaid(note);
      const A = againSaid(note);
      assert.ok(L && A, "no re-check sentence");
      assert.equal(A.sizes.length, RECHECK_CALLS, "the note gives the sizes of the first calls");
      const calls = againCalls(L, A);
      assert.ok(calls.length > RECHECK_CALLS, `${calls.length} calls, so the size after the first ones holds nothing here`);
      const dropped = [];
      for (const chunk of calls) {
        const r = await call(chunk.map((i) => purls[i]));
        assert.ok(JSON.stringify(r).length <= STRUCTURED_BUDGET);
        if (r.data.results.length < chunk.length) dropped.push(`${chunk.length} sent, ${r.data.results.length} kept`);
        assert.equal(r.truncated?.results?.returned ?? chunk.length, chunk.length);
      }
      assert.deepEqual(dropped, [], "a call the note gives dropped rows");
      // Control: chunks of the page sentence's N of the same rows, in index order, drop some.
      const N = Number(PAGE_SAID.exec(note)?.[1]);
      const byIndex = [...L.kev, ...L.other].sort((a, b) => a - b);
      let lost = 0;
      for (let c = 0; c < RECHECK_CALLS; c++) {
        const chunk = byIndex.slice(c * N, c * N + N);
        if (chunk.length) lost += chunk.length - (await call(chunk.map((i) => purls[i]))).data.results.length;
      }
      assert.ok(lost > 0, "calls of N of these rows keep them all, so this case holds nothing");
    });
  }
});

// #3284: the structured cut keeps the rows with a KEV-listed or ransomware match first
// (SBOM_LEAVE_LAST), while the first text block left rows from the end in input order, so a
// KEV-bearing row data kept could leave the text and be named in no text block and in no note (the
// DATA CUT sentence names rows left out of data only). The reviewer's text-only client (the first
// text block and the note, then workload_triage's step 6) missed 95 of 413 KEV-bearing rows on 36
// realistic Debian-12 images and 23 of 119 on the 2,000-purl and image-mix sets at d42d4697. The
// text now keeps such rows last to leave, as check_affected keeps its KEV-listed matches (#2899),
// and names by index each one that still leaves. Replayed on the probe's rows, three times over
// (600 purls, re-keyed), with its one KEV-bearing row (log4j-core 2.14.1) put last. Control: the
// same answer through the same TextCut without leaveOutLast (d42d4697's cut) leaves that row out
// first.
describe("#3284: check_sbom's first text block keeps the KEV-bearing rows last to leave, and names by index any that leave", () => {
  let stub, client;
  const call = async (args) => {
    const res = await client.callTool({ name: "check_sbom", arguments: args });
    assert.notEqual(res.isError, true, JSON.stringify(res.content).slice(0, 600));
    return res;
  };
  const KEV_ROW = PROBE_BY_PURL.get(LOG4J);
  const PLAIN = PROBE.results.filter((r) => r.purl !== LOG4J);
  // 599 rows without a KEV-listed or ransomware match, then the KEV-bearing one, each its own purl.
  const ROWS_600 = [...Array.from({ length: 599 }, (_, i) => ({ ...PLAIN[i % PLAIN.length], purl: `pkg:npm/kev-last-${i}@1.0.0` })), KEV_ROW];
  const BY = new Map(ROWS_600.map((r) => [r.purl, r]));
  // With kevAll, each row's first match KEV-listed.
  let kevAll = false;
  before(async () => {
    stub = await startStub();
    stub.state.answer = (purls) =>
      batchAnswer(
        purls.map((p, i) => {
          const r = { ...(BY.get(p) ?? PROBE_BY_PURL.get(p)), index: i };
          return kevAll ? { ...r, matches: (r.matches ?? []).map((m, j) => (j === 0 ? { ...m, kev_listed: true } : m)) } : r;
        }),
      );
    client = await connect({ era: MODERN, ...serverCommand(), env: { ...process.env, ECHELONGRAPH_API_BASE: stub.base, ECHELONGRAPH_API_TIMEOUT_MS: "5000" }, stderr: "inherit" });
  });
  after(async () => {
    try {
      await client?.close();
    } finally {
      await stub?.close();
    }
  });
  const TB = () => import(pathToFileURL(path.join(PKG_DIR, "dist", "textBudget.js")).href);
  const SB = () => import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "check_sbom.js")).href);

  it("the KEV-bearing row put last of 600 stays in the text while rows before it leave; d42d4697's cut leaves it out first", async () => {
    kevAll = false;
    const purls = ROWS_600.map((r) => r.purl);
    const n = purls.length;
    const res = await call({ purls });
    const shown = JSON.parse(res.content[0].text).results;
    const note = res.content[1].text;
    const gone = n - shown.length;
    assert.ok(gone > 0, `the text keeps all ${n} rows, so this case does not test the cut`);
    assert.ok(shown.some((r) => r.index === n - 1 && r.purl === LOG4J), "the KEV-bearing row left the text while rows before it stayed");
    assert.deepEqual(shown.map((r) => r.index), [...[...Array(shown.length - 1).keys()], n - 1], "the rows kept are the first in order and the KEV-bearing one");
    assert.ok(note.includes(`Only ${shown.length} of the ${n} rows of results are in it; the other ${gone} are left out of it, the last ${gone} without a KEV-listed or ransomware match, and structuredContent.data holds them with full: true.`), note);
    assert.doesNotMatch(note, /Of the rows left out of it/, "no KEV-bearing row left, so none is named");
    // The replay is the server's own cut.
    const whole = (await call({ purls, full: true })).structuredContent.data;
    const { dataText } = await TB();
    const { sbomText } = await SB();
    assert.equal(dataText(whole, sbomText(n)).text, res.content[0].text, "the replay is not the server's cut");
    // Control: without leaveOutLast the row leaves first, from the end.
    const old = JSON.parse(dataText(whole, { ...sbomText(n), leaveOutLast: undefined }).text).results;
    assert.ok(!old.some((r) => r.index === n - 1), "the control does not show d42d4697's cut");
    assert.deepEqual(old.map((r) => r.index), [...Array(old.length).keys()], "d42d4697's cut kept the first rows in order");
  });

  it("every row KEV-bearing: rows leave from the end, and the note names each one left out by index, in runs", async () => {
    kevAll = true;
    try {
      const purls = ROWS_600.map((r) => r.purl);
      const res = await call({ purls });
      const shown = JSON.parse(res.content[0].text).results;
      const n = purls.length;
      const gone = n - shown.length;
      assert.ok(gone > 0);
      assert.deepEqual(shown.map((r) => r.index), [...Array(shown.length).keys()], "the rows kept are the first, in order");
      const named = `Of the rows left out of it, ${gone} have a KEV-listed or ransomware match: at index ${shown.length} to ${n - 1}.`;
      const note = res.content[1].text;
      assert.ok(note.includes(`the other ${gone} are left out of it, the last ${gone} in order, and structuredContent.data holds them with full: true. ${named}`), note);
      // The same sentence is in structuredContent's notes, which the last text block carries too.
      assert.ok(res.structuredContent.notes.includes(named));
      assert.ok(JSON.stringify(res.structuredContent).length <= STRUCTURED_BUDGET);
    } finally {
      kevAll = false;
    }
  });
});
