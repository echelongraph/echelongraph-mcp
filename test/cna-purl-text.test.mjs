// #3767: what the server says of an answer that only the CVE record's CNA makes (#3757).
//
// Since #3757 core-backend's registry matcher (internal/cve/pkgmatch_cnapurl.go) also decides, for a language registry's
// package, a CVE that no OSV advisory record names the package for, where the CVE record's CNA names the
// package by its package URL (purl): the match says match_method "cna package url", version_evidence cna_affected_range,
// matched_criteria the CNA's purl and match_confidence 0.8, and a CNA statement alone never clears a package (a package
// no advisory record names stays assessed false, package_not_in_advisory_corpus, unless one calls the version affected;
// cve_remediation's installed verdict for such a CVE is affected or not_assessed). Through 3.2.2 the tools said the
// registry path decides "each OSV advisory EchelonGraph holds for that package", named no CNA record as a source, and
// cve_remediation called the CNA's fixed_in "as the advisory states it" where no advisory names the package.
//
// What is under test, each with 3.2.2's wording as its control:
//   - check_affected's description names, on the registry path, the CVEs only the CVE record's CNA names by purl;
//   - the method strings of check_affected and of the batch route (check_sbom, scan_manifest) name the CNA's statement
//     as a source, and that it alone never makes a package clean;
//   - the output schemas describe match_method's cna package url, the undetermined reasons cna_range_status_unknown and
//     cna_range_undecidable_scheme, what not_affected_count counts beside assessed false, and the installed verdict;
//   - the notes, on production's answers of 2026-11-11 (test/fixtures/cna-purl-wire.json) for npm suneditor 3.3.0 and
//     3.4.0, Maven org.apache.tomee:openejb-http 11.0.0 and CVE-2026-124494: check_affected names the matches only the
//     CNA makes, check_sbom and scan_manifest count them, the not-assessed reason no longer says the package was "not
//     located" and, where CNA records were read, says how many and that the name is not in doubt, the 0-match note says
//     a CNA-only CVE may be among those not_affected_count counts (#3825), and cve_remediation says the installed
//     fixed_in is the CNA's, not an advisory's; the UNDETERMINED sentence naming the CNA is held on an answer written in
//     core-backend's shape, not read from production (cna_only_not_assessed: production served no such answer to us);
//   - every answer validates against its tool's outputSchema (strict-output.mjs).
// One test is a relay check, not a 3.2.3 change: cve_remediation's not_assessed reason is relayed as 3.2.2 relays it, and
// its name says so.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { StrictOutputValidator } from "./strict-output.mjs";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { PKG_DIR, serverCommand } from "./server-under-test.mjs";
import { BATCH_PATH, ROWS, batchAnswer } from "./fixtures/match-batch.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WIRE = JSON.parse(fs.readFileSync(path.join(HERE, "fixtures", "cna-purl-wire.json"), "utf8"));
const CA = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "check_affected.js")).href);
const MB = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "match_batch.js")).href);

// 3.2.2's sentences: the controls.
const OLD_REGISTRY_SENTENCE =
  "The registry path takes ecosystem (npm, PyPI, Maven and other OSV ecosystem names), package and version, and decides each OSV advisory EchelonGraph holds for that package as affected, not affected or undetermined.";
const OLD_REGISTRY_METHOD =
  "EchelonGraph's registry matcher, the matcher behind echelongraph.io/am-i-affected for a registry package: the OSV advisory records EchelonGraph holds for this package in this ecosystem, each decided against this version as affected, not affected, or undetermined (and, once its API reads them, the CVE record's CNA statements beside each).";
const OLD_BATCH_METHOD =
  "EchelonGraph's registry advisory matcher (POST /api/v1/public/cves/match/batch): each component's purl is mapped to its OSV ecosystem, package name and version, and matched against the affected version ranges EchelonGraph holds from OSV.dev advisory records, the same matcher GET /api/v1/public/cves/match uses when given an ecosystem. No CPE matching, no score, no ranking.";
const OLD_NOT_IN_CORPUS = "so the package was not located, not cleared";
const OLD_CLEARED = "decided not to affect this version (not_affected_count, one per CVE however many of its advisory records are stored), and only those are cleared.";
const OLD_REMEDIATION_METHOD_CLAUSE = "An installed version's verdict and fixed_in are the registry matcher's";
const OLD_UNDETERMINED = /CVEs? with advisories naming this package could not be decided/;

// The registry path's sentence of check_affected's description, and what it lacks.
const REGISTRY_SENTENCE = /The registry path takes [^.]*\./;
export function cnaDescriptionProblems(description) {
  const s = description.match(REGISTRY_SENTENCE)?.[0];
  if (!s) return ["the description has no registry-path sentence"];
  const out = [];
  if (!/\bCNA\b/.test(s)) out.push(`the registry path's sentence names no CNA record: "${s}"`);
  if (!/\bpurl\b|package URL/.test(s)) out.push(`the registry path's sentence names no package URL (purl): "${s}"`);
  if (/decides each OSV advisory EchelonGraph holds for that package as affected/.test(s)) out.push("the registry path's sentence says it decides OSV advisories alone");
  // Within the client cut (src/requiredText.ts CLIENT_DESCRIPTION_CUT), as every claim of the description is.
  if (description.indexOf(s) + s.length > 2048) out.push("the registry path's sentence ends past the 2,048-character client cut");
  return out;
}
// A method string's account of the CNA-only source, and what it lacks. check_affected's says it in full; the batch
// route's, in every check_sbom and scan_manifest answer's text and structured result, in about 3.2.2's length (the
// 201-purl probe's cut keeps its 43 rows within a few characters of it: check_sbom-large-rows.test.mjs).
export function cnaMethodProblems(method) {
  const out = [];
  if (!method.includes("(match_method cna package url)")) out.push("names no match_method cna package url");
  if (!/each CVE no advisory record holds for it whose CVE record's CNA names it by package URL|for a language package's CVE none names, its CNA's purl statement/.test(method)) {
    out.push("does not name the CVE record's CNA statement by package URL as the source of a CVE no advisory record names the package for");
  }
  if (!/A package only CNA records name is never answered clean|never clean alone/.test(method)) out.push("does not say a CNA statement alone never clears");
  if (!/language registry's package|language package's/.test(method)) out.push("does not say it is read for a language registry's package only");
  return out;
}

// The descriptions of every property named `name` in a schema, at any depth.
function propertyDescriptions(schema, name, out = []) {
  if (Array.isArray(schema)) for (const x of schema) propertyDescriptions(x, name, out);
  else if (schema && typeof schema === "object") {
    for (const [k, v] of Object.entries(schema.properties ?? {})) if (k === name && typeof v?.description === "string") out.push(v.description);
    for (const v of Object.values(schema)) propertyDescriptions(v, name, out);
  }
  return out;
}

describe("#3767: the CNA-only purl source, in descriptions and methods (with 3.2.2's wording as the control)", () => {
  it("check_affected's description names the CVEs only the CVE record's CNA names by purl on the registry path", () => {
    assert.deepEqual(cnaDescriptionProblems(CA.CHECK_AFFECTED_DESCRIPTION), []);
    assert.ok(CA.CHECK_AFFECTED_DESCRIPTION.length <= 2048 - 100, `${CA.CHECK_AFFECTED_DESCRIPTION.length} characters, inside #2924's 100 under the cut`);
    // Control: 3.2.2's sentence, put back.
    const old = CA.CHECK_AFFECTED_DESCRIPTION.replace(REGISTRY_SENTENCE, OLD_REGISTRY_SENTENCE);
    assert.notEqual(old, CA.CHECK_AFFECTED_DESCRIPTION);
    const p = cnaDescriptionProblems(old);
    assert.ok(p.some((x) => x.startsWith("the registry path's sentence names no CNA record")), p.join("\n"));
    assert.ok(p.includes("the registry path's sentence says it decides OSV advisories alone"), p.join("\n"));
  });
  it("check_affected's registry method and the batch route's method name the CNA's statement, read for a language registry's package, and that it alone never clears", () => {
    assert.deepEqual(cnaMethodProblems(CA.REGISTRY_METHOD), []);
    assert.deepEqual(cnaMethodProblems(MB.METHOD), []);
    assert.match(CA.REGISTRY_METHOD, /A package only CNA records name is never answered clean\.$/);
    // The registries named, as core-backend's registryEcosystems has them (cve/pkgmatch.go): npm, PyPI, Maven and nine more.
    assert.ok(CA.REGISTRY_METHOD.includes("(npm, PyPI, Maven and nine other registries; not a Linux distribution's, CRAN's or Hackage's)"), CA.REGISTRY_METHOD);
    assert.doesNotMatch(CA.REGISTRY_METHOD, /and the like/);
    // Controls: 3.2.2's.
    assert.equal(cnaMethodProblems(OLD_REGISTRY_METHOD).length, 4, cnaMethodProblems(OLD_REGISTRY_METHOD).join("\n"));
    assert.equal(cnaMethodProblems(OLD_BATCH_METHOD).length, 4, cnaMethodProblems(OLD_BATCH_METHOD).join("\n"));
  });
});

// The stub: GET .../match answers state.match; a batch row for state.purl is state.match as core-backend's matchbatch.go
// makes a row of it, any other purl not affected; .../remediation answers state.remediation.
const verdictOf = (b) =>
  b.assessed && b.count > 0 ? "affected" : (b.assessed && b.undetermined_count > 0) || (!b.assessed && b.not_assessed_reason === "no_decidable_advisory") ? "undetermined" : b.assessed ? "not_affected" : "not_assessed";
const state = { match: null, purl: null, remediation: null };
let stub;
let client;
let tools;
const validator = new StrictOutputValidator();
before(async () => {
  stub = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const send = (o) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(o));
      };
      if (req.url === "/api/v1/public/cves/match") return send(state.match);
      if (req.url === BATCH_PATH && req.method === "POST") {
        const purls = JSON.parse(body).components.map((c) => c.purl);
        return send(
          batchAnswer(
            purls.map((p, i) =>
              p === state.purl ? { ...state.match, index: i, input_kind: "purl", purl: p, verdict: verdictOf(state.match) } : ROWS.notAffected(i, p, p.slice(8).split("@")[0], p.split("@")[1]),
            ),
          ),
        );
      }
      if (state.remediation && req.url === `/api/v1/public/cves/${state.remediation.cve_id}/remediation`) return send(state.remediation);
      res.writeHead(404, { "content-type": "application/json" });
      res.end('{"error":"not found"}');
    });
  });
  await new Promise((resolve) => stub.listen(0, "127.0.0.1", resolve));
  client = await connect({
    era: MODERN,
    ...serverCommand(),
    env: { ...process.env, ECHELONGRAPH_API_BASE: `http://127.0.0.1:${stub.address().port}`, ECHELONGRAPH_API_TIMEOUT_MS: "5000" },
    stderr: "inherit",
  });
  ({ tools } = await client.listTools());
});
after(async () => {
  try {
    await client?.close();
  } finally {
    await new Promise((resolve) => stub.close(resolve));
  }
});

const textBlocks = (res) => (res.content ?? []).filter((c) => c.type === "text").map((c) => c.text);
const noteOf = (res) => textBlocks(res)[res.isError ? 0 : 1] ?? "";
const schemaOf = (name) => tools.find((t) => t.name === name).outputSchema;
async function call(name, args) {
  const res = await client.callTool({ name, arguments: args });
  assert.notEqual(res.isError, true, noteOf(res));
  const v = validator.getValidator(schemaOf(name))(res.structuredContent);
  assert.ok(v.valid, `${name}: ${JSON.stringify(v.errors ?? v.errorMessage)}`);
  return res;
}
const asRegistryPackage = (m) => ({ ...m, match_method: "registry package", match_confidence: 0.95, version_evidence: "advisory_interval" });

describe("#3767: the output schemas describe the CNA-only values", () => {
  it("match_method names cna package url, and undetermined[].reason the two reasons only a CNA-only CVE gives", () => {
    const ca = schemaOf("check_affected");
    const method = propertyDescriptions(ca, "match_method");
    assert.ok(method.length > 0 && method.every((d) => d.includes("cna package url") && d.includes("match_confidence 0.8")), method.join("\n"));
    const reason = propertyDescriptions(ca, "reason");
    assert.ok(reason.some((d) => d.includes("cna_range_status_unknown") && d.includes("cna_range_undecidable_scheme")), reason.join("\n"));
    assert.ok(reason.some((d) => d.includes("(on the CPE path, version_not_comparable: a CPE range the version has no order against)")), reason.join("\n"));
    const notAffected = propertyDescriptions(ca, "not_affected_count");
    assert.ok(notAffected.some((d) => /each CVE only its CNA names the package for once, decided or not/.test(d) && /CNA records only, and is not a clean answer/.test(d)), notAffected.join("\n"));
    // version_evidence, in every tool that relays a registry match.
    for (const t of ["check_affected", "check_sbom", "scan_manifest", "cve_remediation"]) {
      const ve = propertyDescriptions(schemaOf(t), "version_evidence");
      assert.ok(ve.length > 0 && ve.every((d) => d.includes("match_method is cna package url, no advisory record names the package for the CVE at all")), `${t}: ${ve.join("\n")}`);
    }
  });
  it("cve_remediation's installed verdict and fixed_in say a CVE only the CNA names the package for is not cleared by it", () => {
    const rem = schemaOf("cve_remediation");
    const verdict = propertyDescriptions(rem, "verdict");
    assert.ok(verdict.some((d) => d.includes("or only the CVE record's CNA names it, by package URL, and does not call this version affected, which alone never clears it")), verdict.join("\n"));
    assert.ok(verdict.every((d) => !d.includes("the record names no such package for this CVE, or the lookup did not run")), "3.2.2's verdict sentence");
    assert.ok(verdict.some((d) => d.includes("not_assessed (no advisory record, and no CNA package URL, names the package for this CVE;")), verdict.join("\n"));
    const fixedIn = propertyDescriptions(rem, "fixed_in");
    assert.ok(fixedIn.some((d) => d.includes("or, where installed.version_evidence is cna_affected_range, the CVE record's CNA range")), fixedIn.join("\n"));
  });
});

describe("#3767: the notes on production's CNA-only answers (npm suneditor 3.3.0 and 3.4.0, Maven tomee openejb-http 11.0.0, 2026-11-11)", () => {
  it("check_affected names the matches only the CNA makes, and its method says so", async () => {
    state.match = WIRE.match;
    const res = await call("check_affected", { ecosystem: "npm", package: "suneditor", version: "3.3.0" });
    const sc = res.structuredContent;
    assert.equal(sc.state, "measured");
    assert.equal(sc.method, CA.REGISTRY_METHOD);
    assert.deepEqual(sc.data.matches.map((m) => [m.cve_id, m.match_method, m.match_confidence, m.version_evidence]), [
      ["CVE-2026-124494", "cna package url", 0.8, "cna_affected_range"],
      ["CVE-2026-124422", "cna package url", 0.8, "cna_affected_range"],
    ]);
    const note = noteOf(res);
    assert.ok(
      note.includes(
        "AFFECTED: 2 CVEs match this version. Every match is on the CVE record's CNA statement alone (match_method cna package url: CVE-2026-124494, CVE-2026-124422): no OSV advisory record names this package for those CVEs, so the CNA is the only source.",
      ),
      note,
    );
    // Control: the same matches, made from an advisory record.
    state.match = { ...WIRE.match, matches: WIRE.match.matches.map(asRegistryPackage) };
    assert.doesNotMatch(noteOf(await call("check_affected", { ecosystem: "npm", package: "suneditor", version: "3.3.0" })), /CNA statement alone/);
    // One of two.
    state.match = { ...WIRE.match, matches: [WIRE.match.matches[0], asRegistryPackage(WIRE.match.matches[1])] };
    assert.match(noteOf(await call("check_affected", { ecosystem: "npm", package: "suneditor", version: "3.3.0" })), / 1 match is on the CVE record's CNA statement alone \(match_method cna package url: CVE-2026-124494\): no OSV advisory record names this package for that CVE, so the CNA is the only source\./);
  });
  it("check_affected: a package only CNA records name is not assessed, and its undetermined CVEs name the CNA (an answer in core-backend's shape, not read from production)", async () => {
    state.match = WIRE.cna_only_not_assessed;
    const res = await call("check_affected", { ecosystem: "npm", package: "cna-only-pkg", version: "1.0.0" });
    const sc = res.structuredContent;
    assert.equal(sc.state, "not_assessed");
    assert.equal(sc.coverage.not_assessed_reason, "package_not_in_advisory_corpus");
    const note = noteOf(res);
    assert.ok(
      note.includes(
        "(not_assessed_reason package_not_in_advisory_corpus): EchelonGraph holds no advisory record for this package in this ecosystem, so the package was not cleared: a CVE record's CNA may name it by package URL, but a CNA statement alone never clears a package (such CVEs are counted in not_affected_count or listed in undetermined, never as a clean answer). 3 CVE records' CNAs name this package by package URL (advisories_considered 3); none calls this version affected, so the name is not in doubt, and a CNA statement alone never clears it.",
      ),
      note,
    );
    assert.ok(!note.includes(OLD_NOT_IN_CORPUS), note);
    assert.ok(
      note.includes(
        "UNDETERMINED: 2 CVEs whose advisory records name this package, or whose CVE record's CNA names it by package URL, could not be decided at this version (undetermined_count, one per CVE, listed in undetermined): report them as undetermined, never as safe.",
      ),
      note,
    );
    assert.doesNotMatch(note, OLD_UNDETERMINED);
    assert.doesNotMatch(note, /found nothing|a measured result|are cleared|AFFECTED: \d/);
    assert.deepEqual(sc.data.undetermined.map((u) => u.reason), ["cna_range_status_unknown", "cna_range_undecidable_scheme"]);
  });
  it("check_affected: no_decidable_advisory names a CVE no advisory holds whose CNA statement could not be decided", async () => {
    state.match = { ...WIRE.cna_only_not_assessed, not_assessed_reason: "no_decidable_advisory", not_affected_count: 0 };
    assert.match(
      noteOf(await call("check_affected", { ecosystem: "npm", package: "cna-only-pkg", version: "1.0.0" })),
      /or a CVE no advisory holds whose CNA statement for the package could not be decided\)\./,
    );
  });
  it("check_affected: production's tomee openejb-http 11.0.0, named only by CNA purls, says how many CNAs name it and that the name is not in doubt", async () => {
    state.match = WIRE.match_not_in_corpus;
    const args = { ecosystem: "Maven", package: "org.apache.tomee:openejb-http", version: "11.0.0" };
    const res = await call("check_affected", args);
    assert.equal(res.structuredContent.state, "not_assessed");
    assert.equal(res.structuredContent.coverage.not_assessed_reason, "package_not_in_advisory_corpus");
    const note = noteOf(res);
    assert.ok(
      note.includes(
        "never as a clean answer). 7 CVE records' CNAs name this package by package URL (advisories_considered 7); none calls this version affected, so the name is not in doubt, and a CNA statement alone never clears it. A count of 0 here does not mean this version is not affected",
      ),
      note,
    );
    // Where CNA records were read, the name is not said to be worth checking, and 3.2.2's "not located" is gone.
    assert.ok(!note.includes("the ecosystem and package name are worth checking") && !note.includes(OLD_NOT_IN_CORPUS), note);
    assert.doesNotMatch(note, /found nothing|a measured result|are cleared/);
    // Control: the same answer with no record read (advisories_considered 0) says the name is worth checking, and names
    // no CNA count; 3.2.2 said neither sentence of the CNAs.
    state.match = { ...WIRE.match_not_in_corpus, advisories_considered: 0, not_affected_count: 0 };
    const none = noteOf(await call("check_affected", args));
    assert.ok(none.includes("never as a clean answer); the ecosystem and package name are worth checking. A count of 0"), none);
    assert.doesNotMatch(none, /name this package by package URL \(advisories_considered|not in doubt/);
    // One record: the singular.
    state.match = { ...WIRE.match_not_in_corpus, advisories_considered: 1, not_affected_count: 1 };
    assert.ok(
      noteOf(await call("check_affected", args)).includes(
        " 1 CVE record's CNA names this package by package URL (advisories_considered 1); it does not call this version affected, so the name is not in doubt, and a CNA statement alone never clears it.",
      ),
    );
  });
  it("check_affected: production's suneditor 3.4.0, assessed with 0 matches, says a CNA-only CVE may be among not_affected_count's, which cve_remediation answers not_assessed (#3825)", async () => {
    state.match = WIRE.match_cleared;
    const res = await call("check_affected", { ecosystem: "npm", package: "suneditor", version: "3.4.0" });
    assert.equal(res.structuredContent.state, "measured");
    const note = noteOf(res);
    assert.ok(
      note.includes(
        "4 CVEs were decided not to affect this version (not_affected_count, one per CVE however many of its records are stored), and only those are cleared; a CVE no advisory record names the package for counts here where its CNA's purl statement calls this version unaffected, on that statement alone, and cve_remediation answers that CVE not_assessed.",
      ),
      note,
    );
    // Control: 3.2.2's sentence counted them as advisory records.
    assert.ok(!note.includes(OLD_CLEARED), note);
  });
  it("check_affected on the CPE path says its undetermined CVEs are the CPE ranges', not advisories'", async () => {
    state.match = {
      assessed: true, candidate_count: 3, candidates_capped: false, capped: false, count: 0, excluded: [], excluded_count: 0, match_layer: "cpe", matches: [], not_assessed_reason: "",
      product: "openssl", product_named_count: 3, undecidable_excluded_count: 0, undecided_candidate_count: 0, vendor: "", vendor_advisory_count: 0, version: "3.0.0",
      undetermined_count: 1, undetermined: [{ cve_id: "CVE-2099-37572", reason: "version_not_comparable" }],
    };
    const note = noteOf(await call("check_affected", { product: "openssl", version: "3.0.0" }));
    assert.match(note, /UNDETERMINED: 1 CVE whose NVD CPE match criteria name this product could not be decided at this version/);
    assert.doesNotMatch(note, /advisor|CNA/);
  });
  for (const [tool, args] of [
    ["check_sbom", { purls: ["pkg:npm/suneditor@3.3.0", "pkg:npm/left-pad@1.3.0"] }],
    [
      "scan_manifest",
      {
        files: [
          {
            filename: "package-lock.json",
            content: JSON.stringify({ name: "app", lockfileVersion: 3, requires: true, packages: { "": { name: "app", version: "1.0.0" }, "node_modules/suneditor": { version: "3.3.0" }, "node_modules/left-pad": { version: "1.3.0" } } }),
          },
        ],
      },
    ],
  ]) {
    it(`${tool} counts the matches only the CNA makes, and its method names the CNA's statement`, async () => {
      state.match = WIRE.match;
      state.purl = "pkg:npm/suneditor@3.3.0";
      const res = await call(tool, args);
      assert.equal(res.structuredContent.method, MB.METHOD);
      const row = res.structuredContent.data.results.find((r) => r.purl === state.purl);
      assert.equal(row.verdict, "affected");
      const note = noteOf(res);
      assert.ok(note.includes("2 matches, on 1 component, are on the CVE record's CNA statement alone (match_method cna package url): no OSV advisory record names the package for those CVEs, so the CNA is the only source."), note);
      // Control: the same row, made from an advisory record.
      state.match = { ...WIRE.match, matches: WIRE.match.matches.map(asRegistryPackage) };
      assert.doesNotMatch(noteOf(await call(tool, args)), /CNA statement alone/);
    });
  }
  it("cve_remediation: the installed fixed_in is the CNA's, not an advisory's, and fixed_branches holds no advisory range", async () => {
    state.remediation = WIRE.remediation_affected;
    const res = await call("cve_remediation", { cve_id: "CVE-2026-124494", ecosystem: "npm", package: "suneditor", version: "3.3.0" });
    const note = noteOf(res);
    assert.ok(
      note.includes(
        "For the installed version asked (npm suneditor 3.3.0), installed.verdict is affected and fixed_in is 3.4.0: the fixed bound of the affected range [0, 3.4.0) that holds it, as the CVE record's CNA states it, not an advisory (installed.version_evidence cna_affected_range); EchelonGraph has not tested it.",
      ),
      note,
    );
    assert.doesNotMatch(note, /as the advisory states it/);
    // The method names the records the installed verdict is decided on, and that check_affected counts the CVE where
    // cve_remediation does not clear it (#3825); 3.2.2's had no installed-verdict sentence, and round 1's called it "the
    // registry matcher's".
    const method = res.structuredContent.method;
    assert.ok(
      method.includes(
        "An installed version's verdict and fixed_in are decided on the records check_affected's registry path reads: the OSV advisory records, with the CVE record's CNA statements read beside them, and, where none names the package for the CVE, the CNA's purl statement alone, which gives affected or not_assessed here, never not_affected, though check_affected counts such a CVE in not_affected_count where the CNA calls the version unaffected.",
      ),
      method,
    );
    assert.ok(!method.includes(OLD_REMEDIATION_METHOD_CLAUSE), method);
    assert.ok(note.includes("fixed_branches is empty: no advisory record's affected package range is on record (the CVE record's own CNA ranges are not listed in it), which is not a finding that no fix exists."), note);
    // Control: the same answer, decided on an advisory interval.
    state.remediation = { ...WIRE.remediation_affected, installed: { ...WIRE.remediation_affected.installed, version_evidence: "advisory_interval" } };
    assert.match(noteOf(await call("cve_remediation", { cve_id: "CVE-2026-124494", ecosystem: "npm", package: "suneditor", version: "3.3.0" })), /\[0, 3\.4\.0\) that holds it, as the advisory states it;/);
  });
  // A relay check, not a control of a 3.2.3 change: 3.2.2 relays this answer the same way, and passes it.
  it("cve_remediation relays production's not_assessed for a version the CNA does not call affected, its reason as sent (a relay check: 3.2.2 passes it too)", async () => {
    state.remediation = WIRE.remediation_not_assessed;
    const res = await call("cve_remediation", { cve_id: "CVE-2026-124494", ecosystem: "npm", package: "suneditor", version: "3.4.0" });
    assert.equal(res.structuredContent.data.installed.verdict, "not_assessed");
    assert.ok(noteOf(res).includes(`installed.verdict is not_assessed and fixed_in is null: ${WIRE.remediation_not_assessed.fixed_in_reason}.`), noteOf(res));
  });
});
