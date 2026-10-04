// check_sbom (#2721) against a stub of POST /api/v1/public/cves/match/batch, over both protocol
// eras, with every structured result validated against the tool's advertised outputSchema by ajv
// (as the SDK ships it, which is what an MCP client runs).
//
// Fixtures, both real documents:
//   fixtures/juice-shop-11.1.2-50.cdx.json  50 components of OWASP Juice Shop 11.1.2's CycloneDX
//       1.2 SBOM, verbatim (CycloneDX/bom-examples, SBOM/juice-shop/v11.1.2/bom.json, fetched
//       2026-10-03; Apache-2.0): its known-vulnerable direct dependencies first (jsonwebtoken
//       0.1.0, express-jwt 0.1.3, sanitize-html 1.4.2, lodash 4.17.19, …), then the document's
//       first components to 50. Top-level fields and metadata as in the original.
//   fixtures/SPDXJSONExample-v2.3.spdx.json  the SPDX project's own SPDX 2.3 JSON example
//       (spdx/tools-java testResources, fetched 2026-10-03; Apache-2.0), verbatim: 4 packages,
//       one with a purl externalRef.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { AjvJsonSchemaValidator } from "@modelcontextprotocol/server/validators/ajv";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { serverCommand } from "./server-under-test.mjs";
import { BATCH_PATH, ROWS, batchAnswer } from "./fixtures/match-batch.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name) => fs.readFileSync(path.join(HERE, "fixtures", name), "utf8");
const CDX_TEXT = fixture("juice-shop-11.1.2-50.cdx.json");
const CDX = JSON.parse(CDX_TEXT);
const SPDX = JSON.parse(fixture("SPDXJSONExample-v2.3.spdx.json"));
const CDX_PURLS = CDX.components.map((c) => c.purl);
const TOOL = "check_sbom";
// What the shipped texts must never claim (tools.test.mjs REMOVED_CLAIMS), and the unit they must
// never use for a count.
const REMOVED_CLAIMS = /passive|no other|unique|real-?time|\blive\b|right now/i;

// Components the stub calls affected, by package name, with the CVE ids it returns. The ids are
// the stub's; the production check (the report) is what proves real ones come back.
const STUB_AFFECTED = { jsonwebtoken: ["CVE-2015-9235"], "express-jwt": ["CVE-2020-15084"], "sanitize-html": ["CVE-2016-1000237", "CVE-2017-16016"], lodash: ["CVE-2020-8203", "CVE-2021-23337"] };
const STUB_UNDETERMINED = new Set(["moment"]);
const STUB_TIME_BUDGET = new Set(["sequelize"]);

// The stub's answer to a batch: one row per purl, in order, by the rules above.
function answerFor(purls) {
  const rows = purls.map((p, i) => {
    const m = /^pkg:npm\/(?:%40[^/]+\/)?([^@]+)@(.+)$/.exec(p);
    if (/^pkg:(deb|apk|rpm)\//.test(p) && !/[?&]distro=/.test(p)) return ROWS.distro(i, p);
    if (!m) return ROWS.malformed(i, p);
    const [, name, version] = m;
    if (STUB_AFFECTED[name]) return ROWS.affected(i, p, name, version, STUB_AFFECTED[name]);
    if (STUB_UNDETERMINED.has(name)) return ROWS.undetermined(i, p, name, version);
    if (STUB_TIME_BUDGET.has(name)) return ROWS.timeBudget(i, p, name, version);
    if (name.length % 2 === 0) return ROWS.notAffected(i, p, name, version);
    return ROWS.unknown(i, p, name, version);
  });
  return batchAnswer(rows);
}

async function startStub() {
  const state = { mode: "ok", requests: [] };
  const pending = new Set();
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      state.requests.push({ method: req.method, url: req.url, headers: req.headers, body });
      const send = (status, ctype, b) => {
        res.writeHead(status, { "content-type": ctype });
        res.end(b);
      };
      if (state.mode === "hang") {
        pending.add(res);
        return;
      }
      if (req.url !== BATCH_PATH || req.method !== "POST") return send(404, "text/plain", "404 page not found\n");
      switch (state.mode) {
        case "400":
          return send(400, "application/json", JSON.stringify({ error: "components is required and must hold at least one component", code: "NO_COMPONENTS" }));
        case "429":
          return send(429, "application/json", JSON.stringify({ error: "component budget exceeded", code: "RATE_LIMIT_EXCEEDED", cost: 50, limit: 1200, retry_after: 30 }));
        case "html":
          return send(200, "text/html", "<!doctype html><html></html>");
        case "allUnknown": {
          const { components } = JSON.parse(body);
          return send(200, "application/json", JSON.stringify(batchAnswer(components.map((c, i) => ROWS.unknown(i, c.purl, "x", "1")))));
        }
        default: {
          const { components } = JSON.parse(body);
          return send(200, "application/json", JSON.stringify(answerFor(components.map((c) => c.purl))));
        }
      }
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return {
    state,
    base: `http://127.0.0.1:${server.address().port}`,
    close: () => {
      for (const r of pending) r.destroy();
      server.closeAllConnections();
      return new Promise((r) => server.close(r));
    },
  };
}

const textBlocks = (res) => (res.content ?? []).filter((c) => c.type === "text").map((c) => c.text);
const noteOf = (res) => textBlocks(res)[res.isError ? 0 : 1] ?? "";
const validator = new AjvJsonSchemaValidator();

for (const era of [MODERN, "2025-06-18"]) {
  describe(`check_sbom [${era}]`, () => {
    let stub, client, tool;
    const collected = [];
    const call = async (args) => {
      const res = await client.callTool({ name: TOOL, arguments: args });
      collected.push([args, res]);
      return res;
    };
    before(async () => {
      stub = await startStub();
      client = await connect({ era, ...serverCommand(), env: { ...process.env, ECHELONGRAPH_API_BASE: stub.base, ECHELONGRAPH_API_TIMEOUT_MS: "1500" }, stderr: "inherit" });
      const { tools } = await client.listTools();
      tool = tools.find((t) => t.name === TOOL);
    });
    after(async () => {
      try {
        await client?.close();
      } finally {
        await stub?.close();
      }
    });
    const fresh = (mode = "ok") => {
      stub.state.mode = mode;
      stub.state.requests.length = 0;
    };

    it("is listed with a title, read-only annotations, an inputSchema and an outputSchema", () => {
      assert.ok(tool, "check_sbom is not in tools/list");
      assert.ok(tool.title && tool.outputSchema && tool.inputSchema, JSON.stringify(tool).slice(0, 300));
      assert.equal(tool.annotations.readOnlyHint, true);
      assert.deepEqual(Object.keys(tool.inputSchema.properties).sort(), ["purls", "sbom"]);
      assert.doesNotMatch(tool.description, REMOVED_CLAIMS);
      assert.doesNotMatch(tool.description, /\bhosts\b/i);
      assert.match(tool.description, /not_affected is the only clean verdict/);
      assert.match(tool.description, /distro qualifier naming its release/);
    });

    describe("a real CycloneDX SBOM (OWASP Juice Shop 11.1.2, 50 components)", () => {
      let res, req;
      before(async () => {
        fresh();
        res = await call({ sbom: CDX });
        [req] = stub.state.requests;
      });
      it("sends one POST of exactly the document's purls, in order, in the body and not the URL", () => {
        assert.equal(stub.state.requests.length, 1);
        assert.equal(req.method, "POST");
        assert.equal(req.url, BATCH_PATH, "nothing typed may travel in the URL (#1983)");
        assert.match(req.headers["content-type"], /^application\/json/);
        assert.deepEqual(JSON.parse(req.body), { components: CDX_PURLS.map((purl) => ({ purl })) });
      });
      it("sends nothing else of the document", () => {
        for (const s of ["bomFormat", "serialNumber", CDX.serialNumber, "juice-shop", "licenses", "hashes", "description"]) {
          assert.ok(!req.body.includes(s), `the request body carries ${s}`);
        }
      });
      it("answers a measured success whose data is the API's JSON and whose coverage says what was read and sent", () => {
        assert.notEqual(res.isError, true, textBlocks(res).join("\n"));
        const sc = res.structuredContent;
        assert.equal(sc.state, "measured");
        assert.equal(sc.measured_at, null);
        assert.equal(sc.freshness, null);
        assert.deepEqual(JSON.parse(textBlocks(res)[0]), sc.data);
        assert.deepEqual(sc.data, answerFor(CDX_PURLS));
        assert.deepEqual(sc.coverage, { input: "cyclonedx", components_in_document: 50, with_purl: 50, without_purl: 0, duplicates_removed: 0, sent: 50, not_assessed: sc.data.summary.not_assessed, partial: true });
      });
      it("the note gives every verdict's count, names the affected components with their CVEs, and says what time_budget means", () => {
        const s = res.structuredContent.data.summary;
        const note = noteOf(res);
        assert.match(note, /^check_sbom OK: EchelonGraph answered HTTP 200 from /);
        assert.ok(note.includes(`Read 50 components from the CycloneDX document: 50 with a purl; sent 50.`), note);
        assert.ok(note.includes(`Of the 50 components checked: ${s.affected} affected, ${s.not_affected} not affected, ${s.undetermined} undetermined, ${s.not_assessed} not assessed.`), note);
        assert.ok(s.affected === 4 && s.undetermined === 1 && s.not_assessed > 0, JSON.stringify(s));
        assert.ok(note.includes("pkg:npm/jsonwebtoken@0.1.0 (CVE-2015-9235)"), note);
        assert.ok(note.includes("pkg:npm/sanitize-html@1.4.2 (CVE-2016-1000237, CVE-2017-16016)"), note);
        assert.match(note, /time_budget 1/);
        assert.match(note, /time budget ran out before 1 component was looked up: it is not assessed, not clean/);
      });
      it("the envelope's own notes always state the distro-release refusal and that not_assessed is never clean", () => {
        const notes = res.structuredContent.notes;
        assert.ok(notes.some((n) => /distro qualifier naming its release/.test(n) && /does not guess one/.test(n)), notes.join("\n"));
        assert.ok(notes.some((n) => /Only not_affected is a clean verdict/.test(n)), notes.join("\n"));
        // The last text block repeats the envelope less data and the note (#2440, #2467).
        const env = JSON.parse(textBlocks(res).at(-1));
        assert.equal(env.data, undefined);
        assert.ok(env.notes.some((n) => /distro qualifier/.test(n)));
      });
    });

    it("reads the same CycloneDX document passed as JSON text", async () => {
      fresh();
      const res = await call({ sbom: CDX_TEXT });
      assert.notEqual(res.isError, true);
      assert.deepEqual(JSON.parse(stub.state.requests[0].body).components.map((c) => c.purl), CDX_PURLS);
      assert.equal(res.structuredContent.coverage.input, "cyclonedx");
    });

    it("reads a real SPDX 2.3 JSON document: the one package with a purl is sent, the three without are counted, not clean", async () => {
      fresh();
      const res = await call({ sbom: SPDX });
      assert.notEqual(res.isError, true, textBlocks(res).join("\n"));
      assert.deepEqual(JSON.parse(stub.state.requests[0].body), { components: [{ purl: "pkg:maven/org.apache.jena/apache-jena@3.12.0" }] });
      assert.deepEqual(res.structuredContent.coverage, { input: "spdx", components_in_document: 4, with_purl: 1, without_purl: 3, duplicates_removed: 0, sent: 1, not_assessed: 1, partial: false });
      assert.match(noteOf(res), /Read 4 packages from the SPDX document: 1 with a purl, and 3 without one, which were not checked and are not clean; sent 1\./);
    });

    it("a purl list: duplicates sent once, a deb purl without a distro and a malformed purl come back not assessed with their reasons", async () => {
      fresh();
      const purls = ["pkg:npm/lodash@4.17.19", "pkg:deb/debian/openssl@3.0.11-1~deb12u1", "not-a-purl", "pkg:npm/lodash@4.17.19"];
      const res = await call({ purls });
      assert.notEqual(res.isError, true);
      assert.deepEqual(JSON.parse(stub.state.requests[0].body).components.map((c) => c.purl), purls.slice(0, 3));
      const rows = res.structuredContent.data.results;
      assert.equal(rows[1].not_assessed_reason, "distro_release_unknown");
      assert.equal(rows[2].not_assessed_reason, "invalid_component");
      const note = noteOf(res);
      assert.match(note, /Sent 3 purls \(1 duplicate was sent once\)\./);
      assert.match(note, /1 affected, 0 not affected, 0 undetermined, 2 not assessed\./);
      assert.match(note, /Not assessed, by not_assessed_reason: distro_release_unknown 1, invalid_component 1\./);
      assert.equal(res.structuredContent.coverage.duplicates_removed, 1);
    });

    it("an answer with no verdict at all is not_assessed, not measured, and never reads as clean", async () => {
      fresh("allUnknown");
      const res = await call({ purls: ["pkg:npm/a@1", "pkg:npm/b@1"] });
      assert.notEqual(res.isError, true);
      assert.equal(res.structuredContent.state, "not_assessed");
      assert.match(noteOf(res), /0 affected, 0 not affected, 0 undetermined, 2 not assessed\./);
      assert.doesNotMatch(noteOf(res), /\bclean\b(?![^.]*not)/i);
    });

    describe("refused locally: invalid_input, and no request is made", () => {
      const cases = [
        ["neither argument", {}, /exactly one of purls/],
        ["both arguments", { purls: ["pkg:npm/a@1"], sbom: CDX }, /exactly one of purls/],
        ["201 distinct purls", { purls: Array.from({ length: 201 }, (_, i) => `pkg:npm/p${i}@1.0.0`) }, /201 distinct purls; at most 200 .* split the list/],
        ["sbom that is not JSON", { sbom: "<bom xmlns='http://cyclonedx.org/schema/bom/1.5'/>" }, /sbom is not JSON/],
        ["a JSON object that is neither format", { sbom: { hello: "world" } }, /neither a CycloneDX JSON document .* nor an SPDX JSON document/],
        ["a CycloneDX document whose components carry no purl", { sbom: { bomFormat: "CycloneDX", specVersion: "1.5", components: [{ type: "library", name: "x", version: "1" }] } }, /holds 1 components and none carries a purl/],
        ["an oversized sbom", { sbom: "x".repeat(5_000_001) }, /at most 5000000 are read/],
      ];
      for (const [name, args, why] of cases) {
        it(name, async () => {
          fresh();
          const res = await call(args);
          assert.equal(res.isError, true);
          assert.equal(res.structuredContent.state, "invalid_input");
          assert.match(textBlocks(res)[0], why);
          assert.match(textBlocks(res)[0], /Nothing was looked up, so this is not a finding/);
          assert.equal(stub.state.requests.length, 0, `${name}: a request was made`);
        });
      }
    });

    describe("upstream failures are failures, never an all-clear", () => {
      it("HTTP 400 is invalid_input, quoting the API", async () => {
        fresh("400");
        const res = await call({ purls: ["pkg:npm/a@1"] });
        assert.equal(res.isError, true);
        assert.equal(res.structuredContent.state, "invalid_input");
        assert.match(textBlocks(res)[0], /HTTP 400 from .* for POST \/api\/v1\/public\/cves\/match\/batch/);
      });
      it("HTTP 429 is failed, names POST, and says it is not a finding", async () => {
        fresh("429");
        const res = await call({ sbom: CDX });
        assert.equal(res.isError, true);
        assert.equal(res.structuredContent.state, "failed");
        assert.match(textBlocks(res)[0], /answered HTTP 429 from .* for POST \/api\/v1\/public\/cves\/match\/batch — the API said: component budget exceeded/);
        assert.match(textBlocks(res)[0], /this is not a finding/);
      });
      it("a 200 that is not JSON is failed", async () => {
        fresh("html");
        const res = await call({ purls: ["pkg:npm/a@1"] });
        assert.equal(res.isError, true);
        assert.match(textBlocks(res)[0], /was not JSON/);
      });
      it("no answer within the timeout is failed and names POST", async () => {
        fresh("hang");
        const res = await call({ purls: ["pkg:npm/a@1"] });
        assert.equal(res.isError, true);
        assert.match(textBlocks(res)[0], /did not answer POST \/api\/v1\/public\/cves\/match\/batch within 1500 ms/);
      });
    });

    it("ajv: every structured result above validates against check_sbom's outputSchema", () => {
      assert.ok(collected.length >= 16, `only ${collected.length} results collected`);
      const v = validator.getValidator(tool.outputSchema);
      for (const [args, res] of collected) {
        const r = v(res.structuredContent);
        assert.ok(r.valid, `${JSON.stringify(args).slice(0, 80)}: ${r.errorMessage}\n${JSON.stringify(res.structuredContent).slice(0, 400)}`);
        assert.equal(res.structuredContent.state === "failed" || res.structuredContent.state === "invalid_input", res.isError === true);
      }
    });
    it("ajv control: the schema refuses a success without coverage counts", () => {
      const [, res] = collected.find(([, r]) => !r.isError);
      const broken = { ...res.structuredContent, coverage: { ...res.structuredContent.coverage, sent: "50" } };
      assert.equal(validator.getValidator(tool.outputSchema)(broken).valid, false);
    });
  });
}
