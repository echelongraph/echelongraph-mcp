// #2316: the hosted remote endpoint (dist/http.js) over Streamable HTTP, both eras, against a
// stub API on 127.0.0.1. Nothing leaves the machine.
//
// What it holds, in #2316's "Done means" order where a local test can hold it:
//   1. a modern server/discover answers 200 application/json with a DiscoverResult (asserted on
//      the JSON, not the status);
//   2. a legacy initialize with 2025-06-18 (and 2025-11-25) succeeds, and the legacy leg serves
//      tools/call;
//   3. tools/call cve_summary carries exactly what the API answered for /api/v1/public/cves/summary,
//      and the structured result validates against the tool's own outputSchema;
//   4. a modern request without MCP-Protocol-Version is 400 with -32020;
//   5. the Origin policy: absent and https served, "null", non-https and malformed refused;
//   6. over the per-client limit: OUR JSON-RPC error (429, -32029, application/json), per client;
// plus the request-body cap, the access log (no body, no query, no typed value), the forward
// headers the API keys remote users on (#2212), that the npm stdio entry never sends them, the
// requests an instance serves at once (#2773) and the listen streams that are not among them, and
// what stops when a client goes (#2775). The memory those bounds keep the instance under is
// test/http-memory.test.mjs.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import http2 from "node:http2";
import net from "node:net";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawn } from "node:child_process";
import { AjvJsonSchemaValidator } from "@modelcontextprotocol/server/validators/ajv";
import { connect, MODERN, SERVER_INFO_META_KEY } from "./mcp-stdio-client.mjs";
import { ACCEPT, legacy, modern, modernHeaders, modernMeta, parseRpcBody, post } from "./mcp-http-client.mjs";
import { PKG, PKG_DIR, readPkgFile, serverCommand } from "./server-under-test.mjs";
import { BATCH_PATH, ROWS, batchAnswer } from "./fixtures/match-batch.mjs";

const HTTP_ENTRY = path.join(PKG_DIR, "dist", "http.js");
const FIVE = ["cve_summary", "search_cves", "get_cve", "cve_exposure", "exposure_radar"];
const SUMMARY = { summary: { critical: 1, high: 2, medium: 3, low: 4, none: 0, total: 10, last_updated: "2026-09-27T01:00:00Z" } };
const TOKEN = "forward-token-for-tests-2316";
const MARKER = "zzmarkerterm2316";
// The platform's chain for a direct client at `addr` (core-backend ratelimitkey_test.go).
const chain = (addr) => `${addr}, 169.254.169.126, 0.0.0.0`;
const validator = new AjvJsonSchemaValidator();

// ── the stub API ──
let stub;
const seen = []; // { path, url, clientIp, token }
const batchPurls = []; // every purl check_sbom sent the batch route
before(async () => {
  stub = http.createServer((req, res) => {
    const u = new URL(req.url, "http://stub");
    seen.push({ path: u.pathname, url: req.url, clientIp: req.headers["x-eg-client-ip"], token: req.headers["x-eg-mcp-forward"], search: req.headers["x-eg-search"] });
    if (u.pathname === "/api/v1/public/cves/summary") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(SUMMARY));
      return;
    }
    if (u.pathname === BATCH_PATH && req.method === "POST") {
      let b = "";
      req.on("data", (c) => (b += c));
      req.on("end", () => {
        const { components } = JSON.parse(b);
        batchPurls.push(...components.map((c) => c.purl));
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(batchAnswer(components.map((c, i) => ROWS.notAffected(i, c.purl, "x", "1")))));
      });
      return;
    }
    res.writeHead(404, { "content-type": "text/plain" });
    res.end("404 page not found\n");
  });
  await new Promise((resolve) => stub.listen(0, "127.0.0.1", resolve));
});
after(() => new Promise((resolve) => stub.close(resolve)));
const stubBase = () => `http://127.0.0.1:${stub.address().port}`;

// ── the server under test ──
// Spawns dist/http.js on an ephemeral port and resolves once it logs that it is listening.
// stdout is kept line by line: it is the access log the tests read.
async function startHttp(extraEnv = {}) {
  const env = {
    ...process.env,
    PORT: "0",
    ECHELONGRAPH_API_BASE: stubBase(),
    ECHELONGRAPH_API_TIMEOUT_MS: "2000",
    ECHELONGRAPH_FORWARD_TOKEN: TOKEN,
    ECHELONGRAPH_FORWARD_HOST: "127.0.0.1",
    ...extraEnv,
  };
  const proc = spawn(process.execPath, [HTTP_ENTRY], { env, stdio: ["pipe", "pipe", "pipe"] });
  const lines = [];
  let stderr = "";
  proc.stderr.setEncoding("utf8").on("data", (d) => (stderr += d));
  const exited = new Promise((resolve) => proc.once("exit", (code) => resolve(code)));
  const port = await new Promise((resolve, reject) => {
    let buf = "";
    const timer = setTimeout(() => reject(new Error(`http.js did not start: ${stderr}`)), 15_000);
    proc.stdout.setEncoding("utf8").on("data", (d) => {
      buf += d;
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 1);
        lines.push(line);
        try {
          const j = JSON.parse(line);
          if (j.message === "mcp_remote_listening") {
            clearTimeout(timer);
            resolve(j.port);
          }
        } catch {
          // not JSON: kept in lines, and the log test fails on it
        }
      }
    });
    exited.then((code) => {
      clearTimeout(timer);
      reject(new Error(`http.js exited ${code} before listening: ${stderr}${lines.join("\n")}`));
    });
  });
  return {
    url: `http://127.0.0.1:${port}/mcp`,
    base: `http://127.0.0.1:${port}`,
    lines,
    stderr: () => stderr,
    proc,
    async stop() {
      proc.kill("SIGTERM");
      const t = setTimeout(() => proc.kill("SIGKILL"), 5000);
      await exited;
      clearTimeout(t);
    },
  };
}

const accessLines = (srv) => srv.lines.map((l) => JSON.parse(l)).filter((j) => j.message === "mcp_request");

describe("#2316: the hosted endpoint over Streamable HTTP", () => {
  let srv;
  before(async () => {
    srv = await startHttp({ MCP_RATE_LIMIT_PER_MIN: "1000", MCP_MAX_BODY_BYTES: "4096" });
  });
  after(() => srv?.stop());

  describe("health", () => {
    it("GET /health is 200 JSON with the package identity (not /healthz, which Cloud Run reserves)", async () => {
      const res = await fetch(`${srv.base}/health`);
      assert.equal(res.status, 200);
      assert.match(res.headers.get("content-type"), /application\/json/);
      assert.deepEqual(await res.json(), { status: "ok", name: PKG.name, version: PKG.version });
    });
    it("any other path is a JSON 404, not an HTML page", async () => {
      const res = await fetch(`${srv.base}/healthz`);
      assert.equal(res.status, 404);
      assert.match(res.headers.get("content-type"), /application\/json/);
    });
  });

  describe("done means 1: the modern era (2026-07-28)", () => {
    it("server/discover is 200 application/json with a DiscoverResult (asserted on the JSON)", async () => {
      const r = await modern(srv.url, "server/discover");
      assert.equal(r.status, 200, r.text);
      assert.match(r.contentType, /^application\/json/);
      const d = r.message.result;
      assert.ok(d, r.text);
      // SDK 2.1.0 lists only modern revisions here; 2025-era revisions are negotiated through
      // initialize (Server._ondiscover), which the legacy block below proves for 2025-11-25.
      assert.deepEqual(d.supportedVersions, [MODERN]);
      assert.ok(d.capabilities?.tools);
      assert.match(d.instructions, /Shodan data is owned by Shodan/);
      assert.deepEqual(d._meta?.[SERVER_INFO_META_KEY], { name: PKG.name, version: PKG.version });
    });
    it("tools/list lists the npm package's tools, each with an outputSchema — one tool module", async () => {
      const r = await modern(srv.url, "tools/list");
      assert.equal(r.status, 200, r.text);
      const names = r.message.result.tools.map((t) => t.name);
      for (const n of FIVE) assert.ok(names.includes(n), `${n} missing from ${names}`);
      for (const t of r.message.result.tools) assert.ok(t.outputSchema && t.annotations, t.name);
    });
  });

  describe("done means 3: tools/call cve_summary relays the API's answer", () => {
    for (const era of ["modern", "legacy 2025-06-18"]) {
      it(`${era}: structuredContent.data equals /api/v1/public/cves/summary and validates against the outputSchema`, async () => {
        const call = { name: "cve_summary", arguments: {} };
        const list = era === "modern" ? await modern(srv.url, "tools/list") : await legacy(srv.url, "tools/list", {}, { revision: "2025-06-18" });
        const schema = list.message.result.tools.find((t) => t.name === "cve_summary").outputSchema;
        const r = era === "modern" ? await modern(srv.url, "tools/call", call) : await legacy(srv.url, "tools/call", call, { revision: "2025-06-18" });
        assert.equal(r.status, 200, r.text);
        const res = r.message.result;
        assert.notEqual(res.isError, true, r.text);
        assert.deepEqual(JSON.parse(res.content[0].text), SUMMARY);
        assert.equal(res.structuredContent.state, "measured");
        assert.deepEqual(res.structuredContent.data, SUMMARY);
        const v = validator.getValidator(schema)(res.structuredContent);
        assert.ok(v.valid, v.errorMessage);
      });
    }
  });

  describe("done means 2: the legacy era (2025-era initialize, stateless)", () => {
    for (const revision of ["2025-06-18", "2025-11-25"]) {
      it(`initialize with ${revision} negotiates ${revision}, with the package identity`, async () => {
        const r = await legacy(srv.url, "initialize", { protocolVersion: revision, capabilities: {}, clientInfo: { name: "t", version: "0" } });
        assert.equal(r.status, 200, r.text);
        assert.equal(r.message.result.protocolVersion, revision);
        assert.deepEqual(r.message.result.serverInfo, { name: PKG.name, version: PKG.version });
        assert.ok(r.message.result.capabilities.tools);
      });
    }
    it("GET /mcp (a 2025 session stream) is 405: the endpoint keeps no sessions", async () => {
      const res = await fetch(srv.url, { headers: { Accept: "text/event-stream" } });
      assert.equal(res.status, 405);
    });
  });

  describe("done means 4: a modern request without MCP-Protocol-Version", () => {
    it("is 400 with JSON-RPC error -32020 (HeaderMismatch)", async () => {
      const r = await modern(srv.url, "tools/list", {}, { omit: ["MCP-Protocol-Version"] });
      assert.equal(r.status, 400, r.text);
      assert.equal(r.message.error.code, -32020, r.text);
    });
    it("control: the same request with the header is served", async () => {
      const r = await modern(srv.url, "tools/list");
      assert.equal(r.status, 200, r.text);
    });
  });

  describe("done means 5: the Origin policy (none or any https served; null, non-https, malformed refused)", () => {
    for (const origin of ["https://claude.ai", "https://example.com:8443"]) {
      it(`Origin ${origin} is served, with CORS for a browser client`, async () => {
        const r = await modern(srv.url, "tools/list", {}, { headers: { Origin: origin } });
        assert.equal(r.status, 200, r.text);
        assert.equal(r.headers.get("access-control-allow-origin"), "*");
      });
    }
    it("no Origin is served (every non-browser client)", async () => {
      const r = await modern(srv.url, "tools/list");
      assert.equal(r.status, 200, r.text);
    });
    for (const origin of ["null", "http://example.com", "not a url", "https://example.com/path", "https://a.example, https://b.example", "file://", "chrome-extension://abcdef"]) {
      it(`Origin ${JSON.stringify(origin)} is refused 403 with a JSON-RPC error, before any tool runs`, async () => {
        const before = seen.length;
        const r = await modern(srv.url, "tools/call", { name: "cve_summary", arguments: {} }, { headers: { Origin: origin } });
        assert.equal(r.status, 403, r.text);
        assert.match(r.contentType, /^application\/json/);
        assert.equal(r.message.jsonrpc, "2.0");
        assert.equal(r.message.error.code, -32000);
        assert.equal(seen.length, before, "a refused request reached the API");
      });
    }
    it("a CORS preflight from an https Origin is 204 with the MCP headers allowed", async () => {
      const res = await fetch(srv.url, {
        method: "OPTIONS",
        headers: { Origin: "https://claude.ai", "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type, mcp-protocol-version" },
      });
      assert.equal(res.status, 204);
      assert.match(res.headers.get("access-control-allow-headers"), /MCP-Protocol-Version/);
      assert.match(res.headers.get("access-control-allow-methods"), /POST/);
    });
  });

  describe("the request-body cap", () => {
    const big = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: { pad: "x".repeat(5000) } });
    it("a body over the cap is 413 with a JSON-RPC error (declared Content-Length)", async () => {
      const r = await post(srv.url, big, { "MCP-Protocol-Version": MODERN });
      assert.equal(r.status, 413, r.text);
      assert.equal(r.message.error.code, -32600);
    });
    it("a body over the cap is 413 when it arrives chunked, with no Content-Length", async () => {
      const status = await new Promise((resolve, reject) => {
        const u = new URL(srv.url);
        const req = http.request({ host: u.hostname, port: u.port, path: u.pathname, method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", "Transfer-Encoding": "chunked" } }, (res) => {
          res.resume();
          resolve(res.statusCode);
        });
        req.on("error", reject);
        for (let i = 0; i < 10; i++) req.write(big.slice(i * 600, (i + 1) * 600));
        req.end();
      });
      assert.equal(status, 413);
    });
    it("control: a body under the cap is served", async () => {
      const r = await modern(srv.url, "tools/list");
      assert.equal(r.status, 200);
    });
  });

  describe("#2212: the API is told who the remote user is", () => {
    it("a tool call from a public client carries its address and the forward token to the API", async () => {
      const before = seen.length;
      const r = await modern(srv.url, "tools/call", { name: "cve_summary", arguments: {} }, { headers: { "X-Forwarded-For": chain("198.51.100.23") } });
      assert.equal(r.status, 200, r.text);
      const calls = seen.slice(before);
      assert.equal(calls.length, 1);
      assert.equal(calls[0].clientIp, "198.51.100.23");
      assert.equal(calls[0].token, TOKEN);
    });
    it("a forged hop LEFT of the platform's is not the address the API is told", async () => {
      const before = seen.length;
      await modern(srv.url, "tools/call", { name: "cve_summary", arguments: {} }, { headers: { "X-Forwarded-For": `1.2.3.4, ${chain("198.51.100.24")}` } });
      assert.equal(seen.slice(before)[0].clientIp, "198.51.100.24");
    });
    it("no public client address (a local peer) means no forward headers at all", async () => {
      const before = seen.length;
      await modern(srv.url, "tools/call", { name: "cve_summary", arguments: {} });
      const [c] = seen.slice(before);
      assert.equal(c.clientIp, undefined);
      assert.equal(c.token, undefined);
    });
  });

  describe("done means 8 (local half): the access log holds no body, no query string and no typed value", () => {
    it("a search and a query string leave no trace of what was typed, and every line is bounded JSON", async () => {
      await modern(srv.url, "tools/call", { name: "search_cves", arguments: { search: MARKER } });
      await post(`${srv.url}?q=${MARKER}q`, { jsonrpc: "2.0", id: 9, method: "tools/list", params: {} }, { "MCP-Protocol-Version": MODERN });
      // The API call carries the term in X-EG-Search, never in its URL (#1983): a control that the
      // term really was sent, and that no hop's URL holds it.
      assert.ok(seen.some((s) => s.search === MARKER), "control: the search never reached the stub");
      assert.ok(!seen.some((s) => s.url.includes(MARKER)), "the term is in the API URL");
      // Let the last lines flush.
      await new Promise((r) => setTimeout(r, 100));
      for (const line of srv.lines) {
        assert.ok(!line.includes(MARKER), `a log line carries the typed value: ${line}`);
        const j = JSON.parse(line); // every stdout line is JSON
        assert.ok(!("params" in j) && !("arguments" in j) && !("body" in j), line);
      }
      assert.ok(!srv.stderr().includes(MARKER), "stderr carries the typed value");
      const lines = accessLines(srv);
      assert.ok(lines.some((l) => l.rpc_method === "tools/call" && l.tool === "search_cves"), "control: the call was logged, by tool name");
      for (const l of lines) assert.ok(["/mcp", "/health", "(other)"].includes(l.path), `path ${l.path}`);
    });
  });

  describe("the HTTP entry does not also serve stdio", () => {
    it("a JSON-RPC message on its stdin is not answered on stdout", async () => {
      const before = srv.lines.length;
      srv.proc.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "x", version: "0" } } })}\n`);
      await new Promise((r) => setTimeout(r, 500));
      for (const line of srv.lines.slice(before)) assert.ok(!line.includes('"jsonrpc"'), `stdio answered: ${line}`);
    });
  });
});

describe("done means 6: the per-client limit answers with OUR JSON-RPC error", () => {
  let srv;
  before(async () => {
    srv = await startHttp({ MCP_RATE_LIMIT_PER_MIN: "3" });
  });
  after(() => srv?.stop());
  const as = (xff) => modern(srv.url, "tools/list", {}, { headers: { "X-Forwarded-For": xff } });

  it("the request over the limit is 429 application/json, JSON-RPC -32029, with Retry-After; another client is unaffected", async () => {
    for (let i = 1; i <= 3; i++) assert.equal((await as(chain("203.0.113.10"))).status, 200, `request ${i}`);
    const r = await as(chain("203.0.113.10"));
    assert.equal(r.status, 429, r.text);
    assert.match(r.contentType, /^application\/json/);
    assert.equal(r.message.jsonrpc, "2.0");
    assert.equal(r.message.error.code, -32029);
    assert.equal(r.message.error.data.limit, 3);
    assert.ok(Number(r.headers.get("retry-after")) >= 1);
    assert.equal((await as(chain("203.0.113.11"))).status, 200, "a second client was charged for the first");
  });
  it("SECURITY: rotating a forged hop left of the platform's does not reset the budget", async () => {
    for (let i = 1; i <= 3; i++) assert.equal((await as(`1.2.3.${i}, ${chain("203.0.113.20")}`)).status, 200);
    assert.equal((await as(`1.2.3.9, ${chain("203.0.113.20")}`)).status, 429);
  });
  it("an IPv6 client is counted per /64: another address in the same /64 shares the budget", async () => {
    for (let i = 1; i <= 3; i++) assert.equal((await as(chain(`2001:db8:5:6::${i}`))).status, 200);
    assert.equal((await as(chain("2001:db8:5:6::ffff"))).status, 429);
    assert.equal((await as(chain("2001:db8:5:7::1"))).status, 200);
  });
  it("the throttle is logged with the key, and never with the body", () => {
    const throttles = srv.lines.map((l) => JSON.parse(l)).filter((j) => j.message === "mcp_rate_limited");
    assert.ok(throttles.some((t) => t.client === "203.0.113.10"), JSON.stringify(throttles));
    assert.ok(accessLines(srv).some((l) => l.status === 429 && l.throttled === true));
  });
});

// #2747: a realistic CycloneDX SBOM over the hosted endpoint. The 64 KiB cap refused any real
// document, so a remote-only client could pass check_sbom only a purl list. The document here is
// Juice Shop 11.1.2's 50 real components (check_sbom.test.mjs's fixture), each field kept, cycled
// to 2,000 distinct purls (check_sbom's own maximum), pretty-printed as an SBOM tool writes it:
// ~1.75 M characters, a ~2 MB request body.
describe("#2747: check_sbom takes a real SBOM document over the hosted endpoint", () => {
  const CDX = JSON.parse(fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures", "juice-shop-11.1.2-50.cdx.json"), "utf8"));
  const cdxOf = (n) => {
    const components = Array.from({ length: n }, (_, i) => {
      const t = CDX.components[i % CDX.components.length];
      const name = `${t.name}-r${i}`;
      return { ...t, name, "bom-ref": `pkg:npm/${name}@${t.version}`, purl: `pkg:npm/${name}@${t.version}` };
    });
    return { ...CDX, components };
  };
  const SBOM_2000 = JSON.stringify(cdxOf(2000), null, 2);
  const call = { name: "check_sbom", arguments: { sbom: SBOM_2000 } };
  const bodyBytes = Buffer.byteLength(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: call }));
  let srv;
  before(async () => {
    srv = await startHttp({ MCP_RATE_LIMIT_PER_MIN: "1000" });
  });
  after(() => srv?.stop());

  it("control: the document is far past the 64 KiB cap that refused it", () => {
    assert.ok(bodyBytes > 1_500_000, `${bodyBytes}`);
  });
  for (const era of ["modern", "legacy 2025-06-18"]) {
    it(`${era}: tools/call check_sbom with a 2,000-component CycloneDX document answers measured, every purl checked`, async () => {
      const before = batchPurls.length;
      const r = era === "modern" ? await modern(srv.url, "tools/call", call) : await legacy(srv.url, "tools/call", call, { revision: "2025-06-18" });
      assert.equal(r.status, 200, r.text.slice(0, 500));
      const sc = r.message.result.structuredContent;
      assert.notEqual(r.message.result.isError, true, r.text.slice(0, 500));
      assert.equal(sc.state, "measured");
      assert.equal(sc.coverage.input, "cyclonedx");
      assert.deepEqual([sc.coverage.components_in_document, sc.coverage.distinct_purls, sc.coverage.sent, sc.coverage.not_sent], [2000, 2000, 2000, 0]);
      assert.equal(batchPurls.length - before, 2000, "the batch route did not receive every purl");
    });
  }
  it("the access line names the tool and the size, and holds nothing from the document", async () => {
    await new Promise((r) => setTimeout(r, 100));
    const big = accessLines(srv).filter((l) => l.tool === "check_sbom" && l.body_bytes > 64 * 1024);
    assert.equal(big.length, 2, JSON.stringify(accessLines(srv)));
    for (const line of srv.lines) assert.ok(!line.includes("juice") && !line.includes("pkg:npm"), `a log line carries the document: ${line.slice(0, 300)}`);
  });
  it("a body past 64 KiB that is not check_sbom is still refused 413, read or not", async () => {
    const pad = "x".repeat(70 * 1024);
    // A modern client names its method: refused on the declared length, before the body is read.
    const named = await modern(srv.url, "tools/call", { name: "search_cves", arguments: { search: pad } });
    // A legacy client does not: refused once the body says what it is.
    const unnamed = await legacy(srv.url, "tools/call", { name: "search_cves", arguments: { search: pad } }, { revision: "2025-06-18" });
    const listed = await legacy(srv.url, "tools/list", { pad }, { revision: "2025-06-18" });
    for (const r of [named, unnamed, listed]) {
      assert.equal(r.status, 413, r.text);
      assert.equal(r.message.error.code, -32600);
      assert.equal(r.message.error.data.max_bytes, 64 * 1024);
      assert.match(r.message.error.message, /tools\/call of check_sbom/);
    }
  });
  it("a check_sbom document at the tool's own 5,000,000-character cap fits the large cap", async () => {
    const P = await import(pathToFileURL(path.join(PKG_DIR, "dist", "httpPolicy.js")).href);
    // Pad the 2,000-component document with more components (no purl, not checked) to the cap.
    const filler = { type: "library", name: "filler", description: "x".repeat(200), licenses: [{ license: { id: "MIT" } }] };
    const doc = cdxOf(2000);
    const padded = (n) => JSON.stringify({ ...doc, components: [...doc.components, ...Array(n).fill(filler)] }, null, 2);
    const per = padded(1).length - SBOM_2000.length;
    const text = padded(Math.floor((5_000_000 - SBOM_2000.length) / per));
    assert.ok(text.length <= 5_000_000 && text.length > 4_900_000, `${text.length}`);
    const bytes = Buffer.byteLength(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "check_sbom", arguments: { sbom: text } } }));
    assert.ok(bytes < P.DEFAULT_MAX_SBOM_BODY_BYTES, `${bytes} bytes`);
  });
});

describe("#2747: the large-body cap and slots", () => {
  let srv;
  before(async () => {
    srv = await startHttp({ MCP_RATE_LIMIT_PER_MIN: "1000", MCP_MAX_SBOM_BODY_BYTES: "300000", MCP_LARGE_BODY_SLOTS: "1" });
  });
  after(() => srv?.stop());
  // 2,000 purls of ~45 bytes: a body past 64 KiB that is not a document.
  const purlsCall = { name: "check_sbom", arguments: { purls: Array.from({ length: 2000 }, (_, i) => `pkg:npm/a-longer-package-name-${i}@1.0.0`) } };

  it("a check_sbom body over MCP_MAX_SBOM_BODY_BYTES is 413", async () => {
    const r = await legacy(srv.url, "tools/call", { name: "check_sbom", arguments: { sbom: "x".repeat(310_000) } }, { revision: "2025-06-18" });
    assert.equal(r.status, 413, r.text);
    assert.equal(r.message.error.data.max_bytes_sbom, 300000);
  });
  it("with every slot held, a second large body is 503 JSON-RPC -32030 with Retry-After; once released, it is served", async () => {
    const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: purlsCall });
    assert.ok(body.length > 64 * 1024 && body.length < 300_000, `${body.length}`);
    // The first holds the only slot: it sends past 64 KiB, then stalls before its last bytes.
    const u = new URL(srv.url);
    let release;
    const first = new Promise((resolve, reject) => {
      const req = http.request(
        { host: u.hostname, port: u.port, path: u.pathname, method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", "MCP-Protocol-Version": "2025-06-18", "Content-Length": Buffer.byteLength(body) } },
        (res) => {
          let t = "";
          res.setEncoding("utf8").on("data", (d) => (t += d)).on("end", () => resolve({ status: res.statusCode, text: t }));
        },
      );
      req.on("error", reject);
      req.write(body.slice(0, body.length - 10));
      release = () => req.end(body.slice(body.length - 10));
    });
    await new Promise((r) => setTimeout(r, 200));
    const busy = await post(srv.url, body, { "MCP-Protocol-Version": "2025-06-18" });
    assert.equal(busy.status, 503, busy.text);
    assert.equal(busy.message.error.code, -32030);
    assert.equal(busy.headers.get("retry-after"), "5");
    // A small request is never held behind the slot.
    assert.equal((await modern(srv.url, "tools/list")).status, 200);
    release();
    const f = await first;
    assert.equal(f.status, 200, f.text.slice(0, 300));
    const again = await post(srv.url, body, { "MCP-Protocol-Version": "2025-06-18" });
    assert.equal(again.status, 200, "the slot was not released after the first was served");
    // And a refused large body gives its slot back too.
    const refused = await legacy(srv.url, "tools/list", { pad: "x".repeat(70 * 1024) }, { revision: "2025-06-18" });
    assert.equal(refused.status, 413);
    assert.equal((await post(srv.url, body, { "MCP-Protocol-Version": "2025-06-18" })).status, 200, "a refused large body kept its slot");
  });
});

// ── #2773 and #2775: a stub API that answers slowly ──
// Each answer takes state.ms (state.batchMs for the batch route). It counts what it is sent, how
// many are open at once, and the requests the MCP server gave up on (cancelled: the connection
// closed before the answer).
async function slowStub() {
  // retryAfter (#2775): when set, the batch route answers 429 with that Retry-After at once, as
  // production's API did to the canary's calls (1,200 components a minute per caller).
  const state = { ms: 200, batchMs: 200, open: 0, maxOpen: 0, batches: 0, cancelled: 0, retryAfter: undefined };
  const server = http.createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      const u = new URL(req.url, "http://stub");
      const batch = u.pathname === BATCH_PATH;
      if (batch) state.batches++;
      if (batch && state.retryAfter !== undefined) {
        res.writeHead(429, { "content-type": "application/json", "retry-after": String(state.retryAfter) });
        res.end(JSON.stringify({ error: "rate limit exceeded" }));
        return;
      }
      state.open++;
      state.maxOpen = Math.max(state.maxOpen, state.open);
      const t = setTimeout(
        () => {
          state.open--;
          if (u.pathname === "/api/v1/public/cves/summary") {
            res.writeHead(200, { "content-type": "application/json" });
            res.end(JSON.stringify(SUMMARY));
          } else if (batch) {
            const { components } = JSON.parse(b);
            res.writeHead(200, { "content-type": "application/json" });
            res.end(JSON.stringify(batchAnswer(components.map((c, i) => ROWS.notAffected(i, c.purl, "x", "1")))));
          } else {
            res.writeHead(404, { "content-type": "text/plain" });
            res.end("404 page not found\n");
          }
        },
        batch ? state.batchMs : state.ms,
      );
      res.on("close", () => {
        if (res.writableFinished) return;
        clearTimeout(t);
        state.open--;
        state.cancelled++;
      });
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    state,
    base: `http://127.0.0.1:${server.address().port}`,
    close: () => {
      server.closeAllConnections();
      return new Promise((resolve) => server.close(resolve));
    },
  };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(cond, what, ms = 5000) {
  const t0 = Date.now();
  while (!cond()) {
    if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`);
    await sleep(10);
  }
}

// One request on a raw socket, which the test can close without reading the answer: what a client
// that times out, or whose user closes the tab, does. `bytes` sends only the first n bytes of the
// body. Resolves the socket once the request is written.
function rawRequest(url, era, params, { bytes } = {}) {
  const u = new URL(url);
  const modernEra = era === "modern";
  const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: modernEra ? { ...params, _meta: modernMeta() } : params });
  const headers = modernEra ? modernHeaders("tools/call", params) : { "MCP-Protocol-Version": "2025-06-18" };
  const head = [
    `POST ${u.pathname} HTTP/1.1`,
    `Host: ${u.host}`,
    "Content-Type: application/json",
    "Accept: application/json, text/event-stream",
    `Content-Length: ${Buffer.byteLength(body)}`,
    ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`),
    "",
    "",
  ].join("\r\n");
  return new Promise((resolve, reject) => {
    const sock = net.connect(Number(u.port), u.hostname, () => {
      sock.write(head + (bytes === undefined ? body : body.slice(0, bytes)), () => resolve(sock));
    });
    sock.on("data", () => {});
    sock.on("error", () => {});
    sock.once("error", reject);
  });
}

describe("#2773: at most MCP_MAX_IN_FLIGHT requests are served at once; the next waits, then 503", () => {
  let stub, srv;
  before(async () => {
    stub = await slowStub();
    srv = await startHttp({ ECHELONGRAPH_API_BASE: stub.base, MCP_RATE_LIMIT_PER_MIN: "1000", MCP_MAX_IN_FLIGHT: "2", MCP_ADMISSION_WAIT_MS: "1500" });
  });
  after(async () => {
    await srv?.stop();
    await stub?.close();
  });
  const call = { name: "cve_summary", arguments: {} };
  const summary = () => modern(srv.url, "tools/call", call);

  it("six at once are all answered, never more than two at a time, four of them after waiting", async () => {
    stub.state.ms = 300;
    stub.state.maxOpen = 0;
    const before = accessLines(srv).length;
    const rs = await Promise.all(Array.from({ length: 6 }, summary));
    for (const r of rs) assert.equal(r.status, 200, r.text);
    assert.equal(stub.state.maxOpen, 2, "the API saw more than MCP_MAX_IN_FLIGHT at once");
    await sleep(100);
    const lines = accessLines(srv).slice(before);
    assert.equal(lines.length, 6);
    for (const l of lines) assert.ok(l.in_flight >= 1 && l.in_flight <= 2, JSON.stringify(l));
    assert.ok(lines.filter((l) => l.queued_ms >= 200).length >= 4, JSON.stringify(lines.map((l) => l.queued_ms)));
  });

  it("one that waits MCP_ADMISSION_WAIT_MS is answered 503, JSON-RPC -32030, with Retry-After; /health is never held", async () => {
    stub.state.ms = 4000;
    const held = [summary(), summary()];
    await waitFor(() => stub.state.open === 2, "two requests at the API");
    const t0 = Date.now();
    const r = await summary();
    const waited = Date.now() - t0;
    assert.equal(r.status, 503, r.text);
    assert.match(r.contentType, /^application\/json/);
    assert.equal(r.message.error.code, -32030);
    assert.match(r.message.error.message, /already serving its 2 requests at once/);
    assert.equal(r.headers.get("retry-after"), "5");
    assert.ok(waited >= 1400 && waited < 3800, `answered after ${waited} ms`);
    assert.equal((await fetch(`${srv.base}/health`)).status, 200, "/health was held behind the full instance");
    for (const h of await Promise.all(held)) assert.equal(h.status, 200, h.text);
    await sleep(100);
    const refusal = accessLines(srv).find((l) => l.status === 503 && l.refused === "busy");
    assert.ok(refusal && refusal.queued_ms >= 1400, JSON.stringify(refusal));
    assert.ok(srv.lines.some((l) => JSON.parse(l).message === "mcp_busy"));
  });

  // The body is read before admission: a client that sends its body slowly, or never finishes
  // it, holds no place, so more of them than there are places leave every other request served.
  it("clients that upload slowly hold no place: with more stalled uploads than places, the next request is served at once", async () => {
    stub.state.ms = 50;
    const stalled = [];
    for (let i = 0; i < 3; i++) stalled.push(await rawRequest(srv.url, "modern", call, { bytes: 20 }));
    await sleep(200);
    const before = accessLines(srv).length;
    const t0 = Date.now();
    const r = await summary();
    const took = Date.now() - t0;
    for (const sock of stalled) sock.destroy();
    assert.equal(r.status, 200, r.text);
    assert.ok(took < 1000, `answered after ${took} ms: the stalled uploads held the places`);
    await sleep(100);
    const line = accessLines(srv)
      .slice(before)
      .find((l) => l.status === 200);
    assert.deepEqual([line.in_flight, line.queued_ms <= 50], [1, true], JSON.stringify(line));
  });

  it("a waiting request whose client goes leaves the queue (logged 499, client_closed) and takes no place", async () => {
    stub.state.ms = 1500;
    const held = [summary(), summary()];
    await waitFor(() => stub.state.open === 2, "two requests at the API");
    const before = accessLines(srv).length;
    const sock = await rawRequest(srv.url, "modern", call);
    await sleep(200);
    sock.destroy();
    for (const h of await Promise.all(held)) assert.equal(h.status, 200);
    stub.state.ms = 50;
    const next = await summary();
    assert.equal(next.status, 200);
    await sleep(100);
    const lines = accessLines(srv).slice(before);
    const gone = lines.find((l) => l.client_closed === true);
    assert.ok(gone, JSON.stringify(lines));
    assert.equal(gone.status, 499);
    assert.equal(gone.refused, "client_closed");
    const last = lines.at(-1);
    assert.deepEqual([last.status, last.in_flight, last.queued_ms <= 50], [200, 1, true], JSON.stringify(last));
  });
});

// A 2026-07-28 subscriptions/listen on a connection of its own: the SSE stream the SDK keeps open
// until the client leaves. Resolves on the server's first event (the acknowledgement), or on a
// whole answer that is not a stream; close() is the client leaving.
function openListen(url) {
  const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "subscriptions/listen", params: { notifications: { toolsListChanged: true }, _meta: modernMeta() } });
  return new Promise((resolve, reject) => {
    const req = http.request(
      url,
      {
        method: "POST",
        agent: false,
        headers: { "Content-Type": "application/json", Accept: ACCEPT, "Content-Length": Buffer.byteLength(body), ...modernHeaders("subscriptions/listen") },
      },
      (res) => {
        let text = "";
        const contentType = res.headers["content-type"] ?? "";
        const stream = /^text\/event-stream/.test(contentType);
        const settle = (t) => resolve({ status: res.statusCode, contentType, stream, message: parseRpcBody(contentType, t), close: () => req.destroy() });
        res.setEncoding("utf8");
        res.on("data", (d) => {
          text += d;
          const end = text.indexOf("\n\n");
          if (end >= 0 && stream) settle(text.slice(0, end));
        });
        res.on("end", () => settle(text));
        res.on("error", () => {});
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

// #2773: a listen stream is open until its client leaves and carries only keepalives here (the
// server declares no listChanged). It takes no place: held, MCP_MAX_IN_FLIGHT of them left every
// other request waiting MCP_ADMISSION_WAIT_MS for a 503.
describe("#2773: subscriptions/listen streams take no place; the gate still bounds every other request", () => {
  const N = 2;
  let stub, srv;
  before(async () => {
    stub = await slowStub();
    srv = await startHttp({ ECHELONGRAPH_API_BASE: stub.base, MCP_RATE_LIMIT_PER_MIN: "1000", MCP_MAX_IN_FLIGHT: String(N), MCP_ADMISSION_WAIT_MS: "1500" });
  });
  after(async () => {
    await srv?.stop();
    await stub?.close();
  });
  const call = { name: "cve_summary", arguments: {} };
  const summary = (era) => (era === "modern" ? modern(srv.url, "tools/call", call) : legacy(srv.url, "tools/call", call, { revision: "2025-06-18" }));
  const opening = (era) =>
    era === "modern" ? modern(srv.url, "server/discover") : legacy(srv.url, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } });
  // The access lines of 2026-era listens (a 2025-era body naming the method is not one).
  const listenLines = () => accessLines(srv).filter((l) => l.rpc_method === "subscriptions/listen" && l.protocol_version === MODERN);
  // Opens `count` listen streams into `streams`, one after another, each acknowledged.
  async function openAll(streams, count) {
    for (let i = 0; i < count; i++) {
      const s = await openListen(srv.url);
      streams.push(s);
      assert.equal(s.status, 200, `listen ${i + 1} of ${count}: ${JSON.stringify(s.message)}`);
      assert.ok(s.stream, s.contentType);
      assert.equal(s.message?.method, "notifications/subscriptions/acknowledged", JSON.stringify(s.message));
    }
  }
  // The client leaves every stream; resolves once each one's access line is written, so no line
  // of one case lands in the next.
  async function closeAll(streams) {
    const logged = listenLines().length;
    const open = streams.filter((s) => s.stream);
    for (const s of streams) s.close();
    await waitFor(() => listenLines().length >= logged + open.length, "the closed streams' access lines");
  }

  for (const count of [N, N + 5]) {
    for (const era of ["modern", "legacy"]) {
      it(`${count} listen streams open, MCP_MAX_IN_FLIGHT ${N}: a ${era} tools/call, and the era's opening request, are answered 200 at once`, async () => {
        stub.state.ms = 50;
        const streams = [];
        try {
          await openAll(streams, count);
          const before = accessLines(srv).length;
          const t0 = Date.now();
          const r = await summary(era);
          const took = Date.now() - t0;
          assert.equal(r.status, 200, r.text);
          assert.notEqual(r.message.result.isError, true, r.text);
          assert.deepEqual(r.message.result.structuredContent.data, SUMMARY);
          assert.ok(took < 1000, `answered after ${took} ms: the listen streams held the places`);
          const o = await opening(era);
          assert.equal(o.status, 200, o.text);
          await sleep(100);
          const line = accessLines(srv)
            .slice(before)
            .find((l) => l.rpc_method === "tools/call");
          assert.deepEqual([line.status, line.in_flight, line.queued_ms <= 50], [200, 1, true], JSON.stringify(line));
        } finally {
          await closeAll(streams);
        }
      });
    }
  }

  it("a listen stream is logged when its client ends it: 499 and client_closed, as #2775 logs a client that went, holding no place (in_flight 0)", async () => {
    const before = listenLines().length;
    const streams = [];
    await openAll(streams, 1);
    await sleep(200);
    assert.equal(listenLines().length, before, "the line was written before the stream ended");
    await closeAll(streams);
    const line = listenLines()[before];
    assert.deepEqual(
      [line.method, line.path, line.status, line.client_closed, line.refused, line.in_flight, line.queued_ms, line.protocol_version],
      ["POST", "/mcp", 499, true, "", 0, 0, MODERN],
      JSON.stringify(line),
    );
    assert.ok(line.body_bytes > 0 && line.duration_ms >= 200, JSON.stringify(line));
  });

  it(`control: with ${N + 5} listen streams open the gate still bounds ordinary calls of both eras, and a 2025-era body naming subscriptions/listen waits like one`, async () => {
    const streams = [];
    try {
      await openAll(streams, N + 5);
      stub.state.ms = 3000;
      stub.state.maxOpen = 0;
      const held = [summary("modern"), summary("legacy")];
      await waitFor(() => stub.state.open === N, `${N} calls at the API`);
      // A listen opened now, with every place taken, is served at once.
      const t0 = Date.now();
      await openAll(streams, 1);
      assert.ok(Date.now() - t0 < 1000, `a listen waited ${Date.now() - t0} ms for a place`);
      // Every other request waits MCP_ADMISSION_WAIT_MS, then 503.
      const t1 = Date.now();
      const refused = await Promise.all([
        summary("modern"),
        summary("legacy"),
        opening("modern"),
        legacy(srv.url, "subscriptions/listen", { notifications: { toolsListChanged: true } }, { revision: "2025-06-18" }),
      ]);
      const waited = Date.now() - t1;
      for (const r of refused) {
        assert.equal(r.status, 503, r.text);
        assert.equal(r.message.error.code, -32030, r.text);
      }
      assert.ok(waited >= 1400 && waited < 3800, `answered after ${waited} ms`);
      for (const h of await Promise.all(held)) assert.equal(h.status, 200, h.text);
      assert.equal(stub.state.maxOpen, N, "the API saw more than MCP_MAX_IN_FLIGHT at once");
    } finally {
      await closeAll(streams);
    }
  });
});

// #2775: a hosted check_sbom whose client has gone must stop: its batches stop (at most the one in
// flight), its large-body slot is free again within about a second, and the access line says the
// client closed. The call is 2,000 purls, an 84,991-byte body (past 64 KiB, so it holds the
// instance's only slot), ten batches at 400 ms each; the client closes once the first is at the API.
describe("#2775: a check_sbom call whose client goes stops, and frees its slot", () => {
  let stub, srv;
  before(async () => {
    stub = await slowStub();
    srv = await startHttp({ ECHELONGRAPH_API_BASE: stub.base, MCP_RATE_LIMIT_PER_MIN: "1000", MCP_LARGE_BODY_SLOTS: "1", MCP_MAX_IN_FLIGHT: "3" });
  });
  after(async () => {
    await srv?.stop();
    await stub?.close();
  });
  const purls = { name: "check_sbom", arguments: { purls: Array.from({ length: 2000 }, (_, i) => `pkg:npm/a-longer-package-name-${i}@1.0.0`) } };
  // Another body past 64 KiB that needs the slot and makes no API call: a document that is not JSON.
  const probe = { name: "check_sbom", arguments: { sbom: "x".repeat(70 * 1024) } };

  for (const era of ["modern", "legacy"]) {
    it(`${era}: the batches stop, the slot is free within ~1 s, and the line says 499 client_closed`, async () => {
      stub.state.batchMs = 400;
      const batchesBefore = stub.state.batches;
      const cancelledBefore = stub.state.cancelled;
      const before = accessLines(srv).length;
      const sock = await rawRequest(srv.url, era, purls);
      await waitFor(() => stub.state.batches > batchesBefore, "the first batch at the API");
      const sentBeforeClose = stub.state.batches;
      const closedAt = Date.now();
      sock.destroy();
      await waitFor(() => stub.state.cancelled > cancelledBefore, "the batch at the API to be cut off", 1000);
      // The next large body: 503 while the slot is held, 200 (an invalid_input result) once it is free.
      let freedAfter;
      while (Date.now() - closedAt < 6000) {
        const r = era === "modern" ? await modern(srv.url, "tools/call", probe) : await legacy(srv.url, "tools/call", probe, { revision: "2025-06-18" });
        if (r.status !== 503) {
          assert.equal(r.status, 200, r.text.slice(0, 300));
          assert.equal(r.message.result.structuredContent.state, "invalid_input");
          freedAfter = Date.now() - closedAt;
          break;
        }
        await sleep(100);
      }
      assert.ok(freedAfter !== undefined && freedAfter < 1500, `the slot was still held ${Date.now() - closedAt} ms after the client closed`);
      // Long enough for four more batches, had the call kept going.
      await sleep(1700);
      assert.ok(stub.state.batches - sentBeforeClose <= 1, `${stub.state.batches - sentBeforeClose} batches were sent after the client closed`);
      assert.ok(stub.state.batches - batchesBefore < 10, "the call ran to its end");
      // The 2,000-purl call's line (~85 KB), not the probes' (~72 KB).
      const line = accessLines(srv)
        .slice(before)
        .find((l) => l.tool === "check_sbom" && l.body_bytes > 80_000);
      assert.ok(line, JSON.stringify(accessLines(srv).slice(before)));
      assert.deepEqual([line.status, line.client_closed], [499, true], JSON.stringify(line));
    });
  }

  // Not only check_sbom: every API call of a request whose client has gone is cancelled (runtime.ts
  // requestSignal, read by index.ts api()). cve_summary passes no signal of its own, so this is
  // the only thing that stops its call.
  for (const era of ["modern", "legacy"]) {
    it(`${era}: a cve_summary whose client goes has its API call cancelled within ~1 s, and the line says 499 client_closed`, async () => {
      stub.state.ms = 3000;
      // Nothing left at the API: a call still there would be cut off by api()'s own timeout
      // (ECHELONGRAPH_API_TIMEOUT_MS, 2 s here) and counted below as this one's cancellation.
      await waitFor(() => stub.state.open === 0, "the API to be idle");
      const openBefore = stub.state.open;
      const cancelledBefore = stub.state.cancelled;
      const before = accessLines(srv).length;
      const sock = await rawRequest(srv.url, era, { name: "cve_summary", arguments: {} });
      await waitFor(() => stub.state.open > openBefore, "the call at the API");
      sock.destroy();
      await waitFor(() => stub.state.cancelled > cancelledBefore, "the API call to be cancelled", 1000);
      await sleep(100);
      const line = accessLines(srv)
        .slice(before)
        .find((l) => l.tool === "cve_summary");
      assert.ok(line, JSON.stringify(accessLines(srv).slice(before)));
      assert.deepEqual([line.status, line.client_closed], [499, true], JSON.stringify(line));
    });
  }

  it("a client that goes mid-upload frees its slot, and held no place: the next request is admitted alone", async () => {
    for (let i = 0; i < 4; i++) {
      const sock = await rawRequest(srv.url, "legacy", purls, { bytes: 70_000 });
      await sleep(100);
      sock.destroy();
    }
    await sleep(200);
    const before = accessLines(srv).length;
    const r = await legacy(srv.url, "tools/call", probe, { revision: "2025-06-18" });
    assert.equal(r.status, 200, r.text.slice(0, 300));
    await sleep(100);
    const line = accessLines(srv).slice(before).at(-1);
    assert.deepEqual([line.in_flight, line.queued_ms <= 50], [1, true], JSON.stringify(line));
    const aborted = accessLines(srv).filter((l) => l.status === 499 && l.refused === "client_closed" && l.body_bytes === 0);
    assert.ok(aborted.length >= 4, JSON.stringify(accessLines(srv).slice(-8)));
  });

  it("stdio: a client's notifications/cancelled stops the call the same way", async () => {
    stub.state.batchMs = 400;
    const env = { ...process.env, ECHELONGRAPH_API_BASE: stub.base, ECHELONGRAPH_API_TIMEOUT_MS: "5000" };
    const client = await connect({ era: "2025-06-18", ...serverCommand(), env, stderr: "ignore", requestTimeoutMs: 3000 });
    try {
      const batchesBefore = stub.state.batches;
      const cancelledBefore = stub.state.cancelled;
      const requestId = client.nextId;
      const call = client.callTool(purls).then(
        () => "answered",
        (e) => (/no answer within/.test(e.message) ? "unanswered" : e.message),
      );
      await waitFor(() => stub.state.batches > batchesBefore, "the first batch at the API");
      const sentBeforeCancel = stub.state.batches;
      client.write({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId, reason: "test #2775" } });
      await waitFor(() => stub.state.cancelled > cancelledBefore, "the batch at the API to be cut off", 1000);
      await sleep(1700);
      assert.ok(stub.state.batches - sentBeforeCancel <= 1, `${stub.state.batches - sentBeforeCancel} batches were sent after the cancellation`);
      assert.equal(await call, "unanswered", "the SDK answers nothing for a cancelled request");
    } finally {
      await client.close();
    }
  });
});

// #2775 over h2c. Cloud Run does not tell an HTTP/1.1 container that its client went (measured in
// production on 2026-10-05: every abandoned call was logged 200 and kept its slot to the end), so
// production serves h2c (MCP_H2C=1 with `--use-http2`), where a client that goes resets its
// stream. These tests are that path: one h2 connection carrying several streams, as Cloud Run's
// front end multiplexes clients onto one connection, and a stream reset (RST_STREAM CANCEL) while
// the connection stays open. Whether Cloud Run sends that reset is for the canary to show
// (infrastructure/cloudrun/deploy-all.sh mcp-remote); what this server does with it is held here.
function h2Call(session, era, params, { bytes, path: p = "/mcp", headers: extra = {} } = {}) {
  const modernEra = era === "modern";
  const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: modernEra ? { ...params, _meta: modernMeta() } : params });
  const std = modernEra ? modernHeaders("tools/call", params) : { "MCP-Protocol-Version": "2025-06-18" };
  const headers = {
    ":method": "POST",
    ":path": p,
    "content-type": "application/json",
    accept: ACCEPT,
    "content-length": String(Buffer.byteLength(body)),
    ...Object.fromEntries(Object.entries({ ...std, ...extra }).map(([k, v]) => [k.toLowerCase(), v])),
  };
  const stream = session.request(headers);
  stream.on("error", () => {});
  if (bytes === undefined) stream.end(body);
  else stream.write(body.slice(0, bytes));
  const answer = new Promise((resolve) => {
    let status;
    let responseHeaders = {};
    let text = "";
    stream.on("response", (h) => {
      status = h[":status"];
      responseHeaders = h;
    });
    stream.setEncoding("utf8");
    stream.on("data", (d) => (text += d));
    stream.on("close", () => {
      let message;
      try {
        message = parseRpcBody(responseHeaders["content-type"], text);
      } catch {
        message = undefined;
      }
      resolve({ status, headers: responseHeaders, text, message, rstCode: stream.rstCode });
    });
  });
  return { stream, answer };
}

function h2Get(session, p) {
  return new Promise((resolve, reject) => {
    const stream = session.request({ ":method": "GET", ":path": p });
    let status;
    let text = "";
    stream.on("response", (h) => (status = h[":status"]));
    stream.setEncoding("utf8");
    stream.on("data", (d) => (text += d));
    stream.on("end", () => resolve({ status, text }));
    stream.on("error", reject);
  });
}

describe("#2775: over h2c (MCP_H2C=1), a stream reset is a client that went", () => {
  let stub, srv, session;
  before(async () => {
    stub = await slowStub();
    srv = await startHttp({ ECHELONGRAPH_API_BASE: stub.base, MCP_RATE_LIMIT_PER_MIN: "1000", MCP_LARGE_BODY_SLOTS: "1", MCP_MAX_IN_FLIGHT: "3", MCP_H2C: "1" });
    session = http2.connect(srv.base);
    session.on("error", () => {});
  });
  after(async () => {
    session?.close();
    await srv?.stop();
    await stub?.close();
  });
  const purls = { name: "check_sbom", arguments: { purls: Array.from({ length: 2000 }, (_, i) => `pkg:npm/a-longer-package-name-${i}@1.0.0`) } };
  const probe = { name: "check_sbom", arguments: { sbom: "x".repeat(70 * 1024) } };

  it("it serves h2c, and its start-up line says so: /health and tools/call in both eras are answered", async () => {
    const listening = srv.lines.map((l) => JSON.parse(l)).find((j) => j.message === "mcp_remote_listening");
    assert.equal(listening.protocol, "h2c");
    const health = await h2Get(session, "/health");
    assert.equal(health.status, 200);
    assert.equal(JSON.parse(health.text).status, "ok");
    stub.state.ms = 10;
    const before = accessLines(srv).length;
    for (const era of ["modern", "legacy"]) {
      const r = await h2Call(session, era, { name: "cve_summary", arguments: {} }).answer;
      assert.equal(r.status, 200, r.text.slice(0, 300));
      assert.deepEqual(r.message.result.structuredContent.data, SUMMARY, `${era}: ${r.text.slice(0, 300)}`);
    }
    await sleep(50);
    const lines = accessLines(srv).slice(before);
    assert.deepEqual(
      lines.map((l) => [l.tool, l.status, l.client_closed]),
      [
        ["cve_summary", 200, false],
        ["cve_summary", 200, false],
      ],
    );
  });

  it("a refusal that would close an HTTP/1.1 connection is answered on its stream, with no connection header", async () => {
    const big = { name: "check_sbom", arguments: { sbom: "x".repeat(7 * 1024 * 1024) } };
    const r = await h2Call(session, "modern", big).answer;
    assert.equal(r.status, 413, r.text.slice(0, 300));
    assert.equal(r.message.error.code, -32600, r.text.slice(0, 300));
    assert.equal(r.headers.connection, undefined);
    assert.doesNotMatch(srv.stderr(), /connection header|UnsupportedWarning/i);
  });

  for (const era of ["modern", "legacy"]) {
    it(`${era}: a check_sbom whose stream is reset stops; the slot is free within ~1 s on the same connection; the line says 499 client_closed`, async () => {
      stub.state.batchMs = 400;
      await waitFor(() => stub.state.open === 0, "the API to be idle");
      const batchesBefore = stub.state.batches;
      const cancelledBefore = stub.state.cancelled;
      const before = accessLines(srv).length;
      const { stream } = h2Call(session, era, purls);
      await waitFor(() => stub.state.batches > batchesBefore, "the first batch at the API");
      const sentBeforeClose = stub.state.batches;
      const closedAt = Date.now();
      stream.close(http2.constants.NGHTTP2_CANCEL);
      await waitFor(() => stub.state.cancelled > cancelledBefore, "the batch at the API to be cut off", 1000);
      let freedAfter;
      while (Date.now() - closedAt < 6000) {
        const r = await h2Call(session, era, probe).answer;
        if (r.status !== 503) {
          assert.equal(r.status, 200, r.text.slice(0, 300));
          assert.equal(r.message.result.structuredContent.state, "invalid_input");
          freedAfter = Date.now() - closedAt;
          break;
        }
        await sleep(100);
      }
      assert.ok(freedAfter !== undefined && freedAfter < 1500, `the slot was still held ${Date.now() - closedAt} ms after the stream was reset`);
      assert.ok(!session.closed && !session.destroyed, "the connection stayed open, as Cloud Run's does");
      await sleep(1700);
      assert.ok(stub.state.batches - sentBeforeClose <= 1, `${stub.state.batches - sentBeforeClose} batches were sent after the reset`);
      const line = accessLines(srv)
        .slice(before)
        .find((l) => l.tool === "check_sbom" && l.body_bytes > 80_000);
      assert.ok(line, JSON.stringify(accessLines(srv).slice(before)));
      assert.deepEqual([line.status, line.client_closed], [499, true], JSON.stringify(line));
    });
  }

  it("a stream reset mid-upload frees its slot, and held no place: the next request is admitted alone", async () => {
    const before = accessLines(srv).length;
    for (let i = 0; i < 4; i++) {
      const { stream } = h2Call(session, "legacy", purls, { bytes: 70_000 });
      await sleep(100);
      stream.close(http2.constants.NGHTTP2_CANCEL);
    }
    await sleep(200);
    const aborted = accessLines(srv)
      .slice(before)
      .filter((l) => l.status === 499 && l.refused === "client_closed" && l.body_bytes === 0);
    assert.equal(aborted.length, 4, JSON.stringify(accessLines(srv).slice(before)));
    const mark = accessLines(srv).length;
    const r = await h2Call(session, "legacy", probe).answer;
    assert.equal(r.status, 200, r.text.slice(0, 300));
    await sleep(100);
    const line = accessLines(srv).slice(mark).at(-1);
    assert.deepEqual([line.in_flight, line.queued_ms <= 50], [1, true], JSON.stringify(line));
  });

  it("control: an HTTP/1.1 request to an h2c-only server gets no answer, which is why MCP_H2C=1 and --use-http2 go together", async () => {
    await assert.rejects(fetch(`${srv.base}/health`));
  });
});

// #2775, as the canary of 2026-10-05 met it: the API answers check_sbom's batch 429 with a
// Retry-After the call waits out (production's 1,200 components a minute per caller), and the
// client goes during that wait. The wait must end when the client goes, not when it runs out: the
// slot is free within ~1 s, no batch is sent again, the access line says 499 with duration_ms
// about the time the client held on (the call stopped then), and mcp_client_gone says when the
// server learned it and that no answer had started. Over HTTP/1.1 (a closed socket) and over h2c
// (a reset stream on a connection that stays open).
describe("#2775: a check_sbom call waiting out a 429's Retry-After stops when its client goes", () => {
  let stub, h1, h2, session;
  before(async () => {
    stub = await slowStub();
    const env = { ECHELONGRAPH_API_BASE: stub.base, MCP_RATE_LIMIT_PER_MIN: "1000", MCP_LARGE_BODY_SLOTS: "1", MCP_MAX_IN_FLIGHT: "3" };
    h1 = await startHttp(env);
    h2 = await startHttp({ ...env, MCP_H2C: "1" });
    session = http2.connect(h2.base);
    session.on("error", () => {});
  });
  after(async () => {
    session?.close();
    await h1?.stop();
    await h2?.stop();
    await stub?.close();
  });
  const purls = { name: "check_sbom", arguments: { purls: Array.from({ length: 2000 }, (_, i) => `pkg:npm/a-longer-package-name-${i}@1.0.0`) } };
  const probe = { name: "check_sbom", arguments: { sbom: "x".repeat(70 * 1024) } };
  const goneLines = (srv) => srv.lines.map((l) => JSON.parse(l)).filter((j) => j.message === "mcp_client_gone");

  for (const proto of ["http/1.1", "h2c"]) {
    it(`${proto}: the client goes 700 ms into a 20 s Retry-After wait; the call stops then, and frees its slot`, async () => {
      const srv = proto === "h2c" ? h2 : h1;
      stub.state.retryAfter = 20;
      const batchesBefore = stub.state.batches;
      const before = accessLines(srv).length;
      const goneBefore = goneLines(srv).length;
      const sentAt = Date.now();
      let close;
      if (proto === "h2c") {
        const { stream } = h2Call(session, "modern", purls);
        close = () => stream.close(http2.constants.NGHTTP2_CANCEL);
      } else {
        const sock = await rawRequest(srv.url, "modern", purls);
        close = () => sock.destroy();
      }
      await waitFor(() => stub.state.batches > batchesBefore, "the first batch at the API (answered 429)");
      await sleep(700);
      const heldMs = Date.now() - sentAt;
      const closedAt = Date.now();
      close();
      stub.state.retryAfter = undefined;
      let freedAfter;
      while (Date.now() - closedAt < 6000) {
        const r = proto === "h2c" ? await h2Call(session, "modern", probe).answer : await modern(srv.url, "tools/call", probe);
        if (r.status !== 503) {
          assert.equal(r.status, 200, r.text.slice(0, 300));
          freedAfter = Date.now() - closedAt;
          break;
        }
        await sleep(100);
      }
      assert.ok(freedAfter !== undefined && freedAfter < 1500, `the slot was still held ${Date.now() - closedAt} ms after the client went`);
      await sleep(300);
      assert.equal(stub.state.batches - batchesBefore, 1, "the 429'd batch was sent again after the client went");
      const line = accessLines(srv)
        .slice(before)
        .find((l) => l.tool === "check_sbom" && l.body_bytes > 80_000);
      assert.ok(line, JSON.stringify(accessLines(srv).slice(before)));
      assert.deepEqual([line.status, line.client_closed], [499, true], JSON.stringify(line));
      assert.ok(line.duration_ms < heldMs + 1000, `the call ran ${line.duration_ms} ms; its client held on ${heldMs} ms`);
      const gone = goneLines(srv).slice(goneBefore);
      assert.equal(gone.length, 1, JSON.stringify(gone));
      assert.equal(gone[0].answer_started, false, JSON.stringify(gone[0]));
      assert.ok(Math.abs(gone[0].after_ms - heldMs) < 500, `learned ${gone[0].after_ms} ms in; the client went ${heldMs} ms in`);
      assert.deepEqual(Object.keys(gone[0]).sort(), ["after_ms", "answer_started", "message", "rst_code", "severity"]);
      if (proto === "h2c") assert.equal(gone[0].rst_code, http2.constants.NGHTTP2_CANCEL);
      else assert.equal(gone[0].rst_code, null);
    });
  }

  it("h2c: a reset with NO_ERROR is a client that went too", async () => {
    stub.state.retryAfter = 20;
    const batchesBefore = stub.state.batches;
    const before = accessLines(h2).length;
    const { stream } = h2Call(session, "modern", purls);
    await waitFor(() => stub.state.batches > batchesBefore, "the first batch at the API (answered 429)");
    await sleep(300);
    stream.close(http2.constants.NGHTTP2_NO_ERROR);
    stub.state.retryAfter = undefined;
    await waitFor(
      () => accessLines(h2).slice(before).some((l) => l.tool === "check_sbom" && l.body_bytes > 80_000),
      "the call's access line",
      1500,
    );
    const line = accessLines(h2)
      .slice(before)
      .find((l) => l.tool === "check_sbom" && l.body_bytes > 80_000);
    assert.deepEqual([line.status, line.client_closed], [499, true], JSON.stringify(line));
  });

  it("an answer that is written is no client gone: no mcp_client_gone line, over either protocol", async () => {
    stub.state.retryAfter = undefined;
    stub.state.ms = 10;
    const g1 = goneLines(h1).length;
    const g2 = goneLines(h2).length;
    assert.equal((await modern(h1.url, "tools/call", { name: "cve_summary", arguments: {} })).status, 200);
    assert.equal((await h2Call(session, "modern", { name: "cve_summary", arguments: {} }).answer).status, 200);
    await sleep(200);
    assert.equal(goneLines(h1).length, g1, JSON.stringify(goneLines(h1).slice(g1)));
    assert.equal(goneLines(h2).length, g2, JSON.stringify(goneLines(h2).slice(g2)));
  });
});

describe("server.json advertises the remote (#1879's registry entry)", () => {
  it("one streamable-http remote at https://mcp.echelongraph.io/mcp, the path this server serves", () => {
    const sj = JSON.parse(readPkgFile("server.json"));
    assert.deepEqual(sj.remotes, [{ type: "streamable-http", url: "https://mcp.echelongraph.io/mcp" }]);
    assert.equal(new URL(sj.remotes[0].url).pathname, "/mcp");
  });
});

describe("start-up refuses without the forward token when deploy-all requires it", () => {
  it("MCP_REQUIRE_FORWARD_TOKEN=1 with no token exits 1 and says why", async () => {
    await assert.rejects(startHttp({ MCP_REQUIRE_FORWARD_TOKEN: "1", ECHELONGRAPH_FORWARD_TOKEN: "" }), /exited 1 before listening[\s\S]*mcp_remote_refusing_to_start/);
  });
});

describe("the npm stdio entry never sends the forward headers (no-telemetry promise)", () => {
  it("with a token and the stub's host configured, a stdio tool call carries neither header", async () => {
    const before = seen.length;
    const env = { ...process.env, ECHELONGRAPH_API_BASE: stubBase(), ECHELONGRAPH_API_TIMEOUT_MS: "2000", ECHELONGRAPH_FORWARD_TOKEN: TOKEN, ECHELONGRAPH_FORWARD_HOST: "127.0.0.1" };
    const client = await connect({ era: MODERN, ...serverCommand(), env, stderr: "ignore" });
    try {
      const res = await client.callTool({ name: "cve_summary", arguments: {} });
      assert.deepEqual(res.structuredContent.data, SUMMARY);
    } finally {
      await client.close();
    }
    const calls = seen.slice(before);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].clientIp, undefined);
    assert.equal(calls[0].token, undefined);
  });
});
