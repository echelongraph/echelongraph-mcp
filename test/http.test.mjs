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
// #3121: answers are validated against the closed success branch (strict-output.mjs).
import { StrictOutputValidator } from "./strict-output.mjs";
import { connect, MODERN, SERVER_INFO_META_KEY, StdioMcpClient } from "./mcp-stdio-client.mjs";
import { ACCEPT, legacy, modern, modernHeaders, modernMeta, parseRpcBody, post } from "./mcp-http-client.mjs";
import { PKG, PKG_DIR, readPkgFile, serverCommand } from "./server-under-test.mjs";
import { BATCH_PATH, ROWS, batchAnswer } from "./fixtures/match-batch.mjs";
import { REQUIRED, cutProblems } from "./client-cut.mjs";

const HTTP_ENTRY = path.join(PKG_DIR, "dist", "http.js");
const FIVE = ["cve_summary", "search_cves", "get_cve", "cve_exposure", "exposure_radar"];
const SUMMARY = { summary: { critical: 1, high: 2, medium: 3, low: 4, none: 0, total: 10, last_updated: "2026-09-27T01:00:00Z" } };
const TOKEN = "forward-token-for-tests-2316";
const MARKER = "zzmarkerterm2316";
// The platform's chain for a direct client at `addr` (core-backend ratelimitkey_test.go).
const chain = (addr) => `${addr}, 169.254.169.126, 0.0.0.0`;
const validator = new StrictOutputValidator();

// A bound on this whole file (M1's review of #2775): a large-body slot held forever (a wait that never times out)
// hung the file until the CI job's own 20-minute limit killed it, a hang and not a failure. The two describes that
// wait for a slot carry their own timeouts below; this catches a hang anywhere else. The file runs in about a minute
// alone and a few beside the rest of npm test. Each test file runs in its own process (node --test), so exiting fails
// this file only; unref()'d, it never keeps the process alive.
const FILE_BOUND_MS = 10 * 60_000;
setTimeout(() => {
  process.stderr.write(`http.test.mjs: still running after ${FILE_BOUND_MS / 60_000} minutes, so a test hangs: failing the file\n`);
  process.exit(1);
}, FILE_BOUND_MS).unref();

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
// Every stdout line of every server this file starts, and each one's stderr, for #2863's checks at the end.
const EVERY_LINE = [];
const EVERY_STDERR = [];
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
  EVERY_STDERR.push(() => stderr);
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
        EVERY_LINE.push(line);
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

  // #2842 (step 5): the client cut, over the hosted transport. tools.test.mjs holds stdio to it and
  // its controls show cutProblems failing; this holds the HTTP entry to the same check in both eras,
  // so a text the hosted build serves differently (instructions on server/discover, tools/list over
  // POST) cannot pass stdio and fail here unseen.
  describe(`#2842: the client ${REQUIRED.CLIENT_DESCRIPTION_CUT.toLocaleString("en-US")}-character cut over HTTP`, () => {
    for (const era of ["modern", "legacy 2025-06-18"]) {
      it(`${era}: the instructions and every description fit the cut, and each head holds its required sentences`, async () => {
        const opening = era === "modern"
          ? (await modern(srv.url, "server/discover")).message.result
          : (await legacy(srv.url, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } })).message.result;
        const list = era === "modern" ? await modern(srv.url, "tools/list") : await legacy(srv.url, "tools/list", {}, { revision: "2025-06-18" });
        assert.equal(list.status, 200, list.text);
        const served = { instructions: opening.instructions, tools: list.message.result.tools };
        assert.equal(typeof served.instructions, "string", "the opening exchange carries no instructions");
        assert.deepEqual(cutProblems(served), []);
        // The check can fail here too: the same served text with one description past the cut.
        const grown = { ...served, tools: served.tools.map((t) => (t.name === "get_cwe" ? { ...t, description: `${t.description} ${"y".repeat(REQUIRED.CLIENT_DESCRIPTION_CUT)}` } : t)) };
        assert.ok(cutProblems(grown).some((p) => p.startsWith("(b) get_cwe")), "control: a get_cwe description past the cut was not caught");
      });
    }
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

// #2835: scan_manifest's files are the request body over the hosted endpoint, as check_sbom's
// document is. A real package-lock (fixtures/manifests/tree.v3.package-lock.json, written by npm
// 10), its registry entries cycled under new names to 700 distinct packages: ~200 KiB of
// lockfile, three times the general 64 KiB cap. Control: before #2835, LARGE_BODY_TARGETS named
// check_sbom alone, and this body was refused 413. It now names a tools/call of check_sbom or
// scan_manifest and a prompts/get of sbom_review (#3149), and nothing else.
describe("#2835: scan_manifest takes a lockfile past 64 KiB over the hosted endpoint", () => {
  const TREE = JSON.parse(fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures", "manifests", "tree.v3.package-lock.json"), "utf8"));
  const registry = Object.entries(TREE.packages).filter(([k, e]) => k.startsWith("node_modules/") && !e.link && String(e.resolved ?? "").startsWith("https://registry.npmjs.org/"));
  const packages = { "": TREE.packages[""] };
  for (let i = 0; i < 700; i++) {
    const [key, e] = registry[i % registry.length];
    // name: undefined drops an alias's own name, so each copy is its own package.
    packages[`node_modules/${key.split("node_modules/").pop().replace("@", "")}-r${i}`] = { ...e, name: undefined };
  }
  const LOCK = JSON.stringify({ ...TREE, packages }, null, 2);
  const call = { name: "scan_manifest", arguments: { files: [{ filename: "package-lock.json", content: LOCK }] } };
  const bodyBytes = Buffer.byteLength(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: call }));
  let srv;
  before(async () => {
    srv = await startHttp({ MCP_RATE_LIMIT_PER_MIN: "1000" });
  });
  after(() => srv?.stop());

  it("control: the lockfile is far past the 64 KiB general cap", () => {
    assert.ok(bodyBytes > 3 * 64 * 1024, `${bodyBytes}`);
  });
  for (const era of ["modern", "legacy 2025-06-18"]) {
    it(`${era}: tools/call scan_manifest with the lockfile answers 200, measured, every purl checked`, async () => {
      const before = batchPurls.length;
      const r = era === "modern" ? await modern(srv.url, "tools/call", call) : await legacy(srv.url, "tools/call", call, { revision: "2025-06-18" });
      assert.equal(r.status, 200, r.text.slice(0, 500));
      assert.notEqual(r.message.result.isError, true, r.text.slice(0, 500));
      const sc = r.message.result.structuredContent;
      assert.equal(sc.state, "measured");
      assert.deepEqual([sc.coverage.files_read, sc.coverage.entries_pinned, sc.coverage.distinct_purls, sc.coverage.sent, sc.coverage.not_sent], [1, 700, 700, 700, 0]);
      assert.equal(batchPurls.length - before, 700, "the batch route did not receive every purl");
    });
  }
  it("the access line names the tool and the size, and no line holds anything from the lockfile", async () => {
    await new Promise((r) => setTimeout(r, 100));
    const big = accessLines(srv).filter((l) => l.tool === "scan_manifest" && l.body_bytes > 64 * 1024);
    assert.equal(big.length, 2, JSON.stringify(accessLines(srv)));
    for (const line of srv.lines) assert.ok(!line.includes("node_modules") && !line.includes("-r1") && !line.includes("pkg:npm"), `a log line carries the lockfile: ${line.slice(0, 300)}`);
  });
});

// #2775's waits run out at 300 ms here, and the describe takes about 3 s: a slot held forever fails it at 60 s.
describe("#2747: the large-body cap and slots", { timeout: 60_000 }, () => {
  let srv;
  before(async () => {
    // #2775: a large body waits MCP_LARGE_BODY_WAIT_MS for a slot (15 s by default) before it is refused; 300 ms here.
    srv = await startHttp({ MCP_RATE_LIMIT_PER_MIN: "1000", MCP_MAX_SBOM_BODY_BYTES: "300000", MCP_LARGE_BODY_SLOTS: "1", MCP_LARGE_BODY_WAIT_MS: "300" });
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
    const linesBefore = accessLines(srv).length;
    const busy = await post(srv.url, body, { "MCP-Protocol-Version": "2025-06-18" });
    assert.equal(busy.status, 503, busy.text);
    assert.equal(busy.message.error.code, -32030);
    assert.equal(busy.headers.get("retry-after"), "5");
    // #2775: refused only once its wait for the slot ran out, and its line says how long it waited.
    await waitFor(() => accessLines(srv).slice(linesBefore).some((l) => l.refused === "large_body_busy"), "the refusal's access line");
    const refusedLine = accessLines(srv).slice(linesBefore).find((l) => l.refused === "large_body_busy");
    assert.ok(refusedLine.slot_wait_ms >= 300 && refusedLine.slot_wait_ms < 2000, JSON.stringify(refusedLine));
    // #2775: a chunked body (no Content-Length) that crosses 64 KiB while the slot is held waits too, and is refused
    // once its wait runs out, promptly, with what it had not sent discarded.
    const chunkedAt = Date.now();
    const chunked = await new Promise((resolve, reject) => {
      const req = http.request(
        { host: u.hostname, port: u.port, path: u.pathname, method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", "MCP-Protocol-Version": "2025-06-18", "Transfer-Encoding": "chunked" } },
        (res) => {
          let t = "";
          res.setEncoding("utf8").on("data", (d) => (t += d)).on("end", () => resolve({ status: res.statusCode, text: t }));
        },
      );
      req.on("error", (e) => resolve({ status: 0, text: String(e) }));
      for (let i = 0; i < body.length; i += 8192) req.write(body.slice(i, i + 8192));
      req.end();
    });
    assert.equal(chunked.status, 503, chunked.text.slice(0, 300));
    assert.ok(Date.now() - chunkedAt < 3000, `the chunked refusal took ${Date.now() - chunkedAt} ms`);
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
      let settled = false;
      // gate (#2773's 503 test): while set, an answer also waits for the test to release it, so a
      // request holds its place exactly as long as the test needs and no timer races the admission wait.
      const t = setTimeout(
        () => Promise.resolve(state.gate).then(() => {
          if (settled) return;
          settled = true;
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
        }),
        batch ? state.batchMs : state.ms,
      );
      res.on("close", () => {
        if (res.writableFinished || settled) return;
        settled = true;
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
    // The 503 test holds its two places behind the stub's gate, and the API timeout is far past any
    // hold. It used to hold them with a 4,000 ms stub against startHttp's 2,000 ms timeout: the held
    // requests gave up at 2 s and freed their places only ~500 ms after the third's 1,500 ms wait ran
    // out, so on a loaded, cold server the third was admitted and served instead of refused
    // (2026-10-17, the 3.0.2 dry run: 200 !== 503, "did not answer ... within 2000 ms").
    srv = await startHttp({ ECHELONGRAPH_API_BASE: stub.base, ECHELONGRAPH_API_TIMEOUT_MS: "30000", MCP_RATE_LIMIT_PER_MIN: "1000", MCP_MAX_IN_FLIGHT: "2", MCP_ADMISSION_WAIT_MS: "1500" });
  });
  after(async () => {
    await srv?.stop();
    await stub?.close();
  });
  const call = { name: "cve_summary", arguments: {} };
  const summary = () => modern(srv.url, "tools/call", call);

  // Its own server, with an admission wait far past any queue this test builds: it is about the cap
  // and the queue, and the next test holds the 503 deadline. On the shared 1,500 ms server the third
  // pair's wait is ~730 ms idle but reached 1,259 ms under 16 busy loops on 4 cores, and under the
  // dev box's load during the 3.0.2 tarball test one request passed 1,500 ms and was refused
  // (2026-10-17: 503 !== 200, after the dry run two minutes earlier had passed it).
  it("six at once are all answered, never more than two at a time, four of them after waiting", async () => {
    const wide = await startHttp({ ECHELONGRAPH_API_BASE: stub.base, MCP_RATE_LIMIT_PER_MIN: "1000", MCP_MAX_IN_FLIGHT: "2", MCP_ADMISSION_WAIT_MS: "20000" });
    try {
      stub.state.ms = 300;
      stub.state.maxOpen = 0;
      const before = accessLines(wide).length;
      const rs = await Promise.all(Array.from({ length: 6 }, () => modern(wide.url, "tools/call", call)));
      for (const r of rs) assert.equal(r.status, 200, r.text);
      assert.equal(stub.state.maxOpen, 2, "the API saw more than MCP_MAX_IN_FLIGHT at once");
      await sleep(100);
      const lines = accessLines(wide).slice(before);
      assert.equal(lines.length, 6);
      for (const l of lines) assert.ok(l.in_flight >= 1 && l.in_flight <= 2, JSON.stringify(l));
      assert.ok(lines.filter((l) => l.queued_ms >= 200).length >= 4, JSON.stringify(lines.map((l) => l.queued_ms)));
    } finally {
      await wide.stop();
    }
  });

  it("one that waits MCP_ADMISSION_WAIT_MS is answered 503, JSON-RPC -32030, with Retry-After; /health is never held", async () => {
    stub.state.ms = 50;
    let release;
    stub.state.gate = new Promise((resolve) => (release = resolve));
    const held = [summary(), summary()];
    try {
      await waitFor(() => stub.state.open === 2, "two requests at the API");
      const t0 = Date.now();
      const r = await summary();
      const waited = Date.now() - t0;
      assert.equal(r.status, 503, r.text);
      assert.equal(stub.state.open, 2, "refused after a held place was freed, not while both were held");
      assert.match(r.contentType, /^application\/json/);
      assert.equal(r.message.error.code, -32030);
      assert.match(r.message.error.message, /already serving its 2 requests at once/);
      assert.equal(r.headers.get("retry-after"), "5");
      assert.ok(waited >= 1400 && waited < 10_000, `answered after ${waited} ms`);
      assert.equal((await fetch(`${srv.base}/health`)).status, 200, "/health was held behind the full instance");
    } finally {
      stub.state.gate = undefined;
      release();
    }
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
    // Served at once is the server's own queued_ms below, not this test's clock: stalled uploads
    // that held the places would leave this call to wait MCP_ADMISSION_WAIT_MS and be refused 503,
    // while a wall-clock bound of 1 s failed under load with nothing held (2026-10-17).
    const r = await summary();
    for (const sock of stalled) sock.destroy();
    assert.equal(r.status, 200, r.text);
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

// A 2026-07-28 subscriptions/listen on a connection of its own. Resolves once the answer has ended,
// with every SSE event it carried, or, if it is still open after `openMs`, with the events so far
// and open: true; close() is the client leaving.
//
// #3345: since @modelcontextprotocol/server 2.2.0 (its #2651) the SDK ends a listen stream right
// after the acknowledgement when it honours none of the notification types asked for, with a
// resultType "complete" result. This server declares no listChanged (index.ts), so it honours none
// and every listen ends that way, at once. Through 3.1.0 (SDK 2.1.0) the stream stayed open,
// carrying only keepalives, until its client left, and was logged 499 then.
function openListen(url, openMs = 3000) {
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
        let timer;
        const settle = (open) => {
          clearTimeout(timer);
          const events = stream
            ? text
                .split(/\r?\n/)
                .filter((l) => l.startsWith("data:"))
                .map((l) => JSON.parse(l.slice(5).trim()))
            : [parseRpcBody(contentType, text)].filter(Boolean);
          resolve({ status: res.statusCode, contentType, stream, open, events, message: events[0], close: () => req.destroy() });
        };
        timer = setTimeout(() => settle(true), openMs);
        res.setEncoding("utf8");
        res.on("data", (d) => (text += d));
        res.on("end", () => settle(false));
        res.on("error", () => {});
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

// #2773: a listen takes no place and holds no work (httpPolicy.ts isListenStream): held open, as it
// was through SDK 2.1.0, MCP_MAX_IN_FLIGHT of them left every other request waiting
// MCP_ADMISSION_WAIT_MS for a 503. It still takes none, though it now ends at once (above).
describe("#2773: subscriptions/listen streams take no place; the gate still bounds every other request", () => {
  const N = 2;
  let stub, srv;
  before(async () => {
    stub = await slowStub();
    // The control below holds its places behind the stub's gate, and the API timeout is far past any
    // hold: a 3,000 ms stub against startHttp's 2,000 ms timeout freed them ~500 ms after the refused
    // requests' 1,500 ms wait ran out, the race the test above lost on 2026-10-17.
    srv = await startHttp({ ECHELONGRAPH_API_BASE: stub.base, ECHELONGRAPH_API_TIMEOUT_MS: "30000", MCP_RATE_LIMIT_PER_MIN: "1000", MCP_MAX_IN_FLIGHT: String(N), MCP_ADMISSION_WAIT_MS: "1500" });
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
  // Opens `count` listens, one after another; each is acknowledged, then ends with its complete
  // result, and its access line is written.
  async function openAll(count) {
    const logged = listenLines().length;
    for (let i = 0; i < count; i++) {
      const s = await openListen(srv.url);
      s.close();
      assert.equal(s.status, 200, `listen ${i + 1} of ${count}: ${JSON.stringify(s.events)}`);
      assert.ok(s.stream, s.contentType);
      assert.equal(s.open, false, `listen ${i + 1} of ${count} is still open after 3 s: ${JSON.stringify(s.events)}`);
      assert.equal(s.events[0]?.method, "notifications/subscriptions/acknowledged", JSON.stringify(s.events));
      assert.deepEqual(s.events[0].params.notifications, {}, "the acknowledgement honours a notification type this server does not send");
      assert.equal(s.events.at(-1)?.id, 1, JSON.stringify(s.events));
      assert.equal(s.events.at(-1)?.result?.resultType, "complete", JSON.stringify(s.events));
    }
    await waitFor(() => listenLines().length >= logged + count, "the listens' access lines");
  }

  it("a listen is acknowledged and ends at once with its complete result: logged 200, holding no place (in_flight 0, queued_ms 0)", async () => {
    const before = listenLines().length;
    await openAll(1);
    const line = listenLines()[before];
    assert.deepEqual(
      [line.method, line.path, line.status, line.client_closed, line.refused, line.in_flight, line.queued_ms, line.protocol_version],
      ["POST", "/mcp", 200, false, "", 0, 0, MODERN],
      JSON.stringify(line),
    );
    assert.ok(line.body_bytes > 0 && line.duration_ms < 3000, JSON.stringify(line));
  });

  for (const era of ["modern", "legacy"]) {
    it(`${N + 5} listens, MCP_MAX_IN_FLIGHT ${N}: a ${era} tools/call, and the era's opening request, are answered 200 at once`, async () => {
      stub.state.ms = 50;
      await openAll(N + 5);
      const before = accessLines(srv).length;
      // "At once" is the server's own queued_ms below, not this test's clock (a wall-clock bound of
      // 1 s failed 2 runs in 6 on a loaded runner, 2026-10-17, with nothing held).
      const r = await summary(era);
      assert.equal(r.status, 200, r.text);
      assert.notEqual(r.message.result.isError, true, r.text);
      assert.deepEqual(r.message.result.structuredContent.data, SUMMARY);
      const o = await opening(era);
      assert.equal(o.status, 200, o.text);
      await sleep(100);
      const line = accessLines(srv)
        .slice(before)
        .find((l) => l.rpc_method === "tools/call");
      assert.deepEqual([line.status, line.in_flight, line.queued_ms <= 50], [200, 1, true], JSON.stringify(line));
    });
  }

  it(`control: with every place taken a 2026-era listen is answered at once, while ordinary calls of both eras, and a 2025-era body naming subscriptions/listen, wait like any request, then 503`, async () => {
    let release = () => {};
    try {
      stub.state.ms = 50;
      stub.state.maxOpen = 0;
      stub.state.gate = new Promise((resolve) => (release = resolve));
      const held = [summary("modern"), summary("legacy")];
      await waitFor(() => stub.state.open === N, `${N} calls at the API`);
      // A listen opened now, with every place taken, is served at once: it is not admitted. Were it
      // admitted, it would wait MCP_ADMISSION_WAIT_MS and be refused 503 like the requests below.
      const t0 = Date.now();
      await openAll(1);
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
      assert.equal(stub.state.open, N, "refused after a held place was freed, not while every place was held");
      assert.ok(waited >= 1400 && waited < 10_000, `answered after ${waited} ms`);
      stub.state.gate = undefined;
      release();
      for (const h of await Promise.all(held)) assert.equal(h.status, 200, h.text);
      assert.equal(stub.state.maxOpen, N, "the API saw more than MCP_MAX_IN_FLIGHT at once");
    } finally {
      stub.state.gate = undefined;
      release();
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
    // The server writes each access line to its stdout as it answers, and this process reads that
    // pipe on its own schedule, so a line can arrive after its response. Under load (the whole
    // suite, load 9) the /health line arrived after `before` was taken and was read as a third
    // line, [undefined, 200, false]: a GET has no tool. Wait for it, and for the two calls' lines,
    // rather than for a fixed 50 ms.
    await waitFor(() => accessLines(srv).some((l) => l.method === "GET" && l.path === "/health"), "the /health request's access line");
    stub.state.ms = 10;
    const before = accessLines(srv).length;
    for (const era of ["modern", "legacy"]) {
      const r = await h2Call(session, era, { name: "cve_summary", arguments: {} }).answer;
      assert.equal(r.status, 200, r.text.slice(0, 300));
      assert.deepEqual(r.message.result.structuredContent.data, SUMMARY, `${era}: ${r.text.slice(0, 300)}`);
    }
    await waitFor(() => accessLines(srv).length >= before + 2, "the two calls' access lines");
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

  // The flake above, made to happen: this process stops reading the server's stdout across the
  // /health request, as a loaded box can, so its access line is read after `before` is taken. It is
  // then the third line the flake showed, [undefined, 200, false], a GET of /health.
  it("control: an access line read after its response lands after `before`, as the flake's [undefined, 200, false] did", async () => {
    srv.proc.stdout.pause();
    let before;
    try {
      const health = await h2Get(session, "/health");
      assert.equal(health.status, 200);
      before = accessLines(srv).length;
    } finally {
      srv.proc.stdout.resume();
    }
    await waitFor(() => accessLines(srv).length > before, "the /health line, read late");
    const late = accessLines(srv).slice(before);
    assert.deepEqual(late.map((l) => [l.tool, l.status, l.client_closed]), [[undefined, 200, false]]);
    assert.deepEqual([late[0].method, late[0].path], ["GET", "/health"]);
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

  // The HTTP/1.1 waiter test below sends only 8 KiB of its body: there a close that sits behind bytes the server has
  // not read is seen only once they are read, at the waiter's turn. This is the same waiter over production's
  // protocol, its whole body sent: h2 flow control lets 65,535 bytes of it out (the stream window, unread while it
  // waits; Node 20, 22 and 24 alike) and holds the rest. Its stream is then reset: the reset is a frame the session
  // reads whatever the stream holds, so the waiter leaves the queue then, not at its turn. Without this test no h2c
  // test had a waiter: with readBody's slot wait deaf to its client (Slots.acquire without the signal), all passed.
  it("a waiter whose stream is reset leaves the queue while the slot is held: 499, and the next waiter gets the slot", async () => {
    stub.state.batchMs = 500;
    await waitFor(() => stub.state.open === 0, "the API to be idle");
    const before = accessLines(srv).length;
    const batches = stub.state.batches;
    let holderDone = false;
    const held = h2Call(session, "modern", purls).answer.finally(() => (holderDone = true));
    await waitFor(() => stub.state.batches > batches, "the holder's first batch at the API");
    // Ten batches of 500 ms: the holder holds the slot for 5 s at least. The waits below are as the HTTP/1.1 test's.
    const waiter = h2Call(session, "modern", probe);
    await sleep(600);
    const next = h2Call(session, "modern", probe).answer;
    await sleep(600);
    assert.ok(!holderDone, "the holder was done before the waiter's stream was reset: nothing would be tested");
    waiter.stream.close(http2.constants.NGHTTP2_CANCEL);
    await waitFor(() => accessLines(srv).slice(before).some((l) => l.status === 499), "the reset waiter's access line", 20_000);
    // It left when its stream was reset, while the slot was held: its line comes before the holder's. The server's
    // own lines say so, not the holder's answer reaching this client: with the waiter made deaf to its reset, the
    // holder's stream closed here only after the server had logged the waiter leaving at its turn.
    const atGone = accessLines(srv).slice(before);
    assert.ok(!atGone.some((l) => l.body_bytes > 80_000), `the reset waiter left only at its turn, after the holder: ${JSON.stringify(atGone)}`);
    const gone = atGone.find((l) => l.status === 499);
    assert.deepEqual([gone.refused, gone.client_closed, gone.body_bytes], ["client_closed", true, 0], JSON.stringify(gone));
    assert.ok(gone.slot_wait_ms > 0, `it never waited for the slot: ${JSON.stringify(gone)}`);
    const [n, h] = await Promise.all([next, held]);
    assert.deepEqual([n.status, h.status], [200, 200], n.text.slice(0, 300));
    assert.ok(!session.closed && !session.destroyed, "the connection stayed open, as Cloud Run's does");
    await waitFor(() => accessLines(srv).length >= before + 3, "3 access lines");
    const served = accessLines(srv).slice(before).filter((l) => l.status === 200 && l.body_bytes < 80_000);
    assert.ok(served.some((l) => l.slot_wait_ms > 0), `the next waiter did not wait for the slot: ${JSON.stringify(served)}`);
  });

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

  // 3.1.0's final panel: under h2c rst_code was the client's own RST_STREAM code, any 32-bit number (0x7a71c0de logged
  // 2054275294). It is a code HTTP/2 defines, else (other).
  it("h2c: a reset whose code HTTP/2 does not define logs rst_code (other), never the client's number", async () => {
    stub.state.retryAfter = 20;
    const batchesBefore = stub.state.batches;
    const goneBefore = goneLines(h2).length;
    const { stream } = h2Call(session, "modern", purls);
    await waitFor(() => stub.state.batches > batchesBefore, "the first batch at the API (answered 429)");
    await sleep(300);
    stream.close(0x7a71c0de);
    stub.state.retryAfter = undefined;
    await waitFor(() => goneLines(h2).length > goneBefore, "its mcp_client_gone line", 1500);
    const gone = goneLines(h2).slice(goneBefore);
    assert.equal(gone.length, 1, JSON.stringify(gone));
    assert.equal(gone[0].rst_code, "(other)", JSON.stringify(gone[0]));
    assert.ok(!h2.lines.some((l) => l.includes(String(0x7a71c0de))), "the client's reset code reached a log line");
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

// ── #2775, decided 2026-10-18: a large body that finds every slot busy waits for one ──
// Behind the Google Frontend a client's close reaches the container too late to free its slot (the 2026-10-18 probe:
// both follow-up bodies sent 1 s after two aborted check_sbom calls were refused 503 large_body_busy while those calls
// ran on to 200). So the retry is made to succeed instead: a large body that finds both slots busy waits up to
// DEFAULT_LARGE_BODY_WAIT_MS (15 s) for one, at most DEFAULT_LARGE_BODY_WAITERS (2) at once, first come first served,
// and is refused as before only when its wait runs out, or at once when two already wait. The access line records the
// wait (slot_wait_ms); mcp_large_body_busy is written only on a real refusal.
// M1's review: with Slots.acquire's wait made endless, this describe hung the file (killed at 300 s, no failure). Its
// four tests take about 15 s together; a slot held forever now fails it at 90 s.
describe("#2775: a large body that finds every slot busy waits up to 15 s for one, two at most", { timeout: 90_000 }, () => {
  let stub;
  let srv;
  before(async () => {
    stub = await slowStub();
    srv = await startHttp({ ECHELONGRAPH_API_BASE: stub.base, MCP_RATE_LIMIT_PER_MIN: "1000", MCP_LARGE_BODY_SLOTS: "1", MCP_MAX_IN_FLIGHT: "8" });
  });
  after(async () => {
    await srv?.stop();
    await stub?.close();
  });
  const purls = { name: "check_sbom", arguments: { purls: Array.from({ length: 2000 }, (_, i) => `pkg:npm/a-longer-package-name-${i}@1.0.0`) } };
  // A body past 64 KiB that needs the slot and makes no API call: a document that is not JSON.
  const probe = { name: "check_sbom", arguments: { sbom: "x".repeat(70 * 1024) } };
  const busyLines = () => srv.lines.map((l) => JSON.parse(l)).filter((j) => j.message === "mcp_large_body_busy");
  // A request's access line is written once it has settled, after its answer: wait for this test's n lines.
  const settled = (before, n) => waitFor(() => accessLines(srv).length >= before + n, `${n} access lines`);
  // In each test the 2,000-purl call (~85 KB) holds the only slot for its ten batches, 300 ms each.
  it("a retry while the slot is held waits, then is served: 200, slot_wait_ms > 0, no mcp_large_body_busy", async () => {
    const before = accessLines(srv).length;
    const busyBefore = busyLines().length;
    stub.state.batchMs = 300;
    const batches = stub.state.batches;
    const held = modern(srv.url, "tools/call", purls);
    await waitFor(() => stub.state.batches > batches, "the holder's first batch at the API");
    const t0 = Date.now();
    const retry = await modern(srv.url, "tools/call", probe);
    const waited = Date.now() - t0;
    assert.equal(retry.status, 200, retry.text.slice(0, 300));
    assert.equal(retry.message.result.structuredContent.state, "invalid_input");
    const h = await held;
    assert.equal(h.status, 200, h.text.slice(0, 300));
    assert.ok(waited > 500, `the retry was answered in ${waited} ms, so it never waited for the slot`);
    await settled(before, 2);
    const line = accessLines(srv).slice(before).find((l) => l.tool === "check_sbom" && l.body_bytes < 80_000);
    assert.ok(line, JSON.stringify(accessLines(srv).slice(before)));
    assert.deepEqual([line.status, line.refused], [200, ""], JSON.stringify(line));
    assert.ok(line.slot_wait_ms > 0 && line.slot_wait_ms < 15_000, `slot_wait_ms ${line.slot_wait_ms}`);
    const holder = accessLines(srv).slice(before).find((l) => l.tool === "check_sbom" && l.body_bytes > 80_000);
    assert.equal(holder.slot_wait_ms, 0, "the holder found the slot free");
    assert.equal(busyLines().length, busyBefore, "mcp_large_body_busy was written for a body that was served");
  });

  it("with two already waiting, a third large body is refused at once: 503 -32030, slot_wait_ms 0, one mcp_large_body_busy", async () => {
    const before = accessLines(srv).length;
    const busyBefore = busyLines().length;
    stub.state.batchMs = 300;
    const batches = stub.state.batches;
    const held = modern(srv.url, "tools/call", purls);
    await waitFor(() => stub.state.batches > batches, "the holder's first batch at the API");
    const w1 = modern(srv.url, "tools/call", probe);
    const w2 = modern(srv.url, "tools/call", probe);
    await sleep(300);
    const t0 = Date.now();
    const third = await modern(srv.url, "tools/call", probe);
    const took = Date.now() - t0;
    assert.equal(third.status, 503, third.text.slice(0, 300));
    assert.equal(third.message.error.code, -32030);
    assert.equal(third.headers.get("retry-after"), "5");
    assert.ok(took < 1000, `the third waited ${took} ms`);
    const [a, b, h] = await Promise.all([w1, w2, held]);
    assert.deepEqual([a.status, b.status, h.status], [200, 200, 200], "a waiter or the holder was not served");
    await settled(before, 4);
    const lines = accessLines(srv).slice(before);
    const refused = lines.filter((l) => l.refused === "large_body_busy");
    assert.equal(refused.length, 1, JSON.stringify(lines));
    assert.equal(refused[0].slot_wait_ms, 0, JSON.stringify(refused[0]));
    assert.equal(lines.filter((l) => l.tool === "check_sbom" && l.body_bytes < 80_000 && l.status === 200 && l.slot_wait_ms > 0).length, 2, JSON.stringify(lines));
    assert.equal(busyLines().length - busyBefore, 1, "mcp_large_body_busy is not written once, for the one refusal");
  });

  // 3.1.0's release dry run (2026-10-25) failed this under load: "timed out waiting for the gone waiter's access
  // line". The gone waiter had sent its whole ~72 KB body. Over HTTP/1.1 a client's close is read only after the bytes
  // it sent, and a waiting body is not read on: once the request's read buffer is full the close sits unread until the
  // waiter gets the slot, and the waiter was then read and answered 200, with no 499. The buffer is 16 KiB on Node 20,
  // so there it failed every run; from Node 22 it is 64 KiB, so it failed when the server's first read of the body
  // ended past 64 KiB, before the rest came (a write split there fails it every run). So this waiter sends 8 KiB of
  // its body, as a client whose upload is held does, and its close is read when it comes. (Over h2c, production's
  // protocol, a reset is read whatever its stream holds: the h2c test "a waiter whose stream is reset leaves the
  // queue while the slot is held", above, sends its whole body.)
  it("a waiter whose client goes leaves the queue: it is 499, and the next waiter gets the slot", async () => {
    const before = accessLines(srv).length;
    // Ten batches of 500 ms: the holder holds the slot for 5 s at least, across the waits below.
    stub.state.batchMs = 500;
    const batches = stub.state.batches;
    let holderDone = false;
    const held = modern(srv.url, "tools/call", purls).finally(() => (holderDone = true));
    await waitFor(() => stub.state.batches > batches, "the holder's first batch at the API");
    const sock = await rawRequest(srv.url, "modern", probe, { bytes: 8192 });
    // rawRequest resolves once its bytes are written, not once the server has them, and the server says nothing when
    // a body starts to wait: these waits are long enough for a loaded machine to queue each waiter in turn.
    await sleep(600);
    const next = modern(srv.url, "tools/call", probe);
    await sleep(600);
    assert.ok(!holderDone, "the holder was done before the waiter's client went: nothing would be tested");
    sock.destroy();
    await waitFor(() => accessLines(srv).slice(before).some((l) => l.status === 499), "the gone waiter's access line", 20_000);
    // It left the queue when its client went, while the slot was still held: not at its turn, after the holder.
    assert.ok(!holderDone, "the gone waiter's line came only after the holder's answer");
    const gone = accessLines(srv).slice(before).find((l) => l.status === 499);
    assert.deepEqual([gone.refused, gone.client_closed], ["client_closed", true], JSON.stringify(gone));
    assert.ok(gone.slot_wait_ms > 0, `it never waited for the slot: ${JSON.stringify(gone)}`);
    const [n, h] = await Promise.all([next, held]);
    assert.deepEqual([n.status, h.status], [200, 200]);
    // The slot is free again: a large body is served at once.
    const t0 = Date.now();
    assert.equal((await modern(srv.url, "tools/call", probe)).status, 200);
    assert.ok(Date.now() - t0 < 1000, "the gone waiter kept a slot");
    await settled(before, 4);
    const served = accessLines(srv).slice(before).filter((l) => l.status === 200 && l.body_bytes < 80_000);
    assert.ok(served.some((l) => l.slot_wait_ms > 0), `the next waiter did not wait for the slot: ${JSON.stringify(served)}`);
  });

  it("a chunked large body (no Content-Length) that crosses 64 KiB while the slot is held waits too, and is served", async () => {
    const before = accessLines(srv).length;
    stub.state.batchMs = 300;
    const batches = stub.state.batches;
    const held = modern(srv.url, "tools/call", purls);
    await waitFor(() => stub.state.batches > batches, "the holder's first batch at the API");
    const u = new URL(srv.url);
    const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: probe });
    const chunked = await new Promise((resolve, reject) => {
      const req = http.request(
        { host: u.hostname, port: u.port, path: u.pathname, method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", "MCP-Protocol-Version": "2025-06-18", "Transfer-Encoding": "chunked" } },
        (res) => {
          let t = "";
          res.setEncoding("utf8").on("data", (d) => (t += d)).on("end", () => resolve({ status: res.statusCode, text: t }));
        },
      );
      req.on("error", reject);
      for (let i = 0; i < body.length; i += 8192) req.write(body.slice(i, i + 8192));
      req.end();
    });
    assert.equal(chunked.status, 200, chunked.text.slice(0, 300));
    assert.equal((await held).status, 200);
    await settled(before, 2);
    const line = accessLines(srv).slice(before).find((l) => l.tool === "check_sbom" && l.body_bytes < 80_000);
    assert.ok(line && line.slot_wait_ms > 0, JSON.stringify(accessLines(srv).slice(before)));
  });
});

// ── #2948: every upstream failure writes one line ──
// On 2026-10-07 a hosted get_cve answered "EchelonGraph at https://app.echelongraph.io could not be
// reached for GET /api/…" in 460 ms, core-backend logged no request for it, and the hosted service
// logged only mcp_request status=200: the cause (reset, timeout, DNS or a status) went to the client
// and nowhere else. The 2.7.1 audit found the same for the synthetic's 10-08 state=failed answers
// (vendor_advisories_for_cve, epss_history: core-backend 503s). Each API call that fails now writes
// one mcp_upstream_failed line: the failure class, the API route as a template (core-backend's own
// route names, no ID and no query string) and the tool, never an argument. WARNING, except for the
// API's own answer about the input (a 400, or a 404 for a named record), which the tool reports as
// invalid input or no record and which is INFO. A call cancelled because its client went is no
// upstream failure: mcp_client_gone says so. This stub fails each way on purpose.
async function failingStub() {
  // mode, per request: state.byPath[pathname] ?? state.mode. ok: the JSON a 200 carries.
  const state = { mode: "503", byPath: {}, ok: {}, urls: [], headers: [] };
  const sockets = new Set();
  const server = http.createServer((req, res) => {
    const u = new URL(req.url, "http://stub");
    state.urls.push(req.url);
    state.headers.push(req.headers);
    req.resume();
    const mode = state.byPath[u.pathname] ?? state.mode;
    const json = (status, v) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(v));
    };
    if (mode === "hang") return; // never answers: the API timeout fires
    if (mode === "reset") return void req.socket.resetAndDestroy(); // TCP RST: ECONNRESET
    if (mode === "close") return void req.socket.destroy(); // closed before any answer: undici's "other side closed"
    if (mode === "midbody") {
      res.writeHead(200, { "content-type": "application/json", "content-length": "1000" });
      res.write('{"cve_id":');
      setTimeout(() => req.socket.resetAndDestroy(), 30);
      return;
    }
    if (mode === "html") {
      res.writeHead(200, { "content-type": "text/html" });
      return void res.end("<html><title>Just a moment...</title></html>");
    }
    if (mode === "ok") return json(200, state.ok[u.pathname] ?? {});
    const status = Number(mode);
    json(status, { error: `stub ${status}` });
  });
  server.on("connection", (s) => {
    sockets.add(s);
    s.on("close", () => sockets.delete(s));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    state,
    base: `http://127.0.0.1:${server.address().port}`,
    close: () =>
      new Promise((resolve) => {
        for (const s of sockets) s.destroy();
        server.close(resolve);
      }),
  };
}

const CVE_MARK = "CVE-2099-29480";
const TERM_2948 = "zzterm2948upstream";
const PRODUCT_2948 = "zzproduct2948";
const VERSION_2948 = "9.29.48";
const VENDOR_2948 = "zzvendor2948";
const ADVISORY_2948 = "ZZ-ADV-2948-0001";
const MARKS_2948 = [CVE_MARK, TERM_2948, PRODUCT_2948, VERSION_2948, VENDOR_2948, ADVISORY_2948];
const UPSTREAM_KEYS = ["after_ms", "failure_class", "message", "route", "rpc_method", "severity", "status", "synthetic", "tool"];
const parsedLines = (lines) => lines.map((l) => JSON.parse(l));
const upstreamOf = (lines) => parsedLines(lines).filter((j) => j.message === "mcp_upstream_failed");

describe("#2948: every upstream failure of the hosted endpoint writes one mcp_upstream_failed line", () => {
  let fs2948, srv;
  before(async () => {
    fs2948 = await failingStub();
    srv = await startHttp({ ECHELONGRAPH_API_BASE: fs2948.base, ECHELONGRAPH_API_TIMEOUT_MS: "500", MCP_RATE_LIMIT_PER_MIN: "1000" });
  });
  after(async () => {
    await srv?.stop();
    await fs2948?.close();
  });

  // One hosted call and every line it wrote. Its upstream lines are written before its answer and
  // its access line after, so once the access line is in, every line of the call is.
  async function call(server, method, params, { headers } = {}) {
    const from = server.lines.length;
    const r = await modern(server.url, method, params, { headers });
    const mine = (j) => j.message === "mcp_request" && j.rpc_method === method && (method !== "tools/call" || j.tool === params.name);
    await waitFor(() => parsedLines(server.lines.slice(from)).some(mine), `the access line of ${method} ${params.name ?? params.uri ?? ""}`);
    const raw = server.lines.slice(from);
    return { r, result: r.message?.result, upstream: upstreamOf(raw), raw };
  }
  const tool = (name, args, opts) => call(srv, "tools/call", { name, arguments: args }, opts);
  // Nothing typed reaches any line the call wrote, in any case.
  const noMarks = (raw) => {
    for (const line of raw) for (const m of MARKS_2948) assert.ok(!line.toLowerCase().includes(m.toLowerCase()), `a log line carries ${m}: ${line}`);
  };
  const one = (got) => {
    assert.equal(got.upstream.length, 1, `want one mcp_upstream_failed line, got ${JSON.stringify(got.upstream)}`);
    const [line] = got.upstream;
    assert.deepEqual(Object.keys(line).sort(), UPSTREAM_KEYS, JSON.stringify(line));
    noMarks(got.raw);
    return line;
  };
  const without = (line, ...keys) => Object.fromEntries(Object.entries(line).filter(([k]) => !keys.includes(k)));

  it("an HTTP 5xx: one WARNING line with the class, the status, the route template and the tool, and no argument", async () => {
    fs2948.state.mode = "503";
    const before = fs2948.state.urls.length;
    const got = await tool("get_cve", { cve_id: CVE_MARK });
    // Controls: the failure reached the client as a failure, and the CVE ID was in the API URL.
    assert.equal(got.result?.isError, true, got.r.text);
    assert.equal(got.result.structuredContent.state, "failed");
    assert.equal(got.result.structuredContent.error.status, 503);
    assert.ok(fs2948.state.urls.slice(before).some((u) => u.includes(CVE_MARK)), "control: the CVE ID never reached the stub's URL");
    const line = one(got);
    assert.deepEqual(without(line, "after_ms"), {
      severity: "WARNING",
      message: "mcp_upstream_failed",
      tool: "get_cve",
      rpc_method: "tools/call",
      route: "/api/v1/public/cves/:id",
      failure_class: "http",
      status: 503,
      synthetic: false,
    });
    assert.ok(Number.isInteger(line.after_ms) && line.after_ms >= 0 && line.after_ms < 5000, `after_ms ${line.after_ms}`);
  });

  for (const [mode, cls, why] of [
    ["hang", "timeout", "no answer within ECHELONGRAPH_API_TIMEOUT_MS"],
    ["reset", "reset", "a TCP reset before any answer (ECONNRESET)"],
    ["close", "reset", "the connection closed before any answer (undici: other side closed)"],
    ["midbody", "reset", "a reset after the status line, while the body was read"],
  ]) {
    it(`${why}: failure_class ${cls}, status null`, async () => {
      fs2948.state.mode = mode;
      const got = await tool("get_cve", { cve_id: CVE_MARK });
      assert.equal(got.result?.isError, true, got.r.text);
      const line = one(got);
      assert.deepEqual(without(line, "after_ms"), { severity: "WARNING", message: "mcp_upstream_failed", tool: "get_cve", rpc_method: "tools/call", route: "/api/v1/public/cves/:id", failure_class: cls, status: null, synthetic: false });
      if (cls === "timeout") assert.ok(line.after_ms >= 450, `a 500 ms timeout logged after ${line.after_ms} ms`);
    });
  }

  it("a 2xx that is not JSON (an edge challenge page): failure_class not_json, with its status", async () => {
    fs2948.state.mode = "html";
    const line = one(await tool("get_cve", { cve_id: CVE_MARK }));
    assert.deepEqual([line.severity, line.failure_class, line.status, line.route], ["WARNING", "not_json", 200, "/api/v1/public/cves/:id"]);
  });

  it("search_cves: the route carries no query string, and neither the search term nor a filter is in any line", async () => {
    fs2948.state.mode = "503";
    const before = fs2948.state.urls.length;
    const got = await tool("search_cves", { search: TERM_2948, severity: "CRITICAL", limit: 7 });
    assert.ok(fs2948.state.urls.slice(before).some((u) => u.includes("?") && u.includes("CRITICAL")), "control: the filters never reached the stub's query string");
    assert.ok(fs2948.state.headers.slice(before).some((h) => decodeURIComponent(h["x-eg-search"] ?? "") === TERM_2948), "control: the term never reached the stub");
    const line = one(got);
    assert.deepEqual([line.tool, line.route, line.status], ["search_cves", "/api/v1/public/cves/", 503]);
    for (const raw of got.raw) assert.ok(!raw.includes("CRITICAL") && !raw.includes("?"), `a line carries the query: ${raw}`);
  });

  it("check_affected and get_vendor_advisory: product, version, vendor and advisory ID are in no line", async () => {
    fs2948.state.mode = "503";
    const a = one(await tool("check_affected", { product: PRODUCT_2948, version: VERSION_2948 }));
    assert.deepEqual([a.tool, a.route, a.status], ["check_affected", "/api/v1/public/cves/match", 503]);
    const v = await tool("get_vendor_advisory", { vendor: VENDOR_2948, advisory_id: ADVISORY_2948 });
    noMarks(v.raw);
    const routes = v.upstream.map((l) => l.route).sort();
    assert.ok(routes.includes("/api/v1/public/vendor-advisories/:vendor/:advisory_id"), JSON.stringify(v.upstream));
    for (const l of v.upstream) assert.deepEqual([l.tool, l.severity, l.status], ["get_vendor_advisory", "WARNING", 503]);
  });

  it("exposure_radar: one line per radar whose call failed, each its own route (ai-exposure's without ?service=mcp)", async () => {
    fs2948.state.mode = "503";
    const got = await tool("exposure_radar", {});
    noMarks(got.raw);
    assert.deepEqual(got.upstream.map((l) => l.route).sort(), [
      "/api/v1/public/ai-exposure/stats",
      "/api/v1/public/exposed-databases/stats",
      "/api/v1/public/kev-exposure/stats",
      "/api/v1/public/leaked-credentials/stats",
      "/api/v1/public/shadow-ai-radar/stats",
    ]);
    for (const l of got.upstream) assert.deepEqual([l.tool, l.failure_class, l.status], ["exposure_radar", "http", 503]);
  });

  it("the API's answer about the input is INFO: a 404 for a named record and a 400; a 404 on a route with no ID is WARNING", async () => {
    fs2948.state.mode = "404";
    const missing = one(await tool("get_cve", { cve_id: CVE_MARK }));
    assert.deepEqual([missing.severity, missing.failure_class, missing.status, missing.route], ["INFO", "http", 404, "/api/v1/public/cves/:id"]);
    const gone = one(await tool("cve_summary", {}));
    assert.deepEqual([gone.severity, gone.status, gone.route], ["WARNING", 404, "/api/v1/public/cves/summary"]);
    fs2948.state.mode = "400";
    const refused = one(await tool("get_cve", { cve_id: CVE_MARK }));
    assert.deepEqual([refused.severity, refused.status], ["INFO", 400]);
    fs2948.state.mode = "429";
    const limited = one(await tool("get_cve", { cve_id: CVE_MARK }));
    assert.deepEqual([limited.severity, limited.status], ["WARNING", 429]);
  });

  it("a 2xx the tool cannot use is unexpected_shape: cve_intel with none of its sections, exposure_radar's mcp_servers without its counts", async () => {
    fs2948.state.mode = "ok";
    fs2948.state.ok = {};
    const intel = await tool("cve_intel", { cve_id: CVE_MARK });
    assert.equal(intel.result.structuredContent.error.kind, "unexpected_shape", intel.r.text);
    const i = one(intel);
    assert.deepEqual(without(i, "message"), { severity: "WARNING", tool: "cve_intel", rpc_method: "tools/call", route: "/api/v1/public/cves/:id/enrichment", failure_class: "unexpected_shape", status: 200, after_ms: null, synthetic: false });
    const radar = await tool("exposure_radar", {});
    const r = one(radar);
    assert.deepEqual([r.tool, r.route, r.failure_class, r.status], ["exposure_radar", "/api/v1/public/ai-exposure/stats", "unexpected_shape", 200]);
    // An answer refused against the tool's own outputSchema (index.ts checked()) has no path at hand. #2948's review: it
    // is this server's fault (its schema, or an envelope it built), not the API's: class output_schema, at ERROR, which
    // the upstream metric (WARNING lines) and its alert do not count. The client's error kind is unchanged.
    fs2948.state.ok = { "/api/v1/public/cves/summary": { summary: { total: "ten" } } };
    const shape = await tool("cve_summary", {});
    assert.equal(shape.result.structuredContent.error.kind, "unexpected_shape", shape.r.text);
    const c = one(shape);
    assert.deepEqual([c.severity, c.tool, c.route, c.failure_class, c.status, c.after_ms], ["ERROR", "cve_summary", "(none)", "output_schema", null, null]);
  });

  it("a refused connection and a failed DNS lookup: failure_class refused and dns", async () => {
    const closed = await new Promise((resolve) => {
      const s = net.createServer().listen(0, "127.0.0.1", () => {
        const { port } = s.address();
        s.close(() => resolve(port));
      });
    });
    for (const [base, cls] of [
      [`http://127.0.0.1:${closed}`, "refused"],
      // .invalid never resolves (RFC 6761 6.4).
      ["http://upstream-2948.invalid", "dns"],
    ]) {
      const other = await startHttp({ ECHELONGRAPH_API_BASE: base, ECHELONGRAPH_API_TIMEOUT_MS: "5000" });
      try {
        const got = await call(other, "tools/call", { name: "get_cve", arguments: { cve_id: CVE_MARK } });
        assert.equal(got.result?.isError, true, got.r.text);
        const line = one(got);
        assert.deepEqual([line.severity, line.failure_class, line.status, line.route, line.tool], ["WARNING", cls, null, "/api/v1/public/cves/:id", "get_cve"], JSON.stringify(line));
      } finally {
        await other.stop();
      }
    }
  });

  it("the synthetic's call is marked synthetic; a resources/read names no tool", async () => {
    fs2948.state.mode = "503";
    const syn = one(await tool("get_cve", { cve_id: CVE_MARK }, { headers: { "User-Agent": "echelongraph-mcp-synthetic/1.0 (+https://echelongraph.io)" } }));
    assert.equal(syn.synthetic, true);
    const res = await call(srv, "resources/read", { uri: "echelongraph://sources" });
    assert.ok(res.upstream.length >= 1, `no line for the resource's failed reads: ${JSON.stringify(res.raw)}`);
    for (const l of res.upstream) assert.deepEqual([l.tool, l.rpc_method, l.severity], ["(none)", "resources/read", "WARNING"]);
  });

  it("controls: a call that succeeds writes none, and a call whose client went writes none (mcp_client_gone does)", async () => {
    fs2948.state.mode = "ok";
    fs2948.state.ok = { "/api/v1/public/cves/summary": SUMMARY };
    const ok = await tool("cve_summary", {});
    assert.equal(ok.result?.isError, undefined, ok.r.text);
    assert.deepEqual(ok.upstream, []);
    fs2948.state.mode = "hang";
    const from = srv.lines.length;
    const ac = new AbortController();
    const pending = fetch(srv.url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: ACCEPT, ...modernHeaders("tools/call", { name: "get_cve" }) },
      body: JSON.stringify({ jsonrpc: "2.0", id: 2948, method: "tools/call", params: { name: "get_cve", arguments: { cve_id: CVE_MARK }, _meta: modernMeta() } }),
      signal: ac.signal,
    }).catch(() => undefined);
    await sleep(150);
    ac.abort();
    await pending;
    await waitFor(() => parsedLines(srv.lines.slice(from)).some((j) => j.message === "mcp_request" && j.tool === "get_cve"), "the abandoned call's access line");
    const raw = srv.lines.slice(from);
    assert.ok(parsedLines(raw).some((j) => j.message === "mcp_client_gone"), `control: the client's going was not seen: ${raw.join("\n")}`);
    assert.deepEqual(upstreamOf(raw), [], "a cancelled call was logged as an upstream failure");
  });

  it("stdio: the npm package writes no such line, on stdout (the protocol) or stderr", async () => {
    fs2948.state.mode = "503";
    const env = { ...process.env, ECHELONGRAPH_API_BASE: fs2948.base, ECHELONGRAPH_API_TIMEOUT_MS: "10000" };
    const client = new StdioMcpClient({ ...serverCommand(), env, stderr: "pipe" });
    let out = "";
    let err = "";
    client.proc.stdout.on("data", (d) => (out += d));
    client.proc.stderr.setEncoding("utf8").on("data", (d) => (err += d));
    try {
      await client.open(MODERN);
      const res = await client.callTool({ name: "get_cve", arguments: { cve_id: CVE_MARK } });
      assert.equal(res.isError, true, "control: the stdio call did not fail");
      assert.equal(res.structuredContent.error.status, 503);
    } finally {
      await client.close();
    }
    assert.equal(client.protocolViolation, undefined);
    for (const line of out.split("\n").filter(Boolean)) {
      const j = JSON.parse(line);
      assert.equal(j.jsonrpc, "2.0", `stdout carries a line that is not JSON-RPC: ${line}`);
    }
    assert.ok(!out.includes("mcp_upstream_failed") && !err.includes("mcp_upstream_failed"), `stdio wrote the line: ${out}\n${err}`);
  });
});

// #2923: each mcp_handler_error says which request it arose in, by fixed labels only: the request's JSON-RPC method
// (bodyFacts: one of MCP_METHODS, else "(other)") and its MCP-Protocol-Version label (revisionLabel), read from the request's
// AsyncLocalStorage scope (runtime.ts requestLabels), since the SDK's onerror is handed only the error. Never a param.
describe("#2923: mcp_handler_error names its request's JSON-RPC method and protocol version, never its params", () => {
  let srv;
  before(async () => {
    srv = await startHttp({ MCP_RATE_LIMIT_PER_MIN: "1000" });
  });
  after(() => srv?.stop());
  const errorLines = () => srv.lines.map((l) => JSON.parse(l)).filter((j) => j.message === "mcp_handler_error");
  const SECRET = "zzsecret2923";
  const meta = (v) => ({ "io.modelcontextprotocol/protocolVersion": v, "io.modelcontextprotocol/clientInfo": { name: SECRET, version: "1" }, "io.modelcontextprotocol/clientCapabilities": {} });
  for (const [what, headers, body, want] of [
    ["a crawler's server/discover naming 1999-01-01", { "MCP-Protocol-Version": "1999-01-01" }, { jsonrpc: "2.0", id: 1, method: "server/discover", params: { _meta: meta("1999-01-01") } }, { rpc_method: "server/discover", protocol_version: "1999-01-01", error_class: "unsupported_protocol_version", error_code: -32022 }],
    ["the same with no header", {}, { jsonrpc: "2.0", id: 1, method: "server/discover", params: { _meta: meta("1999-01-01") } }, { rpc_method: "server/discover", protocol_version: "(none)", error_class: "unsupported_protocol_version", error_code: -32022 }],
    ["a 2025-era initialize under a 2026-07-28 header", { "MCP-Protocol-Version": "2026-07-28" }, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: SECRET, version: "1" } } }, { rpc_method: "initialize", protocol_version: "2026-07-28", error_class: "rejected_inbound_request" }],
    ["a header that is no revision", { "MCP-Protocol-Version": `${SECRET} 2026` }, { jsonrpc: "2.0", id: 1, method: "tools/list", params: { _meta: meta("2099-01-01") } }, { rpc_method: "tools/list", protocol_version: "(other)" }],
  ]) {
    it(`${what}: ${JSON.stringify(want)}`, async () => {
      const before = errorLines().length;
      const r = await post(srv.url, body, headers);
      assert.ok(r.status >= 400, `${r.status} ${r.text.slice(0, 200)}`);
      await waitFor(() => errorLines().length > before, "the mcp_handler_error line");
      const line = errorLines().slice(before)[0];
      for (const [k, v] of Object.entries(want)) assert.equal(line[k], v, `${k}: ${JSON.stringify(line)}`);
      assert.ok(!JSON.stringify(line).includes(SECRET), `the line holds a request value: ${JSON.stringify(line)}`);
    });
  }
  // #2923's review (nit): the method is a label from a closed set (httpPolicy.ts MCP_METHODS). A string MCP does not
  // define, however well shaped, is "(other)" on every line that names the request; the old shape check logged it.
  // Letters only, so the old shape check (/^[a-z][a-z/_]{0,39}$/i) passed each.
  for (const method of ["zzsecretmethod/list", "sampling/createMessage"]) {
    it(`a method MCP does not define for a client (${method}) is (other) on its lines, never its own string`, async () => {
      const before = srv.lines.length;
      // Its own User-Agent family tells its access line from an earlier test's, which is written once that request
      // has settled and can land after `before`.
      const ua = method.startsWith("zz") ? "probe2923own" : "probe2923sdk";
      const r = await post(srv.url, { jsonrpc: "2.0", id: 9, method, params: { _meta: meta("2026-07-28") } }, { "MCP-Protocol-Version": "2026-07-28", "User-Agent": `${ua}/1.0` });
      assert.ok(r.status >= 200, `${r.status}`);
      const mine = () => srv.lines.slice(before).map((l) => JSON.parse(l)).filter((j) => j.message === "mcp_request" && j.ua_family === ua);
      await waitFor(() => mine().length > 0, "the access line");
      assert.equal(mine().length, 1, JSON.stringify(mine()));
      assert.equal(mine()[0].rpc_method, "(other)", JSON.stringify(mine()[0]));
      // And no line of any kind (an mcp_handler_error among them) holds the client's string.
      assert.ok(!srv.lines.slice(before).join("\n").includes(method), `a line holds the client's method: ${srv.lines.slice(before).join("\n")}`);
    });
  }
});

// 3.1.0's final review (low): the access line's `method` was req.method as sent. Over HTTP/1.1 Node's parser admits only
// its own method list (a request with method ZZCANARYMETHOD got a 400 and wrote no line), but over h2c, which deploy-all.sh
// makes production's protocol, any :method token reached the log verbatim: "JOHN.DOE-SSN-123-45-6789" and an
// 8,000-character token, each on /health with status 405. It is now one of the nine HTTP methods (httpPolicy.ts
// HTTP_METHODS), else "(other)", as the README and /privacy Section 11 say.
describe("over h2c (MCP_H2C=1), the access line's method is one of nine HTTP methods, else (other), never the client's token", () => {
  let srv, session;
  before(async () => {
    srv = await startHttp({ MCP_RATE_LIMIT_PER_MIN: "1000", MCP_H2C: "1" });
    session = http2.connect(srv.base);
    session.on("error", () => {});
  });
  after(async () => {
    session?.close();
    await srv?.stop();
  });
  /** One h2 request with this :method, no body; resolves its status (or the stream's error code when it is reset). */
  const h2Method = (method, p, ua) =>
    new Promise((resolve) => {
      const stream = session.request({ ":method": method, ":path": p, "user-agent": `${ua}/1.0` }, { endStream: true });
      let status;
      stream.on("response", (h) => (status = h[":status"]));
      stream.on("error", () => {});
      stream.resume();
      stream.on("close", () => resolve(status ?? `reset ${stream.rstCode}`));
    });
  const mine = (before, ua) => srv.lines.slice(before).map((l) => JSON.parse(l)).filter((j) => j.message === "mcp_request" && j.ua_family === ua);
  const CANARIES = [["JOHN.DOE-SSN-123-45-6789", "ssn"], ["ZZCANARYMETHOD", "zz"], ["get", "lower"], ["Q".repeat(8000), "long"]];
  for (const [canary, tag] of CANARIES) {
    for (const p of ["/health", "/mcp", "/elsewhere"]) {
      const shown = canary.length > 40 ? `a ${canary.length}-character token` : canary;
      it(`:method ${shown} on ${p} is logged (other), and no line holds it`, async () => {
        const ua = `probe3101meth-${tag}-${p.slice(1)}`;
        const before = srv.lines.length;
        const status = await h2Method(canary, p, ua);
        assert.ok(typeof status === "number" && status >= 400, `${shown} on ${p}: ${status}`);
        await waitFor(() => mine(before, ua).length > 0, "the access line");
        await sleep(50);
        assert.equal(mine(before, ua).length, 1, JSON.stringify(mine(before, ua)));
        assert.equal(mine(before, ua)[0].method, "(other)", JSON.stringify(mine(before, ua)[0]).slice(0, 300));
        const written = srv.lines.slice(before).join("\n");
        assert.ok(!written.includes(JSON.stringify(canary)), `a line holds the client's :method as a value: ${written.slice(0, 400)}`);
        if (canary.length >= 8) assert.ok(!written.includes(canary), `a line holds the client's :method: ${written.slice(0, 400)}`);
      });
    }
  }
  it("each HTTP method an h2 client can send without a body is logged as itself", async () => {
    // CONNECT is one of the nine (httpPolicy.ts HTTP_METHODS) but takes no :path over h2, so it is held in http-policy.test.mjs.
    for (const m of ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"]) {
      const ua = `probe3101std-${m.toLowerCase()}`;
      const before = srv.lines.length;
      await h2Method(m, "/health", ua);
      await waitFor(() => mine(before, ua).length > 0, `${m}'s access line`);
      assert.equal(mine(before, ua)[0].method, m, JSON.stringify(mine(before, ua)[0]));
    }
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

// #2863: /privacy Section 11 lists what the hosted endpoint's access line records (the first word of
// the client's User-Agent and nothing else of it; no client address), and only a marketing-site test
// (privacyMcpEndpoint.test.ts) held http.ts's log calls to that list. That test runs in the marketing
// deploy alone, so adding the client address and the whole User-Agent to mcp_request passed this
// suite, the npm publish (scripts/npm-publish-mcp.sh runs only this suite) and the mcp-remote deploy,
// and made Section 11 false until an unrelated marketing deploy. Since 07d94fc8 the lines below were
// held to keys this file kept; a line its servers never wrote (a heap warning, a request that threw)
// had no check at all, and a new one would have had none either.
//
// Now the lines and their keys are src/logLines.ts LOG_LINES, one exported list. http.ts's log() is
// typed against it, so a new line or key does not build (npm test builds first) until it is added
// there; and here: every stdout line this file's servers wrote has exactly its listed keys, every
// listed line is written by them (or is one of NOT_DRIVEN, with the reason), dist/ has no other
// stdout or stderr writer, their stderr is empty, and the README's privacy section names every
// access-line key. A new line, or a key, is a change to what EchelonGraph logs: say it in Section 11
// and the README (README_ACCESS_PHRASES), then in privacyMcpEndpoint.test.ts's ACCESS_FIELDS / OTHER_LINES.
const { LOG_LINES } = await import(pathToFileURL(path.join(PKG_DIR, "dist", "logLines.js")).href);

describe("#2863: every line the hosted endpoint writes is one of LOG_LINES, with exactly its keys", () => {
  const ENVELOPE = ["message", "severity"];
  const sorted = (xs) => [...xs].sort();
  // Which of the access line's optional keys each JSON-RPC method brings (httpPolicy.ts bodyFacts).
  const BODY_FACTS = { "tools/call": ["tool"], "prompts/get": ["prompt"] };
  // The lines no request to this file's servers can make. log()'s type holds their keys at build time.
  const NOT_DRIVEN = {
    mcp_remote_heap_unbounded:
      "written only where Node reads a container memory limit below V8's heap limit; http-memory.test.mjs runs Dockerfile.http's flags and asserts it is absent",
    mcp_request_failed: "written only when serveMcp throws, which no request this file sends makes it do",
  };
  // A key naming a client or a request's content. The access line's keys are each named in the README
  // (README_ACCESS_PHRASES); on any other line only CLIENT_KEYS' are allowed, which the README names too.
  // (A body is read only as its size: max_body_bytes, a start-up setting, names none.)
  const CLIENTISH = /client|addr|address|^ip$|user_agent|^ua$|header|origin|body$|params|arguments|query|url/;
  const CLIENT_KEYS = { mcp_rate_limited: { client: "Past the per-client limit it logs that client's address key." } };
  // Each access-line key → the words of the README's hosted-endpoint paragraph that say it.
  const README_ACCESS_PHRASES = {
    // 3.1.0's final review: and that it is a closed set (httpPolicy.ts HTTP_METHODS).
    method: "the HTTP method (GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, CONNECT or TRACE, else `(other)`)",
    path: "and path, the status",
    status: "the status",
    duration_ms: "the duration",
    queued_ms: "its wait for a place",
    slot_wait_ms: "and for a large-body slot",
    in_flight: "the requests served at once",
    body_bytes: "the body size",
    rpc_method: "the JSON-RPC method",
    tool: "the tool or prompt name",
    prompt: "the tool or prompt name",
    protocol_version: "the protocol version",
    origin_present: "whether an `Origin` header was sent",
    ua_family: "the first word of your client's User-Agent",
    client_public: "whether your address is public (not the address)",
    client_closed: "whether your client closed early",
    throttled: "whether it was throttled or refused",
    refused: "throttled or refused, and why",
  };
  // #2948: each key of the upstream-failure line → the words of the same paragraph that say it.
  const README_UPSTREAM_PHRASES = {
    tool: "it logs the tool and JSON-RPC method",
    rpc_method: "it logs the tool and JSON-RPC method",
    route: "the call's route without the ID or query",
    failure_class: "what failed (such as",
    status: "the status the API answered",
    after_ms: "how long it took",
    synthetic: "whether the request was our monitor's",
  };
  // #2923: each key of a handler error's line → its words in the same paragraph.
  const README_HANDLER_ERROR_PHRASES = {
    error_name: "An error it logs by its type",
    error_class: "a fixed cause label",
    error_code: "and its code",
    rpc_method: "with its request's JSON-RPC method and protocol version",
    protocol_version: "with its request's JSON-RPC method and protocol version",
  };
  // The lines the README's hosted-endpoint paragraph names field by field.
  const README_LINE_PHRASES = { mcp_request: README_ACCESS_PHRASES, mcp_upstream_failed: README_UPSTREAM_PHRASES, mcp_handler_error: README_HANDLER_ERROR_PHRASES };
  const linesOf = (lines) => Object.entries(lines).map(([m, l]) => [m, [...l.keys], [...(l.optional ?? [])]]);

  /** What is wrong with stdout `raw` lines, held to `lines` (LOG_LINES, or a control's copy); and which messages were seen. */
  function lineProblems(raw, lines) {
    const out = [];
    const seen = new Set();
    const want = new Map(linesOf(lines).map(([m, keys, opt]) => [m, { keys, opt }]));
    for (const line of raw) {
      let j;
      try {
        j = JSON.parse(line);
      } catch {
        out.push(`a stdout line that is not JSON: ${line}`);
        continue;
      }
      seen.add(j.message);
      const w = want.get(j.message);
      if (!w) {
        out.push(`a line logLines.ts does not list: ${line}`);
        continue;
      }
      const present = w.opt.filter((k) => k in j);
      if (j.message === "mcp_request") {
        if (sorted(present).join() !== sorted(BODY_FACTS[j.rpc_method] ?? []).join()) out.push(`an access line's ${present.join(", ") || "no"} optional key for ${j.rpc_method}: ${line}`);
        // Section 11: "the first word of your client's User-Agent ... not the rest of it".
        if (!/^[^\s/]+$/.test(String(j.ua_family))) out.push(`ua_family is more than the User-Agent's first word: ${line}`);
      }
      const got = sorted(Object.keys(j)).join();
      const exact = sorted([...ENVELOPE, ...w.keys, ...present]).join();
      if (got !== exact) out.push(`${j.message}'s keys are ${got}, not the listed ${exact}: ${line}`);
    }
    return { out, seen };
  }

  /** Lines LOG_LINES lists that `seen` lacks, beyond NOT_DRIVEN; and NOT_DRIVEN entries it does not list. */
  const unseenProblems = (lines, seen) => [
    ...Object.keys(lines).filter((m) => !seen.has(m) && !(m in NOT_DRIVEN)).map((m) => `no ${m} line was written by this file's servers, so its keys are not checked`),
    ...Object.keys(NOT_DRIVEN).filter((m) => !(m in lines)).map((m) => `NOT_DRIVEN names ${m}, which logLines.ts does not list`),
    ...Object.keys(NOT_DRIVEN).filter((m) => seen.has(m)).map((m) => `NOT_DRIVEN names ${m}, which this file's servers did write: take it out there`),
  ];

  /** What the README's privacy section fails to say of `lines`' keys. */
  function readmeProblems(lines, readme) {
    const section = (readme.split(/^## Privacy: what is sent where$/m)[1] ?? "").split(/^## /m)[0];
    const hosted = (section.split("**The hosted endpoint.**")[1] ?? "").replace(/\s+/g, " ");
    if (hosted.length < 500) return ["the README has no hosted-endpoint paragraph under \"## Privacy: what is sent where\": re-aim this check"];
    const out = [];
    for (const [m, phrases] of Object.entries(README_LINE_PHRASES)) {
      if (!lines[m]) {
        out.push(`README_LINE_PHRASES names ${m}, which logLines.ts no longer lists: take it out of the README and here`);
        continue;
      }
      const keys = [...lines[m].keys, ...(lines[m].optional ?? [])];
      for (const k of keys) {
        const phrase = phrases[k];
        if (!phrase) out.push(`${m} logs ${k}, and README_LINE_PHRASES has no README phrase for it: say it in the README's privacy section (and /privacy Section 11) first`);
        else if (!hosted.includes(phrase)) out.push(`${m} logs ${k}, and the README's hosted-endpoint paragraph no longer says "${phrase}"`);
      }
      for (const k of Object.keys(phrases)) if (!keys.includes(k)) out.push(`README_LINE_PHRASES names ${k} for ${m}, which that line no longer logs: take it out of the README and here`);
    }
    for (const [m, keys] of linesOf(lines).map(([m, k, o]) => [m, [...k, ...o]])) {
      if (m in README_LINE_PHRASES) continue;
      for (const k of keys.filter((x) => CLIENTISH.test(x))) {
        const said = CLIENT_KEYS[m]?.[k];
        if (!said) out.push(`${m} logs ${k}, which names a client or a request: review it for /privacy Section 11, say it in the README, and add it to CLIENT_KEYS`);
        else if (!hosted.includes(said)) out.push(`${m} logs ${k}, and the README no longer says "${said}"`);
      }
    }
    return out;
  }

  /** Every stdout or stderr writer in `files` ([path, js] pairs) but the three reviewed ones. */
  const REVIEWED_WRITERS = [
    // http.ts log(), the one writer of the hosted endpoint's stdout.
    ["http.js", "process.stdout.write(`${JSON.stringify({ severity, message, ...fields })}\\n`)"],
    // index.ts: the ECHELONGRAPH_MCP_UA notice (its length, never its text) and the stdio start-up banner.
    ["index.js", "process.stderr.write(`echelongraph-mcp: ECHELONGRAPH_MCP_UA ignored: not a single product token (${v.length} characters)\\n`)"],
    ["index.js", "console.error(`EchelonGraph CVE MCP server ${NAME}@${VERSION} running (API: ${SHOWN_BASE}, timeout ${TIMEOUT_MS} ms)`)"],
  ];
  function writerProblems(files) {
    const out = [];
    for (const [rel, js] of files) {
      // #2863's review: any reference to process.stdout or process.stderr (so a writer by another name is read), a
      // destructured one, a console method, a process warning, or a write to fd 1 or 2.
      for (const m of js.matchAll(/\bprocess\.(?:stdout|stderr)\b|\{\s*(?:stdout|stderr)\b[^}]*\}\s*=\s*process\b|\bconsole\.\w+\(|\bemitWarning\(|\b(?:writeSync|write)\(\s*[12]\s*,/g)) {
        const call = js.slice(m.index, js.indexOf("\n", m.index)).replace(/;\s*$/, "");
        if (!REVIEWED_WRITERS.some(([f, c]) => rel === f && call === c)) out.push(`a writer of stdout or stderr nobody reviewed for /privacy Section 11, in dist/${rel}: ${call}`);
      }
    }
    return out;
  }
  const distFiles = () => {
    const out = [];
    const walk = (dir, rel) => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        if (e.isDirectory()) walk(path.join(dir, e.name), `${rel}${e.name}/`);
        else if (e.name.endsWith(".js")) out.push([`${rel}${e.name}`, fs.readFileSync(path.join(dir, e.name), "utf8")]);
      }
    };
    walk(path.join(PKG_DIR, "dist"), "");
    return out;
  };

  it("LOG_LINES is what dist/http.js writes: each log() call names a listed line, and each listed line has a call", () => {
    const http = fs.readFileSync(HTTP_ENTRY, "utf8");
    // A severity is a literal or one call of a helper (#2948's upstreamSeverity(...)); the message is always a literal.
    const calls = [...http.matchAll(/\blog\((?:"(?:INFO|WARNING|ERROR)"|[A-Za-z_$][\w$]*\([^()]*\)), "([a-z_]+)"/g)];
    const called = new Set(calls.map((m) => m[1]));
    assert.ok(called.size >= 8, `dist/http.js: ${called.size} log() calls read: re-aim this check`);
    // Every log( call site but the definition is one read above: a call this pattern cannot read is not unchecked.
    const sites = [...http.matchAll(/\blog\(/g)].length - [...http.matchAll(/\bfunction log\(/g)].length;
    assert.equal(calls.length, sites, `dist/http.js has ${sites} log() calls and ${calls.length} are read: re-aim this check`);
    assert.deepEqual(sorted(called), sorted(Object.keys(LOG_LINES)), "dist/http.js's log() messages are not logLines.ts's LOG_LINES");
    assert.deepEqual(sorted(LOG_LINES.mcp_request.optional), sorted(Object.values(BODY_FACTS).flat()), "the access line's optional keys are not BodyFacts' tool and prompt");
  });

  it("dist/ writes to stdout and stderr only through log() and the two reviewed stdio-side lines", () => {
    const files = distFiles();
    assert.ok(files.some(([f]) => f === "http.js") && files.some(([f]) => f === "logLines.js"), "dist/ lacks http.js or logLines.js: re-aim this check");
    assert.deepEqual(writerProblems(files), []);
  });

  it("every stdout line this file's servers wrote has exactly its listed keys, and every listed line was written", () => {
    const { out, seen } = lineProblems(EVERY_LINE, LOG_LINES);
    assert.deepEqual(out, []);
    assert.ok(seen.has("mcp_request") && EVERY_LINE.some((l) => JSON.parse(l).tool !== undefined), "no access line for a tools/call was written");
    assert.deepEqual(unseenProblems(LOG_LINES, seen), []);
  });

  // Node's own process warnings name an API, never a request; anything else on stderr is a writer to review.
  const NODE_WARNING = /^\(node:\d+\) [A-Za-z]*Warning: |^\(Use `node --trace-warnings \.\.\.` to show where the warning was created\)$/;
  it("every server this file started wrote nothing to stderr but Node's own warnings", () => {
    assert.ok(EVERY_STDERR.length >= 10, `only ${EVERY_STDERR.length} servers' stderr kept`);
    for (const err of EVERY_STDERR) {
      const other = err().split("\n").filter((l) => l !== "" && !NODE_WARNING.test(l));
      assert.deepEqual(other, [], "a hosted server wrote to stderr");
    }
  });

  it("the README's privacy section names every key of the access line and the upstream-failure line, and the one other line that names a client", () => {
    assert.deepEqual(readmeProblems(LOG_LINES, readPkgFile("README.md")), []);
  });

  it("control: the two-field edit (#2863), a new line, a line nobody wrote, a client key on another line and a new writer each fail", () => {
    const access = EVERY_LINE.find((l) => JSON.parse(l).message === "mcp_request" && JSON.parse(l).tool !== undefined);
    assert.ok(access, "no tools/call access line to mutate: re-aim this control");
    const j = JSON.parse(access);
    // #2863's edit: the client address from X-Forwarded-For and the whole User-Agent on mcp_request.
    const twoField = JSON.stringify({ ...j, client_addr: "203.0.113.9", user_agent: "claude-code/2.1.0 (darwin; arm64)" });
    assert.equal(lineProblems([twoField], LOG_LINES).out.length, 1, "the two-field edit's access line passes");
    assert.equal(lineProblems([JSON.stringify({ ...j, ua_family: "claude-code/2.1.0 (darwin)" })], LOG_LINES).out.length, 1, "a whole User-Agent in ua_family passes");
    // ... and with the two keys added to LOG_LINES too (the build then passes), the README check fails on both.
    const listed = { ...LOG_LINES, mcp_request: { ...LOG_LINES.mcp_request, keys: [...LOG_LINES.mcp_request.keys, "client_addr", "user_agent"] } };
    assert.deepEqual(lineProblems([twoField], listed).out, []);
    assert.equal(readmeProblems(listed, readPkgFile("README.md")).length, 2, "the two keys pass the README check");
    // A new line, unlisted; and listed but written by no server here.
    const upstream = JSON.stringify({ severity: "WARNING", message: "mcp_upstream_slow", status: 502 });
    assert.match(lineProblems([upstream], LOG_LINES).out.join(), /does not list/);
    const withUpstream = { ...LOG_LINES, mcp_upstream_slow: { keys: ["status"] } };
    assert.deepEqual(unseenProblems(withUpstream, lineProblems(EVERY_LINE, withUpstream).seen), ["no mcp_upstream_slow line was written by this file's servers, so its keys are not checked"]);
    // The client address on another line, and a key dropped from a listed line.
    const busyClient = { ...LOG_LINES, mcp_busy: { keys: [...LOG_LINES.mcp_busy.keys, "client_addr"] } };
    assert.equal(readmeProblems(busyClient, readPkgFile("README.md")).length, 1, "a client address on mcp_busy passes the README check");
    const gone = EVERY_LINE.find((l) => JSON.parse(l).message === "mcp_client_gone");
    assert.ok(gone, "no mcp_client_gone line to mutate: re-aim this control");
    const { rst_code: _dropped, ...lessGone } = JSON.parse(gone);
    assert.equal(lineProblems([JSON.stringify(lessGone)], LOG_LINES).out.length, 1, "mcp_client_gone without rst_code passes");
    // The README's old list (through 3.0.2): it named neither queued_ms nor in_flight, the prompt or tool name as such,
    // ua_family as the first word, client_public, client_closed, throttled or refused (#2863's 2.7.1 audit comment); nor
    // slot_wait_ms, which came with #2775's wait for a large-body slot; nor the HTTP method as a closed set (3.1.0's
    // final review).
    const old = readPkgFile("README.md").replace(/Per request it logs the HTTP method[\s\S]*?and why\.\s/, "Per request it logs the HTTP method and path, the status, the duration, the body size, the JSON-RPC method and (for `tools/call`) the tool name, the protocol version, whether an `Origin` header was sent, and the family of your client's User-Agent. ");
    assert.notEqual(old, readPkgFile("README.md"), "the README's access-line sentence moved: re-aim this control");
    assert.deepEqual(
      readmeProblems(LOG_LINES, old).map((p) => p.match(/logs (\w+)/)?.[1]).sort(),
      ["client_closed", "client_public", "in_flight", "method", "prompt", "queued_ms", "refused", "slot_wait_ms", "throttled", "tool", "ua_family"],
      "the README's old access-line list passes",
    );
    // #2948: without its upstream-failure sentence, the README fails on each of that line's keys.
    const noUpstream = readPkgFile("README.md").replace(/When one of its API calls fails,[\s\S]*?monitor's\.\s/, "");
    assert.notEqual(noUpstream, readPkgFile("README.md"), "the README's upstream-failure sentence moved: re-aim this control");
    assert.deepEqual(
      readmeProblems(LOG_LINES, noUpstream).map((p) => p.match(/^mcp_upstream_failed logs (\w+)/)?.[1]).sort(),
      ["after_ms", "failure_class", "route", "rpc_method", "status", "synthetic", "tool"],
      "the README passes without its upstream-failure sentence",
    );
    // A console.log added to a tool, and the reviewed log() rewritten to spread the request.
    assert.equal(writerProblems([["tools/get_cve.js", "    console.log(`get_cve ${args.cve_id}`);\n"]]).length, 1);
    assert.equal(writerProblems([["http.js", "    process.stdout.write(`${JSON.stringify({ severity, message, ...fields, ...req.headers })}\\n`);\n"]]).length, 1);
    // #2863's review: a writer reached by another name, a process warning, a write to fd 1 or 2 (all of them unreviewed).
    for (const js of [
      "    const out = process.stdout;\n    out.write(String(req.headers[\"x-forwarded-for\"]));\n",
      "    process.emitWarning(`client ${req.headers[\"user-agent\"]}`);\n",
      "    fs.writeSync(2, String(body));\n",
      "    const { stderr } = process; stderr.write(String(body));\n",
    ]) assert.equal(writerProblems([["tools/x.js", js]]).length, 1, `an unreviewed writer passes: ${js.trim()}`);
  });
});
