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
// headers the API keys remote users on (#2212), and that the npm stdio entry never sends them.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import path from "node:path";
import { spawn } from "node:child_process";
import { AjvJsonSchemaValidator } from "@modelcontextprotocol/server/validators/ajv";
import { connect, MODERN, SERVER_INFO_META_KEY } from "./mcp-stdio-client.mjs";
import { legacy, modern, post } from "./mcp-http-client.mjs";
import { PKG, PKG_DIR, readPkgFile, serverCommand } from "./server-under-test.mjs";

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
before(async () => {
  stub = http.createServer((req, res) => {
    const u = new URL(req.url, "http://stub");
    seen.push({ path: u.pathname, url: req.url, clientIp: req.headers["x-eg-client-ip"], token: req.headers["x-eg-mcp-forward"] });
    if (u.pathname === "/api/v1/public/cves/summary") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(SUMMARY));
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
      // The API call itself carries the term (its query string is core-backend's to keep out of
      // its logs, #1983): a control that the term really was sent.
      assert.ok(seen.some((s) => s.url.includes(MARKER)), "control: the search never reached the stub");
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
