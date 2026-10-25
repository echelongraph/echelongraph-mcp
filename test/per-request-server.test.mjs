// #3345: @modelcontextprotocol/server 2.3.0 (its #2918, the fix for CVE-2026-111770) serves one
// connection per Server or McpServer, and one request per stateless transport. An app that shares
// one server, or one transport, across requests fails from its second request on: connect()
// rejects with an SdkError ALREADY_CONNECTED, and createMcpHandler(() => server) answers a request
// that overlaps another 500, JSON-RPC -32603. Through 2.1.0 such sharing let one client's messages
// reach another (the CVE). This server builds a server per request on the hosted endpoint (http.ts:
// createMcpHandler(createServer, …)) and per connection on stdio (index.ts: serveStdio(createServer,
// …)), which the advisory names as not affected; this file holds that both keep working on the
// bundled SDK for many clients one after another and at once, each answered with its own answer.
//
// The control at the end holds that the bundled SDK does refuse a shared server, so the cases above
// pass because each request and each connection gets its own server, not because nothing is
// checked. On SDK 2.1.0 (echelongraph-mcp 3.1.0) the control fails: the shared server refuses
// neither of two overlapping requests (the pair was not answered within the test's 20 s).
//
// Every API request goes to a stub on 127.0.0.1 that answers each CVE ID with a record naming it.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import path from "node:path";
import { spawn } from "node:child_process";
import { pathToFileURL } from "node:url";
import { createMcpHandler } from "@modelcontextprotocol/server";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { connectHttp } from "./mcp-http-client.mjs";
import { PKG_DIR, serverCommand } from "./server-under-test.mjs";

const LEGACY = "2025-06-18";
const ERAS = [MODERN, LEGACY];
const SEQUENTIAL = 30;
const CONCURRENT = 30;
const idOf = (i) => `CVE-2026-${String(70000 + i).padStart(5, "0")}`;

const state = { delayMs: 0, requests: 0 };
const stub = http.createServer((req, res) => {
  state.requests++;
  const m = /^\/api\/v1\/public\/cves\/(CVE-\d{4}-\d+)$/.exec(new URL(req.url, "http://stub").pathname);
  setTimeout(() => {
    if (!m) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end('{"error":"not found"}');
      return;
    }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ cve_id: m[1], description: `The record of ${m[1]}.`, severity: "HIGH", updated_at: "2026-10-20T10:00:00Z" }));
  }, state.delayMs);
});
await new Promise((r) => stub.listen(0, "127.0.0.1", r));
const API = `http://127.0.0.1:${stub.address().port}`;
const env = () => ({ ...process.env, ECHELONGRAPH_API_BASE: API, ECHELONGRAPH_API_TIMEOUT_MS: "10000" });

// One client's whole conversation: list the tools, then get_cve for its own CVE ID; its answer
// must be its own record, and nobody else's.
async function converse(client, i) {
  const { tools } = await client.listTools();
  assert.equal(tools.length, 16, `client ${i}: ${tools.length} tools`);
  const res = await client.callTool({ name: "get_cve", arguments: { cve_id: idOf(i) } });
  assert.notEqual(res.isError, true, `client ${i}: ${JSON.stringify(res).slice(0, 300)}`);
  assert.equal(res.structuredContent?.state, "measured", `client ${i}: ${JSON.stringify(res).slice(0, 300)}`);
  assert.equal(res.structuredContent.data.cve_id, idOf(i), `client ${i} was answered another client's record`);
  assert.ok(res.content[0].text.includes(idOf(i)), `client ${i}: its text does not name its own CVE`);
}

describe("#3345: the hosted endpoint builds a server per request: many clients one after another and at once (SDK 2.3.0)", { timeout: 120_000 }, () => {
  let proc, url, exited;
  const lines = [];
  before(async () => {
    proc = spawn(process.execPath, [path.join(PKG_DIR, "dist", "http.js")], { env: { ...env(), PORT: "0", MCP_RATE_LIMIT_PER_MIN: "100000" }, stdio: ["ignore", "pipe", "pipe"] });
    exited = new Promise((resolve) => proc.once("exit", resolve));
    url = await new Promise((resolve, reject) => {
      let buf = "";
      let err = "";
      const timer = setTimeout(() => reject(new Error(`http.js did not start: ${err}`)), 15_000);
      proc.stderr.setEncoding("utf8").on("data", (d) => (err += d));
      proc.stdout.setEncoding("utf8").on("data", (d) => {
        buf += d;
        let i;
        while ((i = buf.indexOf("\n")) >= 0) {
          const line = buf.slice(0, i);
          buf = buf.slice(i + 1);
          try {
            const j = JSON.parse(line);
            lines.push(j);
            if (j.message === "mcp_remote_listening") {
              clearTimeout(timer);
              resolve(`http://127.0.0.1:${j.port}/mcp`);
            }
          } catch {
            // a partial or non-JSON line
          }
        }
      });
    });
  });
  after(async () => {
    proc?.kill("SIGTERM");
    await exited;
  });
  const handlerErrors = () => lines.filter((l) => l.message === "mcp_handler_error");
  const failures = () => lines.filter((l) => l.message === "mcp_request" && l.status >= 500);

  it(`${SEQUENTIAL} clients one after another, both eras, each answered with its own record`, async () => {
    for (let i = 0; i < SEQUENTIAL; i++) await converse(await connectHttp({ era: ERAS[i % 2], url }), i);
    assert.deepEqual(handlerErrors(), []);
    assert.deepEqual(failures(), []);
  });

  it(`${CONCURRENT} clients at once, both eras, their calls overlapping at the API, each answered with its own record`, async () => {
    state.delayMs = 200;
    try {
      const clients = await Promise.all(Array.from({ length: CONCURRENT }, (_, i) => connectHttp({ era: ERAS[i % 2], url })));
      await Promise.all(clients.map((c, i) => converse(c, 100 + i)));
    } finally {
      state.delayMs = 0;
    }
    assert.deepEqual(handlerErrors(), []);
    assert.deepEqual(failures(), []);
  });
});

describe("#3345: stdio builds a server per connection: many calls on one connection, and many connections (SDK 2.3.0)", { timeout: 120_000 }, () => {
  for (const era of ERAS) {
    it(`[${era}] one connection: ${SEQUENTIAL} calls one after another, then ${CONCURRENT} at once, each answered with its own record`, async () => {
      const client = await connect({ era, ...serverCommand(), env: env(), stderr: "ignore" });
      try {
        for (let i = 0; i < SEQUENTIAL; i++) await converse(client, 200 + i);
        state.delayMs = 200;
        await Promise.all(Array.from({ length: CONCURRENT }, (_, i) => converse(client, 300 + i)));
      } finally {
        state.delayMs = 0;
        await client.close();
      }
    });
  }

  it("connections one after another, then six at once, both eras, each answered with its own record", async () => {
    for (let i = 0; i < 4; i++) {
      const client = await connect({ era: ERAS[i % 2], ...serverCommand(), env: env(), stderr: "ignore" });
      try {
        await converse(client, 400 + i);
      } finally {
        await client.close();
      }
    }
    state.delayMs = 200;
    const clients = await Promise.all(Array.from({ length: 6 }, (_, i) => connect({ era: ERAS[i % 2], ...serverCommand(), env: env(), stderr: "ignore" })));
    try {
      await Promise.all(clients.map((c, i) => converse(c, 500 + i)));
    } finally {
      state.delayMs = 0;
      await Promise.all(clients.map((c) => c.close()));
    }
  });
});

// The bundled SDK's own rule, against index.ts's createServer: one server per connection.
describe("#3345 control: the bundled SDK refuses a shared server (what 2.3.0 fixed), so the factory above is what keeps clients apart", () => {
  let I;
  before(async () => {
    process.env.ECHELONGRAPH_API_BASE = API;
    process.env.ECHELONGRAPH_API_TIMEOUT_MS = "10000";
    const R = await import(pathToFileURL(path.join(PKG_DIR, "dist", "runtime.js")).href);
    R.markHttpEntrypoint();
    I = await import(pathToFileURL(path.join(PKG_DIR, "dist", "index.js")).href);
  });
  after(async () => {
    stub.closeAllConnections();
    await new Promise((r) => stub.close(r));
  });

  const call = (i) =>
    new Request("http://localhost/mcp", {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream", "mcp-protocol-version": LEGACY },
      body: JSON.stringify({ jsonrpc: "2.0", id: i, method: "tools/call", params: { name: "get_cve", arguments: { cve_id: idOf(600 + i) } } }),
    });

  // Bounded: on SDK 2.1.0 neither request to a shared server was refused, and the overlapping pair
  // was not answered within 20 s (run 2026-10-25 against 3.1.0's lockfile), so without a bound this
  // test hung there instead of failing.
  it("createMcpHandler(() => one shared server): of two overlapping requests one is refused 500, JSON-RPC -32603, ALREADY_CONNECTED", { timeout: 20_000 }, async () => {
    const shared = I.createServer();
    const errors = [];
    const handler = createMcpHandler(() => shared, { legacy: "stateless", onerror: (e) => errors.push(e) });
    state.delayMs = 300;
    try {
      const answers = await Promise.all([0, 1].map((i) => handler.fetch(call(i))));
      const statuses = answers.map((r) => r.status).sort();
      await Promise.all(answers.map((r) => r.text()));
      assert.deepEqual(statuses, [200, 500], "a shared server served two overlapping requests: the SDK does not enforce one connection per server");
      assert.ok(errors.some((e) => /ALREADY_CONNECTED|already connected/i.test(`${e?.code} ${e?.message}`)), errors.map((e) => `${e?.name} ${e?.code} ${e?.message}`).join("; "));
    } finally {
      state.delayMs = 0;
      await handler.close();
    }
  });

  it("createMcpHandler(createServer), as http.ts builds it: the same two overlapping requests are both answered, each with its own record", { timeout: 20_000 }, async () => {
    const errors = [];
    const handler = createMcpHandler(I.createServer, { legacy: "stateless", onerror: (e) => errors.push(e) });
    state.delayMs = 300;
    try {
      const answers = await Promise.all([0, 1].map((i) => handler.fetch(call(i))));
      assert.deepEqual(answers.map((r) => r.status), [200, 200]);
      const texts = await Promise.all(answers.map((r) => r.text()));
      texts.forEach((t, i) => assert.ok(t.includes(idOf(600 + i)) && !t.includes(idOf(600 + 1 - i)), `request ${i} was not answered with its own record`));
      assert.deepEqual(errors, []);
    } finally {
      state.delayMs = 0;
      await handler.close();
    }
  });
});
