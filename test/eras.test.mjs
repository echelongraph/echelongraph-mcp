// #2311: both MCP protocol eras on stdio, asked directly on the wire.
//
//   modern (2026-07-28)   the client opens with server/discover carrying the per-request `_meta`
//                         envelope, and every request after it carries one too.
//   legacy (2025-era)     the client opens with initialize, as every 1.x SDK client does.
//
// The first message of a connection picks its era, and the connection stays in it. Run against
// whatever server-under-test.mjs names: dist/, an unpacked tarball, or an installed bin.
// Every API request goes to a stub on 127.0.0.1; nothing leaves the machine.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { connect, MODERN, RpcError, StdioMcpClient, SERVER_INFO_META_KEY } from "./mcp-stdio-client.mjs";
import { PKG, serverCommand } from "./server-under-test.mjs";

const TOOLS = ["cve_summary", "search_cves", "get_cve", "cve_exposure", "exposure_radar"];
// The legacy revisions this server negotiates through initialize (SDK 2.1.0
// SUPPORTED_PROTOCOL_VERSIONS): a client asking for one of them gets it back.
const LEGACY = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const SUMMARY = { summary: { critical: 1, high: 2, medium: 3, low: 4, none: 0, total: 10, last_updated: "2026-09-27T01:00:00Z" } };

let stub;
let env;
before(async () => {
  stub = http.createServer((req, res) => {
    if (new URL(req.url, "http://stub").pathname === "/api/v1/public/cves/summary") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(SUMMARY));
      return;
    }
    res.writeHead(404, { "content-type": "text/plain" });
    res.end("404 page not found\n");
  });
  await new Promise((resolve) => stub.listen(0, "127.0.0.1", resolve));
  env = { ...process.env, ECHELONGRAPH_API_BASE: `http://127.0.0.1:${stub.address().port}`, ECHELONGRAPH_API_TIMEOUT_MS: "2000" };
});
after(() => new Promise((resolve) => stub.close(resolve)));

const open = (era) => connect({ era, ...serverCommand(), env, stderr: "ignore" });
const identity = { name: PKG.name, version: PKG.version };

describe("#2311: the modern era (2026-07-28): server/discover and the per-request envelope", () => {
  let client;
  before(async () => {
    client = await open(MODERN);
  });
  after(() => client?.close());

  // SDK 2.1.0 lists only modern revisions in supportedVersions ("2025-era versions are
  // negotiated via initialize", Server._ondiscover): 2025-11-25 is served, through initialize,
  // and the legacy block below asks for it there.
  it("server/discover answers a DiscoverResult: 2026-07-28, the tools capability, the instructions, and package.json's identity", () => {
    const d = client.opening;
    assert.deepEqual(d.supportedVersions, [MODERN]);
    assert.ok(d.capabilities?.tools, JSON.stringify(d));
    assert.equal(typeof d.instructions, "string");
    assert.match(d.instructions, /Shodan data is owned by Shodan, which holds its copyright \(© Shodan\)\./);
    assert.equal(d.resultType, "complete");
    assert.deepEqual(d._meta?.[SERVER_INFO_META_KEY], identity);
  });
  it("tools/list lists the five tools in order, each with a title, annotations and an outputSchema", async () => {
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map((t) => t.name), TOOLS);
    for (const t of tools) assert.ok(t.title && t.annotations && t.outputSchema, t.name);
  });
  it("tools/call answers with the text blocks and the structured result, stamped with the server's identity", async () => {
    const res = await client.callTool({ name: "cve_summary", arguments: {} });
    assert.notEqual(res.isError, true, JSON.stringify(res));
    assert.equal(res.resultType, "complete");
    assert.deepEqual(res._meta?.[SERVER_INFO_META_KEY], identity);
    assert.deepEqual(JSON.parse(res.content[0].text), SUMMARY);
    assert.equal(res.structuredContent.state, "measured");
    assert.deepEqual(res.structuredContent.data, SUMMARY);
  });
  // After server/discover the connection is a probe; the first enveloped request pins it modern.
  it("once a modern request has pinned the connection, a request without the envelope is refused", async () => {
    await client.listTools();
    await assert.rejects(client.rawRequest("tools/list", {}), (e) => e instanceof RpcError && typeof e.code === "number");
  });
  it("once a modern request has pinned the connection, a legacy initialize is refused", async () => {
    await client.listTools();
    await assert.rejects(
      client.rawRequest("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "late", version: "0" } }),
      (e) => e instanceof RpcError,
    );
  });
});

// The stdio probe: a client may send server/discover and then open with initialize anyway (a
// dual-era client falls back when it does not recognise the answer). The server drops the probe
// and serves the connection as legacy.
describe("#2311: a server/discover probe followed by initialize is served as legacy", () => {
  it("initialize after the probe negotiates 2025-06-18, and tools/call works", async () => {
    const client = new StdioMcpClient({ ...serverCommand(), env, stderr: "ignore" });
    try {
      const probe = await client.rawRequest("server/discover", { _meta: client.meta() });
      assert.deepEqual(probe.supportedVersions, [MODERN]);
      await client.open("2025-06-18");
      assert.equal(client.opening.protocolVersion, "2025-06-18");
      const res = await client.callTool({ name: "cve_summary", arguments: {} });
      assert.notEqual(res.isError, true, JSON.stringify(res));
      assert.deepEqual(res.structuredContent.data, SUMMARY);
    } finally {
      await client.close();
    }
  });
});

describe("#2311: an unsupported modern revision is answered with the supported one", () => {
  it("server/discover claiming 2099-01-01 gets UnsupportedProtocolVersionError naming 2026-07-28", async () => {
    const client = new StdioMcpClient({ ...serverCommand(), env, stderr: "ignore" });
    try {
      await assert.rejects(
        client.rawRequest("server/discover", {
          _meta: { "io.modelcontextprotocol/protocolVersion": "2099-01-01", "io.modelcontextprotocol/clientCapabilities": {} },
        }),
        // -32022 UnsupportedProtocolVersionError (2026-07-28 basic/versioning).
        (e) => e instanceof RpcError && e.code === -32022 && JSON.stringify(e.data?.supported) === JSON.stringify([MODERN]) && e.data.requested === "2099-01-01",
      );
    } finally {
      await client.close();
    }
  });
});

describe("#2311: the legacy era: initialize, as 1.x clients open", () => {
  for (const version of LEGACY) {
    it(`initialize with protocolVersion ${version} succeeds, and negotiates ${version}`, async () => {
      const client = await open(version);
      try {
        const init = client.opening;
        assert.equal(init.protocolVersion, version);
        assert.deepEqual(init.serverInfo, identity);
        assert.ok(init.capabilities?.tools);
        assert.match(init.instructions, /Everything these tools return is public/);
      } finally {
        await client.close();
      }
    });
  }
  it("initialize with a version the server does not know is answered with its newest legacy one, 2025-11-25", async () => {
    const client = await open("2024-01-01");
    try {
      assert.equal(client.opening.protocolVersion, "2025-11-25");
    } finally {
      await client.close();
    }
  });

  describe("a 2025-06-18 connection", () => {
    let client;
    before(async () => {
      client = await open("2025-06-18");
    });
    after(() => client?.close());
    it("tools/list lists the five tools in order, each with a title, annotations and an outputSchema", async () => {
      const { tools } = await client.listTools();
      assert.deepEqual(tools.map((t) => t.name), TOOLS);
      for (const t of tools) assert.ok(t.title && t.annotations && t.outputSchema, t.name);
    });
    it("tools/call works: the text blocks and the structured result, unwrapped", async () => {
      const res = await client.callTool({ name: "cve_summary", arguments: {} });
      assert.notEqual(res.isError, true, JSON.stringify(res));
      assert.deepEqual(JSON.parse(res.content[0].text), SUMMARY);
      assert.match(res.content[1].text, /^cve_summary OK: EchelonGraph answered HTTP 200 from /);
      // An object-rooted outputSchema, so the 2025 wire carries structuredContent as it is, not
      // wrapped as {result: ...}.
      assert.equal(res.structuredContent.state, "measured");
      assert.deepEqual(res.structuredContent.data, SUMMARY);
      assert.equal(res.resultType, undefined, "a 2025-era result carries no 2026-era resultType");
    });
    it("tools/call reports a failure as a failure on this era too", async () => {
      const res = await client.callTool({ name: "get_cve", arguments: { cve_id: "CVE-2023-44487" } });
      assert.equal(res.isError, true);
      assert.equal(res.structuredContent.state, "failed");
      assert.match(res.content[0].text, /HTTP 404/);
    });
    it("the connection stays legacy: server/discover is not served on it", async () => {
      await assert.rejects(client.rawRequest("server/discover", {}), (e) => e instanceof RpcError);
    });
    it("the instructions are the ones the modern era serves", async () => {
      const modern = await open(MODERN);
      try {
        assert.equal(client.opening.instructions, modern.opening.instructions);
      } finally {
        await modern.close();
      }
    });
  });
});
