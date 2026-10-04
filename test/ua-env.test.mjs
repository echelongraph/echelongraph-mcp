// ECHELONGRAPH_MCP_UA (#2724): one product token put ahead of the package's own User-Agent, so
// an automated caller (the production synthetic) is filed under its own family by the API's
// access log and never counted as MCP adoption. Unset, the User-Agent is exactly what it was.
// A value that is not a single token is ignored, and the stderr line about it names its
// length, never its text.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { PKG, serverCommand } from "./server-under-test.mjs";

const ERA = globalThis.MCP_TEST_ERA ?? MODERN;
const OWN = `echelongraph-mcp/${PKG.version} (+https://echelongraph.io/pulse/mcp)`;

describe(`ECHELONGRAPH_MCP_UA [${ERA}]`, () => {
  let server, base;
  const seen = [];
  before(async () => {
    server = http.createServer((req, res) => {
      seen.push(req.headers["user-agent"]);
      res.writeHead(500, { "content-type": "application/json" });
      res.end('{"error":"stub"}');
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${server.address().port}`;
  });
  after(() => {
    server.closeAllConnections();
    return new Promise((resolve) => server.close(resolve));
  });

  // One get_cve call with the given value; returns the User-Agent the API saw and the stderr.
  async function uaWith(value) {
    seen.length = 0;
    const env = { ...process.env, ECHELONGRAPH_API_BASE: base };
    delete env.ECHELONGRAPH_MCP_UA;
    if (value !== undefined) env.ECHELONGRAPH_MCP_UA = value;
    const client = await connect({ era: ERA, ...serverCommand(), env, stderr: "pipe" });
    let stderr = "";
    client.proc.stderr.setEncoding("utf8");
    client.proc.stderr.on("data", (c) => (stderr += c));
    try {
      await client.callTool({ name: "get_cve", arguments: { cve_id: "CVE-2021-44228" } });
    } finally {
      await client.close();
    }
    assert.equal(seen.length, 1, "one API request expected");
    return { ua: seen[0], stderr };
  }

  it("unset or empty: the package's own User-Agent, unchanged", async () => {
    assert.equal((await uaWith(undefined)).ua, OWN);
    assert.equal((await uaWith("")).ua, OWN);
  });
  it("a single token is put ahead of it, so the leading family is the caller's", async () => {
    assert.equal((await uaWith("echelongraph-mcp-synthetic/1.0")).ua, `echelongraph-mcp-synthetic/1.0 ${OWN}`);
    assert.equal((await uaWith("my-monitor")).ua, `my-monitor ${OWN}`);
  });
  it("anything else is ignored, and stderr names its length, not its text", async () => {
    for (const bad of ["two tokens", "evil\r\nX-Injected: 1", "/leading-slash", "a/b/c", "x".repeat(65)]) {
      const { ua, stderr } = await uaWith(bad);
      assert.equal(ua, OWN, JSON.stringify(bad));
      assert.match(stderr, new RegExp(`ECHELONGRAPH_MCP_UA ignored: not a single product token \\(${bad.length} characters\\)`));
      assert.ok(!stderr.includes(bad), `stderr quotes the value ${JSON.stringify(bad)}`);
    }
  });
});
