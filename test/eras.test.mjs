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

const TOOLS = ["cve_summary", "search_cves", "get_cve", "cve_exposure", "exposure_radar", "kev_recent", "epss_history", "check_affected", "check_sbom", "cve_intel", "get_cwe", "vendor_advisories_for_cve", "get_vendor_advisory", "search_vendor_advisories"];
// The legacy revisions this server negotiates through initialize (SDK 2.1.0
// SUPPORTED_PROTOCOL_VERSIONS): a client asking for one of them gets it back.
const LEGACY = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const SUMMARY = { summary: { critical: 1, high: 2, medium: 3, low: 4, none: 0, total: 10, last_updated: "2026-09-27T01:00:00Z" } };
// #2439: production's per-CVE answer shape (2026-09-27), whose last_seen is the poller's write
// time. 2.0.0 answered it state measured in every era; no era may.
const EXPOSURE_CVE = "CVE-2026-87902";
const EXPOSURE = {
  cve_id: EXPOSURE_CVE,
  exposed_hosts: 229,
  countries: 32,
  kev_listed: true,
  kev_seen_in_observations: true,
  kev_catalog_listed: true,
  tracked: true,
  method: "Shodan banner match over the radar's tracked product queries.",
  ransomware: false,
  top_countries: [{ country: "United States", hosts: 130 }],
  top_products: [{ product: "wordpress", hosts: 229 }],
  last_seen: "2026-09-27T21:52:34.976885Z",
  generated_at: "2026-09-27T22:06:13.516192827Z",
};
// #2717: GET /api/v1/public/kev/recent, shaped as core-backend kevrecent answers it.
const KEV_RECENT = {
  kev: [{ cve_id: "CVE-2026-0002", kev_added_date: "2026-10-02", kev_due_date: "2026-10-23", kev_vendor: "Ivanti", kev_product: "Connect Secure", kev_vuln_name: "Ivanti Connect Secure Authentication Bypass", kev_ransomware: false, severity: "CRITICAL", cvss_v3_score: 9.8, epss_score: 0.42, epss_percentile: 0.97, eg_kev_tier: 1, our_first_seen_kev: "2026-10-02T17:04:12Z" }],
  count: 1,
  total: 1,
  kev_listed_total: 1452,
  limit: 50,
  next_cursor: null,
  order: "kev_added_date DESC, cve_id ASC",
  filters: { since: null, until: null, ransomware: null, vendor: null },
  catalog: { source: "CISA KEV catalog", feed_url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", last_successful_fetch_at: "2026-10-03T11:55:01Z", catalog_version: "2026.10.02", date_released: "2026-10-02T17:00:41.1622Z", catalog_count: 1452 },
  method: "EchelonGraph polls CISA's known_exploited_vulnerabilities.json every 5 minutes.",
  notes: ["CISA's requiredAction and shortDescription are not stored, so they are not served."],
  generated_at: "2026-10-03T12:00:00Z",
};
const ANSWERS = {
  "/api/v1/public/cves/summary": SUMMARY,
  [`/api/v1/public/kev-exposure/cve/${EXPOSURE_CVE}`]: EXPOSURE,
  "/api/v1/public/kev/recent": KEV_RECENT,
};
// One call per tool: three successes (cve_summary and kev_recent measured, cve_exposure
// not_assessed) and three failures (the stub answers every other path 404), so both result
// shapes reach every era.
const CALLS = [
  ["cve_summary", {}],
  ["search_cves", { search: "tomcat", limit: 2 }],
  ["get_cve", { cve_id: "CVE-2023-44487" }],
  ["cve_exposure", { cve_id: EXPOSURE_CVE }],
  ["exposure_radar", {}],
  ["kev_recent", { vendor: "Ivanti", ransomware: false }],
];

let stub;
let env;
before(async () => {
  stub = http.createServer((req, res) => {
    const answer = ANSWERS[new URL(req.url, "http://stub").pathname];
    if (answer) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(answer));
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
  it("tools/list lists every tool in order, each with a title, annotations and an outputSchema", async () => {
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
    it("tools/list lists every tool in order, each with a title, annotations and an outputSchema", async () => {
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

// #2440: a client that passes only `content` to the model must still see how each answer was
// measured, whichever protocol version it negotiated. The last text block of every result is
// structuredContent as JSON, less what an earlier block says verbatim (#2467): data, which is
// the first block on a success, the sentences of the block just before it, with which notes
// ends, and method where that block quotes it. #2439: the production-shaped cve_exposure answer
// is not_assessed in every version.
const sentencesOf = (t) => t.replace(/\s+/g, " ").trim().split(/(?<=[.!?])\s+/).filter(Boolean);
describe("#2440: in every protocol version, every tool's text carries its structured envelope", () => {
  for (const era of [MODERN, ...LEGACY]) {
    it(`${era}: each tool's text blocks together are its structuredContent, and the last repeats nothing`, async () => {
      const client = await open(era);
      try {
        const states = {};
        let methodQuoted = 0;
        for (const [name, args] of CALLS) {
          const res = await client.callTool({ name, arguments: args });
          const sc = res.structuredContent;
          assert.ok(sc && typeof sc === "object", `${era} ${name}: no structuredContent`);
          const blocks = (res.content ?? []).filter((c) => c.type === "text").map((c) => c.text);
          assert.equal(blocks.length, res.isError ? 2 : 3, `${era} ${name}: ${blocks.length} text blocks`);
          const { data, ...envelope } = sc;
          const text = JSON.parse(blocks.at(-1));
          const said = blocks.at(-2);
          for (const k of ["state", "measured_at", "coverage", "freshness"]) {
            assert.deepEqual(text[k], sc[k], `${era} ${name}: the text's ${k} is not structuredContent's`);
          }
          // method: in the envelope block, or quoted verbatim by the block before it, not both.
          const quoted = typeof sc.method === "string" && said.includes(sc.method);
          if ("method" in text) {
            assert.deepEqual(text.method, sc.method, `${era} ${name}: the text's method is not structuredContent's`);
            assert.ok(!quoted, `${era} ${name}: the envelope block repeats the method the note quotes`);
          } else {
            assert.ok(quoted, `${era} ${name}: no text block carries method`);
            methodQuoted++;
          }
          // notes: the envelope block's own, then the block before's sentences, each verbatim.
          const before = sentencesOf(said);
          for (const s of before) assert.ok(said.includes(s), `${era} ${name}: "${s}"`);
          const own = text.notes ?? [];
          assert.deepEqual(own.filter((s) => before.includes(s)), [], `${era} ${name}: the envelope block repeats the note`);
          assert.deepEqual(sc.notes, [...own, ...before], `${era} ${name}: the text's notes and note are not structuredContent's notes`);
          assert.deepEqual({ ...text, method: sc.method, notes: sc.notes }, envelope, `${era} ${name}`);
          if (!res.isError) assert.deepEqual(JSON.parse(blocks[0]), data, `${era} ${name}: the first block is not data`);
          states[name] = sc.state;
        }
        assert.equal(methodQuoted, 1, `${era}: cve_exposure's note quotes its method, so its envelope block leaves it out`);
        assert.deepEqual(states, { cve_summary: "measured", search_cves: "failed", get_cve: "failed", cve_exposure: "not_assessed", exposure_radar: "failed", kev_recent: "measured" });
      } finally {
        await client.close();
      }
    });
    it(`${era}: production's cve_exposure answer, dated only by a write time, is not_assessed with measured_at null, in text and structure`, async () => {
      const client = await open(era);
      try {
        const res = await client.callTool({ name: "cve_exposure", arguments: { cve_id: EXPOSURE_CVE } });
        assert.notEqual(res.isError, true);
        const text = JSON.parse(res.content.filter((c) => c.type === "text").at(-1).text);
        for (const env of [res.structuredContent, text]) {
          assert.equal(env.state, "not_assessed");
          assert.equal(env.measured_at, null);
          assert.equal(env.exposure_state, "exposed");
        }
        assert.equal(res.structuredContent.data.exposed_hosts, 229, "the count is relayed");
      } finally {
        await client.close();
      }
    });
  }
});
