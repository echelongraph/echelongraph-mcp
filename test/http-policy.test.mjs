// #2316: the hosted endpoint's edge rules in isolation (dist/httpPolicy.js): the Origin policy,
// who the client is, the per-client window, and the bounded access-log fields.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { PKG_DIR } from "./server-under-test.mjs";
import { MODERN } from "./mcp-stdio-client.mjs";
import { modernMeta } from "./mcp-http-client.mjs";

const P = await import(pathToFileURL(path.join(PKG_DIR, "dist", "httpPolicy.js")).href);
const R = await import(pathToFileURL(path.join(PKG_DIR, "dist", "runtime.js")).href);

describe("originVerdict: absent or https served; everything else refused", () => {
  for (const o of [undefined, "https://claude.ai", "https://example.com:8443", "HTTPS://Example.COM"]) {
    it(`${JSON.stringify(o)} is served`, () => assert.equal(P.originVerdict(o).ok, true));
  }
  for (const o of ["", " ", "null", "NULL", "http://example.com", "http://localhost:6274", "file://", "chrome-extension://abc", "not a url", "https://example.com/", "https://example.com/path", "https://user:pw@example.com", "https://a.example, https://b.example", "https://a.example https://b.example"]) {
    it(`${JSON.stringify(o)} is refused`, () => {
      const v = P.originVerdict(o);
      assert.equal(v.ok, false);
      assert.equal(typeof v.reason, "string");
    });
  }
});

describe("resolveClient: the rightmost public X-Forwarded-For hop, else the socket peer", () => {
  const rows = [
    // [xff, socket, key, forwardAddress]
    ["198.51.100.21, 169.254.169.126,0.0.0.0", "169.254.169.126", "198.51.100.21", "198.51.100.21"],
    ["1.2.3.4, 198.51.100.21, 169.254.169.126, 0.0.0.0", "169.254.169.126", "198.51.100.21", "198.51.100.21"],
    ["10.0.0.1, 198.51.100.21, 169.254.169.126", "169.254.169.126", "198.51.100.21", "198.51.100.21"],
    ["203.0.113.7:51234, 169.254.169.126", "169.254.169.126", "203.0.113.7", "203.0.113.7"],
    ["::ffff:203.0.113.7, 169.254.169.126", "169.254.169.126", "203.0.113.7", "203.0.113.7"],
    ["2001:db8:1:2:aaaa::1, fe80::1, ::", "169.254.169.126", "2001:db8:1:2::/64", "2001:db8:1:2:aaaa::1"],
    ["[2001:db8:1:2::1]:443, 169.254.169.126", "169.254.169.126", "2001:db8:1:2::/64", "2001:db8:1:2::1"],
    ["2001:DB8:1:2::1%eth0, 169.254.169.126", "169.254.169.126", "2001:db8:1:2::/64", "2001:db8:1:2::1"],
    // no public hop: the peer, not forwarded
    ["10.128.0.5, 169.254.169.126, 0.0.0.0", "169.254.169.126", "169.254.169.126", undefined],
    ["unknown, garbage, fd00::1, ::1, 127.0.0.1, 100.64.0.0x", "127.0.0.1", "127.0.0.1", undefined],
    [undefined, "::ffff:127.0.0.1", "127.0.0.1", undefined],
    // a public peer with no header (no front end in the way) is a client like any other
    [undefined, "198.51.100.5", "198.51.100.5", "198.51.100.5"],
  ];
  for (const [xff, sock, key, fwd] of rows) {
    it(`${xff ?? "(no header)"} / ${sock}`, () => {
      const c = P.resolveClient(xff, sock);
      assert.equal(c.key, key);
      assert.equal(c.forwardAddress, fwd);
    });
  }
  it("every excluded class is not public", () => {
    for (const a of ["0.0.0.0", "10.1.2.3", "127.0.0.1", "169.254.1.1", "172.16.0.1", "172.31.255.255", "192.168.0.1", "224.0.0.1", "255.255.255.255", "::", "::1", "fe80::1", "ff02::1", "fc00::1", "fdff::1"]) {
      assert.equal(P.isPublic(P.parseAddress(a)), false, a);
    }
    for (const a of ["8.8.8.8", "172.32.0.1", "100.64.0.1", "2001:4860::8888", "2606:4700::1111"]) {
      assert.equal(P.isPublic(P.parseAddress(a)), true, a);
    }
  });
});

describe("FixedWindowLimiter", () => {
  it("admits max per window per key, refuses with a Retry-After, and resets with the window", () => {
    let t = 1_000_000;
    const l = new P.FixedWindowLimiter(2, 60_000, () => t);
    assert.equal(l.hit("a").allowed, true);
    assert.equal(l.hit("a").allowed, true);
    const refused = l.hit("a");
    assert.equal(refused.allowed, false);
    assert.equal(refused.retryAfterSec, 60);
    assert.equal(l.hit("b").allowed, true, "another key has its own budget");
    t += 30_000;
    assert.equal(l.hit("a").retryAfterSec, 30);
    t += 30_000;
    assert.equal(l.hit("a").allowed, true, "the window reset");
  });
  it("stays bounded under a flood of distinct keys, and forgetting a key only ever admits", () => {
    const t = 0;
    const l = new P.FixedWindowLimiter(1, 60_000, () => t, 100);
    for (let i = 0; i < 1000; i++) l.hit(`k${i}`);
    assert.ok(l.windows.size <= 100, `size ${l.windows.size}`);
  });
});

describe("#2775: Slots.wouldWait says whether acquire would wait, so an at-once refusal is never timed", () => {
  it("free: no wait; full with room to wait: a wait; full with every place taken, or no wait configured: no wait", async () => {
    const s = new P.Slots(1, 2);
    assert.equal(s.wouldWait(1000), false, "a free slot");
    assert.equal(s.tryAcquire(), true);
    assert.equal(s.wouldWait(1000), true, "full, none waiting");
    assert.equal(s.wouldWait(0), false, "no wait configured");
    const w1 = s.acquire(1000);
    const w2 = s.acquire(1000);
    assert.equal(s.wouldWait(1000), false, "two already wait");
    assert.equal(await s.acquire(1000), false, "and acquire refuses at once, as wouldWait said");
    s.release();
    s.release();
    assert.deepEqual(await Promise.all([w1, w2]), [true, true]);
  });
});

describe("bounded access-log fields", () => {
  it("bodyFacts names the method and a shape-checked tool, and nothing else", () => {
    const b = (o) => Buffer.from(JSON.stringify(o));
    assert.deepEqual(P.bodyFacts(b({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "search_cves", arguments: { search: "secret" } } })), { rpc_method: "tools/call", tool: "search_cves" });
    assert.deepEqual(P.bodyFacts(b({ method: "tools/call", params: { name: "secret value with spaces" } })), { rpc_method: "tools/call", tool: "(other)" });
    assert.deepEqual(P.bodyFacts(b({ method: "x".repeat(80) })), { rpc_method: "(other)" });
    assert.deepEqual(P.bodyFacts(b([{ method: "tools/list" }])), { rpc_method: "(batch)" });
    assert.deepEqual(P.bodyFacts(Buffer.from("{not json")), { rpc_method: "(unparseable)" });
    assert.deepEqual(P.bodyFacts(undefined), { rpc_method: "(none)" });
  });
  // #2923's review (nit): rpc_method was the client's own string, shape-checked (/^[a-z][a-z/_]{0,39}$/i): a closed
  // set of labels it was not. Now a method MCP defines for a client is itself and any other string is "(other)".
  it("bodyFacts' rpc_method is a method MCP defines for a client, else (other), however well shaped (#2923's review)", () => {
    const b = (o) => Buffer.from(JSON.stringify(o));
    assert.ok(P.MCP_METHODS.size >= 13, `MCP_METHODS has ${P.MCP_METHODS.size}`);
    for (const m of P.MCP_METHODS) {
      const want = m === "tools/call" ? { rpc_method: m, tool: "get_cve" } : m === "prompts/get" ? { rpc_method: m, prompt: "get_cve" } : { rpc_method: m };
      assert.deepEqual(P.bodyFacts(b({ jsonrpc: "2.0", id: 1, method: m, params: { name: "get_cve" } })), want, m);
    }
    for (const m of ["initialize", "notifications/initialized", "tools/list", "tools/call", "prompts/list", "prompts/get", "resources/list", "resources/read", "resources/templates/list", "ping", "logging/setLevel", "completion/complete", "notifications/cancelled"]) {
      assert.ok(P.MCP_METHODS.has(m), `MCP_METHODS lacks ${m}`);
    }
    // CONTROLS: each of these passed the old shape check and was logged as sent.
    for (const m of ["my_api_key_abc", "secret/value", "tools/lists", "Tools/List", "TOOLS/CALL", "sampling/createMessage", "roots/list", "elicitation/create", "notifications/message", "x".repeat(40)]) {
      assert.deepEqual(P.bodyFacts(b({ jsonrpc: "2.0", id: 1, method: m })), { rpc_method: "(other)" }, m);
    }
  });
  it("MCP_METHODS is exactly the SDK's client requests and notifications, and its task methods (#2923's review)", async () => {
    // The SDK the server bundles: an upgrade that adds or drops a client method fails here until MCP_METHODS follows.
    const core = await import("@modelcontextprotocol/core");
    const methods = (u) => u.options.map((o) => o.shape.method.value);
    const sdk = new Set([
      ...methods(core.ClientRequestSchema),
      ...methods(core.ClientNotificationSchema),
      ...["GetTaskRequestSchema", "GetTaskPayloadRequestSchema", "ListTasksRequestSchema", "CancelTaskRequestSchema", "TaskStatusNotificationSchema"].map((n) => core[n].shape.method.value),
    ]);
    assert.ok(sdk.size >= 20 && [...sdk].every((m) => typeof m === "string"), `read ${sdk.size} methods from the SDK: re-aim this test`);
    assert.deepEqual([...P.MCP_METHODS].sort(), [...sdk].sort());
  });
  // 3.1.0's final review (low): the access line's `method` was req.method as sent, and over h2c that is any :method token.
  it("httpMethodLabel is one of nine HTTP methods, else (other)", () => {
    const NINE = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE"];
    assert.deepEqual([...P.HTTP_METHODS].sort(), [...NINE].sort());
    for (const m of NINE) assert.equal(P.httpMethodLabel(m), m, m);
    // CONTROLS: each of these was logged as sent over h2c.
    for (const m of ["JOHN.DOE-SSN-123-45-6789", "ZZCANARYMETHOD", "get", "Get", "PROPFIND", "MKCOL", "GET ", " GET", "GET\n", "Q".repeat(8000), "", undefined]) {
      assert.equal(P.httpMethodLabel(m), "(other)", JSON.stringify(m)?.slice(0, 40));
    }
  });
  it("rstCodeLabel: an HTTP/2 reset code RFC 9113 defines (0x0-0xd), else (other); null with no reset (3.1.0's final panel)", () => {
    for (let c = 0; c <= 0xd; c++) assert.equal(P.rstCodeLabel(c), c, String(c));
    assert.equal(P.rstCodeLabel(undefined), null);
    assert.equal(P.rstCodeLabel(null), null);
    // CONTROLS: a client's own RST_STREAM code was logged as sent under h2c (0x7a71c0de as 2054275294).
    for (const c of [0xe, 0x7a71c0de, 0xffffffff, -1, 1.5, Number.NaN]) assert.equal(P.rstCodeLabel(c), "(other)", String(c));
  });
  it("revisionLabel and uaFamily keep only bounded shapes", () => {
    assert.equal(P.revisionLabel("2026-07-28"), "2026-07-28");
    assert.equal(P.revisionLabel("2026-07-28; drop table"), "(other)");
    assert.equal(P.revisionLabel(undefined), "(none)");
    assert.equal(P.uaFamily("claude-user/1.0 (+https://x)"), "claude-user");
    assert.equal(P.uaFamily("<script>/1"), "(other)");
    assert.equal(P.uaFamily(undefined), "(none)");
  });
});

describe("#2747: the request-body caps and the large-body slots", () => {
  it("the large cap is for a tools/call of check_sbom or scan_manifest and a prompts/get of sbom_review alone (#3149), above their content caps and below Cloud Run's 32 MiB", async () => {
    const S = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "check_sbom.js")).href);
    // #2835: scan_manifest takes a project's lockfiles, up to the same number of characters.
    const M = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "scan_manifest.js")).href);
    assert.deepEqual(P.LARGE_BODY_TARGETS, { "tools/call": [S.CHECK_SBOM, M.SCAN_MANIFEST], "prompts/get": ["sbom_review"] });
    assert.equal(P.DEFAULT_MAX_BODY_BYTES, 64 * 1024);
    assert.ok(P.DEFAULT_MAX_SBOM_BODY_BYTES > S.MAX_SBOM_CHARS, "a document at check_sbom's own cap could never arrive");
    assert.ok(P.DEFAULT_MAX_SBOM_BODY_BYTES > M.MAX_MANIFEST_CHARS, "lockfiles at scan_manifest's own cap could never arrive");
    assert.equal(P.LARGE_BODY_TARGETS_TEXT, "a tools/call of check_sbom or scan_manifest, or a prompts/get of sbom_review");
    assert.ok(P.DEFAULT_MAX_SBOM_BODY_BYTES < 32 * 1024 * 1024, "over Cloud Run's HTTP/1 request limit");
  });
  it("largeBodyAdmissible: absent headers, or a target named by them, may be large; any other named method or name may not", () => {
    assert.equal(P.largeBodyAdmissible(undefined, undefined), true);
    assert.equal(P.largeBodyAdmissible("tools/call", "check_sbom"), true);
    assert.equal(P.largeBodyAdmissible("tools/call", undefined), true);
    assert.equal(P.largeBodyAdmissible("prompts/get", "sbom_review"), true);
    assert.equal(P.largeBodyAdmissible("tools/call", "scan_manifest"), true);
    assert.equal(P.largeBodyAdmissible(undefined, "scan_manifest"), true);
    assert.equal(P.largeBodyAdmissible("prompts/get", "scan_manifest"), false);
    assert.equal(P.largeBodyAdmissible("tools/call", "cve_summary"), false);
    assert.equal(P.largeBodyAdmissible("tools/call", "sbom_review"), false);
    assert.equal(P.largeBodyAdmissible("prompts/get", "check_sbom"), false);
    // #2846: workload_triage takes no workload data (one optional source word), so it is no large-body target.
    assert.equal(P.largeBodyAdmissible("prompts/get", "workload_triage"), false);
    assert.equal(P.largeBodyAdmissible("tools/list", undefined), false);
    assert.equal(P.largeBodyAdmissible("initialize", "check_sbom"), false);
    assert.equal(P.largeBodyAdmissible("toString", undefined), false);
    assert.equal(P.largeBodyAdmissible(undefined, "cve_summary"), false);
  });
  it("isLargeBodyTarget reads the body's own method and name", () => {
    const b = (o) => P.bodyFacts(Buffer.from(JSON.stringify(o)));
    assert.equal(P.isLargeBodyTarget(b({ method: "tools/call", params: { name: "check_sbom" } })), true);
    assert.equal(P.isLargeBodyTarget(b({ method: "prompts/get", params: { name: "sbom_review" } })), true);
    assert.equal(P.isLargeBodyTarget(b({ method: "tools/call", params: { name: "scan_manifest" } })), true);
    assert.equal(P.isLargeBodyTarget(b({ method: "prompts/get", params: { name: "scan_manifest" } })), false);
    assert.equal(P.isLargeBodyTarget(b({ method: "tools/call", params: { name: "sbom_review" } })), false);
    assert.equal(P.isLargeBodyTarget(b({ method: "prompts/get", params: { name: "workload_triage" } })), false);
    assert.equal(P.isLargeBodyTarget(b({ method: "tools/list" })), false);
    assert.equal(P.isLargeBodyTarget(b([{ method: "tools/call", params: { name: "check_sbom" } }])), false, "a batch");
  });
  // #2775, decided 2026-10-18: a large body that finds every slot busy may wait for one, two waiters at most.
  it("Slots.acquire waits for a release, first come first served, at most maxWaiting; a timeout or an abort gives up", async () => {
    const s = new P.Slots(1, 2);
    assert.equal(await s.acquire(1000), true, "a free slot is taken at once");
    const order = [];
    const a = s.acquire(5000).then((ok) => order.push(["a", ok]));
    const b = s.acquire(5000).then((ok) => order.push(["b", ok]));
    assert.equal(s.waiting, 2);
    assert.equal(await s.acquire(5000), false, "a third waiter is refused at once");
    assert.equal(s.tryAcquire(), false, "tryAcquire does not jump the queue");
    s.release();
    await a;
    assert.deepEqual(order, [["a", true]], "the first waiter gets the freed slot");
    assert.equal(s.inUse, 1, "a slot handed over is not counted twice");
    const ctl = new AbortController();
    const c = s.acquire(5000, ctl.signal);
    ctl.abort();
    assert.equal(await c, false, "an aborted wait gives up");
    s.release();
    await b;
    assert.deepEqual(order, [["a", true], ["b", true]]);
    const t0 = Date.now();
    assert.equal(await s.acquire(50), false, "a wait that runs out gives up");
    assert.ok(Date.now() - t0 >= 45);
    assert.equal(s.waiting, 0);
    s.release();
    assert.equal(s.inUse, 0);
    assert.equal(await new P.Slots(1).acquire(1000).then(() => new P.Slots(1, 0).acquire(1000)), true);
  });
  it("Slots never waits: past max, tryAcquire is false until a release", () => {
    const s = new P.Slots(2);
    assert.equal(s.tryAcquire(), true);
    assert.equal(s.tryAcquire(), true);
    assert.equal(s.tryAcquire(), false);
    s.release();
    assert.equal(s.inUse, 1);
    assert.equal(s.tryAcquire(), true);
    s.release();
    s.release();
    s.release();
    assert.equal(s.inUse, 0, "a release past zero went negative");
  });
});

describe("#2773: Admission, the requests served at once per instance", () => {
  const settled = async (p) => Promise.race([p.then((v) => ({ v })), new Promise((r) => setTimeout(() => r("pending"), 20))]);
  it("the defaults: 64 served at once, a 10 s wait, at most 250 waiting (Cloud Run's concurrency)", () => {
    assert.equal(P.DEFAULT_MAX_IN_FLIGHT, 64);
    assert.equal(P.DEFAULT_ADMISSION_WAIT_MS, 10_000);
    assert.equal(P.DEFAULT_MAX_WAITING, 250);
  });
  it("admits up to max at once; the next waits and is admitted, in arrival order, as each is released", async () => {
    const a = new P.Admission(2, 10);
    assert.equal(await a.acquire(1000), true);
    assert.equal(await a.acquire(1000), true);
    const third = a.acquire(1000);
    const fourth = a.acquire(1000);
    assert.equal(await settled(third), "pending");
    assert.deepEqual([a.inUse, a.waiting], [2, 2]);
    a.release();
    assert.deepEqual(await settled(third), { v: true });
    assert.equal(await settled(fourth), "pending", "the second waiter went first");
    assert.deepEqual([a.inUse, a.waiting], [2, 1], "a release hands its place over: in use stays at max");
    a.release();
    assert.deepEqual(await settled(fourth), { v: true });
    a.release();
    a.release();
    assert.equal(a.inUse, 0);
    a.release();
    assert.equal(a.inUse, 0, "a release past zero went negative");
  });
  it("a wait ends false after waitMs, or at once when its signal aborts, and leaves no place behind", async () => {
    const a = new P.Admission(1, 10);
    assert.equal(await a.acquire(1000), true);
    const t0 = Date.now();
    assert.equal(await a.acquire(60), false);
    assert.ok(Date.now() - t0 >= 50, "the wait was not waited");
    const ac = new AbortController();
    const gone = a.acquire(5000, ac.signal);
    ac.abort();
    assert.deepEqual(await settled(gone), { v: false });
    assert.equal(a.waiting, 0, "a waiter that gave up is still queued");
    a.release();
    assert.equal(a.inUse, 0, "a release was handed to a waiter that had gone");
    assert.equal(await a.acquire(0), true);
  });
  it("refuses at once when maxWaiting already wait, or the signal has already aborted", async () => {
    const a = new P.Admission(1, 1);
    assert.equal(await a.acquire(1000), true);
    const waiting = a.acquire(1000);
    assert.deepEqual(await settled(a.acquire(1000)), { v: false });
    const ac = new AbortController();
    ac.abort();
    const b = new P.Admission(1, 5);
    assert.equal(await b.acquire(1000), true);
    assert.deepEqual(await settled(b.acquire(1000, ac.signal)), { v: false });
    a.release();
    assert.equal(await waiting, true);
  });
});

// #2773: the one request that is a stream, decided by the SDK's own routing step.
describe("#2773: isListenStream, the request that takes no place", () => {
  const listen = { notifications: { toolsListChanged: true } };
  const msg = (method, params) => Buffer.from(JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }));
  const modernHead = (method) => ({ protocolVersion: MODERN, mcpMethod: method });
  const is = (body, headers) => P.isListenStream(P.bodyFacts(body), body, headers);
  it("a 2026-era subscriptions/listen is one", () => {
    assert.equal(is(msg("subscriptions/listen", { ...listen, _meta: modernMeta() }), modernHead("subscriptions/listen")), true);
  });
  it("a 2025-era body naming the method is not: the SDK's legacy fallback answers it at once", () => {
    assert.equal(is(msg("subscriptions/listen", listen), { protocolVersion: "2025-06-18" }), false);
    assert.equal(is(msg("subscriptions/listen", listen), {}), false);
  });
  it("nor is a listen the SDK refuses before its listen router (a method header that names another method)", () => {
    assert.equal(is(msg("subscriptions/listen", { ...listen, _meta: modernMeta() }), modernHead("tools/list")), false);
  });
  it("nor any other 2026-era request, nor a batch or a body that is not JSON", () => {
    assert.equal(is(msg("tools/call", { name: "cve_summary", arguments: {}, _meta: modernMeta() }), { ...modernHead("tools/call"), mcpName: "cve_summary" }), false);
    assert.equal(is(msg("server/discover", { _meta: modernMeta() }), modernHead("server/discover")), false);
    assert.equal(is(Buffer.from(JSON.stringify([{ jsonrpc: "2.0", id: 1, method: "subscriptions/listen", params: listen }])), {}), false);
    assert.equal(is(Buffer.from('{"method":"subscriptions/listen"'), modernHead("subscriptions/listen")), false);
  });
});

// #2948: the upstream-failure line names the API call by its route template and its failure by a
// class, never by the path (which holds what was looked up) or the error's message.
describe("#2948: apiRoute, upstreamSeverity and networkFailureClass", () => {
  const ROWS = [
    // #2948's review: a list route is named as core-backend's http_request line names it, with the group's slash.
    ["/api/v1/public/cves?severity=CRITICAL&limit=7&offset=0", "/api/v1/public/cves/"],
    ["/api/v1/public/cves/", "/api/v1/public/cves/"],
    ["/api/v1/public/cves/summary", "/api/v1/public/cves/summary"],
    ["/api/v1/public/cves/match", "/api/v1/public/cves/match"],
    ["/api/v1/public/cves/match/batch", "/api/v1/public/cves/match/batch"],
    ["/api/v1/public/cves/CVE-2099-29480", "/api/v1/public/cves/:id"],
    ["/api/v1/public/cves/CVE-2099-29480/enrichment", "/api/v1/public/cves/:id/enrichment"],
    ["/api/v1/public/cves/CVE-2099-29480/epss-history", "/api/v1/public/cves/:id/epss-history"],
    ["/api/v1/public/cves/CVE-2099-29480/remediation", "/api/v1/public/cves/:id/remediation"],
    ["/api/v1/public/cwes/CWE-79?page=3", "/api/v1/public/cwes/:cwe_id"],
    ["/api/v1/public/kev/recent", "/api/v1/public/kev/recent"],
    ["/api/v1/public/kev-exposure/stats", "/api/v1/public/kev-exposure/stats"],
    ["/api/v1/public/kev-exposure/cve/CVE-2099-29480", "/api/v1/public/kev-exposure/cve/:id"],
    ["/api/v1/public/exposed-databases/stats", "/api/v1/public/exposed-databases/stats"],
    ["/api/v1/public/leaked-credentials/stats", "/api/v1/public/leaked-credentials/stats"],
    ["/api/v1/public/shadow-ai-radar/stats", "/api/v1/public/shadow-ai-radar/stats"],
    ["/api/v1/public/ai-exposure/stats?service=mcp", "/api/v1/public/ai-exposure/stats"],
    ["/api/v1/public/vendor-advisories?vendor=zzvendor&limit=20", "/api/v1/public/vendor-advisories/"],
    ["/api/v1/public/vendor-advisories/coverage", "/api/v1/public/vendor-advisories/coverage"],
    ["/api/v1/public/vendor-advisories/by-cve/CVE-2099-29480", "/api/v1/public/vendor-advisories/by-cve/:cve_id"],
    ["/api/v1/public/vendor-advisories/zzvendor/ZZ-ADV%2F2948", "/api/v1/public/vendor-advisories/:vendor/:advisory_id"],
  ];
  for (const [p, route] of ROWS) it(`${p} is ${route}`, () => assert.equal(P.apiRoute(p), route));
  it("a path no template matches is (other), and no path at all (none): never the path", () => {
    for (const p of ["/api/v1/public/cves/CVE-2099-29480/blast-radius", "/api/v1/internal/x", "/", "", "/api/v1/public/cves/a/b/c", "zzsecret2948"]) {
      assert.equal(P.apiRoute(p), "(other)", p);
    }
    assert.equal(P.apiRoute(null), "(none)");
  });
  it("every template is core-backend's route shape: fixed words and named parameters, nothing looked up", () => {
    assert.equal(P.API_ROUTE_TEMPLATES.length, new Set(P.API_ROUTE_TEMPLATES).size, "a template is listed twice");
    for (const t of P.API_ROUTE_TEMPLATES) assert.match(t, /^\/api\/v1\/public(?:\/(?:[a-z][a-z-]*|:[a-z_]+))+\/?$/, t);
  });

  // Every path the tool modules build, as written in the shipped dist: a string or template literal
  // that starts with /api/v1/public/, each ${…} read as one placeholder segment. A new route the line
  // would log as (other) fails here until it has a template; a template no tool calls fails too.
  const literals = (src) => {
    const out = [];
    const start = /(["'`])\/api\/v1\/public\//g;
    let m;
    while ((m = start.exec(src))) {
      const q = m[1];
      let i = m.index + 1;
      let s = "";
      for (; i < src.length && src[i] !== q; i++) {
        if (q === "`" && src[i] === "$" && src[i + 1] === "{") {
          let depth = 0;
          for (i++; i < src.length; i++) {
            if (src[i] === "{") depth++;
            else if (src[i] === "}" && --depth === 0) break;
          }
          s += "X";
        } else s += src[i];
      }
      out.push(s);
      start.lastIndex = i + 1;
    }
    return out;
  };
  const dist = path.join(PKG_DIR, "dist");
  // httpPolicy.js itself is left out: its templates are literals too, and would match themselves.
  const files = fs.readdirSync(dist, { recursive: true }).filter((f) => String(f).endsWith(".js") && path.basename(String(f)) !== "httpPolicy.js");
  const found = [...new Set(files.flatMap((f) => literals(fs.readFileSync(path.join(dist, String(f)), "utf8"))))];
  it("every API path the server builds has a template, and every template is one a tool calls", () => {
    assert.ok(found.length >= 18, `${found.length} API path literals read from dist: re-aim this check (${found.join(" ")})`);
    assert.ok(!found.some((p) => p.includes(":")), `a template was read as a path the server calls: ${found.join(" ")}`);
    for (const p of found) assert.notEqual(P.apiRoute(p), "(other)", `the server calls ${p}, which the upstream-failure line would log as (other): add its template`);
    const used = new Set(found.map((p) => P.apiRoute(p)));
    for (const t of P.API_ROUTE_TEMPLATES) assert.ok(used.has(t), `${t} is a template no tool calls: take it out`);
  });
  it("control: the reader sees a template literal's placeholders and a nested template", () => {
    assert.deepEqual(literals('a(`/api/v1/public/cwes/${enc(c)}${n > 1 ? `?page=${n}` : ""}`); b("/api/v1/public/kev/recent")'), ["/api/v1/public/cwes/XX", "/api/v1/public/kev/recent"]);
  });

  it("upstreamSeverity: a 400, or a 404 for a named record, is the API's answer (INFO); this server's own schema refusing an answer is ERROR; everything else WARNING", () => {
    // #2948's review: output_schema is a fault of this server, not of the API: never WARNING, so never the upstream alert's.
    assert.equal(P.upstreamSeverity("output_schema", null, "(none)"), "ERROR");
    assert.equal(P.upstreamSeverity("http", 400, "/api/v1/public/cves/"), "INFO");
    assert.equal(P.upstreamSeverity("http", 404, "/api/v1/public/cves/:id"), "INFO");
    assert.equal(P.upstreamSeverity("http", 404, "/api/v1/public/vendor-advisories/:vendor/:advisory_id"), "INFO");
    for (const [cls, status, route] of [
      ["http", 404, "/api/v1/public/cves/summary"],
      ["http", 404, "(other)"],
      ["http", 404, "(none)"],
      ["http", 429, "/api/v1/public/cves/:id"],
      ["http", 503, "/api/v1/public/cves/:id"],
      ["http", 403, "/api/v1/public/cves/:id"],
      ["not_json", 200, "/api/v1/public/cves/:id"],
      ["timeout", null, "/api/v1/public/cves/:id"],
      ["unexpected_shape", 404, "/api/v1/public/cves/:id"],
    ]) assert.equal(P.upstreamSeverity(cls, status, route), "WARNING", `${cls} ${status} ${route}`);
  });

  // undici's fetch throws TypeError("fetch failed") with the system error as its cause (measured on
  // Node 22.22: ENOTFOUND, ECONNREFUSED, ECONNRESET, UND_ERR_SOCKET "other side closed", and a
  // reset mid-body as TypeError("terminated") caused by ECONNRESET).
  const fetchFailed = (code, message = `x ${code}`, outer = "fetch failed") => Object.assign(new TypeError(outer), { cause: Object.assign(new Error(message), { code }) });
  it("networkFailureClass reads the codes in the cause chain, never the message", () => {
    for (const [code, cls] of [
      ["ENOTFOUND", "dns"],
      ["EAI_AGAIN", "dns"],
      ["ECONNREFUSED", "refused"],
      ["ECONNRESET", "reset"],
      ["UND_ERR_SOCKET", "reset"],
      ["EPIPE", "reset"],
      ["UND_ERR_CONNECT_TIMEOUT", "connect_timeout"],
      ["ETIMEDOUT", "connect_timeout"],
      ["UND_ERR_HEADERS_TIMEOUT", "timeout"],
      ["EHOSTUNREACH", "unreachable"],
      ["ENETUNREACH", "unreachable"],
      ["ERR_TLS_CERT_ALTNAME_INVALID", "tls"],
      ["CERT_HAS_EXPIRED", "tls"],
      ["UNABLE_TO_VERIFY_LEAF_SIGNATURE", "tls"],
      ["ERR_SSL_PACKET_LENGTH_TOO_LONG", "tls"],
      ["EWHATEVER", "network"],
    ]) assert.equal(R.networkFailureClass(fetchFailed(code)), cls, code);
    assert.equal(R.networkFailureClass(fetchFailed("ECONNRESET", "read ECONNRESET", "terminated")), "reset");
    // Several addresses tried: an AggregateError of each one's error.
    const agg = Object.assign(new TypeError("fetch failed"), { cause: new AggregateError([Object.assign(new Error("a"), { code: "ECONNREFUSED" }), Object.assign(new Error("b"), { code: "ECONNREFUSED" })]) });
    assert.equal(R.networkFailureClass(agg), "refused");
    // No code anywhere ("bad port"), or not an Error: network.
    assert.equal(R.networkFailureClass(Object.assign(new TypeError("fetch failed"), { cause: new Error("bad port") })), "network");
    assert.equal(R.networkFailureClass("ECONNRESET"), "network");
    assert.equal(R.networkFailureClass(fetchFailed("ENOTFOUND", "getaddrinfo ENOTFOUND zzsecret2948.example")), "dns");
  });

  it("upstreamFailed writes nothing until http.ts registers its line, and never outside the HTTP entrypoint", () => {
    // This test process never called markHttpEntrypoint: the npm package's state.
    let got = 0;
    R.onUpstreamFailure(() => got++);
    R.upstreamFailed({ failureClass: "http", path: "/api/v1/public/cves/summary", status: 503, afterMs: 1 });
    assert.equal(got, 0, "a failure was reported on the stdio entrypoint");
  });
});
