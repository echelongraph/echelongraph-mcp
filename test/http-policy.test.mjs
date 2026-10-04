// #2316: the hosted endpoint's edge rules in isolation (dist/httpPolicy.js): the Origin policy,
// who the client is, the per-client window, and the bounded access-log fields.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { PKG_DIR } from "./server-under-test.mjs";

const P = await import(pathToFileURL(path.join(PKG_DIR, "dist", "httpPolicy.js")).href);

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
  it("the large cap is for check_sbom alone, above its document cap and below Cloud Run's 32 MiB", async () => {
    const S = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "check_sbom.js")).href);
    assert.deepEqual(P.LARGE_BODY_TARGETS, { "tools/call": S.CHECK_SBOM, "prompts/get": "sbom_review" });
    assert.equal(P.DEFAULT_MAX_BODY_BYTES, 64 * 1024);
    assert.ok(P.DEFAULT_MAX_SBOM_BODY_BYTES > S.MAX_SBOM_CHARS, "a document at check_sbom's own cap could never arrive");
    assert.ok(P.DEFAULT_MAX_SBOM_BODY_BYTES < 32 * 1024 * 1024, "over Cloud Run's HTTP/1 request limit");
  });
  it("largeBodyAdmissible: absent headers, or a target named by them, may be large; any other named method or name may not", () => {
    assert.equal(P.largeBodyAdmissible(undefined, undefined), true);
    assert.equal(P.largeBodyAdmissible("tools/call", "check_sbom"), true);
    assert.equal(P.largeBodyAdmissible("tools/call", undefined), true);
    assert.equal(P.largeBodyAdmissible("prompts/get", "sbom_review"), true);
    assert.equal(P.largeBodyAdmissible("tools/call", "cve_summary"), false);
    assert.equal(P.largeBodyAdmissible("tools/call", "sbom_review"), false);
    assert.equal(P.largeBodyAdmissible("prompts/get", "check_sbom"), false);
    assert.equal(P.largeBodyAdmissible("tools/list", undefined), false);
    assert.equal(P.largeBodyAdmissible("initialize", "check_sbom"), false);
    assert.equal(P.largeBodyAdmissible("toString", undefined), false);
    assert.equal(P.largeBodyAdmissible(undefined, "cve_summary"), false);
  });
  it("isLargeBodyTarget reads the body's own method and name", () => {
    const b = (o) => P.bodyFacts(Buffer.from(JSON.stringify(o)));
    assert.equal(P.isLargeBodyTarget(b({ method: "tools/call", params: { name: "check_sbom" } })), true);
    assert.equal(P.isLargeBodyTarget(b({ method: "prompts/get", params: { name: "sbom_review" } })), true);
    assert.equal(P.isLargeBodyTarget(b({ method: "tools/call", params: { name: "sbom_review" } })), false);
    assert.equal(P.isLargeBodyTarget(b({ method: "tools/list" })), false);
    assert.equal(P.isLargeBodyTarget(b([{ method: "tools/call", params: { name: "check_sbom" } }])), false, "a batch");
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
