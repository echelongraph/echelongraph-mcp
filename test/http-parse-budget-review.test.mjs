// #3381's review: the hosted endpoint's parse budget, started as its image starts it (test/image-server.mjs), on each
// way the review found it failing real calls or the process.
//   1. The deadline gave a request's parse holds back while what they stand for was still reachable (the tool stops
//      only when its aborted signal reaches it), so waiting requests parsed beside it and V8 ended the process (3 of 22
//      runs at production's deadline). The reviewer's layout, at a 4 s deadline: nine check_sbom calls filling the
//      budget, each sleeping on the API's 429 past its deadline, and 28 small bodies waiting for room. The holds now go
//      back as the request unwinds: the process lives, and V8's live heap after a full collection stays where the
//      budget puts it (63 to 68 MB measured, where the old release reached 95 to 102 MB).
//   2. One waiter that did not fit held every request behind it (a tools/list waited 9.4 s). Now one that fits passes it.
//   3. And that waiter is not starved: once it has waited BUDGET_STARVE_MS, a large one that fits is taken only beside
//      its room, so it reaches the API before one that came after it.
//   4. A document that finds no room in the wait is answered busy, and its access line says so (refused doc_busy, its
//      wait in queued_ms): through round 3 it wrote refused "" and queued_ms 0. scan_manifest's reservation too.
//   5. A document its request could never hold beside its own body is refused at once, invalid_input, naming the bound:
//      through round 3 it waited 10 s and answered "busy, retry", on an idle instance, every time.
//   6. Two calls with a real-sized document each are both answered: a document's hold is given back once it is read,
//      but for what the answer keeps (through round 3 it was held for the whole API phase, and the second was refused).
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { PKG_DIR } from "./server-under-test.mjs";
import { IMAGE_SKIP, assertAlive, imageBudgets, post, resultOf, sleep, startServer, stubApi, toolCall } from "./image-server.mjs";

const P = await import(pathToFileURL(path.join(PKG_DIR, "dist", "httpPolicy.js")).href);
const B = await import(pathToFileURL(path.join(PKG_DIR, "dist", "parseBudget.js")).href);
const SM = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "scan_manifest.js")).href);
const IMAGE = IMAGE_SKIP ? B : imageBudgets();
const IMG = B.budgetsFor(B.IMAGE_HEAP_LIMIT);
// #3381's round-4 review (F4): the most one request may hold: the budget less the small bodies' share (http.ts).
const MOST = IMAGE.INFLIGHT_BUDGET_BYTES - Math.floor(IMAGE.INFLIGHT_BUDGET_BYTES / 4);

// A check_sbom call whose object-form sbom is estimated at about `mb` MB, waiting at the API with its arguments.
const heldOf = (mb, tag) =>
  toolCall("check_sbom", { sbom: { bomFormat: "CycloneDX", specVersion: "1.5", components: [{ type: "library", name: `a${tag}`, version: "1.0.0", purl: `pkg:npm/a${tag}@1.0.0` }, ...Array(Math.floor((mb * 1e6) / 67)).fill({})] } });
// A check_sbom of one purl and empty objects, 64 KiB: a small body (the general cap).
function smallSbom(tag) {
  const b = heldOf(1.4, tag);
  const n = Math.floor((P.DEFAULT_MAX_BODY_BYTES - (b.length - Math.floor(1.4e6 / 67) * 3)) / 3);
  return toolCall("check_sbom", { sbom: { bomFormat: "CycloneDX", specVersion: "1.5", components: [{ type: "library", name: `a${tag}`, version: "1.0.0", purl: `pkg:npm/a${tag}@1.0.0` }, ...Array(n - 40).fill({})] } });
}
// A tools/call of cve_summary of 64 KiB carrying a list of empty objects.
function smallDense() {
  const head = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cve_summary","arguments":{"junk":[';
  const tail = "]}}}";
  const room = P.DEFAULT_MAX_BODY_BYTES - head.length - tail.length;
  const n = Math.floor((room + 1) / 3);
  const list = Array(n).fill("{}").join(",");
  return head + list + " ".repeat(room - list.length) + tail;
}
// A POST whose last two bytes come `last1` and `last2` ms after the rest.
function slowPost(port, body, last1, last2) {
  return new Promise((resolve) => {
    const buf = Buffer.from(body);
    const req = http.request(
      { host: "127.0.0.1", port, path: "/mcp", method: "POST", agent: false, headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", "MCP-Protocol-Version": "2025-06-18", "Content-Length": buf.length } },
      (res) => {
        res.resume();
        res.on("end", () => resolve({ status: res.statusCode }));
        res.on("error", () => resolve({ status: "reset" }));
      },
    );
    req.on("error", () => resolve({ status: "reset" }));
    req.write(buf.subarray(0, buf.length - 2));
    setTimeout(() => req.write(buf.subarray(buf.length - 2, buf.length - 1)), last1);
    setTimeout(() => req.end(buf.subarray(buf.length - 1)), last2);
  });
}
const SMALL_CALLS = [
  JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
  JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } }),
  JSON.stringify({ jsonrpc: "2.0", id: 1, method: "prompts/list", params: {} }),
  JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
];
// A Syft-shaped CycloneDX document of `n` components over `distinct` purls, as text.
const comp = (i, distinct) => {
  const k = i % distinct;
  return {
    type: "library", "bom-ref": `pkg:npm/elements-${k}@1.0.${k % 10}?package-id=${i.toString(16)}`, name: `elements-${k}`, version: `1.0.${k % 10}`, purl: `pkg:npm/elements-${k}@1.0.${k % 10}`,
    licenses: [{ license: { id: "MIT" } }], hashes: [{ alg: "SHA-256", content: "0123456789abcdef".repeat(4) }],
    properties: Array.from({ length: 8 }, (_, j) => ({ name: `syft:location:${j}:path`, value: `/usr/lib/node_modules/elements-${k}/package.json` })),
  };
};
const syftText = (n, distinct) => JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.6", version: 1, components: Array.from({ length: n }, (_, i) => comp(i, distinct)) });
// An npm lockfile of `n` packages, as npm 10 writes one, `extra` characters of license text on each.
const npmLock = (n, extra = "") =>
  JSON.stringify(
    {
      name: "app", version: "1.0.0", lockfileVersion: 3, requires: true,
      packages: Object.fromEntries([
        ["", { name: "app", version: "1.0.0", dependencies: { "pkg-0": "^1.0.0" } }],
        ...Array.from({ length: n }, (_, i) => [
          `node_modules/pkg-${i}`,
          {
            version: `1.${i % 40}.${i % 7}`, resolved: `https://registry.npmjs.org/pkg-${i}/-/pkg-${i}-1.${i % 40}.${i % 7}.tgz`, integrity: `sha512-${"A".repeat(86)}==`, license: `MIT${extra}`,
            dependencies: Object.fromEntries(Array.from({ length: 8 }, (_, j) => [`pkg-${(i + j + 1) % n}`, "^1.0.0"])), funding: { url: `https://github.com/sponsors/pkg-${i}` }, engines: { node: ">=14" },
          },
        ]),
      ]),
    },
    null,
    2,
  );

// An npm lockfile of `n` packages over `distinct` names (each nested under one of its own), as npm 10 writes one.
const nestedLock = (n, distinct) =>
  JSON.stringify(
    {
      name: "app", version: "1.0.0", lockfileVersion: 3, requires: true,
      packages: Object.fromEntries([
        ["", { name: "app", version: "1.0.0" }],
        ...Array.from({ length: n }, (_, i) => [
          `node_modules/a${i}/node_modules/pkg-${i % distinct}`,
          {
            version: `1.${(i % distinct) % 40}.0`, resolved: `https://registry.npmjs.org/pkg-${i % distinct}/-/pkg-1.0.0.tgz`, integrity: `sha512-${"A".repeat(86)}==`, license: "MIT",
            dependencies: Object.fromEntries(Array.from({ length: 8 }, (_, j) => [`pkg-${(i + j + 1) % distinct}`, "^1.0.0"])), funding: { url: `https://github.com/sponsors/pkg-${i}` }, engines: { node: ">=14" },
          },
        ]),
      ]),
    },
    null,
    2,
  );

describe("#3381's review: the parse budget, on each way the review found it failing", { skip: IMAGE_SKIP, concurrency: false, timeout: 900_000 }, () => {
  let stub;
  before(async () => {
    stub = await stubApi();
  });
  after(async () => {
    stub?.release();
    await stub?.close();
  });

  it("1. a budget-filling set stopped at its deadline while another waits: holds go back as each unwinds, the process lives, its live heap within the budget's", async () => {
    const DEADLINE = 4000;
    const g = [heldOf(29, "g"), ...Array.from({ length: 8 }, (_, i) => smallSbom(`s${i}`))];
    const gEst = g.reduce((n, b) => n + B.scanJson(Buffer.from(b)).estimate, 0);
    const sd = smallDense();
    const wEst = 28 * B.scanJson(Buffer.from(sd)).estimate;
    assert.ok(B.scanJson(Buffer.from(g[0])).estimate <= IMAGE.PARSE_BUDGET_BYTES && gEst > 0.95 * IMAGE.INFLIGHT_BUDGET_BYTES && wEst > 0.95 * IMAGE.INFLIGHT_BUDGET_BYTES, `G ${gEst}, W ${wEst}`);
    for (let run = 1; run <= 2; run++) {
      const srv = await startServer(stub.base, { MCP_REQUEST_TIMEOUT_MS: String(DEADLINE), ECHELONGRAPH_API_TIMEOUT_MS: "15000" }, { nodeFlags: ["--trace-gc"] });
      stub.state.retryAfter = 45;
      try {
        const G = g.map((b) => slowPost(srv.port, b, 800, 1600));
        await sleep(DEADLINE - 500);
        const W = Array.from({ length: 28 }, () => post(srv.port, sd));
        for (let i = 0; i < 40 && srv.alive(); i++) await sleep(100);
        await assertAlive(srv, `run ${run}: the deadline set and the waiting set (live after a full collection at most ${srv.maxLiveMb()} MB)`);
        assert.ok(srv.maxLiveMb() > 0, "no --trace-gc line was read: re-aim this test");
        assert.ok(srv.maxLiveMb() < 85, `run ${run}: ${srv.maxLiveMb()} MB live after a full collection: the deadline set's memory and the waiting set's were held at once`);
        await Promise.all([...G, ...W]);
        assert.ok(srv.access().some((l) => l.refused === "timeout"), "no request reached its deadline: re-aim this test");
      } finally {
        stub.state.retryAfter = null;
        await srv.stop();
      }
    }
  });

  it("2. a waiter that does not fit holds nothing behind it: tools/list, initialize, prompts/list and ping are answered at once while it waits; it is let in once room comes", async () => {
    const srv = await startServer(stub.base);
    stub.hold();
    try {
      const a = heldOf(24, "a");
      const b = heldOf(24, "b");
      const est = B.scanJson(Buffer.from(a)).estimate;
      assert.ok(2 * est > IMAGE.INFLIGHT_BUDGET_BYTES && est < IMAGE.PARSE_BUDGET_BYTES, `${est}`);
      const batches = stub.state.batches;
      const ra = post(srv.port, a);
      for (const t = Date.now(); stub.state.batches === batches && Date.now() - t < 10_000; ) await sleep(20);
      assert.equal(stub.state.batches, batches + 1, "the first did not reach the API");
      let bDone = false;
      const rb = post(srv.port, b).then((r) => ((bDone = true), r));
      await sleep(500);
      for (const body of SMALL_CALLS) {
        const t0 = Date.now();
        const r = await post(srv.port, body);
        const ms = Date.now() - t0;
        assert.equal(r.status, 200, `${body.slice(0, 60)}: ${r.status}`);
        assert.ok(ms < 1500, `${JSON.parse(body).method} waited ${ms} ms behind a waiter that did not fit`);
      }
      assert.equal(bDone, false, "the waiter was answered before room came: re-aim this test");
      await sleep(1000);
      stub.release();
      assert.equal((await ra).status, 200);
      const r = await rb;
      assert.equal(r.status, 200, `the waiter was refused once room came: ${r.text?.slice(0, 200)}`);
      assert.equal(resultOf(r)?.structuredContent?.state, "measured");
      await assertAlive(srv, "after the waiter");
    } finally {
      stub.release();
      await srv.stop();
    }
  });

  it("3. a waiter is not starved: once it has waited its time, a large one that fits beside the holder but not beside it waits, and reaches the API after it", async () => {
    const srv = await startServer(stub.base);
    stub.hold();
    try {
      const batches = stub.state.batches;
      const ra = post(srv.port, heldOf(24, "a"));
      for (const t = Date.now(); stub.state.batches === batches && Date.now() - t < 10_000; ) await sleep(20);
      const rb = post(srv.port, heldOf(24, "b"));
      await sleep(B.BUDGET_STARVE_MS + 500);
      const c = heldOf(12, "c");
      assert.ok(B.scanJson(Buffer.from(heldOf(24, "a"))).estimate + B.scanJson(Buffer.from(c)).estimate < IMAGE.INFLIGHT_BUDGET_BYTES, "c does not fit beside the holder: it tests nothing");
      const rc = post(srv.port, c);
      // Small ones still pass meanwhile.
      const t0 = Date.now();
      assert.equal((await post(srv.port, SMALL_CALLS[0])).status, 200);
      assert.ok(Date.now() - t0 < 1500, `${Date.now() - t0} ms`);
      await sleep(500);
      assert.equal(stub.state.batches, batches + 1, `a large one passed the waiter that had waited its time: ${JSON.stringify(stub.state.purls.slice(-3))}`);
      stub.release();
      const [a, b, cc] = await Promise.all([ra, rb, rc]);
      assert.deepEqual([a.status, b.status, cc.status], [200, 200, 200]);
      const order = stub.state.purls.slice(-3);
      assert.deepEqual(order, ["pkg:npm/aa@1.0.0", "pkg:npm/ab@1.0.0", "pkg:npm/ac@1.0.0"], "the waiter was passed");
      await assertAlive(srv, "after the waiter");
    } finally {
      stub.release();
      await srv.stop();
    }
  });

  it("4. a document that finds no room in the wait is answered busy, by check_sbom and scan_manifest, and its access line says so (doc_busy, its wait in queued_ms); with room, the same call is answered", async () => {
    const WAIT = 1500;
    // A short deadline, so a call that is not refused (its reservation gone) fails here at once, not after 60 s.
    const srv = await startServer(stub.base, { MCP_ADMISSION_WAIT_MS: String(WAIT), MCP_REQUEST_TIMEOUT_MS: "8000" });
    stub.hold();
    try {
      const batches = stub.state.batches;
      const holder = post(srv.port, heldOf(22, "h"));
      for (const t = Date.now(); stub.state.batches === batches && Date.now() - t < 10_000; ) await sleep(20);
      const holderEst = B.scanJson(Buffer.from(heldOf(22, "h"))).estimate;
      // check_sbom: an sbom passed as text whose document does not fit beside the holder; scan_manifest: a lockfile
      // whose reading does not.
      const doc = JSON.stringify({ bomFormat: "CycloneDX", components: [{ name: "a", version: "1", purl: "pkg:npm/a@1" }, ...Array(340_000).fill({})] });
      const lock = JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/a": { version: "1.0.0" }, "node_modules/b": { version: "1.0.0", x: Array(300_000).fill({}) } } });
      const calls = [
        ["check_sbom", { sbom: doc }, B.documentCost(doc).bytes],
        ["scan_manifest", { files: [{ filename: "package-lock.json", content: lock }] }, SM.manifestEstimate({ files: [{ filename: "package-lock.json", content: lock }] }, IMG)],
      ];
      for (const [tool, args, bytes] of calls) {
        const body = toolCall(tool, args);
        const own = B.scanJson(Buffer.from(body)).estimate;
        assert.ok(bytes <= IMAGE.PARSE_BUDGET_BYTES && own + bytes <= MOST && holderEst + own + bytes > IMAGE.INFLIGHT_BUDGET_BYTES, `${tool}: ${own} + ${bytes}`);
        const from = srv.lines.length;
        const t0 = Date.now();
        const r = await post(srv.port, body);
        const res = resultOf(r);
        assert.equal(res?.structuredContent?.state, "failed", `${tool}: ${r.text?.slice(0, 300)}`);
        assert.deepEqual([res.structuredContent.error.kind, res.structuredContent.error.status], ["internal", 503]);
        assert.match(res.structuredContent.error.message, /^server busy: this instance's memory for reading documents is taken by other calls; retry in a few seconds$/);
        assert.ok(Date.now() - t0 < WAIT + 3000, `${tool}: waited past its bound`);
        await sleep(100);
        const line = srv.access(from).find((l) => l.tool === tool);
        assert.ok(line && line.status === 200 && line.refused === "doc_busy" && line.queued_ms >= WAIT - 100, `${tool}: ${JSON.stringify(line)}`);
      }
      assert.equal(stub.state.batches, batches + 1, "a refused call reached the API");
      stub.release();
      assert.equal((await holder).status, 200);
      // With room: answered.
      for (const [tool, args] of calls) {
        const r = await post(srv.port, toolCall(tool, args));
        const st = resultOf(r)?.structuredContent?.state;
        assert.ok(st === "measured" || st === "not_assessed" || st === "invalid_input", `${tool} with room: ${r.text?.slice(0, 300)}`);
        assert.notEqual(st, "failed", tool);
      }
      await assertAlive(srv, "after the busy answers");
    } finally {
      stub.release();
      await srv.stop();
    }
  });

  it("5. a document its request could never hold beside its own body is refused at once, invalid_input naming the bound, on an idle instance: never busy, never a wait", async () => {
    const srv = await startServer(stub.base);
    try {
      // An sbom passed as text with one character past U+00FF (its body's string is two bytes a character), its
      // document within what one document's parse may take, the two together past what a request may hold.
      const doc = JSON.stringify({ bomFormat: "CycloneDX", metadata: { component: { name: "app – 1", description: "p".repeat(3_700_000) } }, components: [{ name: "a", version: "1", purl: "pkg:npm/a@1" }, ...Array(380_000).fill({})] });
      const body = toolCall("check_sbom", { sbom: doc });
      const own = B.scanJson(Buffer.from(body)).estimate;
      const bytes = B.documentCost(doc).bytes;
      assert.ok(body.length <= P.DEFAULT_MAX_SBOM_BODY_BYTES && own <= IMAGE.PARSE_BUDGET_BYTES && bytes <= IMAGE.PARSE_BUDGET_BYTES && own + bytes > IMAGE.INFLIGHT_BUDGET_BYTES, `body ${own}, document ${bytes}`);
      // A lockfile likewise: within every per-file bound, too much with its body.
      const lock = npmLock(7000, " – see LICENSE");
      const largs = { files: [{ filename: "package-lock.json", content: lock }] };
      const lbody = toolCall("scan_manifest", largs);
      const lown = B.scanJson(Buffer.from(lbody)).estimate;
      const lbytes = SM.manifestEstimate(largs, IMG);
      // #3381's round 6: past what one request may hold (MOST), which the endpoint refuses at; with the entry weight
      // measured (parseBudget.ts WEIGHT_MANIFEST_ENTRY) it is no longer past the whole budget.
      assert.ok(lock.length <= SM.MAX_MANIFEST_CHARS && lown + lbytes > MOST, `lockfile ${lock.length} chars, body ${lown}, reading ${lbytes}`);
      for (const [tool, b, bytesOf, what, instead] of [
        ["check_sbom", body, bytes, "the sbom", "pass its purls instead, in calls of 2,000 or fewer"],
        // #3381's round-5 review (C1): one file cannot be passed as fewer; the hosted bound in files.
        ["scan_manifest", lbody, lbytes, "the file", "pass the lockfile's purls to check_sbom, in calls of 2,000 or fewer"],
      ]) {
        for (let attempt = 1; attempt <= 2; attempt++) {
          const from = srv.lines.length;
          const t0 = Date.now();
          const r = await post(srv.port, b);
          const ms = Date.now() - t0;
          const res = resultOf(r);
          assert.equal(res?.structuredContent?.state, "invalid_input", `${tool}: ${r.text?.slice(0, 400)}`);
          const text = res.content[0].text;
          assert.ok(text.includes(`reading ${what} would take an estimated ${Math.ceil(bytesOf)} bytes of this server's memory beside the `), text);
          const plain = tool === "scan_manifest" ? ` (${SM.HOSTED_READS})` : "";
          assert.ok(text.includes(`more than the ${MOST} bytes (30 MiB) one request may hold at once on the hosted endpoint, its body and what reading it holds together${plain}, so it is not read, and retrying the same call will not change that: ${instead}; or run this server locally (npx -y echelongraph-mcp), whose bounds are a share of its own machine's memory, not this endpoint's`), text);
          assert.ok(ms < 3000, `${tool}: answered after ${ms} ms: it waited`);
          await sleep(100);
          const line = srv.access(from).find((l) => l.tool === tool);
          assert.ok(line && line.refused === "doc_too_large" && line.queued_ms < 1000, `${tool}: ${JSON.stringify(line)}`);
        }
      }
      await assertAlive(srv, "after the refusals");
    } finally {
      await srv.stop();
    }
  });

  it("6. two calls 1 s apart, each with a near-cap sbom passed as text, both answered while the API holds the first: its document's hold went back once it was read", async () => {
    const srv = await startServer(stub.base);
    stub.hold();
    try {
      let n = 1500;
      while (syftText(n, 690).length < 4_800_000) n += 100;
      const docs = [syftText(n, 690), syftText(n - 100, 800)];
      const each = docs.map((d) => B.scanJson(Buffer.from(toolCall("check_sbom", { sbom: d }))).estimate + B.documentCost(d).bytes);
      assert.ok(docs.every((d) => d.length <= 5_000_000) && each[0] + each[1] > IMAGE.INFLIGHT_BUDGET_BYTES, `each ${each}: together they fit, it tests nothing`);
      const batches = stub.state.batches;
      const r1 = post(srv.port, toolCall("check_sbom", { sbom: docs[0] }));
      for (const t = Date.now(); stub.state.batches === batches && Date.now() - t < 20_000; ) await sleep(20);
      await sleep(1000);
      const r2 = post(srv.port, toolCall("check_sbom", { sbom: docs[1] }));
      for (const t = Date.now(); stub.state.batches < batches + 2 && Date.now() - t < 20_000; ) await sleep(20);
      assert.ok(stub.state.batches >= batches + 2, "the second did not reach the API while the first was held there");
      stub.release();
      for (const r of await Promise.all([r1, r2])) assert.equal(resultOf(r)?.structuredContent?.state, "measured", r.text?.slice(0, 300));
      // And a lockfile pair: 5,000 packages over 1,500 names, each call reserving what together the budget cannot hold
      // (its body, its parse and its entries), and the first holding only its body and entries once it has been read.
      const lock = nestedLock(5000, 1500);
      const largs = { files: [{ filename: "package-lock.json", content: lock }] };
      const per = B.scanJson(Buffer.from(toolCall("scan_manifest", largs))).estimate + SM.manifestEstimate(largs, IMG);
      assert.ok(2 * per > IMAGE.INFLIGHT_BUDGET_BYTES, `each lockfile call ${per}: together they fit, it tests nothing`);
      stub.hold();
      const b2 = stub.state.batches;
      const l1 = post(srv.port, toolCall("scan_manifest", { files: [{ filename: "package-lock.json", content: lock }] }));
      for (const t = Date.now(); stub.state.batches === b2 && Date.now() - t < 20_000; ) await sleep(20);
      await sleep(1000);
      const l2 = post(srv.port, toolCall("scan_manifest", { files: [{ filename: "package-lock.json", content: lock }] }));
      for (const t = Date.now(); stub.state.batches < b2 + 2 && Date.now() - t < 20_000; ) await sleep(20);
      assert.ok(stub.state.batches >= b2 + 2, "the second lockfile did not reach the API while the first was held there");
      stub.release();
      for (const r of await Promise.all([l1, l2])) assert.equal(resultOf(r)?.structuredContent?.state, "measured", r.text?.slice(0, 300));
      await assertAlive(srv, "after the pairs");
    } finally {
      stub.release();
      await srv.stop();
    }
  });
});
