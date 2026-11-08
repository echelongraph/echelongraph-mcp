// #3381: the hosted endpoint, started as its image starts it, bounds what all its requests in flight hold parsed, not
// only what each holds (src/parseBudget.ts INFLIGHT_BUDGET_BYTES, http.ts).
//
// Each request's body, small or large, is counted before it is parsed and its estimate held in one budget for the
// process until the request ends; what a tool parses from a string is held there too while it does. Through 3.1.5
// nothing weighed what the admission's 64 places held: 64 tools/call each carrying a 64 KiB list of empty objects, held
// at the API, ended the process once 44 to 48 had reached it ("JavaScript heap out of memory"). Here, under
// Dockerfile.http's CMD flags (test/image-server.mjs):
//   - that burst is answered or refused 503 (refused "parse_busy"), the process alive, /health 200;
//   - what a request holds is given back on every way it can end: its client going while it waits for room, its client
//     going while it is served, its deadline (#3362's lesson: a hold never given back is a budget lost for good), each
//     seen by a request that needs nearly the whole budget being let in at once afterwards;
//   - a tool whose document finds no room is answered as busy, not left to wait without bound.
// Without the budget the burst ends the process. Skipped in the published-tarball run.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { PKG_DIR } from "./server-under-test.mjs";
import { IMAGE_SKIP, assertAlive, assertAnsweredOrRefused, imageBudgets, post, resultOf, sleep, startServer, stubApi, toolCall } from "./image-server.mjs";

const P = await import(pathToFileURL(path.join(PKG_DIR, "dist", "httpPolicy.js")).href);
const B = await import(pathToFileURL(path.join(PKG_DIR, "dist", "parseBudget.js")).href);
// The server under test is started with the image's flags, so its bounds are the image's, not this process's (#3381).
const IMAGE = IMAGE_SKIP ? B : imageBudgets();

// A tools/call of cve_summary of exactly 64 KiB, its arguments carrying a list of empty objects (the general cap: no
// large-body slot).
function smallDense() {
  const head = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cve_summary","arguments":{"junk":[';
  const tail = "]}}}";
  const room = P.DEFAULT_MAX_BODY_BYTES - head.length - tail.length;
  const n = Math.floor((room + 1) / 3);
  const list = Array(n).fill("{}").join(",");
  return head + list + " ".repeat(room - list.length) + tail;
}
// A check_sbom call that waits at the API holding its arguments, estimated at about `mb` MB.
function heldOf(mb, tag) {
  const n = Math.floor((mb * 1e6) / 67);
  return toolCall("check_sbom", { sbom: { bomFormat: "CycloneDX", specVersion: "1.5", components: [{ type: "library", name: `a${tag}`, version: "1.0.0", purl: `pkg:npm/a${tag}@1.0.0` }, ...Array(n).fill({})] } });
}

describe("#3381: what the requests in flight hold parsed is bounded together, and given back however each ends", { skip: IMAGE_SKIP, concurrency: false, timeout: 900_000 }, () => {
  let stub;
  before(async () => {
    stub = await stubApi();
  });
  after(async () => {
    stub?.release();
    await stub?.close();
  });

  it("64 tools/call of 64 KiB of empty objects, held at the API: each answered or refused 503, the process alive, /health 200", async () => {
    const srv = await startServer(stub.base);
    stub.hold();
    try {
      const body = smallDense();
      assert.equal(Buffer.byteLength(body), P.DEFAULT_MAX_BODY_BYTES);
      const est = B.scanJson(Buffer.from(body)).estimate;
      assert.ok(64 * est > IMAGE.INFLIGHT_BUDGET_BYTES, "the burst fits the budget: it tests nothing");
      const at = stub.state.open;
      const sent = Array.from({ length: 64 }, () => post(srv.port, body));
      // Those let in reach the API and wait there; the rest wait for room (ADMISSION_WAIT_MS) and are refused.
      const deadline = Date.now() + 30_000;
      while (stub.state.open - at < Math.floor(IMAGE.INFLIGHT_BUDGET_BYTES / est) && srv.alive() && Date.now() < deadline) await sleep(50);
      await sleep(1000);
      await assertAlive(srv, `${stub.state.open - at} held at the API`);
      const held = stub.state.open - at;
      assert.ok(held >= 1 && held <= Math.floor(IMAGE.INFLIGHT_BUDGET_BYTES / est), `${held} at the API, budget for ${Math.floor(IMAGE.INFLIGHT_BUDGET_BYTES / est)}`);
      // The rest are refused once their wait runs out; then the held ones are answered.
      await sleep(P.DEFAULT_ADMISSION_WAIT_MS + 1000);
      stub.release();
      const rs = await Promise.all(sent);
      for (const r of rs) assertAnsweredOrRefused(r, "a 64 KiB body of the burst");
      const by = rs.reduce((m, r) => ((m[r.status] = (m[r.status] ?? 0) + 1), m), {});
      assert.deepEqual(Object.keys(by).sort(), ["200", "503"], JSON.stringify(by));
      assert.equal(by[200], held);
      const refused = srv.access().filter((l) => l.status === 503);
      assert.ok(refused.length === by[503] && refused.every((l) => l.refused === "parse_busy" && l.rpc_method === "(unparseable)"), JSON.stringify(refused[0]));
      for (const r of rs.filter((x) => x.status === 503)) assert.equal(JSON.parse(r.text).error.code, P.BUSY_CODE);
      await assertAlive(srv, "after the burst");
    } finally {
      stub.release();
      await srv.stop();
    }
  });

  it("given back however a request ends: its client going while it waits, while it is served, and its deadline", async () => {
    // Short waits, so the test does not wait out production's.
    const srv = await startServer(stub.base, { MCP_ADMISSION_WAIT_MS: "2000", MCP_REQUEST_TIMEOUT_MS: "5000" });
    const big = (tag) => heldOf(26, tag);
    const bigEst = B.scanJson(Buffer.from(big("x"))).estimate;
    assert.ok(bigEst < IMAGE.PARSE_BUDGET_BYTES && 2 * bigEst > IMAGE.INFLIGHT_BUDGET_BYTES, `${bigEst}`);
    // Whether a request of nearly the whole budget is let in at once: it reaches the API within a second.
    const letIn = async (tag) => {
      const batches = stub.state.batches;
      const r = post(srv.port, big(tag));
      const deadline = Date.now() + 1500;
      while (stub.state.batches === batches && Date.now() < deadline) await sleep(20);
      return { reached: stub.state.batches > batches, r };
    };
    stub.hold();
    try {
      // 1. Clients that go while served: 20 small dense bodies held at the API, then their clients go.
      const ctls = Array.from({ length: 20 }, () => new AbortController());
      const at = stub.state.open;
      const smalls = ctls.map((c) => post(srv.port, smallDense(), { signal: c.signal }));
      const d1 = Date.now() + 20_000;
      while (stub.state.open - at < 20 && Date.now() < d1) await sleep(20);
      assert.equal(stub.state.open - at, 20, "20 small bodies did not reach the API");
      for (const c of ctls) c.abort();
      await Promise.all(smalls);
      await sleep(500);
      const one = await letIn("a");
      assert.ok(one.reached, "a request of nearly the whole budget waited: what the 20 gone clients held was not given back");

      // 2. A client that goes while it waits for room: one big body held, a second waits, its client goes.
      const ctl = new AbortController();
      const waiting = post(srv.port, big("b"), { signal: ctl.signal });
      await sleep(500);
      ctl.abort();
      await waiting;
      // 3. The deadline: the first big body is held at the API past MCP_REQUEST_TIMEOUT_MS and stopped there.
      const first = await one.r;
      assert.equal(first.status, "reset", "the held request was not ended by its deadline");
      await sleep(300);
      assert.ok(srv.access().some((l) => l.refused === "timeout"), "no timeout line");
      const two = await letIn("c");
      assert.ok(two.reached, "a request of nearly the whole budget waited: the deadline or the gone waiter kept what it held");
      stub.release();
      assert.equal((await two.r).status, 200);
      await assertAlive(srv, "after every way of ending");
    } finally {
      stub.release();
      await srv.stop();
    }
  });

  it("a document that finds no room within the wait is answered as busy (state failed, status 503), never left waiting", async () => {
    const srv = await startServer(stub.base, { MCP_ADMISSION_WAIT_MS: "1500" });
    stub.hold();
    try {
      const batches = stub.state.batches;
      const holder = post(srv.port, heldOf(22, "h"));
      const deadline = Date.now() + 10_000;
      while (stub.state.batches === batches && Date.now() < deadline) await sleep(20);
      // An sbom passed as text: its body is one string (small to hold), its document estimated at about 20 MB, which
      // does not fit beside the holder's 22 MB.
      const doc = JSON.stringify({ bomFormat: "CycloneDX", components: [{ name: "a", version: "1", purl: "pkg:npm/a@1" }, ...Array(340_000).fill({})] });
      const c = B.documentCost(doc);
      const holderEst = B.scanJson(Buffer.from(heldOf(22, "h"))).estimate;
      assert.ok(c.bytes < IMAGE.PARSE_BUDGET_BYTES && c.bytes + holderEst > IMAGE.INFLIGHT_BUDGET_BYTES, `${c.bytes}`);
      const t0 = Date.now();
      const r = await post(srv.port, toolCall("check_sbom", { sbom: doc }));
      assert.equal(r.status, 200, r.text?.slice(0, 300));
      const res = resultOf(r);
      assert.equal(res?.structuredContent?.state, "failed", r.text?.slice(0, 300));
      assert.deepEqual([res.structuredContent.error.kind, res.structuredContent.error.status], ["internal", 503]);
      assert.match(res.structuredContent.error.message, /^server busy: this instance's memory for reading documents is taken by other calls; retry in a few seconds$/);
      assert.ok(Date.now() - t0 < 10_000, "the call waited past its bound");
      stub.release();
      assert.equal((await holder).status, 200);
      await assertAlive(srv, "after the busy answer");
    } finally {
      stub.release();
      await srv.stop();
    }
  });
});
