// #2835: a scan_manifest call whose client goes stops, as check_sbom's does (#2775,
// check_sbom-cancel.test.mjs, whose loopback set-up this mirrors). Both tools send their purls
// through match_batch.ts's loop; what is scan_manifest's own is its registration in index.ts: the
// handler's ctx.mcpReq.signal handed to the loop, and the call held as its request's work
// (runtime.ts holdRequest), so that the hosted request's place and large-body slot are freed only
// once the call has stopped. Driven through the SDK's handler with index.ts's createServer, as
// http.ts relay() drives it, against the real api() and a loopback API that answers late.
import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { createMcpHandler } from "@modelcontextprotocol/server";
import { PKG_DIR } from "./server-under-test.mjs";
import { ROWS, batchAnswer } from "./fixtures/match-batch.mjs";

const dist = (f) => pathToFileURL(path.join(PKG_DIR, "dist", f)).href;

// Three batches' worth of pinned requirements: 600 distinct purls.
const FILES = [{ filename: "requirements.txt", content: Array.from({ length: 600 }, (_, i) => `cancel-${i}==1.0.0`).join("\n") }];
const answerFor = (body) => batchAnswer(JSON.parse(body).components.map((c, i) => ROWS.notAffected(i, c.purl, "cancel", "1.0.0")));

const plan = {};
const seen = [];
const server = http.createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    const entry = { aborted: false };
    const p = plan[seen.length] ?? {};
    seen.push(entry);
    res.on("close", () => {
      if (!res.writableEnded) entry.aborted = true;
    });
    setTimeout(() => {
      if (res.destroyed) return;
      res.writeHead(p.status ?? 200, { "content-type": "application/json", ...(p.headers ?? {}) });
      res.end(p.status ? JSON.stringify({ error: "component budget exceeded" }) : JSON.stringify(answerFor(body)));
    }, p.delayMs ?? 0);
  });
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
process.env.ECHELONGRAPH_API_BASE = `http://127.0.0.1:${server.address().port}`;
process.env.ECHELONGRAPH_API_TIMEOUT_MS = "5000";
const R = await import(dist("runtime.js"));
R.markHttpEntrypoint();
const I = await import(dist("index.js"));

const reset = (p) => {
  for (const k of Object.keys(plan)) delete plan[k];
  Object.assign(plan, p);
  seen.length = 0;
};
const until = async (cond) => {
  while (!cond()) await new Promise((r) => setTimeout(r, 5));
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// One hosted tools/call of scan_manifest, through the SDK's handler; `gone` is its client leaving.
function hostedCall() {
  const handler = createMcpHandler(I.createServer, { legacy: "stateless" });
  const work = new Set();
  const gone = new AbortController();
  const request = new Request("http://localhost/mcp", {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", "mcp-protocol-version": "2025-06-18" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "scan_manifest", arguments: { files: FILES } } }),
    signal: gone.signal,
  });
  const response = R.withClient(undefined, () => handler.fetch(request), { signal: gone.signal, work });
  return { handler, work, gone, response };
}

describe("#2835: a hosted scan_manifest call whose client goes stops, and frees its request", () => {
  after(async () => {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
  });

  it("the call is held as its request's work until it has stopped; the batch at the API is cut off and no other is sent", async () => {
    reset({ 0: { delayMs: 1_500 } });
    const { handler, work, gone, response } = hostedCall();
    await until(() => seen.length === 1);
    assert.equal(work.size, 1, "the call is not held as its request's work");
    let settled = false;
    const waited = R.requestSettled(work).then(() => (settled = true));
    await sleep(100);
    assert.equal(settled, false, "requestSettled resolved while the call was still at the API");
    const t0 = performance.now();
    gone.abort();
    await waited;
    assert.ok(performance.now() - t0 < 1_000, `requestSettled waited ${Math.round(performance.now() - t0)} ms after the abort`);
    assert.equal(work.size, 0, "the call is still held after it stopped");
    await sleep(50);
    assert.equal(seen.length, 1, `${seen.length} batches were sent`);
    assert.equal(seen[0].aborted, true, "the batch at the API was not cut off");
    await (await response).body?.cancel().catch(() => {});
    await handler.close();
  });

  // The call's own signal (ctx.mcpReq.signal, which index.ts hands the loop) is what ends a
  // Retry-After wait: the request's signal cuts off API calls, not a timer.
  it("the client goes during a Retry-After wait: the wait ends at once, the call is freed, and no other batch is sent", async () => {
    reset({ 1: { status: 429, headers: { "retry-after": "20" } } });
    const { handler, work, gone, response } = hostedCall();
    await until(() => seen.length === 2);
    await sleep(100);
    const t0 = performance.now();
    gone.abort();
    await R.requestSettled(work);
    assert.ok(performance.now() - t0 < 1_500, `the 20 s wait was waited: ${Math.round(performance.now() - t0)} ms`);
    await sleep(200);
    assert.equal(seen.length, 2, `${seen.length} batches were sent`);
    await (await response).body?.cancel().catch(() => {});
    await handler.close();
  });

  it("control: the same hosted call, its client staying, sends all three batches", async () => {
    reset({});
    const { handler, response } = hostedCall();
    const res = await response;
    await res.text();
    assert.equal(seen.length, 3);
    await handler.close();
  });
});
