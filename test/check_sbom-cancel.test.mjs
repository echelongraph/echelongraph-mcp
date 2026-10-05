// #2775: a check_sbom call whose signal aborts stops. The signal is the handler's
// ctx.mcpReq.signal: the SDK aborts it when the client sends notifications/cancelled (stdio), or
// when the hosted request's client has gone (http.ts closes its transport). Before, nothing read
// it: the batch at the API ran to its answer, a Retry-After wait was waited out, and every batch
// after was sent, spending the client's API budget for an answer nobody would read.
//
// What must hold, on a loopback API with the real api() (dist/index.js, loaded as the hosted
// entrypoint loads it, so no stdio server starts here) and the tool's own sleep (no `sleep` seam),
// so the aborts are a real fetch's and a real timer's:
//   - api(): init.signal cuts the request off when it aborts, and an aborted signal sends none;
//   - the batch at the API when the signal aborts is cut off, and no other batch is sent;
//   - a Retry-After wait ends when the signal aborts, and no other batch is sent;
//   - on the hosted entrypoint, the call is held as its request's work (runtime.ts holdRequest),
//     and requestSettled, which http.ts awaits before it frees the request's place and large-body
//     slot, resolves only once the call has stopped. Driven through the SDK's handler with
//     index.ts's createServer, as http.ts relay() drives it, so index.ts's wiring is what is held.
// Over stdio, end to end: test/http.test.mjs ("#2775").
import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { createMcpHandler } from "@modelcontextprotocol/server";
import { PKG_DIR } from "./server-under-test.mjs";
import { ROWS, batchAnswer } from "./fixtures/match-batch.mjs";

const dist = (f) => pathToFileURL(path.join(PKG_DIR, "dist", f)).href;
const { checkSbom, MAX_COMPONENTS, BATCH_PATH } = await import(dist("tools/check_sbom.js"));

const purls = (n) => Array.from({ length: n }, (_, i) => `pkg:npm/cancel-${String(i).padStart(4, "0")}@1.0.0`);
const answerFor = (body) => batchAnswer(JSON.parse(body).components.map((c, i) => ROWS.notAffected(i, c.purl, "cancel", "1.0.0")));

// The loopback API answers request n after plan[n].delayMs, with plan[n].status and
// plan[n].headers in place of the 200 when set. A request the client aborts is recorded as aborted.
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
// As http.ts does before it loads index.ts, so that loading it starts no stdio server in this
// process (whose stdout is the test runner's).
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
const deps = (signal) => ({
  api: I.api,
  failed: I.failed,
  describeFailure: I.describeFailure,
  badInput: I.badInput,
  crashed: I.crashed,
  checked: I.checked,
  succeeded: I.succeeded,
  okHead: I.okHead,
  envelopeSchema: I.envelopeSchema,
  annotations: {},
  signal,
});

describe("#2775: a cancelled check_sbom call stops", () => {
  after(async () => {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
  });

  it("api(): init.signal cuts the request off when it aborts, and an aborted signal sends none", async () => {
    reset({ 0: { delayMs: 1_500 } });
    const ac = new AbortController();
    const t0 = performance.now();
    const pending = I.api(BATCH_PATH, { method: "POST", body: JSON.stringify({ components: [] }), signal: ac.signal });
    await until(() => seen.length === 1);
    ac.abort();
    const r = await pending;
    assert.ok(performance.now() - t0 < 1_000, "the request ran on after its signal aborted");
    assert.deepEqual([r.ok, r.kind], [false, "network"]);
    assert.match(r.detail, /^cancelled/);
    await sleep(50);
    assert.equal(seen[0].aborted, true, "the API saw no abort");
    const again = await I.api(BATCH_PATH, { method: "POST", body: "{}", signal: ac.signal });
    assert.match(again.detail, /^cancelled/);
    assert.equal(seen.length, 1, "a request was sent on an aborted signal");
  });

  it("aborted while a batch is at the API: that batch is cut off and no other is sent", async () => {
    reset({ 1: { delayMs: 1_500 } });
    const ac = new AbortController();
    const t0 = performance.now();
    const call = checkSbom(deps(ac.signal), { purls: purls(5 * MAX_COMPONENTS) });
    await until(() => seen.length === 2);
    ac.abort();
    const res = await call;
    assert.ok(performance.now() - t0 < 1_000, `the call ran ${Math.round(performance.now() - t0)} ms`);
    assert.equal(res.isError, true);
    await sleep(300);
    assert.equal(seen.length, 2, `${seen.length} batches were sent`);
    assert.equal(seen[1].aborted, true, "the batch at the API was not cut off");
  });

  it("aborted during a Retry-After wait: the wait ends at once and no other batch is sent", async () => {
    reset({ 1: { status: 429, headers: { "retry-after": "20" } } });
    const ac = new AbortController();
    const t0 = performance.now();
    const call = checkSbom(deps(ac.signal), { purls: purls(3 * MAX_COMPONENTS) });
    await until(() => seen.length === 2);
    await sleep(100);
    ac.abort();
    const res = await call;
    assert.ok(performance.now() - t0 < 1_500, `the 20 s wait was waited: ${Math.round(performance.now() - t0)} ms`);
    assert.equal(res.isError, true);
    await sleep(200);
    assert.equal(seen.length, 2, `${seen.length} batches were sent`);
  });

  it("hosted: the call is held as its request's work until it has stopped, and requestSettled waits for that", async () => {
    reset({ 0: { delayMs: 1_500 } });
    const handler = createMcpHandler(I.createServer, { legacy: "stateless" });
    const work = new Set();
    const gone = new AbortController();
    const request = new Request("http://localhost/mcp", {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream", "mcp-protocol-version": "2025-06-18" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "check_sbom", arguments: { purls: purls(3 * MAX_COMPONENTS) } } }),
      signal: gone.signal,
    });
    const response = R.withClient(undefined, () => handler.fetch(request), { signal: gone.signal, work });
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

  it("control: the same call with no signal runs every batch", async () => {
    reset({});
    const res = await checkSbom(deps(undefined), { purls: purls(3 * MAX_COMPONENTS) });
    assert.notEqual(res.isError, true, res.content[0].text);
    assert.equal(seen.length, 3);
  });
});
