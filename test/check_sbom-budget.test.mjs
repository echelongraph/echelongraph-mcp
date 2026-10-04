// #2756: check_sbom's 50 s budget bounds the whole call, not only when a batch may start.
//
// Through 2.6.2 the budget was checked only before each batch, so a batch started at 49.9 s ran
// for the request timeout (15 s) and the call ended at about 65 s: past the SDK's 60 s default and
// the hosted endpoint's 60 s Cloud Run timeout, where the client gets nothing at all. Nothing made
// a batch slow, so disabling the check left check_sbom.test.mjs green. Now each batch's request
// may take only what is left of the budget (api()'s init.timeoutMs), and a batch cut off by it is
// answered as not sent, reason time_budget.
//
// Two kinds of stub, both slow:
//   - on a clock the test owns (the tool's own `now` and `sleep` seams), batches that take 12 s
//     each, the ticket's case, at the real 50 s budget, without waiting 50 s;
//   - on the wall clock, the real api() (dist/index.js, loaded as the hosted entrypoint loads it,
//     so no stdio server starts here) against a loopback API that answers a batch late, so the
//     abort is a real fetch's, not a fake's.
// Each has a control: what the case would be without the guard it holds.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { PKG_DIR } from "./server-under-test.mjs";
import { ROWS, batchAnswer } from "./fixtures/match-batch.mjs";

const dist = (f) => pathToFileURL(path.join(PKG_DIR, "dist", f)).href;
const S = await import(dist("tools/check_sbom.js"));
const { checkSbom, TIME_BUDGET_MS, MAX_COMPONENTS, BATCH_PATH } = S;

const purls = (n) => Array.from({ length: n }, (_, i) => `pkg:npm/budget-${String(i).padStart(4, "0")}@1.0.0`);
const answerFor = (body) => batchAnswer(JSON.parse(body).components.map((c, i) => ROWS.notAffected(i, c.purl, "budget", "1.0.0")));

// Minimal stand-ins for index.ts's envelope helpers: what is under test is checkSbom's loop.
const kit = {
  failed: (tool, f) => ({ isError: true, content: [{ type: "text", text: `${tool} FAILED: ${f.kind}` }], structuredContent: { state: "failed", error: f } }),
  describeFailure: (f) => `${f.kind}${f.status ? ` ${f.status}` : ""} for POST ${f.path}.`,
  badInput: (tool, why) => ({ isError: true, content: [{ type: "text", text: why }], structuredContent: { state: "invalid_input" } }),
  crashed: (tool, e) => ({ isError: true, content: [{ type: "text", text: String(e) }], structuredContent: { state: "failed" } }),
  checked: (_tool, _schema, r) => r,
  succeeded: (data, note, env) => ({ content: [{ type: "text", text: JSON.stringify(data) }, { type: "text", text: note }], structuredContent: { ...env, data } }),
  okHead: (tool, status) => `${tool} OK: HTTP ${status}.`,
  envelopeSchema: () => null,
  annotations: {},
};

// The API on a clock the test owns: every batch takes batchMs of it, and a request whose
// timeoutMs (capped at the client's own request timeout, as api() caps it) is shorter is answered
// as a timeout at that limit, as api() answers one.
function slowAPI({ batchMs, requestTimeoutMs = 15_000 }) {
  const clock = { t: 0 };
  const requests = [];
  const api = async (p, init) => {
    const limit = init?.timeoutMs === undefined ? requestTimeoutMs : Math.max(0, Math.min(requestTimeoutMs, init.timeoutMs));
    const took = typeof batchMs === "function" ? batchMs(requests.length) : batchMs;
    requests.push({ at: clock.t, limit, components: JSON.parse(init.body).components.length });
    if (took > limit) {
      clock.t += limit;
      return { ok: false, kind: "timeout", path: p, method: "POST", detail: `no response within ${limit} ms` };
    }
    clock.t += took;
    return { ok: true, status: 200, data: answerFor(init.body) };
  };
  return { clock, requests, deps: { ...kit, api, now: () => clock.t, sleep: async (ms) => void (clock.t += ms) } };
}

describe("#2756: on a test-owned clock, at the real 50 s budget", () => {
  it("batches of 12 s each: the fifth is cut off at 50 s, and the call answers partial, time_budget, within the budget", async () => {
    const s = slowAPI({ batchMs: 12_000 });
    const list = purls(7 * MAX_COMPONENTS);
    const res = await checkSbom(s.deps, { purls: list });
    assert.notEqual(res.isError, true, res.content[0].text);
    // Four answered (0, 12, 24, 36 s); the fifth started at 48 s with 2 s of budget left.
    assert.deepEqual(s.requests.map((r) => r.at), [0, 12_000, 24_000, 36_000, 48_000]);
    assert.equal(s.requests[4].limit, TIME_BUDGET_MS - 48_000, "the fifth batch was not limited to what was left of the budget");
    assert.ok(s.clock.t <= TIME_BUDGET_MS, `the call took ${s.clock.t} ms, past its ${TIME_BUDGET_MS} ms budget`);
    const c = res.structuredContent.coverage;
    assert.deepEqual(
      [c.batches, c.batches_sent, c.sent, c.not_sent, c.not_sent_reason, c.partial],
      [7, 4, 4 * MAX_COMPONENTS, 3 * MAX_COMPONENTS, "time_budget", true],
    );
    assert.deepEqual(res.structuredContent.data.not_sent_purls, list.slice(4 * MAX_COMPONENTS));
    assert.equal(res.structuredContent.data.summary.components, 4 * MAX_COMPONENTS);
    assert.match(
      res.content[1].text,
      /600 purls were NOT sent \(not_sent_reason time_budget: the call's 50 s budget ran out while batch 5 of 7 was unanswered, so it was cut off\), so they are not checked and not clean;/,
    );
  });

  it("batches of 12.5 s each: the budget is spent when the fourth answers, so no fifth request is made", async () => {
    const s = slowAPI({ batchMs: 12_500 });
    const res = await checkSbom(s.deps, { purls: purls(7 * MAX_COMPONENTS) });
    assert.equal(s.requests.length, 4, `a request was sent with no budget left: ${JSON.stringify(s.requests)}`);
    assert.equal(s.clock.t, TIME_BUDGET_MS);
    const c = res.structuredContent.coverage;
    assert.deepEqual([c.batches_sent, c.not_sent_reason], [4, "time_budget"]);
    assert.match(res.content[1].text, /not_sent_reason time_budget: the call's 50 s budget ran out after 4 of 7 batches\)/);
  });

  it("a first batch slower than the budget, under a request timeout longer than it, is a failure at 50 s, not at the request timeout", async () => {
    // ECHELONGRAPH_API_TIMEOUT_MS can be set above 50 s; the budget still bounds the call.
    const s = slowAPI({ batchMs: 70_000, requestTimeoutMs: 120_000 });
    const res = await checkSbom(s.deps, { purls: purls(2 * MAX_COMPONENTS) });
    assert.equal(res.isError, true);
    assert.equal(res.structuredContent.error.kind, "timeout");
    assert.deepEqual(s.requests.map((r) => r.limit), [TIME_BUDGET_MS]);
    assert.equal(s.clock.t, TIME_BUDGET_MS);
  });

  it("a 429 whose wait ends at the budget's end, before anything answered: that 429 is the answer, and no request is sent with no time left", async () => {
    const clock = { t: 0 };
    const requests = [];
    const deps = {
      ...kit,
      now: () => clock.t,
      sleep: async (ms) => void (clock.t += ms),
      api: async (p, init) => {
        requests.push({ at: clock.t, limit: init.timeoutMs });
        return { ok: false, kind: "http", path: p, method: "POST", status: 429, retryAfter: 50, detail: "component budget exceeded" };
      },
    };
    const res = await checkSbom(deps, { purls: purls(2 * MAX_COMPONENTS) });
    assert.equal(res.isError, true);
    assert.equal(res.structuredContent.error.status, 429);
    assert.deepEqual(requests, [{ at: 0, limit: TIME_BUDGET_MS }], "a request was sent with no budget left");
    assert.equal(clock.t, TIME_BUDGET_MS);
  });

  it("a request timeout inside the budget is still request_failed, not time_budget", async () => {
    // Batch 2 outlasts the 15 s request timeout at 16 s, with 34 s of budget left.
    const s = slowAPI({ batchMs: (n) => (n === 1 ? 20_000 : 1_000) });
    const res = await checkSbom(s.deps, { purls: purls(3 * MAX_COMPONENTS) });
    assert.deepEqual(s.requests.map((r) => r.limit), [15_000, 15_000]);
    const c = res.structuredContent.coverage;
    assert.deepEqual([c.batches_sent, c.not_sent, c.not_sent_reason], [1, 2 * MAX_COMPONENTS, "request_failed"]);
  });

  it("control: without the per-batch limit, the same 12 s stub runs the call past the budget", async () => {
    // The pre-#2756 behaviour: api() called without timeoutMs, so every batch gets the request timeout.
    const s = slowAPI({ batchMs: 12_000 });
    const api = s.deps.api;
    const res = await checkSbom({ ...s.deps, api: (p, { timeoutMs: _dropped, ...init }) => api(p, init) }, { purls: purls(7 * MAX_COMPONENTS) });
    assert.ok(s.clock.t > TIME_BUDGET_MS, `control: ${s.clock.t} ms`);
    assert.equal(res.structuredContent.coverage.batches_sent, 5);
    assert.throws(() => assert.ok(s.clock.t <= TIME_BUDGET_MS), "the elapsed-time assertion above catches it");
  });
});

// ── On the wall clock: the real api() aborting a real request ──
//
// The loopback API answers each batch after plan[n].delayMs, and plan[n].onAnswer runs before it
// answers (the case below moves the tool's clock on there). A request the client aborts is
// recorded as aborted.
const plan = {};
const seen = [];
const server = http.createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    const n = seen.length;
    const entry = { url: req.url, method: req.method, aborted: false };
    seen.push(entry);
    res.on("close", () => {
      if (!res.writableEnded) entry.aborted = true;
    });
    const p = plan[n] ?? {};
    setTimeout(() => {
      if (res.destroyed) return;
      p.onAnswer?.();
      res.writeHead(200, { "content-type": "application/json" });
      res.end(req.url === BATCH_PATH ? JSON.stringify(answerFor(body)) : "{}");
    }, p.delayMs ?? 0);
  });
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
// Read by dist/index.js when it loads: the request timeout is 2 s here.
process.env.ECHELONGRAPH_API_BASE = `http://127.0.0.1:${server.address().port}`;
process.env.ECHELONGRAPH_API_TIMEOUT_MS = "2000";
// As http.ts does before it loads index.ts, so that loading it starts no stdio server in this
// process (whose stdout is the test runner's).
(await import(dist("runtime.js"))).markHttpEntrypoint();
const I = await import(dist("index.js"));

describe("#2756: on the wall clock, the real api() against a loopback API", () => {
  before(() => {
    seen.length = 0;
  });
  after(async () => {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
  });
  const reset = (p) => {
    for (const k of Object.keys(plan)) delete plan[k];
    Object.assign(plan, p);
    seen.length = 0;
  };

  it("init.timeoutMs below the request timeout aborts the request at it, and the failure names it", async () => {
    reset({ 0: { delayMs: 1_500 } });
    const t0 = performance.now();
    const r = await I.api(BATCH_PATH, { method: "POST", body: JSON.stringify({ components: [] }), timeoutMs: 300 });
    const took = performance.now() - t0;
    assert.equal(r.ok, false);
    assert.equal(r.kind, "timeout");
    assert.ok(took < 1_200, `answered after ${Math.round(took)} ms: the 300 ms limit was not applied`);
    assert.match(I.describeFailure(r), /did not answer POST \/api\/v1\/public\/cves\/match\/batch within 300 ms\.$/);
  });

  it("init.timeoutMs never lengthens the request timeout", async () => {
    reset({ 0: { delayMs: 3_500 } });
    const t0 = performance.now();
    const r = await I.api(BATCH_PATH, { method: "POST", body: JSON.stringify({ components: [] }), timeoutMs: 60_000 });
    const took = performance.now() - t0;
    assert.equal(r.kind, "timeout");
    assert.ok(took < 3_000, `answered after ${Math.round(took)} ms: the 2 s request timeout was lengthened`);
    assert.match(I.describeFailure(r), /within 2000 ms\.$/);
  });

  it("check_sbom: a batch still unanswered when the budget runs out is aborted then, and the call answers partial, time_budget", async () => {
    // The tool's clock runs with the wall clock, but jumps 49 s when the first batch is answered:
    // a first batch that took 49 s. The second answers 1.8 s later on the wall clock, inside the
    // 2 s request timeout, but past the 1 s of budget left.
    let skew = 0;
    const now = () => Date.now() + skew;
    reset({ 0: { onAnswer: () => (skew = 49_000) }, 1: { delayMs: 1_800 } });
    const deps = { api: I.api, failed: I.failed, describeFailure: I.describeFailure, badInput: I.badInput, crashed: I.crashed, checked: I.checked, succeeded: I.succeeded, okHead: I.okHead, envelopeSchema: I.envelopeSchema, annotations: {}, now };
    const started = now();
    const t0 = performance.now();
    const res = await checkSbom(deps, { purls: purls(3 * MAX_COMPONENTS) });
    const took = performance.now() - t0;
    const elapsed = now() - started;
    assert.notEqual(res.isError, true, res.content[0].text);
    assert.equal(seen.length, 2);
    assert.ok(took < 1_700, `the second batch was not aborted at the budget: ${Math.round(took)} ms on the wall clock`);
    assert.ok(elapsed <= TIME_BUDGET_MS + 250, `the call took ${elapsed} ms on its own clock, past its ${TIME_BUDGET_MS} ms budget`);
    // The loopback API saw the second request go away unanswered.
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(seen[1].aborted, true);
    const c = res.structuredContent.coverage;
    assert.deepEqual([c.batches, c.batches_sent, c.sent, c.not_sent, c.not_sent_reason], [3, 1, MAX_COMPONENTS, 2 * MAX_COMPONENTS, "time_budget"]);
    assert.match(res.content[1].text, /the call's 50 s budget ran out while batch 2 of 3 was unanswered, so it was cut off/);
  });
});
