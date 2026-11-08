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
// recorded as aborted. #3381's round-10 review (R10-M1): plan[n].text is the batch's answer, sent with its
// Content-Length; plan[n].chunks, its answer in pieces, without one (chunked).
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
      res.writeHead(200, { "content-type": "application/json", ...(p.text === undefined ? {} : { "content-length": String(Buffer.byteLength(p.text)) }) });
      if (p.chunks) {
        for (const c of p.chunks) if (!res.destroyed) res.write(c);
        return res.end();
      }
      res.end(req.url === BATCH_PATH ? (p.text ?? JSON.stringify(answerFor(body))) : "{}");
    }, p.delayMs ?? 0);
  });
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
// The loopback API serves the describe below and #3381's round-10 one after it, whichever of them a name filter runs:
// it is never closed under them, and holds no process open (unref) once the file's tests are done.
server.unref();
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

// #3381's round-4 review (F1): on the hosted endpoint a call reserves what the API's answers to its purls will hold
// before its first batch (WEIGHT_BATCH_ROW a purl), adds what they hold past that as they come, and sends no further
// batch once the budget says it is past its overdraft (not_sent_reason server_busy). Through round 4 nothing reserved
// it. Here the reservation is a stand-in that records what it was asked and answers as told.
const B = await import(dist("parseBudget.js"));
describe("#3381's round-4 review: the answers to a call's purls are reserved before its first batch, and their excess charged as they come", () => {
  const reservation = ({ state = "held", within = () => true } = {}) => {
    const seen = { reserved: [], charged: [] };
    const reserve = async (bytes, opts) => {
      seen.reserved.push({ bytes, opts });
      if (state === "busy") return { state: "busy" };
      if (state === "too_large") return { state: "too_large", heldBytes: 30_000_000, maxBytes: 31_457_280 };
      return { state: "held", keep: () => {}, charge: (b) => (seen.charged.push(b), within(seen.charged.length)) };
    };
    return { seen, reserve, busy: (tool, why) => ({ isError: false, content: [{ type: "text", text: why }], structuredContent: { state: "failed", error: { message: why, status: 503 } } }) };
  };
  // The API: every row with `matches` real-sized matches, its answer's length in bytes, as api() sends it.
  const heavyApi = (matches) => async (_p, init) => {
    const rows = JSON.parse(init.body).components.map((c, i) => ({ ...ROWS.affected(i, c.purl, "budget", "1.0.0", ["CVE-1"]), matches: Array.from({ length: matches }, (_, j) => ({ cve_id: `CVE-2099-${j}`, description: "d".repeat(1200) })) }));
    const text = JSON.stringify(batchAnswer(rows));
    return { ok: true, status: 200, data: JSON.parse(text), bytes: text.length };
  };
  it("a purl list reserves WEIGHT_BATCH_ROW a purl first, as answers (not small past one batch); busy and too_large answer at once, nothing sent", async () => {
    let sent = 0;
    const api = async (p, init) => (sent++, { ok: true, status: 200, data: answerFor(init.body), bytes: 10 });
    const r = reservation();
    const res = await checkSbom({ ...kit, api, reserve: r.reserve, busy: r.busy }, { purls: purls(3 * MAX_COMPONENTS) });
    assert.notEqual(res.isError, true, res.content[0].text);
    assert.deepEqual(r.seen.reserved, [{ bytes: 3 * MAX_COMPONENTS * B.WEIGHT_BATCH_ROW, opts: { answers: true } }]);
    assert.equal(sent, 3);
    for (const [state, says] of [["busy", /^server busy: no room in this instance's parse budget \(what its requests in flight hold, other calls' API answers among them\) came for this call's answers within the wait; retry in a few seconds$/], ["too_large", /^reading the API's answers for its 600 purls would take an estimated 768000 bytes of this server's memory beside the 30000000 bytes its request already holds \(its body, and its JSON-RPC batch's other calls\), more than the 31457280 bytes \(30 MiB\) one request may hold at once on the hosted endpoint, its body and what reading it holds together, so it is not read, and retrying the same call will not change that: pass fewer purls per call; or run this server locally \(npx -y echelongraph-mcp\), whose bounds are a share of its own machine's memory, not this endpoint's$/]]) {
      sent = 0;
      const q = reservation({ state });
      const out = await checkSbom({ ...kit, api, reserve: q.reserve, busy: q.busy }, { purls: purls(3 * MAX_COMPONENTS) });
      assert.equal(sent, 0, `${state}: a batch was sent`);
      assert.match(out.content[0].text, says);
    }
  });
  it("answers holding more than was reserved are charged as they come; past the overdraft no further batch is sent, and the purls not sent say server_busy", async () => {
    let sent = 0;
    const api = heavyApi(3);
    const counting = async (p, init) => (sent++, api(p, init));
    // Control: within the overdraft every batch is sent, and each one's excess is charged.
    const ok = reservation();
    const all = await checkSbom({ ...kit, api: counting, reserve: ok.reserve, busy: ok.busy }, { purls: purls(4 * MAX_COMPONENTS) });
    assert.equal(sent, 4);
    assert.equal(ok.seen.charged.length, 4);
    assert.ok(ok.seen.charged.every((b) => b > 0), `the excess of rows of three matches was not charged: ${ok.seen.charged}`);
    assert.equal(all.structuredContent.coverage.not_sent, 0);
    // Past the overdraft after the second batch: the third and fourth are not sent.
    sent = 0;
    const over = reservation({ within: (n) => n < 2 });
    const part = await checkSbom({ ...kit, api: counting, reserve: over.reserve, busy: over.busy }, { purls: purls(4 * MAX_COMPONENTS) });
    assert.equal(sent, 2);
    const c = part.structuredContent.coverage;
    assert.deepEqual([c.batches_sent, c.sent, c.not_sent, c.not_sent_reason], [2, 2 * MAX_COMPONENTS, 2 * MAX_COMPONENTS, "server_busy"]);
    assert.match(part.content[1].text, /NOT sent \(not_sent_reason server_busy: after 2 of 4 batches this instance's parse budget was more than a quarter past its bound, so no further batch was sent\)/);
    // Rows the reservation covers are not charged at all.
    const light = reservation();
    await checkSbom({ ...kit, api: async (p, init) => ({ ok: true, status: 200, data: answerFor(init.body), bytes: init.body.length }), reserve: light.reserve, busy: light.busy }, { purls: purls(2 * MAX_COMPONENTS) });
    assert.deepEqual(light.seen.charged, [0, 0]);
  });
});

// #3381's round-10 review. R10-M1: on the hosted endpoint a batch's answer is read only to the room the call has (what
// its reservation still covers of it, and what the budget has left before its overdraft, at WEIGHT_ANSWER_BYTE a byte):
// past it the read stops, the answer is dropped, and that batch's purls and the rest are not sent (server_busy), or, on
// the first batch, the call is answered "server busy". Through round 10 it was read and parsed whole: one of 26 MB ended
// the hosted process. R10-B1: the call sends no further batch once its own request holds more than the most one request
// may reserve, and check_sbom's keep() never grows its document's hold past what was reserved for it.
describe("#3381's round-10 review: a batch's answer is read to the room left, and a request's hold to its bound", () => {
  const reset = (p) => {
    for (const k of Object.keys(plan)) delete plan[k];
    Object.assign(plan, p);
    seen.length = 0;
  };
  const heavy = (n) => JSON.stringify(batchAnswer(Array.from({ length: 200 }, (_, i) => ({ ...ROWS.affected(i, `pkg:npm/x${i}@1`, "x", "1", ["CVE-1"]), matches: Array.from({ length: n }, (_, j) => ({ cve_id: `CVE-2099-${j}`, description: "d".repeat(1000) })) }))));
  // The reservation: room() as told, charge() and keep() recorded.
  const held = (room, { within = () => true } = {}) => {
    const seen = { reserved: [], charged: [], kept: [] };
    return {
      seen,
      reserve: async (bytes, opts) => (seen.reserved.push({ bytes, opts }), { state: "held", keep: (b) => seen.kept.push(b), charge: (b) => (seen.charged.push(b), within(seen.charged.length)), room }),
    };
  };
  const deps = (r) => ({ api: I.api, failed: I.failed, describeFailure: I.describeFailure, badInput: I.badInput, crashed: I.crashed, busy: I.busy, checked: I.checked, succeeded: I.succeeded, okHead: I.okHead, envelopeSchema: I.envelopeSchema, annotations: {}, reserve: r.reserve });
  const ROOM = 1_000_000;
  const roomy = () => ({ budget: ROOM, request: ROOM, requestMax: 31_457_280 });

  it("api(): an answer past init.maxBytes, by its Content-Length or as it comes, is read no further and answered as cut; one within it is read as res.text() reads it", async () => {
    reset({ 0: { text: "x".repeat(100_000) }, 1: { chunks: Array.from({ length: 5 }, () => "y".repeat(40_000)) }, 2: { text: `\uFEFF${JSON.stringify({ a: "é" })}` } });
    const declared = await I.api(BATCH_PATH, { method: "POST", body: "{}", maxBytes: 50_000 });
    assert.deepEqual(declared, { ok: false, cut: true, path: BATCH_PATH, status: 200, bytes: 100_000, maxBytes: 50_000 });
    const streamed = await I.api(BATCH_PATH, { method: "POST", body: "{}", maxBytes: 100_000 });
    assert.equal(streamed.cut, true);
    // Stopped at the chunk that passed the bound, before the answer's end (200,000 bytes).
    assert.ok(streamed.bytes > 100_000 && streamed.bytes < 200_000, `read ${streamed.bytes} bytes of it`);
    const whole = await I.api(BATCH_PATH, { method: "POST", body: "{}", maxBytes: 50_000 });
    assert.deepEqual([whole.ok, whole.data], [true, { a: "é" }]);
  });

  it("R10-M1: check_sbom of two batches whose second answer is past the room: the first's purls checked, the second's not sent, server_busy", async () => {
    reset({ 1: { text: heavy(10) } });
    const r = held(roomy);
    const res = await checkSbom(deps(r), { purls: purls(2 * MAX_COMPONENTS) });
    assert.notEqual(res.isError, true, res.content[0].text);
    const c = res.structuredContent.coverage;
    assert.deepEqual([c.batches_sent, c.sent, c.not_sent, c.not_sent_reason], [1, MAX_COMPONENTS, MAX_COMPONENTS, "server_busy"]);
    // What the reservation still covered of the second batch, and the room, read at what its rows' matches would cost.
    const first = JSON.stringify(answerFor(JSON.stringify({ components: purls(MAX_COMPONENTS).map((purl) => ({ purl })) }))).length;
    const cap = B.mostAnswerBytes(2 * MAX_COMPONENTS * B.WEIGHT_BATCH_ROW + r.seen.charged[0] - B.answerCost(first, MAX_COMPONENTS) + ROOM, MAX_COMPONENTS);
    assert.match(res.structuredContent.notes.join(" "), new RegExp(`not_sent_reason server_busy: the API's answer to batch 2 of 2 came to more than the ${cap} bytes this instance's memory had room for, so it was not read, and no further batch was sent`));
    assert.equal(res.structuredContent.data.not_sent_purls[0], purls(2 * MAX_COMPONENTS)[MAX_COMPONENTS]);
  });

  it("R10-M1: check_sbom whose first batch's answer is past the room: failed, server busy, naming the request made and that its answer was not read", async () => {
    reset({ 0: { chunks: [heavy(10)] } });
    const res = await checkSbom(deps(held(roomy)), { purls: purls(MAX_COMPONENTS) });
    assert.equal(res.isError, true);
    const sc = res.structuredContent;
    assert.deepEqual([sc.state, sc.coverage, sc.error.kind, sc.error.path, sc.error.status], ["failed", null, "internal", BATCH_PATH, 200]);
    assert.match(sc.error.message, /^server busy: the API's answer to batch 1 of 1 came to more than the \d+ bytes this instance's memory had room for, so it was not read; retry in a few seconds, or pass fewer purls per call$/);
    assert.match(res.content[0].text, /The API's answer was not read, so this is not a finding/);
    assert.doesNotMatch(res.content[0].text, /Nothing was read or sent to the API/);
  });

  it("R10-M1's verification: a batch's answer costs WEIGHT_ANSWER_BYTE a byte for its rows' first ROW_ANSWER_BYTES, WEIGHT_MATCH_BYTE for its matches, and is read to what that leaves room for", () => {
    const rows = MAX_COMPONENTS;
    const light = rows * B.ROW_ANSWER_BYTES;
    assert.deepEqual([B.answerCost(light, rows), B.answerCost(light + 1000, rows)], [B.WEIGHT_ANSWER_BYTE * light, B.WEIGHT_ANSWER_BYTE * (light + 1000) + (B.WEIGHT_MATCH_BYTE - B.WEIGHT_ANSWER_BYTE) * 1000]);
    for (const room of [0, 1, 1000, B.WEIGHT_ANSWER_BYTE * light - 1, B.WEIGHT_ANSWER_BYTE * light, 5_000_000, 52_428_800]) {
      const most = B.mostAnswerBytes(room, rows);
      assert.ok(B.answerCost(most, rows) <= room, `${room}: ${most} costs ${B.answerCost(most, rows)}`);
      assert.ok(B.answerCost(most + 1, rows) > room, `${room}: ${most + 1} still fits`);
    }
    // A batch of rows not affected (about 410 B each) costs three bytes a byte, within what each purl reserves.
    const a = JSON.stringify(answerFor(JSON.stringify({ components: purls(rows).map((purl) => ({ purl })) }))).length;
    assert.ok(B.answerCost(a, rows) <= rows * B.WEIGHT_BATCH_ROW, `${a} bytes cost ${B.answerCost(a, rows)}`);
  });

  it("R10-M1: without a budget (stdio), or within the room, every answer is read as before", async () => {
    reset({ 1: { text: heavy(10) } });
    const res = await checkSbom({ ...deps(held(roomy)), reserve: undefined }, { purls: purls(2 * MAX_COMPONENTS) });
    assert.deepEqual([res.structuredContent.coverage.sent, res.structuredContent.coverage.not_sent], [2 * MAX_COMPONENTS, 0]);
    reset({ 1: { text: heavy(10) } });
    const wide = await checkSbom(deps(held(() => ({ budget: 50_000_000, request: 1, requestMax: 31_457_280 }))), { purls: purls(2 * MAX_COMPONENTS) });
    assert.deepEqual([wide.structuredContent.coverage.sent, wide.structuredContent.coverage.not_sent], [2 * MAX_COMPONENTS, 0]);
  });

  it("R10-B1: once charge() says no and the call's request is past what one request may reserve, no further batch is sent, and the detail says so", async () => {
    reset({});
    const r = held(() => ({ budget: ROOM, request: -1, requestMax: 31_457_280 }), { within: () => false });
    const res = await checkSbom(deps(r), { purls: purls(3 * MAX_COMPONENTS) });
    const c = res.structuredContent.coverage;
    assert.deepEqual([c.batches_sent, c.sent, c.not_sent_reason], [1, MAX_COMPONENTS, "server_busy"]);
    assert.match(res.structuredContent.notes.join(" "), /after 1 of 3 batches the API's answers took this call's request past the 31457280 bytes one request may reserve, so no further batch was sent/);
  });

  it("R10-B1: keep() never grows the document's hold past what was reserved, where its \"purl\" keys are written with an escape", async () => {
    reset({});
    const n = 2_000;
    const sbom = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[${Array.from({ length: n }, (_, i) => `{"\\u0070url":"pkg:npm/a-${String(i).padStart(4, "0")}@1.0.0"}`).join(",")}]}`;
    const reserved = B.documentCost(sbom).bytes;
    assert.ok(n * B.WEIGHT_MANIFEST_ENTRY > reserved, `the case's premise: its purls (${n * B.WEIGHT_MANIFEST_ENTRY}) are more than its reservation (${reserved})`);
    const r = held(roomy);
    const res = await checkSbom(deps(r), { sbom });
    assert.notEqual(res.isError, true, res.content[0].text);
    assert.equal(res.structuredContent.coverage.with_purl, n);
    assert.equal(r.seen.reserved[0].bytes, reserved);
    assert.deepEqual(r.seen.kept, [reserved]);
  });
});
