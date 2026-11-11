// The batch loop behind check_sbom and scan_manifest (#2835): a list of distinct purls sent to
// POST /api/v1/public/cves/match/batch, at most MAX_COMPONENTS per request, one request after
// another, within the call's TIME_BUDGET_MS, waiting out a 429's Retry-After while the wait fits,
// and stopping when the call is cancelled. Moved here from check_sbom.ts unchanged (#2734, #2756,
// #2775), so every tool that checks purls through the batch route uses one loop: the same batch
// size, budget, waits and cancellation, and the same sentences for what happened to the purls.
//
// What a tool keeps for itself: how it reads its input into purls, its own refusals, and how its
// note says what it read. Everything after "these are the distinct purls to check" is here.
import * as z from "zod";
import { CNA_PACKAGE_URL, blankUnreadableDisputes, disputedOf, disputesSentence, fixedInDisputeSchema, isDispute, unreadDisputesSentence, versionEvidenceSchema } from "../fixedInDispute.js";
import { WEIGHT_BATCH_ROW, answerCost, mostAnswerBytes, tooLargeToHold } from "../parseBudget.js";
import type { Reservation, ReserveFor, Room } from "../runtime.js";

// What index.ts hands a tool module, so it uses the server's one api(), envelope and failure
// contract instead of a copy (and index.ts stays the only place that defines them).
type Text = { type: "text"; text: string };
export type ToolResult = { content: Text[]; structuredContent: Record<string, unknown>; isError?: boolean };
// bytes: the answer's length (#3381's round-4 review), which the call's reservation counts (sendBatches).
export type ApiOk = { ok: true; status: number; data: object; bytes?: number };
// The part of index.ts's Failure this module reads: a 429's Retry-After (whole seconds), #2734.
export type FailureLike = { ok: false; kind: string; status?: number; retryAfter?: number };
// #3381's round-10 review (R10-M1): what api() answers for a 2xx answer past init.maxBytes: read no further (bytes, what
// had come, or its Content-Length), the request ended. Neither data nor a failure of the API's.
export type ApiCut = { ok: false; cut: true; path: string; status: number; bytes: number; maxBytes: number };
const isCut = (r: object): r is ApiCut => (r as { cut?: unknown }).cut === true;
export type MatchBatchDeps<F extends FailureLike> = {
  // init.timeoutMs: what is left of the call's budget, the most this request may take (#2756).
  // init.signal: the call's own (below); api() answers a failure at once when it has aborted.
  // init.maxBytes (R10-M1): the most of the answer read; past it api() answers ApiCut.
  api: (path: string, init?: { headers?: Record<string, string>; method?: string; body?: string; timeoutMs?: number; signal?: AbortSignal; maxBytes?: number }) => Promise<ApiOk | ApiCut | F>;
  failed: (tool: string, f: F) => ToolResult;
  // #3381: on the hosted endpoint, index.ts busy: the answer when this instance had no room; with `unread`, for the
  // API's answer to a call's first batch, not read past what it had room for (R10-M1).
  busy?: (tool: string, why: string, unread?: { path: string; status: number }) => ToolResult;
  // index.ts's one sentence for a failure: quoted when a batch after the first fails.
  describeFailure: (f: F) => string;
  // For a caller that must not wait in real time; production uses the clock and setTimeout. A
  // wait ends early when `signal` aborts.
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
  now?: () => number;
  // #2775: the call's cancellation, the handler's ctx.mcpReq.signal: the SDK aborts it when the
  // client sends notifications/cancelled, or when the hosted request's client has gone (its
  // transport closes). Each batch request carries it, a Retry-After wait ends on it, and once it
  // has aborted no further batch is sent: the SDK sends nothing for a cancelled call.
  signal?: AbortSignal;
};

export const BATCH_PATH = "/api/v1/public/cves/match/batch";
// The backend's cap per request (cveBatchMaxComponents): the batch size. A longer list is sent
// as consecutive batches of at most this many, one after another (#2734).
export const MAX_COMPONENTS = 200;
// The backend charges the batch route per component: 1,200 components a minute per caller
// (core-backend internal/waf/weighted.go, CVEMatchBatchComponentsPerWindow). Over it, it answers
// 429 with Retry-After and looks nothing up.
export const API_COMPONENTS_PER_MINUTE = 1200;
// The most distinct purls one call checks: two minutes of that budget. From a fresh budget, 2,000
// purls are 10 batches: six go at once, the API then asks for a wait of at most a minute, and the
// other four follow, and waiting out that minute would pass TIME_BUDGET_MS, so the call answers partial:
// the first 1,200 checked, the rest named for a second call. A list with
// more is refused before any request, never truncated: a dropped component would read as clean.
export const MAX_PURLS = 2000;
// How long one call may spend, waits for Retry-After included. When the next wait would pass it,
// the call stops and answers what it has, with the purls not sent counted in coverage.not_sent
// and listed in data.not_sent_purls, never dropped silently.
// 50 s, not more: MCP clients time a tools/call out (the TypeScript SDK's default request timeout is
// 60 s), and a call that outlives its client returns nothing at all — not even the partial answer
// below. From a fresh budget, 1,200 purls (6 batches) go at once; a larger list answers partial
// with the rest in data.not_sent_purls, for a call a minute later.
// The budget bounds the whole call, not only when a batch may start (#2756): each batch's request
// may take at most what is left of it (api()'s init.timeoutMs), so a batch started at 49.9 s is cut
// off at 50 s and its purls answered as not sent (time_budget), instead of running on for the
// request timeout (15 s) past the client's and the hosted endpoint's 60 s.
export const TIME_BUDGET_MS = 50_000;
// Retry-After 0 is waited this long; a 429 without Retry-After is not retried. At most MAX_WAITS
// waits per call.
const MIN_WAIT_MS = 1000;
const MAX_WAITS = 10;
// The backend's per-purl cap (cveBatchMaxPurlLen).
export const MAX_PURL_LEN = 512;

// #3767: since #3757 the matcher also decides, for a language registry's package, a CVE no advisory record holds for the
// package from the CVE record's CNA statement naming it by package URL (core-backend cve/pkgmatch_cnapurl.go), and such a
// statement alone never makes a component not_affected: a package only CNA records name is not_assessed
// (package_not_in_advisory_corpus) unless one calls the version affected. The method is in every batch answer's text and
// structured result, and the 201-purl probe's cut keeps its 43 rows only within a few characters of it
// (check_sbom-large-rows.test.mjs; measured 2026-11-11 beside CLEAN_NOTE's 210 characters: 3.2.2's 374 plus 8 kept 43,
// plus 12 kept 42), so the sentence says it in 384, about 3.2.2's length: "registry matcher" for "registry advisory
// matcher", "as GET .../match" for "the same matcher GET /api/v1/public/cves/match uses", and "No CPE match, score or
// ranking."; the detail is in docs/tools.md and the note's sentence on each match the CNA alone makes.
export const METHOD =
  "EchelonGraph's registry matcher (POST /api/v1/public/cves/match/batch, as GET .../match given an ecosystem): each purl is mapped to its OSV ecosystem, package and version, and matched against EchelonGraph's OSV.dev advisory ranges and, for a language package's CVE none names, its CNA's purl statement (match_method cna package url), never clean alone. No CPE match, score or ranking.";

// Always in the envelope's notes, whatever the answer: the refusals a model must not read as clean.
export const DISTRO_NOTE =
  "A deb, apk or rpm purl without a distro qualifier naming its release (for example ?distro=debian-12 or ?distro=alpine-3.20) is not assessed (distro_release_unknown): the advisory corpus is keyed per distro release, and EchelonGraph does not guess one.";
export const CLEAN_NOTE =
  "Only not_affected is a clean verdict, and only for the CVEs decided at that version: an undetermined or not_assessed component is not a finding of no vulnerability, and is reported as unchecked, never as clean.";
export const MEASURED_AT_NOTE =
  "measured_at is null: the corpus rows are read through a cache whose maximum age the answer states (summary.corpus_cache_max_age_ms), so the answer gives no single time at which they were read.";
export const FRESHNESS_NOTE = "freshness is null: the answer carries no time at which the advisory corpus was last refreshed.";

// How many affected components the note names, and how many CVE ids per component.
const NOTE_AFFECTED_MAX = 25;
const NOTE_CVES_MAX = 5;

export const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
export const field = (o: unknown, k: string): unknown => (isObj(o) ? o[k] : undefined);
export const count = (o: unknown, k: string): number | undefined => {
  const v = field(o, k);
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
};
export const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

// The distinct purls of a list, each at its first place.
export function dedupe(all: string[]): { purls: string[]; removed: number } {
  const seen = new Set<string>();
  const purls: string[] = [];
  for (const p of all) {
    if (seen.has(p)) continue;
    seen.add(p);
    purls.push(p);
  }
  return { purls, removed: all.length - purls.length };
}

// How the batches went: what the note and the coverage say about sending.
export type NotSentReason = "time_budget" | "rate_limited" | "request_failed" | "server_busy";
export type Sending = {
  batches: number;
  batches_sent: number;
  sent: number;
  not_sent_purls: string[];
  not_sent_reason: NotSentReason | null;
  not_sent_detail: string | null;
  waits: number;
  waited_ms: number;
  // Round 11 (the round-10 verify's d5 F7): how many fixed_in_dispute values the answers held that this server cannot
  // read, each relayed empty (fixedInDispute.ts blankUnreadableDisputes), by where. The note's, never coverage's.
  unread_disputes?: string[];
};

// Summary fields summed over the batches, and bounds that hold per batch (the largest held for all).
const SUMMED = ["components", "affected", "not_affected", "undetermined", "not_assessed", "lookups", "elapsed_ms"];
const MAXED = ["time_budget_ms", "corpus_cache_max_age_ms"];

// The batches' answers as one (#2734): results concatenated with index counted across batches
// (batch b's row i becomes index b*MAX_COMPONENTS+i, its position in the list sent), summaries
// summed, not_assessed_by_reason summed per reason, partial true when any batch's was, answered_at
// the last batch's. A count some batch did not send is left out, never summed as 0.
export function mergeAnswers(answers: object[]): Record<string, unknown> {
  const out: Record<string, unknown> = { ...(answers[0] as Record<string, unknown>) };
  const results: unknown[] = [];
  answers.forEach((a, b) => {
    const rows = field(a, "results");
    if (!Array.isArray(rows)) return;
    for (const r of rows) {
      const i = field(r, "index");
      results.push(isObj(r) && typeof i === "number" ? { ...r, index: i + b * MAX_COMPONENTS } : r);
    }
  });
  const total = (vs: unknown[]): number | undefined =>
    vs.every((v) => typeof v === "number" && Number.isFinite(v)) ? (vs as number[]).reduce((t, v) => t + v, 0) : undefined;

  const comps = total(answers.map((a) => field(a, "components")));
  if (comps === undefined) delete out.components;
  else out.components = comps;

  const ss = answers.map((a) => field(a, "summary"));
  if (ss.every(isObj)) {
    const sums = ss as Record<string, unknown>[];
    const m: Record<string, unknown> = { ...sums[0] };
    for (const k of SUMMED) {
      const t = total(sums.map((x) => x[k]));
      if (t === undefined) delete m[k];
      else m[k] = t;
    }
    for (const k of MAXED) {
      const vs = sums.map((x) => x[k]).filter((v): v is number => typeof v === "number");
      if (vs.length) m[k] = Math.max(...vs);
    }
    if (sums.some((x) => typeof x.partial === "boolean")) m.partial = sums.some((x) => x.partial === true);
    if (sums.some((x) => isObj(x.not_assessed_by_reason))) {
      const by: Record<string, number> = {};
      for (const x of sums) {
        if (!isObj(x.not_assessed_by_reason)) continue;
        for (const [r, n] of Object.entries(x.not_assessed_by_reason)) if (typeof n === "number") by[r] = (by[r] ?? 0) + n;
      }
      m.not_assessed_by_reason = by;
    }
    out.summary = m;
  } else {
    delete out.summary;
  }
  const last = answers[answers.length - 1];
  if (field(last, "answered_at") !== undefined) out.answered_at = field(last, "answered_at");
  out.results = results;
  return out;
}

export const realSleep = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((r) => {
    if (signal?.aborted) return r();
    const done = (): void => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", done);
      r();
    };
    const timer = setTimeout(done, ms);
    signal?.addEventListener("abort", done, { once: true });
  });

// The purls a call may send, or why it may not: none, more than MAX_PURLS (refused before any
// request, never truncated), or one longer than the backend takes. `split` says how the caller
// can make the list smaller.
export function purlsRefusal(purls: string[], split: string): string | null {
  if (purls.length > MAX_PURLS) {
    return `${purls.length} distinct purls; at most ${MAX_PURLS} are checked per call (in batches of ${MAX_COMPONENTS}, within the API's budget of ${API_COMPONENTS_PER_MINUTE} components a minute), and none is dropped silently: ${split}`;
  }
  const long = purls.findIndex((p) => p.length > MAX_PURL_LEN);
  if (long >= 0) return `purl ${long + 1} is longer than ${MAX_PURL_LEN} characters`;
  return null;
}

// #3381's round-4 review: before a call sends its first batch, the hosted endpoint reserves in its parse budget what the
// API's answers for its purls will hold (parseBudget.ts WEIGHT_BATCH_ROW): one that finds no room in the wait is
// answered busy, one its request could never hold beside what it holds is refused, at once, as a document is. Answers
// the reservation's charge (sendBatches), or the call's answer. On stdio nothing is reserved.
export const ANSWER_BUSY_WHY = "server busy: no room in this instance's parse budget (what its requests in flight hold, other calls' API answers among them) came for this call's answers within the wait; retry in a few seconds";
export async function reserveAnswers(
  deps: { reserve?: (bytes: number, opts?: ReserveFor) => Promise<Reservation>; busy?: (tool: string, why: string) => ToolResult; badInput: (tool: string, why: string) => ToolResult },
  tool: string,
  purls: number,
): Promise<AnswersHeld | { result: ToolResult }> {
  if (!deps.reserve || !deps.busy) return {};
  const bytes = purls * WEIGHT_BATCH_ROW;
  const r = await deps.reserve(bytes, { answers: true });
  if (r.state === "busy") return { result: deps.busy(tool, ANSWER_BUSY_WHY) };
  if (r.state === "too_large") return { result: deps.badInput(tool, tooLargeToHold(`the API's answers for its ${plural(purls, "purl", "purls")}`, bytes, r.heldBytes, r.maxBytes, "pass fewer purls per call")) };
  return { charge: r.charge, room: r.room };
}
/** The call's reservation for its answers (reserveAnswers): its charge(), and its room() where it has a budget. */
export type AnswersHeld = { charge?: (bytes: number) => boolean; room?: () => Room };

// What sendBatches answers: the API's answer (one batch: its JSON as it came; more: merged) and
// how the sending went, or the failure that is the call's answer (nothing was measured).
export type BatchRun = { ok: true; data: Record<string, unknown>; status: number; sending: Sending } | { ok: false; result: ToolResult };

// The loop (#2734, #2756, #2775): one batch at a time, in order; a 429 with Retry-After is waited
// out and the same batch sent again, while the wait fits in the call's budget. #3381's round-4 review: `held.charge`, the
// call's reservation's (reserveAnswers): what the answers so far hold past what was reserved for the purls they answer
// is added to it, and once the budget says it is past its overdraft no further batch is sent (not_sent_reason
// server_busy). #3381's round-10 review: nor once the call's request holds more than the most one request may reserve
// (R10-B1: charge() answers no then too); and, with `held.room`, each batch's answer is read only to what the call's
// reservation still covers of it and what the budget has left before its overdraft, at WEIGHT_ANSWER_BYTE a byte
// (R10-M1): an answer past that is not read (api()'s maxBytes), and that batch's purls and the rest are not sent
// (server_busy), or, on the first batch, the call is answered "server busy". Through round 10 a batch's answer was read
// and parsed whole, whatever its size: one of 26 MB ended the hosted process.
export async function sendBatches<F extends FailureLike>(deps: MatchBatchDeps<F>, tool: string, purls: string[], held: AnswersHeld = {}): Promise<BatchRun> {
  const { charge, room } = held;
  const sleep = deps.sleep ?? realSleep;
  const now = deps.now ?? Date.now;
  const batches: string[][] = [];
  for (let i = 0; i < purls.length; i += MAX_COMPONENTS) batches.push(purls.slice(i, i + MAX_COMPONENTS));
  const started = now();
  const budgetS = TIME_BUDGET_MS / 1000;
  const answers: object[] = [];
  let status = 200;
  let waits = 0;
  let waitedMs = 0;
  let stop: { reason: NotSentReason; detail: string } | null = null;
  // The 429 last waited out, for the one way the budget can be gone before anything answered.
  let waitedFor: F | undefined;
  // #3381's round-4 review: what the answers so far come to past what was reserved for them, added to the reservation.
  let charged = 0;
  let answered = 0;
  while (answers.length < batches.length) {
    const left = TIME_BUDGET_MS - (now() - started);
    if (left <= 0 && answers.length === 0 && waitedFor) {
      // A wait that ended at the budget's end: no time is left to send the first batch again, and
      // nothing was measured, so that 429 is the answer, not a request given no time at all.
      return { ok: false, result: deps.failed(tool, waitedFor) };
    }
    if (answers.length > 0 && left <= 0) {
      stop = { reason: "time_budget", detail: `the call's ${budgetS} s budget ran out after ${answers.length} of ${batches.length} batches` };
      break;
    }
    // R10-M1: the most of this batch's answer read: what its cost (parseBudget.ts answerCost) may come to within what the
    // reservation still covers of it (WEIGHT_BATCH_ROW for each purl through this batch, and what was charged, less what
    // the answers so far came to) and what the budget has left before its overdraft. Only where the call has a budget,
    // and a busy answer.
    const batch = batches[answers.length];
    const now_ = room && deps.busy ? room() : undefined;
    const covered = Math.min(purls.length, (answers.length + 1) * MAX_COMPONENTS) * WEIGHT_BATCH_ROW + charged - answered;
    const maxBytes = now_ === undefined ? undefined : mostAnswerBytes(covered + Math.max(0, now_.budget), batch.length);
    // At most what is left of the budget (#2756): a slow batch is cut off at its end.
    const r = await deps.api(BATCH_PATH, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ components: batch.map((purl) => ({ purl })) }),
      timeoutMs: Math.max(0, left),
      signal: deps.signal,
      ...(maxBytes === undefined ? {} : { maxBytes }),
    });
    if (isCut(r)) {
      const what = `the API's answer to batch ${answers.length + 1} of ${batches.length} came to more than the ${r.maxBytes} bytes this instance's memory had room for, so it was not read`;
      if (answers.length === 0 && deps.busy) return { ok: false, result: deps.busy(tool, `server busy: ${what}; retry in a few seconds, or pass fewer purls per call`, { path: r.path, status: r.status }) };
      stop = { reason: "server_busy", detail: `${what}, and no further batch was sent` };
      break;
    }
    if (r.ok) {
      answers.push(r.data);
      status = r.status;
      // #3381's round-10 verification: a row's matches charged as they cost (parseBudget.ts answerCost).
      answered += typeof r.bytes === "number" ? answerCost(r.bytes, batch.length) : 0;
      const past = Math.max(0, answered - (answers.length * MAX_COMPONENTS > purls.length ? purls.length : answers.length * MAX_COMPONENTS) * WEIGHT_BATCH_ROW - charged);
      charged += past;
      if (charge && !charge(past) && answers.length < batches.length) {
        // #3381's round-5 review (C2): the stop is the instance's, whatever this call's own answers held; R10-B1: or the
        // call's own request's, past the most one request may reserve.
        const after = room?.();
        stop =
          after !== undefined && after.request < 0
            ? { reason: "server_busy", detail: `after ${answers.length} of ${batches.length} batches the API's answers took this call's request past the ${after.requestMax} bytes one request may reserve, so no further batch was sent` }
            : { reason: "server_busy", detail: `after ${answers.length} of ${batches.length} batches this instance's parse budget was more than a quarter past its bound, so no further batch was sent` };
        break;
      }
      continue;
    }
    // Cancelled (#2775): this batch was cut off, or never sent after a wait the signal ended.
    // Nothing more is sent, and the answer goes nowhere.
    if (deps.signal?.aborted) return { ok: false, result: deps.failed(tool, r) };
    if (r.kind === "http" && r.status === 429) {
      if (r.retryAfter === undefined) {
        stop = { reason: "rate_limited", detail: "the API answered 429 without a Retry-After to wait for" };
      } else if (waits >= MAX_WAITS) {
        stop = { reason: "rate_limited", detail: `the API answered 429 again after ${MAX_WAITS} waits` };
      } else {
        const waitMs = Math.max(MIN_WAIT_MS, r.retryAfter * 1000);
        if (now() - started + waitMs <= TIME_BUDGET_MS) {
          await sleep(waitMs, deps.signal);
          waits++;
          waitedMs += waitMs;
          waitedFor = r;
          continue;
        }
        stop = { reason: "time_budget", detail: `the API answered 429 asking for a wait of ${r.retryAfter} s (Retry-After), which would pass the call's ${budgetS} s budget` };
      }
    } else if (r.kind === "timeout" && now() - started >= TIME_BUDGET_MS) {
      // Cut off by the budget, not by the API failing: the purls are not sent for want of time.
      stop = { reason: "time_budget", detail: `the call's ${budgetS} s budget ran out while batch ${answers.length + 1} of ${batches.length} was unanswered, so it was cut off` };
    } else {
      stop = { reason: "request_failed", detail: deps.describeFailure(r).replace(/\.$/, "") };
    }
    // Nothing answered yet: nothing was measured, so the failure is the answer.
    if (answers.length === 0) return { ok: false, result: deps.failed(tool, r) };
    break;
  }

  const notSentPurls = purls.slice(answers.length * MAX_COMPONENTS);
  const sending: Sending = {
    batches: batches.length,
    batches_sent: answers.length,
    sent: purls.length - notSentPurls.length,
    not_sent_purls: notSentPurls,
    not_sent_reason: notSentPurls.length ? (stop?.reason ?? null) : null,
    not_sent_detail: notSentPurls.length ? (stop?.detail ?? null) : null,
    waits,
    waited_ms: waitedMs,
  };
  // One batch: data is the API's JSON as it came. More: the merged answer.
  const data: Record<string, unknown> = batches.length === 1 ? (answers[0] as Record<string, unknown>) : mergeAnswers(answers);
  if (notSentPurls.length) data.not_sent_purls = notSentPurls;
  sending.unread_disputes = blankUnreadableDisputes(data);
  return { ok: true, data, status, sending };
}

// ── The note's sentences on sending and on the verdicts ──

// How the batches went: their count, the Retry-After waits, and the purls not sent. #2799: the
// position, not only the list. Past DATA_TEXT_BUDGET the first text block keeps the first 10 of
// data.not_sent_purls, so a model that reads the text alone cannot send "that list"; the purls not
// sent are always the input's distinct purls from position sent + 1 on
// (purls.slice(answers.length * MAX_COMPONENTS)), which it can rebuild from its own input, given
// the order they are counted in (`readOrder`), which the sentence says whenever it gives the
// position, not only when the text cuts the list. #3013: the structured result's cut empties
// data.not_sent_purls before any row leaves (it is rebuilt from the position). #3132's review:
// round 1 then gave it back the first entries the room the rows left held (3 of the rate-limited
// case's 800), a list a client would retry as though it were the whole; the cut now keeps it whole
// or not at all (check_sbom.ts sbomData), and the sentence gives the positions as coverage holds
// them. `retry` is the tool and argument to send them to ("check_sbom again with purls set to").
// #3132's second review: those positions index the purls this tool read, which a check_sbom
// client rebuilds from its own purl list (or SBOM), but a scan_manifest client cannot without
// reading the files as this tool does; with `positions` false (scan_manifest), the sentence sends
// it to the same call with full: true, which always returns the list, instead.
export function sendingSentences(g: Sending, distinct: number, readOrder: string, retry: string, positions = true): string[] {
  const out: string[] = [];
  if (g.batches > 1) {
    out.push(
      `The ${distinct} distinct purls make ${g.batches} batches of at most ${MAX_COMPONENTS}, sent one after another; the API answered ${g.batches_sent} of them, and data.summary sums those answers.`,
    );
  }
  if (g.waits > 0) {
    out.push(
      `The API's component budget (${API_COMPONENTS_PER_MINUTE} components a minute) ran out ${g.waits === 1 ? "once" : `${g.waits} times`}: the tool waited ${Math.round(g.waited_ms / 1000)} s in all, as its Retry-After asked, and sent the batch again.`,
    );
  }
  const notSent = g.not_sent_purls.length;
  if (notSent > 0) {
    const one = notSent === 1;
    const where = one ? `it is the input's distinct purl at position ${g.sent + 1}` : `they are the input's distinct purls from position ${g.sent + 1} on`;
    out.push(
      `${plural(notSent, "purl was", "purls were")} NOT sent (not_sent_reason ${g.not_sent_reason}: ${g.not_sent_detail}), so ${one ? "it is" : "they are"} not checked and not clean; ${where}, ${readOrder}, and data.not_sent_purls lists ${one ? "it" : "them"} (past the structured result's budget it is left out whole by default, never cut short${positions ? `, and ${one ? "that position is" : "those positions are"} coverage.sent + 1 to coverage.distinct_purls; with full: true it is always there` : ": the same call with full: true always returns it"}): call ${retry} ${one ? "it" : "them"}${g.not_sent_reason === "request_failed" ? "" : " after a minute"}.`,
    );
  }
  return out;
}

// One affected component as the note names it: its purl, and its first NOTE_CVES_MAX cve_ids.
const affectedNamed = (r: unknown): string => {
  const who = (typeof field(r, "purl") === "string" && (field(r, "purl") as string)) || `${field(r, "ecosystem") ?? ""} ${field(r, "package") ?? ""} ${field(r, "version") ?? ""}`.trim();
  const ids = field(r, "cve_ids");
  const list = Array.isArray(ids) ? ids.filter((i): i is string => typeof i === "string") : [];
  const shown = list.slice(0, NOTE_CVES_MAX).join(", ");
  return `${who} (${shown}${list.length > NOTE_CVES_MAX ? `, and ${list.length - NOTE_CVES_MAX} more` : ""})`;
};
const affectedTail = (more: number): string => (more > 0 ? `; and ${more} more affected components in data.results (whole with full: true)` : "");
// The note's sentence naming the affected components, the first NOTE_AFFECTED_MAX of `hits`.
function affectedSaid(hits: readonly unknown[]): string {
  return `Affected: ${hits.slice(0, NOTE_AFFECTED_MAX).map(affectedNamed).join("; ")}${affectedTail(hits.length - NOTE_AFFECTED_MAX)}.`;
}
// #3269's third review: the characters, as a JSON string, of each row's name in that sentence,
// measured once per row object (the structured cut asks of the same rows many times).
const namedChars = new WeakMap<object, number>();
const namedCharsOf = (r: unknown): number => {
  if (!isObj(r)) return JSON.stringify(affectedNamed(r)).length - 2;
  let c = namedChars.get(r);
  if (c === undefined) namedChars.set(r, (c = JSON.stringify(affectedNamed(r)).length - 2));
  return c;
};
const isAffected = (r: unknown) => field(r, "verdict") === "affected";
// The sentence's characters in the answer being cut, once per answer's rows.
const saidChars = new WeakMap<readonly unknown[], number>();
/**
 * #3269's third review: for a call of `m` of `rows` alone, the most characters (as JSON) the note's
 * Affected sentence can take there, less what it takes in the answer of `all` (the call being cut;
 * negative where a call of m of them names fewer or shorter components). A call of other purls
 * names other components there, so a call that re-checks the rows a cut left out can carry a longer
 * note than this one; it names at most NOTE_AFFECTED_MAX of its affected rows, so at most that many,
 * or m, of these rows' longest names, and the tail counting the rest.
 */
export function affectedSaidOver(rows: readonly unknown[], all: readonly unknown[]): (m: number) => number {
  const longest = rows.filter(isAffected).map(namedCharsOf).sort((a, b) => b - a);
  const top: number[] = [0];
  for (const c of longest.slice(0, NOTE_AFFECTED_MAX)) top.push(top[top.length - 1] + c);
  let now = saidChars.get(all);
  if (now === undefined) {
    const own = all.filter(isAffected);
    saidChars.set(all, (now = own.length ? JSON.stringify(affectedSaid(own)).length - 2 : 0));
  }
  const was = now;
  return (m) => {
    const hits = Math.min(m, longest.length);
    if (hits === 0) return -was;
    const named = Math.min(hits, NOTE_AFFECTED_MAX);
    return "Affected: ".length + top[named] + 2 * (named - 1) + affectedTail(hits - NOTE_AFFECTED_MAX).length + 1 - was;
  };
}

// The verdict counts, the not-assessed reasons, the affected components by name, and the
// upstream-matched rows, from the (merged) answer.
export function verdictSentences(d: object, g: Sending): { sentences: string[]; assessed: number } {
  const s = field(d, "summary");
  const affected = count(s, "affected") ?? 0;
  const notAffected = count(s, "not_affected") ?? 0;
  const undetermined = count(s, "undetermined") ?? 0;
  const notAssessed = count(s, "not_assessed") ?? 0;
  const components = count(s, "components") ?? g.sent;
  const out: string[] = [];
  out.push(`Of the ${components} components checked: ${affected} affected, ${notAffected} not affected, ${undetermined} undetermined, ${notAssessed} not assessed.`);

  const by = field(s, "not_assessed_by_reason");
  if (isObj(by)) {
    const parts = Object.entries(by)
      .filter(([, n]) => typeof n === "number" && n > 0)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([r, n]) => `${r} ${n}`);
    if (parts.length) out.push(`Not assessed, by not_assessed_reason: ${parts.join(", ")}.`);
    const tb = count(by, "time_budget") ?? 0;
    if (tb > 0) {
      out.push(`The batch's time budget ran out before ${plural(tb, "component was", "components were")} looked up: ${tb === 1 ? "it is" : "they are"} not assessed, not clean; check ${tb === 1 ? "it" : "them"} again.`);
    }
  }

  const rows = field(d, "results");
  if (Array.isArray(rows)) {
    const hits = rows.filter((r) => field(r, "verdict") === "affected");
    if (hits.length) {
      out.push(affectedSaid(hits));
      // Said only when the answer carries fixed_in (an API before #2834 sends none).
      if (hits.some((r) => (Array.isArray(field(r, "matches")) ? (field(r, "matches") as unknown[]) : []).some((m) => isObj(m) && "fixed_in" in m))) {
        // #3381's review: on a disputed match (fixed_in_dispute) fixed_in follows the source its higher names. Round 6:
        // "the CVE's record", as fixed_in's own description says, where 3.1.5 said "the advisory"; "shown unaffected"
        // keeps the sentence no longer than 3.1.5's (the 201-purl probe's cut, check_sbom-large-rows.test.mjs, keeps
        // 43 rows only within that).
        const disputedHit = hits.some((r) => (Array.isArray(field(r, "matches")) ? (field(r, "matches") as unknown[]) : []).some((m) => isObj(m) && isDispute(m.fixed_in_dispute)));
        out.push(
          disputedHit
            ? "Each match's fixed_in is the first version above the component's that no affected interval of the CVE's record holds, except on a match with fixed_in_dispute, where it follows the source the dispute's higher names; null, with fixed_in_reason, where no higher version is shown unaffected."
            : "Each match's fixed_in is the first version above the component's that no affected interval of the CVE's record holds; null, with fixed_in_reason, where no higher version is shown unaffected.",
        );
      }
    }
    // #3767: the matches only the CVE record's CNA makes (match_method "cna package url", #3757), counted with the
    // components holding them: their provenance is the CNA's alone, and the text's cut levels keep no match_method.
    let cnaOnly = 0;
    let cnaRows = 0;
    for (const r of hits) {
      const n = (Array.isArray(field(r, "matches")) ? (field(r, "matches") as unknown[]) : []).filter((m) => field(m, "match_method") === CNA_PACKAGE_URL).length;
      cnaOnly += n;
      if (n > 0) cnaRows++;
    }
    if (cnaOnly > 0) {
      out.push(
        `${plural(cnaOnly, "match", "matches")}, on ${plural(cnaRows, "component", "components")}, ${cnaOnly === 1 ? "is" : "are"} on the CVE record's CNA statement alone (match_method cna package url): no OSV advisory record names the package for ${cnaOnly === 1 ? "that CVE" : "those CVEs"}, so the CNA is the only source.`,
      );
    }
    // #3391: the matches whose range the CVE's own record (its CNA) and the advisory disagree on, each with its note.
    const disputed = rows.flatMap((r) => {
      const purl = field(r, "purl");
      return disputedOf(field(r, "matches"), typeof purl === "string" ? purl : undefined);
    });
    const said = disputesSentence(disputed).trim();
    if (said) out.push(said);
    const unread = unreadDisputesSentence(g.unread_disputes ?? []).trim();
    if (unread) out.push(unread);
    // #2836: rows matched by the source package their purl's upstream qualifier names.
    const upstream = rows.filter((r) => field(r, "matched_via") === "upstream").length;
    if (upstream > 0) {
      out.push(
        `${plural(upstream, "component was", "components were")} matched by the source package ${upstream === 1 ? "its" : "their"} purl's upstream qualifier names (matched_via upstream, matched_package), not by the purl's own (binary) name, which is how Debian and Alpine file advisories.`,
      );
    }
  }
  return { sentences: out, assessed: affected + notAffected + undetermined };
}

// The coverage fields every batch-route tool reports on its sending.
export function sendingCoverage(g: Sending, distinct: number, summary: unknown): Record<string, unknown> {
  const summaryPartial = typeof field(summary, "partial") === "boolean" ? (field(summary, "partial") as boolean) : null;
  return {
    distinct_purls: distinct,
    batch_size: MAX_COMPONENTS,
    batches: g.batches,
    batches_sent: g.batches_sent,
    sent: g.sent,
    not_sent: g.not_sent_purls.length,
    not_sent_reason: g.not_sent_reason,
    rate_limit_waits: g.waits,
    waited_ms: g.waited_ms,
    not_assessed: count(summary, "not_assessed") ?? null,
    partial: g.not_sent_purls.length > 0 ? true : summaryPartial,
  };
}

// ── Schemas ──

const opt = <T extends z.ZodType>(t: T) => t.nullable().optional();

// One row of the batch route's answer, as core-backend internal/cve/matchbatch.go writes it.
export const Row = z.looseObject({
  index: opt(z.number()),
  input_kind: opt(z.string()),
  purl: opt(z.string()),
  verdict: opt(z.string()).describe(
    "affected (count > 0); not_affected (assessed, no match, nothing undetermined: the only clean verdict); undetermined (advisories name the package, at least one of its CVEs could not be decided, none matched: not clean); not_assessed (no verdict: not clean).",
  ),
  ecosystem: opt(z.string()),
  package: opt(z.string()),
  version: opt(z.string()),
  assessed: opt(z.boolean()).describe("Whether the matcher produced a verdict for this component. false is never clean."),
  not_assessed_reason: opt(z.string()).describe(
    "Why assessed is false: package_not_in_advisory_corpus, no_decidable_advisory, advisory_lookup_failed, candidate_window_truncated, time_budget, distro_release_unknown, purl_type_unsupported, version_missing or invalid_component.",
  ),
  code: opt(z.string()),
  error: opt(z.string()),
  cve_ids: opt(z.array(z.string())),
  matched_package: opt(z.string()).describe(
    "The package name the advisories were looked up by (#2836): the purl's own name, or, for a deb or apk purl with an upstream qualifier, the source package it names, which is how Debian and Alpine file advisories.",
  ),
  matched_via: opt(z.string()).describe("Which name matched_package is: purl_name (the purl's name), upstream (the purl's upstream qualifier) or coordinates (the component's package)."),
  matched_version_from: opt(z.string()).describe("Upstream rows: upstream when the qualifier named a version (upstream=name@version) and it was used, purl when the purl's own version was."),
  purl_name: opt(z.string()).describe("Upstream rows: the purl's own (binary) package name, not looked up."),
  matches: opt(
    z.array(
      z.looseObject({
        cve_id: opt(z.string()),
        kev_listed: opt(z.boolean()).describe("Whether the CVE is in CISA's Known Exploited Vulnerabilities catalog, as EchelonGraph's record holds it."),
        epss_score: opt(z.number()).describe("The CVE's EPSS score (FIRST), as EchelonGraph's record holds it; null when it has none."),
        // #3381's round-4 review (F12): as check_affected's: where version_evidence is cna_affected_range, the range is
        // the CNA's, not the advisory's.
        match_reason: opt(z.string()).describe(
          "Why the match applies, with the affected interval the version falls inside: \"[A, B)\" names that interval's fixed bound B (another interval can still hold B; fixed_in is the version past them all), \"[A, B]\" the last affected version B. The interval is the advisory's, or, where version_evidence is cna_affected_range, the CVE record's CNA range. On an upstream row it ends by naming the source package and the purl name.",
        ),
        version_evidence: versionEvidenceSchema(),
        interval: opt(z.looseObject({ introduced: opt(z.string()), fixed: opt(z.string()), last_affected: opt(z.string()) })).describe(
          "The affected interval that holds this component's version (fixed is exclusive, last_affected inclusive): the advisory's, or, where version_evidence is cna_affected_range, the CVE record's CNA range. Absent when no interval holds it.",
        ),
        fixed_in: opt(z.string()).describe(
          "The lowest version above this component's that no affected interval of the CVE's record for the package holds, always above it: the fixed bound of the interval that holds the component's version, moved past any overlapping interval that still holds that bound (fixed_in_detail then names it). null when no such version is on record (an interval on the way records no fix: it ends at last_affected, or has no end) or no interval holds the version, with fixed_in_reason saying which. Where fixed_in_dispute is set, the CVE record's CNA and the advisory disagree on the range that holds the component's version, and fixed_in follows the source its higher names (its note says how).",
        ),
        fixed_in_reason: opt(z.string()).describe("Why fixed_in is null; absent when fixed_in is a version."),
        fixed_in_detail: opt(z.string()).describe(
          "Set when fixed_in is not the fixed bound of the interval that holds the component's version: the overlapping intervals of the same record it moved past, which still hold that bound.",
        ),
        // #3391: the CVE's own record and the advisory disagree on this range (fixedInDispute.ts).
        fixed_in_dispute: fixedInDisputeSchema(),
      }),
    ),
  ),
  count: opt(z.number()),
  advisories_considered: opt(z.number()),
  not_affected_count: opt(z.number()),
  undetermined_count: opt(z.number()),
  undetermined: opt(z.array(z.looseObject({ cve_id: opt(z.string()) }))),
  capped: opt(z.boolean()),
  candidates_capped: opt(z.boolean()),
  // #3132: set by this server's structured cut (check_sbom.ts SBOM_ROW_LEVELS), never by the API.
  matches_truncated: z
    .strictObject({
      total: z.number().int().min(0),
      returned: z.number().int().min(0),
      kev_listed_cve_ids: z.array(z.string()).optional(),
      ransomware_cve_ids: z.array(z.string()).optional(),
      fixed_in_versions: z.array(z.string()).optional(),
    })
    .optional()
    .describe(
      "Present only on a row whose matches the structured result's cut (DATA CUT) shortened or left out: total, the row's matches in the answer; returned, the ones data keeps (chosen used in ransomware first, then the other KEV-listed ones, then highest effective_score, and listed in the API's order); and, while they fit, of all its matches, the CVE IDs KEV-listed (kev_listed_cve_ids) or used in ransomware (ransomware_cve_ids), and the distinct fixed_in versions (fixed_in_versions). The same call with full: true returns every match.",
    ),
});

// The batch route's answer, as data carries it: its fields, merged over the batches.
export const batchDataShape = {
  match_layer: opt(z.string()),
  components: opt(z.number()),
  summary: z
    .looseObject({
      components: opt(z.number()),
      affected: opt(z.number()),
      not_affected: opt(z.number()).describe("Components with a decided, clean verdict."),
      undetermined: opt(z.number()).describe("Components whose CVEs could not all be decided, with an advisory naming the package, and none matched: not clean."),
      not_assessed: opt(z.number()).describe("Components with no verdict: not clean."),
      not_assessed_by_reason: opt(
        z.looseObject({
          package_not_in_advisory_corpus: z.number().optional(),
          no_decidable_advisory: z.number().optional(),
          advisory_lookup_failed: z.number().optional(),
          candidate_window_truncated: z.number().optional(),
          time_budget: z.number().optional().describe("Components the batch's time budget ran out before: not clean; check them again."),
          distro_release_unknown: z.number().optional().describe("deb, apk or rpm purls without a distro qualifier naming the release, which EchelonGraph does not guess."),
          purl_type_unsupported: z.number().optional(),
          version_missing: z.number().optional(),
          invalid_component: z.number().optional(),
        }),
      ).describe("The not_assessed components, counted by not_assessed_reason."),
      lookups: opt(z.number()),
      partial: opt(z.boolean()).describe("true when the time budget ran out before every component was looked up."),
      time_budget_ms: opt(z.number()),
      elapsed_ms: opt(z.number()),
      corpus_cache_max_age_ms: opt(z.number()),
    })
    .optional(),
  answered_at: opt(z.string()),
  results: z.array(Row).optional(),
  not_sent_purls: opt(z.array(z.string())).describe("The distinct purls not sent (coverage.not_sent_reason says why): not checked, and not clean. Present only when some were not sent."),
};

// #3381's round-10 review (d4-release R10-1): the success branch's not_sent_reason names server_busy; a failure carries
// coverage null, so the failure branch's (failureSendingCoverageShape) keeps 3.1.5's enum and description: a client
// holding 3.1.5's tool list validates every answer of this release, and the release's schema-compat gate finds nothing.
const NOT_SENT_REASON_3_1_3 =
  "Why not_sent is above 0: time_budget (the call's 50 s budget ran out, before a batch or while one was unanswered, which is then cut off; or waiting out the API's Retry-After would pass it), rate_limited (a 429 without Retry-After, or a 429 after 10 waits), request_failed (a batch after the first failed; the note quotes how). null when every purl was sent.";
// The coverage fields sendingCoverage fills, as the schema holds them.
export const sendingCoverageShape = {
  distinct_purls: z.number().int().describe("Distinct purls to check: sent plus not_sent."),
  batch_size: z.number().int().describe("The most purls one request carries (the API's cap per request)."),
  batches: z.number().int().describe("Requests the distinct purls make, at batch_size each."),
  batches_sent: z.number().int().describe("Of those, the ones the API answered."),
  sent: z.number().int().describe("Distinct purls sent and answered."),
  not_sent: z.number().int().describe("Distinct purls not sent, listed in data.not_sent_purls: not checked, and not clean."),
  not_sent_reason: z
    .enum(["time_budget", "rate_limited", "request_failed", "server_busy"])
    .nullable()
    .describe(
      "Why not_sent is above 0: time_budget (the call's 50 s budget ran out, before a batch or while one was unanswered, which is then cut off; or waiting out the API's Retry-After would pass it), rate_limited (a 429 without Retry-After, or a 429 after 10 waits), request_failed (a batch after the first failed; the note quotes how), server_busy (hosted endpoint: the API's answers took this instance's parse budget more than a quarter past its bound, or this call's request past the 30 MiB one request may reserve, or a batch's answer was larger than the room left, so it was not read; no further batch was sent). null when every purl was sent.",
    ),
  rate_limit_waits: z.number().int().describe("How many times the API answered 429 and the tool waited its Retry-After before sending the batch again."),
  waited_ms: z.number().int().describe("Milliseconds spent in those waits."),
  not_assessed: z.number().int().nullable().describe("Of those sent, the components with no verdict, as the answer counts them."),
  partial: z
    .boolean()
    .nullable()
    .describe("true when not every purl was sent (not_sent above 0) or any batch's summary.partial was true (its time budget ran out first); otherwise the answer's summary.partial."),
};
/** The failure branch's: as sendingCoverageShape, its not_sent_reason 3.1.5's (R10-1, above). */
export const failureSendingCoverageShape = {
  ...sendingCoverageShape,
  not_sent_reason: z.enum(["time_budget", "rate_limited", "request_failed"]).nullable().describe(NOT_SENT_REASON_3_1_3),
};
