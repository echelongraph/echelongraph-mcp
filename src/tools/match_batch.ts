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

// What index.ts hands a tool module, so it uses the server's one api(), envelope and failure
// contract instead of a copy (and index.ts stays the only place that defines them).
type Text = { type: "text"; text: string };
export type ToolResult = { content: Text[]; structuredContent: Record<string, unknown>; isError?: boolean };
export type ApiOk = { ok: true; status: number; data: object };
// The part of index.ts's Failure this module reads: a 429's Retry-After (whole seconds), #2734.
export type FailureLike = { ok: false; kind: string; status?: number; retryAfter?: number };
export type MatchBatchDeps<F extends FailureLike> = {
  // init.timeoutMs: what is left of the call's budget, the most this request may take (#2756).
  // init.signal: the call's own (below); api() answers a failure at once when it has aborted.
  api: (path: string, init?: { headers?: Record<string, string>; method?: string; body?: string; timeoutMs?: number; signal?: AbortSignal }) => Promise<ApiOk | F>;
  failed: (tool: string, f: F) => ToolResult;
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

export const METHOD =
  "EchelonGraph's registry advisory matcher (POST /api/v1/public/cves/match/batch): each component's purl is mapped to its OSV ecosystem, package name and version, and matched against the affected version ranges EchelonGraph holds from OSV.dev advisory records, the same matcher GET /api/v1/public/cves/match uses when given an ecosystem. No CPE matching, no score, no ranking.";

// Always in the envelope's notes, whatever the answer: the refusals a model must not read as clean.
export const DISTRO_NOTE =
  "A deb, apk or rpm purl without a distro qualifier naming its release (for example ?distro=debian-12 or ?distro=alpine-3.20) is not assessed (distro_release_unknown): the advisory corpus is keyed per distro release, and EchelonGraph does not guess one.";
export const CLEAN_NOTE =
  "Only not_affected is a clean verdict, and only for the advisories decided at that version: an undetermined or not_assessed component is not a finding of no vulnerability, and is reported as unchecked, never as clean.";
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
export type NotSentReason = "time_budget" | "rate_limited" | "request_failed";
export type Sending = {
  batches: number;
  batches_sent: number;
  sent: number;
  not_sent_purls: string[];
  not_sent_reason: NotSentReason | null;
  not_sent_detail: string | null;
  waits: number;
  waited_ms: number;
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

// What sendBatches answers: the API's answer (one batch: its JSON as it came; more: merged) and
// how the sending went, or the failure that is the call's answer (nothing was measured).
export type BatchRun = { ok: true; data: Record<string, unknown>; status: number; sending: Sending } | { ok: false; result: ToolResult };

// The loop (#2734, #2756, #2775): one batch at a time, in order; a 429 with Retry-After is waited
// out and the same batch sent again, while the wait fits in the call's budget.
export async function sendBatches<F extends FailureLike>(deps: MatchBatchDeps<F>, tool: string, purls: string[]): Promise<BatchRun> {
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
    // At most what is left of the budget (#2756): a slow batch is cut off at its end.
    const r = await deps.api(BATCH_PATH, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ components: batches[answers.length].map((purl) => ({ purl })) }),
      timeoutMs: Math.max(0, left),
      signal: deps.signal,
    });
    if (r.ok) {
      answers.push(r.data);
      status = r.status;
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
  return { ok: true, data, status, sending };
}

// ── The note's sentences on sending and on the verdicts ──

// How the batches went: their count, the Retry-After waits, and the purls not sent. #2799: the
// position, not only the list. Past DATA_TEXT_BUDGET the first text block keeps the first 10 of
// data.not_sent_purls, so a model that reads the text alone cannot send "that list"; the purls not
// sent are always the input's distinct purls from position sent + 1 on
// (purls.slice(answers.length * MAX_COMPONENTS)), which it can rebuild from its own input, given
// the order they are counted in (`readOrder`), which the sentence says whenever it gives the
// position, not only when the text cuts the list. `retry` is the tool and argument to send them
// to ("check_sbom again with purls set to").
export function sendingSentences(g: Sending, distinct: number, readOrder: string, retry: string): string[] {
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
      `${plural(notSent, "purl was", "purls were")} NOT sent (not_sent_reason ${g.not_sent_reason}: ${g.not_sent_detail}), so ${one ? "it is" : "they are"} not checked and not clean; ${where}, ${readOrder}, and data.not_sent_purls lists ${one ? "it" : "them"}: call ${retry} ${one ? "it" : "them"}${g.not_sent_reason === "request_failed" ? "" : " after a minute"}.`,
    );
  }
  return out;
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
      const named = hits.slice(0, NOTE_AFFECTED_MAX).map((r) => {
        const who = (typeof field(r, "purl") === "string" && (field(r, "purl") as string)) || `${field(r, "ecosystem") ?? ""} ${field(r, "package") ?? ""} ${field(r, "version") ?? ""}`.trim();
        const ids = field(r, "cve_ids");
        const list = Array.isArray(ids) ? ids.filter((i): i is string => typeof i === "string") : [];
        const shown = list.slice(0, NOTE_CVES_MAX).join(", ");
        return `${who} (${shown}${list.length > NOTE_CVES_MAX ? `, and ${list.length - NOTE_CVES_MAX} more` : ""})`;
      });
      out.push(`Affected: ${named.join("; ")}${hits.length > NOTE_AFFECTED_MAX ? `; and ${hits.length - NOTE_AFFECTED_MAX} more affected components in data.results` : ""}.`);
      // Said only when the answer carries fixed_in (an API before #2834 sends none).
      if (hits.some((r) => (Array.isArray(field(r, "matches")) ? (field(r, "matches") as unknown[]) : []).some((m) => isObj(m) && "fixed_in" in m))) {
        out.push("Each match's fixed_in is the fixed bound of the advisory interval that holds the component's version; null, with fixed_in_reason, where the advisory records no fix for that version.");
      }
    }
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
    "affected (count > 0); not_affected (assessed, no match, nothing undetermined: the only clean verdict); undetermined (advisories name the package, at least one could not be decided, none matched: not clean); not_assessed (no verdict: not clean).",
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
        match_reason: opt(z.string()).describe(
          "Why the advisory applies, with the advisory interval the version falls inside: \"[A, B)\" names the fixed version B, \"[A, B]\" the last affected version B. On an upstream row it ends by naming the source package and the purl name.",
        ),
        interval: opt(z.looseObject({ introduced: opt(z.string()), fixed: opt(z.string()), last_affected: opt(z.string()) })).describe(
          "The advisory interval that holds this component's version (fixed is exclusive, last_affected inclusive); absent when no interval holds it.",
        ),
        fixed_in: opt(z.string()).describe(
          "The fixed bound of the advisory interval that holds this component's version, always above it. null when that interval records no fix (it ends at last_affected, or has no end) or no interval holds the version, with fixed_in_reason saying which.",
        ),
        fixed_in_reason: opt(z.string()).describe("Why fixed_in is null; absent when fixed_in is a version."),
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
      undetermined: opt(z.number()).describe("Components whose advisories could not all be decided and none matched: not clean."),
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

// The coverage fields sendingCoverage fills, as the schema holds them.
export const sendingCoverageShape = {
  distinct_purls: z.number().int().describe("Distinct purls to check: sent plus not_sent."),
  batch_size: z.number().int().describe("The most purls one request carries (the API's cap per request)."),
  batches: z.number().int().describe("Requests the distinct purls make, at batch_size each."),
  batches_sent: z.number().int().describe("Of those, the ones the API answered."),
  sent: z.number().int().describe("Distinct purls sent and answered."),
  not_sent: z.number().int().describe("Distinct purls not sent, listed in data.not_sent_purls: not checked, and not clean."),
  not_sent_reason: z
    .enum(["time_budget", "rate_limited", "request_failed"])
    .nullable()
    .describe(
      "Why not_sent is above 0: time_budget (the call's 50 s budget ran out, before a batch or while one was unanswered, which is then cut off; or waiting out the API's Retry-After would pass it), rate_limited (a 429 without Retry-After, or a 429 after 10 waits), request_failed (a batch after the first failed; the note quotes how). null when every purl was sent.",
    ),
  rate_limit_waits: z.number().int().describe("How many times the API answered 429 and the tool waited its Retry-After before sending the batch again."),
  waited_ms: z.number().int().describe("Milliseconds spent in those waits."),
  not_assessed: z.number().int().nullable().describe("Of those sent, the components with no verdict, as the answer counts them."),
  partial: z
    .boolean()
    .nullable()
    .describe("true when not every purl was sent (not_sent above 0) or any batch's summary.partial was true (its time budget ran out first); otherwise the answer's summary.partial."),
};
