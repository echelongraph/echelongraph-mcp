// check_sbom (#2721): a dependency list checked against EchelonGraph's advisory corpus, one
// verdict per component, through POST /api/v1/public/cves/match/batch.
//
// Where the SBOM is parsed: HERE, in this MCP server — on the caller's machine when it runs from
// npm, on EchelonGraph's hosted endpoint when it is called there (http.ts, whose body cap admits
// a document only for this tool, #2747). The backend accepts only a list of
// components ({purl} or {ecosystem, package, version}); a CycloneDX or SPDX document posted to it
// whole is refused. So this tool reads the document, takes each component's purl, and sends only
// those, in a POST body (never a URL, #1983). The document's metadata, licences, hashes and free
// text never leave the machine, and the public route parses nothing but a flat list
// (core-backend internal/cve/matchbatch.go says the same from its side).
//
// What it is not: a ranking. It is not the rejected prioritize_cves (#2304, "Considered and
// rejected"); it relays each component's own verdict, assessed / not_assessed_reason included,
// and orders nothing.
//
// The note never renders not_assessed or undetermined as clean, and always says why a deb, apk or
// rpm purl without a distro release is not assessed.
import type { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod";

// What index.ts hands this module, so the tool uses the server's one api(), envelope and failure
// contract instead of a copy (and index.ts stays the only place that defines them).
type Text = { type: "text"; text: string };
export type ToolResult = { content: Text[]; structuredContent: Record<string, unknown>; isError?: boolean };
type ApiOk = { ok: true; status: number; data: object };
// The part of index.ts's Failure this module reads: a 429's Retry-After (whole seconds), #2734.
type FailureLike = { ok: false; kind: string; status?: number; retryAfter?: number };
export type CheckSbomDeps<F extends FailureLike> = {
  api: (path: string, init?: { headers?: Record<string, string>; method?: string; body?: string }) => Promise<ApiOk | F>;
  failed: (tool: string, f: F) => ToolResult;
  // index.ts's one sentence for a failure: quoted when a batch after the first fails.
  describeFailure: (f: F) => string;
  // For a caller that must not wait in real time; production uses the clock and setTimeout.
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
  badInput: (tool: string, why: string) => ToolResult;
  crashed: (tool: string, e: unknown) => ToolResult;
  checked: (tool: string, schema: z.ZodType, r: ToolResult) => ToolResult;
  succeeded: (
    data: object,
    note: string,
    env: { state: "measured" | "not_assessed"; measured_at: string | null; method: string; coverage: Record<string, unknown> | null; freshness: null; notes?: string[] },
  ) => ToolResult;
  okHead: (tool: string, status?: number) => string;
  envelopeSchema: (o: { data: z.ZodType; coverage: z.ZodType | null; freshness: z.ZodType | null }) => z.ZodType;
  annotations: Record<string, boolean>;
};

export const CHECK_SBOM = "check_sbom";
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
export const TIME_BUDGET_MS = 50_000;
// Retry-After 0 is waited this long; a 429 without Retry-After is not retried. At most MAX_WAITS
// waits per call.
const MIN_WAIT_MS = 1000;
const MAX_WAITS = 10;
// The backend's per-purl cap (cveBatchMaxPurlLen).
const MAX_PURL_LEN = 512;
// The document's size cap, as JSON text. OWASP Juice Shop 11.1.2's full CycloneDX SBOM (840
// components) is 0.74 MB; this leaves room for a much larger one while bounding what this process
// parses.
export const MAX_SBOM_CHARS = 5_000_000;
// How many affected components the note names, and how many CVE ids per component.
const NOTE_AFFECTED_MAX = 25;
const NOTE_CVES_MAX = 5;
// CycloneDX nests components; this bounds the walk.
const MAX_DEPTH = 32;

const METHOD =
  "EchelonGraph's registry advisory matcher (POST /api/v1/public/cves/match/batch): each component's purl is mapped to its OSV ecosystem, package name and version, and matched against the affected version ranges EchelonGraph holds from OSV.dev advisory records, the same matcher GET /api/v1/public/cves/match uses when given an ecosystem. No CPE matching, no score, no ranking.";

// Always in the envelope's notes, whatever the answer: the refusals a model must not read as clean.
const DISTRO_NOTE =
  "A deb, apk or rpm purl without a distro qualifier naming its release (for example ?distro=debian-12 or ?distro=alpine-3.20) is not assessed (distro_release_unknown): the advisory corpus is keyed per distro release, and EchelonGraph does not guess one.";
const CLEAN_NOTE =
  "Only not_affected is a clean verdict, and only for the advisories decided at that version: an undetermined or not_assessed component is not a finding of no vulnerability, and is reported as unchecked, never as clean.";
const MEASURED_AT_NOTE =
  "measured_at is null: the corpus rows are read through a cache whose maximum age the answer states (summary.corpus_cache_max_age_ms), so the answer gives no single time at which they were read.";
const FRESHNESS_NOTE = "freshness is null: the answer carries no time at which the advisory corpus was last refreshed.";

export const CHECK_SBOM_TITLE = "Check an SBOM against the advisory corpus";
export const CHECK_SBOM_DESCRIPTION =
  "Check a dependency list against EchelonGraph's advisory corpus, one verdict per component. Pass purls (package URLs, up to 2,000 distinct) or sbom (a CycloneDX JSON or SPDX JSON document, as JSON text or as an object, up to 5,000,000 characters). The purls are read from the document by this MCP server and only they are sent to the API, in POST bodies of at most 200 purls each, one after another, never in a URL; the document itself is not sent on. Run from npm, this server is on your machine; over the hosted endpoint (mcp.echelongraph.io) it is EchelonGraph's, and the document is the request body, accepted up to 6 MiB. A component without a purl is counted and not checked. Each purl is mapped to its OSV ecosystem, package name and version and matched against the affected version ranges EchelonGraph holds from OSV.dev advisory records; there is no ranking and no score. data.results holds one row per component sent, in order (index counts across batches), with verdict (affected, not_affected, undetermined or not_assessed), assessed, not_assessed_reason, cve_ids, matches, count, not_affected_count and undetermined_count; data.summary counts the verdicts, summed over the batches (partial is true when any batch's was). not_affected is the only clean verdict. undetermined: advisories name the package but at least one could not be decided at this version and none matched. not_assessed: no verdict at all, because the package is not in the corpus, the purl type has no OSV ecosystem, a deb, apk or rpm purl carries no distro qualifier naming its release (EchelonGraph does not guess one), the version is missing, the lookup failed, or the batch's time budget ran out first (time_budget). Neither undetermined nor not_assessed is clean, and the note gives their counts. The API allows 1,200 components a minute per caller; when it answers 429 with Retry-After, the tool waits as asked and sends the batch again, within 50 seconds per call. When the next wait would pass that, or a batch after the first fails, the tool stops and answers what it has: coverage.not_sent counts the purls not sent and coverage.not_sent_reason says why (time_budget, rate_limited or request_failed), data.not_sent_purls lists them for a later call, and they are not checked and not clean. A list or document with more than 2,000 distinct purls is refused, not truncated: split it. Its structured result carries state (measured when at least one component got a verdict, else not_assessed), measured_at (null: the corpus is read through a cache, so no single read time exists), method, coverage (what the input held, what was sent in how many batches, and what was not sent and why), freshness (null) and notes, with data equal to the API's JSON (for more than one batch, the batches' answers merged); the result's last text block repeats it without data (the first text block) and without the note's sentences (the text block before it), with which notes ends.";

// ── Reading the input ──

export type Extracted = {
  input: "purls" | "cyclonedx" | "spdx";
  // Components (CycloneDX) or packages (SPDX) in the document; null for a plain purl list.
  components_in_document: number | null;
  with_purl: number;
  without_purl: number;
  duplicates_removed: number;
  purls: string[];
};

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

function dedupe(all: string[]): { purls: string[]; removed: number } {
  const seen = new Set<string>();
  const purls: string[] = [];
  for (const p of all) {
    if (seen.has(p)) continue;
    seen.add(p);
    purls.push(p);
  }
  return { purls, removed: all.length - purls.length };
}

// The purls of a CycloneDX JSON document: every components[] entry, nested ones included.
// metadata.component (the subject of the SBOM, not a dependency of it) is not checked.
function fromCycloneDX(doc: Record<string, unknown>): Extracted | string {
  if (doc.components !== undefined && !Array.isArray(doc.components)) return "its components is not an array";
  let total = 0;
  let without = 0;
  const found: string[] = [];
  const walk = (cs: unknown, depth: number): string | null => {
    if (!Array.isArray(cs)) return null;
    if (depth > MAX_DEPTH) return `its components nest deeper than ${MAX_DEPTH} levels`;
    for (const c of cs) {
      if (!isObj(c)) continue;
      total++;
      const p = typeof c.purl === "string" ? c.purl.trim() : "";
      if (p) found.push(p);
      else without++;
      const err = walk(c.components, depth + 1);
      if (err) return err;
    }
    return null;
  };
  const err = walk(doc.components, 0);
  if (err) return err;
  const { purls, removed } = dedupe(found);
  return { input: "cyclonedx", components_in_document: total, with_purl: found.length, without_purl: without, duplicates_removed: removed, purls };
}

// The purls of an SPDX JSON document: each package's externalRefs entry of referenceType purl
// (referenceCategory PACKAGE-MANAGER, spelled PACKAGE_MANAGER by some tools; the type decides).
function fromSPDX(doc: Record<string, unknown>): Extracted | string {
  if (doc.packages !== undefined && !Array.isArray(doc.packages)) return "its packages is not an array";
  const pkgs = Array.isArray(doc.packages) ? doc.packages : [];
  let total = 0;
  let without = 0;
  const found: string[] = [];
  for (const p of pkgs) {
    if (!isObj(p)) continue;
    total++;
    const refs = Array.isArray(p.externalRefs) ? p.externalRefs : [];
    const ref = refs.find((r) => isObj(r) && typeof r.referenceType === "string" && r.referenceType.toLowerCase() === "purl" && typeof r.referenceLocator === "string" && r.referenceLocator.trim());
    if (ref && isObj(ref)) found.push(String(ref.referenceLocator).trim());
    else without++;
  }
  const { purls, removed } = dedupe(found);
  return { input: "spdx", components_in_document: total, with_purl: found.length, without_purl: without, duplicates_removed: removed, purls };
}

// Reads the tool's arguments into the purls to send, or says why it cannot.
export function extract(a: { purls?: unknown; sbom?: unknown }): Extracted | string {
  const hasPurls = a.purls !== undefined;
  const hasSbom = a.sbom !== undefined;
  if (hasPurls === hasSbom) return "pass exactly one of purls (a list of package URLs) or sbom (a CycloneDX JSON or SPDX JSON document)";
  if (hasPurls) {
    if (!Array.isArray(a.purls) || a.purls.some((p) => typeof p !== "string")) return "purls must be a list of strings";
    const trimmed = (a.purls as string[]).map((p) => p.trim()).filter(Boolean);
    const { purls, removed } = dedupe(trimmed);
    return { input: "purls", components_in_document: null, with_purl: trimmed.length, without_purl: (a.purls as string[]).length - trimmed.length, duplicates_removed: removed, purls };
  }
  let doc: unknown = a.sbom;
  if (typeof doc === "string") {
    if (doc.length > MAX_SBOM_CHARS) return `sbom is ${doc.length} characters; at most ${MAX_SBOM_CHARS} are read`;
    try {
      doc = JSON.parse(doc);
    } catch {
      return "sbom is not JSON: pass a CycloneDX JSON or SPDX JSON document (XML and SPDX tag-value are not read)";
    }
  } else {
    let size = 0;
    try {
      size = JSON.stringify(doc)?.length ?? 0;
    } catch {
      return "sbom could not be serialised as JSON";
    }
    if (size > MAX_SBOM_CHARS) return `sbom is ${size} characters as JSON; at most ${MAX_SBOM_CHARS} are read`;
  }
  if (!isObj(doc)) return "sbom must be a JSON object: a CycloneDX JSON or SPDX JSON document";
  if (typeof doc.bomFormat === "string" && doc.bomFormat.toLowerCase() === "cyclonedx") {
    const r = fromCycloneDX(doc);
    return typeof r === "string" ? `the CycloneDX document cannot be read: ${r}` : r;
  }
  if (typeof doc.spdxVersion === "string" && doc.spdxVersion.toUpperCase().startsWith("SPDX-")) {
    const r = fromSPDX(doc);
    return typeof r === "string" ? `the SPDX document cannot be read: ${r}` : r;
  }
  return 'sbom is neither a CycloneDX JSON document (bomFormat "CycloneDX") nor an SPDX JSON document (spdxVersion "SPDX-…")';
}

// ── The answer ──

const field = (o: unknown, k: string): unknown => (isObj(o) ? o[k] : undefined);
const count = (o: unknown, k: string): number | undefined => {
  const v = field(o, k);
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
};
const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

// How the batches went: what the note and the coverage say about sending.
type NotSentReason = "time_budget" | "rate_limited" | "request_failed";
type Sending = {
  batches: number;
  batches_sent: number;
  sent: number;
  not_sent_purls: string[];
  not_sent_reason: NotSentReason | null;
  not_sent_detail: string | null;
  waits: number;
  waited_ms: number;
};

function noteFor(head: string, x: Extracted, d: object, g: Sending): { note: string; assessed: number } {
  const s = field(d, "summary");
  const affected = count(s, "affected") ?? 0;
  const notAffected = count(s, "not_affected") ?? 0;
  const undetermined = count(s, "undetermined") ?? 0;
  const notAssessed = count(s, "not_assessed") ?? 0;
  const components = count(s, "components") ?? g.sent;
  const out: string[] = [head];

  if (x.input === "purls") {
    out.push(`Sent ${plural(g.sent, "purl", "purls")}${x.duplicates_removed ? ` (${plural(x.duplicates_removed, "duplicate was", "duplicates were")} sent once)` : ""}.`);
  } else {
    const kind = x.input === "cyclonedx" ? "CycloneDX" : "SPDX";
    const unit = x.input === "cyclonedx" ? "component" : "package";
    out.push(
      `Read ${plural(x.components_in_document ?? 0, unit, `${unit}s`)} from the ${kind} document: ${x.with_purl} with a purl${x.without_purl ? `, and ${x.without_purl} without one, which ${x.without_purl === 1 ? "was" : "were"} not checked and ${x.without_purl === 1 ? "is" : "are"} not clean` : ""}${x.duplicates_removed ? `; ${plural(x.duplicates_removed, "duplicate purl was", "duplicate purls were")} sent once` : ""}; sent ${g.sent}.`,
    );
  }
  if (g.batches > 1) {
    out.push(
      `The ${x.purls.length} distinct purls make ${g.batches} batches of at most ${MAX_COMPONENTS}, sent one after another; the API answered ${g.batches_sent} of them, and data.summary sums those answers.`,
    );
  }
  if (g.waits > 0) {
    out.push(
      `The API's component budget (${API_COMPONENTS_PER_MINUTE} components a minute) ran out ${g.waits === 1 ? "once" : `${g.waits} times`}: the tool waited ${Math.round(g.waited_ms / 1000)} s in all, as its Retry-After asked, and sent the batch again.`,
    );
  }
  const notSent = g.not_sent_purls.length;
  if (notSent > 0) {
    out.push(
      `${plural(notSent, "purl was", "purls were")} NOT sent (not_sent_reason ${g.not_sent_reason}: ${g.not_sent_detail}), so ${notSent === 1 ? "it is" : "they are"} not checked and not clean; data.not_sent_purls lists ${notSent === 1 ? "it" : "them"}: call check_sbom again with purls set to that list${g.not_sent_reason === "request_failed" ? "" : " after a minute"}.`,
    );
  }
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
    }
  }
  return { note: out.join(" "), assessed: affected + notAffected + undetermined };
}

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

const realSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export async function checkSbom<F extends FailureLike>(deps: CheckSbomDeps<F>, a: { purls?: unknown; sbom?: unknown }): Promise<ToolResult> {
  const tool = CHECK_SBOM;
  const sleep = deps.sleep ?? realSleep;
  const now = deps.now ?? Date.now;
  try {
    const x = extract(a);
    if (typeof x === "string") return deps.badInput(tool, x);
    if (x.purls.length === 0) {
      return deps.badInput(tool, x.input === "purls" ? "purls holds no package URL" : `the document holds ${x.components_in_document ?? 0} components and none carries a purl, so there is nothing to check`);
    }
    if (x.purls.length > MAX_PURLS) {
      return deps.badInput(
        tool,
        `${x.purls.length} distinct purls; at most ${MAX_PURLS} are checked per call (in batches of ${MAX_COMPONENTS}, within the API's budget of ${API_COMPONENTS_PER_MINUTE} components a minute), and none is dropped silently: split the list into calls of ${MAX_PURLS} or fewer`,
      );
    }
    const long = x.purls.findIndex((p) => p.length > MAX_PURL_LEN);
    if (long >= 0) return deps.badInput(tool, `purl ${long + 1} is longer than ${MAX_PURL_LEN} characters`);

    const batches: string[][] = [];
    for (let i = 0; i < x.purls.length; i += MAX_COMPONENTS) batches.push(x.purls.slice(i, i + MAX_COMPONENTS));
    const started = now();
    const budgetS = TIME_BUDGET_MS / 1000;
    const answers: object[] = [];
    let status = 200;
    let waits = 0;
    let waitedMs = 0;
    let stop: { reason: NotSentReason; detail: string } | null = null;
    // One batch at a time, in order; a 429 with Retry-After is waited out and the same batch sent
    // again, while the wait fits in the call's budget.
    while (answers.length < batches.length) {
      if (answers.length > 0 && now() - started >= TIME_BUDGET_MS) {
        stop = { reason: "time_budget", detail: `the call's ${budgetS} s budget ran out after ${answers.length} of ${batches.length} batches` };
        break;
      }
      const r = await deps.api(BATCH_PATH, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ components: batches[answers.length].map((purl) => ({ purl })) }),
      });
      if (r.ok) {
        answers.push(r.data);
        status = r.status;
        continue;
      }
      if (r.kind === "http" && r.status === 429) {
        if (r.retryAfter === undefined) {
          stop = { reason: "rate_limited", detail: "the API answered 429 without a Retry-After to wait for" };
        } else if (waits >= MAX_WAITS) {
          stop = { reason: "rate_limited", detail: `the API answered 429 again after ${MAX_WAITS} waits` };
        } else {
          const waitMs = Math.max(MIN_WAIT_MS, r.retryAfter * 1000);
          if (now() - started + waitMs <= TIME_BUDGET_MS) {
            await sleep(waitMs);
            waits++;
            waitedMs += waitMs;
            continue;
          }
          stop = { reason: "time_budget", detail: `the API answered 429 asking for a wait of ${r.retryAfter} s (Retry-After), which would pass the call's ${budgetS} s budget` };
        }
      } else {
        stop = { reason: "request_failed", detail: deps.describeFailure(r).replace(/\.$/, "") };
      }
      // Nothing answered yet: nothing was measured, so the failure is the answer.
      if (answers.length === 0) return deps.failed(tool, r);
      break;
    }

    const notSentPurls = x.purls.slice(answers.length * MAX_COMPONENTS);
    const g: Sending = {
      batches: batches.length,
      batches_sent: answers.length,
      sent: x.purls.length - notSentPurls.length,
      not_sent_purls: notSentPurls,
      not_sent_reason: notSentPurls.length ? (stop?.reason ?? null) : null,
      not_sent_detail: notSentPurls.length ? (stop?.detail ?? null) : null,
      waits,
      waited_ms: waitedMs,
    };
    // One batch: data is the API's JSON as it came. More: the merged answer.
    const data: Record<string, unknown> = batches.length === 1 ? (answers[0] as Record<string, unknown>) : mergeAnswers(answers);
    if (notSentPurls.length) data.not_sent_purls = notSentPurls;
    const { note, assessed } = noteFor(deps.okHead(tool, status), x, data, g);
    const s = field(data, "summary");
    const summaryPartial = typeof field(s, "partial") === "boolean" ? (field(s, "partial") as boolean) : null;
    return deps.succeeded(data, note, {
      state: assessed > 0 ? "measured" : "not_assessed",
      measured_at: null,
      method: METHOD,
      coverage: {
        input: x.input,
        components_in_document: x.components_in_document,
        with_purl: x.with_purl,
        without_purl: x.without_purl,
        duplicates_removed: x.duplicates_removed,
        distinct_purls: x.purls.length,
        batch_size: MAX_COMPONENTS,
        batches: g.batches,
        batches_sent: g.batches_sent,
        sent: g.sent,
        not_sent: notSentPurls.length,
        not_sent_reason: g.not_sent_reason,
        rate_limit_waits: waits,
        waited_ms: waitedMs,
        not_assessed: count(s, "not_assessed") ?? null,
        partial: notSentPurls.length > 0 ? true : summaryPartial,
      },
      freshness: null,
      notes: [DISTRO_NOTE, CLEAN_NOTE, MEASURED_AT_NOTE, FRESHNESS_NOTE],
    });
  } catch (e) {
    return deps.crashed(tool, e);
  }
}

// ── Schemas ──

const opt = <T extends z.ZodType>(t: T) => t.nullable().optional();

const Row = z.looseObject({
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
  matches: opt(z.array(z.looseObject({ cve_id: opt(z.string()) }))),
  count: opt(z.number()),
  advisories_considered: opt(z.number()),
  not_affected_count: opt(z.number()),
  undetermined_count: opt(z.number()),
  undetermined: opt(z.array(z.looseObject({ cve_id: opt(z.string()) }))),
  capped: opt(z.boolean()),
  candidates_capped: opt(z.boolean()),
});

export function checkSbomOutput(envelopeSchema: CheckSbomDeps<FailureLike>["envelopeSchema"]): z.ZodType {
  return envelopeSchema({
    data: z.looseObject({
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
    }),
    coverage: z.strictObject({
      input: z.enum(["purls", "cyclonedx", "spdx"]).describe("What was passed: a purl list, a CycloneDX JSON document or an SPDX JSON document."),
      components_in_document: z.number().int().nullable().describe("Components (CycloneDX) or packages (SPDX) in the document; null for a purl list."),
      with_purl: z.number().int().describe("Of those, the ones carrying a purl."),
      without_purl: z.number().int().describe("The ones without a purl: not checked, and not clean."),
      duplicates_removed: z.number().int().describe("Purls that appeared more than once and were sent once."),
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
          "Why not_sent is above 0: time_budget (the call's 50 s budget ran out, or waiting out the API's Retry-After would pass it), rate_limited (a 429 without Retry-After, or a 429 after 10 waits), request_failed (a batch after the first failed; the note quotes how). null when every purl was sent.",
        ),
      rate_limit_waits: z.number().int().describe("How many times the API answered 429 and the tool waited its Retry-After before sending the batch again."),
      waited_ms: z.number().int().describe("Milliseconds spent in those waits."),
      not_assessed: z.number().int().nullable().describe("Of those sent, the components with no verdict, as the answer counts them."),
      partial: z
        .boolean()
        .nullable()
        .describe("true when not every purl was sent (not_sent above 0) or any batch's summary.partial was true (its time budget ran out first); otherwise the answer's summary.partial."),
    }),
    freshness: null,
  });
}

// A literal server.registerTool(name, { title, description, … }) call with constant strings:
// marketing-site lib/mcpToolClaims.test.ts reads it here (it follows index.ts's call to this
// function) and holds the /pulse/mcp row to this title and description.
export function registerCheckSbom<F extends FailureLike>(server: McpServer, deps: CheckSbomDeps<F>): void {
  const output = checkSbomOutput(deps.envelopeSchema as CheckSbomDeps<FailureLike>["envelopeSchema"]);
  server.registerTool(
    CHECK_SBOM,
    {
      title: CHECK_SBOM_TITLE,
      description: CHECK_SBOM_DESCRIPTION,
      inputSchema: z.object({
        purls: z.array(z.string()).optional().describe("package URLs to check, e.g. pkg:npm/lodash@4.17.20 or pkg:deb/debian/openssl@3.0.11-1~deb12u1?distro=debian-12 (up to 2,000 distinct, sent in batches of 200)"),
        sbom: z
          .union([z.string(), z.record(z.string(), z.unknown())])
          .optional()
          .describe("a CycloneDX JSON or SPDX JSON document, as JSON text or as an object; its purls are read here and only they are sent"),
      }),
      outputSchema: output as z.ZodObject,
      annotations: deps.annotations,
    },
    async (a: { purls?: string[]; sbom?: unknown }) => deps.checked(CHECK_SBOM, output, await checkSbom(deps, a)) as never,
  );
}
