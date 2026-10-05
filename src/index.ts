#!/usr/bin/env node
// EchelonGraph CVE & internet-exposure MCP server.
// Exposes EchelonGraph's free, keyless public CVE and exposure data as MCP tools for Claude,
// Cursor, Cline and any MCP client: the CVE feed, and per CVE the internet-exposure footprint
// that EchelonGraph's KEV-exposure radar derives from Shodan data. Every figure is as fresh as
// the schedule that refreshes it, and the tool texts say which schedule that is.
// stdio transport; no auth required; read-only. It makes no request other than the API call a
// tool needs to answer. The hosted Streamable HTTP endpoint (mcp.echelongraph.io, #2316) is
// http.ts, which serves this file's createServer — one tool module for both.
//
// Result contract (#1874). A tool answers in exactly one of two shapes, and they never blur:
//   - success: content[0] is the API's JSON verbatim; content[1] is a one-line note saying
//     the call succeeded, where, and what it found — in words, including when it found
//     nothing ("we looked and found nothing" is a measurement). One exception: exposure_radar
//     relays each radar's answer cut to the fields it can label by what they count, and names
//     what it left out (readKEVExposure, readExposedDatabases, readLeakedCredentials,
//     readShadowAI and readMCPServers; #2307, #2313, #2315). content[2] is the envelope below,
//     as JSON, less what content[0] and the note already say. Past 30,000 characters of JSON,
//     content[0] is that JSON cut to fit and the note ends by saying how (TEXT CUT); the
//     envelope's data is always the answer whole (textBudget.ts, #2783).
//   - failure (isError: true): the lookup did not complete — unreachable host, non-2xx,
//     timeout, or a 2xx whose body is not a JSON object — named by tool, cause and base URL,
//     in content[0]; content[1] is the envelope below, as JSON, less the message's sentences.
//     Never a success with null fields: a model handed one of those tells its user "no
//     exposure found", and an outage becomes an all-clear.
//
// Structured results (#2311, #2313). Every result, success or failure, also carries
// structuredContent: one envelope that says how the answer was measured — state (measured,
// not_assessed, failed, invalid_input), measured_at, method, coverage, freshness and notes —
// with, on a success, `data`, the answer whole, and on a failure an `error`. content[0] carries
// `data` as JSON up to 30,000 characters, and past them a cut of it that the note names (TEXT
// CUT, #2783), so past them content[0] is not equal to `data` (#2802). Each tool advertises the
// envelope as its outputSchema.
//
// The envelope in the text (#2440, #2467). Many clients pass only `content` to the model, so the
// last text block of every result is structuredContent serialized as JSON, less what an earlier
// text block already carries: `data` (content[0] on a success, whole or cut as above), the note's
// sentences (the block just before, which structuredContent's notes end with), and method where
// that note quotes it. The rest — state, measured_at, coverage, freshness, the envelope's own notes
// and, on a failure, error — is copied key for key, so the text blocks together are the whole of
// structuredContent, but for what a TEXT CUT leaves out of `data`, and cannot disagree with it. The
// MCP spec (2025-06-18, Tools, Structured Content) asks a tool that returns structured content to
// return it serialized in a text block too; the JSON block stays first and the note second, as in
// 1.x, so a client that parses content[0] still parses the answer's JSON, which past 30,000
// characters is a cut of it (fields, entries and string ends left out, no value changed) and no
// longer the whole answer: structuredContent.data is (#2802).
//
// Protocol eras (#2311). serveStdio answers both: a 2026-07-28 client's server/discover and
// per-request `_meta` envelope, and a 2025-era client's `initialize` handshake. The first
// message of a connection picks the era; the same factory builds the server for either.
import { readFileSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import * as z from "zod";
import { registerKevRecent } from "./tools/kev_recent.js";
import { registerEPSSHistory } from "./tools/epss_history.js";
import { registerCheckAffected } from "./tools/check_affected.js";
import { registerCheckSbom } from "./tools/check_sbom.js";
import { registerCveIntel } from "./tools/cve_intel.js";
import { registerGetCwe } from "./tools/get_cwe.js";
import { holdRequest, isHttpEntrypoint, requestSignal, upstreamHeaders, upstreamUserAgent } from "./runtime.js";
import { registerVendorAdvisoryTools } from "./tools/vendor_advisories.js";
import { registerPrompts } from "./prompts.js";
import { registerResources } from "./resources.js";
import { dataText, GET_CVE_WHOLE, TEXT_BUDGET_DESCRIPTION, type TextCut } from "./textBudget.js";

// The package actually running, read from the package.json that ships beside dist/. The MCP
// handshake (serverInfo) and the User-Agent both carry its name and version, so the API's
// access log can count adoption per version without a code change per release.
const PKG: Record<string, unknown> = (() => {
  try {
    const pkg: unknown = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
    return pkg !== null && typeof pkg === "object" && !Array.isArray(pkg) ? (pkg as Record<string, unknown>) : {};
  } catch {
    return {};
  }
})();
const pkgField = (k: string, fallback: string): string => {
  const v = PKG[k];
  return typeof v === "string" && v ? v : fallback;
};
const NAME = pkgField("name", "echelongraph-mcp");
const VERSION = pkgField("version", "unknown");

const BASE = (process.env.ECHELONGRAPH_API_BASE || "https://app.echelongraph.io").replace(/\/+$/, "");
// ECHELONGRAPH_MCP_UA (#2724): one product token, such as echelongraph-mcp-synthetic/1.0, put
// AHEAD of the package's own User-Agent. The API's access log reads the family from the leading
// token, so a caller that is not a user (our production synthetic) is filed under its own family
// and never counted as MCP adoption, while the package and version stay readable after it.
// Unset by default. A value that is not a single token (spaces, control characters, a name over 64
// or a version over 32 characters) is ignored, with one line on stderr naming its length, not its text.
const UA_TOKEN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}(?:\/[A-Za-z0-9][A-Za-z0-9._-]{0,31})?$/;
const UA_PREFIX = (() => {
  const v = process.env.ECHELONGRAPH_MCP_UA;
  if (v === undefined || v === "") return "";
  if (UA_TOKEN.test(v)) return `${v} `;
  process.stderr.write(`echelongraph-mcp: ECHELONGRAPH_MCP_UA ignored: not a single product token (${v.length} characters)\n`);
  return "";
})();
const UA = `${UA_PREFIX}${NAME}/${VERSION} (+https://echelongraph.io/pulse/mcp)`;
const DEFAULT_TIMEOUT_MS = 15_000;
const TIMEOUT_MS = (() => {
  const n = Number(process.env.ECHELONGRAPH_API_TIMEOUT_MS);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : DEFAULT_TIMEOUT_MS;
})();
// The base as quoted in tool results. A proxy credential in the URL's userinfo is dropped.
export const SHOWN_BASE = (() => {
  try {
    const u = new URL(BASE);
    if (!u.username && !u.password) return BASE;
    return `${u.protocol}//***@${u.host}${u.pathname.replace(/\/+$/, "")}`;
  } catch {
    return "the configured ECHELONGRAPH_API_BASE (not a valid URL)";
  }
})();

// unexpected_shape is never returned by api(): it is exposure_radar refusing an answer that is
// not the counts it asked for (mcpRefusal, #2315), named per radar like any other failure.
type Failure = {
  ok: false;
  kind: "network" | "timeout" | "http" | "not_json" | "not_object" | "unexpected_shape";
  path: string;
  // The request's method when it was not GET (check_sbom's POST, #2721); describeFailure names it.
  method?: string;
  status?: number;
  // A non-2xx's Retry-After, in whole seconds, when it sent one (check_sbom honours it between
  // batches, #2734). Never part of the failure text or envelope.
  retryAfter?: number;
  // A timeout's own limit, when the caller set one under TIMEOUT_MS (check_sbom, #2756);
  // describeFailure names it.
  timeoutMs?: number;
  detail: string;
};
export type ApiResult = { ok: true; status: number; data: object } | Failure;

// Collapse a response body to something quotable: one line, at most 160 characters.
function snippet(body: string): string {
  const s = body.replace(/\s+/g, " ").trim();
  if (!s) return "(empty body)";
  return s.length > 160 ? `${s.slice(0, 160)}…` : s;
}

// A message may echo a URL — undici's refusal of a credentialed URL quotes it whole — so
// anything shaped scheme://user:pass@host is masked before it can reach a result.
const redactCredentials = (s: string): string => s.replace(/(\w+:\/\/)[^/\s@]+@/g, "$1***@");

// The useful part of a fetch error is usually in its cause chain (ECONNREFUSED, ENOTFOUND,
// "bad port"), so walk it. Messages and codes only — never headers, never a credential.
function describeError(e: unknown): string {
  if (!(e instanceof Error)) return String(e);
  const parts = [e.message];
  let cause: unknown = e.cause;
  for (let depth = 0; cause instanceof Error && depth < 4; depth++) {
    const c = cause as Error & { code?: unknown; errors?: unknown };
    const codes = Array.isArray(c.errors)
      ? c.errors.map((x) => (x as { code?: unknown }).code).filter((x): x is string => typeof x === "string")
      : [];
    if (codes.length) parts.push(codes.join(", "));
    else if (typeof c.code === "string") parts.push(c.code);
    else if (c.message) parts.push(c.message);
    cause = c.cause;
  }
  return redactCredentials(parts.join(": "));
}

// The API's error envelope is {"error": "..."}; quote that string when a non-2xx carries it.
function apiMessage(body: string): string {
  try {
    const parsed: unknown = JSON.parse(body);
    const msg = (parsed as { error?: unknown } | null)?.error;
    if (typeof msg === "string" && msg) return msg;
  } catch {
    // not JSON — fall through to the raw snippet
  }
  return snippet(body);
}

// A Retry-After header as whole seconds from now: delta-seconds, or an HTTP-date (RFC 9110
// 10.2.3). undefined when absent or unreadable.
function retryAfterSeconds(v: string | null): number | undefined {
  const t = v?.trim();
  if (!t) return undefined;
  if (/^\d{1,9}$/.test(t)) return Number(t);
  const at = Date.parse(t);
  return Number.isFinite(at) ? Math.max(0, Math.ceil((at - Date.now()) / 1000)) : undefined;
}

// One request against the API, a GET unless init says otherwise. Never throws: every way the call
// can fail comes back as a typed Failure so the tool renders it as an error result. A 2xx whose
// body is not a JSON object (an SPA shell, an edge challenge page, a literal null) is a failure
// too — it is not data. init.headers carries what a caller typed (#1983: X-EG-* headers, never
// the URL); the User-Agent and Accept are this server's and are not overridden. init.timeoutMs
// can only shorten the request's timeout below TIMEOUT_MS, never lengthen it: check_sbom passes
// what is left of its call's budget, so a slow batch cannot carry the call past it (#2756).
// The request is cancelled when init.signal aborts (check_sbom's call was cancelled) or, on the
// hosted endpoint, when the client it answers has gone (runtime.ts requestSignal, #2775): a
// network failure saying so, which nobody reads, since the SDK sends nothing for a cancelled call.
export async function api(
  path: string,
  init?: { headers?: Record<string, string>; method?: string; body?: string; timeoutMs?: number; signal?: AbortSignal },
): Promise<ApiResult> {
  const limitMs = init?.timeoutMs === undefined ? TIMEOUT_MS : Math.max(0, Math.min(TIMEOUT_MS, Math.floor(init.timeoutMs)));
  const m = init?.method && init.method.toUpperCase() !== "GET" ? { method: init.method.toUpperCase() } : {};
  const callers = [init?.signal, requestSignal()].filter((s): s is AbortSignal => s !== undefined);
  const cancelledFailure = (): Failure => ({ ok: false, kind: "network", path, ...m, detail: "cancelled: the call was abandoned before the API answered" });
  if (callers.some((s) => s.aborted)) return cancelledFailure();
  const ctrl = new AbortController();
  let timedOut = false;
  let cancelled = false;
  const timer = setTimeout(() => {
    timedOut = true;
    ctrl.abort();
  }, limitMs);
  const cancel = (): void => {
    cancelled = true;
    ctrl.abort();
  };
  for (const s of callers) s.addEventListener("abort", cancel, { once: true });
  const own = limitMs === TIMEOUT_MS ? {} : { timeoutMs: limitMs };
  const timeout = (): Failure => ({ ok: false, kind: "timeout", path, ...m, ...own, detail: `no response within ${limitMs} ms` });
  try {
    let res: Response;
    try {
      res = await fetch(`${BASE}${path}`, {
        method: init?.method,
        body: init?.body,
        // upstreamHeaders: empty on stdio; on the hosted endpoint, the forward token and the
        // end client's address (runtime.ts, #2316). upstreamUserAgent: UA, unless the hosted
        // endpoint is answering the production synthetic (#2737).
        headers: { ...upstreamHeaders(`${BASE}${path}`), ...(init?.headers ?? {}), "User-Agent": upstreamUserAgent(UA), Accept: "application/json" },
        signal: ctrl.signal,
      });
    } catch (e) {
      return timedOut ? timeout() : cancelled ? cancelledFailure() : { ok: false, kind: "network", path, ...m, detail: describeError(e) };
    }
    let body: string;
    try {
      body = await res.text();
    } catch (e) {
      return timedOut ? timeout() : cancelled ? cancelledFailure() : { ok: false, kind: "network", path, ...m, detail: `reading the body failed: ${describeError(e)}` };
    }
    if (!res.ok) {
      const retryAfter = retryAfterSeconds(res.headers.get("retry-after"));
      return { ok: false, kind: "http", path, ...m, status: res.status, ...(retryAfter === undefined ? {} : { retryAfter }), detail: apiMessage(body) };
    }
    let data: unknown;
    try {
      data = JSON.parse(body);
    } catch {
      const ctype = res.headers.get("content-type") ?? "no content-type";
      return { ok: false, kind: "not_json", path, ...m, status: res.status, detail: `${ctype}; body starts: ${snippet(body)}` };
    }
    if (data === null || typeof data !== "object") {
      return { ok: false, kind: "not_object", path, ...m, status: res.status, detail: `body was ${snippet(body)}` };
    }
    return { ok: true, status: res.status, data };
  } finally {
    clearTimeout(timer);
    for (const s of callers) s.removeEventListener("abort", cancel);
  }
}

type Text = { type: "text"; text: string };
// structuredContent is an object keyed by field name; ToolResult keeps it that loose so the
// SDK's CallToolResult accepts it. Its shape is each tool's outputSchema (see Envelope below).
export type ToolResult = { content: Text[]; structuredContent: Record<string, unknown>; isError?: boolean };
const text = (t: string): Text => ({ type: "text", text: t });

// ── The result envelope (#2313) ──
//
//   state        measured: the answer is a measurement of what was asked. An exposure count
//                is only ever measured with an observation time (measured_at) and a method.
//                not_assessed: the answer holds no dated measurement of what was asked — the
//                radar does not look for this CVE, cannot say whether it does, or the answer
//                does not say when what it counts was observed — so no count in it is presented
//                as one. It can still relay a count, as what the source holds on record,
//                undated, and its notes (and cve_exposure's exposure_state) say what each count
//                is (#2465): every cve_exposure count of services on record, and exposure_radar's
//                totals, are relayed under this state, so it never says its numbers are not
//                findings.
//                failed / invalid_input: nothing was measured (the #1874 failure contract).
//   measured_at  when the underlying observation was made, as the API states it; null when the
//                answer does not say or holds no observation. Never the Go zero time.
//   method       how the numbers were produced; null on a failure.
//   coverage     what the answer covers (the denominator, and in_scope where it applies).
//   freshness    the producing radar's last completed check (last_run_at) where the API
//                serves one; null where it serves none.
//   notes        the caveats, one sentence each: the note in content[1], split, after any
//                sentence about the envelope itself.
// Every field is derived from what the API sends. Where the API does not say, the envelope
// says null and a note says so; nothing is filled in. The result's last text block repeats the
// envelope, less what the text before it already says (see envelopeText).
type State = "measured" | "not_assessed" | "failed" | "invalid_input";
type ErrorKind = Failure["kind"] | "invalid_input" | "internal" | "unexpected_shape" | "radars";
// radars: exposure_radar's per-radar failures, when more than one request was made.
type ErrorInfo = { kind: ErrorKind; path: string | null; status: number | null; message: string; radars?: RadarFailure[] };
type Envelope = {
  state: State;
  measured_at: string | null;
  method: string | null;
  coverage: Record<string, unknown> | null;
  freshness: Record<string, unknown> | null;
  notes: string[];
  // cve_exposure only: the note's exposure_state, as a field.
  exposure_state?: CVEExposureState | null;
};

// A note, one sentence per entry. Sentences end in ".", "!" or "?" before whitespace, so a URL,
// a version or a field path (observed.total, crt.sh) does not split one.
export const sentences = (t: string): string[] =>
  t
    .replace(/\s+/g, " ")
    .trim()
    .split(/(?<=[.!?])\s+/)
    .filter(Boolean);
// A timestamp worth relaying as one: see realInstant below.
export const instantOrNull = (s: string | undefined): string | null => (realInstant(s) ? s : null);

// One sentence per failure kind: where we looked, for what, and what came back.
export function describeFailure(f: Failure): string {
  const verb = f.method ?? "GET";
  const where = `from ${SHOWN_BASE} for ${verb} ${f.path}`;
  switch (f.kind) {
    case "network":
      return `EchelonGraph at ${SHOWN_BASE} could not be reached for ${verb} ${f.path}: ${f.detail}.`;
    case "timeout":
      return `EchelonGraph at ${SHOWN_BASE} did not answer ${verb} ${f.path} within ${f.timeoutMs ?? TIMEOUT_MS} ms.`;
    case "http":
      return `EchelonGraph answered HTTP ${f.status} ${where} — the API said: ${f.detail}.`;
    case "not_json":
      return `EchelonGraph answered HTTP ${f.status} ${where} but the body was not JSON (${f.detail}).`;
    case "not_object":
      return `EchelonGraph answered HTTP ${f.status} ${where} but the body was not a JSON object (${f.detail}).`;
    case "unexpected_shape":
      return `EchelonGraph answered HTTP ${f.status} ${where}, but ${f.detail}.`;
  }
}

// What a model must not conclude from a failure.
export const NOT_A_FINDING =
  "The lookup did not complete, so this is not a finding: do not report it as zero, none found, absent, or unexposed. Retry later or check ECHELONGRAPH_API_BASE.";
// A 404 is the one non-2xx that carries an answer of its own — the API's not-found message,
// quoted in the sentence before it — so it is worded as "no record", not as an outage.
const NO_RECORD =
  "The API returned no record for this request; the quoted message is the API's own explanation. This says nothing about internet exposure.";
// A 400 is the API refusing the input itself, so nothing was looked up and nothing measured.
// It is tagged invalid_input, the same state a request this server refuses locally carries.
const INVALID_INPUT = "(state: invalid_input)";
const REJECTED_INPUT =
  "The API rejected the request as invalid input, so nothing was looked up: this is not a finding. Do not report it as zero, none found, or unexposed; correct the input and retry.";

// The envelope as a text block (#2440), so a client that passes only `content` to the model
// still sees how the answer was measured: structuredContent serialized as JSON, less what an
// earlier text block already carries verbatim (#2467). 2.1.0 sent the whole envelope without
// `data`, so every note went out twice, once as prose and once as the notes array, and
// cve_exposure's method a third time.
//   data    left out: content[0] carries it, verbatim up to DATA_TEXT_BUDGET and past it cut,
//           with the note saying what the cut leaves out (TEXT CUT, #2783).
//   notes   only the envelope's own sentences (`own`), which no text block says; the rest of
//           structuredContent's notes are the sentences of `said`, the text block just before
//           this one (the note, or a failure's message). Left out when there are none.
//   method  left out when `said` quotes it verbatim (cve_exposure's note, "Method: …").
// Every other key is copied as is, in structuredContent's order, so the text blocks together are
// the whole of structuredContent, but for what a TEXT CUT leaves out of data, which the note names,
// and cannot disagree with it (#2802).
const envelopeText = (structured: Record<string, unknown>, said: string, own: readonly string[]): Text => {
  const envelope: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(structured)) {
    if (k === "data") continue;
    if (k === "notes") {
      if (own.length) envelope.notes = own;
    } else if (!(k === "method" && typeof v === "string" && said.includes(v))) envelope[k] = v;
  }
  return text(JSON.stringify(envelope, null, 2));
};

// A failure result: the #1874 text, and an envelope saying nothing was measured, in
// structuredContent and again as the last text block. The error quotes only what
// describeFailure already quotes (a redacted cause, the API's own message). Every note is a
// sentence of the message, so the text envelope carries none.
export const failure = (state: "failed" | "invalid_input", message: string, error: ErrorInfo, coverage: Record<string, unknown> | null = null): ToolResult => {
  const structuredContent = { state, measured_at: null, method: null, coverage, freshness: null, notes: sentences(message), error };
  return { content: [text(message), envelopeText(structuredContent, message, [])], structuredContent, isError: true };
};
const errorOf = (f: Failure): ErrorInfo => ({ kind: f.kind, path: f.path, status: f.status ?? null, message: f.detail });

export const failed = (tool: string, f: Failure): ToolResult => {
  if (f.kind === "http" && f.status === 400) {
    return failure("invalid_input", `${tool} FAILED ${INVALID_INPUT}: ${describeFailure(f)} ${REJECTED_INPUT}`, errorOf(f));
  }
  return failure("failed", `${tool} FAILED: ${describeFailure(f)} ${f.kind === "http" && f.status === 404 ? NO_RECORD : NOT_A_FINDING}`, errorOf(f));
};

export const badInput = (tool: string, why: string): ToolResult =>
  failure("invalid_input", `${tool} FAILED ${INVALID_INPUT}: ${why}. Nothing was looked up, so this is not a finding.`, {
    kind: "invalid_input",
    path: null,
    status: null,
    message: why,
  });

// A bug in this server is still not a finding — it must never surface as an empty success.
export const crashed = (tool: string, e: unknown): ToolResult =>
  failure("failed", `${tool} FAILED inside the MCP server while querying ${SHOWN_BASE}: ${describeError(e)}. ${NOT_A_FINDING}`, {
    kind: "internal",
    path: null,
    status: null,
    message: describeError(e),
  });

// A 2xx whose fields do not match the tool's outputSchema (a field of a type the schema does
// not allow) cannot be relayed as structuredContent: a client validates it against the schema
// and rejects it. So it is a failure, worded as one, rather than the SDK's bare validation error.
function unexpectedShape(tool: string, error: z.ZodError): ToolResult {
  const issues = error.issues
    .slice(0, 3)
    .map((i) => `${i.path.map(String).join(".") || "(root)"}: ${i.message}`)
    .join("; ");
  const detail = `the answer did not match this tool's output schema (${issues})`;
  return failure("failed", `${tool} FAILED: EchelonGraph at ${SHOWN_BASE} answered, but ${detail}, so it is not relayed. ${NOT_A_FINDING}`, {
    kind: "unexpected_shape",
    path: null,
    status: null,
    message: detail,
  });
}

// Every success is checked against the tool's own outputSchema before it is returned.
export const checked = (tool: string, schema: z.ZodType, r: ToolResult): ToolResult => {
  if (r.isError) return r;
  const p = schema.safeParse(r.structuredContent);
  return p.success ? r : unexpectedShape(tool, p.error);
};

// A success: content[0] is the data (cut to DATA_TEXT_BUDGET when it is larger, #2783), content[1]
// the note, content[2] the envelope less both; the envelope carries both, the note as sentences
// after any the envelope adds about itself. structuredContent.data is the data whole.
export const succeeded = (data: object, note: string, env: Omit<Envelope, "notes"> & { notes?: string[] }, cut?: TextCut): ToolResult => {
  const own = env.notes ?? [];
  const shown = dataText(data, cut);
  const said = shown.said ? `${note} ${shown.said}` : note;
  const structuredContent = { ...env, notes: [...own, ...sentences(said)], data };
  return { content: [text(shown.text), text(said), envelopeText(structuredContent, said, own)], structuredContent };
};
export const okHead = (tool: string, status?: number) =>
  `${tool} OK: EchelonGraph answered${status === undefined ? "" : ` HTTP ${status}`} from ${SHOWN_BASE}.`;

// Tolerant readers for the note: a missing or renamed field degrades the sentence, never
// the result — content[0] still carries whatever the API sent.
export const field = (o: unknown, ...keys: string[]): unknown =>
  keys.reduce<unknown>((v, k) => (v !== null && typeof v === "object" ? (v as Record<string, unknown>)[k] : undefined), o);
export const numAt = (o: unknown, ...keys: string[]): number | undefined => {
  const v = field(o, ...keys);
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
};
export const strAt = (o: unknown, ...keys: string[]): string | undefined => {
  const v = field(o, ...keys);
  return typeof v === "string" && v ? v : undefined;
};
export const lenAt = (o: unknown, ...keys: string[]): number | undefined => {
  const v = field(o, ...keys);
  return Array.isArray(v) ? v.length : undefined;
};
export const boolAt = (o: unknown, ...keys: string[]): boolean | undefined => {
  const v = field(o, ...keys);
  return typeof v === "boolean" ? v : undefined;
};
// A timestamp worth repeating as prose. The API has been seen answering the Go zero time
// (0001-01-01T00:00:00Z) where it had no instant to give; that is not a time, so it is never
// presented as one.
export const realInstant = (s: string | undefined): s is string => s !== undefined && Date.parse(s) > 0;

// ── The CVE feed tools: cve_summary, search_cves, get_cve ──
//
// Their numbers are CVE records and scores, not exposure counts, so a success is measured.
// measured_at is the time the answer itself gives for its records, where it gives one:
// summary.last_updated (MAX(modified) over the active records, core-backend cve/store.go
// Summary) for cve_summary, the record's updated_at (when EchelonGraph last wrote it) for
// get_cve, and none for a search page, whose rows each carry their own. None of them serves a
// fleet-wide time at which the feed's pollers last completed, so freshness is null: the
// summary's poller.last_poll_at is the answering instance's own NVD poller (cve/poller.go
// Stats, in memory), and is relayed in data but not presented as the feed's freshness; the note
// says what the whole poller block is (summaryPollerNote, #2647).
const CVE_FEED_METHOD =
  "EchelonGraph's CVE Pulse feed: CVE records compiled from NVD, MITRE-CNA pre-NVD records, CISA-KEV, EPSS and GitHub GHSA, each polled from its source on a schedule.";
const NO_FEED_FRESHNESS =
  "freshness is null: the CVE feed's answer carries no time at which its pollers last completed a poll for the feed as a whole.";

// ── The EchelonGraph score, and score_assessed (#2535) ──
//
// score_assessed is what makes echelongraph_score readable (core-backend cve/store.go, the CVE
// struct's ScoreAssessed, migration 097). true: EchelonGraph scored the CVE. false: it could not,
// and the scorer's echelongraph_score is 0 as a PLACEHOLDER, not a rating (cve/scoring/scorer.go
// Output.Assessed: no real assessment has scored below 0.4, so a 0 is always an absence). The
// fields derived from the score hold placeholders too: echelongraph_severity NONE and
// echelongraph_risk 0, beside score_confidence NONE and a score_rationale saying no assessment is
// available (scorer.go Rule 0 and Rule 7). store.go scanFullCVE, which both endpoints these tools
// call marshal through, withholds echelongraph_score, echelongraph_severity and echelongraph_risk
// on the FLAG, never on the value (#1106, #1949); an API before those sent the placeholders, and 0
// is the bottom of every sort. score_unassessed_reason says why: no_signal (no source has
// published severity data yet, so the CVE is revisited when one does) or rejected (the record was
// withdrawn by its numbering authority, and is never scored). The API never omits score_assessed,
// so an answer without it comes from an API older than migration 097.
//
// A model handed echelongraph_score 0 reports "EG score 0, no risk", which is how CVE-2026-41566
// was indexed as "EG 0.0" before it was scored. So the note labels each CVE whose answer says
// score_assessed false, per CVE for get_cve and per row for search_cves: NOT YET SCORED, or NOT
// SCORED for a rejected record, which never will be. A CVE whose answer carries no score_assessed
// is labelled as one the answer does not say about. An assessed CVE's note is unchanged.
//
// The JSON is relayed as the API sent it, placeholders included: nothing is rewritten. The file
// rewrites a not-assessed value in one place only, exposure_radar's newest_kev (newestKEVRow),
// because that tool relays its own cut of each answer and its description says so. A tool that
// relays the API's JSON verbatim labels instead, as cve_exposure labels a 0 outside the radar's
// tracked set (exposure_state), and these two do the same.
type ScoreState = "assessed" | "not_assessed" | "unstated";
function scoreStateOf(rec: unknown): ScoreState {
  const v = boolAt(rec, "score_assessed");
  return v === true ? "assessed" : v === false ? "not_assessed" : "unstated";
}
const scoreRejected = (rec: unknown): boolean => strAt(rec, "score_unassessed_reason") === "rejected";
// The fields that hold a placeholder, not a score, on a CVE that is not scored.
const PLACEHOLDER_FIELDS = ["echelongraph_score", "echelongraph_severity", "echelongraph_risk"] as const;
// No sentence below writes a digit: a note that says "0" beside "score" is the defect itself.
const UNSTATED_SCORE =
  "echelongraph_score is EchelonGraph's score only when score_assessed is true, so a zero echelongraph_score there is not a rating: it can be the placeholder a CVE not yet scored carries.";

// get_cve's sentences about the one CVE's score, each starting with a space; none when the
// answer says the CVE is scored.
function cveScoreNote(cve: string, rec: object): string {
  const state = scoreStateOf(rec);
  if (state === "assessed") return "";
  if (state === "unstated") {
    return ` The answer does not say whether EchelonGraph has scored ${cve}: it carries no score_assessed (an API older than that field sends none). ${UNSTATED_SCORE}`;
  }
  const rejected = scoreRejected(rec);
  const reportAs = rejected ? "not scored" : "not yet scored";
  const head = rejected
    ? ` (score_assessed: false) NOT SCORED: the record of ${cve} was rejected (withdrawn) by its numbering authority (score_unassessed_reason rejected), and EchelonGraph does not score a withdrawn record, so the record holds no EchelonGraph score for it.`
    : ` (score_assessed: false) NOT YET SCORED: EchelonGraph has not yet scored ${cve}, so the record holds no EchelonGraph score for it, and the absence of one does not mean ${cve} is harmless.`;
  const why = strAt(rec, "score_unassessed_reason") === "no_signal" ? " score_unassessed_reason is no_signal: no source has yet published severity data EchelonGraph can score." : "";
  const carried = PLACEHOLDER_FIELDS.filter((k) => field(rec, k) !== undefined && field(rec, k) !== null);
  const placeholders = carried.length
    ? ` ${listed(carried)} ${carried.length === 1 ? "is a placeholder" : "are placeholders"}, not a score: report ${cve} as ${reportAs}, and do not repeat ${carried.length === 1 ? "that value" : "those values"} as its score.`
    : ` Report ${cve} as ${reportAs}, not as a zero or low score.`;
  return `${head}${why}${placeholders}`;
}

// search_cves' sentences about its rows' scores, naming each row a sentence is about, each
// starting with a space; none when every row says it is scored.
export function rowsScoreNote(d: object): string {
  const rows = field(d, "cves");
  if (!Array.isArray(rows) || rows.length === 0) return "";
  const n = rows.length;
  const ids = (pred: (r: unknown) => boolean): string[] => rows.flatMap((r, i) => (pred(r) ? [strAt(r, "cve_id") ?? `cves[${i}]`] : []));
  const notYet = ids((r) => scoreStateOf(r) === "not_assessed" && !scoreRejected(r));
  const rejected = ids((r) => scoreStateOf(r) === "not_assessed" && scoreRejected(r));
  const unstated = ids((r) => scoreStateOf(r) === "unstated");
  const of = (k: number): string => (k < n ? `${k} of the ${n} CVEs in this page` : n === 1 ? "the 1 CVE in this page" : `all ${n} CVEs in this page`);
  const out: string[] = [];
  if (notYet.length) {
    out.push(
      `(score_assessed: false) NOT YET SCORED: ${of(notYet.length)} ${be(notYet.length)} not yet scored by EchelonGraph: ${listed(notYet)}. For each, echelongraph_score, echelongraph_severity and echelongraph_risk, where its row carries them, are placeholders, not a score, and the absence of a score does not mean the CVE is harmless: report each as not yet scored, not as a zero or low score.`,
    );
  }
  if (rejected.length) {
    out.push(
      `(score_assessed: false) NOT SCORED: ${of(rejected.length)} ${rejected.length === 1 ? "has a record" : "have records"} rejected (withdrawn) by the numbering authority (score_unassessed_reason rejected), which EchelonGraph does not score: ${listed(rejected)}. For each, echelongraph_score, echelongraph_severity and echelongraph_risk, where its row carries them, are placeholders, not a score: report each as not scored.`,
    );
  }
  if (unstated.length) {
    out.push(
      `The answer does not say whether EchelonGraph has scored ${of(unstated.length)}: ${listed(unstated)} (no score_assessed in ${unstated.length === 1 ? "its row" : "their rows"}; an API older than that field sends none). ${UNSTATED_SCORE}`,
    );
  }
  return out.map((s) => ` ${s}`).join("");
}

// ── summary.none, the not-yet-scored bucket (#2610) ──
//
// core-backend cve/store.go Summary buckets the active CVEs on effectiveSeverityExpr: the
// EchelonGraph band, else NVD's, else the CVSS v2 band, else NONE, where a band of NONE or UNKNOWN
// counts as none. So summary.none counts the CVEs with no severity band from any source, and the
// store sends the same number again as summary.unscored (CVESummary: "the residual band-less
// bucket … numerically identical to None"; Critical+High+Medium+Low+Unscored == Total). It is not
// a count of CVEs rated severity None, but a model handed "counts by severity … none" reports
// "3,381 CVEs rated None" (production on 2026-09-30: none 3,381, unscored 3,381). The JSON is
// relayed as sent; the note says what the count is whenever it is above zero, and names
// summary.unscored as the same count when the answer carries it equal. A zero is not labelled:
// there is no CVE in it to misreport.
function summaryNoneNote(d: object): string {
  const none = numAt(d, "summary", "none");
  if (none === undefined || none <= 0) return "";
  const unscored = numAt(d, "summary", "unscored");
  const same = unscored === none ? ` summary.unscored (${unscored}) is the same count under its own name.` : "";
  return ` summary.none (${none}) is not a severity rating of None: it counts the active CVEs with no severity band from any source, that is, CVEs not yet scored.${same} Report them as not yet scored, not as CVEs rated None.`;
}

// ── summary.nvd_*, NVD's label, and summary.rejected (#2641) ──
//
// core-backend cve/store.go Summary sends a second histogram beside the first: nvd_critical,
// nvd_high, nvd_medium, nvd_low and nvd_none bucket the same active CVEs on the records' own
// `severity` column instead of effectiveSeverityExpr. That column holds NVD's CVSS label (v3.1, else
// v3.0, else v4.0: cve/poller.go). Before NVD's record arrives it holds a pre-NVD label, the CVE.org
// record's (cve/mitre/convert.go) or a GitHub advisory's (vendoradv SeedStubCVEFromAdvisory), and
// where NVD's record gives none, CISA's Vulnrichment v4 label can fill it (vulnrichment/backfill.go).
// nvd_none counts every active CVE whose label there is none of CRITICAL, HIGH, MEDIUM or LOW.
// CVESummary's own comment says to render it "as provenance, never as a rating", and nvd_none is
// large by design: #1107 measured that the feed holds NVD's own CVSS v2 score for 72,359 of them.
// So nvd_none is not a count of CVEs rated None, and not the count of CVEs with no severity, which
// is summary.none. rejected is COUNT(*) of the rows whose vuln_status is REJECTED: records withdrawn
// by their numbering authority, outside the active rows that total and both histograms count.
// Through 2.3.3 the tool relayed all six fields with no word about any of them, and a model handed
// nvd_none 75,962 beside a note about summary.none 3,408 (production, 2026-09-30) reports "75,962
// CVEs rated None". The JSON is relayed as sent. As for summary.none, the note says what nvd_none
// and rejected count, with the answer's own numbers, whenever each is above zero (a zero has no CVE
// in it to misreport); it says the five nvd_ counts add up to summary.total only when the answer's
// do; and an answer without the fields (an API older than them) gets no sentence about them.
const NVD_HISTOGRAM = ["nvd_critical", "nvd_high", "nvd_medium", "nvd_low", "nvd_none"] as const;
function summaryNVDNote(d: object): string {
  const nvdNone = numAt(d, "summary", "nvd_none");
  if (nvdNone === undefined || nvdNone <= 0) return "";
  const counts = NVD_HISTOGRAM.map((k) => numAt(d, "summary", k));
  const total = numAt(d, "summary", "total");
  const present = NVD_HISTOGRAM.filter((_, i) => counts[i] !== undefined).map((k) => `summary.${k}`);
  const adds = total !== undefined && counts.every((n) => n !== undefined) && counts.reduce<number>((a, n) => a + (n ?? 0), 0) === total;
  const histogram = adds
    ? ` ${listed(present)} add up to summary.total (${total}): the same active CVEs, counted by NVD's severity label as provenance, not by EchelonGraph's severity.`
    : ` ${listed(present)} ${present.length === 1 ? "counts" : "count"} active CVEs by NVD's severity label, as provenance, not by EchelonGraph's severity.`;
  return `${histogram} summary.nvd_none (${nvdNone}) is not a count of CVEs rated None, nor of CVEs with no severity: it counts the active CVEs with no Critical, High, Medium or Low CVSS label from NVD (v3.x, else v4.0) or a pre-NVD record, many of them with an NVD CVSS v2 score instead. Report them as CVEs without an NVD severity label, not as CVEs rated None or as CVEs not yet scored.`;
}
function summaryRejectedNote(d: object): string {
  const rejected = numAt(d, "summary", "rejected");
  if (rejected === undefined || rejected <= 0) return "";
  return ` summary.rejected (${rejected}) counts CVE records rejected (withdrawn) by their numbering authority, not active CVEs: report them as withdrawn records, never as vulnerabilities.`;
}

// ── poller, one instance's counters (#2647) ──
//
// The summary answer carries a poller block beside summary: cves_ingested, cves_skipped,
// http_retries, interval, last_poll_at, last_poll_dur_ms, poll_count and poll_errors. They are
// core-backend cve/poller.go Stats: the in-memory counters of the NVD poller of the ONE API
// instance that answered, since that instance last started, and every restart zeroes them. So
// cves_ingested 7195 (production, 2026-09-30T10:02:13Z) is what that instance ingested since it
// started, not the feed's size or intake, and poll_errors is not the feed's reliability. Through
// 2.6.1 the tool relayed the block with no word about it. The JSON is still relayed as sent; the
// outputSchema describes the block, and whenever the answer carries one the note says what it is,
// with the counters a model would quote, and an answer without it gets no sentence.
const POLLER_QUOTED = ["cves_ingested", "poll_count", "poll_errors"] as const;
function summaryPollerNote(d: object): string {
  const poller = field(d, "poller");
  if (!isPlainObject(poller) || Object.keys(poller).length === 0) return "";
  const quoted = POLLER_QUOTED.flatMap((k) => {
    const n = numAt(poller, k);
    return n === undefined ? [] : [`poller.${k} ${n}`];
  });
  const counters = quoted.length > 0 ? ` (${quoted.join(", ")})` : "";
  return ` poller is one API instance's NVD poller, counted in that instance's memory since it last started and zeroed on every restart: report its counters${counters} as that instance's, never as the feed's size, intake or reliability, and poller.last_poll_at as that instance's last poll, never as the feed's freshness.`;
}

// ── poller's JSON types, never a reason to withhold summary (#2771) ──
//
// 2.6.2 typed poller's eight fields in the outputSchema (CVE_SUMMARY_OUTPUT), and every success
// goes through checked(), so one counter core-backend sent in another JSON type failed the whole
// call and withheld summary.total: cve/poller.go Stats returns a map[string]interface{}, so
// emitting interval as a time.Duration (1200000000000) instead of interval.String() compiles.
// The block is one instance's diagnostics, never the feed's, so it degrades on its own: a field of
// another type is left out of data and named in the note, a poller that is neither a JSON object
// nor null (an array, a string) is left out whole and named, and summary and the rest of the
// answer are relayed as sent. What the schema allows is kept as sent: null for a field (opt), null
// or an empty object for the block, and keys this version does not know. Installed 2.6.2 and
// 2.6.3 copies still fail on such a change, so core-backend's cve/poller_stats_wire_test.go pins
// Stats()'s eight keys to these JSON types.
const SUMMARY_POLLER_KINDS = {
  cves_ingested: "number",
  cves_skipped: "number",
  http_retries: "number",
  interval: "string",
  last_poll_at: "string",
  last_poll_dur_ms: "number",
  poll_count: "number",
  poll_errors: "number",
} as const;
type PollerField = keyof typeof SUMMARY_POLLER_KINDS;
const pollerField = (k: PollerField, description: string) => opt(SUMMARY_POLLER_KINDS[k] === "number" ? z.number() : z.string()).describe(description);
const jsonKind = (v: unknown): string =>
  v === null ? "null" : Array.isArray(v) ? "an array" : typeof v === "object" ? "an object" : typeof v === "number" ? "a number" : typeof v === "boolean" ? "a boolean" : typeof v === "string" ? "a string" : typeof v;
function summaryPollerShaped(d: object): { data: object; note: string } {
  const poller = field(d, "poller");
  if (poller === undefined || poller === null) return { data: d, note: "" };
  const relayed = " The rest of the answer, summary with it, is relayed as sent.";
  if (!isPlainObject(poller)) {
    const { poller: _dropped, ...rest } = d as Record<string, unknown>;
    return { data: rest, note: ` poller was left out of the data above because the answer sent it as ${jsonKind(poller)}, where this tool reads an object.${relayed}` };
  }
  const unusable = (Object.keys(SUMMARY_POLLER_KINDS) as PollerField[]).filter((k) => {
    const v = poller[k];
    if (v === undefined || v === null) return false;
    return SUMMARY_POLLER_KINDS[k] === "number" ? !isCount(v) : typeof v !== "string";
  });
  if (unusable.length === 0) return { data: d, note: "" };
  const kept = Object.fromEntries(Object.entries(poller).filter(([k]) => !(unusable as string[]).includes(k)));
  const named = unusable.map((k) => `poller.${k} (${jsonKind(poller[k])}, where this tool reads ${SUMMARY_POLLER_KINDS[k] === "number" ? "a number" : "a string"})`);
  return {
    data: { ...d, poller: kept },
    note: ` Left out of the data above because the answer sent ${unusable.length === 1 ? "it" : "them"} in a JSON type other than the one this tool reads: ${listed(named)}.${relayed}`,
  };
}

async function cveSummary(): Promise<ToolResult> {
  const tool = "cve_summary";
  try {
    const r = await api("/api/v1/public/cves/summary");
    if (!r.ok) return failed(tool, r);
    const head = okHead(tool, r.status);
    // #2771: a poller field of another JSON type is left out, never a failure of the call.
    const { data, note: pollerShape } = summaryPollerShaped(r.data);
    const updated = strAt(data, "summary", "last_updated");
    const env = {
      state: "measured" as const,
      measured_at: instantOrNull(updated),
      method: CVE_FEED_METHOD,
      coverage: null,
      freshness: null,
      notes: [
        realInstant(updated)
          ? "measured_at is summary.last_updated: the newest modification time among the active CVE records these counts include."
          : "measured_at is null: the answer carries no real summary.last_updated.",
        NO_FEED_FRESHNESS,
      ],
    };
    const total = numAt(data, "summary", "total");
    // What summary.none (#2610), the NVD histogram and summary.rejected (#2641) count, what the
    // poller block is (#2647), and what of it was left out (#2771).
    const labels = `${summaryNoneNote(data)}${summaryNVDNote(data)}${summaryRejectedNote(data)}${summaryPollerNote(data)}${pollerShape}`;
    if (total === undefined) return succeeded(data, `${head}${labels}`, env);
    if (total === 0) {
      return succeeded(data, `${head} The feed reports 0 active CVEs — a measured empty result (we looked and found nothing), not a lookup failure.${labels}`, env);
    }
    // A stamp that is not a real instant stays in the JSON and is not repeated as prose.
    const stamp = realInstant(updated) ? ` (last updated ${updated})` : "";
    return succeeded(data, `${head} The feed holds ${total} active CVEs${stamp}.${labels}`, env);
  } catch (e) {
    return crashed(tool, e);
  }
}

// search_cves' coverage is the list answer's own account of itself (core-backend cve/handler.go
// ListCVEs): total, and whether it was counted (total_counted false: no count is in hand and
// total means nothing) or is a floor (total_is_lower_bound); search_relaxed, true when a phrase
// was relaxed to all of its words so the rows are a superset of the phrase's; and the limit and
// offset the page was built with. An older API sends none of the three flags, and null says so.
type SearchArgs = { search?: string; severity?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"; min_cvss?: number; sort?: string; limit?: number; offset?: number };
// #2783: a page of production rows is about 6,600 characters a row as pretty JSON (38 fields, the
// description, cpe_match, references and score_factors among them), so the default page of 20 was
// 133,300 characters of text. Past DATA_TEXT_BUDGET each row in the first text block keeps the
// fields the description promises and a few more a triage reads, the description cut to 200
// characters; then, for a page of 50, the fields the description promises with the description cut
// to 100. structuredContent.data keeps every field of every row; get_cve returns one record, whole in
// its structuredContent.data and in its own first text block with every field (its lists cut past
// the budget, #2802).
const SEARCH_CVES_TEXT: TextCut = {
  rows: "cves",
  levels: [
    {
      keep: ["cve_id", "description", "severity", "cvss_v3_score", "echelongraph_score", "echelongraph_severity", "echelongraph_risk", "score_assessed", "score_unassessed_reason", "epss_score", "kev_listed", "kev_ransomware", "published", "vuln_status", "patch_available", "exploit_poc_available"],
      clip: 200,
    },
    { keep: ["cve_id", "description", "severity", "cvss_v3_score", "echelongraph_score", "score_assessed", "score_unassessed_reason", "epss_score", "kev_listed", "published"], clip: 100 },
  ],
  whole: `${GET_CVE_WHOLE}.`,
  page: (shown, _rows, d) =>
    `To read the rows left out in the text, call search_cves again with the same arguments and offset ${(numAt(d, "offset") ?? 0) + shown}; a page of ${shown} rows or fewer like these fits the text without leaving rows out.`,
};
async function searchCVEs(a: SearchArgs): Promise<ToolResult> {
  const tool = "search_cves";
  try {
    // #1983: the free-text search travels percent-encoded in X-EG-Search, never in the URL. Cloud
    // Run keeps every request URL in its trace spans for 30 days and no request header; core-backend
    // (cve/handler.go listSearchTerm) reads the header first and decodes it with url.PathUnescape.
    const q = new URLSearchParams();
    if (a.severity) q.set("severity", a.severity);
    if (a.min_cvss !== undefined) q.set("min_cvss", String(a.min_cvss));
    if (a.sort) q.set("sort", a.sort);
    q.set("limit", String(a.limit ?? 20));
    if (a.offset) q.set("offset", String(a.offset));
    const r = await api(`/api/v1/public/cves?${q.toString()}`, a.search ? { headers: { "X-EG-Search": encodeURIComponent(a.search) } } : undefined);
    if (!r.ok) return failed(tool, r);
    const head = okHead(tool, r.status);
    const shown = lenAt(r.data, "cves");
    const counted = boolAt(r.data, "total_counted");
    const floor = boolAt(r.data, "total_is_lower_bound");
    const relaxed = boolAt(r.data, "search_relaxed");
    const offset = numAt(r.data, "offset");
    const env = {
      state: "measured" as const,
      measured_at: null,
      method: CVE_FEED_METHOD,
      coverage: {
        total: numAt(r.data, "total") ?? null,
        total_counted: counted ?? null,
        total_is_lower_bound: floor ?? null,
        search_relaxed: relaxed ?? null,
        returned: shown ?? null,
        limit: numAt(r.data, "limit") ?? null,
        offset: offset ?? null,
      },
      freshness: null,
      notes: [
        "measured_at is null: a page of search results has no single observation time; each CVE record in data.cves carries its own times where the API sends them.",
        NO_FEED_FRESHNESS,
      ],
    };
    const relaxedNote =
      relaxed === true
        ? " The API relaxed the search phrase to all of its words (search_relaxed is true), so these rows are a superset of the rows that match the phrase itself."
        : "";
    // Then what each row's score is (#2535): empty when every row says it is scored, or there
    // are no rows.
    const tail = `${relaxedNote}${rowsScoreNote(r.data)}`;
    // A total the API did not count is not a count: the page's own rows are all that is known.
    if (counted === false) {
      const empty = shown === 0 && (offset ?? 0) === 0;
      return succeeded(
        r.data,
        empty
          ? `${head} The query returned 0 CVEs — a measured empty result: EchelonGraph was queried successfully and nothing matched these filters (we looked and found nothing). This is not a lookup failure.${tail}`
          : `${head} The API did not count the matches (total_counted is false), so its total is not a count${shown === undefined ? "" : `; ${shown} returned in this page`}.${tail}`,
        env,
        SEARCH_CVES_TEXT,
      );
    }
    const total = numAt(r.data, "total") ?? shown;
    if (total === undefined) return succeeded(r.data, `${head}${tail}`, env, SEARCH_CVES_TEXT);
    if (total === 0 && floor !== true) {
      return succeeded(r.data, `${head} The query matched 0 CVEs — a measured empty result: EchelonGraph was queried successfully and nothing matched these filters (we looked and found nothing). This is not a lookup failure.${tail}`, env, SEARCH_CVES_TEXT);
    }
    const matched = floor === true ? `at least ${total} CVEs (total_is_lower_bound is true: the count stopped at that floor)` : `${total} CVEs`;
    return succeeded(r.data, `${head} The query matched ${matched}${shown === undefined ? "" : `; ${shown} returned in this page`}.${tail}`, env, SEARCH_CVES_TEXT);
  } catch (e) {
    return crashed(tool, e);
  }
}

// #2720: cpe_configurations is NVD's configuration tree, stored since migration 152 and filled
// as the NVD poller next writes each CVE, so an answer without it is "not stored", never "no
// product affected". Said in the envelope's own notes, so the note in content[1] is unchanged.
function cpeConfigurationsNote(rec: object): string {
  const cfg = field(rec, "cpe_configurations");
  if (Array.isArray(cfg)) {
    return `cpe_configurations is NVD's configurations array as sent (${cfg.length}): a cpeMatch with vulnerable false in an AND configuration is a platform, not an affected product.`;
  }
  return "No cpe_configurations in the answer: EchelonGraph holds no stored NVD configuration tree for this CVE, which does not mean no product is affected; cpe_match lists its CPE criteria flattened, without the AND/OR operators.";
}

async function getCVE(cve_id: string): Promise<ToolResult> {
  const tool = "get_cve";
  const id = cve_id.trim();
  if (!id) return badInput(tool, "cve_id is required");
  try {
    const r = await api(`/api/v1/public/cves/${encodeURIComponent(id)}`);
    if (!r.ok) return failed(tool, r);
    const written = strAt(r.data, "updated_at");
    const cve = strAt(r.data, "cve_id") ?? id;
    return succeeded(r.data, `${okHead(tool, r.status)} Returned the record for ${cve}.${cveScoreNote(cve, r.data)}`, {
      state: "measured",
      measured_at: instantOrNull(written),
      method: CVE_FEED_METHOD,
      coverage: null,
      freshness: null,
      notes: [
        realInstant(written)
          ? "measured_at is the record's updated_at: when EchelonGraph last wrote this record."
          : "measured_at is null: the record carries no real updated_at.",
        NO_FEED_FRESHNESS,
        cpeConfigurationsNote(r.data),
      ],
    });
  } catch (e) {
    return crashed(tool, e);
  }
}

// cve_exposure. What the API's footprint means, and what it does not (#2306, #2307).
//
// The counts come from the KEV-exposure radar, which does not look at every CVE: every 12 h,
// when Shodan query credits allow (the poller skips the search below SHODAN_MIN_QUERY_BUDGET),
// it runs one Shodan query per tracked product and keeps services whose banner version maps
// to a CISA-KEV or high-EPSS CVE. So a 0 is only a measurement when the CVE is inside that
// tracked set. The unit is a service, not a machine: the radar keys each observation on
// ip:port (Shodan returns one banner per port), and exposed_hosts counts distinct ip:port.
// The API says which with `tracked`; the note reads it and, when the field is absent (an older
// API, or a CVE the radar cannot decide on), makes no claim either way about the zero.
//
// last_seen is not an observation time (#2439). It is when EchelonGraph last wrote or refreshed
// a service's row: core-backend kevexposure store.go Upsert sets it to now() when a search
// matches the banner, and Touch sets it to now() when the InternetDB re-check (poller.go
// reconcileStale) finds the service's PORT still listed, without re-reading the version. So a
// patched service can stay counted while its port stays open, and last_seen is our write time,
// not the time Shodan saw the service: on 2026-09-27 production's 50 newest rows carried
// last_seen within 0.78 s of one another, a batch write. Shodan's own banner timestamp is not
// stored.
// Every text calls last_seen a write or refresh time, never a sighting ("last seen listening",
// "re-seen", "most recently seen"), and it is never measured_at (see observedAt).
export const CVE_ID = /^CVE-\d{4}-\d{4,}$/i;
// Quoted when the API does not send its own `method` string.
const EXPOSURE_METHOD =
  "Shodan banner match on the radar's tracked products; up to 100 ip:port services per product query; searched every 12 h when Shodan query credits allow";
const SHODAN_ATTRIBUTION = "Exposure counts are derived from Shodan data.";
// Shodan's terms (https://static.shodan.io/legal/terms.html, read 2026-09-27) ask for two
// things: "You must attribute such usage to Shodan", and materials "referencing, including or
// otherwise based on Shodan information or materials, must clearly indicate Shodan's ownership
// and copyright in the applicable Shodan materials" (#2306). The attribution above does the
// first; this sentence, placed beside it wherever Shodan data is named, does the second.
const SHODAN_OWNERSHIP = "Shodan data is owned by Shodan, which holds its copyright (© Shodan).";

const CVE_EXPOSURE_DESCRIPTION = `Internet-exposure footprint for one CVE from EchelonGraph's KEV-exposure radar: how many internet-facing services (distinct ip:port, returned as exposed_hosts; a machine answering on two ports counts twice) the radar has on record running a version its CVE matcher maps to this CVE, with a country/product breakdown and a ransomware flag. Aggregate and host-redacted; free and keyless. Method: exposure counts are derived from Shodan data. ${SHODAN_OWNERSHIP} Every 12 h, when Shodan query credits allow, the radar runs one Shodan query per tracked product, reads up to 100 ip:port services per query, and keeps a service when its banner version matches a CISA-KEV or high-EPSS CVE; a service whose row has not been written or refreshed for 21 days is dropped. last_seen is when EchelonGraph last wrote or refreshed a service's row, not when the service was observed and not when its vulnerable version was last confirmed: it is set to the time of the write when a search matches the banner, and again when a re-check finds the port still listed by Shodan InternetDB, without re-reading the banner, so a patched service can stay counted while its port stays open. A count is therefore a banner-version inference over a sample, not an exploit test and not an internet-wide census. The radar only looks for its tracked set of CVEs: for a CVE outside that set the note says NOT ASSESSED (exposure_state not_assessed), and its 0 is not a measurement.`;

function exposureNote(head: string, id: string, d: object): string {
  const cve = strAt(d, "cve_id") ?? id;
  const hosts = numAt(d, "exposed_hosts");
  const tracked = boolAt(d, "tracked");
  // The API's own method sentence may end in a full stop; the note supplies one.
  const how = `Method: ${(strAt(d, "method") ?? EXPOSURE_METHOD).replace(/[.\s]+$/, "")}. ${SHODAN_ATTRIBUTION} ${SHODAN_OWNERSHIP}`;
  // Before kev_catalog_listed existed, kev_listed was bool_or over the radar's observations:
  // false for every CVE the radar has no host for, whatever the CISA-KEV catalog says.
  // kev_catalog_listed is cves.kev_listed, the flag the KEV fetcher sets on EchelonGraph's CVE
  // record. The fetcher only UPDATEs rows that already exist, and the API answers false when
  // there is no row, so false cannot be told apart from "no record": it is worded as what
  // EchelonGraph's data says, never as a fact about the CISA catalog.
  const catalog = boolAt(d, "kev_catalog_listed");
  const kev =
    catalog === undefined
      ? "Its kev_listed field reflects the radar's own observations, not the CISA-KEV catalog; use get_cve for catalog status."
      : catalog
        ? `EchelonGraph's CVE record marks ${cve} as CISA-KEV-listed.`
        : `EchelonGraph's CVE data does not mark ${cve} as CISA-KEV-listed (kev_catalog_listed is false, which it also is when EchelonGraph holds no record of ${cve}); get_cve shows the record.`;
  if (hosts === undefined) {
    return `${head} The answer carries no exposed_hosts count, so it says nothing about exposure to ${cve}. ${how}`;
  }
  if (tracked === false) {
    const why =
      hosts === 0
        ? "outside the radar's tracked set; 0 is not a measurement, and it says nothing about whether any host is exposed to it."
        : `outside the radar's tracked set, so the radar is not looking for it; the ${hosts} service(s) (distinct ip:port) on record are left from earlier scans and are not a current measurement.`;
    return `${head} (exposure_state: not_assessed) NOT ASSESSED: ${cve} is ${why} ${kev} ${how}`;
  }
  // The tag in parentheses is exposure_state, named as such (#2440): it says what the count is,
  // and is not the envelope's state, which the last text block gives.
  if (hosts === 0 && tracked === true) {
    // The backend answers tracked:true only when it holds rows (exposed_hosts > 0), so this
    // branch does not fire today; it is worded for the day it does.
    return `${head} (exposure_state: measured_zero) The radar has 0 internet-facing services (distinct ip:port) on record whose banner version maps to ${cve}: a measured zero in the radar's sample. ${cve} is in the tracked set, and the radar looked and found nothing. This is not a lookup failure. It is a zero in a sample, not an internet-wide zero: the radar reads at most the first 100 Shodan results per tracked-product query, so a vulnerable service outside those results is not counted. ${kev} ${how}`;
  }
  if (hosts === 0) {
    return `${head} (exposure_state: tracking_unknown) EchelonGraph reports 0 exposed services (distinct ip:port) on record for ${cve}. The API does not say whether ${cve} is in the radar's tracked set: it is an API older than that field, or the radar cannot decide for this CVE (for example a CISA-KEV or high-EPSS CVE in a tracked product that it has no service on record for). The radar only looks for a tracked set of CISA-KEV and high-EPSS CVEs in specific products, so this 0 is not evidence either way: it neither shows that nothing is exposed nor that ${cve} went unassessed. This is not a lookup failure. ${kev} ${how}`;
  }
  const countries = numAt(d, "countries");
  const last = strAt(d, "last_seen");
  const seen = realInstant(last)
    ? ` Their latest last_seen is ${last}: when EchelonGraph last wrote or refreshed one of their rows, not when any of them was observed and not when a vulnerable version was last confirmed.`
    : "";
  return `${head} (exposure_state: exposed) The radar has ${hosts} internet-facing services (distinct ip:port, the exposed_hosts field) on record whose banner version maps to ${cve}${countries === undefined ? "" : ` across ${countries} countries`}.${seen} ${kev} ${how}`;
}

// The note's exposure_state, as a field: exposed, measured_zero, not_assessed, tracking_unknown,
// or null when the answer carries no exposed_hosts count. The same branches as exposureNote.
type CVEExposureState = "exposed" | "measured_zero" | "not_assessed" | "tracking_unknown";
function cveExposureState(d: object): CVEExposureState | null {
  const hosts = numAt(d, "exposed_hosts");
  const tracked = boolAt(d, "tracked");
  if (hosts === undefined) return null;
  if (tracked === false) return "not_assessed";
  if (hosts === 0) return tracked === true ? "measured_zero" : "tracking_unknown";
  return "exposed";
}

// The seam for an observation time (#2439). A cve_exposure count is measured only when the
// answer says when the services it counts were observed, and this is the one place that reads
// such a time. The per-CVE answer serves none today: its fields are cve_id, exposed_hosts,
// countries, tracked, kev_listed, kev_catalog_listed, kev_seen_in_observations, ransomware,
// top_countries, top_products, method, last_seen and generated_at (production, 2026-09-27), and
// last_seen is EchelonGraph's write or refresh time (see the comment above CVE_ID), while
// generated_at is when the API built the answer. So this returns null and every cve_exposure
// answer is not_assessed. When the API serves an observation time (#2438), read that field here
// and nowhere else: measured and measured_at follow from this function alone, never from
// last_seen.
function observedAt(_d: object): string | null {
  return null;
}

// The envelope of a cve_exposure answer. Only a count of services on record that the answer
// dates by when they were observed (observedAt) is measured; every other answer is
// not_assessed, and its notes say why. Today that is every answer: the count is relayed,
// labelled by exposure_state and the note, as what the radar holds on record. A tracked zero
// is not_assessed too: it has no observation to date it, and the per-CVE answer does not carry
// the time of the radar's last completed check (exposure_radar relays that as
// kev_exposure.last_run_at).
function cveExposureEnvelope(cve: string, d: object) {
  const exposureState = cveExposureState(d);
  const observed = observedAt(d);
  const measured = exposureState === "exposed" && realInstant(observed ?? undefined);
  const last = strAt(d, "last_seen");
  const tracked = boolAt(d, "tracked");
  const why: Record<string, string> = {
    exposed: measured
      ? `state is measured: exposed_hosts counts the services the radar has on record for ${cve}, and measured_at is the time the API gives for when they were observed.`
      : `state is not_assessed: exposed_hosts counts the services the radar has on record for ${cve}, but the answer does not say when any of them was observed, so that count is relayed as what the radar holds on record, not as a dated measurement, and measured_at is null.`,
    measured_zero: `state is not_assessed: the API marks ${cve} as tracked with 0 services on record, but a zero has no observation to date it and the answer does not say when the radar last looked, so it is not presented as a dated measurement.`,
    not_assessed: `state is not_assessed: ${cve} is outside the radar's tracked set, so no number in data is a measurement of its exposure.`,
    tracking_unknown: `state is not_assessed: the API does not say whether ${cve} is in the radar's tracked set, so its 0 is not a measurement.`,
    none: `state is not_assessed: the answer carries no exposed_hosts count for ${cve}.`,
  };
  return {
    state: measured ? ("measured" as const) : ("not_assessed" as const),
    measured_at: measured ? (observed as string) : null,
    method: (strAt(d, "method") ?? EXPOSURE_METHOD).replace(/\s+$/, ""),
    coverage: { in_scope: tracked ?? null },
    freshness: null,
    exposure_state: exposureState,
    notes: [
      why[exposureState ?? "none"],
      ...(realInstant(last)
        ? [
            `last_seen (${last}) is not measured_at: it is when EchelonGraph last wrote or refreshed one of these rows (when a Shodan search matched the banner, or a re-check found the port still listed), not when any service was observed, and Shodan's own banner time is not stored.`,
          ]
        : []),
      tracked === undefined
        ? "coverage.in_scope is null: the answer does not say whether the CVE is in the radar's tracked set."
        : `coverage.in_scope is the API's tracked verdict: ${tracked ? "the CVE is in the radar's tracked set" : "the CVE is outside the radar's tracked set"}.`,
      "freshness is null: the per-CVE answer does not carry the time of the radar's last completed check.",
    ],
  };
}

async function cveExposure(cve_id: string): Promise<ToolResult> {
  const tool = "cve_exposure";
  const id = cve_id.trim();
  if (!id) return badInput(tool, "cve_id is required");
  // Refused here rather than sent: an API older than the id check answers a malformed id
  // with a 200 and zeros, which would read as an answer about a CVE that does not exist.
  if (!CVE_ID.test(id)) {
    return badInput(tool, `cve_id ${JSON.stringify(id.slice(0, 32))} is not a CVE id (expected the form CVE-2023-44487)`);
  }
  // The canonical form, which is how the API stores and answers it.
  const cve = id.toUpperCase();
  try {
    const r = await api(`/api/v1/public/kev-exposure/cve/${encodeURIComponent(cve)}`);
    if (!r.ok) return failed(tool, r);
    return succeeded(r.data, exposureNote(okHead(tool, r.status), cve, r.data), cveExposureEnvelope(strAt(r.data, "cve_id") ?? cve, r.data));
  } catch (e) {
    return crashed(tool, e);
  }
}

// Every quadrant that finds its services through Shodan, attributed. The exposed-database
// radar searches Shodan dorks and falls back to LeakIX when the Shodan query budget is low
// (core-backend/internal/exposeddb/poller.go). MCP-server discovery is named too, as the one
// that uses none (#2315; see the block comment above readMCPServers), so the attribution is
// never read as covering it.
const RADAR_SOURCES =
  "KEV-exposure, exposed-database and shadow-AI discovery use Shodan data (shadow AI also uses Certificate Transparency logs; exposed databases fall back to LeakIX when Shodan query credits run low). MCP-server discovery uses no Shodan data: its hostnames come from EchelonGraph's own Certificate Transparency feed, matched by hostname pattern.";

const RADARS = [
  ["kev_exposure", "/api/v1/public/kev-exposure/stats"],
  ["exposed_databases", "/api/v1/public/exposed-databases/stats"],
  ["leaked_credentials", "/api/v1/public/leaked-credentials/stats"],
  ["shadow_ai", "/api/v1/public/shadow-ai-radar/stats"],
  ["mcp_servers", "/api/v1/public/ai-exposure/stats?service=mcp"],
] as const;

// The shadow-AI stats answer, regrouped by what each number counts (#2307).
//
// GET /api/v1/public/shadow-ai-radar/stats (core-backend shadowctlog store.go Stats) mixes
// three kinds of number, and only one of them counts exposed services:
//   - confirmed exposed: rows whose liveness is active or rechecking, the published exposure
//     set (visible_by_category, last_24h_visible_count);
//   - observed: every Certificate Transparency or Shodan observation on record, whatever its
//     verification state (total, by_category, last_24h_count, trend_30d, and the top_products,
//     top_countries and top_issuers rankings);
//   - authentication state: rows where a probe observed an authentication gate (auth_confirmed,
//     liveness authenticated) or could not tell (auth_undetermined, liveness inconclusive).
// On 2026-09-27 total was 36,222 against 2,000 confirmed exposed, and top_products ranked
// LiteLLM at 6,813 observations while 1,395 LLM-PROXY services were confirmed exposed. Relayed
// under the API's names, every one of those reads as an exposure count. So the tool relays them
// grouped as confirmed_exposed, observed and authentication, with the note labelling each, and
// relays nothing it cannot label: a stats field this version does not know, a field other than
// a ranked row's label and count, and the poller block's instance fields are left out, and a
// field of any of them this version does not know is named in the note.
//
// The `poller` block's running and last_run_at describe the radar's fleet, not the instance
// that answered (core-backend shadowctlog Poller.Status): last_run_at is when the fleet's
// leader last COMPLETED a crt.sh (Certificate Transparency) cycle, and running is true only
// when that was within pollerSilentAfter, 30 minutes, of the answer. The API sends both or
// neither, and omits both when it cannot tell; it never sends the Go zero time. An API older
// than that answered from the serving instance's own memory, so a follower sent running:false
// and last_run_at 0001-01-01T00:00:00Z, which reads as "the radar is down and has never run".
// So the note reads three cases: running with a real completion time, stopped since a real
// completion time, and unknown. Only the first two are relayed, as those two fields alone; an
// unknown block (no real completion time and running verdict) is dropped, so no running:false
// or zero time reaches the model as freshness. The block's other fields (interval_seconds,
// shodan_enabled, and a polling instance's last_new_inserts, skipped_as_follower,
// consecutive_fails and shodan_last_new) describe the instance that answered, not the fleet,
// and none of them counts AI services.
const SHADOW_AI_SILENT_AFTER = "30 minutes";
// The stats fields readShadowAI knows how to label. Any other is left out and named.
const SHADOW_AI_STATS = new Set([
  "total",
  "by_category",
  "visible_by_category",
  "confirmed_window",
  "last_observation",
  "last_24h_count",
  "last_24h_visible_count",
  "auth_confirmed",
  "auth_undetermined",
  "top_products",
  "top_countries",
  "top_issuers",
  "trend_30d",
]);
// The poller block's fields this version knows (core-backend shadowctlog poller.go Status):
// running and last_run_at, relayed when both are real; the rest describe the instance that
// answered and are left out by design (see above). Any other key is left out and named, as a
// stats field is (#2313 item 7, #2440): an injected poller.exposed_now must not vanish unnamed.
const SHADOW_AI_POLLER = new Set([
  "running",
  "last_run_at",
  "interval_seconds",
  "shodan_enabled",
  "last_new_inserts",
  "last_error",
  "skipped_as_follower",
  "source_health",
  "consecutive_fails",
  "shodan_last_new",
]);
// The observed rankings and the daily series: API field, and the row field that names each row.
const SHADOW_AI_ROWS = [
  ["trend_30d", "date"],
  ["top_products", "product"],
  ["top_countries", "country"],
  ["top_issuers", "issuer"],
] as const;

const isCount = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);
const isPlainObject = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

// A category → count map, or nothing unless every value is a count: a partial map is an
// undercount that reads as a measurement (store.go categoryCounts).
function countMap(v: unknown): Record<string, number> | undefined {
  if (!isPlainObject(v)) return undefined;
  const entries = Object.entries(v);
  return entries.every(([, n]) => isCount(n)) ? (Object.fromEntries(entries) as Record<string, number>) : undefined;
}

// What a relayed row field must be. "number" is a finite number: a count or a score.
type Kind = "string" | "number" | "boolean";
type RowSpec = { required: Readonly<Record<string, Kind>>; optional?: Readonly<Record<string, Kind>> };
const isKind = (v: unknown, k: Kind): boolean => (k === "number" ? isCount(v) : typeof v === k);
type Rows = { rows?: Record<string, unknown>[]; extra: string[] };

// A ranking, a series or a list, each row cut down to the fields its spec names, so a field the
// backend adds to a row later is left out rather than relayed unlabelled; extra lists those
// fields so the note can name them. All rows or none: a row that is not an object, lacks a
// required field, or carries a known field of the wrong type leaves the whole list out, since
// a partial list reads as a complete one. An optional field may be absent (Go's omitempty).
function readRows(v: unknown, spec: RowSpec): Rows {
  if (!Array.isArray(v)) return { extra: [] };
  const optional = spec.optional ?? {};
  const rows: Record<string, unknown>[] = [];
  const extra = new Set<string>();
  for (const r of v) {
    if (!isPlainObject(r)) return { extra: [] };
    const row: Record<string, unknown> = {};
    for (const [k, kind] of Object.entries(spec.required)) {
      if (!isKind(r[k], kind)) return { extra: [] };
      row[k] = r[k];
    }
    for (const [k, kind] of Object.entries(optional)) {
      if (r[k] === undefined) continue;
      if (!isKind(r[k], kind)) return { extra: [] };
      row[k] = r[k];
    }
    // An own-property test: `in` would also find toString and constructor on the prototype.
    for (const k of Object.keys(r)) if (!Object.prototype.hasOwnProperty.call(spec.required, k) && !Object.prototype.hasOwnProperty.call(optional, k)) extra.add(k);
    rows.push(row);
  }
  return { rows, extra: [...extra] };
}

// A ranking or a daily series whose rows are a label and a count (the shadow-AI shape).
const countRows = (v: unknown, label: string): Rows => readRows(v, { required: { [label]: "string", count: "number" } });

// The note's sentences about what a radar's answer carried that the tool left out.
function leftOut(radar: string, unknown: string[], unusable: string[]): string[] {
  const out: string[] = [];
  if (unknown.length) out.push(`Left out of ${radar} because this version of the tool cannot label them: ${unknown.join(", ")}.`);
  if (unusable.length) out.push(`Left out of ${radar} because they were not in the expected shape: ${unusable.join(", ")}.`);
  return out;
}

// A radar stats answer with a flat shape: top-level counts, top-level lists of rows, and
// top-level timestamps. readRadar relays exactly those fields, in this order, and nothing else.
type RadarSpec = {
  counts: readonly string[];
  rows: Readonly<Record<string, RowSpec>>;
  instants: readonly string[];
  // The API's observation-window field (#2438), relayed as `window`; absent for a radar whose
  // answer serves none.
  window?: string;
};
type RadarRead = { data: Record<string, unknown>; unknown: string[]; unusable: string[]; undated?: number };

// ── observation windows (#2438) ──
//
// Since #2438 the exposed-databases and leaked-credentials stats answers carry observed_window,
// and the shadow-AI one stats.confirmed_window: {from, to, undated}, the earliest and latest
// observation time over the rows the counts count, read in the same statement as the counts
// (core-backend exposeddb store.go Stats: verified_at, when EchelonGraph's own check last
// confirmed a service open; leakedcreds store.go Stats: last_seen, when the detector last found
// a pair; shadowctlog store.go visibleByCategory: last_checked_at, when the verifier's deciding
// probe ran). undated counts counted rows with no such time. kev_exposure serves none: its
// last_seen is our write time and Shodan's banner time is not stored (#2439).
//
// A window is relayed as {from, to} only when both are real instants and undated is 0, so it
// describes every row counted; with undated above 0 it describes only some of them, so it is
// not relayed and the note says how many rows carry no time. Like mcp_servers.window, it is a
// span of observations made at different times, not one observation time, so it never becomes
// measured_at (see the envelope comment above RADAR_METHOD).
type WindowRead = { window?: { from: string; to: string }; undated?: number; bad: boolean };
function readWindow(v: unknown): WindowRead {
  if (v === undefined || v === null) return { bad: false };
  if (!isPlainObject(v)) return { bad: true };
  const from = strAt(v, "from");
  const to = strAt(v, "to");
  const undated = v.undated;
  if (!isCount(undated) || undated < 0 || !Number.isInteger(undated)) return { bad: true };
  if (undated > 0) return { undated, bad: false };
  if (v.from === null && v.to === null) return { bad: false }; // nothing counted, so nothing dated
  if (!realInstant(from) || !realInstant(to) || Date.parse(from) > Date.parse(to)) return { bad: true };
  return { window: { from, to }, bad: false };
}

// The sentence for a radar's window, or for the rows it leaves undated.
function windowSentences(prefix: string, w: WindowRead, what: string): string[] {
  if (w.window) {
    return [`${prefix}.window.from (${w.window.from}) and ${prefix}.window.to (${w.window.to}) are timestamps, not counts: ${what}. They span observations made at different times, not one observation time.`];
  }
  if (w.undated !== undefined) {
    return [`${prefix} carries no window: ${w.undated} of the rows it counts have no observation time on record, so a window over the rest would not describe them.`];
  }
  return [];
}

function readRadar(body: unknown, spec: RadarSpec): RadarRead {
  const src = isPlainObject(body) ? body : {};
  const data: Record<string, unknown> = {};
  const unknown: string[] = [];
  const unusable: string[] = [];
  const present = (k: string) => src[k] !== undefined && src[k] !== null;
  for (const k of spec.counts) {
    if (isCount(src[k])) data[k] = src[k];
    else if (present(k)) unusable.push(k);
  }
  for (const [k, rowSpec] of Object.entries(spec.rows)) {
    const r = readRows(src[k], rowSpec);
    if (r.rows) {
      data[k] = r.rows;
      unknown.push(...r.extra.map((x) => `${k}[].${x}`));
    } else if (present(k)) unusable.push(k);
  }
  // A timestamp that is not a real instant (the Go zero time) is not relayed as one.
  for (const k of spec.instants) {
    const s = strAt(src, k);
    if (realInstant(s)) data[k] = s;
    else if (present(k) && typeof src[k] !== "string") unusable.push(k);
  }
  let undated: number | undefined;
  if (spec.window) {
    const w = readWindow(src[spec.window]);
    if (w.window) data.window = w.window;
    else if (w.bad) unusable.push(spec.window);
    undated = w.undated;
  }
  const known = new Set([...spec.counts, ...Object.keys(spec.rows), ...spec.instants, ...(spec.window ? [spec.window] : [])]);
  unknown.unshift(...Object.keys(src).filter((k) => !known.has(k)));
  return { data, unknown, unusable, undated };
}

// ── last_run_at: when a radar last COMPLETED a check (#2335) ──
//
// Since #2335 the kev_exposure, exposed_databases and leaked_credentials stats answers carry
// last_run_at (core-backend pollerlock/published.go): the radar's completion row in
// poller_run_state, recorded for the radar as a whole rather than for the instance that
// answered, UTC, truncated to the second. Each poller writes that row at the END of a cycle,
// and only when the cycle's reads succeeded (poller.go checkCompleted / recordCheck), so a
// cycle that read nothing never moves it. What counts as a completed check differs per radar,
// and LAST_CHECK words each. The API omits the field when no completed check is on record,
// when its read failed, or when its last good read is more than two minutes old; it never
// sends the Go zero time.
//
// It is a timestamp, not a count, and not the time of the numbers beside it: those count
// everything still on record, not only what the last check found. Nor is it generated_at,
// which is only when the API's 60 s stats cache recomputed the totals. An absent stamp (or one
// that is not a real instant) means the API could not tell, so the note says nothing about it:
// no "never", no zero.
const LAST_CHECK = {
  kev_exposure:
    "its Shodan search answered at least one query (others may have failed) and its list of services due for a re-check was read; a cycle that skipped the search for want of Shodan query credits, or whose reads failed, does not move it",
  exposed_databases:
    "its Shodan search, or the LeakIX fallback, answered at least one query (others may have failed), its list of services due for a re-check was read, and the scan opt-out register could be consulted; a cycle that searched nothing, or whose reads failed, does not move it",
  leaked_credentials:
    "it read the public GitHub event stream (fetches of some of the commits it lists may have failed); a cycle whose read of that stream failed does not move it",
} as const;

// The note's sentences for one radar's relayed last_run_at, each naming the field so that any
// one of them quoted alone still says what it is; none when the stamp was not relayed.
function lastCheck(radar: keyof typeof LAST_CHECK, data: Record<string, unknown>): string[] {
  const at = data.last_run_at;
  if (typeof at !== "string") return [];
  return [
    `${radar} last completed check: ${at} (${radar}.last_run_at, a timestamp, not a count).`,
    `${radar}.last_run_at is when the radar last finished a cycle whose reads succeeded: ${LAST_CHECK[radar]}.`,
    `${radar}.last_run_at is not the time of every record the ${radar} numbers count, which cover everything still on record, not only what that check found; nor is it ${radar}.generated_at, when the API computed those numbers.`,
  ];
}

// The first row of a relayed ranking, for the note: "(first: http_server, 9120 services)".
function firstOf(rows: unknown, label: string, count: string, unit: string): string {
  const top = Array.isArray(rows) ? (rows[0] as Record<string, unknown> | undefined) : undefined;
  return top === undefined ? "" : ` (first: ${String(top[label])}, ${String(top[count])} ${unit})`;
}
// "a", "a and b", "a, b and c".
const listed = (xs: string[]): string => (xs.length < 2 ? xs.join("") : `${xs.slice(0, -1).join(", ")} and ${xs[xs.length - 1]}`);
const numIn = (d: Record<string, unknown>, k: string): number | undefined => (isCount(d[k]) ? d[k] : undefined);
const be = (n: number): string => (n === 1 ? "is" : "are");

// ── kev_exposure: GET /api/v1/public/kev-exposure/stats (#2313 items 6 and 7) ──
//
// core-backend/internal/kevexposure store.go Stats. Every count is over the observation
// table, one row per (ip:port, CVE) (Upsert keys it obsID(host, cve), the host being
// "ip:port" from poller.go), filtered to rows whose kev_listed flag the poller copied in at
// match time:
//   distinct_hosts    COUNT(DISTINCT host): distinct ip:port services, not machines
//   kev_cves_exposed  COUNT(DISTINCT cve_id): CVEs with at least one such service
//   correlations      COUNT(*): service×CVE pairs, so a service with three CVEs counts 3 times
//   ransomware_cves   COUNT(DISTINCT cve_id) FILTER (WHERE ransomware)
//   ransomware_hosts  COUNT(DISTINCT host) FILTER (WHERE ransomware): services, not machines
//   top_products / top_cves / top_countries   COUNT(DISTINCT host) per group, LIMIT 12/12/10;
//                     a top_cves row's cvss_v3_score and epss_score are MAX() over its rows
//   trend             COUNT(*) per date_trunc('week', first_seen) over 12 weeks: pairs still on
//                     record, by the week first recorded (a pruned pair is gone, so earlier
//                     weeks read low)
//   newest_kev        the 15 cves rows with kev_listed and the latest kev_added_date, LEFT JOINed
//                     to COUNT(DISTINCT host) of their KEV-flagged rows, COALESCE(e.h, 0).
//   last_run_at       the radar's last completed check, KeyKEVExposureCheckCompleted (#2335; see
//                     LAST_CHECK). Its own row: KeyKEVExposure is the Shodan-credit watermark.
// So newest_kev[].exposed_hosts is 0 for every CVE the radar holds no row for, whether or not
// it could ever hold one: the join default, not a measurement. The per-CVE endpoint decides
// that with `tracked` (store.go trackedVerdict), which is true ONLY when rows exist
// (exposedHosts > 0) and otherwise false or absent: the backend never reports a measured zero.
// So a 0 here is never relayed: its row says exposure_state not_assessed and carries no
// count. If the stats answer ever sends a row's `tracked` (the contract proposed on #2313), it
// is read the way cve_exposure reads it: false is not assessed whatever the count, and true
// with 0 is a measured zero in the radar's sample.
const KEV_SPEC: RadarSpec = {
  counts: ["distinct_hosts", "ransomware_hosts", "kev_cves_exposed", "ransomware_cves", "correlations"],
  rows: {
    top_products: { required: { product: "string", hosts: "number" } },
    top_countries: { required: { country: "string", hosts: "number" } },
    top_cves: {
      required: { cve_id: "string", hosts: "number" },
      optional: { severity: "string", cvss_v3_score: "number", epss_score: "number", ransomware: "boolean" },
    },
    trend: { required: { week: "string", new_exposures: "number" } },
    newest_kev: {
      required: { cve_id: "string", exposed_hosts: "number" },
      optional: {
        added_date: "string",
        vuln_name: "string",
        severity: "string",
        cvss_v3_score: "number",
        epss_score: "number",
        ransomware: "boolean",
        tracked: "boolean",
      },
    },
  },
  instants: ["generated_at", "last_run_at"],
};

type ExposureState = "exposed" | "measured_zero" | "not_assessed";

// One newest_kev row as relayed: the CVE record's fields, its exposure_state, and a count only
// when the count is a measurement. `tracked` is read, not relayed: exposure_state says it.
function newestKEVRow(r: Record<string, unknown>): { row: Record<string, unknown>; state: ExposureState; outside: boolean } {
  const hosts = r.exposed_hosts as number;
  const tracked = r.tracked as boolean | undefined;
  const state: ExposureState = tracked === false ? "not_assessed" : hosts > 0 ? "exposed" : tracked === true ? "measured_zero" : "not_assessed";
  const row: Record<string, unknown> = {};
  for (const k of ["cve_id", "added_date", "vuln_name", "severity", "cvss_v3_score", "epss_score", "ransomware"]) {
    if (r[k] !== undefined) row[k] = r[k];
  }
  row.exposure_state = state;
  if (state !== "not_assessed") row.exposed_hosts = hosts;
  return { row, state, outside: tracked === false };
}

function readKEVExposure(body: unknown): { data: object; sentences: string[] } {
  const { data, unknown, unusable } = readRadar(body, KEV_SPEC);
  const sentences: string[] = [];
  const n = (k: string) => numIn(data, k);

  const totals = [
    n("distinct_hosts") !== undefined &&
      `kev_exposure.distinct_hosts (${n("distinct_hosts")}) counts distinct ip:port services, not machines (a machine answering on two ports counts twice), with at least one CISA-KEV-listed CVE on record`,
    n("ransomware_hosts") !== undefined &&
      `kev_exposure.ransomware_hosts (${n("ransomware_hosts")}) counts the services among them with at least one ransomware-linked KEV CVE (one whose KEV entry notes known use in ransomware campaigns)`,
    n("kev_cves_exposed") !== undefined &&
      `kev_exposure.kev_cves_exposed (${n("kev_cves_exposed")}) counts distinct CISA-KEV-listed CVEs with at least one service on record`,
    n("ransomware_cves") !== undefined && `kev_exposure.ransomware_cves (${n("ransomware_cves")}) counts the ransomware-linked CVEs among them`,
    n("correlations") !== undefined &&
      `kev_exposure.correlations (${n("correlations")}) counts service×CVE pairs, not services: a service with three KEV CVEs counts three times`,
  ].filter((p): p is string => typeof p === "string");
  if (totals.length) sentences.push(`KEV exposure: ${totals.join("; ")}.`);

  const rankings = [
    data.top_products !== undefined && `kev_exposure.top_products ranks up to 12 products${firstOf(data.top_products, "product", "hosts", "services")}`,
    data.top_countries !== undefined && `kev_exposure.top_countries ranks up to 10 countries${firstOf(data.top_countries, "country", "hosts", "services")}`,
    data.top_cves !== undefined && `kev_exposure.top_cves ranks up to 12 CVEs${firstOf(data.top_cves, "cve_id", "hosts", "services")}`,
  ].filter((p): p is string => typeof p === "string");
  if (rankings.length) sentences.push(`${listed(rankings)}, each by distinct ip:port services with a CISA-KEV-listed CVE on record.`);
  if (data.top_cves !== undefined) {
    sentences.push(
      "kev_exposure.top_cves[].cvss_v3_score and kev_exposure.top_cves[].epss_score are the highest CVSS v3 base score and EPSS probability (0 to 1) recorded on that CVE's observations: scores, not counts.",
    );
  }
  if (data.trend !== undefined) {
    sentences.push(
      "kev_exposure.trend counts service×CVE pairs, not services, by the week (starting Monday) in which each pair was first recorded, over the last 12 weeks; only pairs still on record are counted, so earlier weeks read low.",
    );
  }

  // newest_kev: a 0 is the join's default, never a measurement (see the block comment above).
  if (Array.isArray(data.newest_kev)) {
    const read = (data.newest_kev as Record<string, unknown>[]).map(newestKEVRow);
    data.newest_kev = read.map((x) => x.row);
    const ids = (pred: (x: (typeof read)[number]) => boolean) => read.filter(pred).map((x) => String(x.row.cve_id));
    const exposed = read.filter((x) => x.state === "exposed");
    const zero = ids((x) => x.state === "measured_zero");
    const outside = ids((x) => x.state === "not_assessed" && x.outside);
    const unsaid = ids((x) => x.state === "not_assessed" && !x.outside);
    sentences.push(
      read.length
        ? `kev_exposure.newest_kev lists the ${read.length} CVEs that EchelonGraph's CVE records most recently mark as CISA-KEV-listed (by added_date), each with an exposure_state.`
        : "kev_exposure.newest_kev is empty: EchelonGraph's CVE records returned no CISA-KEV-listed CVE with a date added.",
    );
    if (exposed.length) {
      sentences.push(
        `${exposed.length} of them ${be(exposed.length)} exposed (exposure_state exposed): kev_exposure.newest_kev[].exposed_hosts counts distinct ip:port services on record with that CVE (${exposed.map((x) => `${String(x.row.cve_id)}: ${String(x.row.exposed_hosts)}`).join(", ")}).`,
      );
    }
    if (zero.length) {
      sentences.push(
        `${zero.length} ${be(zero.length)} a measured zero in the radar's sample (exposure_state measured_zero, exposed_hosts 0): the API says the radar tracks them and holds no service for them, though it reads at most the first 100 Shodan results per tracked-product query, so this is not an internet-wide zero: ${zero.join(", ")}.`,
      );
    }
    if (outside.length) {
      sentences.push(
        `${outside.length} ${be(outside.length)} NOT ASSESSED (exposure_state not_assessed) because the API says they are outside the radar's tracked set, so no count is relayed for them: ${outside.join(", ")}.`,
      );
    }
    if (unsaid.length) {
      sentences.push(
        `${unsaid.length} ${be(unsaid.length)} NOT ASSESSED (exposure_state not_assessed): ${unsaid.join(", ")}. The API answers 0 for each, and that 0 is not a measurement: it is what the stats answer gives any CVE the radar holds no service for, whether or not the radar looks for that CVE at all, so no count is relayed for them. cve_exposure says per CVE whether it is in the radar's tracked set.`,
      );
    }
    sentences.push(
      "kev_exposure.newest_kev[].cvss_v3_score and kev_exposure.newest_kev[].epss_score are the CVE record's CVSS v3 base score and EPSS probability (0 to 1), absent when the record has none: scores, not counts.",
    );
  }
  sentences.push(...lastCheck("kev_exposure", data));
  sentences.push(...leftOut("kev_exposure", unknown, unusable));
  return { data, sentences };
}

// ── exposed_databases: GET /api/v1/public/exposed-databases/stats (#2313 item 7) ──
//
// core-backend/internal/exposeddb store.go Stats, over one row per (ip:port, engine)
// (obsID(host, engine); the host is "ip:port", poller.go obsFrom). A row is stored only after
// EchelonGraph's own check confirmed the service answering without authentication.
//   distinct_hosts  COUNT(DISTINCT host): ip:port services, not machines
//   engines         COUNT(DISTINCT engine): engine types (mongodb, redis, grafana, ...)
//   pii_likely / pci_likely   COUNT(DISTINCT host) whose data_class names pii / pci AND whose
//                   schema terms pass the high-confidence gate (2+ distinct indicators, or one
//                   tier-1 term), mirroring classify.go dataConfidence. The classifier reads
//                   NAMES only (index / database / table / field names in the banner and the
//                   check's response, classify.go), never a record, and is precision-first:
//                   a service whose names miss the gate is not counted, whatever it holds.
//                   So these are a schema gate, not a census, and the rest are not "no PII".
//   top_engines / top_countries   COUNT(DISTINCT host) per group, LIMIT 15 / 10.
//   last_run_at     the radar's last completed check, KeyExposedDBCheckCompleted (#2335; see
//                   LAST_CHECK). Its own row: KeyExposedDB is claimed at the START of a cycle.
const EXPOSED_DB_SPEC: RadarSpec = {
  counts: ["distinct_hosts", "engines", "pii_likely", "pci_likely"],
  rows: {
    top_engines: { required: { engine: "string", hosts: "number" } },
    top_countries: { required: { country: "string", hosts: "number" } },
  },
  instants: ["generated_at", "last_run_at"],
  window: "observed_window",
};

function readExposedDatabases(body: unknown): { data: object; sentences: string[] } {
  const { data, unknown, unusable, undated } = readRadar(body, EXPOSED_DB_SPEC);
  const sentences: string[] = [];
  const n = (k: string) => numIn(data, k);
  const totals = [
    n("distinct_hosts") !== undefined &&
      `exposed_databases.distinct_hosts (${n("distinct_hosts")}) counts distinct ip:port services, not machines (a machine answering on two ports counts twice), that EchelonGraph's check confirmed answering without authentication, data stores and observability UIs alike`,
    n("engines") !== undefined && `exposed_databases.engines (${n("engines")}) counts the distinct engine types among them`,
  ].filter((p): p is string => typeof p === "string");
  if (totals.length) sentences.push(`Exposed data stores: ${totals.join("; ")}.`);
  const rankings = [
    data.top_engines !== undefined && `exposed_databases.top_engines ranks up to 15 engines${firstOf(data.top_engines, "engine", "hosts", "services")}`,
    data.top_countries !== undefined && `exposed_databases.top_countries ranks up to 10 countries${firstOf(data.top_countries, "country", "hosts", "services")}`,
  ].filter((p): p is string => typeof p === "string");
  if (rankings.length) sentences.push(`${listed(rankings)}, each by those services.`);
  const gated = [
    n("pii_likely") !== undefined && `exposed_databases.pii_likely (${n("pii_likely")}) counts services whose schema names pass a high-confidence gate for personal data`,
    n("pci_likely") !== undefined && `exposed_databases.pci_likely (${n("pci_likely")}) counts services whose schema names pass a high-confidence gate for payment-card data`,
  ].filter((p): p is string => typeof p === "string");
  if (gated.length) {
    sentences.push(
      `${gated.join("; ")}. The names are index, database, table or field names in the Shodan or LeakIX banner or in the check's response, never record values, and the gate passes one unambiguous term (such as ssn or cardholder) or two distinct indicators. It is precision-first: a service whose names do not pass it is not counted, whatever it holds, so the other services are not shown to hold no personal or card data.`,
    );
  }
  sentences.push(
    ...windowSentences(
      "exposed_databases",
      { window: data.window as WindowRead["window"], undated, bad: false },
      "when EchelonGraph's check last confirmed the oldest and the newest of the services counted answering without authentication",
    ),
  );
  sentences.push(...lastCheck("exposed_databases", data));
  sentences.push(...leftOut("exposed_databases", unknown, unusable));
  return { data, sentences };
}

// ── leaked_credentials: GET /api/v1/public/leaked-credentials/stats (#2313 item 7) ──
//
// core-backend/internal/leakedcreds store.go Stats, over one row per (repository, secret):
// obsID(repo, fingerprint), "one row per leaked secret per repo".
//   total             COUNT(*): (repository, secret) pairs, so one secret in three
//                     repositories counts three times; not distinct secrets
//   distinct_secrets  COUNT(DISTINCT fingerprint);  distinct_repos  COUNT(DISTINCT repo)
//   top_providers / top_types   COUNT(*) per group, LIMIT 15: pairs again
// None is validated: detect.go says "verified" means STRUCTURALLY verified (a checksum or format
// decode), never "confirmed live", and the radar never uses a credential it finds.
//   last_run_at       the radar's last completed check, its own KeyLeakedCreds row, written at
//                     the END of a cycle that read the event stream (#2335; see LAST_CHECK).
const LEAKED_CREDS_SPEC: RadarSpec = {
  counts: ["total", "distinct_secrets", "distinct_repos"],
  rows: {
    top_providers: { required: { provider: "string", count: "number" } },
    top_types: { required: { secret_type: "string", count: "number" } },
  },
  instants: ["generated_at", "last_run_at"],
  window: "observed_window",
};

function readLeakedCredentials(body: unknown): { data: object; sentences: string[] } {
  const { data, unknown, unusable, undated } = readRadar(body, LEAKED_CREDS_SPEC);
  const sentences: string[] = [];
  const n = (k: string) => numIn(data, k);
  const totals = [
    n("total") !== undefined &&
      `leaked_credentials.total (${n("total")}) counts (repository, secret) pairs, not distinct secrets: a secret committed to three repositories counts three times`,
    n("distinct_secrets") !== undefined && `leaked_credentials.distinct_secrets (${n("distinct_secrets")}) counts each secret once`,
    n("distinct_repos") !== undefined && `leaked_credentials.distinct_repos (${n("distinct_repos")}) counts public GitHub repositories`,
  ].filter((p): p is string => typeof p === "string");
  if (totals.length) sentences.push(`Leaked credentials: ${totals.join("; ")}.`);
  const rankings = [
    data.top_providers !== undefined && `leaked_credentials.top_providers ranks up to 15 providers${firstOf(data.top_providers, "provider", "count", "pairs")}`,
    data.top_types !== undefined && `leaked_credentials.top_types ranks up to 15 secret types${firstOf(data.top_types, "secret_type", "count", "pairs")}`,
  ].filter((p): p is string => typeof p === "string");
  if (rankings.length) sentences.push(`${listed(rankings)}, each by the same (repository, secret) pairs.`);
  if (totals.length || rankings.length) {
    sentences.push(
      "None of these is validated: each is a credential-shaped string in a public commit that passed EchelonGraph's filters, at most structurally checked (a checksum or format decode) and never tested against its provider, so none of them is a count of working credentials.",
    );
  }
  sentences.push(
    ...windowSentences(
      "leaked_credentials",
      { window: data.window as WindowRead["window"], undated, bad: false },
      "when EchelonGraph's detector last found the oldest and the newest of the (repository, secret) pairs counted in a public commit",
    ),
  );
  sentences.push(...lastCheck("leaked_credentials", data));
  sentences.push(...leftOut("leaked_credentials", unknown, unusable));
  return { data, sentences };
}

function readShadowAI(sa: object): { data: object; sentences: string[] } {
  const sentences: string[] = [];
  const stats = field(sa, "stats");
  const used = new Set<string>();
  const take = <T>(key: string, v: T | undefined): T | undefined => {
    if (v !== undefined) used.add(key);
    return v;
  };

  // Confirmed exposed: liveness IN ('active','rechecking') (store.go Stats, visible_by_category
  // and last_24h_visible_count).
  const confirmed: Record<string, unknown> = {};
  const visible = take("visible_by_category", countMap(field(stats, "visible_by_category")));
  if (visible) {
    confirmed.total = Object.values(visible).reduce((a, b) => a + b, 0);
    confirmed.by_category = visible;
  }
  const last24Visible = take("last_24h_visible_count", numAt(stats, "last_24h_visible_count"));
  if (last24Visible !== undefined) confirmed.last_24h = last24Visible;
  // When the confirmed rows were observed (#2438): the verifier's deciding probe times, over the
  // rows visible_by_category counts. Relayed only beside the count it dates.
  const confirmedWindow = readWindow(field(stats, "confirmed_window"));
  if (!confirmedWindow.bad && field(stats, "confirmed_window") !== undefined) used.add("confirmed_window");
  if (confirmedWindow.window && confirmed.total !== undefined) confirmed.window = confirmedWindow.window;

  // Observed: every row of shadow_ct_observations, whatever its liveness.
  const observed: Record<string, unknown> = {};
  const total = take("total", numAt(stats, "total"));
  if (total !== undefined) observed.total = total;
  const byCategory = take("by_category", countMap(field(stats, "by_category")));
  if (byCategory) observed.by_category = byCategory;
  const last24 = take("last_24h_count", numAt(stats, "last_24h_count"));
  if (last24 !== undefined) observed.last_24h = last24;
  const rows: Partial<Record<(typeof SHADOW_AI_ROWS)[number][0], Record<string, unknown>[]>> = {};
  const rowExtras: string[] = [];
  for (const [key, label] of SHADOW_AI_ROWS) {
    const r = countRows(field(stats, key), label);
    if (take(key, r.rows)) {
      observed[key] = rows[key] = r.rows;
      rowExtras.push(...r.extra.map((x) => `stats.${key}[].${x}`));
    }
  }
  // A timestamp, not a count; one that is not a real instant is dropped (see realInstant).
  const lastObservation = take("last_observation", strAt(stats, "last_observation"));
  if (realInstant(lastObservation)) observed.last_observation = lastObservation;

  // Authentication state: liveness 'authenticated' and 'inconclusive'.
  const authentication: Record<string, unknown> = {};
  const authSeen = take("auth_confirmed", numAt(stats, "auth_confirmed"));
  if (authSeen !== undefined) authentication.observed = authSeen;
  const authUnknown = take("auth_undetermined", numAt(stats, "auth_undetermined"));
  if (authUnknown !== undefined) authentication.not_determined = authUnknown;

  sentences.push(
    confirmed.total === undefined
      ? `Shadow AI: the answer carries no usable stats.visible_by_category, so it does not say how many services are confirmed exposed${last24Visible === undefined ? "" : `; confirmed_exposed.last_24h (${last24Visible}) counts confirmed-exposed services first recorded in the last 24 h`}.`
      : `Shadow AI confirmed exposed: ${confirmed.total} (confirmed_exposed.total, the sum of confirmed_exposed.by_category: services EchelonGraph's probes found answering without an authentication gate, with liveness active or, during a re-check, rechecking)${last24Visible === undefined ? "" : `, ${last24Visible} of them first recorded in the last 24 h (confirmed_exposed.last_24h)`}. Of the shadow_ai numbers, only confirmed_exposed counts exposed services.`,
  );
  if (confirmed.total !== undefined) {
    sentences.push(
      ...windowSentences(
        "shadow_ai.confirmed_exposed",
        { window: confirmedWindow.window, undated: confirmedWindow.undated, bad: false },
        "when EchelonGraph's verifier ran the probe that last decided the oldest and the newest of the services confirmed_exposed counts",
      ),
    );
  }
  if (total !== undefined) {
    sentences.push(
      `Shadow AI observed: ${total} (observed.total) counts every Certificate Transparency or Shodan observation on record, whatever its verification state: that many observed, not that many exposed.`,
    );
  }
  const first = (key: (typeof SHADOW_AI_ROWS)[number][0], label: string): string => {
    const top = rows[key]?.[0];
    return top === undefined ? "" : ` (first: ${top[label]}, ${top.count} observations)`;
  };
  const observedParts = [
    byCategory && "observed.by_category counts them by category",
    last24 !== undefined && `observed.last_24h (${last24}) counts those first recorded in the last 24 h`,
    rows.trend_30d && "observed.trend_30d counts them per UTC day over the last 30 days",
    rows.top_products && `observed.top_products ranks up to ten products by observations${first("top_products", "product")}`,
    rows.top_countries && `observed.top_countries ranks up to ten countries by observations${first("top_countries", "country")}`,
    rows.top_issuers &&
      `observed.top_issuers ranks up to ten issuers by observations, an issuer being the certificate's CA for a Certificate Transparency observation and the hosting operator Shodan reports for a Shodan one${first("top_issuers", "issuer")}`,
  ].filter((p): p is string => typeof p === "string");
  if (observedParts.length) {
    sentences.push(
      `${total === undefined ? "Every number" : "Every other number"} under observed counts the same observations, not exposed services: ${observedParts.join("; ")}.`,
    );
  }
  const authParts = [
    authSeen !== undefined &&
      `authentication.observed (${authSeen}) counts observations where a probe observed an authentication gate (a 401/403, a login page or an auth marker; liveness authenticated)`,
    authUnknown !== undefined &&
      `authentication.not_determined (${authUnknown}) counts observations whose service answered but where no probe could tell whether it enforces authentication (liveness inconclusive)`,
  ].filter((p): p is string => typeof p === "string");
  if (authParts.length) {
    sentences.push(`Shadow AI authentication, over every observation on record: ${authParts.join("; ")}.`);
    sentences.push(
      "Neither authentication count is part of confirmed_exposed, and observed.total minus confirmed_exposed.total is not a count of secured services: it also holds observations not yet verified (liveness unverified), whose hostname no longer resolves (unreachable), or whose service no longer answers openly (resolved).",
    );
  }

  // What the answer carried that the tool cannot label: named, and left out. The poller block's
  // keys are checked like the stats keys: its known instance fields are left out by design, and
  // any other key is named.
  const poller = field(sa, "poller");
  const unknown = [
    ...Object.keys(isPlainObject(sa) ? sa : {}).filter((k) => k !== "stats" && k !== "poller"),
    ...Object.keys(isPlainObject(stats) ? stats : {})
      .filter((k) => !SHADOW_AI_STATS.has(k))
      .map((k) => `stats.${k}`),
    ...rowExtras,
    ...Object.keys(isPlainObject(poller) ? poller : {})
      .filter((k) => !SHADOW_AI_POLLER.has(k))
      .map((k) => `poller.${k}`),
  ];
  const unusable = Object.entries(isPlainObject(stats) ? stats : {})
    .filter(([k, v]) => SHADOW_AI_STATS.has(k) && !used.has(k) && v !== null)
    .map(([k]) => `stats.${k}`);
  if (!isPlainObject(stats)) sentences.push("The answer carries no stats object, so it gives no shadow-AI counts.");
  sentences.push(...leftOut("shadow_ai", unknown, unusable));

  const data: Record<string, unknown> = {};
  if (Object.keys(confirmed).length) data.confirmed_exposed = confirmed;
  if (Object.keys(observed).length) data.observed = observed;
  if (Object.keys(authentication).length) data.authentication = authentication;

  const lastRun = strAt(sa, "poller", "last_run_at");
  const running = boolAt(sa, "poller", "running");
  if (realInstant(lastRun) && running === true) {
    data.poller = { running, last_run_at: lastRun };
    sentences.push(
      `Shadow-AI radar freshness: the radar's leader last completed a Certificate Transparency (crt.sh) discovery cycle at ${lastRun} (poller.running is true: that was within ${SHADOW_AI_SILENT_AFTER} of the API's answer).`,
    );
  } else if (realInstant(lastRun) && running === false) {
    data.poller = { running, last_run_at: lastRun };
    sentences.push(
      `Shadow-AI radar freshness: no Certificate Transparency (crt.sh) discovery cycle has completed since ${lastRun}, when the radar's leader last completed one (poller.running is false: that was more than ${SHADOW_AI_SILENT_AFTER} before the API's answer), so the shadow-AI figures may be stale.`,
    );
  } else if (poller === undefined) {
    sentences.push("Shadow-AI radar freshness is unknown: the answer carries no poller block.");
  } else {
    sentences.push(
      "Shadow-AI radar freshness is unknown: the answer's poller block does not give both a real time at which the radar's leader last completed a cycle (poller.last_run_at) and a running verdict (poller.running), so that block was left out of the data above.",
    );
  }
  if (realInstant(lastObservation)) sentences.push(`Latest shadow-AI observation on record: ${lastObservation}.`);
  return { data, sentences };
}

// ── mcp_servers: GET /api/v1/public/ai-exposure/stats?service=mcp (#2315) ──
//
// core-backend/internal/aiexposure (handler.go MCPPublicCounts, store.go): the AI-exposure
// radar's MCP rows, one per hostname, each counted once by its latest verdict on record, with
// EchelonGraph's own control servers left out and counted in own_controls_excluded, and every
// hostname whose owner opted out of scanning left out and counted in withheld_opted_out (#2822).
// Counts, timestamps and one constant (service "mcp"); no hostname, version or server name.
//   total                   protected + pending_readjudication + not_assessed
//   protected               the /mcp endpoint answered 401/403 and its RFC 9728 protected-resource
//                           metadata validated (prm.go); prm_via divides exactly these rows by
//                           where that document was found
//   pending_readjudication  a verdict of a rule since replaced, not yet re-checked (store.go
//                           readjudicationPredicate); in neither of the other two
//   not_assessed            the rest; not_assessed_by_reason divides exactly these rows, first
//                           match wins: the eight prm.go reason codes (a challenge whose metadata
//                           did not validate), identified_no_challenge, challenge_unadjudicated
//                           (a challenge recorded before #2312), no_http_answer, not_identified_as_mcp
//   era, transport          divide every counted row; a row written before #2314 recorded an era
//                           is not_measured (era.go says what each value rests on)
//   withheld_opted_out      hostnames a verified scan opt-out covered when the radar last reached
//                           them (store.go opted_out_at, #2363): not re-checked while it stands, so
//                           their last verdict is frozen, and in no other count (#2822). The unparameterised
//                           answer withholds the same rows under the same key. An API older than
//                           #2822 carries no such field and counted those rows; the note says so
//                           rather than reading the absence as 0.
//   window                  from/to: the oldest and newest last-check time over the counted rows
//   enabled, last_run_at    exactly as the unparameterised answer computes them: the AI-exposure
//                           radar's fleet-wide liveness and last completed check, over every AI
//                           service it checks, not MCP servers alone. enabled is true when a check
//                           completed within liveWindow (45 minutes) of the answer.
//   counted_at              when the API read the counts
//
// Discovery uses no Shodan data, so this reader carries no Shodan attribution. poller.go
// discover enqueues only hostnames that store.go CandidateHosts matches by pattern (catalog.go
// HostPatternIndex) in ct_domains and shadow_ct_observations, and that query drops every domain
// holding a ':'; a Shodan row's domain is its ip:port (shadowctlog poller.go shodanDomain), so
// none reaches the queue.
//
// identified_no_challenge is where #2307's mistake would be made again: a server that
// identified itself as an MCP server and asked for no credentials at the handshake. MCP
// authorization is optional (MCP 2026-07-28, Authorization › Protocol Requirements), a server
// can enforce it at tools/call, and the probe never sends tools/call (mcp.go), so nothing here
// says whether such a server gives anything away. Every text says what the bucket is, and never
// calls it open, exposed or unauthenticated.
//
// What is refused, and what is left out. An API older than ?service=mcp ignores the parameter
// and answers its counts over EVERY AI service, `protected` among them (aiexposure PublicCounts);
// relayed as MCP-server counts, that is #2307 again. And the API refuses to serve counts that
// contradict its method (a 500, never a 200 that breaks a sum), so a 200 that breaks one is not
// an answer of that contract. So the radar is refused, as a per-radar failure (mcpRefusal),
// when the answer does not say service "mcp", when a headline count is missing or not a whole
// number, or when total is not the sum of the other three. Below the headline, the file's rule
// for a known field in an unexpected shape holds: a partition is relayed only with exactly its
// buckets, each a whole number, adding up to the count it divides, or it is left out whole and
// named, since a partition missing a bucket, or carrying one this version cannot label, is an
// undercount that reads as complete. A field this version does not know is left out, and named
// only when its name is shaped like a field name: the answer is counts only, a key could itself
// be a hostname, and the tool repeats no string the answer carries but its timestamps.
const MCP_HEADLINE = ["total", "protected", "pending_readjudication", "not_assessed"] as const;
const MCP_CHALLENGE_REASONS = [
  "resource_mismatch",
  "cross_origin_pointer",
  "bare_challenge_no_prm",
  "pointer_unreachable",
  "pointer_invalid",
  "no_authorization_servers",
  "wellknown_unreachable",
  "metadata_invalid",
] as const;
const MCP_PARTITIONS = {
  not_assessed_by_reason: {
    of: "not_assessed",
    buckets: ["identified_no_challenge", ...MCP_CHALLENGE_REASONS, "challenge_unadjudicated", "no_http_answer", "not_identified_as_mcp"],
  },
  prm_via: { of: "protected", buckets: ["header", "wellknown_path", "wellknown_root"] },
  era: { of: "total", buckets: ["legacy", "dual", "modern", "unknown", "not_measured"] },
  transport: { of: "total", buckets: ["streamable_http", "legacy_sse", "unknown", "not_measured"] },
} as const satisfies Record<string, { of: (typeof MCP_HEADLINE)[number]; buckets: readonly string[] }>;
type MCPPartition = keyof typeof MCP_PARTITIONS;
const MCP_PARTITION_NAMES = Object.keys(MCP_PARTITIONS) as MCPPartition[];
const MCP_INSTANTS = ["last_run_at", "counted_at"] as const;
const MCP_KNOWN = new Set<string>(["service", ...MCP_HEADLINE, ...MCP_PARTITION_NAMES, "own_controls_excluded", "withheld_opted_out", "window", "enabled", ...MCP_INSTANTS]);
// What each challenge reason code says (prm.go prmReasonCodes), for the note.
const MCP_CHALLENGE_MEANS: Record<(typeof MCP_CHALLENGE_REASONS)[number], string> = {
  resource_mismatch: "the document's resource is absent or not identical to the server's identifier",
  cross_origin_pointer: "the challenge pointed to metadata on another origin, which EchelonGraph does not request",
  bare_challenge_no_prm: "no metadata URL was named and neither well-known URI answered 2xx",
  pointer_unreachable: "the same-origin metadata URL did not answer 2xx in full",
  pointer_invalid: "the metadata pointer is not a URL EchelonGraph will request",
  no_authorization_servers: "the document names no authorization server",
  wellknown_unreachable: "a well-known metadata request got no complete HTTP answer",
  metadata_invalid: "the answer is not a 200 JSON object within the size cap",
};
// A count as the MCP answer states one: a whole number, zero or more.
const isWhole = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
// The shape of a field name. An unknown key of this shape is named when left out; any other is
// counted, not repeated, since it could be a hostname.
const FIELD_NAME = /^[a-z][a-z0-9_]{0,63}$/;
// core-backend aiexposure handler.go liveWindow: how recently a check must have completed for
// the API to answer enabled true. A liveness window, not a re-probe interval.
// MCP_CHALLENGE_REASONS as the tool description names them, spelled out as ONE constant string: the
// description is published, and the site's tool-claims check (marketing-site lib/mcpToolClaims.test.ts)
// reads every description statically, folding only references to constant strings, so a .map() here
// made the whole description unreadable to it. tools.test.mjs pins this to MCP_CHALLENGE_REASONS.
const MCP_CHALLENGE_REASON_FIELDS =
  "mcp_servers.not_assessed_by_reason.resource_mismatch, mcp_servers.not_assessed_by_reason.cross_origin_pointer, mcp_servers.not_assessed_by_reason.bare_challenge_no_prm, mcp_servers.not_assessed_by_reason.pointer_unreachable, mcp_servers.not_assessed_by_reason.pointer_invalid, mcp_servers.not_assessed_by_reason.no_authorization_servers, mcp_servers.not_assessed_by_reason.wellknown_unreachable and mcp_servers.not_assessed_by_reason.metadata_invalid";
const MCP_ENABLED_WITHIN = "45 minutes";

// Why an ?service=mcp answer is not relayed at all, or undefined when it can be read. The
// sentence quotes no value the answer carries.
function mcpRefusal(body: object): string | undefined {
  if (!isPlainObject(body)) return "the answer is not a JSON object carrying the MCP-server counts";
  if (body.service === undefined) {
    return "the answer carries no service field, so it is not the MCP-server counts: an API older than service=mcp ignores that parameter and answers the AI-exposure radar's counts over every AI service it checks, which this tool does not relay as MCP-server counts";
  }
  if (body.service !== "mcp") return "the answer names a service other than mcp, so it is not the MCP-server counts";
  const bad = MCP_HEADLINE.filter((k) => !isWhole(body[k]));
  if (bad.length) return `its ${listed(bad)} ${be(bad.length)} missing or not a whole number of zero or more, so its counts are not relayed`;
  const [total, protectedN, pending, notAssessed] = MCP_HEADLINE.map((k) => body[k] as number);
  if (total !== protectedN + pending + notAssessed) {
    return "its counts contradict each other (total is not protected + pending_readjudication + not_assessed, an answer the API's own integrity check does not serve), so they are not relayed";
  }
  return undefined;
}

function readMCPServers(src: Record<string, unknown>): { data: object; sentences: string[] } {
  const data: Record<string, unknown> = {};
  const unusable: string[] = [];
  const unsummed: string[] = [];
  for (const k of MCP_HEADLINE) data[k] = src[k];
  for (const k of MCP_PARTITION_NAMES) {
    const { of, buckets } = MCP_PARTITIONS[k];
    const v = src[k];
    const exact = isPlainObject(v) && Object.keys(v).length === buckets.length && buckets.every((b) => Object.prototype.hasOwnProperty.call(v, b) && isWhole(v[b]));
    if (!exact) {
      unusable.push(k);
      continue;
    }
    if (buckets.reduce((sum, b) => sum + (v[b] as number), 0) !== src[of]) {
      unsummed.push(k);
      continue;
    }
    data[k] = Object.fromEntries(buckets.map((b) => [b, v[b]]));
  }
  if (isWhole(src.own_controls_excluded)) data.own_controls_excluded = src.own_controls_excluded;
  else unusable.push("own_controls_excluded");
  // An API older than #2822 carries no withheld_opted_out, and counted those rows (the note says
  // so); one that carries it in another shape has it left out and named.
  if (isWhole(src.withheld_opted_out)) data.withheld_opted_out = src.withheld_opted_out;
  else if (src.withheld_opted_out !== undefined) unusable.push("withheld_opted_out");
  // window: from and to, both real instants, from not after to. With no row counted the API has
  // no window to give (null, or from and to null), and none is relayed.
  const w = src.window;
  const from = strAt(w, "from");
  const to = strAt(w, "to");
  const noWindow = w === null || w === undefined || (isPlainObject(w) && w.from === null && w.to === null && Object.keys(w).length === 2);
  if (isPlainObject(w) && Object.keys(w).length === 2 && realInstant(from) && realInstant(to) && Date.parse(from) <= Date.parse(to)) data.window = { from, to };
  else if (!(noWindow && src.total === 0)) unusable.push("window");
  if (typeof src.enabled === "boolean") data.enabled = src.enabled;
  else unusable.push("enabled");
  // A timestamp that is not a real instant is not relayed as one (readRadar's rule).
  for (const k of MCP_INSTANTS) {
    const s = strAt(src, k);
    if (realInstant(s)) data[k] = s;
    else if (src[k] !== undefined && src[k] !== null && typeof src[k] !== "string") unusable.push(k);
  }
  const extra = Object.keys(src).filter((k) => !MCP_KNOWN.has(k));
  const named = extra.filter((k) => FIELD_NAME.test(k));
  const unnamed = extra.length - named.length;

  const sentences: string[] = [];
  const n = (k: string): number => data[k] as number;
  const b = (p: MCPPartition, bucket: string): string => `mcp_servers.${p}.${bucket} (${(data[p] as Record<string, number>)[bucket]})`;
  sentences.push(
    `MCP servers: mcp_servers.total (${n("total")}) counts hostnames the AI-exposure radar has checked for an MCP server, each once, by its latest verdict on record; each was named like an MCP server in EchelonGraph's own Certificate Transparency feed, and not every one is an MCP server.`,
  );
  if (n("total") === 0) sentences.push("mcp_servers.total is 0: the radar holds no verdict on record for a hostname named like an MCP server.");
  sentences.push(
    `mcp_servers.protected (${n("protected")}) counts hostnames whose /mcp endpoint asked for credentials (a 401 or 403) and whose OAuth protected-resource metadata validated under RFC 9728: a 200 JSON document whose resource is identical to the server's identifier and that names at least one authorization server.`,
  );
  if (data.prm_via) {
    sentences.push(
      `mcp_servers.prm_via divides them by where that document was found: ${b("prm_via", "header")}, the same-origin URL the challenge named; ${b("prm_via", "wellknown_path")}, /.well-known/oauth-protected-resource followed by the endpoint's path; and ${b("prm_via", "wellknown_root")}, that URI at the root.`,
    );
  }
  sentences.push(
    `mcp_servers.pending_readjudication (${n("pending_readjudication")}) counts verdicts decided by a rule EchelonGraph has since replaced and not yet re-checked under the current rules; they are in neither mcp_servers.protected nor mcp_servers.not_assessed.`,
    `mcp_servers.not_assessed (${n("not_assessed")}) counts the rest, whose protection the radar could not assess; not assessed does not mean unprotected${data.not_assessed_by_reason ? ", and mcp_servers.not_assessed_by_reason puts each in exactly one bucket" : ""}.`,
  );
  if (data.not_assessed_by_reason) {
    sentences.push(
      `${b("not_assessed_by_reason", "identified_no_challenge")} counts servers that identified themselves as MCP servers (a DiscoverResult, an InitializeResult, or the endpoint event of the deprecated HTTP+SSE transport) and did not ask for credentials at the handshake.`,
      "That is normal in MCP: authorization is optional in the spec, and a server can enforce it at tools/call instead, which EchelonGraph never sends, so this bucket is not a finding of exposure.",
      `Endpoints that asked for credentials (a 401 or 403) but whose RFC 9728 metadata did not validate are counted by why: ${MCP_CHALLENGE_REASONS.map((r, i) => `${i === MCP_CHALLENGE_REASONS.length - 1 ? "and " : ""}${b("not_assessed_by_reason", r)}, ${MCP_CHALLENGE_MEANS[r]}`).join("; ")}.`,
      "Each of those endpoints asked for credentials, so none of them is shown to lack protection: only its metadata did not validate.",
      `${b("not_assessed_by_reason", "challenge_unadjudicated")} counts endpoints that asked for credentials before EchelonGraph read RFC 9728 metadata, not re-checked since.`,
      `${b("not_assessed_by_reason", "no_http_answer")} counts hostnames that gave no HTTP answer (DNS, TCP or TLS failed, or the request timed out), and ${b("not_assessed_by_reason", "not_identified_as_mcp")} hostnames that answered HTTP with nothing that identified an MCP server (a login or error page, a body that is not JSON-RPC, a 4xx or 5xx): neither is a count of MCP servers.`,
    );
  }
  if (data.era) {
    sentences.push(
      `mcp_servers.era divides every counted hostname by the protocol era its answer identified: ${b("era", "legacy")}, an initialize-era server (an InitializeResult, or the legacy SSE endpoint event); ${b("era", "dual")}, answered server/discover and named an initialize-era version too, a lower bound, since a server built on the reference SDK names only modern versions there and is counted modern; ${b("era", "modern")}, answered server/discover and named no initialize-era version, not proven modern-only, since EchelonGraph does not send initialize to tell; ${b("era", "unknown")}, nothing identified an era, every credential challenge included; and ${b("era", "not_measured")}, a verdict recorded before EchelonGraph's probe began recording the era and not re-checked since.`,
    );
  }
  if (data.transport) {
    sentences.push(
      `mcp_servers.transport divides them by the transport that identified the server: ${b("transport", "streamable_http")}, a POST to /mcp; ${b("transport", "legacy_sse")}, the endpoint event of GET /sse (the deprecated HTTP+SSE transport); ${b("transport", "unknown")}, nothing identified one; and ${b("transport", "not_measured")}, recorded before the era probe and not re-checked since.`,
    );
  }
  if (data.own_controls_excluded !== undefined) {
    sentences.push(`mcp_servers.own_controls_excluded (${n("own_controls_excluded")}) counts EchelonGraph's own control servers, which are left out of every other mcp_servers number.`);
  }
  if (data.withheld_opted_out !== undefined) {
    sentences.push(
      `mcp_servers.withheld_opted_out (${n("withheld_opted_out")}) counts hostnames whose owner opted out of EchelonGraph's scanning: they are not checked again while the opt-out stands, so their last verdict cannot be re-checked, and they are left out of every other mcp_servers number.`,
    );
  } else if (src.withheld_opted_out === undefined) {
    sentences.push(
      "The answer does not say how many hostnames whose owner opted out of scanning it withheld (mcp_servers.withheld_opted_out), so its counts may include such a hostname's last verdict, which is not re-checked while the opt-out stands.",
    );
  }
  if (data.window) {
    sentences.push(
      `mcp_servers.window says when the verdicts counted were last checked: the oldest at ${from} (mcp_servers.window.from) and the newest at ${to} (mcp_servers.window.to), so the counts are each hostname's latest verdict, not one sweep at one time.`,
    );
  }
  const at = data.last_run_at;
  if (typeof at === "string") {
    sentences.push(
      `mcp_servers last completed check: ${at} (mcp_servers.last_run_at, a timestamp, not a count).`,
      "mcp_servers.last_run_at is when the AI-exposure radar, which checks other AI services as well as MCP servers, last finished a cycle whose reads succeeded and whose scan opt-out register answered.",
      "mcp_servers.last_run_at is not the time of every verdict the mcp_servers numbers count (mcp_servers.window says when those were checked); nor is it mcp_servers.counted_at, when the API read those numbers.",
    );
  }
  if (data.enabled === true) {
    sentences.push(`mcp_servers.enabled is true: the API reports the AI-exposure radar running, a check having completed within ${MCP_ENABLED_WITHIN} of its answer.`);
  } else if (data.enabled === false) {
    sentences.push(
      `mcp_servers.enabled is false: the API does not report the AI-exposure radar running (no check completed within ${MCP_ENABLED_WITHIN} of its answer), so these numbers may be stale.`,
    );
  }
  if (typeof data.counted_at === "string") {
    sentences.push(`mcp_servers.counted_at (${data.counted_at}) is when the API read these counts: a timestamp, not a count, and not when any verdict was checked.`);
  }
  sentences.push(...leftOut("mcp_servers", named, unusable));
  if (unsummed.length) sentences.push(`Left out of mcp_servers because their buckets do not add up to the count they divide: ${unsummed.join(", ")}.`);
  if (unnamed) {
    sentences.push(
      `Also left out of mcp_servers: ${unnamed} field${unnamed === 1 ? "" : "s"} whose name is not shaped like a field name, not repeated here, since a name could itself identify a server.`,
    );
  }
  return { data, sentences };
}

const EXPOSURE_RADAR_DESCRIPTION =
  `Aggregate totals from EchelonGraph's internet-exposure radars, each refreshed on its own schedule: internet-facing services running actively-exploited (CISA-KEV) CVEs, plus the ransomware-linked subset, derived from Shodan data; unauthenticated data stores and observability UIs, found through Shodan (LeakIX when Shodan query credits run low) and then confirmed by EchelonGraph's own identified check (not a pure read: on Redis it names its client, and on ClickHouse its query is recorded in the server's query log); leaked credentials sampled from public GitHub push events; and shadow AI services found through Certificate Transparency logs and Shodan and then checked by EchelonGraph's identified probes. It also gives MCP-server counts: hostnames named like an MCP server in EchelonGraph's own Certificate Transparency feed (no Shodan data), each counted once by its latest verdict from EchelonGraph's identified MCP probe, which never sends tools/call. Every number in the result is labelled here and in the result's note by what it counts; a field this version cannot label is left out and named in the note. ` +
    `kev_exposure: kev_exposure.distinct_hosts counts distinct ip:port services, not machines (a machine answering on two ports counts twice), with at least one CISA-KEV-listed CVE on record, and kev_exposure.ransomware_hosts those with a ransomware-linked one; kev_exposure.kev_cves_exposed and kev_exposure.ransomware_cves count distinct CVEs with at least one such service; kev_exposure.correlations counts service×CVE pairs, not services, so a service with three KEV CVEs counts three times. kev_exposure.top_products, kev_exposure.top_countries and kev_exposure.top_cves rank up to 12 products, 10 countries and 12 CVEs by those services; kev_exposure.top_cves[].cvss_v3_score and kev_exposure.top_cves[].epss_score are the highest CVSS v3 base score and EPSS probability recorded on that CVE's observations. kev_exposure.trend counts service×CVE pairs still on record by the week in which each was first recorded, over 12 weeks, so earlier weeks read low. kev_exposure.newest_kev lists the 15 CVEs that EchelonGraph's CVE records most recently mark as CISA-KEV-listed, each with an exposure_state: exposed, where kev_exposure.newest_kev[].exposed_hosts counts distinct ip:port services on record with it; or not_assessed, where the API's answer holds no measurement for that CVE (its 0 is not one) and no count is relayed, and this answer does not say whether the radar tracks that CVE: tracking is answered per CVE. kev_exposure.newest_kev[].cvss_v3_score and kev_exposure.newest_kev[].epss_score are the CVE record's CVSS v3 base score and EPSS probability. ` +
    `exposed_databases: exposed_databases.distinct_hosts counts distinct ip:port services the check confirmed answering without authentication, and exposed_databases.engines the distinct engine types among them; exposed_databases.top_engines and exposed_databases.top_countries rank up to 15 engines and 10 countries by those services. exposed_databases.pii_likely and exposed_databases.pci_likely count services whose schema names (never record values) pass a high-confidence, precision-first gate for personal or payment-card data, so a service outside them is not shown to hold no such data. exposed_databases.window.from and exposed_databases.window.to are timestamps, not counts: when EchelonGraph's check last confirmed the oldest and the newest of the services counted, a span of checks made at different times; with a counted service that has no such time on record there is no window. ` +
    `leaked_credentials: leaked_credentials.total counts (repository, secret) pairs, not distinct secrets, so one secret in three repositories counts three times; leaked_credentials.distinct_secrets counts each secret once and leaked_credentials.distinct_repos counts repositories; leaked_credentials.top_providers and leaked_credentials.top_types rank up to 15 providers and secret types by those pairs. None is validated: each is a credential-shaped string that passed EchelonGraph's filters, at most structurally checked and never tested against its provider. leaked_credentials.window.from and leaked_credentials.window.to are timestamps, not counts: when EchelonGraph's detector last found the oldest and the newest of the pairs counted. Each of those three radars also carries generated_at, when the API computed its totals, and, when the API can tell, last_run_at. kev_exposure.last_run_at, exposed_databases.last_run_at and leaked_credentials.last_run_at are timestamps, not counts: each is when that radar last completed a check, a cycle whose reads succeeded, among them a Shodan search (for exposed_databases, or its LeakIX fallback) that answered at least one query, or for leaked_credentials a read of the public GitHub event stream. A cycle that read nothing does not move it, and it is not the time of every record a radar's numbers count, which cover everything still on record, not only what the last check found. A radar whose answer carries no last_run_at has none in the result, and the note says nothing about it. ` +
    `shadow_ai: the result is regrouped by what each number counts. shadow_ai.confirmed_exposed counts services EchelonGraph's probes found answering without an authentication gate (liveness active, or rechecking during a re-check): confirmed_exposed.total is the sum of confirmed_exposed.by_category, and confirmed_exposed.last_24h counts those first recorded in the last 24 h. Of the shadow_ai numbers, only confirmed_exposed counts exposed services. confirmed_exposed.window.from and confirmed_exposed.window.to are timestamps, not counts: when EchelonGraph's verifier ran the probe that last decided the oldest and the newest of those services, a span of probes made at different times. shadow_ai.observed counts every Certificate Transparency or Shodan observation on record, whatever its verification state: its numbers are observed, not exposed. They are observed.total; observed.by_category (the same observations by category); observed.last_24h (those first recorded in the last 24 h); observed.trend_30d (observations per UTC day over the last 30 days); and observed.top_products, observed.top_countries and observed.top_issuers (up to ten products, countries and issuers ranked by observations, where an issuer is the certificate's CA for a Certificate Transparency observation and the hosting operator Shodan reports for a Shodan one). shadow_ai.authentication counts observations by probe outcome: authentication.observed where a probe observed an authentication gate (a 401/403, a login page or an auth marker), and authentication.not_determined where the service answered but no probe could tell. Neither authentication count is part of confirmed_exposed, and observed.total minus confirmed_exposed.total is not a count of secured services. The shadow-AI poller block carries only running and last_run_at: last_run_at is when the radar's leader last completed a Certificate Transparency (crt.sh) cycle, and its running is true only when that was within ${SHADOW_AI_SILENT_AFTER} of the answer. ` +
    `mcp_servers: counts and timestamps only, no hostname. mcp_servers.total counts hostnames the AI-exposure radar has checked for an MCP server, each once by its latest verdict on record, and not every one is an MCP server; EchelonGraph's own control servers are left out, and mcp_servers.own_controls_excluded counts them; hostnames whose owner opted out of scanning are not checked again while the opt-out stands, so their last verdict is left out too, and mcp_servers.withheld_opted_out counts them. mcp_servers.total is mcp_servers.protected plus mcp_servers.pending_readjudication plus mcp_servers.not_assessed. mcp_servers.protected counts hostnames whose /mcp endpoint asked for credentials and whose OAuth protected-resource metadata validated under RFC 9728; mcp_servers.prm_via divides them by where that document was found: mcp_servers.prm_via.header, mcp_servers.prm_via.wellknown_path and mcp_servers.prm_via.wellknown_root. mcp_servers.pending_readjudication counts verdicts of a rule since replaced, not yet re-checked. mcp_servers.not_assessed counts the rest, whose protection the radar could not assess (not assessed does not mean unprotected), and mcp_servers.not_assessed_by_reason puts each in one bucket. mcp_servers.not_assessed_by_reason.identified_no_challenge holds servers that identified themselves as MCP servers and did not ask for credentials at the handshake. That is normal in MCP: authorization is optional in the spec, and a server can enforce it at tools/call instead, which EchelonGraph never sends, so this bucket is not a finding of exposure. ${MCP_CHALLENGE_REASON_FIELDS} hold endpoints that asked for credentials but whose RFC 9728 metadata did not validate, by why, so none of them is shown to lack protection; mcp_servers.not_assessed_by_reason.challenge_unadjudicated holds endpoints that asked for credentials before that check existed, not yet re-checked. mcp_servers.not_assessed_by_reason.no_http_answer holds hostnames that gave no HTTP answer, and mcp_servers.not_assessed_by_reason.not_identified_as_mcp hostnames whose HTTP answer identified no MCP server. mcp_servers.era divides every counted hostname by protocol era: mcp_servers.era.legacy; mcp_servers.era.dual, a lower bound; mcp_servers.era.modern, not proven modern-only; mcp_servers.era.unknown; and mcp_servers.era.not_measured, recorded before the era probe and not re-checked since. mcp_servers.transport divides them by transport: mcp_servers.transport.streamable_http, mcp_servers.transport.legacy_sse, mcp_servers.transport.unknown and mcp_servers.transport.not_measured. mcp_servers.window.from and mcp_servers.window.to are when the oldest and the newest of the verdicts counted were last checked. mcp_servers.last_run_at is a timestamp, not a count: when the AI-exposure radar, which checks other AI services too, last completed a check; mcp_servers.enabled is whether one completed within ${MCP_ENABLED_WITHIN} of the answer, and mcp_servers.counted_at is when the API read the counts. A partition whose buckets do not add up to the count it divides is left out and named; an answer that does not say it is the MCP-server counts, or whose mcp_servers.total, mcp_servers.protected, mcp_servers.pending_readjudication and mcp_servers.not_assessed are missing or contradict each other, is a failure. ${SHODAN_OWNERSHIP}`;

// exposure_radar's envelope. Every radar answered, but no stats answer says when the services
// or records it counts were observed: each count covers everything that radar still holds on
// record, and the answer carries only generated_at (when the API computed the totals) and
// last_run_at (the radar's last completed check), neither of which is that time (#2335). So
// the result is not_assessed with measured_at null, and says why; its numbers keep their labels,
// and freshness carries each radar's last_run_at where the API serves one.
//
// mcp_servers (#2315) does not change that, by the envelope's own rule (the `state` block above
// the State type): an exposure count is measured only with measured_at, "when the underlying
// observation was made, as the API states it", and otherwise it is not_assessed and relayed as
// what the source holds on record. The MCP answer states no such time. Its counts are each
// hostname's LATEST verdict, and window.from and window.to are the oldest and newest last-check
// times over the counted rows, a span of checks made at different times, not one observation.
// Taking window.to as measured_at would date every count by its newest verdict, the reading
// #2335 and #2439 refuse for last_run_at and last_seen; window.from would date each one by its
// oldest. And the envelope is one for five radars, four of which carry no time of observation at
// all, so a measured state would date their numbers too (#2313 done-means 5). So the state stays
// not_assessed with measured_at null, the window is relayed in data and labelled by the note,
// and the envelope's own note names it.
const RADAR_METHOD =
  "Aggregate counts over what each radar holds on record: kev_exposure, Shodan banners whose version maps to a CISA-KEV-listed CVE; exposed_databases, services found through Shodan (LeakIX when Shodan query credits run low) and confirmed by EchelonGraph's own identified check; leaked_credentials, credential-shaped strings in public GitHub push events; shadow_ai, services found through Certificate Transparency logs and Shodan and checked by EchelonGraph's identified probes; mcp_servers, the latest verdict on record per hostname named like an MCP server in EchelonGraph's own Certificate Transparency feed, from EchelonGraph's identified MCP probe (server/discover, and initialize only if that is refused; never tools/call), where protected means the endpoint's RFC 9728 protected-resource metadata validated.";
const RADAR_NAMES = RADARS.map(([name]) => name);
const RADAR_STATE_NOTE =
  "state is not_assessed: every radar answered, but none gives one time at which what it counts was observed: kev_exposure gives none, and exposed_databases, leaked_credentials, shadow_ai's confirmed_exposed and mcp_servers date what they count at most by a window (exposed_databases.window, leaked_credentials.window, shadow_ai.confirmed_exposed.window, mcp_servers.window), from the oldest observation among the rows counted to the newest, so no count here is presented as a dated measurement and measured_at is null. Each count is what that radar holds on record, and the note labels each one by what it counts.";
const RADAR_FRESHNESS_NOTE =
  "freshness gives each radar's last completed check where the API serves one (freshness.kev_exposure.last_run_at, freshness.exposed_databases.last_run_at, freshness.leaked_credentials.last_run_at, freshness.shadow_ai.last_run_at with freshness.shadow_ai.running, and freshness.mcp_servers.last_run_at with freshness.mcp_servers.enabled), and null where it does not.";

type RadarFailure = { radar: string; kind: Failure["kind"]; path: string; status: number | null; message: string };

async function exposureRadar(): Promise<ToolResult> {
  const tool = "exposure_radar";
  try {
    const results = await Promise.all(RADARS.map(([, path]) => api(path)));
    const data: Record<string, object> = {};
    const failures: [string, Failure][] = [];
    RADARS.forEach(([name, path], i) => {
      const r = results[i];
      if (!r.ok) return void failures.push([name, r]);
      // mcp_servers is read only when the answer is the MCP-server counts at all (mcpRefusal): an
      // answer that is not is a failure of that radar, named like any other, never zeros.
      const refused = name === "mcp_servers" ? mcpRefusal(r.data) : undefined;
      if (refused === undefined) data[name] = r.data;
      else failures.push([name, { ok: false, kind: "unexpected_shape", path, status: r.status, detail: refused }]);
    });
    if (failures.length) {
      // All or nothing: a radar picture with one quadrant missing reads as the whole one,
      // and the missing quadrant reads as zero. Name every failure; withhold the rest.
      const answered = Object.keys(data);
      const lines = failures.map(([name, f]) => `- ${name}: ${describeFailure(f)}`);
      const withheld = answered.length
        ? ` The ${answered.length} radar(s) that did answer (${answered.join(", ")}) are withheld: a partial radar picture would be read as the whole one.`
        : "";
      const message = `${tool} FAILED: ${failures.length} of ${RADARS.length} radars could not be read from ${SHOWN_BASE}.\n${lines.join("\n")}\n${NOT_A_FINDING}${withheld}`;
      const radars: RadarFailure[] = failures.map(([radar, f]) => ({ radar, kind: f.kind, path: f.path, status: f.status ?? null, message: f.detail }));
      return failure(
        "failed",
        message,
        { kind: "radars", path: null, status: null, message: `${failures.length} of ${RADARS.length} radars could not be read`, radars },
        { radars: RADAR_NAMES, answered, failed: failures.map(([name]) => name) },
      );
    }
    // Each radar's answer is relayed cut to the fields its reader can label, in RADARS order.
    const read = {
      kev_exposure: readKEVExposure(data.kev_exposure),
      exposed_databases: readExposedDatabases(data.exposed_databases),
      leaked_credentials: readLeakedCredentials(data.leaked_credentials),
      shadow_ai: readShadowAI(data.shadow_ai),
      mcp_servers: readMCPServers(data.mcp_servers as Record<string, unknown>),
    };
    const relayed: Record<string, object> = {};
    const said: string[] = [];
    for (const [name] of RADARS) {
      relayed[name] = read[name].data;
      said.push(...read[name].sentences);
    }
    // Only what the readers relayed: a last_run_at that is not a real instant never got there.
    const stamp = (radar: string, ...keys: string[]): string | null => instantOrNull(strAt(relayed[radar], ...keys));
    const running = boolAt(relayed.shadow_ai, "poller", "running");
    const enabled = boolAt(relayed.mcp_servers, "enabled");
    return succeeded(
      relayed,
      `${okHead(tool)} All ${RADARS.length} radars answered: ${RADARS.map(([name]) => name).join(", ")}. Every number relayed is labelled below by what it counts, and a field this version cannot label is left out and named. ${said.join(" ")} ${RADAR_SOURCES} ${SHODAN_OWNERSHIP} Each radar refreshes on its own schedule.`,
      {
        state: "not_assessed",
        measured_at: null,
        method: RADAR_METHOD,
        coverage: { radars: RADAR_NAMES, answered: RADAR_NAMES, failed: [] },
        freshness: {
          kev_exposure: { last_run_at: stamp("kev_exposure", "last_run_at") },
          exposed_databases: { last_run_at: stamp("exposed_databases", "last_run_at") },
          leaked_credentials: { last_run_at: stamp("leaked_credentials", "last_run_at") },
          shadow_ai: { last_run_at: stamp("shadow_ai", "poller", "last_run_at"), running: running ?? null },
          mcp_servers: { last_run_at: stamp("mcp_servers", "last_run_at"), enabled: enabled ?? null },
        },
        notes: [RADAR_STATE_NOTE, RADAR_FRESHNESS_NOTE],
      },
    );
  } catch (e) {
    return crashed(tool, e);
  }
}

// ── outputSchema: the envelope, per tool (#2311, #2313) ──
//
// A discriminated union on state: a success (measured, not_assessed) carries data and a method;
// a failure (failed, invalid_input) carries error, and measured_at, method and freshness null.
// The CVE-feed and cve_exposure tools relay the API's JSON verbatim as data, so their data
// schemas name the fields the tool descriptions mention and admit the rest (a field the API
// adds later must not turn an answer into a failure). exposure_radar's data is the tool's own
// cut, so its schema is closed: exactly the fields the readers relay, and nothing else.
const Instant = z.string().describe("An RFC 3339 instant.");
const ERROR_KINDS = ["network", "timeout", "http", "not_json", "not_object", "invalid_input", "internal", "unexpected_shape", "radars"] as const;
const ErrorSchema = z.strictObject({
  kind: z.enum(ERROR_KINDS).describe("What failed: the request (network, timeout), the answer (http, not_json, not_object, unexpected_shape), the input, or this server."),
  path: z.string().nullable().describe("The API path requested, when a request was made."),
  status: z.number().int().nullable().describe("The HTTP status, when the API answered one."),
  message: z.string().describe("The cause: the API's own message, or what went wrong."),
});
export const NOTES = z.array(z.string()).describe("Caveats, one sentence each.");
// The success states (#2465). 2.1.0 described not_assessed as no dated measurement whose numbers
// were all denied the status of findings, on the same schema as a cve_exposure answer relaying
// services on record for a CISA-KEV CVE, which is not_assessed because its count is undated
// (#2439). A client that respects the schema was told that count is not a finding. The count is
// what the radar holds on record: not a dated measurement, and not nothing. So the description
// says both, and leaves what each count is to the notes and exposure_state, which say it per
// answer; it makes no blanket claim about the numbers, in either direction.
const SUCCESS_STATE =
  "measured: a measurement of what was asked; an exposure count is measured only with measured_at and method. not_assessed: the answer holds no dated measurement of what was asked, so no count in it is presented as one; it can still relay a count, as what the source holds on record, undated, and its notes (and exposure_state, where the result carries it) say what each count is.";

export function envelopeSchema(o: {
  data: z.ZodType;
  coverage: z.ZodType | null;
  freshness: z.ZodType | null;
  extra?: Record<string, z.ZodType>;
  error?: z.ZodType;
}) {
  const coverage = o.coverage ? o.coverage.nullable() : z.null();
  return z.discriminatedUnion("state", [
    z.strictObject({
      state: z.enum(["measured", "not_assessed"]).describe(SUCCESS_STATE),
      measured_at: Instant.nullable().describe("When the underlying observation was made, as the API states it; null when the answer does not say or holds no observation."),
      method: z.string().describe("How the numbers were produced."),
      coverage: coverage.describe("What the answer covers; null where the answer says nothing about it."),
      freshness: (o.freshness ? o.freshness.nullable() : z.null()).describe("The producing radar's last completed check (last_run_at), where the API serves one."),
      notes: NOTES,
      ...(o.extra ?? {}),
      data: o.data,
    }),
    z.strictObject({
      state: z.enum(["failed", "invalid_input"]).describe("failed: the lookup did not complete. invalid_input: the input was refused, so nothing was looked up. Neither is a finding."),
      measured_at: z.null(),
      method: z.null(),
      coverage,
      freshness: z.null(),
      notes: NOTES,
      error: o.error ?? ErrorSchema,
    }),
  ]);
}

// A field of the API's JSON: optional, and null where the Go type can marshal null.
export const opt = <T extends z.ZodType>(t: T) => t.nullable().optional();
// #2720: what cpe_match and cpe_configurations are, one constant string each (the site's
// tool-claims check folds only constant strings).
const CPE_MATCH_DESCRIPTION =
  "The record's CPE match criteria as one flat list, every configuration's cpeMatch entries together: the AND/OR operator and negate of each configuration and node, versionStartExcluding and matchCriteriaId are not in it, so a CPE that is only a platform a product runs on reads as one more entry.";
const CPE_CONFIGURATIONS_DESCRIPTION =
  "NVD's configurations array as NVD sent it: each configuration and node with its operator (AND, OR) and negate, and each cpeMatch with criteria, vulnerable, versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding and matchCriteriaId. A cpeMatch with vulnerable false inside an AND configuration is the platform the vulnerable product runs on, not an affected product. Absent: EchelonGraph holds no stored NVD configuration for the CVE, which is not a finding that no product is affected.";
const CVERecord = z.looseObject({
  cve_id: opt(z.string()),
  description: opt(z.string()),
  severity: opt(z.string()),
  cvss_v3_score: opt(z.number()),
  cvss_v4_score: opt(z.number()),
  cvss_v4_severity: opt(z.string()),
  // #2535: the score is a score only beside score_assessed true (see cveScoreNote).
  echelongraph_score: opt(z.number()).describe("EchelonGraph's 0-10 score for the CVE: a score only when score_assessed is true. With score_assessed false it is a placeholder, not a rating."),
  echelongraph_severity: opt(z.string()).describe("The severity band of echelongraph_score: a rating only when score_assessed is true. With score_assessed false it is a placeholder (NONE)."),
  echelongraph_risk: opt(z.number()).describe("EchelonGraph's 0-100 risk priority, fused from the score, exploitation and automatability: a rating only when score_assessed is true. With score_assessed false it is a placeholder."),
  score_confidence: opt(z.string()),
  score_assessed: opt(z.boolean()).describe(
    "Whether EchelonGraph has scored the CVE. true: echelongraph_score, echelongraph_severity and echelongraph_risk are its score. false: the CVE is NOT YET SCORED, not scored 0, and any of those three it carries is a placeholder, not a rating; the API may leave them out. Absent (an API older than the field): the answer does not say whether the CVE was scored.",
  ),
  score_unassessed_reason: opt(z.string()).describe(
    "Why score_assessed is false: no_signal, no source has yet published severity data EchelonGraph can score; or rejected, the record was withdrawn by its numbering authority and is never scored. Absent when the CVE is scored.",
  ),
  epss_score: opt(z.number()),
  epss_percentile: opt(z.number()),
  kev_listed: opt(z.boolean()),
  kev_ransomware: opt(z.boolean()),
  kev_added_date: opt(z.string()),
  ghsa_id: opt(z.string()),
  references: z.unknown().optional(),
  // #2720: NVD's configurations, losslessly, beside the flat list (see cpeConfigurationsNote).
  cpe_match: z.unknown().optional().describe(CPE_MATCH_DESCRIPTION),
  cpe_configurations: opt(z.array(z.unknown())).describe(CPE_CONFIGURATIONS_DESCRIPTION),
  published: opt(z.string()),
  modified: opt(z.string()),
  updated_at: opt(z.string()),
});

// #2647: what cve_summary says the poller block is (summaryPollerNote). Like the #2641 strings
// beside SUMMARY_NONE_DESCRIPTION, it uses none of #2610's six words ("any", "not", "rating",
// "scored", "source", "yet"), #2771's sentence on a field of another JSON type among them. Declared
// here, before the outputSchema that describes poller with it.
const SUMMARY_POLLER_DESCRIPTION =
  "poller holds the in-memory counters of the NVD poller of the one API instance that answered (cves_ingested, cves_skipped, http_retries, poll_count, poll_errors, last_poll_at, last_poll_dur_ms, interval), counted since that instance last started and zeroed on every restart: they describe that instance, never the feed's size, intake, reliability or freshness. Whenever the answer carries poller the note says so. A poller field the answer sends in a JSON type other than the one described here is left out of data and named in the note, and a poller that is neither a JSON object nor null is left out whole: summary is relayed either way.";

// One of the NVD histogram's four labelled buckets (#2641).
const nvdBand = (label: string) =>
  opt(z.number()).describe(`Of the active CVEs total counts, those whose NVD CVSS severity label is ${label}: NVD's label, as provenance, never EchelonGraph's severity band.`);
const CVE_SUMMARY_OUTPUT = envelopeSchema({
  data: z.looseObject({
    summary: z
      .looseObject({
        total: opt(z.number()),
        critical: opt(z.number()),
        high: opt(z.number()),
        medium: opt(z.number()),
        low: opt(z.number()),
        // #2610: the not-yet-scored bucket, not a rating (see summaryNoneNote).
        none: opt(z.number()).describe("The active CVEs with no severity band from any source: CVEs not yet scored, not a severity rating of None."),
        unscored: opt(z.number()).describe("The same count as none, under its own name."),
        // #2641: NVD's label, as provenance, not a rating; and the withdrawn records (see
        // summaryNVDNote and summaryRejectedNote).
        nvd_critical: nvdBand("Critical"),
        nvd_high: nvdBand("High"),
        nvd_medium: nvdBand("Medium"),
        nvd_low: nvdBand("Low"),
        nvd_none: opt(z.number()).describe(
          "Of the active CVEs total counts, those with no Critical, High, Medium or Low NVD CVSS severity label, many of them with an NVD CVSS v2 score instead: neither a count of CVEs rated None nor the count of CVEs with no severity, which is none.",
        ),
        rejected: opt(z.number()).describe("The CVE records rejected (withdrawn) by their numbering authority, which total and every other count here leave out: withdrawn records, never vulnerabilities."),
        last_updated: opt(z.string()),
      })
      .optional(),
    // #2647: one instance's counters, never the feed's (see summaryPollerNote).
    // #2771: each field's JSON type is SUMMARY_POLLER_KINDS', which summaryPollerShaped enforces
    // before this check, so a field of another type is left out, never a failed call.
    poller: z
      .looseObject({
        cves_ingested: pollerField("cves_ingested", "CVE records this instance's NVD poller wrote since the instance last started: never the feed's size or intake."),
        cves_skipped: pollerField("cves_skipped", "CVE records this instance's NVD poller skipped since the instance last started."),
        http_retries: pollerField("http_retries", "HTTP retries this instance's NVD poller made since the instance last started."),
        interval: pollerField("interval", "How often this instance's NVD poller polls."),
        last_poll_at: pollerField("last_poll_at", "When this instance's NVD poller last polled: never the feed's freshness."),
        last_poll_dur_ms: pollerField("last_poll_dur_ms", "How long that poll took, in milliseconds."),
        poll_count: pollerField("poll_count", "Polls this instance's NVD poller made since the instance last started."),
        poll_errors: pollerField("poll_errors", "Polls of this instance's NVD poller that failed since the instance last started: never the feed's reliability."),
      })
      .nullable()
      .optional()
      .describe(SUMMARY_POLLER_DESCRIPTION),
  }),
  coverage: null,
  freshness: null,
});

const SEARCH_CVES_OUTPUT = envelopeSchema({
  data: z.looseObject({
    cves: z.array(CVERecord).optional(),
    total: opt(z.number()),
    total_counted: opt(z.boolean()),
    total_is_lower_bound: opt(z.boolean()),
    search_relaxed: opt(z.boolean()),
    limit: opt(z.number()),
    offset: opt(z.number()),
  }),
  coverage: z.strictObject({
    total: z.number().nullable(),
    total_counted: z.boolean().nullable(),
    total_is_lower_bound: z.boolean().nullable(),
    search_relaxed: z.boolean().nullable(),
    returned: z.number().nullable(),
    limit: z.number().nullable(),
    offset: z.number().nullable(),
  }),
  freshness: null,
});

const GET_CVE_OUTPUT = envelopeSchema({ data: CVERecord, coverage: null, freshness: null });

const CountryRows = z.array(z.looseObject({ country: opt(z.string()), hosts: opt(z.number()) }));
const CVE_EXPOSURE_OUTPUT = envelopeSchema({
  data: z.looseObject({
    cve_id: opt(z.string()),
    exposed_hosts: opt(z.number()),
    countries: opt(z.number()),
    tracked: opt(z.boolean()),
    kev_listed: opt(z.boolean()),
    kev_catalog_listed: opt(z.boolean()),
    kev_seen_in_observations: opt(z.boolean()),
    ransomware: opt(z.boolean()),
    top_countries: opt(CountryRows),
    top_products: opt(z.array(z.looseObject({ product: opt(z.string()), hosts: opt(z.number()) }))),
    last_seen: opt(z.string()),
    method: opt(z.string()),
    generated_at: opt(z.string()),
  }),
  coverage: z.strictObject({
    in_scope: z.boolean().nullable().describe("The API's tracked verdict: whether the CVE is in the radar's tracked set; null when the answer does not say."),
  }),
  freshness: null,
  extra: {
    exposure_state: z
      .enum(["exposed", "measured_zero", "not_assessed", "tracking_unknown"])
      .nullable()
      .describe(
        "What the answer's count is, as the note's (exposure_state: …) tag says; not state, which says whether the answer is a dated measurement. exposed: data.exposed_hosts counts the services the radar holds on record for the CVE, above 0. measured_zero: the API marks the CVE as tracked with 0 services, a zero in the radar's sample. not_assessed: the CVE is outside the radar's tracked set, so its count, if any, is not a current measurement. tracking_unknown: the API does not say whether the radar tracks the CVE, so its 0 is not evidence either way. null: the answer carries no count.",
      ),
  },
});

// exposure_radar's data, from the readers' own specs, so the schema cannot drift from them.
const zKind = (k: Kind): z.ZodType => (k === "number" ? z.number() : k === "string" ? z.string() : z.boolean());
const zRow = (spec: RowSpec) =>
  z.strictObject({
    ...Object.fromEntries(Object.entries(spec.required).map(([k, kind]) => [k, zKind(kind)])),
    ...Object.fromEntries(Object.entries(spec.optional ?? {}).map(([k, kind]) => [k, zKind(kind).optional()])),
  });
// A relayed observation window (#2438): two instants, never a count.
const Window = z.strictObject({ from: Instant, to: Instant });
const zRadar = (spec: RadarSpec, rows: Record<string, z.ZodType> = {}) =>
  z.strictObject({
    ...Object.fromEntries(spec.counts.map((k) => [k, z.number().optional()])),
    ...Object.fromEntries(Object.entries(spec.rows).map(([k, rs]) => [k, (rows[k] ?? z.array(zRow(rs))).optional()])),
    ...Object.fromEntries(spec.instants.map((k) => [k, Instant.optional()])),
    ...(spec.window ? { window: Window.optional() } : {}),
  });
// A newest_kev row as newestKEVRow relays it: `tracked` is read, not relayed, and a count only
// when the row's exposure_state is not not_assessed.
const { tracked: _read, ...newestKEVOptional } = KEV_SPEC.rows.newest_kev.optional ?? {};
const NewestKEVRow = z.strictObject({
  cve_id: z.string(),
  ...Object.fromEntries(Object.entries(newestKEVOptional).map(([k, kind]) => [k, zKind(kind).optional()])),
  exposure_state: z.enum(["exposed", "measured_zero", "not_assessed"]),
  exposed_hosts: z.number().optional(),
});
const CountMap = z.record(z.string(), z.number());
const countRowsOf = (label: string) => z.array(z.strictObject({ [label]: z.string(), count: z.number() }));
const ShadowAIData = z.strictObject({
  confirmed_exposed: z
    .strictObject({ total: z.number().optional(), by_category: CountMap.optional(), last_24h: z.number().optional(), window: Window.optional() })
    .optional(),
  observed: z
    .strictObject({
      total: z.number().optional(),
      by_category: CountMap.optional(),
      last_24h: z.number().optional(),
      ...Object.fromEntries(SHADOW_AI_ROWS.map(([key, label]) => [key, countRowsOf(label).optional()])),
      last_observation: Instant.optional(),
    })
    .optional(),
  authentication: z.strictObject({ observed: z.number().optional(), not_determined: z.number().optional() }).optional(),
  poller: z.strictObject({ running: z.boolean(), last_run_at: Instant }).optional(),
});
const LastRun = z.strictObject({ last_run_at: Instant.nullable() });
// mcp_servers as readMCPServers relays it, from the same constants (#2315): the headline counts
// always (an answer without them is refused), and each partition with exactly its buckets or not
// at all.
const Whole = z.number().int().min(0);
const MCPServersData = z.strictObject({
  ...Object.fromEntries(MCP_HEADLINE.map((k) => [k, Whole])),
  ...Object.fromEntries(MCP_PARTITION_NAMES.map((k) => [k, z.strictObject(Object.fromEntries(MCP_PARTITIONS[k].buckets.map((b) => [b, Whole]))).optional()])),
  own_controls_excluded: Whole.optional(),
  withheld_opted_out: Whole.optional(),
  window: z.strictObject({ from: Instant, to: Instant }).optional(),
  enabled: z.boolean().optional(),
  ...Object.fromEntries(MCP_INSTANTS.map((k) => [k, Instant.optional()])),
});
const EXPOSURE_RADAR_OUTPUT = envelopeSchema({
  data: z.strictObject({
    kev_exposure: zRadar(KEV_SPEC, { newest_kev: z.array(NewestKEVRow) }),
    exposed_databases: zRadar(EXPOSED_DB_SPEC),
    leaked_credentials: zRadar(LEAKED_CREDS_SPEC),
    shadow_ai: ShadowAIData,
    mcp_servers: MCPServersData,
  }),
  coverage: z.strictObject({
    radars: z.array(z.string()).describe("The radars this tool reads."),
    answered: z.array(z.string()).describe("The radars that answered. On a failure their answers are withheld."),
    failed: z.array(z.string()).describe("The radars that could not be read."),
  }),
  freshness: z.strictObject({
    kev_exposure: LastRun,
    exposed_databases: LastRun,
    leaked_credentials: LastRun,
    shadow_ai: z.strictObject({ last_run_at: Instant.nullable(), running: z.boolean().nullable() }),
    mcp_servers: z.strictObject({ last_run_at: Instant.nullable(), enabled: z.boolean().nullable() }),
  }),
  error: ErrorSchema.extend({
    radars: z
      .array(
        z.strictObject({
          radar: z.string(),
          kind: z.enum(["network", "timeout", "http", "not_json", "not_object", "unexpected_shape"]),
          path: z.string(),
          status: z.number().int().nullable(),
          message: z.string(),
        }),
      )
      .optional()
      .describe("Each radar that could not be read, and why."),
  }),
});

// ── Server instructions (#2311) ──
// No sentence here names a re-probe interval; any that does must say it applies to hosts we do
// not own (the package's tests hold every shipped text to that).
const INSTRUCTIONS = [
  "EchelonGraph's public CVE and internet-exposure data, read-only and keyless.",
  "Everything these tools return is public: EchelonGraph's CVE Pulse feed, and aggregate, host-redacted totals from its exposure radars.",
  "Every result says how it was measured: state, measured_at, method, coverage, freshness and notes, in its structuredContent and again in its text.",
  "Its last text block is that structuredContent as JSON, less what an earlier text block already gives verbatim: data, which is a success's first text block; the sentences of the text block just before it (the note, or a failure's message), with which structuredContent's notes end; and method, where that block quotes it.",
  "Past 30,000 characters of JSON, that first text block holds data cut to fit, and the note says what the cut leaves out and where to read it (TEXT CUT); structuredContent's data always holds it whole.",
  "state is measured, not_assessed, failed or invalid_input.",
  "not_assessed means the answer holds no dated measurement of what was asked, so no count in it is presented as one.",
  "It can still relay a count, as what the source holds on record, undated, and its notes say what each count is: cve_exposure's exposed_hosts when its exposure_state is exposed, and exposure_radar's labelled totals, are such counts.",
  "A zero is not a finding of no exposure where the answer holds no measurement for that CVE, for example a CVE outside the KEV-exposure radar's tracked set (exposure_state not_assessed).",
  "failed and invalid_input mean nothing was measured: never report them as zero, none found or unexposed.",
  "measured_at is when the underlying observation was made, and null when the answer does not say or holds none.",
  "freshness gives the producing radar's last_run_at: when it last completed a check whose reads succeeded.",
  "That is not the time of every record the radar's numbers count, which cover everything still on record, and it is null when the API does not say.",
  "Every figure is as fresh as the schedule that refreshes it.",
  "Exposure numbers are aggregate: counts of distinct ip:port services on EchelonGraph's record (a machine answering on two ports counts twice), not machines, and not an internet-wide census.",
  "exposure_radar's mcp_servers counts hostnames instead, each by its latest verdict on record.",
  `${SHODAN_ATTRIBUTION} ${SHODAN_OWNERSHIP}`,
  "exposure_radar's mcp_servers counts use no Shodan data: their hostnames come from EchelonGraph's own Certificate Transparency feed.",
].join(" ");

export const ANNOTATIONS = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true } as const;
const CVE_ID_ARG = z.string().describe("a CVE ID, e.g. CVE-2023-44487");

// What each description says about its structured result, naming only fields its schema holds.
const FEED_ENVELOPE =
  "Its structured result carries state (measured), measured_at, method, coverage, freshness (null: the feed serves no poll-completion time) and notes, with data equal to the API's JSON; the result's last text block repeats it without data (the first text block) and without the note's sentences (the text block before it), with which notes ends.";
// #2771: cve_summary's own, since its data is the API's JSON less each poller field (or the whole
// poller) summaryPollerShaped leaves out. Like SUMMARY_POLLER_DESCRIPTION it uses none of #2610's
// six words ("any", "not", "rating", "scored", "source", "yet").
const CVE_SUMMARY_ENVELOPE =
  "Its structured result carries state (measured), measured_at, method, coverage, freshness (null: the feed serves no poll-completion time) and notes, with data equal to the API's JSON less each poller field (or the whole poller) the note names as left out; the result's last text block repeats it without data (the first text block) and without the note's sentences (the text block before it), with which notes ends.";
// #2610: what cve_summary says summary.none is (summaryNoneNote), one constant string for the same
// reason as SCORE_ASSESSED_DESCRIPTION below.
const SUMMARY_NONE_DESCRIPTION =
  "summary.none is not a severity rating of None: it counts the active CVEs with no severity band from any source, that is, CVEs not yet scored, and the answer may carry the same count again as summary.unscored. Whenever summary.none is above zero the note says so, and names those CVEs not yet scored, not CVEs rated None.";
// #2641: what cve_summary says the NVD histogram and summary.rejected are (summaryNVDNote,
// summaryRejectedNote), constant strings for the same reason. Neither uses the words "any", "not",
// "rating", "scored", "source" or "yet": the site's #2610 control (marketing-site
// lib/mcpToolClaims.test.ts) holds that exactly those words of the /pulse/mcp cve_summary row are
// backed by SUMMARY_NONE_DESCRIPTION alone, and fails if another sentence backs one.
const SUMMARY_NVD_DESCRIPTION =
  "summary.nvd_critical, summary.nvd_high, summary.nvd_medium, summary.nvd_low and summary.nvd_none count the same active CVEs as summary.total by NVD's CVSS severity label (v3.x, else v4.0; before NVD's record arrives, or where it gives none, a pre-NVD label from the CVE.org record or a GitHub advisory can stand in): provenance, never EchelonGraph's severity band. summary.nvd_none counts the active CVEs with no Critical, High, Medium or Low label there, CVEs NVD never labelled under CVSS v3 among them, and many of those carry an NVD CVSS v2 score instead: it is neither a count of CVEs rated None nor the count of CVEs with no severity, which is summary.none. Whenever summary.nvd_none is above zero the note says what it counts, with its count.";
const SUMMARY_REJECTED_DESCRIPTION =
  "summary.rejected counts the CVE records rejected (withdrawn) by their numbering authority, which summary.total and the other counts above leave out: they are withdrawn records, none of them a vulnerability.";
// #2535: what search_cves and get_cve say about score_assessed, one constant string, since the
// site's tool-claims check (marketing-site lib/mcpToolClaims.test.ts) folds only constant strings.
const SCORE_ASSESSED_DESCRIPTION =
  "echelongraph_score, echelongraph_severity and echelongraph_risk are EchelonGraph's score only when score_assessed is true. With score_assessed false the CVE is NOT YET SCORED, not scored 0: any of those three it carries (0, NONE, 0) is a placeholder, not a rating, and does not mean the CVE is harmless; the API may leave them out instead, score_confidence is NONE, and score_unassessed_reason says why (a rejected record, withdrawn by its numbering authority, is never scored, and the note says NOT SCORED). The note labels each such CVE NOT YET SCORED, which is not a score of 0. An answer with no score_assessed (an API older than that field) does not say whether the CVE was scored, the note says so, and a 0 there is not a rating either.";

// The shared helpers a tool in src/tools/ is handed (#2718), so its file holds its own logic.
const TOOL_KIT = { api, succeeded, failed, badInput, crashed, checked, okHead, envelopeSchema, annotations: ANNOTATIONS, cveIdArg: CVE_ID_ARG, instant: Instant };

// One server, built per connection by serveStdio for whichever era the client opens with, and
// per request by the hosted HTTP entrypoint (http.ts, #2316): one tool module for both.
// tools/list answers in registration order, which is the order below.
export function createServer(): McpServer {
  const server = new McpServer({ name: NAME, version: VERSION }, { instructions: INSTRUCTIONS, capabilities: { tools: { listChanged: false }, prompts: { listChanged: false }, resources: { listChanged: false } } });

  server.registerTool(
    "cve_summary",
    {
      title: "CVE feed summary",
      description: `Summary of EchelonGraph's CVE Pulse feed: summary.total active CVEs, their counts by severity band (summary.critical, summary.high, summary.medium, summary.low), the count with no band (summary.none), and summary.last_updated, the newest modification time among those records. ${SUMMARY_NONE_DESCRIPTION} ${SUMMARY_NVD_DESCRIPTION} ${SUMMARY_REJECTED_DESCRIPTION} ${SUMMARY_POLLER_DESCRIPTION} The feed is polled from its sources on a schedule, so this is the state as of that update. ${CVE_SUMMARY_ENVELOPE} ${TEXT_BUDGET_DESCRIPTION}`,
      outputSchema: CVE_SUMMARY_OUTPUT,
      annotations: ANNOTATIONS,
    },
    async () => checked("cve_summary", CVE_SUMMARY_OUTPUT, await cveSummary()),
  );

  server.registerTool(
    "search_cves",
    {
      title: "Search CVEs",
      description: `Search/list CVEs from EchelonGraph's CVE feed (NVD + MITRE-CNA pre-NVD + CISA-KEV + EPSS + GitHub GHSA, each polled on a schedule). Filter by severity, minimum CVSS, free text, and sort; page with limit and offset. Returns cves, each with cve_id, severity, cvss_v3_score, echelongraph_score and score_assessed (whether EchelonGraph has scored it), epss_score and kev_listed where the record has them, and the list's total, total_counted (false: the matches were not counted, so total is not a count), total_is_lower_bound (true: at least total), search_relaxed (true: a phrase was relaxed to all of its words), limit and offset. ${SCORE_ASSESSED_DESCRIPTION} ${FEED_ENVELOPE} coverage repeats total, total_counted, total_is_lower_bound, search_relaxed, limit and offset, and gives returned, the rows in this page. ${TEXT_BUDGET_DESCRIPTION} Cut, each row keeps at least the fields named above and the first 200 characters of its description (100 on a page too long for that), or rows are left out and the note gives the offset to call next.`,
      inputSchema: z.object({
        search: z.string().optional().describe("free-text search (product, vendor, or keyword, e.g. 'tomcat')"),
        severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"]).optional().describe("filter to one severity"),
        min_cvss: z.number().min(0).max(10).optional().describe("minimum CVSS score"),
        sort: z.enum(["published", "modified", "nvd", "echelongraph", "epss"]).optional().describe("sort order (default: published)"),
        limit: z.number().int().min(1).max(50).optional().describe("page size (default 20, max 50)"),
        // #2783: the next page, which the note names when the text leaves rows out.
        offset: z.number().int().min(0).max(10000).optional().describe("rows to skip (default 0)"),
      }),
      outputSchema: SEARCH_CVES_OUTPUT,
      annotations: ANNOTATIONS,
    },
    async (a) => checked("search_cves", SEARCH_CVES_OUTPUT, await searchCVEs(a)),
  );

  server.registerTool(
    "get_cve",
    {
      title: "CVE detail",
      description: `One CVE's record: description, severity, cvss_v3_score, cvss_v4_score and cvss_v4_severity (when the record has a CVSS v4 score), echelongraph_score and echelongraph_severity with score_confidence (EchelonGraph's multi-source score) and score_assessed (whether EchelonGraph has scored it), epss_score and epss_percentile, CISA-KEV status (kev_listed, kev_added_date, and kev_ransomware for known ransomware-campaign use), ghsa_id (GitHub GHSA), references, cpe_match (the CPE criteria as one flat list) and cpe_configurations (NVD's configurations as NVD sent them, with each AND/OR operator, negate, versionStartExcluding and matchCriteriaId; absent where EchelonGraph has stored none, which is not a finding that no product is affected), published, modified and updated_at; each field only where the record has it. Pass a CVE ID like CVE-2023-44487. ${SCORE_ASSESSED_DESCRIPTION} ${FEED_ENVELOPE} ${TEXT_BUDGET_DESCRIPTION} Cut, each list in the record keeps its first entries, and the note names each list cut with its full length.`,
      inputSchema: z.object({ cve_id: CVE_ID_ARG }),
      outputSchema: GET_CVE_OUTPUT,
      annotations: ANNOTATIONS,
    },
    async ({ cve_id }) => checked("get_cve", GET_CVE_OUTPUT, await getCVE(cve_id)),
  );

  server.registerTool(
    "cve_exposure",
    {
      title: "Internet exposure for one CVE",
      description: `${CVE_EXPOSURE_DESCRIPTION} Its structured result's state is not_assessed with measured_at null: the per-CVE answer says when EchelonGraph last wrote a row (last_seen), not when any counted service was observed, so no count is presented as a dated measurement; the count is still relayed, labelled, as what the radar holds on record. exposure_state says what the count is: exposed, measured_zero, not_assessed or tracking_unknown; coverage.in_scope is the API's tracked verdict; freshness is null, since the per-CVE answer carries no last completed check; data is the API's JSON. The result's last text block repeats the structured result without data (the first text block), without the note's sentences (the text block before it), with which notes ends, and without method where the note quotes it verbatim ("Method: …"). ${TEXT_BUDGET_DESCRIPTION}`,
      inputSchema: z.object({ cve_id: CVE_ID_ARG }),
      outputSchema: CVE_EXPOSURE_OUTPUT,
      annotations: ANNOTATIONS,
    },
    async ({ cve_id }) => checked("cve_exposure", CVE_EXPOSURE_OUTPUT, await cveExposure(cve_id)),
  );

  server.registerTool(
    "exposure_radar",
    {
      title: "Exposure radar totals",
      description: `${EXPOSURE_RADAR_DESCRIPTION} Its structured result's state is not_assessed with measured_at null: every radar answered, but none gives one time at which what it counts was observed (mcp_servers dates its verdicts at most by a window, mcp_servers.window), so no count is presented as a dated measurement; each count is still relayed, labelled, as what that radar holds on record. freshness gives each radar's last_run_at (and running for shadow_ai, enabled for mcp_servers) where the API serves one; coverage names the radars that answered; data is the relayed result above. The result's last text block repeats the structured result without data (the first text block) and without the note's sentences (the text block before it), with which notes ends. ${TEXT_BUDGET_DESCRIPTION}`,
      outputSchema: EXPOSURE_RADAR_OUTPUT,
      annotations: ANNOTATIONS,
    },
    async () => checked("exposure_radar", EXPOSURE_RADAR_OUTPUT, await exposureRadar()),
  );

  registerKevRecent(server, { api, succeeded, failed, badInput, crashed, checked, envelopeSchema, okHead, annotations: ANNOTATIONS });
  registerEPSSHistory(server, TOOL_KIT);
  // #2716: its logic, schemas and description live in tools/check_affected.ts.
  registerCheckAffected(server, { api, succeeded, failed, badInput, crashed, checked, okHead, envelopeSchema, annotations: ANNOTATIONS });

  // #2721: tools/check_sbom.ts, on this file's api(), envelope and failure contract. holdRequest
  // (#2775): on the hosted endpoint, a call keeps its request's admission and large-body slot
  // until it has stopped, not only until its answer, or its client, has gone.
  registerCheckSbom(server, { api, failed, describeFailure, badInput, crashed, checked, succeeded, okHead, envelopeSchema, annotations: ANNOTATIONS, hold: holdRequest });

  registerCveIntel(server);
  registerGetCwe(server);

  // #2719: vendor_advisories_for_cve, get_vendor_advisory, search_vendor_advisories.
  registerVendorAdvisoryTools(server, { api, failed, describeFailure, badInput, crashed, succeeded, checked, okHead, envelopeSchema, annotations: ANNOTATIONS });

  // #2722: prompts and resources, in prompts.ts and resources.ts. Both lists are fixed per
  // connection, so listChanged is false above.
  registerPrompts(server, { cveId: CVE_ID });
  registerResources(server, { api, cveId: CVE_ID, shownBase: SHOWN_BASE, sentences, getCve: async (id) => checked("get_cve", GET_CVE_OUTPUT, await getCVE(id)) });

  return server;
}

// The package identity and API settings, for the hosted HTTP entrypoint's health answer and
// start-up line (http.ts).
export { NAME, VERSION, TIMEOUT_MS }; // SHOWN_BASE is exported where it is declared.

// Both eras on stdio: a 2026-07-28 client's server/discover, and a 2025-era client's initialize.
// Not when the hosted HTTP entrypoint loaded this module (runtime.ts): it serves createServer
// itself, and a stdio transport there would read the container's stdin.
if (!isHttpEntrypoint()) {
  serveStdio(createServer, { legacy: "serve" });
  // MCP uses stdout for the protocol — diagnostics go to stderr.
  console.error(`EchelonGraph CVE MCP server ${NAME}@${VERSION} running (API: ${SHOWN_BASE}, timeout ${TIMEOUT_MS} ms)`);
}
