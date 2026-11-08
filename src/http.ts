#!/usr/bin/env node
// The hosted, keyless remote MCP endpoint: https://mcp.echelongraph.io/mcp (#2316).
//
// Streamable HTTP on @modelcontextprotocol/server 2.x's createMcpHandler, serving the SAME tool
// module as the npm package (index.ts's createServer), in both protocol eras: a 2026-07-28
// client's per-request envelope (server/discover first), and a 2025-era client's initialize,
// answered statelessly by the SDK's legacy fallback. Nothing is kept between requests: each one
// gets a fresh server from the factory.
//
//   POST /mcp     the MCP endpoint (GET and DELETE are the 2025 session operations; stateless,
//                 the SDK answers them 405)
//   OPTIONS /mcp  CORS preflight, for a browser client on an https Origin
//   GET /health   liveness. Not /healthz: Cloud Run's front end reserves paths ending in "z"
//                 and answers them itself, so a /healthz would never reach this process.
//
// HTTP/1.1 by default; HTTP/2 cleartext (h2c, prior knowledge) ONLY when MCP_H2C=1 (#2775). Cloud
// Run tells a container that its client went away only over HTTP/2 or a WebSocket ("When you use
// HTTP/1.1 on Cloud Run, client disconnect events are not propagated to the Cloud Run container",
// https://docs.cloud.google.com/run/docs/troubleshooting): over HTTP/1.1 its front end reads the
// whole answer itself, so an abandoned call ran to its end, holding its large-body slot. With
// `--use-http2` Cloud Run sends the container h2c and nothing else, and a client that goes resets
// its stream, which this server acts on at once (serveMcp). But on a canary of 2026-10-05 that reset
// came only when the answer was written, 15 and 34 s in, not when the client went:
// mcp_client_gone (after_ms, answer_started) is how production shows which. The flag and
// MCP_H2C=1 go together (deploy-all.sh mcp-remote): either one alone answers no request at all.
//
// No auth: the endpoint serves only public data (MCP makes authorization optional), and the
// server's instructions say what it is. The edge rules — Origin policy, per-client limit, body
// cap, what is logged — are in httpPolicy.ts, each with its reasoning.
//
// The API sees every remote user as the client it is, not as this service: each call carries the
// client's address and a forward token core-backend checks (runtime.ts; core-backend
// waf/mcpforward.go, #2212). MCP_REQUIRE_FORWARD_TOKEN=1 (set by deploy-all.sh) makes a missing
// token fatal at start-up, because without it every remote user would share one API budget.
import http from "node:http";
import http2 from "node:http2";
import type net from "node:net";
import v8 from "node:v8";
import { createMcpHandler } from "@modelcontextprotocol/server";
import { forwardToken, markHttpEntrypoint, onUpstreamFailure, requestLabels, requestSettled, SYNTHETIC_UA_FAMILY, withClient, type Reservation, type ReserveFor } from "./runtime.js";
import {
  Admission,
  apiRoute,
  BODY_DENSE_CODE,
  BODY_STALLED_CODE,
  BODY_TOO_LARGE_CODE,
  BUSY_CODE,
  DEFAULT_ADMISSION_WAIT_MS,
  DEFAULT_BODY_IDLE_MS,
  DEFAULT_LARGE_BODY_SLOTS,
  DEFAULT_LARGE_BODY_WAIT_MS,
  DEFAULT_LARGE_BODY_WAITERS,
  DEFAULT_MAX_BODY_BYTES,
  DEFAULT_MAX_IN_FLIGHT,
  DEFAULT_MAX_SBOM_BODY_BYTES,
  DEFAULT_MAX_WAITING,
  DEFAULT_RATE_LIMIT_PER_MIN,
  DEFAULT_REQUEST_TIMEOUT_MS,
  LARGE_BODY_TARGETS_TEXT,
  Slots,
  type SlotHold,
  FixedWindowLimiter,
  hstsFor,
  ORIGIN_REFUSED_CODE,
  RATE_LIMITED_CODE,
  bodyFacts,
  handlerErrorClass,
  httpMethodLabel,
  protocolErrorCode,
  originVerdict,
  resolveClient,
  revisionLabel,
  rpcError,
  rstCodeLabel,
  settleBy,
  isLargeBodyTarget,
  isListenStream,
  uaFamily,
  upstreamSeverity,
} from "./httpPolicy.js";
import type { LogFields, LogMessage, NotAny } from "./logLines.js";
import { INFLIGHT_BUDGET_BYTES, PARSE_BUDGET_BYTES, ParseBudget, SMALL_ANSWERS_BYTES, scanJson, type BudgetGroup, type BudgetHold, type JsonStructure } from "./parseBudget.js";
import { bodyReader, header, type BodyRead } from "./readBody.js";

// Must run before index.ts is evaluated: it is how index.ts knows not to start stdio.
markHttpEntrypoint();
const { createServer, NAME, VERSION, SHOWN_BASE, TIMEOUT_MS } = await import("./index.js");

const positiveInt = (v: string | undefined, fallback: number): number => {
  const n = Number(v);
  return Number.isInteger(n) && n > 0 ? n : fallback;
};
const PORT = (() => {
  const n = Number(process.env.PORT);
  return Number.isInteger(n) && n >= 0 && n < 65536 && process.env.PORT !== "" && process.env.PORT !== undefined ? n : 8080;
})();
const RATE_LIMIT_PER_MIN = positiveInt(process.env.MCP_RATE_LIMIT_PER_MIN, DEFAULT_RATE_LIMIT_PER_MIN);
// The body caps and the large-body slots (#2747): see httpPolicy.ts "Request-body caps".
const MAX_BODY_BYTES = positiveInt(process.env.MCP_MAX_BODY_BYTES, DEFAULT_MAX_BODY_BYTES);
const MAX_SBOM_BODY_BYTES = Math.max(MAX_BODY_BYTES, positiveInt(process.env.MCP_MAX_SBOM_BODY_BYTES, DEFAULT_MAX_SBOM_BODY_BYTES));
const LARGE_BODY_SLOTS = positiveInt(process.env.MCP_LARGE_BODY_SLOTS, DEFAULT_LARGE_BODY_SLOTS);
// #2775: how long a large body that finds every slot busy waits for one (at most DEFAULT_LARGE_BODY_WAITERS wait).
const LARGE_BODY_WAIT_MS = positiveInt(process.env.MCP_LARGE_BODY_WAIT_MS, DEFAULT_LARGE_BODY_WAIT_MS);
// The requests served at once, and how long the next may wait (#2773): httpPolicy.ts "Requests
// in flight per instance".
const MAX_IN_FLIGHT = positiveInt(process.env.MCP_MAX_IN_FLIGHT, DEFAULT_MAX_IN_FLIGHT);
const ADMISSION_WAIT_MS = positiveInt(process.env.MCP_ADMISSION_WAIT_MS, DEFAULT_ADMISSION_WAIT_MS);
// #3362: how long a body may send nothing while it is read, and how long a request may take in all: httpPolicy.ts
// DEFAULT_BODY_IDLE_MS and DEFAULT_REQUEST_TIMEOUT_MS.
const BODY_IDLE_MS = positiveInt(process.env.MCP_BODY_IDLE_MS, DEFAULT_BODY_IDLE_MS);
const REQUEST_TIMEOUT_MS = positiveInt(process.env.MCP_REQUEST_TIMEOUT_MS, DEFAULT_REQUEST_TIMEOUT_MS);
// A large body that waited LARGE_BODY_WAIT_MS for a slot (or found two waiting already), and a
// request that waited ADMISSION_WAIT_MS for admission, are told to come back.
const BUSY_RETRY_AFTER_SEC = 5;
// #2775: serve h2c instead of HTTP/1.1 (see the top of this file). Exactly "1": anything else is
// HTTP/1.1, the default for a local run and for every test that does not ask.
const H2C = process.env.MCP_H2C === "1";
const MCP_PATH = "/mcp";
const HEALTH_PATH = "/health";

// One JSON object per line on stdout: Cloud Logging reads `severity` and `message`. #2863: the message is one of
// logLines.ts LOG_LINES and the fields are exactly that line's keys, or this does not compile: a new line or a new
// key is added there, where what each line carries is reviewed against /privacy Section 11 and the README.
function log<M extends LogMessage, F extends LogFields<M>>(
  severity: "INFO" | "WARNING" | "ERROR",
  message: M,
  fields: F & Record<Exclude<keyof F, keyof LogFields<M>>, never> & NotAny<F>,
): void {
  process.stdout.write(`${JSON.stringify({ severity, message, ...fields })}\n`);
}

// #2948: one line per API call that failed (runtime.ts upstreamFailed, from index.ts api()), so an
// answer that says "could not be reached" is on our record too, with its cause. The route is a
// template (httpPolicy.ts apiRoute): never the path, which can hold what was looked up, nor the
// query string. tool and rpc_method are the request's bodyFacts (a shape-checked tool, a method from
// httpPolicy.ts MCP_METHODS or "(other)"); synthetic says the request was the production synthetic's (its User-Agent family). WARNING, except the API's own
// answer about the input (httpPolicy.ts upstreamSeverity). Written before the request's own
// mcp_request line, which still says status 200: the JSON-RPC call itself succeeded.
onUpstreamFailure((f) => {
  const route = apiRoute(f.path);
  log(upstreamSeverity(f.failureClass, f.status, route), "mcp_upstream_failed", {
    tool: f.tool,
    rpc_method: f.rpcMethod,
    route,
    failure_class: f.failureClass,
    status: f.status,
    after_ms: f.afterMs,
    synthetic: f.synthetic,
  });
});

if (process.env.MCP_REQUIRE_FORWARD_TOKEN === "1" && !forwardToken()) {
  log("ERROR", "mcp_remote_refusing_to_start", {
    reason:
      "MCP_REQUIRE_FORWARD_TOKEN=1 but ECHELONGRAPH_FORWARD_TOKEN is empty: the API would count every remote user as this one service (#2212)",
  });
  process.exit(1);
}

const handler = createMcpHandler(createServer, {
  legacy: "stateless",
  // responseMode stays the SDK default, "auto": a modern request is answered with one JSON body
  // unless a handler emits something before its result (none of these tools does). The legacy
  // leg answers over SSE, as a 2025-era streamable HTTP server does.
  // The largest body readBody can hand on; which request may be that large is decided here first.
  maxRequestBodySize: MAX_SBOM_BODY_BYTES,
  // Never the message: an SDK error message can quote what the client sent. A fixed label and
  // the JSON-RPC code instead, so each one can be told apart (#2923).
  // #2923: the error by a fixed class and its code, never its message; and the request it arose in by its fixed labels,
  // read from the request's scope (runtime.ts requestLabels): its JSON-RPC method (MCP_METHODS or "(other)"), its
  // protocol version.
  onerror: (e) => {
    const labels = requestLabels();
    log("WARNING", "mcp_handler_error", {
      error_name: e.name,
      error_class: handlerErrorClass(e),
      error_code: protocolErrorCode(e),
      rpc_method: labels.rpcMethod,
      protocol_version: labels.protocolVersion,
    });
  },
});

const limiter = new FixedWindowLimiter(RATE_LIMIT_PER_MIN);
const largeBodies = new Slots(LARGE_BODY_SLOTS, DEFAULT_LARGE_BODY_WAITERS);
const admission = new Admission(MAX_IN_FLIGHT, DEFAULT_MAX_WAITING);
// #3381: what the requests in flight may hold parsed, all together (parseBudget.ts INFLIGHT_BUDGET_BYTES): each its
// body's estimate (scanJson), from before its body is parsed until the request has stopped, and what its tool parses
// from a string, from before it parses it until it has read it (then only what its answer keeps of it, runtime.ts
// Reservation keep) or the request has stopped, and (#3381's round-4 review) what the API's answers to a check_sbom or
// scan_manifest call's purls hold, from before its first batch (match_batch.ts reserveAnswers). A request that does not
// fit waits as for a place, up to
// ADMISSION_WAIT_MS, at most DEFAULT_MAX_WAITING at once, and is then answered 503; one that can never fit is refused at
// once (reserveParse). A body within MAX_BODY_BYTES is small (parseBudget.ts BUDGET_STARVE_MS): it is let in ahead of a
// large one that waits, while the small ones together hold at most their share.
const parseBudget = new ParseBudget(INFLIGHT_BUDGET_BYTES, DEFAULT_MAX_WAITING);

// CORS for a browser client on an https Origin (the Origin policy has already admitted it).
// A wildcard is safe here because nothing is credentialed: no cookies, no auth.
const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Expose-Headers": "Mcp-Session-Id, MCP-Protocol-Version, Retry-After",
};
const PREFLIGHT_HEADERS: Record<string, string> = {
  ...CORS_HEADERS,
  "Access-Control-Allow-Methods": "POST, GET, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Accept, MCP-Protocol-Version, Mcp-Method, Mcp-Name, Mcp-Session-Id, Last-Event-ID",
  "Access-Control-Max-Age": "600",
};

const HOP_BY_HOP = new Set(["host", "connection", "content-length", "transfer-encoding", "keep-alive", "upgrade", "expect"]);

// HTTP/2 has no connection-specific headers (RFC 9113 8.2.2): Node drops them from an h2 answer
// with a warning, so they are never set on one. A refusal's "Connection: close" (the rest of the
// body is discarded unread) is the stream's own end there.
const CONNECTION_SPECIFIC = new Set(["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"]);
function forProtocol(res: http.ServerResponse, headers: Record<string, string>): Record<string, string> {
  if (!((res as unknown) instanceof http2.Http2ServerResponse)) return headers;
  return Object.fromEntries(Object.entries(headers).filter(([k]) => !CONNECTION_SPECIFIC.has(k.toLowerCase())));
}

function send(res: http.ServerResponse, status: number, body: string, headers: Record<string, string> = {}): void {
  res.writeHead(status, forProtocol(res, { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers }));
  res.end(body);
}

// clientPublic (#2737): this request named a public client address, so its API calls carried the
// forward headers. false on an /mcp request means its calls went WITHOUT them (runtime.ts
// upstreamHeaders sends neither header without a public client), so core-backend reads
// mcp_forward=absent and keys them on this service by design. That does NOT fire core-backend's
// forward-token-mismatch alert: no state the alert matches, client_refused included, comes from a
// request of ours without a fault, because isPublic accepts no address core-backend's
// publicUnicast refuses (infrastructure/monitoring/create-mcp-remote-monitoring.sh, #2794).
// clientClosed (#2775): the client went before its answer was written; logged as status 499 (the
// "client closed request" of nginx and of the SDK), whatever status line had already been sent.
// inFlight / queuedMs (#2773): the requests in flight when this one was admitted, itself
// included, and how long it waited for that: #3381, for room in the parse budget too (its body's, and its tool's
// while it was served), and for its place. A subscriptions/listen stream is never admitted
// (httpPolicy.ts isListenStream), so its line says 0 and 0. Since SDK 2.2.0 (3.1.1, #3345) a listen
// here ends at once, its status 200; through 3.1.0 it stayed open until its client ended it, logged
// 499 with clientClosed.
type Outcome = {
  status: number;
  body?: Buffer;
  facts?: ReturnType<typeof bodyFacts>;
  throttled?: boolean;
  refused?: string;
  clientPublic?: boolean;
  clientClosed?: boolean;
  inFlight?: number;
  queuedMs?: number;
  slotWaitMs?: number;
};

// The body is read by readBody.ts, over this instance's large-body slots and caps.
const readBody = bodyReader(largeBodies, { maxBodyBytes: MAX_BODY_BYTES, maxSbomBodyBytes: MAX_SBOM_BODY_BYTES, largeBodyWaitMs: LARGE_BODY_WAIT_MS, bodyIdleMs: BODY_IDLE_MS });

// #3362: what a request holds of its instance, each given back once: by the request as it settles, or, its place and its
// slot, by its deadline (serveMcp) if it has not settled by then (its parse holds wait for it to unwind: see parse,
// below). A second release of its place would free a place that another request
// holds, letting one more in past the bound (a second release of its slot's hold frees nothing: httpPolicy.ts Slots).
// body and facts: what its access line says of it, if the deadline writes that line; clientGone: its client went
// (clientWent in serveMcpTimed; the deadline stopping it is not its client going), which that line says too.
// #3381: parse, what it holds of the parse budget (its body's estimate, and what its tool reserved), all given back at
// once, by the request as it settles: never by its deadline (#3381's review). The memory a hold stands for is the
// request's parsed body and what its tool parsed, which stay reachable until the request has actually unwound (a tool
// stops only when its aborted signal reaches it); given back at the deadline, waiting requests were let in to parse
// beside them, and V8 ended the process. parseClosed, once the request is stopped or has given them back, so a tool that
// reserves after that holds nothing. parseWaitMs: how long it waited for room, which its access line counts in
// queued_ms. docRefused: its tool's reservation was refused (reserveParse), which its access line says. #3381's round-4
// review: small, its body is within MAX_BODY_BYTES (none is), so its tool's reservations are small too; since, when the
// request began, which places its tool's reservations among the waiters (parseBudget.ts BUDGET_STARVE_MS).
type Held = {
  small: boolean;
  since: number;
  // #3381's round-5 review (B3): the request's tool reservations, one after another (reserveParse).
  reserving: Promise<void>;
  // #3381's round-6 verification (R6V-1.1): what the request holds of the budget, kept live by it (parseBudget.ts
  // BudgetGroup): its body's hold and each of its tools' are taken with it.
  group: BudgetGroup;
  slot?: SlotHold;
  admitted: boolean;
  clientGone: boolean;
  body?: Buffer;
  facts?: ReturnType<typeof bodyFacts>;
  parse: BudgetHold[];
  parseClosed: boolean;
  parseWaitMs: number;
  docRefused?: "busy" | "too_large";
};
function releaseSlot(held: Held): void {
  largeBodies.release(held.slot);
  held.slot = undefined;
}
function releaseParse(held: Held): void {
  held.parseClosed = true;
  for (const h of held.parse.splice(0)) parseBudget.release(h);
}
// #3381: room in the parse budget for `bytes` more (runtime.ts reserveParse, from a tool), held until the tool keeps
// less of it or the request ends. What the request already holds counts: a reservation that with it would pass the whole
// budget can never be granted, whatever else ends, so it is refused at once, never waited for (#3381's review). #3381's
// round-4 review (F4): nor one that with it would pass the most a waiter is sure to be let in at (parseBudget.ts
// BUDGET_STARVE_MS: the budget less the small bodies' share): through round 4 one between the two waited, and under a
// steady flow of small requests was answered busy on every retry.
const BUSY: Reservation = { state: "busy" };
const MOST_ONE_REQUEST_HOLDS = parseBudget.max - parseBudget.smallShare;
// #3381's round-5 review (B3): a JSON-RPC batch is one request whose messages the SDK serves at once, so one request
// can reserve for several tools at once. They are taken one after another: each counts what the ones before it hold
// (own, and the bound one request may hold, are the request's), and the request is among those waiting at most once
// (parseBudget.ts queuedOwn). Through round 5 each counted the body alone, and each that waited counted it again.
// #3381's round-6 verification: what the request holds is its group's bytes, kept live by the budget (R6V-1.1), and a
// reservation after one that found no room is still taken where it fits at once, without a wait (R6V-1.3).
// A reservation that had to wait for room, its wait counted in the request's queued_ms. One taken at once is not timed:
// timing the await of a hold already granted counted 1 ms now and then, and a listen's queued_ms read 1, not 0.
async function waitedFor(held: Held, wait: () => Promise<BudgetHold | undefined>): Promise<BudgetHold | undefined> {
  const t = Date.now();
  try {
    return await wait();
  } finally {
    held.parseWaitMs += Date.now() - t;
  }
}
function reserveParse(held: Held, bytes: number, gone: AbortSignal, opts: ReserveFor = {}): Promise<Reservation> {
  const before = held.reserving;
  let done!: () => void;
  held.reserving = new Promise<void>((r) => (done = r));
  return before.then(() => reserveOne(held, bytes, gone, opts)).finally(done);
}
async function reserveOne(held: Held, bytes: number, gone: AbortSignal, opts: ReserveFor): Promise<Reservation> {
  if (held.parseClosed) return BUSY;
  const own = held.group.bytes;
  if (own + Math.ceil(bytes) > MOST_ONE_REQUEST_HOLDS) {
    held.docRefused = "too_large";
    return { state: "too_large", heldBytes: own, maxBytes: MOST_ONE_REQUEST_HOLDS };
  }
  const reserve = { small: held.small && (opts.answers !== true || bytes <= SMALL_ANSWERS_BYTES), group: held.group, since: held.since };
  // Once one of a request's reservations found no room within its wait, its batch's later ones do not wait (one after
  // another, each would wait as long again), but each is still taken where it fits at once (R6V-1.3: through round 6
  // a call of 150 purls, room for it, was answered busy because a sibling before it was).
  const hold = parseBudget.tryReserve(bytes, reserve) ?? (held.docRefused === "busy" ? undefined : await waitedFor(held, () => parseBudget.acquire(bytes, ADMISSION_WAIT_MS, gone, reserve)));
  if (!hold) {
    if (!gone.aborted) held.docRefused = "busy";
    return BUSY;
  }
  if (held.parseClosed) {
    parseBudget.release(hold);
    return BUSY;
  }
  held.parse.push(hold);
  // #3381's round-10 review (R10-B1): charge() answers no once the request holds more than the most one request may
  // reserve, as well as once the budget is past its overdraft: through round 10 only the budget was asked, and one
  // check_sbom of 2,000 purls whose rows held ten matches each held 52.9 MB, its answers charged past the bound that
  // refused its reservations. room(): what each of the two has left, from which sendBatches bounds a batch's answer as
  // it is read (R10-M1).
  return {
    state: "held",
    keep: (b: number) => parseBudget.resize(hold, b),
    charge: (b: number) => parseBudget.grow(hold, b) && held.group.bytes <= MOST_ONE_REQUEST_HOLDS,
    room: () => ({ budget: parseBudget.max + parseBudget.overdraft - parseBudget.inUse, request: MOST_ONE_REQUEST_HOLDS - held.group.bytes, requestMax: MOST_ONE_REQUEST_HOLDS }),
  };
}
// The access line's refused for a tool's refused reservation: doc_busy (it found no room within the wait, answered
// failed, "server busy") or doc_too_large (it could never fit, answered invalid_input). Each a literal reason.
function docRefusal(held: Held): Pick<Outcome, "refused"> {
  if (held.docRefused === "busy") return { refused: "doc_busy" };
  if (held.docRefused === "too_large") return { refused: "doc_too_large" };
  return {};
}
function releaseAdmission(held: Held): void {
  if (held.admitted) admission.release();
  held.admitted = false;
}

function tooLarge(res: http.ServerResponse, cors: Record<string, string>): Outcome {
  send(
    res,
    413,
    rpcError(
      BODY_TOO_LARGE_CODE,
      `Request body too large: at most ${MAX_BODY_BYTES} bytes, or ${MAX_SBOM_BODY_BYTES} bytes for ${LARGE_BODY_TARGETS_TEXT}. A larger SBOM or lockfile can be passed to check_sbom as its purls.`,
      { max_bytes: MAX_BODY_BYTES, max_bytes_sbom: MAX_SBOM_BODY_BYTES },
    ),
    { ...cors, Connection: "close" },
  );
  return { status: 413, refused: "body_size" };
}

// #3381: a body whose parse is estimated past what one request may take (parseBudget.ts PARSE_BUDGET_BYTES), refused
// unparsed. Its access line names no method (rpc_method "(unparseable)": it was not parsed, so none is known) and logs
// its size; refused "body_dense".
function tooDenseToParse(res: http.ServerResponse, cors: Record<string, string>, s: JsonStructure): Outcome {
  send(
    res,
    413,
    rpcError(
      BODY_DENSE_CODE,
      `Request body too dense to parse: its ${s.containers} objects and arrays, ${s.elements} elements (list entries and object members) and ${s.keys} keys, counted outside its strings, are estimated at ${s.estimate} bytes of this instance's memory parsed; at most ${PARSE_BUDGET_BYTES} bytes, far more than a CycloneDX or SPDX document of 6 MiB takes. Pass check_sbom a larger document's purls.`,
      { containers: s.containers, elements: s.elements, keys: s.keys, estimated_bytes: s.estimate, max_bytes: PARSE_BUDGET_BYTES },
    ),
    cors,
  );
  return { status: 413, refused: "body_dense", facts: { rpc_method: "(unparseable)" } };
}

// #3381: no room in the parse budget came within ADMISSION_WAIT_MS: the instance's busy answer. Not parsed, so its line
// names no method either; refused "parse_busy".
function parseBusy(res: http.ServerResponse, cors: Record<string, string>): Outcome {
  send(
    res,
    503,
    rpcError(
      BUSY_CODE,
      `Server busy: this instance's memory for parsing request bodies is taken by the requests it is serving. Retry after ${BUSY_RETRY_AFTER_SEC} s.`,
      { retry_after_seconds: BUSY_RETRY_AFTER_SEC },
    ),
    { ...cors, "Retry-After": String(BUSY_RETRY_AFTER_SEC), Connection: "close" },
  );
  return { status: 503, refused: "parse_busy", facts: { rpc_method: "(unparseable)" } };
}

// #2775: the access line's slot_wait_ms is how long the request's large body waited for a slot, whatever came of it.
// #3362: and every request is over by REQUEST_TIMEOUT_MS (httpPolicy.ts DEFAULT_REQUEST_TIMEOUT_MS). Then it is stopped
// as one whose client went is, its place and its slot are given back (its parse holds once it has unwound, #3381's
// review), and this answers for it at once, so its access line is
// written then (refused "timeout") even if what it was doing never settles. What it settles with later is neither
// logged (settleBy) nor released (Held) again. That line's status is the one the request would have had:
//   - its client had gone (clientWent): 499 and client_closed, as any request's whose client went, whatever status line
//     had already been sent;
//   - else its answer had ended: the status it was answered with. That answer is left alone: over HTTP/1.1 its socket
//     may already carry the client's next request;
//   - else 504, a status for the log only: no HTTP answer is sent, and its stream (h2c) or connection (HTTP/1.1) is reset.
async function serveMcp(req: http.IncomingMessage, res: http.ServerResponse, pathname: string): Promise<Outcome> {
  const timing = { slotWaitMs: 0 };
  const held: Held = { small: true, since: Date.now(), reserving: Promise.resolve(), group: parseBudget.newGroup(), admitted: false, clientGone: false, parse: [], parseClosed: false, parseWaitMs: 0 };
  const o = await settleBy(
    REQUEST_TIMEOUT_MS,
    (deadline) => serveMcpTimed(req, res, pathname, timing, held, deadline),
    (): Outcome => {
      releaseAdmission(held);
      releaseSlot(held);
      // #3381's review: its parse holds stay until serveMcpTimed has unwound (its finally gives them back): what they
      // stand for is still reachable now. No tool of it reserves more.
      held.parseClosed = true;
      const answered = res.writableEnded;
      if (!answered) res.destroy();
      const status = held.clientGone ? 499 : answered ? res.statusCode : 504;
      return { status, refused: "timeout", clientClosed: held.clientGone, body: held.body, facts: held.facts };
    },
  );
  return { ...o, slotWaitMs: timing.slotWaitMs, queuedMs: (o.queuedMs ?? 0) + held.parseWaitMs };
}

async function serveMcpTimed(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  pathname: string,
  timing: { slotWaitMs: number },
  held: Held,
  deadline: AbortSignal,
): Promise<Outcome> {
  const method = req.method ?? "GET";

  const origin = req.headers.origin;
  const verdict = originVerdict(Array.isArray(origin) ? origin.join(", ") : origin);
  if (!verdict.ok) {
    send(res, 403, rpcError(ORIGIN_REFUSED_CODE, `Origin refused: ${verdict.reason}. This endpoint serves requests with no Origin or an https Origin.`));
    return { status: 403, refused: "origin" };
  }
  const cors = origin === undefined ? {} : CORS_HEADERS;

  if (method === "OPTIONS") {
    res.writeHead(204, PREFLIGHT_HEADERS);
    res.end();
    return { status: 204 };
  }

  const xff = req.headers["x-forwarded-for"];
  const client = resolveClient(Array.isArray(xff) ? xff.join(",") : xff, req.socket.remoteAddress);
  const hit = limiter.hit(client.key);
  if (!hit.allowed) {
    send(
      res,
      429,
      rpcError(
        RATE_LIMITED_CODE,
        `Rate limit exceeded: at most ${RATE_LIMIT_PER_MIN} requests per minute per client address. Retry after ${hit.retryAfterSec} s.`,
        { limit: RATE_LIMIT_PER_MIN, window_seconds: 60, retry_after_seconds: hit.retryAfterSec },
      ),
      { ...cors, "Retry-After": String(hit.retryAfterSec) },
    );
    log("WARNING", "mcp_rate_limited", { client: client.key, limit: RATE_LIMIT_PER_MIN });
    return { status: 429, throttled: true };
  }

  // #2775: the client has gone when the response closes before it has finished. That aborts the
  // request: its wait for admission, the SDK's handling of it (which cancels the tool's call), and
  // its API calls (runtime.ts requestSignal).
  // Over h2c the response of a reset stream closes marked finished (node:http2's compatibility
  // API ends it), so there the stream itself is watched, from the moment the reset arrives:
  // 'aborted' (a reset before the answer was written, any error code) and a 'close' before this
  // server ended its answer (a reset with NO_ERROR emits no 'aborted').
  // mcp_client_gone says WHEN this server learned it: after_ms from the request's start, and
  // whether its answer had started (answer_started). On 2026-10-05 a canary behind Cloud Run's
  // --use-http2 logged its aborted calls 499 only when their answers were written, 15 and 34 s
  // in: this line tells a reset that arrived then from one that arrived early and was not acted on
  // (the access line's duration_ms is when the call actually stopped). rst_code is the stream's reset code when it is
  // one HTTP/2 defines (0 to 13), else "(other)" (httpPolicy.ts rstCodeLabel): under h2c the client chooses it.
  const gone = new AbortController();
  const t0 = Date.now();
  const h2stream = (res as unknown as Partial<http2.Http2ServerResponse>).stream;
  const clientWent = (): void => {
    if (gone.signal.aborted) return;
    held.clientGone = true;
    gone.abort();
    log("INFO", "mcp_client_gone", { after_ms: Date.now() - t0, answer_started: res.headersSent, rst_code: rstCodeLabel(h2stream?.rstCode) });
  };
  res.on("close", () => {
    if (!res.writableFinished || h2stream?.aborted) clientWent();
  });
  if (h2stream) {
    h2stream.once("aborted", clientWent);
    h2stream.once("close", () => {
      if (!res.writableEnded) clientWent();
    });
  }
  // #3362: the request's deadline (serveMcp) stops it as its client going does, but is not its client going: it neither
  // writes mcp_client_gone nor sets held.clientGone, and once it has, a later close of the response is not one either.
  deadline.addEventListener("abort", () => gone.abort(), { once: true });

  // The body is read BEFORE the request waits for admission (#2773), so a client that uploads
  // slowly holds its socket, and a large body its large-body slot, as before admission existed,
  // never one of the MAX_IN_FLIGHT places every other request needs. What a waiting request holds
  // is its body: at most MAX_BODY_BYTES, or a large body that holds one of the slots. And only while
  // its bytes keep coming (#3362: BODY_IDLE_MS between them, readBody "stalled") and to its deadline.
  try {
    let body: Buffer | undefined;
    let facts: ReturnType<typeof bodyFacts> | undefined;
    if (method === "POST") {
      let read: BodyRead;
      try {
        read = await readBody(req, gone.signal, timing);
      } catch (e) {
        // The request stream fails only when its connection does: the client went mid-upload.
        if (req.destroyed) return { status: 499, refused: "client_closed", clientClosed: true };
        throw e;
      }
      if (read === "gone") return { status: 499, refused: "client_closed", clientClosed: true };
      if (read === "too_large") return tooLarge(res, cors);
      if (read === "stalled") {
        send(
          res,
          408,
          rpcError(BODY_STALLED_CODE, `Request body incomplete: no byte of it came for ${BODY_IDLE_MS / 1000} s, so it was not read on.`, { idle_ms: BODY_IDLE_MS }),
          { ...cors, Connection: "close" },
        );
        return { status: 408, refused: "body_stalled" };
      }
      if (read === "busy") {
        send(
          res,
          503,
          rpcError(
            BUSY_CODE,
            `Server busy: this instance is already reading its ${LARGE_BODY_SLOTS} large request bodies at once. Retry after ${BUSY_RETRY_AFTER_SEC} s, or pass check_sbom the document's purls.`,
            { retry_after_seconds: BUSY_RETRY_AFTER_SEC },
          ),
          { ...cors, "Retry-After": String(BUSY_RETRY_AFTER_SEC), Connection: "close" },
        );
        log("WARNING", "mcp_large_body_busy", { slots: LARGE_BODY_SLOTS });
        return { status: 503, refused: "large_body_busy" };
      }
      body = read.body;
      held.slot = read.slot;
      // #3381: every body is counted before anything parses it (bodyFacts below is the first parse, then the SDK's): one
      // whose parse is estimated past PARSE_BUDGET_BYTES is refused unparsed, and the estimate of any other is held in
      // the parse budget until the request ends, waiting for room as for a place. Its slot and its hold are given back by
      // the finally below.
      const structure = scanJson(body);
      if (structure.estimate > PARSE_BUDGET_BYTES) return { ...tooDenseToParse(res, cors, structure), body };
      held.small = body.length <= MAX_BODY_BYTES;
      // #3381's round-7 verification (R7V-1.1): the body alone may take the tiny lane (parseBudget.ts).
      const reserve = { small: held.small, lane: true, group: held.group };
      const hold = parseBudget.tryReserve(structure.estimate, reserve) ?? (await waitedFor(held, () => parseBudget.acquire(structure.estimate, ADMISSION_WAIT_MS, gone.signal, reserve)));
      if (!hold) {
        if (gone.signal.aborted) return { status: 499, refused: "client_closed", clientClosed: true, body, facts: { rpc_method: "(unparseable)" } };
        return { ...parseBusy(res, cors), body };
      }
      if (held.parseClosed) parseBudget.release(hold);
      else held.parse.push(hold);
      facts = bodyFacts(body);
      held.body = body;
      held.facts = facts;
      // Past the general cap, the body itself must be what the headers (if any) said: one of
      // LARGE_BODY_TARGETS. A 2025-era client sends no Mcp-Method, so this is where its large body
      // is held to that.
      if (body.length > MAX_BODY_BYTES && !isLargeBodyTarget(facts)) return { ...tooLarge(res, cors), body, facts };

      // A 2026-era subscriptions/listen is a stream that does no work here (since SDK 2.2.0 it ends
      // right after its acknowledgement; through 2.1.0 it stayed open until its client left): it
      // takes no place and holds no work, or 64 idle ones would leave every other request waiting
      // for a 503 (#2773; httpPolicy.ts isListenStream says what bounds it).
      const standard = { protocolVersion: header(req, "mcp-protocol-version"), mcpMethod: header(req, "mcp-method"), mcpName: header(req, "mcp-name") };
      if (isListenStream(facts, body, standard)) return { ...(await relay(req, res, pathname, method, cors, client, body, facts, gone.signal, held)), facts };
    }

    // #2773: at most MAX_IN_FLIGHT requests are served at once; the next waits here.
    const waitStart = Date.now();
    if (!(await admission.acquire(ADMISSION_WAIT_MS, gone.signal))) {
      const queuedMs = Date.now() - waitStart;
      if (gone.signal.aborted) return { status: 499, refused: "client_closed", clientClosed: true, body, facts, queuedMs };
      req.resume();
      send(
        res,
        503,
        rpcError(
          BUSY_CODE,
          `Server busy: this instance is already serving its ${MAX_IN_FLIGHT} requests at once. Retry after ${BUSY_RETRY_AFTER_SEC} s.`,
          { retry_after_seconds: BUSY_RETRY_AFTER_SEC },
        ),
        { ...cors, "Retry-After": String(BUSY_RETRY_AFTER_SEC), Connection: "close" },
      );
      log("WARNING", "mcp_busy", { max_in_flight: MAX_IN_FLIGHT, waiting: admission.waiting });
      return { status: 503, refused: "busy", body, facts, queuedMs };
    }
    held.admitted = true;
    const admitted = { inFlight: admission.inUse, queuedMs: Date.now() - waitStart };
    // What is still running for this request (runtime.ts holdRequest): its admission and its
    // large-body slot are held until all of it has settled, not only until the answer is written.
    const work = new Set<Promise<unknown>>();
    try {
      return { ...(await relay(req, res, pathname, method, cors, client, body, facts, gone.signal, held, work)), facts, ...admitted, ...docRefusal(held) };
    } finally {
      // Every tool call stops on `gone` (#2775), so this wait is long only if one does not: then the deadline gives
      // the place and the slot back (#3362).
      await requestSettled(work);
      releaseAdmission(held);
    }
  } finally {
    releaseSlot(held);
    releaseParse(held);
  }
}

// Hands one admitted request (or a listen stream, which is not admitted and passes no `work`) to
// the SDK's handler and streams its answer back.
async function relay(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  pathname: string,
  method: string,
  cors: Record<string, string>,
  client: ReturnType<typeof resolveClient>,
  body: Buffer | undefined,
  facts: ReturnType<typeof bodyFacts> | undefined,
  gone: AbortSignal,
  held: Held,
  work?: Set<Promise<unknown>>,
): Promise<Outcome> {
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    // ":method", ":path", ":authority", ":scheme": an h2 request's pseudo-headers, which a Request cannot carry.
    if (v === undefined || HOP_BY_HOP.has(k) || k.startsWith(":")) continue;
    for (const one of Array.isArray(v) ? v : [v]) headers.append(k, one);
  }
  const request = new Request(`http://localhost${pathname}`, {
    method,
    headers,
    body: body && body.length > 0 ? new Uint8Array(body) : undefined,
    signal: gone,
  });

  // #2737: the production synthetic names itself by its user-agent family; its API calls then
  // carry the synthetic's fixed token (runtime.ts upstreamUserAgent), so they are never counted
  // as hosted adoption.
  const synthetic = uaFamily(req.headers["user-agent"]) === SYNTHETIC_UA_FAMILY;
  // #2948: the method and tool name a failed API call's line names (runtime.ts upstreamFailed).
  // #2923: and the protocol-version label a handler error's line names (runtime.ts requestLabels).
  const protocolVersion = revisionLabel(req.headers["mcp-protocol-version"] as string | undefined);
  const response = await withClient(client.forwardAddress, () => handler.fetch(request), {
    synthetic,
    signal: gone,
    work,
    // #3381: what a tool parses from a string is reserved in the parse budget first (reserveParse).
    reserve: (bytes: number, opts?: ReserveFor) => reserveParse(held, bytes, gone, opts),
    rpcMethod: facts?.rpc_method,
    tool: facts?.tool,
    protocolVersion,
  });
  const out: Record<string, string> = { ...cors };
  response.headers.forEach((v, k) => {
    out[k] = v;
  });
  res.writeHead(response.status, forProtocol(res, out));
  if (response.body) {
    for await (const chunk of response.body as unknown as AsyncIterable<Uint8Array>) res.write(chunk);
  }
  res.end();
  const clientPublic = client.forwardAddress !== undefined;
  if (gone.aborted) return { status: 499, body, clientPublic, clientClosed: true };
  return { status: response.status, body, clientPublic };
}

function onRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
  const start = process.hrtime.bigint();
  // The path only: a query string is never read, kept or logged.
  let pathname = "/";
  try {
    pathname = new URL(req.url ?? "/", "http://localhost").pathname;
  } catch {
    pathname = "(unparseable)";
  }
  const method = req.method ?? "GET";
  // #3354: Strict-Transport-Security on every answer to a request that arrived over HTTPS (httpPolicy.ts hstsFor), set
  // before any answer is written, so every writeHead below (send, the preflight, relay) carries it: Node merges headers
  // set with setHeader into writeHead's, over HTTP/1.1 and h2c alike. A proxy in front that sets its own header of the
  // same name (the edge load balancer does) replaces it.
  const hsts = hstsFor(req.headers["x-forwarded-proto"]);
  if (hsts) res.setHeader("Strict-Transport-Security", hsts);

  const finish = (o: Outcome): void => {
    const facts = o.facts ?? (o.body ? bodyFacts(o.body) : { rpc_method: "(none)" });
    log("INFO", "mcp_request", {
      method: httpMethodLabel(method),
      path: pathname === MCP_PATH || pathname === HEALTH_PATH ? pathname : "(other)",
      status: o.status,
      duration_ms: Number((process.hrtime.bigint() - start) / 1_000_000n),
      ...facts,
      protocol_version: revisionLabel(req.headers["mcp-protocol-version"] as string | undefined),
      origin_present: req.headers.origin !== undefined,
      body_bytes: o.body?.length ?? 0,
      throttled: o.throttled === true,
      refused: o.refused ?? "",
      ua_family: uaFamily(req.headers["user-agent"]),
      client_public: o.clientPublic === true,
      client_closed: o.clientClosed === true,
      in_flight: o.inFlight ?? 0,
      queued_ms: o.queuedMs ?? 0,
      slot_wait_ms: o.slotWaitMs ?? 0,
      // #3362: the instance's, not the request's: its large-body slots held as this line is written (this request's
      // own already given back), and how long the oldest of them has been held (httpPolicy.ts Slots.oldestHoldMs).
      // Every hold ends by its request's deadline, so a hold far older is one no request will give back, whether its
      // holder hangs or has gone, and whatever else is served meanwhile.
      large_body_held: largeBodies.inUse,
      large_body_oldest_hold_ms: largeBodies.oldestHoldMs(),
    });
  };

  if (pathname === HEALTH_PATH) {
    if (method !== "GET" && method !== "HEAD") {
      send(res, 405, JSON.stringify({ error: "method not allowed" }), { Allow: "GET, HEAD" });
      return finish({ status: 405 });
    }
    send(res, 200, JSON.stringify({ status: "ok", name: NAME, version: VERSION }));
    return finish({ status: 200 });
  }
  if (pathname !== MCP_PATH) {
    send(res, 404, JSON.stringify({ error: "not found", mcp_endpoint: MCP_PATH }));
    return finish({ status: 404 });
  }
  serveMcp(req, res, pathname).then(finish, (e: unknown) => {
    log("ERROR", "mcp_request_failed", { error_name: e instanceof Error ? e.name : typeof e });
    if (!res.headersSent) send(res, 500, rpcError(-32603, "Internal error"));
    else res.end();
    finish({ status: 500 });
  });
}

// #2775: with MCP_H2C=1, node:http2's compatibility API, whose request and response carry the
// IncomingMessage / ServerResponse members used above. Where they differ the code says so:
// pseudo-headers (relay), connection-specific headers (forProtocol), a stream reset mid-upload
// (readBody "gone"). A stream reset after that closes the response unfinished, which aborts
// `gone` in serveMcp exactly as a closed HTTP/1.1 socket does.
const server: net.Server = H2C
  ? http2.createServer((req, res) => onRequest(req as unknown as http.IncomingMessage, res as unknown as http.ServerResponse))
  : http.createServer(onRequest);

// #2773: the heap V8 may grow to, and the memory the container allows (0 when none is known). A
// heap allowed past the container's memory is collected only when the kernel kills the instance:
// Dockerfile.http caps it, and this says when a process was started without that cap. It can say
// so only where Node can read the container's limit (process.constrainedMemory(), from cgroups):
// where it cannot, memory_limit_mb is null, this never fires, and heap_limit_mb is what to read.
const MiB = 1024 * 1024;
const heapLimit = v8.getHeapStatistics().heap_size_limit;
const memoryLimit = process.constrainedMemory?.() ?? 0;
const memoryKnown = memoryLimit > 0 && memoryLimit < 2 ** 50;
if (memoryKnown && heapLimit > memoryLimit * 0.75) {
  log("WARNING", "mcp_remote_heap_unbounded", {
    heap_limit_mb: Math.round(heapLimit / MiB),
    memory_limit_mb: Math.round(memoryLimit / MiB),
    reason: "V8 may grow its heap past the container's memory, and the kernel then kills the instance with every request on it (#2773): start http.js as Dockerfile.http does",
  });
}

server.listen(PORT, () => {
  const addr = server.address();
  log("INFO", "mcp_remote_listening", {
    port: typeof addr === "object" && addr ? addr.port : PORT,
    protocol: H2C ? "h2c" : "http/1.1",
    name: NAME,
    version: VERSION,
    api_base: SHOWN_BASE,
    api_timeout_ms: TIMEOUT_MS,
    forward_token_configured: forwardToken() !== "",
    rate_limit_per_min: RATE_LIMIT_PER_MIN,
    max_body_bytes: MAX_BODY_BYTES,
    max_sbom_body_bytes: MAX_SBOM_BODY_BYTES,
    large_body_slots: LARGE_BODY_SLOTS,
    large_body_wait_ms: LARGE_BODY_WAIT_MS,
    max_in_flight: MAX_IN_FLIGHT,
    admission_wait_ms: ADMISSION_WAIT_MS,
    body_idle_ms: BODY_IDLE_MS,
    request_timeout_ms: REQUEST_TIMEOUT_MS,
    heap_limit_mb: Math.round(heapLimit / MiB),
    memory_limit_mb: memoryKnown ? Math.round(memoryLimit / MiB) : null,
  });
});

const shutdown = (): void => {
  server.close();
  void handler.close();
};
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
