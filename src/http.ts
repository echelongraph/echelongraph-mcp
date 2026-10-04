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
// No auth: the endpoint serves only public data (MCP makes authorization optional), and the
// server's instructions say what it is. The edge rules — Origin policy, per-client limit, body
// cap, what is logged — are in httpPolicy.ts, each with its reasoning.
//
// The API sees every remote user as the client it is, not as this service: each call carries the
// client's address and a forward token core-backend checks (runtime.ts; core-backend
// waf/mcpforward.go, #2212). MCP_REQUIRE_FORWARD_TOKEN=1 (set by deploy-all.sh) makes a missing
// token fatal at start-up, because without it every remote user would share one API budget.
import http from "node:http";
import { createMcpHandler } from "@modelcontextprotocol/server";
import { forwardToken, markHttpEntrypoint, SYNTHETIC_UA_FAMILY, withClient } from "./runtime.js";
import {
  BODY_TOO_LARGE_CODE,
  BUSY_CODE,
  DEFAULT_LARGE_BODY_SLOTS,
  DEFAULT_MAX_BODY_BYTES,
  DEFAULT_MAX_SBOM_BODY_BYTES,
  DEFAULT_RATE_LIMIT_PER_MIN,
  LARGE_BODY_TARGETS_TEXT,
  Slots,
  FixedWindowLimiter,
  ORIGIN_REFUSED_CODE,
  RATE_LIMITED_CODE,
  bodyFacts,
  originVerdict,
  resolveClient,
  revisionLabel,
  rpcError,
  isLargeBodyTarget,
  largeBodyAdmissible,
  uaFamily,
} from "./httpPolicy.js";

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
// A large body's wait for a slot is not queued: the client is told to come back.
const BUSY_RETRY_AFTER_SEC = 5;
const MCP_PATH = "/mcp";
const HEALTH_PATH = "/health";

// One JSON object per line on stdout: Cloud Logging reads `severity` and `message`.
function log(severity: "INFO" | "WARNING" | "ERROR", message: string, fields: Record<string, unknown> = {}): void {
  process.stdout.write(`${JSON.stringify({ severity, message, ...fields })}\n`);
}

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
  // Names only: an SDK error message can quote what the client sent.
  onerror: (e) => log("WARNING", "mcp_handler_error", { error_name: e.name }),
});

const limiter = new FixedWindowLimiter(RATE_LIMIT_PER_MIN);
const largeBodies = new Slots(LARGE_BODY_SLOTS);

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

function send(res: http.ServerResponse, status: number, body: string, headers: Record<string, string> = {}): void {
  res.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers });
  res.end(body);
}

// clientPublic (#2737): this request named a public client address, so its API calls carried the
// forward headers. false on an /mcp request means its calls went WITHOUT them and core-backend
// keyed them on this service: the one innocent reason core-backend's forward-token-mismatch alert
// can fire (infrastructure/monitoring/create-mcp-remote-monitoring.sh).
type Outcome = {
  status: number;
  body?: Buffer;
  facts?: ReturnType<typeof bodyFacts>;
  throttled?: boolean;
  refused?: string;
  clientPublic?: boolean;
};

// Reads the body. Up to MAX_BODY_BYTES it is read for any request. Past it, only a request that
// may be one of LARGE_BODY_TARGETS (largeBodyAdmissible: its Mcp-Method / Mcp-Name headers,
// when sent, say so) reads on, up to MAX_SBOM_BODY_BYTES, and only while it holds one of this
// instance's large-body slots: none free is "busy". Over the cap that applies: "too_large".
// Either way the rest is discarded unread (the response closes the connection). A body that
// crossed MAX_BODY_BYTES returns holding its slot; the caller releases it.
type BodyRead = { body: Buffer; slot: boolean } | "too_large" | "busy";
function readBody(req: http.IncomingMessage): Promise<BodyRead> {
  const mayBeLarge = largeBodyAdmissible(header(req, "mcp-method"), header(req, "mcp-name"));
  const cap = mayBeLarge ? MAX_SBOM_BODY_BYTES : MAX_BODY_BYTES;
  const declared = Number(req.headers["content-length"]);
  if (Number.isFinite(declared) && declared > cap) {
    req.resume();
    return Promise.resolve("too_large");
  }
  let slot = false;
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
    if (!largeBodies.tryAcquire()) {
      req.resume();
      return Promise.resolve("busy");
    }
    slot = true;
  }
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let done = false;
    const stop = (r: "too_large" | "busy"): void => {
      done = true;
      chunks.length = 0;
      if (slot) largeBodies.release();
      slot = false;
      resolve(r);
    };
    req.on("data", (chunk: Buffer) => {
      if (done) return;
      size += chunk.length;
      if (size > cap) return stop("too_large");
      if (size > MAX_BODY_BYTES && !slot) {
        if (!largeBodies.tryAcquire()) return stop("busy");
        slot = true;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (!done) resolve({ body: Buffer.concat(chunks), slot });
    });
    req.on("error", (e) => {
      if (done) return;
      done = true;
      if (slot) largeBodies.release();
      reject(e);
    });
  });
}

function header(req: http.IncomingMessage, name: string): string | undefined {
  const v = req.headers[name];
  return Array.isArray(v) ? v.join(", ") : v;
}

function tooLarge(res: http.ServerResponse, cors: Record<string, string>): Outcome {
  send(
    res,
    413,
    rpcError(
      BODY_TOO_LARGE_CODE,
      `Request body too large: at most ${MAX_BODY_BYTES} bytes, or ${MAX_SBOM_BODY_BYTES} bytes for ${LARGE_BODY_TARGETS_TEXT}. A larger SBOM can be passed to check_sbom as its purls.`,
      { max_bytes: MAX_BODY_BYTES, max_bytes_sbom: MAX_SBOM_BODY_BYTES },
    ),
    { ...cors, Connection: "close" },
  );
  return { status: 413, refused: "body_size" };
}

async function serveMcp(req: http.IncomingMessage, res: http.ServerResponse, pathname: string): Promise<Outcome> {
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

  let body: Buffer | undefined;
  let facts: ReturnType<typeof bodyFacts> | undefined;
  let slot = false;
  if (method === "POST") {
    const read = await readBody(req);
    if (read === "too_large") return tooLarge(res, cors);
    if (read === "busy") {
      send(
        res,
        503,
        rpcError(
          BUSY_CODE,
          `Server busy: this instance is already reading its ${LARGE_BODY_SLOTS} large request bodies at once. Retry after ${BUSY_RETRY_AFTER_SEC} s, or pass check_sbom the SBOM's purls.`,
          { retry_after_seconds: BUSY_RETRY_AFTER_SEC },
        ),
        { ...cors, "Retry-After": String(BUSY_RETRY_AFTER_SEC), Connection: "close" },
      );
      log("WARNING", "mcp_large_body_busy", { slots: LARGE_BODY_SLOTS });
      return { status: 503, refused: "large_body_busy" };
    }
    body = read.body;
    slot = read.slot;
    facts = bodyFacts(body);
    // Past the general cap, the body itself must be what the headers (if any) said: one of
    // LARGE_BODY_TARGETS. A 2025-era client sends no Mcp-Method, so this is where its large body
    // is held to that.
    if (body.length > MAX_BODY_BYTES && !isLargeBodyTarget(facts)) {
      if (slot) largeBodies.release();
      return { ...tooLarge(res, cors), body, facts };
    }
  }
  try {
    return { ...(await relay(req, res, pathname, method, cors, client, body)), facts };
  } finally {
    if (slot) largeBodies.release();
  }
}

// Hands one admitted request to the SDK's handler and streams its answer back.
async function relay(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  pathname: string,
  method: string,
  cors: Record<string, string>,
  client: ReturnType<typeof resolveClient>,
  body: Buffer | undefined,
): Promise<Outcome> {
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    if (v === undefined || HOP_BY_HOP.has(k)) continue;
    for (const one of Array.isArray(v) ? v : [v]) headers.append(k, one);
  }
  const abort = new AbortController();
  res.on("close", () => abort.abort());
  const request = new Request(`http://localhost${pathname}`, {
    method,
    headers,
    body: body && body.length > 0 ? new Uint8Array(body) : undefined,
    signal: abort.signal,
  });

  // #2737: the production synthetic names itself by its user-agent family; its API calls then
  // carry the synthetic's fixed token (runtime.ts upstreamUserAgent), so they are never counted
  // as hosted adoption.
  const synthetic = uaFamily(req.headers["user-agent"]) === SYNTHETIC_UA_FAMILY;
  const response = await withClient(client.forwardAddress, () => handler.fetch(request), { synthetic });
  const out: Record<string, string> = { ...cors };
  response.headers.forEach((v, k) => {
    out[k] = v;
  });
  res.writeHead(response.status, out);
  if (response.body) {
    for await (const chunk of response.body as unknown as AsyncIterable<Uint8Array>) res.write(chunk);
  }
  res.end();
  return { status: response.status, body, clientPublic: client.forwardAddress !== undefined };
}

const server = http.createServer((req, res) => {
  const start = process.hrtime.bigint();
  // The path only: a query string is never read, kept or logged.
  let pathname = "/";
  try {
    pathname = new URL(req.url ?? "/", "http://localhost").pathname;
  } catch {
    pathname = "(unparseable)";
  }
  const method = req.method ?? "GET";

  const finish = (o: Outcome): void => {
    const facts = o.facts ?? (o.body ? bodyFacts(o.body) : { rpc_method: "(none)" });
    log("INFO", "mcp_request", {
      method,
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
});

server.listen(PORT, () => {
  const addr = server.address();
  log("INFO", "mcp_remote_listening", {
    port: typeof addr === "object" && addr ? addr.port : PORT,
    name: NAME,
    version: VERSION,
    api_base: SHOWN_BASE,
    api_timeout_ms: TIMEOUT_MS,
    forward_token_configured: forwardToken() !== "",
    rate_limit_per_min: RATE_LIMIT_PER_MIN,
    max_body_bytes: MAX_BODY_BYTES,
    max_sbom_body_bytes: MAX_SBOM_BODY_BYTES,
    large_body_slots: LARGE_BODY_SLOTS,
  });
});

const shutdown = (): void => {
  server.close();
  void handler.close();
};
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
