// Which entrypoint is running, and — for the hosted HTTP entrypoint only — the end client a
// request is being answered for (#2316).
//
// One tool module (index.ts) serves two entrypoints: the npm package's stdio bin (index.ts
// itself) and the hosted remote endpoint at mcp.echelongraph.io (http.ts). http.ts marks itself
// here BEFORE it loads index.ts, which is how index.ts knows not to start the stdio transport.
// The default is stdio: an entrypoint that forgets to mark itself gets the npm behaviour,
// which is the published package's, unchanged.
//
// The npm package sends nothing extra, ever: upstreamHeaders() is empty unless the HTTP
// entrypoint is running (the no-telemetry promise, #2304).
import { AsyncLocalStorage } from "node:async_hooks";

let httpEntrypoint = false;

/** Called by http.ts before it imports index.ts. */
export function markHttpEntrypoint(): void {
  httpEntrypoint = true;
}

export function isHttpEntrypoint(): boolean {
  return httpEntrypoint;
}

// The client a tool call is being answered for. http.ts runs each request inside
// withClient(), and the SDK dispatches the tool handler inside that same async context, so
// api() can read it without the tool module passing it through every function.
//   signal     aborted when the request's client has gone before its answer was written (#2775)
//   work       what is still running for the request: http.ts keeps the request's admission and
//              large-body slot until all of it has settled (holdRequest)
//   rpcMethod  the request's JSON-RPC method and, for a tools/call, the tool name (#2948): http.ts
//   tool       passes httpPolicy.ts bodyFacts' (the method one of MCP_METHODS or "(other)", the tool
//              shape-checked), so a failed API call can say which
//              tool it was for (upstreamFailed)
//   protocolVersion  the request's MCP-Protocol-Version as httpPolicy.ts revisionLabel gives it (#2923):
//              a date-shaped revision, "(other)" or "(none)"; with rpcMethod, what mcp_handler_error
//              says of the request it arose in (requestLabels)
type RequestScope = {
  clientIp?: string;
  synthetic?: boolean;
  signal?: AbortSignal;
  work?: Set<Promise<unknown>>;
  rpcMethod?: string;
  tool?: string;
  protocolVersion?: string;
};
const clientStore = new AsyncLocalStorage<RequestScope>();

export function withClient<T>(
  clientIp: string | undefined,
  fn: () => T,
  opts: { synthetic?: boolean; signal?: AbortSignal; work?: Set<Promise<unknown>>; rpcMethod?: string; tool?: string; protocolVersion?: string } = {},
): T {
  return clientStore.run(
    { clientIp, synthetic: opts.synthetic === true, signal: opts.signal, work: opts.work, rpcMethod: opts.rpcMethod, tool: opts.tool, protocolVersion: opts.protocolVersion },
    fn,
  );
}

/** #2923: the fixed labels of the request being served, for a line the SDK's onerror writes (it is handed only the
 *  error): the JSON-RPC method (MCP_METHODS or "(other)") and the protocol-version label; "(none)" outside a request. */
export function requestLabels(): { rpcMethod: string; protocolVersion: string } {
  const scope = clientStore.getStore();
  return { rpcMethod: scope?.rpcMethod ?? "(none)", protocolVersion: scope?.protocolVersion ?? "(none)" };
}

// ── Upstream failures (#2948) ──
//
// On 2026-10-07 a hosted get_cve answered "EchelonGraph ... could not be reached" in 460 ms and the
// hosted service logged only its access line, status 200: the cause went to the client and nowhere
// else. Every API call that fails is now reported here, and on the hosted endpoint http.ts writes it
// as one mcp_upstream_failed line. On stdio nothing is registered and nothing is written: stdout is
// the protocol there, and the npm package sends and writes nothing of its own (#2304).
//
// The classes. timeout: the call's own limit (ECHELONGRAPH_API_TIMEOUT_MS, or check_sbom's budget)
// passed. A network failure is classed by the codes in its cause chain (undici's fetch throws
// "fetch failed" with the system error as its cause): dns, refused, reset (a reset or a connection
// closed before or while the answer was read), connect_timeout, unreachable, tls, or network for any
// other. http: the API answered a non-2xx (its status). not_json, not_object: a 2xx whose body is not
// a JSON object. unexpected_shape: a 2xx the tool could not use (index.ts failure()). output_schema
// (#2948's review): the tool's own outputSchema refused the answer it built (index.ts checked()),
// which is a fault of this server, not of the API: http.ts logs it at ERROR, which the upstream
// metric and its alert do not count. A call
// cancelled because its client went, or because its caller cancelled it, is not reported: no
// upstream failed (http.ts's mcp_client_gone records a client that went).
export type UpstreamFailureClass =
  | "timeout"
  | "dns"
  | "refused"
  | "reset"
  | "connect_timeout"
  | "unreachable"
  | "tls"
  | "network"
  | "http"
  | "not_json"
  | "not_object"
  | "unexpected_shape"
  | "output_schema";
/** One failed API call: its class, the path it asked for (with its query, if any: http.ts logs only its route), its status and how long it took. */
export type UpstreamFailure = { failureClass: UpstreamFailureClass; path: string | null; status: number | null; afterMs: number | null };
/** What http.ts is handed: the failure, and the request it was for, from the request's scope. */
export type UpstreamFailureReport = UpstreamFailure & { tool: string; rpcMethod: string; synthetic: boolean };

let upstreamSink: ((r: UpstreamFailureReport) => void) | undefined;

/** http.ts only: where each failed API call is reported. */
export function onUpstreamFailure(sink: (r: UpstreamFailureReport) => void): void {
  upstreamSink = sink;
}

/** Reports one failed API call: on the hosted endpoint to http.ts's line; on stdio, nowhere. */
export function upstreamFailed(f: UpstreamFailure): void {
  if (!httpEntrypoint || !upstreamSink) return;
  const scope = clientStore.getStore();
  try {
    upstreamSink({ ...f, tool: scope?.tool ?? "(none)", rpcMethod: scope?.rpcMethod ?? "(none)", synthetic: scope?.synthetic === true });
  } catch {
    // A log line never fails the call it describes.
  }
}

const DNS_CODES = new Set(["ENOTFOUND", "EAI_AGAIN", "EAI_FAIL", "EAI_NONAME", "EAI_NODATA"]);
const RESET_CODES = new Set(["ECONNRESET", "EPIPE", "ECONNABORTED", "UND_ERR_SOCKET"]);
const CONNECT_TIMEOUT_CODES = new Set(["UND_ERR_CONNECT_TIMEOUT", "ETIMEDOUT"]);
const TIMEOUT_CODES = new Set(["UND_ERR_HEADERS_TIMEOUT", "UND_ERR_BODY_TIMEOUT"]);
const UNREACHABLE_CODES = new Set(["EHOSTUNREACH", "ENETUNREACH", "EHOSTDOWN", "ENETDOWN"]);
const TLS_CODE = /^(?:ERR_TLS_|ERR_SSL_|ERR_OSSL_|CERT_|UNABLE_TO_|DEPTH_ZERO_SELF_SIGNED_CERT$|SELF_SIGNED_CERT_IN_CHAIN$|HOSTNAME_MISMATCH$)/;

/** The class of a fetch that threw: from the first code in its cause chain this knows, else network. Codes only, never a message. */
export function networkFailureClass(e: unknown): UpstreamFailureClass {
  const codes: string[] = [];
  let c: unknown = e;
  for (let depth = 0; c instanceof Error && depth < 5; depth++) {
    const x = c as Error & { code?: unknown; errors?: unknown };
    if (typeof x.code === "string") codes.push(x.code);
    // A connection tried on several addresses fails as an AggregateError of each one's error.
    if (Array.isArray(x.errors)) {
      for (const y of x.errors) {
        const code = (y as { code?: unknown } | null)?.code;
        if (typeof code === "string") codes.push(code);
      }
    }
    c = x.cause;
  }
  for (const code of codes) {
    if (DNS_CODES.has(code)) return "dns";
    if (code === "ECONNREFUSED") return "refused";
    if (RESET_CODES.has(code)) return "reset";
    if (CONNECT_TIMEOUT_CODES.has(code)) return "connect_timeout";
    if (TIMEOUT_CODES.has(code)) return "timeout";
    if (UNREACHABLE_CODES.has(code)) return "unreachable";
    if (TLS_CODE.test(code)) return "tls";
  }
  return "network";
}

// #2775: a hosted client can go before its answer is ready (its own timeout, a closed tab, a
// retry). Nobody will read that answer, so the request's API calls are cancelled (index.ts api()
// reads this signal) and check_sbom sends no further batch: they would spend the client's API
// budget and hold the instance's memory for nothing. On stdio there is none: the SDK's own
// cancellation (notifications/cancelled) reaches check_sbom through its handler's signal.
export function requestSignal(): AbortSignal | undefined {
  return httpEntrypoint ? clientStore.getStore()?.signal : undefined;
}

/** Registers `p` as the hosted request's work, so its admission and large-body slot are held until p settles; on stdio, p untouched. */
export function holdRequest<T>(p: Promise<T>): Promise<T> {
  const work = httpEntrypoint ? clientStore.getStore()?.work : undefined;
  if (!work) return p;
  work.add(p);
  const drop = (): void => {
    work.delete(p);
  };
  p.then(drop, drop);
  return p;
}

/** Resolves once everything held for a request (holdRequest) has settled, including what is held while it waits. */
export async function requestSettled(work: Set<Promise<unknown>>): Promise<void> {
  while (work.size > 0) await Promise.allSettled([...work]);
}

// #2737: the production MCP synthetic probes this endpoint too, and its calls must reach the API
// under its own family, never as hosted MCP adoption. The synthetic names itself to this service
// with this family as its User-Agent's leading token; http.ts marks such a request (synthetic:
// true) and upstreamUserAgent() then puts this FIXED token ahead of the service's own user-agent,
// exactly as ECHELONGRAPH_MCP_UA does for the npm package. The client's text is never relayed: a
// request either carries this one constant or nothing. Anyone can claim the family, as anyone can
// send it to the API directly; the consequence is an undercounted adoption number, never a bypass
// (core-backend: user-agent classification is for counting only).
export const SYNTHETIC_UA_FAMILY = "echelongraph-mcp-synthetic";
export const SYNTHETIC_UA_TOKEN = `${SYNTHETIC_UA_FAMILY}/1.0`;

/** The User-Agent for one API call: `ua`, led by the synthetic's token when the request is the synthetic's. */
export function upstreamUserAgent(ua: string): string {
  if (!httpEntrypoint || clientStore.getStore()?.synthetic !== true) return ua;
  const lead = ua.split(/[/\s]/, 1)[0];
  return lead === SYNTHETIC_UA_FAMILY ? ua : `${SYNTHETIC_UA_TOKEN} ${ua}`;
}

/** The header that carries the forward token, and the one that names the client (core-backend waf/mcpforward.go). */
export const FORWARD_TOKEN_HEADER = "X-EG-MCP-Forward";
export const CLIENT_IP_HEADER = "X-EG-Client-IP";

/** The token, trimmed: a Secret Manager value can carry a trailing newline. */
export function forwardToken(): string {
  return (process.env.ECHELONGRAPH_FORWARD_TOKEN ?? "").trim();
}

// The hosts the token may be sent to: core-backend's public host, plus one exact hostname an
// operator (or a test's stub) names. Host-exact, never a suffix, for the reason marketing-site's
// internalApiHeaders gives: nothing look-alike may coax the token out, even if
// ECHELONGRAPH_API_BASE is ever pointed somewhere else.
function tokenMayGoTo(url: string): boolean {
  let host: string;
  try {
    host = new URL(url).hostname;
  } catch {
    return false;
  }
  const extra = (process.env.ECHELONGRAPH_FORWARD_HOST ?? "").trim();
  return host === "app.echelongraph.io" || (extra !== "" && host === extra);
}

/**
 * The extra request headers for one API call to `url`: on the HTTP entrypoint, with a token
 * configured, a client known and the URL on the allowlist, the token and the client's address;
 * otherwise nothing. Why the API believes them, and under what rule, is core-backend's
 * waf.MCPForwardedClient: without them every remote user would be keyed on this service's
 * one address and share one budget (#2212).
 */
export function upstreamHeaders(url: string): Record<string, string> {
  if (!httpEntrypoint) return {};
  const token = forwardToken();
  const clientIp = clientStore.getStore()?.clientIp;
  if (!token || !clientIp || !tokenMayGoTo(url)) return {};
  return { [FORWARD_TOKEN_HEADER]: token, [CLIENT_IP_HEADER]: clientIp };
}
