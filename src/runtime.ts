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
//   signal  aborted when the request's client has gone before its answer was written (#2775)
//   work    what is still running for the request: http.ts keeps the request's admission and
//           large-body slot until all of it has settled (holdRequest)
type RequestScope = { clientIp?: string; synthetic?: boolean; signal?: AbortSignal; work?: Set<Promise<unknown>> };
const clientStore = new AsyncLocalStorage<RequestScope>();

export function withClient<T>(
  clientIp: string | undefined,
  fn: () => T,
  opts: { synthetic?: boolean; signal?: AbortSignal; work?: Set<Promise<unknown>> } = {},
): T {
  return clientStore.run({ clientIp, synthetic: opts.synthetic === true, signal: opts.signal, work: opts.work }, fn);
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
