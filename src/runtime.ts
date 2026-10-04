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
const clientStore = new AsyncLocalStorage<{ clientIp?: string }>();

export function withClient<T>(clientIp: string | undefined, fn: () => T): T {
  return clientStore.run({ clientIp }, fn);
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
