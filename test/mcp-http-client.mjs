// A minimal MCP client over Streamable HTTP, for the hosted endpoint's tests (#2316). Like
// mcp-stdio-client.mjs it speaks the wire directly, so a test chooses the era and the headers
// exactly and sees exactly what the server answered: status, headers and body.
//
//   modern (2026-07-28)  every request carries the per-request `_meta` envelope AND the standard
//                        headers the transport requires: MCP-Protocol-Version, Mcp-Method, and
//                        Mcp-Name on tools/call.
//   legacy (2025-era)    initialize, then plain requests with MCP-Protocol-Version naming the
//                        negotiated revision; the server is stateless, so there is no session id.
import { CLIENT_CAPABILITIES_META_KEY, CLIENT_INFO_META_KEY, MODERN, PROTOCOL_VERSION_META_KEY } from "./mcp-stdio-client.mjs";

export const ACCEPT = "application/json, text/event-stream";
const clientInfo = { name: "echelongraph-mcp-http-test", version: "0.0.0" };

export const modernMeta = () => ({
  [PROTOCOL_VERSION_META_KEY]: MODERN,
  [CLIENT_INFO_META_KEY]: clientInfo,
  [CLIENT_CAPABILITIES_META_KEY]: {},
});

// The JSON-RPC message in a response body: the body itself, or the last `data:` event of an
// SSE stream.
export function parseRpcBody(contentType, text) {
  if ((contentType ?? "").includes("text/event-stream")) {
    const events = text.split(/\r?\n/).filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trim());
    return events.length ? JSON.parse(events[events.length - 1]) : undefined;
  }
  return text ? JSON.parse(text) : undefined;
}

let nextId = 1;

// One raw POST. Returns { status, headers, contentType, message } where message is the parsed
// JSON-RPC message (or undefined for an empty body).
export async function post(url, body, headers = {}) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: ACCEPT, ...headers },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
  const text = await res.text();
  const contentType = res.headers.get("content-type");
  let message;
  try {
    message = parseRpcBody(contentType, text);
  } catch {
    message = undefined;
  }
  return { status: res.status, headers: res.headers, contentType, text, message };
}

// A modern request with everything the transport requires; `omit` drops named headers.
export function modern(url, method, params = {}, { headers = {}, omit = [] } = {}) {
  const h = { "MCP-Protocol-Version": MODERN, "Mcp-Method": method, ...headers };
  if (method === "tools/call" && params.name) h["Mcp-Name"] = params.name;
  for (const k of omit) delete h[k];
  return post(url, { jsonrpc: "2.0", id: nextId++, method, params: { ...params, _meta: { ...(params._meta ?? {}), ...modernMeta() } } }, h);
}

// A legacy request. `revision` goes in MCP-Protocol-Version, as a 2025-era client sends it after
// initialize; initialize itself is sent without it.
export function legacy(url, method, params = {}, { revision, headers = {} } = {}) {
  const h = { ...headers };
  if (revision && method !== "initialize") h["MCP-Protocol-Version"] = revision;
  return post(url, { jsonrpc: "2.0", id: nextId++, method, params }, h);
}
