// A minimal MCP client over Streamable HTTP, for the hosted endpoint's tests (#2316). Like
// mcp-stdio-client.mjs it speaks the wire directly, so a test chooses the era and the headers
// exactly and sees exactly what the server answered: status, headers and body.
//
//   modern (2026-07-28)  every request carries the per-request `_meta` envelope AND the standard
//                        headers the transport requires: MCP-Protocol-Version, Mcp-Method, and
//                        Mcp-Name on tools/call, prompts/get and resources/read.
//   legacy (2025-era)    initialize, then plain requests with MCP-Protocol-Version naming the
//                        negotiated revision; the server is stateless, so there is no session id.
//
// HttpMcpClient (#2737) is the same wire behind StdioMcpClient's interface (open, listTools,
// callTool, listPrompts, getPrompt, listResources, readResource, getServerVersion, close), so the
// production synthetic probes the hosted endpoint with the code that probes the npm package.
import { CLIENT_CAPABILITIES_META_KEY, CLIENT_INFO_META_KEY, MODERN, PROTOCOL_VERSION_META_KEY, RpcError, SERVER_INFO_META_KEY } from "./mcp-stdio-client.mjs";

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
// JSON-RPC message (or undefined for an empty body). `signal` bounds it (HttpMcpClient's timeout).
export async function post(url, body, headers = {}, { signal } = {}) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: ACCEPT, ...headers },
    body: typeof body === "string" ? body : JSON.stringify(body),
    signal,
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

// The methods whose Mcp-Name header mirrors a body field (SEP-2243; the SDK's
// MCP_NAME_HEADER_SOURCE): a modern request to one of them without the header is refused.
export const MCP_NAME_SOURCE = { "tools/call": "name", "prompts/get": "name", "resources/read": "uri" };

// The standard headers a modern request carries.
export function modernHeaders(method, params = {}) {
  const h = { "MCP-Protocol-Version": MODERN, "Mcp-Method": method };
  const field = MCP_NAME_SOURCE[method];
  if (field && typeof params?.[field] === "string" && params[field]) h["Mcp-Name"] = params[field];
  return h;
}

// A modern request with everything the transport requires; `omit` drops named headers.
export function modern(url, method, params = {}, { headers = {}, omit = [] } = {}) {
  const h = { ...modernHeaders(method, params), ...headers };
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

// An answer that is not a JSON-RPC response: the endpoint, not the MCP server, answered (a 404
// from a broken route, a 403 from the Origin policy, a 5xx from the platform or a cold start).
export class HttpStatusError extends Error {
  constructor(method, status) {
    super(`${method}: HTTP ${status} with no JSON-RPC answer`);
    this.status = status;
  }
}

// A client of one Streamable HTTP endpoint, opened in one era. Stateless like the server: every
// request is one POST. The legacy era sends initialize once (and notifications/initialized, as a
// 2025-era client does) and names the negotiated revision on every later request. `userAgent`
// goes on every request.
export class HttpMcpClient {
  constructor({ url, userAgent, headers = {}, clientInfo = { name: "echelongraph-mcp-http-test", version: "0.0.0" }, requestTimeoutMs = 30_000 }) {
    this.url = url;
    this.clientInfo = clientInfo;
    this.requestTimeoutMs = requestTimeoutMs;
    this.headers = { ...headers, ...(userAgent ? { "User-Agent": userAgent } : {}) };
    this.era = undefined;
    this.revision = undefined;
    this.serverInfo = undefined;
  }

  meta() {
    return { [PROTOCOL_VERSION_META_KEY]: MODERN, [CLIENT_INFO_META_KEY]: this.clientInfo, [CLIENT_CAPABILITIES_META_KEY]: {} };
  }

  // One request (or, with notification, one notification) in the connection's era, `params` on
  // the wire as given. Resolves to the result; rejects with RpcError, HttpStatusError, or an Error
  // whose message says "no answer within" on the timeout.
  async send(method, params, { notification = false } = {}) {
    const h = { ...this.headers };
    if (this.era === MODERN) Object.assign(h, modernHeaders(method, params));
    else if (this.revision && method !== "initialize") h["MCP-Protocol-Version"] = this.revision;
    const body = { jsonrpc: "2.0", ...(notification ? {} : { id: nextId++ }), method, ...(params === undefined ? {} : { params }) };
    let r;
    try {
      r = await post(this.url, body, h, { signal: AbortSignal.timeout(this.requestTimeoutMs) });
    } catch (e) {
      if (e?.name === "TimeoutError" || e?.name === "AbortError") throw new Error(`${method}: no answer within ${this.requestTimeoutMs} ms`);
      throw new Error(`${method}: the request failed: ${e?.cause?.code ?? e?.message ?? e}`);
    }
    if (notification) return undefined;
    if (r.message?.error) throw new RpcError(method, r.message.error);
    if (r.status < 200 || r.status > 299 || !r.message || !("result" in r.message)) throw new HttpStatusError(method, r.status);
    return r.message.result;
  }

  // A request in the connection's era: on the modern era it carries the `_meta` envelope.
  request(method, params = {}) {
    return this.send(method, this.era === MODERN ? { ...params, _meta: { ...(params._meta ?? {}), ...this.meta() } } : params);
  }

  async open(era) {
    this.era = era;
    if (era === MODERN) {
      this.opening = await this.send("server/discover", { _meta: this.meta() });
      this.serverInfo = this.opening?._meta?.[SERVER_INFO_META_KEY];
    } else {
      this.opening = await this.send("initialize", { protocolVersion: era, capabilities: {}, clientInfo: this.clientInfo });
      this.revision = typeof this.opening?.protocolVersion === "string" ? this.opening.protocolVersion : era;
      this.serverInfo = this.opening?.serverInfo;
      await this.send("notifications/initialized", undefined, { notification: true }).catch(() => {});
    }
    return this.opening;
  }

  getServerVersion() {
    return this.serverInfo;
  }

  async listAll(method, key) {
    const out = [];
    let cursor;
    do {
      const page = await this.request(method, cursor === undefined ? {} : { cursor });
      out.push(...(page?.[key] ?? []));
      cursor = page?.nextCursor;
    } while (cursor);
    return { [key]: out };
  }

  listTools() {
    return this.listAll("tools/list", "tools");
  }

  callTool({ name, arguments: args }) {
    return this.request("tools/call", { name, arguments: args ?? {} });
  }

  listPrompts() {
    return this.listAll("prompts/list", "prompts");
  }

  getPrompt({ name, arguments: args }) {
    return this.request("prompts/get", args === undefined ? { name } : { name, arguments: args });
  }

  listResources() {
    return this.listAll("resources/list", "resources");
  }

  readResource({ uri }) {
    return this.request("resources/read", { uri });
  }

  // Nothing to close: the server keeps no session.
  async close() {}
}

// Open a client of `url` in the given era.
export async function connectHttp({ era = MODERN, ...options }) {
  const client = new HttpMcpClient(options);
  await client.open(era);
  return client;
}
