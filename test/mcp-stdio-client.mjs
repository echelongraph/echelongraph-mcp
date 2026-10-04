// A minimal MCP client over stdio, for the tests and the smoke scripts. It speaks the wire
// format directly (newline-delimited JSON-RPC) rather than through an SDK client, so a test
// chooses the protocol era exactly and sees exactly what the server wrote:
//
//   era "2026-07-28"  the modern opening: server/discover, then every request carries the
//                     per-request `_meta` envelope (protocol version, client info, capabilities).
//   era "2025-..."    the legacy opening: initialize with that protocolVersion, then
//                     notifications/initialized, then plain requests.
//
// It needs nothing outside Node, so it runs inside an unpacked tarball installed with only the
// package's production dependencies, the way the published-tarball checks run the suite.
import { spawn } from "node:child_process";

export const MODERN = "2026-07-28";
export const PROTOCOL_VERSION_META_KEY = "io.modelcontextprotocol/protocolVersion";
export const CLIENT_INFO_META_KEY = "io.modelcontextprotocol/clientInfo";
export const CLIENT_CAPABILITIES_META_KEY = "io.modelcontextprotocol/clientCapabilities";
export const SERVER_INFO_META_KEY = "io.modelcontextprotocol/serverInfo";

// A JSON-RPC error answer, kept whole so a test can assert on its code and data.
export class RpcError extends Error {
  constructor(method, error) {
    super(`${method}: JSON-RPC error ${error?.code}: ${error?.message}`);
    this.code = error?.code;
    this.data = error?.data;
  }
}

export class StdioMcpClient {
  constructor({ command, args = [], env, stderr = "inherit", clientInfo = { name: "echelongraph-mcp-test", version: "0.0.0" }, requestTimeoutMs = 30_000 }) {
    this.clientInfo = clientInfo;
    this.requestTimeoutMs = requestTimeoutMs;
    this.era = undefined;
    this.opening = undefined;
    this.serverInfo = undefined;
    this.nextId = 1;
    this.pending = new Map();
    this.buffer = "";
    this.proc = spawn(command, args, { env, stdio: ["pipe", "pipe", stderr] });
    this.exited = new Promise((resolve) => this.proc.once("exit", (code, signal) => resolve({ code, signal })));
    this.proc.stdout.setEncoding("utf8");
    this.proc.stdout.on("data", (chunk) => this.onData(chunk));
    this.exited.then(({ code, signal }) => {
      this.exitStatus = { code, signal };
      for (const [, p] of this.pending) {
        clearTimeout(p.timer);
        p.reject(new Error(`the server exited (code ${code}, signal ${signal}) before answering ${p.method}`));
      }
      this.pending.clear();
    });
  }

  onData(chunk) {
    this.buffer += chunk;
    let i;
    while ((i = this.buffer.indexOf("\n")) >= 0) {
      const line = this.buffer.slice(0, i).trim();
      this.buffer = this.buffer.slice(i + 1);
      if (!line) continue;
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        // The stdio binding forbids anything on stdout but MCP messages.
        this.protocolViolation = `not JSON on stdout: ${line.slice(0, 200)}`;
        continue;
      }
      if (msg.id === undefined || msg.method !== undefined) continue; // a notification, or a request to us
      const p = this.pending.get(msg.id);
      if (!p) continue;
      this.pending.delete(msg.id);
      clearTimeout(p.timer);
      if (msg.error) p.reject(new RpcError(p.method, msg.error));
      else p.resolve(msg.result);
    }
  }

  write(msg) {
    this.proc.stdin.write(`${JSON.stringify(msg)}\n`);
  }

  // The per-request envelope a 2026-07-28 request carries.
  meta() {
    return {
      [PROTOCOL_VERSION_META_KEY]: MODERN,
      [CLIENT_INFO_META_KEY]: this.clientInfo,
      [CLIENT_CAPABILITIES_META_KEY]: {},
    };
  }

  // One raw request, answered or rejected; `params` goes on the wire as given.
  rawRequest(method, params) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      // A server that has already exited answers nothing: say so now rather than at the timeout.
      if (this.exitStatus) {
        reject(new Error(`the server exited (code ${this.exitStatus.code}, signal ${this.exitStatus.signal}) before answering ${method}`));
        return;
      }
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`${method}: no answer within ${this.requestTimeoutMs} ms`));
      }, this.requestTimeoutMs);
      this.pending.set(id, { method, resolve, reject, timer });
      this.write({ jsonrpc: "2.0", id, method, ...(params === undefined ? {} : { params }) });
    });
  }

  // A request in the connection's era: on the modern era it carries the `_meta` envelope.
  request(method, params = {}) {
    return this.rawRequest(method, this.era === MODERN ? { ...params, _meta: { ...(params._meta ?? {}), ...this.meta() } } : params);
  }

  async open(era) {
    this.era = era;
    if (era === MODERN) {
      this.opening = await this.rawRequest("server/discover", { _meta: this.meta() });
      this.serverInfo = this.opening?._meta?.[SERVER_INFO_META_KEY];
    } else {
      this.opening = await this.rawRequest("initialize", { protocolVersion: era, capabilities: {}, clientInfo: this.clientInfo });
      this.serverInfo = this.opening?.serverInfo;
      this.write({ jsonrpc: "2.0", method: "notifications/initialized" });
    }
    return this.opening;
  }

  getServerVersion() {
    return this.serverInfo;
  }

  async listTools() {
    const tools = [];
    let cursor;
    do {
      const page = await this.request("tools/list", cursor === undefined ? {} : { cursor });
      tools.push(...(page.tools ?? []));
      cursor = page.nextCursor;
    } while (cursor);
    return { tools };
  }

  callTool({ name, arguments: args }) {
    return this.request("tools/call", { name, arguments: args ?? {} });
  }

  // #2722: prompts and resources, each list followed through its pages.
  async listAll(method, key) {
    const out = [];
    let cursor;
    do {
      const page = await this.request(method, cursor === undefined ? {} : { cursor });
      out.push(...(page[key] ?? []));
      cursor = page.nextCursor;
    } while (cursor);
    return { [key]: out };
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

  listResourceTemplates() {
    return this.listAll("resources/templates/list", "resourceTemplates");
  }

  readResource({ uri }) {
    return this.request("resources/read", { uri });
  }

  // Closing stdin is the stdio binding's shutdown signal; a server that does not exit on it
  // within the grace period is killed, so a test run never hangs on one.
  async close(graceMs = 5_000) {
    this.proc.stdin.end();
    const timer = setTimeout(() => this.proc.kill("SIGKILL"), graceMs);
    const result = await this.exited;
    clearTimeout(timer);
    return result;
  }
}

// Spawn a server and open it in the given era.
export async function connect({ era = MODERN, ...options }) {
  const client = new StdioMcpClient(options);
  try {
    await client.open(era);
  } catch (e) {
    await client.close();
    throw e;
  }
  return client;
}
