// The hosted endpoint's edge rules (#2316), kept apart from the server wiring so each can be
// tested on its own: who the client is, which Origins are served, the per-client limit, and the
// JSON-RPC error bodies the edge answers with.
import { isIP } from "node:net";

// ── JSON-RPC errors from the edge ──
//
// Every refusal at the edge is a JSON-RPC error object, never an HTML page and never a bare
// status: an MCP client parses the body, and a model shown an HTML error page has nothing to say
// to its user. id is null because the edge answers before it has read (or trusted) the body.
export const ORIGIN_REFUSED_CODE = -32000; // the SDK's own code for an Origin refusal (originValidationResponse)
export const RATE_LIMITED_CODE = -32029; // implementation-defined server error range (-32000..-32099); "429"
export const BODY_TOO_LARGE_CODE = -32600; // Invalid Request

export function rpcError(code: number, message: string, data?: Record<string, unknown>): string {
  return JSON.stringify({ jsonrpc: "2.0", id: null, error: { code, message, ...(data ? { data } : {}) } });
}

// ── Origin policy ──
//
// THE POLICY, written down before building as #2316 asks. The transport spec's Origin check
// exists against DNS rebinding: a web page making a victim's browser talk to an MCP server on
// the victim's own network. This server is a public, keyless, read-only service on the public
// internet that serves only public data; there is nothing behind the victim's firewall for a
// rebinding page to reach, and no credential for a cross-site page to ride. So:
//
//   - no Origin header: served. Every non-browser MCP client (claude.ai's connector backend,
//     Cursor, Copilot, the SDK clients) sends none.
//   - an https Origin, any host: served. A browser-based MCP client on any https site may use
//     a free public endpoint, as it may fetch the public API.
//   - anything else is refused 403: "null" (sandboxed iframes, file: pages, redirects across
//     origins — an origin that cannot be named), a non-https scheme (http:, file:, chrome-
//     extension:, …), a value that is not a bare serialized origin (a path, a userinfo, a
//     list of several), and an empty header.
export type OriginVerdict = { ok: true } | { ok: false; reason: string };

export function originVerdict(origin: string | undefined): OriginVerdict {
  if (origin === undefined) return { ok: true };
  const o = origin.trim();
  if (o === "") return { ok: false, reason: "an empty Origin header" };
  if (o.toLowerCase() === "null") return { ok: false, reason: 'the opaque Origin "null"' };
  if (/[\s,]/.test(o)) return { ok: false, reason: "a malformed Origin header (not a single origin)" };
  let url: URL;
  try {
    url = new URL(o);
  } catch {
    return { ok: false, reason: "a malformed Origin header" };
  }
  if (url.protocol !== "https:") return { ok: false, reason: "a non-https Origin" };
  // A serialized origin is scheme://host[:port] and nothing else.
  if (url.username || url.password || `${url.protocol}//${url.host}` !== o.toLowerCase()) {
    return { ok: false, reason: "a malformed Origin header (not a bare origin)" };
  }
  return { ok: true };
}

// ── Who the client is ──
//
// The client is the rightmost PUBLIC hop of X-Forwarded-For, or the socket peer when there is
// none: the same rule as core-backend's waf.RateLimitKey, for its reason. Cloud Run's front end
// APPENDS the address it saw to whatever the client sent, so a value the client forges can only
// sit to the LEFT of the hop the platform recorded, and walking from the right means no forged
// value can become the key. CF-Connecting-IP, X-Real-IP and Forwarded are never read: nothing in
// front of this service writes them, so they are pure client input. (That also means
// mcp.echelongraph.io must stay DNS-only at Cloudflare: a proxied record would put a Cloudflare
// address in that slot, and every client of one PoP would be one key.)

type Parsed = { family: 4; octets: number[]; text: string } | { family: 6; hextets: number[]; text: string };

// The eight 16-bit words of an IPv6 literal that net.isIP has already accepted.
function expandIPv6(s: string): number[] | undefined {
  // A dotted IPv4 tail ("::ffff:203.0.113.7") is rewritten as its two words first.
  const lastColon = s.lastIndexOf(":");
  const v4 = s.slice(lastColon + 1);
  if (v4.includes(".")) {
    const o = v4.split(".").map(Number);
    if (o.length !== 4 || o.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return undefined;
    s = `${s.slice(0, lastColon + 1)}${((o[0] << 8) | o[1]).toString(16)}:${((o[2] << 8) | o[3]).toString(16)}`;
  }
  const parts = s.split("::");
  if (parts.length > 2) return undefined;
  const head = parts[0] ? parts[0].split(":") : [];
  const rest = parts.length === 2 && parts[1] ? parts[1].split(":") : [];
  const fill = parts.length === 2 ? 8 - head.length - rest.length : 0;
  if (fill < 0 || (parts.length === 1 && head.length !== 8)) return undefined;
  const words = [...head, ...Array<string>(fill).fill("0"), ...rest].map((h) => parseInt(h, 16));
  if (words.length !== 8 || words.some((w) => !Number.isInteger(w) || w < 0 || w > 0xffff)) return undefined;
  return words;
}

/** One forwarded hop or socket address, parsed with a forwarded hop's tolerances; undefined if it is not an address. */
export function parseAddress(raw: string | undefined): Parsed | undefined {
  if (!raw) return undefined;
  let s = raw.trim();
  if (!s) return undefined;
  // "[2001:db8::1]:443" / "[2001:db8::1]" → the literal; "203.0.113.7:51234" → the address.
  const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(s);
  if (bracketed) s = bracketed[1];
  else if (/^[\d.]+:\d+$/.test(s)) s = s.slice(0, s.lastIndexOf(":"));
  const zone = s.indexOf("%");
  if (zone >= 0) s = s.slice(0, zone);
  const fam = isIP(s);
  if (fam === 4) return { family: 4, octets: s.split(".").map(Number), text: s };
  if (fam !== 6) return undefined;
  const h = expandIPv6(s.toLowerCase());
  if (!h) return undefined;
  // IPv4-mapped (::ffff:a.b.c.d) is the IPv4 address.
  if (h.slice(0, 5).every((w) => w === 0) && h[5] === 0xffff) {
    const octets = [h[6] >> 8, h[6] & 0xff, h[7] >> 8, h[7] & 0xff];
    return { family: 4, octets, text: octets.join(".") };
  }
  return { family: 6, hextets: h, text: s.toLowerCase() };
}

/** Whether a parsed address is one a client on the public internet could have arrived from (core-backend's publicUnicast). */
export function isPublic(a: Parsed): boolean {
  if (a.family === 4) {
    const [o0, o1] = a.octets;
    if (o0 === 0 || o0 === 10 || o0 === 127 || o0 >= 224) return false; // this-network, private, loopback, multicast/reserved/broadcast
    if (o0 === 169 && o1 === 254) return false; // link-local (the platform's front end)
    if (o0 === 172 && o1 >= 16 && o1 <= 31) return false;
    if (o0 === 192 && o1 === 168) return false;
    return true;
  }
  const h = a.hextets;
  if (h.every((w) => w === 0)) return false; // ::
  if (h.slice(0, 7).every((w) => w === 0) && h[7] === 1) return false; // ::1
  if ((h[0] & 0xffc0) === 0xfe80) return false; // fe80::/10 link-local
  if ((h[0] & 0xff00) === 0xff00) return false; // ff00::/8 multicast
  if ((h[0] & 0xfe00) === 0xfc00) return false; // fc00::/7 unique local
  return true;
}

export type Client = {
  /** The address the API is told (X-EG-Client-IP), when it is public; undefined otherwise. */
  forwardAddress?: string;
  /** The key this service counts the client against: an IPv4 address, or an IPv6 /64. */
  key: string;
};

function keyOf(a: Parsed): string {
  if (a.family === 4) return a.octets.join(".");
  return `${a.hextets.slice(0, 4).map((w) => w.toString(16)).join(":")}::/64`;
}

/** The client of one request: see the section comment. */
export function resolveClient(xff: string | undefined, socketAddress: string | undefined): Client {
  if (xff) {
    const hops = xff.split(",");
    for (let i = hops.length - 1; i >= 0; i--) {
      const a = parseAddress(hops[i]);
      if (a && isPublic(a)) return { forwardAddress: a.text, key: keyOf(a) };
    }
  }
  const peer = parseAddress(socketAddress);
  if (!peer) return { key: socketAddress || "(unknown)" };
  return { forwardAddress: isPublic(peer) ? peer.text : undefined, key: isPublic(peer) ? keyOf(peer) : peer.text };
}

// ── Per-client limit ──
//
// A fixed one-minute window per client key, in this instance's memory. The default is derived
// from the public API's own per-client ceiling, not invented: core-backend's WAF admits 600
// requests a minute per client address on the API's base paths (waf.DefaultTierConfigs
// ["default"], 10 a second), and the costliest tool here, exposure_radar, makes up to five API
// calls per MCP request. 600 / 5 = 120 MCP requests a minute keeps one client's heaviest use
// inside the ceiling the API applies to it (core-backend keys this service's calls on the
// forwarded client, #2212), so a client meets THIS limit — a JSON-RPC error it can read — before
// the API's. It is not a tier: it grants nothing the API does not already grant one address.
//
// Counted per instance: with Cloud Run's max-instances at N, one client spread over every
// instance could make N times this many requests a minute here; the API's own ceiling, which
// is counted fleet-wide, still binds behind it.
export const DEFAULT_RATE_LIMIT_PER_MIN = 120;

export type LimitVerdict = { allowed: true; remaining: number } | { allowed: false; retryAfterSec: number };

export class FixedWindowLimiter {
  private readonly windows = new Map<string, { start: number; count: number }>();
  constructor(
    readonly max: number,
    readonly windowMs = 60_000,
    private readonly now: () => number = Date.now,
    private readonly maxKeys = 50_000,
  ) {}

  hit(key: string): LimitVerdict {
    const t = this.now();
    let w = this.windows.get(key);
    if (!w || t - w.start >= this.windowMs) {
      if (!w && this.windows.size >= this.maxKeys) this.sweep(t);
      w = { start: t, count: 0 };
      this.windows.set(key, w);
    }
    if (w.count >= this.max) {
      return { allowed: false, retryAfterSec: Math.max(1, Math.ceil((w.start + this.windowMs - t) / 1000)) };
    }
    w.count++;
    return { allowed: true, remaining: this.max - w.count };
  }

  // Drop expired windows; if every key is live (a flood of distinct addresses), drop the oldest
  // half rather than grow without bound. Forgetting a key early can only admit, never refuse.
  private sweep(t: number): void {
    for (const [k, w] of this.windows) if (t - w.start >= this.windowMs) this.windows.delete(k);
    if (this.windows.size < this.maxKeys) return;
    let drop = Math.floor(this.windows.size / 2);
    for (const k of this.windows.keys()) {
      if (drop-- <= 0) break;
      this.windows.delete(k);
    }
  }
}

// ── Bounded access-log fields ──
//
// The access line carries no body, no query string, no argument and no client address: only
// values from small closed sets or shapes, so nothing a client types reaches the log (#1983).

const RPC_METHOD = /^[a-z][a-z/_]{0,39}$/i;
const TOOL_NAME = /^[a-z][a-z0-9_]{0,39}$/;
const REVISION = /^\d{4}-\d{2}-\d{2}$/;
const UA_FAMILY = /^[A-Za-z0-9._-]{1,40}$/;

/** The JSON-RPC method and, for tools/call, the tool name, shape-checked; never anything else from the body. */
export function bodyFacts(body: Buffer | undefined): { rpc_method: string; tool?: string } {
  if (!body || body.length === 0) return { rpc_method: "(none)" };
  let parsed: unknown;
  try {
    parsed = JSON.parse(body.toString("utf8"));
  } catch {
    return { rpc_method: "(unparseable)" };
  }
  if (Array.isArray(parsed)) return { rpc_method: "(batch)" };
  if (parsed === null || typeof parsed !== "object") return { rpc_method: "(other)" };
  const m = (parsed as { method?: unknown }).method;
  if (typeof m !== "string") return { rpc_method: "(response)" };
  if (!RPC_METHOD.test(m)) return { rpc_method: "(other)" };
  if (m !== "tools/call") return { rpc_method: m };
  const name = (parsed as { params?: { name?: unknown } }).params?.name;
  return { rpc_method: m, tool: typeof name === "string" && TOOL_NAME.test(name) ? name : "(other)" };
}

export function revisionLabel(v: string | undefined): string {
  if (v === undefined) return "(none)";
  return REVISION.test(v.trim()) ? v.trim() : "(other)";
}

export function uaFamily(ua: string | undefined): string {
  if (!ua) return "(none)";
  const fam = ua.split(/[/\s]/, 1)[0];
  return UA_FAMILY.test(fam) ? fam : "(other)";
}
