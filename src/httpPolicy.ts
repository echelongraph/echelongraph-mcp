// The hosted endpoint's edge rules (#2316), kept apart from the server wiring so each can be
// tested on its own: who the client is, which Origins are served, the per-client limit, and the
// JSON-RPC error bodies the edge answers with.
import { isIP } from "node:net";
import { classifyInboundRequest } from "@modelcontextprotocol/server";

// ── JSON-RPC errors from the edge ──
//
// Every refusal at the edge is a JSON-RPC error object, never an HTML page and never a bare
// status: an MCP client parses the body, and a model shown an HTML error page has nothing to say
// to its user. id is null because the edge answers before it has read (or trusted) the body.
export const ORIGIN_REFUSED_CODE = -32000; // the SDK's own code for an Origin refusal (originValidationResponse)
export const RATE_LIMITED_CODE = -32029; // implementation-defined server error range (-32000..-32099); "429"
export const BODY_TOO_LARGE_CODE = -32600; // Invalid Request
export const BUSY_CODE = -32030; // implementation-defined server error range; "503": no large-body slot free (#2747), or the instance full (#2773)

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

// ── Request-body caps (#2747) ──
//
// Two caps, because one tool's input is a document and every other tool's is a CVE ID or a short
// search.
//
//   - 64 KiB for every request: far above any real request but an SBOM's, and the cap the
//     endpoint shipped with (#2316).
//   - 6 MiB for one tools/call of check_sbom or scan_manifest (#2835: a project's lockfiles, up to
//     the same 5,000,000 characters), or one prompts/get of sbom_review, which takes the
//     same document to hand to check_sbom (LARGE_BODY_TARGETS). The sbom argument is up to MAX_SBOM_CHARS
//     (5,000,000) characters, and over this endpoint that document IS the JSON-RPC body: JSON
//     text passed as a string is escaped once more (every '"' and newline doubles), which for a
//     pretty-printed CycloneDX document is about 10% (a 4,998,809-character one is a 5,470,320-byte
//     body; test/http.test.mjs holds the cap above it). Below Cloud Run's 32 MiB HTTP/1 request
//     limit. OWASP Juice Shop 11.1.2's 0.74 MB SBOM, which the 64 KiB cap refused, fits eight
//     times over; a 2,000-component one in the same shape is a ~2 MB body.
//
// Which request may be large is decided before it is read where the client says so (a
// 2026-07-28 client sends Mcp-Method and Mcp-Name; another value is held to 64 KiB without
// reading on), and from the body itself otherwise: a body past 64 KiB that is not one of
// LARGE_BODY_TARGETS is refused 413 once read.
//
// Memory, not the cap, is what bounds this. An instance has 256 MiB and serves up to 250
// requests at once (deploy-all.sh SVC_MEMORY / SVC_CONCURRENCY); a check_sbom call holds the raw
// body, its JSON parse here, the SDK's own parse, the tool's parse of the document and the answer.
// Measured 2026-10-04 on dist/http.js, Node 22, peak RSS (VmHWM) over an idle ~80 MB: one
// 2,000-purl ~2 MB body +62 MB; one 5.47 MB body +76 MB; two 5.47 MB bodies at once 209 MB in
// all, also with V8's old space held to 64 MB: ~59 MB of 256 MiB left for everything else, so
// not a third. So a body past 64 KiB must hold one of DEFAULT_LARGE_BODY_SLOTS (2) slots per
// instance for as long as it is read, waits for a place (below) and is served; with none free it
// is answered 503 with Retry-After, never queued. The per-client limit still counts each large
// request as one request, before its body is read. That budget measured the two bodies alone, not
// the requests served beside them, which were enough to kill the instance (#2773): "Requests in
// flight per instance" below bounds those and records what each costs.
export const DEFAULT_MAX_BODY_BYTES = 64 * 1024;
export const DEFAULT_MAX_SBOM_BODY_BYTES = 6 * 1024 * 1024;
export const DEFAULT_LARGE_BODY_SLOTS = 2;
/** The requests whose body may pass DEFAULT_MAX_BODY_BYTES: JSON-RPC method → the tools or prompts it may name.
 *  #2835: scan_manifest takes a project's lockfiles as text, up to the same 5,000,000 characters as
 *  check_sbom's document (scan_manifest.ts MAX_MANIFEST_CHARS), so it is admitted the same way. */
export const LARGE_BODY_TARGETS: Readonly<Record<string, readonly string[]>> = { "tools/call": ["check_sbom", "scan_manifest"], "prompts/get": ["sbom_review"] };
/** LARGE_BODY_TARGETS in words, for the refusals. */
export const LARGE_BODY_TARGETS_TEXT = Object.entries(LARGE_BODY_TARGETS)
  .map(([m, ns]) => `a ${m} of ${ns.join(" or ")}`)
  .join(", or ");

const targetsOf = (method: string): readonly string[] => (Object.hasOwn(LARGE_BODY_TARGETS, method) ? LARGE_BODY_TARGETS[method] : []);

/** Whether a request's own Mcp-Method / Mcp-Name headers leave it free to be one of LARGE_BODY_TARGETS. Absent headers do (a 2025-era client sends neither). */
export function largeBodyAdmissible(mcpMethod: string | undefined, mcpName: string | undefined): boolean {
  const name = mcpName?.trim();
  if (mcpMethod === undefined) return name === undefined || Object.values(LARGE_BODY_TARGETS).some((ns) => ns.includes(name));
  const want = targetsOf(mcpMethod.trim());
  return want.length > 0 && (name === undefined || want.includes(name));
}

/** Whether a read body is one of LARGE_BODY_TARGETS, by its bodyFacts. */
export function isLargeBodyTarget(facts: BodyFacts): boolean {
  const name = facts.rpc_method === "tools/call" ? facts.tool : facts.rpc_method === "prompts/get" ? facts.prompt : undefined;
  return name !== undefined && targetsOf(facts.rpc_method).includes(name);
}

/** A counting semaphore that never waits: tryAcquire answers at once. */
export class Slots {
  private used = 0;
  constructor(readonly max: number) {}
  tryAcquire(): boolean {
    if (this.used >= this.max) return false;
    this.used++;
    return true;
  }
  release(): void {
    if (this.used > 0) this.used--;
  }
  get inUse(): number {
    return this.used;
  }
}

// ── Requests in flight per instance (#2773) ──
//
// The slots bound the large bodies, not the requests served beside them. Cloud Run sends one
// instance up to 250 requests at once (deploy-all.sh SVC_CONCURRENCY) into 256 MiB. Measured
// 2026-10-04 on dist/http.js, Node 22.22, in a 256 MiB memory cgroup, against a stub API
// answering in 1.5 s, two 4,999,913-character check_sbom documents in flight plus N tools/call
// cve_summary at once, 2025-era (answered over SSE, the costlier era): N=100 peaked at 226 MB,
// N=125 at 259 MB (96%), N=200 and N=250 were OOM-killed; with no document, N=200 peaked at
// 240 MB and N=250 was OOM-killed.
//
// Two bounds hold that load (test/http-memory.test.mjs drives the real server with it; what each
// case does without each bound is below):
//   - V8's heap. In that sandbox (a cgroup v1 on a 16 GB host) Node 22 sized V8's heap from the
//     host's memory, not the cgroup's (heap_size_limit 8,195 MiB in 256 MiB), so V8 left the
//     garbage of the requests served (~1 MB each) uncollected until the kernel killed the
//     instance. So the image caps V8's old space at 128 MiB (Dockerfile.http), and V8 collects
//     first. On Cloud Run this is not verified: an instance that shows Node only its 256 MiB gets
//     a default heap near the cap already, and then the cap changes little. Its start-up line says
//     which (heap_limit_mb; memory_limit_mb, null where Node is told no limit).
//   - The live set. Under the cap, what must fit is what is live at once, and 250 requests at once
//     do not: with every answer held until all 250 were inside the instance, V8 aborted
//     ("JavaScript heap out of memory"). So an instance serves at most DEFAULT_MAX_IN_FLIGHT /mcp
//     requests at once, large ones included (they hold a slot as well), whatever its heap.
// A request's body is read before it waits for a place, so a client that uploads slowly holds its
// socket (and a large body its slot), never a place. It then waits, first come first served, up
// to DEFAULT_ADMISSION_WAIT_MS for one to finish, and is then answered 503 with Retry-After: it
// waits rather than being refused at once because Cloud Run still routes up to 250 to the
// instance and counts a waiting request toward scaling out. A waiting request costs its socket and
// its body: at most 64 KiB, or a large body that holds a slot. At most DEFAULT_MAX_WAITING wait;
// past that, 503 at once. A request counts until its answer is written AND its work has stopped: a
// check_sbom call whose client has gone keeps its place until it stops (#2775). /health is never
// held, and nor is a subscriptions/listen stream (isListenStream below).
//
// With both, in that cgroup, the two documents at the API, then 248 cve_summary sent at once:
//   - the API answering in 1.5 s: all 250 answered 200, 64 served at once and the last waiting
//     ~9 s (one core here serves about 28 a second, so on a slower one the last of such a burst
//     wait past DEFAULT_ADMISSION_WAIT_MS and are answered 503), cgroup peak 221-225 MB of 268 MB
//     (82-84%). Without the heap cap: OOM-killed in three runs of four, the fourth at 248 MB.
//     Without the admission: V8 aborted, four of four.
//   - every answer held until all 250 were inside the instance at once: 64 served and answered
//     200, the other 186 answered 503 after waiting 10 s, peak 201-208 MB (75-77%), and 204-206 MB
//     without the heap cap. Without the admission: V8 aborted, two of two.
// What this does not bound is a request whose ANSWER is large: a check_sbom call of 2,000 purls
// fits a 64 KiB body, and with production-shaped rows (~2.2 KB each) one peaks at +77 MB; beside
// the two documents, 8 at once peaked at 84%, and 16 at once exhausted the 128 MiB heap. Bounding
// that needs a weight per call (its purls), not a count of requests.
export const DEFAULT_MAX_IN_FLIGHT = 64;
export const DEFAULT_ADMISSION_WAIT_MS = 10_000;
export const DEFAULT_MAX_WAITING = 250;

/**
 * A counting semaphore whose callers may wait, in arrival order, for a bounded time. acquire
 * resolves true once admitted (the caller then calls release() exactly once), or false when the
 * wait timed out, `signal` aborted, or maxWaiting callers were already waiting.
 */
export class Admission {
  private used = 0;
  private readonly queue: Array<() => void> = [];
  constructor(
    readonly max: number,
    readonly maxWaiting: number,
  ) {}

  acquire(waitMs: number, signal?: AbortSignal): Promise<boolean> {
    if (this.used < this.max && this.queue.length === 0) {
      this.used++;
      return Promise.resolve(true);
    }
    if (signal?.aborted || waitMs <= 0 || this.queue.length >= this.maxWaiting) return Promise.resolve(false);
    return new Promise((resolve) => {
      // admit is called by release(), which hands its unit straight over (used is unchanged).
      const admit = (): void => {
        done();
        resolve(true);
      };
      const giveUp = (): void => {
        const i = this.queue.indexOf(admit);
        if (i >= 0) this.queue.splice(i, 1);
        done();
        resolve(false);
      };
      const timer = setTimeout(giveUp, waitMs);
      const done = (): void => {
        clearTimeout(timer);
        signal?.removeEventListener("abort", giveUp);
      };
      signal?.addEventListener("abort", giveUp, { once: true });
      this.queue.push(admit);
    });
  }

  release(): void {
    const next = this.queue.shift();
    if (next) next();
    else if (this.used > 0) this.used--;
  }

  get inUse(): number {
    return this.used;
  }

  get waiting(): number {
    return this.queue.length;
  }
}

// ── The request that is a stream: subscriptions/listen ──
//
// A 2026-07-28 client opens subscriptions/listen to hear of list changes, and the SDK answers it
// with an SSE stream that stays open until the client leaves (or the server closes). This server
// declares no listChanged (index.ts), so the stream carries the acknowledgement and then only
// the SDK's keepalives: no work, no API call. Admitted like any other request, it held its place
// for as long as it was open, so 64 idle listeners (under the per-client limit) left every
// tools/call, initialize and server/discover on the instance waiting 10 s for a 503 (#2773). So it
// is relayed without admission and without a work hold. What bounds the streams instead: the
// per-client limit, which counts each one when it opens; the SDK's own cap of
// DEFAULT_MAX_SUBSCRIPTIONS (1024 in @modelcontextprotocol/server 2.1.0) open per process, past
// which it answers JSON-RPC -32603 "Subscription limit reached" at once; and on Cloud Run the
// instance's 250 requests at once and its 60 s request timeout, which ends every stream
// (deploy-all.sh SVC_CONCURRENCY, --timeout). Measured 2026-10-04 on dist/http.js, Node 22.22,
// started as Dockerfile.http starts it, in a 256 MiB memory cgroup, with every place taken (two
// maximum check_sbom documents and 62 cve_summary held at the API): beside 186 open listen
// streams (Cloud Run's 250 at once) the cgroup peaked at 209-218 MB of 268 MB, and beside 1,024
// (the SDK's cap) at 224-225 MB, never OOM-killed. Within Cloud Run's 250, a listen stream
// takes the instance's concurrency that a waiting request would, and Cloud Run scales out.
//
// It is the only such request. GET and DELETE /mcp (the 2025 session stream and its end) are
// answered 405 at once by the SDK's stateless legacy fallback, a 2025-era POST's SSE answer ends
// with its result, and the server registers no task or resource subscription. Which request is a
// listen stream is decided by the SDK's own routing step (classifyInboundRequest, what
// createMcpHandler runs), so the two cannot disagree: a 2025-era body naming the method goes to
// the legacy fallback, which answers it at once, and it waits for a place like any request.
export const LISTEN_METHOD = "subscriptions/listen";

/** The standard MCP headers of a request, as the SDK reads them. */
export type StandardHeaders = { protocolVersion?: string; mcpMethod?: string; mcpName?: string };

/** Whether a read POST body is one the SDK serves as a subscriptions/listen stream: see the section comment. */
export function isListenStream(facts: BodyFacts, body: Buffer, headers: StandardHeaders): boolean {
  if (facts.rpc_method !== LISTEN_METHOD) return false;
  let parsed: unknown;
  try {
    parsed = JSON.parse(body.toString("utf8"));
  } catch {
    return false;
  }
  const route = classifyInboundRequest({
    httpMethod: "POST",
    protocolVersionHeader: headers.protocolVersion,
    mcpMethodHeader: headers.mcpMethod,
    mcpNameHeader: headers.mcpName,
    body: parsed,
  });
  return route.kind === "modern" && route.messageKind === "request" && route.message.method === LISTEN_METHOD;
}

// ── Bounded access-log fields ──
//
// The access line carries no body, no query string, no argument and no client address: only
// values from small closed sets or shapes, so nothing a client types reaches the log (#1983).

const RPC_METHOD = /^[a-z][a-z/_]{0,39}$/i;
const TOOL_NAME = /^[a-z][a-z0-9_]{0,39}$/;
const REVISION = /^\d{4}-\d{2}-\d{2}$/;
const UA_FAMILY = /^[A-Za-z0-9._-]{1,40}$/;

export type BodyFacts = { rpc_method: string; tool?: string; prompt?: string };

/** The JSON-RPC method and, for tools/call, the tool name (for prompts/get, the prompt name), shape-checked; never anything else from the body. */
export function bodyFacts(body: Buffer | undefined): BodyFacts {
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
  if (m !== "tools/call" && m !== "prompts/get") return { rpc_method: m };
  const name = (parsed as { params?: { name?: unknown } }).params?.name;
  const shaped = typeof name === "string" && TOOL_NAME.test(name) ? name : "(other)";
  return m === "tools/call" ? { rpc_method: m, tool: shaped } : { rpc_method: m, prompt: shaped };
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
