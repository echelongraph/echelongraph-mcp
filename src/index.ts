#!/usr/bin/env node
// EchelonGraph CVE & internet-exposure MCP server.
// Exposes EchelonGraph's free, keyless public CVE and exposure data as MCP tools for Claude,
// Cursor, Cline and any MCP client: the CVE feed, and per CVE the internet-exposure footprint
// that EchelonGraph's KEV-exposure radar derives from Shodan data. Every figure is as fresh as
// the schedule that refreshes it, and the tool texts say which schedule that is.
// stdio transport; no auth required; read-only. It makes no request other than the API call a
// tool needs to answer.
//
// Result contract (#1874). A tool answers in exactly one of two shapes, and they never blur:
//   - success: content[0] is the API's JSON verbatim; content[1] is a one-line note saying
//     the call succeeded, where, and what it found — in words, including when it found
//     nothing ("we looked and found nothing" is a measurement). One exception: exposure_radar
//     relays each radar's answer cut to the fields it can label by what they count, and names
//     what it left out (readKEVExposure, readExposedDatabases, readLeakedCredentials and
//     readShadowAI; #2307, #2313).
//   - failure (isError: true): the lookup did not complete — unreachable host, non-2xx,
//     timeout, or a 2xx whose body is not a JSON object — named by tool, cause and base URL.
//     Never a success with null fields: a model handed one of those tells its user "no
//     exposure found", and an outage becomes an all-clear.
import { readFileSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

// The release actually running, read from the package.json that ships beside dist/. The MCP
// handshake and the User-Agent both carry it, so the API's access log can count adoption per
// version without a code change per release.
const VERSION = (() => {
  try {
    const pkg: unknown = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
    const v = (pkg as { version?: unknown } | null)?.version;
    return typeof v === "string" && v ? v : "unknown";
  } catch {
    return "unknown";
  }
})();

const BASE = (process.env.ECHELONGRAPH_API_BASE || "https://app.echelongraph.io").replace(/\/+$/, "");
const UA = `echelongraph-mcp/${VERSION} (+https://echelongraph.io/pulse/mcp)`;
const DEFAULT_TIMEOUT_MS = 15_000;
const TIMEOUT_MS = (() => {
  const n = Number(process.env.ECHELONGRAPH_API_TIMEOUT_MS);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : DEFAULT_TIMEOUT_MS;
})();
// The base as quoted in tool results. A proxy credential in the URL's userinfo is dropped.
const SHOWN_BASE = (() => {
  try {
    const u = new URL(BASE);
    if (!u.username && !u.password) return BASE;
    return `${u.protocol}//***@${u.host}${u.pathname.replace(/\/+$/, "")}`;
  } catch {
    return "the configured ECHELONGRAPH_API_BASE (not a valid URL)";
  }
})();

type Failure = {
  ok: false;
  kind: "network" | "timeout" | "http" | "not_json" | "not_object";
  path: string;
  status?: number;
  detail: string;
};
type ApiResult = { ok: true; status: number; data: object } | Failure;

// Collapse a response body to something quotable: one line, at most 160 characters.
function snippet(body: string): string {
  const s = body.replace(/\s+/g, " ").trim();
  if (!s) return "(empty body)";
  return s.length > 160 ? `${s.slice(0, 160)}…` : s;
}

// A message may echo a URL — undici's refusal of a credentialed URL quotes it whole — so
// anything shaped scheme://user:pass@host is masked before it can reach a result.
const redactCredentials = (s: string): string => s.replace(/(\w+:\/\/)[^/\s@]+@/g, "$1***@");

// The useful part of a fetch error is usually in its cause chain (ECONNREFUSED, ENOTFOUND,
// "bad port"), so walk it. Messages and codes only — never headers, never a credential.
function describeError(e: unknown): string {
  if (!(e instanceof Error)) return String(e);
  const parts = [e.message];
  let cause: unknown = e.cause;
  for (let depth = 0; cause instanceof Error && depth < 4; depth++) {
    const c = cause as Error & { code?: unknown; errors?: unknown };
    const codes = Array.isArray(c.errors)
      ? c.errors.map((x) => (x as { code?: unknown }).code).filter((x): x is string => typeof x === "string")
      : [];
    if (codes.length) parts.push(codes.join(", "));
    else if (typeof c.code === "string") parts.push(c.code);
    else if (c.message) parts.push(c.message);
    cause = c.cause;
  }
  return redactCredentials(parts.join(": "));
}

// The API's error envelope is {"error": "..."}; quote that string when a non-2xx carries it.
function apiMessage(body: string): string {
  try {
    const parsed: unknown = JSON.parse(body);
    const msg = (parsed as { error?: unknown } | null)?.error;
    if (typeof msg === "string" && msg) return msg;
  } catch {
    // not JSON — fall through to the raw snippet
  }
  return snippet(body);
}

// One GET against the API. Never throws: every way the call can fail comes back as a typed
// Failure so the tool renders it as an error result. A 2xx whose body is not a JSON object
// (an SPA shell, an edge challenge page, a literal null) is a failure too — it is not data.
async function api(path: string): Promise<ApiResult> {
  const ctrl = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    ctrl.abort();
  }, TIMEOUT_MS);
  const timeout = (): Failure => ({ ok: false, kind: "timeout", path, detail: `no response within ${TIMEOUT_MS} ms` });
  try {
    let res: Response;
    try {
      res = await fetch(`${BASE}${path}`, {
        headers: { "User-Agent": UA, Accept: "application/json" },
        signal: ctrl.signal,
      });
    } catch (e) {
      return timedOut ? timeout() : { ok: false, kind: "network", path, detail: describeError(e) };
    }
    let body: string;
    try {
      body = await res.text();
    } catch (e) {
      return timedOut ? timeout() : { ok: false, kind: "network", path, detail: `reading the body failed: ${describeError(e)}` };
    }
    if (!res.ok) return { ok: false, kind: "http", path, status: res.status, detail: apiMessage(body) };
    let data: unknown;
    try {
      data = JSON.parse(body);
    } catch {
      const ctype = res.headers.get("content-type") ?? "no content-type";
      return { ok: false, kind: "not_json", path, status: res.status, detail: `${ctype}; body starts: ${snippet(body)}` };
    }
    if (data === null || typeof data !== "object") {
      return { ok: false, kind: "not_object", path, status: res.status, detail: `body was ${snippet(body)}` };
    }
    return { ok: true, status: res.status, data };
  } finally {
    clearTimeout(timer);
  }
}

type Text = { type: "text"; text: string };
type ToolResult = { content: Text[]; isError?: boolean };
const text = (t: string): Text => ({ type: "text", text: t });

// One sentence per failure kind: where we looked, for what, and what came back.
function describeFailure(f: Failure): string {
  const where = `from ${SHOWN_BASE} for GET ${f.path}`;
  switch (f.kind) {
    case "network":
      return `EchelonGraph at ${SHOWN_BASE} could not be reached for GET ${f.path}: ${f.detail}.`;
    case "timeout":
      return `EchelonGraph at ${SHOWN_BASE} did not answer GET ${f.path} within ${TIMEOUT_MS} ms.`;
    case "http":
      return `EchelonGraph answered HTTP ${f.status} ${where} — the API said: ${f.detail}.`;
    case "not_json":
      return `EchelonGraph answered HTTP ${f.status} ${where} but the body was not JSON (${f.detail}).`;
    case "not_object":
      return `EchelonGraph answered HTTP ${f.status} ${where} but the body was not a JSON object (${f.detail}).`;
  }
}

// What a model must not conclude from a failure.
const NOT_A_FINDING =
  "The lookup did not complete, so this is not a finding: do not report it as zero, none found, absent, or unexposed. Retry later or check ECHELONGRAPH_API_BASE.";
// A 404 is the one non-2xx that carries an answer of its own — the API's not-found message,
// quoted in the sentence before it — so it is worded as "no record", not as an outage.
const NO_RECORD =
  "The API returned no record for this request; the quoted message is the API's own explanation. This says nothing about internet exposure.";
// A 400 is the API refusing the input itself, so nothing was looked up and nothing measured.
// It is tagged invalid_input, the same state a request this server refuses locally carries.
const INVALID_INPUT = "(state: invalid_input)";
const REJECTED_INPUT =
  "The API rejected the request as invalid input, so nothing was looked up: this is not a finding. Do not report it as zero, none found, or unexposed; correct the input and retry.";

const failed = (tool: string, f: Failure): ToolResult => {
  if (f.kind === "http" && f.status === 400) {
    return { content: [text(`${tool} FAILED ${INVALID_INPUT}: ${describeFailure(f)} ${REJECTED_INPUT}`)], isError: true };
  }
  return {
    content: [text(`${tool} FAILED: ${describeFailure(f)} ${f.kind === "http" && f.status === 404 ? NO_RECORD : NOT_A_FINDING}`)],
    isError: true,
  };
};

const badInput = (tool: string, why: string): ToolResult => ({
  content: [text(`${tool} FAILED ${INVALID_INPUT}: ${why}. Nothing was looked up, so this is not a finding.`)],
  isError: true,
});

// A bug in this server is still not a finding — it must never surface as an empty success.
const crashed = (tool: string, e: unknown): ToolResult => ({
  content: [text(`${tool} FAILED inside the MCP server while querying ${SHOWN_BASE}: ${describeError(e)}. ${NOT_A_FINDING}`)],
  isError: true,
});

const succeeded = (data: object, note: string): ToolResult => ({
  content: [text(JSON.stringify(data, null, 2)), text(note)],
});
const okHead = (tool: string, status?: number) =>
  `${tool} OK: EchelonGraph answered${status === undefined ? "" : ` HTTP ${status}`} from ${SHOWN_BASE}.`;

// Tolerant readers for the note: a missing or renamed field degrades the sentence, never
// the result — content[0] still carries whatever the API sent.
const field = (o: unknown, ...keys: string[]): unknown =>
  keys.reduce<unknown>((v, k) => (v !== null && typeof v === "object" ? (v as Record<string, unknown>)[k] : undefined), o);
const numAt = (o: unknown, ...keys: string[]): number | undefined => {
  const v = field(o, ...keys);
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
};
const strAt = (o: unknown, ...keys: string[]): string | undefined => {
  const v = field(o, ...keys);
  return typeof v === "string" && v ? v : undefined;
};
const lenAt = (o: unknown, ...keys: string[]): number | undefined => {
  const v = field(o, ...keys);
  return Array.isArray(v) ? v.length : undefined;
};
const boolAt = (o: unknown, ...keys: string[]): boolean | undefined => {
  const v = field(o, ...keys);
  return typeof v === "boolean" ? v : undefined;
};
// A timestamp worth repeating as prose. The API has been seen answering the Go zero time
// (0001-01-01T00:00:00Z) where it had no instant to give; that is not a time, so it is never
// presented as one.
const realInstant = (s: string | undefined): s is string => s !== undefined && Date.parse(s) > 0;

const server = new McpServer({ name: "echelongraph-cve", version: VERSION });

server.tool(
  "cve_summary",
  "Summary of EchelonGraph's CVE Pulse feed: total active CVEs and counts by severity (critical/high/medium/low/none), plus when the feed was last updated. The feed is polled from its sources on a schedule, so this is the state as of that update.",
  {},
  async () => {
    const tool = "cve_summary";
    try {
      const r = await api("/api/v1/public/cves/summary");
      if (!r.ok) return failed(tool, r);
      const head = okHead(tool, r.status);
      const total = numAt(r.data, "summary", "total");
      if (total === undefined) return succeeded(r.data, head);
      if (total === 0) {
        return succeeded(r.data, `${head} The feed reports 0 active CVEs — a measured empty result (we looked and found nothing), not a lookup failure.`);
      }
      // A stamp that is not a real instant stays in the JSON and is not repeated as prose.
      const updated = strAt(r.data, "summary", "last_updated");
      const stamp = realInstant(updated) ? ` (last updated ${updated})` : "";
      return succeeded(r.data, `${head} The feed holds ${total} active CVEs${stamp}.`);
    } catch (e) {
      return crashed(tool, e);
    }
  },
);

server.tool(
  "search_cves",
  "Search/list CVEs from EchelonGraph's CVE feed (NVD + MITRE-CNA pre-NVD + CISA-KEV + EPSS + GitHub GHSA, each polled on a schedule). Filter by severity, minimum CVSS, free text, and sort. Returns CVEs with the EchelonGraph multi-source score, severity, CVSS, EPSS, and KEV status.",
  {
    search: z.string().optional().describe("free-text search (product, vendor, or keyword, e.g. 'tomcat')"),
    severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"]).optional().describe("filter to one severity"),
    min_cvss: z.number().min(0).max(10).optional().describe("minimum CVSS score"),
    sort: z.enum(["published", "modified", "nvd", "echelongraph", "epss"]).optional().describe("sort order (default: published)"),
    limit: z.number().int().min(1).max(50).optional().describe("page size (default 20, max 50)"),
  },
  async (a) => {
    const tool = "search_cves";
    try {
      const q = new URLSearchParams();
      if (a.search) q.set("search", a.search);
      if (a.severity) q.set("severity", a.severity);
      if (a.min_cvss !== undefined) q.set("min_cvss", String(a.min_cvss));
      if (a.sort) q.set("sort", a.sort);
      q.set("limit", String(a.limit ?? 20));
      const r = await api(`/api/v1/public/cves?${q.toString()}`);
      if (!r.ok) return failed(tool, r);
      const head = okHead(tool, r.status);
      const shown = lenAt(r.data, "cves");
      const total = numAt(r.data, "total") ?? shown;
      if (total === undefined) return succeeded(r.data, head);
      if (total === 0) {
        return succeeded(r.data, `${head} The query matched 0 CVEs — a measured empty result: EchelonGraph was queried successfully and nothing matched these filters (we looked and found nothing). This is not a lookup failure.`);
      }
      return succeeded(r.data, `${head} The query matched ${total} CVEs${shown === undefined ? "" : `; ${shown} returned in this page`}.`);
    } catch (e) {
      return crashed(tool, e);
    }
  },
);

server.tool(
  "get_cve",
  "Full detail for one CVE: description, NVD CVSS v3/v4, the EchelonGraph multi-source score + confidence, EPSS, CISA-KEV status (including ransomware-campaign use), GitHub GHSA, CWE, and references. Pass a CVE ID like CVE-2023-44487.",
  { cve_id: z.string().describe("a CVE ID, e.g. CVE-2023-44487") },
  async ({ cve_id }) => {
    const tool = "get_cve";
    const id = cve_id.trim();
    if (!id) return badInput(tool, "cve_id is required");
    try {
      const r = await api(`/api/v1/public/cves/${encodeURIComponent(id)}`);
      if (!r.ok) return failed(tool, r);
      return succeeded(r.data, `${okHead(tool, r.status)} Returned the record for ${strAt(r.data, "cve_id") ?? id}.`);
    } catch (e) {
      return crashed(tool, e);
    }
  },
);

// cve_exposure. What the API's footprint means, and what it does not (#2306, #2307).
//
// The counts come from the KEV-exposure radar, which does not look at every CVE: every 12 h,
// when Shodan query credits allow (the poller skips the search below SHODAN_MIN_QUERY_BUDGET),
// it runs one Shodan query per tracked product and keeps services whose banner version maps
// to a CISA-KEV or high-EPSS CVE. So a 0 is only a measurement when the CVE is inside that
// tracked set. The unit is a service, not a machine: the radar keys each observation on
// ip:port (Shodan returns one banner per port), and exposed_hosts counts distinct ip:port.
// The API says which with `tracked`; the note reads it and, when the field is absent (an older
// API, or a CVE the radar cannot decide on), makes no claim either way about the zero.
//
// last_seen is not a re-sighting of the vulnerable banner: between searches the radar refreshes
// it when Shodan InternetDB still lists the service's PORT, without re-reading the version, so
// a patched service can stay counted while its port stays open. Every text says "last seen
// listening on its port", never "re-seen" or "most recently seen".
const CVE_ID = /^CVE-\d{4}-\d{4,}$/i;
// Quoted when the API does not send its own `method` string.
const EXPOSURE_METHOD =
  "Shodan banner match on the radar's tracked products; up to 100 ip:port services per product query; searched every 12 h when Shodan query credits allow";
const SHODAN_ATTRIBUTION = "Exposure counts are derived from Shodan data.";
// Shodan's terms (https://static.shodan.io/legal/terms.html, read 2026-09-27) ask for two
// things: "You must attribute such usage to Shodan", and materials "referencing, including or
// otherwise based on Shodan information or materials, must clearly indicate Shodan's ownership
// and copyright in the applicable Shodan materials" (#2306). The attribution above does the
// first; this sentence, placed beside it wherever Shodan data is named, does the second.
const SHODAN_OWNERSHIP = "Shodan data is owned by Shodan, which holds its copyright (© Shodan).";

function exposureNote(head: string, id: string, d: object): string {
  const cve = strAt(d, "cve_id") ?? id;
  const hosts = numAt(d, "exposed_hosts");
  const tracked = boolAt(d, "tracked");
  // The API's own method sentence may end in a full stop; the note supplies one.
  const how = `Method: ${(strAt(d, "method") ?? EXPOSURE_METHOD).replace(/[.\s]+$/, "")}. ${SHODAN_ATTRIBUTION} ${SHODAN_OWNERSHIP}`;
  // Before kev_catalog_listed existed, kev_listed was bool_or over the radar's observations:
  // false for every CVE the radar has no host for, whatever the CISA-KEV catalog says.
  // kev_catalog_listed is cves.kev_listed, the flag the KEV fetcher sets on EchelonGraph's CVE
  // record. The fetcher only UPDATEs rows that already exist, and the API answers false when
  // there is no row, so false cannot be told apart from "no record": it is worded as what
  // EchelonGraph's data says, never as a fact about the CISA catalog.
  const catalog = boolAt(d, "kev_catalog_listed");
  const kev =
    catalog === undefined
      ? "Its kev_listed field reflects the radar's own observations, not the CISA-KEV catalog; use get_cve for catalog status."
      : catalog
        ? `EchelonGraph's CVE record marks ${cve} as CISA-KEV-listed.`
        : `EchelonGraph's CVE data does not mark ${cve} as CISA-KEV-listed (kev_catalog_listed is false, which it also is when EchelonGraph holds no record of ${cve}); get_cve shows the record.`;
  if (hosts === undefined) {
    return `${head} The answer carries no exposed_hosts count, so it says nothing about exposure to ${cve}. ${how}`;
  }
  if (tracked === false) {
    const why =
      hosts === 0
        ? "outside the radar's tracked set; 0 is not a measurement, and it says nothing about whether any host is exposed to it."
        : `outside the radar's tracked set, so the radar is not looking for it; the ${hosts} service(s) (distinct ip:port) on record are left from earlier scans and are not a current measurement.`;
    return `${head} (state: not_assessed) NOT ASSESSED: ${cve} is ${why} ${kev} ${how}`;
  }
  if (hosts === 0 && tracked === true) {
    // The backend answers tracked:true only when it holds rows (exposed_hosts > 0), so this
    // branch does not fire today; it is worded for the day it does.
    return `${head} (state: measured_zero) The radar has 0 internet-facing services (distinct ip:port) on record whose banner version maps to ${cve}: a measured zero in the radar's sample. ${cve} is in the tracked set, and the radar looked and found nothing. This is not a lookup failure. It is a zero in a sample, not an internet-wide zero: the radar reads at most the first 100 Shodan results per tracked-product query, so a vulnerable service outside those results is not counted. ${kev} ${how}`;
  }
  if (hosts === 0) {
    return `${head} (state: tracking_unknown) EchelonGraph reports 0 exposed services (distinct ip:port) on record for ${cve}. The API does not say whether ${cve} is in the radar's tracked set: it is an API older than that field, or the radar cannot decide for this CVE (for example a CISA-KEV or high-EPSS CVE in a tracked product that it has no service on record for). The radar only looks for a tracked set of CISA-KEV and high-EPSS CVEs in specific products, so this 0 is not evidence either way: it neither shows that nothing is exposed nor that ${cve} went unassessed. This is not a lookup failure. ${kev} ${how}`;
  }
  const countries = numAt(d, "countries");
  const last = strAt(d, "last_seen");
  const seen = realInstant(last)
    ? ` Their latest last_seen is ${last}: when one of them was last seen listening on its port, not when its vulnerable version was last confirmed.`
    : "";
  return `${head} (state: exposed) The radar has ${hosts} internet-facing services (distinct ip:port, the exposed_hosts field) on record whose banner version maps to ${cve}${countries === undefined ? "" : ` across ${countries} countries`}.${seen} ${kev} ${how}`;
}

server.tool(
  "cve_exposure",
  `Internet-exposure footprint for one CVE from EchelonGraph's KEV-exposure radar: how many internet-facing services (distinct ip:port, returned as exposed_hosts; a machine answering on two ports counts twice) the radar has on record running a version its CVE matcher maps to this CVE, with a country/product breakdown and a ransomware flag. Aggregate and host-redacted; free and keyless. Method: exposure counts are derived from Shodan data. ${SHODAN_OWNERSHIP} Every 12 h, when Shodan query credits allow, the radar runs one Shodan query per tracked product, reads up to 100 ip:port services per query, and keeps a service when its banner version matches a CISA-KEV or high-EPSS CVE; a service not seen on its port for 21 days is dropped. last_seen is when a service was last seen listening on its port, not when its vulnerable version was last confirmed: between searches a re-check that finds the port still listed refreshes it without re-reading the banner, so a patched service can stay counted while its port stays open. A count is therefore a banner-version inference over a sample, not an exploit test and not an internet-wide census. The radar only looks for its tracked set of CVEs: for a CVE outside that set the result says NOT ASSESSED, and its 0 is not a measurement.`,
  { cve_id: z.string().describe("a CVE ID, e.g. CVE-2023-44487") },
  async ({ cve_id }) => {
    const tool = "cve_exposure";
    const id = cve_id.trim();
    if (!id) return badInput(tool, "cve_id is required");
    // Refused here rather than sent: an API older than the id check answers a malformed id
    // with a 200 and zeros, which would read as an answer about a CVE that does not exist.
    if (!CVE_ID.test(id)) {
      return badInput(tool, `cve_id ${JSON.stringify(id.slice(0, 32))} is not a CVE id (expected the form CVE-2023-44487)`);
    }
    // The canonical form, which is how the API stores and answers it.
    const cve = id.toUpperCase();
    try {
      const r = await api(`/api/v1/public/kev-exposure/cve/${encodeURIComponent(cve)}`);
      if (!r.ok) return failed(tool, r);
      return succeeded(r.data, exposureNote(okHead(tool, r.status), cve, r.data));
    } catch (e) {
      return crashed(tool, e);
    }
  },
);

// Every quadrant that finds its services through Shodan, attributed. The exposed-database
// radar searches Shodan dorks and falls back to LeakIX when the Shodan query budget is low
// (core-backend/internal/exposeddb/poller.go).
const RADAR_SOURCES =
  "KEV-exposure, exposed-database and shadow-AI discovery use Shodan data (shadow AI also uses Certificate Transparency logs; exposed databases fall back to LeakIX when Shodan query credits run low).";

const RADARS = [
  ["kev_exposure", "/api/v1/public/kev-exposure/stats"],
  ["exposed_databases", "/api/v1/public/exposed-databases/stats"],
  ["leaked_credentials", "/api/v1/public/leaked-credentials/stats"],
  ["shadow_ai", "/api/v1/public/shadow-ai-radar/stats"],
] as const;

// The shadow-AI stats answer, regrouped by what each number counts (#2307).
//
// GET /api/v1/public/shadow-ai-radar/stats (core-backend shadowctlog store.go Stats) mixes
// three kinds of number, and only one of them counts exposed services:
//   - confirmed exposed: rows whose liveness is active or rechecking, the published exposure
//     set (visible_by_category, last_24h_visible_count);
//   - observed: every Certificate Transparency or Shodan observation on record, whatever its
//     verification state (total, by_category, last_24h_count, trend_30d, and the top_products,
//     top_countries and top_issuers rankings);
//   - authentication state: rows where a probe observed an authentication gate (auth_confirmed,
//     liveness authenticated) or could not tell (auth_undetermined, liveness inconclusive).
// On 2026-09-27 total was 36,222 against 2,000 confirmed exposed, and top_products ranked
// LiteLLM at 6,813 observations while 1,395 LLM-PROXY services were confirmed exposed. Relayed
// under the API's names, every one of those reads as an exposure count. So the tool relays them
// grouped as confirmed_exposed, observed and authentication, with the note labelling each, and
// relays nothing it cannot label: a stats field this version does not know, a field other than
// a ranked row's label and count, and the poller block's instance fields are left out, the
// first named in the note.
//
// The `poller` block's running and last_run_at describe the radar's fleet, not the instance
// that answered (core-backend shadowctlog Poller.Status): last_run_at is when the fleet's
// leader last COMPLETED a crt.sh (Certificate Transparency) cycle, and running is true only
// when that was within pollerSilentAfter, 30 minutes, of the answer. The API sends both or
// neither, and omits both when it cannot tell; it never sends the Go zero time. An API older
// than that answered from the serving instance's own memory, so a follower sent running:false
// and last_run_at 0001-01-01T00:00:00Z, which reads as "the radar is down and has never run".
// So the note reads three cases: running with a real completion time, stopped since a real
// completion time, and unknown. Only the first two are relayed, as those two fields alone; an
// unknown block (no real completion time and running verdict) is dropped, so no running:false
// or zero time reaches the model as freshness. The block's other fields (interval_seconds,
// shodan_enabled, and a polling instance's last_new_inserts, skipped_as_follower,
// consecutive_fails and shodan_last_new) describe the instance that answered, not the fleet,
// and none of them counts AI services.
const SHADOW_AI_SILENT_AFTER = "30 minutes";
// The stats fields readShadowAI knows how to label. Any other is left out and named.
const SHADOW_AI_STATS = new Set([
  "total",
  "by_category",
  "visible_by_category",
  "last_observation",
  "last_24h_count",
  "last_24h_visible_count",
  "auth_confirmed",
  "auth_undetermined",
  "top_products",
  "top_countries",
  "top_issuers",
  "trend_30d",
]);
// The observed rankings and the daily series: API field, and the row field that names each row.
const SHADOW_AI_ROWS = [
  ["trend_30d", "date"],
  ["top_products", "product"],
  ["top_countries", "country"],
  ["top_issuers", "issuer"],
] as const;

const isCount = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);
const isPlainObject = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

// A category → count map, or nothing unless every value is a count: a partial map is an
// undercount that reads as a measurement (store.go categoryCounts).
function countMap(v: unknown): Record<string, number> | undefined {
  if (!isPlainObject(v)) return undefined;
  const entries = Object.entries(v);
  return entries.every(([, n]) => isCount(n)) ? (Object.fromEntries(entries) as Record<string, number>) : undefined;
}

// What a relayed row field must be. "number" is a finite number: a count or a score.
type Kind = "string" | "number" | "boolean";
type RowSpec = { required: Readonly<Record<string, Kind>>; optional?: Readonly<Record<string, Kind>> };
const isKind = (v: unknown, k: Kind): boolean => (k === "number" ? isCount(v) : typeof v === k);
type Rows = { rows?: Record<string, unknown>[]; extra: string[] };

// A ranking, a series or a list, each row cut down to the fields its spec names, so a field the
// backend adds to a row later is left out rather than relayed unlabelled; extra lists those
// fields so the note can name them. All rows or none: a row that is not an object, lacks a
// required field, or carries a known field of the wrong type leaves the whole list out, since
// a partial list reads as a complete one. An optional field may be absent (Go's omitempty).
function readRows(v: unknown, spec: RowSpec): Rows {
  if (!Array.isArray(v)) return { extra: [] };
  const optional = spec.optional ?? {};
  const rows: Record<string, unknown>[] = [];
  const extra = new Set<string>();
  for (const r of v) {
    if (!isPlainObject(r)) return { extra: [] };
    const row: Record<string, unknown> = {};
    for (const [k, kind] of Object.entries(spec.required)) {
      if (!isKind(r[k], kind)) return { extra: [] };
      row[k] = r[k];
    }
    for (const [k, kind] of Object.entries(optional)) {
      if (r[k] === undefined) continue;
      if (!isKind(r[k], kind)) return { extra: [] };
      row[k] = r[k];
    }
    // An own-property test: `in` would also find toString and constructor on the prototype.
    for (const k of Object.keys(r)) if (!Object.prototype.hasOwnProperty.call(spec.required, k) && !Object.prototype.hasOwnProperty.call(optional, k)) extra.add(k);
    rows.push(row);
  }
  return { rows, extra: [...extra] };
}

// A ranking or a daily series whose rows are a label and a count (the shadow-AI shape).
const countRows = (v: unknown, label: string): Rows => readRows(v, { required: { [label]: "string", count: "number" } });

// The note's sentences about what a radar's answer carried that the tool left out.
function leftOut(radar: string, unknown: string[], unusable: string[]): string[] {
  const out: string[] = [];
  if (unknown.length) out.push(`Left out of ${radar} because this version of the tool cannot label them: ${unknown.join(", ")}.`);
  if (unusable.length) out.push(`Left out of ${radar} because they were not in the expected shape: ${unusable.join(", ")}.`);
  return out;
}

// A radar stats answer with a flat shape: top-level counts, top-level lists of rows, and
// top-level timestamps. readRadar relays exactly those fields, in this order, and nothing else.
type RadarSpec = {
  counts: readonly string[];
  rows: Readonly<Record<string, RowSpec>>;
  instants: readonly string[];
};
type RadarRead = { data: Record<string, unknown>; unknown: string[]; unusable: string[] };

function readRadar(body: unknown, spec: RadarSpec): RadarRead {
  const src = isPlainObject(body) ? body : {};
  const data: Record<string, unknown> = {};
  const unknown: string[] = [];
  const unusable: string[] = [];
  const present = (k: string) => src[k] !== undefined && src[k] !== null;
  for (const k of spec.counts) {
    if (isCount(src[k])) data[k] = src[k];
    else if (present(k)) unusable.push(k);
  }
  for (const [k, rowSpec] of Object.entries(spec.rows)) {
    const r = readRows(src[k], rowSpec);
    if (r.rows) {
      data[k] = r.rows;
      unknown.push(...r.extra.map((x) => `${k}[].${x}`));
    } else if (present(k)) unusable.push(k);
  }
  // A timestamp that is not a real instant (the Go zero time) is not relayed as one.
  for (const k of spec.instants) {
    const s = strAt(src, k);
    if (realInstant(s)) data[k] = s;
    else if (present(k) && typeof src[k] !== "string") unusable.push(k);
  }
  const known = new Set([...spec.counts, ...Object.keys(spec.rows), ...spec.instants]);
  unknown.unshift(...Object.keys(src).filter((k) => !known.has(k)));
  return { data, unknown, unusable };
}

// ── last_run_at: when a radar last COMPLETED a check (#2335) ──
//
// Since #2335 the kev_exposure, exposed_databases and leaked_credentials stats answers carry
// last_run_at (core-backend pollerlock/published.go): the radar's completion row in
// poller_run_state, recorded for the radar as a whole rather than for the instance that
// answered, UTC, truncated to the second. Each poller writes that row at the END of a cycle,
// and only when the cycle's reads succeeded (poller.go checkCompleted / recordCheck), so a
// cycle that read nothing never moves it. What counts as a completed check differs per radar,
// and LAST_CHECK words each. The API omits the field when no completed check is on record,
// when its read failed, or when its last good read is more than two minutes old; it never
// sends the Go zero time.
//
// It is a timestamp, not a count, and not the time of the numbers beside it: those count
// everything still on record, not only what the last check found. Nor is it generated_at,
// which is only when the API's 60 s stats cache recomputed the totals. An absent stamp (or one
// that is not a real instant) means the API could not tell, so the note says nothing about it:
// no "never", no zero.
const LAST_CHECK = {
  kev_exposure:
    "its Shodan search answered at least one query (others may have failed) and its list of services due for a re-check was read; a cycle that skipped the search for want of Shodan query credits, or whose reads failed, does not move it",
  exposed_databases:
    "its Shodan search, or the LeakIX fallback, answered at least one query (others may have failed), its list of services due for a re-check was read, and the scan opt-out register could be consulted; a cycle that searched nothing, or whose reads failed, does not move it",
  leaked_credentials:
    "it read the public GitHub event stream (fetches of some of the commits it lists may have failed); a cycle whose read of that stream failed does not move it",
} as const;

// The note's sentences for one radar's relayed last_run_at, each naming the field so that any
// one of them quoted alone still says what it is; none when the stamp was not relayed.
function lastCheck(radar: keyof typeof LAST_CHECK, data: Record<string, unknown>): string[] {
  const at = data.last_run_at;
  if (typeof at !== "string") return [];
  return [
    `${radar} last completed check: ${at} (${radar}.last_run_at, a timestamp, not a count).`,
    `${radar}.last_run_at is when the radar last finished a cycle whose reads succeeded: ${LAST_CHECK[radar]}.`,
    `${radar}.last_run_at is not the time of every record the ${radar} numbers count, which cover everything still on record, not only what that check found; nor is it ${radar}.generated_at, when the API computed those numbers.`,
  ];
}

// The first row of a relayed ranking, for the note: "(first: http_server, 9120 services)".
function firstOf(rows: unknown, label: string, count: string, unit: string): string {
  const top = Array.isArray(rows) ? (rows[0] as Record<string, unknown> | undefined) : undefined;
  return top === undefined ? "" : ` (first: ${String(top[label])}, ${String(top[count])} ${unit})`;
}
// "a", "a and b", "a, b and c".
const listed = (xs: string[]): string => (xs.length < 2 ? xs.join("") : `${xs.slice(0, -1).join(", ")} and ${xs[xs.length - 1]}`);
const numIn = (d: Record<string, unknown>, k: string): number | undefined => (isCount(d[k]) ? d[k] : undefined);
const be = (n: number): string => (n === 1 ? "is" : "are");

// ── kev_exposure: GET /api/v1/public/kev-exposure/stats (#2313 items 6 and 7) ──
//
// core-backend/internal/kevexposure store.go Stats. Every count is over the observation
// table, one row per (ip:port, CVE) (Upsert keys it obsID(host, cve), the host being
// "ip:port" from poller.go), filtered to rows whose kev_listed flag the poller copied in at
// match time:
//   distinct_hosts    COUNT(DISTINCT host): distinct ip:port services, not machines
//   kev_cves_exposed  COUNT(DISTINCT cve_id): CVEs with at least one such service
//   correlations      COUNT(*): service×CVE pairs, so a service with three CVEs counts 3 times
//   ransomware_cves   COUNT(DISTINCT cve_id) FILTER (WHERE ransomware)
//   ransomware_hosts  COUNT(DISTINCT host) FILTER (WHERE ransomware): services, not machines
//   top_products / top_cves / top_countries   COUNT(DISTINCT host) per group, LIMIT 12/12/10;
//                     a top_cves row's cvss_v3_score and epss_score are MAX() over its rows
//   trend             COUNT(*) per date_trunc('week', first_seen) over 12 weeks: pairs still on
//                     record, by the week first recorded (a pruned pair is gone, so earlier
//                     weeks read low)
//   newest_kev        the 15 cves rows with kev_listed and the latest kev_added_date, LEFT JOINed
//                     to COUNT(DISTINCT host) of their KEV-flagged rows, COALESCE(e.h, 0).
//   last_run_at       the radar's last completed check, KeyKEVExposureCheckCompleted (#2335; see
//                     LAST_CHECK). Its own row: KeyKEVExposure is the Shodan-credit watermark.
// So newest_kev[].exposed_hosts is 0 for every CVE the radar holds no row for, whether or not
// it could ever hold one: the join default, not a measurement. The per-CVE endpoint decides
// that with `tracked` (store.go trackedVerdict), which is true ONLY when rows exist
// (exposedHosts > 0) and otherwise false or absent: the backend never reports a measured zero.
// So a 0 here is never relayed: its row says exposure_state not_assessed and carries no
// count. If the stats answer ever sends a row's `tracked` (the contract proposed on #2313), it
// is read the way cve_exposure reads it: false is not assessed whatever the count, and true
// with 0 is a measured zero in the radar's sample.
const KEV_SPEC: RadarSpec = {
  counts: ["distinct_hosts", "ransomware_hosts", "kev_cves_exposed", "ransomware_cves", "correlations"],
  rows: {
    top_products: { required: { product: "string", hosts: "number" } },
    top_countries: { required: { country: "string", hosts: "number" } },
    top_cves: {
      required: { cve_id: "string", hosts: "number" },
      optional: { severity: "string", cvss_v3_score: "number", epss_score: "number", ransomware: "boolean" },
    },
    trend: { required: { week: "string", new_exposures: "number" } },
    newest_kev: {
      required: { cve_id: "string", exposed_hosts: "number" },
      optional: {
        added_date: "string",
        vuln_name: "string",
        severity: "string",
        cvss_v3_score: "number",
        epss_score: "number",
        ransomware: "boolean",
        tracked: "boolean",
      },
    },
  },
  instants: ["generated_at", "last_run_at"],
};

type ExposureState = "exposed" | "measured_zero" | "not_assessed";

// One newest_kev row as relayed: the CVE record's fields, its exposure_state, and a count only
// when the count is a measurement. `tracked` is read, not relayed: exposure_state says it.
function newestKEVRow(r: Record<string, unknown>): { row: Record<string, unknown>; state: ExposureState; outside: boolean } {
  const hosts = r.exposed_hosts as number;
  const tracked = r.tracked as boolean | undefined;
  const state: ExposureState = tracked === false ? "not_assessed" : hosts > 0 ? "exposed" : tracked === true ? "measured_zero" : "not_assessed";
  const row: Record<string, unknown> = {};
  for (const k of ["cve_id", "added_date", "vuln_name", "severity", "cvss_v3_score", "epss_score", "ransomware"]) {
    if (r[k] !== undefined) row[k] = r[k];
  }
  row.exposure_state = state;
  if (state !== "not_assessed") row.exposed_hosts = hosts;
  return { row, state, outside: tracked === false };
}

function readKEVExposure(body: unknown): { data: object; sentences: string[] } {
  const { data, unknown, unusable } = readRadar(body, KEV_SPEC);
  const sentences: string[] = [];
  const n = (k: string) => numIn(data, k);

  const totals = [
    n("distinct_hosts") !== undefined &&
      `kev_exposure.distinct_hosts (${n("distinct_hosts")}) counts distinct ip:port services, not machines (a machine answering on two ports counts twice), with at least one CISA-KEV-listed CVE on record`,
    n("ransomware_hosts") !== undefined &&
      `kev_exposure.ransomware_hosts (${n("ransomware_hosts")}) counts the services among them with at least one ransomware-linked KEV CVE (one whose KEV entry notes known use in ransomware campaigns)`,
    n("kev_cves_exposed") !== undefined &&
      `kev_exposure.kev_cves_exposed (${n("kev_cves_exposed")}) counts distinct CISA-KEV-listed CVEs with at least one service on record`,
    n("ransomware_cves") !== undefined && `kev_exposure.ransomware_cves (${n("ransomware_cves")}) counts the ransomware-linked CVEs among them`,
    n("correlations") !== undefined &&
      `kev_exposure.correlations (${n("correlations")}) counts service×CVE pairs, not services: a service with three KEV CVEs counts three times`,
  ].filter((p): p is string => typeof p === "string");
  if (totals.length) sentences.push(`KEV exposure: ${totals.join("; ")}.`);

  const rankings = [
    data.top_products !== undefined && `kev_exposure.top_products ranks up to 12 products${firstOf(data.top_products, "product", "hosts", "services")}`,
    data.top_countries !== undefined && `kev_exposure.top_countries ranks up to 10 countries${firstOf(data.top_countries, "country", "hosts", "services")}`,
    data.top_cves !== undefined && `kev_exposure.top_cves ranks up to 12 CVEs${firstOf(data.top_cves, "cve_id", "hosts", "services")}`,
  ].filter((p): p is string => typeof p === "string");
  if (rankings.length) sentences.push(`${listed(rankings)}, each by distinct ip:port services with a CISA-KEV-listed CVE on record.`);
  if (data.top_cves !== undefined) {
    sentences.push(
      "kev_exposure.top_cves[].cvss_v3_score and kev_exposure.top_cves[].epss_score are the highest CVSS v3 base score and EPSS probability (0 to 1) recorded on that CVE's observations: scores, not counts.",
    );
  }
  if (data.trend !== undefined) {
    sentences.push(
      "kev_exposure.trend counts service×CVE pairs, not services, by the week (starting Monday) in which each pair was first recorded, over the last 12 weeks; only pairs still on record are counted, so earlier weeks read low.",
    );
  }

  // newest_kev: a 0 is the join's default, never a measurement (see the block comment above).
  if (Array.isArray(data.newest_kev)) {
    const read = (data.newest_kev as Record<string, unknown>[]).map(newestKEVRow);
    data.newest_kev = read.map((x) => x.row);
    const ids = (pred: (x: (typeof read)[number]) => boolean) => read.filter(pred).map((x) => String(x.row.cve_id));
    const exposed = read.filter((x) => x.state === "exposed");
    const zero = ids((x) => x.state === "measured_zero");
    const outside = ids((x) => x.state === "not_assessed" && x.outside);
    const unsaid = ids((x) => x.state === "not_assessed" && !x.outside);
    sentences.push(
      read.length
        ? `kev_exposure.newest_kev lists the ${read.length} CVEs that EchelonGraph's CVE records most recently mark as CISA-KEV-listed (by added_date), each with an exposure_state.`
        : "kev_exposure.newest_kev is empty: EchelonGraph's CVE records returned no CISA-KEV-listed CVE with a date added.",
    );
    if (exposed.length) {
      sentences.push(
        `${exposed.length} of them ${be(exposed.length)} exposed (exposure_state exposed): kev_exposure.newest_kev[].exposed_hosts counts distinct ip:port services on record with that CVE (${exposed.map((x) => `${String(x.row.cve_id)}: ${String(x.row.exposed_hosts)}`).join(", ")}).`,
      );
    }
    if (zero.length) {
      sentences.push(
        `${zero.length} ${be(zero.length)} a measured zero in the radar's sample (exposure_state measured_zero, exposed_hosts 0): the API says the radar tracks them and holds no service for them, though it reads at most the first 100 Shodan results per tracked-product query, so this is not an internet-wide zero: ${zero.join(", ")}.`,
      );
    }
    if (outside.length) {
      sentences.push(
        `${outside.length} ${be(outside.length)} NOT ASSESSED (exposure_state not_assessed) because the API says they are outside the radar's tracked set, so no count is relayed for them: ${outside.join(", ")}.`,
      );
    }
    if (unsaid.length) {
      sentences.push(
        `${unsaid.length} ${be(unsaid.length)} NOT ASSESSED (exposure_state not_assessed): ${unsaid.join(", ")}. The API answers 0 for each, and that 0 is not a measurement: it is what the stats answer gives any CVE the radar holds no service for, whether or not the radar looks for that CVE at all, so no count is relayed for them. cve_exposure says per CVE whether it is in the radar's tracked set.`,
      );
    }
    sentences.push(
      "kev_exposure.newest_kev[].cvss_v3_score and kev_exposure.newest_kev[].epss_score are the CVE record's CVSS v3 base score and EPSS probability (0 to 1), absent when the record has none: scores, not counts.",
    );
  }
  sentences.push(...lastCheck("kev_exposure", data));
  sentences.push(...leftOut("kev_exposure", unknown, unusable));
  return { data, sentences };
}

// ── exposed_databases: GET /api/v1/public/exposed-databases/stats (#2313 item 7) ──
//
// core-backend/internal/exposeddb store.go Stats, over one row per (ip:port, engine)
// (obsID(host, engine); the host is "ip:port", poller.go obsFrom). A row is stored only after
// EchelonGraph's own check confirmed the service answering without authentication.
//   distinct_hosts  COUNT(DISTINCT host): ip:port services, not machines
//   engines         COUNT(DISTINCT engine): engine types (mongodb, redis, grafana, ...)
//   pii_likely / pci_likely   COUNT(DISTINCT host) whose data_class names pii / pci AND whose
//                   schema terms pass the high-confidence gate (2+ distinct indicators, or one
//                   tier-1 term), mirroring classify.go dataConfidence. The classifier reads
//                   NAMES only (index / database / table / field names in the banner and the
//                   check's response, classify.go), never a record, and is precision-first:
//                   a service whose names miss the gate is not counted, whatever it holds.
//                   So these are a schema gate, not a census, and the rest are not "no PII".
//   top_engines / top_countries   COUNT(DISTINCT host) per group, LIMIT 15 / 10.
//   last_run_at     the radar's last completed check, KeyExposedDBCheckCompleted (#2335; see
//                   LAST_CHECK). Its own row: KeyExposedDB is claimed at the START of a cycle.
const EXPOSED_DB_SPEC: RadarSpec = {
  counts: ["distinct_hosts", "engines", "pii_likely", "pci_likely"],
  rows: {
    top_engines: { required: { engine: "string", hosts: "number" } },
    top_countries: { required: { country: "string", hosts: "number" } },
  },
  instants: ["generated_at", "last_run_at"],
};

function readExposedDatabases(body: unknown): { data: object; sentences: string[] } {
  const { data, unknown, unusable } = readRadar(body, EXPOSED_DB_SPEC);
  const sentences: string[] = [];
  const n = (k: string) => numIn(data, k);
  const totals = [
    n("distinct_hosts") !== undefined &&
      `exposed_databases.distinct_hosts (${n("distinct_hosts")}) counts distinct ip:port services, not machines (a machine answering on two ports counts twice), that EchelonGraph's check confirmed answering without authentication, data stores and observability UIs alike`,
    n("engines") !== undefined && `exposed_databases.engines (${n("engines")}) counts the distinct engine types among them`,
  ].filter((p): p is string => typeof p === "string");
  if (totals.length) sentences.push(`Exposed data stores: ${totals.join("; ")}.`);
  const rankings = [
    data.top_engines !== undefined && `exposed_databases.top_engines ranks up to 15 engines${firstOf(data.top_engines, "engine", "hosts", "services")}`,
    data.top_countries !== undefined && `exposed_databases.top_countries ranks up to 10 countries${firstOf(data.top_countries, "country", "hosts", "services")}`,
  ].filter((p): p is string => typeof p === "string");
  if (rankings.length) sentences.push(`${listed(rankings)}, each by those services.`);
  const gated = [
    n("pii_likely") !== undefined && `exposed_databases.pii_likely (${n("pii_likely")}) counts services whose schema names pass a high-confidence gate for personal data`,
    n("pci_likely") !== undefined && `exposed_databases.pci_likely (${n("pci_likely")}) counts services whose schema names pass a high-confidence gate for payment-card data`,
  ].filter((p): p is string => typeof p === "string");
  if (gated.length) {
    sentences.push(
      `${gated.join("; ")}. The names are index, database, table or field names in the Shodan or LeakIX banner or in the check's response, never record values, and the gate passes one unambiguous term (such as ssn or cardholder) or two distinct indicators. It is precision-first: a service whose names do not pass it is not counted, whatever it holds, so the other services are not shown to hold no personal or card data.`,
    );
  }
  sentences.push(...lastCheck("exposed_databases", data));
  sentences.push(...leftOut("exposed_databases", unknown, unusable));
  return { data, sentences };
}

// ── leaked_credentials: GET /api/v1/public/leaked-credentials/stats (#2313 item 7) ──
//
// core-backend/internal/leakedcreds store.go Stats, over one row per (repository, secret):
// obsID(repo, fingerprint), "one row per leaked secret per repo".
//   total             COUNT(*): (repository, secret) pairs, so one secret in three
//                     repositories counts three times; not distinct secrets
//   distinct_secrets  COUNT(DISTINCT fingerprint);  distinct_repos  COUNT(DISTINCT repo)
//   top_providers / top_types   COUNT(*) per group, LIMIT 15: pairs again
// None is validated: detect.go says "verified" means STRUCTURALLY verified (a checksum or format
// decode), never "confirmed live", and the radar never uses a credential it finds.
//   last_run_at       the radar's last completed check, its own KeyLeakedCreds row, written at
//                     the END of a cycle that read the event stream (#2335; see LAST_CHECK).
const LEAKED_CREDS_SPEC: RadarSpec = {
  counts: ["total", "distinct_secrets", "distinct_repos"],
  rows: {
    top_providers: { required: { provider: "string", count: "number" } },
    top_types: { required: { secret_type: "string", count: "number" } },
  },
  instants: ["generated_at", "last_run_at"],
};

function readLeakedCredentials(body: unknown): { data: object; sentences: string[] } {
  const { data, unknown, unusable } = readRadar(body, LEAKED_CREDS_SPEC);
  const sentences: string[] = [];
  const n = (k: string) => numIn(data, k);
  const totals = [
    n("total") !== undefined &&
      `leaked_credentials.total (${n("total")}) counts (repository, secret) pairs, not distinct secrets: a secret committed to three repositories counts three times`,
    n("distinct_secrets") !== undefined && `leaked_credentials.distinct_secrets (${n("distinct_secrets")}) counts each secret once`,
    n("distinct_repos") !== undefined && `leaked_credentials.distinct_repos (${n("distinct_repos")}) counts public GitHub repositories`,
  ].filter((p): p is string => typeof p === "string");
  if (totals.length) sentences.push(`Leaked credentials: ${totals.join("; ")}.`);
  const rankings = [
    data.top_providers !== undefined && `leaked_credentials.top_providers ranks up to 15 providers${firstOf(data.top_providers, "provider", "count", "pairs")}`,
    data.top_types !== undefined && `leaked_credentials.top_types ranks up to 15 secret types${firstOf(data.top_types, "secret_type", "count", "pairs")}`,
  ].filter((p): p is string => typeof p === "string");
  if (rankings.length) sentences.push(`${listed(rankings)}, each by the same (repository, secret) pairs.`);
  if (totals.length || rankings.length) {
    sentences.push(
      "None of these is validated: each is a credential-shaped string in a public commit that passed EchelonGraph's filters, at most structurally checked (a checksum or format decode) and never tested against its provider, so none of them is a count of working credentials.",
    );
  }
  sentences.push(...lastCheck("leaked_credentials", data));
  sentences.push(...leftOut("leaked_credentials", unknown, unusable));
  return { data, sentences };
}

function readShadowAI(sa: object): { data: object; sentences: string[] } {
  const sentences: string[] = [];
  const stats = field(sa, "stats");
  const used = new Set<string>();
  const take = <T>(key: string, v: T | undefined): T | undefined => {
    if (v !== undefined) used.add(key);
    return v;
  };

  // Confirmed exposed: liveness IN ('active','rechecking') (store.go Stats, visible_by_category
  // and last_24h_visible_count).
  const confirmed: Record<string, unknown> = {};
  const visible = take("visible_by_category", countMap(field(stats, "visible_by_category")));
  if (visible) {
    confirmed.total = Object.values(visible).reduce((a, b) => a + b, 0);
    confirmed.by_category = visible;
  }
  const last24Visible = take("last_24h_visible_count", numAt(stats, "last_24h_visible_count"));
  if (last24Visible !== undefined) confirmed.last_24h = last24Visible;

  // Observed: every row of shadow_ct_observations, whatever its liveness.
  const observed: Record<string, unknown> = {};
  const total = take("total", numAt(stats, "total"));
  if (total !== undefined) observed.total = total;
  const byCategory = take("by_category", countMap(field(stats, "by_category")));
  if (byCategory) observed.by_category = byCategory;
  const last24 = take("last_24h_count", numAt(stats, "last_24h_count"));
  if (last24 !== undefined) observed.last_24h = last24;
  const rows: Partial<Record<(typeof SHADOW_AI_ROWS)[number][0], Record<string, unknown>[]>> = {};
  const rowExtras: string[] = [];
  for (const [key, label] of SHADOW_AI_ROWS) {
    const r = countRows(field(stats, key), label);
    if (take(key, r.rows)) {
      observed[key] = rows[key] = r.rows;
      rowExtras.push(...r.extra.map((x) => `stats.${key}[].${x}`));
    }
  }
  // A timestamp, not a count; one that is not a real instant is dropped (see realInstant).
  const lastObservation = take("last_observation", strAt(stats, "last_observation"));
  if (realInstant(lastObservation)) observed.last_observation = lastObservation;

  // Authentication state: liveness 'authenticated' and 'inconclusive'.
  const authentication: Record<string, unknown> = {};
  const authSeen = take("auth_confirmed", numAt(stats, "auth_confirmed"));
  if (authSeen !== undefined) authentication.observed = authSeen;
  const authUnknown = take("auth_undetermined", numAt(stats, "auth_undetermined"));
  if (authUnknown !== undefined) authentication.not_determined = authUnknown;

  sentences.push(
    confirmed.total === undefined
      ? `Shadow AI: the answer carries no usable stats.visible_by_category, so it does not say how many services are confirmed exposed${last24Visible === undefined ? "" : `; confirmed_exposed.last_24h (${last24Visible}) counts confirmed-exposed services first recorded in the last 24 h`}.`
      : `Shadow AI confirmed exposed: ${confirmed.total} (confirmed_exposed.total, the sum of confirmed_exposed.by_category: services EchelonGraph's probes found answering without an authentication gate, with liveness active or, during a re-check, rechecking)${last24Visible === undefined ? "" : `, ${last24Visible} of them first recorded in the last 24 h (confirmed_exposed.last_24h)`}. Of the shadow_ai numbers, only confirmed_exposed counts exposed services.`,
  );
  if (total !== undefined) {
    sentences.push(
      `Shadow AI observed: ${total} (observed.total) counts every Certificate Transparency or Shodan observation on record, whatever its verification state: that many observed, not that many exposed.`,
    );
  }
  const first = (key: (typeof SHADOW_AI_ROWS)[number][0], label: string): string => {
    const top = rows[key]?.[0];
    return top === undefined ? "" : ` (first: ${top[label]}, ${top.count} observations)`;
  };
  const observedParts = [
    byCategory && "observed.by_category counts them by category",
    last24 !== undefined && `observed.last_24h (${last24}) counts those first recorded in the last 24 h`,
    rows.trend_30d && "observed.trend_30d counts them per UTC day over the last 30 days",
    rows.top_products && `observed.top_products ranks up to ten products by observations${first("top_products", "product")}`,
    rows.top_countries && `observed.top_countries ranks up to ten countries by observations${first("top_countries", "country")}`,
    rows.top_issuers &&
      `observed.top_issuers ranks up to ten issuers by observations, an issuer being the certificate's CA for a Certificate Transparency observation and the hosting operator Shodan reports for a Shodan one${first("top_issuers", "issuer")}`,
  ].filter((p): p is string => typeof p === "string");
  if (observedParts.length) {
    sentences.push(
      `${total === undefined ? "Every number" : "Every other number"} under observed counts the same observations, not exposed services: ${observedParts.join("; ")}.`,
    );
  }
  const authParts = [
    authSeen !== undefined &&
      `authentication.observed (${authSeen}) counts observations where a probe observed an authentication gate (a 401/403, a login page or an auth marker; liveness authenticated)`,
    authUnknown !== undefined &&
      `authentication.not_determined (${authUnknown}) counts observations whose service answered but where no probe could tell whether it enforces authentication (liveness inconclusive)`,
  ].filter((p): p is string => typeof p === "string");
  if (authParts.length) {
    sentences.push(`Shadow AI authentication, over every observation on record: ${authParts.join("; ")}.`);
    sentences.push(
      "Neither authentication count is part of confirmed_exposed, and observed.total minus confirmed_exposed.total is not a count of secured services: it also holds observations not yet verified (liveness unverified), whose hostname no longer resolves (unreachable), or whose service no longer answers openly (resolved).",
    );
  }

  // What the answer carried that the tool cannot label: named, and left out.
  const unknown = [
    ...Object.keys(isPlainObject(sa) ? sa : {}).filter((k) => k !== "stats" && k !== "poller"),
    ...Object.keys(isPlainObject(stats) ? stats : {})
      .filter((k) => !SHADOW_AI_STATS.has(k))
      .map((k) => `stats.${k}`),
    ...rowExtras,
  ];
  const unusable = Object.entries(isPlainObject(stats) ? stats : {})
    .filter(([k, v]) => SHADOW_AI_STATS.has(k) && !used.has(k) && v !== null)
    .map(([k]) => `stats.${k}`);
  if (!isPlainObject(stats)) sentences.push("The answer carries no stats object, so it gives no shadow-AI counts.");
  sentences.push(...leftOut("shadow_ai", unknown, unusable));

  const data: Record<string, unknown> = {};
  if (Object.keys(confirmed).length) data.confirmed_exposed = confirmed;
  if (Object.keys(observed).length) data.observed = observed;
  if (Object.keys(authentication).length) data.authentication = authentication;

  const lastRun = strAt(sa, "poller", "last_run_at");
  const running = boolAt(sa, "poller", "running");
  if (realInstant(lastRun) && running === true) {
    data.poller = { running, last_run_at: lastRun };
    sentences.push(
      `Shadow-AI radar freshness: the radar's leader last completed a Certificate Transparency (crt.sh) discovery cycle at ${lastRun} (poller.running is true: that was within ${SHADOW_AI_SILENT_AFTER} of the API's answer).`,
    );
  } else if (realInstant(lastRun) && running === false) {
    data.poller = { running, last_run_at: lastRun };
    sentences.push(
      `Shadow-AI radar freshness: no Certificate Transparency (crt.sh) discovery cycle has completed since ${lastRun}, when the radar's leader last completed one (poller.running is false: that was more than ${SHADOW_AI_SILENT_AFTER} before the API's answer), so the shadow-AI figures may be stale.`,
    );
  } else if (field(sa, "poller") === undefined) {
    sentences.push("Shadow-AI radar freshness is unknown: the answer carries no poller block.");
  } else {
    sentences.push(
      "Shadow-AI radar freshness is unknown: the answer's poller block does not give both a real time at which the radar's leader last completed a cycle (poller.last_run_at) and a running verdict (poller.running), so that block was left out of the data above.",
    );
  }
  if (realInstant(lastObservation)) sentences.push(`Latest shadow-AI observation on record: ${lastObservation}.`);
  return { data, sentences };
}

server.tool(
  "exposure_radar",
  `Aggregate totals from EchelonGraph's internet-exposure radars, each refreshed on its own schedule: internet-facing services running actively-exploited (CISA-KEV) CVEs, plus the ransomware-linked subset, derived from Shodan data; unauthenticated data stores and observability UIs, found through Shodan (LeakIX when Shodan query credits run low) and then confirmed by EchelonGraph's own identified check (not a pure read: on Redis it names its client, and on ClickHouse its query is recorded in the server's query log); leaked credentials sampled from public GitHub push events; and shadow AI services found through Certificate Transparency logs and Shodan and then checked by EchelonGraph's identified probes. Every number in the result is labelled here and in the result's note by what it counts; a field this version cannot label is left out and named in the note. ` +
    `kev_exposure: kev_exposure.distinct_hosts counts distinct ip:port services, not machines (a machine answering on two ports counts twice), with at least one CISA-KEV-listed CVE on record, and kev_exposure.ransomware_hosts those with a ransomware-linked one; kev_exposure.kev_cves_exposed and kev_exposure.ransomware_cves count distinct CVEs with at least one such service; kev_exposure.correlations counts service×CVE pairs, not services, so a service with three KEV CVEs counts three times. kev_exposure.top_products, kev_exposure.top_countries and kev_exposure.top_cves rank up to 12 products, 10 countries and 12 CVEs by those services; kev_exposure.top_cves[].cvss_v3_score and kev_exposure.top_cves[].epss_score are the highest CVSS v3 base score and EPSS probability recorded on that CVE's observations. kev_exposure.trend counts service×CVE pairs still on record by the week in which each was first recorded, over 12 weeks, so earlier weeks read low. kev_exposure.newest_kev lists the 15 CVEs that EchelonGraph's CVE records most recently mark as CISA-KEV-listed, each with an exposure_state: exposed, where kev_exposure.newest_kev[].exposed_hosts counts distinct ip:port services on record with it; or not_assessed, where the API's answer holds no measurement for that CVE (its 0 is not one) and no count is relayed, and cve_exposure says per CVE whether the radar tracks it. kev_exposure.newest_kev[].cvss_v3_score and kev_exposure.newest_kev[].epss_score are the CVE record's CVSS v3 base score and EPSS probability. ` +
    `exposed_databases: exposed_databases.distinct_hosts counts distinct ip:port services the check confirmed answering without authentication, and exposed_databases.engines the distinct engine types among them; exposed_databases.top_engines and exposed_databases.top_countries rank up to 15 engines and 10 countries by those services. exposed_databases.pii_likely and exposed_databases.pci_likely count services whose schema names (never record values) pass a high-confidence, precision-first gate for personal or payment-card data, so a service outside them is not shown to hold no such data. ` +
    `leaked_credentials: leaked_credentials.total counts (repository, secret) pairs, not distinct secrets, so one secret in three repositories counts three times; leaked_credentials.distinct_secrets counts each secret once and leaked_credentials.distinct_repos counts repositories; leaked_credentials.top_providers and leaked_credentials.top_types rank up to 15 providers and secret types by those pairs. None is validated: each is a credential-shaped string that passed EchelonGraph's filters, at most structurally checked and never tested against its provider. Each of those three radars also carries generated_at, when the API computed its totals, and, when the API can tell, last_run_at. kev_exposure.last_run_at, exposed_databases.last_run_at and leaked_credentials.last_run_at are timestamps, not counts: each is when that radar last completed a check, a cycle whose reads succeeded, among them a Shodan search (for exposed_databases, or its LeakIX fallback) that answered at least one query, or for leaked_credentials a read of the public GitHub event stream. A cycle that read nothing does not move it, and it is not the time of every record a radar's numbers count, which cover everything still on record, not only what the last check found. A radar whose answer carries no last_run_at has none in the result, and the note says nothing about it. ` +
    `shadow_ai: the result is regrouped by what each number counts. shadow_ai.confirmed_exposed counts services EchelonGraph's probes found answering without an authentication gate (liveness active, or rechecking during a re-check): confirmed_exposed.total is the sum of confirmed_exposed.by_category, and confirmed_exposed.last_24h counts those first recorded in the last 24 h. Of the shadow_ai numbers, only confirmed_exposed counts exposed services. shadow_ai.observed counts every Certificate Transparency or Shodan observation on record, whatever its verification state: its numbers are observed, not exposed. They are observed.total; observed.by_category (the same observations by category); observed.last_24h (those first recorded in the last 24 h); observed.trend_30d (observations per UTC day over the last 30 days); and observed.top_products, observed.top_countries and observed.top_issuers (up to ten products, countries and issuers ranked by observations, where an issuer is the certificate's CA for a Certificate Transparency observation and the hosting operator Shodan reports for a Shodan one). shadow_ai.authentication counts observations by probe outcome: authentication.observed where a probe observed an authentication gate (a 401/403, a login page or an auth marker), and authentication.not_determined where the service answered but no probe could tell. Neither authentication count is part of confirmed_exposed, and observed.total minus confirmed_exposed.total is not a count of secured services. The shadow-AI poller block carries only running and last_run_at: last_run_at is when the radar's leader last completed a Certificate Transparency (crt.sh) cycle, and its running is true only when that was within ${SHADOW_AI_SILENT_AFTER} of the answer. ${SHODAN_OWNERSHIP}`,
  {},
  async () => {
    const tool = "exposure_radar";
    try {
      const results = await Promise.all(RADARS.map(([, path]) => api(path)));
      const data: Record<string, object> = {};
      const failures: [string, Failure][] = [];
      RADARS.forEach(([name], i) => {
        const r = results[i];
        if (r.ok) data[name] = r.data;
        else failures.push([name, r]);
      });
      if (failures.length) {
        // All or nothing: a radar picture with one quadrant missing reads as the whole one,
        // and the missing quadrant reads as zero. Name every failure; withhold the rest.
        const answered = Object.keys(data);
        const lines = failures.map(([name, f]) => `- ${name}: ${describeFailure(f)}`);
        const withheld = answered.length
          ? ` The ${answered.length} radar(s) that did answer (${answered.join(", ")}) are withheld: a partial radar picture would be read as the whole one.`
          : "";
        return {
          content: [text(`${tool} FAILED: ${failures.length} of ${RADARS.length} radars could not be read from ${SHOWN_BASE}.\n${lines.join("\n")}\n${NOT_A_FINDING}${withheld}`)],
          isError: true,
        };
      }
      // Each radar's answer is relayed cut to the fields its reader can label, in RADARS order.
      const read = {
        kev_exposure: readKEVExposure(data.kev_exposure),
        exposed_databases: readExposedDatabases(data.exposed_databases),
        leaked_credentials: readLeakedCredentials(data.leaked_credentials),
        shadow_ai: readShadowAI(data.shadow_ai),
      };
      const relayed: Record<string, object> = {};
      const sentences: string[] = [];
      for (const [name] of RADARS) {
        relayed[name] = read[name].data;
        sentences.push(...read[name].sentences);
      }
      return succeeded(
        relayed,
        `${okHead(tool)} All ${RADARS.length} radars answered: ${RADARS.map(([name]) => name).join(", ")}. Every number relayed is labelled below by what it counts, and a field this version cannot label is left out and named. ${sentences.join(" ")} ${RADAR_SOURCES} ${SHODAN_OWNERSHIP} Each radar refreshes on its own schedule.`,
      );
    } catch (e) {
      return crashed(tool, e);
    }
  },
);

const transport = new StdioServerTransport();
await server.connect(transport);
// MCP uses stdout for the protocol — diagnostics go to stderr.
console.error(`EchelonGraph CVE MCP server running (API: ${SHOWN_BASE}, timeout ${TIMEOUT_MS} ms)`);
