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
//     regroups the shadow-AI answer by what each number counts (readShadowAI, #2307).
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

// A ranking or a daily series, each row cut down to its label and its count, so a field the
// backend adds to a row later is left out rather than relayed unlabelled. All rows or none.
function countRows(v: unknown, label: string): Record<string, string | number>[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const rows: Record<string, string | number>[] = [];
  for (const r of v) {
    const name = field(r, label);
    const count = field(r, "count");
    if (typeof name !== "string" || !isCount(count)) return undefined;
    rows.push({ [label]: name, count });
  }
  return rows;
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
  const rows: Partial<Record<(typeof SHADOW_AI_ROWS)[number][0], Record<string, string | number>[]>> = {};
  for (const [key, label] of SHADOW_AI_ROWS) {
    const r = take(key, countRows(field(stats, key), label));
    if (r) observed[key] = rows[key] = r;
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
      : `Shadow AI confirmed exposed: ${confirmed.total} (confirmed_exposed.total, the sum of confirmed_exposed.by_category: services EchelonGraph's probes found answering without an authentication gate, with liveness active or, during a re-check, rechecking)${last24Visible === undefined ? "" : `, ${last24Visible} of them first recorded in the last 24 h (confirmed_exposed.last_24h)`}. Only confirmed_exposed counts exposed services.`,
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
  ];
  const unusable = Object.entries(isPlainObject(stats) ? stats : {})
    .filter(([k, v]) => SHADOW_AI_STATS.has(k) && !used.has(k) && v !== null)
    .map(([k]) => `stats.${k}`);
  if (!isPlainObject(stats)) sentences.push("The answer carries no stats object, so it gives no shadow-AI counts.");
  if (unknown.length) {
    sentences.push(`Left out of shadow_ai because this version of the tool cannot label them: ${unknown.join(", ")}.`);
  }
  if (unusable.length) {
    sentences.push(`Left out of shadow_ai because they were not in the expected shape: ${unusable.join(", ")}.`);
  }

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
  `Aggregate totals from EchelonGraph's internet-exposure radars, each refreshed on its own schedule: shadow AI services found through Certificate Transparency logs and Shodan and then checked by EchelonGraph's identified probes; internet-facing services running actively-exploited (CISA-KEV) CVEs, plus the ransomware-linked subset, derived from Shodan data; unauthenticated data stores and observability UIs, found through Shodan (LeakIX when Shodan query credits run low) and then confirmed by EchelonGraph's own identified check (not a pure read: on Redis it names its client, and on ClickHouse its query is recorded in the server's query log); and leaked credentials sampled from public GitHub push events. The kev_exposure and exposed_databases distinct_hosts figures count distinct ip:port services, so a machine answering on two ports counts twice. The shadow_ai result is regrouped by what each number counts, and carries no number the tool cannot label. shadow_ai.confirmed_exposed counts services EchelonGraph's probes found answering without an authentication gate (liveness active, or rechecking during a re-check): confirmed_exposed.total is the sum of confirmed_exposed.by_category, and confirmed_exposed.last_24h counts those first recorded in the last 24 h. Only confirmed_exposed counts exposed services. shadow_ai.observed counts every Certificate Transparency or Shodan observation on record, whatever its verification state: its numbers are observed, not exposed. They are observed.total; observed.by_category (the same observations by category); observed.last_24h (those first recorded in the last 24 h); observed.trend_30d (observations per UTC day over the last 30 days); and observed.top_products, observed.top_countries and observed.top_issuers (up to ten products, countries and issuers ranked by observations, where an issuer is the certificate's CA for a Certificate Transparency observation and the hosting operator Shodan reports for a Shodan one). shadow_ai.authentication counts observations by probe outcome: authentication.observed where a probe observed an authentication gate (a 401/403, a login page or an auth marker), and authentication.not_determined where the service answered but no probe could tell. Neither authentication count is part of confirmed_exposed, and observed.total minus confirmed_exposed.total is not a count of secured services. The shadow-AI poller block carries only running and last_run_at: last_run_at is when the radar's leader last completed a Certificate Transparency (crt.sh) cycle, and its running is true only when that was within ${SHADOW_AI_SILENT_AFTER} of the answer. ${SHODAN_OWNERSHIP}`,
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
      const shadow = readShadowAI(data.shadow_ai);
      data.shadow_ai = shadow.data;
      return succeeded(
        data,
        `${okHead(tool)} All ${RADARS.length} radars answered: ${RADARS.map(([name]) => name).join(", ")}. ${shadow.sentences.join(" ")} ${RADAR_SOURCES} ${SHODAN_OWNERSHIP} Each radar refreshes on its own schedule.`,
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
