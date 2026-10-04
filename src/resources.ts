// MCP resources (#2722): context a client can attach.
//
//   echelongraph://methodology  static text: what each evidence-envelope field means, the state
//                               values, and how each tool measures (from the README's envelope
//                               docs). No API request.
//   echelongraph://sources      the feeds and what the API itself reports about their polling,
//                               read from the API at request time and never hard-coded: the CVE
//                               summary's poller block (/api/v1/public/cves/summary) and the KEV
//                               answer's catalog block and method (/api/v1/public/kev/recent).
//                               What no endpoint reports is named as not reported.
//   cve://{cve_id}              get_cve's structured result for one CVE, as JSON: the envelope
//                               (state, measured_at, method, notes) with data, the API's record.
//
// A resource read either answers or is a JSON-RPC error; it never answers a failure as data that
// reads like a record. sources is the exception by design: each feed it reads carries its own
// state, and a feed that could not be read says so (state failed), never an empty block.
import { McpServer, ProtocolError, ProtocolErrorCode, ResourceNotFoundError, ResourceTemplate } from "@modelcontextprotocol/server";
import type { ApiResult, ToolResult } from "./index.js";

export type ResourceKit = {
  api: (path: string, init?: { headers?: Record<string, string> }) => Promise<ApiResult>;
  cveId: RegExp;
  // get_cve, run through its outputSchema check: the same result tools/call answers.
  getCve: (cveId: string) => Promise<ToolResult>;
  shownBase: string;
};

export const METHODOLOGY_URI = "echelongraph://methodology";
export const SOURCES_URI = "echelongraph://sources";
export const CVE_TEMPLATE = "cve://{cve_id}";

export const METHODOLOGY = `# How EchelonGraph MCP results are measured

Every tool result carries an evidence envelope in its structuredContent, and repeats it in its last text block (less what an earlier text block already carries verbatim), so a client that passes text blocks alone still sees it.

## Envelope fields

| Field | What it holds |
|---|---|
| state | measured, not_assessed, failed or invalid_input (below). |
| measured_at | When the underlying observation was made, as the API states it. null when the answer does not say or holds no observation; never the Go zero time. |
| method | How the numbers were produced. null on a failure. |
| coverage | What the answer covers, where the tool can say: for example in_scope for cve_exposure, the list's account of its own count for search_cves, assessed and not_assessed_reason first for check_affected. |
| freshness | The producing radar's or fetcher's last completed check, where the API serves one; null where it serves none. |
| notes | The caveats, one sentence each. |
| data | On a success: the API's JSON (exposure_radar and cve_intel relay a labelled selection). |
| error | On a failure: kind, path, status and message. |

## state

| state | What it means |
|---|---|
| measured | A measurement of what was asked. An exposure count is measured when the answer says when what it counts was observed and how it was produced; no exposure answer says when today, so neither exposure tool answers measured. |
| not_assessed | The answer holds no dated measurement of what was asked, so no count in it is presented as one. It can still relay a count, as what the source holds on record, undated; the notes say what each count is. Never clean. |
| failed | The lookup did not complete: unreachable host, non-2xx, timeout, or a body that is not a JSON object. Not a finding, never zero. |
| invalid_input | The input was refused, by this server or by the API, so nothing was looked up. Not a finding. |

A count of 0 is a finding of none when the answer measured it. Under assessed: false, or state not_assessed, it is not: report it as not assessed.

## How each tool measures

- cve_summary: measured; measured_at is summary.last_updated, the newest modification time among the active CVE records it counts. freshness is null: the feed serves no poll-completion time for the feed as a whole.
- search_cves: measured, measured_at null (each record carries its own times); coverage repeats total, total_counted, total_is_lower_bound, search_relaxed, limit and offset.
- get_cve: measured; measured_at is the record's updated_at, when EchelonGraph last wrote it. score_assessed false means not yet scored, not a score of 0.
- cve_exposure: not_assessed with measured_at null, every answer: its last_seen is when EchelonGraph last wrote or refreshed a service's row, not an observation time. exposure_state (exposed, measured_zero, not_assessed, tracking_unknown) says what the count is; exposed_hosts counts distinct ip:port services from Shodan data, not machines, and is not an internet-wide census.
- exposure_radar: not_assessed with measured_at null: no radar's answer gives one time at which what it counts was observed. freshness gives each radar's last_run_at where the API serves one.
- kev_recent: measured; measured_at is EchelonGraph's last successful fetch of CISA's KEV feed; freshness carries that fetch time, catalog_version and date_released.
- epss_history: measured_at is current.epss_updated_at, when EchelonGraph last wrote a changed EPSS value; the series is change-only, so a missing point is not recorded, not unchanged.
- check_affected: measured when the answer says assessed true; not_assessed when it says false or does not say. measured_at and freshness are null.
- check_sbom: measured when at least one component got a verdict, else not_assessed; measured_at null. not_affected is the one clean verdict; undetermined and not_assessed are not clean.
- cve_intel: measured_at null: each row carries its own first_seen_at or enriched_at. An empty exploits list is not evidence that no public exploit exists.
- get_cwe: measured_at null: each row carries its own published date. A total of 0 says no CVE in EchelonGraph's feed is classified under that CWE.
- vendor_advisories_for_cve, search_vendor_advisories: measured_at null (each row carries vendor_published_at and our_first_seen_at). get_vendor_advisory: measured_at is our_first_seen_at, when EchelonGraph first recorded the advisory.

Every figure is as fresh as the schedule that refreshes it. The resource ${SOURCES_URI} reports what the API itself says about its feeds' polling.
`;

const SUMMARY_PATH = "/api/v1/public/cves/summary";
const KEV_PATH = "/api/v1/public/kev/recent";

const obj = (v: unknown): Record<string, unknown> | undefined => (v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined);
const pick = (o: Record<string, unknown> | undefined, keys: readonly string[]): Record<string, unknown> =>
  Object.fromEntries(keys.filter((k) => o !== undefined && o[k] !== undefined).map((k) => [k, o![k]]));
const failure = (r: Extract<ApiResult, { ok: false }>) => ({ state: "failed", error: { kind: r.kind, path: r.path, status: r.status ?? null, message: r.detail } });

// What /api/v1/public/cves/summary reports about the NVD poller: its interval and last poll, of
// the server instance that answered (core-backend cve/poller.go Stats, in memory).
const POLLER_FIELDS = ["interval", "last_poll_at", "poll_count", "poll_errors"] as const;
const CATALOG_FIELDS = ["source", "feed_url", "last_successful_fetch_at", "catalog_version", "date_released", "catalog_count"] as const;

export async function readSources(kit: ResourceKit): Promise<Record<string, unknown>> {
  const [summary, kev] = await Promise.all([kit.api(SUMMARY_PATH), kit.api(KEV_PATH, { headers: { "X-EG-Limit": "1" } })]);
  const nvd: Record<string, unknown> = { feed: "NVD CVE records (EchelonGraph's CVE feed poller)", endpoint: SUMMARY_PATH };
  if (!summary.ok) Object.assign(nvd, failure(summary));
  else {
    const poller = obj(obj(summary.data)?.poller);
    if (poller === undefined) {
      Object.assign(nvd, { state: "not_reported", reported: null, notes: ["The answer carries no poller block, so it reports neither a poll interval nor a last poll time."] });
    } else {
      Object.assign(nvd, {
        state: "reported",
        reported: pick(poller, POLLER_FIELDS),
        notes: [
          "poller is the NVD poller of the server instance that answered, held in its memory: interval is its configured interval (each cycle adds a start-up jitter), and last_poll_at is that instance's last poll, not a fleet-wide time.",
        ],
      });
    }
  }
  const cisa: Record<string, unknown> = { feed: "CISA Known Exploited Vulnerabilities catalog", endpoint: KEV_PATH };
  if (!kev.ok) Object.assign(cisa, failure(kev));
  else {
    const d = obj(kev.data);
    const catalog = obj(d?.catalog);
    const method = typeof d?.method === "string" ? d.method : null;
    Object.assign(cisa, {
      state: catalog === undefined && method === null ? "not_reported" : "reported",
      reported: { catalog: catalog === undefined ? null : pick(catalog, CATALOG_FIELDS), method },
      notes: [
        "method is the API's own sentence about how it polls CISA's feed, quoted as sent; catalog.last_successful_fetch_at is when CISA last answered that poll.",
      ],
    });
  }
  return {
    uri: SOURCES_URI,
    api_base: kit.shownBase,
    read_at: new Date().toISOString(),
    sources: [nvd, cisa],
    not_reported: [
      "No public endpoint this server reads reports a poll cadence or a last poll time for the MITRE-CNA pre-NVD records, EPSS, GitHub GHSA, the OSV.dev advisory records, the vendor-advisory feeds, or the exposure radars' sources; this resource states none for them.",
      "exposure_radar's freshness gives each radar's last_run_at, its last completed check, where the API serves one.",
    ],
  };
}

const json = (uri: string, v: unknown) => ({ contents: [{ uri, mimeType: "application/json", text: JSON.stringify(v, null, 2) }] });

export function registerResources(server: McpServer, kit: ResourceKit): void {
  server.registerResource(
    "methodology",
    METHODOLOGY_URI,
    {
      title: "How results are measured",
      description: "What each evidence-envelope field (state, measured_at, method, coverage, freshness, notes) means, the state values, and how each tool measures.",
      mimeType: "text/markdown",
    },
    async (uri) => ({ contents: [{ uri: uri.href, mimeType: "text/markdown", text: METHODOLOGY }] }),
  );

  server.registerResource(
    "sources",
    SOURCES_URI,
    {
      title: "Feed sources and polling",
      description:
        "The feeds and what the API reports about their polling, read from the API when the resource is read: the NVD poller's interval and last poll (of the instance that answered) and the CISA KEV catalog's last successful fetch and method. What no endpoint reports is named as not reported.",
      mimeType: "application/json",
    },
    async (uri) => json(uri.href, await readSources(kit)),
  );

  server.registerResource(
    "cve",
    new ResourceTemplate(CVE_TEMPLATE, { list: undefined }),
    {
      title: "CVE record",
      description: "One CVE's record as get_cve returns it, as JSON: the evidence envelope (state, measured_at, method, notes) with data, the API's record. cve_id is a CVE ID such as CVE-2024-3400.",
      mimeType: "application/json",
    },
    async (uri, vars) => {
      const raw = Array.isArray(vars.cve_id) ? vars.cve_id[0] : vars.cve_id;
      const id = decodeURIComponent(String(raw ?? "")).trim();
      if (!kit.cveId.test(id)) {
        throw new ProtocolError(ProtocolErrorCode.InvalidParams, `cve:// takes a CVE ID such as CVE-2024-3400 (${id.length} characters given)`, { uri: uri.href, reason: "invalid_cve_id" });
      }
      const r = await kit.getCve(id.toUpperCase());
      if (r.isError) {
        const msg = r.content[0]?.text ?? "get_cve failed";
        const err = obj(r.structuredContent.error);
        if (err?.status === 404) throw new ResourceNotFoundError(uri.href);
        throw new ProtocolError(ProtocolErrorCode.InternalError, msg, { uri: uri.href, state: r.structuredContent.state ?? null, error: err ?? null });
      }
      return json(uri.href, r.structuredContent);
    },
  );
}
