// MCP resources (#2722): context a client can attach.
//
//   echelongraph://methodology  static text: what each evidence-envelope field means, the state
//                               values, and how each tool measures (from the README's envelope
//                               docs). No API request.
//   echelongraph://sources      the feeds and what the API itself reports about their polling,
//                               read from the API at request time and never hard-coded: the CVE
//                               summary's poller block (/api/v1/public/cves/summary; its interval,
//                               last poll and two counters, the answering instance's) and the KEV
//                               answer's catalog block and method (/api/v1/public/kev/recent).
//                               What no endpoint reports is named as not reported.
//   cve://{cve_id}              get_cve's structured result for one CVE, as JSON: the envelope
//                               (state, measured_at, method, notes) with data, the API's record,
//                               cut past 30,000 characters as get_cve's first text block is.
//
// A resource read either answers or is a JSON-RPC error; it never answers a failure as data that
// reads like a record. sources is the exception by design: each feed it reads carries its own
// state, and a feed that could not be read says so (state failed), never an empty block.
import { McpServer, ProtocolError, ProtocolErrorCode, ResourceNotFoundError, ResourceTemplate } from "@modelcontextprotocol/server";
import type { ApiResult, ToolResult } from "./index.js";
import { DATA_TEXT_BUDGET, dataText, type CutPlace } from "./textBudget.js";

export type ResourceKit = {
  api: (path: string, init?: { headers?: Record<string, string> }) => Promise<ApiResult>;
  cveId: RegExp;
  // get_cve, run through its outputSchema check: the same result tools/call answers.
  getCve: (cveId: string) => Promise<ToolResult>;
  // index.ts's sentences: how a note is split into structuredContent's notes.
  sentences: (t: string) => string[];
  shownBase: string;
};

export const METHODOLOGY_URI = "echelongraph://methodology";
export const SOURCES_URI = "echelongraph://sources";
export const CVE_TEMPLATE = "cve://{cve_id}";

export const METHODOLOGY = `# How EchelonGraph MCP results are measured

Every tool result carries an evidence envelope in its structuredContent, and repeats it in its last text block (less what an earlier text block already carries verbatim), so a client that passes text blocks alone still sees it.

A success's first text block is the API's JSON, cut to fit 30,000 characters when it is longer: the note then says what the cut leaves out and how to read it (TEXT CUT), and structuredContent's data holds the answer whole. The resource ${CVE_TEMPLATE} cuts its data the same way, and its notes say so (DATA CUT).

## Envelope fields

| Field | What it holds |
|---|---|
| state | measured, not_assessed, failed or invalid_input (below). |
| measured_at | When the underlying observation was made, as the API states it. null when the answer does not say or holds no observation; never the Go zero time. |
| method | How the numbers were produced. null on a failure. |
| coverage | What the answer covers, where the tool can say: for example in_scope for cve_exposure, the list's account of its own count for search_cves, assessed and not_assessed_reason first for check_affected. |
| freshness | The producing radar's or fetcher's last completed check, where the API serves one; null where it serves none. |
| notes | The caveats, one sentence each. |
| data | On a success: the API's JSON (exposure_radar and cve_intel relay a labelled selection, and cve_summary leaves out a poller field of another JSON type, named in the note). |
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
// A JSON value's type in words, for a value that is not the JSON object read here.
const jsonKind = (v: unknown): string =>
  Array.isArray(v) ? "an array" : typeof v === "number" ? "a number" : typeof v === "boolean" ? "a boolean" : typeof v === "string" ? "a string" : typeof v;

// What /api/v1/public/cves/summary reports about the NVD poller: its interval and last poll, and
// its poll and failed-poll counts, of the server instance that answered (core-backend
// cve/poller.go Stats, in memory).
const POLLER_FIELDS = ["interval", "last_poll_at", "poll_count", "poll_errors"] as const;
// #2770: poll_count and poll_errors are that instance's counters since it last started, zeroed on
// every restart (cve_summary's summaryPollerNote, #2647, says the same of the whole block). 2.6.3
// relayed them here with a note on interval and last_poll_at alone, so poll_errors 0 over
// poll_count 7 read as the feed's track record. Whenever reported carries either, notes says so.
const SOURCES_POLLER_COUNTERS_NOTE =
  "poll_count and poll_errors, where reported carries them, are that one instance's counters since it last started, zeroed on every restart: they count that instance's polls and failed polls, never the feed's reliability.";
const CATALOG_FIELDS = ["source", "feed_url", "last_successful_fetch_at", "catalog_version", "date_released", "catalog_count"] as const;

export async function readSources(kit: ResourceKit): Promise<Record<string, unknown>> {
  const [summary, kev] = await Promise.all([kit.api(SUMMARY_PATH), kit.api(KEV_PATH, { headers: { "X-EG-Limit": "1" } })]);
  const nvd: Record<string, unknown> = { feed: "NVD CVE records (EchelonGraph's CVE feed poller)", endpoint: SUMMARY_PATH };
  if (!summary.ok) Object.assign(nvd, failure(summary));
  else {
    const sent = obj(summary.data)?.poller;
    const poller = obj(sent);
    if (poller === undefined && sent !== undefined && sent !== null) {
      // #2770's review: a poller of another JSON type (cve_summary leaves it out and names it,
      // #2771) is one the answer carries, so it is never described as missing.
      Object.assign(nvd, {
        state: "not_reported",
        reported: null,
        notes: [`The answer carries poller as ${jsonKind(sent)}, where a JSON object was expected, so it reports neither a poll interval nor a last poll time.`],
      });
    } else if (poller === undefined) {
      Object.assign(nvd, { state: "not_reported", reported: null, notes: ["The answer carries no poller block, so it reports neither a poll interval nor a last poll time."] });
    } else {
      const reported = pick(poller, POLLER_FIELDS);
      const counted = reported.poll_count !== undefined || reported.poll_errors !== undefined;
      Object.assign(nvd, {
        state: "reported",
        reported,
        notes: [
          "poller is the NVD poller of the server instance that answered, held in its memory: interval is its configured interval (each cycle adds a start-up jitter), and last_poll_at is that instance's last poll, not a fleet-wide time.",
          ...(counted ? [SOURCES_POLLER_COUNTERS_NOTE] : []),
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

// cve://{cve_id}'s text (#2801). Through 2.6.3 it was get_cve's structuredContent pretty-printed
// whole: 86,559 characters for CVE-2021-44228 on the hosted endpoint (2026-10-04), past #2467's
// ceiling of 60,000 (test/text-bound.mjs), its notes ending with get_cve's TEXT CUT sentences, which
// describe a first text block the resource does not have ("Every list in it keeps at most its first
// 64 entries: cpe_match (396)…" beside all 396 of them). A resource is one text, with no
// structuredContent beside it, so its data is now cut as get_cve's first text block is (dataText:
// the same answer, cut the same way, laid out as that block lays it out) after the envelope,
// pretty-printed as before; its notes leave out get_cve's sentences about its first text block and,
// when data is cut, end with the resource's own, starting DATA CUT, which names get_cve's
// structuredContent.data as the record whole. A record that fits is the structured result
// pretty-printed, character for character as before.
const CVE_RESOURCE_CUT: CutPlace = {
  opens: (chars) =>
    `DATA CUT: the API's answer is ${chars} characters of JSON, more than the ${DATA_TEXT_BUDGET} this resource's data holds, so data here is cut, and get_cve's structuredContent.data carries the answer whole.`,
};
export function cveResourceText(structured: Record<string, unknown>, sentences: (t: string) => string[]): string {
  const { data, ...envelope } = structured;
  if (data === null || typeof data !== "object" || Array.isArray(data)) return JSON.stringify(structured, null, 2);
  const firstBlock = new Set(sentences(dataText(data).said));
  const own = dataText(data, undefined, CVE_RESOURCE_CUT);
  const notes = Array.isArray(envelope.notes) ? [...envelope.notes.filter((n) => !firstBlock.has(n)), ...sentences(own.said)] : envelope.notes;
  const head = JSON.stringify({ ...envelope, ...(notes === undefined ? {} : { notes }) }, null, 2);
  const body = own.text.replace(/\n/g, "\n  ");
  return head === "{}" ? `{\n  "data": ${body}\n}` : `${head.slice(0, -2)},\n  "data": ${body}\n}`;
}

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
        "The feeds and what the API reports about their polling, read from the API when the resource is read: the NVD poller's interval, last poll, poll_count and poll_errors, all of the one instance that answered (the two counts since that instance last started, zeroed on every restart, never the feed's reliability), and the CISA KEV catalog's last successful fetch and method. What no endpoint reports is named as not reported.",
      mimeType: "application/json",
    },
    async (uri) => json(uri.href, await readSources(kit)),
  );

  server.registerResource(
    "cve",
    new ResourceTemplate(CVE_TEMPLATE, { list: undefined }),
    {
      title: "CVE record",
      description:
        "One CVE's record as get_cve returns it, as JSON: the evidence envelope (state, measured_at, method, notes) with data, the API's record. Past 30,000 characters of JSON, data is cut as get_cve's first text block is, and a note starting DATA CUT says what the cut leaves out; get_cve's structured result holds the record whole. cve_id is a CVE ID such as CVE-2024-3400.",
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
      return { contents: [{ uri: uri.href, mimeType: "application/json", text: cveResourceText(r.structuredContent, kit.sentences) }] };
    },
  );
}
