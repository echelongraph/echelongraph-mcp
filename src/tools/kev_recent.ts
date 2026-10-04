// kev_recent (#2717): the CVEs CISA has added to its Known Exploited Vulnerabilities catalog,
// newest first, from GET /api/v1/public/kev/recent.
//
// The rows are EchelonGraph's copy of CISA's catalog: core-backend's KEV fetcher polls CISA's
// known_exploited_vulnerabilities.json every 5 minutes and writes each entry onto its CVE's
// record. So the answer is a measurement of that copy, dated by our last successful fetch of
// CISA's feed (catalog.last_successful_fetch_at: a 200 we applied, or a 304), which is both
// measured_at and freshness here. Where the API gives no such time, both are null and a note
// says freshness is unknown; nothing is filled in.
//
// Every input travels as an X-EG-* header, never in the URL (#1983), and the API answers it
// `private, no-store`. Nothing here logs an input.
//
// The logic lives here, and index.ts passes in the shared envelope helpers, so the tool
// registers with one call there (createServer) and its result contract is the same as every
// other tool's: content[0] the API's JSON verbatim, content[1] the note, content[2] the envelope.
import type { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod";

type Text = { type: "text"; text: string };
type ToolResult = { content: Text[]; structuredContent: Record<string, unknown>; isError?: boolean };
type Failure = {
  ok: false;
  kind: "network" | "timeout" | "http" | "not_json" | "not_object" | "unexpected_shape";
  path: string;
  status?: number;
  detail: string;
};
type ApiResult = { ok: true; status: number; data: object } | Failure;
type Env = {
  state: "measured";
  measured_at: string | null;
  method: string;
  coverage: Record<string, unknown>;
  freshness: Record<string, unknown>;
  notes: string[];
};

// What index.ts hands over: its own helpers, so this tool cannot drift from the envelope.
export interface KevRecentDeps {
  api(path: string, init?: { headers?: Record<string, string> }): Promise<ApiResult>;
  succeeded(data: object, note: string, env: Env): ToolResult;
  failed(tool: string, f: Failure): ToolResult;
  badInput(tool: string, why: string): ToolResult;
  crashed(tool: string, e: unknown): ToolResult;
  checked(tool: string, schema: z.ZodType, r: ToolResult): ToolResult;
  envelopeSchema(o: { data: z.ZodType; coverage: z.ZodType | null; freshness: z.ZodType | null }): z.ZodType;
  okHead(tool: string, status?: number): string;
  annotations: { readOnlyHint: boolean; destructiveHint: boolean; idempotentHint: boolean; openWorldHint: boolean };
}

const TOOL = "kev_recent";
const PATH = "/api/v1/public/kev/recent";
export const KEV_RECENT_MAX_LIMIT = 200;
const MAX_VENDOR = 128;
const MAX_CURSOR = 128;

const KEV_RECENT_METHOD =
  "EchelonGraph's copy of the CISA KEV catalog: CISA's feed is polled every 5 minutes and each entry is written onto its CVE's record; rows are read from those records, newest kev_added_date first.";
const KEV_RECENT_COVERAGE = "CISA KEV catalog";

const KEV_RECENT_DESCRIPTION =
  "The CVEs CISA has added to its Known Exploited Vulnerabilities (KEV) catalog, newest first, from EchelonGraph's copy of that catalog, which polls CISA's feed every 5 minutes. Each row in kev gives cve_id, kev_added_date (CISA's dateAdded), kev_due_date, kev_vendor, kev_product, kev_vuln_name and kev_ransomware (known ransomware-campaign use), EchelonGraph's severity, cvss_v3_score, epss_score, epss_percentile and eg_kev_tier for the CVE, and our_first_seen_kev, when EchelonGraph's poller first recorded the CVE entering the catalog (null where no such record exists). Filter by since and until (YYYY-MM-DD, inclusive, on kev_added_date; an RFC 3339 timestamp, such as the kev_added_date 2024-04-12T00:00:00Z that CVE records carry, is read as its UTC date, and anything else is refused), ransomware, and vendor (an exact, case-insensitive match on kev_vendor); page with limit (1 to 200, default 50) and cursor, passing back the previous page's next_cursor with the same filters. Rows within one date are ordered by cve_id. total counts the CVEs matching the filters; kev_listed_total counts every CVE EchelonGraph holds as KEV-listed, and catalog.catalog_count is CISA's own count in the catalog last fetched, so a gap between the two is entries not yet in EchelonGraph's CVE table, which no page returns. CISA's requiredAction and shortDescription are not returned. Its structured result carries state (measured), measured_at (our last successful fetch of CISA's feed, null when the API does not give it), method, coverage (the CISA KEV catalog: total, returned, kev_listed_total, catalog_count, limit, has_more), freshness (last_successful_fetch_at, catalog_version, date_released) and notes, with data equal to the API's JSON; the result's last text block repeats it without data (the first text block) and without the note's sentences (the text block before it), with which notes ends.";

export type KevRecentArgs = {
  since?: string;
  until?: string;
  ransomware?: boolean;
  vendor?: string;
  limit?: number;
  cursor?: string;
};

const opt = <T extends z.ZodType>(t: T) => t.nullable().optional();
const KEVRow = z.looseObject({
  cve_id: opt(z.string()),
  kev_added_date: opt(z.string()),
  kev_due_date: opt(z.string()),
  kev_vendor: opt(z.string()),
  kev_product: opt(z.string()),
  kev_vuln_name: opt(z.string()),
  kev_ransomware: opt(z.boolean()),
  severity: opt(z.string()),
  cvss_v3_score: opt(z.number()),
  epss_score: opt(z.number()),
  epss_percentile: opt(z.number()),
  eg_kev_tier: opt(z.number()),
  our_first_seen_kev: opt(z.string()).describe("When EchelonGraph's poller first recorded the CVE entering the catalog; null where no such record exists."),
});
const Data = z.looseObject({
  kev: z.array(KEVRow).optional(),
  count: opt(z.number()),
  total: opt(z.number()),
  kev_listed_total: opt(z.number()),
  limit: opt(z.number()),
  next_cursor: opt(z.string()),
  order: opt(z.string()),
  filters: opt(z.looseObject({})),
  catalog: opt(
    z.looseObject({
      source: opt(z.string()),
      feed_url: opt(z.string()),
      last_successful_fetch_at: opt(z.string()),
      catalog_version: opt(z.string()),
      date_released: opt(z.string()),
      catalog_count: opt(z.number()),
    }),
  ),
  method: opt(z.string()),
  notes: opt(z.array(z.string())),
  generated_at: opt(z.string()),
});
const Coverage = z.strictObject({
  catalog: z.literal(KEV_RECENT_COVERAGE),
  total: z.number().nullable().describe("CVEs matching the filters."),
  returned: z.number().nullable().describe("Rows in this page."),
  kev_listed_total: z.number().nullable().describe("Every CVE EchelonGraph holds as KEV-listed."),
  catalog_count: z.number().nullable().describe("CISA's own count, in the catalog last fetched."),
  limit: z.number().nullable(),
  has_more: z.boolean().nullable().describe("Whether next_cursor names a further page."),
});
const Freshness = z.strictObject({
  last_successful_fetch_at: z.string().nullable().describe("When CISA last answered our poll of its feed: a 200 we applied, or a 304 Not Modified."),
  catalog_version: z.string().nullable(),
  date_released: z.string().nullable(),
});

// Inputs this side refuses before any request, with the reason.
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const isDate = (s: string): boolean => DATE.test(s) && new Date(`${s}T00:00:00Z`).toISOString().slice(0, 10) === s;
// An RFC 3339 date-time (#2736): get_cve gives kev_added_date as one ("2024-04-12T00:00:00Z"), and a
// model passes it on as given. It is read as its UTC date; the time of day is dropped.
const RFC3339 = /^(\d{4}-\d{2}-\d{2})T([01]\d|2[0-3]):[0-5]\d:[0-5]\d(\.\d{1,9})?(Z|[+-]([01]\d|2[0-3]):[0-5]\d)$/;
// since or until as the YYYY-MM-DD the API takes, or null when it is neither form.
export function kevDate(raw: string): string | null {
  if (isDate(raw)) return raw;
  const m = RFC3339.exec(raw.toUpperCase());
  if (!m || !isDate(m[1])) return null;
  const t = Date.parse(raw.toUpperCase());
  return Number.isFinite(t) ? new Date(t).toISOString().slice(0, 10) : null;
}
// A header value must be visible ASCII: fetch refuses others, and that refusal would read as an outage.
const PRINTABLE = /^[\x20-\x7e]+$/;

function headersFor(a: KevRecentArgs): { headers: Record<string, string> } | { why: string } {
  const h: Record<string, string> = {};
  const sinceRaw = a.since?.trim();
  const untilRaw = a.until?.trim();
  const since = sinceRaw ? kevDate(sinceRaw) : undefined;
  const until = untilRaw ? kevDate(untilRaw) : undefined;
  if (since === null) return { why: "since must be a date, YYYY-MM-DD, or an RFC 3339 timestamp such as 2024-04-12T00:00:00Z" };
  if (until === null) return { why: "until must be a date, YYYY-MM-DD, or an RFC 3339 timestamp such as 2024-04-12T00:00:00Z" };
  if (since) h["X-EG-Since"] = since;
  if (until) h["X-EG-Until"] = until;
  if (since && until && since > until) return { why: "since must not be after until" };
  if (a.ransomware !== undefined) h["X-EG-Ransomware"] = String(a.ransomware);
  const vendor = a.vendor?.trim();
  if (vendor) {
    if (vendor.length > MAX_VENDOR || !PRINTABLE.test(vendor)) return { why: `vendor must be at most ${MAX_VENDOR} printable ASCII characters` };
    h["X-EG-Vendor"] = vendor;
  }
  if (a.limit !== undefined) h["X-EG-Limit"] = String(a.limit);
  const cursor = a.cursor?.trim();
  if (cursor) {
    if (cursor.length > MAX_CURSOR || !/^[A-Za-z0-9_-]+$/.test(cursor)) return { why: "cursor must be a next_cursor this tool returned" };
    h["X-EG-Cursor"] = cursor;
  }
  return { headers: h };
}

const at = (o: unknown, ...keys: string[]): unknown =>
  keys.reduce<unknown>((v, k) => (v !== null && typeof v === "object" ? (v as Record<string, unknown>)[k] : undefined), o);
const num = (o: unknown, ...k: string[]): number | null => {
  const v = at(o, ...k);
  return typeof v === "number" && Number.isFinite(v) ? v : null;
};
const str = (o: unknown, ...k: string[]): string | null => {
  const v = at(o, ...k);
  return typeof v === "string" && v ? v : null;
};
const realInstant = (s: string | null): s is string => s !== null && Date.parse(s) > 0;

async function kevRecent(d: KevRecentDeps, a: KevRecentArgs): Promise<ToolResult> {
  try {
    const h = headersFor(a);
    if ("why" in h) return d.badInput(TOOL, h.why);
    const r = await d.api(PATH, { headers: h.headers });
    if (!r.ok) return d.failed(TOOL, r);

    const rowsV = at(r.data, "kev");
    const rows = Array.isArray(rowsV) ? rowsV : null;
    const total = num(r.data, "total");
    const listed = num(r.data, "kev_listed_total");
    const catCount = num(r.data, "catalog", "catalog_count");
    const fetchedRaw = str(r.data, "catalog", "last_successful_fetch_at");
    const fetched = realInstant(fetchedRaw) ? fetchedRaw : null;
    const version = str(r.data, "catalog", "catalog_version");
    const released = str(r.data, "catalog", "date_released");
    const next = str(r.data, "next_cursor");

    const said: string[] = [d.okHead(TOOL, r.status)];
    if (total === 0) {
      said.push("No CVE in EchelonGraph's copy of the CISA KEV catalog matched these filters: a measured empty result, not a lookup failure.");
    } else if (rows && rows.length === 0) {
      said.push(`This page is empty: the cursor is past the last of the ${total ?? "matching"} rows.`);
    } else if (rows) {
      const first = rows[0] as Record<string, unknown>;
      const newest = typeof first?.cve_id === "string" && typeof first?.kev_added_date === "string" ? ` The first is ${first.cve_id}, added by CISA on ${first.kev_added_date}.` : "";
      said.push(`${total === null ? "The API did not say how many CVEs match" : `${total} CVEs in EchelonGraph's copy of the CISA KEV catalog match`}; ${rows.length} are in this page, newest kev_added_date first.${newest}`);
    }
    if (rows && rows.length > 0) said.push(next ? "More rows follow: call again with cursor set to next_cursor and the same filters." : "This is the last page.");
    said.push(
      fetched
        ? `EchelonGraph last fetched CISA's feed successfully at ${fetched}${version ? `, catalog version ${version}` : ""}.`
        : "The API gave no time for EchelonGraph's last successful fetch of CISA's feed, so how fresh this list is is unknown, not stale.",
    );
    if (catCount !== null && listed !== null && catCount > listed) {
      said.push(`CISA's catalog as last fetched counts ${catCount} entries and EchelonGraph holds ${listed} CVEs as KEV-listed, so ${catCount - listed} are not in its CVE table yet and no page returns them.`);
    }

    return d.succeeded(r.data, said.join(" "), {
      state: "measured",
      measured_at: fetched,
      method: KEV_RECENT_METHOD,
      coverage: {
        catalog: KEV_RECENT_COVERAGE,
        total,
        returned: rows ? rows.length : null,
        kev_listed_total: listed,
        catalog_count: catCount,
        limit: num(r.data, "limit"),
        has_more: rows ? next !== null : null,
      },
      freshness: { last_successful_fetch_at: fetched, catalog_version: version, date_released: released },
      notes: [
        fetched
          ? "measured_at is EchelonGraph's last successful fetch of CISA's feed, the time this copy of the catalog was last confirmed."
          : "measured_at is null: the answer does not give EchelonGraph's last successful fetch of CISA's feed.",
      ],
    });
  } catch (e) {
    return d.crashed(TOOL, e);
  }
}

// Registers the tool on a server built by index.ts's createServer.
export function registerKevRecent(server: McpServer, d: KevRecentDeps): void {
  const output = d.envelopeSchema({ data: Data, coverage: Coverage, freshness: Freshness });
  server.registerTool(
    "kev_recent",
    {
      title: "Recent CISA KEV additions",
      description: KEV_RECENT_DESCRIPTION,
      inputSchema: z.object({
        since: z.string().optional().describe("earliest kev_added_date to include, YYYY-MM-DD (an RFC 3339 timestamp is read as its UTC date)"),
        until: z.string().optional().describe("latest kev_added_date to include, YYYY-MM-DD (an RFC 3339 timestamp is read as its UTC date)"),
        ransomware: z.boolean().optional().describe("true: only CVEs with known ransomware-campaign use; false: only those without"),
        vendor: z.string().optional().describe("CISA vendorProject, an exact case-insensitive match, e.g. 'Microsoft'"),
        limit: z.number().int().min(1).max(KEV_RECENT_MAX_LIMIT).optional().describe("page size (default 50, max 200)"),
        cursor: z.string().optional().describe("next_cursor from the previous page"),
      }),
      outputSchema: output,
      annotations: d.annotations,
    },
    async (a) => d.checked(TOOL, output, await kevRecent(d, a)),
  );
}
