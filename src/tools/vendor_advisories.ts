// The vendor-advisory tools (#2719): vendor_advisories_for_cve, get_vendor_advisory and
// search_vendor_advisories, over core-backend's /api/v1/public/vendor-advisories routes
// (internal/cve/vendoradv/handler.go: ByCVE, Detail, List).
//
// What these answers are. EchelonGraph polls vendors' own advisory feeds on a schedule and
// stores each advisory as the vendor published it (vendor_advisories, migration 063). A row
// carries two dates that mean different things, and every tool relays both:
// vendor_published_at is the date the vendor gives, our_first_seen_at is when EchelonGraph
// first recorded the advisory. withdrawn is the vendor rescinding its own advisory; the list
// and the search leave such advisories out, the per-CVE lookup and the detail keep them, and
// the note names each one. Advisories of a vendor feed EchelonGraph has disabled are left out
// of all three. None of the answers carries a time at which the pollers last completed a poll,
// so freshness is null.
//
// The search term never travels in a URL (#1983). search_vendor_advisories sends it in the
// X-EG-Advisory-Search header, percent-encoded, which the API reads first (handler.go
// listSearch); the URL carries only the filters. An API that does not read that header answers
// the UNSEARCHED list, so the tool requires the answer's search_applied to be true whenever it
// sent a term, and fails otherwise rather than relay the whole list as the search's matches.
// The term is never written into a note, an error or a log either.
//
// The other two put a CVE ID, a vendor slug and a vendor advisory ID in the path: identifiers
// the routes are keyed on, refused locally unless they have an identifier's shape, so no free
// text reaches a URL through them.
//
// Logic only: the envelope, the failure contract and the API call are index.ts's, handed in as
// a VendorAdvisoryKit so this file cannot drift from them.
import * as z from "zod";
import type { McpServer, StandardSchemaWithJSON } from "@modelcontextprotocol/server";

// The shapes index.ts's helpers take and return, structurally.
type FailureKind = "network" | "timeout" | "http" | "not_json" | "not_object" | "unexpected_shape";
type Failure = { ok: false; kind: FailureKind; path: string; status?: number; detail: string };
type ApiResult = { ok: true; status: number; data: object } | Failure;
type Text = { type: "text"; text: string };
type ToolResult = { content: Text[]; structuredContent: Record<string, unknown>; isError?: boolean };
type SuccessEnv = {
  state: "measured" | "not_assessed";
  measured_at: string | null;
  method: string;
  coverage: Record<string, unknown> | null;
  freshness: Record<string, unknown> | null;
  notes?: string[];
};
type OutputSchema = z.ZodType & StandardSchemaWithJSON;

export type VendorAdvisoryKit = {
  api: (path: string, init?: { headers?: Record<string, string>; method?: string; body?: string }) => Promise<ApiResult>;
  failed: (tool: string, f: Failure) => ToolResult;
  badInput: (tool: string, why: string) => ToolResult;
  crashed: (tool: string, e: unknown) => ToolResult;
  succeeded: (data: object, note: string, env: SuccessEnv) => ToolResult;
  checked: (tool: string, schema: z.ZodType, r: ToolResult) => ToolResult;
  okHead: (tool: string, status?: number) => string;
  envelopeSchema: (o: { data: z.ZodType; coverage: z.ZodType | null; freshness: z.ZodType | null }) => OutputSchema;
  annotations: { readonly readOnlyHint: true; readonly destructiveHint: false; readonly idempotentHint: true; readonly openWorldHint: true };
};

// core-backend vendoradv.SearchHeader.
export const VENDOR_ADVISORY_SEARCH_HEADER = "X-EG-Advisory-Search";
// handler.go List caps the search at 100 bytes; a longer term would be cut, possibly inside a
// character, so it is refused here instead.
const SEARCH_MAX_BYTES = 100;
// store.go ListAdvisoriesByCVE: LIMIT 20, newest first.
const BY_CVE_CAP = 20;

const CVE_ID = /^CVE-\d{4}-\d{4,}$/i;
// vendors.slug's CHECK constraint (migration 063).
const VENDOR_SLUG = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
// No control characters (a header or log line could carry them), at most 200 characters.
const ADVISORY_ID = /^[^\x00-\x1f\x7f]{1,200}$/;

const METHOD =
  "EchelonGraph's vendor-advisory feed: advisories as each vendor published them in its own feed (for example Microsoft MSRC, Red Hat, Cisco, Palo Alto Networks and GitHub GHSA), each feed polled on a schedule; advisories of a feed EchelonGraph has disabled are left out.";
const NO_FRESHNESS = "freshness is null: these answers carry no time at which the vendor-advisory pollers last completed a poll.";
const DATES =
  "vendor_published_at is the date the vendor gives for the advisory; our_first_seen_at is when EchelonGraph first recorded it, which is not the vendor's date.";
const LIST_MEASURED_AT = "measured_at is null: a list of advisories has no single observation time; each row carries vendor_published_at and our_first_seen_at.";
const ONLY_POLLED =
  "Only the vendor feeds EchelonGraph polls are covered, so an advisory a vendor published elsewhere is not in this answer.";

const realInstant = (s: unknown): s is string => typeof s === "string" && Date.parse(s) > 0;
const field = (o: unknown, k: string): unknown => (o !== null && typeof o === "object" ? (o as Record<string, unknown>)[k] : undefined);
const num = (o: unknown, k: string): number | undefined => {
  const v = field(o, k);
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
};
const str = (o: unknown, k: string): string | undefined => {
  const v = field(o, k);
  return typeof v === "string" && v ? v : undefined;
};
const rowsOf = (o: unknown): unknown[] | undefined => {
  const v = field(o, "advisories");
  return Array.isArray(v) ? v : undefined;
};
const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

// Each withdrawn row named by vendor and id: report it as withdrawn, never as a current advisory.
function withdrawnNote(rows: unknown[]): string {
  const w = rows.flatMap((r, i) => (field(r, "withdrawn") === true ? [`${str(r, "vendor") ?? "?"}/${str(r, "vendor_advisory_id") ?? `advisories[${i}]`}`] : []));
  if (!w.length) return "";
  return ` WITHDRAWN: ${w.length} of these ${rows.length} ${plural(rows.length, "advisory", "advisories")} ${plural(w.length, "was", "were")} withdrawn (rescinded) by ${plural(w.length, "its", "their")} vendor (withdrawn true): ${w.join(", ")}. Report ${plural(w.length, "it", "them")} as withdrawn, not as a current advisory.`;
}

// ── Output schemas ──
const opt = <T extends z.ZodType>(t: T) => t.nullable().optional();
const DATE_FIELDS = {
  vendor_published_at: opt(z.string()).describe("The date the vendor gives for the advisory."),
  our_first_seen_at: opt(z.string()).describe("When EchelonGraph first recorded the advisory; not the vendor's date."),
  withdrawn: opt(z.boolean()).describe("true: the vendor withdrew (rescinded) this advisory; report it as withdrawn."),
};
const AdvisoryRow = z.looseObject({
  advisory_id: opt(z.string()),
  vendor: opt(z.string()),
  vendor_display_name: opt(z.string()),
  vendor_advisory_id: opt(z.string()),
  cve_ids: opt(z.array(z.string())),
  title: opt(z.string()),
  severity: opt(z.string()),
  cvss_v3_score: opt(z.number()),
  summary: opt(z.string()),
  affected_products: opt(z.array(z.string())),
  ...DATE_FIELDS,
});

// Shared by the three descriptions. Top-level consts, so the site's tool-claims check
// (marketing-site/lib/mcpToolClaims.test.ts) can fold the descriptions to their text.
const DATES_DESCRIPTION =
  "Each advisory carries vendor_published_at (the vendor's date), our_first_seen_at (when EchelonGraph first recorded it) and withdrawn (true: the vendor rescinded it; the note names each such advisory).";
const ENVELOPE_DESCRIPTION =
  "Its structured result carries state (measured), measured_at, method, coverage, freshness (null: the answer carries no poll-completion time) and notes, with data equal to the API's JSON; the result's last text block repeats it without data (the first text block) and without the note's sentences (the text block before it), with which notes ends.";

export function registerVendorAdvisoryTools(server: McpServer, kit: VendorAdvisoryKit): void {
  const FOR_CVE_OUTPUT = kit.envelopeSchema({
    data: z.looseObject({ cve_id: opt(z.string()), advisories: opt(z.array(AdvisoryRow)), total: opt(z.number()) }),
    coverage: z.strictObject({
      returned: z.number().nullable().describe("The advisories in this answer."),
      cap: z.number().describe("The most the API returns for one CVE, newest first."),
      at_cap: z.boolean().nullable().describe("true: the answer is full, so the vendor feeds may hold more advisories for this CVE than it lists."),
    }),
    freshness: null,
  });
  const DETAIL_OUTPUT = kit.envelopeSchema({
    data: AdvisoryRow.extend({
      description: opt(z.string()),
      known_cve_ids: opt(z.array(z.string())).describe("The CVE IDs of cve_ids that have a record in EchelonGraph's CVE feed."),
      remediation: opt(z.string()),
      references: z.unknown().optional(),
      vendor_modified_at: opt(z.string()),
      withdrawn_at: opt(z.string()),
      withdrawn_reason: opt(z.string()),
    }),
    coverage: null,
    freshness: null,
  });
  const SEARCH_OUTPUT = kit.envelopeSchema({
    data: z.looseObject({
      advisories: opt(z.array(AdvisoryRow)),
      total: opt(z.number()),
      limit: opt(z.number()),
      offset: opt(z.number()),
      search_applied: opt(z.boolean()).describe("Whether a free-text search filtered this answer."),
    }),
    coverage: z.strictObject({
      total: z.number().nullable(),
      returned: z.number().nullable(),
      limit: z.number().nullable(),
      offset: z.number().nullable(),
      search_applied: z.boolean().nullable(),
    }),
    freshness: null,
  });

  // ── vendor_advisories_for_cve ──
  async function forCVE(cveArg: string): Promise<ToolResult> {
    const tool = "vendor_advisories_for_cve";
    const raw = cveArg.trim();
    if (!raw) return kit.badInput(tool, "cve_id is required");
    if (!CVE_ID.test(raw)) return kit.badInput(tool, "cve_id must be a CVE ID such as CVE-2024-21412");
    const cve = raw.toUpperCase();
    try {
      const r = await kit.api(`/api/v1/public/vendor-advisories/by-cve/${encodeURIComponent(cve)}`);
      if (!r.ok) return kit.failed(tool, r);
      const rows = rowsOf(r.data);
      const returned = rows?.length ?? null;
      const atCap = returned === null ? null : returned >= BY_CVE_CAP;
      const env: SuccessEnv = {
        state: "measured",
        measured_at: null,
        method: METHOD,
        coverage: { returned, cap: BY_CVE_CAP, at_cap: atCap },
        freshness: null,
        notes: [LIST_MEASURED_AT, NO_FRESHNESS, DATES],
      };
      const head = kit.okHead(tool, r.status);
      if (returned === 0) {
        return kit.succeeded(
          r.data,
          `${head} No vendor advisory on record names ${cve}: a measured empty result, EchelonGraph was queried successfully and found nothing (we looked and found nothing). This is not a lookup failure. ${ONLY_POLLED}`,
          env,
        );
      }
      if (rows === undefined) return kit.succeeded(r.data, head, env);
      const cap = atCap ? ` The API returns at most ${BY_CVE_CAP} advisories for one CVE, newest first, and this answer is full (at_cap true), so there may be more.` : "";
      return kit.succeeded(
        r.data,
        `${head} ${rows.length} vendor ${plural(rows.length, "advisory names", "advisories name")} ${cve}.${cap}${withdrawnNote(rows)} ${ONLY_POLLED}`,
        env,
      );
    } catch (e) {
      return kit.crashed(tool, e);
    }
  }

  // ── get_vendor_advisory ──
  async function detail(vendorArg: string, idArg: string): Promise<ToolResult> {
    const tool = "get_vendor_advisory";
    const vendor = vendorArg.trim();
    const id = idArg.trim();
    if (!vendor) return kit.badInput(tool, "vendor is required");
    if (!VENDOR_SLUG.test(vendor) || vendor.length > 64) return kit.badInput(tool, "vendor must be a vendor slug such as microsoft, redhat or github, as the advisory's vendor field gives it");
    if (!id) return kit.badInput(tool, "advisory_id is required");
    if (!ADVISORY_ID.test(id)) return kit.badInput(tool, "advisory_id must be the vendor's advisory ID (vendor_advisory_id), at most 200 characters, with no control characters");
    try {
      const r = await kit.api(`/api/v1/public/vendor-advisories/${encodeURIComponent(vendor)}/${encodeURIComponent(id)}`);
      if (!r.ok) return kit.failed(tool, r);
      const firstSeen = field(r.data, "our_first_seen_at");
      const cveIDs = field(r.data, "cve_ids");
      const known = field(r.data, "known_cve_ids");
      const env: SuccessEnv = {
        state: "measured",
        measured_at: realInstant(firstSeen) ? firstSeen : null,
        method: METHOD,
        coverage: null,
        freshness: null,
        notes: [
          realInstant(firstSeen)
            ? "measured_at is our_first_seen_at: when EchelonGraph first recorded this advisory."
            : "measured_at is null: the answer carries no real our_first_seen_at.",
          NO_FRESHNESS,
          DATES,
        ],
      };
      const shown = `${str(r.data, "vendor") ?? vendor}/${str(r.data, "vendor_advisory_id") ?? id}`;
      const withdrawn =
        field(r.data, "withdrawn") === true
          ? ` WITHDRAWN: the vendor withdrew (rescinded) ${shown} (withdrawn true${realInstant(field(r.data, "withdrawn_at")) ? `, withdrawn_at ${field(r.data, "withdrawn_at")}` : ""}). Report it as withdrawn, not as a current advisory.`
          : "";
      const cves =
        Array.isArray(cveIDs) && Array.isArray(known) && cveIDs.length > known.length
          ? ` Of the ${cveIDs.length} CVE IDs it lists (cve_ids), ${known.length} ${plural(known.length, "has", "have")} a record in EchelonGraph's CVE feed (known_cve_ids); the others have no record there yet, which does not mean they are not CVEs.`
          : "";
      return kit.succeeded(r.data, `${kit.okHead(tool, r.status)} Returned the advisory ${shown}.${withdrawn}${cves}`, env);
    } catch (e) {
      return kit.crashed(tool, e);
    }
  }

  // ── search_vendor_advisories ──
  type SearchArgs = { query?: string; vendor?: string; severity?: "Critical" | "High" | "Medium" | "Low"; has_cve?: boolean; limit?: number; offset?: number };
  async function search(a: SearchArgs): Promise<ToolResult> {
    const tool = "search_vendor_advisories";
    const query = (a.query ?? "").trim();
    if (Buffer.byteLength(query, "utf8") > SEARCH_MAX_BYTES) return kit.badInput(tool, `query is longer than the API's ${SEARCH_MAX_BYTES}-byte search limit`);
    const vendor = (a.vendor ?? "").trim();
    if (vendor && (!VENDOR_SLUG.test(vendor) || vendor.length > 64)) return kit.badInput(tool, "vendor must be a vendor slug such as microsoft, redhat or github");
    try {
      const q = new URLSearchParams();
      if (vendor) q.set("vendor", vendor);
      if (a.severity) q.set("severity", a.severity);
      if (a.has_cve !== undefined) q.set("has_cve", String(a.has_cve));
      q.set("limit", String(a.limit ?? 20));
      q.set("offset", String(a.offset ?? 0));
      // The term in the header only, never the URL (#1983).
      const headers: Record<string, string> = query ? { [VENDOR_ADVISORY_SEARCH_HEADER]: encodeURIComponent(query) } : {};
      const path = `/api/v1/public/vendor-advisories?${q.toString()}`;
      const r = await kit.api(path, { headers });
      if (!r.ok) return kit.failed(tool, r);
      const applied = field(r.data, "search_applied");
      if (query && applied !== true) {
        return kit.failed(tool, {
          ok: false,
          kind: "unexpected_shape",
          path,
          status: r.status,
          detail: `the answer does not say the search was applied (search_applied is ${applied === undefined ? "absent" : JSON.stringify(applied)}: an API that does not read the ${VENDOR_ADVISORY_SEARCH_HEADER} header answers the unsearched list), so it is not relayed as the search's matches`,
        });
      }
      const rows = rowsOf(r.data);
      const total = num(r.data, "total");
      const env: SuccessEnv = {
        state: "measured",
        measured_at: null,
        method: METHOD,
        coverage: {
          total: total ?? null,
          returned: rows?.length ?? null,
          limit: num(r.data, "limit") ?? null,
          offset: num(r.data, "offset") ?? null,
          search_applied: typeof applied === "boolean" ? applied : null,
        },
        freshness: null,
        notes: [
          LIST_MEASURED_AT,
          NO_FRESHNESS,
          DATES,
          "Advisories their vendor withdrew are left out of this list (withdrawn advisories stay reachable through get_vendor_advisory and vendor_advisories_for_cve).",
        ],
      };
      const head = kit.okHead(tool, r.status);
      const what = query ? "The search matched" : "The list holds";
      if (total === 0) {
        return kit.succeeded(
          r.data,
          `${head} ${what} 0 vendor advisories: a measured empty result, EchelonGraph was queried successfully and nothing matched these filters (we looked and found nothing). This is not a lookup failure. ${ONLY_POLLED}`,
          env,
        );
      }
      if (total === undefined) return kit.succeeded(r.data, head, env);
      const page = rows === undefined ? "" : `; ${rows.length} returned in this page (offset ${num(r.data, "offset") ?? a.offset ?? 0})`;
      return kit.succeeded(r.data, `${head} ${what} ${total} vendor ${plural(total, "advisory", "advisories")}${page}.`, env);
    } catch (e) {
      return kit.crashed(tool, e);
    }
  }

  server.registerTool(
    "vendor_advisories_for_cve",
    {
      title: "Vendor advisories for one CVE",
      description: `The vendor-published advisories that name one CVE, newest first, at most 20: for each, vendor, vendor_display_name, vendor_advisory_id, title, severity and cvss_v3_score where the vendor gives them. Covers the vendor feeds EchelonGraph polls, for example Microsoft MSRC, Red Hat, Cisco, Palo Alto Networks and GitHub GHSA; an empty answer means none of those names the CVE. ${DATES_DESCRIPTION} Pass a CVE ID like CVE-2024-21412. coverage gives returned, cap and at_cap (true: the answer is full, so there may be more). measured_at is null. ${ENVELOPE_DESCRIPTION}`,
      inputSchema: z.object({ cve_id: z.string().describe("a CVE ID, e.g. CVE-2024-21412") }),
      outputSchema: FOR_CVE_OUTPUT,
      annotations: kit.annotations,
    },
    async ({ cve_id }) => kit.checked("vendor_advisories_for_cve", FOR_CVE_OUTPUT, await forCVE(cve_id)),
  );

  server.registerTool(
    "get_vendor_advisory",
    {
      title: "Vendor advisory detail",
      description: `One vendor advisory in full, by vendor and the vendor's advisory ID (the vendor and vendor_advisory_id fields of a row from search_vendor_advisories or vendor_advisories_for_cve): title, description, severity, cvss_v3_score, cve_ids and known_cve_ids (those with a record in EchelonGraph's CVE feed), affected_products, remediation, references, vendor_modified_at, and withdrawn_at and withdrawn_reason when the vendor withdrew it. ${DATES_DESCRIPTION} measured_at is our_first_seen_at. ${ENVELOPE_DESCRIPTION}`,
      inputSchema: z.object({
        vendor: z.string().describe("the vendor slug, e.g. microsoft, redhat, github"),
        advisory_id: z.string().describe("the vendor's advisory ID, e.g. RHSA-2024:1234 or GHSA-xxxx-xxxx-xxxx"),
      }),
      outputSchema: DETAIL_OUTPUT,
      annotations: kit.annotations,
    },
    async ({ vendor, advisory_id }) => kit.checked("get_vendor_advisory", DETAIL_OUTPUT, await detail(vendor, advisory_id)),
  );

  server.registerTool(
    "search_vendor_advisories",
    {
      title: "Search vendor advisories",
      description: `Search or list vendor-published advisories, newest first. query is matched case-insensitively as a substring of each advisory's title, description, vendor name, vendor_advisory_id, affected_products and cve_ids; filter by vendor (slug), by severity band, and by whether the advisory names any CVE ID. Advisories their vendor withdrew are left out. Returns advisories, each with vendor, vendor_advisory_id, title, severity, cvss_v3_score, cve_ids, summary and affected_products where present, and the answer's total, limit, offset and search_applied. ${DATES_DESCRIPTION} The query is sent in a request header, never in the URL. coverage repeats total, limit, offset and search_applied, and gives returned, the rows in this page. measured_at is null. ${ENVELOPE_DESCRIPTION}`,
      inputSchema: z.object({
        query: z.string().optional().describe("free text, at most 100 bytes: a product, an advisory ID, a CVE ID or a keyword, e.g. 'exchange server'"),
        vendor: z.string().optional().describe("a vendor slug, e.g. microsoft, redhat, github"),
        severity: z.enum(["Critical", "High", "Medium", "Low"]).optional().describe("one severity band"),
        has_cve: z.boolean().optional().describe("true: only advisories naming a CVE; false: only those naming none"),
        limit: z.number().int().min(1).max(50).optional().describe("page size (default 20, max 50)"),
        offset: z.number().int().min(0).max(10000).optional().describe("rows to skip (default 0)"),
      }),
      outputSchema: SEARCH_OUTPUT,
      annotations: kit.annotations,
    },
    async (a) => kit.checked("search_vendor_advisories", SEARCH_OUTPUT, await search(a)),
  );
}
