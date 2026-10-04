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
// How a search matched (#2728). A term of one or two characters cannot use the API's trigram
// index, so the API matches it as a WHOLE WORD (a run of letters and digits) and says so with
// search_match "word"; a longer term is a substring, search_match "substring". And a search
// counts at most 1,000 matches: past that the API answers total 1000 with total_capped true. The
// tools relay both in coverage, the description states the whole-word rule, and a capped total is
// written "1,000+" in the note, never as an exact count.
//
// What is held of each vendor (#2729). What EchelonGraph holds of a vendor is not the vendor's
// whole history: Palo Alto's RSS feed carries only its ~25 newest updates, and MSRC's poller moved
// past documents it never read, so vendor_advisories_for_cve answered 0 for CVE-2024-3400 and
// CVE-2024-21412, which both vendors did publish advisories for. core-backend now reads those
// histories back (vendoradv backfill.go) and serves each vendor's window at
// /api/v1/public/vendor-advisories/coverage (coverage.go): advisories held, the earliest and latest
// vendor_published_at among them, and history_backfill. All three tools read it beside their own
// request and relay it in coverage, and the note says when a CVE's ID year begins before a
// vendor's earliest held advisory, or a vendor's history is still being read, so an empty answer
// is never read as "the vendor published none". The window is context, not the answer: when it
// cannot be read (an API older than the route, a failure), the answer is relayed as before, with
// the windows null and a note saying they are unknown, never failed. The coverage request carries
// nothing typed: a fixed path, no query, no search header.
//
// Logic only: the envelope, the failure contract and the API call are index.ts's, handed in as
// a VendorAdvisoryKit so this file cannot drift from them.
import * as z from "zod";
import type { McpServer, StandardSchemaWithJSON } from "@modelcontextprotocol/server";
import { TEXT_BUDGET_DESCRIPTION, type TextCut } from "../textBudget.js";

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
  // index.ts's one sentence for a failure: quoted when the vendors' windows cannot be read.
  describeFailure: (f: Failure) => string;
  badInput: (tool: string, why: string) => ToolResult;
  crashed: (tool: string, e: unknown) => ToolResult;
  succeeded: (data: object, note: string, env: SuccessEnv, cut?: TextCut) => ToolResult;
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
// #2729: every enabled vendor's window (handler.go CoverageHandler).
export const VENDOR_COVERAGE_PATH = "/api/v1/public/vendor-advisories/coverage";
// history_backfill values that mean the vendor's older advisories are not all held yet
// (backfill.go backfillStatus).
const BACKFILLING = new Set(["in_progress", "not_started"]);

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

// ── Each vendor's window (#2729) ──

// One vendor's window as relayed in coverage: the API's row, its "" dates as null.
type VendorWindow = {
  vendor: string;
  vendor_display_name: string | null;
  advisories: number | null;
  earliest_vendor_published_at: string | null;
  latest_vendor_published_at: string | null;
  history_backfill: string | null;
};
// The windows, or why there are none.
type Windows = { ok: true; windows: VendorWindow[] } | { ok: false; why: string };

const instantOrNull = (o: unknown, k: string): string | null => {
  const v = field(o, k);
  return realInstant(v) ? v : null;
};

// The /coverage answer's rows; undefined when it carries no vendors list. A row without a vendor
// slug cannot be named, so it is left out.
function windowsOf(d: unknown): VendorWindow[] | undefined {
  const rows = field(d, "vendors");
  if (!Array.isArray(rows)) return undefined;
  return rows.flatMap((r) => {
    const vendor = str(r, "vendor");
    if (!vendor) return [];
    return [
      {
        vendor,
        vendor_display_name: str(r, "vendor_display_name") ?? null,
        advisories: num(r, "advisories") ?? null,
        earliest_vendor_published_at: instantOrNull(r, "earliest_vendor_published_at"),
        latest_vendor_published_at: instantOrNull(r, "latest_vendor_published_at"),
        history_backfill: str(r, "history_backfill") ?? null,
      },
    ];
  });
}

const day = (instant: string) => instant.slice(0, 10);
const backfilling = (w: VendorWindow) => w.history_backfill !== null && BACKFILLING.has(w.history_backfill);
// What a note says of one window: what is held, and the history read when it is not done.
const windowItem = (w: VendorWindow, heldOnly: boolean) => {
  const held =
    w.earliest_vendor_published_at === null
      ? "none held"
      : `held ${heldOnly ? "only " : ""}from ${day(w.earliest_vendor_published_at)}${w.latest_vendor_published_at ? ` to ${day(w.latest_vendor_published_at)}` : ""}`;
  return `${w.vendor} (${held}${backfilling(w) ? `; history_backfill ${w.history_backfill}` : ""})`;
};

// The sentence for windows that could not be read: no "none here" is a finding about a vendor.
const windowsUnknown = (why: string) =>
  ` The vendors' coverage windows could not be read (${why}), so this answer cannot say from what date each vendor's advisories are held: no advisory here from a vendor is not a finding that it published none.`;

// vendor_advisories_for_cve: the vendors with no advisory in the answer that may have published
// one EchelonGraph does not hold: none held at all, the earliest held dated after 1 January of the
// year in the CVE ID, or a history still being read.
function notFullyHeld(windows: VendorWindow[], rows: unknown[], year: number): VendorWindow[] {
  const answered = new Set(rows.map((r) => str(r, "vendor")).filter((v): v is string => v !== undefined));
  const yearStart = Date.UTC(year, 0, 1);
  return windows.filter(
    (w) => !answered.has(w.vendor) && (w.earliest_vendor_published_at === null || Date.parse(w.earliest_vendor_published_at) > yearStart || backfilling(w)),
  );
}

function notFullyHeldNote(cve: string, year: number, missing: VendorWindow[]): string {
  if (!missing.length) return "";
  const k = missing.length;
  const yearStart = Date.UTC(year, 0, 1);
  const items = missing.map((w) => windowItem(w, w.earliest_vendor_published_at !== null && Date.parse(w.earliest_vendor_published_at) > yearStart));
  return ` ${cve} is a ${year} CVE ID, and EchelonGraph may not hold every advisory ${plural(k, "1 vendor", `${k} vendors`)} published for it (vendors_not_fully_held): ${items.join("; ")}. An advisory a vendor published before the earliest one EchelonGraph holds is not held, and while history_backfill is in_progress or not_started the vendor's older advisories are still being read, so no advisory here from ${plural(k, "that vendor", "those vendors")} is not a finding that ${plural(k, "it", "they")} published none.`;
}

// search_vendor_advisories and get_vendor_advisory: the vendors whose history is still being read.
function backfillingNote(windows: VendorWindow[]): string {
  const b = windows.filter(backfilling);
  if (!b.length) return "";
  const k = b.length;
  return ` The older advisories of ${plural(k, "1 vendor", `${k} vendors`)} are still being read (history_backfill in_progress or not_started): ${b.map((w) => windowItem(w, false)).join("; ")}. EchelonGraph does not yet hold all of ${plural(k, "its", "their")} older advisories, so none found from ${plural(k, "it", "them")} is not a finding that ${plural(k, "it", "they")} published none.`;
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
// #2729: what a vendor's window is.
const HISTORY_BACKFILL_DESCRIPTION =
  "history_backfill: complete (the vendor's published history has been read back as far as its source goes), in_progress or not_started (it is still being read, so the vendor's older advisories are not all held yet), or not_supported (EchelonGraph has no history read for that vendor, so what it holds is what the vendor's feed has carried)";
const WINDOW_DESCRIPTION = `vendor, advisories (how many EchelonGraph holds from that vendor), earliest_vendor_published_at and latest_vendor_published_at (the earliest and latest vendor_published_at among them, null when none is held) and ${HISTORY_BACKFILL_DESCRIPTION}`;
const NOT_HELD_DESCRIPTION =
  "An advisory a vendor published before its earliest_vendor_published_at is not held, so no advisory from a vendor is not a finding that it published none.";
// #2728: how a search matches, and its capped total.
const SEARCH_MATCH_DESCRIPTION =
  "A query of 3 or more characters is matched case-insensitively as a substring of each advisory's title, description, vendor name, vendor_advisory_id, affected_products and cve_ids (search_match substring). A query of 1 or 2 characters matches whole words only (search_match word): it must equal, ignoring case, a whole word (a run of letters and digits) of one of those, so xz finds xz-utils but not xzibit, and a 1- or 2-character query with any other character, such as c#, matches nothing.";
const TOTAL_CAPPED_DESCRIPTION =
  "A search counts at most 1,000 matches: past that, total is 1000 and total_capped is true, which means 1,000 or more (the note writes 1,000+), never exactly 1,000; paging past it still works. Without a query, total is the exact count and total_capped is false.";

const VendorWindowSchema = z.strictObject({
  vendor: z.string().describe("The vendor slug."),
  vendor_display_name: z.string().nullable(),
  advisories: z.number().nullable().describe("How many advisories EchelonGraph holds from this vendor, withdrawn ones not counted."),
  earliest_vendor_published_at: z
    .string()
    .nullable()
    .describe("The earliest vendor_published_at among them; null when none is held. An advisory this vendor published before it is not held."),
  latest_vendor_published_at: z.string().nullable().describe("The latest vendor_published_at among them; null when none is held."),
  // The four values the API sends today, and any later one as a string: a new state must not turn
  // the answer into a failure.
  history_backfill: z
    .union([z.enum(["complete", "in_progress", "not_started", "not_supported"]), z.string()])
    .nullable()
    .describe(`${HISTORY_BACKFILL_DESCRIPTION}.`),
});
const WINDOWS = z.array(VendorWindowSchema).nullable().describe(`Each vendor's window in what EchelonGraph holds; null when the windows could not be read. ${NOT_HELD_DESCRIPTION}`);

// #2783: a production row is up to about 2,000 characters as pretty JSON (its summary, its
// affected_products and, for a library like log4j, dozens of cve_ids), so search_vendor_advisories
// "log4j" at limit 50 was 103,147 characters of text. Past DATA_TEXT_BUDGET each row in the first
// text block keeps what identifies and rates the advisory, every string cut to 200 characters and
// every list to 20 entries; then fewer fields, strings to 100 and lists to 10.
const ROW_CUT_LEVELS: TextCut["levels"] = [
  { keep: ["vendor", "vendor_display_name", "vendor_advisory_id", "title", "severity", "cvss_v3_score", "cve_ids", "summary", "affected_products", "vendor_published_at", "withdrawn"], clip: 200, cap: 20 },
  { keep: ["vendor", "vendor_advisory_id", "title", "severity", "cve_ids", "vendor_published_at", "withdrawn"], clip: 100, cap: 10 },
];
const WHOLE = "get_vendor_advisory returns any one of these advisories whole, by its vendor and vendor_advisory_id.";
const FOR_CVE_TEXT: TextCut = { rows: "advisories", levels: ROW_CUT_LEVELS, whole: WHOLE };
const searchText = (a: { offset?: number }): TextCut => ({
  rows: "advisories",
  levels: ROW_CUT_LEVELS,
  whole: WHOLE,
  page: (shown, _rows, d) =>
    `To read the rows left out in the text, call search_vendor_advisories again with the same arguments and offset ${(num(d, "offset") ?? a.offset ?? 0) + shown}; a page of ${shown} rows or fewer like these fits the text without leaving rows out.`,
});
const ROW_CUT_DESCRIPTION = " Cut, each row keeps vendor, vendor_advisory_id, title, severity and cve_ids at least, its strings and lists shortened";

export function registerVendorAdvisoryTools(server: McpServer, kit: VendorAdvisoryKit): void {
  const FOR_CVE_OUTPUT = kit.envelopeSchema({
    data: z.looseObject({ cve_id: opt(z.string()), advisories: opt(z.array(AdvisoryRow)), total: opt(z.number()) }),
    coverage: z.strictObject({
      returned: z.number().nullable().describe("The advisories in this answer."),
      cap: z.number().describe("The most the API returns for one CVE, newest first."),
      at_cap: z.boolean().nullable().describe("true: the answer is full, so the vendor feeds may hold more advisories for this CVE than it lists."),
      cve_year: z.number().describe("The year in the CVE ID."),
      vendor_windows: WINDOWS,
      vendors_not_fully_held: z
        .array(z.string())
        .nullable()
        .describe(
          "The vendors with no advisory in this answer that may have published one EchelonGraph does not hold: none held, the earliest held dated after 1 January of cve_year, or history_backfill in_progress or not_started. No advisory from them is not a finding that they published none. null when the windows could not be read.",
        ),
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
    coverage: z.strictObject({
      vendor_window: VendorWindowSchema.nullable().describe("This advisory's vendor's window in what EchelonGraph holds; null when the windows could not be read or carry none for this vendor."),
    }),
    freshness: null,
  });
  const SEARCH_OUTPUT = kit.envelopeSchema({
    data: z.looseObject({
      advisories: opt(z.array(AdvisoryRow)),
      total: opt(z.number()).describe("The matches; when total_capped is true, a lower bound: 1,000 or more."),
      limit: opt(z.number()),
      offset: opt(z.number()),
      search_applied: opt(z.boolean()).describe("Whether a free-text search filtered this answer."),
      search_match: opt(z.string()).describe("How the query was matched: word (a query of 1 or 2 characters, whole words only) or substring; null without a query."),
      total_capped: opt(z.boolean()).describe("true: the search stopped counting at total, so total is a lower bound (1,000+), not the count."),
    }),
    coverage: z.strictObject({
      total: z.number().nullable().describe("The API's total; when total_capped is true, a lower bound, not the count."),
      total_capped: z.boolean().nullable().describe("true: total is the API's cap on a search's count, so 1,000 or more match."),
      returned: z.number().nullable(),
      limit: z.number().nullable(),
      offset: z.number().nullable(),
      search_applied: z.boolean().nullable(),
      search_match: z.enum(["word", "substring"]).nullable().describe("word: a query of 1 or 2 characters, matched as a whole word only; substring: a longer query; null without a query."),
      vendor_windows: WINDOWS,
    }),
    freshness: null,
  });

  // The vendors' windows, read beside a tool's own request. Never a failure of the tool.
  async function readWindows(): Promise<Windows> {
    const r = await kit.api(VENDOR_COVERAGE_PATH);
    if (!r.ok) return { ok: false, why: kit.describeFailure(r).replace(/\.$/, "") };
    const windows = windowsOf(r.data);
    return windows ? { ok: true, windows } : { ok: false, why: `the answer of GET ${VENDOR_COVERAGE_PATH} carries no vendors list` };
  }

  // ── vendor_advisories_for_cve ──
  async function forCVE(cveArg: string): Promise<ToolResult> {
    const tool = "vendor_advisories_for_cve";
    const raw = cveArg.trim();
    if (!raw) return kit.badInput(tool, "cve_id is required");
    if (!CVE_ID.test(raw)) return kit.badInput(tool, "cve_id must be a CVE ID such as CVE-2024-21412");
    const cve = raw.toUpperCase();
    const year = Number(cve.slice(4, 8));
    try {
      const windowsRead = readWindows();
      const r = await kit.api(`/api/v1/public/vendor-advisories/by-cve/${encodeURIComponent(cve)}`);
      if (!r.ok) return kit.failed(tool, r);
      const w = await windowsRead;
      const rows = rowsOf(r.data);
      const returned = rows?.length ?? null;
      const atCap = returned === null ? null : returned >= BY_CVE_CAP;
      const missing = w.ok ? notFullyHeld(w.windows, rows ?? [], year) : null;
      const env: SuccessEnv = {
        state: "measured",
        measured_at: null,
        method: METHOD,
        coverage: {
          returned,
          cap: BY_CVE_CAP,
          at_cap: atCap,
          cve_year: year,
          vendor_windows: w.ok ? w.windows : null,
          vendors_not_fully_held: missing ? missing.map((m) => m.vendor) : null,
        },
        freshness: null,
        notes: [LIST_MEASURED_AT, NO_FRESHNESS, DATES],
      };
      const head = kit.okHead(tool, r.status);
      const held = w.ok ? notFullyHeldNote(cve, year, missing ?? []) : windowsUnknown(w.why);
      if (returned === 0) {
        return kit.succeeded(
          r.data,
          `${head} No vendor advisory on record names ${cve}: a measured empty result, EchelonGraph was queried successfully and found nothing (we looked and found nothing). This is not a lookup failure. ${ONLY_POLLED}${held}`,
          env,
          FOR_CVE_TEXT,
        );
      }
      if (rows === undefined) return kit.succeeded(r.data, `${head}${held}`, env, FOR_CVE_TEXT);
      const cap = atCap ? ` The API returns at most ${BY_CVE_CAP} advisories for one CVE, newest first, and this answer is full (at_cap true), so there may be more.` : "";
      return kit.succeeded(
        r.data,
        `${head} ${rows.length} vendor ${plural(rows.length, "advisory names", "advisories name")} ${cve}.${cap}${withdrawnNote(rows)} ${ONLY_POLLED}${held}`,
        env,
        FOR_CVE_TEXT,
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
      const windowsRead = readWindows();
      const r = await kit.api(`/api/v1/public/vendor-advisories/${encodeURIComponent(vendor)}/${encodeURIComponent(id)}`);
      if (!r.ok) return kit.failed(tool, r);
      const w = await windowsRead;
      const firstSeen = field(r.data, "our_first_seen_at");
      const cveIDs = field(r.data, "cve_ids");
      const known = field(r.data, "known_cve_ids");
      const slug = str(r.data, "vendor") ?? vendor;
      const window = w.ok ? (w.windows.find((x) => x.vendor === slug) ?? null) : null;
      const env: SuccessEnv = {
        state: "measured",
        measured_at: realInstant(firstSeen) ? firstSeen : null,
        method: METHOD,
        coverage: { vendor_window: window },
        freshness: null,
        notes: [
          realInstant(firstSeen)
            ? "measured_at is our_first_seen_at: when EchelonGraph first recorded this advisory."
            : "measured_at is null: the answer carries no real our_first_seen_at.",
          NO_FRESHNESS,
          DATES,
        ],
      };
      const shown = `${slug}/${str(r.data, "vendor_advisory_id") ?? id}`;
      const withdrawn =
        field(r.data, "withdrawn") === true
          ? ` WITHDRAWN: the vendor withdrew (rescinded) ${shown} (withdrawn true${realInstant(field(r.data, "withdrawn_at")) ? `, withdrawn_at ${field(r.data, "withdrawn_at")}` : ""}). Report it as withdrawn, not as a current advisory.`
          : "";
      const cves =
        Array.isArray(cveIDs) && Array.isArray(known) && cveIDs.length > known.length
          ? ` Of the ${cveIDs.length} CVE IDs it lists (cve_ids), ${known.length} ${plural(known.length, "has", "have")} a record in EchelonGraph's CVE feed (known_cve_ids); the others have no record there yet, which does not mean they are not CVEs.`
          : "";
      const held = !w.ok ? windowsUnknown(w.why) : window ? backfillingNote([window]) : "";
      return kit.succeeded(r.data, `${kit.okHead(tool, r.status)} Returned the advisory ${shown}.${withdrawn}${cves}${held}`, env);
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
      const windowsRead = readWindows();
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
      const w = await windowsRead;
      // With a vendor filter, only that vendor's window.
      const windows = w.ok ? w.windows.filter((x) => !vendor || x.vendor === vendor) : null;
      const rows = rowsOf(r.data);
      const total = num(r.data, "total");
      const capped = field(r.data, "total_capped");
      const isCapped = capped === true && total !== undefined && total > 0;
      const match = field(r.data, "search_match");
      const env: SuccessEnv = {
        state: "measured",
        measured_at: null,
        method: METHOD,
        coverage: {
          total: total ?? null,
          total_capped: typeof capped === "boolean" ? capped : null,
          returned: rows?.length ?? null,
          limit: num(r.data, "limit") ?? null,
          offset: num(r.data, "offset") ?? null,
          search_applied: typeof applied === "boolean" ? applied : null,
          search_match: match === "word" || match === "substring" ? match : null,
          vendor_windows: windows,
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
      // How the term was matched: a short term is whole words only. The term itself is never written.
      const wordOnly =
        query && match === "word"
          ? " The query is 1 or 2 characters, so it matched whole words only (search_match word): an advisory matches when the query equals, ignoring case, a whole word (a run of letters and digits) of its title, description, vendor_advisory_id, an affected product, a CVE ID or its vendor's name, never part of a longer word."
          : "";
      const held = !w.ok ? windowsUnknown(w.why) : backfillingNote(windows ?? []);
      if (total === 0) {
        return kit.succeeded(
          r.data,
          `${head} ${what} 0 vendor advisories: a measured empty result, EchelonGraph was queried successfully and nothing matched these filters (we looked and found nothing). This is not a lookup failure. ${ONLY_POLLED}${wordOnly}${held}`,
          env,
          searchText(a),
        );
      }
      if (total === undefined) return kit.succeeded(r.data, `${head}${wordOnly}${held}`, env, searchText(a));
      const page = rows === undefined ? "" : `; ${rows.length} returned in this page (offset ${num(r.data, "offset") ?? a.offset ?? 0})`;
      // A capped total is a lower bound: written "1,000+", never as the count.
      const counted = isCapped
        ? `${total.toLocaleString("en-US")}+ vendor advisories (total_capped true: the API stops counting a search's matches at ${total.toLocaleString("en-US")}, so total is a lower bound, not the count; paging past it still works)`
        : `${total} vendor ${plural(total, "advisory", "advisories")}`;
      return kit.succeeded(r.data, `${head} ${what} ${counted}${page}.${wordOnly}${held}`, env, searchText(a));
    } catch (e) {
      return kit.crashed(tool, e);
    }
  }

  server.registerTool(
    "vendor_advisories_for_cve",
    {
      title: "Vendor advisories for one CVE",
      description: `The vendor-published advisories that name one CVE, newest first, at most 20: for each, vendor, vendor_display_name, vendor_advisory_id, title, severity and cvss_v3_score where the vendor gives them. Covers the vendor feeds EchelonGraph polls, for example Microsoft MSRC, Red Hat, Cisco, Palo Alto Networks and GitHub GHSA; an empty answer means that none of the advisories EchelonGraph holds from those feeds names the CVE, not that no vendor published one (see vendor_windows and vendors_not_fully_held). ${DATES_DESCRIPTION} Pass a CVE ID like CVE-2024-21412. coverage gives returned, cap and at_cap (true: the answer is full, so there may be more); cve_year, the year in the CVE ID; vendor_windows, each vendor's window in what EchelonGraph holds: ${WINDOW_DESCRIPTION}; and vendors_not_fully_held, the vendors with no advisory in the answer of which EchelonGraph holds none, whose earliest held advisory is dated after 1 January of cve_year, or whose history is still being read, which the note names. ${NOT_HELD_DESCRIPTION} vendor_windows and vendors_not_fully_held are null when the windows could not be read, and the note says so. measured_at is null. ${ENVELOPE_DESCRIPTION} ${TEXT_BUDGET_DESCRIPTION}${ROW_CUT_DESCRIPTION}.`,
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
      description: `One vendor advisory in full, by vendor and the vendor's advisory ID (the vendor and vendor_advisory_id fields of a row from search_vendor_advisories or vendor_advisories_for_cve): title, description, severity, cvss_v3_score, cve_ids and known_cve_ids (those with a record in EchelonGraph's CVE feed), affected_products, remediation, references, vendor_modified_at, and withdrawn_at and withdrawn_reason when the vendor withdrew it. ${DATES_DESCRIPTION} coverage.vendor_window is that vendor's window in what EchelonGraph holds: ${WINDOW_DESCRIPTION}; null when the windows could not be read or carry none for that vendor. measured_at is our_first_seen_at. ${ENVELOPE_DESCRIPTION} ${TEXT_BUDGET_DESCRIPTION}`,
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
      description: `Search or list vendor-published advisories, newest first. ${SEARCH_MATCH_DESCRIPTION} Filter by vendor (slug), by severity band, and by whether the advisory names any CVE ID. Advisories their vendor withdrew are left out. Returns advisories, each with vendor, vendor_advisory_id, title, severity, cvss_v3_score, cve_ids, summary and affected_products where present, and the answer's total, total_capped, limit, offset, search_applied and search_match. ${TOTAL_CAPPED_DESCRIPTION} ${DATES_DESCRIPTION} The query is sent in a request header, never in the URL. coverage repeats total, total_capped, limit, offset, search_applied and search_match, and gives returned, the rows in this page, and vendor_windows, each vendor's window in what EchelonGraph holds (only that vendor's when vendor is given): ${WINDOW_DESCRIPTION}. ${NOT_HELD_DESCRIPTION} measured_at is null. ${ENVELOPE_DESCRIPTION} ${TEXT_BUDGET_DESCRIPTION}${ROW_CUT_DESCRIPTION}, or rows are left out and the note gives the offset to call next.`,
      inputSchema: z.object({
        query: z.string().optional().describe("free text, at most 100 bytes: a product, an advisory ID, a CVE ID or a keyword, e.g. 'exchange server'; 1 or 2 characters match whole words only"),
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
