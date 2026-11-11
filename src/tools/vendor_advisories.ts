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
// the note names each one. rejected_cve_ids (#2865) is separate from it: the CVE IDs a row names
// whose CVE record was rejected by its numbering authority, while the vendor's own document may
// still read as live; the note names those rows and the by-cve answer's cve_rejected. Advisories
// of a vendor feed EchelonGraph has disabled are left out of all three. freshness is null: no answer has one
// poll time, and each vendor's last successful poll is its window's last_success_at (#3464, below).
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
// vendor_published_at among them, held_since and history_backfill. All three tools read it beside
// their own request and relay it in coverage, and the note says when a CVE's ID year begins before
// the date a vendor is held from, or a vendor's history is still being read, so an empty answer
// is never read as "the vendor published none".
//
// held_since, not the earliest held advisory, is where a vendor's window begins (#2803). A vendor
// with no history read (history_backfill not_supported) is held from its poller's first poll on,
// and Cisco's and Red Hat's first polls read only what the vendor had CHANGED lately: an old
// advisory the vendor revised since is held, so the earliest held advisory reached back to 2024
// for Cisco and 2009 for Red Hat while the advisories published beside it are not held, and
// CVE-2025-20188 read Cisco as fully held for 2025. coverage.go serves held_since as the start of
// the window EchelonGraph has read the vendor's advisories from; an API older than that field gives none, and a vendor is
// then taken as held from its earliest advisory only when its history read is complete.
//
// A history read can cover only part of a vendor's advisories (#3472). GitHub's (#3443) reads its
// REVIEWED advisories only: once done, history_backfill is complete_reviewed_only and held_since the
// earliest advisory held (2017-10-24 on 2026-11-07), while the unreviewed ones (about 361K, not read
// back) are held only from feed_held_since, the start of the feed's own window (2026-05-15).
// coverage.go serves history_scope ("all", "reviewed"; "" without a history read) and
// feed_held_since beside it. Read from held_since alone, GitHub was fully held for every CVE year
// from 2018, while an unreviewed advisory it published before 2026-05-15 may not be held: a vendor
// whose history_scope is a part is fully held for a year only when feed_held_since is on or before
// the year's start too, and the note gives both dates. An API without the two fields reads as before.
//
// A window says nothing of whether the vendor is still being collected (#3464). Cisco's polls were
// refused from 2026-10-12T12:52:55Z, and for 20 days its window read "held to 2026-10-07" here as
// if it were current. coverage.go now serves, from the rule the feed-state alert pages on
// (feed_state.go feedState), each vendor's last_success_at and collection_state: ok; partial (its
// polls succeed, but held_back of the documents it lists could not be used, the oldest since
// held_back_since: those may not be held, the rest of its feed is); failing (failing_since is its
// last successful poll, and what it published after that may not be held, whatever the window says);
// or disabled (this deployment runs no collector for it, so its window ends at last_success_at).
// The tools relay the five fields in each window, the note names each vendor whose state is not ok
// with its date (collectionNote), and vendor_advisories_for_cve lists such a vendor in
// vendors_not_fully_held for any CVE year. A state the API adds later is not read as ok. An API
// without the fields relays them null and reads as before.
//
// Every field the coverage row carries is read here or named in VENDOR_COVERAGE_NOT_RELAYED with why
// (#3628): test/vendor-coverage-fields.test.mjs holds that to docs/api/openapi.yaml's vendor item, so
// a field the API adds is a decision here, not a gap found weeks later (history_scope and
// feed_held_since, #3472; the five above, #3464).
//
// The window is context, not the answer: when it cannot be read (an API older than the route, a failure), the answer is relayed as before, with
// the windows null and a note saying they are unknown, never failed. The coverage request carries
// nothing typed: a fixed path, no query, no search header.
//
// Logic only: the envelope, the failure contract and the API call are index.ts's, handed in as
// a VendorAdvisoryKit so this file cannot drift from them.
import * as z from "zod";
import type { McpServer, StandardSchemaWithJSON } from "@modelcontextprotocol/server";
import { answering, FULL_ARG, NO_DATA_CUT, TEXT_BUDGET_DESCRIPTION, wholePage, type DataCut, type RowKeep, type TextCut } from "../textBudget.js";

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
  // #3011: a refusal worded by this file (index.ts failure), for the one the API's answer decides.
  failure: (state: "failed" | "invalid_input", message: string, error: { kind: "invalid_input"; path: string | null; status: number | null; message: string }) => ToolResult;
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
// #3472: history_backfill values of a finished history read: complete, and complete_reviewed_only,
// which read back GitHub's reviewed advisories only (its history_scope says the same).
const HISTORY_READ = new Set(["complete", "complete_reviewed_only"]);
// #3464: the collection_state values the API sends (feed_state.go FeedState*); any other is relayed as
// sent and read as not known to be collected, never as ok.
export const COLLECTION_STATES = ["ok", "partial", "failing", "disabled"] as const;
// #3628: the coverage row's fields this file does not relay, each with why. Every other field of the
// row (docs/api/openapi.yaml's vendor item) is read by windowsOf: test/vendor-coverage-fields.test.mjs
// fails on a field that is neither.
export const VENDOR_COVERAGE_NOT_RELAYED: Readonly<Record<string, string>> = {
  history_units_done:
    "the history read's bookkeeping, how many units of the vendor's archive it has read so far: history_backfill says whether the read is done, and the count bounds no window",
  history_completed_at:
    "when the history read finished: history_backfill complete or complete_reviewed_only says that it has, and held_since where the window it read begins; the finish time bounds no window",
};

const CVE_ID = /^CVE-\d{4}-\d{4,}$/i;
// vendors.slug's CHECK constraint (migration 063).
const VENDOR_SLUG = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
// No control characters (a header or log line could carry them), at most 200 characters.
const ADVISORY_ID = /^[^\x00-\x1f\x7f]{1,200}$/;
// #3011: a row's advisory_id is EchelonGraph's own ID for the advisory, a UUID (vendor_advisories,
// migration 063). The detail route is keyed on the vendor's ID, vendor_advisory_id (handler.go
// Detail, store.go GetAdvisoryByVendorAndID: WHERE v.slug = $1 AND va.vendor_advisory_id = $2), and
// the API has no route by the UUID, so get_vendor_advisory given a row's advisory_id answered a
// 404, worded as no record, for an advisory the API holds (CVE-2024-3400's Palo Alto row,
// a68d033b-5d1e-4537-8190-5e37897a27e8, 2026-10-10). A vendor's own ID could have that shape too, so
// the API is still asked; only its 404 for an ID of that shape is answered as the refusal it is.
const INTERNAL_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// What a row's two IDs are, in the outputSchema of all three tools (the detail echoes advisory_id).
// Facts only, naming no other tool (test/description-policy.test.mjs: the MCP Directory policy).
const ROW_ADVISORY_ID_FIELD =
  "EchelonGraph's internal ID for this advisory, a UUID. It is not the vendor's advisory ID (vendor_advisory_id), and an advisory's detail is not looked up by it: the detail is keyed on vendor and vendor_advisory_id.";
const VENDOR_ADVISORY_ID_FIELD =
  "The vendor's own ID for the advisory (e.g. RHSA-2024:1234, GHSA-xxxx-xxxx-xxxx, or the CVE ID for Microsoft and Palo Alto Networks). With vendor, it is the key an advisory's detail is looked up by, as its advisory_id argument.";

const METHOD =
  "EchelonGraph's vendor-advisory feed: advisories as each vendor published them in its own feed (for example Microsoft MSRC, Red Hat, Cisco, Palo Alto Networks and GitHub GHSA), each feed polled on a schedule; advisories of a feed EchelonGraph has disabled are left out.";
const NO_FRESHNESS = "freshness is null: these answers carry no time at which the vendor-advisory pollers last completed a poll.";
// #3464: once the windows carry last_success_at, the answer does carry poll times, one per vendor.
const PER_VENDOR_FRESHNESS =
  "freshness is null: the answer has no single poll time; each vendor's last successful poll is its window's last_success_at in coverage, and its collection_state says whether it is being collected now, by EchelonGraph's feed-state rule.";
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
const listed = (xs: string[]) => (xs.length <= 1 ? (xs[0] ?? "") : `${xs.slice(0, -1).join(", ")} and ${xs.at(-1)}`);

// Each withdrawn row named by vendor and id: report it as withdrawn, never as a current advisory.
function withdrawnNote(rows: unknown[]): string {
  const w = rows.flatMap((r, i) => (field(r, "withdrawn") === true ? [`${str(r, "vendor") ?? "?"}/${str(r, "vendor_advisory_id") ?? `advisories[${i}]`}`] : []));
  if (!w.length) return "";
  return ` WITHDRAWN: ${w.length} of these ${rows.length} ${plural(rows.length, "advisory", "advisories")} ${plural(w.length, "was", "were")} withdrawn (rescinded) by ${plural(w.length, "its", "their")} vendor (withdrawn true): ${w.join(", ")}. Report ${plural(w.length, "it", "them")} as withdrawn, not as a current advisory.`;
}

// #2865: a vendor advisory can name a CVE ID its numbering authority rejected while the vendor's own
// text still reads as a live advisory (CVE-2026-7936's MSRC entry). core-backend serves
// rejected_cve_ids, the CVE IDs of the row whose CVE record was rejected, beside the vendor's own
// withdrawn, which it leaves as the vendor set it. A row the vendor withdrew is named by
// withdrawnNote already, so this names the live ones.
const rejectedIDs = (r: unknown): string[] => {
  const v = field(r, "rejected_cve_ids");
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && x !== "") : [];
};
function rejectedCVENote(rows: unknown[]): string {
  const hit = rows.flatMap((r, i) =>
    field(r, "withdrawn") !== true && rejectedIDs(r).length
      ? [`${str(r, "vendor") ?? "?"}/${str(r, "vendor_advisory_id") ?? `advisories[${i}]`} (${rejectedIDs(r).join(", ")})`]
      : [],
  );
  if (!hit.length) return "";
  const k = hit.length;
  return ` CVE REJECTED: ${k} of these ${rows.length} ${plural(rows.length, "advisory", "advisories")}, not withdrawn by ${plural(k, "its", "their")} vendor, ${plural(k, "names", "name")} a CVE ID whose CVE record was rejected (withdrawn) by its numbering authority (rejected_cve_ids): ${hit.join("; ")}. Report each such CVE ID as a rejected record, not as an active vulnerability, even where the vendor's text reads as a current advisory.`;
}
// The rows' rejected_cve_ids could not be checked (null on every row that names a CVE).
function rejectedUnknownNote(rows: unknown[]): string {
  const unknown = rows.filter((r) => Array.isArray(field(r, "cve_ids")) && (field(r, "cve_ids") as unknown[]).length > 0 && field(r, "rejected_cve_ids") === null);
  if (!unknown.length) return "";
  return ` For ${unknown.length} of these advisories rejected_cve_ids is null: whether a CVE ID they name was rejected could not be checked, which is not a finding that none was.`;
}

// ── Each vendor's window (#2729) ──

// One vendor's window as relayed in coverage: the API's row, its "" dates as null.
type VendorWindow = {
  vendor: string;
  vendor_display_name: string | null;
  advisories: number | null;
  earliest_vendor_published_at: string | null;
  latest_vendor_published_at: string | null;
  held_since: string | null;
  // #3472: the start of the window the vendor's own feed has read every one of its advisories from;
  // null from an API older than the field.
  feed_held_since: string | null;
  history_backfill: string | null;
  // #3472: what the history read covers: "all", or a part such as "reviewed"; null without a
  // history read or from an API older than the field.
  history_scope: string | null;
  // #3464: the vendor's last successful poll; null when none is on record or from an API older than
  // the field.
  last_success_at: string | null;
  // #3464: ok, partial, failing, disabled, or a later value as sent; null from an older API.
  collection_state: string | null;
  // #3464: while failing, the last successful poll; null otherwise.
  failing_since: string | null;
  // #3197: how many of the documents the vendor lists are held back, and since when the oldest failed.
  held_back: number | null;
  held_back_since: string | null;
};
// The windows, or why there are none.
type Windows = { ok: true; windows: VendorWindow[] } | { ok: false; why: string };

const instantOrNull = (o: unknown, k: string): string | null => {
  const v = field(o, k);
  return realInstant(v) ? v : null;
};

// The /coverage answer's rows; undefined when it carries no vendors list. A row without a vendor
// slug cannot be named, so it is left out. Each field relayed has the row's own name (#3628's check
// reads a field as read when the window carries it under that name).
export function windowsOf(d: unknown): VendorWindow[] | undefined {
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
        held_since: instantOrNull(r, "held_since"),
        feed_held_since: instantOrNull(r, "feed_held_since"),
        history_backfill: str(r, "history_backfill") ?? null,
        history_scope: str(r, "history_scope") ?? null,
        last_success_at: instantOrNull(r, "last_success_at"),
        collection_state: str(r, "collection_state") ?? null,
        failing_since: instantOrNull(r, "failing_since"),
        held_back: num(r, "held_back") ?? null,
        held_back_since: instantOrNull(r, "held_back_since"),
      },
    ];
  });
}

const day = (instant: string) => instant.slice(0, 10);
const backfilling = (w: VendorWindow) => w.history_backfill !== null && BACKFILLING.has(w.history_backfill);
// #2803: the start of the window a vendor's advisories have been read from: held_since as the API
// gives it; from an API without it, the earliest held advisory when the vendor's history read is
// complete (that is the archive's start), else unknown (null). #3472: complete_reviewed_only is a
// finished read too, of the part of the vendor's advisories history_scope names; from when the rest
// is held is restHeldFromYear's.
const heldFrom = (w: VendorWindow): string | null =>
  w.held_since ?? (w.history_backfill !== null && HISTORY_READ.has(w.history_backfill) ? w.earliest_vendor_published_at : null);
// Whether a vendor's window starts on or before 1 January of a CVE ID's year.
const heldFromYear = (w: VendorWindow, yearStart: number) => {
  const from = heldFrom(w);
  return from !== null && Date.parse(from) <= yearStart;
};
// #3472: the part of a vendor's advisories its history read covers, when that is not all of them
// (history_scope reviewed: GitHub's read), else null. An answer that says complete_reviewed_only
// without a history_scope is read as "reviewed", never as all.
const partScope = (w: VendorWindow): string | null => {
  const scope = w.history_scope ?? (w.history_backfill === "complete_reviewed_only" ? "reviewed" : null);
  return scope !== null && scope !== "all" ? scope : null;
};
// #3472: the vendor's advisories outside that part, as a note names them.
const outsidePart = (part: string) => (part === "reviewed" ? "unreviewed advisories" : `advisories outside history_scope ${part}`);
// #3472: whether a vendor's advisories outside its history read's part are held from 1 January of a
// CVE ID's year: its feed_held_since is on or before it. True for a vendor whose read is not a part.
const restHeldFromYear = (w: VendorWindow, yearStart: number) =>
  partScope(w) === null || (w.feed_held_since !== null && Date.parse(w.feed_held_since) <= yearStart);
// #3472: whether the advisories outside a vendor's part are held from another date than held_since,
// or from one not known: a note then gives the two apart.
const restApart = (w: VendorWindow) => {
  const from = heldFrom(w);
  return (
    partScope(w) !== null &&
    w.earliest_vendor_published_at !== null &&
    (w.feed_held_since === null || from === null || Date.parse(w.feed_held_since) !== Date.parse(from))
  );
};
// What a note says of one window: what is held, and the history read when it is not done. #3472: of
// a vendor whose history read covers a part of its advisories, what is held of that part, and from
// when the rest is held.
const windowItem = (w: VendorWindow, heldOnly: boolean) => {
  const from = heldFrom(w);
  const to = w.latest_vendor_published_at ? ` to ${day(w.latest_vendor_published_at)}` : "";
  const held =
    w.earliest_vendor_published_at === null
      ? "none held"
      : from === null
        ? `held from ${day(w.earliest_vendor_published_at)}${to}, not known to be without a gap`
        : `held ${heldOnly ? "only " : ""}from ${day(from)}${to}${
            day(w.earliest_vendor_published_at) < day(from) ? `, and before that only in part, the earliest held dated ${day(w.earliest_vendor_published_at)}` : ""
          }`;
  const part = partScope(w);
  const scoped =
    part !== null && restApart(w)
      ? `${part} advisories ${held}; ${outsidePart(part)} ${w.feed_held_since === null ? "held from a date not known" : `held only from ${day(w.feed_held_since)}`}`
      : held;
  const reading = backfilling(w) ? `; history_backfill ${w.history_backfill}${part !== null ? `, which reads its ${part} advisories only (history_scope ${part})` : ""}` : "";
  // #3464: why a vendor collected in full is listed; collectionNote says what the state means.
  const collecting = notCollectedOk(w) ? `; collection_state ${stateShown(w) ?? "of a value this server does not read"}` : "";
  return `${w.vendor} (${scoped}${reading}${collecting})`;
};

// ── Whether each vendor is being collected (#3464) ──

// A collection_state as a note writes it: as sent when it has a state's shape, else null (not echoed).
const stateShown = (w: VendorWindow): string | null => (w.collection_state !== null && /^[a-z][a-z0-9_]{0,31}$/.test(w.collection_state) ? w.collection_state : null);
// Whether the API says the vendor is not collected in full now: any state but ok, a later one too.
// From an API without collection_state (null), nothing is said, as before.
const notCollectedOk = (w: VendorWindow) => w.collection_state !== null && w.collection_state !== "ok";
// How a note names a vendor: its display name and slug, or the slug alone.
const vendorNamed = (w: VendorWindow) => (w.vendor_display_name && w.vendor_display_name !== w.vendor ? `${w.vendor_display_name} (${w.vendor})` : w.vendor);
const vendorShort = (w: VendorWindow) => w.vendor_display_name ?? w.vendor;

// One vendor's sentence, by its collection_state; "" when it is ok or not given.
export function collectionSentence(w: VendorWindow): string {
  if (!notCollectedOk(w)) return "";
  const who = vendorNamed(w);
  const short = vendorShort(w);
  switch (w.collection_state) {
    case "failing": {
      // failing_since is the last successful poll; an API that sends last_success_at without it is read the same.
      const since = w.failing_since ?? w.last_success_at;
      const by = w.failing_since !== null ? "failing_since" : "last_success_at";
      return since !== null
        ? ` ${who} collection has failed since ${day(since)} (collection_state failing; ${by} ${since}, its last successful poll); advisories ${short} published after that may not be held, whatever its window says.`
        : ` ${who} collection is failing, with no successful poll on record (collection_state failing, last_success_at null); advisories ${short} published may not be held, whatever its window says.`;
    }
    case "partial": {
      const n = w.held_back !== null && w.held_back > 0 ? w.held_back : null;
      const one = n === 1;
      const count = n === null ? `Some ${who} documents are` : `${n} ${who} ${plural(n, "document is", "documents are")}`;
      const since = w.held_back_since === null ? "" : one ? ` since ${day(w.held_back_since)}` : `, the oldest since ${day(w.held_back_since)}`;
      const field = n === null ? "collection_state partial" : `collection_state partial, held_back ${n}`;
      return one
        ? ` ${count} held back${since} (${field}: EchelonGraph could not use it); one ${short} advisory may be missing: that advisory, or that revision, may not be held, and the rest of its feed is.`
        : ` ${count} held back${since} (${field}: EchelonGraph could not use them); some ${short} advisories may be missing: those advisories, or those revisions, may not be held, and the rest of its feed is.`;
    }
    case "disabled":
      return w.last_success_at !== null
        ? ` ${who} is not collected in this deployment (collection_state disabled): its window ends at its last successful poll, ${day(w.last_success_at)} (last_success_at ${w.last_success_at}); advisories ${short} published after that may not be held.`
        : ` ${who} is not collected in this deployment (collection_state disabled), with no successful poll on record (last_success_at null); advisories ${short} published may not be held.`;
    default: {
      const shown = stateShown(w);
      return ` ${who} has a collection_state this server does not know${shown !== null ? ` (${shown})` : ""}: whether it is being collected is not known, so advisories ${short} published may not be held.`;
    }
  }
}

// All three tools: each vendor of the windows whose collection_state is not ok, then what that means
// for an empty answer.
// #3663 review: vendor_advisories_for_cve's vendors_not_fully_held sentence already ends "is not a
// finding that it published none" for each vendor it lists (covered), so the closing sentence names
// only the vendors it has not: none, or the ones the answer holds an advisory from.
function collectionNote(windows: VendorWindow[], covered: ReadonlySet<string> = new Set()): string {
  const c = windows.filter(notCollectedOk);
  if (!c.length) return "";
  const rest = c.filter((w) => !covered.has(w.vendor));
  const k = rest.length;
  const who = k === c.length ? plural(k, "that vendor", "those vendors") : listed(rest.map(vendorShort));
  const tail = k ? ` So no advisory here from ${who} is not a finding that ${plural(k, "it", "they")} published none.` : "";
  return `${c.map(collectionSentence).join("")}${tail}`;
}

// The freshness note: per vendor once any window carries last_success_at, else as before.
const freshnessNote = (windows: VendorWindow[] | null) => (windows?.some((w) => w.last_success_at !== null) ? PER_VENDOR_FRESHNESS : NO_FRESHNESS);

// The sentence for windows that could not be read: no "none here" is a finding about a vendor.
const windowsUnknown = (why: string) =>
  ` The vendors' coverage windows could not be read (${why}), so this answer cannot say from what date each vendor's advisories are held: no advisory here from a vendor is not a finding that it published none.`;

// vendor_advisories_for_cve: the vendors with no advisory in the answer that may have published
// one EchelonGraph does not hold: none held at all, held (held_since) only from after 1 January of
// the year in the CVE ID or from a date not known, a history still being read, or (#3472) a history
// read of only part of the vendor's advisories whose rest is held (feed_held_since) only from after
// that 1 January or from a date not known. Never the earliest held advisory: for a vendor with no
// history read it can be years before held_since (#2803). #3464: and, for any year, a vendor whose
// collection_state is not ok: what it published after its last successful poll, or a document it
// holds back, may name the CVE.
function notFullyHeld(windows: VendorWindow[], rows: unknown[], year: number): VendorWindow[] {
  const answered = new Set(rows.map((r) => str(r, "vendor")).filter((v): v is string => v !== undefined));
  const yearStart = Date.UTC(year, 0, 1);
  return windows.filter(
    (w) =>
      !answered.has(w.vendor) &&
      (w.earliest_vendor_published_at === null || !heldFromYear(w, yearStart) || backfilling(w) || !restHeldFromYear(w, yearStart) || notCollectedOk(w)),
  );
}

function notFullyHeldNote(cve: string, year: number, missing: VendorWindow[]): string {
  if (!missing.length) return "";
  const k = missing.length;
  const yearStart = Date.UTC(year, 0, 1);
  const items = missing.map((w) => {
    const from = heldFrom(w);
    return windowItem(w, from !== null && Date.parse(from) > yearStart);
  });
  // #3472: the rule for a vendor whose history read covers a part of its advisories, when one is named.
  const parts = [...new Set(missing.map(partScope).filter((p): p is string => p !== null))];
  const outside = parts.length
    ? ` an advisory outside the part of a vendor's advisories its history read covers (history_scope ${parts.join(", ")}) may not be held when published before that vendor's feed_held_since,`
    : "";
  return ` ${cve} is a ${year} CVE ID, and EchelonGraph may not hold every advisory ${plural(k, "1 vendor", `${k} vendors`)} published for it (vendors_not_fully_held): ${items.join("; ")}. An advisory a vendor published before the date EchelonGraph holds that vendor from (held_since) may not be held, even when an older one is,${outside} and while history_backfill is in_progress or not_started the vendor's older advisories are still being read, so no advisory here from ${plural(k, "that vendor", "those vendors")} is not a finding that ${plural(k, "it", "they")} published none.`;
}

// search_vendor_advisories and get_vendor_advisory: the vendors whose history is still being read.
function backfillingNote(windows: VendorWindow[]): string {
  const b = windows.filter(backfilling);
  if (!b.length) return "";
  const k = b.length;
  return ` The older advisories of ${plural(k, "1 vendor", `${k} vendors`)} are still being read (history_backfill in_progress or not_started): ${b.map((w) => windowItem(w, false)).join("; ")}. EchelonGraph does not yet hold all of ${plural(k, "its", "their")} older advisories, so none found from ${plural(k, "it", "them")} is not a finding that ${plural(k, "it", "they")} published none.`;
}

// #3472: search_vendor_advisories and get_vendor_advisory: the vendors whose history read covers
// only part of their advisories, the rest held from another date (feed_held_since). A vendor whose
// history is still being read is backfillingNote's, whose item gives the same dates.
function heldInPartNote(windows: VendorWindow[]): string {
  const p = windows.filter((w) => !backfilling(w) && restApart(w));
  if (!p.length) return "";
  const k = p.length;
  return ` The history read of ${plural(k, "1 vendor", `${k} vendors`)} covers only part of ${plural(k, "its", "their")} advisories (history_scope): ${p.map((w) => windowItem(w, false)).join("; ")}. An advisory outside that part published before ${plural(k, "its", "their")} feed_held_since may not be held, so none found from ${plural(k, "it", "them")} is not a finding that ${plural(k, "it", "they")} published none.`;
}

// #3663: what a note adds beside the kinds where a Cisco row lists no_fix_planned. The parser makes it
// from a vendor_fix only when the advisory's Summary says, in wording it reads, that Cisco will not
// release a fix and no fix note says one exists (core-backend vendoradv cisco_csaf_doc.go ciscoNoFix),
// so the note says what such an item may be, never that every such advisory is one.
export const CISCO_NO_FIX_NOTE = " (no_fix_planned may also be a Cisco vendor_fix whose summary says no fix will be released)";
export const ciscoListsNoFix = (r: unknown): boolean => {
  const ks = field(r, "remediation_kinds");
  return str(r, "vendor") === "cisco" && Array.isArray(ks) && ks.includes("no_fix_planned");
};

// #2840: what the rows say of their remediation, where the API sends remediation_state.
function remediationNote(cve: string, rows: unknown[]): string {
  const states = rows.map((r) => field(r, "remediation_state")).filter((x): x is string => typeof x === "string");
  if (!states.length) return "";
  const count = (st: string) => states.filter((x) => x === st).length;
  const kinds = new Map<string, number>();
  for (const r of rows) {
    const ks = field(r, "remediation_kinds");
    if (Array.isArray(ks)) for (const k of ks) if (typeof k === "string") kinds.set(k, (kinds.get(k) ?? 0) + 1);
  }
  const listedKinds = [...kinds].map(([k, n]) => `${k} (${n})`).join(", ");
  // #3663: a Cisco no_fix_planned may be Cisco's vendor_fix, not Cisco's category: said where a Cisco
  // row lists one, and only there (a Red Hat no_fix_planned is Red Hat's own).
  const noFix = rows.some(ciscoListsNoFix) ? CISCO_NO_FIX_NOTE : "";
  const parts = [
    listedKinds ? ` By the vendors' own categories${noFix}, the advisories list for ${cve}: ${listedKinds}; each is the vendor's text, untested by EchelonGraph, and cve_remediation or get_vendor_advisory returns it.` : "",
    count("none_in_source") ? ` ${count("none_in_source")} ${plural(count("none_in_source"), "lists", "list")} no remediation for ${cve} (none_in_source), which is not a finding that no fix exists.` : "",
    count("not_parsed") ? ` EchelonGraph does not read the remediation of ${count("not_parsed")} (remediation_state not_parsed), which is not a finding that ${plural(count("not_parsed"), "it lists", "they list")} none.` : "",
  ];
  return parts.join("");
}

// ── Output schemas ──
const opt = <T extends z.ZodType>(t: T) => t.nullable().optional();
const DATE_FIELDS = {
  vendor_published_at: opt(z.string()).describe("The date the vendor gives for the advisory."),
  our_first_seen_at: opt(z.string()).describe("When EchelonGraph first recorded the advisory; not the vendor's date."),
  withdrawn: opt(z.boolean()).describe("true: the vendor withdrew (rescinded) this advisory, so it is a withdrawn advisory, not a current one."),
  rejected_cve_ids: opt(z.array(z.string())).describe(
    "The CVE IDs this advisory names whose CVE record was rejected (withdrawn) by its numbering authority: each is a rejected record, not an active vulnerability, whatever the advisory's text says. The vendor's withdrawn is separate and unchanged by it. [] when none is; null when that could not be checked.",
  ),
};
// #2840: what remediation_kinds and remediation_state are, on a by-cve row and on the detail.
const REMEDIATION_STATE_FIELD =
  "parsed; none_in_source (EchelonGraph read the vendor's remediation, and it lists none for this CVE, which is not a finding that no fix exists); not_parsed (EchelonGraph does not read this vendor's remediation, or has not yet read this advisory: not a finding of none); withdrawn (the vendor rescinded the advisory).";
const REMEDIATION_KINDS_FIELD =
  "The kinds of remediation the advisory lists (for the CVE asked about, on a by-cve row), each the vendor's own category (vendor_fix, workaround, mitigation, no_fix_planned, none_available or other), or may be no_fix_planned where a Cisco advisory's summary says no fix will be released. [] with remediation_state not_parsed is not a finding that it lists none.";
// #3663: kind is not always the vendor's category. The Cisco parser (core-backend vendoradv
// cisco_csaf_doc.go ciscoNoFix) stores a vendor_fix as no_fix_planned when both hold: the Summary
// matches its no-fix wording (ciscoNoFixRe), and none of the five notes it reads (ciscoFixNoteTitles)
// says a fix exists by its negation-aware markers (ciscoReleased). Other wording leaves vendor_fix
// (#3719), so this says the rule, not that every no-fix advisory is caught. cve_remediation.ts's items
// carry the same two texts.
export const REMEDIATION_ITEM_KIND_FIELD =
  "The vendor's own category: vendor_fix, workaround, mitigation, no_fix_planned, none_available or other. One exception: a Cisco vendor_fix is no_fix_planned when the advisory's Summary says, in wording EchelonGraph's parser reads, that Cisco will not release a fix, and none of its Summary, Fixed Software, Recommendations, Details or Affected Products notes says, by the parser's markers, that a fix exists; its source_category then stays vendor_fix, its source_subcategory names the note its text is from, and it carries no url. Wording the parser does not read leaves the item vendor_fix, so a Cisco vendor_fix is not a finding that a fix was released.";
export const REMEDIATION_ITEM_SUBCATEGORY_FIELD =
  "MSRC's SubType, e.g. Security Update; for a Cisco no_fix_planned item, the title of the note its text is from (Summary); null elsewhere.";
const REMEDIATION_KINDS = ["vendor_fix", "workaround", "mitigation", "no_fix_planned", "none_available", "other"] as const;
const REMEDIATION_STATES = ["parsed", "none_in_source", "not_parsed", "withdrawn"] as const;
// #3642: what vendor_text_withheld says, on every row and on the detail. The API withholds
// Microsoft's advisory text (core-backend internal/cve/vendor_text.go) and these tools relay its
// answer as sent, so the rule is the API's and reaches every version of this server at once.
const VENDOR_TEXT_WITHHELD_FIELD =
  "true: the vendor's advisory page is not copied (Microsoft's): title is EchelonGraph's (Microsoft security update for its first CVE where it lists a vendor fix, Microsoft advisory otherwise, by its own ID when it names no CVE), and the advisory's description, summary, remediation, withdrawn_reason and each remediation's text are empty (instead, a detail's cve_records lists the first cve_records_cap CVEs it names, each with the CVE record's description or null, as cve_records says when); severity, cvss_v3_score, cvss_v3_vector, cve_ids, affected_products, the dates and the links are the vendor's facts, and, where the advisory names a CVE ID, references lead with the vendor's own advisory page.";
// #3643: each source's licence, on the field that names the source (the site's /pulse/api says the
// same, marketing-site/lib/apiDataLicences.ts; Red Hat's read at https://access.redhat.com/security/data,
// GitHub's in github/advisory-database's LICENSE.md, both 2026-11-08).
export const VENDOR_LICENCE_FIELD =
  "The vendor's slug. Each vendor's advisory data stays under its own licence, and EchelonGraph's terms add no restriction to it: redhat, Red Hat's security advisories, © Red Hat, Inc., licensed CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/; source https://access.redhat.com/security/data); github, the GitHub Advisory Database, licensed CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/; source https://github.com/github/advisory-database); microsoft, Microsoft's own terms (its advisory pages are not copied: the facts and EchelonGraph's title are served, with a link to Microsoft's advisory where it names a CVE ID); every other vendor, that vendor's own terms.";
// #3642 round-3 review: what get_vendor_advisory's description says of a vendor whose text is withheld,
// the last sentence of it, within the client cut and #2924's 100-character headroom under it
// (requiredText.ts CLIENT_DESCRIPTION_CUT; test/prompts-resources.test.mjs).
const WITHHELD_DETAIL_DESCRIPTION =
  "vendor_text_withheld true (Microsoft): title is EchelonGraph's; description, remediation and item texts are empty; cve_records: its first CVEs, each with its CVE-record description or null.";
// #3642: EchelonGraph's own facts of each CVE a withheld vendor's advisory names, on the detail.
const CVE_RECORDS_FIELD =
  "When vendor_text_withheld is true: EchelonGraph's facts of the first cve_records_cap CVEs the advisory names, in its order: the CVE record's own description, as the CVE Numbering Authority that assigned the CVE (cna) published it in the CVE record at cve_record_url, reused under the CVE Program's Terms of Use (https://www.cve.org/Legal/TermsOfUse; © The MITRE Corporation; for a CVE the vendor assigned, the vendor wrote it; null where the record has none, was rejected or is still the stub a GitHub advisory seeded, where EchelonGraph holds no record (known false), or where description_withheld_reason says it is withheld), EchelonGraph's score as the CVE feed serves it (null unless score_assessed), the CISA KEV listing, and the fix status by the CVE feed's rule. null when the vendor's text is served, or when the facts could not be read.";
const CVE_RECORD_ROW = z.looseObject({
  cve_id: opt(z.string()),
  known: opt(z.boolean()).describe("Whether EchelonGraph holds a CVE record for it; false: EchelonGraph holds no CVE record for it; only cve_id and cve_record_url are set."),
  vuln_status: opt(z.string()),
  description: opt(z.string()).describe("The CVE record's description, as its CVE Numbering Authority (cna) published it in the CVE record at cve_record_url; null when there is none to serve, or when description_withheld_reason says why it is withheld."),
  description_withheld_reason: opt(z.string()).describe("Why a description the CVE record has is null: matches_vendor_title: it repeats the advisory's own title, and a server-side switch for such descriptions, off by default, withheld it; null otherwise."),
  cve_record_url: opt(z.string()),
  cna: opt(z.string()).describe("The CVE Numbering Authority that assigned the CVE and wrote its record, by its name in the CVE Program's CNA list, else its short name (e.g. Microsoft Corporation, kernel.org); null when none is on record."),
  echelongraph_score: opt(z.number()),
  echelongraph_severity: opt(z.string()),
  score_assessed: opt(z.boolean()),
  score_unassessed_reason: opt(z.string()),
  score_confidence: opt(z.string()),
  kev_listed: opt(z.boolean()),
  kev_added_date: opt(z.string()),
  fix_status: z.unknown().optional().describe("The fix status by the CVE feed's rule (state, basis, unread_inputs and the rule's evidence); null for a rejected record."),
});
const AdvisoryRow = z.looseObject({
  advisory_id: opt(z.string()).describe(ROW_ADVISORY_ID_FIELD),
  vendor: opt(z.string()).describe(VENDOR_LICENCE_FIELD),
  vendor_display_name: opt(z.string()),
  vendor_advisory_id: opt(z.string()).describe(VENDOR_ADVISORY_ID_FIELD),
  cve_ids: opt(z.array(z.string())),
  title: opt(z.string()),
  severity: opt(z.string()),
  cvss_v3_score: opt(z.number()),
  cvss_v3_vector: opt(z.string()).describe("The CVSS v3 vector of cvss_v3_score where the vendor's source carries one (Microsoft's); null otherwise. On by-cve rows and the detail."),
  vendor_text_withheld: opt(z.boolean()).describe(VENDOR_TEXT_WITHHELD_FIELD),
  summary: opt(z.string()),
  affected_products: opt(z.array(z.string())),
  ...DATE_FIELDS,
  remediation_kinds: opt(z.array(z.union([z.enum(REMEDIATION_KINDS), z.string()]))).describe(REMEDIATION_KINDS_FIELD),
  remediation_state: opt(z.union([z.enum(REMEDIATION_STATES), z.string()])).describe(REMEDIATION_STATE_FIELD),
});

// Shared by the three descriptions. Top-level consts, so the site's tool-claims check
// (marketing-site/lib/mcpToolClaims.test.ts) can fold the descriptions to their text.
const DATES_DESCRIPTION =
  "Each advisory carries vendor_published_at (the vendor's date), our_first_seen_at (when EchelonGraph first recorded it) and withdrawn (true: the vendor rescinded it).";
// #2865: the CVE-state flag beside the vendor's own withdrawn. #2842: the head the descriptions
// carry; rejected_cve_ids' and cve_rejected's outputSchema descriptions say the rest (null: not checked).
const REJECTED_CVE_DESCRIPTION =
  "Each advisory also carries rejected_cve_ids: the CVE IDs it names whose CVE record was rejected (withdrawn) by its numbering authority, which are not active vulnerabilities.";
// #2842: the generic rule for the result's last text block is in the README and the methodology
// resource, not in each description.
// #3464: the window carries the vendor's last successful poll, so the answer is not without one.
const ENVELOPE_DESCRIPTION = "freshness is null; vendor_window.last_success_at is the last successful poll.";
// #2729: what a vendor's window is.
const HISTORY_BACKFILL_DESCRIPTION =
  "history_backfill: complete (the vendor's published history has been read back as far as its source goes), complete_reviewed_only (the vendor's reviewed advisories have been read back as far as its source goes and its unreviewed ones have not: GitHub's, history_scope reviewed), in_progress or not_started (it is still being read, so the vendor's older advisories are not all held yet), or not_supported (EchelonGraph has no history read for that vendor, so what it holds is what the vendor's feed has carried)";
// #2803: where a vendor's window begins.
const HELD_SINCE_DESCRIPTION =
  "held_since (the start of the window EchelonGraph has read that vendor's advisories from, before which an advisory may not be held; null when none is held or the API does not say; for a vendor with no history read it is when its feed was first read from, and can be years after earliest_vendor_published_at, since an older advisory is held when the vendor revised it later, not the ones published beside it; where history_scope is a part of the vendor's advisories, it is where that part is held from, and the rest is held from feed_held_since)";
// #3472: where the advisories outside a history read's part begin, and what the read covers.
const FEED_HELD_SINCE_DESCRIPTION =
  "feed_held_since (the start of the window the vendor's own feed has read every one of its advisories from, which is held_since as it would be without any history read; an advisory outside history_scope published before it may not be held; null when none is held or the API does not say)";
const HISTORY_SCOPE_DESCRIPTION =
  "history_scope (what the vendor's history read covers: all, or reviewed for GitHub, whose read covers its reviewed advisories and not its unreviewed ones, which are held only from feed_held_since; a value the API adds later as it sends it; null for a vendor with no history read, or when the API does not say)";
// #3464: whether the vendor is being collected now, beside the window.
const COLLECTION_STATE_DESCRIPTION =
  "last_success_at (the vendor's last successful poll), collection_state (whether the vendor is being collected now, by EchelonGraph's feed-state rule: ok; partial, its polls succeed but held_back of the documents it lists could not be used, the oldest since held_back_since, and those advisories, or those revisions, may not be held while the rest of its feed is; failing, it is not being collected, and what it published after failing_since, its last successful poll, may not be held, whatever the window says; disabled, this deployment runs no collector for it (its held advisories are still served), so its window ends at last_success_at; a value the API adds later as it sends it, never read as ok), failing_since, held_back and held_back_since (each null when the API does not say)";
const WINDOW_DESCRIPTION = `vendor, advisories (how many EchelonGraph holds from that vendor), earliest_vendor_published_at and latest_vendor_published_at (the earliest and latest vendor_published_at among them, null when none is held), ${HELD_SINCE_DESCRIPTION}, ${FEED_HELD_SINCE_DESCRIPTION}, ${HISTORY_BACKFILL_DESCRIPTION}, ${HISTORY_SCOPE_DESCRIPTION}, and ${COLLECTION_STATE_DESCRIPTION}`;
// #2842: what the descriptions say of a window, within the client cut (requiredText.ts);
// WINDOW_DESCRIPTION in full is the outputSchema's description of a window.
const WINDOW_HEAD_FIELDS = "vendor, advisories, earliest_vendor_published_at, latest_vendor_published_at, held_since (where that window begins)";
const BACKFILL_HEAD = "history_backfill (in_progress or not_started: older advisories not all held yet)";
const WINDOW_HEAD = `${WINDOW_HEAD_FIELDS} and ${BACKFILL_HEAD}`;
// #3472: search_vendor_advisories' and get_vendor_advisory's heads name history_scope and
// feed_held_since too; vendor_advisories_for_cve's names them where it says what
// vendors_not_fully_held lists, within its headroom (test/prompts-resources.test.mjs, #2924).
const WINDOW_HEAD_SCOPED = `${WINDOW_HEAD_FIELDS}, ${BACKFILL_HEAD}, history_scope and feed_held_since`;
// #3663, #3642 re-review: get_vendor_advisory's, without vendor and advisories (its outputSchema names
// them), so its description keeps #2924's headroom with the Cisco kind sentence and a cve_records
// sentence that is true of every description it serves.
const WINDOW_HEAD_DETAIL = `earliest_vendor_published_at, latest_vendor_published_at, held_since (where that window begins), ${BACKFILL_HEAD}, history_scope and feed_held_since`;
const NOT_HELD_DESCRIPTION =
  "An advisory a vendor published before its held_since may not be held, even when its earliest_vendor_published_at is older, and one outside its history_scope (GitHub's unreviewed advisories) published before its feed_held_since may not be held either, nor one it published after its last successful poll while its collection_state is failing or disabled, nor one of the documents it holds back (partial), so no advisory from a vendor is not a finding that it published none.";
// #2842: the same rule within the client cut; NOT_HELD_DESCRIPTION whole is the windows' outputSchema description.
const NOT_HELD_HEAD =
  "An advisory published before its vendor's held_since may not be held, so no advisory from a vendor is not a finding that it published none.";
// #2728: how a search matches, and its capped total.
// #2842: what search_vendor_advisories' description says; SEARCH_MATCH_DESCRIPTION and
// TOTAL_CAPPED_DESCRIPTION in full are the outputSchema's descriptions of search_match and total_capped.
const SEARCH_MATCH_HEAD =
  "A query of 3 or more characters is matched case-insensitively as a substring of each advisory's title, description, vendor name, IDs and affected_products (search_match substring). A query of 1 or 2 characters matches whole words only (search_match word).";
const TOTAL_CAPPED_HEAD =
  "A search counts at most 1,000 matches: past that, total is 1000 and total_capped is true, which means 1,000 or more (the note writes 1,000+), never exactly 1,000.";
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
    .describe("The earliest vendor_published_at among them; null when none is held. Not where the window begins: see held_since."),
  latest_vendor_published_at: z.string().nullable().describe("The latest vendor_published_at among them; null when none is held."),
  held_since: z
    .string()
    .nullable()
    .describe(
      "The start of the window EchelonGraph has read this vendor's advisories from; null when none is held or the API does not say. An advisory this vendor published before it may not be held, even when earliest_vendor_published_at is older. Where history_scope is a part of the vendor's advisories (reviewed), it is where that part is held from; the rest is held from feed_held_since.",
    ),
  // #3472: coverage.go FeedHeldSince.
  feed_held_since: z
    .string()
    .nullable()
    .describe(
      "The start of the window this vendor's own feed has read every one of its advisories from: held_since as it would be without any history read, and equal to it for a vendor with no history read. Where history_scope is a part of the vendor's advisories (reviewed: GitHub's history read covers its reviewed advisories only), an advisory outside it published before feed_held_since may not be held, however early held_since is. null when none is held or the API does not say.",
    ),
  // The five values the API sends today, and any later one as a string: a new state must not turn
  // the answer into a failure.
  history_backfill: z
    .union([z.enum(["complete", "complete_reviewed_only", "in_progress", "not_started", "not_supported"]), z.string()])
    .nullable()
    .describe(`${HISTORY_BACKFILL_DESCRIPTION}.`),
  // #3472: coverage.go HistoryScope ("" without a history read, relayed as null). A string, so a
  // scope the API adds later is relayed as sent.
  history_scope: z
    .string()
    .nullable()
    .describe(
      "What this vendor's history read covers: all (every advisory its archive publishes) or reviewed (GitHub: its reviewed advisories, not its unreviewed ones, which are held only from feed_held_since); a value the API adds later as it sends it. null for a vendor with no history read, or when the API does not say.",
    ),
  // #3464: coverage.go LastSuccessAt, CollectionState, FailingSince; #3197: HeldBack, HeldBackSince.
  last_success_at: z
    .string()
    .nullable()
    .describe("This vendor's last successful poll; null when none is on record or the API does not say. While collection_state is disabled, the window ends here."),
  // A string, as history_scope: the four values the API sends today (COLLECTION_STATES) are named in
  // the description, and a later one is relayed as sent, never turned into a failure or read as ok.
  // (An enum beside any string would add no check, and would be a fifth open enum in the failure
  // branch, which README Versioning counts.)
  collection_state: z
    .string()
    .nullable()
    .describe(
      "Whether this vendor is being collected now, by EchelonGraph's feed-state rule: ok, partial, failing or disabled. ok: it is being collected. partial: its polls succeed, but held_back of the documents it lists could not be used, the oldest since held_back_since; those advisories, or those revisions, may not be held, and the rest of its feed is. failing: it is not being collected, and an advisory it published after failing_since, its last successful poll, may not be held, whatever the window says. disabled: this deployment runs no collector for it (its held advisories are still served), so its window ends at last_success_at, and an advisory it published after that may not be held. A value the API adds later is relayed as sent and is not read as ok. null when the API does not say.",
    ),
  failing_since: z
    .string()
    .nullable()
    .describe(
      "While collection_state is failing, this vendor's last successful poll: an advisory it published after it may not be held, whatever the window says. null when it is not failing, when no successful poll is on record, or when the API does not say.",
    ),
  held_back: z
    .number()
    .nullable()
    .describe(
      "How many of the documents this vendor lists EchelonGraph could not use (collection_state partial): those advisories, or those revisions, may not be held. 0 when none is held back; null when the API does not say.",
    ),
  held_back_since: z.string().nullable().describe("When the oldest held-back document first failed; null when none is held back or the API does not say."),
}).describe(`A vendor's window in what EchelonGraph holds: ${WINDOW_DESCRIPTION}.`);
const WINDOWS = z.array(VendorWindowSchema).nullable().describe(`Each vendor's window in what EchelonGraph holds; null when the windows could not be read. ${NOT_HELD_DESCRIPTION}`);

// #2783: a production row is up to about 2,000 characters as pretty JSON (its summary, its
// affected_products and, for a library like log4j, dozens of cve_ids), so search_vendor_advisories
// "log4j" at limit 50 was 103,147 characters of text. Past DATA_TEXT_BUDGET each row in the first
// text block keeps what identifies and rates the advisory, every string cut to 200 characters and
// every list to 20 entries; then fewer fields, strings to 100 and lists to 10.
const ROW_CUT_LEVELS: TextCut["levels"] = [
  { keep: ["vendor", "vendor_display_name", "vendor_advisory_id", "title", "severity", "cvss_v3_score", "cve_ids", "summary", "affected_products", "vendor_published_at", "withdrawn", "rejected_cve_ids", "remediation_kinds", "remediation_state"], clip: 200, cap: 20 },
  { keep: ["vendor", "vendor_advisory_id", "title", "severity", "cve_ids", "vendor_published_at", "withdrawn", "rejected_cve_ids", "remediation_kinds", "remediation_state"], clip: 100, cap: 10 },
];
// get_vendor_advisory's own first text block is cut too past the budget (#2802): only its
// structuredContent.data is one advisory whole, with full: true (#3013).
const WHOLE =
  "get_vendor_advisory returns any one of these advisories by its vendor and vendor_advisory_id, whole in its structuredContent.data with full: true, and in its first text block with every field (past 30,000 characters, each list cut to its first entries).";
const FOR_CVE_TEXT: TextCut = { rows: "advisories", levels: ROW_CUT_LEVELS, whole: WHOLE };
const searchText = (a: { offset?: number }): TextCut => ({
  rows: "advisories",
  levels: ROW_CUT_LEVELS,
  whole: WHOLE,
  page: (shown, _rows, d) =>
    `To read the rows left out in the text, call search_vendor_advisories again with the same arguments and offset ${(num(d, "offset") ?? a.offset ?? 0) + shown}; a page of ${shown} rows or fewer like these fits the text without leaving rows out.`,
});
// #3013: the structured result's cut. A production row is up to about 1,700 characters of compact
// JSON, 782 of them its affected_products, so search_vendor_advisories "log4j" at its default page
// was 38,733 characters of structured result. Before any row leaves, every row is thinned: first
// without affected_products, then without summary too (get_vendor_advisory returns one whole);
// only then do rows leave data from the end, and the note gives the offset to read them from. The
// by-CVE answer (at most 20 advisories, 12,652 characters for CVE-2021-44228) is cut the same way.
const ADVISORY_ROW_THIN: readonly RowKeep[] = [
  [
    "vendor", "vendor_display_name", "vendor_advisory_id", "advisory_id", "title", "severity", "cvss_v3_score", "cve_ids", "summary", "vendor_published_at", "our_first_seen_at", "withdrawn",
    "rejected_cve_ids", "remediation_kinds", "remediation_state",
  ],
  ["vendor", "vendor_advisory_id", "title", "severity", "cvss_v3_score", "cve_ids", "vendor_published_at", "withdrawn", "rejected_cve_ids", "remediation_kinds", "remediation_state"],
];
const FOR_CVE_DATA: DataCut = { steps: [{ lists: ["advisories"], thin: ADVISORY_ROW_THIN }] };
// The page size the note says fits data whole is counted on the rows whole (#3013's review: it was
// the number of thinned rows kept, and a page of that many came back thinned again).
const SEARCH_DATA: DataCut = {
  steps: [{ lists: ["advisories"], thin: ADVISORY_ROW_THIN }],
  page: (t, d, at) => {
    const k = t.advisories?.returned;
    if (!k || !t.advisories || k === t.advisories.total) return "";
    return `To read the rows past the first ${k} in data, call search_vendor_advisories again with the same arguments and offset ${(num(d, "offset") ?? 0) + k}; ${wholePage(at.wholeFit("advisories"))}`;
  },
};
const ROW_CUT_DESCRIPTION = " Cut, each row keeps vendor, vendor_advisory_id, title, severity and cve_ids at least, its strings and lists shortened";

// The three tools' output schemas, one each per process, not per request (3.0.2; index.ts
// envelopeSchema says why).
const OUTPUTS = new WeakMap<object, ReturnType<typeof outputsOf>>();
function outputsOf(envelopeSchema: VendorAdvisoryKit["envelopeSchema"]) {
  const FOR_CVE_OUTPUT = envelopeSchema({
    data: z.looseObject({
      cve_id: opt(z.string()),
      advisories: opt(z.array(AdvisoryRow)),
      total: opt(z.number()),
      cve_rejected: opt(z.boolean()).describe(
        "true: the CVE record of cve_id was rejected (withdrawn) by its numbering authority, so these advisories name a rejected record, not an active vulnerability; null when that could not be checked.",
      ),
    }),
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
          "The vendors with no advisory in this answer that may have published one EchelonGraph does not hold: none held, held_since after 1 January of cve_year or not known, history_backfill in_progress or not_started, a history_scope that is a part of the vendor's advisories (reviewed) with feed_held_since after 1 January of cve_year or not known: GitHub, whose unreviewed advisories are held only from feed_held_since, however early its held_since, or, for any cve_year, a collection_state that is not ok (failing, partial, disabled, or a value the API adds later). No advisory from them is not a finding that they published none. null when the windows could not be read.",
        ),
    }),
    freshness: null,
  });
  const DETAIL_OUTPUT = envelopeSchema({
    data: AdvisoryRow.extend({
      description: opt(z.string()),
      known_cve_ids: opt(z.array(z.string())).describe("The CVE IDs of cve_ids that have a record in EchelonGraph's CVE feed."),
      remediation: opt(z.string()).describe("The vendor's remediation as one text (the legacy field), beside remediations."),
      remediations: opt(
        z.array(
          z.looseObject({
            // #3663: as cve_remediation's items say them.
            kind: opt(z.union([z.enum(REMEDIATION_KINDS), z.string()])).describe(REMEDIATION_ITEM_KIND_FIELD),
            source_category: opt(z.string()).describe("The vendor's own name for the category."),
            source_subcategory: opt(z.string()).describe(REMEDIATION_ITEM_SUBCATEGORY_FIELD),
            text: opt(z.string()).describe("The vendor's text, verbatim but for HTML markup removed, untested by EchelonGraph; at most 2,000 characters (text_truncated, text_chars). Empty, with text_chars 0, when vendor_text_withheld is true."),
            text_truncated: opt(z.boolean()),
            text_chars: opt(z.number()),
            url: opt(z.string()),
            fixed_build: opt(z.string()),
            cve_ids: opt(z.array(z.string())).describe("The CVEs the item covers; [] for the whole advisory."),
            product_ids: opt(z.array(z.string())),
            product_count: opt(z.number()),
            kb_article: opt(z.string()).describe("The KB article the item's url names, e.g. KB5055519, when vendor_text_withheld is true; absent otherwise."),
          }),
        ),
      ).describe("Each remediation the vendor lists, with its kind: the vendor's own category, or it may be no_fix_planned where a Cisco advisory's summary says no fix will be released."),
      remediation_items_not_stored: opt(z.number()).describe("Items past the 64 stored per advisory."),
      references: z.unknown().optional(),
      vendor_modified_at: opt(z.string()),
      withdrawn_at: opt(z.string()),
      withdrawn_reason: opt(z.string()),
      cve_records: opt(z.array(CVE_RECORD_ROW)).describe(CVE_RECORDS_FIELD),
      cve_records_total: opt(z.number()).describe("How many CVE IDs the advisory names; cve_records holds the first cve_records_cap of them."),
      cve_records_cap: opt(z.number()),
      content_changed_at: opt(z.string()).describe("When what EchelonGraph's page of this advisory shows changed with no change to the advisory: when the vendor-text rule began serving; empty when none is recorded."),
    }),
    coverage: z.strictObject({
      vendor_window: VendorWindowSchema.nullable().describe("This advisory's vendor's window in what EchelonGraph holds; null when the windows could not be read or carry none for this vendor."),
    }),
    freshness: null,
  });
  const SEARCH_OUTPUT = envelopeSchema({
    data: z.looseObject({
      advisories: opt(z.array(AdvisoryRow)),
      total: opt(z.number()).describe("The matches; when total_capped is true, a lower bound: 1,000 or more."),
      limit: opt(z.number()),
      offset: opt(z.number()),
      search_applied: opt(z.boolean()).describe("Whether a free-text search filtered this answer."),
      search_match: opt(z.string()).describe(`How the query was matched: word (a query of 1 or 2 characters, whole words only) or substring; null without a query. ${SEARCH_MATCH_DESCRIPTION}`),
      total_capped: opt(z.boolean()).describe(`true: the search stopped counting at total, so total is a lower bound (1,000+), not the count. ${TOTAL_CAPPED_DESCRIPTION}`),
    }),
    coverage: z.strictObject({
      total: z.number().nullable().describe("The API's total; when total_capped is true, a lower bound, not the count."),
      total_capped: z.boolean().nullable().describe("true: total is the API's cap on a search's count, so 1,000 or more match."),
      returned: z.number().nullable(),
      limit: z.number().nullable(),
      offset: z.number().nullable(),
      search_applied: z.boolean().nullable(),
      search_match: z.enum(["word", "substring"]).nullable().describe("word: a query of 1 or 2 characters, matched as a whole word only; substring: a longer query; null without a query."),
      vendor_windows: WINDOWS.describe(`Each vendor's window in what EchelonGraph holds, only that vendor's when vendor is given; null when the windows could not be read. ${NOT_HELD_DESCRIPTION}`),
    }),
    freshness: null,
  });
  return { FOR_CVE_OUTPUT, DETAIL_OUTPUT, SEARCH_OUTPUT };
}

export function registerVendorAdvisoryTools(server: McpServer, kit: VendorAdvisoryKit): void {
  const outputs = OUTPUTS.get(kit.envelopeSchema) ?? outputsOf(kit.envelopeSchema);
  OUTPUTS.set(kit.envelopeSchema, outputs);
  const { FOR_CVE_OUTPUT, DETAIL_OUTPUT, SEARCH_OUTPUT } = outputs;

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
        notes: [LIST_MEASURED_AT, freshnessNote(w.ok ? w.windows : null), DATES],
      };
      const head = kit.okHead(tool, r.status);
      // #3464: every vendor not collected in full, answered or not: what it published after its last
      // successful poll may name this CVE too.
      const held = w.ok ? `${notFullyHeldNote(cve, year, missing ?? [])}${collectionNote(w.windows, new Set((missing ?? []).map((m) => m.vendor)))}` : windowsUnknown(w.why);
      // #2865: the queried CVE's own state, first, so no advisory below reads as a live CVE's.
      const cveState = field(r.data, "cve_rejected");
      const rejectedHead =
        cveState === true
          ? ` CVE REJECTED: the CVE record of ${cve} was rejected (withdrawn) by its numbering authority (cve_rejected true). It is a rejected record, not an active vulnerability: report it that way, even where a vendor advisory below reads as a current one.`
          : cveState === null
            ? ` Whether the CVE record of ${cve} was rejected could not be checked (cve_rejected null), which is not a finding that it was not.`
            : "";
      if (returned === 0) {
        return kit.succeeded(
          r.data,
          `${head}${rejectedHead} No vendor advisory on record names ${cve}: a measured empty result, EchelonGraph was queried successfully and found nothing (we looked and found nothing). This is not a lookup failure. ${ONLY_POLLED}${held}`,
          env,
          FOR_CVE_TEXT,
        );
      }
      if (rows === undefined) return kit.succeeded(r.data, `${head}${rejectedHead}${held}`, env, FOR_CVE_TEXT);
      const cap = atCap ? ` The API returns at most ${BY_CVE_CAP} advisories for one CVE, newest first, and this answer is full (at_cap true), so there may be more.` : "";
      // With cve_rejected true the head has said it of the one CVE every row names; the per-row
      // note then only adds the other rejected IDs a multi-CVE advisory names.
      const perRow = cveState === true ? rejectedCVENote(rows.map((x) => ({ ...(x as object), rejected_cve_ids: rejectedIDs(x).filter((id) => id.toUpperCase() !== cve) }))) : rejectedCVENote(rows);
      return kit.succeeded(
        r.data,
        `${head}${rejectedHead} ${rows.length} vendor ${plural(rows.length, "advisory names", "advisories name")} ${cve}.${cap}${withdrawnNote(rows)}${perRow}${rejectedUnknownNote(rows)}${remediationNote(cve, rows)} ${ONLY_POLLED}${held}`,
        env,
        FOR_CVE_TEXT,
      );
    } catch (e) {
      return kit.crashed(tool, e);
    }
  }

  // ── get_vendor_advisory ──
  // #3011: advisory_id was a row's advisory_id (a UUID), not its vendor_advisory_id. The API was
  // asked (a vendor's own ID could be shaped so) and holds no advisory of the vendor under it, which
  // is the wrong ID passed, not a missing advisory: invalid_input, naming the field to pass.
  function internalIdRefusal(vendor: string, id: string, path: string): ToolResult {
    const why = `advisory_id ${id} has the shape of a row's advisory_id, EchelonGraph's internal ID for an advisory (a UUID), which this tool does not take, and EchelonGraph holds no ${vendor} advisory whose vendor_advisory_id it is (HTTP 404)`;
    return kit.failure(
      "invalid_input",
      `get_vendor_advisory FAILED (state: invalid_input): ${why}. Call get_vendor_advisory again with the row's vendor and its vendor_advisory_id as advisory_id (e.g. CVE-2024-3400 for Palo Alto Networks, RHSA-2024:1234 for Red Hat). This says nothing about whether the advisory exists, and it is not a finding.`,
      { kind: "invalid_input", path, status: 404, message: `${why}; pass the row's vendor_advisory_id as advisory_id` },
    );
  }

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
      if (!r.ok && r.kind === "http" && r.status === 404 && INTERNAL_ID.test(id)) return internalIdRefusal(vendor, id, r.path);
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
          freshnessNote(window ? [window] : null),
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
      const held = !w.ok ? windowsUnknown(w.why) : window ? `${backfillingNote([window])}${heldInPartNote([window])}${collectionNote([window])}` : "";
      // #2865: the CVE IDs it names that were rejected, said whether or not the vendor withdrew it.
      const rej = rejectedIDs(r.data);
      const rejectedCVEs = rej.length
        ? ` CVE REJECTED: ${rej.length} of the CVE IDs it lists ${plural(rej.length, "was", "were")} rejected (withdrawn) by ${plural(rej.length, "its", "their")} numbering authority (rejected_cve_ids): ${rej.join(", ")}. Report ${plural(rej.length, "it", "each")} as a rejected record, not as an active vulnerability${field(r.data, "withdrawn") === true ? "" : ", even though the vendor has not withdrawn this advisory and its text reads as a current one"}.`
        : field(r.data, "rejected_cve_ids") === null && Array.isArray(cveIDs) && cveIDs.length > 0
          ? " Whether a CVE ID it lists was rejected could not be checked (rejected_cve_ids null), which is not a finding that none was."
          : "";
      return kit.succeeded(r.data, `${kit.okHead(tool, r.status)} Returned the advisory ${shown}.${withdrawn}${rejectedCVEs}${cves}${held}`, env);
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
          freshnessNote(windows),
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
      const held = !w.ok ? windowsUnknown(w.why) : `${backfillingNote(windows ?? [])}${heldInPartNote(windows ?? [])}${collectionNote(windows ?? [])}`;
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
      const rejected = rows === undefined ? "" : `${rejectedCVENote(rows)}${rejectedUnknownNote(rows)}`;
      return kit.succeeded(r.data, `${head} ${what} ${counted}${page}.${rejected}${wordOnly}${held}`, env, searchText(a));
    } catch (e) {
      return kit.crashed(tool, e);
    }
  }

  server.registerTool(
    "vendor_advisories_for_cve",
    {
      title: "Vendor advisories for one CVE",
      description: `The vendor-published advisories that name one CVE, newest first, at most 20: for each, vendor, vendor_advisory_id, title, severity and cvss_v3_score where given. Covers the vendor feeds EchelonGraph polls, for example Microsoft MSRC, Red Hat, Cisco, Palo Alto Networks and GitHub GHSA; an empty answer means none of the advisories EchelonGraph holds names the CVE, not that no vendor published one. ${DATES_DESCRIPTION} ${REJECTED_CVE_DESCRIPTION} The answer's cve_rejected is true when the CVE record of the CVE asked for was rejected. Each row has remediation_kinds and remediation_state (not_parsed is not none). coverage gives returned, cap, at_cap (true: may be more) and cve_year; vendor_windows, each vendor's window: ${WINDOW_HEAD}; and vendors_not_fully_held, the vendors absent from the answer of which EchelonGraph holds none, whose held_since is after 1 January of cve_year or not known (outside history_scope, feed_held_since), or whose history is still being read or collection_state is not ok. ${NOT_HELD_HEAD} ${TEXT_BUDGET_DESCRIPTION}${ROW_CUT_DESCRIPTION}.`,
      inputSchema: z.object({ cve_id: z.string().describe("a CVE ID, e.g. CVE-2024-21412"), full: FULL_ARG }),
      outputSchema: FOR_CVE_OUTPUT,
      annotations: kit.annotations,
    },
    async ({ cve_id, full }) => kit.checked("vendor_advisories_for_cve", FOR_CVE_OUTPUT, await answering(full, FOR_CVE_DATA, () => forCVE(cve_id))),
  );

  server.registerTool(
    "get_vendor_advisory",
    {
      title: "Vendor advisory detail",
      description: `One vendor advisory in full, by vendor and advisory ID (the vendor and vendor_advisory_id of a vendor advisory row, never its advisory_id): title, description, severity, cvss_v3_score, cve_ids and known_cve_ids (in EchelonGraph's CVE feed), affected_products, remediation, references, vendor_modified_at, and withdrawn_at and withdrawn_reason when the vendor withdrew it. remediations: each the vendor lists, with kind (vendor_fix, workaround, mitigation, no_fix_planned, none_available or other: the vendor's category, or may be no_fix_planned if Cisco's summary says none will be released), source_category, text, url, cve_ids and product_ids; each text is the vendor's, verbatim, untested by EchelonGraph. remediation_state none_in_source or not_parsed is not a finding that no fix exists. ${DATES_DESCRIPTION} ${REJECTED_CVE_DESCRIPTION} coverage.vendor_window is what EchelonGraph holds of that vendor: ${WINDOW_HEAD_DETAIL}; null if unreadable or empty. measured_at is our_first_seen_at. ${ENVELOPE_DESCRIPTION} ${TEXT_BUDGET_DESCRIPTION} ${WITHHELD_DETAIL_DESCRIPTION}`,
      inputSchema: z.object({
        vendor: z.string().describe("the vendor slug, e.g. microsoft, redhat, github"),
        advisory_id: z
          .string()
          .describe("the vendor's own advisory ID, a row's vendor_advisory_id, e.g. RHSA-2024:1234, GHSA-xxxx-xxxx-xxxx or CVE-2024-3400; not a row's advisory_id, EchelonGraph's internal UUID"),
        full: FULL_ARG,
      }),
      outputSchema: DETAIL_OUTPUT,
      annotations: kit.annotations,
    },
    async ({ vendor, advisory_id, full }) => kit.checked("get_vendor_advisory", DETAIL_OUTPUT, await answering(full, NO_DATA_CUT, () => detail(vendor, advisory_id))),
  );

  server.registerTool(
    "search_vendor_advisories",
    {
      title: "Search vendor advisories",
      description: `Search or list vendor-published advisories, newest first. ${SEARCH_MATCH_HEAD} Filter by vendor (slug), severity band and whether the advisory names any CVE ID. Advisories their vendor withdrew are left out. Returns advisories, each with vendor, vendor_advisory_id, title, severity, cvss_v3_score, cve_ids, summary and affected_products where present, and total, total_capped, limit, offset, search_applied and search_match. ${TOTAL_CAPPED_HEAD} ${REJECTED_CVE_DESCRIPTION} The query is sent in a request header, never in the URL. coverage repeats those beside returned, and gives vendor_windows, each vendor's window in what EchelonGraph holds: ${WINDOW_HEAD_SCOPED}. ${NOT_HELD_HEAD} ${TEXT_BUDGET_DESCRIPTION}${ROW_CUT_DESCRIPTION}, or rows are left out and the note gives the offset to call next.`,
      inputSchema: z.object({
        query: z.string().optional().describe("free text, at most 100 bytes: a product, an advisory ID, a CVE ID or a keyword, e.g. 'exchange server'; 1 or 2 characters match whole words only"),
        vendor: z.string().optional().describe("a vendor slug, e.g. microsoft, redhat, github"),
        severity: z.enum(["Critical", "High", "Medium", "Low"]).optional().describe("one severity band"),
        has_cve: z.boolean().optional().describe("true: only advisories naming a CVE; false: only those naming none"),
        limit: z.number().int().min(1).max(50).optional().describe("page size (default 20, max 50)"),
        offset: z.number().int().min(0).max(10000).optional().describe("rows to skip (default 0)"),
        full: FULL_ARG,
      }),
      outputSchema: SEARCH_OUTPUT,
      annotations: kit.annotations,
    },
    async (a) => kit.checked("search_vendor_advisories", SEARCH_OUTPUT, await answering(a.full, SEARCH_DATA, () => search(a))),
  );
}
