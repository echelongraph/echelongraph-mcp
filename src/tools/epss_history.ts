// epss_history (#2718): how one CVE's EPSS score has changed, as EchelonGraph recorded it.
//
// GET /api/v1/public/cves/:id/epss-history (core-backend cve/epss_history.go). cves.epss_score
// is overwritten by the nightly EPSS fetcher (cve/epss/fetcher.go applyBatch), which records
// the NEW values in cve_enrichment_history (kind epss_batch) for each CVE whose score or
// percentile changed. So the series is CHANGE-ONLY: a point is a recorded change, and a night
// with no change has no point. This tool relays the points exactly as the API sends them and
// never fills the gaps: interpolating a daily series out of change points would present values
// nobody recorded as measurements.
//
// What the answer can and cannot say, and where the note says it:
//   - series_starts_at is the earliest epss_batch row in the whole table, when recording began.
//     Before it a missing point means "not recorded", not "unchanged". Null: nothing recorded.
//   - complete_since (#2867) is where the record becomes complete: the first row written by the
//     fetcher's atomic write (score and history row in one statement). Before it, between
//     series_starts_at and complete_since, the old write path dropped changes (measured on
//     production against FIRST's dated files: 202 of 300 sampled changes missing on 2026-09-21,
//     89 of 300 on 2026-09-27, 0 of 300 on 2026-10-05), so a missing point there does not mean
//     unchanged, and an empty series is "measured" only from complete_since. The note says so,
//     and never calls a series that reaches back before complete_since complete.
//   - coverage.first_day / last_day / days_held / days_partial / days_missing are FIRST score
//     dates from the fetcher's run log (epss_refresh_runs), which starts at run_log_since; each
//     point's score_date is that of the logged refresh that wrote it, null where none covers it.
//   - The value in force before a CVE's first point is not in the series.
//   - latest_point_matches_current false says a change is missing for this CVE.
//   - measured_at is current.epss_updated_at: when EchelonGraph last wrote a changed EPSS value
//     for the CVE. The fetcher writes only on change, so it is not when the value was last
//     checked, and it is not FIRST's score date, which the API does not serve.
//
// The cve_id is checked against the CVE id form before any request, so only a canonical CVE id
// ever travels in the URL path, never other typed text (#1983).
//
// Merge-friendliness (epic #2304 brief): the tool's logic, schema and texts live here; index.ts
// passes its shared helpers in (ToolKit) and calls registerEPSSHistory once.
import type { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod";
import { TEXT_BUDGET_DESCRIPTION } from "../textBudget.js";

type Text = { type: "text"; text: string };
type Result = { content: Text[]; structuredContent: Record<string, unknown>; isError?: boolean };
type SuccessEnvelope = {
  state: "measured" | "not_assessed";
  measured_at: string | null;
  method: string;
  coverage: Record<string, unknown> | null;
  freshness: Record<string, unknown> | null;
  notes?: string[];
};

// The helpers index.ts shares with this tool. Method syntax, so index.ts's own (narrower)
// Failure type is accepted where F stands.
export interface ToolKit<F extends { ok: false }> {
  api(path: string): Promise<{ ok: true; status: number; data: object } | F>;
  succeeded(data: object, note: string, env: SuccessEnvelope): Result;
  failed(tool: string, f: F): Result;
  badInput(tool: string, why: string): Result;
  crashed(tool: string, e: unknown): Result;
  checked(tool: string, schema: z.ZodType, r: Result): Result;
  okHead(tool: string, status?: number): string;
  envelopeSchema(o: { data: z.ZodType; coverage: z.ZodType | null; freshness: z.ZodType | null }): z.ZodType;
  annotations: { readOnlyHint: boolean; destructiveHint: boolean; idempotentHint: boolean; openWorldHint: boolean };
  cveIdArg: z.ZodString;
  instant: z.ZodString;
}

const TOOL = "epss_history";
const CVE_ID = /^CVE-\d{4}-\d{4,}$/i;

export const EPSS_HISTORY_METHOD =
  "EchelonGraph's record of FIRST's EPSS scores: the nightly EPSS fetcher overwrites each CVE's epss_score and epss_percentile from FIRST's published file and, for every CVE whose value changed, records the new values with the time it wrote them; this series is those records, oldest first, with repeated records of one change collapsed into the first.";

const CHANGE_ONLY =
  "series_kind is change_only: each point is a change EchelonGraph recorded, at the time it recorded it, and a day with no point is not a recorded value, so the series must not be read or redrawn as a daily series; no point here is interpolated.";
const BEFORE_FIRST = "The value in force before a CVE's first point is not in the series.";
const NO_FRESHNESS = "freshness is null: the answer does not carry the time of the EPSS fetcher's last completed run.";

export const EPSS_HISTORY_DESCRIPTION = `How one CVE's EPSS score (FIRST's exploit-prediction probability, 0 to 1, with its percentile) has changed, as EchelonGraph recorded it: points, oldest first, each with at, epss_score, epss_percentile and score_date (FIRST's score date, null where the record does not hold it); current, the record's value now (epss_score, epss_percentile, epss_updated_at); series_kind, always change_only; series_starts_at, when EchelonGraph began recording EPSS changes for any CVE; complete_since, from when the record holds every change; coverage, which FIRST score dates the record holds; history_rows, points_truncated and latest_point_matches_current. Pass a CVE ID like CVE-2023-44487. The series is change-only: a point is a recorded change, and a day without a point is not a recorded value. A daily series interpolated from it holds values EchelonGraph never recorded, so the series is never a daily series. Before series_starts_at nothing was recorded, so a missing point there means not recorded, not unchanged, and the value in force before a CVE's first point is not in the series. Between series_starts_at and complete_since the record misses changes, so a missing point there does not mean unchanged either; only from complete_since on is every change a point. coverage.days_missing and coverage.days_partial name the FIRST score dates the record does not hold, or holds for some CVEs only. latest_point_matches_current false means a change is missing from the series. Its structured result's measured_at is current.epss_updated_at (when EchelonGraph last wrote a changed value, not FIRST's score date), its coverage says which part of the record is complete and which score dates it holds, and its freshness is null. ${TEXT_BUDGET_DESCRIPTION}`;

// The API's JSON. points, series_kind and current are required: an answer without them is not
// this series, and a series_kind other than change_only would make every note above wrong, so
// either is a failure (checked), never relayed.
const opt = <T extends z.ZodType>(t: T) => t.nullable().optional();
const Point = (instant: z.ZodString) =>
  z.looseObject({
    at: instant.describe("When EchelonGraph recorded this change."),
    epss_score: z.number().describe("The EPSS probability (0 to 1) from that change on."),
    epss_percentile: opt(z.number()).describe("Its percentile (0 to 1), null where the record held none."),
    score_date: opt(z.string()).describe("FIRST's score date (YYYY-MM-DD) of the logged refresh that wrote this point; null where no logged refresh covers it."),
  });
const Day = z.string().describe("A FIRST score date, YYYY-MM-DD.");
const ApiCoverage = (instant: z.ZodString) =>
  z.looseObject({
    recorded_from: opt(instant).describe("series_starts_at: when recording began."),
    complete_since: opt(instant).describe("From here on every change a refresh applied is a point; before it changes are missing."),
    series_complete: opt(z.boolean()).describe("True only when nothing in the record predates complete_since."),
    points_before_complete_since: opt(z.number().int().min(0)).describe("This CVE's points in the part of the record that misses changes."),
    run_log_since: opt(instant).describe("The first logged refresh: score dates before it are not listed, held or missing."),
    first_day: opt(Day).describe("The earliest score date in the run log."),
    last_day: opt(Day).describe("The latest score date in the run log."),
    days_held: opt(z.number().int().min(0)).describe("Score dates from first_day to last_day that a refresh applied completely."),
    days_partial: opt(z.array(Day)).describe("Score dates whose refreshes all failed part-way: some CVEs hold that day, some do not."),
    days_missing: opt(z.array(Day)).describe("Score dates from first_day to last_day that no refresh applied."),
    runs_undated: opt(z.number().int().min(0)),
    refresh_runs_truncated: opt(z.boolean()),
  });
const data = (instant: z.ZodString) =>
  z.looseObject({
    cve_id: z.string(),
    series_kind: z.enum(["change_only"]).describe("Always change_only: one point per recorded change, none for a day without one."),
    series_starts_at: instant.nullable().describe("The earliest EPSS change EchelonGraph recorded for any CVE: when recording began. Null when nothing has been recorded."),
    complete_since: opt(instant).describe("From when the record holds every change a refresh applied. Between series_starts_at and complete_since changes are missing, so a missing point there does not mean unchanged. Absent from an API older than #2867."),
    coverage: opt(ApiCoverage(instant)).describe("Which part of the record is complete and which FIRST score dates it holds."),
    current: z.looseObject({
      epss_score: opt(z.number()).describe("The record's EPSS probability now; null when it holds none."),
      epss_percentile: opt(z.number()),
      epss_updated_at: opt(instant).describe("When EchelonGraph last wrote a changed EPSS value for this CVE."),
    }),
    points: z.array(Point(instant)).describe("Recorded changes, oldest first. Never a daily series."),
    history_rows: opt(z.number().int().min(0)).describe("Raw history rows read, before repeated records of one change were collapsed."),
    points_truncated: opt(z.boolean()).describe("True when only the newest rows were read, so the earliest points are missing."),
    latest_point_matches_current: opt(z.boolean()).describe("Whether the newest point equals current; false means a change is missing from the series; null when there is no point or no current value."),
  });

export function epssHistoryOutput<F extends { ok: false }>(kit: ToolKit<F>): z.ZodType {
  return kit.envelopeSchema({
    data: data(kit.instant),
    coverage: z.strictObject({
      series_kind: z.enum(["change_only"]),
      series_starts_at: kit.instant.nullable(),
      complete_since: kit.instant.nullable().describe("From when every change is a point; null when the API did not say, and then no part of the series is known complete."),
      series_complete: z.boolean().describe("True only when the API says nothing in the record predates complete_since."),
      points: z.number().int().min(0).describe("How many points the series holds."),
      points_before_complete_since: z.number().int().min(0).nullable().describe("How many of them fall where changes are missing; null when the API did not say."),
      points_truncated: z.boolean(),
      first_day: z.string().nullable().describe("The earliest FIRST score date the run log lists; null when it lists none."),
      last_day: z.string().nullable(),
      days_held: z.number().int().min(0).nullable().describe("Score dates from first_day to last_day the record holds; null when none are listed."),
      days_partial: z.array(z.string()).describe("Score dates held for some CVEs only."),
      days_missing: z.array(z.string()).describe("Score dates from first_day to last_day the record does not hold."),
    }),
    freshness: null,
  });
}

const isNum = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);
const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const realInstant = (v: unknown): v is string => typeof v === "string" && Date.parse(v) > 0;
const isDay = (v: unknown): v is string => typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v);
const dayList = (v: unknown): string[] => (Array.isArray(v) ? v.filter(isDay) : []);
// A day list in the note: the first DAYS_IN_NOTE, then how many more coverage holds.
const DAYS_IN_NOTE = 10;
const sayDays = (days: string[], field: string): string =>
  days.length <= DAYS_IN_NOTE ? days.join(", ") : `${days.slice(0, DAYS_IN_NOTE).join(", ")} and ${days.length - DAYS_IN_NOTE} more (coverage.${field})`;

// What the answer says about its own completeness (#2867), read once for the note and coverage.
type Completeness = {
  completeSince: string | undefined;
  seriesComplete: boolean;
  pointsBefore: number | undefined;
  firstDay: string | undefined;
  lastDay: string | undefined;
  daysHeld: number | undefined;
  daysPartial: string[];
  daysMissing: string[];
  runLogSince: string | undefined;
  hasCoverage: boolean;
};

function completeness(d: Record<string, unknown>, points: Record<string, unknown>[]): Completeness {
  const cov = isObj(d.coverage) ? d.coverage : {};
  const completeSince = realInstant(d.complete_since) ? d.complete_since : realInstant(cov.complete_since) ? cov.complete_since : undefined;
  let pointsBefore: number | undefined;
  if (isNum(cov.points_before_complete_since)) pointsBefore = cov.points_before_complete_since;
  else if (completeSince) pointsBefore = points.filter((p) => realInstant(p.at) && Date.parse(p.at) < Date.parse(completeSince)).length;
  const firstDay = isDay(cov.first_day) ? cov.first_day : undefined;
  const lastDay = isDay(cov.last_day) ? cov.last_day : undefined;
  return {
    completeSince,
    // Complete only on the API's word AND with a complete_since to be complete from.
    seriesComplete: completeSince !== undefined && cov.series_complete === true,
    pointsBefore,
    firstDay,
    lastDay,
    daysHeld: firstDay && isNum(cov.days_held) ? cov.days_held : undefined,
    daysPartial: dayList(cov.days_partial),
    daysMissing: dayList(cov.days_missing),
    runLogSince: realInstant(cov.run_log_since) ? cov.run_log_since : undefined,
    hasCoverage: isObj(d.coverage),
  };
}

// The note: what came back, in words, and what it does not say.
function note(head: string, id: string, d: Record<string, unknown>, c: Completeness): { note: string; own: string[] } {
  const points = Array.isArray(d.points) ? d.points.filter(isObj) : [];
  const cur = isObj(d.current) ? d.current : {};
  const curScore = isNum(cur.epss_score) ? cur.epss_score : undefined;
  const start = realInstant(d.series_starts_at) ? d.series_starts_at : undefined;
  const s: string[] = [head];
  s.push(
    curScore === undefined
      ? `EchelonGraph's record holds no EPSS score for ${id} (current.epss_score is null).`
      : `${id}'s EPSS score in EchelonGraph's record is ${curScore}${isNum(cur.epss_percentile) ? ` (percentile ${cur.epss_percentile})` : ""}.`,
  );
  if (points.length === 0) {
    if (!start) {
      s.push("No EPSS change has been recorded for any CVE yet (series_starts_at is null), so this empty series says nothing about how the score moved.");
    } else if (c.seriesComplete) {
      s.push(`No EPSS change is recorded for ${id} since recording began at ${start}: a measured empty series, not a lookup failure.`);
    } else if (c.completeSince) {
      // "Measured" only for the complete part (#2867).
      s.push(
        `No EPSS change is recorded for ${id} since recording began at ${start}. From complete_since (${c.completeSince}) that is measured: no refresh since then changed it. Before complete_since the record misses changes, so the empty series is not evidence that the score held still from ${start} to ${c.completeSince}.`,
      );
    } else {
      s.push(
        `No EPSS change is recorded for ${id} since recording began at ${start}. The answer does not say from when the record is complete, so the empty series is not evidence that the score held still.`,
      );
    }
  } else {
    const first = points[0];
    const last = points[points.length - 1];
    s.push(
      `${points.length} recorded change${points.length === 1 ? "" : "s"}, from ${first.epss_score} at ${first.at} to ${last.epss_score} at ${last.at}.`,
    );
  }
  if (start) s.push(`Recording began at ${start} (series_starts_at): before it a missing point means not recorded, not unchanged.`);
  if (c.seriesComplete) {
    s.push(`The record is complete (complete_since ${c.completeSince}): every change a refresh applied since recording began is a point.`);
  } else if (c.completeSince) {
    const where = c.pointsBefore ? ` ${c.pointsBefore} of this series' ${points.length} point${points.length === 1 ? "" : "s"} fall there.` : "";
    s.push(
      `The record is complete only from ${c.completeSince} (complete_since): from then on every change a refresh applied is a point. Between ${start ?? "series_starts_at"} and complete_since EchelonGraph's earlier write path missed changes, so there a missing point does not mean unchanged, and this series is not complete.${where}`,
    );
  } else if (start) {
    s.push("The answer does not say from when the record is complete (complete_since is absent), so a missing point anywhere in this series may be a missed change, not an unchanged score.");
  }
  if (c.firstDay && c.lastDay) {
    const held = c.daysHeld === undefined ? "" : `, ${c.daysHeld} held`;
    const missing = c.daysMissing.length ? `; not held: ${sayDays(c.daysMissing, "days_missing")}` : "; none missing";
    const partial = c.daysPartial.length ? `; held for some CVEs only (a refresh failed part-way): ${sayDays(c.daysPartial, "days_partial")}` : "";
    const since = c.runLogSince ? ` (run log since ${c.runLogSince}; earlier dates are not listed)` : "";
    s.push(`FIRST score dates in EchelonGraph's run log${since}: ${c.firstDay} to ${c.lastDay}${held}${missing}${partial}.`);
  } else if (c.hasCoverage) {
    s.push("The run log lists no FIRST score date yet, so this answer does not say which days the record holds, and no point carries a score_date.");
  }
  if (d.points_truncated === true) s.push("points_truncated is true: only the newest records were read, so the earliest changes are missing from this series.");
  if (d.latest_point_matches_current === false) {
    s.push("latest_point_matches_current is false: the newest recorded point is not the record's current value, so at least one change is missing from the series.");
  }
  return { note: s.join(" "), own: [CHANGE_ONLY, BEFORE_FIRST] };
}

export async function epssHistory<F extends { ok: false }>(kit: ToolKit<F>, cve_id: string): Promise<Result> {
  const id = cve_id.trim();
  if (!id) return kit.badInput(TOOL, "cve_id is required");
  if (!CVE_ID.test(id)) return kit.badInput(TOOL, `cve_id ${JSON.stringify(id.slice(0, 32))} is not a CVE id (expected the form CVE-2023-44487)`);
  const cve = id.toUpperCase();
  try {
    const r = await kit.api(`/api/v1/public/cves/${encodeURIComponent(cve)}/epss-history`);
    if (!r.ok) return kit.failed(TOOL, r);
    const d = r.data as Record<string, unknown>;
    const name = typeof d.cve_id === "string" && d.cve_id ? d.cve_id : cve;
    const c = completeness(d, Array.isArray(d.points) ? d.points.filter(isObj) : []);
    const { note: n, own } = note(kit.okHead(TOOL, r.status), name, d, c);
    const cur = isObj(d.current) ? d.current : {};
    const written = realInstant(cur.epss_updated_at) ? cur.epss_updated_at : null;
    return kit.succeeded(r.data, n, {
      state: "measured",
      measured_at: written,
      method: EPSS_HISTORY_METHOD,
      coverage: {
        series_kind: d.series_kind,
        series_starts_at: d.series_starts_at ?? null,
        complete_since: c.completeSince ?? null,
        series_complete: c.seriesComplete,
        points: Array.isArray(d.points) ? d.points.length : 0,
        points_before_complete_since: c.pointsBefore ?? null,
        points_truncated: d.points_truncated === true,
        first_day: c.firstDay ?? null,
        last_day: c.lastDay ?? null,
        days_held: c.daysHeld ?? null,
        days_partial: c.daysPartial,
        days_missing: c.daysMissing,
      },
      freshness: null,
      notes: [
        ...own,
        written
          ? "measured_at is current.epss_updated_at: when EchelonGraph last wrote a changed EPSS value for this CVE; values are written only on change, so it is not when the value was last checked, and it is not FIRST's score date."
          : "measured_at is null: the record carries no epss_updated_at.",
        NO_FRESHNESS,
      ],
    });
  } catch (e) {
    return kit.crashed(TOOL, e);
  }
}

export function registerEPSSHistory<F extends { ok: false }>(server: McpServer, kit: ToolKit<F>): void {
  const output = epssHistoryOutput(kit);
  server.registerTool(
    TOOL,
    {
      title: "EPSS change history for one CVE",
      description: EPSS_HISTORY_DESCRIPTION,
      inputSchema: z.object({ cve_id: kit.cveIdArg }),
      outputSchema: output,
      annotations: kit.annotations,
    },
    async ({ cve_id }) => kit.checked(TOOL, output, await epssHistory(kit, cve_id)),
  );
}
