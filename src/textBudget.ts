// The text budget (#2783), and the structured result's (#3013): what a success may cost in each
// channel a client hands a model, and how an answer larger than that is cut. index.ts's
// `succeeded` builds every success's first text block with dataText (a tool that returns a list of
// rows names it with a TextCut), and its structured result with cutData (each tool names its lists
// in the order they are cut with a DataCut, and answering() hands the call's `full` and DataCut to
// `succeeded`). A module of its own, so a tool module can import its types,
// TEXT_BUDGET_DESCRIPTION and FULL_ARG without importing index.ts, which starts the stdio server
// when loaded.
import { AsyncLocalStorage } from "node:async_hooks";
import * as z from "zod";

// What a success costs in the channel a model reads is mostly its first text block, and through
// 2.6.2 that block was the API's JSON pretty-printed, whatever its size. Measured on production
// through https://mcp.echelongraph.io/mcp (2.6.2, 2026-10-04): search_cves {search: "openssl"} at
// its default limit was 133,300 characters of text, get_cve CVE-2021-44228 80,897, check_affected
// openssl 3.0.0 156,058 and linux_kernel 5.10.0 364,408, kev_recent at limit 200 105,925 and
// search_vendor_advisories "log4j" at limit 50 103,147, against #2467's ceiling of 60,000
// (mcp-server/test/text-bound.mjs). Claude Code warns past 10,000 tokens of tool output and past
// 25,000 saves the result to a file and hands the model its path instead; Anthropic's guidance to
// tool authors ("Writing effective tools for agents") is pagination, filtering and truncation with
// sensible defaults, steering the agent when a response is cut. The MCP spec (2025-06-18 and
// 2025-11-25, Tools, Structured Content) asks a tool that returns structuredContent to return it
// serialized in a text block too, as a SHOULD, for backwards compatibility, and SEP-1624 proposes
// content as the model-facing, token-efficient form and structuredContent as the machine-facing one.
//
// So the first text block is the API's JSON when it fits DATA_TEXT_BUDGET, half the ceiling, and
// cut when it does not (structuredContent.data, below, is cut on its own terms, never from this):
//   1. pretty-printed, as since 1.x, when that fits;
//   2. else the same JSON with each element of a list on a line of its own, which parses to the
//      same value, when that fits;
//   3. else, for a tool that names its list of rows (TextCut), each row cut as the tool's first
//      level says (the fields it keeps, every string in it to its first `clip` characters, ending
//      in "…", every list in it to its first `cap` entries); then, for a tool that names the
//      lists beside its rows (`sides`: check_affected's excluded sample, check_sbom's
//      not_sent_purls), the same level with those lists cut as it says; then each next level with
//      them cut; and when no level fits, rows are left out of the text, those the tool names
//      first, then from the end. A list beside the rows is cut before any row field the first
//      level keeps, and before any row leaves the text;
//   4. else every list keeps its first n entries, n halving, and then strings are cut too.
// Whenever the text is not the JSON whole, the note ends with one sentence, starting TEXT CUT,
// that says what the first text block leaves out, where structuredContent.data carries all of it,
// and how to read the rest in the text: the tool that returns one row, and what of it, and the page
// size or offset at which a page fits. The cut is deterministic: the same answer is cut the same way.
//
// The structured result, per client (#3013). Through 2.7.x structuredContent.data was the API's
// JSON whole, on the reading above that structuredContent is the machine-facing form. It is not, in
// the client the README gives first-class install steps: Claude Code hands the model
// structuredContent, not the text blocks (reproduced 2026-10-11 over raw JSON-RPC: get_cve
// CVE-2021-44228 was 65,540 characters of structuredContent beside a first text block of 23,759,
// and Claude Code refused it, "exceeds maximum allowed tokens", against its default
// MAX_MCP_OUTPUT_TOKENS of 25,000, and saved it to a file, so the model got a path, not an answer).
// The spec (MCP 2025-06-18, Tools, Structured Content) does not say which of the two a client gives
// the model. So the text cut above reached every client but that one. Since 3.0.0 the structured
// result is held to the same budget, STRUCTURED_BUDGET: the whole of it, envelope and notes with
// data, as compact JSON, since that is what such a client sizes. Past it, data is cut (cutData):
//   1. the lists the tool's DataCut names, step by step in its order. Where a step names thinning
//      levels (a list whose single entries are large: check_sbom's and scan_manifest's results,
//      check_affected's matches, cve_remediation's vendor_remediations, search_cves' and the
//      vendor-advisory tools' rows), every entry is first cut to the fields each level keeps, level
//      by level, all entries kept, so that no row leaves while thinning its detail would do; then
//      each step keeps the most entries that fit, every list in the step at most the same number,
//      its first ones, or for a list named with leaveOutFirst (check_sbom's results) those entries
//      the tool names leave first (the clean rows, counted in data.summary), then the last of the
//      rest, or for a step of series named keepNewest (exposure_radar's daily and weekly counts,
//      which the API sends oldest first) its last ones, the newest, the oldest leaving first; a
//      step that cannot fit even empty is emptied, and the next one is cut. A level can cut inside
//      each entry on its own terms (an EntryLevel, #3132: check_sbom's rows keep at most the same
//      number of matches, the most that fit, so only the rows with more lose any), and a step named
//      keepAll (#3139: cve_remediation's vendor_remediations) keeps every entry at its leanest level
//      while the later steps are cut, its entries leaving only once they all are;
//   2. then every other list at the top level of data, the same way. A list inside an object of
//      data (get_cve's remediation summary, with fix_status, #2841) is cut only where a DataCut
//      names it, and none names get_cve's. Once a step fits, the room it leaves goes back to the
//      steps emptied before it, the last first, each the same way (scan_manifest's not_checked,
//      emptied while its rows were whole, keeps its entries once the thinned rows fit);
//   3. no string is shortened and no value changes: a thinned entry keeps some of its fields as
//      they are (every field a thinning level drops is optional in the outputSchema, so data still
//      validates against it), and no field outside the lists cut changes (the one field a cut
//      adds is an EntryLevel's mark, check_sbom's matches_truncated, which says what the row's own
//      cut left out, and which its outputSchema names); the envelope says
//      data_truncated true, truncated gives each list cut by its path in data with its total, the
//      number returned and, where its entries are thinned, thinned true, and the note ends with
//      sentences starting DATA CUT that say what was cut and to which fields, how to read the rest
//      (the offset or page size, where the tool pages: a page size the note says fits data whole
//      is counted on the entries whole, never on the thinned ones, #3013's review) and that the
//      same call with full: true returns data whole.
// The first text block is cut from the whole answer as before, not from the cut data: what it
// holds is unchanged for the clients that read it. full: true is for programs, which read data
// whole whatever its size; a client that sizes structured results, Claude Code among them, may
// still refuse such an answer past its own cap (MAX_MCP_OUTPUT_TOKENS raises Claude Code's).
// Rejected (#3013's decision of 2026-10-11): saying only that Claude Code gets files; cutting only
// for a client whose clientInfo.name is Claude Code (the same call would answer differently by
// client, and the next client to pass structuredContent on would get the 65,540 again); and dropping
// structuredContent (it loses the outputSchema check the spec recommends and the suite relies on).
export const DATA_TEXT_BUDGET = 30_000;
// What a note may say of reading one CVE's record through get_cve (#2802): get_cve's own first text
// block is cut too past the budget (each list to its first entries, every other field kept), and
// since #3013 so is its structured result's data, unless the call says full: true. A row tool's
// `whole` sentence starts with it.
export const GET_CVE_WHOLE =
  "get_cve returns any one of these CVEs' records, whole in its structuredContent.data with full: true, and in its first text block with every field (past 30,000 characters, each list cut to its first entries)";
// What every tool description says about it, one constant string (marketing-site
// lib/mcpToolClaims.test.ts folds only constant strings); the suite holds its number to
// DATA_TEXT_BUDGET's. It uses none of the words that check reviews as the page's own prose (how,
// when, does, have, on and the rest of its PROSE list), so no reviewed entry goes stale. #3013: the
// same length as 2.7.x's (203 characters), since several descriptions sit within ten characters of
// the floor the suite keeps under the client cut (#2924); FULL_ARG says the rest.
export const TEXT_BUDGET_DESCRIPTION =
  "Past 30,000 characters of JSON, the first text block holds data cut to fit, and the note says what the cut leaves out and where to read it (TEXT CUT); so is structured data (DATA CUT), unless full: true.";

const isPlainObject = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const field = (o: unknown, k: string): unknown => (isPlainObject(o) ? o[k] : undefined);
const listed = (xs: string[]): string => (xs.length < 2 ? xs.join("") : `${xs.slice(0, -1).join(", ")} and ${xs[xs.length - 1]}`);

// What a row keeps at one level of a cut: the fields named (in the row's own order; [field,
// subfields] keeps a list of objects inside the row, each cut to its subfields), every string to
// its first `clip` characters and, with `cap`, every list inside the row to its first `cap` entries.
export type RowKeep = readonly (string | readonly [string, readonly string[]])[];
export type TextCutLevel = { keep: RowKeep; clip: number; cap?: number };
// A list beside the rows (another top-level list in data) and how the text cuts it once the first
// level alone does not fit: each entry that is an object to the fields `keep` names, every string
// in it to its first `clip` characters, and the list to its first `cap` entries; and the tool's
// sentence for what the list still says, given how many entries the text keeps and how many the
// list holds (`said`).
export type TextSide = { list: string; keep?: RowKeep; clip?: number; cap?: number; said?: (inText: number, total: number, data: object) => string };
// A tool's cut: the list in data whose rows it cuts (`rows`), its levels, most kept first; the
// lists beside the rows and how each is cut (`sides`); the rows left out first when rows must go
// (`leaveOutFirst`: those whose `field` is one of `values`, in that order, and why that loses
// nothing); the sentence naming the tool that returns one row whole; and the sentence saying how
// to read the rows left out in the text.
export type TextCut = {
  rows: string;
  levels: readonly TextCutLevel[];
  sides?: readonly TextSide[];
  leaveOutFirst?: { field: string; values: readonly string[]; why: string };
  whole?: string;
  page?: (inText: number, rows: number, data: object) => string;
};

// The JSON with each element of a list of objects, at the top or one level down, on a line of its
// own: the same value as JSON.stringify(data), without the indentation of every nested key.
function lined(v: Record<string, unknown>): string {
  const entry = (x: unknown): string =>
    Array.isArray(x) && x.some((e) => e !== null && typeof e === "object") ? `[\n${x.map((e) => `    ${JSON.stringify(e)}`).join(",\n")}\n  ]` : JSON.stringify(x);
  return `{\n${Object.entries(v)
    .map(([k, x]) => `  ${JSON.stringify(k)}: ${entry(x)}`)
    .join(",\n")}\n}`;
}

// A string's first n characters and "…", never splitting a surrogate pair.
const clipString = (s: string, n: number): string => {
  const end = n > 0 && /[\uD800-\uDBFF]/.test(s[n - 1]) ? n - 1 : n;
  return `${s.slice(0, end)}…`;
};
type CutStats = { left: Set<string>; clipped: number; capped: number };
function cutValue(v: unknown, clip: number, cap: number, s: CutStats): unknown {
  if (typeof v === "string") {
    if (v.length <= clip) return v;
    s.clipped++;
    return clipString(v, clip);
  }
  if (Array.isArray(v)) {
    if (v.length > cap) s.capped++;
    return v.slice(0, cap).map((x) => cutValue(x, clip, cap, s));
  }
  if (isPlainObject(v)) return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, cutValue(x, clip, cap, s)]));
  return v;
}
function cutRow(row: Record<string, unknown>, keep: RowKeep, level: TextCutLevel, s: CutStats, prefix = ""): Record<string, unknown> {
  const wanted = new Map<string, readonly string[] | null>(keep.map((k) => (typeof k === "string" ? [k, null] : [k[0], k[1]])));
  const cap = level.cap ?? Number.POSITIVE_INFINITY;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(row)) {
    if (!wanted.has(k)) {
      s.left.add(`${prefix}${k}`);
      continue;
    }
    const sub = wanted.get(k);
    if (sub && Array.isArray(v)) {
      if (v.length > cap) s.capped++;
      out[k] = v.slice(0, cap).map((e) => (isPlainObject(e) ? cutRow(e, sub, level, s, `${prefix}${k}[].`) : cutValue(e, level.clip, cap, s)));
    } else {
      out[k] = cutValue(v, level.clip, cap, s);
    }
  }
  return out;
}
// Step 4: every list to its first n entries (and, with clip, every string to its first clip
// characters), recording the longest list cut at each path.
function capAll(v: unknown, n: number, clip: number, caps: Map<string, number>, s: CutStats, path: string): unknown {
  if (Array.isArray(v)) {
    if (v.length > n) caps.set(path, Math.max(caps.get(path) ?? 0, v.length));
    return v.slice(0, n).map((x) => capAll(x, n, clip, caps, s, `${path}[]`));
  }
  if (isPlainObject(v)) return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, capAll(x, n, clip, caps, s, path ? `${path}.${k}` : k)]));
  return cutValue(v, clip, Number.POSITIVE_INFINITY, s);
}
const CAP_LEVELS: readonly { n: number; clip: number }[] = [
  ...[128, 64, 32, 16, 8, 4, 2, 1].map((n) => ({ n, clip: Number.POSITIVE_INFINITY })),
  { n: 1, clip: 200 },
  { n: 0, clip: 50 },
];

// The sentence for a level of a TextCut: what each row leaves out.
function levelSaid(rows: string, n: number, level: TextCutLevel, s: CutStats): string {
  const parts: string[] = [];
  if (s.left.size) parts.push(`each of the ${n} rows of ${rows} in it leaves out ${listed([...s.left])}`);
  if (s.clipped) parts.push(`every string in a row longer than ${level.clip} characters keeps its first ${level.clip}, ending in "…"`);
  if (s.capped && level.cap !== undefined) parts.push(`every list in a row longer than ${level.cap} entries keeps its first ${level.cap}`);
  if (!parts.length) return "";
  const said = parts.join("; ");
  return `${said[0].toUpperCase()}${said.slice(1)}.`;
}

// The lists beside the rows, each cut as its TextSide says, and the sentences saying how: what its
// entries leave out, and how many of them the text keeps, then the tool's own sentence.
function cutSides(data: Record<string, unknown>, sides: readonly TextSide[]): { fields: Record<string, unknown>; said: string[] } {
  const fields: Record<string, unknown> = {};
  const said: string[] = [];
  for (const side of sides) {
    const v = data[side.list];
    if (!Array.isArray(v) || v.length === 0) continue;
    const clip = side.clip ?? Number.POSITIVE_INFINITY;
    const cap = side.cap ?? v.length;
    const s: CutStats = { left: new Set(), clipped: 0, capped: 0 };
    const level: TextCutLevel = { keep: side.keep ?? [], clip };
    const kept = v.slice(0, cap).map((e) => (side.keep && isPlainObject(e) ? cutRow(e, side.keep, level, s) : cutValue(e, clip, Number.POSITIVE_INFINITY, s)));
    fields[side.list] = kept;
    const parts: string[] = [];
    if (kept.length < v.length) parts.push(`in it, ${side.list} keeps its first ${kept.length} of ${v.length} entries`);
    if (s.left.size) parts.push(`each entry of ${side.list} in it leaves out ${listed([...s.left])}`);
    if (s.clipped) parts.push(`every string in ${side.list} longer than ${clip} characters keeps its first ${clip}, ending in "…"`);
    if (!parts.length) continue;
    const one = parts.join("; ");
    said.push(`${one[0].toUpperCase()}${one.slice(1)}.`);
    const own = side.said?.(kept.length, v.length, data);
    if (own) said.push(own);
  }
  return { fields, said };
}

// Where the cut JSON goes, as the sentence that opens what the note says of the cut names it: by
// default a tool result's first text block, beside a structuredContent.data that holds the answer
// whole. The cve:// resource has no first text block and no data beside its own, so it names its
// own place (resources.ts, #2801). `leftOut` says where the rows a cut leaves out of the text are
// (`which` says which they are); by default, in structuredContent.data only.
export type CutPlace = { opens: (chars: number) => string; leftOut?: (n: number, which: string) => string };
export const FIRST_TEXT_BLOCK: CutPlace = {
  opens: (chars) =>
    `TEXT CUT: the API's answer is ${chars} characters of JSON, more than the ${DATA_TEXT_BUDGET} the first text block holds, so that block is cut, and structuredContent.data carries the answer whole.`,
};
// #3013: the first text block beside a structuredContent.data that is cut too (DATA CUT): the same
// text, cut the same way, and sentences that say data is whole only with full: true.
export const FIRST_TEXT_BLOCK_BESIDE_A_CUT: CutPlace = {
  opens: (chars) =>
    `TEXT CUT: the API's answer is ${chars} characters of JSON, more than the ${DATA_TEXT_BUDGET} the first text block holds, so that block is cut, and structuredContent.data carries the answer whole with full: true (DATA CUT, below).`,
  leftOut: (n, which) => `the other ${n} are left out of it${which}, and structuredContent.data holds them with full: true`,
};

// What step 4 cut, for a caller that states it as a structured result's truncated does (the cve://
// resource, #3013's review): each list it cut to its first entries, by its path in data (a dot
// between the names of an object and a list inside it, and [] for a list inside each entry of a
// list), with total, its length (for a list inside each entry, the longest), and returned, the
// most entries each keeps. Present only when step 4 cut a list; a cut of strings alone has none.
export type Capped = Record<string, { total: number; returned: number }>;

/** The first text block for `data` within DATA_TEXT_BUDGET, and the TEXT CUT sentence when it is cut. */
export function dataText(data: object, cut?: TextCut, place: CutPlace = FIRST_TEXT_BLOCK): { text: string; said: string; capped?: Capped } {
  const pretty = JSON.stringify(data, null, 2);
  if (pretty.length <= DATA_TEXT_BUDGET) return { text: pretty, said: "" };
  const layout = (v: unknown): string => (isPlainObject(v) ? lined(v) : JSON.stringify(v));
  const all = layout(data);
  if (all.length <= DATA_TEXT_BUDGET) return { text: all, said: "" };
  const head = place.opens(pretty.length);
  const say = (...xs: (string | undefined)[]) => [head, ...xs].filter((x): x is string => Boolean(x)).join(" ");
  let base: unknown = data;
  let rowsSaid = "";
  let sidesSaid: string[] = [];
  const rows = cut && isPlainObject(data) ? data[cut.rows] : undefined;
  if (cut && isPlainObject(data) && Array.isArray(rows) && rows.length > 0 && cut.levels.length > 0) {
    const n = rows.length;
    // The lists beside the rows, cut once; tried with the first level after it fails with them
    // whole, and with every later level.
    const sides = cut.sides?.length ? cutSides(data, cut.sides) : { fields: {}, said: [] };
    const sided = sides.said.length > 0;
    const attempts = cut.levels.flatMap((level, i) => (i === 0 && sided ? [{ level, sided: false }, { level, sided: true }] : [{ level, sided }]));
    let cutRows: unknown[] = [];
    let beside: Record<string, unknown> = data;
    for (const attempt of attempts) {
      const { level } = attempt;
      const s: CutStats = { left: new Set(), clipped: 0, capped: 0 };
      const cap = level.cap ?? Number.POSITIVE_INFINITY;
      cutRows = rows.map((r) => (isPlainObject(r) ? cutRow(r, level.keep, level, s) : cutValue(r, level.clip, cap, s)));
      rowsSaid = levelSaid(cut.rows, n, level, s);
      beside = attempt.sided ? { ...data, ...sides.fields } : data;
      sidesSaid = attempt.sided ? sides.said : [];
      const shown = lined({ ...beside, [cut.rows]: cutRows });
      if (shown.length <= DATA_TEXT_BUDGET) return { text: shown, said: say(rowsSaid, ...sidesSaid, cut.whole) };
    }
    // No level fits: rows leave the text, those the tool names first (by value, in its order,
    // each from the end), then the rest from the end, until it fits.
    const lens = cutRows.map((r) => 4 + JSON.stringify(r).length);
    const emptyLen = lined({ ...beside, [cut.rows]: [] }).length;
    const textLen = (kept: number, sum: number) => (kept === 0 ? emptyLen : emptyLen + 2 + sum + 2 * kept);
    const firstOut = cut.leaveOutFirst;
    const order: number[] = [];
    for (const value of firstOut?.values ?? []) {
      for (let i = n - 1; i >= 0; i--) if (field(rows[i], firstOut?.field ?? "") === value) order.push(i);
    }
    const queued = new Set(order);
    for (let i = n - 1; i >= 0; i--) if (!queued.has(i)) order.push(i);
    const out = new Set<number>();
    let sum = lens.reduce((t, x) => t + x, 0);
    for (const i of order) {
      if (textLen(n - out.size, sum) <= DATA_TEXT_BUDGET) break;
      out.add(i);
      sum -= lens[i];
    }
    const kept = cutRows.filter((_, i) => !out.has(i));
    const shown = lined({ ...beside, [cut.rows]: kept });
    if (kept.length > 0 && shown.length <= DATA_TEXT_BUDGET) {
      const outFirst = firstOut ? [...out].filter((i) => firstOut.values.includes(String(field(rows[i], firstOut.field)))).length : 0;
      const which =
        outFirst > 0
          ? `: the ${outFirst} whose ${firstOut?.field} is ${(firstOut?.values ?? []).join(" or ")} (${firstOut?.why})${out.size > outFirst ? `, and the last ${out.size - outFirst} of the rest` : ""}`
          : `, the last ${out.size} in order`;
      const elsewhere = place.leftOut ? place.leftOut(out.size, which) : `the other ${out.size} are in structuredContent.data only${which}`;
      const left = `Only ${kept.length} of the ${n} rows of ${cut.rows} are in it; ${elsewhere}.`;
      return { text: shown, said: say(rowsSaid, ...sidesSaid, left, cut.whole, cut.page?.(kept.length, n, data)) };
    }
    base = { ...beside, [cut.rows]: cutRows };
  }
  // Step 4: lists, then strings.
  let last = { text: all, caps: new Map<string, number>(), s: { left: new Set<string>(), clipped: 0, capped: 0 } as CutStats, n: 0, clip: 0 };
  for (const { n, clip } of CAP_LEVELS) {
    const caps = new Map<string, number>();
    const s: CutStats = { left: new Set(), clipped: 0, capped: 0 };
    last = { text: layout(capAll(base, n, clip, caps, s, "")), caps, s, n, clip };
    if (last.text.length <= DATA_TEXT_BUDGET) break;
  }
  const named = [...last.caps].slice(0, 8).map(([p, len]) => `${p || "the answer"} (${len})`);
  const more = last.caps.size > 8 ? `, and ${last.caps.size - 8} more` : "";
  const lists = last.caps.size ? `Every list in it keeps at most its first ${last.n} ${last.n === 1 ? "entry" : "entries"}: ${listed(named)}${more}, each named with its full length.` : "";
  const strings = last.s.clipped ? `Every string in it longer than ${last.clip} characters keeps its first ${last.clip}, ending in "…".` : "";
  const said = say(rowsSaid, ...sidesSaid, lists, strings, cut?.whole);
  if (last.caps.size === 0) return { text: last.text, said };
  return { text: last.text, said, capped: Object.fromEntries([...last.caps].map(([p, len]) => [p || "the answer", { total: len, returned: Math.min(last.n, len) }])) };
}


// ── The structured result's budget (#3013) ──
//
// What a success's structured result may cost, all of it (the envelope, its notes and data), as
// compact JSON, which is how a client that hands structuredContent to a model reads it: the same
// number as the first text block's. See "The structured result, per client" above.
export const STRUCTURED_BUDGET = DATA_TEXT_BUDGET;

// The entries a list cut leaves out first, before the last of the rest (check_sbom's clean rows,
// which data.summary counts), and why that loses nothing.
export type LeaveOutFirst = { field: string; values: readonly string[]; why: string };
// One step of a cut: the lists it cuts, each by its path in data ("a.b" for a list inside an
// object of data), each to at most the same number of entries. With `thin`, before any entry
// leaves, every entry is cut to the fields each level names, level by level, the leanest last, as
// a TextCut level names them (a [field, subfields] pair cuts each object of a list in the entry to
// its subfields), but with no string shortened and no list in an entry capped; then entries leave
// from the leanest level. With `keepNewest` (#3013's review), the step's lists are series the API
// sends oldest first (exposure_radar's shadow_ai.observed.trend_30d, ORDER BY d ASC in core-backend
// shadowctlog/store.go, and kev_exposure.trend, ORDER BY wk in kevexposure/store.go
// statsTrendSQL): each keeps its last entries, the newest, its oldest leaving first, so a cut
// series still ends at the latest day or week, and the note says it keeps the newest. The data is
// never reordered.
//
// #3132: a level of `thin` is the fields it keeps (RowKeep), or an EntryLevel, which also cuts
// inside each entry on that entry's own terms. Through 3.0.0 every level was a RowKeep, and the
// same for every entry, so check_sbom's one level (SBOM_ROW_THIN) kept every match object of every
// row, and a single row still past the budget so thinned (linux-libc-dev 6.1.55-1's 200 matches,
// 42,417 characters thinned; magento/community-edition 2.3.0's 200) left, and every row after it
// with it: a Debian 12 SBOM of five affected rows kept 1, one large purl alone kept none. An
// EntryLevel with `capped` names a list inside each entry (check_sbom's matches) and caps it in
// every entry at the same number m, the most that fit with every entry kept, so only the entries
// with more than m lose any of it, the largest first; `mark` gives the fields an entry carries
// beside those kept (check_sbom's per-row matches_truncated: the row's own total, the number its
// matches keep, and what the matches cut held), given the entry whole and m (Infinity at a level
// that caps nothing); `said` is the clause the DATA CUT sentence adds for the level. Only at the
// leanest level do entries leave, as before.
//
// #3132's review: `least` is the smallest cap at which a capped level is taken; below it the next
// level is tried (check_sbom's SBOM_ROW_THIN capped is passed rather than kept with no match, where
// the compact level after it still holds some).
export type EntryLevel = {
  keep: RowKeep;
  capped?: string;
  least?: number;
  mark?: (whole: Record<string, unknown>, cap: number) => Record<string, unknown>;
  said?: (cap: number) => string;
};
export type ThinLevel = RowKeep | EntryLevel;
// #3139: with `keepAll`, the step's entries are thinned level by level as above, but none leaves
// in it: when even its leanest level does not fit with every entry, every entry is kept at that
// level and the cut goes on to the next steps; only once every later step is cut, and the result is
// still past the budget, do this step's entries leave (cve_remediation's vendor_remediations: its
// fixed_branches and patches are cut before any advisory leaves, so CVE-2023-44487 keeps all 20
// advisories thinned, where 3.0.0 kept 2 and fixed_branches whole).
//
// #3132's review: three more, for check_sbom's and scan_manifest's lists.
//  - `leaveAt`: when not even the leanest level keeps every entry, the entries leave at this level
//    of `thin` (its index), capped at `cap` where it caps, not at the leanest. Once entries leave
//    anyway, the page sentence names a page size whose rows come back with that level's detail; at
//    the leanest level (check_sbom's cve_ids-only rows) a page of that size came back with none.
//  - `giveBack`: once the cut is settled, the step's entries, in their order in data, take back
//    detail while the result fits: each the richest level of `thin` above its own that fits, a
//    capped level at the most entries that fit, stopping at the first entry that takes back none.
//  - `whole`: each list of the step keeps all its entries or none, never its first ones
//    (data.not_sent_purls: a client retries the list, and its first entries are not it).
export type DataCutStep = {
  lists: readonly string[];
  leaveOutFirst?: LeaveOutFirst;
  thin?: readonly ThinLevel[];
  keepNewest?: true;
  keepAll?: true;
  leaveAt?: { level: number; cap: number };
  giveBack?: true;
  whole?: true;
};
// What data keeps of each list cut, by its path in data: its entries in the answer, the entries
// data holds, and thinned, true when each of them is cut to some of its fields (absent otherwise).
export type Truncated = Record<string, { total: number; returned: number; thinned?: true }>;
// What a DataCut's page sentence is told besides truncated and data (#3013's review): the fields
// each thinned list's entries keep (`keeps`, by its path), and `wholeFit`, how many of a list's
// first entries, each whole (not thinned), the structured result holds within STRUCTURED_BUDGET
// with the rest of data whole, its note as the call's own without the DATA CUT sentences, and no
// truncated. A page sentence that names a page size fitting data whole counts it so: a page of the
// thinned entries' number comes back thinned again.
export type PageAt = { keeps: Readonly<Record<string, RowKeep>>; wholeFit: (path: string) => number };
// The clause of a paging tool's DATA CUT sentence that names the page size whose rows fit data
// whole, given PageAt.wholeFit for its rows (search_cves, search_vendor_advisories).
export const wholePage = (n: number): string =>
  n > 0
    ? `a page of ${n} ${n === 1 ? "row" : "rows"} or fewer like these fits data whole.`
    : `even a page of one row like these is past ${STRUCTURED_BUDGET} characters with that row whole, so its data is cut too.`;
// A tool's cut of its structured result's data: the steps, in the order they are cut, and, for a
// tool that pages or names where a thinned entry's fields are, the sentence that says how to read
// what the cut leaves out.
export type DataCut = { steps: readonly DataCutStep[]; page?: (truncated: Truncated, data: object, at: PageAt) => string };
// A tool that names no list: only step 2 (every list at the top level of data) cuts its data.
export const NO_DATA_CUT: DataCut = { steps: [] };

// The call being answered: its full argument and its tool's DataCut. Each tool's handler runs
// inside answering(), and index.ts's succeeded reads it with answeringNow(), so no tool module
// passes either through its own functions (runtime.ts's request scope works the same way).
type Answering = { full: boolean; cut: DataCut };
const calls = new AsyncLocalStorage<Answering>();
export function answering<T>(full: unknown, cut: DataCut, fn: () => T): T {
  return calls.run({ full: full === true, cut }, fn);
}
export const answeringNow = (): Answering | undefined => calls.getStore();

// The argument every tool takes (#3013), and what it says, one constant string. It names no other
// tool and directs no model (test/description-policy.test.mjs reads inputSchema descriptions too).
export const FULL_ARG_DESCRIPTION =
  "true: data in the structured result is the answer whole, however long. Without it, a structured result past 30,000 characters of JSON has its data cut (DATA CUT): in an order the note states, the entries of its longest lists keep only some of their fields, and then the lists only some of their entries; data_truncated is true, and truncated gives each list cut with its total, the number returned and whether its entries are thinned. Whole data is for a program; a client that sizes structured results, as Claude Code does against MAX_MCP_OUTPUT_TOKENS, can refuse an answer past its cap.";
export const FULL_ARG = z.boolean().optional().describe(FULL_ARG_DESCRIPTION);

// One list of data as a cut reads it, at one level of thinning (none, or the fields `thin`
// names): its entries, the order they leave in (those leaveOutFirst names, value by value, each
// from the end, then the rest from the end; with `newest`, a series sent oldest first, from the
// start instead, so the last entries stay), and, for keeping k of them, the characters of their
// JSON between the list's brackets.
type CutList = {
  path: string;
  at: readonly string[];
  n: number;
  firstOut?: LeaveOutFirst;
  thin?: RowKeep;
  // #3132: the clause an EntryLevel's `said` gives for the cap it was cut at.
  thinSaid?: string;
  newest?: true;
  named: number;
  // #3132's review: the level of the step's `thin` the entries are cut to (absent: whole) and the
  // cap it was cut at; and the entries that took back detail (giveBack), by their index in the
  // list, each with its level and cap. chars counts the entries without those.
  level?: number;
  cap: number;
  over: Map<number, GivenBack>;
  chars: (k: number) => number;
  kept: (k: number) => number[];
  keep: (k: number) => unknown[];
};
// An entry that took back detail (#3132's review): the entry so cut, its level of the step's `thin`
// and cap, and the fields and clause the DATA CUT sentence says of it.
type GivenBack = { entry: unknown; level: number; cap: number; keep: RowKeep; said?: string };
// A level as its fields, and what it does inside each entry (#3132).
const levelOf = (l: ThinLevel): EntryLevel => (Array.isArray(l) ? { keep: l as RowKeep } : (l as EntryLevel));
const thinned = (e: unknown, level: ThinLevel, cap = Number.POSITIVE_INFINITY): unknown => {
  if (!isPlainObject(e)) return e;
  const { keep, capped, mark } = levelOf(level);
  const t = cutRow(e, keep, { keep, clip: Number.POSITIVE_INFINITY }, { left: new Set(), clipped: 0, capped: 0 });
  const inner = capped ? t[capped] : undefined;
  if (capped && Array.isArray(inner) && inner.length > cap) t[capped] = inner.slice(0, cap);
  return mark ? { ...t, ...mark(e, cap) } : t;
};
// The longest list named `capped` inside any entry of a list (#3132): the cap a level starts below.
const longestInside = (v: unknown, capped: string): number =>
  Array.isArray(v) ? v.reduce<number>((m, e) => Math.max(m, Array.isArray(field(e, capped)) ? (field(e, capped) as unknown[]).length : 0), 0) : 0;
// An entry JSON cannot write (undefined) is written null in a list.
const entryChars = (e: unknown): number => JSON.stringify(e)?.length ?? 4;
const listOf = (data: Record<string, unknown>, at: readonly string[]): unknown => at.reduce<unknown>((o, k) => field(o, k), data);
function listAt(data: Record<string, unknown>, path: string, firstOut?: LeaveOutFirst, level?: ThinLevel, newest?: true, cap = Number.POSITIVE_INFINITY, levelAt?: number): CutList | undefined {
  const at = path.split(".");
  const v = listOf(data, at);
  if (!Array.isArray(v) || v.length === 0) return undefined;
  const n = v.length;
  const entries = level ? v.map((e) => thinned(e, level, cap)) : v;
  const thin = level ? levelOf(level).keep : undefined;
  // A capped level's clause only where its cap cuts an entry's list (#3139's review: a package
  // with one range is not "at most its first 1").
  const lv = level ? levelOf(level) : undefined;
  const bites = lv?.capped === undefined || v.some((e) => (Array.isArray(field(e, lv.capped as string)) ? (field(e, lv.capped as string) as unknown[]).length : 0) > cap);
  const thinSaid = lv && bites ? lv.said?.(cap) : undefined;
  const lens = entries.map(entryChars);
  // The indices in the order they leave: from the end, or, for a series kept newest, from the start.
  const leavingOrder = (i: number) => (newest ? i : n - 1 - i);
  const order: number[] = [];
  for (const value of firstOut?.values ?? []) for (let j = 0; j < n; j++) if (field(v[leavingOrder(j)], firstOut?.field ?? "") === value) order.push(leavingOrder(j));
  const named = order.length;
  const queued = new Set(order);
  for (let j = 0; j < n; j++) if (!queued.has(leavingOrder(j))) order.push(leavingOrder(j));
  const leaving = [0];
  for (const i of order) leaving.push(leaving[leaving.length - 1] + lens[i]);
  const all = leaving[n];
  const kept = (k: number) => Math.max(0, Math.min(n, k));
  const over = new Map<number, GivenBack>();
  const keptAt = (k: number): number[] => {
    const out = new Set(order.slice(0, n - kept(k)));
    return entries.map((_, i) => i).filter((i) => !out.has(i));
  };
  return {
    path,
    at,
    n,
    firstOut,
    thin,
    ...(thinSaid ? { thinSaid } : {}),
    ...(newest ? { newest } : {}),
    named,
    ...(levelAt !== undefined ? { level: levelAt } : {}),
    cap,
    over,
    chars: (k) => all - leaving[n - kept(k)] + Math.max(0, kept(k) - 1),
    kept: keptAt,
    keep: (k) => keptAt(k).map((i) => (over.has(i) ? over.get(i)?.entry : entries[i])),
  };
}
// `o` with the list at `at` replaced by `v`, each object on the way copied, its keys in their order.
function withList(o: Record<string, unknown>, at: readonly string[], v: unknown[]): Record<string, unknown> {
  const [k, ...rest] = at;
  return { ...o, [k]: rest.length ? withList(o[k] as Record<string, unknown>, rest, v) : v };
}
const orListed = (xs: readonly string[]): string => (xs.length < 2 ? xs.join("") : `${xs.slice(0, -1).join(", ")} or ${xs[xs.length - 1]}`);
// The fields a thinning level keeps, as a sentence says them.
const keepSaid = (keep: RowKeep): string => listed(keep.map((x) => (typeof x === "string" ? x : `${x[0]} (each with ${listed([...x[1]])})`)));

// The clause on the entries that took back detail (#3132's review): their positions among those
// kept, in their order in data, grouped where one level and cap holds a run of them (#3132's second
// review: not always the first kept, since give-back passes an entry that cannot take any back).
function givenBackSaid(list: CutList, k: number): string {
  const kept = list.kept(k);
  const runs: { from: number; to: number; g: GivenBack }[] = [];
  kept.forEach((i, pos) => {
    const g = list.over.get(i);
    if (!g) return;
    const last = runs[runs.length - 1];
    if (last && last.to === pos && last.g.level === g.level && last.g.cap === g.cap) last.to = pos + 1;
    else runs.push({ from: pos + 1, to: pos + 1, g });
  });
  if (runs.length === 0) return "";
  const n = runs.reduce((t, r) => t + r.to - r.from + 1, 0);
  const one = (r: (typeof runs)[number]) =>
    `${r.from === r.to ? `entry ${r.from}` : `entries ${r.from} to ${r.to}`} cut to ${keepSaid(r.g.keep)}${r.g.said ? `, ${r.g.said}` : ""}`;
  return `; with the room left, ${n} of the entries kept take back detail (by position among those kept, in their order in data): ${runs.map(one).join("; ")}`;
}

// What a cut keeps of each list it has cut so far, as truncated and as the DATA CUT sentences.
function cutSaid(
  cut: DataCut,
  kept: readonly { list: CutList; k: number }[],
  wholeChars: number,
  data: object,
  over: boolean,
  wholeFit: PageAt["wholeFit"],
): { truncated?: Truncated; said: string } {
  const isThinned = ({ list, k }: { list: CutList; k: number }) => list.thin !== undefined && k > 0;
  const cutOnes = kept.filter((x) => x.k < x.list.n || isThinned(x));
  if (cutOnes.length === 0) return { said: "" };
  const truncated: Truncated = Object.fromEntries(cutOnes.map((x) => [x.list.path, { total: x.list.n, returned: x.k, ...(isThinned(x) ? { thinned: true as const } : {}) }]));
  // In the order cut: one part per list that is thinned or leaves entries named first, and one per
  // number kept for the rest, at its first list's place (lists that keep the same number, at the
  // same end, share a part, and truncated gives each one's total). A series kept newest (#3013's
  // review) says it keeps its newest entries, and that its oldest left.
  type Group = { k: number; newest: boolean; lists: CutList[] };
  const parts: (string | Group)[] = [];
  const byKept = new Map<string, Group>();
  for (const x of cutOnes) {
    const { list, k } = x;
    const out = list.n - k;
    const first = Math.min(out, list.named);
    const end = list.newest ? "oldest" : "last";
    const which = list.firstOut ? `whose ${list.firstOut.field} is ${orListed(list.firstOut.values)} (${list.firstOut.why})` : "";
    const leftOut =
      out === 0 ? "" : first === 0 ? `, the ${end} ${out} left out` : first === out ? `, the ${out} left out being entries ${which}` : `, the ${out} left out being the ${first} ${which} and the ${end} ${out - first} of the rest`;
    if (isThinned(x)) {
      parts.push(
        `${list.path} keeps ${k === list.n ? `all ${k}` : `${k} of its ${list.n}`} entries, each cut to ${keepSaid(list.thin as RowKeep)}${list.thinSaid ? `, ${list.thinSaid}` : ""}${leftOut}${givenBackSaid(list, k)}`,
      );
      continue;
    }
    if (!list.firstOut || first === 0 || k === 0) {
      const newest = list.newest === true && k > 0;
      const key = `${k}:${newest}`;
      const group = byKept.get(key);
      if (group) group.lists.push(list);
      else {
        const g = { k, newest, lists: [list] };
        byKept.set(key, g);
        parts.push(g);
      }
      continue;
    }
    parts.push(`${list.path} keeps ${k} of its ${list.n} entries${leftOut}`);
  }
  const cuts = parts.map((p) => {
    if (typeof p === "string") return p;
    const paths = listed(p.lists.map((l) => l.path));
    const which = p.newest ? "newest" : "first";
    if (p.lists.length === 1) return p.k === 0 ? `${paths} keeps none of its ${p.lists[0].n} entries` : `${paths} keeps its ${which} ${p.k} of ${p.lists[0].n} entries`;
    return p.k === 0 ? `${paths} keep none of their entries` : `${paths} keep their ${which} ${p.k} entries each`;
  });
  const keeps: Record<string, RowKeep> = Object.fromEntries(cutOnes.filter(isThinned).map((x) => [x.list.path, x.list.thin as RowKeep]));
  const page = cut.page?.(truncated, data, { keeps, wholeFit }) ?? "";
  const said = [
    `DATA CUT: with data whole, this structured result is ${wholeChars} characters of JSON, more than the ${STRUCTURED_BUDGET} it holds unless the call says full: true, so its data is cut: ${cuts.join("; ")}.`,
    "truncated gives the total and the number returned of each list cut, and thinned where its entries are cut to some of their fields.",
    page,
    over ? `Cut so, the structured result is still past ${STRUCTURED_BUDGET} characters: data holds no other list to cut.` : "",
    "The same call with full: true returns data whole.",
  ];
  return { truncated, said: said.filter(Boolean).join(" ") };
}

/**
 * The structured result for `data` cut to STRUCTURED_BUDGET, as `cut` says (see "The structured
 * result, per client" above): `structured` builds the result for a data, its truncated and the DATA
 * CUT sentences, and is called with data null to size the rest of it. `wholeChars` is the result's
 * size with data whole. undefined when data holds no list to cut.
 */
export function cutData(
  data: object,
  cut: DataCut,
  wholeChars: number,
  structured: (data: object | null, truncated: Truncated | undefined, said: string) => object,
): { data: object; truncated: Truncated; said: string; structured: object } | undefined {
  if (!isPlainObject(data)) return undefined;
  const named = new Set(cut.steps.flatMap((s) => s.lists));
  const steps: readonly DataCutStep[] = [...cut.steps, { lists: Object.keys(data).filter((k) => !named.has(k)) }];
  // Each list cut so far, in the order cut, at the level it was thinned to, how many entries it
  // keeps, and the step that cut it.
  const kept = new Map<string, { list: CutList; k: number; step: number }>();
  const apply = (also: readonly { list: CutList; k: number }[] = []): Record<string, unknown> =>
    [...kept.values(), ...also].reduce((d, { list, k }) => withList(d, list.at, list.keep(k)), data);
  // PageAt.wholeFit: of the list at `path`, the most first entries, each whole, that the result
  // holds within the budget with the rest of data whole and no DATA CUT sentence (structured with
  // truncated undefined): the shape of the same call at that page size. Counted once per path.
  const wholeFits = new Map<string, number>();
  const wholeFit = (path: string): number => {
    const known = wholeFits.get(path);
    if (known !== undefined) return known;
    const at = path.split(".");
    const v = listOf(data, at);
    let k = 0;
    if (Array.isArray(v)) {
      let chars = JSON.stringify(structured(withList(data, at, []), undefined, "")).length;
      for (const e of v) {
        chars += entryChars(e) + (k > 0 ? 1 : 0);
        if (chars > STRUCTURED_BUDGET) break;
        k++;
      }
    }
    wholeFits.set(path, k);
    return k;
  };
  // The result's size with this step's lists at k entries each: the rest of the result (data
  // null), data with this step's lists empty (`base`), and their entries.
  const size = (lists: readonly CutList[], k: number, base: number): number => {
    const all = [...kept.values(), ...lists.map((list) => ({ list, k: Math.min(k, list.n) }))];
    const { truncated, said } = cutSaid(cut, all, wholeChars, data, false, wholeFit);
    return JSON.stringify(structured(null, truncated, said)).length - "null".length + base + lists.reduce((t, l) => t + l.chars(k), 0);
  };
  let fits = false;
  for (const [s, step] of steps.entries()) {
    // Every entry whole, then each thinning level in turn, every entry kept; at the leanest level
    // the entries leave until the result fits (with keepAll, #3139, not in this step: see below).
    const levels: readonly (ThinLevel | undefined)[] = [undefined, ...(step.thin ?? [])];
    let lists: CutList[] = [];
    let k = 0;
    const at = (level: ThinLevel | undefined, cap?: number, levelAt?: number) =>
      step.lists.map((p) => listAt(data, p, step.leaveOutFirst, level, step.keepNewest, cap, levelAt)).filter((l): l is CutList => l !== undefined && !kept.has(l.path));
    for (const [i, thin] of levels.entries()) {
      lists = at(thin, undefined, i - 1);
      if (lists.length === 0) break;
      const base = JSON.stringify(apply(lists.map((list) => ({ list, k: 0 })))).length;
      const top = Math.max(...lists.map((l) => l.n));
      // #3132: a level that caps a list inside each entry, every entry kept: the most entries of
      // that inner list, the same number in each, that fit; a level where even none fits is passed.
      // #3132's review: a level with `least` is taken at that cap or more, or passed.
      const capped = thin === undefined ? undefined : levelOf(thin).capped;
      if (capped !== undefined) {
        const longest = Math.max(0, ...step.lists.map((p) => longestInside(listOf(data, p.split(".")), capped)));
        const least = (thin === undefined ? undefined : levelOf(thin).least) ?? 0;
        if (longest > least && size(at(thin, least, i - 1), top, base) <= STRUCTURED_BUDGET) {
          let m = least;
          let hi = longest - 1;
          while (m < hi) {
            const mid = Math.ceil((m + hi) / 2);
            if (size(at(thin, mid, i - 1), top, base) <= STRUCTURED_BUDGET) m = mid;
            else hi = mid - 1;
          }
          lists = at(thin, m, i - 1);
          k = top;
          fits = true;
          break;
        }
        if (i < levels.length - 1) continue;
        // The last level, and even its least cap does not fit: the entries go on at that cap.
        lists = at(thin, least, i - 1);
      }
      if (i < levels.length - 1) {
        if (size(lists, top, base) <= STRUCTURED_BUDGET) {
          k = top;
          fits = true;
          break;
        }
        continue;
      }
      if (step.keepAll) {
        // #3139: every entry stays, at this level; the later steps are cut first.
        k = top;
        fits = size(lists, top, base) <= STRUCTURED_BUDGET;
        break;
      }
      // #3132's review: entries leave at the step's leaveAt level, where it names one.
      if (step.leaveAt && step.thin) {
        const { level, cap } = step.leaveAt;
        lists = at(step.thin[level], cap, level);
      }
      if (step.whole) {
        // Every entry or none (#3132's review: data.not_sent_purls).
        if (size(lists, 0, base) <= STRUCTURED_BUDGET) {
          k = size(lists, top, base) <= STRUCTURED_BUDGET ? top : 0;
          fits = true;
        }
        break;
      }
      if (size(lists, 0, base) <= STRUCTURED_BUDGET) {
        // The most entries each list of the step keeps with the result inside the budget.
        let hi = top;
        while (k < hi) {
          const mid = Math.ceil((k + hi) / 2);
          if (size(lists, mid, base) <= STRUCTURED_BUDGET) k = mid;
          else hi = mid - 1;
        }
        fits = true;
      }
    }
    for (const list of lists) kept.set(list.path, { list, k: Math.min(k, list.n), step: s });
    if (fits) break;
  }
  const exact = (): number => {
    const { truncated, said } = cutSaid(cut, [...kept.values()], wholeChars, data, false, wholeFit);
    return JSON.stringify(structured(apply(), truncated, said)).length;
  };
  // #3139: every step cut and the result still past the budget: a keepAll step's entries leave now,
  // the step's first, as many as must, the rest of data as the steps after it left it. The steps
  // after it then take back what room is left (below), as though it were the step that fits.
  // #3139's review: with more than one keepAll step, the last one's entries leave first
  // (cve_remediation's fixed_branches before any vendor advisory).
  if (!fits) {
    for (const [s, step] of [...steps.entries()].reverse()) {
      if (!step.keepAll || fits) continue;
      const entries = [...kept.values()].filter((e) => e.step === s);
      if (entries.length === 0) continue;
      const set = (k: number) => {
        for (const e of entries) e.k = Math.min(k, e.list.n);
      };
      set(0);
      if (exact() > STRUCTURED_BUDGET) continue;
      let k = 0;
      let hi = Math.max(...entries.map((e) => e.list.n));
      while (k < hi) {
        const mid = Math.ceil((k + hi) / 2);
        set(mid);
        if (exact() <= STRUCTURED_BUDGET) k = mid;
        else hi = mid - 1;
      }
      set(k);
      for (const e of entries) e.step = steps.length;
      fits = true;
    }
  }
  // The room the step that fits leaves goes back to the steps emptied before it, the last first,
  // each step's lists keeping at most the same number of their entries, as many as fit, at the
  // level they were thinned to (scan_manifest's not_checked, emptied while its rows were whole,
  // keeps its entries once the thinned rows fit).
  if (fits) {
    const last = Math.max(...[...kept.values()].map((e) => e.step));
    for (let s = last - 1; s >= 0; s--) {
      const entries = [...kept.values()].filter((e) => e.step === s);
      if (entries.length === 0) continue;
      const at = (k: number) => {
        for (const e of entries) e.k = Math.min(k, e.list.n);
      };
      let k = Math.min(...entries.map((e) => e.k));
      let hi = Math.max(...entries.map((e) => e.list.n));
      if (steps[s].whole) {
        // Every entry or none (#3132's review).
        at(hi);
        if (exact() > STRUCTURED_BUDGET) at(k);
        continue;
      }
      while (k < hi) {
        const mid = Math.ceil((k + hi) / 2);
        at(mid);
        if (exact() <= STRUCTURED_BUDGET) k = mid;
        else hi = mid - 1;
      }
      at(k);
    }
  }
  // #3132's review: then a giveBack step's entries, in their order in data, take back detail (see
  // DataCutStep): each the richest level above its own that fits. A RowKeep level is tried whole;
  // of the capped levels, only the leanest at or above the entry's own (check_sbom's compact one,
  // or the entry's own), uncapped and then at the most inner entries that fit, so a row takes back
  // more of its matches compact before fewer of them thinned. #3132's second review: an entry that
  // takes back nothing is passed, not an end (through round 2 it ended give-back, so a row at the
  // compact level holding every match, too large to move up, kept every later capped row at its
  // cap while room was left); the entries that took some are named by position (givenBackSaid).
  if (fits) {
    for (const [s, step] of steps.entries()) {
      if (!step.giveBack || !step.thin) continue;
      const thin = step.thin;
      for (const e of [...kept.values()].filter((x) => x.step === s)) {
        const { list } = e;
        const own = list.level;
        if (own === undefined || list.thin === undefined) continue;
        const whole = listOf(data, list.at);
        if (!Array.isArray(whole)) continue;
        let leanestCapped = -1;
        for (let j = 0; j <= own; j++) if (levelOf(thin[j]).capped !== undefined) leanestCapped = j;
        const tryAt = (i: number, j: number, c: number): boolean => {
          const l = levelOf(thin[j]);
          list.over.set(i, { entry: thinned(whole[i], thin[j], c), level: j, cap: c, keep: l.keep, ...(l.said && l.capped && c < Number.POSITIVE_INFINITY ? { said: l.said(c) } : {}) });
          if (exact() <= STRUCTURED_BUDGET) return true;
          list.over.delete(i);
          return false;
        };
        for (const i of list.kept(e.k)) {
          // An entry its own level already keeps as the richest would is passed, not an end.
          if (JSON.stringify(thinned(whole[i], thin[0])) === JSON.stringify(thinned(whole[i], thin[own], list.cap))) continue;
          let took = false;
          for (let j = 0; j <= own && !took; j++) {
            const l = levelOf(thin[j]);
            const inner = l.capped !== undefined && Array.isArray(field(whole[i], l.capped)) ? (field(whole[i], l.capped) as unknown[]).length : 0;
            if (l.capped === undefined) {
              if (j < own) took = tryAt(i, j, Number.POSITIVE_INFINITY);
              continue;
            }
            if (j !== leanestCapped) continue;
            if (j < own || list.cap < inner) took = tryAt(i, j, Number.POSITIVE_INFINITY);
            if (took) break;
            let c = j === own ? list.cap + 1 : (l.least ?? 0);
            let hi = inner - 1;
            if (c > hi || !tryAt(i, j, c)) continue;
            while (c < hi) {
              const mid = Math.ceil((c + hi) / 2);
              if (tryAt(i, j, mid)) c = mid;
              else hi = mid - 1;
            }
            took = tryAt(i, j, c);
          }
        }
      }
    }
  }
  const { truncated, said } = cutSaid(cut, [...kept.values()], wholeChars, data, !fits, wholeFit);
  if (truncated === undefined) return undefined;
  const d = apply();
  return { data: d, truncated, said, structured: structured(d, truncated, said) };
}
