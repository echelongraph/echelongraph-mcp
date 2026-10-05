// The text budget (#2783): what a success's first text block may cost, and how an answer larger
// than that is cut. index.ts's `succeeded` builds every success's first text block with dataText;
// a tool that returns a list of rows names it with a TextCut. structuredContent.data is never cut.
// A module of its own, so a tool module can import its types and TEXT_BUDGET_DESCRIPTION without
// importing index.ts, which starts the stdio server when loaded.
//
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
// So structuredContent.data is always the API's JSON whole, and the first text block is that JSON
// when it fits DATA_TEXT_BUDGET, half the ceiling, and cut when it does not:
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
// that says what the first text block leaves out, that structuredContent.data carries all of it,
// and how to read the rest in the text: the tool that returns one row, and what of it, and the page
// size or offset at which a page fits. The cut is deterministic: the same answer is cut the same way.
export const DATA_TEXT_BUDGET = 30_000;
// What a note may say of reading one CVE's record through get_cve (#2802): get_cve's own first text
// block is cut too past the budget (each list to its first entries, every other field kept), so
// only its structuredContent.data is the record whole. A row tool's `whole` sentence starts with it.
export const GET_CVE_WHOLE =
  "get_cve returns any one of these CVEs' records, whole in its structuredContent.data, and in its first text block with every field (past 30,000 characters, each list cut to its first entries)";
// What every tool description says about it, one constant string (marketing-site
// lib/mcpToolClaims.test.ts folds only constant strings); the suite holds its number to
// DATA_TEXT_BUDGET's. It uses none of the words that check reviews as the page's own prose (how,
// when, does, have, on and the rest of its PROSE list), so no reviewed entry goes stale.
export const TEXT_BUDGET_DESCRIPTION =
  "Past 30,000 characters of JSON, the first text block holds data cut to fit, and the note says what the cut leaves out and where to read it (TEXT CUT); data in the structured result always holds it whole.";

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
// own place (resources.ts, #2801).
export type CutPlace = { opens: (chars: number) => string };
export const FIRST_TEXT_BLOCK: CutPlace = {
  opens: (chars) =>
    `TEXT CUT: the API's answer is ${chars} characters of JSON, more than the ${DATA_TEXT_BUDGET} the first text block holds, so that block is cut, and structuredContent.data carries the answer whole.`,
};

/** The first text block for `data` within DATA_TEXT_BUDGET, and the TEXT CUT sentence when it is cut. */
export function dataText(data: object, cut?: TextCut, place: CutPlace = FIRST_TEXT_BLOCK): { text: string; said: string } {
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
      const left = `Only ${kept.length} of the ${n} rows of ${cut.rows} are in it; the other ${out.size} are in structuredContent.data only${which}.`;
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
  return { text: last.text, said: say(rowsSaid, ...sidesSaid, lists, strings, cut?.whole) };
}

