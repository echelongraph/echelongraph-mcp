// What a tool's result costs in the channel a model reads, measured one way everywhere: the suite's
// per-case bounds (tools.test.mjs, #2467/#2531), the ceiling they sit under (#2617), every tool on
// production-shaped answers (text-bound.test.mjs, #2783), and the operator check that measures
// production's answers (text-bound-live.mjs, #2616, #2783) all import this.
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";

// #2467's trip-wire, named once (#2617): "P2 the moment any tool's text exceeds 60,000 chars". A
// per-case bound is resolved by re-measuring and raising it; nothing here may be raised past this,
// and a bound that would be is the moment #2467 said to stop and look, not a number to edit.
export const CEILING = 60_000;
// #2617's trip-wire, 75% of the ceiling: past it, the run says so on every case.
export const TRIP_WIRE = 45_000;
// How far a measurement may move from its recorded size: one changed word, never a sentence.
export const MARGIN = 50;
// The base URL a result is counted against, so a stub's address costs what production's does.
export const PROD_BASE = "https://app.echelongraph.io";
// #3013: the path a stub at `origin` serves under, so that its base is as long as PROD_BASE. A
// server pointed at it then says its base in as many characters as production's and cuts its
// structured result where production's would: a cut that fills the budget to the character (the
// room a cut leaves goes back to the lists cut before it) would pass it once the shorter stub base
// is counted as production's. `unprefixed` is the request's URL as the API would see it.
export const prefixFor = (origin) => (PROD_BASE.length - origin.length > 1 ? `/${"p".repeat(PROD_BASE.length - origin.length - 1)}` : "");
export const unprefixed = (url, prefix) => (prefix && url.startsWith(`${prefix}/`) ? url.slice(prefix.length) : url);

// ── The structured result (#3013) ──
//
// Claude Code hands the model structuredContent, not the text blocks, and refuses one past its
// MAX_MCP_OUTPUT_TOKENS (25,000 by default), saving it to a file: get_cve CVE-2021-44228 was 65,540
// characters of structuredContent beside a first text block of 23,759. So a success's structured
// result, all of it as compact JSON, is held to the first text block's budget (src/textBudget.ts
// STRUCTURED_BUDGET, which text-bound.test.mjs holds equal to this), unless the call says full: true.
export const STRUCTURED_BUDGET = 30_000;

/** A result's structuredContent as compact JSON, with `stubBase` counted as production's: its size; undefined for a resource read. */
export function structuredSize(res, stubBase) {
  if (res.structuredContent === undefined) return undefined;
  const s = JSON.stringify(res.structuredContent);
  return (stubBase ? s.split(stubBase).join(PROD_BASE) : s).length;
}

/** Throws, naming the case and its size, when a structured result is past STRUCTURED_BUDGET (#3013). */
export function assertStructuredUnderBudget(label, size) {
  if (size > STRUCTURED_BUDGET) {
    throw new Error(
      `${label}: structuredContent is ${size} characters of JSON, past the ${STRUCTURED_BUDGET} a client that hands structuredContent to a model is held to (Claude Code saves a longer one to a file): cut its data (src/textBudget.ts cutData), do not raise the budget.`,
    );
  }
  return size;
}

const at = (o, path) => path.reduce((v, k) => (v !== null && typeof v === "object" && !Array.isArray(v) ? v[k] : undefined), o);
const without = (o, path) => {
  const [k, ...rest] = path;
  return rest.length ? { ...o, [k]: without(o[k], rest) } : { ...o, [k]: "(a list truncated names)" };
};

/**
 * #3013: whether `t` is `d` thinned: an object keeps some of `d`'s fields, each thinned the same
 * way; a list keeps every one of `d`'s entries, in order, each thinned; anything else is equal. No
 * string is shortened and no value changes.
 */
export function isThinOf(t, d) {
  if (Array.isArray(t)) return Array.isArray(d) && t.length === d.length && t.every((x, i) => isThinOf(x, d[i]));
  if (t !== null && typeof t === "object") return d !== null && typeof d === "object" && !Array.isArray(d) && Object.keys(t).every((k) => Object.hasOwn(d, k) && isThinOf(t[k], d[k]));
  return isDeepStrictEqual(t, d);
}

/**
 * #3270: the indices of the `n` matches of `all` a capped check_sbom row keeps (written here from
 * the rule, not imported from src/tools/check_sbom.ts pickMatches): those used in ransomware, then
 * the other KEV-listed ones, then the highest effective_score (none last), the API's order breaking
 * ties; in the API's order. Through 3.0.2 a row kept its first n.
 */
export function pickedMatches(all, n) {
  const tier = (m) => (m?.ransomware === true ? 0 : m?.kev_listed === true ? 1 : 2);
  const score = (m) => (typeof m?.effective_score === "number" && Number.isFinite(m.effective_score) ? m.effective_score : -Infinity);
  return all
    .map((_, i) => i)
    .sort((a, b) => tier(all[a]) - tier(all[b]) || (score(all[a]) === score(all[b]) ? a - b : score(all[b]) - score(all[a])))
    .slice(0, n)
    .sort((a, b) => a - b);
}

/**
 * #3132: whether `t` is `d`, a check_sbom or scan_manifest row, cut on its own terms
 * (src/tools/check_sbom.ts SBOM_ROW_LEVELS): a row without matches_truncated is `d` thinned
 * (isThinOf); a row with it keeps some of `d`'s other fields unchanged, matches_truncated.returned
 * of its matches, each thinned (none, and no matches field, at the leanest levels): since #3270
 * those pickedMatches names, in the API's order, through 3.0.2 its first; and matches_truncated's
 * total is `d`'s matches; its lists, where present, are drawn from all of them: the CVE IDs
 * KEV-listed, those used in ransomware, and the distinct fixed_in versions.
 */
export function isEntryCutOf(t, d) {
  // #3139's review: a cve_remediation fixed_branches row whose ranges are capped keeps its first
  // fixed_branches_truncated.returned ranges, each thinned, and the total is the row's ranges.
  if (t !== null && typeof t === "object" && !Array.isArray(t) && Object.hasOwn(t, "fixed_branches_truncated")) {
    const { fixed_branches_truncated: ft, fixed_branches: ranges, ...rest } = t;
    const all = Array.isArray(d?.fixed_branches) ? d.fixed_branches : [];
    if (!isThinOf(rest, d) || ft === null || typeof ft !== "object" || Object.keys(ft).some((k) => k !== "total" && k !== "returned")) return false;
    return ft.total === all.length && ft.returned >= 1 && ft.returned < ft.total && Array.isArray(ranges) && ranges.length === ft.returned && isThinOf(ranges, all.slice(0, ft.returned));
  }
  if (t === null || typeof t !== "object" || Array.isArray(t) || !Object.hasOwn(t, "matches_truncated")) return isThinOf(t, d);
  const { matches_truncated: mt, matches, ...rest } = t;
  const all = Array.isArray(d?.matches) ? d.matches : [];
  if (!isThinOf(rest, d) || mt === null || typeof mt !== "object") return false;
  if (mt.total !== all.length || !(mt.returned >= 0 && mt.returned < mt.total)) return false;
  if (matches === undefined ? mt.returned !== 0 : !(matches.length === mt.returned && isThinOf(matches, pickedMatches(all, mt.returned).map((j) => all[j])))) return false;
  const ids = (f) => [...new Set(all.filter((m) => m?.[f] === true && typeof m.cve_id === "string").map((m) => m.cve_id))];
  const lists = { kev_listed_cve_ids: ids("kev_listed"), ransomware_cve_ids: ids("ransomware"), fixed_in_versions: [...new Set(all.map((m) => m?.fixed_in).filter((v) => typeof v === "string"))] };
  for (const [k, v] of Object.entries(lists)) if (Object.hasOwn(mt, k) && !isDeepStrictEqual(mt[k], v)) return false;
  return Object.keys(mt).every((k) => ["total", "returned", ...Object.keys(lists)].includes(k));
}

/**
 * #3013: that `sc.data` is `whole` (the answer, as the same call with full: true returns it) cut as
 * `sc.truncated` says: with data_truncated false, data is whole and truncated absent; with it true,
 * each list truncated names (by its path in data) holds `returned` of the answer's `total` entries,
 * each one of the answer's in the answer's order, whole, or, where truncated says thinned, each
 * keeping some of its fields unchanged (isThinOf); and every other field of data is the answer's.
 * Throws, naming where, when it is not.
 */
export function assertDataCutOf(sc, whole, label = "data") {
  assert.equal(typeof sc.data_truncated, "boolean", `${label}: data_truncated is ${JSON.stringify(sc.data_truncated)}, not a boolean`);
  if (!sc.data_truncated) {
    assert.equal(sc.truncated, undefined, `${label}: data_truncated is false and truncated is present`);
    assert.deepEqual(sc.data, whole, `${label}: data_truncated is false and data is not the answer whole`);
    return;
  }
  assert.ok(sc.truncated && Object.keys(sc.truncated).length > 0, `${label}: data_truncated is true and truncated names no list`);
  let rest = sc.data;
  let restWhole = whole;
  for (const [p, { total, returned, thinned, ...more }] of Object.entries(sc.truncated)) {
    const path = p.split(".");
    const cut = at(sc.data, path);
    const all = at(whole, path);
    assert.deepEqual(more, {}, `${label}: truncated.${p} carries more than total, returned and thinned`);
    assert.ok(thinned === undefined || thinned === true, `${label}: truncated.${p}.thinned is ${JSON.stringify(thinned)}`);
    assert.ok(Array.isArray(cut) && Array.isArray(all), `${label}: truncated names ${p}, which is not a list in data and in the answer`);
    assert.equal(all.length, total, `${label}: truncated.${p}.total is ${total}, and the answer's list holds ${all.length}`);
    assert.equal(cut.length, returned, `${label}: truncated.${p}.returned is ${returned}, and data's list holds ${cut.length}`);
    assert.ok(returned < total || thinned, `${label}: truncated names ${p}, which is neither cut nor thinned (${returned} of ${total})`);
    assert.ok(!thinned || returned > 0, `${label}: truncated.${p} says thinned with no entry kept`);
    const same = thinned ? isEntryCutOf : isDeepStrictEqual;
    let j = 0;
    for (const [i, e] of cut.entries()) {
      while (j < all.length && !same(e, all[j])) j++;
      assert.ok(j < all.length, `${label}: ${p}[${i}] is not one of the answer's entries, ${thinned ? "thinned" : "whole"}, in the answer's order`);
      j++;
    }
    rest = without(rest, path);
    restWhole = without(restWhole, path);
  }
  assert.deepEqual(rest, restWhole, `${label}: data differs from the answer in more than the lists truncated names`);
}

// #3140: what text-bound-live.mjs --hosted replays as the API's answer. Since 3.0.0 (#3013) a
// hosted tool's default structuredContent.data is cut past STRUCTURED_BUDGET, so through 3.0.0 the
// replay measured data already cut, and stayed green whatever happened: get_cve CVE-2021-44228's
// default data on hosted 3.0.0 has cpe_match 77 of 396 and references 77 of 103, kev_recent at
// limit 200 keeps 64 of 200 entries, and every row tool comes back thinned. The hosted call now says
// full: true to a server at 3.0.0 or later (one before it has no such argument, and its data is
// never cut), and the replay refuses an answer whose data_truncated is true, or a call to a server
// at 3.0.0 or later without full: true, rather than measure a cut as the API's answer.
export const FULL_SINCE = [3, 0, 0];
const versionAtLeast = (v, min) => {
  const m = /^(\d+)\.(\d+)\.(\d+)/.exec(String(v ?? ""));
  if (!m) return undefined;
  for (let i = 0; i < 3; i++) if (Number(m[i + 1]) !== min[i]) return Number(m[i + 1]) > min[i];
  return true;
};
/** The arguments the hosted call is made with, for a server reporting `version`; throws for a server that reports none. */
export function hostedArgs(args, version) {
  const cuts = versionAtLeast(version, FULL_SINCE);
  if (cuts === undefined) throw new Error(`the hosted server reports no version (${JSON.stringify(version)}), so whether its data is cut by default is unknown: refusing to replay it`);
  return cuts ? { ...args, full: true } : args;
}
/** The data to replay from the hosted answer `there` to a call made with `args`; throws where it would be a cut, not the API's answer. */
export function hostedReplay(there, args, version) {
  if (versionAtLeast(version, FULL_SINCE) !== false && args?.full !== true) {
    throw new Error(`the hosted server is ${version ?? "of no reported version"}, which cuts structuredContent.data by default (#3013), and the call did not say full: true: refusing to replay its data as the API's answer`);
  }
  if (there?.structuredContent?.data_truncated === true) {
    throw new Error(`the hosted answer's data is cut (data_truncated true, truncated ${JSON.stringify(there.structuredContent.truncated)}): refusing to replay it as the API's answer`);
  }
  return there.structuredContent.data;
}

/** Every text block of a result (or text of a resource read, #2801), with `stubBase` counted as production's, summed; and each block's size. */
export function textSize(res, stubBase) {
  const texts = res.contents ? res.contents.filter((c) => typeof c.text === "string") : (res.content ?? []).filter((c) => c.type === "text");
  const blocks = texts.map((c) => (stubBase ? c.text.split(stubBase).join(PROD_BASE) : c.text));
  return { total: blocks.reduce((n, t) => n + t.length, 0), blocks: blocks.map((t) => t.length), envelope: blocks.at(-1)?.length ?? 0 };
}

/** "exposure_radar: 30,949 / 60,000 = 52%", the share a size is of the ceiling. */
export function shareOfCeiling(label, n) {
  const pct = Math.round((n / CEILING) * 100);
  return `${label}: ${n.toLocaleString("en-US")} / ${CEILING.toLocaleString("en-US")} = ${pct}%${n > TRIP_WIRE ? ` (past #2617's trip-wire of ${TRIP_WIRE.toLocaleString("en-US")})` : ""}`;
}

/** Throws when a bound (a measured size plus MARGIN) is past the ceiling (#2617). */
export function assertBoundUnderCeiling(label, size) {
  const bound = size + MARGIN;
  if (bound > CEILING) {
    throw new Error(`${label}: its bound of ${bound} (${size} measured, plus ${MARGIN}) is past #2467's ceiling of ${CEILING} characters. Do not raise the ceiling to pass: cut the text, or reopen #2467.`);
  }
  return bound;
}

// ── Production's measured text (#2616) ──
//
// The suite's bounds are measured on fixtures; production's answers grow (radar rows, a new
// radar, a new field), and what a production client receives is what costs it context. The record
// below is production's own: each tool's text measured on production's answers, replayed from
// localhost by text-bound-live.mjs so the package's User-Agent never reaches production as
// adoption. The answers themselves are kept beside it (fixtures/prod-answers/), so the suite
// measures the same tool on them (tools.test.mjs) and the record cannot drift from the code
// without a red test; text-bound-live.mjs is the red signal when production drifts from the record.
const HERE = path.dirname(fileURLToPath(import.meta.url));
export const LIVE_RECORD = path.join(HERE, "fixtures", "text-bound-live.json");
export const PROD_ANSWERS = path.join(HERE, "fixtures", "prod-answers");
// #2822: the source text-bound-live.mjs writes when it re-measures the answers kept here
// (--answers test/fixtures/prod-answers): probe-prod's answers, read when they were kept.
export const KEPT_SOURCE = "probe-prod answers kept in fixtures/prod-answers";
// Every source text-bound-live.mjs writes into the record, and nothing else: a source written by
// hand is not one of these (#2822).
export const RECORD_SOURCE = /^(probe-prod|probe-prod answers kept in fixtures\/prod-answers|answers in \S.*|hosted https?:\/\/\S+, its data replayed to this checkout's server|the hosted endpoint's own text \(.+\), not this checkout's)$/;

// ── When the record says production was read (#2782) ──
//
// Through 3.0.2 a re-measure of the kept answers (text-bound-live.mjs --answers
// test/fixtures/prod-answers --record) wrote its own time as measured_at, and package.json's version
// as the code: e20db98c moved the record from production's read at 07:47:17Z to 07:56:38Z and filed
// exposure_radar's 39,575 under 2.6.2, which measures 39,445 on those answers (the 39,575 was
// Unreleased #2438's). Every intentional text change re-records that way, so the record and the
// suite's diagnostic said the answers were current when they were weeks old. Now measured_at is when
// production was read for the number, and read_ms how long that read took; a re-measure of the kept
// answers moves neither. The code is recorded apart: code_measured_at, when this checkout's server
// measured, and code_version, which code that was (codeVersion).

/** The code a checkout runs: package.json's `version`, with "+unreleased" when CHANGELOG.md's newest section is an unreleased one that lists a change. */
export function codeVersion(version, changelog) {
  const heads = [...String(changelog).matchAll(/^## (.*)$/gm)];
  if (!heads.length || !/unreleased/i.test(heads[0][1])) return version;
  const body = changelog.slice(heads[0].index + heads[0][0].length, heads[1]?.index ?? changelog.length);
  return /^\s*[-*] \S/m.test(body) ? `${version}+unreleased` : version;
}

// How old an answer can be when production serves it: no fixed bound. core-backend's cache.SWR
// (internal/cache/swr.go; kevexposure, exposeddb and leakedcreds use cache.NewSWR(60*time.Second,
// ...)) serves its last value, of any age, to the first request after the 60 s TTL and refreshes
// behind it, and the stats handlers send Cache-Control s-maxage=60, stale-while-revalidate=300 for
// the CDN. So a read made while traffic is quiet can be given answers minutes old: on 2026-10-05
// exposed-databases' was 152 s old and leaked-credentials' 146 s. Only the read can say how old each
// answer it kept was, so it records that (answers_age_ms, answerAges), and the record's date is held
// to it: measured_at less each kept answer's own generated_at must be the age the read recorded.

/** The newest generated_at in each kept production answer (any depth), by file name: {file: {at, ms}}; a file that carries none is left out. */
export function generatedAtByFile(dir = PROD_ANSWERS) {
  const out = {};
  const visit = (v, file) => {
    if (Array.isArray(v)) return v.forEach((x) => visit(x, file));
    if (v === null || typeof v !== "object") return;
    for (const [k, x] of Object.entries(v)) {
      const ms = k === "generated_at" && typeof x === "string" ? Date.parse(x) : NaN;
      if (!Number.isNaN(ms)) {
        if (!out[file] || ms > out[file].ms) out[file] = { at: x, ms };
      } else visit(x, file);
    }
  };
  for (const f of fs.readdirSync(dir).filter((n) => n.endsWith(".json")).sort()) visit(JSON.parse(fs.readFileSync(path.join(dir, f), "utf8")), f);
  return out;
}

/** The newest generated_at in the kept production answers (any depth of any file in `dir`): {at, ms, file}; undefined when none carries one. */
export function newestGeneratedAt(dir = PROD_ANSWERS) {
  let best;
  for (const [file, g] of Object.entries(generatedAtByFile(dir))) if (!best || g.ms > best.ms) best = { ...g, file };
  return best;
}

/**
 * #2782: how old each kept answer in `dir` was, by its own generated_at, when production was read at
 * `readAt` (an ISO time): {file: ms}, the read's own evidence for the record's date. text-bound-live.mjs
 * --record writes it at the read, as answers_age_ms; null when readAt is not a time.
 */
export function answerAges(readAt, dir = PROD_ANSWERS) {
  const at = typeof readAt === "string" ? Date.parse(readAt) : NaN;
  if (Number.isNaN(at)) return null;
  return Object.fromEntries(Object.entries(generatedAtByFile(dir)).map(([f, g]) => [f, at - g.ms]));
}

/**
 * #2782: when production was read for a record entry. A tools entry's answers_read_at (#2822): the
 * read writes it, and no re-measure, of this harness or an older one, moves it. An entry written
 * before code_measured_at existed (through 3.0.2) used measured_at for when this checkout's server
 * last measured, and a merge can keep this harness's code_measured_at beside such a re-dated
 * measured_at, so measured_at is read only for an entry with no answers_read_at that this harness
 * wrote.
 */
export const readTimeOf = (r) => (r === undefined || r === null ? null : (r.answers_read_at ?? (Object.hasOwn(r, "code_measured_at") ? (r.measured_at ?? null) : null)));

/**
 * #2782: the record's entries measured on the kept answers (tools.* with answers_kept, and cases.*
 * whose source is KEPT_SOURCE) whose date is not the read's: measured_at less a kept answer's own
 * generated_at is not the age the read recorded for that answer (answers_age_ms), so the record is
 * dated by something other than the read of those answers. Named too: measured_at not a time, no
 * answers_age_ms, a kept answer the read did not record or one it recorded that is gone (the
 * answers were replaced after the read), and kept answers that carry no generated_at at all.
 */
export function datedAfterAnswers(record = readLiveRecord(), dir = PROD_ANSWERS) {
  const gens = generatedAtByFile(dir);
  const entries = [
    ...Object.entries(record.tools ?? {}).filter(([, r]) => r.answers_kept).map(([k, r]) => [`tools.${k}`, r]),
    ...Object.entries(record.cases ?? {}).filter(([, r]) => r.source === KEPT_SOURCE).map(([k, r]) => [`cases.${k}`, r]),
  ];
  const out = [];
  for (const [where, r] of entries) {
    const at = typeof r.measured_at === "string" ? Date.parse(r.measured_at) : NaN;
    const ages = r.answers_age_ms !== null && typeof r.answers_age_ms === "object" ? r.answers_age_ms : undefined;
    const base = { where, measured_at: r.measured_at ?? null };
    if (Number.isNaN(at)) out.push({ ...base, problem: "not_a_time" });
    else if (!Object.keys(gens).length) out.push({ ...base, problem: "no_generated_at" });
    else if (!ages) out.push({ ...base, problem: "no_ages" });
    else {
      // One line per entry, naming the first answer that does not agree with the read.
      const wrong = [];
      for (const [file, g] of Object.entries(gens)) {
        const recorded = ages[file];
        if (!Number.isInteger(recorded)) wrong.push({ problem: "unrecorded_answer", file, generated_at: g.at });
        else if (at - g.ms !== recorded) wrong.push({ problem: "re_dated", file, generated_at: g.at, age_ms: at - g.ms, recorded_ms: recorded });
      }
      for (const file of Object.keys(ages)) if (!gens[file]) wrong.push({ problem: "answer_gone", file });
      if (wrong.length) out.push({ ...base, ...wrong[0] });
    }
  }
  return out;
}

const REMEDY = "Re-measure with node test/text-bound-live.mjs --answers test/fixtures/prod-answers --record, which keeps the read's time (answers_read_at) and the ages it saw, or read production again (its default source, scripts/probe-prod.sh).";
const secs = (ms) => `${(ms / 1000).toFixed(1)} s`;

/** What to do about one datedAfterAnswers entry. */
export const datedAfterAnswersMessage = (o) => {
  const head = `${o.where}: measured_at ${JSON.stringify(o.measured_at)}`;
  switch (o.problem) {
    case "re_dated": {
      const by = o.age_ms - o.recorded_ms;
      return `${head} is ${secs(Math.abs(by))} ${by > 0 ? "later" : "earlier"} than the read that kept these answers says: ${o.file} (generated_at ${o.generated_at}) would have been ${secs(o.age_ms)} old at it, and the read recorded that answer ${secs(o.recorded_ms)} old (answers_age_ms), so the record is dated by something other than the production read. ${REMEDY}`;
    }
    case "no_ages":
      return `${head}: the entry records no answers_age_ms (how old each kept answer was, by its own generated_at, when production was read), so its date is held to nothing. ${REMEDY}`;
    case "unrecorded_answer":
      return `${head}: the kept answer ${o.file} (generated_at ${o.generated_at}) is not one the read recorded in answers_age_ms: the kept answers were replaced after the read. Read production again (scripts/probe-prod.sh), or restore the answers the read kept.`;
    case "answer_gone":
      return `${head}: the read recorded ${o.file} in answers_age_ms, and no kept answer of that name carries a generated_at: the kept answers were changed after the read. Read production again (scripts/probe-prod.sh), or restore the answers the read kept.`;
    case "no_generated_at":
      return `${head}: no kept answer carries a generated_at, so the record's date is held to nothing. Read production again (scripts/probe-prod.sh).`;
    default:
      return `${head} is not a time: the record is dated by nothing. ${REMEDY}`;
  }
};

// What fixtures/text-bound-live.json says of itself; text-bound-live.mjs --record writes it, so it
// says what the code that writes the record does (#2782: through 3.0.2 it said exposure_radar's entry
// was a seed "until the first --record replaces it" long after one had, and that a re-measure moves
// measured_at).
export const RECORD_ABOUT =
  "#2616, #2783: production's text, measured on production's answers with this checkout's server. Written by test/text-bound-live.mjs --record, this about included (text-bound.mjs RECORD_ABOUT). tools: the production-wide tools (exposure_radar, cve_summary), held to MARGIN from this record, their answers kept in fixtures/prod-answers/ (written only from scripts/probe-prod.sh); answers_kept says so. cases: each case of text-bound.mjs SHAPED measured on production, held to the ceiling, and text-bound.test.mjs holds each SHAPED case's text, and (#3273) its structured result, within SHAPED_DRIFT of its record here (STRUCTURED_DRIFT_KNOWN names the cases past it, and what clears each); source says where the answers came from (probe-prod, the answers kept here, the hosted endpoint, replayed, or for exposure_radar and cve_intel the hosted endpoint's own text). Dates (#2782): measured_at is when production was read for the number, and read_ms how long that read took (null where it was not recorded); a re-measure of the kept answers (--answers test/fixtures/prod-answers --record) moves neither. answers_age_ms is how old each kept answer was, by its own generated_at, when production was read, written by the read: the API serves a radar's aggregate stale past its 60 s cache TTL to the first request after it, and the CDN 300 s more, so an honest read's answers can be minutes old; text-bound.test.mjs fails when measured_at less a kept answer's generated_at is not the age the read recorded for it. answers_read_at (#2822) is when the kept answers were read, the same read. code_measured_at is when this checkout's server last measured the answers, and code_version which code that was: package.json's version, with +unreleased when CHANGELOG.md's newest section is unreleased; package_version is package.json's version alone. total and blocks: the text's characters, all blocks and each. structured (#3013): the answer's structuredContent as compact JSON, what Claude Code hands the model, held to STRUCTURED_BUDGET (30,000); a case recorded before 3.0.0 carries none. data_truncated and truncated (#3273): whether the server measured cut that structured result's data, and what it cut, so the cut level is on record, not inferred; a case recorded before carries neither.";

/** The tools whose answer is production-wide (no input), measured live, and the API paths each one reads. */
export const LIVE_TOOLS = {
  exposure_radar: [
    "/api/v1/public/kev-exposure/stats",
    "/api/v1/public/exposed-databases/stats",
    "/api/v1/public/leaked-credentials/stats",
    "/api/v1/public/shadow-ai-radar/stats",
    "/api/v1/public/ai-exposure/stats?service=mcp",
  ],
  cve_summary: ["/api/v1/public/cves/summary"],
};

/** The file a production answer for `apiPath` is kept in. */
export const answerFile = (apiPath) => path.join(PROD_ANSWERS, `${apiPath.replace(/^\/api\/v1\/public\//, "").replace(/[^A-Za-z0-9.-]+/g, "_")}.json`);

export function readLiveRecord() {
  return JSON.parse(fs.readFileSync(LIVE_RECORD, "utf8"));
}

/**
 * #2822: each SHAPED case measured on kept production answers (`kept`) whose size is more than
 * MARGIN from the record's total for that tool, with the size to set. The suite measures those
 * answers on every run and holds the text within MARGIN of the case's size, so a re-record that
 * moves the total without moving the size fails the release; text-bound-live.mjs --record names
 * them and exits 1, and text-bound.test.mjs fails on them, each saying what to set.
 */
export function keptSizesOffRecord(record = readLiveRecord()) {
  return SHAPED.filter((c) => c.kept && record.tools?.[c.kept] && Math.abs(c.size - record.tools[c.kept].total) > MARGIN).map((c) => ({
    label: c.label,
    size: c.size,
    total: record.tools[c.kept].total,
    measured_at: record.tools[c.kept].measured_at,
  }));
}

/** What to do about one keptSizesOffRecord entry. */
export const setKeptSize = (o) =>
  `${o.label}: SHAPED's size is ${o.size}, but the record (${o.measured_at}) measured ${o.total}, more than MARGIN ${MARGIN} away: set its size to ${o.total} in test/text-bound.mjs, run npm test, and commit it with the record`;

/** The kept production answers for `tool`, as stub overrides (request URL -> body); undefined when any is missing. */
export function keptAnswers(tool) {
  const out = {};
  for (const p of LIVE_TOOLS[tool]) {
    const f = answerFile(p);
    if (!fs.existsSync(f)) return undefined;
    out[p] = JSON.parse(fs.readFileSync(f, "utf8"));
  }
  return out;
}

// ── Production-shaped answers, for every tool (#2783) ──
//
// Through 2.6.2 the ceiling was checked against the stub fixtures of tools.test.mjs alone: one
// search_cves row of 6 fields printed "search_cves: 1,115 / 60,000 = 2%" while production's default
// search_cves answer was 133,298 characters, and 9 of the 14 tools printed nothing. SHAPED is one
// case per tool at its default call and, for a tool with a page size, one at its largest page, each
// on production's own answer read through the hosted endpoint (fixtures/prod-shaped/, the capture
// and production's text at the time in each file) or kept by #2616 (fixtures/prod-answers/). A file
// keeps a few of production's rows, every k-th, and a case repeats them to its page size
// (`repeat`), so the rows the text is measured on are production's rows, field for field, without
// keeping megabytes. `size` is the case's text measured on it, which text-bound.test.mjs holds it
// to within MARGIN either way (#2800: a text that shrinks is re-measured, as one that grows is);
// `production` in the file is what production's 2.6.2 text was for the same call. `structured`
// (#3013) is the case's structuredContent measured on it, as compact JSON (structuredSize), held
// the same way and under STRUCTURED_BUDGET; a resource read has none. Through 2.7.x it was the
// answer whole: 64,170 characters for get_cve CVE-2021-44228, 3,790,686 for check_sbom's 2,000 purls.
//   page     "default": the call as a client makes it first; "max": the largest page the
//            tool's inputSchema allows (limit at its maximum; check_sbom's 2,000 purls);
//            "forced": production's rows made longer (`stretch`) so that a tool whose every
//            production answer fits is cut, and its cut level is checked (#2800 review).
//   answers  the file's answers this case serves; the stub answers each request by its path.
//   take     {list: n}: the file's first n rows of `list`, before `repeat`: the rows of a smaller
//            page than the one the file was read at (#3273: the default page's own rows).
//   set      top-level fields of the answer this case sets (the page size the API echoes).
//   recount  check_sbom: summary recounted from the repeated rows, as the API counts them.
//   stretch  a forced case's longer rows: {list: {field: n}}, each row's string `field` n times
//            over, joined by a space (after `repeat`).
//   limited  the API's component budget as production spends it: the stub answers the first
//            `after` requests and every later one 429 with Retry-After `retryAfter` seconds.
//   resource a resource read instead of a tool call (cve://{cve_id}, #2801): its text is measured,
//            under the same ceiling; `tool` is then the tool whose answer it reads.
//   live     set: text-bound-live.mjs does not measure it on production, and why.
//   annotate {list: {key, values, otherwise}}: fields set on each row of `list` by the value of its
//            field `key` (values[row[key]], else otherwise): an answer field production does not
//            serve yet, on production's rows (#2817).
export const SHAPED_DIR = path.join(HERE, "fixtures", "prod-shaped");
// #2817: the ranges of OSV GHSA-jfh8-c2jp-5v3q (CVE-2021-44228) per package, as core-backend's
// fixed_branches serves them (cve/fixed_branches.go: fixed and last_affected kept apart, each null
// when absent, and each range naming the OSV record that published it, advisory_id and source).
// log4j-core's are in the record's order; the order of the others does not change the size.
const range = (introduced, fixed, last_affected = null) => ({ introduced, fixed, last_affected, source: "osv_bulk", advisory_id: "GHSA-jfh8-c2jp-5v3q" });
export const LOG4SHELL_FIXED_BRANCHES = {
  "org.apache.logging.log4j:log4j-core": { fixed_branches: [range("2.13.0", "2.15.0"), range("2.0-beta9", "2.3.1"), range("2.4", "2.12.2")] },
  "org.ops4j.pax.logging:pax-logging-log4j2": { fixed_branches: [range("1.8.0", "1.9.2"), range("1.10.0", "1.10.8"), range("1.11.0", "1.11.10"), range("2.0.0", "2.0.11")] },
  "com.guicedee.services:log4j-core": { fixed_branches: [range("0", null, "1.2.1.2-jre17")] },
  "org.xbib.elasticsearch:log4j": { fixed_branches: [] },
  "uk.co.nichesolutions.logging.log4j:log4j-core": { fixed_branches: [] },
};
// #2839: CISA's KEV text for CVE-2021-44228 as core-backend serves it on the record
// (kev_required_action, kev_short_description, kev_notes_urls), copied verbatim from CISA's
// known_exploited_vulnerabilities.json, catalogVersion 2026.10.04 (read 2026-10-05). Production's
// get_cve answer kept in fixtures/prod-shaped/ predates the fields, so the get_cve cases `set` them
// on it until that answer is re-captured from production after core-backend ships them.
export const LOG4SHELL_KEV_TEXT = {
  kev_required_action:
    "For all affected software assets for which updates exist, the only acceptable remediation actions are: 1) Apply updates; OR 2) remove affected assets from agency networks. Temporary mitigations using one of the measures provided at https://www.cisa.gov/uscert/ed-22-02-apache-log4j-recommended-mitigation-measures are only acceptable until updates are available.",
  kev_short_description:
    "Apache Log4j2 contains a vulnerability where JNDI features do not protect against attacker-controlled JNDI-related endpoints, allowing for remote code execution.",
  kev_notes_urls: ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
};
const JUICE_SHOP = path.join(HERE, "fixtures", "juice-shop-11.1.2-50.cdx.json");
// 2,000 distinct purls, check_sbom's most per call (MAX_PURLS).
export const SBOM_MAX_PURLS = 2000;
const manyPurls = () => Array.from({ length: SBOM_MAX_PURLS }, (_, i) => `pkg:npm/shaped-${i}@1.0.${i % 10}`);
// #2835: scan_manifest's files. A real package-lock (fixtures/manifests/tree.v3.package-lock.json,
// npm 10, 64 registry packages and 3 entries not checked), and the same file's registry entries
// cycled under new names to a 1,500-entry lockfile, 100 of them installed from git (not checked):
// 1,400 distinct purls, seven batches of 200.
const MANIFESTS = path.join(HERE, "fixtures", "manifests");
export const TREE_LOCK = () => fs.readFileSync(path.join(MANIFESTS, "tree.v3.package-lock.json"), "utf8");
export function bigLock(entries = 1500, git = 100) {
  const tree = JSON.parse(TREE_LOCK());
  const registry = Object.entries(tree.packages).filter(([k, e]) => k.startsWith("node_modules/") && !e.link && String(e.resolved ?? "").startsWith("https://registry.npmjs.org/"));
  const packages = { "": tree.packages[""] };
  for (let i = 0; i < entries; i++) {
    const [key, e] = registry[i % registry.length];
    const name = `${key.split("node_modules/").pop().replace("@", "")}-r${i}`;
    packages[`node_modules/${name}`] = i < git ? { ...e, name: undefined, resolved: `git+ssh://git@github.com/example/${name}.git#${String(i).padStart(40, "0")}` } : { ...e, name: undefined };
  }
  return JSON.stringify({ ...tree, packages }, null, 2);
}
export const SHAPED = [
  { label: "cve_summary", tool: "cve_summary", page: "default", args: {}, kept: "cve_summary", size: 2_725, structured: 2_565 },
  // #3140: fixtures/prod-shaped/search_cves.json re-sampled from hosted 3.0.0 (full: true,
  // 2026-10-11): the record's largest page was 18,831 characters against the old rows' 31,648, as
  // production's rows had grown past the text cut's 200-character level. 14,455 / 26,761 and
  // 31,648 / 14,730 on the old rows.
  // #3273: the default page repeats the file's first 4 rows, rows 0, 5, 10 and 15 of production's
  // page: every 5th of the default page's own 20. It lands where production's size does (8,927
  // characters of structuredContent against production's 9,064), cut here at the second level (no
  // description). Production's level for this call is inferred from that size, not measured: the
  // record holds no truncated for it until the next --hosted --record writes one. Every 5th of the
  // 50, repeated to 20, fit at the first level (28,336, every row's description kept), three times
  // production's size.
  { label: "search_cves, default page (search openssl)", tool: "search_cves", page: "default", args: { search: "openssl" }, fixture: "search_cves", answers: ["openssl"], take: { cves: 4 }, repeat: { cves: 20 }, set: { limit: 20 }, size: 15_780, structured: 8_927 },
  { label: "search_cves, largest page (search openssl, limit 50)", tool: "search_cves", page: "max", args: { search: "openssl", limit: 50 }, fixture: "search_cves", answers: ["openssl"], repeat: { cves: 50 }, set: { limit: 50 }, size: 18_717, structured: 17_409 },
  // #3084 (merged from 24dad5eb): the KEV note names BOD 26-04, which replaced BOD 22-01, 43 characters longer in
  // the text and in the structured result's notes; the cut then keeps 86 cpe_match and references entries, not 87
  // (24,833 and 29,963 before).
  { label: "get_cve, CVE-2021-44228", tool: "get_cve", page: "default", args: { cve_id: "CVE-2021-44228" }, fixture: "get_cve", answers: ["CVE-2021-44228"], repeat: { cpe_match: 396, references: 103 }, set: LOG4SHELL_KEV_TEXT, size: 24_876, structured: 29_705 },
  // #2801: the cve:// resource reads get_cve's answer; through 2.6.3 it was that answer's structured
  // result pretty-printed whole, 86,559 characters for this CVE on the hosted endpoint (2026-10-04).
  {
    label: "cve://CVE-2021-44228, the resource",
    resource: "cve://CVE-2021-44228",
    tool: "get_cve",
    page: "default",
    args: { cve_id: "CVE-2021-44228" },
    fixture: "get_cve",
    answers: ["CVE-2021-44228"],
    repeat: { cpe_match: 396, references: 103 },
    set: LOG4SHELL_KEV_TEXT,
    live: "it reads get_cve's answer for the same CVE, which the get_cve case measures on production; text-bound-live.mjs reads tools only",
    // #3013's review: 24,682 until the envelope said what the resource cut (data_truncated true,
    // truncated naming cpe_match and references), +155. #3084 (merged from 24dad5eb): 24,837 until
    // get_cve's KEV note named BOD 26-04, which replaced BOD 22-01, +43.
    size: 24_880,
  },
  { label: "cve_exposure, CVE-2023-44487", tool: "cve_exposure", page: "default", args: { cve_id: "CVE-2023-44487" }, fixture: "cve_exposure", answers: ["CVE-2023-44487"], size: 4_392, structured: 4_803 },
  { label: "exposure_radar", tool: "exposure_radar", page: "default", args: {}, kept: "exposure_radar", size: 43_702, structured: 29_962 }, // #3010: three radars past their threshold on these 2026-10-05 answers, and the last sentence
  { label: "kev_recent, default page (limit 50)", tool: "kev_recent", page: "default", args: {}, fixture: "kev_recent", answers: ["recent"], repeat: { kev: 50 }, set: { limit: 50, count: 50 }, size: 29_187, structured: 23_257 },
  { label: "kev_recent, largest page (limit 200)", tool: "kev_recent", page: "max", args: { limit: 200 }, fixture: "kev_recent", answers: ["recent"], repeat: { kev: 200 }, set: { limit: 200, count: 200 }, size: 32_672, structured: 29_778 },
  // #2867: 2,379 through 2.6.8. The fixture is production's answer from before core-backend served
  // complete_since and coverage, so the note now says the answer does not say from when the record
  // is complete, and the envelope's coverage carries the completeness fields (null / []).
  // #3140: fixtures/prod-shaped/epss_history.json re-read from hosted 3.0.0 (full: true,
  // 2026-10-11), the API having added complete_since and coverage; 2,798 / 2,531 before.
  // #3143: production's runs_undated 1 is now named in the note, and the envelope's coverage carries
  // runs_undated, refresh_runs_truncated and days_in_progress; 3,750 / 3,382 before (the record's
  // 3,750 is 3.0.1's).
  { label: "epss_history, CVE-2021-44228", tool: "epss_history", page: "default", args: { cve_id: "CVE-2021-44228" }, fixture: "epss_history", answers: ["CVE-2021-44228"], size: 4_119, structured: 3_737 },
  { label: "check_affected, openssl 3.0.0", tool: "check_affected", page: "default", args: { product: "openssl", version: "3.0.0" }, fixture: "check_affected", answers: ["openssl"], repeat: { matches: 71 }, size: 26_828, structured: 11_990 },
  { label: "check_affected, linux_kernel 5.10.0 (200 matches, the API's cap)", tool: "check_affected", page: "max", args: { product: "linux_kernel", version: "5.10.0" }, fixture: "check_affected", answers: ["linux_kernel"], repeat: { matches: 200 }, size: 30_373, structured: 29_181 },
  // The cap with the CPE path's excluded sample beside it: 50 entries, each with a sentence of detail.
  {
    label: "check_affected, flash_player 10.0.0 (200 matches and an excluded sample of 50)",
    tool: "check_affected",
    page: "max",
    args: { product: "flash_player", version: "10.0.0" },
    fixture: "check_affected",
    answers: ["flash_player"],
    repeat: { matches: 200, excluded: 50 },
    size: 30_901, structured: 29_921,
  },
  // #2834: the first thinned data level keeps a CPE match's cpe_version_end_excluding and
  // cpe_version_end_including, and the DATA CUT note, which the text carries too, names that
  // level's fields, so it names them here as well: 24,807 / 14,352 before (54 characters each).
  { label: "check_affected, PyPI django 1.11.0 (the registry path)", tool: "check_affected", page: "default", args: { ecosystem: "PyPI", package: "django", version: "1.11.0" }, fixture: "check_affected", answers: ["django"], repeat: { matches: 29 }, size: 24_861, structured: 14_406 },
  // #3013's review: each thinned match keeps ransomware, effective_score and score_assessed too,
  // which workload_triage reads (structured 17,122 before, text 31,303: the DATA CUT sentence names
  // the fields); all 50 rows still stay.
  { label: "check_sbom, Juice Shop 11.1.2 (50 components)", tool: "check_sbom", page: "default", args: () => ({ sbom: JSON.parse(fs.readFileSync(JUICE_SHOP, "utf8")) }), fixture: "check_sbom", answers: ["batch"], repeat: { results: 50 }, recount: true, size: 31_348, structured: 21_262 },
  {
    label: "check_sbom, 2,000 purls (10 batches of 200)",
    tool: "check_sbom",
    page: "max",
    args: () => ({ purls: manyPurls() }),
    fixture: "check_sbom",
    answers: ["batch"],
    repeat: { results: 200 },
    recount: true,
    live: "2,000 lookups would pass production's 1,200 components a minute per caller; the suite measures the same rows, repeated",
    // #3013's review: 36,606 and 29,921 (35 rows in data) before each thinned match kept ransomware,
    // effective_score and score_assessed; 21 rows. #3132: 36,651 and 29,224 (21 rows, each with
    // its matches) before rows left only once every row was cut to index, purl, verdict,
    // not_assessed_reason and cve_ids; 90 rows. #3132's review: 36,575 and 29,892 (90 rows, no
    // match in any) before rows left at the compact level (check_sbom.ts leaveAt); 28 rows now,
    // every one affected, each with its matches compact. The text is the same cut; its note's DATA
    // CUT sentence is longer. 36,999 and 29,483 (28 rows) while the note named a cap of 10 matches
    // a row that no row here reaches; 29 rows now. #3270: 36,639 and 29,760 (29 rows) before the
    // compact level kept epss_score and score_assessed, which workload_triage ranks by; 21 rows.
    // #3269's review: 36,667 and 29,240 before the page sentence named the purls a call of the
    // first that many keeps whole, and said so; 21 rows still. #3269's second review: 36,788 and
    // 29,361 before the note named by index the affected rows that left data (up to 100 indices
    // or runs of them) and the text had no page sentence; 21 rows still. #3269's third review:
    // 37,402 and 29,973 before the note named the rows left out with a KEV-listed match apart and
    // gave the sizes of the calls that check them again; 21 rows still.
    size: 37_413, structured: 29_986,
  },
  // What production answers the same call from a fresh budget (src/tools/check_sbom.ts MAX_PURLS):
  // six batches, then 429 asking for a wait past the call's 50 s, so 1,200 rows and 800 purls in
  // data.not_sent_purls.
  {
    label: "check_sbom, 2,000 purls, rate-limited after 6 batches (production's answer from a fresh budget)",
    tool: "check_sbom",
    page: "max",
    args: () => ({ purls: manyPurls() }),
    fixture: "check_sbom",
    answers: ["batch"],
    repeat: { results: 200 },
    recount: true,
    limited: { after: 6, retryAfter: 60 },
    live: "it spends production's whole budget of 1,200 components a minute per caller and is then refused; the suite measures the same rows, repeated, and the 429",
    // #3013's review: 37,740 and 29,985 (33 rows and 13 purls not sent in data) before each thinned
    // match kept ransomware, effective_score and score_assessed; 20 rows and 21 purls. #3132:
    // 37,785 and 29,982 before rows left only at the leanest level; 86 rows and 3 purls.
    // #3132's review: 37,707 and 29,973 before not_sent_purls was kept whole or not at all and rows
    // left at the compact level; 27 rows, each with its matches compact, and no purl not sent (the
    // note and coverage give their positions). 38,228 and 29,654 while the note named a cap no row
    // here reaches; 27 rows still, the first taking back its matches thinned (giveBack). #3270:
    // 38,223 and 29,863 (27 rows) before the compact level kept epss_score and score_assessed; 20
    // rows, none taking back detail (compact is now SBOM_ROW_THIN less fixed_in_reason, which these
    // rows' matches do not carry), so the note's DATA CUT sentence is shorter too. #3269's review:
    // 37,896 and 29,506 before the page sentence named the purls a call of the first that many
    // keeps whole, and said so; 20 rows still. #3269's second review: 38,017 and 29,627 (20 rows)
    // before the note named by index the affected rows that left data (up to 100 indices or runs) and the text
    // had no page sentence; 20 rows still, chosen by fit (a larger row passed for a smaller).
    // #3269's third review: 38,630 and 29,801 before the note named the rows left out with a
    // KEV-listed match apart and gave the sizes of the calls that check them again; 20 rows still.
    size: 38_718, structured: 29_891,
  },
  // #2817: production's answer after core-backend with #2817 was deployed and before the OSV
  // backfill has run (prod-shaped/cve_intel.json, read again 2026-10-05T07:38Z): every
  // affected_packages row carries fixed_branches, each range with source and advisory_id null
  // (log4j-core: [2.0-beta9, 2.3.1), [2.4, 2.12.2), [2.13.0, 2.15.0)), and the answer carries
  // failed_sections []. 17,355 characters, production's own text for the call (text-bound-live.mjs,
  // 2026-10-05T07:37:21Z); through the 2026-10-04 read, with no fixed_branches and no
  // failed_sections, it was 14,693.
  // #2835: production's batch rows (prod-shaped/check_sbom.json), one per distinct purl.
  // #3140: measured on production for the first time (hosted 3.0.0, full: true, 2026-10-11): 32,922
  // characters of text against the 16,540 of check_sbom's rows repeated to 64, so the case now
  // replays production's own answer for this lock (fixtures/prod-shaped/scan_manifest.json, all 64
  // rows); 16,540 / 28,633 on the repeated rows.
  { label: "scan_manifest, package-lock.json (64 packages)", tool: "scan_manifest", page: "default", args: () => ({ files: [{ filename: "package-lock.json", content: TREE_LOCK() }] }), fixture: "scan_manifest", answers: ["batch"], size: 32_922, structured: 22_787 }, // #3013's review: 16,401 and 22,761 before the thinned match's three fields and the note's "whole with full: true" on not_checked; all 64 rows stay
  {
    label: "scan_manifest, package-lock.json of 1,500 entries (1,400 distinct purls, 100 from git)",
    tool: "scan_manifest",
    page: "max",
    args: () => ({ files: [{ filename: "package-lock.json", content: bigLock() }] }),
    fixture: "check_sbom",
    answers: ["batch"],
    repeat: { results: 200 },
    recount: true,
    live: "1,400 lookups would pass production's 1,200 components a minute per caller; the suite measures the same rows, repeated",
    // #3013's review: 37,566 and 29,786 (33 rows in data) before the not_checked sentence said the
    // list is whole with full: true, and each thinned match kept three more fields; 20 rows.
    // #3132: 37,708 and 29,903 before rows left only at the leanest level; 85 rows.
    // #3132's review: 37,629 and 29,871 before rows left at the compact level; 27 rows now (38,053
    // and 29,817 while the note named a cap no row here reaches). #3270: 37,696 and 29,988 (27
    // rows) before the compact level kept epss_score and score_assessed; 20 rows. #3269's review:
    // 37,724 and 29,919 before the page sentence named the purls a call of the first that many
    // keeps whole, and said so; 20 rows still. #3269's second review: 37,853 and 29,801 (20 rows)
    // before the note named by index the affected rows that left data (up to 100 indices or runs) and the text
    // had no page sentence; 20 rows still. #3269's third review: 38,418 and 29,927 before the note
    // named the rows left out with a KEV-listed match apart (scan_manifest gives no re-check
    // sizes: its rows are checked again through check_sbom, by purls its note does not give); 20
    // rows still.
    size: 38_391, structured: 29_900,
  },
  // #3074: 17,355 until the fixed_branches description and the several-ranges note said how an
  // installed version's fix moves past an overlapping range (+199). #3039: +204 text and +231
  // structured once the note counts Nuclei detection templates apart from exploit code (17,608 and
  // 12,888 before, measured on the merge of both, 2026-10-11). #3221: +138 text and +138 structured
  // once the method names GitHub checker repositories (github_checker) beside Nuclei templates as
  // detection checks (17,812 and 13,119 before). #3267's review: +92 and +92 once the method says
  // what a kind on neither list is ("A kind on neither list is one this server does not classify:
  // the note counts it as neither.", 17,950 and 13,257 before).
  { label: "cve_intel, CVE-2021-44228", tool: "cve_intel", page: "default", args: { cve_id: "CVE-2021-44228" }, fixture: "cve_intel", answers: ["CVE-2021-44228"], repeat: { timeline: 100 }, size: 18_042, structured: 13_349 },
  // #2817: the same rows once the OSV backfill (BACKFILL_OSV_PACKAGES_FORCE, pending) has filled
  // each range's record: the ranges of GHSA-jfh8-c2jp-5v3q (api.osv.dev, 2026-10-05) with
  // advisory_id and source, log4j-core's three in the record's order, pax-logging-log4j2's four,
  // guicedee's one range with a last_affected bound, and [] for the two packages the record gives no
  // range; the Debian rows keep production's own ranges (otherwise {}), source and advisory_id null,
  // since this case does not know their record. 17,539 characters, under the 30,000 ceiling (17,001
  // when built on the 2026-10-04 read, the Debian rows then set to null). Not measured on production
  // (live) until the backfill has run: re-measure there then (text-bound-live.mjs).
  {
    label: "cve_intel, CVE-2021-44228, with fixed_branches (#2817)",
    tool: "cve_intel",
    page: "default",
    args: { cve_id: "CVE-2021-44228" },
    fixture: "cve_intel",
    answers: ["CVE-2021-44228"],
    repeat: { timeline: 100 },
    annotate: { affected_packages: { key: "package_name", values: LOG4SHELL_FIXED_BRANCHES, otherwise: {} } },
    // #3140: hosted 3.0.0's cve_intel CVE-2021-44228 serves each range's advisory_id and source
    // (2026-10-11: 14 ranges over 11 packages, DLA-2842-1 among them), so the backfill has run and
    // this case is measured on production; cve_intel relays its own cut, so the record is the
    // hosted endpoint's own text, as for the case above.
    // #3074: 17,539 before the overlapping-range wording (+199, as above); #3039: +204 and +231, as above.
    // #3221: +138 and +138, as above (17,996 and 13,303 before). #3267's review: +92 and +92, as
    // above (18,134 and 13,441 before).
    size: 18_226, structured: 13_533,
  },
  // #2841: cve_remediation for Log4Shell on production's data (prod-shaped/cve_remediation.json,
  // assembled 2026-10-05 from the stored advisories by the parsers, before the route is live): 20
  // vendor advisories, 19 of them Red Hat's with their vendor_fix and workaround texts, the
  // packages' fixed_branches, CISA's text and the Patch/Mitigation references. Its JSON is past the
  // 30,000-character budget, so the cut is measured: texts shortened first, kinds, states and URLs kept.
  {
    label: "cve_remediation, CVE-2021-44228",
    tool: "cve_remediation",
    page: "default",
    args: { cve_id: "CVE-2021-44228" },
    fixture: "cve_remediation",
    answers: ["CVE-2021-44228"],
    // #3140: the route is deployed (hosted 3.0.0 answers cve_remediation, 2026-10-11), so this
    // case is measured on production.
    // 20,644 through 2.7.1. 20,809 since #2841's fix-reference wording: the API keeps a CNA's
    // lowercase patch and mitigation tags, and the note and method now say both spellings.
    // #3074: 20,941 since the fixed_branches sentence says how the fix moves past an overlapping range.
    // #3013's review: 21,730 and 25,901 before the DATA CUT said where each item's text is
    // (get_vendor_advisory), the level this answer is thinned to keeping no item text.
    size: 22_031, structured: 26_204,
  },
  { label: "get_cwe, CWE-79", tool: "get_cwe", page: "default", args: { cwe_id: "CWE-79" }, fixture: "get_cwe", answers: ["CWE-79"], repeat: { cves: 50 }, size: 28_743, structured: 24_299 },
  // #2800 review: no answer the API serves reaches get_cwe's cut. It cuts each row's description to
  // 240 characters (core-backend cve/cwe_landing_store.go ListCVEsByCWE) in pages of 50, so a page
  // fits whole: CWE-79's is 26,907 characters, and CWE-416's first, hosted on 2026-10-04, 27,073.
  // So the cut's level was checked by no case, and dropping a field the description names from it
  // left the suite green. Forced: CWE-79's rows, each description four times over.
  {
    label: "get_cwe, CWE-79, each description four times over (a forced cut)",
    tool: "get_cwe",
    page: "forced",
    args: { cwe_id: "CWE-79" },
    fixture: "get_cwe",
    answers: ["CWE-79"],
    repeat: { cves: 50 },
    stretch: { cves: { description: 4 } },
    live: "a forced cut: no page the API serves reaches it (each row's description is cut to 240 characters at the source)",
    size: 20_557, structured: 29_519,
  },
  { label: "vendor_advisories_for_cve, CVE-2021-44228", tool: "vendor_advisories_for_cve", page: "default", args: { cve_id: "CVE-2021-44228" }, fixture: "vendor_advisories_for_cve", answers: ["CVE-2021-44228"], extra: ["coverage"], size: 18_686, structured: 14_983 },
  // #2800 review: nor does any answer reach vendor_advisories_for_cve's cut: the API sends at most 20
  // advisories for a CVE (core-backend vendoradv/store.go ListAdvisoriesByCVE, LIMIT 20), each
  // without summary, affected_products or cve_ids: CVE-2021-44228's 20 are 9,753 characters of
  // pretty JSON (12,670 on hosted 3.0.0, 2026-10-11, its rows re-read for #3140: 15,432 / 12,675 and,
  // forced, 15,606 / 29,447 on the earlier rows).
  // Its cut levels are search_vendor_advisories' (ROW_CUT_LEVELS), but its TextCut is its own.
  // #2803: re-measured for held_since. The coverage answer in the fixture is 2.6.4's API, which has
  // no held_since, so each vendor with no complete history read is written "not known to be
  // without a gap" and relayed with held_since null (the two search cases below likewise).
  // Forced: CVE-2021-44228's rows, each title twenty times over.
  {
    label: "vendor_advisories_for_cve, CVE-2021-44228, each title twenty times over (a forced cut)",
    tool: "vendor_advisories_for_cve",
    page: "forced",
    args: { cve_id: "CVE-2021-44228" },
    fixture: "vendor_advisories_for_cve",
    answers: ["CVE-2021-44228"],
    stretch: { advisories: { title: 20 } },
    extra: ["coverage"],
    live: "a forced cut: no answer the API serves reaches it (at most 20 advisories, each a few hundred characters)",
    size: 17_914, structured: 29_170,
  },
  { label: "get_vendor_advisory, aws 2026-098-AWS", tool: "get_vendor_advisory", page: "default", args: { vendor: "aws", advisory_id: "2026-098-AWS" }, fixture: "get_vendor_advisory", answers: ["aws 2026-098-AWS"], extra: ["coverage"], size: 3_091, structured: 2_855 },
  { label: "search_vendor_advisories, default page (query log4j)", tool: "search_vendor_advisories", page: "default", args: { query: "log4j" }, fixture: "search_vendor_advisories", answers: ["log4j"], repeat: { advisories: 20 }, set: { limit: 20 }, extra: ["coverage"], size: 34_472, structured: 23_851 },
  { label: "search_vendor_advisories, largest page (query log4j, limit 50)", tool: "search_vendor_advisories", page: "max", args: { query: "log4j", limit: 50 }, fixture: "search_vendor_advisories", answers: ["log4j"], repeat: { advisories: 50 }, set: { limit: 50 }, extra: ["coverage"], size: 23_483, structured: 29_833 },
];

// How far a case's size may be from production's text for the same call, as text-bound-live.mjs
// last recorded it, as a fraction of production's (#2783). A fixture keeps every k-th of
// production's rows, and its pretty JSON was held to within a few percent of production's; but the
// cut works in levels, so rows a little longer than production's average can be cut one level
// further than production's page is, and the bound is then not production's: kev_recent's page of
// 200, sampled from row 4, was 25,286 characters against production's 31,588. Held only where both
// sizes are this checkout's server's text (not where the record is the hosted endpoint's own).
export const SHAPED_DRIFT = 0.1;

// #3273: the same held of the structured result. #3140 recorded production's structuredContent size
// for every case, and only the two kept tools' were compared with SHAPED's: search_cves' default page
// was 28,336 characters here against production's 9,064 (the fixture cut at the first level, while
// production's size is where the second lands, its level inferred, not measured) and passed. Each case's `structured` is now held within SHAPED_DRIFT of
// the record's for the same label, where the record is this checkout's server on production's data
// (not the hosted endpoint's own text).
//
// STRUCTURED_DRIFT_KNOWN names the cases past it on the committed record, each with why and what
// clears it, pinned to the sizes it was named at (within MARGIN): a case named here that moves, or
// comes back within SHAPED_DRIFT, fails until this list is looked at again, so it cannot hide a
// further drift. Both need a read of production, so they are an operator's to clear.
export const STRUCTURED_DRIFT_KNOWN = {
  "check_sbom, Juice Shop 11.1.2 (50 components)": {
    shaped: 21_262,
    recorded: 24_884,
    why: "fixtures/prod-shaped/check_sbom.json keeps every 5th of production's 50 rows from 2026-10-04 (2 of its 10 affected), repeated to 50; production's own 50 rows for this SBOM (hosted 3.0.0, full: true, 2026-10-11) were measured but not kept",
    clears: "re-capture fixtures/prod-shaped/check_sbom.json from the hosted endpoint for this SBOM with full: true (all 50 rows), as scan_manifest's was for #3140, re-measure the case and drop this entry",
  },
  "epss_history, CVE-2021-44228": {
    shaped: 3_737,
    recorded: 3_382,
    why: "the record is 3.0.1's server on production's answer (2026-10-11); since #3143 (unreleased) the envelope's coverage carries runs_undated, refresh_runs_truncated and days_in_progress, +355 here",
    clears: "npm run text-bound:live -- --hosted --record (this checkout's server on production's answer again), then drop this entry",
  },
};

/** #3273: each case whose structured size is more than SHAPED_DRIFT from the record's for the same label (the hosted endpoint's own text left out), with the drift; `known` (STRUCTURED_DRIFT_KNOWN) marks the ones named there. */
export function structuredOffRecord(record = readLiveRecord(), shaped = SHAPED) {
  const out = [];
  for (const c of shaped) {
    const r = record.cases?.[c.label];
    if (typeof c.structured !== "number" || typeof r?.structured !== "number" || /own text/.test(r.source)) continue;
    const drift = (c.structured - r.structured) / r.structured;
    if (Math.abs(drift) > SHAPED_DRIFT) out.push({ label: c.label, structured: c.structured, recorded: r.structured, drift, measured_at: r.measured_at, known: Object.hasOwn(STRUCTURED_DRIFT_KNOWN, c.label) });
  }
  return out;
}

/** What to do about one structuredOffRecord entry. */
export const structuredDriftMessage = (o) =>
  `${o.label}: its structuredContent here, ${o.structured}, is ${o.drift >= 0 ? "+" : ""}${(o.drift * 100).toFixed(1)}% from production's ${o.recorded} (${o.measured_at}), more than SHAPED_DRIFT ${SHAPED_DRIFT * 100}%: its fixture's rows are not cut as production's are (re-sample them), or the record is another code's (re-record)`;

/** A case's arguments. */
export const argsOf = (c) => (typeof c.args === "function" ? c.args() : c.args);

export function readShaped(name) {
  return JSON.parse(fs.readFileSync(path.join(SHAPED_DIR, `${name}.json`), "utf8"));
}

// The rows of `list` repeated in order to n.
const cycled = (list, n) => Array.from({ length: n }, (_, i) => list[i % list.length]);
// A row with each string field named in `fields` n times over, joined by a space.
const stretched = (row, fields) => ({ ...row, ...Object.fromEntries(Object.entries(fields).filter(([f]) => typeof row[f] === "string").map(([f, n]) => [f, Array(n).fill(row[f]).join(" ")])) });
// check_sbom's summary and components, counted from the rows as the API counts them.
function recounted(body) {
  const rows = body.results ?? [];
  const v = { affected: 0, not_affected: 0, undetermined: 0, not_assessed: 0 };
  const by = {};
  for (const r of rows) {
    if (r.verdict in v) v[r.verdict]++;
    if (r.verdict === "not_assessed" && r.not_assessed_reason) by[r.not_assessed_reason] = (by[r.not_assessed_reason] ?? 0) + 1;
  }
  return { ...body, components: rows.length, results: rows.map((r, i) => ({ ...r, index: i })), summary: { ...body.summary, ...v, components: rows.length, lookups: rows.length, not_assessed_by_reason: by } };
}

/** The API answers a case is measured on, as stub overrides (request path -> body). */
export function shapedAnswers(c) {
  if (c.kept) return keptAnswers(c.kept);
  const f = readShaped(c.fixture);
  const out = {};
  for (const name of c.answers) {
    const a = f.answers[name];
    let body = { ...a.body, ...(c.set ?? {}) };
    for (const [key, n] of Object.entries(c.repeat ?? {})) body[key] = cycled(c.take?.[key] ? a.body[key].slice(0, c.take[key]) : a.body[key], n);
    for (const [key, fields] of Object.entries(c.stretch ?? {})) body[key] = body[key].map((r) => stretched(r, fields));
    for (const [key, { key: by, values, otherwise }] of Object.entries(c.annotate ?? {})) body[key] = body[key].map((r) => ({ ...r, ...(values[r[by]] ?? otherwise) }));
    if (c.recount) body = recounted(body);
    out[a.path] = body;
  }
  // Answers the tool reads beside the one it relays (the vendor tools' /coverage, #2729), served as
  // production gave them: no set, repeat or recount, and after the relayed answer.
  for (const name of c.extra ?? []) out[f.answers[name].path] = f.answers[name].body;
  return out;
}

/**
 * #3140: the answers a case's tool reads beside the one it relays (its `extra`: the vendor tools'
 * /coverage), by path, as shapedAnswers serves them. text-bound-live.mjs --hosted serves these
 * beside the replayed answer: the hosted endpoint answers the tool, not the API's other routes, and
 * through the first --hosted --record (2026-10-11) the replay answered /coverage with the tool's own
 * answer, so the vendor tools' notes were not production's (search_vendor_advisories' default page
 * 31,104 characters against 34,472 here, its note 1,297 characters where the coverage note is 4,600).
 */
export function extraAnswers(c) {
  if (!c.extra?.length) return {};
  const f = readShaped(c.fixture);
  return Object.fromEntries(c.extra.map((name) => [f.answers[name].path, f.answers[name].body]));
}

/** Production's text for a case's call where it was measured: {total, blocks, version, at}. */
export function productionText(c) {
  if (c.kept) {
    const r = readLiveRecord().tools?.[c.kept];
    // #2782: the code that measured them (code_version), and when production was read (measured_at).
    return r && { total: r.total, blocks: r.blocks, version: `${r.code_version ?? r.package_version} on its kept answers`, at: r.measured_at };
  }
  const f = readShaped(c.fixture);
  const p = f.production?.[c.label];
  return p && { total: p.total, blocks: p.blocks, version: `${f.captured.server_version}, through the hosted endpoint`, at: f.captured.at };
}

// ── The stub and the cut check, shared by text-bound.test.mjs and prompt-fields.test.mjs ──

// The API's answer when a caller's component budget is spent (core-backend internal/waf/weighted.go).
export const RATE_LIMITED = { error: "component budget exceeded: this batch costs 200 components and this address has 0 left in the window. Nothing was looked up", code: "RATE_LIMIT_EXCEEDED", cost: 200, limit: 1200 };

// A stub API answering each request with the case's answer for its path (whole URL first), and,
// for a case with `limited`, every request after the first `after` with 429 and its Retry-After.
export async function startStub() {
  const state = { answers: {}, limited: undefined, requests: 0 };
  let prefix = "";
  const server = http.createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      const url = unprefixed(req.url, prefix);
      const { pathname } = new URL(url, "http://stub");
      state.requests++;
      if (state.limited && state.requests > state.limited.after) {
        res.writeHead(429, { "content-type": "application/json", "retry-after": String(state.limited.retryAfter) });
        res.end(JSON.stringify(RATE_LIMITED));
        return;
      }
      const body = state.answers[url] ?? state.answers[pathname];
      res.writeHead(body ? 200 : 404, { "content-type": body ? "application/json" : "text/plain" });
      res.end(body ? JSON.stringify(body) : "404 page not found\n");
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const origin = `http://127.0.0.1:${server.address().port}`;
  prefix = prefixFor(origin);
  return {
    state,
    base: `${origin}${prefix}`,
    close: () => {
      server.closeAllConnections();
      return new Promise((r) => server.close(r));
    },
  };
}

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/**
 * Whether `t`, read from a first text block, is a cut of `d`, structuredContent.data: every key it
 * has, `d` has; a string is equal or `d`'s first characters and "…"; a list is some of `d`'s
 * entries, in `d`'s order; anything else is equal. Throws, naming where, when it is not. Each pair
 * of objects it matched (`t`'s object and the object of `d` it is a cut of) is handed to `visit`.
 */
export function assertCutOf(t, d, at = "data", visit = undefined) {
  if (typeof t === "string" && typeof d === "string") {
    if (t === d) return;
    assert.ok(t.endsWith("…") && d.startsWith(t.slice(0, -1)) && t.length <= d.length, `${at}: ${JSON.stringify(t.slice(0, 80))} is neither the answer's string nor its start and "…"`);
    return;
  }
  if (Array.isArray(t)) {
    assert.ok(Array.isArray(d), `${at}: a list in the text where the answer has ${typeof d}`);
    let j = 0;
    for (const [i, x] of t.entries()) {
      while (j < d.length && !isCut(x, d[j])) j++;
      assert.ok(j < d.length, `${at}[${i}]: not one of the answer's entries, in the answer's order`);
      if (visit) assertCutOf(x, d[j], `${at}[${i}]`, visit);
      j++;
    }
    return;
  }
  if (isObj(t)) {
    assert.ok(isObj(d), `${at}: an object in the text where the answer has ${JSON.stringify(d)?.slice(0, 40)}`);
    for (const k of Object.keys(t)) {
      assert.ok(Object.hasOwn(d, k), `${at}.${k}: in the text, not in the answer`);
      assertCutOf(t[k], d[k], `${at}.${k}`, visit);
    }
    visit?.(t, d, at);
    return;
  }
  assert.deepEqual(t, d, at);
}
export function isCut(t, d) {
  try {
    assertCutOf(t, d);
    return true;
  } catch {
    return false;
  }
}

/**
 * Every object of the text paired with the object of the answer it is a cut of, with its path in
 * the text (`data.cves[3]`): a list's entries are paired in order, as assertCutOf matches them.
 */
export function cutPairs(t, d) {
  const out = [];
  assertCutOf(t, d, "data", (x, y, at) => out.push({ text: x, answer: y, at }));
  return out;
}
