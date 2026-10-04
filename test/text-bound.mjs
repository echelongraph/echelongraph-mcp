// What a tool's result costs in the channel a model reads, measured one way everywhere: the suite's
// per-case bounds (tools.test.mjs, #2467/#2531), the ceiling they sit under (#2617), and the
// operator check that measures production's answers (text-bound-live.mjs, #2616) all import this.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

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

/** Every text block of a result, with `stubBase` counted as production's, summed; and each block's size. */
export function textSize(res, stubBase) {
  const blocks = (res.content ?? []).filter((c) => c.type === "text").map((c) => (stubBase ? c.text.split(stubBase).join(PROD_BASE) : c.text));
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
