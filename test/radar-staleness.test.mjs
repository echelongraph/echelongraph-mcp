// #3010: exposure_radar's staleness thresholds, held to the cadences core-backend runs its radars
// at, and the note's both polarities on a clock the test owns.
//
// During the #2975 scanning pause exposure_radar flagged only the two radars whose answer carries a
// liveness verdict and ended every answer "Each radar refreshes on its own schedule.", while
// exposed_databases and leaked_credentials had not completed a check for 77 h and 68 h. index.ts
// STALE_AFTER now gives each radar a threshold past which the note says its numbers may be stale,
// keyed to the cadence core-backend runs it at. That cadence is core-backend's number and the
// threshold is a second copy of it, so this file reads the Go source and holds the invariant:
// every radar's threshold is at least twice the cadence core-backend runs it at, and a cycle the
// note names is that cadence. A Go constant this guard can no longer read FAILS it: a guard that
// cannot find its number and passes anyway is how this kind of check dies.
//
// Where the cadence lives (core-backend/cmd/server/main.go builds every poller, and an interval of
// 0 takes the package's defaultInterval):
//   kev_exposure        kevexposure.NewPoller(..., 0)   internal/kevexposure/poller.go defaultInterval
//   exposed_databases   exposeddb.NewPoller(..., 0)     internal/exposeddb/poller.go defaultInterval
//   leaked_credentials  leakedcreds.NewPoller(..., 0)   internal/leakedcreds/poller.go defaultInterval
//   shadow_ai           shadowctlog.NewPoller(..., 60*time.Second, ...), and the API's running window,
//                       internal/shadowctlog/poller.go pollerSilentAfter
//   mcp_servers         aiexposure.NewPoller(..., 15*time.Minute, ...), and the API's enabled window,
//                       internal/aiexposure/handler.go liveWindow
//
// The Go half runs in the monorepo (this package's directory is mcp-server, or a core-backend sits
// beside it); there a missing file fails. The npm tarball's test run and the public repository
// carry mcp-server alone, and there it is skipped and says why. The other half calls the tool's
// own formatter, radarAnswer (dist/index.js, loaded as the hosted entrypoint loads it, so that no
// stdio server starts in this process), on production's kept answers (fixtures/prod-answers/) with
// the clock set by the test: each radar exactly at its threshold, one second past it, and, from
// the parsed cadence, one second under twice it.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { PKG_DIR } from "./server-under-test.mjs";
import { LIVE_TOOLS, keptAnswers } from "./text-bound.mjs";

const dist = (f) => pathToFileURL(path.join(PKG_DIR, "dist", f)).href;
(await import(dist("runtime.js"))).markHttpEntrypoint();
const I = await import(dist("index.js"));

const SECOND = 1000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

// What the package must export for any of this to be checked; named, so a build without it fails
// here and says what is missing rather than on an undefined further down.
function exported() {
  assert.ok(I.STALE_AFTER && typeof I.STALE_AFTER === "object", "dist/index.js exports no STALE_AFTER: exposure_radar has no per-radar staleness threshold (#3010)");
  assert.ok(Array.isArray(I.RADAR_NAMES) && I.RADAR_NAMES.length > 0, "dist/index.js exports no RADAR_NAMES");
  assert.equal(typeof I.radarAnswer, "function", "dist/index.js exports no radarAnswer: exposure_radar's formatter cannot be called with a set clock");
  return { STALE_AFTER: I.STALE_AFTER, RADAR_NAMES: I.RADAR_NAMES, radarAnswer: I.radarAnswer };
}

// ── The Go source ──

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = path.resolve(HERE, "..");
const CORE = path.resolve(PKG_ROOT, "..", "core-backend");
const IN_MONOREPO = path.basename(PKG_ROOT) === "mcp-server" || fs.existsSync(CORE);
const OUTSIDE = "no core-backend beside this package (the npm tarball or the public repository): the Go cadences cannot be read here";

// Each radar's poller package. A radar with none here fails the guard: a sixth radar needs its
// cadence named before its threshold can be held to it.
const PACKAGE = { kev_exposure: "kevexposure", exposed_databases: "exposeddb", leaked_credentials: "leakedcreds", shadow_ai: "shadowctlog", mcp_servers: "aiexposure" };
// The API's own verdict window, for the two radars whose answer carries one.
const WINDOW = { shadow_ai: ["internal/shadowctlog/poller.go", "pollerSilentAfter"], mcp_servers: ["internal/aiexposure/handler.go", "liveWindow"] };

function readGo(rel) {
  const f = path.join(CORE, rel);
  assert.ok(fs.existsSync(f), `core-backend/${rel} is gone: find where that radar's cadence lives now and re-aim this guard (never skip it)`);
  return fs.readFileSync(f, "utf8");
}

const UNIT = { Hour: HOUR, Minute: MINUTE, Second: SECOND };
// A Go duration written as N * time.Hour|Minute|Second (or time.Hour alone). Anything else throws:
// a cadence written another way is re-read by hand, never passed over.
function goDuration(expr, where) {
  const e = expr.trim();
  let m = e.match(/^(\d+)\s*\*\s*time\.(Hour|Minute|Second)$/);
  if (m) return Number(m[1]) * UNIT[m[2]];
  m = e.match(/^time\.(Hour|Minute|Second)$/);
  if (m) return UNIT[m[1]];
  throw new Error(`${where}: cannot read ${JSON.stringify(e)} as a duration (this guard reads N * time.Hour, time.Minute or time.Second): re-aim it`);
}

// The one declaration of `name` as a duration in `src`: a line of a const block, or `const name = ...`.
function goConst(src, name, where) {
  const re = new RegExp(`^[ \\t]*(?:const[ \\t]+)?${name}[ \\t]*(?:time\\.Duration[ \\t]*)?=[ \\t]*([^\\n]+?)[ \\t]*(?://[^\\n]*)?$`, "gm");
  const found = [...src.matchAll(re)];
  if (found.length !== 1) throw new Error(`${where}: expected one declaration of ${name}, found ${found.length}: re-aim this guard`);
  return goDuration(found[0][1], `${where} ${name}`);
}

// The arguments of the one call `${pkg}.NewPoller(` in main.go, split at its top-level commas.
function callArgs(src, callee, where) {
  const calls = [...src.matchAll(new RegExp(`\\b${callee.replace(".", "\\.")}\\(`, "g"))];
  if (calls.length !== 1) throw new Error(`${where}: expected one call of ${callee}, found ${calls.length}: re-aim this guard`);
  const args = [];
  let depth = 1;
  let start = calls[0].index + calls[0][0].length;
  for (let i = start; i < src.length; i++) {
    const c = src[i];
    if (c === "(") depth++;
    else if (c === ")" && --depth === 0) {
      args.push(src.slice(start, i).trim());
      return args;
    } else if (c === "," && depth === 1) {
      args.push(src.slice(start, i).trim());
      start = i + 1;
    }
  }
  throw new Error(`${where}: the call of ${callee} is not closed`);
}

// The cadence core-backend runs a radar's poller at: the interval main.go passes its NewPoller, or
// the package's defaultInterval when that is 0.
function cadenceOf(pkg) {
  const where = `core-backend/internal/${pkg}/poller.go`;
  const poller = readGo(`internal/${pkg}/poller.go`);
  const sig = poller.match(/^func NewPoller\(([^)]*)\)/m);
  if (!sig) throw new Error(`${where}: no func NewPoller(...): re-aim this guard`);
  const params = sig[1].split(",").map((p) => p.trim());
  if (!params.every((p) => /^\w+\s+\S+$/.test(p))) throw new Error(`${where}: NewPoller's parameters are not one name and one type each (${sig[1]}): re-aim this guard`);
  const at = params.flatMap((p, i) => (/\stime\.Duration$/.test(p) ? [i] : []));
  if (at.length !== 1) throw new Error(`${where}: NewPoller takes ${at.length} time.Duration parameters, not one: re-aim this guard`);
  const args = callArgs(readGo("cmd/server/main.go"), `${pkg}.NewPoller`, "core-backend/cmd/server/main.go");
  if (args.length !== params.length) throw new Error(`core-backend/cmd/server/main.go: ${pkg}.NewPoller is called with ${args.length} arguments, and takes ${params.length}`);
  const arg = args[at[0]];
  const passed = arg === "0" ? 0 : goDuration(arg, `core-backend/cmd/server/main.go ${pkg}.NewPoller interval`);
  if (passed > 0) return { ms: passed, from: `main.go passes ${arg}` };
  if (!/if interval <= 0 \{\s*interval = defaultInterval\s*\}/.test(poller)) throw new Error(`${where}: NewPoller no longer takes defaultInterval for an interval of 0: re-aim this guard`);
  return { ms: goConst(poller, "defaultInterval", where), from: `${pkg} defaultInterval (main.go passes 0)` };
}

// The thresholds under twice their radar's cadence, the radars with no threshold, and the cycles
// named that are not the cadence: the invariant, one function, so its control runs what the guard runs.
function violations(staleAfter, radars, cadence) {
  const out = [];
  for (const r of radars) {
    const s = staleAfter[r];
    if (!s || !(typeof s.after === "number" && s.after > 0)) {
      out.push(`${r}: no threshold in STALE_AFTER`);
      continue;
    }
    if (!(r in cadence)) {
      out.push(`${r}: no cadence read for it (name its poller package in this guard)`);
      continue;
    }
    if (s.after < 2 * cadence[r]) out.push(`${r}: threshold ${s.after / MINUTE} min is under twice the ${cadence[r] / MINUTE} min core-backend runs it at`);
    if (s.cycle !== undefined && s.cycle !== cadence[r]) out.push(`${r}: the note names a ${s.cycle / MINUTE} min cycle, and core-backend runs it every ${cadence[r] / MINUTE} min`);
  }
  for (const r of Object.keys(staleAfter)) if (!radars.includes(r)) out.push(`${r}: a threshold for a radar exposure_radar does not read`);
  return out;
}

describe("#3010: every radar's staleness threshold is at least twice the cadence core-backend runs it at", () => {
  const cadence = {};
  const read = {};
  const goHalf = (name, fn) => it(name, (t) => (IN_MONOREPO ? fn(t) : t.skip(OUTSIDE)));

  goHalf("reads each radar's cadence from the Go source: 12 h, 12 h and 10 min from defaultInterval, 60 s and 15 min from main.go", (t) => {
    const { RADAR_NAMES } = exported();
    for (const r of RADAR_NAMES) {
      assert.ok(PACKAGE[r], `${r} is a radar exposure_radar reads, and this guard names no poller package for it: add it to PACKAGE`);
      read[r] = cadenceOf(PACKAGE[r]);
      cadence[r] = read[r].ms;
      t.diagnostic(`${r}: ${cadence[r] / MINUTE} min (${read[r].from})`);
    }
    // The parse itself, proved on today's values: a guard that read the wrong line would pass anything.
    assert.deepEqual(
      { kev_exposure: cadence.kev_exposure, exposed_databases: cadence.exposed_databases, leaked_credentials: cadence.leaked_credentials },
      { kev_exposure: 12 * HOUR, exposed_databases: 12 * HOUR, leaked_credentials: 10 * MINUTE },
    );
    for (const r of ["kev_exposure", "exposed_databases", "leaked_credentials"]) assert.match(read[r].from, /defaultInterval \(main\.go passes 0\)$/, r);
    assert.deepEqual({ shadow_ai: cadence.shadow_ai, mcp_servers: cadence.mcp_servers }, { shadow_ai: 60 * SECOND, mcp_servers: 15 * MINUTE });
  });
  goHalf("STALE_AFTER covers exactly the radars exposure_radar reads; every threshold is at least twice its cadence and every cycle named is it", () => {
    const { STALE_AFTER, RADAR_NAMES } = exported();
    assert.deepEqual(Object.keys(cadence).sort(), [...RADAR_NAMES].sort(), "the cadences were not all read (the test above failed)");
    assert.deepEqual(Object.keys(STALE_AFTER).sort(), [...RADAR_NAMES].sort());
    assert.deepEqual(violations(STALE_AFTER, RADAR_NAMES, cadence), []);
  });
  goHalf("shadow_ai's and mcp_servers' thresholds are the API's own verdict windows (pollerSilentAfter 30 min, liveWindow 45 min)", () => {
    const { STALE_AFTER } = exported();
    for (const [r, [file, name]] of Object.entries(WINDOW)) {
      const ms = goConst(readGo(file), name, `core-backend/${file}`);
      assert.equal(STALE_AFTER[r].after, ms, `${r}: its threshold is not the API's ${name}, so the note's fallback would disagree with the API's own verdict`);
    }
    assert.deepEqual([STALE_AFTER.shadow_ai.after, STALE_AFTER.mcp_servers.after], [30 * MINUTE, 45 * MINUTE]);
  });
  goHalf("the formatter itself does not call a radar stale one second under twice its parsed cadence", () => {
    const { RADAR_NAMES } = exported();
    assert.deepEqual(Object.keys(cadence).sort(), [...RADAR_NAMES].sort(), "the cadences were not all read (the first test failed)");
    for (const r of RADAR_NAMES) {
      assert.equal(staleOf(noteAt(r, 2 * cadence[r] - SECOND)), "", `${r} at ${(2 * cadence[r] - SECOND) / SECOND} s`);
    }
  });

  // The guard can fail. Each control feeds it what drift would look like and expects it to refuse.
  it("control: a threshold under twice its cadence, a missing entry, a wrong cycle and an extra entry are each refused", () => {
    const cad = { kev_exposure: 12 * HOUR, exposed_databases: 12 * HOUR, leaked_credentials: 10 * MINUTE, shadow_ai: MINUTE, mcp_servers: 15 * MINUTE };
    const ok = { kev_exposure: { after: 24 * HOUR, cycle: 12 * HOUR }, exposed_databases: { after: 24 * HOUR, cycle: 12 * HOUR }, leaked_credentials: { after: HOUR, cycle: 10 * MINUTE }, shadow_ai: { after: 30 * MINUTE }, mcp_servers: { after: 45 * MINUTE } };
    const radars = Object.keys(cad);
    assert.deepEqual(violations(ok, radars, cad), []);
    // core-backend moves leaked_credentials to a 45-minute cycle and nothing here follows.
    assert.match(violations(ok, radars, { ...cad, leaked_credentials: 45 * MINUTE }).join(" | "), /leaked_credentials: threshold 60 min is under twice the 45 min/);
    assert.match(violations(ok, radars, { ...cad, kev_exposure: 6 * HOUR }).join(" | "), /kev_exposure: the note names a 720 min cycle, and core-backend runs it every 360 min/);
    const { exposed_databases: _gone, ...missing } = ok;
    assert.match(violations(missing, radars, cad).join(" | "), /exposed_databases: no threshold in STALE_AFTER/);
    assert.match(violations(ok, [...radars, "sixth_radar"], cad).join(" | "), /sixth_radar: no threshold/);
    assert.match(violations({ ...ok, sixth_radar: { after: HOUR } }, radars, cad).join(" | "), /sixth_radar: a threshold for a radar exposure_radar does not read/);
  });
  it("control: a cadence the guard cannot read fails it, never passes it", () => {
    assert.equal(goDuration("12 * time.Hour", "x"), 12 * HOUR);
    assert.equal(goDuration("60*time.Second", "x"), MINUTE);
    for (const bad of ["12*time.Hour + 30*time.Minute", "envDuration(\"KEV_INTERVAL\", 12*time.Hour)", "12 * hour", "", "time.Millisecond"]) {
      assert.throws(() => goDuration(bad, "control"), /cannot read/, bad);
    }
    const src = "const (\n\tdefaultInterval  = 12 * time.Hour      // comment (with parens)\n\tother = 3 * time.Minute\n)\n";
    assert.equal(goConst(src, "defaultInterval", "control"), 12 * HOUR);
    assert.throws(() => goConst(src, "pollerSilentAfter", "control"), /expected one declaration of pollerSilentAfter, found 0/);
    assert.throws(() => goConst(`${src}const defaultInterval = 6 * time.Hour\n`, "defaultInterval", "control"), /expected one declaration of defaultInterval, found 2/);
    assert.throws(() => goConst("const defaultInterval = cfg.Interval()\n", "defaultInterval", "control"), /cannot read/);
    assert.deepEqual(callArgs("x := kevexposure.NewPoller(s, cve.NewStore(db), 0)\n", "kevexposure.NewPoller", "control"), ["s", "cve.NewStore(db)", "0"]);
    assert.throws(() => callArgs("a := exposeddb.NewPoller(s, g, 0)\nb := exposeddb.NewPoller(s, g, 0)\n", "exposeddb.NewPoller", "control"), /found 2/);
    assert.throws(() => callArgs("nothing here\n", "leakedcreds.NewPoller", "control"), /found 0/);
  });
});

// ── The note, on a clock the test owns ──

const NOW = Date.parse("2026-10-11T07:18:00Z"); // the ticket's re-measure, 2026-10-11 07:18Z
const iso = (t) => new Date(t).toISOString();
const PATH = Object.fromEntries(LIVE_TOOLS.exposure_radar.map((p) => [p.includes("kev-exposure") ? "kev_exposure" : p.includes("exposed-databases") ? "exposed_databases" : p.includes("leaked-credentials") ? "leaked_credentials" : p.includes("shadow-ai") ? "shadow_ai" : "mcp_servers", p]));
const KEPT = keptAnswers("exposure_radar");

// Production's kept answers with every radar fresh at `now` (a check a minute ago, and the API's
// verdicts running), then `set` applied radar by radar.
function answers(now, set = {}) {
  assert.ok(KEPT, "fixtures/prod-answers/ lacks one of exposure_radar's kept answers");
  const minuteAgo = iso(now - MINUTE);
  const d = {
    kev_exposure: { ...KEPT[PATH.kev_exposure], last_run_at: minuteAgo },
    exposed_databases: { ...KEPT[PATH.exposed_databases], last_run_at: minuteAgo },
    leaked_credentials: { ...KEPT[PATH.leaked_credentials], last_run_at: minuteAgo },
    shadow_ai: { ...KEPT[PATH.shadow_ai], poller: { running: true, last_run_at: minuteAgo } },
    mcp_servers: { ...KEPT[PATH.mcp_servers], enabled: true, last_run_at: minuteAgo },
  };
  for (const [r, f] of Object.entries(set)) d[r] = f(d[r]);
  return d;
}
// Radar r's last completed check set `ago` before now, the way its threshold reads it: a stats
// radar's last_run_at, and for shadow_ai and mcp_servers a stamp with no verdict (with a verdict,
// the verdict decides, and the time is not read).
const agedBy = (r, now, ago) => {
  const t = iso(now - ago);
  if (r === "shadow_ai") return (b) => ({ ...b, poller: { last_run_at: t } });
  if (r === "mcp_servers") return ({ enabled: _e, ...b }) => ({ ...b, last_run_at: t });
  return (b) => ({ ...b, last_run_at: t });
};
const answerFor = (data, now = NOW) => exported().radarAnswer(data, now);
const noteOf = (res) => res.content[1].text;
const lastOf = (n) => I.sentences(n).at(-1);
const staleOf = (n) => I.sentences(n).filter((s) => /may be stale/.test(s)).join(" | ");
function noteAt(r, ago) {
  return noteOf(answerFor(answers(NOW, { [r]: agedBy(r, NOW, ago) })));
}
const NONE_STALE =
  "Each radar has its own cycle, and neither freshness nor anything else in this answer shows a radar past its threshold for calling its numbers stale (24 hours for kev_exposure and exposed_databases, 1 hour for leaked_credentials; for shadow_ai and mcp_servers, the API's own poller.running and enabled verdicts, or 30 minutes and 45 minutes where the answer gives none).";
const oneStale = (r) => `Each radar has its own cycle, and 1 of the 5 radars may be stale: ${r}.`;

describe("#3010: exposure_radar's note at, past and under each radar's threshold (radarAnswer, on production's kept answers)", () => {
  it("every radar fresh: no sentence says may be stale, and the last names each threshold", () => {
    const n = noteOf(answerFor(answers(NOW)));
    assert.equal(staleOf(n), "");
    assert.equal(lastOf(n), NONE_STALE);
  });
  for (const r of ["kev_exposure", "exposed_databases", "leaked_credentials", "shadow_ai", "mcp_servers"]) {
    it(`${r}: exactly at its threshold it is not stale; one second past it, it is, and is the one radar named`, () => {
      const { STALE_AFTER } = exported();
      const after = STALE_AFTER[r].after;
      const at = noteAt(r, after);
      assert.equal(staleOf(at), "");
      assert.equal(lastOf(at), NONE_STALE);
      const past = noteAt(r, after + SECOND);
      assert.equal(lastOf(past), oneStale(r));
      // A month old, too: an entry wired to the note, not only present in the table.
      assert.equal(lastOf(noteAt(r, 30 * DAY)), oneStale(r));
    });
  }
  it("the ticket's day: exposed_databases 77 h and leaked_credentials 68 h are each said to be stale, by age and cycle; kev_exposure at 2 h is not", () => {
    const now = NOW;
    const res = answerFor(
      answers(now, {
        kev_exposure: (b) => ({ ...b, last_run_at: "2026-10-11T04:58:08Z" }),
        exposed_databases: (b) => ({ ...b, last_run_at: "2026-10-08T02:17:23Z" }),
        leaked_credentials: (b) => ({ ...b, last_run_at: "2026-10-08T11:12:09Z" }),
        shadow_ai: (b) => ({ ...b, poller: { running: false, last_run_at: "2026-10-08T11:16:10.995501Z" } }),
        mcp_servers: (b) => ({ ...b, enabled: false, last_run_at: "2026-10-08T11:20:51Z" }),
      }),
      now,
    );
    const said = I.sentences(noteOf(res));
    assert.ok(said.includes("exposed_databases.last_run_at is about 77 hours before this answer, more than twice the radar's 12-hour cycle, so the exposed_databases numbers may be stale."), staleOf(noteOf(res)));
    assert.ok(said.includes("leaked_credentials.last_run_at is about 68 hours before this answer, more than 6 times the radar's 10-minute cycle, so the leaked_credentials numbers may be stale."), staleOf(noteOf(res)));
    assert.equal(said.filter((s) => s.startsWith("kev_exposure.last_run_at is about")).length, 0);
    // shadow_ai's and mcp_servers' sentences are 2.7.1's, verbatim.
    assert.ok(said.includes("Shadow-AI radar freshness: no Certificate Transparency (crt.sh) discovery cycle has completed since 2026-10-08T11:16:10.995501Z, when the radar's leader last completed one (poller.running is false: that was more than 30 minutes before the API's answer), so the shadow-AI figures may be stale."));
    assert.ok(said.includes("mcp_servers.enabled is false: the API does not report the AI-exposure radar running (no check completed within 45 minutes of its answer), so these numbers may be stale."));
    assert.equal(said.at(-1), "Each radar has its own cycle, and 4 of the 5 radars may be stale: exposed_databases, leaked_credentials, shadow_ai and mcp_servers.");
    // The structured freshness block is the API's stamps and verdicts, as before.
    assert.deepEqual(res.structuredContent.freshness, {
      kev_exposure: { last_run_at: "2026-10-11T04:58:08Z" },
      exposed_databases: { last_run_at: "2026-10-08T02:17:23Z" },
      leaked_credentials: { last_run_at: "2026-10-08T11:12:09Z" },
      shadow_ai: { last_run_at: "2026-10-08T11:16:10.995501Z", running: false },
      mcp_servers: { last_run_at: "2026-10-08T11:20:51Z", enabled: false },
    });
  });
  it("shadow_ai and mcp_servers: their verdict decides in both states, whatever their stamp's age; their sentences are 2.7.1's", () => {
    const old = iso(NOW - 30 * DAY);
    const running = I.sentences(noteOf(answerFor(answers(NOW, { shadow_ai: (b) => ({ ...b, poller: { running: true, last_run_at: old } }), mcp_servers: (b) => ({ ...b, enabled: true, last_run_at: old }) }))));
    assert.ok(running.includes(`Shadow-AI radar freshness: the radar's leader last completed a Certificate Transparency (crt.sh) discovery cycle at ${old} (poller.running is true: that was within 30 minutes of the API's answer).`));
    assert.ok(running.includes("mcp_servers.enabled is true: the API reports the AI-exposure radar running, a check having completed within 45 minutes of its answer."));
    assert.equal(running.filter((s) => /may be stale/.test(s)).length, 0, running.join(" | "));
    assert.equal(running.at(-1), NONE_STALE);
    const recent = iso(NOW - MINUTE);
    const stopped = I.sentences(noteOf(answerFor(answers(NOW, { shadow_ai: (b) => ({ ...b, poller: { running: false, last_run_at: recent } }), mcp_servers: (b) => ({ ...b, enabled: false, last_run_at: recent }) }))));
    assert.ok(stopped.includes(`Shadow-AI radar freshness: no Certificate Transparency (crt.sh) discovery cycle has completed since ${recent}, when the radar's leader last completed one (poller.running is false: that was more than 30 minutes before the API's answer), so the shadow-AI figures may be stale.`));
    assert.ok(stopped.includes("mcp_servers.enabled is false: the API does not report the AI-exposure radar running (no check completed within 45 minutes of its answer), so these numbers may be stale."));
    assert.equal(stopped.at(-1), "Each radar has its own cycle, and 2 of the 5 radars may be stale: shadow_ai and mcp_servers.");
  });
  it("no answer says the radars refresh on their own schedule, stale or not", () => {
    for (const data of [answers(NOW), answers(NOW, { exposed_databases: agedBy("exposed_databases", NOW, 3 * DAY) }), answers(NOW, { leaked_credentials: agedBy("leaked_credentials", NOW, 2 * HOUR) })]) {
      const res = answerFor(data);
      const all = res.content.map((c) => c.text).join("\n") + JSON.stringify(res.structuredContent);
      assert.ok(!/refreshes on its own|refresh on their own/.test(all), `an answer says the radars refresh on their own: ${all.match(/[^.]*refresh(?:es)? on (?:its|their) own[^.]*\./)?.[0]}`);
    }
  });
});
