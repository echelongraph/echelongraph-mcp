#!/usr/bin/env node
// #2616, #2783: the operator check for what production's answers cost a client, against the record.
//
// The suite's per-tool bounds are measured on fixtures. Production's answers are not frozen: on
// 2026-09-30 exposure_radar's text on production's answers was 39,359 characters against the
// 30,949 its fixture bound asserted, and nothing measured it (#2616); on 2026-10-04 a default
// search_cves was 133,298 characters, past the 60,000 ceiling, while the suite printed 2% for it
// (#2783). This measures every case of text-bound.mjs SHAPED, each tool at its default call and at
// its largest page, on production's answers, with this package's own server (so the text measured
// is the text this checkout would send), and compares each with the ceiling and the record
// (fixtures/text-bound-live.json).
//
// Where production's answers come from:
//   (default)        scripts/probe-prod.sh, which names itself as an operator so the read is never
//                    counted as adoption: a proxy on 127.0.0.1 forwards each request this package's
//                    server makes, with its X-EG-* headers and its body, so the package's own
//                    User-Agent never reaches production either. Run from a checkout of the
//                    repository.
//   --hosted [URL]   the hosted MCP endpoint (default https://mcp.echelongraph.io/mcp), as
//                    echelongraph-mcp-synthetic/1.0, the synthetic's identity, never counted as
//                    adoption: each case's call is made there, and its structuredContent.data,
//                    which is the API's answer for every tool that relays it as sent, is replayed
//                    to this package. exposure_radar and cve_intel relay their own cut of their
//                    answers, so for them the endpoint's own text, the released version's, is
//                    reported instead, marked, and compared with nothing but the ceiling.
//   --answers DIR    exposure_radar's and cve_summary's answers from DIR (files named as
//                    answerFile names them); only those two are measured.
//
//   node test/text-bound-live.mjs [--hosted [URL]]   measure and compare; exit 1 when a case is
//                                                    past CEILING or answered an error, or when
//                                                    exposure_radar or cve_summary moved more than
//                                                    MARGIN from its record or has none
//   ... --record                                     then write the record: every case measured,
//                                                    and (not with --hosted) exposure_radar's and
//                                                    cve_summary's answers, kept in
//                                                    fixtures/prod-answers/ so the suite measures
//                                                    them on every run; commit both. It exits 1
//                                                    when exposure_radar's or cve_summary's
//                                                    SHAPED size in text-bound.mjs is then more
//                                                    than MARGIN from its record, naming the size
//                                                    to set (#2822): set it, run npm test, and
//                                                    commit text-bound.mjs with the record
//
// Only exposure_radar and cve_summary, production-wide answers to no input, are held to MARGIN
// from their record (#2616). Every other case's rows change as the feeds do (a search page, the
// newest KEV entries), so it is held to the ceiling, and its move from the record is printed, not
// judged here. The record is judged against the suite instead: text-bound.test.mjs fails when a
// SHAPED case's size is more than SHAPED_DRIFT from production's recorded text for the same call,
// so a fixture whose rows are cut at another level than production's (kev_recent's page of 200,
// once 20% under it) is re-sampled, not trusted. A case with `live` set is not measured here
// (SHAPED says why).
//
// Run after `npm run build`, or as `npm run text-bound:live` (`npm run text-bound:live -- --hosted`
// for the hosted source). The output is one line per case and a final JSON line; keep it with the
// release it was run for.
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { connectHttp } from "./mcp-http-client.mjs";
import { PKG, serverCommand } from "./server-under-test.mjs";
import { CEILING, KEPT_SOURCE, LIVE_RECORD, LIVE_TOOLS, MARGIN, PROD_ANSWERS, SHAPED, answerFile, argsOf, keptSizesOffRecord, readLiveRecord, setKeptSize, shareOfCeiling, textSize } from "./text-bound.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PROBE = path.resolve(HERE, "..", "..", "scripts", "probe-prod.sh");
const HOSTED = "https://mcp.echelongraph.io/mcp";
const SYNTHETIC_UA = "echelongraph-mcp-synthetic/1.0";
// The tools whose data is their own cut of the answer, not the answer: it cannot be replayed.
const RELAYS_A_CUT = new Set(["exposure_radar", "cve_intel"]);
const argv = process.argv.slice(2);
const record = argv.includes("--record");
const answersDir = argv.includes("--answers") ? argv[argv.indexOf("--answers") + 1] : undefined;
const hostedAt = argv.indexOf("--hosted");
const hosted = hostedAt < 0 ? undefined : argv[hostedAt + 1]?.startsWith("http") ? argv[hostedAt + 1] : HOSTED;
// #2822: the answers kept in fixtures/prod-answers are named as such, so a record re-measured from
// them says where they came from without a hand edit (KEPT_SOURCE, which text-bound.test.mjs knows).
const keptDir = answersDir !== undefined && path.resolve(answersDir) === path.resolve(PROD_ANSWERS);
const source = keptDir ? KEPT_SOURCE : answersDir ? `answers in ${answersDir}` : hosted ? `hosted ${hosted}, its data replayed to this checkout's server` : "probe-prod";
const run = promisify(execFile);

// One production request through probe-prod.sh: its status and body.
async function probe(method, url, headers, body) {
  if (!fs.existsSync(PROBE)) throw new Error(`${PROBE} not found: run from a checkout of the repository, or pass --hosted or --answers DIR`);
  const args = ["-w", "\n%{http_code}"];
  for (const [k, v] of Object.entries(headers)) args.push("-H", `${k}: ${v}`);
  if (method !== "GET") args.push("-X", method, "--data-binary", "@-");
  args.push(url);
  const p = run(PROBE, args, { encoding: "utf8", maxBuffer: 256 * 1024 * 1024 });
  if (body !== undefined) p.child.stdin.end(body);
  else p.child.stdin.end();
  const { stdout } = await p;
  const cut = stdout.lastIndexOf("\n");
  return { status: Number(stdout.slice(cut + 1)), body: stdout.slice(0, cut) };
}

// What the stub answers: a fixed map (request URL or path -> body), one body for every request
// (a replayed hosted answer), or production through probe-prod.sh.
let serve = { kind: "map", answers: {} };
const fetched = {};
const stub = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", async () => {
    const { pathname } = new URL(req.url, "http://stub");
    try {
      if (serve.kind === "probe") {
        const headers = Object.fromEntries(Object.entries(req.headers).filter(([k]) => k.startsWith("x-eg-") || k === "content-type"));
        const body = chunks.length ? Buffer.concat(chunks).toString("utf8") : undefined;
        const r = await probe(req.method, req.url, headers, body);
        if (r.status === 200) fetched[req.url] = r.body;
        res.writeHead(r.status, { "content-type": "application/json" });
        res.end(r.body);
        return;
      }
      const body = serve.kind === "one" ? serve.body : (serve.answers[req.url] ?? serve.answers[pathname]);
      res.writeHead(body ? 200 : 404, { "content-type": body ? "application/json" : "text/plain" });
      res.end(body ? JSON.stringify(body) : "404 page not found\n");
    } catch (e) {
      res.writeHead(502, { "content-type": "text/plain" });
      res.end(`probe failed: ${e?.message ?? e}`);
    }
  });
});
await new Promise((r) => stub.listen(0, "127.0.0.1", r));
const stubBase = `http://127.0.0.1:${stub.address().port}`;
const env = { ...process.env, ECHELONGRAPH_API_BASE: stubBase, ECHELONGRAPH_API_TIMEOUT_MS: "60000" };
const client = await connect({ era: MODERN, ...serverCommand(), env, stderr: "ignore" });
const remote = hosted ? await connectHttp({ era: MODERN, url: hosted, userAgent: SYNTHETIC_UA, requestTimeoutMs: 120_000 }) : undefined;
const readAt = new Date().toISOString();

const prior = fs.existsSync(LIVE_RECORD) ? readLiveRecord() : { tools: {} };
const cases = answersDir ? SHAPED.filter((c) => c.kept) : SHAPED;
const measured = {};
const keptBodies = {};
let red = false;
try {
  for (const c of cases) {
    if (c.live) {
      console.log(`${c.label}: not measured here: ${c.live}`);
      continue;
    }
    const args = argsOf(c);
    let res;
    let how = source;
    let stubbed = true;
    if (answersDir) {
      serve = { kind: "map", answers: Object.fromEntries(LIVE_TOOLS[c.kept].map((p) => [p, JSON.parse(fs.readFileSync(path.join(answersDir, path.basename(answerFile(p))), "utf8"))])) };
      Object.assign(keptBodies, serve.answers);
    } else if (hosted) {
      const there = await remote.callTool({ name: c.tool, arguments: args });
      if (RELAYS_A_CUT.has(c.tool) || there.isError) {
        res = there;
        stubbed = false;
        how = `the hosted endpoint's own text (${remote.getServerVersion()?.version ?? "its released version"}), not this checkout's`;
      } else {
        serve = { kind: "one", body: there.structuredContent.data };
      }
    } else {
      serve = { kind: "probe" };
    }
    if (!res) res = await client.callTool({ name: c.tool, arguments: args });
    const { total, blocks } = textSize(res, stubbed ? stubBase : undefined);
    const m = { total, blocks, state: res.structuredContent?.state ?? null, isError: res.isError === true, source: how };
    measured[c.label] = m;
    const drift = c.kept && stubbed ? prior.tools?.[c.kept] : undefined;
    const was = prior.cases?.[c.label];
    let verdict;
    if (m.isError) {
      verdict = "FAILED: the tool answered an error, so this is not a measurement of its answer";
      red = true;
    } else if (c.kept && stubbed && !drift) {
      verdict = "no record";
      red = red || !record;
    } else if (drift && Math.abs(total - drift.total) > MARGIN) {
      verdict = `MOVED ${total - drift.total > 0 ? "+" : ""}${total - drift.total} from the record of ${drift.total} (${drift.measured_at}), more than MARGIN ${MARGIN}`;
      red = red || !record;
    } else if (drift) {
      verdict = `within ${MARGIN} of the record of ${drift.total} (${drift.measured_at})`;
    } else {
      verdict = was ? `${total - was.total >= 0 ? "+" : ""}${total - was.total} from the record of ${was.total} (${was.measured_at}); held to the ceiling only` : "held to the ceiling only";
    }
    if (total > CEILING) {
      verdict += `; PAST THE CEILING of ${CEILING}`;
      red = true;
    }
    console.log(`${shareOfCeiling(c.label, total)}; blocks ${blocks.join(" + ")}; ${verdict}${how === source ? "" : `; ${how}`}`);
    if (c.kept && serve.kind === "probe") for (const p of LIVE_TOOLS[c.kept]) if (fetched[p] !== undefined) keptBodies[p] = JSON.parse(fetched[p]);
  }
} finally {
  await client.close();
  await remote?.close();
  stub.close();
}

if (record) {
  const tools = {};
  const keptAll = !hosted;
  if (keptAll) {
    fs.mkdirSync(PROD_ANSWERS, { recursive: true });
    for (const [p, body] of Object.entries(keptBodies)) fs.writeFileSync(answerFile(p), `${JSON.stringify(body, null, 2)}\n`);
  }
  const cs = {};
  for (const c of cases) {
    const m = measured[c.label];
    if (!m || m.isError) continue;
    cs[c.label] = { measured_at: readAt, package_version: PKG.version, total: m.total, blocks: m.blocks, source: m.source };
    // #2822: when the answers were read from production. Read here (probe-prod) it is now; the
    // answers already kept keep the time they were read; answers from another directory carry no
    // time, so it is null rather than now.
    const answersReadAt = !answersDir ? readAt : keptDir ? (prior.tools?.[c.kept]?.answers_read_at ?? null) : null;
    if (c.kept && keptAll) tools[c.kept] = { measured_at: readAt, answers_read_at: answersReadAt, package_version: PKG.version, total: m.total, blocks: m.blocks, answers_kept: true };
  }
  const written = { ...prior, tools: { ...prior.tools, ...tools }, cases: { ...(prior.cases ?? {}), ...cs } };
  fs.writeFileSync(LIVE_RECORD, `${JSON.stringify(written, null, 2)}\n`);
  console.log(`recorded ${Object.keys(cs).length} cases${Object.keys(tools).length ? ` and ${Object.keys(tools).join(", ")}, answers in ${PROD_ANSWERS}` : ""} in ${LIVE_RECORD}`);
  // #2822: the suite measures the kept answers on every run and holds them within MARGIN of
  // SHAPED's size for the case, so a record that moved past it leaves `npm test`, and the release
  // that runs it, red until that size is set. Say which, and fail, so the re-record is not committed alone.
  const off = keptSizesOffRecord(written);
  for (const o of off) console.log(`SHAPED SIZE STALE: ${setKeptSize(o)}`);
  if (off.length) red = true;
}
console.log(JSON.stringify({ check: "text-bound-live", read_at: readAt, package_version: PKG.version, source, ceiling: CEILING, margin: MARGIN, measured, red }));
process.exit(red ? 1 : 0);
