#!/usr/bin/env node
// #2616: the operator check for what production's answers cost a client, against the record.
//
// The suite's per-tool bounds are measured on fixtures. Production's answers are not frozen: on
// 2026-09-30 exposure_radar's text on production's answers was 39,359 characters against the
// 30,949 its fixture bound asserted, and nothing measured it. This measures it: it reads
// production's answers for each production-wide tool (text-bound.mjs LIVE_TOOLS) through
// scripts/probe-prod.sh, which names itself as an operator so the read is never counted as
// adoption, replays them to this package's own server from a stub on 127.0.0.1 (so the package's
// User-Agent never reaches production either), and measures every text block the same way the
// suite does. It then compares each tool to the record (fixtures/text-bound-live.json).
//
//   node test/text-bound-live.mjs             measure and compare; exit 1 when a tool moved more
//                                             than MARGIN from its record, has no record, or is
//                                             past CEILING
//   node test/text-bound-live.mjs --record    measure, then write the record and keep the answers
//                                             (fixtures/prod-answers/), so the suite measures the
//                                             same answers on every run; commit both
//   --answers DIR                             read the answers from DIR (files named as
//                                             answerFile names them) instead of production
//
// Run from a checkout of the repository (scripts/probe-prod.sh), after `npm run build`. The
// output is one line per tool and a final JSON line; keep it with the release it was run for.
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { PKG, serverCommand } from "./server-under-test.mjs";
import { CEILING, LIVE_RECORD, LIVE_TOOLS, MARGIN, PROD_ANSWERS, answerFile, readLiveRecord, shareOfCeiling, textSize } from "./text-bound.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PROBE = path.resolve(HERE, "..", "..", "scripts", "probe-prod.sh");
const argv = process.argv.slice(2);
const record = argv.includes("--record");
const answersDir = argv.includes("--answers") ? argv[argv.indexOf("--answers") + 1] : undefined;

function readAnswer(apiPath) {
  if (answersDir) return JSON.parse(fs.readFileSync(path.join(answersDir, path.basename(answerFile(apiPath))), "utf8"));
  if (!fs.existsSync(PROBE)) throw new Error(`${PROBE} not found: run from a checkout of the repository, or pass --answers DIR`);
  const out = execFileSync(PROBE, ["--fail", apiPath], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  return JSON.parse(out);
}

const answers = {};
for (const paths of Object.values(LIVE_TOOLS)) for (const p of paths) answers[p] = readAnswer(p);
const readAt = new Date().toISOString();

const stub = http.createServer((req, res) => {
  const body = answers[req.url];
  res.writeHead(body ? 200 : 404, { "content-type": body ? "application/json" : "text/plain" });
  res.end(body ? JSON.stringify(body) : "404 page not found\n");
});
await new Promise((r) => stub.listen(0, "127.0.0.1", r));
const stubBase = `http://127.0.0.1:${stub.address().port}`;
const env = { ...process.env, ECHELONGRAPH_API_BASE: stubBase, ECHELONGRAPH_API_TIMEOUT_MS: "10000" };
const client = await connect({ era: MODERN, ...serverCommand(), env, stderr: "ignore" });

const prior = fs.existsSync(LIVE_RECORD) ? readLiveRecord() : { tools: {} };
const measured = {};
let red = false;
try {
  for (const tool of Object.keys(LIVE_TOOLS)) {
    const res = await client.callTool({ name: tool, arguments: {} });
    const { total, blocks } = textSize(res, stubBase);
    measured[tool] = { total, blocks, state: res.structuredContent?.state ?? null, isError: res.isError === true };
    const was = prior.tools?.[tool];
    let verdict;
    if (res.isError) {
      verdict = "FAILED: the tool answered an error, so this is not a measurement of its answer";
      red = true;
    } else if (!was) {
      verdict = "no record";
      red = red || !record;
    } else if (Math.abs(total - was.total) > MARGIN) {
      verdict = `MOVED ${total - was.total > 0 ? "+" : ""}${total - was.total} from the record of ${was.total} (${was.measured_at}), more than MARGIN ${MARGIN}`;
      red = red || !record;
    } else {
      verdict = `within ${MARGIN} of the record of ${was.total} (${was.measured_at})`;
    }
    if (total > CEILING) red = true;
    console.log(`${shareOfCeiling(tool, total)}; blocks ${blocks.join(" + ")}; ${verdict}`);
  }
} finally {
  await client.close();
  stub.close();
}

if (record) {
  fs.mkdirSync(PROD_ANSWERS, { recursive: true });
  for (const [p, body] of Object.entries(answers)) fs.writeFileSync(answerFile(p), `${JSON.stringify(body, null, 2)}\n`);
  const tools = {};
  for (const [tool, m] of Object.entries(measured)) {
    if (m.isError) continue;
    tools[tool] = { measured_at: readAt, package_version: PKG.version, total: m.total, blocks: m.blocks, answers_kept: true };
  }
  fs.writeFileSync(LIVE_RECORD, `${JSON.stringify({ ...prior, tools: { ...prior.tools, ...tools } }, null, 2)}\n`);
  console.log(`recorded ${Object.keys(tools).join(", ")} in ${LIVE_RECORD}, answers in ${PROD_ANSWERS}`);
}
console.log(JSON.stringify({ check: "text-bound-live", read_at: readAt, package_version: PKG.version, ceiling: CEILING, margin: MARGIN, measured, red }));
process.exit(red ? 1 : 0);
