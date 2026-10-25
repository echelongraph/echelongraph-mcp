#!/usr/bin/env node
// The production MCP synthetic (#2724).
//
// Every 15 minutes (Cloud Scheduler → the Cloud Run job echelon-mcp-synthetic) this installs
// the PUBLISHED echelongraph-mcp from npm into a temporary directory, starts it over stdio the
// way `npx echelongraph-mcp` does, and on each protocol era (a 2026-07-28 server/discover, a
// 2025-06-18 initialize) lists the tools and calls every one once with a known-good input from
// probes.mjs. Each result is judged the way an MCP client judges it:
//
//   success       structuredContent validates against the tool's own advertised outputSchema
//                 (ajv, as the SDK ships it: the validator tools.test.mjs uses), isError is not
//                 set, and state is measured or not_assessed. not_assessed is a success here:
//                 the tool answered honestly that it could not assess; it is never read as
//                 "clean", and it is not an outage. A tool probes.mjs EXPECTs more of must also
//                 show it (check_sbom: two batches answered, #2757), else reason expectation_unmet.
//   failure       anything else: a JSON-RPC error, a timeout, isError, state failed or
//                 invalid_input, no structuredContent, a structuredContent the schema refuses,
//                 or no input the synthetic can send. `reason` says which.
//   not_published a tool probes.mjs names that this version does not list (a planned tool, or one
//                 whose probes.mjs SHIPPED_IN release is past the version the server reports).
//   failure, reason not_listed (#3282): a tool, prompt or resource the server does not list
//                 although the version it reports is at or past the one probes.mjs SHIPPED_IN
//                 gives it (shipped_in on the line): a rolled-back or mis-registered endpoint.
//
// OUTPUT: one JSON line per tool per era on stdout, and one for the cve:// resource (#2781,
// below), message "mcp tool probe", which Cloud Run stores as jsonPayload; the log-based metric
// mcp_tool_probe_total{tool,era,outcome,transport} counts them, mcp_tool_probe_latency_ms reads
// latency_ms, and mcp_tool_probe_text_chars and mcp_tool_probe_structured_chars read text_chars and
// structured_chars (#2781, below)
// (infrastructure/monitoring/create-mcp-synthetic-monitoring.sh). Then one "mcp synthetic run complete" line, the
// liveness signal. Every line has the one severity of its message, INFO: the outcome is a
// field, never the severity, so a re-levelled line cannot silence a metric.
//
// The session itself can fail (install, spawn, handshake, tools/list): that is a probe line
// with tool "(install)" or "(session)" and outcome failure, so the same alert sees it.
//
// WHAT AN ANSWER COSTS A CLIENT (#2781). Every probe line whose call was answered (a tool, a
// verdict, a chain probe, a prompt or a resource) carries text_chars: the characters of every text block it
// returned (a resource's contents, a prompt's messages), what lands in a client's context. That
// includes cve://CVE-2021-44228, read on BOTH legs once per era after the leg's other probes, tool
// "resource:cve" (probes.mjs CVE_RESOURCE_PROBE): get_cve's record as a resource, cut by the
// resource's own construction since #2801 and, until this line, measured nowhere in production.
// It is listed when resources/templates/list names cve://{cve_id}; an empty or error read is a
// failure (resource_*, rpc_error, or expectation_unmet when the text is not the record). And it
// includes the own call of every test/text-bound.mjs SHAPED case production can make (#2781's
// review; a case with `live` set is past the API's per-minute budget, or a forced cut no answer
// reaches): the hosted leg makes each one no other probe makes (a default or largest page, a
// heavier lookup) once per run, in its first era, tools "size:…" (probes.mjs SIZE_PROBES), so the
// answers that cost a client most are measured where they are served, not only when an operator
// runs `npm run text-bound:live`. A
// tools/call line carries structured_chars too: its structuredContent as compact JSON, what Claude
// Code hands the model, null when the answer has none. Both are measured as test/text-bound.mjs
// measures them (textSize's total, structuredSize; run.test.mjs holds the two equal), so the series
// is the same number the suite bounds: under #2617's trip-wire of 45,000 characters of text and
// #3013's budget of 30,000 of structuredContent. create-mcp-synthetic-monitoring.sh reads them
// (mcp_tool_probe_text_chars, mcp_tool_probe_structured_chars) and alerts past either. Sizes only:
// a count of characters, never a character of the answer. On the stdio leg the package talks to
// the forwarder, whose base is as long as the API base it stands for (forwarder.mjs), and that
// base is counted as the API's, so the size is the one a client of that API receives.
//
// THE CLIENT CUT (#2842). Once per era and transport, after tools/list, one more line, message
// "mcp text cut": what a client that cuts MCP text at 2,048 characters (Claude Code from v2.1.280;
// the package's src/requiredText.ts cites where) hands the model of that session's server instructions and tool
// descriptions. instructions_chars is the opening exchange's instructions length (initialize, or
// server/discover on the modern era); description_heads_ok says whether every sentence the
// package's REQUIRED_IN_HEAD names for a tool sits in that tool's first 2,048 characters, and no
// head names Shodan without its ownership sentence; instructions_head_ok the same of
// REQUIRED_IN_INSTRUCTIONS in the instructions. The sentences are the package's own: its
// dist/requiredText.js, beside the server the stdio leg runs, so a release is held to what it
// ships. The hosted leg is judged by them only when the endpoint reports the same version (else
// description_heads_ok is null, basis version_mismatch); a package without the file (before
// #2842) gives null, basis no_required_text. instructions_chars is measured either way. outcome is
// failure when instructions_chars is past the cut or either head check is false;
// create-mcp-synthetic-monitoring.sh alerts on those fields.
//
// THE HOSTED LEG (#2737). With MCP_SYNTHETIC_REMOTE_URL set (deploy.sh sets
// https://mcp.echelongraph.io/mcp; unset, there is no hosted leg), the same run then speaks
// Streamable HTTP to that endpoint (test/mcp-http-client.mjs's HttpMcpClient, the wire the
// endpoint's own tests use) on both eras: lists the tools, calls every one with the same probe
// table, judged the same way against the outputSchema the ENDPOINT advertises, then a tools/call per
// probes.mjs VERDICT_PROBES entry not in EXPECT_PENDING (#3135: the matcher answers that tell #3074's
// fixed_in walk and the #3101/#3131 comparators from the rules before them, tools "verdict:…"; a
// label held back in EXPECT_PENDING is not called, and none is), then a tools/call per probes.mjs
// CHAIN_PROBES entry (#3011: get_vendor_advisory given a vendor_advisories_for_cve row's
// advisory_id, the chaining mistake, which must answer the advisory or invalid_input naming
// vendor_advisory_id, never failed; not_published until the endpoint advertises that fix), then a
// prompts/get
// per probes.mjs PROMPT_PROBES entry (triage_cve with a CVE; workload_triage with source
// kubernetes, #2846) and one resources/read (echelongraph://methodology), tools "prompt:triage_cve",
// "prompt:workload_triage" and "resource:methodology", then, in the run's first era only, a
// tools/call per probes.mjs SIZE_PROBES entry (#2781's review: the SHAPED cases' own calls, tools
// "size:…", none past 64 KiB), then the cve:// read both legs make ("resource:cve", #2781).
// check_sbom is sent its 201 purls as
// a CycloneDX document, a request body twice the endpoint's 64 KiB general cap, and must answer
// measured from the document (probes.mjs HTTP_PROBES and HTTP_EXPECT, #2774): the large-body path
// #2747 opened is probed every run, and a return of its 413 fails the probe (rpc_error, rpc_code
// -32600) instead of leaving every probe green. Every line carries `transport`,
// "stdio" or "http", the metric's fourth label, so a hosted outage is its own series and its own
// alert; package_version on an http line is the version the endpoint reports in its handshake.
// The hosted leg runs even when the npm install failed: they are independent products.
//
// HOSTED VERSUS NPM (#3097). The hosted endpoint reports a version in its handshake, and #2741's
// gate holds the image deploy-all.sh builds to that release; a hand deploy, the gate's override or a
// rollback to a pre-gate revision does not, and on 2026-10-11 hosted and npm both said 2.7.1 and
// served different cve_intel descriptions. So when both legs ran and the endpoint reports the
// version the npm leg runs, each era's catalog of the two is compared: every tool object as
// tools/list gives it (name, title, description, inputSchema, outputSchema, annotations, every
// field), every prompt and resource as prompts/list and resources/list give them, every resource
// template as resources/templates/list gives it (keyed by uriTemplate: cve://{cve_id} is listed
// only there, never in resources/list), and the instructions. One more probe line per era on the
// http leg, tool "(hosted-vs-npm)": success when they are the same; failure, reason
// hosted_differs_from_npm, when not, with differences (the
// count) and detail (the first few, e.g. "tool cve_intel: description differs at character 221"),
// so "MCP tool failed 2 synthetic runs in a row" opens on a divergence that lasts two runs. A list
// one side could not read is named in uncompared and is not a difference (its own probe line
// says why). #3097's review: when the endpoint reports another version than the npm leg runs (a
// rollback to an older release, a deploy reporting another number), it is compared with npm's own
// package of the version it reports, echelongraph-mcp@<that version>, installed once per run as the
// npm leg's is and listed over stdio for each era (no tool is called); the line says
// compared_with "hosted_version" ("npm_leg" otherwise). npm not serving that version is a failure,
// reason hosted_version_not_on_npm (a build no release has); an install that fails otherwise is
// hosted_version_install_failed, never read as the same. Without both legs, or a version unknown,
// nothing is compared and no line is written. The run-complete line's hosted_vs_npm says which:
// identical, differs, hosted_version_not_on_npm, hosted_version_install_failed, version_unknown or
// not_compared, and hosted_vs_npm_at the npm version compared.
// An answer that is not JSON-RPC (a platform 5xx, a 403 from the Origin policy, a 404) is reason
// http_status with the status in http_status.
//
// Its IDENTITY: every request to the endpoint carries User-Agent echelongraph-mcp-synthetic/1.0,
// and the endpoint (src/http.ts, runtime.ts upstreamUserAgent) leads its own API calls with that
// token for such a request, so core-backend files them under echelongraph-mcp-synthetic, never as
// hosted adoption (mcp_forwarded=true, ua_family echelongraph-mcp).
//
// IDENTITY: the package is run with ECHELONGRAPH_MCP_UA=echelongraph-mcp-synthetic/1.0 and,
// unless --direct, behind forwarder.mjs, which puts that token ahead of the user-agent of a
// version that predates the variable. Either way core-backend files the requests under the
// family echelongraph-mcp-synthetic (class ours), never under echelongraph-mcp adoption.
//
// No value is logged that a person typed: the inputs are this file's own public constants, and
// a line names the candidate it sent by index.
//
// Exit status: 0 when every probe line is success or not_published (never not_listed, a failure)
// and no client-cut line is a
// failure, 2 when any is, 1 when the runner itself broke. The metric, not the exit status, is
// what alerts.
//
// Configuration (flags for a local run, environment for the job):
//   --package  / MCP_SYNTHETIC_PACKAGE   npm spec to install (echelongraph-mcp@latest), or a pin
//   --bin      / MCP_SYNTHETIC_BIN       run this server .js instead of installing (tests)
//   --api-base / MCP_SYNTHETIC_API_BASE  the API the package is pointed at (https://app.echelongraph.io)
//   --direct   / MCP_SYNTHETIC_DIRECT=1  no forwarder: the package talks to the API itself
//   --force-tool / MCP_SYNTHETIC_FORCE_TOOLS  comma list: call these even if not listed. The
//                                          deliberate-failure test of the alert uses a name no
//                                          version lists.
//   --eras     / MCP_SYNTHETIC_ERAS      comma list (2026-07-28,2025-06-18)
//   --timeout-ms / MCP_SYNTHETIC_CALL_TIMEOUT_MS  per request (90000)
//   --remote-url / MCP_SYNTHETIC_REMOTE_URL  the hosted endpoint for the http leg (unset: no
//                                          http leg). https, or http on a loopback host (tests).
//   --no-stdio / MCP_SYNTHETIC_STDIO=0     skip the npm stdio leg (a hosted-only local check)
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs, promisify } from "node:util";
import { AjvJsonSchemaValidator } from "@modelcontextprotocol/server/validators/ajv";
import { connect, MODERN, RpcError } from "../test/mcp-stdio-client.mjs";
import { connectHttp, HttpStatusError } from "../test/mcp-http-client.mjs";
import { AFTER, CHAIN_PROBES, CVE_RESOURCE_PROBE, EXPECT, EXPECT_PENDING, HTTP_EXPECT, HTTP_PROBES, PROBES, PROMPT_PROBES, RESOURCE_PROBE, SHIPPED_IN, SIZE_PROBES, VERDICT_PROBES } from "./probes.mjs";
import { startForwarder } from "./forwarder.mjs";

export const LEGACY = "2025-06-18";
export const STDIO = "stdio";
export const HTTP = "http";
export const DEFAULT_ERAS = [MODERN, LEGACY];
export const UA_TOKEN = "echelongraph-mcp-synthetic/1.0";
export const PROBE_MESSAGE = "mcp tool probe";
export const COMPLETE_MESSAGE = "mcp synthetic run complete";
export const TEXT_CUT_MESSAGE = "mcp text cut";
// #3097: the probe line of the hosted-versus-npm comparison, one per era on the http leg.
export const DRIFT_TOOL = "(hosted-vs-npm)";
// The cut when the package under test ships no requiredText.js: Claude Code's default, the value
// src/requiredText.ts CLIENT_DESCRIPTION_CUT holds.
export const DEFAULT_CLIENT_CUT = 2048;
export const DEFAULT_PACKAGE = "echelongraph-mcp@latest";
export const DEFAULT_API_BASE = "https://app.echelongraph.io";
const SUCCESS_STATES = new Set(["measured", "not_assessed"]);
const FAILURE_STATES = new Set(["failed", "invalid_input"]);
// A metric label must stay bounded: a forced name is a tool-name shape, nothing else.
const TOOL_NAME = /^[a-z][a-z0-9_]{0,63}$/;
const PACKAGE_SPEC = /^echelongraph-mcp@[0-9A-Za-z.^~*-]{1,40}$/;

const validator = new AjvJsonSchemaValidator();
const validates = (schema, value) => {
  try {
    return validator.getValidator(schema)(value);
  } catch (e) {
    return { valid: false, errorMessage: `the schema did not compile: ${e?.message ?? e}` };
  }
};

// Install the published package into a fresh directory, as `npx` would: production
// dependencies only, no lifecycle scripts, a private npm cache.
export async function installPackage(spec, dir) {
  if (!PACKAGE_SPEC.test(spec)) throw new Error(`refusing package spec ${JSON.stringify(spec)}: not echelongraph-mcp@<version or tag>`);
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "echelongraph-mcp-synthetic-install", private: true }));
  try {
    await promisify(execFile)(
      "npm",
      ["install", "--omit=dev", "--ignore-scripts", "--no-audit", "--no-fund", "--no-package-lock", "--loglevel=error", spec],
      { cwd: dir, env: { ...process.env, npm_config_cache: path.join(dir, ".npm-cache"), npm_config_update_notifier: "false" }, timeout: 180_000 },
    );
  } catch (e) {
    // npm's own reason (its "npm error code …" and the line after), not the command line.
    const said = String(e?.stderr ?? "").split("\n").filter((l) => /^npm (error|ERR!)/.test(l)).slice(0, 3).join(" | ");
    throw new Error(said || (e?.killed ? "npm install timed out" : String(e?.message ?? e).split("\n")[0]));
  }
  const pkgDir = path.join(dir, "node_modules", "echelongraph-mcp");
  const pkg = JSON.parse(fs.readFileSync(path.join(pkgDir, "package.json"), "utf8"));
  const bin = typeof pkg.bin === "string" ? pkg.bin : pkg.bin?.["echelongraph-mcp"];
  if (typeof bin !== "string") throw new Error("the installed package declares no echelongraph-mcp bin");
  return { serverJs: path.join(pkgDir, bin), version: pkg.version };
}

// The probe order for one era: what the package lists, in its order, then every tool
// probes.mjs names that it does not list, then forced names; a tool that reads another's
// answer (AFTER) after that one.
export function probeOrder(listed, forced = []) {
  const names = [...new Set([...listed, ...Object.keys(PROBES), ...forced])];
  const first = names.filter((n) => !AFTER[n]);
  return [...first, ...names.filter((n) => AFTER[n])];
}

// The input a probe sends: the first candidate that validates against the tool's inputSchema.
// Returns { args, index } or { reason } when there is none. `table` is the leg's probe table.
export function chooseInput(name, tool, seen, table = PROBES) {
  const candidates = table[name];
  const schema = tool?.inputSchema;
  const fits = (args) => !schema || validates(schema, args).valid;
  if (!candidates) {
    // A listed tool nobody wrote an entry for: {} if it needs no argument.
    return fits({}) ? { args: {}, index: -1 } : { reason: "no_probe_input" };
  }
  for (const [index, c] of candidates.entries()) {
    const args = typeof c === "function" ? c(seen) : c;
    if (args && typeof args === "object" && fits(args)) return { args, index };
  }
  return { reason: "no_valid_probe_input" };
}

// How a tools/call answer is judged. `tool` is the tools/list entry, or undefined for a forced
// name the package does not list. `expect` is the tool's EXPECT entry (probes.mjs), if any: a
// success it does not hold for is a failure, reason expectation_unmet, with what it saw as detail.
export function judge(res, tool, expect) {
  const sc = res?.structuredContent;
  const state = sc && typeof sc === "object" ? sc.state : undefined;
  if (res?.isError === true) return { outcome: "failure", reason: FAILURE_STATES.has(state) ? `state_${state}` : "is_error", state };
  if (!tool) return { outcome: "failure", reason: "not_listed", state };
  if (!tool.outputSchema || typeof tool.outputSchema !== "object") return { outcome: "failure", reason: "no_output_schema", state };
  if (!sc || typeof sc !== "object") return { outcome: "failure", reason: "no_structured_content" };
  const v = validates(tool.outputSchema, sc);
  if (!v.valid) return { outcome: "failure", reason: "schema_invalid", state, detail: String(v.errorMessage ?? "").slice(0, 300) };
  if (FAILURE_STATES.has(state)) return { outcome: "failure", reason: `state_${state}_without_is_error`, state };
  if (!SUCCESS_STATES.has(state)) return { outcome: "failure", reason: "unknown_state", state };
  const unmet = expect?.(sc);
  if (unmet !== undefined) return { outcome: "failure", reason: "expectation_unmet", state, detail: String(unmet).slice(0, 300) };
  return { outcome: "success", state };
}

// How a CHAIN_PROBES call is judged (#3011): an invalid_input answer is the specified refusal when it
// is a failure result (isError) that fits the tool's outputSchema and the probe's `refusal` holds of
// it; any other answer is judged as a tools/call is, with the probe's `expect` of the arguments sent.
export function judgeChain(res, tool, probe, args) {
  const sc = res?.structuredContent;
  if (res?.isError === true && sc && typeof sc === "object" && sc.state === "invalid_input") {
    if (!tool?.outputSchema || typeof tool.outputSchema !== "object") return { outcome: "failure", reason: "no_output_schema", state: sc.state };
    const v = validates(tool.outputSchema, sc);
    if (!v.valid) return { outcome: "failure", reason: "schema_invalid", state: sc.state, detail: String(v.errorMessage ?? "").slice(0, 300) };
    const unmet = probe.refusal(sc);
    return unmet === undefined ? { outcome: "success", state: sc.state } : { outcome: "failure", reason: "expectation_unmet", state: sc.state, detail: String(unmet).slice(0, 300) };
  }
  return judge(res, tool, (x) => probe.expect(x, args));
}

// How a prompts/get answer is judged (#2737): at least one message, every one a user or
// assistant message with a content block, a text block that is not blank, and a text block naming
// `expect`, the probe's own text (probes.mjs PROMPT_PROBES: the CVE triage_cve was sent, the tool
// workload_triage must route to, #2846). An answer without it is reason `unmet`, the probe's own.
// An empty `expect` is refused, never matched: "".includes("") would pass any text.
export function judgePrompt(res, expect, unmet = "prompt_argument_not_applied") {
  if (typeof expect !== "string" || expect === "") return { outcome: "failure", reason: "prompt_probe_without_expect" };
  const msgs = res?.messages;
  if (!Array.isArray(msgs) || msgs.length === 0) return { outcome: "failure", reason: "prompt_no_messages" };
  for (const m of msgs) {
    if (!m || !["user", "assistant"].includes(m.role) || !m.content || typeof m.content !== "object" || typeof m.content.type !== "string") {
      return { outcome: "failure", reason: "prompt_invalid_message" };
    }
  }
  const texts = msgs.filter((m) => m.content.type === "text" && typeof m.content.text === "string").map((m) => m.content.text);
  if (!texts.some((t) => t.trim() !== "")) return { outcome: "failure", reason: "prompt_empty" };
  if (texts.some((t) => t.includes(expect))) return { outcome: "success" };
  return { outcome: "failure", reason: unmet, detail: `no text block names ${JSON.stringify(expect)}` };
}

// How a resources/read answer is judged (#2737): an entry for the URI that was read, with a
// non-empty text. `expect`, where the probe has one (#2781: probes.mjs CVE_RESOURCE_PROBE, whose
// text must be the record), is a function of that text: a success it does not hold for is a
// failure, reason expectation_unmet, with what it saw as detail, as judge() reads EXPECT.
export function judgeResource(res, uri, expect) {
  const contents = res?.contents;
  if (!Array.isArray(contents) || contents.length === 0) return { outcome: "failure", reason: "resource_no_contents" };
  const hit = contents.find((c) => c && c.uri === uri);
  if (!hit) return { outcome: "failure", reason: "resource_uri_missing" };
  if (typeof hit.text !== "string" || hit.text.trim() === "") return { outcome: "failure", reason: "resource_empty" };
  const unmet = expect?.(hit.text);
  if (unmet !== undefined) return { outcome: "failure", reason: "expectation_unmet", detail: String(unmet).slice(0, 300) };
  return { outcome: "success" };
}

// #2842: the package's own registry of what must sit inside the client cut (src/requiredText.ts),
// from the dist beside the server .js the stdio leg runs. It is read in a child node with only
// PATH, as the server itself is run, never imported into the runner: it is the published package's
// code. undefined when the package ships none (a release before #2842), or it does not load or
// does not have the registry's shape: then nothing is judged against it.
const READ_REQUIRED = `const m = await import(process.argv[1]);
process.stdout.write(JSON.stringify({ CLIENT_DESCRIPTION_CUT: m.CLIENT_DESCRIPTION_CUT, SHODAN_OWNERSHIP: m.SHODAN_OWNERSHIP, REQUIRED_IN_INSTRUCTIONS: m.REQUIRED_IN_INSTRUCTIONS, REQUIRED_IN_HEAD: m.REQUIRED_IN_HEAD }));`;
const strings = (a) => Array.isArray(a) && a.every((s) => typeof s === "string");
export async function loadRequiredText(serverJs) {
  const file = path.join(path.dirname(serverJs), "requiredText.js");
  if (!fs.existsSync(file)) return undefined;
  try {
    const { stdout } = await promisify(execFile)(process.execPath, ["--input-type=module", "-e", READ_REQUIRED, pathToFileURL(file).href], {
      env: { PATH: process.env.PATH ?? "" },
      timeout: 15_000,
      maxBuffer: 1 << 20,
    });
    const m = JSON.parse(stdout);
    const heads = m?.REQUIRED_IN_HEAD;
    if (Number.isInteger(m?.CLIENT_DESCRIPTION_CUT) && m.CLIENT_DESCRIPTION_CUT > 0 && typeof m.SHODAN_OWNERSHIP === "string" && strings(m.REQUIRED_IN_INSTRUCTIONS) && heads && typeof heads === "object" && Object.values(heads).every(strings)) return m;
  } catch {
    // it does not load: not judged
  }
  return undefined;
}

// #2842: what a client that cuts at the cut hands the model of one session, from its opening
// exchange's instructions and its tools/list. `required` (loadRequiredText) supplies the sentences;
// without it only the lengths are measured and the two head checks are null. Each missing sentence
// is named in detail (a fixed string of the package's, never an input).
export function judgeTextCut({ instructions, tools }, required) {
  const cut = required?.CLIENT_DESCRIPTION_CUT ?? DEFAULT_CLIENT_CUT;
  const list = Array.isArray(tools) ? tools : [];
  const descs = list.map((t) => (typeof t?.description === "string" ? t.description : ""));
  const out = {
    cut,
    instructions_chars: typeof instructions === "string" ? instructions.length : null,
    tools_listed: list.length,
    description_max_chars: descs.reduce((m, d) => Math.max(m, d.length), 0),
    descriptions_over_cut: descs.filter((d) => d.length > cut).length,
    instructions_head_ok: null,
    description_heads_ok: null,
    description_heads_missing: null,
    tools_without_required_entry: null,
  };
  if (required) {
    const own = required.SHODAN_OWNERSHIP;
    const ownershipMissing = (head) => /Shodan/.test(head) && !head.includes(own);
    const lacks = [];
    if (typeof instructions !== "string") lacks.push("instructions: none served");
    else {
      const head = instructions.slice(0, cut);
      for (const s of required.REQUIRED_IN_INSTRUCTIONS ?? []) if (!head.includes(s)) lacks.push(`instructions: ${s}`);
      if (ownershipMissing(head)) lacks.push("instructions: names Shodan without its ownership sentence");
    }
    const missing = [];
    let without = 0;
    list.forEach((t, i) => {
      const head = descs[i].slice(0, cut);
      const want = required.REQUIRED_IN_HEAD[t?.name];
      if (!Array.isArray(want)) without++;
      for (const s of want ?? []) if (!head.includes(s)) missing.push(`${t.name}: ${s}`);
      if (ownershipMissing(head)) missing.push(`${t?.name}: names Shodan without its ownership sentence`);
    });
    Object.assign(out, {
      instructions_head_ok: lacks.length === 0,
      description_heads_ok: missing.length === 0,
      description_heads_missing: missing.length,
      tools_without_required_entry: without,
    });
    if (lacks.length || missing.length) out.detail = [...lacks, ...missing].join(" | ").slice(0, 300);
  }
  const past = (out.instructions_chars ?? 0) > cut || out.instructions_head_ok === false || out.description_heads_ok === false;
  return { outcome: past ? "failure" : "success", ...out };
}

// #2781: what an answer costs a client, as test/text-bound.mjs measures it (the header says why).
// `localBase` is the base the package was pointed at, counted as `asBase`, the API's. A prompt's
// or a resource's answer has no structuredContent, so its line carries text_chars alone.
export function sizesOf(res, { localBase, asBase } = {}) {
  const count = (s) => (localBase && asBase && localBase !== asBase ? s.split(localBase).join(asBase) : s).length;
  if (Array.isArray(res?.contents)) return { text_chars: res.contents.filter((c) => typeof c?.text === "string").reduce((n, c) => n + count(c.text), 0) };
  if (Array.isArray(res?.messages)) return { text_chars: res.messages.filter((m) => m?.content?.type === "text" && typeof m.content.text === "string").reduce((n, m) => n + count(m.content.text), 0) };
  const text = (Array.isArray(res?.content) ? res.content : []).filter((c) => c?.type === "text" && typeof c.text === "string");
  return {
    text_chars: text.reduce((n, c) => n + count(c.text), 0),
    structured_chars: res?.structuredContent === undefined ? null : count(JSON.stringify(res.structuredContent)),
  };
}

// #3097: what differs between two catalogs of one era, the npm package's and the hosted
// endpoint's: { differences: [string], compared: { tools, prompts, resources, resourceTemplates },
// uncompared: [string] }. A catalog is { instructions, tools, prompts, resources,
// resourceTemplates }; prompts, resources and resourceTemplates are a list, or { error } when that
// side could not read it. Objects are compared whole, keys in any order. A resource template
// (resources/templates/list, keyed by uriTemplate) is compared as a resource is: cve://{cve_id} is
// served only through that list, so without it a template changed or dropped would read the same.
const canon = (v) => (Array.isArray(v) ? v.map(canon) : v && typeof v === "object" ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, canon(v[k])])) : v);
const same = (a, b) => JSON.stringify(canon(a)) === JSON.stringify(canon(b));
const firstDiff = (a, b) => {
  let i = 0;
  while (i < a.length && i < b.length && a[i] === b[i]) i++;
  return i;
};
function diffField(what, field, a, b) {
  if (typeof a === "string" && typeof b === "string") return `${what}: ${field} differs at character ${firstDiff(a, b) + 1} (npm ${a.length} characters, hosted ${b.length})`;
  if (a === undefined) return `${what}: ${field} only on the hosted endpoint`;
  if (b === undefined) return `${what}: ${field} only on npm`;
  return `${what}: ${field} differs`;
}
function diffItems(kind, key, npm, hosted, out) {
  const a = new Map(npm.map((x) => [x?.[key], x]));
  const b = new Map(hosted.map((x) => [x?.[key], x]));
  for (const k of [...new Set([...a.keys(), ...b.keys()])].sort()) {
    const what = `${kind} ${k}`;
    if (!b.has(k)) out.push(`${what}: only on npm`);
    else if (!a.has(k)) out.push(`${what}: only on the hosted endpoint`);
    else {
      const x = a.get(k), y = b.get(k);
      for (const f of [...new Set([...Object.keys(x ?? {}), ...Object.keys(y ?? {})])].sort()) if (!same(x?.[f], y?.[f])) out.push(diffField(what, f, x?.[f], y?.[f]));
    }
  }
  return a.size;
}
export function compareCatalogs(npm, hosted) {
  const differences = [];
  const uncompared = [];
  const compared = { tools: diffItems("tool", "name", npm.tools ?? [], hosted.tools ?? [], differences), prompts: 0, resources: 0, resourceTemplates: 0 };
  for (const [kind, list, key, method] of [
    ["prompt", "prompts", "name", "prompts/list"],
    ["resource", "resources", "uri", "resources/list"],
    ["resource template", "resourceTemplates", "uriTemplate", "resources/templates/list"],
  ]) {
    const a = npm[list], b = hosted[list];
    if (Array.isArray(a) && Array.isArray(b)) compared[list] = diffItems(kind, key, a, b, differences);
    else if (!Array.isArray(a) && !Array.isArray(b) && same(a, b)) compared[list] = 0;
    else uncompared.push(`${method} (${Array.isArray(a) ? "npm read it" : `npm: ${a?.error ?? "unread"}`}, ${Array.isArray(b) ? "hosted read it" : `hosted: ${b?.error ?? "unread"}`})`);
  }
  if (!same(npm.instructions, hosted.instructions)) differences.unshift(diffField("the server", "instructions", npm.instructions, hosted.instructions));
  return { differences, compared, uncompared };
}

function errorReason(e) {
  if (e instanceof RpcError) return { reason: "rpc_error", rpc_code: e.code };
  if (e instanceof HttpStatusError) return { reason: "http_status", http_status: e.status };
  const msg = String(e?.message ?? e);
  if (/no answer within/.test(msg)) return { reason: "timeout" };
  if (/exited/.test(msg)) return { reason: "server_exited" };
  return { reason: "error" };
}

const CLIENT_INFO = { name: "echelongraph-mcp-synthetic", version: "1.0.0" };

// #3097: a session's catalog: the instructions, the tools as listed, and prompts/list,
// resources/list and resources/templates/list ({ error } where one could not be read).
async function catalogOf(client, tools, promptsOnce, resourcesOnce, templatesOnce) {
  const settle = async (once, key) => {
    try {
      return (await once())[key] ?? [];
    } catch (e) {
      const r = errorReason(e);
      return { error: [r.reason, r.rpc_code ?? r.http_status].filter((x) => x !== undefined).join(" ") };
    }
  };
  return {
    instructions: client.opening?.instructions,
    tools,
    prompts: await settle(promptsOnce, "prompts"),
    resources: await settle(resourcesOnce, "resources"),
    resourceTemplates: await settle(templatesOnce, "resourceTemplates"),
  };
}

// #3097's review: one era's catalog of the npm package at `serverJs`, listed over stdio, no tool
// called. Throws when the session or tools/list fails.
export async function readCatalog({ era, serverJs, env, timeoutMs }) {
  const client = await connect({ era, command: process.execPath, args: [serverJs], env, stderr: "ignore", clientInfo: CLIENT_INFO, requestTimeoutMs: timeoutMs });
  try {
    const { tools } = await client.listTools();
    return await catalogOf(client, tools, () => client.listPrompts(), () => client.listResources(), () => client.listResourceTemplates());
  } finally {
    await client.close().catch(() => {});
  }
}

// Probe one era of the npm package over stdio: one line per tool, then one for the cve:// resource
// (#2781). `measure` sizes an answer (sizesOf, with the forwarder's base counted as the API's).
export function probeEra({ era, serverJs, env, force, timeoutMs, emit, onServerInfo = () => {}, onListed = () => {}, onCatalog, measure = sizesOf }) {
  const open = () =>
    connect({ era, command: process.execPath, args: [serverJs], env, stderr: "ignore", clientInfo: CLIENT_INFO, requestTimeoutMs: timeoutMs });
  return probeSession({ era, open, force, emit, onServerInfo, onListed, onCatalog, measure });
}

// Probe one era of the hosted endpoint over Streamable HTTP (#2737): one line per tool, then one
// per prompt probe, one for the methodology resource, with `sizes` one per SIZE_PROBES entry
// (#2781's review: runSynthetic sets it for the run's first era only), and one for the cve://
// resource (#2781). Its own inputs and expectations where probes.mjs has them (#2774: check_sbom is
// sent a document past the endpoint's 64 KiB general body cap).
export function probeHttpEra({ era, url, force, timeoutMs, emit, onServerInfo = () => {}, onListed = () => {}, onCatalog, sizes = false }) {
  const open = () => connectHttp({ era, url, userAgent: UA_TOKEN, clientInfo: CLIENT_INFO, requestTimeoutMs: timeoutMs });
  return probeSession({ era, open, force, emit, onServerInfo, onListed, onCatalog, extras: true, probes: { ...PROBES, ...HTTP_PROBES }, expect: { ...EXPECT, ...HTTP_EXPECT }, sizes: sizes ? SIZE_PROBES : [] });
}

// #3282: a version as its release triple, or undefined where it is not one ("unknown", "1.2", a
// tag): such a version gates nothing. A pre-release sorts below its release (2.7.0-rc.1 < 2.7.0).
function releaseOf(v) {
  const m = /^v?(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$/.exec(String(v ?? "").trim());
  return m ? { nums: [Number(m[1]), Number(m[2]), Number(m[3])], pre: Boolean(m[4]) } : undefined;
}
export function versionAtLeast(version, floor) {
  const a = releaseOf(version);
  const b = releaseOf(floor);
  if (!a || !b) return false;
  for (let i = 0; i < 3; i++) if (a.nums[i] !== b.nums[i]) return a.nums[i] > b.nums[i];
  return !a.pre || b.pre;
}
// #3282: the line for a probe the server does not list: a failure, reason not_listed, where the
// version it reports is at or past the release SHIPPED_IN gives the probe (it should list it),
// else not_published. `key` is the probe's SHIPPED_IN key; `shipped` the table (probes.mjs's, or a
// test's).
export function unlisted(key, served, shipped = SHIPPED_IN) {
  const since = shipped[key];
  return since && versionAtLeast(served, since) ? { outcome: "failure", reason: "not_listed", shipped_in: since } : { outcome: "not_published" };
}

// One prompt or resource probe: listed? then called, sized and judged.
async function probeExtra({ era, emit, label, list, listed, call, judgeIt, served, shipped, measure }) {
  let items;
  try {
    items = await list();
  } catch (e) {
    emit({ tool: label, era, outcome: "failure", step: "list", ...errorReason(e) });
    return;
  }
  if (!items.some(listed)) {
    emit({ tool: label, era, ...unlisted(label, served, shipped) });
    return;
  }
  const t0 = performance.now();
  let res;
  try {
    res = await call();
  } catch (e) {
    emit({ tool: label, era, outcome: "failure", latency_ms: Math.round(performance.now() - t0), ...errorReason(e) });
    return;
  }
  emit({ tool: label, era, latency_ms: Math.round(performance.now() - t0), ...measure(res), ...judgeIt(res) });
}

// Probe one era of one session, however it is opened: one line per tool (and, with extras, one
// per VERDICT_PROBES entry not in EXPECT_PENDING (#3135: a pending one is not called and writes no
// line), one per CHAIN_PROBES entry (#3011, not_published where the endpoint does not advertise its
// fix), one per PROMPT_PROBES entry and one for the methodology resource), then one per `sizes`
// entry (#2781's review: probes.mjs SIZE_PROBES, a SHAPED case's own call each, on the leg and era
// that pass them), then, on every leg, one for the cve:// resource (#2781, CVE_RESOURCE_PROBE), with
// the leg's probe table and expectations.
// onListed gets the opening exchange's instructions and the tools/list answer (#2842). onCatalog,
// when given, gets the session's catalog once its probes are done (#3097): the instructions, the
// tools as listed, and prompts/list, resources/list and resources/templates/list (each read once
// per session, the first two shared with the prompt and resource probes; { error } when it could
// not be read). `measure` sizes each
// answer for its line (#2781, sizesOf).
export async function probeSession({ era, open, force, emit, onServerInfo = () => {}, onListed = () => {}, onCatalog, extras = false, probes = PROBES, expect = EXPECT, shipped = SHIPPED_IN, measure = sizesOf, sizes = [] }) {
  let client;
  try {
    client = await open();
  } catch (e) {
    emit({ tool: "(session)", era, outcome: "failure", step: "open", ...errorReason(e) });
    return;
  }
  const serverInfo = client.getServerVersion();
  onServerInfo(serverInfo);
  // #3282: the version the server reports, which a probe it does not list is held to.
  const served = serverInfo?.version;
  try {
    let tools;
    try {
      ({ tools } = await client.listTools());
    } catch (e) {
      emit({ tool: "(session)", era, outcome: "failure", step: "tools/list", ...errorReason(e) });
      return;
    }
    onListed({ instructions: client.opening?.instructions, tools });
    let promptsP, resourcesP, templatesP;
    const promptsOnce = () => (promptsP ??= client.listPrompts());
    const resourcesOnce = () => (resourcesP ??= client.listResources());
    const templatesOnce = () => (templatesP ??= client.listResourceTemplates());
    const byName = new Map(tools.map((t) => [t.name, t]));
    const seen = {};
    for (const name of probeOrder(tools.map((t) => t.name), force)) {
      const tool = byName.get(name);
      const forced = force.includes(name);
      if (!tool && !forced) {
        emit({ tool: name, era, ...unlisted(name, served, shipped) });
        continue;
      }
      const choice = tool ? chooseInput(name, tool, seen, probes) : { args: {}, index: -1 };
      if (!choice.args) {
        emit({ tool: name, era, outcome: "failure", reason: choice.reason });
        continue;
      }
      const t0 = performance.now();
      let res;
      try {
        res = await client.callTool({ name, arguments: choice.args });
      } catch (e) {
        emit({ tool: name, era, outcome: "failure", latency_ms: Math.round(performance.now() - t0), input: choice.index, ...errorReason(e) });
        continue;
      }
      const latency = Math.round(performance.now() - t0);
      const verdict = judge(res, tool, expect[name]);
      if (verdict.outcome === "success") seen[name] = res.structuredContent;
      emit({ tool: name, era, latency_ms: latency, input: choice.index, ...measure(res), ...verdict });
    }
    if (extras) {
      // #3135: the matcher's verdicts, each one call of a listed tool under its own label, judged as
      // the tool's own probe is and then by its expect. Its arguments are checked against the tool's
      // inputSchema before they are sent, as chooseInput checks a candidate. A label in EXPECT_PENDING
      // is not called and writes no line: its fix is not deployed yet, and a line would page.
      for (const v of VERDICT_PROBES) {
        if (EXPECT_PENDING[v.label]) continue;
        const tool = byName.get(v.tool);
        if (!tool) {
          emit({ tool: v.label, era, ...unlisted(v.tool, served, shipped) });
          continue;
        }
        const choice = chooseInput(v.tool, tool, seen, { [v.tool]: [v.arguments] });
        if (!choice.args) {
          emit({ tool: v.label, era, outcome: "failure", reason: choice.reason });
          continue;
        }
        const t0 = performance.now();
        let res;
        try {
          res = await client.callTool({ name: v.tool, arguments: choice.args });
        } catch (e) {
          emit({ tool: v.label, era, outcome: "failure", latency_ms: Math.round(performance.now() - t0), ...errorReason(e) });
          continue;
        }
        emit({ tool: v.label, era, latency_ms: Math.round(performance.now() - t0), ...measure(res), ...judge(res, tool, v.expect) });
      }
      // #3011: the chaining mistake, judged only where the endpoint advertises its fix (`published`).
      for (const c of CHAIN_PROBES) {
        const tool = byName.get(c.tool);
        // #3282: its tool unlisted is held to that tool's release; listed without the fix, the
        // probe is not_published until the endpoint advertises it.
        if (!tool) {
          emit({ tool: c.label, era, ...unlisted(c.tool, served, shipped) });
          continue;
        }
        if (!c.published(tool)) {
          emit({ tool: c.label, era, outcome: "not_published" });
          continue;
        }
        const choice = chooseInput(c.tool, tool, seen, { [c.tool]: [c.arguments] });
        if (!choice.args) {
          emit({ tool: c.label, era, outcome: "failure", reason: choice.reason });
          continue;
        }
        const t0 = performance.now();
        let res;
        try {
          res = await client.callTool({ name: c.tool, arguments: choice.args });
        } catch (e) {
          emit({ tool: c.label, era, outcome: "failure", latency_ms: Math.round(performance.now() - t0), ...errorReason(e) });
          continue;
        }
        emit({ tool: c.label, era, latency_ms: Math.round(performance.now() - t0), ...measure(res), ...judgeChain(res, tool, c, choice.args) });
      }
      // One prompts/list per era, read by every prompt probe: a list that fails is a failure line
      // for each prompt's label, as one that answers is read for each.
      const listPrompts = async () => (await promptsOnce()).prompts;
      for (const probe of PROMPT_PROBES) {
        await probeExtra({
          era,
          emit,
          label: probe.label,
          list: listPrompts,
          listed: (p) => p?.name === probe.name,
          call: () => client.getPrompt({ name: probe.name, arguments: probe.arguments }),
          judgeIt: (res) => judgePrompt(res, probe.expect, probe.unmet),
          served,
          shipped,
          measure,
        });
      }
      await probeExtra({
        era,
        emit,
        label: RESOURCE_PROBE.label,
        list: async () => (await resourcesOnce()).resources,
        listed: (r) => r?.uri === RESOURCE_PROBE.uri,
        call: () => client.readResource({ uri: RESOURCE_PROBE.uri }),
        judgeIt: (res) => judgeResource(res, RESOURCE_PROBE.uri),
        served,
        shipped,
        measure,
      });
    }
    // #2781's review: each SHAPED case's own call that no probe above makes, sized and judged as a
    // tools/call is, with no EXPECT (its job is the size). Its arguments are checked against the
    // tool's inputSchema before they are sent, as chooseInput checks a candidate; one that cannot be
    // built (its file unread) or does not fit is no_valid_probe_input, never sent.
    for (const s of sizes) {
      const tool = byName.get(s.tool);
      if (!tool) {
        emit({ tool: s.label, era, ...unlisted(s.tool, served, shipped) });
        continue;
      }
      const choice = chooseInput(s.tool, tool, seen, { [s.tool]: [s.arguments] });
      if (!choice.args) {
        emit({ tool: s.label, era, outcome: "failure", reason: choice.reason });
        continue;
      }
      const t0 = performance.now();
      let res;
      try {
        res = await client.callTool({ name: s.tool, arguments: choice.args });
      } catch (e) {
        emit({ tool: s.label, era, outcome: "failure", latency_ms: Math.round(performance.now() - t0), ...errorReason(e) });
        continue;
      }
      emit({ tool: s.label, era, latency_ms: Math.round(performance.now() - t0), ...measure(res), ...judge(res, tool) });
    }
    // #2781: cve://CVE-2021-44228 on every leg, after its other probes: listed by
    // resources/templates/list, read, sized and judged (probes.mjs CVE_RESOURCE_PROBE).
    await probeExtra({
      era,
      emit,
      label: CVE_RESOURCE_PROBE.label,
      list: async () => (await client.listResourceTemplates()).resourceTemplates,
      listed: (t) => t?.uriTemplate === CVE_RESOURCE_PROBE.template,
      call: () => client.readResource({ uri: CVE_RESOURCE_PROBE.uri }),
      judgeIt: (res) => judgeResource(res, CVE_RESOURCE_PROBE.uri, CVE_RESOURCE_PROBE.expect),
      served,
      shipped,
      measure,
    });
    if (onCatalog) onCatalog(await catalogOf(client, tools, promptsOnce, resourcesOnce, templatesOnce));
    if (client.protocolViolation) emit({ tool: "(session)", era, outcome: "failure", step: "stdout", reason: "protocol_violation" });
  } finally {
    await client.close().catch(() => {});
  }
}

// The hosted endpoint the http leg may be pointed at: https anywhere, or plain http on a loopback
// host (the tests' local server), never with credentials in it. Anything else is refused before
// a request is sent.
export function remoteUrlAllowed(u) {
  let url;
  try {
    url = new URL(u);
  } catch {
    return false;
  }
  if (url.username || url.password) return false;
  if (url.protocol === "https:") return true;
  return url.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname);
}

const VERSION_SHAPE = /^[0-9A-Za-z.+-]{1,40}$/;

export async function runSynthetic(opts = {}) {
  const runId = opts.runId ?? randomUUID();
  const write = opts.write ?? ((line) => process.stdout.write(`${JSON.stringify(line)}\n`));
  const started = Date.now();
  const eras = opts.eras ?? DEFAULT_ERAS;
  const force = (opts.force ?? []).filter((n) => TOOL_NAME.test(n));
  const timeoutMs = opts.timeoutMs ?? 90_000;
  const stdio = opts.stdio !== false;
  const remoteUrl = opts.remoteUrl || undefined;
  if (remoteUrl && !remoteUrlAllowed(remoteUrl)) throw new Error("refusing the remote URL: not https (or http on a loopback host), or it carries credentials");
  const transports = [...(stdio ? [STDIO] : []), ...(remoteUrl ? [HTTP] : [])];
  const counts = { success: 0, failure: 0, not_published: 0 };
  let version = opts.version ?? "unknown";
  let remoteVersion = "unknown";
  const emitter = (transport) => (fields) => {
    counts[fields.outcome] = (counts[fields.outcome] ?? 0) + 1;
    const v = transport === HTTP ? remoteVersion : version;
    write({ severity: "INFO", message: PROBE_MESSAGE, run_id: runId, package_version: v, transport, ...fields });
  };
  // #2842: one client-cut line per era and transport. The sentences are the stdio package's
  // (loadRequiredText); the hosted endpoint is held to them only when it reports that version.
  let required;
  const textCut = { lines: 0, failures: 0 };
  const textCutLine = (transport, era) => (served) => {
    const v = transport === HTTP ? remoteVersion : version;
    const basis = !required ? "no_required_text" : transport === HTTP && remoteVersion !== version ? "version_mismatch" : "judged";
    const fields = judgeTextCut(served, basis === "judged" ? required : undefined);
    textCut.lines++;
    if (fields.outcome === "failure") textCut.failures++;
    write({ severity: "INFO", message: TEXT_CUT_MESSAGE, run_id: runId, package_version: v, transport, era, ...fields, description_heads_basis: basis, required_version: required ? version : null });
  };

  // #3097: each leg's catalog per era, compared when both legs ran.
  const catalogs = { [STDIO]: {}, [HTTP]: {} };
  const keep = (transport, era) => (c) => (catalogs[transport][era] = c);
  let hostedVsNpm;
  let hostedVsNpmAt;
  // #3097's review: how npm's package of the hosted version is installed (tests pass their own).
  const install = opts.installPackage ?? installPackage;
  let stdioEnv;
  const tmps = [];

  let tmp;
  let forwarder;
  try {
    if (stdio) await stdioLeg();
    if (remoteUrl) {
      const emit = emitter(HTTP);
      // The version the endpoint reports in its handshake: what is deployed, not what npm has.
      const onServerInfo = (info) => {
        if (remoteVersion === "unknown" && typeof info?.version === "string" && VERSION_SHAPE.test(info.version)) remoteVersion = info.version;
      };
      // #2781's review: the size probes once per run, in the first era (a tool's text is the same on both).
      for (const [i, era] of eras.entries()) await probeHttpEra({ era, url: remoteUrl, force, timeoutMs, emit, onServerInfo, onListed: textCutLine(HTTP, era), onCatalog: keep(HTTP, era), sizes: i === 0 });
      if (stdio) hostedVsNpm = await compareLegs(emit);
    }
    return finish();
  } finally {
    await forwarder?.close();
    for (const d of [tmp, ...tmps]) if (d) fs.rmSync(d, { recursive: true, force: true });
  }

  // #3097's review: npm's package of the version the endpoint reports, installed once per run into a
  // directory of its own, and each era's catalog of it: { catalogs } or { reason, detail }.
  async function hostedVersionCatalogs() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "eg-mcp-synthetic-hosted-"));
    tmps.push(dir);
    let installed;
    try {
      installed = await install(`echelongraph-mcp@${remoteVersion}`, dir);
    } catch (e) {
      const said = String(e?.message ?? e).split("\n")[0].slice(0, 300);
      return { reason: /\bE(TARGET|404)\b|notarget|No matching version|is not in this registry/i.test(said) ? "hosted_version_not_on_npm" : "hosted_version_install_failed", detail: said };
    }
    const out = {};
    for (const era of eras) {
      if (!catalogs[HTTP][era]) continue;
      try {
        out[era] = await readCatalog({ era, serverJs: installed.serverJs, env: stdioEnv, timeoutMs });
      } catch (e) {
        return { reason: "hosted_version_install_failed", detail: `echelongraph-mcp@${remoteVersion} [${era}]: ${errorReason(e).reason}` };
      }
    }
    return { catalogs: out };
  }

  // #3097: the hosted endpoint against the npm package, era by era: the npm leg's when both report
  // one version, npm's package of the hosted version when they do not.
  async function compareLegs(emit) {
    if (version === "unknown" || remoteVersion === "unknown") return "version_unknown";
    let against = catalogs[STDIO];
    let comparedWith = "npm_leg";
    if (version !== remoteVersion) {
      comparedWith = "hosted_version";
      const got = await hostedVersionCatalogs();
      if (!got.catalogs) {
        for (const era of eras) {
          if (catalogs[HTTP][era]) emit({ tool: DRIFT_TOOL, era, outcome: "failure", reason: got.reason, detail: got.detail, npm_version: remoteVersion, compared_with: comparedWith });
        }
        hostedVsNpmAt = remoteVersion;
        return got.reason;
      }
      against = got.catalogs;
    }
    hostedVsNpmAt = comparedWith === "npm_leg" ? version : remoteVersion;
    let lines = 0;
    let differs = false;
    for (const era of eras) {
      const npm = against[era];
      const hosted = catalogs[HTTP][era];
      if (!npm || !hosted) continue;
      const r = compareCatalogs(npm, hosted);
      lines++;
      differs ||= r.differences.length > 0;
      emit({
        tool: DRIFT_TOOL,
        era,
        outcome: r.differences.length ? "failure" : "success",
        ...(r.differences.length ? { reason: "hosted_differs_from_npm", differences: r.differences.length, detail: r.differences.slice(0, 5).join("; ").slice(0, 300) } : {}),
        npm_version: hostedVsNpmAt,
        compared_with: comparedWith,
        compared_tools: r.compared.tools,
        compared_prompts: r.compared.prompts,
        compared_resources: r.compared.resources,
        compared_resource_templates: r.compared.resourceTemplates,
        ...(r.uncompared.length ? { uncompared: r.uncompared.join("; ").slice(0, 300) } : {}),
      });
    }
    return lines === 0 ? "not_compared" : differs ? "differs" : "identical";
  }

  // The npm package over stdio. An install that fails is an (install) line per era, and the
  // hosted leg still runs.
  async function stdioLeg() {
    const emit = emitter(STDIO);
    let serverJs = opts.serverJs;
    if (!serverJs) {
      tmp = fs.mkdtempSync(path.join(os.tmpdir(), "eg-mcp-synthetic-"));
      try {
        const installed = await installPackage(opts.packageSpec ?? DEFAULT_PACKAGE, tmp);
        serverJs = installed.serverJs;
        version = installed.version;
      } catch (e) {
        for (const era of eras) emit({ tool: "(install)", era, outcome: "failure", reason: "install_failed", detail: String(e?.message ?? e).split("\n")[0].slice(0, 300) });
        return;
      }
    }
    required = await loadRequiredText(serverJs);
    const apiBase = opts.apiBase ?? DEFAULT_API_BASE;
    if (!opts.direct) forwarder = await startForwarder({ upstream: apiBase, token: UA_TOKEN });
    const env = {
      PATH: process.env.PATH ?? "",
      HOME: process.env.HOME ?? os.tmpdir(),
      ECHELONGRAPH_API_BASE: forwarder ? forwarder.base : apiBase,
      ECHELONGRAPH_MCP_UA: UA_TOKEN,
      ...(opts.serverEnv ?? {}),
    };
    stdioEnv = env;
    // The version the server reports in its handshake, when it was not installed by spec here.
    const onServerInfo = (info) => {
      if (version === "unknown" && typeof info?.version === "string" && VERSION_SHAPE.test(info.version)) version = info.version;
    };
    // #2781: the forwarder's base, which the package quotes, counted as the API's.
    const measure = (res) => sizesOf(res, { localBase: forwarder?.base, asBase: apiBase.replace(/\/+$/, "") });
    for (const era of eras) await probeEra({ era, serverJs, env, force, timeoutMs, emit, onServerInfo, onListed: textCutLine(STDIO, era), onCatalog: remoteUrl ? keep(STDIO, era) : undefined, measure });
  }

  function finish() {
    const summary = {
      severity: "INFO",
      message: COMPLETE_MESSAGE,
      run_id: runId,
      package_version: version,
      eras,
      transports,
      ...(remoteUrl ? { remote_version: remoteVersion } : {}),
      // #3097: identical, differs, hosted_version_not_on_npm, hosted_version_install_failed,
      // version_unknown or not_compared (both legs ran, neither era had both catalogs), and
      // hosted_vs_npm_at, the npm version compared; absent without both legs.
      ...(remoteUrl && stdio ? { hosted_vs_npm: hostedVsNpm ?? "not_compared", ...(hostedVsNpmAt ? { hosted_vs_npm_at: hostedVsNpmAt } : {}) } : {}),
      ...counts,
      // #2842: the client-cut lines this run wrote, and how many of them were failures.
      text_cut_lines: textCut.lines,
      text_cut_failures: textCut.failures,
      duration_ms: Date.now() - started,
      // Which mechanism identified the requests: requests that already led with the token
      // (the package honoured ECHELONGRAPH_MCP_UA) and requests the forwarder prefixed.
      ...(forwarder ? { api_requests: forwarder.stats.requests, ua_identified_by_package: forwarder.stats.identified, ua_prefixed_by_forwarder: forwarder.stats.rewritten, forwarder_upstream_errors: forwarder.stats.upstream_errors } : {}),
      ...(opts.direct ? { forwarder: "off" } : {}),
    };
    write(summary);
    return { summary, exitCode: counts.failure > 0 || textCut.failures > 0 ? 2 : 0 };
  }
}

function optionsFromCli(argv, env) {
  const { values } = parseArgs({
    args: argv,
    options: {
      package: { type: "string" },
      bin: { type: "string" },
      "api-base": { type: "string" },
      direct: { type: "boolean" },
      "force-tool": { type: "string", multiple: true },
      eras: { type: "string" },
      "timeout-ms": { type: "string" },
      "remote-url": { type: "string" },
      "no-stdio": { type: "boolean" },
    },
  });
  const list = (s) => (s ? s.split(",").map((x) => x.trim()).filter(Boolean) : undefined);
  const timeout = Number(values["timeout-ms"] ?? env.MCP_SYNTHETIC_CALL_TIMEOUT_MS);
  return {
    packageSpec: values.package ?? env.MCP_SYNTHETIC_PACKAGE ?? DEFAULT_PACKAGE,
    serverJs: values.bin ?? env.MCP_SYNTHETIC_BIN ?? undefined,
    apiBase: values["api-base"] ?? env.MCP_SYNTHETIC_API_BASE ?? DEFAULT_API_BASE,
    direct: values.direct ?? env.MCP_SYNTHETIC_DIRECT === "1",
    force: values["force-tool"]?.flatMap(list) ?? list(env.MCP_SYNTHETIC_FORCE_TOOLS) ?? [],
    eras: list(values.eras ?? env.MCP_SYNTHETIC_ERAS) ?? DEFAULT_ERAS,
    timeoutMs: Number.isFinite(timeout) && timeout > 0 ? timeout : 90_000,
    remoteUrl: values["remote-url"] ?? (env.MCP_SYNTHETIC_REMOTE_URL || undefined),
    stdio: !(values["no-stdio"] ?? env.MCP_SYNTHETIC_STDIO === "0"),
  };
}

if (process.argv[1] && pathToFileURL(fs.realpathSync(process.argv[1])).href === pathToFileURL(fileURLToPath(import.meta.url)).href) {
  try {
    const { exitCode } = await runSynthetic(optionsFromCli(process.argv.slice(2), process.env));
    process.exitCode = exitCode;
  } catch (e) {
    process.stdout.write(`${JSON.stringify({ severity: "ERROR", message: "mcp synthetic runner crashed", error: String(e?.message ?? e).slice(0, 300) })}\n`);
    process.exitCode = 1;
  }
}
