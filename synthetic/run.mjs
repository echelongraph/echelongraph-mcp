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
//                 "clean", and it is not an outage.
//   failure       anything else: a JSON-RPC error, a timeout, isError, state failed or
//                 invalid_input, no structuredContent, a structuredContent the schema refuses,
//                 or no input the synthetic can send. `reason` says which.
//   not_published a tool probes.mjs names that this version does not list (a planned tool).
//
// OUTPUT: one JSON line per tool per era on stdout, message "mcp tool probe", which Cloud Run
// stores as jsonPayload; the log-based metric mcp_tool_probe_total{tool,era,outcome} counts
// them and mcp_tool_probe_latency_ms reads latency_ms (infrastructure/monitoring/
// create-mcp-synthetic-monitoring.sh). Then one "mcp synthetic run complete" line, the
// liveness signal. Every line has the one severity of its message, INFO: the outcome is a
// field, never the severity, so a re-levelled line cannot silence a metric.
//
// The session itself can fail (install, spawn, handshake, tools/list): that is a probe line
// with tool "(install)" or "(session)" and outcome failure, so the same alert sees it.
//
// IDENTITY: the package is run with ECHELONGRAPH_MCP_UA=echelongraph-mcp-synthetic/1.0 and,
// unless --direct, behind forwarder.mjs, which puts that token ahead of the user-agent of a
// version that predates the variable. Either way core-backend files the requests under the
// family echelongraph-mcp-synthetic (class ours), never under echelongraph-mcp adoption.
//
// No value is logged that a person typed: the inputs are this file's own public constants, and
// a line names the candidate it sent by index.
//
// Exit status: 0 when every probe line is success or not_published, 2 when any is a failure,
// 1 when the runner itself broke. The metric, not the exit status, is what alerts.
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
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs, promisify } from "node:util";
import { AjvJsonSchemaValidator } from "@modelcontextprotocol/server/validators/ajv";
import { connect, MODERN, RpcError } from "../test/mcp-stdio-client.mjs";
import { AFTER, PROBES } from "./probes.mjs";
import { startForwarder } from "./forwarder.mjs";

export const LEGACY = "2025-06-18";
export const DEFAULT_ERAS = [MODERN, LEGACY];
export const UA_TOKEN = "echelongraph-mcp-synthetic/1.0";
export const PROBE_MESSAGE = "mcp tool probe";
export const COMPLETE_MESSAGE = "mcp synthetic run complete";
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
// Returns { args, index } or { reason } when there is none.
export function chooseInput(name, tool, seen) {
  const candidates = PROBES[name];
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
// name the package does not list.
export function judge(res, tool) {
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
  return { outcome: "success", state };
}

function errorReason(e) {
  if (e instanceof RpcError) return { reason: "rpc_error", rpc_code: e.code };
  const msg = String(e?.message ?? e);
  if (/no answer within/.test(msg)) return { reason: "timeout" };
  if (/exited/.test(msg)) return { reason: "server_exited" };
  return { reason: "error" };
}

// Probe one era: one line per tool.
export async function probeEra({ era, serverJs, env, force, timeoutMs, emit, onServerInfo = () => {} }) {
  let client;
  try {
    client = await connect({
      era,
      command: process.execPath,
      args: [serverJs],
      env,
      stderr: "ignore",
      clientInfo: { name: "echelongraph-mcp-synthetic", version: "1.0.0" },
      requestTimeoutMs: timeoutMs,
    });
  } catch (e) {
    emit({ tool: "(session)", era, outcome: "failure", step: "open", ...errorReason(e) });
    return;
  }
  onServerInfo(client.getServerVersion());
  try {
    let tools;
    try {
      ({ tools } = await client.listTools());
    } catch (e) {
      emit({ tool: "(session)", era, outcome: "failure", step: "tools/list", ...errorReason(e) });
      return;
    }
    const byName = new Map(tools.map((t) => [t.name, t]));
    const seen = {};
    for (const name of probeOrder(tools.map((t) => t.name), force)) {
      const tool = byName.get(name);
      const forced = force.includes(name);
      if (!tool && !forced) {
        emit({ tool: name, era, outcome: "not_published" });
        continue;
      }
      const choice = tool ? chooseInput(name, tool, seen) : { args: {}, index: -1 };
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
      const verdict = judge(res, tool);
      if (verdict.outcome === "success") seen[name] = res.structuredContent;
      emit({ tool: name, era, latency_ms: latency, input: choice.index, ...verdict });
    }
    if (client.protocolViolation) emit({ tool: "(session)", era, outcome: "failure", step: "stdout", reason: "protocol_violation" });
  } finally {
    await client.close().catch(() => {});
  }
}

export async function runSynthetic(opts = {}) {
  const runId = opts.runId ?? randomUUID();
  const write = opts.write ?? ((line) => process.stdout.write(`${JSON.stringify(line)}\n`));
  const started = Date.now();
  const eras = opts.eras ?? DEFAULT_ERAS;
  const force = (opts.force ?? []).filter((n) => TOOL_NAME.test(n));
  const counts = { success: 0, failure: 0, not_published: 0 };
  let version = opts.version ?? "unknown";
  const emit = (fields) => {
    counts[fields.outcome] = (counts[fields.outcome] ?? 0) + 1;
    write({ severity: "INFO", message: PROBE_MESSAGE, run_id: runId, package_version: version, ...fields });
  };

  let tmp;
  let forwarder;
  try {
    let serverJs = opts.serverJs;
    if (!serverJs) {
      tmp = fs.mkdtempSync(path.join(os.tmpdir(), "eg-mcp-synthetic-"));
      try {
        const installed = await installPackage(opts.packageSpec ?? DEFAULT_PACKAGE, tmp);
        serverJs = installed.serverJs;
        version = installed.version;
      } catch (e) {
        for (const era of eras) emit({ tool: "(install)", era, outcome: "failure", reason: "install_failed", detail: String(e?.message ?? e).split("\n")[0].slice(0, 300) });
        return finish();
      }
    }
    const apiBase = opts.apiBase ?? DEFAULT_API_BASE;
    if (!opts.direct) forwarder = await startForwarder({ upstream: apiBase, token: UA_TOKEN });
    const env = {
      PATH: process.env.PATH ?? "",
      HOME: process.env.HOME ?? os.tmpdir(),
      ECHELONGRAPH_API_BASE: forwarder ? forwarder.base : apiBase,
      ECHELONGRAPH_MCP_UA: UA_TOKEN,
      ...(opts.serverEnv ?? {}),
    };
    // The version the server reports in its handshake, when it was not installed by spec here.
    const onServerInfo = (info) => {
      if (version === "unknown" && typeof info?.version === "string" && /^[0-9A-Za-z.+-]{1,40}$/.test(info.version)) version = info.version;
    };
    for (const era of eras) await probeEra({ era, serverJs, env, force, timeoutMs: opts.timeoutMs ?? 90_000, emit, onServerInfo });
    return finish();
  } finally {
    await forwarder?.close();
    if (tmp) fs.rmSync(tmp, { recursive: true, force: true });
  }

  function finish() {
    const summary = {
      severity: "INFO",
      message: COMPLETE_MESSAGE,
      run_id: runId,
      package_version: version,
      eras,
      ...counts,
      duration_ms: Date.now() - started,
      // Which mechanism identified the requests: requests that already led with the token
      // (the package honoured ECHELONGRAPH_MCP_UA) and requests the forwarder prefixed.
      ...(forwarder ? { api_requests: forwarder.stats.requests, ua_identified_by_package: forwarder.stats.identified, ua_prefixed_by_forwarder: forwarder.stats.rewritten, forwarder_upstream_errors: forwarder.stats.upstream_errors } : {}),
      ...(opts.direct ? { forwarder: "off" } : {}),
    };
    write(summary);
    return { summary, exitCode: counts.failure > 0 ? 2 : 0 };
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
