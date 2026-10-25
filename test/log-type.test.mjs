// #2863's review (2026-10-18): http.ts log() is typed against src/logLines.ts LOG_LINES, so a log call whose message or
// keys are not listed there does not build. The lane's controls for that were run by hand; these run them here, by
// type-checking http.ts as written and as each mutant, and the review's evasion is closed: a spread of an `any` value
// (log("WARNING", "mcp_busy", { ...JSON.parse(x) })) compiled, and would have put whatever it held on the line.
// Reads src/, which only this repository has: an installed package (ECHELONGRAPH_MCP_BIN) ships dist/ alone.
//
// typescript is a devDependency. Both release pipelines (scripts/npm-publish-mcp.sh and the public release.yml) run
// this file against the PACKED TARBALL with production dependencies only, where a top-level `import ts from
// "typescript"` threw ERR_MODULE_NOT_FOUND and refused the 3.1.0 publish (phase D2 final review). So typescript is
// imported here, and its absence alone is a named skip; the guard at the end fails the repository suite if these
// checks are skipped where typescript is installed or src/ is present.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const HTTP_TS = path.join(ROOT, "src", "http.ts");
const HAS_SRC = fs.existsSync(HTTP_TS);
const TS_ABSENT = "typescript is a devDependency; the repo suite runs this check";

/** typescript, or undefined only when the package itself cannot be found. Any other failure to load it throws. */
async function loadTypescript() {
  try {
    return (await import("typescript")).default;
  } catch (e) {
    if (e?.code === "ERR_MODULE_NOT_FOUND" && /'typescript'/.test(String(e.message))) return undefined;
    throw e;
  }
}
const ts = await loadTypescript();
const SKIP = !ts ? TS_ABSENT : !HAS_SRC ? "no src/ here" : false;

/** The type errors in http.ts when its text is `text`, as tsconfig.json compiles it. */
function httpTypeErrors(text) {
  const cfg = ts.getParsedCommandLineOfConfigFile(path.join(ROOT, "tsconfig.json"), {}, { ...ts.sys, onUnRecoverableConfigFileDiagnostic: () => {} });
  const host = ts.createCompilerHost(cfg.options);
  const read = host.readFile.bind(host);
  host.readFile = (f) => (path.resolve(f) === HTTP_TS ? text : read(f));
  const program = ts.createProgram({ rootNames: [HTTP_TS], options: { ...cfg.options, noEmit: true }, host });
  const sf = program.getSourceFile(HTTP_TS);
  return ts.getPreEmitDiagnostics(program, sf).map((d) => `${d.code}: ${ts.flattenDiagnosticMessageText(d.messageText, " ")}`);
}

describe("#2863: a log line or key not in LOG_LINES does not build, nor does an any-spread", { skip: SKIP }, () => {
  const src = HAS_SRC ? fs.readFileSync(HTTP_TS, "utf8") : "";
  const BUSY = 'log("WARNING", "mcp_busy", { max_in_flight: MAX_IN_FLIGHT, waiting: admission.waiting });';
  const ACCESS = "      queued_ms: o.queuedMs ?? 0,\n";
  it("http.ts as written type-checks", () => {
    assert.ok(src.includes(BUSY) && src.includes(ACCESS), "http.ts's busy line or access line moved: re-aim these controls");
    assert.deepEqual(httpTypeErrors(src), []);
  });
  for (const [what, from, to] of [
    ["a spread of an any value (#2863's review)", BUSY, 'log("WARNING", "mcp_busy", { max_in_flight: MAX_IN_FLIGHT, waiting: admission.waiting, ...JSON.parse(String(req.headers["x"])) });'],
    ["a whole any value as the fields", BUSY, 'log("WARNING", "mcp_busy", JSON.parse("{}"));'],
    ["#2863's two-field edit: the client address and the whole User-Agent on the access line", ACCESS, `${ACCESS}      client_addr: req.headers["x-forwarded-for"],\n      user_agent: req.headers["user-agent"],\n`],
    ["a key dropped from a listed line", ACCESS, ""],
    ["a line logLines.ts does not list", BUSY, `${BUSY}\n    log("INFO", "mcp_debug", { waiting: admission.waiting });`],
  ]) {
    it(`does not build with ${what}`, () => {
      assert.ok(src.includes(from), `http.ts lost ${JSON.stringify(from.slice(0, 60))}: re-aim this control`);
      assert.notDeepEqual(httpTypeErrors(src.replace(from, to)), [], `http.ts builds with ${what}`);
    });
  }
});

// The skip above is for the packed tarball alone (production dependencies, no src/). In the repository, where `npm test`
// has just built with tsc, a skip would hide every control above and still report the file as passing.
it("#2863's checks were not skipped where typescript is installed or src/ is present", () => {
  const installed = fs.existsSync(path.join(ROOT, "node_modules", "typescript", "package.json"));
  if (!installed && !HAS_SRC) return; // the packed tarball, as npm-publish-mcp.sh and release.yml test it
  assert.ok(ts, `typescript did not load here (installed: ${installed}, src/: ${HAS_SRC})`);
  assert.equal(SKIP, false, `#2863's checks were skipped (${SKIP}) with typescript installed: ${installed}, src/: ${HAS_SRC}`);
});
