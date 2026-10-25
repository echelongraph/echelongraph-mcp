// The README's Claude Desktop setup and its freshness sentence, held in the package that ships them
// (#2813, #3010). The monorepo's marketing-site/lib/claudeDesktopSetup.test.ts and
// lib/scanningPause.test.ts hold the same README beside /pulse/mcp, but they run only on a marketing
// deploy; this file runs with `npm test`, so in the release that puts the README on npm too.
//
//   * "### Claude Desktop" carries what a first install hits, as walked on a Mac on 2026-10-04: the
//     no-install connector before npx; checking and installing Node.js; merging into the config file
//     Claude Desktop already keeps; a plain-text editor and TextEdit's Smart Quotes; quitting fully;
//     what success looks like; spawn npx ENOENT with the absolute-path and env.PATH fix; the logs.
//   * Its success step names no number of tools. npx runs the newest release on npm and a connector
//     runs the hosted endpoint's, so a count can differ from what a working install shows, and a user
//     reads the difference as a failed install. It points to the Tools table instead.
//   * The README never says, unconditionally, that each radar refreshes. A radar refreshes only while
//     it runs, and four of them were stopped on 8 October 2026 while this README said they refreshed;
//     the README ships to npm and cannot follow a pause, so its sentence is true either way. #3246: nor
//     does any docs/ page, which ships too and now holds exposure_radar's reference (#3012).
import { after, describe, it } from "node:test";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import { readDocs, readPkgFile } from "./server-under-test.mjs";
import { BOTH_STATES, UNCONDITIONAL_REFRESH } from "./barred-claims.mjs";

const README = readPkgFile("README.md");
const REMOTE = JSON.parse(readPkgFile("server.json")).remotes?.[0]?.url;

/** The README's "### Claude Desktop" section, up to the next client's heading. */
function claudeDesktop() {
  const a = README.indexOf("### Claude Desktop\n");
  assert.notEqual(a, -1, "the README has no ### Claude Desktop section: re-aim this check");
  const b = README.indexOf("\n### ", a + 1);
  assert.notEqual(b, -1, "the README's Claude Desktop section has no end: re-aim this check");
  return README.slice(a, b);
}

/** Prose as a reader sees it: emphasis and code ticks removed, whitespace folded. */
const prose = (md) => md.replace(/\*\*/g, "").replace(/`/g, "").replace(/\s+/g, " ").trim();

/** What a first install needs, in the README's words. */
const REQUIRED = [
  ["the no-install custom connector", "Add custom connector"],
  ["the hosted URL for the connector", REMOTE],
  ["the connector's auth choice", "No sign in"],
  ["how to check Node.js", "node -v"],
  ["the Node.js version", "v20 or later"],
  ["where to install Node.js", "nodejs.org"],
  ["the Homebrew install", "brew install node"],
  ["the macOS config path", "~/Library/Application Support/Claude/claude_desktop_config.json"],
  ["the Windows config path", "%APPDATA%\\Claude\\claude_desktop_config.json"],
  ["a plain-text editor", "plain-text editor"],
  ["the smart-quotes warning", "when Smart Quotes is on, and the JSON then breaks"],
  ["merging instead of replacing", "Merge, do not replace"],
  ["where mcpServers goes", "key at the top level"],
  ["mcpServers already there", 'if "mcpServers" is already there, add the "echelongraph" entry inside it'],
  ["quitting fully", "Quit fully, then reopen"],
  ["the macOS quit", "Quit Claude (⌘Q)"],
  ["the Windows quit", "system tray"],
  ["what success looks like", "Settings → Developer lists echelongraph as running"],
  ["the tools menu", 'the tools menu in the chat box lists EchelonGraph\'s tools, the ones under "Tools" below'],
  ["the ENOENT cause", "spawn npx ENOENT"],
  ["the shell PATH cause", "On macOS, an app opened from the Dock does not get your shell's PATH"],
  ["finding npx", "which npx"],
  ["the Homebrew path", "/opt/homebrew/bin"],
  ["the env.PATH fix", 'PATH under "env"'],
  ["this server's macOS log", "~/Library/Logs/Claude/mcp-server-echelongraph.log"],
  ["the macOS connection log", "~/Library/Logs/Claude/mcp.log"],
  ["the Windows logs", "%APPDATA%\\Claude\\logs\\"],
];
const missing = (text) => REQUIRED.filter(([, n]) => !text.includes(n)).map(([what, n]) => `${what} (${n})`);


describe("README Claude Desktop setup (#2813)", () => {
  it("carries every step and the troubleshooting block, the connector before npx", () => {
    const text = prose(claudeDesktop());
    assert.deepEqual(missing(text), []);
    assert.ok(text.indexOf("Add custom connector") < text.indexOf("node -v"), "the README gives npx before the no-install connector");
  });
  it("names no number of tools to look for", () => {
    const n = prose(claudeDesktop()).match(/lists EchelonGraph's (?:\d+|[a-z]+(?:-[a-z]+)?) tools/);
    assert.equal(n, null, `the success step counts the tools ("${n?.[0]}"): a working install of another version shows another number`);
  });
  it("control: a step gone missing, or a count put back, fails", () => {
    const text = prose(claudeDesktop());
    assert.deepEqual(missing(text.replace("spawn npx ENOENT", "an error")), ["the ENOENT cause (spawn npx ENOENT)"]);
    assert.equal(missing("").length, REQUIRED.length);
    assert.match("the tools menu in the chat box lists EchelonGraph's 16 tools", /lists EchelonGraph's (?:\d+|[a-z]+(?:-[a-z]+)?) tools/);
  });
});

// The claim and the sentence that replaced it are barred-claims.mjs's (#3246), one wording for every surface.
const refreshClaims = (pages) =>
  pages.flatMap(([page, text]) => {
    const m = prose(text).match(UNCONDITIONAL_REFRESH);
    return m ? [`${page} says "${m[0]}", which a stopped radar makes false`] : [];
  });

describe("README and docs/ freshness (#3010, #3246)", () => {
  it("no page of the package's documentation says each radar refreshes, and the README says a radar refreshes only while it runs", () => {
    assert.deepEqual(refreshClaims(readDocs()), []);
    const text = prose(README);
    assert.ok(text.includes(BOTH_STATES), `the README no longer says "${BOTH_STATES}"`);
    assert.ok(text.includes("exposure_radar's freshness gives each radar's last completed check (last_run_at)"), "the README no longer says where a radar's last completed check is");
  });
  it("control: the sentence the README carried through the 2026-10-08 pause fails, on the README and on a docs/ page", () => {
    assert.match("The CVE feed is polled from its sources on a schedule; each radar refreshes on its own.", UNCONDITIONAL_REFRESH);
    assert.doesNotMatch(BOTH_STATES, UNCONDITIONAL_REFRESH);
    const docs = readDocs();
    assert.ok(docs.some(([p]) => p === "docs/exposure-radar.md"), "docs/exposure-radar.md is not read: re-aim this control");
    for (const target of ["README.md", "docs/exposure-radar.md", "docs/tools.md"]) {
      const mutated = docs.map(([p, t]) => [p, p === target ? `${t}\nEach radar refreshes on its own schedule.\n` : t]);
      assert.deepEqual(refreshClaims(mutated), [`${target} says "Each radar refreshes on its own", which a stopped radar makes false`]);
    }
  });
});

// #3096: the README's "check that the file parses" command, run as printed. Through 2.7.2 it took a
// quoted "<path to the file>", and the macOS path pasted into it ("~/Library/…") is not expanded
// inside double quotes, so a valid file answered ENOENT.
// 3.1.0's final panel: each home it makes is removed when the describe ends. They were left in TMPDIR, three per run
// of the suite (the repo's, the packed tarball's and the public npm test alike): 195 had piled up on one devbox.
const HOMES = [];
describe("README Claude Desktop parse check (#3096)", () => {
  after(() => {
    for (const h of HOMES) rmSync(h, { recursive: true, force: true });
  });
  const CHECK = /node -e "JSON\.parse\(require\('fs'\)\.readFileSync\(process\.argv\[1\], 'utf8'\)\)" "[^"\n]+"/g;
  const home = (json) => {
    const h = mkdtempSync(join(tmpdir(), "eg-3096-"));
    HOMES.push(h);
    const d = join(h, "Library", "Application Support", "Claude");
    mkdirSync(d, { recursive: true });
    writeFileSync(join(d, "claude_desktop_config.json"), json);
    return h;
  };
  const run = (cmd, h) => spawnSync("bash", ["-c", cmd], { env: { ...process.env, HOME: h }, encoding: "utf8" });
  const VALID = '{"preferences":{},"mcpServers":{"echelongraph":{"command":"npx","args":["-y","echelongraph-mcp"]}}}';
  const checks = claudeDesktop().match(CHECK) ?? [];

  it("prints one per OS, each with its path filled in", () => {
    assert.equal(checks.length, 2, `found ${checks.length} parse checks`);
    assert.ok(checks[0].endsWith('"$HOME/Library/Application Support/Claude/claude_desktop_config.json"'), checks[0]);
    assert.ok(checks[1].endsWith('"$env:APPDATA\\Claude\\claude_desktop_config.json"'), checks[1]);
  });
  it("the macOS one passes a valid file silently and fails one with curly quotes", { skip: process.platform === "win32" }, () => {
    const ok = run(checks[0], home(VALID));
    assert.equal(ok.status, 0, ok.stderr);
    assert.equal(ok.stdout + ok.stderr, "");
    const bad = run(checks[0], home("{“mcpServers”:{}}"));
    assert.notEqual(bad.status, 0);
    assert.match(bad.stderr, /SyntaxError/);
  });
  it("control: the ~ form it replaced fails on a valid file", { skip: process.platform === "win32" }, () => {
    const r = run(`node -e "JSON.parse(require('fs').readFileSync(process.argv[1], 'utf8'))" "~/Library/Application Support/Claude/claude_desktop_config.json"`, home(VALID));
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /ENOENT/);
  });
});

// Runs after the describe above, and its after() hook, have finished (node:test runs a file's suites in order).
describe("README Claude Desktop parse check (#3096): its temporary homes", () => {
  it("are all removed once it ends, none left in TMPDIR", { skip: process.platform === "win32" }, () => {
    assert.equal(HOMES.length, 3, `the parse-check cases made ${HOMES.length} homes, not 3: re-aim this check`);
    assert.deepEqual(HOMES.filter((h) => existsSync(h)), []);
  });
});
