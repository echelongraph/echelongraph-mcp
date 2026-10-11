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
//     the README ships to npm and cannot follow a pause, so its sentence is true either way.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readPkgFile } from "./server-under-test.mjs";

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

/** A claim that the radars refresh, with no condition: true of a radar only while it runs. */
const UNCONDITIONAL_REFRESH = /\beach radar refreshes on its own\b|\brefreshes on its own schedule\b/i;
const BOTH_STATES = "Each radar has its own schedule and refreshes only while it runs";

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

describe("README freshness (#3010)", () => {
  it("never says each radar refreshes, and says a radar refreshes only while it runs", () => {
    const text = prose(README);
    const m = text.match(UNCONDITIONAL_REFRESH);
    assert.equal(m, null, `the README says "${m?.[0]}", which a stopped radar makes false`);
    assert.ok(text.includes(BOTH_STATES), `the README no longer says "${BOTH_STATES}"`);
    assert.ok(text.includes("exposure_radar's freshness gives each radar's last completed check (last_run_at)"), "the README no longer says where a radar's last completed check is");
  });
  it("control: the sentence the README carried through the 2026-10-08 pause fails", () => {
    assert.match("The CVE feed is polled from its sources on a schedule; each radar refreshes on its own.", UNCONDITIONAL_REFRESH);
    assert.doesNotMatch(BOTH_STATES, UNCONDITIONAL_REFRESH);
  });
});
