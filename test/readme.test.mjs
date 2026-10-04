// The README's top half (#2726 docs pass): the quick start, the tool table, the configuration
// tables and the changelog, held to what the package actually is, so a release cannot leave the
// README (the npm page and the public repo's front page) describing another version.
//
//   * the tool table lists exactly the tools tools/list answers, in its order, each with the
//     title the server declares, in both protocol eras;
//   * every environment variable the shipped code reads is documented, and nothing else is;
//   * the hosted endpoint's URL and per-client limit are the ones server.json and the code use;
//   * every JSON block in the README parses, and every MCP client config block names this
//     package or the hosted URL;
//   * the hosted endpoint is described as in service, never as being rolled out (#2739), in
//     agreement with /pulse/mcp's REMOTE_SERVING switch where the monorepo is present;
//   * CHANGELOG.md has an entry for package.json's version, and its preamble says the issue
//     numbers are an internal tracker's (#2740), in the words listings/README.md gives for
//     Release bodies.
//
// Wording (REMOVED_CLAIMS, HOST_UNIT) is tools.test.mjs's, over the whole README.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { StdioMcpClient, MODERN } from "./mcp-stdio-client.mjs";
import { PKG, PKG_DIR, serverCommand, readPkgFile } from "./server-under-test.mjs";

const README = readPkgFile("README.md");
const SERVER_JSON = JSON.parse(readPkgFile("server.json"));
const REMOTE = SERVER_JSON.remotes?.[0]?.url;

// The rows of the README's "## Tools" table: | `name` | Title | What it answers | Example |.
function toolTable() {
  const section = README.split(/^## Tools$/m)[1]?.split(/^## /m)[0] ?? "";
  const header = section.match(/^\| Tool \| Title \| What it answers \| Example question \|$/m);
  assert.ok(header, "the README's Tools section lost its | Tool | Title | What it answers | Example question | header");
  return [...section.matchAll(/^\| `([a-z_]+)` \| ([^|]+?) \| (.+) \| \*([^|*]+)\* \|$/gm)].map((m) => ({
    name: m[1],
    title: m[2],
    ask: m[4],
  }));
}

for (const era of [MODERN, "2025-06-18"]) {
  describe(`README tool table equals tools/list [${era}]`, () => {
    let client, tools;
    before(async () => {
      client = new StdioMcpClient({ ...serverCommand(), env: { ...process.env, ECHELONGRAPH_API_BASE: "http://127.0.0.1:9" }, stderr: "ignore" });
      await client.open(era);
      ({ tools } = await client.listTools());
    });
    after(() => client?.close());

    it("same tools, in tools/list order, each with the server's title", () => {
      assert.deepEqual(
        toolTable().map(({ name, title }) => ({ name, title })),
        tools.map((t) => ({ name: t.name, title: t.title })),
      );
    });
    it("the prose counts the tools the server lists", () => {
      for (const m of README.matchAll(/\b(\d+) (?:read-only )?tools\b/g)) assert.equal(Number(m[1]), tools.length, `"${m[0]}"`);
      assert.ok(README.includes(`${tools.length} tools`), "the README no longer says how many tools there are");
    });
  });
}

describe("README configuration and hosted endpoint", () => {
  // Every process.env.NAME the shipped JavaScript reads.
  const envRead = () => {
    const names = new Set();
    const walk = (dir) => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        const p = path.join(dir, e.name);
        if (e.isDirectory()) walk(p);
        else if (e.name.endsWith(".js")) for (const m of fs.readFileSync(p, "utf8").matchAll(/process\.env\.([A-Z][A-Z0-9_]*)/g)) names.add(m[1]);
      }
    };
    walk(path.join(PKG_DIR, "dist"));
    return names;
  };
  const configSection = () => README.split(/^## Configuration$/m)[1]?.split(/^## /m)[0] ?? "";

  it("every environment variable the code reads is in the Configuration section", () => {
    const read = envRead();
    assert.ok(read.has("ECHELONGRAPH_API_BASE") && read.has("PORT"), `dist/ reads ${[...read].join(", ")}: re-aim this check`);
    const section = configSection();
    for (const n of read) assert.ok(section.includes(`\`${n}\``), `${n} is read by dist/ and not documented under Configuration`);
  });
  it("the Configuration section documents no variable the code does not read", () => {
    const read = envRead();
    const documented = [...configSection().matchAll(/`([A-Z][A-Z0-9_]{2,})`/g)].map((m) => m[1]);
    assert.ok(documented.length >= 9, `only ${documented.length} variables documented`);
    for (const n of documented) assert.ok(read.has(n), `${n} is documented but dist/ does not read it`);
  });
  it("the hosted endpoint's URL is server.json's remote, and the README states its per-client limit as the code's default", async () => {
    assert.equal(REMOTE, "https://mcp.echelongraph.io/mcp");
    assert.ok(README.includes(REMOTE));
    for (const m of README.matchAll(/https:\/\/mcp\.echelongraph\.io\/[a-z]*/g)) {
      assert.ok([REMOTE, "https://mcp.echelongraph.io/health"].includes(m[0]), `an unknown hosted URL: ${m[0]}`);
    }
    const { DEFAULT_RATE_LIMIT_PER_MIN } = await import(pathToFileURL(path.join(PKG_DIR, "dist", "httpPolicy.js")).href);
    assert.match(README.replace(/\s+/g, " "), new RegExp(`\\b${DEFAULT_RATE_LIMIT_PER_MIN} MCP requests a minute per client address`));
    assert.match(configSection(), new RegExp(`\`MCP_RATE_LIMIT_PER_MIN\` \\| \`${DEFAULT_RATE_LIMIT_PER_MIN}\``));
  });
  it("every json block parses, and every client config names this package or the hosted URL", () => {
    const blocks = [...README.matchAll(/^\s*```json\n([\s\S]*?)^\s*```$/gm)].map((m) => m[1]);
    assert.ok(blocks.length >= 6, `found ${blocks.length} json blocks`);
    for (const b of blocks) {
      const cfg = JSON.parse(b);
      const servers = cfg.mcpServers ?? cfg.servers;
      assert.ok(servers?.echelongraph, `a config block without an echelongraph server: ${b}`);
      const s = servers.echelongraph;
      if (s.command) assert.deepEqual([s.command, ...s.args], ["npx", "-y", PKG.name], b);
      else assert.equal(s.url ?? s.serverUrl, REMOTE, b);
    }
  });
  it("the Claude Code commands name this package and the hosted URL", () => {
    assert.ok(README.includes(`claude mcp add --transport stdio echelongraph -- npx -y ${PKG.name}`));
    assert.ok(README.includes(`claude mcp add --transport http echelongraph ${REMOTE}`));
  });
});

describe("README hosted-endpoint state (#2739)", () => {
  // /pulse/mcp's one switch for the hosted endpoint. Present in the monorepo; the public repo and
  // the npm tarball carry no marketing-site, and there only the README's own wording is checked.
  const PAGE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "marketing-site", "app", "pulse", "mcp", "page.tsx");
  const remoteBlock = () => README.split(/^### Remote \(no install\)$/m)[1]?.split(/^##+ /m)[0] ?? "";

  it("never says the hosted endpoint is being rolled out, and names server.json's remote URL in its Remote section", () => {
    assert.doesNotMatch(README, /being rolled out/i);
    assert.doesNotMatch(README, /until [^.]*\/health[^.]* answers/i, "the README still tells readers to wait for /health");
    assert.ok(remoteBlock().includes(REMOTE), `the Remote section does not name ${REMOTE}`);
    assert.match(remoteBlock(), /The hosted endpoint is in service/);
  });
  it("agrees with /pulse/mcp's REMOTE_SERVING switch", (t) => {
    if (!fs.existsSync(PAGE)) return t.skip("no marketing-site beside this package (public repo or tarball)");
    const m = fs.readFileSync(PAGE, "utf8").match(/^const REMOTE_SERVING = (true|false);$/m);
    assert.ok(m, "marketing-site/app/pulse/mcp/page.tsx lost its REMOTE_SERVING switch: re-aim this check");
    assert.equal(m[1], "true", "/pulse/mcp says the hosted endpoint is not serving, and the README says it is");
  });
});

describe("CHANGELOG.md", () => {
  // #2740: the numbers are EchelonGraph's internal tracker's; the public repo's issues are others.
  const CAVEAT = "Issue numbers (#NNNN) refer to EchelonGraph's internal issue tracker, which is not public: they are not issues of the public repository, and cannot be followed from it.";
  it("its preamble says the issue numbers are an internal tracker's, as listings/README.md asks of Release bodies", () => {
    const log = readPkgFile("CHANGELOG.md");
    const preamble = log.split(/^## /m)[0].replace(/\s+/g, " ");
    assert.ok(preamble.includes(CAVEAT), preamble);
    const listings = path.join(PKG_DIR, "listings", "README.md");
    if (fs.existsSync(listings)) assert.ok(fs.readFileSync(listings, "utf8").replace(/\s+/g, " ").includes(CAVEAT), "listings/README.md's Release notes section lost the caveat");
  });
  it("has an entry for package.json's version, and the README links it", () => {
    const log = readPkgFile("CHANGELOG.md");
    assert.match(log, new RegExp(`^## ${PKG.version.replace(/\./g, "\\.")} — \\d{4}-\\d{2}-\\d{2}$`, "m"));
    assert.ok(README.includes("(CHANGELOG.md)"));
    assert.ok(PKG.files.includes("CHANGELOG.md"), "CHANGELOG.md is not in package.json files, so npm does not ship it");
  });
});
