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
//   * while server.json lists the hosted remote, check_sbom's description, its sbom argument, the
//     Tools table's check_sbom row and the privacy section say the document reaches EchelonGraph's
//     server as the request body, and no string of check_sbom's tools/list entry, nor that row, nor
//     the privacy section denies it in any wording of document-denials.mjs, the list /pulse/mcp's
//     check_sbom row is held to (#2796);
//   * the Resources table names what echelongraph://sources relays for the NVD poller (#2770);
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
import { DENIAL_VARIANTS, documentDenials } from "./document-denials.mjs";

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
      // #2813: the Claude Desktop troubleshooting block names npx by its absolute path (the
      // `spawn npx ENOENT` fix), so a command is `npx` or an absolute path ending in /npx.
      if (s.command) {
        assert.match(s.command, /^(?:npx|\/(?:[^/\s]+\/)+npx)$/, b);
        assert.deepEqual(s.args, ["-y", PKG.name], b);
      }
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

// #2796: since 2.6.2 (309b7343) two surfaces say that over the hosted endpoint the check_sbom
// document is the request body: check_sbom's description, which the hosted tools/list serves to
// every agent, and the README's privacy section, where /pulse/mcp sends readers and which the
// Anthropic directory submission links beside /privacy Section 11 (listings/README.md, #2797;
// marketing-site/lib/privacyMcpEndpoint.test.ts holds that section). Rewording both to "the
// document itself is never sent and never leaves your machine" and "A check_sbom document never
// reaches EchelonGraph" left the whole suite green. While server.json lists the hosted remote, both
// must say where the document goes, and neither may deny it.
describe("hosted-endpoint disclosure of the check_sbom document (#2796)", () => {
  let client, tools;
  before(async () => {
    client = new StdioMcpClient({ ...serverCommand(), env: { ...process.env, ECHELONGRAPH_API_BASE: "http://127.0.0.1:9" }, stderr: "ignore" });
    await client.open(MODERN);
    ({ tools } = await client.listTools());
  });
  after(() => client?.close());
  const hosted = () => (SERVER_JSON.remotes ?? []).some((r) => r.type === "streamable-http" && r.url === REMOTE);
  const privacySection = () => README.split(/^## Privacy: what is sent where$/m)[1]?.split(/^## /m)[0] ?? "";
  const privacy = () => privacySection().replace(/\s+/g, " ");
  // A denial that the document is sent, leaves the machine or reaches EchelonGraph is one of
  // document-denials.mjs's DENIALS, the list /pulse/mcp's check_sbom row is held to as well
  // (marketing-site/lib/mcpToolClaims.test.ts imports it). #2796's review found this check's own
  // list, kept here until then, passed most of the page's: "The server never sends the document.",
  // "The document is processed locally.", "Only the purls are sent.", "The document, once parsed, is
  // never sent." and others.
  //
  // One place in the section may deny it: the npm table's check_sbom cell, which says what the npm
  // package sends ("only the purls in it are sent; the document is not"), true of the npm package,
  // and qualifies that in its next sentence, NPM_QUALIFIER. Text before NPM_QUALIFIER in that one
  // cell is not read; everything else in the section is, each table cell and each paragraph as its
  // own text.
  const NPM_QUALIFIER = "(Over the hosted endpoint the document goes to EchelonGraph's server instead: see below.)";
  const units = (section) => {
    const out = [];
    for (const block of section.split(/\n\s*\n/)) {
      const lines = block.split("\n");
      const prose = lines.filter((l) => !l.trimStart().startsWith("|")).join(" ").replace(/\s+/g, " ").trim();
      if (prose) out.push(prose);
      for (const l of lines.filter((l) => l.trimStart().startsWith("|"))) {
        for (const cell of l.split("|").map((c) => c.replace(/\s+/g, " ").trim())) if (cell && !/^-+$/.test(cell)) out.push(cell);
      }
    }
    return out;
  };
  // The denials in a privacy section, and how many cells the NPM_QUALIFIER exception was taken in.
  const privacyDenials = (section) => {
    const u = units(section);
    let excepted = 0;
    const denials = u.flatMap((text, i) => {
      const at = text.indexOf(NPM_QUALIFIER);
      if (at < 0 || !u[i - 1]?.startsWith("`check_sbom`:")) return documentDenials(text);
      excepted++;
      return documentDenials(text.slice(at + NPM_QUALIFIER.length));
    });
    return { denials, excepted };
  };
  const entry = () => {
    const e = tools.find((t) => t.name === "check_sbom");
    assert.ok(e?.description, "tools/list has no check_sbom: re-aim this check");
    return e;
  };
  const description = () => entry().description;
  // #2796's third review: the sbom argument's description, served in the same tools/list entry,
  // said "its purls are read here and only they are sent", which the list counts as a denial, and
  // no check read it. Every string of the entry is read now: its description, title, and each
  // description of inputSchema and outputSchema, at any depth. [path (its keys), string] pairs.
  const strings = (v, at = [], out = []) => {
    if (typeof v === "string") out.push([at, v]);
    else if (v && typeof v === "object") for (const [k, x] of Object.entries(v)) strings(x, [...at, k], out);
    return out;
  };
  const entryDenials = (e) => strings(e).flatMap(([at, s]) => documentDenials(s).map((c) => `${at.join(".")}: ${c}`));
  // The README Tools table's check_sbom row: the What it answers cell names the document too
  // (#2796's third review found it said "…; the document is not." beside no guard).
  const toolsRow = (readme) => {
    const rows = (readme.split(/^## Tools$/m)[1]?.split(/^## /m)[0] ?? "").split("\n").filter((l) => l.startsWith("| `check_sbom` |"));
    assert.equal(rows.length, 1, "the README Tools table has no single check_sbom row: re-aim this check");
    return rows[0];
  };
  const rowDenials = (row) => row.split("|").flatMap((c) => documentDenials(c.replace(/\s+/g, " ").trim()));

  it("server.json lists the hosted streamable-http remote this check is about", () => {
    assert.ok(hosted(), `server.json lists no streamable-http remote at ${REMOTE}: re-aim this check`);
  });
  it("check_sbom's description says the hosted endpoint receives the document as the request body", () => {
    const d = description();
    assert.ok(d.includes("over the hosted endpoint (mcp.echelongraph.io) it is EchelonGraph's, and the document is the request body"), d);
    assert.deepEqual(documentDenials(d), [], d);
  });
  it("no string of check_sbom's tools/list entry denies it, and the sbom argument says where the document goes", () => {
    const e = entry();
    assert.ok(strings(e).length >= 50, `check_sbom's entry holds ${strings(e).length} strings: re-aim this check`);
    assert.deepEqual(entryDenials(e), []);
    const arg = e.inputSchema?.properties?.sbom?.description;
    assert.ok(arg, "check_sbom's inputSchema has no sbom description: re-aim this check");
    assert.ok(arg.includes("only they are sent to the API") && arg.includes("over the hosted endpoint (mcp.echelongraph.io) the document is the request body"), arg);
  });
  it("the README Tools table's check_sbom row says the hosted endpoint receives the document, and denies nothing", () => {
    const row = toolsRow(README);
    assert.ok(row.includes("over the hosted endpoint (`mcp.echelongraph.io`) it is EchelonGraph's, and the document is the request body"), row);
    assert.deepEqual(rowDenials(row), []);
  });
  it("control: a denial in any string of the entry, or in the Tools row, is caught", () => {
    const e = entry();
    const arg = e.inputSchema.properties.sbom.description;
    const OLD_ARG = "a CycloneDX JSON or SPDX JSON document, as JSON text or as an object; its purls are read here and only they are sent";
    const withArg = (s) => ({ ...e, inputSchema: { ...e.inputSchema, properties: { ...e.inputSchema.properties, sbom: { ...e.inputSchema.properties.sbom, description: s } } } });
    assert.notDeepEqual(entryDenials(withArg(OLD_ARG)), [], "the sbom argument's former words pass");
    // A string deep in outputSchema: the first description found under it.
    const deep = strings(e).find(([at]) => at[0] === "outputSchema" && at.length >= 4 && at.at(-1) === "description");
    assert.ok(deep, "check_sbom's outputSchema has no description: re-aim this control");
    const withDeep = (s) => {
      const c = structuredClone(e);
      let o = c;
      for (const k of deep[0].slice(0, -1)) o = o[k];
      o[deep[0].at(-1)] = `${deep[1]} ${s}`;
      return c;
    };
    const row = toolsRow(README);
    const ROW_ON = "; the document itself is not sent on.";
    assert.ok(row.includes(ROW_ON), "the Tools row's sentence changed: re-aim this control");
    assert.notDeepEqual(rowDenials(row.replace(ROW_ON, "; the document is not.")), [], "the Tools row's former words pass");
    for (const bad of DENIAL_VARIANTS) {
      assert.notDeepEqual(entryDenials(withArg(`${arg}; ${bad}`)), [], `the sbom argument passes: ${bad}`);
      assert.notDeepEqual(entryDenials(withDeep(bad)), [], `${deep[0].join(".")} passes: ${bad}`);
      assert.notDeepEqual(rowDenials(row.replace(ROW_ON, `; ${bad}`)), [], `the Tools row passes: ${bad}`);
    }
  });
  it("the README's privacy section says the document reaches EchelonGraph's server, which neither logs nor keeps it", () => {
    const p = privacy();
    assert.ok(p.length > 1000, "the README lost its \"## Privacy: what is sent where\" section: re-aim this check");
    assert.ok(p.includes("it is in the request body, so the whole document reaches EchelonGraph's server"), p);
    assert.ok(p.includes("and neither logs nor keeps the document"), p);
    const { denials, excepted } = privacyDenials(privacySection());
    assert.equal(excepted, 1, `the npm table's check_sbom cell no longer ends its npm-only sentence with ${NPM_QUALIFIER}: re-aim this check`);
    assert.deepEqual(denials, []);
  });
  it("control: every wording of the denial is caught, in the description and anywhere in the privacy section but the npm cell's qualified sentence", () => {
    const d = description();
    const section = privacySection();
    const ON = "; the document itself is not sent on.";
    const KEEP = "To keep the document on your machine, run the npm package, or pass `check_sbom` the purls.";
    // KEEP as the README wraps it: any run of whitespace between its words.
    const KEEP_AT = new RegExp(KEEP.split(" ").map((w) => w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(String.raw`\s+`));
    const npmCell = units(section).find((c) => c.includes(NPM_QUALIFIER));
    assert.ok(d.includes(ON) && KEEP_AT.test(section) && npmCell, "the sentences this control replaces changed: re-aim this control");
    for (const bad of DENIAL_VARIANTS) {
      assert.notDeepEqual(documentDenials(bad), [], `the shared list passes: ${bad}`);
      assert.notDeepEqual(documentDenials(d.replace(ON, `; ${bad}`)), [], `the description passes: ${bad}`);
      assert.notDeepEqual(privacyDenials(section.replace(KEEP_AT, () => bad)).denials, [], `the hosted paragraph passes: ${bad}`);
      assert.notDeepEqual(privacyDenials(section.replace(NPM_QUALIFIER, `${NPM_QUALIFIER} ${bad}`)).denials, [], `the npm cell, after its qualifier, passes: ${bad}`);
    }
    // The npm cell's own sentence is a denial everywhere but in that cell before its qualifier: in
    // the hosted paragraph, or in another row's cell with the qualifier copied in.
    const npmOnly = npmCell.slice(npmCell.indexOf("A CycloneDX"), npmCell.indexOf(NPM_QUALIFIER)).trim();
    assert.ok(npmOnly.endsWith("the document is not."), `the npm cell's sentence changed: ${npmOnly}`);
    assert.notDeepEqual(documentDenials(npmOnly), []);
    assert.notDeepEqual(privacyDenials(section.replace(KEEP_AT, () => npmOnly)).denials, []);
    assert.notDeepEqual(privacyDenials(section.replace("| No input. |", `| ${npmOnly} ${NPM_QUALIFIER} |`)).denials, []);
  });
  it("control: what both texts say truly passes, the npm package's own sentences among them", () => {
    for (const fine of [
      "To keep the document on your machine, run the npm package, or pass `check_sbom` the purls.",
      "The purls are read from the document by this MCP server and only they are sent to the API, in POST bodies of at most 200 purls each, one after another, never in a URL; the document itself is not sent on.",
      "the whole document reaches EchelonGraph's server, which reads the purls from it in memory, sends only those to the API, and neither logs nor keeps the document.",
      "Run from npm, this server is on your machine; over the hosted endpoint (mcp.echelongraph.io) it is EchelonGraph's, and the document is the request body, accepted up to 6 MiB.",
      "Its structured result carries coverage (what the input held, what was sent in how many batches, and what was not sent and why).",
      "not_sent_purls keeps its first 10, and the note says from which position of the input the purls not sent run.",
      "The npm package sends the purls to the API.",
      "Run from npm, the package sends purls, and only the purls are sent on to the API.",
      "Only the purls travel to EchelonGraph's API, never in a URL.",
      "The document itself is not sent on to the API.",
      "The document itself is not sent onward.",
      // The sbom argument's and the Tools row's words (#2796's third review)
      "a CycloneDX JSON or SPDX JSON document, as JSON text or as an object; its purls are read by this MCP server and only they are sent to the API; over the hosted endpoint (mcp.echelongraph.io) the document is the request body",
      "the purls are read from it by the MCP server and only they are sent to the API, in POST bodies of at most 200 each, one after another; the document itself is not sent on.",
      "Run from npm, the server is on your machine; over the hosted endpoint (`mcp.echelongraph.io`) it is EchelonGraph's, and the document is the request body.",
      // The README's own copy beside the widened rules: the GAP, "stays/remains in", any noun after
      // "leaves the", and more words before "purls"
      "The SBOM's purls are what was not sent, and they are listed.",
      "Pass the document to check_sbom (and, once more, the purls a rate limit or the time budget left unsent).",
      "The npm package sends only the distinct purls to the API.",
      // A leading \b: a word that ends in a noun of the document is not the document.
      "Your user profile is never sent.",
      "A tempfile is not uploaded.",
      // #2831's widened rules: purls-only and "make it to" with the API as where the purls go, a
      // POST that is the purls', and what the hosted server does with the document once read
      "Only the purls make it to the API.",
      "Nothing else is sent to the API.",
      "The purls are all that is sent to EchelonGraph's API.",
      "Only the purls are POSTed to the API, never in a URL.",
      "EchelonGraph's server reads the purls from it in memory and does not store the document.",
    ]) {
      assert.deepEqual(documentDenials(fine), [], fine);
    }
    assert.deepEqual(privacyDenials(privacySection()).denials, []);
  });

  // #2835: scan_manifest takes a project's files, which over the hosted endpoint are the request
  // body as check_sbom's document is: its tools/list entry and its README Tools row are held to the
  // same list (#2796, #2831, #2795), and each must say where the files go.
  const manifestEntry = () => {
    const e = tools.find((t) => t.name === "scan_manifest");
    assert.ok(e?.description, "tools/list has no scan_manifest: re-aim this check");
    return e;
  };
  const manifestRow = () => {
    const rows = (README.split(/^## Tools$/m)[1]?.split(/^## /m)[0] ?? "").split("\n").filter((l) => l.startsWith("| `scan_manifest` |"));
    assert.equal(rows.length, 1, "the README Tools table has no single scan_manifest row: re-aim this check");
    return rows[0];
  };
  const MANIFEST_HOSTED = "over the hosted endpoint (mcp.echelongraph.io) it is EchelonGraph's, and the files are the request body";
  it("#2835: scan_manifest's entry says the hosted endpoint receives the files as the request body, and no string of it denies they are sent", () => {
    const e = manifestEntry();
    assert.ok(e.description.includes(MANIFEST_HOSTED), e.description);
    assert.ok(e.inputSchema.properties.files.description.includes("over the hosted endpoint (mcp.echelongraph.io) the files are the request body"));
    assert.deepEqual(entryDenials(e), []);
  });
  it("#2835: the README Tools table's scan_manifest row says the same, and denies nothing", () => {
    const row = manifestRow();
    assert.ok(row.includes("over the hosted endpoint (`mcp.echelongraph.io`) it is EchelonGraph's, and the files are the request body"), row);
    assert.deepEqual(rowDenials(row), []);
  });
  it("#2835 control: a denial in scan_manifest's description, its files argument or its Tools row is caught", () => {
    const e = manifestEntry();
    const ON = "; filenames and file contents are not sent on.";
    assert.ok(e.description.includes(ON), "scan_manifest's sentence changed: re-aim this control");
    const row = manifestRow();
    const ROW_ON = "; filenames and file contents are not sent on.";
    assert.ok(row.includes(ROW_ON), "the Tools row's sentence changed: re-aim this control");
    for (const bad of [...DENIAL_VARIANTS, "the files never leave your machine.", "The lockfile is read locally."]) {
      assert.notDeepEqual(entryDenials({ ...e, description: e.description.replace(ON, `; ${bad}`) }), [], `the description passes: ${bad}`);
      assert.notDeepEqual(rowDenials(row.replace(ROW_ON, `; ${bad}`)), [], `the Tools row passes: ${bad}`);
    }
  });
});

// #2771: cve_summary leaves out a poller field the answer sends in another JSON type, and a poller
// that is neither a JSON object nor null, and relays the rest. Its review found three README
// sentences still saying a success's data is the API's JSON with exposure_radar the one exception,
// and that every outputSchema mismatch is unexpected_shape; and the cve_summary section calling a
// null poller "not a JSON object", which is kept as sent.
describe("README on cve_summary's left-out poller fields (#2771)", () => {
  const flat = README.replace(/\s+/g, " ");
  it("the cve_summary section says a poller of another type is left out whole, a null one aside", () => {
    assert.ok(flat.includes("a `poller` that is neither a JSON object nor null is left out whole; `summary` is relayed either way"), "the cve_summary section's left-out sentence changed");
    assert.ok(!flat.includes("a `poller` that is not a JSON object is left out whole"), "the cve_summary section calls a null poller not a JSON object");
    assert.ok(flat.includes("The tool relays the API's JSON as it was sent, less a `poller` field left out as above."));
  });
  it("the success shape names cve_summary among the exceptions to verbatim", () => {
    assert.ok(
      flat.includes(
        "The exceptions to verbatim are `cve_summary`, which leaves out a `poller` field the answer sends in a JSON type other than its outputSchema's (or a `poller` that is neither a JSON object nor null) and names it in the note, and `exposure_radar`:",
      ),
      "the success shape no longer names cve_summary as an exception to verbatim",
    );
    assert.ok(!flat.includes("The exception to verbatim is `exposure_radar`"), "the success shape names exposure_radar as the one exception");
  });
  it("the unexpected_shape sentence names cve_summary's poller as its exception", () => {
    assert.ok(
      flat.includes(
        "is returned as a failure with `error.kind` `unexpected_shape`, never relayed, with one exception: a `cve_summary` `poller` field of another JSON type is left out of `data` and named in the note, and the rest of the answer is relayed, `summary` with it.",
      ),
      "the unexpected_shape sentence lost cve_summary's exception",
    );
  });
});

// #2770: the Resources table names what echelongraph://sources relays for the NVD poller, its two
// counters as the one instance's, since it last started, never the feed's reliability.
describe("README Resources table (#2770)", () => {
  it("the echelongraph://sources row names interval, last_poll_at, poll_count and poll_errors, the counts as the one instance's", () => {
    const row = README.split("\n").find((l) => l.startsWith("| `echelongraph://sources` |"));
    assert.ok(row, "the README's Resources table has no echelongraph://sources row: re-aim this check");
    for (const f of ["interval", "last_poll_at", "poll_count", "poll_errors"]) assert.ok(row.includes(`\`${f}\``), `the row does not name ${f}: ${row}`);
    assert.match(row, /all of the one instance that answered/);
    assert.match(row, /the two counts are that instance's since it last started, zeroed on every restart, never the feed's reliability/);
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
