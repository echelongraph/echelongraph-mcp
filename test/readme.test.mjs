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
//   * the Resources table names what echelongraph://sources relays for the NVD poller (#2770), and
//     lists resources/list then resources/templates/list, whose lengths every prose count of
//     resources and of resource templates is (#2922);
//   * README.md fits under a ceiling below the 65,536 characters npm keeps of it, with its Privacy
//     and License sections, and the reference it moved to docs/ ships in the package, linked by
//     absolute GitHub URL, every link to a page and heading that exist (#3012);
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
import { PKG, PKG_DIR, serverCommand, readPkgFile, DOC_PAGES, readDocs } from "./server-under-test.mjs";
import { DENIAL_VARIANTS, documentDenials } from "./document-denials.mjs";
import { versioningClaims } from "./schema-openness.mjs";
import { HOSTED_ROLLING_OUT, WAIT_FOR_HEALTH } from "./barred-claims.mjs";

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
      // #3012: and so does every page of docs/, the reference the README links.
      for (const [page, text] of readDocs()) for (const m of text.matchAll(/\b(\d+) (?:read-only )?tools\b/g)) assert.equal(Number(m[1]), tools.length, `${page}: "${m[0]}"`);
      assert.ok(README.includes(`${tools.length} tools`), "the README no longer says how many tools there are");
    });
    // #3257: Versioning said each tool's `data` schema stays closed, while `data` was open at its
    // root for 14 of 16 tools and 86 objects below a success's root, in and outside `data`, were
    // closed. Its sentences on what is open and what is closed are now derived from tools/list
    // (schema-openness.mjs versioningClaims), so they cannot drift from the schemas again.
    // A claim may open a sentence or follow "Since 3.1.0, ", so its first letter is read either case.
    const says = (text, claim) => text.includes(claim) || text.includes(`${claim[0].toLowerCase()}${claim.slice(1)}`);
    it("#3257: Versioning says what tools/list's schemas leave open and closed, in the words derived from them", () => {
      const versioning = (README.split(/^## Versioning$/m)[1]?.split(/^## /m)[0] ?? "").replace(/\s+/g, " ");
      assert.ok(versioning, "the README has no Versioning section");
      for (const claim of versioningClaims(tools)) assert.ok(says(versioning, claim), `README Versioning lacks: ${claim}`);
      // #3268's review: the open-schema promise holds from the release that made it, not before:
      // 3.0.2 and older published success branches closed below the root and null-only slots.
      const [success] = versioningClaims(tools);
      assert.ok(versioning.includes(`Since 3.1.0, ${success[0].toLowerCase()}${success.slice(1)}`), `README Versioning does not anchor "${success}" to "Since 3.1.0"`);
      assert.match(versioning, /listed the tools under 3\.0\.2 or older must reconnect once/);
      assert.doesNotMatch(versioning, /`data` schema stays closed/);
      const log = readPkgFile("CHANGELOG.md").replace(/\s+/g, " ");
      assert.doesNotMatch(log, /each tool's `data` schema stay closed, so a field added inside `data` still needs a reconnect/, "CHANGELOG 3.0.2 still says data stays closed");
      for (const claim of versioningClaims(tools)) assert.ok(says(log, claim), `CHANGELOG lacks: ${claim}`);
    });
    // 3.1.0's phase A review: #2879 (3d4abb3f) typed eg_severity, eg_likelihood and eg_priority on
    // get_cve's data and search_cves' rows, and added componentsNote's sentences, and was the one
    // src change since 3.0.2 with no CHANGELOG bullet. The 3.1.0 section (Unreleased until the release
    // commit renamed it) names each component the two outputSchemas type, under #2879, and that the
    // change is additive.
    const release310 = () => {
      const log = readPkgFile("CHANGELOG.md");
      const at = log.search(/^## 3\.1\.0 — \d{4}-\d{2}-\d{2}$/m);
      const from = at >= 0 ? at : log.search(/^## Unreleased$/m);
      if (from < 0) return "";
      return (log.slice(from).split("\n").slice(1).join("\n").split(/^## /m)[0] ?? "").replace(/\s+/g, " ");
    };
    const componentsOf = (list) => {
      const out = new Set();
      for (const name of ["get_cve", "search_cves"]) {
        const t = list.find((x) => x.name === name);
        const ok = (t?.outputSchema?.oneOf ?? []).find((b) => b.properties?.state?.enum?.includes("measured"));
        const data = ok?.properties?.data;
        const props = name === "get_cve" ? data?.properties : data?.properties?.cves?.items?.properties;
        for (const k of Object.keys(props ?? {})) if (/^eg_/.test(k)) out.add(`${name}:${k}`);
      }
      return [...out];
    };
    const componentsProblems = (log, list) => {
      const found = componentsOf(list);
      const bullet = log.split(/ - \*\*/).find((b) => b.includes("(#2879)")) ?? "";
      return [
        ...(found.length ? [] : ["re-aim: neither outputSchema types an eg_ component"]),
        ...(bullet ? [] : ["no 3.1.0 bullet cites #2879"]),
        ...[...new Set(found.map((f) => f.split(":")[1]))].filter((k) => !bullet.includes(`\`${k}\``)).map((k) => `the #2879 bullet does not name ${k}`),
        ...(/additive/i.test(bullet) ? [] : ["the #2879 bullet does not say the change is additive"]),
      ];
    };
    // #2841: the 2.7.0 entry gave cve_remediation's CVE-2021-44228 text as "20,644 characters
    // (assembled before the route was deployed; re-measure live)". Measured live on 2026-10-18:
    // 22,571 characters on the hosted endpoint and on npm 3.0.2, 18,293 with an installed version.
    // No entry is left waiting for a measurement.
    it("#2841: the CHANGELOG holds no \"re-measure live\" placeholder, and 2.7.0's cve_remediation size is the live one", () => {
      const log = readPkgFile("CHANGELOG.md").replace(/\s+/g, " ");
      assert.doesNotMatch(log, /re-measure live/, "an entry still waits for a live measurement");
      const e270 = log.split("## 2.7.0 — ")[1]?.split(" ## ")[0] ?? "";
      assert.ok(e270.includes("measured live on 2026-10-18, 22,571 characters on the hosted endpoint and on npm 3.0.2, and 18,293 with an installed version"), e270.slice(e270.indexOf("New tool cve_remediation"), e270.indexOf("New tool cve_remediation") + 900));
    });
    // 3.1.0's phase C review (nit): the #3272 bullet's "only where one range a package does not fit
    // do references, then patches, then packages leave" did not parse. It reads "only where even one
    // range per package does not fit".
    const bullet3272 = (log) => log.split(/ - \*\*/).find((b) => b.startsWith("cve_remediation's first text block keeps every advisory")) ?? "";
    const capWhenProblems = (log) => {
      const b = bullet3272(log);
      if (!b) return ["no 3.1.0 bullet on cve_remediation's first text block (#3272)"];
      return [
        ...(b.includes("only where even one range per package does not fit do references, then patches, then packages leave") ? [] : ["the #3272 bullet does not say references, patches and packages leave only where even one range per package does not fit"]),
        ...(/one range a package does not fit/.test(b) ? ["the #3272 bullet still reads \"one range a package does not fit\""] : []),
      ];
    };
    it("3.1.0's phase C review: the #3272 bullet says when references, patches and packages leave, in a sentence that parses", () => {
      assert.deepEqual(capWhenProblems(release310()), []);
    });
    it("3.1.0's phase C review control: 0ee20f11's clause fails", () => {
      const log = release310();
      const old = log.replace("only where even one range per package does not fit", "only where one range a package does not fit");
      assert.notEqual(old, log, "re-aim this control: the clause is gone");
      assert.equal(capWhenProblems(old).length, 2, capWhenProblems(old).join("\n"));
    });
    it("3.1.0's phase A review: CHANGELOG 3.1.0 has a #2879 bullet naming each eg_ component get_cve and search_cves type, as additive", () => {
      assert.deepEqual(componentsOf(tools).sort(), ["get_cve:eg_likelihood", "get_cve:eg_priority", "get_cve:eg_severity", "search_cves:eg_likelihood", "search_cves:eg_priority", "search_cves:eg_severity"]);
      assert.deepEqual(componentsProblems(release310(), tools), []);
    });
    it("3.1.0's phase A review control: the 3.1.0 section without the #2879 bullet, or with one component unnamed, fails", () => {
      const log = release310();
      const bullet = log.split(/ - \*\*/).find((b) => b.includes("(#2879)"));
      assert.ok(bullet, "re-aim this control: no #2879 bullet");
      assert.deepEqual(componentsProblems(log.replace(bullet, ""), tools), ["no 3.1.0 bullet cites #2879", "the #2879 bullet does not name eg_severity", "the #2879 bullet does not name eg_likelihood", "the #2879 bullet does not name eg_priority", "the #2879 bullet does not say the change is additive"]);
      assert.deepEqual(componentsProblems(log.replace(bullet, bullet.replaceAll("`eg_priority`", "the priority")), tools), ["the #2879 bullet does not name eg_priority"]);
    });
    it("#3257 control: one tool's object re-closed, or one failure branch opened, changes the derived sentence, which the README then lacks", () => {
      const versioning = (README.split(/^## Versioning$/m)[1]?.split(/^## /m)[0] ?? "").replace(/\s+/g, " ");
      const edit = (name, f) => tools.map((t) => (t.name === name ? { ...t, outputSchema: f(structuredClone(t.outputSchema)) } : t));
      const success = (s) => s.oneOf.find((b) => b.properties.state.enum.includes("measured"));
      const failure = (s) => s.oneOf.find((b) => b.properties.state.enum.includes("failed"));
      const reclosed = versioningClaims(
        edit("exposure_radar", (s) => {
          success(s).properties.data.properties.kev_exposure.additionalProperties = false;
          return s;
        }),
      );
      assert.equal(reclosed[0], "A success's `outputSchema` is closed in 1 place: exposure_radar data.kev_exposure: additionalProperties false");
      assert.ok(!versioning.includes(reclosed[0]));
      const opened = versioningClaims(
        edit("get_cwe", (s) => {
          failure(s).additionalProperties = {};
          return s;
        }),
      );
      assert.equal(opened[1], "The failure branch admits fields it does not name: get_cwe (root): admits fields it does not name.");
      assert.ok(!versioning.includes(opened[1]));
      // #3268's review: a success slot put back to null alone, as 3.0.2 published it, is a closed place.
      const nullSlot = versioningClaims(
        edit("get_cwe", (s) => {
          success(s).properties.freshness = { type: "null" };
          return s;
        }),
      );
      assert.equal(nullSlot[0], "A success's `outputSchema` is closed in 1 place: get_cwe freshness: admits only null");
      assert.ok(!says(versioning, nullSlot[0]));
      // A fifth failure-branch enum opened changes the count the README gives.
      const fifth = versioningClaims(
        edit("get_cwe", (s) => {
          failure(s).properties.error.properties.kind = { anyOf: [failure(s).properties.error.properties.kind, { type: "string" }] };
          return s;
        }),
      );
      assert.match(fifth[1], /but five, which already accept any string/);
      assert.ok(!says(versioning, fifth[1]));
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

  // #3246: over README.md and every docs/ page (readDocs): #3012 moved the rate limits, which describe the hosted
  // endpoint, to docs/rate-limits.md, and this read the README alone. The patterns are barred-claims.mjs's, which
  // test/barred-claims.test.mjs holds on every other surface; WAIT_FOR_HEALTH reads through a URL's dots, which the
  // README-only pattern's [^.]* stopped at.
  const rolloutProblems = (pages) =>
    pages.flatMap(([page, text]) => [
      ...(HOSTED_ROLLING_OUT.test(text) ? [`${page} says the hosted endpoint is being rolled out`] : []),
      ...(WAIT_FOR_HEALTH.test(text.replace(/\s+/g, " ")) ? [`${page} tells readers to wait for /health`] : []),
    ]);
  it("no page of the package's documentation says the hosted endpoint is being rolled out, and the README names server.json's remote URL in its Remote section", () => {
    assert.deepEqual(rolloutProblems(readDocs()), []);
    assert.ok(remoteBlock().includes(REMOTE), `the Remote section does not name ${REMOTE}`);
    assert.match(remoteBlock(), /The hosted endpoint is in service/);
  });
  it("control (#3246): the rollout sentence on a docs/ page fails as it does on the README", () => {
    const docs = readDocs();
    assert.ok(docs.some(([p]) => p === "docs/rate-limits.md"), "docs/rate-limits.md is not read: re-aim this control");
    for (const target of ["README.md", "docs/rate-limits.md", "docs/exposure-radar.md"]) {
      const with_ = (s) => docs.map(([p, t]) => [p, p === target ? `${t}\n${s}\n` : t]);
      assert.deepEqual(rolloutProblems(with_("The hosted endpoint is being rolled out.")), [`${target} says the hosted endpoint is being rolled out`]);
      assert.deepEqual(rolloutProblems(with_("Use npx until https://mcp.echelongraph.io/health\nanswers.")), [`${target} tells readers to wait for /health`]);
    }
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
  // #3012: "How cve_summary reads its counts" moved to docs/tools.md, which the README links.
  const cveSummarySection = () => {
    const page = readPkgFile("docs/tools.md");
    const sec = page.split(/^## How `cve_summary` reads its counts$/m)[1]?.split(/^## /m)[0];
    assert.ok(sec, "docs/tools.md lost its \"How `cve_summary` reads its counts\" section: re-aim this check");
    return sec.replace(/\s+/g, " ");
  };
  it("the cve_summary section says a poller of another type is left out whole, a null one aside", () => {
    const sec = cveSummarySection();
    assert.ok(sec.includes("a `poller` that is neither a JSON object nor null is left out whole; `summary` is relayed either way"), "the cve_summary section's left-out sentence changed");
    for (const [page, text] of readDocs()) assert.ok(!text.replace(/\s+/g, " ").includes("a `poller` that is not a JSON object is left out whole"), `${page} calls a null poller not a JSON object`);
    assert.ok(sec.includes("The tool relays the API's JSON as it was sent, less a `poller` field left out as above."));
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
// The README's Prompts table and prose name exactly the prompts prompts/list answers, in its
// order (2026-10-06: 2.7.0 added workload_triage while the README kept saying "four prompts").
const NUMBER_WORDS = { one: 1, two: 2, three: 3, four: 4, five: 5, six: 6, seven: 7, eight: 8, nine: 9, ten: 10 };
function promptTable() {
  const section = README.split(/^## /m).find((s) => s.startsWith("Prompts"));
  assert.ok(section, "the README lost its ## Prompts section");
  assert.match(section, /^\| Prompt \| Arguments \| What it asks the model to do \|$/m, "the Prompts table lost its header");
  return [...section.matchAll(/^\| `([a-z_]+)` \| /gm)].map((m) => m[1]);
}
describe("README prompts equal prompts/list", () => {
  let client, prompts;
  before(async () => {
    client = new StdioMcpClient({ ...serverCommand(), env: { ...process.env, ECHELONGRAPH_API_BASE: "http://127.0.0.1:9" }, stderr: "ignore" });
    await client.open(MODERN);
    ({ prompts } = await client.listPrompts());
  });
  after(() => client?.close());
  it("the Prompts table lists exactly the prompts, in prompts/list order", () => {
    assert.deepEqual(promptTable(), prompts.map((p) => p.name));
  });
  it("every prose count of prompts equals prompts/list, and the intro names each one", () => {
    const counts = [...README.matchAll(/\b(\d+|one|two|three|four|five|six|seven|eight|nine|ten) prompts\b/gi)];
    assert.ok(counts.length > 0, "the README no longer says how many prompts there are");
    // #3012: the docs/ pages the README links are held to the same count.
    for (const [page, text] of readDocs()) {
      for (const m of text.matchAll(/\b(\d+|one|two|three|four|five|six|seven|eight|nine|ten) prompts\b/gi)) {
        const n = /^\d+$/.test(m[1]) ? Number(m[1]) : NUMBER_WORDS[m[1].toLowerCase()];
        assert.equal(n, prompts.length, `${page}: "${m[0]}"`);
      }
    }
    const intro = README.split("\n## ")[0];
    for (const p of prompts) assert.ok(intro.includes(`\`${p.name}\``), `the README's opening does not name the ${p.name} prompt`);
  });
});

describe("README Resources table (#2770)", () => {
  it("the echelongraph://sources row names interval, last_poll_at, poll_count and poll_errors, the counts as the one instance's", () => {
    const row = README.split("\n").find((l) => l.startsWith("| `echelongraph://sources` |"));
    assert.ok(row, "the README's Resources table has no echelongraph://sources row: re-aim this check");
    for (const f of ["interval", "last_poll_at", "poll_count", "poll_errors"]) assert.ok(row.includes(`\`${f}\``), `the row does not name ${f}: ${row}`);
    assert.match(row, /all of the one instance that answered/);
    assert.match(row, /the two counts are that instance's since it last started, zeroed on every restart, never the feed's reliability/);
  });
});

// #2922's last review (2026-10-11): the README said "three resources", counting the cve://{cve_id}
// template, which resources/list does not list; nothing held the count. A count of resources is
// held to resources/list and a count of resource templates to resources/templates/list, on every
// page of the package's documentation, and the Resources table lists both, in list order.
const countOf = (w) => (/^\d+$/.test(w) ? Number(w) : NUMBER_WORDS[w.toLowerCase()]);
const RESOURCE_COUNT = /\b(\d+|one|two|three|four|five|six|seven|eight|nine|ten) resources?\b(?! templates?\b)/gi;
const TEMPLATE_COUNT = /\b(\d+|one|two|three|four|five|six|seven|eight|nine|ten) resource templates?\b/gi;
function resourceCountProblems(pages, resources, templates) {
  const out = [];
  for (const [page, text] of pages) {
    const flat = text.replace(/\s+/g, " ");
    for (const m of flat.matchAll(RESOURCE_COUNT)) if (countOf(m[1]) !== resources) out.push(`${page}: "${m[0]}", and resources/list lists ${resources}`);
    for (const m of flat.matchAll(TEMPLATE_COUNT)) if (countOf(m[1]) !== templates) out.push(`${page}: "${m[0]}", and resources/templates/list lists ${templates}`);
  }
  return out;
}
describe("README resources and resource templates equal resources/list and resources/templates/list (#2922)", () => {
  let client, resources, templates;
  before(async () => {
    client = new StdioMcpClient({ ...serverCommand(), env: { ...process.env, ECHELONGRAPH_API_BASE: "http://127.0.0.1:9" }, stderr: "ignore" });
    await client.open(MODERN);
    ({ resources } = await client.listResources());
    ({ resourceTemplates: templates } = await client.listResourceTemplates());
  });
  after(() => client?.close());
  it("every prose count of resources and of resource templates is the server's, and the README states both", () => {
    assert.ok(resources.length > 0 && templates.length > 0, `resources/list ${resources.length}, resources/templates/list ${templates.length}: re-aim this check`);
    assert.deepEqual(resourceCountProblems(readDocs(), resources.length, templates.length), []);
    const flat = README.replace(/\s+/g, " ");
    assert.ok([...flat.matchAll(RESOURCE_COUNT)].length > 0, "the README no longer says how many resources there are");
    assert.ok([...flat.matchAll(TEMPLATE_COUNT)].length > 0, "the README no longer says how many resource templates there are");
  });
  it("control: \"three resources\", the count through 2.7.2, fails, and so does a template counted as a resource", () => {
    assert.notDeepEqual(resourceCountProblems([["c", "It also serves five prompts, and three resources (`echelongraph://methodology`, `echelongraph://sources` and `cve://{cve_id}`)."]], resources.length, templates.length), []);
    assert.notDeepEqual(resourceCountProblems([["c", "two resources and two resource templates"]], resources.length, templates.length), []);
    assert.deepEqual(resourceCountProblems([["c", "two resources (a and b) and one resource template (c)"]], 2, 1), []);
  });
  it("the Resources table lists the resources, then the resource templates, in list order", () => {
    const section = README.split(/^## Resources$/m)[1]?.split(/^## /m)[0] ?? "";
    assert.match(section, /^\| Resource \| What it holds \|$/m, "the Resources table lost its header: re-aim this check");
    const rows = [...section.matchAll(/^\| `([^`]+)` \| /gm)].map((m) => m[1]);
    assert.deepEqual(rows, [...resources.map((r) => r.uri), ...templates.map((t) => t.uriTemplate)]);
  });
});

// #3012: npm keeps the first 65,536 characters of a package's README (the 2.7.1 packument's readme
// was 65,536 characters, cut mid-sentence, with neither "## Privacy: what is sent where" nor
// "## License"; mcp-server/README.md was 85,417 then). The long reference moved to docs/*.md, which
// the package ships, and the README stays under a ceiling with room below npm's cut, keeping both
// headings. The ceiling counts characters and the cap is checked in UTF-8 bytes too, in case npm
// counts those.
const NPM_README_CAP = 65_536;
const README_CEILING = 62_000;
function npmReadmeProblems(text) {
  const out = [];
  if (text.length >= README_CEILING) out.push(`README.md is ${text.length} characters, at or past the ${README_CEILING} ceiling below npm's ${NPM_README_CAP}: move reference to docs/`);
  if (Buffer.byteLength(text) >= NPM_README_CAP) out.push(`README.md is ${Buffer.byteLength(text)} bytes, at or past npm's ${NPM_README_CAP}`);
  for (const h of ["## Privacy: what is sent where", "## License"]) {
    const at = text.search(new RegExp(`^${h.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`, "m"));
    if (at < 0) out.push(`README.md has no "${h}" heading`);
    else if (at >= Math.min(README_CEILING, NPM_README_CAP)) out.push(`README.md's "${h}" starts at character ${at}, past what npm keeps`);
  }
  return out;
}
const DOCS_URL = "https://github.com/echelongraph/echelongraph-mcp/blob/main/";
// GitHub's heading anchor: lower case, punctuation but - and _ dropped, each space a hyphen.
const slug = (heading) => heading.trim().toLowerCase().replace(/[^\p{L}\p{N}\s_-]/gu, "").replace(/\s/g, "-");
const anchorsOf = (md) => new Set([...md.matchAll(/^#{1,6} (.+)$/gm)].map((m) => slug(m[1])));
describe("README fits what npm keeps, and the reference it moved ships in docs/ (#3012)", () => {
  it("README.md is under the ceiling, in characters and bytes, and keeps its Privacy and License sections", () => {
    assert.deepEqual(npmReadmeProblems(README), []);
  });
  it("control: a README at npm's cap, or without the Privacy or the License heading, fails", () => {
    assert.ok(npmReadmeProblems(README + "x".repeat(Math.max(0, README_CEILING - README.length))).some((p) => p.includes("ceiling")));
    assert.ok(npmReadmeProblems("é".repeat(NPM_README_CAP / 2 + 1)).some((p) => p.includes("bytes")));
    assert.ok(npmReadmeProblems(README.replace(/^## License$/m, "## Licence")).some((p) => p.includes('"## License"')));
    assert.ok(npmReadmeProblems(README.replace(/^## Privacy: what is sent where$/m, "## Privacy")).some((p) => p.includes("Privacy")));
  });
  it("package.json ships docs/, which holds the pages the README moved there", () => {
    assert.ok(PKG.files.includes("docs"), "package.json files does not ship docs/, so the pages the README links are not in the package");
    assert.deepEqual(DOC_PAGES, ["docs/exposure-radar.md", "docs/rate-limits.md", "docs/structured-results.md", "docs/tools.md"]);
  });
  it("every docs/ link in the README is absolute, names a page that ships and a heading on it, and every page is linked", () => {
    assert.doesNotMatch(README, /\]\((?:\.\/)?docs\//, "a relative docs/ link: npm renders relative links poorly, so the README links docs/ by absolute URL");
    const links = [...README.matchAll(/https:\/\/github\.com\/echelongraph\/echelongraph-mcp\/blob\/main\/(docs\/[\w.-]+\.md)(?:#([\w-]+))?/g)];
    assert.ok(links.length >= DOC_PAGES.length, `${links.length} docs/ links`);
    for (const [url, page, anchor] of links) {
      assert.ok(url.startsWith(DOCS_URL));
      assert.ok(DOC_PAGES.includes(page), `${url}: ${page} is not a page the package ships`);
      if (anchor) assert.ok(anchorsOf(readPkgFile(page)).has(anchor), `${url}: ${page} has no heading #${anchor}`);
    }
    for (const p of DOC_PAGES) assert.ok(links.some(([, page]) => page === p), `${p} is not linked from the README`);
  });
  it("every relative link on a docs/ page names a file the package ships and a heading on it", () => {
    let n = 0;
    for (const page of DOC_PAGES) {
      for (const [, target, anchor] of readPkgFile(page).matchAll(/\]\(([^)#:\s]+)(?:#([\w-]+))?\)/g)) {
        n++;
        const file = path.posix.normalize(path.posix.join(path.posix.dirname(page), target));
        assert.ok(fs.existsSync(path.join(PKG_DIR, file)), `${page}: ${target} is not in the package`);
        if (anchor) assert.ok(anchorsOf(readPkgFile(file)).has(anchor), `${page}: ${file} has no heading #${anchor}`);
      }
    }
    assert.ok(n >= DOC_PAGES.length, `only ${n} relative links on the docs/ pages`);
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
  // #3018's review: the bullet on the hosted endpoint's Trivy scan said "scanned ... before each deploy", where only a
  // production deploy-all.sh run of mcp-remote (or all) scans, refusing only a HIGH or CRITICAL with a fixed version, with
  // MCP_REMOTE_SCAN_OK as its bypass, and its summary names the image config ID, not the registry digest a revision reports.
  // 3.1.0's final review (low): that check lived in infrastructure/cloudrun/deploy-all-mcp-scan.test.sh, a production
  // preflight of `deploy-all.sh mcp-remote` and `all`, and read the section of package.json's version first: a 3.1.1 whose
  // own bullet said "the deploy-time vulnerability scan moves to Trivy v0.76.0 (#3500)" failed it 6 ways and refused every
  // production `all`, core-backend included. The wording is the release's, so it is held here, to the section that
  // introduced the scan (3.1.0): no later section, released or not, is read.
  const SCAN_SECTION = /^## 3\.1\.0 — \d{4}-\d{2}-\d{2}$/m;
  const scanBullet = (log) => {
    const at = log.search(SCAN_SECTION);
    if (at < 0) return undefined;
    const section = log.slice(at).split("\n").slice(1).join("\n").split(/^## /m)[0];
    const b = section.split(/\n(?=- )/).find((x) => x.includes("Trivy") && x.includes("vulnerabilit"));
    return b === undefined ? undefined : b.replace(/\s+/g, " ");
  };
  const SCAN_SAYS = [
    ["the production deploy only", /production deploy/],
    ["deploy-all.sh", /deploy-all\.sh/],
    ["a HIGH or CRITICAL with a fixed version refused", /HIGH or CRITICAL[^.]*fixed version/],
    ["one with no fix not refused", /no fix(ed version)?[^.]*(not|named)/],
    ["the bypass, MCP_REMOTE_SCAN_OK=1", /MCP_REMOTE_SCAN_OK=1/],
    ["that the summary names the image config ID, not the registry digest", /config ID[^.]*not the registry digest/],
    // This review's item 3: another scanner than the pin only with a reason, labelled override; 0.69.4 to 0.69.6 refused.
    ["that another binary runs only with MCP_REMOTE_TRIVY_OVERRIDE_REASON, labelled mcp-trivy=override", /MCP_REMOTE_TRIVY_OVERRIDE_REASON[^.]*mcp-trivy=override/],
    ["that Trivy 0.69.4, 0.69.5 and 0.69.6 are refused", /Trivy 0\.69\.4, 0\.69\.5 or 0\.69\.6 \(the releases GHSA-69fq-xp46-6x23 names\) is refused/],
  ];
  const scanBulletProblems = (log) => {
    if (log.search(SCAN_SECTION) < 0) return ["no 3.1.0 section: re-aim this check"];
    const b = scanBullet(log);
    if (b === undefined) return ["no 3.1.0 bullet names the Trivy scan"];
    return [
      ...(b.includes("before each deploy") ? ["says the image is scanned before each deploy: only a production deploy-all.sh run of mcp-remote or all scans it"] : []),
      ...SCAN_SAYS.filter(([, rx]) => !rx.test(b)).map(([what]) => `does not say ${what}`),
    ];
  };
  it("3.1.0's bullet on the hosted endpoint's Trivy scan says what runs it, what it refuses, its bypass and its pin", () => {
    assert.deepEqual(scanBulletProblems(readPkgFile("CHANGELOG.md")), []);
  });
  it("control: the bullet as it read before fails; a later section's Trivy bullet (the review's 3.1.1) or a later Unreleased passes", () => {
    const log = readPkgFile("CHANGELOG.md");
    const b = log.slice(log.search(SCAN_SECTION)).split(/^## /m)[1]?.split(/\n(?=- )/).find((x) => x.includes("Trivy") && x.includes("vulnerabilit"));
    assert.ok(b, "re-aim this control: no 3.1.0 Trivy bullet");
    const OLD = "- Hosted endpoint only: the image is pinned. The hosted image is also scanned for\n  vulnerabilities (Trivy) before each deploy, which refuses a HIGH or CRITICAL with a fixed version.\n";
    assert.ok(scanBulletProblems(log.replace(b, OLD)).some((p) => p.includes("before each deploy")), "the old bullet passes");
    assert.deepEqual(scanBulletProblems(log.replace(b, "")), ["no 3.1.0 bullet names the Trivy scan"]);
    const top = log.search(SCAN_SECTION);
    for (const later of [
      "## 3.1.1 — 2026-10-25\n\n- Hosted endpoint only: the deploy-time vulnerability scan moves to Trivy v0.76.0 (#3500).\n\n",
      "## Unreleased\n\n- A later fix (#9999).\n\n",
      "## Unreleased\n\n",
    ]) {
      assert.deepEqual(scanBulletProblems(log.slice(0, top) + later + log.slice(top)), [], `a later section fails it: ${later.split("\n")[0]}`);
    }
  });
  // 3.1.0's final review (nit): the #2775 bullet said "A waiter holds at most the 64 KiB it read before it needed the
  // slot". src/http.ts readBodyHolding: a chunked body (no Content-Length) waits holding what it read past
  // MAX_BODY_BYTES, the chunk that crossed it included; readBody: a body that declares a Content-Length over it waits
  // before reading anything.
  const bullet2775 = (log) => {
    const at = log.search(/^## 3\.1\.0 — \d{4}-\d{2}-\d{2}$/m);
    if (at < 0) return "";
    const section = log.slice(at).split("\n").slice(1).join("\n").split(/^## /m)[0];
    return (section.split(/\n(?=- )/).find((b) => b.includes("(#2775)")) ?? "").replace(/\s+/g, " ");
  };
  const holdProblems = (log) => {
    const b = bullet2775(log);
    if (!b) return ["no 3.1.0 bullet cites #2775"];
    return [
      ...(b.includes("A body that declares its `Content-Length` waits holding nothing") ? [] : ["the #2775 bullet does not say a body with a Content-Length waits holding nothing"]),
      ...(b.includes("a chunked body (no `Content-Length`) waits holding at most the 64 KiB general cap (`MCP_MAX_BODY_BYTES`) plus the chunk that crossed it") ? [] : ["the #2775 bullet does not say a chunked body holds the general cap plus the chunk that crossed it"]),
      ...(/holds at most the 64 KiB it read/.test(b) ? ["the #2775 bullet still says a waiter holds at most the 64 KiB it read"] : []),
    ];
  };
  it("3.1.0's #2775 bullet says what a waiting body holds: nothing with a Content-Length, the cap plus one chunk without", () => {
    assert.deepEqual(holdProblems(readPkgFile("CHANGELOG.md")), []);
  });
  it("control: the #2775 bullet as it read at the 3.1.0 release commit fails", () => {
    const log = readPkgFile("CHANGELOG.md");
    const b = log.slice(log.search(/^## 3\.1\.0 — /m)).split(/\n(?=- )/).find((x) => x.includes("(#2775)"));
    assert.ok(b, "re-aim this control: no #2775 bullet");
    const at = b.search(/A body that\s+declares/);
    assert.ok(at >= 0, "re-aim this control: the bullet's holding sentence moved");
    const tail = b.slice(at);
    const old = log.replace(tail, "A waiter holds\n  at most the 64 KiB it read before it needed the slot, so memory stays bounded as before.\n");
    assert.equal(holdProblems(old).length, 3, holdProblems(old).join("\n"));
  });
  it("has an entry for package.json's version, and the README links it", () => {
    const log = readPkgFile("CHANGELOG.md");
    assert.match(log, new RegExp(`^## ${PKG.version.replace(/\./g, "\\.")} — \\d{4}-\\d{2}-\\d{2}$`, "m"));
    assert.ok(README.includes("(CHANGELOG.md)"));
    assert.ok(PKG.files.includes("CHANGELOG.md"), "CHANGELOG.md is not in package.json files, so npm does not ship it");
  });
});
