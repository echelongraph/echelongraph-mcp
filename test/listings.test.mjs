// Directory listings (#2723): the files that list this server in Smithery (an MCPB bundle's
// manifest), the Docker MCP Catalog (docker/mcp-registry drafts, local and remote, and the Dockerfile),
// Glama (glama.json), and the paste text in listings/README.md for the forms the founder fills in.
//
// What must hold:
//   * one source of truth: every listing carries server.json's description, and the manifest
//     package.json's version, so a release cannot leave a listing describing another version;
//   * our wording (#2304, #2706): no listing text makes a claim the package's own copy is barred
//     from (REMOVED_CLAIMS, read from tools.test.mjs so the two cannot drift), calls a service
//     count "hosts", or says "only" (read-only aside), and the public repository's GitHub topics
//     claim nothing comparative either (#2780, as package.json's keywords);
//   * the manifest names exactly the tools the server lists, with their titles, and declares
//     exactly the prompts it lists, with their descriptions and argument names, in both eras (#2922);
//   * every count of tools or prompts a listing surface states is tools/list's or prompts/list's,
//     and a surface that lists the tools lists them all (#2845);
//   * none of these files is published to npm.
//
// These are repo files: npm does not pack listings/, Dockerfile or glama.json, so a run inside an
// unpacked tarball has none to read and skips instead of failing.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { StdioMcpClient, MODERN } from "./mcp-stdio-client.mjs";
import { serverCommand } from "./server-under-test.mjs";

const REPO_PKG = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const LISTINGS = path.join(REPO_PKG, "listings");
const HAVE = fs.existsSync(LISTINGS);
const SKIP = HAVE ? false : "no listings/ here (npm does not pack it)";
const read = (rel) => fs.readFileSync(path.join(REPO_PKG, rel), "utf8");

// The wording patterns, taken from tools.test.mjs's own source so this file cannot drift from it:
// the barred claims, and (#2780's review) "only" as an exclusivity claim, "read-only" and "read
// only" aside since they say what the tools do, and the comparatives package.json's keywords are
// held to.
const toolsTestRegex = (name) => {
  const m = read("test/tools.test.mjs").match(new RegExp(`^const ${name} = \\/(.+)\\/([a-z]*);$`, "m"));
  assert.ok(m, `tools.test.mjs no longer declares ${name} as a regex literal: re-aim this check`);
  return new RegExp(m[1], m[2]);
};
const REMOVED_CLAIMS = toolsTestRegex("REMOVED_CLAIMS");
const HOST_UNIT = /\bhosts\b|\bhost\(s\)/i;
const ONLY = toolsTestRegex("ONLY");
const COMPARATIVE = toolsTestRegex("COMPARATIVE");
// GitHub topics are slugs, so each is read as written and with its hyphens as spaces, as
// tools.test.mjs reads package.json's keywords: "no-other-source" is "no other source".
const topicsText = (ts) => `${ts.join(" ")} / ${ts.join(" ").replace(/-/g, " ")}`;
const topicProblems = (ts) => {
  const text = topicsText(ts);
  const out = wordingProblems("github-repo-settings.json topics", text);
  const m = text.match(COMPARATIVE);
  if (m) out.push(`github-repo-settings.json topics: a comparative or superlative claim: "${m[0]}" in: ${text}`);
  return out;
};

const wordingProblems = (where, text) => {
  const out = [];
  for (const [re, why] of [[REMOVED_CLAIMS, "a barred claim (REMOVED_CLAIMS)"], [HOST_UNIT, "a service count called hosts"], [ONLY, '"only"']]) {
    const m = text.match(re);
    if (m) out.push(`${where}: ${why}: "${m[0]}" in: ${text.slice(Math.max(0, m.index - 60), m.index + 60).replace(/\s+/g, " ")}`);
  }
  return out;
};

// The fenced ```text blocks of listings/README.md: what the founder pastes into a form.
const pasteBlocks = () => [...read("listings/README.md").matchAll(/^```text\n([\s\S]*?)^```$/gm)].map((m) => m[1]);

// A top-level or nested scalar from the flat server.yaml draft, without a YAML dependency.
const yamlScalar = (text, key) => {
  const m = text.match(new RegExp(`^\\s*${key}:\\s*(.+)$`, "m"));
  return m ? m[1].trim() : undefined;
};

describe("directory listings (#2723)", { skip: SKIP }, () => {
  const pkg = HAVE ? JSON.parse(read("package.json")) : {};
  const serverJson = HAVE ? JSON.parse(read("server.json")) : {};
  const manifest = HAVE ? JSON.parse(read("listings/mcpb/manifest.json")) : {};
  const dockerYaml = HAVE ? read("listings/docker/server.yaml") : "";

  it("the MCPB manifest is at package.json's version and carries server.json's description and title", () => {
    assert.equal(manifest.version, pkg.version, "listings/mcpb/manifest.json version: bump it with package.json");
    assert.equal(manifest.name, pkg.name);
    assert.equal(manifest.description, serverJson.description);
    assert.equal(manifest.display_name, serverJson.title);
    assert.equal(manifest.license, pkg.license);
    assert.equal(manifest.repository?.url, serverJson.repository.url);
    assert.equal(manifest.homepage, serverJson.websiteUrl);
    assert.equal(manifest.server?.entry_point, pkg.bin["echelongraph-mcp"]);
    assert.deepEqual(manifest.server?.mcp_config?.args, [`\${__dirname}/${pkg.bin["echelongraph-mcp"]}`]);
    assert.equal(manifest.compatibility?.runtimes?.node, pkg.engines.node);
    assert.ok(fs.existsSync(path.join(LISTINGS, "mcpb", manifest.icon)), `the manifest's icon ${manifest.icon} is not in listings/mcpb/`);
  });

  it("the Docker catalog draft carries server.json's title, description and repository", () => {
    assert.equal(yamlScalar(dockerYaml, "title"), serverJson.title);
    assert.equal(yamlScalar(dockerYaml, "description"), serverJson.description);
    assert.equal(yamlScalar(dockerYaml, "project"), serverJson.repository.url);
    assert.match(dockerYaml, /^\s*-\s*app\.echelongraph\.io:443$/m, "allowHosts names the default API host");
    // docker/mcp-registry's validator refuses a local server whose source.commit is not a 40-hex SHA.
    assert.match(yamlScalar(dockerYaml, "commit") ?? "", /^[0-9a-f]{40}$/, "source.commit must be a public commit's full SHA");
    assert.doesNotMatch(dockerYaml, /^\s*#/m, "the draft is copied verbatim into docker/mcp-registry: no comments");
  });

  // The remote entry: servers/echelongraph-remote/{server.yaml,tools.json,readme.md} in the
  // registry, as its keyless remote entries are (excalidraw-remote): dynamic tools, tools.json [].
  it("the Docker remote draft carries server.json's title, description and remote URL", () => {
    const remoteYaml = read("listings/docker/remote/server.yaml");
    assert.equal(yamlScalar(remoteYaml, "name"), "echelongraph-remote");
    assert.equal(yamlScalar(remoteYaml, "type"), "remote");
    assert.equal(yamlScalar(remoteYaml, "title"), serverJson.title);
    assert.equal(yamlScalar(remoteYaml, "description"), serverJson.description);
    assert.equal(yamlScalar(remoteYaml, "transport_type"), serverJson.remotes[0].type);
    assert.equal(yamlScalar(remoteYaml, "url"), serverJson.remotes[0].url);
    assert.match(remoteYaml, /^dynamic:\n {2}tools: true$/m, "keyless remote: tools are discovered from the server");
    assert.doesNotMatch(remoteYaml, /^(oauth|config|source):/m, "keyless: no OAuth, no secrets, no source");
    assert.deepEqual(JSON.parse(read("listings/docker/remote/tools.json")), []);
    assert.match(read("listings/docker/remote/readme.md"), /^Docs: https:\/\/\S+\n$/);
    assert.deepEqual(wordingProblems("docker/remote/server.yaml description", yamlScalar(remoteYaml, "description")), []);
  });

  it("glama.json names at least one maintainer against Glama's schema", () => {
    const g = JSON.parse(read("glama.json"));
    assert.equal(g.$schema, "https://glama.ai/mcp/schemas/server.json");
    assert.ok(Array.isArray(g.maintainers) && g.maintainers.length > 0);
    for (const u of g.maintainers) assert.match(u, /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/, `not a GitHub username: ${u}`);
    assert.deepEqual(Object.keys(g).sort(), ["$schema", "maintainers"], "a key Glama's schema does not define");
  });

  it("every paste block carries our wording, and the README pastes server.json's description verbatim", () => {
    const blocks = pasteBlocks();
    assert.ok(blocks.length >= 5, `found ${blocks.length} paste blocks in listings/README.md`);
    assert.ok(blocks.some((b) => b.trim() === serverJson.description), "no paste block is server.json's description verbatim");
    assert.ok(blocks.some((b) => b.trim() === serverJson.title), "no paste block is server.json's title verbatim");
    const bad = blocks.flatMap((b, i) => wordingProblems(`listings/README.md paste block ${i + 1}`, b));
    assert.deepEqual(bad, []);
  });

  it("the manifest and the Docker draft carry our wording", () => {
    const bad = [
      ...wordingProblems("manifest.json description", manifest.description),
      ...wordingProblems("manifest.json long_description", manifest.long_description),
      ...wordingProblems("docker/server.yaml description", yamlScalar(dockerYaml, "description")),
    ];
    assert.deepEqual(bad, []);
  });

  it("control: the wording check catches #2706's sentence and an exclusivity claim, and passes read-only", () => {
    assert.ok(wordingProblems("c", "MCP server for querying live CISA KEV, EPSS, and enriched vulnerability feeds").length);
    assert.ok(wordingProblems("c", "The only free CVE exposure source.").length);
    assert.ok(wordingProblems("c", "1,204 exposed hosts").length);
    assert.deepEqual(wordingProblems("c", "Free and keyless: no API key, no auth, read-only."), []);
  });

  // The public repo's About box: what the orchestrator applies with gh api (listings/README.md,
  // "Public repo settings"). GitHub's limits: a description up to 350 characters; at most 20
  // topics, each lowercase letters, digits and hyphens, up to 50 characters, starting with a
  // letter or digit.
  it("github-repo-settings.json carries our wording, server.json's homepage and valid GitHub topics", () => {
    const gs = JSON.parse(read("listings/github-repo-settings.json"));
    assert.equal(gs.repository, new URL(serverJson.repository.url).pathname.slice(1));
    assert.equal(gs.homepage, serverJson.websiteUrl);
    assert.ok(gs.description.length <= 350, `${gs.description.length} chars`);
    assert.deepEqual(wordingProblems("github-repo-settings.json description", gs.description), []);
    assert.match(gs.description, /Shodan data \(© Shodan\)/, "the description names Shodan without its ownership");
    assert.ok(Array.isArray(gs.topics) && gs.topics.length > 0 && gs.topics.length <= 20, `${gs.topics?.length} topics`);
    for (const t of gs.topics) assert.match(t, /^[a-z0-9][a-z0-9-]{0,49}$/, `not a GitHub topic: ${t}`);
    assert.equal(new Set(gs.topics).size, gs.topics.length, "a topic is listed twice");
    assert.deepEqual(Object.keys(gs).sort(), ["description", "homepage", "repository", "topics"]);
    // #2780's review: topics are the repository's keywords, held to the same wording as npm's.
    assert.deepEqual(topicProblems(gs.topics), []);
  });

  it("control: the topics check catches a barred, exclusive or comparative topic, and passes read-only", () => {
    const gs = JSON.parse(read("listings/github-repo-settings.json"));
    for (const bad of ["real-time", "realtime", "live-exploits", "the-only-free-cve-api", "best-cve-api", "fastest-cve-lookup", "exposed-hosts", "no-other-source", "unique-exposure-data"]) {
      assert.notDeepEqual(topicProblems([...gs.topics, bad]), [], `the topic ${bad} passes`);
    }
    assert.deepEqual(topicProblems(["read-only", ...gs.topics]), []);
  });

  it("the long description fits the Anthropic directory's 2,000 characters and the one-liner its 200", () => {
    assert.ok(manifest.long_description.length <= 2000, `${manifest.long_description.length} chars`);
    assert.ok(serverJson.description.length <= 200);
  });

  it("npm does not publish the listing files", () => {
    // #3012: docs/ holds the README's reference pages, which npm must ship: the README links them.
    for (const f of pkg.files) assert.ok(["dist", "docs", "README.md", "CHANGELOG.md", "server.json"].includes(f), `package.json files gained ${f}: check it publishes no listing file`);
    const [packed] = JSON.parse(execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], { cwd: REPO_PKG, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }));
    const paths = packed.files.map((f) => f.path);
    const leaked = paths.filter((p) => /^(listings\/|Dockerfile(\.http)?$|\.dockerignore$|glama\.json$)/.test(p));
    assert.deepEqual(leaked, []);
    // docs/ ships Markdown pages and nothing else, so it cannot carry a listing file in.
    const docs = paths.filter((p) => p.startsWith("docs/"));
    assert.ok(docs.length >= 4, `npm packs ${docs.length} docs/ pages`);
    assert.deepEqual(docs.filter((p) => !/^docs\/[a-z0-9-]+\.md$/.test(p)), []);
  });

  for (const era of [MODERN, "2025-06-18"]) {
    describe(`the manifest's tools are the server's tools [${era}]`, () => {
      let client, tools, prompts;
      before(async () => {
        client = new StdioMcpClient({ ...serverCommand(), env: { ...process.env, ECHELONGRAPH_API_BASE: "http://127.0.0.1:9" }, stderr: "ignore" });
        await client.open(era);
        ({ tools } = await client.listTools());
        ({ prompts } = await client.listPrompts());
      });
      after(() => client?.close());
      it("same names, in order, each described by the tool's title", () => {
        assert.deepEqual(manifest.tools, tools.map((t) => ({ name: t.name, description: t.title })));
      });
      // #2922's last review: the manifest listed 0 prompts. MCPB v0.3 (the $schema it names, which
      // build.sh's pinned CLI validates) declares each prompt as name, description, arguments (their
      // names) and text, the prompt text with ${arguments.<name>} placeholders. The server's
      // prompts/get answers with the full text (test/prompts-resources.test.mjs snapshots it); the
      // manifest's text is the short form the schema requires.
      it("#2922: the manifest declares the server's prompts: same names, in order, each with its description and argument names", () => {
        assert.ok(prompts.length > 0, "prompts/list is empty: re-aim this check");
        assert.deepEqual(
          (manifest.prompts ?? []).map(({ name, description, arguments: args }) => ({ name, description, arguments: args })),
          prompts.map((p) => ({ name: p.name, description: p.description, arguments: (p.arguments ?? []).map((a) => a.name) })),
        );
      });
      it("#2922: each manifest prompt's text has a placeholder for each of its arguments and no other, names only the server's tools, and carries our wording", () => {
        const toolNames = new Set(tools.map((t) => t.name));
        for (const p of manifest.prompts) {
          assert.deepEqual(Object.keys(p).sort(), ["arguments", "description", "name", "text"], `${p.name}: a key MCPB v0.3's prompts schema does not define`);
          const placeholders = [...new Set([...p.text.matchAll(/\$\{([^}]*)\}/g)].map((m) => m[1]))].sort();
          assert.deepEqual(placeholders, p.arguments.map((a) => `arguments.${a}`).sort(), `${p.name}: its text's placeholders are not its arguments`);
          // A word shaped like one of the server's tool names (get_, search_, check_, scan_, cve_,
          // kev_, epss_, exposure_, vendor_) is one of them.
          const named = [...new Set(p.text.replace(/\$\{[^}]*\}/g, " ").match(/\b(?:get|search|check|scan|cve|kev|epss|exposure|vendor)(?:_[a-z]+)+\b/g) ?? [])];
          assert.ok(named.length > 0, `${p.name}: its text names no tool`);
          for (const w of named) assert.ok(toolNames.has(w), `${p.name}: its text names ${w}, which is not a tool the server lists`);
          assert.deepEqual(wordingProblems(`manifest.json prompt ${p.name}`, `${p.description} ${p.text}`), []);
        }
      });
      it("every tool has the title and readOnlyHint the Anthropic directory requires", () => {
        for (const t of tools) {
          assert.ok(t.title, `${t.name} has no title`);
          assert.equal(t.annotations?.readOnlyHint, true, `${t.name} readOnlyHint`);
        }
      });
    });
  }
});

// #2845: every count of tools or prompts that a listing surface states, the paste blocks of
// listings/README.md (what the founder pastes into a directory's form), the public repo's About
// description (github-repo-settings.json), the MCPB manifest's descriptions and the Docker drafts,
// is tools/list's or prompts/list's length; and a surface that lists the tools by name (three or
// more of them) lists every one. The 2026-10-11 review found that 14 in github-repo-settings.json
// passed every test here. The listing README's dated records ("Smithery's scan read 2.6.4 with 14
// tools") are not paste blocks and say when they were read.
const COUNT_NUMBER = "\\d+|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty";
const COUNT_WORDS = Object.fromEntries(COUNT_NUMBER.split("|").slice(1).map((w, i) => [w, i + 1]));
const TOOL_COUNTS = [new RegExp(`\\b(${COUNT_NUMBER}) (?:(?:read-only|new|MCP|more|keyless)\\s+)*tools\\b`, "gi"), /\bTools \((\d+)\b/g];
const PROMPT_COUNTS = [new RegExp(`\\b(${COUNT_NUMBER}) (?:(?:new|MCP|more)\\s+)*prompts\\b`, "gi")];
function countProblems(where, text, toolNames, promptCount) {
  const flat = text.replace(/\s+/g, " ");
  const n = (w) => (/^\d+$/.test(w) ? Number(w) : COUNT_WORDS[w.toLowerCase()]);
  const out = [];
  let stated = 0;
  for (const [res, want, what] of [[TOOL_COUNTS, toolNames.length, "tools/list"], [PROMPT_COUNTS, promptCount, "prompts/list"]]) {
    for (const re of res) {
      for (const m of flat.matchAll(re)) {
        stated++;
        if (n(m[1]) !== want) out.push(`${where}: "${m[0]}", and ${what} lists ${want}`);
      }
    }
  }
  const named = toolNames.filter((t) => new RegExp(`\\b${t}\\b`).test(flat));
  if (named.length >= 3 && named.length < toolNames.length) out.push(`${where}: lists ${named.length} of the ${toolNames.length} tools, without ${toolNames.filter((t) => !named.includes(t)).join(", ")}`);
  return { out, stated };
}
describe("listing counts equal tools/list and prompts/list (#2845)", { skip: SKIP }, () => {
  let client, toolNames, promptCount;
  before(async () => {
    client = new StdioMcpClient({ ...serverCommand(), env: { ...process.env, ECHELONGRAPH_API_BASE: "http://127.0.0.1:9" }, stderr: "ignore" });
    await client.open(MODERN);
    toolNames = (await client.listTools()).tools.map((t) => t.name);
    promptCount = (await client.listPrompts()).prompts.length;
  });
  after(() => client?.close());
  // Every surface a count can sit on, as [where, text].
  const surfaces = () => {
    const manifest = JSON.parse(read("listings/mcpb/manifest.json"));
    return [
      ...pasteBlocks().map((b, i) => [`listings/README.md paste block ${i + 1}`, b]),
      ["github-repo-settings.json description", JSON.parse(read("listings/github-repo-settings.json")).description],
      ["manifest.json description", manifest.description],
      ["manifest.json long_description", manifest.long_description],
      ["docker/server.yaml description", yamlScalar(read("listings/docker/server.yaml"), "description")],
      ["docker/remote/server.yaml description", yamlScalar(read("listings/docker/remote/server.yaml"), "description")],
      ["docker/remote/readme.md", read("listings/docker/remote/readme.md")],
    ];
  };
  const problems = (list) => {
    const all = list.map(([where, text]) => countProblems(where, text, toolNames, promptCount));
    return { out: all.flatMap((r) => r.out), stated: all.reduce((s, r) => s + r.stated, 0) };
  };
  it("every count of tools or prompts a listing surface states is the server's, and a surface that lists tools lists them all", () => {
    const { out, stated } = problems(surfaces());
    assert.deepEqual(out, []);
    // Not vacuous: the long description, the mcp.so issue, both Docker PR bodies and the About box
    // each state the count.
    assert.ok(stated >= 6, `only ${stated} counts found on the listing surfaces: re-aim this check`);
  });
  it("control: 14 in github-repo-settings.json (the review's mutant), a stale paste block count, a list missing a tool, and four prompts each fail, naming the surface", () => {
    const list = surfaces();
    const at = (where) => list.findIndex(([w]) => w === where);
    const mutate = (where, f) => list.map(([w, t]) => [w, w === where ? f(t) : t]);
    const about = "github-repo-settings.json description";
    assert.ok(at(about) >= 0 && list[at(about)][1].includes(`${toolNames.length} read-only tools`), "the About description no longer states the count this control changes: re-aim it");
    assert.ok(problems(mutate(about, (t) => t.replace(`${toolNames.length} read-only tools`, "14 read-only tools"))).out.some((p) => p.startsWith(`${about}: "14 read-only tools"`)));
    const long = list.find(([, t]) => t.startsWith("CVE and internet-exposure data") && t.includes("read-only tools:"));
    assert.ok(long, "the long description paste block is gone: re-aim this control");
    assert.ok(problems(mutate(long[0], (t) => t.replace(`${toolNames.length} read-only tools`, "15 read-only tools"))).out.some((p) => p.startsWith(`${long[0]}: "15 read-only tools"`)));
    assert.ok(problems(mutate(long[0], (t) => t.replace(/ cve_remediation \([^)]*\),/, ""))).out.some((p) => p.includes("without cve_remediation")));
    assert.ok(problems([["c", "It serves 16 tools and four prompts."]]).out.some((p) => p.includes('"four prompts"')));
    assert.ok(problems([["c", "Tools (14, all read-only): a, b."]]).out.some((p) => p.includes('"Tools (14"')));
  });
});

// Smithery's "Link to Smithery" verification check scans this README (served from the public repo) for a
// link to the server's page (#2723, 2026-10-05). Removing the line un-verifies the listing with no other
// signal, so it is pinned here, with Glama beside it.
describe("README links the directories that list us", () => {
  it("links the Smithery server page and the Glama listing", () => {
    const readme = read("README.md");
    assert.ok(readme.includes("(https://smithery.ai/servers/echelongraph/echelongraph-mcp)"), "README lost the Smithery backlink that Smithery's verification looks for");
    assert.ok(readme.includes("(https://glama.ai/mcp/servers/echelongraph/echelongraph-mcp)"), "README lost the Glama link");
  });
});

// The Anthropic directory steps (#2797 review): a privacy paragraph was once spliced into the middle of
// "automatically", deleting the escalation address and leaving a fragment of the old paragraph behind,
// and every other check here passed. This pins the sentence and the paragraph, and catches the shape
// of a splice anywhere in the file: a word running straight into bold text, or a closing ".)" with a
// word glued to it.
describe("listings/README.md is not spliced", { skip: SKIP }, () => {
  it("keeps the After submitting sentence, its escalation address and the privacy paragraph", () => {
    const text = read("listings/README.md");
    const flat = text.replace(/\s+/g, " ");
    assert.ok(flat.includes('After submitting: "Anthropic scans your submission automatically for policy compliance and, by default, lists it as a Community connector". Escalations: `mcp-review@anthropic.com`.'), "the After submitting sentence or its escalation address is gone");
    assert.match(text, /^\*\*Privacy policy\.\*\* Give https:\/\/echelongraph\.io\/privacy as the privacy policy URL\./m, "the Privacy policy paragraph no longer starts its own line");
  });
  it("has no word fused into bold text and nothing glued after a closing parenthesis", () => {
    const lines = read("listings/README.md").split("\n");
    const bad = lines.map((l, i) => [i + 1, l]).filter(([, l]) => /[a-z]\*\*[A-Z]/.test(l) || /\.\)[A-Za-z]/.test(l));
    assert.deepEqual(bad, [], `spliced lines in listings/README.md: ${bad.map(([n, l]) => `${n}: ${l}`).join(" | ")}`);
  });
});
