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
//   * the manifest names exactly the tools the server lists, with their titles, in both eras;
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
    for (const f of pkg.files) assert.ok(["dist", "README.md", "CHANGELOG.md", "server.json"].includes(f), `package.json files gained ${f}: check it publishes no listing file`);
    const [packed] = JSON.parse(execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], { cwd: REPO_PKG, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }));
    const leaked = packed.files.map((f) => f.path).filter((p) => /^(listings\/|Dockerfile(\.http)?$|\.dockerignore$|glama\.json$)/.test(p));
    assert.deepEqual(leaked, []);
  });

  for (const era of [MODERN, "2025-06-18"]) {
    describe(`the manifest's tools are the server's tools [${era}]`, () => {
      let client, tools;
      before(async () => {
        client = new StdioMcpClient({ ...serverCommand(), env: { ...process.env, ECHELONGRAPH_API_BASE: "http://127.0.0.1:9" }, stderr: "ignore" });
        await client.open(era);
        ({ tools } = await client.listTools());
      });
      after(() => client?.close());
      it("same names, in order, each described by the tool's title", () => {
        assert.deepEqual(manifest.tools, tools.map((t) => ({ name: t.name, description: t.title })));
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
