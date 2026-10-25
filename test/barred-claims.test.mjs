// #3246: #3010's "each radar refreshes on its own" and #2739's "the hosted endpoint is being rolled out" were held
// on the README alone, after #3012 had moved the exposure_radar and rate-limit reference to docs/*.md, which ships
// in the npm tarball and which npm's README links to. Measured on development 19f81a6a: either sentence appended to
// a docs/ page passed the whole suite (2081/2081). barred-claims.mjs keeps the wording; this file holds it on every
// text the package ships or serves:
//   * README.md and every docs/*.md page (readDocs, the DOC_PAGES listing), package.json's description and
//     keywords, server.json's title and description;
//   * what a client is served: the server instructions, every tool's title and description, every prompt's and
//     prompt argument's description, every prompt text (the snapshots prompts-resources.test.mjs holds equal to
//     prompts/get), every resource's and resource template's description, and the static resources' text;
//   * the directory listings (listings/, repo-only: npm does not pack them), whole files, since each is pasted.
// Each surface has a control: each barred sentence put on it fails.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { StdioMcpClient, MODERN } from "./mcp-stdio-client.mjs";
import { PKG, readDocs, readPkgFile, serverCommand } from "./server-under-test.mjs";
import { BARRED_SENTENCES, BOTH_STATES, barredClaimProblems } from "./barred-claims.mjs";

// Beside this file, not in PKG_DIR: an installed package (ECHELONGRAPH_MCP_BIN) has neither.
const HERE = path.dirname(fileURLToPath(import.meta.url));
const LISTINGS = path.join(HERE, "..", "listings");
const PROMPT_SNAPSHOTS = path.join(HERE, "fixtures", "prompts");
const textsOf = (dir, ext) =>
  fs.existsSync(dir)
    ? fs.readdirSync(dir, { recursive: true }).filter((f) => ext.some((e) => String(f).endsWith(e))).sort().map((f) => [path.join(path.basename(dir), String(f)), fs.readFileSync(path.join(dir, String(f)), "utf8")])
    : [];

/** The files the package ships or pastes, as [where, text]. */
function packageSurfaces() {
  const server = JSON.parse(readPkgFile("server.json"));
  return [
    ...readDocs(),
    ["package.json description", PKG.description],
    ["package.json keywords", PKG.keywords.join(" ")],
    ["server.json title", server.title],
    ["server.json description", server.description],
    ...textsOf(LISTINGS, [".md", ".json", ".yaml"]),
    ...textsOf(PROMPT_SNAPSHOTS, [".txt"]),
  ];
}
const problemsOf = (surfaces) => surfaces.flatMap(([where, text]) => barredClaimProblems(where, text));

describe("#3246: no text the package ships or serves says the radars refresh on their own, or that the hosted endpoint is being rolled out", () => {
  let client;
  const served = [];
  before(async () => {
    client = new StdioMcpClient({ ...serverCommand(), env: { ...process.env, ECHELONGRAPH_API_BASE: "http://127.0.0.1:9" }, stderr: "ignore" });
    await client.open(MODERN);
    served.push(["server instructions", client.opening.instructions]);
    for (const t of (await client.listTools()).tools) served.push([`${t.name} title`, t.title ?? ""], [`${t.name} description`, t.description]);
    for (const p of (await client.listPrompts()).prompts) {
      served.push([`prompt ${p.name}`, `${p.title ?? ""} ${p.description ?? ""}`]);
      for (const a of p.arguments ?? []) served.push([`prompt ${p.name}.${a.name}`, a.description ?? ""]);
    }
    for (const r of (await client.listResources()).resources) {
      served.push([`resource ${r.uri}`, `${r.title ?? ""} ${r.description ?? ""}`]);
      // Against a dead API base: what is served then is this package's own text and its failure notes.
      const read = await client.readResource({ uri: r.uri }).catch(() => undefined);
      for (const c of read?.contents ?? []) if (typeof c.text === "string") served.push([`resource ${r.uri} text`, c.text]);
    }
    for (const r of (await client.listResourceTemplates()).resourceTemplates) served.push([`resource template ${r.uriTemplate}`, `${r.title ?? ""} ${r.description ?? ""}`]);
  });
  after(() => client?.close());

  it("the package's files: README.md, every docs/ page, package.json, server.json, the listings and the prompt texts", () => {
    const surfaces = packageSurfaces();
    assert.ok(surfaces.some(([w]) => w === "docs/exposure-radar.md") && surfaces.some(([w]) => w === "docs/rate-limits.md"), "readDocs() lost the docs/ pages: re-aim this check");
    assert.ok(surfaces.filter(([w]) => w.startsWith("prompts/")).length >= 5, "no prompt snapshots read: re-aim this check");
    assert.deepEqual(problemsOf(surfaces), []);
    // The sentence that replaced #3010's is still the README's.
    assert.ok(readPkgFile("README.md").replace(/\s+/g, " ").includes(BOTH_STATES), `the README no longer says "${BOTH_STATES}"`);
  });

  it("what a client is served: the instructions, every tool, prompt and resource text", () => {
    assert.ok(served.length >= 40, `only ${served.length} served texts read`);
    assert.ok(served.some(([w]) => w === "exposure_radar description"), "exposure_radar's description was not read: re-aim this check");
    assert.ok(served.some(([w]) => / text$/.test(w)), "no static resource text was read: re-aim this check");
    assert.deepEqual(problemsOf(served), []);
  });

  it("control: each barred sentence put on a docs/ page, the README, a listing, a prompt text or the instructions fails, naming the surface", () => {
    const surfaces = packageSurfaces();
    const targets = ["docs/exposure-radar.md", "docs/rate-limits.md", "README.md", "prompts/triage_cve.txt", ...(fs.existsSync(LISTINGS) ? ["listings/README.md"] : [])];
    for (const where of targets) {
      const i = surfaces.findIndex(([w]) => w === where);
      assert.ok(i >= 0, `${where} is not among the surfaces read: re-aim this control`);
      for (const s of BARRED_SENTENCES) {
        const mutated = surfaces.map(([w, t], j) => [w, j === i ? `${t}\n\n${s}\n` : t]);
        const found = problemsOf(mutated);
        assert.equal(found.length, 1, `${where} saying "${s}" gives ${found.length} problems`);
        assert.ok(found[0].startsWith(where), found[0]);
      }
    }
    for (const s of BARRED_SENTENCES) {
      assert.equal(problemsOf([...served, ["server instructions", `${served[0][1]} ${s}`]]).length, 1, `the instructions saying "${s}" pass`);
    }
    // ... and what replaced them passes.
    assert.deepEqual(barredClaimProblems("c", `${BOTH_STATES}. The hosted endpoint is in service. Check https://mcp.echelongraph.io/health.`), []);
  });
});
