// #3018: the hosted endpoint's image (Dockerfile.http) is built on a base pinned by digest, the one
// the stdio image (Dockerfile) pins.
//
// Dockerfile.http built both its stages FROM node:22-alpine, a moving tag, so two deploys of one
// commit could ship different base images with no record of the difference, while Dockerfile pinned
// node:22.23.3-alpine3.24@sha256:0a7108bf…. Every FROM of both files must now name an image by a
// sha256 digest (an ARG's default is read where a FROM uses one), and the two files one base: the
// stdio image and the hosted one are the same server, and a base moved in one is moved in both.
// deploy-all.sh's Trivy scan (#3018) refuses a base with a fixed HIGH or CRITICAL; the remedy is a
// new digest here.
//
// #3345: a fixed HIGH in a tool the base bundles but the image never runs has another remedy: the
// 3.1.0 image's 13 fixable HIGH included 10 in the base's own npm (pacote, sigstore, ip-address,
// brace-expansion, picomatch), and Dockerfile.http's runtime stage now removes npm, npx and
// corepack, which nothing in that stage runs (the last describe below holds it).
//
// Dockerfile.http is not in the npm package: where it is absent (the packed tarball's run) this is
// skipped and says why.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PKG = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const HTTP = path.join(PKG, "Dockerfile.http");
const STDIO = path.join(PKG, "Dockerfile");
const skip = !fs.existsSync(HTTP) || !fs.existsSync(STDIO) ? "Dockerfile.http or Dockerfile is not here (the npm package carries neither)" : false;

const PINNED = /^[a-z0-9][a-z0-9._/-]*(?::[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$/;

// Each FROM of a Dockerfile: the image it names (an ARG default substituted), and whether it is an
// earlier stage. Comment and continuation handling as docker reads them; a FROM it cannot resolve
// is returned as written, so it is not pinned.
export function bases(src) {
  const args = {};
  const stages = new Set();
  const out = [];
  const lines = src.replace(/\\\n/g, " ").split("\n");
  lines.forEach((raw, i) => {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) return;
    const [kw, ...rest] = line.split(/\s+/);
    if (/^ARG$/i.test(kw)) {
      const m = rest.join(" ").match(/^([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?$/);
      if (m) args[m[1]] = m[2]?.replace(/^"(.*)"$/, "$1");
      return;
    }
    if (!/^FROM$/i.test(kw)) return;
    const words = rest.filter((w) => !w.startsWith("--platform="));
    const ref = words[0] ?? "";
    const image = ref.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g, (all, a, b) => args[a ?? b] ?? all);
    const as = words[1]?.toUpperCase() === "AS" ? words[2] : undefined;
    out.push({ line: i + 1, written: line, image, stage: stages.has(image) });
    if (as) stages.add(as);
  });
  return out;
}

export const unpinned = (src) => bases(src).filter((b) => !b.stage && !PINNED.test(b.image));

describe("#3018: the hosted image's base is pinned by digest, the stdio image's base", { skip }, () => {
  it("every FROM of Dockerfile.http names its image by a sha256 digest, on the FROM line itself", () => {
    const src = fs.readFileSync(HTTP, "utf8");
    const all = bases(src);
    assert.ok(all.length >= 2, `Dockerfile.http has ${all.length} FROM lines: a build stage and a runtime stage were expected`);
    assert.deepEqual(unpinned(src).map((b) => `Dockerfile.http:${b.line} ${b.written}`), [], "an unpinned base: two deploys of one commit can ship different images (#3018)");
    for (const b of all.filter((x) => !x.stage)) assert.ok(PINNED.test(b.written.split(/\s+/)[1]), `Dockerfile.http:${b.line} pins through a variable (${b.written}): a --build-arg could swap the base; write the digest on the line`);
  });
  it("every FROM of Dockerfile is pinned too", () => {
    assert.deepEqual(unpinned(fs.readFileSync(STDIO, "utf8")).map((b) => `Dockerfile:${b.line} ${b.written} -> ${b.image}`), []);
  });
  it("both files build on one base", () => {
    const of = (f) => [...new Set(bases(fs.readFileSync(f, "utf8")).filter((b) => !b.stage).map((b) => b.image))];
    const http = of(HTTP);
    const stdio = of(STDIO);
    assert.equal(http.length, 1, `Dockerfile.http builds on ${http.length} bases: ${http.join(", ")}`);
    assert.deepEqual(http, stdio, "Dockerfile.http and Dockerfile are the same server: move their base together");
  });

  // The reader can fail. Each control is a Dockerfile drift would write.
  it("control: a tag, a short digest, an unpinned ARG and a tag with a digest-looking suffix are refused; a stage and a pin are not", () => {
    const D = "sha256:" + "0".repeat(64);
    assert.deepEqual(unpinned("FROM node:22-alpine AS build\nFROM node:22-alpine\n").map((b) => b.line), [1, 2]);
    assert.equal(unpinned("FROM node:22-alpine@sha256:0a7108bf\n").length, 1);
    assert.equal(unpinned("ARG NODE_IMAGE=node:22-alpine\nFROM ${NODE_IMAGE}\n").length, 1);
    assert.equal(unpinned("FROM ${UNSET_IMAGE}\n").length, 1);
    assert.equal(unpinned("FROM node:22-alpine-sha256-0a7108bf\n").length, 1);
    assert.deepEqual(unpinned(`FROM node:22@${D} AS build\nFROM build\nFROM --platform=linux/amd64 node@${D}\n`), []);
    assert.deepEqual(unpinned(`ARG NODE_IMAGE=node:22.23.3-alpine3.24@${D}\n# FROM node:22-alpine\nFROM \${NODE_IMAGE} \\\n  AS build\nFROM $NODE_IMAGE\n`), []);
  });
});


// ── #3345: the runtime stage carries no npm, npx or corepack ─────────────────────
//
// Each instruction of a Dockerfile, continuations joined and comment lines dropped as docker reads
// them, with the stage it is in (0 for the first FROM's).
export function instructions(src) {
  const out = [];
  let stage = -1;
  let acc = "";
  let at = 0;
  src.split("\n").forEach((raw, i) => {
    const line = raw.trim();
    if (acc === "" && (line === "" || line.startsWith("#"))) return;
    if (acc !== "" && line.startsWith("#")) return;
    if (acc === "") at = i + 1;
    if (/\\$/.test(line)) {
      acc += `${line.slice(0, -1)} `;
      return;
    }
    const text = (acc + line).trim();
    acc = "";
    const [kw, ...rest] = text.split(/\s+/);
    const k = kw.toUpperCase();
    if (k === "FROM") stage++;
    out.push({ line: at, kw: k, args: rest.join(" "), stage });
  });
  return out;
}

// What the image's npm, npx and corepack are, in node's official images.
export const BUNDLED_TOOLS = ["/usr/local/lib/node_modules/npm", "/usr/local/lib/node_modules/corepack", "/usr/local/bin/npm", "/usr/local/bin/npx", "/usr/local/bin/corepack"];
const RUNS_A_TOOL = /(^|[\s"'\[,;&|(])(npm|npx|corepack)([\s"',\]);&|]|$)/;

// Why the last stage of `src` may still carry or run the base's npm, npx or corepack; [] if not.
export function runtimeNpmProblems(src) {
  const all = instructions(src);
  const last = Math.max(...all.map((x) => x.stage));
  const stage = all.filter((x) => x.stage === last);
  const out = [];
  const removal = stage.findIndex((x) => x.kw === "RUN" && /\brm\s+-[a-z]*r[a-z]*f|\brm\s+-[a-z]*f[a-z]*r/.test(x.args) && BUNDLED_TOOLS.every((p) => x.args.split(/\s+/).includes(p)));
  if (removal < 0) out.push(`the runtime stage removes none or not all of ${BUNDLED_TOOLS.join(", ")} (one RUN rm -rf naming each)`);
  const user = stage.findIndex((x) => x.kw === "USER" && !/^(0|root)(:|$)/.test(x.args));
  if (removal >= 0 && user >= 0 && user < removal) out.push(`line ${stage[removal].line}: the removal runs after USER ${stage[user].args} (line ${stage[user].line}), which cannot delete root's files`);
  for (const [i, x] of stage.entries()) {
    if (i === removal) continue;
    const runs = x.kw === "RUN" || x.kw === "CMD" || x.kw === "ENTRYPOINT" || x.kw === "HEALTHCHECK" || x.kw === "SHELL";
    if (runs && RUNS_A_TOOL.test(x.args)) out.push(`line ${x.line}: ${x.kw} runs npm, npx or corepack in the runtime stage: ${x.args}`);
    if (x.kw === "COPY" && /--from=/.test(x.args) && /node_modules\/(npm|corepack)\b|\/usr\/local\/(bin|lib)/.test(x.args)) out.push(`line ${x.line}: COPY brings a tool back: ${x.args}`);
  }
  const cmd = stage.filter((x) => x.kw === "CMD" || x.kw === "ENTRYPOINT").at(-1);
  if (!cmd || !/^\[\s*"node"/.test(cmd.args)) out.push(`the runtime stage's ${cmd ? `${cmd.kw} (line ${cmd.line})` : "CMD"} is not an exec form starting node`);
  return out;
}

describe("#3345: Dockerfile.http's runtime stage carries no npm, npx or corepack (pacote, sigstore, ip-address, brace-expansion, picomatch)", { skip }, () => {
  it("its last stage removes the five paths before USER, and neither runs nor copies back any of them; the CMD is node", () => {
    assert.deepEqual(runtimeNpmProblems(fs.readFileSync(HTTP, "utf8")), []);
  });

  it("the build stage still installs with npm ci, builds and prunes (the removal is the runtime stage's alone)", () => {
    const build = instructions(fs.readFileSync(HTTP, "utf8")).filter((x) => x.stage === 0);
    assert.ok(build.some((x) => x.kw === "RUN" && /\bnpm ci\b/.test(x.args)), "the build stage no longer runs npm ci");
    assert.ok(build.some((x) => x.kw === "RUN" && /\bnpm prune --omit=dev\b/.test(x.args)), "the build stage no longer prunes the dev dependencies");
  });

  it("no HEALTHCHECK, and the CMD runs dist/http.js under node (Cloud Run's probe is an HTTP GET of /health)", () => {
    const rt = instructions(fs.readFileSync(HTTP, "utf8"));
    const last = rt.filter((x) => x.stage === Math.max(...rt.map((y) => y.stage)));
    assert.equal(last.filter((x) => x.kw === "HEALTHCHECK").length, 0);
    assert.match(last.filter((x) => x.kw === "CMD").at(-1).args, /^\["node",.*"dist\/http\.js"\]$/);
  });

  // The reader can fail. Each control is a Dockerfile.http a later edit could write.
  it("control: no removal, a path left out, the removal after USER, a CMD or HEALTHCHECK that runs npm, and a COPY that brings it back are each refused", () => {
    const src = fs.readFileSync(HTTP, "utf8");
    const removal = instructions(src).find((x) => x.kw === "RUN" && x.args.includes("/usr/local/bin/npx"));
    assert.ok(removal, "control: the removal is not found");
    const lines = src.split("\n");
    // The RUN and its continuation lines.
    let end = removal.line - 1;
    while (/\\\s*$/.test(lines[end])) end++;
    const without = [...lines.slice(0, removal.line - 1), ...lines.slice(end + 1)].join("\n");
    assert.ok(runtimeNpmProblems(without).some((p) => p.includes("removes none or not all")), runtimeNpmProblems(without).join("; "));
    const partial = src.replace(" /usr/local/bin/npx", "");
    assert.ok(runtimeNpmProblems(partial).some((p) => p.includes("removes none or not all")));
    const late = [...lines.slice(0, removal.line - 1), ...lines.slice(end + 1)].join("\n").replace(/^USER node$/m, `USER node\n${lines.slice(removal.line - 1, end + 1).join("\n")}`);
    assert.ok(runtimeNpmProblems(late).some((p) => p.includes("after USER node")), runtimeNpmProblems(late).join("; "));
    assert.ok(runtimeNpmProblems(src.replace(/^CMD .*$/m, 'CMD ["npm", "run", "start:http"]')).some((p) => p.includes("runs npm")));
    assert.ok(runtimeNpmProblems(`${src}\nHEALTHCHECK CMD npx -y wait-on http://localhost:8080/health\n`).some((p) => p.includes("HEALTHCHECK runs npm")));
    assert.ok(runtimeNpmProblems(src.replace(/^COPY --from=build \/app\/dist \.\/dist$/m, "COPY --from=build /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm\nCOPY --from=build /app/dist ./dist")).some((p) => p.includes("brings a tool back")));
    // The other stage's npm ci is not the runtime stage's, and a word that merely contains npm is no tool.
    assert.deepEqual(runtimeNpmProblems(src.replace("ENV NODE_ENV=production", "ENV NODE_ENV=production\nLABEL org.opencontainers.image.source=https://www.npmjs.com/package/echelongraph-mcp")), []);
  });
});
