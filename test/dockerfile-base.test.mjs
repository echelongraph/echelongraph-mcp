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

