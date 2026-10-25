// #3345: the runtime dependencies are pinned exactly (every npm user of a release installs what it
// was tested with), and at or above the first release that fixes each advisory filed against them.
// 3.1.0 (and 3.0.2) pinned @modelcontextprotocol/server 2.1.0 (CVE-2026-111768, CVE-2026-111770)
// and zod 4.6.5 (CVE-2023-54404, GHSA-mrhx-c7xc-m3w5), so every npm user installed both, and #3018's
// Trivy gate refused the hosted image. A pin moved below a fix, or loosened to a range, fails here.
//
// What is installed is held to the pins too: the modules this server loads (resolved from this
// package, as the server resolves them) and, where the lockfile is here (the repository, not the
// packed tarball, which does not ship it), the versions the lockfile locks.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { PKG, PKG_DIR } from "./server-under-test.mjs";

// The first release of each runtime dependency with the advisories named above fixed.
export const PATCHED = {
  "@modelcontextprotocol/server": { version: "2.3.0", fixes: ["CVE-2026-111768", "CVE-2026-111770"] },
  zod: { version: "4.6.6", fixes: ["CVE-2023-54404"] },
};

const EXACT = /^\d+\.\d+\.\d+$/;
const parts = (v) => v.split(".").map(Number);
export function atLeast(v, floor) {
  const [a, b] = [parts(v), parts(floor)];
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] > b[i];
  return true;
}
const installed = (name) => {
  const req = createRequire(path.join(PKG_DIR, "package.json"));
  let dir = path.dirname(req.resolve(name));
  while (!fs.existsSync(path.join(dir, "package.json")) || JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8")).name !== name) dir = path.dirname(dir);
  return JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8")).version;
};

describe("#3345: the runtime dependencies are pinned exactly, at or above each advisory's fix", () => {
  it("package.json's dependencies are exactly the advisories' packages, each an exact version at or above its fix", () => {
    assert.deepEqual(Object.keys(PKG.dependencies).sort(), Object.keys(PATCHED).sort(), "a runtime dependency was added or removed: give it a row in PATCHED");
    for (const [name, { version, fixes }] of Object.entries(PATCHED)) {
      const pin = PKG.dependencies[name];
      assert.match(pin, EXACT, `${name} is pinned as ${pin}, not an exact version`);
      assert.ok(atLeast(pin, version), `${name} ${pin} is below ${version}, the first release that fixes ${fixes.join(", ")}`);
    }
  });

  it("the modules this server loads are the pinned versions (and @modelcontextprotocol/core is the server's own)", () => {
    for (const name of Object.keys(PATCHED)) assert.equal(installed(name), PKG.dependencies[name], `${name}: installed ${installed(name)}, pinned ${PKG.dependencies[name]}`);
    assert.equal(installed("@modelcontextprotocol/core"), PKG.dependencies["@modelcontextprotocol/server"]);
  });

  const LOCK = path.join(PKG_DIR, "package-lock.json");
  it("the lockfile locks the pinned versions", { skip: fs.existsSync(LOCK) ? false : "package-lock.json is not here (the npm package does not ship it)" }, () => {
    const lock = JSON.parse(fs.readFileSync(LOCK, "utf8"));
    assert.deepEqual(lock.packages[""].dependencies, PKG.dependencies);
    for (const name of Object.keys(PATCHED)) assert.equal(lock.packages[`node_modules/${name}`]?.version, PKG.dependencies[name], name);
    assert.equal(lock.packages["node_modules/@modelcontextprotocol/core"]?.version, PKG.dependencies["@modelcontextprotocol/server"]);
    // One copy of each: no second, older zod or SDK nested under another package.
    for (const name of [...Object.keys(PATCHED), "@modelcontextprotocol/core"]) {
      const copies = Object.keys(lock.packages).filter((k) => k === `node_modules/${name}` || k.endsWith(`/node_modules/${name}`));
      assert.deepEqual(copies, [`node_modules/${name}`], `${name} is locked more than once: ${copies.join(", ")}`);
    }
  });

  it("control: a range, and a pin below the fix, are each refused", () => {
    assert.doesNotMatch("^2.3.0", EXACT);
    assert.doesNotMatch("~4.6.6", EXACT);
    assert.equal(atLeast("2.1.0", PATCHED["@modelcontextprotocol/server"].version), false);
    assert.equal(atLeast("4.6.5", PATCHED.zod.version), false);
    assert.equal(atLeast("2.2.9", "2.3.0"), false);
    assert.equal(atLeast("2.10.0", "2.3.0"), true);
    assert.equal(atLeast("4.6.6", "4.6.6"), true);
    assert.equal(atLeast("5.0.0", "4.6.6"), true);
  });
});
