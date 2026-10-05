#!/usr/bin/env node
// Checks an UNPACKED .mcpb bundle before the release workflow publishes to npm, attests the bundle
// and attaches it to the GitHub release (#2815). The bundle is what a Claude Desktop user installs
// with one click, and Claude Desktop runs it with the Node.js it ships, so nothing on the user's
// machine can make up for a file missing from it or differing from what was tested.
//
//   node listings/mcpb/check-bundle.mjs <unpacked-bundle-dir> --version <X.Y.Z> \
//        --package <tested package/> [--node-modules-ref <reference node_modules/>]
//
// --package is the tested npm tarball, unpacked (its package/ directory). In the release workflow
// this runs in its own read-only job, on a fresh runner that has not run the MCPB CLI, from a fresh
// checkout. It fails (exit 1, one line per problem on stderr) unless:
//   * the bundle's top level holds only what build.sh stages: manifest.json, the icon it names,
//     package.json, LICENSE, README.md, dist/ and node_modules/, none of them a symlink;
//   * manifest.json is listings/mcpb/manifest.json byte for byte, at --version, and names its
//     icon and entry point, both present in the bundle;
//   * package.json, LICENSE and README.md are the tested package's byte for byte, and package.json
//     is at --version;
//   * the bundle's dist/ is file for file the tested package's dist/: no file missing, added,
//     different or a symlink;
//   * with --node-modules-ref, every file under the bundle's node_modules/ is byte for byte the
//     file at the same path in the reference (a fresh `npm ci --omit=dev` from the same lockfile),
//     and no entry there is a symlink. The pack may leave files out (its .mcpbignore defaults),
//     and the tools/list run below catches a left-out file the server needs; it may not add or
//     change one;
//   * the bundle's server, started with `node <bundle>/dist/index.js` the way manifest.json's
//     mcp_config starts it, with its working directory outside the bundle and an environment of
//     PATH, HOME and ECHELONGRAPH_API_BASE only (no NODE_PATH, NODE_OPTIONS or any other variable
//     of the caller's that could load code from outside the bundle), lists exactly manifest.json's
//     tools: the same names, in order, each with manifest.json's description as its title.
// A malformed bundle (a manifest.json or package.json that does not parse, a file where build.sh
// stages a directory) is reported the same way, not a crash. Exit 2 is misuse.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { StdioMcpClient, MODERN } from "../../test/mcp-stdio-client.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));

function usage(msg) {
  console.error(`check-bundle: ${msg}\nusage: check-bundle.mjs <unpacked-bundle-dir> --version <X.Y.Z> --package <dir> [--node-modules-ref <dir>]`);
  process.exit(2);
}

const argv = process.argv.slice(2);
const opts = { dir: undefined, version: undefined, pkg: undefined, nmRef: undefined };
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  const val = () => (i + 1 < argv.length ? argv[++i] : usage(`${a} needs a value`));
  if (a === "--version") opts.version = val();
  else if (a === "--package") opts.pkg = val();
  else if (a === "--node-modules-ref") opts.nmRef = val();
  else if (a.startsWith("--")) usage(`unknown option ${a}`);
  else if (opts.dir === undefined) opts.dir = a;
  else usage(`unexpected argument ${a}`);
}
if (!opts.dir || !opts.version || !opts.pkg) usage("the bundle directory, --version and --package are required");
// lstat (or stat, following a symlink) that answers undefined for a path that is not there,
// including one under a regular file (ENOTDIR): a bundle with a file where build.sh stages a
// directory is a problem to report, not a crash.
function statOf(p, follow = false) {
  try {
    return follow ? fs.statSync(p) : fs.lstatSync(p);
  } catch (e) {
    if (e.code === "ENOENT" || e.code === "ENOTDIR") return undefined;
    throw e;
  }
}
// JSON from a file, or undefined (with a problem) when it does not parse.
function jsonOf(file, what, problems) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    problems.push(`${what} is not valid JSON: ${e.message}`);
    return undefined;
  }
}

for (const [what, d] of [["bundle", opts.dir], ["--package", opts.pkg], ["--node-modules-ref", opts.nmRef]]) {
  if (d !== undefined && !statOf(d, true)?.isDirectory()) usage(`${what} ${d} is not a directory`);
}

const problems = [];
const BUNDLE = path.resolve(opts.dir);
const PKG = path.resolve(opts.pkg);

// Every regular file under dir, as paths relative to it; a symlink is reported, not followed.
function files(dir, rel = "", out = new Map()) {
  for (const e of fs.readdirSync(path.join(dir, rel), { withFileTypes: true })) {
    const r = rel ? `${rel}/${e.name}` : e.name;
    if (e.isSymbolicLink()) out.set(r, "symlink");
    else if (e.isDirectory()) files(dir, r, out);
    else if (e.isFile()) out.set(r, "file");
    else out.set(r, "other");
  }
  return out;
}
const same = (a, b) => fs.readFileSync(a).equals(fs.readFileSync(b));

// 1. The top level holds only what build.sh stages; the manifest, and the files it names.
const manifestPath = path.join(BUNDLE, "manifest.json");
let manifest;
const TOP_FILES = ["manifest.json", "package.json", "LICENSE", "README.md"];
const TOP_DIRS = ["dist", "node_modules"];
if (!statOf(manifestPath)?.isFile()) problems.push("manifest.json is missing from the bundle, or is not a regular file");
else {
  if (!same(manifestPath, path.join(HERE, "manifest.json"))) problems.push("the bundle's manifest.json is not listings/mcpb/manifest.json byte for byte");
  manifest = jsonOf(manifestPath, "the bundle's manifest.json", problems);
}
if (manifest) {
  if (manifest.version !== opts.version) problems.push(`manifest.json version is ${manifest.version}; the release is ${opts.version}`);
  if (manifest.icon) TOP_FILES.push(manifest.icon);
  for (const f of [manifest.icon, manifest.server?.entry_point]) {
    if (!f || !statOf(path.join(BUNDLE, f))?.isFile()) problems.push(`the bundle has no ${f ?? "(unnamed file)"}`);
  }
}
for (const e of fs.readdirSync(BUNDLE, { withFileTypes: true })) {
  if (TOP_FILES.includes(e.name)) {
    if (!e.isFile()) problems.push(`${e.name} is not a regular file`);
  } else if (TOP_DIRS.includes(e.name)) {
    if (!e.isDirectory()) problems.push(`${e.name} is not a directory`);
  } else problems.push(`${e.name} is in the bundle, but build.sh stages no such file`);
}
// package.json, LICENSE and README.md are the tested package's.
for (const f of ["package.json", "LICENSE", "README.md"]) {
  const mine = path.join(BUNDLE, f);
  if (!statOf(mine)?.isFile()) problems.push(`the bundle has no ${f}`);
  else if (!statOf(path.join(PKG, f), true)?.isFile()) problems.push(`the tested package has no ${f}`);
  else if (!same(mine, path.join(PKG, f))) problems.push(`${f} differs from the tested package's`);
}
const bundlePkg = statOf(path.join(BUNDLE, "package.json"))?.isFile() && jsonOf(path.join(BUNDLE, "package.json"), "the bundle's package.json", problems);
if (bundlePkg && bundlePkg.version !== opts.version) problems.push(`the bundle's package.json version is ${bundlePkg.version}; the release is ${opts.version}`);

// 2. dist/ is the reference dist/, file for file.
const isDir = (d) => statOf(d)?.isDirectory();
const distB = isDir(path.join(BUNDLE, "dist")) ? files(path.join(BUNDLE, "dist")) : new Map();
const DIST_REF = path.join(PKG, "dist");
const distR = isDir(DIST_REF) ? files(DIST_REF) : new Map();
if (!distR.size) problems.push(`the tested package has no dist/ at ${DIST_REF}`);
for (const [r, kind] of distR) {
  if (!distB.has(r)) problems.push(`dist/${r} is in the tested package but not in the bundle`);
  else if (kind !== "file" || distB.get(r) !== "file") problems.push(`dist/${r} is not a regular file in both`);
  else if (!same(path.join(BUNDLE, "dist", r), path.join(DIST_REF, r))) problems.push(`dist/${r} differs from the tested package's`);
}
for (const r of distB.keys()) if (!distR.has(r)) problems.push(`dist/${r} is in the bundle but not in the tested package`);

// 3. node_modules/ adds or changes nothing the lockfile's production install has.
if (opts.nmRef) {
  const nmDir = path.join(BUNDLE, "node_modules");
  if (!isDir(nmDir)) problems.push("the bundle has no node_modules/: Claude Desktop would start a server with no dependencies");
  else {
    for (const [r, kind] of files(nmDir)) {
      const ref = path.join(opts.nmRef, r);
      if (kind !== "file") problems.push(`node_modules/${r} is a ${kind}, not a regular file`);
      else if (!statOf(ref, true)?.isFile()) problems.push(`node_modules/${r} is in the bundle but not in the production install`);
      else if (!same(path.join(nmDir, r), ref)) problems.push(`node_modules/${r} differs from the production install's`);
    }
  }
}

// 4. The bundle's own server lists the manifest's tools.
if (manifest && distB.get("index.js") === "file") {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "mcpb-check-"));
  // Only what the server needs, none of the caller's: a NODE_PATH, NODE_OPTIONS (--require,
  // --import) or the like inherited from here could load code from outside the bundle.
  const env = { PATH: process.env.PATH ?? "", HOME: cwd, ECHELONGRAPH_API_BASE: "http://127.0.0.1:9" };
  const args = (manifest.server?.mcp_config?.args ?? []).map((a) => a.replaceAll("${__dirname}", BUNDLE));
  const client = new StdioMcpClient({ command: process.execPath, args, env, stderr: "ignore", cwd });
  try {
    await client.open(MODERN);
    const { tools } = await client.listTools();
    const got = tools.map((t) => ({ name: t.name, description: t.title }));
    if (JSON.stringify(got) !== JSON.stringify(manifest.tools)) {
      const want = manifest.tools.map((t) => t.name);
      const names = got.map((t) => t.name);
      problems.push(`the bundle's server lists ${names.length} tools [${names.join(", ")}]; manifest.json names ${want.length} [${want.join(", ")}]${names.join() === want.join() ? " (a title differs)" : ""}`);
    } else console.log(`the bundle's server lists manifest.json's ${got.length} tools`);
  } catch (e) {
    problems.push(`the bundle's server did not answer tools/list: ${e.message}`);
  } finally {
    await client.close();
    fs.rmSync(cwd, { recursive: true, force: true });
  }
}

if (problems.length) {
  for (const p of problems) console.error(`FAIL: ${p}`);
  process.exit(1);
}
console.log(`OK: the bundle is ${opts.version}, holds only what build.sh stages, its package.json, LICENSE, README.md and dist/ are the tested package's${opts.nmRef ? ", its node_modules/ adds or changes nothing" : ""}, and it serves manifest.json's tools`);
