// The one-click Claude Desktop install (#2815): the release workflow builds echelongraph-mcp.mcpb
// from the release tag, checks it (listings/mcpb/check-bundle.mjs), signs it with a SLSA
// build-provenance attestation and attaches it to the GitHub release, and the README links it as
// "Install in Claude Desktop".
//
// What must hold:
//   * release.yml runs the bundle jobs on the same v* tag as the npm publish, and the npm publish
//     waits for the bundle's checks: a bundle defect stops the release before npm has the version;
//   * the job that builds the bundle (and runs dependency code) holds no write permission; build.sh
//     validates the manifest with the pinned MCPB CLI before it packs; check-bundle runs on its own
//     read-only runner, which never runs build.sh or the MCPB CLI, and compares the sha1 of the
//     tarball and the sha256 of the bundle it downloaded and exits on a mismatch (run here, with
//     mismatched and matching values);
//   * the job that signs and attaches holds the write permissions, checks out nothing and runs no
//     npm, npx or node; it compares the bundle's sha256 and exits on a mismatch; it attests with a
//     SHA-pinned actions/attest-build-provenance and checks the served file with
//     `gh attestation verify` against this workflow at this tag; it runs only after npm serves the
//     version with provenance, or for a version npm already had; it attaches the bundle and its
//     Sigstore bundle each on its own, keeping an asset the release already has (its two attach
//     steps run here against a stub gh);
//   * scripts/npm-publish-mcp.sh follows a release run for at least the workflow's critical path
//     plus 30 min of queueing;
//   * check-bundle.mjs passes a faithful bundle and fails one with a file at the top level that
//     build.sh does not stage, or a top-level symlink; whose package.json, README.md or version
//     is not the tested package's; whose dist/ has a file changed, missing or added; whose
//     node_modules/ has a file added or changed, or a symlink, or is missing; whose LICENSE is
//     not the tested package's; that lacks the icon or entry point manifest.json names; whose
//     dist/ or node_modules/ is not a directory; whose manifest drops a tool or changes a title;
//     or that is at another version; it fails when the tested package has no dist/; and it starts
//     the server with PATH, HOME and ECHELONGRAPH_API_BASE only (no NODE_OPTIONS, NODE_PATH or
//     other variable of the caller's);
//   * the README's link names the asset the workflow attaches.
//
// These are repo files (listings/ and the public repo's .github/), not in the npm tarball: a run
// inside an unpacked tarball skips.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const REPO_PKG = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const LISTINGS = path.join(REPO_PKG, "listings");
// The public repo's tree is mcp-server/ plus its .github/; this repo keeps that .github/ at
// scripts/npm-publish-mcp-public/.github/ (scripts/npm-publish-mcp.sh, PUBLIC_GITHUB_PIN).
const WORKFLOW = [
  path.join(REPO_PKG, ".github", "workflows", "release.yml"),
  path.join(REPO_PKG, "..", "scripts", "npm-publish-mcp-public", ".github", "workflows", "release.yml"),
].find((p) => fs.existsSync(p));
const SKIP = !fs.existsSync(LISTINGS) ? "no listings/ here (npm does not pack it)" : !WORKFLOW ? "no release.yml here" : false;
const CHECK = path.join(LISTINGS, "mcpb", "check-bundle.mjs");
const ASSET = "echelongraph-mcp.mcpb";
// The maintainers' publish script follows the run; it is in the EchelonGraph repo only.
const PUBLISH_SH = path.join(REPO_PKG, "..", "scripts", "npm-publish-mcp.sh");
const has = (cmd) => spawnSync("bash", ["-c", `command -v ${cmd}`]).status === 0;
const NO_TOOLS = ["bash", "jq", "tar", "zip", "unzip", "sha1sum", "sha256sum"].filter((c) => !has(c));
const SKIP_RUN = SKIP || (NO_TOOLS.length ? `needs ${NO_TOOLS.join(", ")}` : false);

// The jobs of a workflow, by name: the text from `  <name>:` to the next job.
function jobsOf(text) {
  const body = text.slice(text.indexOf("\njobs:\n"));
  const out = {};
  const re = /^ {2}([A-Za-z0-9_-]+):\n/gm;
  const heads = [...body.matchAll(re)];
  heads.forEach((m, i) => (out[m[1]] = body.slice(m.index, i + 1 < heads.length ? heads[i + 1].index : body.length)));
  return out;
}
// The `run:` text of a job's steps, comments dropped (a comment may name a command it does not run).
const runText = (job) => job.split("\n").filter((l) => !/^\s*#/.test(l)).join("\n");
// A job given its own permissions block, or naming any write permission.
const grantsWrite = (job) => /^ {4}permissions:/m.test(job) || /^\s+[a-z-]+: write\b/m.test(runText(job));
// A job that checks out the repository or runs npm, npx or node.
const runsDependencyCode = (job) => /actions\/checkout|\bnpm\b|\bnpx\b|^\s+(?:run: )?node /m.test(runText(job));
// A job's `needs`, as a list.
function needsOf(job) {
  const m = job.match(/^ {4}needs: (?:\[([^\]]*)\]|(\S+))$/m);
  return !m ? [] : m[1] !== undefined ? m[1].split(",").map((x) => x.trim()).filter(Boolean) : [m[2]];
}
// The longest chain of job timeouts, in minutes, and the chain.
function criticalPath(jobs) {
  const memo = {};
  const walk = (name) => {
    if (memo[name]) return memo[name];
    const t = Number(jobs[name].match(/^ {4}timeout-minutes: (\d+)$/m)?.[1] ?? NaN);
    let best = { min: 0, path: [] };
    for (const n of needsOf(jobs[name])) {
      const w = walk(n);
      if (w.min > best.min) best = w;
    }
    return (memo[name] = { min: best.min + t, path: [...best.path, name] });
  };
  return Object.keys(jobs).map(walk).reduce((a, b) => (b.min > a.min ? b : a));
}
// A step's `run: |` script, by the step's name.
function stepRun(job, name) {
  const at = job.indexOf(`      - name: ${name}\n`);
  assert.ok(at !== -1, `no step named "${name}"`);
  const lines = job.slice(at).split("\n").slice(1);
  const r = lines.findIndex((l) => l === "        run: |");
  assert.ok(r !== -1 && !lines.slice(0, r).some((l) => /^ {6}- /.test(l)), `step "${name}" has no run: | block`);
  const out = [];
  for (const l of lines.slice(r + 1)) {
    if (l.trim() && !l.startsWith("          ")) break;
    out.push(l.slice(10));
  }
  return out.join("\n");
}
// The compare-and-exit line for a checksum: [ "$GOT" = "$WANT_X" ] || { echo "::error::..."; exit 1; }
const comparesAndExits = (text, want) =>
  new RegExp(`^\\s*\\[ "\\$GOT" = "\\$${want}" \\] \\|\\| \\{ echo "::error::[^"\\n]*"; exit 1; \\}$`, "m").test(text);

describe("the release workflow builds, signs and attaches the Claude Desktop bundle (#2815)", { skip: SKIP }, () => {
  const wf = SKIP ? "" : fs.readFileSync(WORKFLOW, "utf8");
  const jobs = SKIP ? {} : jobsOf(wf);

  it("runs on the v* tag that publishes to npm, in the same workflow", () => {
    assert.match(wf, /^on:\n {2}push:\n {4}tags: \["v\*"\]$/m);
    assert.ok(jobs.publish && jobs.bundle && jobs["release-bundle"], `jobs: ${Object.keys(jobs).join(", ")}`);
    assert.match(wf, /^permissions:\n {2}contents: read$/m, "the workflow's default token must stay read-only");
  });

  it("the bundle job builds with build.sh, which validates the manifest before it packs, and holds no write permission", () => {
    const b = jobs.bundle;
    assert.match(b, /^ {4}needs: build$/m);
    assert.ok(!grantsWrite(b), "the bundle job runs dependency code: it keeps the read-only default and names no write permission");
    assert.match(runText(b), /run: bash listings\/mcpb\/build\.sh "\$RUNNER_TEMP\/mcpb"$/m);
    const sh = fs.readFileSync(path.join(LISTINGS, "mcpb", "build.sh"), "utf8");
    const validate = sh.search(/^npx -y "\$MCPB_CLI" validate "\$STAGE\/manifest\.json"$/m);
    const pack = sh.search(/^npx -y "\$MCPB_CLI" pack /m);
    assert.ok(validate !== -1 && validate < pack, "build.sh must run `mcpb validate` on the manifest before `mcpb pack`");
    assert.match(sh, /^MCPB_CLI="@anthropic-ai\/mcpb@\d+\.\d+\.\d+"/m, "the MCPB CLI must be pinned to an exact version");
    assert.match(sh, /^set -euo pipefail$/m);
  });

  it("npm publishes only once the bundle passed its checks, and the header says so", () => {
    assert.deepEqual(needsOf(jobs.publish), ["build", "check-bundle"], "publish must wait for check-bundle: npm versions are immutable");
    assert.match(jobs.publish, /^ {4}if: needs\.build\.outputs\.already != 'true'$/m);
    assert.deepEqual(needsOf(jobs["check-bundle"]), ["build", "bundle"]);
    assert.match(wf, /^# released, the tarball \(build\) and the bundle \(bundle, check-bundle\), runs before the publish:$/m);
  });

  it("check-bundle runs on its own read-only runner, never runs the MCPB CLI, and checks the bundle against the tested tarball and a production install", () => {
    const j = jobs["check-bundle"];
    assert.ok(!grantsWrite(j), "check-bundle keeps the read-only default and names no write permission");
    const r = runText(j);
    assert.ok(!/\bnpx\b|build\.sh|\bmcpb (?:validate|pack)\b/.test(r), "check-bundle must not run build.sh or the MCPB CLI: it checks what they made");
    assert.ok(!/check-bundle\.mjs/.test(runText(jobs.bundle)), "the bundle job must not check its own output");
    assert.match(r, /npm ci --omit=dev --ignore-scripts/);
    assert.match(r, /env -u NODE_PATH node listings\/mcpb\/check-bundle\.mjs "\$RUNNER_TEMP\/unpacked" \\\n\s+--version "\$VERSION" --package "\$RUNNER_TEMP\/tested\/package" \\\n\s+--node-modules-ref "\$RUNNER_TEMP\/nmref\/node_modules"$/m);
    const sums = stepRun(j, "The tarball is the one the build job tested, and the bundle the one the bundle job built");
    assert.ok(comparesAndExits(sums, "WANT_SHA1"), "check-bundle does not compare the tarball's sha1 and exit on a mismatch");
    assert.ok(comparesAndExits(sums, "WANT_SHA256"), "check-bundle does not compare the bundle's sha256 and exit on a mismatch");
    assert.ok(comparesAndExits(stepRun(jobs["release-bundle"], "The bundle is the one check-bundle checked"), "WANT_SHA256"),
      "release-bundle does not compare the bundle's sha256 and exit on a mismatch");
  });

  it("scripts/npm-publish-mcp.sh follows the run for the critical path plus 30 min of queueing", { skip: !fs.existsSync(PUBLISH_SH) && "no scripts/npm-publish-mcp.sh here" }, () => {
    const cp = criticalPath(jobs);
    assert.deepEqual(cp.path, ["build", "bundle", "check-bundle", "publish", "verify", "release-bundle"]);
    assert.match(wf, new RegExp(`^# 15 = ${cp.min} min of job timeouts`, "m"), `release.yml's header does not give the critical path, ${cp.min} min`);
    const sh = fs.readFileSync(PUBLISH_SH, "utf8");
    const polls = Number(sh.match(/^RUN_FINISH_POLLS=(\d+)/m)?.[1]);
    const secs = Number(sh.match(/^RUN_POLL_SECS=(\d+)/m)?.[1]);
    assert.ok((polls * secs) / 60 >= cp.min + 30, `npm-publish-mcp.sh follows a run for ${(polls * secs) / 60} min; the critical path is ${cp.min} min`);
    assert.match(sh, new RegExp(`, build 20 \\+\\n# bundle 20 \\+ check-bundle 15 \\+ publish 15 \\+ verify 30 \\+ release-bundle 15 = ${cp.min} min`));
    assert.match(sh, new RegExp(`a run not finished ${(polls * secs) / 60} min after it`));
  });

  it("the release-bundle job signs and attaches, runs no dependency code, and verifies what the release serves", () => {
    const j = jobs["release-bundle"];
    assert.deepEqual(needsOf(j), ["build", "verify", "bundle", "check-bundle"]);
    assert.match(j, /needs\.verify\.result == 'success' \|\| \(needs\.build\.outputs\.already == 'true' && needs\.verify\.result == 'skipped'\)/,
      "the bundle must be attached only after npm serves the version with provenance, or for a version npm already had");
    assert.match(j, /needs\.build\.result == 'success' && needs\.bundle\.result == 'success' &&\n\s+needs\.check-bundle\.result == 'success' &&/);
    for (const p of ["contents: write", "id-token: write", "attestations: write"]) assert.ok(j.includes(`      ${p}`), `release-bundle lacks ${p}`);
    assert.ok(!runsDependencyCode(j), "release-bundle checks out or runs dependency code");
    assert.match(j, /^ {6}ASSET: echelongraph-mcp\.mcpb$/m);
    assert.match(j, /sha256sum "\$RUNNER_TEMP\/release\/\$ASSET"[\s\S]*WANT_SHA256/, "release-bundle does not check it signs the bundle the bundle job checked");
    assert.match(j, /uses: actions\/attest-build-provenance@[0-9a-f]{40} # v\d/);
    assert.match(j, /subject-path: \$\{\{ runner\.temp \}\}\/release\/echelongraph-mcp\.mcpb$/m);
    const r = runText(j);
    assert.match(r, /gh release upload "\$TAG" "\$RUNNER_TEMP\/release\/\$ASSET"$/m);
    assert.match(r, /gh release upload "\$TAG" "\$RUNNER_TEMP\/release\/\$SIG"$/m);
    assert.match(r, /gh release create "\$TAG" --verify-tag /);
    assert.match(r, /gh release download "\$TAG" --pattern "\$ASSET"/);
    assert.match(r, /gh attestation verify "\$RUNNER_TEMP\/served\/\$ASSET" --repo "\$GH_REPO" \\\n\s+--signer-workflow "\$GH_REPO\/\.github\/workflows\/release\.yml" --source-ref "refs\/tags\/\$TAG" \\\n\s+--deny-self-hosted-runners --format json > "\$RUNNER_TEMP\/verified\.json"$/m);
    assert.ok(r.indexOf("gh release upload") < r.indexOf("gh attestation verify"), "the attestation must be verified on the served file, after the upload");
  });

  it("every action in release.yml is pinned to a commit SHA", () => {
    const uses = [...wf.matchAll(/^\s+(?:- )?uses: (\S+)(.*)$/gm)];
    assert.ok(uses.length >= 10);
    for (const [, ref, rest] of uses) {
      if (ref.startsWith("./")) continue;
      assert.match(ref, /@[0-9a-f]{40}$/, `${ref} is not pinned to a commit SHA`);
      assert.match(rest, /^ # v\d/, `${ref} does not name the version it pins`);
    }
  });

  it("the README links Install in Claude Desktop to the asset the workflow attaches", () => {
    const readme = fs.readFileSync(path.join(REPO_PKG, "README.md"), "utf8");
    assert.ok(readme.includes(`[Install in Claude Desktop](https://github.com/echelongraph/echelongraph-mcp/releases/latest/download/${ASSET})`),
      "the README lost its Install in Claude Desktop link to the release asset");
  });

  it("control: the job checks fail on a bundle job granted a write permission, or a release job that runs npm", () => {
    assert.ok(grantsWrite(jobs.bundle.replace("    runs-on:", "    permissions:\n      contents: write\n    runs-on:")));
    assert.ok(grantsWrite(jobs.bundle.replace("          persist-credentials: false", "          persist-credentials: false\n          id-token: write")));
    assert.ok(runsDependencyCode(jobs["release-bundle"].replace("      - name: Sign", "      - run: npm ci\n      - name: Sign")));
    assert.ok(runsDependencyCode(jobs["release-bundle"].replace("      - name: Sign", "      - uses: actions/checkout@v7\n      - name: Sign")));
    assert.equal(jobsOf("x\njobs:\n  a:\n    y\n  b:\n    z\n").b, "  b:\n    z\n");
  });

  it("control: the gate, checksum and follow-bound checks fail on a publish that does not wait, a checksum computed but not enforced, or a longer path", () => {
    assert.deepEqual(needsOf(jobs.publish.replace("needs: [build, check-bundle]", "needs: build")), ["build"]);
    const sums = stepRun(jobs["check-bundle"], "The tarball is the one the build job tested, and the bundle the one the bundle job built");
    assert.ok(!comparesAndExits(sums.replace('[ "$GOT" = "$WANT_SHA256" ] ||', "true ||"), "WANT_SHA256"));
    assert.ok(!comparesAndExits(sums.replace(/^.*"\$WANT_SHA1" \] \|\|.*$/m, "true"), "WANT_SHA1"));
    assert.ok(!comparesAndExits(sums.replace("exit 1; }\nGOT", "}\nGOT"), "WANT_SHA1"));
    const longer = { ...jobs, verify: jobs.verify.replace("timeout-minutes: 30", "timeout-minutes: 90") };
    assert.equal(criticalPath(longer).min, criticalPath(jobs).min + 60);
  });
});

describe("release.yml's checksum and attach steps, run against a stub gh (#2815)", { skip: SKIP_RUN }, () => {
  const jobs = SKIP_RUN ? {} : jobsOf(fs.readFileSync(WORKFLOW, "utf8"));
  let tmp;
  before(() => (tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mcpb-steps-"))));
  after(() => fs.rmSync(tmp, { recursive: true, force: true }));

  const GH_STUB = `#!/usr/bin/env bash
S="$GH_STUB_STATE"
echo "gh $*" >> "$S/log"
case "$1 $2" in
  "release view") [ -f "$S/release" ] || exit 1; if [[ " $* " == *" assets "* ]]; then cat "$S/assets" 2>/dev/null || true; fi ;;
  "release create") touch "$S/release" ;;
  "release upload") shift 3; for f in "$@"; do basename "$f" >> "$S/assets"; cp "$f" "$S/"; done ;;
  *) echo "unexpected: gh $*" >&2; exit 9 ;;
esac
`;
  let n = 0;
  // Runs a step's script the way Actions runs `shell: bash`, with a stub gh on PATH.
  function runStep(job, name, env, { release = false, assets = [] } = {}) {
    const dir = path.join(tmp, `run${n++}`);
    const state = path.join(dir, "state");
    const bin = path.join(dir, "bin");
    const rt = path.join(dir, "runner");
    fs.mkdirSync(state, { recursive: true });
    fs.mkdirSync(bin);
    fs.mkdirSync(path.join(rt, "release"), { recursive: true });
    fs.writeFileSync(path.join(bin, "gh"), GH_STUB, { mode: 0o755 });
    if (release) fs.writeFileSync(path.join(state, "release"), "");
    if (assets.length) fs.writeFileSync(path.join(state, "assets"), assets.map((a) => `${a}\n`).join(""));
    const script = path.join(dir, "step.sh");
    fs.writeFileSync(script, stepRun(jobs[job], name));
    const r = spawnSync("bash", ["--noprofile", "--norc", "-eo", "pipefail", script], {
      encoding: "utf8",
      env: { PATH: `${bin}:${process.env.PATH}`, GH_STUB_STATE: state, RUNNER_TEMP: rt, TAG: "v9.9.9", VERSION: "9.9.9", ASSET, GH_REPO: "o/r", ...(typeof env === "function" ? env(rt) : env) },
    });
    const log = fs.existsSync(path.join(state, "log")) ? fs.readFileSync(path.join(state, "log"), "utf8") : "";
    const uploaded = log.split("\n").filter((l) => l.startsWith("gh release upload")).map((l) => l.split(" ").slice(4).map((f) => path.basename(f)).join(" "));
    return { ...r, rt, state, log, uploaded };
  }
  const sha = (algo, f) => spawnSync(`${algo}sum`, [f], { encoding: "utf8" }).stdout.split(" ")[0];

  it("check-bundle's checksum step exits on a mismatched sha1 or sha256, and unpacks both on a match", () => {
    const src = path.join(tmp, "src");
    fs.mkdirSync(path.join(src, "package"), { recursive: true });
    fs.writeFileSync(path.join(src, "package", "a.txt"), "a\n");
    const tgz = path.join(tmp, "t.tgz");
    const zipf = path.join(tmp, "b.mcpb");
    assert.equal(spawnSync("tar", ["-czf", tgz, "-C", src, "package"]).status, 0);
    assert.equal(spawnSync("zip", ["-qj", zipf, path.join(src, "package", "a.txt")]).status, 0);
    const name = "The tarball is the one the build job tested, and the bundle the one the bundle job built";
    const env = (sha1, sha256) => (rt) => {
      fs.mkdirSync(path.join(rt, "tarball"));
      fs.mkdirSync(path.join(rt, "mcpb"));
      fs.copyFileSync(tgz, path.join(rt, "tarball", "t.tgz"));
      fs.copyFileSync(zipf, path.join(rt, "mcpb", ASSET));
      return { NAME: "t.tgz", WANT_SHA1: sha1, WANT_SHA256: sha256 };
    };
    const good1 = sha("sha1", tgz), good256 = sha("sha256", zipf);
    const ok = runStep("check-bundle", name, env(good1, good256));
    assert.equal(ok.status, 0, ok.stderr);
    assert.ok(fs.existsSync(path.join(ok.rt, "tested", "package", "a.txt")) && fs.existsSync(path.join(ok.rt, "unpacked", "a.txt")));
    const bad1 = runStep("check-bundle", name, env("0".repeat(40), good256));
    assert.equal(bad1.status, 1);
    assert.match(bad1.stdout, /::error::downloaded tarball sha1 [0-9a-f]{40}, tested 0{40}/);
    const bad256 = runStep("check-bundle", name, env(good1, "0".repeat(64)));
    assert.equal(bad256.status, 1);
    assert.match(bad256.stdout, /::error::downloaded echelongraph-mcp\.mcpb sha256 [0-9a-f]{64}, built 0{64}/);
    assert.ok(!fs.existsSync(path.join(bad256.rt, "unpacked")), "a mismatched bundle was unpacked");
  });

  it("release-bundle's checksum step exits on a mismatched sha256", () => {
    const name = "The bundle is the one check-bundle checked";
    const put = (rt) => fs.writeFileSync(path.join(rt, "release", ASSET), "bundle");
    const right = sha("sha256", (fs.writeFileSync(path.join(tmp, "b"), "bundle"), path.join(tmp, "b")));
    assert.equal(runStep("release-bundle", name, (rt) => (put(rt), { WANT_SHA256: right })).status, 0);
    const bad = runStep("release-bundle", name, (rt) => (put(rt), { WANT_SHA256: "0".repeat(64) }));
    assert.equal(bad.status, 1);
    assert.match(bad.stdout, /::error::downloaded echelongraph-mcp\.mcpb sha256 [0-9a-f]{64}, checked 0{64}/);
  });

  it("the attach step creates a missing release and uploads the bundle alone; a release that has it keeps it", () => {
    const name = "Attach the bundle to release vX.Y.Z";
    const put = (rt) => (fs.writeFileSync(path.join(rt, "release", ASSET), "new"), fs.writeFileSync(path.join(rt, "release", "notes.md"), "n"), {});
    const fresh = runStep("release-bundle", name, put);
    assert.equal(fresh.status, 0, fresh.stderr);
    assert.match(fresh.log, /^gh release create v9\.9\.9 --verify-tag /m);
    assert.deepEqual(fresh.uploaded, [ASSET]);
    const kept = runStep("release-bundle", name, put, { release: true, assets: [ASSET] });
    assert.equal(kept.status, 0, kept.stderr);
    assert.deepEqual(kept.uploaded, [], "a re-run replaced or re-uploaded the bundle the release already carries");
    assert.match(kept.stdout, /already carries echelongraph-mcp\.mcpb: kept, not replaced/);
    assert.ok(!/release create/.test(kept.log));
  });

  it("the Sigstore step attaches it on its own: this run's for this run's bundle, the verified one for an earlier run's, none if present", () => {
    const name = "Attach the bundle's Sigstore bundle to release vX.Y.Z";
    const SIG = `${ASSET}.sigstore.json`;
    const setup = (served) => (rt) => {
      fs.writeFileSync(path.join(rt, "release", ASSET), "ours");
      fs.mkdirSync(path.join(rt, "served"));
      fs.writeFileSync(path.join(rt, "served", ASSET), served);
      fs.writeFileSync(path.join(rt, "verified.json"), JSON.stringify([{ attestation: { bundle: { from: "verified" } }, verificationResult: {} }]));
      fs.writeFileSync(path.join(rt, "ours.sigstore.json"), '{"from":"this run"}\n');
      return { SIGSTORE: path.join(rt, "ours.sigstore.json") };
    };
    const same = runStep("release-bundle", name, setup("ours"), { release: true, assets: [ASSET] });
    assert.equal(same.status, 0, same.stderr);
    assert.deepEqual(same.uploaded, [SIG]);
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(same.state, SIG), "utf8")), { from: "this run" });
    const earlier = runStep("release-bundle", name, setup("an earlier run's"), { release: true, assets: [ASSET] });
    assert.equal(earlier.status, 0, earlier.stderr);
    assert.deepEqual(earlier.uploaded, [SIG]);
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(earlier.state, SIG), "utf8")), { from: "verified" });
    const both = runStep("release-bundle", name, setup("ours"), { release: true, assets: [ASSET, SIG] });
    assert.equal(both.status, 0, both.stderr);
    assert.deepEqual(both.uploaded, []);
  });
});

describe("check-bundle.mjs (#2815)", { skip: SKIP }, () => {
  let tmp;
  const lock = SKIP ? {} : JSON.parse(fs.readFileSync(path.join(REPO_PKG, "package-lock.json"), "utf8"));
  const prod = Object.entries(lock.packages ?? {}).filter(([k, v]) => k.startsWith("node_modules/") && !v.dev).map(([k]) => k);
  const version = SKIP ? "" : JSON.parse(fs.readFileSync(path.join(REPO_PKG, "package.json"), "utf8")).version;

  // A bundle as build.sh stages it: manifest.json, icon, package.json, LICENSE, dist/ and the
  // lockfile's production packages.
  function makeBundle(name) {
    const dir = path.join(tmp, name);
    fs.mkdirSync(dir);
    for (const f of ["manifest.json", "icon.png"]) fs.copyFileSync(path.join(LISTINGS, "mcpb", f), path.join(dir, f));
    for (const f of ["package.json", "LICENSE", "README.md"]) fs.copyFileSync(path.join(REPO_PKG, f), path.join(dir, f));
    fs.cpSync(path.join(REPO_PKG, "dist"), path.join(dir, "dist"), { recursive: true });
    for (const p of prod) fs.cpSync(path.join(REPO_PKG, p), path.join(dir, p), { recursive: true, dereference: true });
    return dir;
  }
  let env = {};
  const check = (dir, ...extra) =>
    spawnSync(process.execPath, [CHECK, dir, "--version", version, "--package", REPO_PKG, "--node-modules-ref", path.join(REPO_PKG, "node_modules"), ...extra], {
      encoding: "utf8",
      env: { ...process.env, NODE_PATH: "", ...env },
      timeout: 60_000,
    });

  before(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mcpb-test-"));
  });
  after(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it("passes a faithful bundle: its own server lists manifest.json's tools", () => {
    assert.ok(prod.includes("node_modules/zod") && prod.some((p) => p.startsWith("node_modules/@modelcontextprotocol/")), `production packages: ${prod.join(", ")}`);
    const r = check(makeBundle("ok"));
    assert.equal(r.status, 0, r.stderr);
    const n = JSON.parse(fs.readFileSync(path.join(LISTINGS, "mcpb", "manifest.json"), "utf8")).tools.length;
    assert.match(r.stdout, new RegExp(`lists manifest\\.json's ${n} tools`));
    assert.match(r.stdout, /^OK: /m);
  });

  it("control: a dist/ file that differs from the tested package fails", () => {
    const dir = makeBundle("dist");
    fs.appendFileSync(path.join(dir, "dist", "index.js"), "\n// changed\n");
    const r = check(dir);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /FAIL: dist\/index\.js differs from the tested package's/);
  });

  it("control: a file node_modules/ adds fails", () => {
    const dir = makeBundle("nm");
    fs.writeFileSync(path.join(dir, "node_modules", "zod", "injected.js"), "process.exit(0)\n");
    const r = check(dir);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /FAIL: node_modules\/zod\/injected\.js is in the bundle but not in the production install/);
  });

  it("control: a manifest that drops a tool fails, naming both lists", () => {
    const dir = makeBundle("tools");
    const m = JSON.parse(fs.readFileSync(path.join(dir, "manifest.json"), "utf8"));
    m.tools.pop();
    fs.writeFileSync(path.join(dir, "manifest.json"), JSON.stringify(m, null, 2));
    const r = check(dir);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /FAIL: the bundle's manifest\.json is not listings\/mcpb\/manifest\.json byte for byte/);
    assert.match(r.stderr, new RegExp(`FAIL: the bundle's server lists ${m.tools.length + 1} tools .*; manifest\\.json names ${m.tools.length} `));
  });

  it("control: a bundle at another version than the release fails", () => {
    const r = spawnSync(process.execPath, [CHECK, makeBundle("ver"), "--version", "0.0.1", "--package", REPO_PKG], { encoding: "utf8", timeout: 60_000 });
    assert.equal(r.status, 1);
    assert.match(r.stderr, new RegExp(`FAIL: manifest\\.json version is ${version.replace(/\./g, "\\.")}; the release is 0\\.0\\.1`));
  });

  // One problem per bundle: [what, change(dir), the FAIL line it must print].
  const CASES = [
    ["a node_modules/ file that changes", (d) => fs.appendFileSync(path.join(d, "node_modules", "zod", "package.json"), "\n"),
      /FAIL: node_modules\/zod\/package\.json differs from the production install's/],
    ["a symlink in node_modules/", (d) => fs.symlinkSync("../../dist/index.js", path.join(d, "node_modules", "zod", "link.js")),
      /FAIL: node_modules\/zod\/link\.js is a symlink, not a regular file/],
    ["a dist/ file missing", (d) => fs.rmSync(path.join(d, "dist", "textBudget.js")),
      /FAIL: dist\/textBudget\.js is in the tested package but not in the bundle/],
    ["a dist/ file added", (d) => fs.writeFileSync(path.join(d, "dist", "extra.js"), "export {};\n"),
      /FAIL: dist\/extra\.js is in the bundle but not in the tested package/],
    ["a dist/ file that is a symlink", (d) => (fs.rmSync(path.join(d, "dist", "textBudget.js")), fs.symlinkSync(path.join(REPO_PKG, "dist", "textBudget.js"), path.join(d, "dist", "textBudget.js"))),
      /FAIL: dist\/textBudget\.js is not a regular file in both/],
    ["a tool title that differs from manifest.json", (d) => {
      const m = JSON.parse(fs.readFileSync(path.join(d, "manifest.json"), "utf8"));
      m.tools[0].description += " (changed)";
      fs.writeFileSync(path.join(d, "manifest.json"), JSON.stringify(m, null, 2));
    }, /FAIL: the bundle's server lists \d+ tools .*\(a title differs\)/],
    ["a package.json at another version", (d) => {
      const p = JSON.parse(fs.readFileSync(path.join(d, "package.json"), "utf8"));
      p.version = "9.9.9";
      fs.writeFileSync(path.join(d, "package.json"), JSON.stringify(p, null, 2));
    }, /FAIL: the bundle's package\.json version is 9\.9\.9; the release is /],
    ["a package.json not the tested package's", (d) => fs.appendFileSync(path.join(d, "package.json"), "\n"),
      /FAIL: package\.json differs from the tested package's/],
    ["a README.md not the tested package's", (d) => fs.appendFileSync(path.join(d, "README.md"), "x"),
      /FAIL: README\.md differs from the tested package's/],
    ["a top-level file build.sh does not stage", (d) => fs.writeFileSync(path.join(d, "postinstall.js"), "\n"),
      /FAIL: postinstall\.js is in the bundle, but build\.sh stages no such file/],
    ["a top-level symlink", (d) => (fs.rmSync(path.join(d, "LICENSE")), fs.symlinkSync(path.join(REPO_PKG, "LICENSE"), path.join(d, "LICENSE"))),
      /FAIL: LICENSE is not a regular file/],
    ["a LICENSE not the tested package's", (d) => fs.appendFileSync(path.join(d, "LICENSE"), "x"),
      /FAIL: LICENSE differs from the tested package's/],
    ["no icon.png, the icon manifest.json names", (d) => fs.rmSync(path.join(d, "icon.png")),
      /FAIL: the bundle has no icon\.png/],
    ["no dist/index.js, the entry point manifest.json names", (d) => fs.rmSync(path.join(d, "dist", "index.js")),
      /FAIL: the bundle has no dist\/index\.js/],
    ["a dist that is a file, not a directory", (d) => (fs.rmSync(path.join(d, "dist"), { recursive: true }), fs.writeFileSync(path.join(d, "dist"), "\n")),
      /FAIL: dist is not a directory/],
    ["a node_modules that is a file, not a directory", (d) => (fs.rmSync(path.join(d, "node_modules"), { recursive: true }), fs.writeFileSync(path.join(d, "node_modules"), "\n")),
      /FAIL: node_modules is not a directory/],
    ["a manifest.json that is not JSON", (d) => fs.writeFileSync(path.join(d, "manifest.json"), "{"),
      /FAIL: the bundle's manifest\.json is not valid JSON: /],
    ["no node_modules/", (d) => fs.rmSync(path.join(d, "node_modules"), { recursive: true }),
      /FAIL: the bundle has no node_modules\/: /],
  ];
  for (const [what, change, line] of CASES) {
    it(`control: ${what} fails`, () => {
      const dir = makeBundle(what.replace(/[^a-z]+/gi, "-"));
      change(dir);
      const r = check(dir);
      assert.equal(r.status, 1, r.stdout);
      assert.match(r.stderr, line);
    });
  }

  it("starts the bundle's server without the caller's NODE_OPTIONS or NODE_PATH", () => {
    // A preload that kills the bundle's server, and only it, when NODE_OPTIONS reaches it.
    const preload = path.join(tmp, "kill-server.cjs");
    fs.writeFileSync(preload, 'if (/[\\/]dist[\\/]index\\.js$/.test(process.argv[1] || "")) process.exit(3);\n');
    const dir = makeBundle("env");
    const direct = spawnSync(process.execPath, [path.join(dir, "dist", "index.js")], { env: { ...process.env, NODE_OPTIONS: `--require=${preload}` }, input: "", timeout: 30_000 });
    assert.equal(direct.status, 3, "control: the preload does not stop the server it reaches");
    env = { NODE_OPTIONS: `--require=${preload}`, NODE_PATH: path.join(REPO_PKG, "node_modules") };
    try {
      const r = check(dir);
      assert.equal(r.status, 0, `the caller's NODE_OPTIONS reached the bundle's server: ${r.stderr}`);
    } finally {
      env = {};
    }
  });

  it("control: a tested package with no dist/ fails", () => {
    // Everything the bundle is compared with, but no dist/: an empty dist/ must not compare equal.
    const pkg = path.join(tmp, "pkg-no-dist");
    fs.mkdirSync(pkg);
    for (const f of ["package.json", "LICENSE", "README.md"]) fs.copyFileSync(path.join(REPO_PKG, f), path.join(pkg, f));
    const dir = makeBundle("pkg-no-dist-bundle");
    fs.rmSync(path.join(dir, "dist"), { recursive: true });
    fs.mkdirSync(path.join(dir, "dist"));
    const r = spawnSync(process.execPath, [CHECK, dir, "--version", version, "--package", pkg], { encoding: "utf8", timeout: 60_000 });
    assert.equal(r.status, 1, r.stdout);
    assert.match(r.stderr, /FAIL: the tested package has no dist\/ at /);
  });

  it("the bundle's server sees PATH, HOME and ECHELONGRAPH_API_BASE only", () => {
    // ESM ignores NODE_PATH, so no import can show it leaking; a module the server loads records
    // the environment it was given instead. The change makes the check fail (a node_modules/ file
    // differs), but the server still runs, and the record is what this asserts on.
    const dir = makeBundle("env-keys");
    const nmReal = fs.realpathSync(path.join(REPO_PKG, "node_modules"));
    const zodEntry = path.relative(nmReal, fileURLToPath(import.meta.resolve("zod")));
    assert.ok(!zodEntry.startsWith(".."), `zod resolves outside node_modules/: ${zodEntry}`);
    const record = path.join(tmp, "env-keys.json");
    fs.appendFileSync(path.join(dir, "node_modules", zodEntry),
      `\nimport __egFs from "node:fs";\n__egFs.writeFileSync(${JSON.stringify(record)}, JSON.stringify(Object.keys(process.env).sort()));\n`);
    env = { NODE_PATH: path.join(REPO_PKG, "node_modules"), NODE_OPTIONS: "--no-warnings", EG_CALLER_ONLY: "1" };
    try {
      const r = check(dir);
      assert.equal(r.status, 1, r.stdout);
      assert.match(r.stderr, /FAIL: node_modules\/zod\/\S+ differs from the production install's/);
      assert.doesNotMatch(r.stderr, /did not answer tools\/list/, "the bundle's server did not run");
    } finally {
      env = {};
    }
    assert.deepEqual(JSON.parse(fs.readFileSync(record, "utf8")), ["ECHELONGRAPH_API_BASE", "HOME", "PATH"]);
  });

  it("misuse exits 2", () => {
    const r = spawnSync(process.execPath, [CHECK, tmp], { encoding: "utf8" });
    assert.equal(r.status, 2);
  });
});
