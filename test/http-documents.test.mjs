// #3381: what a tool reads from a string is bounded too, on the hosted endpoint started as its image starts it.
//
// The body's own estimate (test/http-dense-body.test.mjs) sees a document passed as text as one string: check_sbom's
// sbom, scan_manifest's files. Through 3.1.5 each tool then read it with nothing counted first, and one keyless POST of
// under 5 MB ended the process ("JavaScript heap out of memory", exit 134): check_sbom's JSON.parse of an sbom of empty
// objects; scan_manifest's JSON.parse of such a package-lock.json or composer.lock; its TOML reader on a Cargo.lock of
// inline tables, or on one long string (built a character at a time); its line readers on a requirements.txt of a
// million one-character lines (an array of every line, and an entry for each). Each is now estimated or counted before
// or while it is read (src/parseBudget.ts documentCost, tomlEstimate; #3434's per-call bounds) and refused past the bound,
// answered invalid_input. Each case here: one such call, then two at once (both slots), under Dockerfile.http's CMD
// flags (test/image-server.mjs): answered, the process alive, /health 200. Without each bound its case ends the
// process. Skipped in the published-tarball run.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { IMAGE_SKIP, assertAlive, assertAnsweredOrRefused, post, resultOf, startServer, stubApi, toolCall } from "./image-server.mjs";

const u = (i) => i.toString(36);
// #3434's refusals of a call past its per-call bounds (manifests/common.ts), as test/manifest-lines.test.mjs reads them.
const PAST_LINES = /^the go\.mod, requirements\.txt, Gemfile\.lock and gradle\.lockfile files hold more than 40000 lines in all, counted per call/;
const PAST_JSON = /^the package-lock\.json and composer\.lock files hold more than 300000 objects, arrays and entries in all, counted per call \(counted before each file is parsed\)/;
// #3381's round-5 review (C1): what the hosted endpoint adds to a lockfile past the parse bound (scan_manifest.ts
// HOSTED_READS): the bound in files, and what to do instead.
const HINT = "; on this endpoint one file's read may take 29360128 bytes \\(28 MiB\\) of its memory: run this server locally \\(npx -y echelongraph-mcp\\), whose bounds are a share of its own machine's memory, not this endpoint's, or pass the lockfile's purls to check_sbom, in calls of 2,000 or fewer$";
const objects = (n) => Array(n).fill("{}").join(",");
const file = (filename, content) => toolCall("scan_manifest", { files: [{ filename, content }] });

// Each case: the call, and what its answer must say.
const CASES = [
  ["check_sbom: an sbom passed as text, of 1,600,000 empty objects", () => toolCall("check_sbom", { sbom: `{"bomFormat":"CycloneDX","components":[${objects(1_600_000)}]}` }), /^sbom is too dense to read: its \d+ objects and arrays, \d+ entries and \d+ keys, parsed, are estimated at \d+ bytes, past the 29360128 bytes a document's parse may take; pass its purls instead$/],
  // #3434 (3.1.3) counts a JSON lockfile's values before it is parsed (MAX_JSON_VALUES), and these pass it.
  ["scan_manifest: a package-lock.json of 1,600,000 empty objects", () => file("package-lock.json", `{"lockfileVersion":3,"packages":[${objects(1_600_000)}]}`), PAST_JSON],
  ["scan_manifest: a composer.lock of 1,600,000 empty objects", () => file("composer.lock", `{"packages":[${objects(1_600_000)}]}`), PAST_JSON],
  // One within that bound, estimated past the parse bound: that file is not read.
  ["scan_manifest: a package-lock.json of 290,000 members with keys no other has", () => file("package-lock.json", `{"lockfileVersion":1,"dependencies":{${Array.from({ length: 290_000 }, (_, k) => `"${k.toString(36)}":0`).join(",")}}}`), new RegExp(`^no file could be read: package-lock\\.json: read as package-lock\\.json, it is too dense to read: .* past the 29360128 bytes a file's parse may take${HINT}`)],
  ["scan_manifest: a Cargo.lock of 1,600,000 inline tables", () => file("Cargo.lock", `version = 3\nx = [${objects(1_600_000)}]\n`), new RegExp(`^no file could be read: Cargo\\.lock: read as Cargo\\.lock, it is too dense to read: its tables, keys and values are estimated at \\d+ bytes read, past the 29360128 bytes a file's read may take${HINT}`)],
  // #3381's review (F8): two Cargo.locks the estimate counted at 10 MB, whose structure it took for a string the reader
  // did not: a date token run on into a quote, and an escaped quote ending nothing in a """ string. Each was read past
  // the heap. Now the reader takes neither as the estimate did not, and stops at what it was estimated at.
  ["scan_manifest: a Cargo.lock whose 2024-01-01' runs into 1,660,000 inline tables", () => file("Cargo.lock", `x = [2024-01-01',${"{},".repeat(1_660_000)}{}]\n`), /^no file could be read: Cargo\.lock: read as Cargo\.lock, it is (not TOML this reader can read: an unreadable value "2024-01-01'" on line 1|too dense to read: what reading it built passed the \d+ bytes estimated of it before it was read; .*)$/],
  ["scan_manifest: a Cargo.lock whose \\\"\"\" ends no string, then 1,600,000 inline tables", () => file("Cargo.lock", `a = """q\\""" """\nb = [${"{},".repeat(1_600_000)}{}]\n# """\n`), /^no file could be read: Cargo\.lock: read as Cargo\.lock, it is too dense to read: (its tables, keys and values are estimated at \d+ bytes read, past the 29360128 bytes|what reading it built passed the \d+ bytes estimated of it)/],
  ["scan_manifest: a poetry.lock of 400,000 [[package]] tables", () => file("poetry.lock", "[[package]]\n".repeat(400_000)), /too dense to read: its tables, keys and values are estimated/],
  // #3434's bound on a call's lines (MAX_MANIFEST_LINES), as 3.1.3 refuses them, where #3381 reserved them first.
  ["scan_manifest: a requirements.txt of 2,000,000 one-character lines", () => file("requirements.txt", "a\n".repeat(2_000_000)), PAST_LINES],
  ["scan_manifest: a gradle.lockfile of 400,000 unreadable lines", () => file("gradle.lockfile", Array.from({ length: 400_000 }, (_, i) => `x${u(i)}`).join("\n")), PAST_LINES],
  ["scan_manifest: a Gemfile.lock of 300,000 specs", () => file("Gemfile.lock", `GEM\n  specs:\n${Array.from({ length: 300_000 }, (_, i) => `    g${u(i)} (1)`).join("\n")}`), PAST_LINES],
  ["scan_manifest: a go.mod of 400,000 lines it cannot take", () => file("go.mod", `module m\n${Array.from({ length: 400_000 }, (_, i) => `x${u(i)}`).join("\n")}`), PAST_LINES],
];

describe("#3381: what a tool reads from a string is bounded before or while it reads it, and the instance lives", { skip: IMAGE_SKIP, concurrency: false, timeout: 900_000 }, () => {
  let stub;
  let srv;
  const fresh = async () => {
    if (srv?.alive()) return srv;
    if (srv) await srv.stop();
    srv = await startServer(stub.base);
    return srv;
  };
  before(async () => {
    stub = await stubApi();
  });
  after(async () => {
    await srv?.stop();
    await stub?.close();
  });

  for (const [name, make, says] of CASES) {
    it(`${name}: refused invalid_input, then two at once; /health 200 after each`, async () => {
      const s = await fresh();
      const body = make();
      assert.ok(Buffer.byteLength(body) <= 6 * 1024 * 1024, `${Buffer.byteLength(body)}`);
      const one = await post(s.port, body);
      await assertAlive(s, name);
      assertAnsweredOrRefused(one, name);
      assert.equal(one.status, 200, one.text?.slice(0, 300));
      const res = resultOf(one);
      assert.equal(res?.structuredContent?.state, "invalid_input", one.text?.slice(0, 300));
      assert.match(res.structuredContent.error.message, says);
      const two = await Promise.all([post(s.port, body), post(s.port, body)]);
      await assertAlive(s, `two at once: ${name}`);
      for (const r of two) {
        assertAnsweredOrRefused(r, `two at once: ${name}`);
        assert.equal(resultOf(r)?.structuredContent?.state, "invalid_input", r.text?.slice(0, 300));
      }
    });
  }

  it("a Cargo.lock holding one 4,000,000-character string is read (its string kept whole, not a node a character), then two at once", async () => {
    const s = await fresh();
    const body = file("Cargo.lock", `version = 3\n\n[[package]]\nname = "a"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nnote = "${"x".repeat(4_000_000)}"\n`);
    const one = await post(s.port, body);
    await assertAlive(s, "a 4,000,000-character TOML string");
    assert.equal(one.status, 200);
    assert.notEqual(resultOf(one)?.structuredContent?.state, "invalid_input", one.text?.slice(0, 300));
    const two = await Promise.all([post(s.port, body), post(s.port, body)]);
    await assertAlive(s, "two 4,000,000-character TOML strings");
    for (const r of two) assertAnsweredOrRefused(r, "a 4,000,000-character TOML string");
  });
});
