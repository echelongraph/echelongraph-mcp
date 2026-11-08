// #3381: the hosted endpoint, started as its image starts it, estimates what parsing a body would retain before it
// parses it, whatever the body's shape, and refuses one past what a request may take (src/parseBudget.ts).
//
// Production runs dist/http.js as Dockerfile.http's CMD starts it (heap limit 152 MiB) and admits a body up to
// max_sbom_body_bytes (6 MiB) for a tools/call of check_sbom or scan_manifest, or a prompts/get of sbom_review, on one
// of two large-body slots. Through 3.1.5 such a body was parsed whole before anything counted what it held: one keyless
// POST of a list of empty objects, empty arrays or one-element arrays at the cap ended the process ("JavaScript heap out
// of memory", exit 134), and every request on it failed. Each case here drives a real server started with exactly
// Dockerfile.http's CMD flags (test/image-server.mjs):
//   - for each large-body target and each of those three shapes, one body at the cap, then two at once (both slots);
//   - bodies whose objects cost V8 a hidden class each (a key, an array index or a combination of keys no other object
//     has), which a count of objects and arrays alone let through: one, and two at once, beside 62 requests held at the
//     API (what the admission lets in beside two large bodies);
//   - two bodies whose estimates fit the in-flight budget together, both held at the API at once (both parsed bodies
//     live), beside 62 held requests: answered;
//   - real documents: Juice Shop's CycloneDX components in a ~5.6 MB check_sbom body passed as an object, a Syft-shaped
//     one at 6 MiB, and #2773's 5,000,000-character document passed as text: never refused by the estimate.
// Each must be answered or refused, never a reset connection, and /health must answer 200 after it. Without the
// estimate the first cases end the process; without its weight per new shape, the hidden-class case does.
// Skipped in the published-tarball run (Dockerfile.http is not in the package).
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { PKG_DIR } from "./server-under-test.mjs";
import { IMAGE_SKIP, assertAlive, assertAnsweredOrRefused, imageBudgets, post, resultOf, sleep, startServer, stubApi, toolCall } from "./image-server.mjs";

const P = await import(pathToFileURL(path.join(PKG_DIR, "dist", "httpPolicy.js")).href);
const B = await import(pathToFileURL(path.join(PKG_DIR, "dist", "parseBudget.js")).href);
// The server under test is started with the image's flags, so its bounds are the image's, not this process's (#3381).
const IMAGE = IMAGE_SKIP ? B : imageBudgets();
const CDX = JSON.parse(fs.readFileSync(path.join(PKG_DIR, "test", "fixtures", "juice-shop-11.1.2-50.cdx.json"), "utf8"));
const u = (i) => i.toString(36);

// The three large-body targets, each with the one list a dense body fills.
const TARGETS = [
  ["tools/call", "check_sbom", (list) => `{"sbom":{"components":${list}}}`],
  ["tools/call", "scan_manifest", (list) => `{"files":${list}}`],
  ["prompts/get", "sbom_review", (list) => `{"sbom":${list}}`],
];
const SHAPES = { "empty objects": "{}", "empty arrays": "[]", "one-element arrays": "[0]" };

// One body of exactly `bytes` bytes: `method` naming `name`, whose list holds as many of `item` as fit, padded with
// whitespace to the byte.
function denseBody(method, name, args, item, bytes) {
  const head = `{"jsonrpc":"2.0","id":1,"method":"${method}","params":{"name":"${name}","arguments":`;
  const [pre, post] = args("[\u0000]").split("\u0000");
  const tail = "}}";
  const room = bytes - head.length - pre.length - post.length - tail.length;
  const n = Math.floor((room + 1) / (item.length + 1));
  const list = Array(n).fill(item).join(",");
  const body = head + pre + list + " ".repeat(room - list.length) + post + tail;
  assert.equal(Buffer.byteLength(body), bytes);
  return { body, n };
}

// A check_sbom call whose document holds one real component (so an admitted call waits at the API, holding its parsed
// arguments) and then `junk`, components that cost what the case is about.
const heldSbom = (junk) =>
  `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"check_sbom","arguments":{"sbom":{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name":"a","version":"1.0.0","purl":"pkg:npm/a@1.0.0"},${junk}]}}}}`;

// Juice Shop 11.1.2's real CycloneDX components, cycled with distinct names, as a check_sbom call passing the document
// as an object, to at most `bytes` bytes.
function realisticBody(bytes) {
  const bodyFor = (k) => {
    const components = Array.from({ length: k }, (_, i) => {
      const t = CDX.components[i % CDX.components.length];
      const name = `${t.name}-r${i}`;
      return { ...t, name, "bom-ref": `pkg:npm/${name}@${t.version}`, purl: `pkg:npm/${name}@${t.version}` };
    });
    return toolCall("check_sbom", { sbom: { ...CDX, components } });
  };
  let k = Math.floor(bytes / (bodyFor(1000).length / 1000));
  let body = bodyFor(k);
  while (Buffer.byteLength(body) > bytes) body = bodyFor(--k);
  return body;
}

// A CycloneDX document of `n` components shaped as Syft writes them (test/input-elements.test.mjs's), as a check_sbom
// body of at most `bytes`.
function syftBody(bytes) {
  const comp = (i) => ({
    type: "library",
    "bom-ref": `pkg:npm/elements-${i}@1.0.${i % 10}?package-id=${i.toString(16)}`,
    name: `elements-${i}`,
    version: `1.0.${i % 10}`,
    purl: `pkg:npm/elements-${i}@1.0.${i % 10}`,
    licenses: [{ license: { id: "MIT" } }],
    hashes: [{ alg: "SHA-256", content: "0123456789abcdef".repeat(4) }],
    properties: Array.from({ length: 8 }, (_, k) => ({ name: `syft:location:${k}:path`, value: `/usr/lib/node_modules/elements-${i}/package.json` })),
  });
  const bodyFor = (n) =>
    toolCall("check_sbom", {
      sbom: {
        bomFormat: "CycloneDX",
        specVersion: "1.6",
        version: 1,
        components: Array.from({ length: n }, (_, i) => comp(i)),
        dependencies: Array.from({ length: n }, (_, i) => ({ ref: comp(i)["bom-ref"], dependsOn: i + 1 < n ? [comp(i + 1)["bom-ref"]] : [] })),
      },
    });
  let n = Math.floor(bytes / (bodyFor(100).length / 100));
  let body = bodyFor(n);
  while (Buffer.byteLength(body) > bytes) body = bodyFor((n -= 10));
  return body;
}

// #2773's document (test/http-memory.test.mjs maxDocument): a ~5,000,000-character pretty-printed CycloneDX document
// of 2,000 purls, Juice Shop's real components cycled, padded with components without a purl.
function maxDocument() {
  const components = Array.from({ length: 2000 }, (_, i) => {
    const t = CDX.components[i % CDX.components.length];
    const name = `${t.name}-r${i}`;
    return { ...t, name, "bom-ref": `pkg:npm/${name}@${t.version}`, purl: `pkg:npm/${name}@${t.version}` };
  });
  const filler = { type: "library", name: "filler", description: "x".repeat(200), licenses: [{ license: { id: "MIT" } }] };
  const padded = (n) => JSON.stringify({ ...CDX, components: [...components, ...Array(n).fill(filler)] }, null, 2);
  const base = padded(0).length;
  return padded(Math.floor((5_000_000 - base) / (padded(1).length - base)));
}

// What the hosted endpoint answers a body refused by the estimate: 413, a JSON-RPC error naming what was counted and
// the bound, its access line refused body_dense.
function assertDense(r, srv, from, what) {
  assert.equal(r.status, 413, `${what}: ${r.text?.slice(0, 300)}`);
  const e = JSON.parse(r.text).error;
  assert.equal(e.code, P.BODY_DENSE_CODE);
  assert.match(e.message, /^Request body too dense to parse: its \d+ objects and arrays, \d+ elements \(list entries and object members\) and \d+ keys, counted outside its strings, are estimated at \d+ bytes of this instance's memory parsed; at most 29360128 bytes/);
  assert.ok(e.data.estimated_bytes > e.data.max_bytes && e.data.max_bytes === IMAGE.PARSE_BUDGET_BYTES, JSON.stringify(e.data));
  if (srv) {
    const lines = srv.access(from).filter((l) => l.status === 413);
    assert.ok(lines.length >= 1 && lines.every((l) => l.refused === "body_dense" && l.rpc_method === "(unparseable)"), JSON.stringify(lines));
  }
}

describe("#3381: a body's parse is estimated before it is parsed, whatever its shape, and the instance lives", { skip: IMAGE_SKIP, concurrency: false, timeout: 900_000 }, () => {
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
    stub?.release();
    await srv?.stop();
    await stub?.close();
  });
  // n tools/call of cve_summary held at the API: what the admission lets in beside two large bodies (64 in all).
  const holdPlain = async (s, n) => {
    const at = stub.state.open;
    const calls = Array.from({ length: n }, () => post(s.port, toolCall("cve_summary", {})));
    const deadline = Date.now() + 30_000;
    while (stub.state.open < at + n && s.alive() && Date.now() < deadline) await sleep(20);
    return calls;
  };

  it("the server under test runs with the image's flags and production's body cap and slots", async () => {
    const s = await fresh();
    assert.ok(s.started.heap_limit_mb < 256, `heap limit ${s.started.heap_limit_mb} MiB: http.js did not get the image's flags`);
    assert.equal(s.started.max_sbom_body_bytes, P.DEFAULT_MAX_SBOM_BODY_BYTES);
    assert.equal(s.started.large_body_slots, 2, "the two-at-once cases below fill both slots");
  });

  for (const [method, name, args] of TARGETS) {
    for (const [shape, item] of Object.entries(SHAPES)) {
      it(`${method} ${name}: one body of ${shape} at the cap, then two at once (both slots): refused unparsed, /health 200 after each`, async () => {
        const s = await fresh();
        const { body, n } = denseBody(method, name, args, item, P.DEFAULT_MAX_SBOM_BODY_BYTES);
        const from = s.lines.length;
        const r = await post(s.port, body);
        await assertAlive(s, `${name}, ${n} ${shape}`);
        assertAnsweredOrRefused(r, `${name}, ${n} ${shape}`);
        assertDense(r, s, from, `${name}, ${n} ${shape}`);
        assert.deepEqual(s.access(from).filter((l) => l.status === 413).map((l) => l.body_bytes), [P.DEFAULT_MAX_SBOM_BODY_BYTES]);
        const two = await Promise.all([post(s.port, body), post(s.port, body)]);
        await assertAlive(s, `${name}, two of ${n} ${shape} at once`);
        for (const x of two) {
          assertAnsweredOrRefused(x, `${name}, two of ${n} ${shape} at once`);
          assertDense(x, null, 0, `${name}, two of ${n} ${shape}`);
        }
      });
    }
  }

  // Objects that cost V8 a hidden class each: counted by their keys (parseBudget.ts WEIGHT_NEW_SHAPE, WEIGHT_INDEX_KEY).
  const SHAPED = {
    "a key no other object has": (n) => Array.from({ length: n }, (_, i) => `{"k${u(i)}":0}`).join(","),
    "an array index no other object has": (n) => Array.from({ length: n }, (_, i) => `{"${1_000_000 + i}":0}`).join(","),
    "a combination of four keys no other object has": (n) => {
      const out = [];
      const k = Array.from({ length: 64 }, (_, i) => `k${i}`);
      for (let a = 0; a < 64 && out.length < n; a++) for (let b = a + 1; b < 64 && out.length < n; b++) for (let c = b + 1; c < 64 && out.length < n; c++) for (let d = c + 1; d < 64 && out.length < n; d++) {
        out.push(`{"${k[a]}":0,"${k[b]}":0,"${k[c]}":0,"${k[d]}":0}`);
        if (out.length >= n) break;
      }
      return out.join(",");
    },
  };
  for (const [shape, junk] of Object.entries(SHAPED)) {
    it(`objects of ${shape}, at the cap: one, then two at once beside 62 held requests: answered or refused, /health 200 after`, async () => {
      const s = await fresh();
      let n = 200_000;
      while (Buffer.byteLength(heldSbom(junk(n))) > P.DEFAULT_MAX_SBOM_BODY_BYTES) n -= 10_000;
      const body = heldSbom(junk(n));
      const one = await post(s.port, body);
      await assertAlive(s, `one body of ${n} objects of ${shape}`);
      assertAnsweredOrRefused(one, shape);
      const plain = await holdPlain(s, 62);
      const two = await Promise.all([post(s.port, body), post(s.port, body)]);
      await assertAlive(s, `two bodies of ${n} objects of ${shape} beside 62 held requests`);
      for (const x of two) assertAnsweredOrRefused(x, shape);
      stub.release();
      stub.hold();
      for (const x of await Promise.all(plain)) assertAnsweredOrRefused(x, "a held cve_summary");
      stub.release();
    });
  }

  it("#3381's own case: two bodies of 149,000 objects of a key no other has and 50,000 distinct strings, at both slots, beside 62 held requests", async () => {
    const s = await fresh();
    stub.hold();
    try {
      const plain = await holdPlain(s, 62);
      const bodies = [0, 1].map((c) => heldSbom(`${Array.from({ length: 149_000 }, (_, i) => `{"k${c}${u(i)}":0}`).join(",")},${Array.from({ length: 50_000 }, (_, i) => `"s${c}${u(i)}"`).join(",")}`));
      const from = s.lines.length;
      const two = await Promise.all(bodies.map((b) => post(s.port, b)));
      await assertAlive(s, "two bodies of 149,000 unique-key objects at once");
      for (const x of two) assertAnsweredOrRefused(x, "149,000 unique-key objects");
      // Each is estimated past what one request may take: refused unparsed, both.
      for (const x of two) assertDense(x, s, from, "149,000 unique-key objects");
      stub.release();
      for (const x of await Promise.all(plain)) assert.equal(x.status, 200);
    } finally {
      stub.release();
    }
  });

  it("two bodies whose estimates fit the in-flight budget together, both held at the API at once beside 62 held requests, are answered", async () => {
    const s = await fresh();
    // Each: empty objects (estimated at what they retain) and distinct short strings (0.98 of it), about half the
    // in-flight budget.
    const bodies = [0, 1].map((c) => heldSbom(`${Array(150_000).fill("{}").join(",")},${Array.from({ length: 190_000 }, (_, i) => `"str${c}${u(i).padStart(6, "0")}"`).join(",")}`));
    const estimates = bodies.map((b) => B.scanJson(Buffer.from(b)).estimate);
    assert.ok(estimates.every((e) => e < IMAGE.PARSE_BUDGET_BYTES) && estimates[0] + estimates[1] <= IMAGE.INFLIGHT_BUDGET_BYTES && estimates[0] > 0.45 * IMAGE.INFLIGHT_BUDGET_BYTES, `${estimates}`);
    stub.hold();
    try {
      const plain = await holdPlain(s, 62);
      const batches = stub.state.batches;
      const sent = bodies.map((b) => post(s.port, b));
      const deadline = Date.now() + 60_000;
      while (stub.state.batches < batches + 2 && s.alive() && Date.now() < deadline) await sleep(20);
      assert.equal(stub.state.batches, batches + 2, `both calls did not reach the API at once (alive: ${s.alive()}: ${s.stderrTail()})`);
      await assertAlive(s, "two bodies held at once beside 62 held requests");
      stub.release();
      for (const r of await Promise.all(sent)) assert.equal(r.status, 200, r.text?.slice(0, 300));
      for (const r of await Promise.all(plain)) assert.equal(r.status, 200);
      await assertAlive(s, "after their answers");
    } finally {
      stub.release();
    }
  });

  it("two bodies that fit one at a time but not together: the second waits for room while the first is held, and is answered or refused 503", async () => {
    const s = await fresh();
    const bodies = [0, 1].map((c) => heldSbom(`${Array(200_000).fill("{}").join(",")},${Array.from({ length: 200_000 }, (_, i) => `"str${c}${u(i).padStart(6, "0")}"`).join(",")}`));
    const estimates = bodies.map((b) => B.scanJson(Buffer.from(b)).estimate);
    assert.ok(estimates.every((e) => e <= IMAGE.PARSE_BUDGET_BYTES) && estimates[0] + estimates[1] > IMAGE.INFLIGHT_BUDGET_BYTES, `${estimates}`);
    stub.hold();
    try {
      const from = s.lines.length;
      const first = post(s.port, bodies[0]);
      const deadline = Date.now() + 30_000;
      const batches = stub.state.batches;
      while (stub.state.batches < batches + 1 && Date.now() < deadline) await sleep(20);
      const second = await post(s.port, bodies[1]);
      await assertAlive(s, "the second body while the first is held");
      assert.equal(second.status, 503, second.text?.slice(0, 300));
      assert.equal(JSON.parse(second.text).error.code, P.BUSY_CODE);
      const line = s.access(from).find((l) => l.status === 503 && l.body_bytes === Buffer.byteLength(bodies[1]));
      // #3381's review: its wait for room in the parse budget is in queued_ms (through round 3 it said 0).
      assert.deepEqual([line.refused, line.rpc_method], ["parse_busy", "(unparseable)"]);
      assert.ok(line.queued_ms >= P.DEFAULT_ADMISSION_WAIT_MS - 100 && line.queued_ms < P.DEFAULT_ADMISSION_WAIT_MS + 2000, `queued_ms ${line.queued_ms}`);
      stub.release();
      assert.equal((await first).status, 200);
    } finally {
      stub.release();
    }
  });

  it("positive control: Juice Shop's real CycloneDX components in a ~5.6 MB check_sbom body pass the estimate and reach the tool", async () => {
    const s = await fresh();
    const body = realisticBody(5_600_000);
    const size = Buffer.byteLength(body);
    assert.ok(size > 5_500_000 && size <= 5_600_000, `${size}`);
    assert.ok(B.scanJson(Buffer.from(body)).estimate < IMAGE.PARSE_BUDGET_BYTES);
    const from = s.lines.length;
    const r = await post(s.port, body);
    await assertAlive(s, "the ~5.6 MB real document");
    assert.equal(r.status, 200, r.text.slice(0, 300));
    // Answered by check_sbom itself: the document as an object is past its own 5,000,000 characters, which it says.
    assert.match(r.text, /at most 5000000 are read/);
    // Its own line: another case's last line can still be on its way.
    assert.deepEqual(s.access(from).filter((l) => l.body_bytes === size).map((l) => [l.status, l.refused, l.rpc_method, l.tool]), [[200, "", "tools/call", "check_sbom"]]);
  });

  it("positive control: a Syft-shaped CycloneDX document of 6 MiB passes the estimate and is answered", async () => {
    const s = await fresh();
    const body = syftBody(P.DEFAULT_MAX_SBOM_BODY_BYTES - 1000);
    assert.ok(Buffer.byteLength(body) > 6_000_000, `${Buffer.byteLength(body)}`);
    assert.ok(B.scanJson(Buffer.from(body)).estimate < IMAGE.PARSE_BUDGET_BYTES);
    const from = s.lines.length;
    const r = await post(s.port, body);
    await assertAlive(s, "the 6 MiB Syft-shaped document");
    assert.equal(r.status, 200, r.text.slice(0, 300));
    assert.deepEqual(s.access(from).filter((l) => l.body_bytes === Buffer.byteLength(body)).map((l) => l.refused), [""]);
  });

  it("positive control: #2773's 5,000,000-character document, passed as text, passes the estimate and is checked", async () => {
    const s = await fresh();
    const body = toolCall("check_sbom", { sbom: maxDocument() });
    const batches = stub.state.batches;
    const r = await post(s.port, body);
    await assertAlive(s, "#2773's document");
    assert.equal(r.status, 200, r.text.slice(0, 300));
    assert.equal(resultOf(r)?.structuredContent?.state, "measured", r.text.slice(0, 300));
    assert.ok(stub.state.batches > batches, "check_sbom sent no batch: the document was not checked");
  });
});
