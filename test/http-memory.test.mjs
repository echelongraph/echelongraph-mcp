// #2773: the hosted endpoint, started as its image starts it, survives the load that OOM-killed it.
//
// Production runs dist/http.js as Dockerfile.http's CMD starts it, in 256 MiB (deploy-all.sh
// SVC_MEMORY[mcp-remote]), and Cloud Run sends an instance up to 250 requests at once
// (SVC_CONCURRENCY). Before #2773, two check_sbom documents in flight plus 125 to 250 other
// requests got the instance OOM-killed with every request on it. Each case here drives a real
// server, with production's settings, with that load: two documents at the tool's
// 5,000,000-character cap, both at the API before anything else is sent, then 248 tools/call
// cve_summary, 2025-era (each answered over SSE, the costlier era). Two bounds hold it, V8's heap
// cap (Dockerfile.http) and the admission (httpPolicy.ts "Requests in flight per instance"):
//   1. "served as they come": the API answers in 1.5 s and all 250 are answered 200. Their garbage
//      is made faster than the kernel would wait for, and the admission fills (64 at once, the
//      rest waiting up to ~9 s; the case's wait is long enough that none is refused). Measured
//      without the heap cap: OOM-killed in three runs of four, the fourth peaking at 248 MB (the
//      heap-limit check fails it). Without the admission (DEFAULT_MAX_IN_FLIGHT 100000): V8
//      aborted ("JavaScript heap out of memory"), four of four.
//   2. "all at once": the API holds every answer until each of the 250 is inside the instance at
//      once, either at the API or answered by the instance itself. What this holds is the
//      admission alone (without the heap cap it peaked at 204-206 MB too): exactly
//      DEFAULT_MAX_IN_FLIGHT are served and answered 200, the other 186 wait
//      DEFAULT_ADMISSION_WAIT_MS and are answered 503. Without it (DEFAULT_MAX_IN_FLIGHT 100000),
//      the 250 at once exhaust the capped heap and V8 aborts the process, with or without a cgroup.
// The memory itself is held where it can be measured as Cloud Run limits it: as root with a cgroup
// v1 memory controller (the sandbox this was written in), the server runs inside a memory cgroup
// limited to 256 MiB and must be neither OOM-killed nor past the limit. Elsewhere a peak resident
// set is no stand-in for that (V8 sizes its young generation, and returns memory, by the host's
// memory, not the container's: 292 MB VmHWM unconstrained for 218 MB in the cgroup), so it is
// reported, not held.
// Skipped off Linux, and in the published-tarball run (Dockerfile.http is not in the package).
import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { pathToFileURL } from "node:url";
import { PKG_DIR } from "./server-under-test.mjs";
import { BATCH_PATH, ROWS, batchAnswer } from "./fixtures/match-batch.mjs";

const LIMIT = 256 * 1024 * 1024;
const DOCKERFILE = path.join(PKG_DIR, "Dockerfile.http");
const HTTP_ENTRY = path.join(PKG_DIR, "dist", "http.js");
const CGROUP_V1 = "/sys/fs/cgroup/memory";
const OTHERS = 248;
const TOTAL = 2 + OTHERS;
const LATENCY_MS = 1500;
const SUMMARY = { summary: { critical: 1, high: 2, medium: 3, low: 4, none: 0, total: 10, last_updated: "2026-09-27T01:00:00Z" } };

const skip = process.platform !== "linux" ? "needs Linux (/proc, cgroups)" : !fs.existsSync(DOCKERFILE) ? "Dockerfile.http is not in the package" : false;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const tally = (xs) => xs.reduce((m, s) => ((m[s] = (m[s] ?? 0) + 1), m), {});

// The node flags the image starts http.js with: Dockerfile.http's CMD, ["node", ...flags, "dist/http.js"].
function imageNodeFlags() {
  const cmd = [...fs.readFileSync(DOCKERFILE, "utf8").matchAll(/^CMD (\[.*\])\s*$/gm)].at(-1);
  assert.ok(cmd, "Dockerfile.http has no exec-form CMD");
  const argv = JSON.parse(cmd[1]);
  assert.equal(argv[0], "node");
  assert.equal(argv.at(-1), "dist/http.js");
  return argv.slice(1, -1);
}

// A memory cgroup limited to LIMIT, when this process may make one (cgroup v1, as root).
function makeCgroup(name) {
  try {
    const dir = path.join(CGROUP_V1, `eg-mcp-2773-${process.pid}-${name}`);
    fs.mkdirSync(dir);
    fs.writeFileSync(path.join(dir, "memory.limit_in_bytes"), String(LIMIT));
    return dir;
  } catch {
    return undefined;
  }
}

// A ~5,000,000-character pretty-printed CycloneDX document of 2,000 purls (http.test.mjs's
// construction): Juice Shop's real components, cycled, padded with components without a purl.
function maxDocument() {
  const CDX = JSON.parse(fs.readFileSync(path.join(PKG_DIR, "test", "fixtures", "juice-shop-11.1.2-50.cdx.json"), "utf8"));
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

// The API: a batch is answered with every component not affected, anything else with a summary,
// after latencyMs; while held, no answer goes until release(). It counts the batches it was sent
// and the requests waiting for their answer (open).
async function stubApi() {
  const state = { latencyMs: LATENCY_MS, held: null, open: 0, batches: 0 };
  const server = http.createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (req.url === BATCH_PATH) state.batches++;
      state.open++;
      const answer = () => {
        state.open--;
        if (res.destroyed) return;
        res.writeHead(200, { "content-type": "application/json" });
        if (req.url === BATCH_PATH) {
          const { components } = JSON.parse(b);
          res.end(JSON.stringify(batchAnswer(components.map((c, i) => ROWS.notAffected(i, c.purl, "x", "1")))));
        } else {
          res.end(JSON.stringify(SUMMARY));
        }
      };
      if (state.held) state.held.push(answer);
      else setTimeout(answer, state.latencyMs);
    });
  });
  server.keepAliveTimeout = 60_000;
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    state,
    base: `http://127.0.0.1:${server.address().port}`,
    hold: () => (state.held = []),
    release: () => {
      const held = state.held ?? [];
      state.held = null;
      for (const answer of held) answer();
    },
    close: () => {
      server.closeAllConnections();
      return new Promise((resolve) => server.close(resolve));
    },
  };
}

// dist/http.js as the image starts it, with production's settings but for the API it calls, a
// per-client limit this one client cannot reach, and `extra`; in a cgroup of its own when one can
// be made (the shell joins it, then becomes node, so nothing else is charged to it).
async function startServer(apiBase, name, extra = {}) {
  const env = { ...process.env, PORT: "0", ECHELONGRAPH_API_BASE: apiBase, MCP_RATE_LIMIT_PER_MIN: "100000", ...extra };
  const argv = [...imageNodeFlags(), HTTP_ENTRY];
  const cgroup = makeCgroup(name);
  const proc = cgroup
    ? spawn("sh", ["-c", `echo $$ > "$0/cgroup.procs" && exec "$@"`, cgroup, process.execPath, ...argv], { env, stdio: ["ignore", "pipe", "pipe"] })
    : spawn(process.execPath, argv, { env, stdio: ["ignore", "pipe", "pipe"] });
  const exited = new Promise((resolve) => proc.once("exit", (code, signal) => resolve({ code, signal })));
  proc.stderr.resume();
  const lines = [];
  const started = await new Promise((resolve, reject) => {
    let buf = "";
    proc.stdout.setEncoding("utf8").on("data", (d) => {
      buf += d;
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 1);
        lines.push(JSON.parse(line));
        if (lines.at(-1).message === "mcp_remote_listening") resolve(lines.at(-1));
      }
    });
    exited.then((e) => reject(new Error(`http.js exited before listening: ${JSON.stringify(e)}`)));
  });
  return {
    proc,
    lines,
    started,
    exited,
    cgroup,
    alive: () => proc.exitCode === null && proc.signalCode === null,
    async stop() {
      if (this.alive()) proc.kill("SIGKILL");
      await exited;
      if (cgroup) fs.rmdirSync(cgroup);
    },
  };
}

// One tools/call on a connection of its own; resolves its HTTP status, or the error code of a
// connection the server dropped. onSent: the request has been written whole.
function call(port, name, args, onSent = () => {}) {
  const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } });
  return new Promise((resolve) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        path: "/mcp",
        method: "POST",
        agent: false,
        headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", "MCP-Protocol-Version": "2025-06-18", "Content-Length": Buffer.byteLength(body) },
      },
      (res) => res.on("data", () => {}).on("end", () => resolve(res.statusCode)).on("error", () => resolve("reset")),
    );
    req.on("finish", onSent);
    req.on("error", (e) => resolve(e.code ?? "error"));
    req.end(body);
  });
}

// What the instance went through: whether it died, whether the kernel OOM-killed in its cgroup,
// and its peak memory (the cgroup's, or its resident set's when there is no cgroup).
async function aftermath(t, srv) {
  const died = await Promise.race([srv.exited, sleep(300).then(() => null)]);
  let peak;
  let killed = 0;
  if (srv.cgroup) {
    peak = Number(fs.readFileSync(path.join(srv.cgroup, "memory.max_usage_in_bytes"), "utf8"));
    killed = Number(/oom_kill (\d+)/.exec(fs.readFileSync(path.join(srv.cgroup, "memory.oom_control"), "utf8"))?.[1] ?? 0);
  } else if (!died) {
    peak = 1024 * Number(/VmHWM:\s+(\d+) kB/.exec(fs.readFileSync(`/proc/${srv.proc.pid}/status`, "utf8"))[1]);
  }
  const access = srv.lines.filter((l) => l.message === "mcp_request");
  const queued = access.map((l) => l.queued_ms);
  t.diagnostic(
    `${srv.cgroup ? "cgroup peak" : "peak RSS (VmHWM), not held: no memory cgroup could be made"} ${peak === undefined ? "unread" : (peak / 1e6).toFixed(1)} MB of ${(LIMIT / 1e6).toFixed(1)} MB; heap limit ${srv.started.heap_limit_mb} MiB; oom_kill ${killed}; most in flight ${Math.max(0, ...access.map((l) => l.in_flight))}; waited over 100 ms ${queued.filter((q) => q > 100).length}, longest ${Math.max(0, ...queued)} ms`,
  );
  return { died, killed, peak, access };
}

// What every case holds of the instance itself: alive, not OOM-killed, under the limit, and
// started with the image's heap cap.
function assertSurvived(srv, { died, killed, peak }) {
  assert.equal(died, null, `the server died: ${JSON.stringify(died)}`);
  assert.equal(killed, 0, "the kernel OOM-killed in the cgroup");
  if (srv.cgroup) assert.ok(peak < LIMIT, `cgroup peak ${(peak / 1e6).toFixed(1)} MB at the 256 MiB limit`);
  assert.ok(srv.started.heap_limit_mb < LIMIT / 2 ** 20, `the heap may grow to ${srv.started.heap_limit_mb} MiB: http.js did not get the image's flags`);
  assert.ok(!srv.lines.some((l) => l.message === "mcp_remote_heap_unbounded"), "the server says its heap is unbounded");
}

// The two cases run at once, each with its own API, server and cgroup: each takes 15-30 s.
describe("#2773: two maximum documents plus Cloud Run's concurrency, in 256 MiB", { skip, concurrency: 2 }, () => {
  let P, doc;
  before(async () => {
    P = await import(pathToFileURL(path.join(PKG_DIR, "dist", "httpPolicy.js")).href);
    doc = maxDocument();
    assert.ok(doc.length <= 5_000_000 && doc.length > 4_900_000, `${doc.length}`);
  });

  it("served as they come (the API answering in 1.5 s): all 250 answered 200, the garbage collected under the heap cap", async (t) => {
    const stub = await stubApi();
    // A wait no request reaches, so that all 250 are served whatever this machine's speed: the
    // 2,000-purl documents hold two places for their ten batches, and the instance serves about 28
    // of these a second here, so the last waits ~9 s alone and ~25 s beside the rest of the suite,
    // too near DEFAULT_ADMISSION_WAIT_MS, or past it, to hold.
    const srv = await startServer(stub.base, "as-they-come", { MCP_ADMISSION_WAIT_MS: "120000" });
    try {
      const batches = stub.state.batches;
      const docs = [call(srv.started.port, "check_sbom", { sbom: doc }), call(srv.started.port, "check_sbom", { sbom: doc })];
      while (stub.state.batches < batches + 2 && srv.alive()) await sleep(10);
      const others = Array.from({ length: OTHERS }, () => call(srv.started.port, "cve_summary", {}));
      const statuses = await Promise.all([...docs, ...others]);
      const seen = await aftermath(t, srv);
      assertSurvived(srv, seen);
      assert.deepEqual(tally(statuses), { 200: TOTAL }, "every request answered 200");
      assert.equal(seen.access.length, TOTAL);
    } finally {
      await srv.stop();
      await stub.close();
    }
  });

  it("all 250 inside the instance at once: DEFAULT_MAX_IN_FLIGHT served, the rest answered 503 after DEFAULT_ADMISSION_WAIT_MS, and the instance lives", async (t) => {
    const stub = await stubApi();
    stub.state.latencyMs = 0;
    stub.hold();
    // An API timeout the hold cannot reach: at the default 15 s, on a busy machine, a held call
    // timed out before the last of the 186 was refused, freeing its place to one still waiting.
    const srv = await startServer(stub.base, "at-once", { ECHELONGRAPH_API_TIMEOUT_MS: "120000" });
    try {
      assert.deepEqual(
        [srv.started.max_in_flight, srv.started.admission_wait_ms],
        [P.DEFAULT_MAX_IN_FLIGHT, P.DEFAULT_ADMISSION_WAIT_MS],
        "the server does not run production's admission",
      );
      let sent = 0;
      let answered = 0;
      let allSentAt = Infinity;
      let firstAnsweredAt = Infinity;
      const go = (name, args) =>
        call(srv.started.port, name, args, () => {
          if (++sent === TOTAL) allSentAt = Date.now();
        }).then((s) => {
          answered++;
          firstAnsweredAt = Math.min(firstAnsweredAt, Date.now());
          return s;
        });
      const batches = stub.state.batches;
      const docs = [go("check_sbom", { sbom: doc }), go("check_sbom", { sbom: doc })];
      while (stub.state.batches < batches + 2 && srv.alive()) await sleep(10);
      const others = Array.from({ length: OTHERS }, () => go("cve_summary", {}));
      // Every answer is held until each request is inside the instance: either at the API, its
      // answer held there, or answered by the instance itself (or the instance has died).
      const deadline = Date.now() + 60_000;
      while (!(sent === TOTAL && answered + stub.state.open >= TOTAL) && srv.alive() && Date.now() < deadline) await sleep(20);
      stub.release();
      const statuses = await Promise.all([...docs, ...others]);
      const seen = await aftermath(t, srv);
      assertSurvived(srv, seen);
      assert.ok(firstAnsweredAt > allSentAt, `an answer came ${allSentAt - firstAnsweredAt} ms before the last request was sent: they were never all inside at once`);
      const served = P.DEFAULT_MAX_IN_FLIGHT;
      assert.deepEqual(tally(statuses), { 200: served, 503: TOTAL - served }, "the admission's split");
      assert.deepEqual(statuses.slice(0, 2), [200, 200], "a document was not served");
      assert.equal(seen.access.length, TOTAL);
      assert.equal(Math.max(...seen.access.map((l) => l.in_flight)), served, "the most served at once is not the admission's limit");
      const refused = seen.access.filter((l) => l.status === 503);
      assert.ok(
        refused.every((l) => l.refused === "busy" && l.queued_ms >= P.DEFAULT_ADMISSION_WAIT_MS - 5),
        `a 503 that did not wait DEFAULT_ADMISSION_WAIT_MS: ${JSON.stringify(refused.find((l) => !(l.refused === "busy" && l.queued_ms >= P.DEFAULT_ADMISSION_WAIT_MS - 5)))}`,
      );
    } finally {
      stub.release();
      await srv.stop();
      await stub.close();
    }
  });
});
