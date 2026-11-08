// #3381, #3434: dist/http.js started exactly as its image starts it (Dockerfile.http's CMD flags), for the tests that
// drive the hosted endpoint at the heap's edge (test/http-dense-body.test.mjs, http-documents.test.mjs,
// http-parse-budget*.test.mjs, manifest-lines.test.mjs), with a stub API whose answers can be held, and the requests they
// send. test/http-memory.test.mjs reads the flags the same way.
import assert from "node:assert/strict";
import http from "node:http";
import http2 from "node:http2";
import fs from "node:fs";
import path from "node:path";
import { execFileSync, spawn } from "node:child_process";
import { pathToFileURL } from "node:url";
import { PKG_DIR } from "./server-under-test.mjs";
import { BATCH_PATH, ROWS, batchAnswer } from "./fixtures/match-batch.mjs";

export const DOCKERFILE = path.join(PKG_DIR, "Dockerfile.http");
export const HTTP_ENTRY = path.join(PKG_DIR, "dist", "http.js");
export const IMAGE_SKIP = !fs.existsSync(DOCKERFILE) ? "Dockerfile.http is not in the package" : false;
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export const SUMMARY = { summary: { critical: 1, high: 2, medium: 3, low: 4, none: 0, total: 10, last_updated: "2026-09-27T01:00:00Z" } };

/** The node flags the image starts http.js with: Dockerfile.http's CMD, ["node", ...flags, "dist/http.js"]. */
export function imageNodeFlags() {
  const cmd = [...fs.readFileSync(DOCKERFILE, "utf8").matchAll(/^CMD (\[.*\])\s*$/gm)].at(-1);
  assert.ok(cmd, "Dockerfile.http has no exec-form CMD");
  const argv = JSON.parse(cmd[1]);
  assert.equal(argv[0], "node");
  assert.equal(argv.at(-1), "dist/http.js");
  return argv.slice(1, -1);
}

/** #3381: the bounds dist/parseBudget.js holds a process started with the image's flags to, read from such a process:
 *  they are a share of its own heap limit (parseBudget.ts budgetsFor), so this process's, whose heap Node sized from
 *  the machine, are not the image's. heap_size_limit is that process's, as V8 reports it. */
export function imageBudgets() {
  const url = pathToFileURL(path.join(PKG_DIR, "dist", "parseBudget.js")).href;
  const script = `import v8 from "node:v8"; import * as B from ${JSON.stringify(url)};
console.log(JSON.stringify({ heap_size_limit: v8.getHeapStatistics().heap_size_limit, BUDGETS: B.BUDGETS, PARSE_BUDGET_BYTES: B.PARSE_BUDGET_BYTES, INFLIGHT_BUDGET_BYTES: B.INFLIGHT_BUDGET_BYTES, MAX_MANIFEST_ITEMS: B.MAX_MANIFEST_ITEMS }));`;
  return JSON.parse(execFileSync(process.execPath, [...imageNodeFlags(), "--input-type=module", "-e", script], { encoding: "utf8" }));
}

/** The API: a match/batch answered with every component not affected, anything else with a summary; while held, no
 *  answer goes until release(). `open`: the requests at it, answered or not yet. `purls`: each batch's first purl, in
 *  the order the batches came. With state.retryAfter set, a batch is answered 429 with that Retry-After. */
export async function stubApi() {
  const state = { held: null, batches: 0, open: 0, purls: [], retryAfter: null };
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      if (req.url === BATCH_PATH) {
        state.batches++;
        try {
          state.purls.push(JSON.parse(Buffer.concat(chunks).toString("utf8")).components[0]?.purl);
        } catch {
          state.purls.push(null);
        }
      }
      state.open++;
      if (req.url === BATCH_PATH && state.retryAfter !== null) {
        res.writeHead(429, { "content-type": "application/json", "retry-after": String(state.retryAfter) });
        return res.end('{"error":"rate limited"}');
      }
      const answer = () => {
        if (res.destroyed) return;
        res.writeHead(200, { "content-type": "application/json" });
        if (req.url !== BATCH_PATH) return res.end(JSON.stringify(SUMMARY));
        const { components } = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        res.end(JSON.stringify(batchAnswer(components.map((c, i) => ROWS.notAffected(i, c.purl, "x", "1")))));
      };
      if (state.held) state.held.push(answer);
      else answer();
    });
  });
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

/** dist/http.js exactly as the image starts it, with production's settings but for the API it calls, a per-client
 *  limit this one client cannot reach, and `extra`. `nodeFlags`: more node flags after the image's (--trace-gc: then
 *  maxLiveMb() is the most V8 found live after a full collection, from its trace lines). `entry`: another build's
 *  http.js (a control's). */
export async function startServer(apiBase, extra = {}, { nodeFlags = [], entry = HTTP_ENTRY } = {}) {
  const env = { ...process.env, PORT: "0", ECHELONGRAPH_API_BASE: apiBase, MCP_RATE_LIMIT_PER_MIN: "100000", ECHELONGRAPH_API_TIMEOUT_MS: "120000", ...extra };
  const proc = spawn(process.execPath, [...imageNodeFlags(), ...nodeFlags, entry], { env, stdio: ["ignore", "pipe", "pipe"] });
  let maxLive = 0;
  const exited = new Promise((resolve) => proc.once("exit", (code, signal) => resolve({ code, signal })));
  let stderr = "";
  proc.stderr.setEncoding("utf8").on("data", (d) => (stderr += d));
  const lines = [];
  const started = await new Promise((resolve, reject) => {
    let buf = "";
    proc.stdout.setEncoding("utf8").on("data", (d) => {
      buf += d;
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 1);
        if (!line.startsWith("{")) {
          // V8's own trace (--trace-gc): "Mark-Compact 101.2 (110.0) -> 95.1 (108.5) MB, ...".
          const m = /Mark-Compact[^>]* -> ([0-9.]+) \(/.exec(line);
          if (m) maxLive = Math.max(maxLive, Number(m[1]));
          continue;
        }
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
    port: started.port,
    // #3381's round-5 review (T4): started h2c (MCP_H2C=1, as production serves it): its requests then go over h2c.
    h2c: env.MCP_H2C === "1",
    alive: () => proc.exitCode === null && proc.signalCode === null,
    maxLiveMb: () => maxLive,
    // V8's own line when it aborted ("FATAL ERROR: Reached heap limit ... JavaScript heap out of memory"), else the last lines.
    stderrTail: () => /FATAL ERROR:[^\n]*/.exec(stderr)?.[0] ?? stderr.split("\n").filter(Boolean).slice(-3).join(" | "),
    access: (from = 0) => lines.slice(from).filter((l) => l.message === "mcp_request" && l.path === "/mcp"),
    async stop() {
      if (this.alive()) proc.kill("SIGKILL");
      await exited;
    },
  };
}

/** One POST /mcp on a connection of its own, 2025-era (the era of the measurements). Resolves its status and answer, or
 *  status "reset" and the error code of a connection the server dropped. `signal` aborts it (the client going). */
export function post(port, body, { signal } = {}) {
  return new Promise((resolve) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        path: "/mcp",
        method: "POST",
        agent: false,
        signal,
        headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", "MCP-Protocol-Version": "2025-06-18", "Content-Length": Buffer.byteLength(body) },
      },
      (res) => {
        let text = "";
        res
          .setEncoding("utf8")
          .on("data", (c) => (text += c))
          .on("end", () => resolve({ status: res.statusCode, text }))
          .on("error", (e) => resolve({ status: "reset", code: e.code }));
      },
    );
    req.on("error", (e) => resolve({ status: e.name === "AbortError" ? "aborted" : "reset", code: e.code }));
    req.end(body);
  });
}

/** #3381's round-5 review (T4): one h2c session (prior knowledge, as Cloud Run's --use-http2 speaks to the container),
 *  its POSTs to /mcp each a stream of it, answered as post() answers. */
export function h2cSession(port) {
  const session = http2.connect(`http://127.0.0.1:${port}`);
  session.on("error", () => {});
  return {
    post(body) {
      return new Promise((resolve) => {
        const req = session.request({ ":method": "POST", ":path": "/mcp", "content-type": "application/json", accept: "application/json, text/event-stream", "mcp-protocol-version": "2025-06-18", "content-length": Buffer.byteLength(body) });
        let status;
        let text = "";
        let ended = false;
        req.on("response", (h) => (status = h[":status"]));
        req.setEncoding("utf8");
        req.on("data", (c) => (text += c));
        req.on("end", () => {
          ended = true;
          resolve({ status, text });
        });
        req.on("error", (e) => resolve({ status: "reset", code: e.code }));
        // A stream the server's end closes (its process gone) without an end or an error: dropped, never awaited.
        req.on("close", () => {
          if (!ended) resolve({ status: "reset", code: req.rstCode === undefined ? "closed" : `rst ${req.rstCode}` });
        });
        req.end(body);
      });
    },
    // A session the server's end already closed emits no second close: given up at once, never awaited.
    close: () =>
      new Promise((resolve) => {
        if (session.closed || session.destroyed) return resolve();
        session.close(resolve);
        setTimeout(() => {
          session.destroy();
          resolve();
        }, 2000).unref();
      }),
  };
}

/** GET /health over a session of its own, h2c. */
export function h2cHealth(port) {
  return new Promise((resolve) => {
    const session = http2.connect(`http://127.0.0.1:${port}`);
    session.on("error", (e) => resolve(e.code));
    const req = session.request({ ":method": "GET", ":path": "/health" });
    req.on("response", (h) => {
      req.resume();
      req.on("end", () => {
        session.close();
        resolve(h[":status"]);
      });
    });
    req.on("error", (e) => {
      session.destroy();
      resolve(e.code);
    });
    req.end();
  });
}

export function health(port) {
  return new Promise((resolve) => {
    const req = http.get({ host: "127.0.0.1", port, path: "/health", agent: false }, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode));
    });
    req.on("error", (e) => resolve(e.code));
  });
}

/** A tools/call body. */
export const toolCall = (name, args) => JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } });

/** The JSON-RPC result of an answer (SSE or JSON), or undefined. */
export function resultOf(r) {
  if (typeof r.text !== "string") return undefined;
  const data = r.text.startsWith("event:") ? r.text.split("\n").find((l) => l.startsWith("data: "))?.slice(6) : r.text;
  try {
    return JSON.parse(data ?? "").result;
  } catch {
    return undefined;
  }
}

/** What every case holds of the instance after its requests: alive (a V8 abort is the failure these guard against, and
 *  says so), its /health answering 200. */
export async function assertAlive(srv, what) {
  const died = await Promise.race([srv.exited, sleep(300).then(() => null)]);
  assert.equal(died, null, `${what}: the process exited ${JSON.stringify(died)}${died?.signal === "SIGABRT" ? " (ABORTED, exit 134)" : ""}: ${srv.stderrTail()}`);
  assert.equal(await (srv.h2c ? h2cHealth : health)(srv.port), 200, `${what}: /health did not answer 200 after it`);
}

/** Answered (any HTTP status with a body) or refused, never a dropped connection. */
export function assertAnsweredOrRefused(r, what) {
  assert.notEqual(r.status, "reset", `${what}: the connection was reset (${r.code}), not answered or refused`);
  assert.ok(Number.isInteger(r.status), `${what}: ${JSON.stringify(r).slice(0, 300)}`);
}
