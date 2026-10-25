// #3389: the stdio test client turns a write the server can no longer read into a rejected
// request, never an uncaught exception.
//
// A server that has exited, before the parent processes its exit event, or that closed its stdin
// makes the client's write fail with EPIPE, which the stdin socket emits as `error`. With no
// listener that was an uncaught exception. On 2026-10-25 it failed synthetic/run.test.mjs's "a
// server that cannot start" test in one loaded full run (2553/2554), and that test passed alone 6
// of 6. The production synthetic (synthetic/run.mjs) runs on this client, where it would crash the
// run. The race needs the OS to deschedule the parent between spawn and write long enough for a
// fast-failing child to exit. The first two cases make each ordering certain rather than waiting
// for load to produce it. Neutralise the fix (no stdin `error` listener) and both fail with
// `uncaughtException: write EPIPE`.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { connect, MODERN, StdioMcpClient } from "./mcp-stdio-client.mjs";

const LEGACY = "2025-06-18";
const HERE = path.dirname(fileURLToPath(import.meta.url));

// Block this thread (no event loop turn, so no exit event) until `pid` is a zombie: dead, its
// pipes closed, not yet reaped.
function blockUntilZombie(pid, capMs = 10_000) {
  const nap = new Int32Array(new SharedArrayBuffer(4));
  const deadline = Date.now() + capMs;
  while (Date.now() < deadline) {
    const state = fs.readFileSync(`/proc/${pid}/stat`, "utf8").replace(/^.*\) /s, "")[0];
    if (state === "Z") return;
    Atomics.wait(nap, 0, 0, 5);
  }
  throw new Error(`pid ${pid} still running after ${capMs} ms`);
}

describe("#3389: a write the server cannot read rejects the request, with no uncaught exception", () => {
  // The write fails with EPIPE at once, but the error comes back only once the stream has closed,
  // a turn of the event loop later, and the exit may be processed in that same turn. So the
  // rejection names whichever came first; under load, either does.
  it("a server that exited before its exit event is processed: open() rejects", { skip: process.platform !== "linux" && "needs /proc" }, async () => {
    const client = new StdioMcpClient({ command: process.execPath, args: ["-e", ""], stderr: "ignore" });
    blockUntilZombie(client.proc.pid);
    assert.equal(client.exitStatus, undefined, "control: the exit is not yet recorded, so rawRequest's early return cannot answer");
    const opened = await client.open(MODERN).then(() => "resolved", (e) => e.message);
    assert.ok(
      ["server/discover: the request could not be written to the server (EPIPE)", "the server exited (code 0, signal null) before answering server/discover"].includes(opened),
      opened,
    );
    assert.deepEqual(await client.close(), { code: 0, signal: null });
  });

  it("a server that closed its stdin and keeps running: each request rejects at once, not at the exit or the timeout", { skip: process.platform === "win32" && "closes fd 0" }, async () => {
    const script = `require("fs").closeSync(0); process.stdout.write('{"jsonrpc":"2.0","method":"notifications/message","params":{}}\\n'); setInterval(() => {}, 1000);`;
    const client = new StdioMcpClient({ command: process.execPath, args: ["-e", script], stderr: "ignore", requestTimeoutMs: 60_000 });
    try {
      await new Promise((resolve) => client.proc.stdout.once("data", resolve)); // its stdin is closed
      const t0 = performance.now();
      await assert.rejects(client.open(LEGACY), { message: "initialize: the request could not be written to the server (EPIPE)" });
      // The stream is gone now; a later request names the write error that ended it.
      await assert.rejects(client.rawRequest("ping"), { message: "ping: the request could not be written to the server (EPIPE)" });
      const ms = performance.now() - t0;
      assert.ok(ms < 5_000, `rejected after ${Math.round(ms)} ms; the timeout is 60000`);
      assert.deepEqual([client.exitStatus, client.proc.exitCode, client.pending.size], [undefined, null, 0], "rejected by the write, the server still running");
    } finally {
      await client.close(100);
    }
  });

  it("a request written from inside the exit event (stdin destroyed, exit not yet recorded) says the server exited", async () => {
    const client = new StdioMcpClient({ command: process.execPath, args: ["-e", "process.exitCode = 3"], stderr: "ignore" });
    const opened = await new Promise((resolve) => client.proc.once("exit", () => resolve(client.open(MODERN).then(() => "resolved", (e) => e.message))));
    assert.equal(opened, "the server exited (code 3, signal null) before answering server/discover");
  });

  // The case #3389 was seen in, as the synthetic opens it, many at once: every one rejects,
  // whichever of the write or the exit is first, and none throws.
  it("connect() to a server that cannot start rejects in both eras, 24 at once", async () => {
    const missing = path.join(HERE, "does-not-exist.js");
    const results = await Promise.allSettled(
      Array.from({ length: 24 }, (_, i) => connect({ era: i % 2 ? MODERN : LEGACY, command: process.execPath, args: [missing], stderr: "ignore" })),
    );
    for (const [i, r] of results.entries()) {
      const method = i % 2 ? "server/discover" : "initialize";
      assert.equal(r.status, "rejected", `connect ${i}`);
      const want = [`the server exited (code 1, signal null) before answering ${method}`, `${method}: the request could not be written to the server (EPIPE)`];
      assert.ok(want.includes(r.reason.message), `connect ${i}: ${r.reason.message}`);
    }
  });
});
