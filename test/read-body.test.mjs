// #2775, found by 3.1.0's release dry run (2026-10-25): readBody (src/readBody.ts) learns that a client went from
// the request's 'close' and from the abort of the signal its response aborts, through listeners it attaches when
// it starts. An event that came before those listeners is never emitted again, so a request whose client had
// already gone kept its place among the large-body waiters (to its 15 s wait's end), or took a free slot and held
// it for good: readBodyHolding waited for a 'data', 'end' or 'close' that a closed request never emits. Only a
// reader started late meets this. http.ts calls readBody in the request's own event, and no request to http.js met
// it (3.1.0's review: a reset or a close sent with the request's headers was logged 499 at once, its slot free).
//
// These tests hand readBody requests whose client has gone BEFORE it is called, ordered by events (the request's own
// 'close'), never by a timer. Seeing a client that has gone needs no I/O, so readBody must have answered before the
// event loop turns once: "pending" then is the failure, whatever the machine's load.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import http2 from "node:http2";
import net from "node:net";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { PKG_DIR } from "./server-under-test.mjs";

const { bodyReader } = await import(pathToFileURL(path.join(PKG_DIR, "dist", "readBody.js")).href);
const { Slots, DEFAULT_MAX_BODY_BYTES, DEFAULT_MAX_SBOM_BODY_BYTES, DEFAULT_LARGE_BODY_WAITERS } = await import(
  pathToFileURL(path.join(PKG_DIR, "dist", "httpPolicy.js")).href
);

// http.ts's defaults, but a 2 s wait: the code before the fix waits it out, and the file must not hang on it.
const LIMITS = { maxBodyBytes: DEFAULT_MAX_BODY_BYTES, maxSbomBodyBytes: DEFAULT_MAX_SBOM_BODY_BYTES, largeBodyWaitMs: 2000 };
const LARGE = DEFAULT_MAX_BODY_BYTES + 6 * 1024; // past the general cap: a body that needs a slot
const SMALL = 1024;

// What readBody answered before the event loop turned once, or "pending"; a body read is named by its size (an
// assertion handed the Buffer itself made the test runner exhaust its heap reporting it).
const atOnce = (p) =>
  Promise.race([p, new Promise((resolve) => setImmediate(() => resolve("pending")))]).then((r) => (typeof r === "string" ? r : `a body of ${r.body.length} bytes, holding a slot: ${r.slot}`));
const live = () => new AbortController().signal; // a response still open
const aborted = () => AbortSignal.abort();

// An HTTP/1.1 server that hands each request to the test, unread.
let h1, h1Port;
const h1Requests = [];
// An h2c server, as http.ts serves with MCP_H2C=1 (node:http2's compatibility API).
let h2, h2Port, session;
const h2Requests = [];
before(async () => {
  h1 = http.createServer((req) => h1Requests.push(req));
  await new Promise((resolve) => h1.listen(0, "127.0.0.1", resolve));
  h1Port = h1.address().port;
  h2 = http2.createServer((req) => h2Requests.push(req));
  await new Promise((resolve) => h2.listen(0, "127.0.0.1", resolve));
  h2Port = h2.address().port;
  session = http2.connect(`http://127.0.0.1:${h2Port}`);
  session.on("error", () => {});
});
after(async () => {
  session?.destroy();
  h1.closeAllConnections();
  await new Promise((resolve) => h1.close(resolve));
  await new Promise((resolve) => h2.close(resolve));
});

const nextRequest = async (list) => {
  const n = list.length;
  while (list.length === n) await new Promise((resolve) => setImmediate(resolve));
  return list[n];
};

// An HTTP/1.1 request declaring `declared` bytes, of which `sent` are sent. Resolves the server's request and the
// client's socket once the request has reached the handler.
async function h1Request(declared, sent) {
  const waiting = nextRequest(h1Requests);
  const sock = net.connect(h1Port, "127.0.0.1");
  sock.on("error", () => {});
  await new Promise((resolve) => sock.once("connect", resolve));
  sock.write(`POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: ${declared}\r\n\r\n${"x".repeat(sent)}`);
  return { req: await waiting, sock };
}
// The same, whose client then goes; resolves once the server's request has emitted 'close'.
async function h1Gone(declared) {
  const { req, sock } = await h1Request(declared, 10);
  const closed = new Promise((resolve) => req.once("close", resolve));
  sock.destroy();
  await closed;
  return req;
}
// An h2c request whose stream the client resets; resolves once the server's request has emitted 'close'.
async function h2Gone(declared) {
  const waiting = nextRequest(h2Requests);
  const stream = session.request({ ":method": "POST", ":path": "/mcp", "content-type": "application/json", "content-length": String(declared) }, { endStream: false });
  stream.on("error", () => {});
  stream.write("x".repeat(10));
  const req = await waiting;
  const closed = new Promise((resolve) => req.once("close", resolve));
  stream.close(http2.constants.NGHTTP2_CANCEL);
  await closed;
  return req;
}
// One slot, held by someone else: a large body must wait for it.
const busySlots = () => {
  const slots = new Slots(1, DEFAULT_LARGE_BODY_WAITERS);
  assert.equal(slots.tryAcquire(), true);
  return slots;
};

// A request that never reaches its server, or a read that never settles, fails here rather than hanging the file.
describe("#2775: readBody answers 'gone' for a client that went before it looked, and keeps no slot or place", { timeout: 30_000 }, () => {
  it("control: a live request's body is read, and a large one holds the slot it took", async () => {
    const slots = new Slots(1, DEFAULT_LARGE_BODY_WAITERS);
    const { req, sock } = await h1Request(LARGE, LARGE);
    const r = await bodyReader(slots, LIMITS)(req, live(), { slotWaitMs: 0 });
    assert.equal(r.body?.length, LARGE, typeof r === "string" ? r : "a body of another size");
    assert.equal(r.slot, true);
    assert.equal(slots.inUse, 1);
    slots.release();
    sock.destroy();
  });

  it("control: a waiter whose client goes during its wait is 'gone' and leaves the queue", async () => {
    const slots = busySlots();
    const { req, sock } = await h1Request(LARGE, 10);
    const read = bodyReader(slots, LIMITS)(req, live(), { slotWaitMs: 0 });
    assert.equal(slots.waiting, 1, "the large body is waiting for the slot");
    sock.destroy();
    assert.equal(await read, "gone");
    assert.equal(slots.waiting, 0);
  });

  for (const [what, gonePrep] of [
    ["HTTP/1.1: a request that closed", h1Gone],
    ["h2c: a request whose stream was reset", h2Gone],
  ]) {
    it(`${what} before readBody, a slot free: 'gone' at once, and the slot stays free`, async () => {
      const slots = new Slots(1, DEFAULT_LARGE_BODY_WAITERS);
      const req = await gonePrep(LARGE);
      assert.equal(await atOnce(bodyReader(slots, LIMITS)(req, live(), { slotWaitMs: 0 })), "gone");
      assert.equal(slots.inUse, 0, "a client that had gone took the slot");
    });
    it(`${what} before readBody, every slot busy: 'gone' at once, never among the waiters`, async () => {
      const slots = busySlots();
      const timing = { slotWaitMs: 0 };
      const read = bodyReader(slots, LIMITS)(await gonePrep(LARGE), live(), timing);
      assert.equal(slots.waiting, 0, "a client that had gone took a place among the waiters");
      assert.equal(await atOnce(read), "gone");
      assert.equal(timing.slotWaitMs, 0);
    });
    it(`${what} before readBody, a small body: 'gone' at once`, async () => {
      const slots = new Slots(1, DEFAULT_LARGE_BODY_WAITERS);
      assert.equal(await atOnce(bodyReader(slots, LIMITS)(await gonePrep(SMALL), live(), { slotWaitMs: 0 })), "gone");
      assert.equal(slots.inUse, 0);
    });
  }

  it("a response that closed before readBody (its signal aborted), every slot busy: 'gone' at once, never among the waiters", async () => {
    const slots = busySlots();
    const { req, sock } = await h1Request(LARGE, 10);
    const read = bodyReader(slots, LIMITS)(req, aborted(), { slotWaitMs: 0 });
    assert.equal(slots.waiting, 0, "a client that had gone took a place among the waiters");
    assert.equal(await atOnce(read), "gone");
    sock.destroy();
  });

  it("a response that closed before readBody (its signal aborted), a slot free: 'gone' at once, and the slot stays free", async () => {
    const slots = new Slots(1, DEFAULT_LARGE_BODY_WAITERS);
    const { req, sock } = await h1Request(LARGE, LARGE);
    assert.equal(await atOnce(bodyReader(slots, LIMITS)(req, aborted(), { slotWaitMs: 0 })), "gone");
    assert.equal(slots.inUse, 0, "a client that had gone took the slot");
    sock.destroy();
  });
});
