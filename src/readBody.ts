// Reading an /mcp request's body under the large-body slots (#2747, #2775). It was part of http.ts, which starts
// serving when it is imported; here a test can drive it with requests of its own (test/read-body.test.mjs).
import type http from "node:http";
import type http2 from "node:http2";
import { largeBodyAdmissible, type SlotHold, type Slots } from "./httpPolicy.js";

export function header(req: http.IncomingMessage, name: string): string | undefined {
  const v = req.headers[name];
  return Array.isArray(v) ? v.join(", ") : v;
}

// Whether the request has closed or is closing, so that a 'close' listener attached now may never be called (#2775).
// HTTP/1.1: IncomingMessage.destroyed is set the moment it is destroyed; .closed only once that has finished, with
// 'close' on a later tick (Node 20 and 22 alike). h2c: node:http2's compatibility request is never destroyed itself
// (after a reset its .destroyed and .closed stay false), so its stream is read.
function closedAlready(req: http.IncomingMessage): boolean {
  const stream = (req as unknown as Partial<http2.Http2ServerRequest>).stream;
  return req.destroyed || stream?.destroyed === true || stream?.closed === true;
}

// Reads the body. Up to MAX_BODY_BYTES it is read for any request. Past it, only a request that
// may be one of LARGE_BODY_TARGETS (largeBodyAdmissible: its Mcp-Method / Mcp-Name headers,
// when sent, say so) reads on, up to MAX_SBOM_BODY_BYTES, and only while it holds one of this
// instance's large-body slots. None free: it waits up to LARGE_BODY_WAIT_MS for one, at most
// DEFAULT_LARGE_BODY_WAITERS at once (#2775, decided 2026-10-18), its body not read on meanwhile, and
// is "busy" when the wait runs out or two already wait. `timing.slotWaitMs` is how long it waited.
// Over the cap that applies: "too_large". Either way the rest is discarded unread (the response
// closes the connection). A body that crossed MAX_BODY_BYTES returns holding its slot; the caller
// releases it. "gone": the request closed before its body ended, so the client went mid-upload or
// mid-wait (a reset h2 stream ends the request with 'close' and no 'error', #2775); its slot or its
// place among the waiters is given up here. Over HTTP/1.1 a close is read only after the bytes sent
// before it, and a waiting body is not read on: a waiter whose client went after sending more than
// the server buffers for its request (a whole ~72 KB body did on Node 20, every run) keeps its place
// to its turn, and its close is seen only once its body has been read. Over h2c, production's
// protocol, a reset is read at once, whatever the stream holds (test/http.test.mjs's waiter tests).
// "stalled" (#3362): no byte came for BODY_IDLE_MS while the body was read (its wait for a slot aside), and nothing
// ended it either: such as a client that went mid-upload whose going never reached this server. Its slot is given back
// here. `slot` (#3362): the hold of the slot a body read whole still holds, which the caller gives back
// (Slots.release(hold)); undefined for a body that needed none.
export type BodyRead = { body: Buffer; slot: SlotHold | undefined } | "too_large" | "busy" | "gone" | "stalled";

// The caps and the waits readBody applies, which http.ts reads from its environment.
export type BodyLimits = { maxBodyBytes: number; maxSbomBodyBytes: number; largeBodyWaitMs: number; bodyIdleMs: number };

// readBody over these slots (http.ts: the instance's large-body slots) and these limits.
export function bodyReader(
  largeBodies: Slots,
  limits: BodyLimits,
): (req: http.IncomingMessage, gone: AbortSignal, timing: { slotWaitMs: number }) => Promise<BodyRead> {
  const { maxBodyBytes: MAX_BODY_BYTES, maxSbomBodyBytes: MAX_SBOM_BODY_BYTES, largeBodyWaitMs: LARGE_BODY_WAIT_MS, bodyIdleMs: BODY_IDLE_MS } = limits;
  return readBody;

  async function readBody(req: http.IncomingMessage, gone: AbortSignal, timing: { slotWaitMs: number }): Promise<BodyRead> {
    const mayBeLarge = largeBodyAdmissible(header(req, "mcp-method"), header(req, "mcp-name"));
    const cap = mayBeLarge ? MAX_SBOM_BODY_BYTES : MAX_BODY_BYTES;
    const declared = Number(req.headers["content-length"]);
    if (Number.isFinite(declared) && declared > cap) {
      req.resume();
      return "too_large";
    }
    // The wait for a slot stops when the client goes (the response closes) or the request closes.
    const waitOver = new AbortController();
    const stopWaiting = (): void => waitOver.abort();
    gone.addEventListener("abort", stopWaiting, { once: true });
    req.once("close", stopWaiting);
    // #2775 (3.1.0's release dry run, 2026-10-25): an abort or a close that came before these listeners is never
    // emitted again, so it is read from the signal and the request as they are now. Without this, a reader started
    // after its client went would take a place among the waiters (to the end of its wait), or a free slot, which
    // readBodyHolding would then hold for good. http.ts never starts one late: it calls readBody in the request's own
    // event, and a reset or a close sent with the request's headers still reaches these listeners (3.1.0's review).
    // test/read-body.test.mjs calls it late.
    if (gone.aborted || closedAlready(req)) stopWaiting();
    const waitForSlot = async (): Promise<SlotHold | undefined> => {
      // A free slot is no wait (slot_wait_ms stays 0), however the clock falls; nor is a refusal at once (two already
      // wait): only a real wait is timed. Timing the at-once refusal across its await logged slot_wait_ms 1 when the
      // clock's millisecond turned under load (a full npm test run, 2026-10-18).
      const free = largeBodies.tryAcquire();
      if (free) return free;
      if (!largeBodies.wouldWait(LARGE_BODY_WAIT_MS) || waitOver.signal.aborted) return undefined;
      const t = Date.now();
      const got = await largeBodies.acquire(LARGE_BODY_WAIT_MS, waitOver.signal);
      timing.slotWaitMs += Date.now() - t;
      return got;
    };
    let slot: SlotHold | undefined;
    try {
      if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
        slot = await waitForSlot();
        if (!slot) {
          if (waitOver.signal.aborted) return "gone";
          req.resume();
          return "busy";
        }
      }
      return await readBodyHolding(req, cap, slot, waitForSlot, waitOver.signal);
    } finally {
      gone.removeEventListener("abort", stopWaiting);
      req.off("close", stopWaiting);
    }
  }

  function readBodyHolding(
    req: http.IncomingMessage,
    cap: number,
    holding: SlotHold | undefined,
    waitForSlot: () => Promise<SlotHold | undefined>,
    waitOver: AbortSignal,
  ): Promise<BodyRead> {
    let slot = holding;
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      let size = 0;
      let done = false;
      // #3362: armed while the body is read, from the first moment and again at each chunk; cleared while it waits for
      // a slot (paused, so nothing can come) and once it is settled.
      let idle: ReturnType<typeof setTimeout> | undefined;
      const watch = (reading: boolean): void => {
        clearTimeout(idle);
        idle = reading
          ? setTimeout(() => {
              if (!done) stop("stalled");
            }, BODY_IDLE_MS)
          : undefined;
      };
      const stop = (r: "too_large" | "busy" | "gone" | "stalled"): void => {
        done = true;
        watch(false);
        chunks.length = 0;
        largeBodies.release(slot);
        slot = undefined;
        resolve(r);
      };
      // The client went (waitOver: readBody's listeners, which also read whether it had gone before they were
      // attached), however long ago: a request that closed first emits no 'data', 'end' or 'close' for the listeners
      // below, and would hold its slot for good (#2775).
      const onGone = (): void => {
        if (!done) stop("gone");
      };
      if (waitOver.aborted) return onGone();
      waitOver.addEventListener("abort", onGone, { once: true });
      watch(true);
      req.on("data", (chunk: Buffer) => {
        if (done) return;
        watch(true);
        size += chunk.length;
        if (size > cap) return stop("too_large");
        if (size > MAX_BODY_BYTES && !slot) {
          // A body with no Content-Length crossed MAX_BODY_BYTES: it waits for a slot holding what it has read (at most
          // MAX_BODY_BYTES and this chunk), and reads on once it has one.
          req.pause();
          watch(false);
          chunks.push(chunk);
          void waitForSlot().then((got) => {
            if (done) {
              largeBodies.release(got);
              return;
            }
            if (!got) return stop(waitOver.aborted ? "gone" : "busy");
            slot = got;
            watch(true);
            req.resume();
          });
          return;
        }
        chunks.push(chunk);
      });
      req.on("end", () => {
        if (done) return;
        done = true;
        watch(false);
        resolve({ body: Buffer.concat(chunks), slot });
      });
      req.on("close", () => {
        if (!done) stop("gone");
      });
      req.on("error", (e) => {
        if (done) return;
        done = true;
        watch(false);
        largeBodies.release(slot);
        reject(e);
      });
    });
  }
}
