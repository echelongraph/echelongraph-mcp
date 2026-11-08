// What parsing a client's text costs this process's heap, estimated before it is parsed (#3381).
//
// A JSON text is parsed whole before anything counts what it holds: a hosted request's body (http.ts: bodyFacts, then
// the SDK), and a document a tool reads from a string (check_sbom's sbom passed as text, scan_manifest's JSON
// lockfiles). Per byte, what parsing builds can cost V8 far more than the text it came in. So the text is counted
// first, in one pass over it (scanJson), into an estimate of the bytes its parse retains (estimateOf), and a text past
// the bound is refused unparsed. The estimate is a worst case per unit, each unit's weight measured under
// Dockerfile.http's flags (WEIGHTS says what was measured), so whatever its shape a text costs no more than it says.
//
// The hosted endpoint also reserves each request's estimate in one budget for the whole process (ParseBudget, http.ts),
// with what a tool parses from a string when it parses it (runtime.ts reserveParse), so that what all requests in
// flight hold at once is bounded too, not only what each holds.
import { randomFillSync } from "node:crypto";
import v8 from "node:v8";

// ── The weights (#3381) ──
//
// Retained bytes after JSON.parse, measured 2026-10-29 under Dockerfile.http's flags (Node 22.22, heap limit 152 MiB),
// N items in one array, the heap read after a full collection with the parsed value held:
//   {} 64 B, [] 40 B, [0] 64 B, [0.5] 64 B, {"a":0} 40 B, {"a":0.5} 56 B, [0,0,0,0,0,0,0,0] 120 B, an integer 8 B, a
//   number no small integer holds (0.5) beside an object 24 B, a short string no other value repeats 32 B (5
//   characters); and, where an object's keys are what costs:
//   {"0":0} (an array-index key) 88 B; {"1000123":0} (an index past the first, a dictionary of elements) 208 B;
//   {"k1a2b":0} (a key no other object has: a hidden class of its own) 184 B; objects of a combination of four keys of
//   64 that no other object has 280 B; one object of 300,000 keys no other object has 66 B a key.
// The units the scan counts, and the weight each is charged:
//   - WEIGHT_CONTAINER per object or array: its own header, with its in-object slack;
//   - WEIGHT_ELEMENT per array entry or object member: its slot, and a value that is no object or array (a number, a
//     string's header);
//   - WEIGHT_NEW_SHAPE per key that gives its object a hidden class no object before it in the text had (a key, or an
//     order of keys, not seen at that place before): the class, its descriptors and the key;
//   - WEIGHT_INDEX_KEY per key that is an array index (digits only): a backing store of elements, per object;
//   - each character inside a string (keys' included) one byte, two where the string holds one past U+00FF (V8 then
//     keeps all of it two bytes a character);
//   - each byte of the text itself one byte: the text is a string while it is parsed.
// So {} is 32 + 32 = 64 B, a 5-character string 32 + 5 = 37 B (32 measured), {"k1a2b":0} 32 + 2 x 32 + 120 + 5 = 221 B
// (184 measured), {"1000123":0} 32 + 64 + 120 + 160 + 7 = 383 B (208 measured): every shape measured costs no more than
// its estimate, the nearest a short distinct string (0.86 of it).
export const WEIGHT_CONTAINER = 32;
export const WEIGHT_ELEMENT = 32;
export const WEIGHT_NEW_SHAPE = 120;
export const WEIGHT_INDEX_KEY = 160;

/** What scanJson counts in a JSON text, and the bytes its parse is estimated to retain (estimateOf). */
export type JsonStructure = {
  /** The text's length: its bytes, or a string's characters. */
  bytes: number;
  /** Objects and arrays. */
  containers: number;
  /** Array entries and object members, as the SDK's maxToolInputElements counts them. */
  elements: number;
  /** Object members' keys. */
  keys: number;
  /** Keys that gave their object a hidden class not seen before in the text (see WEIGHT_NEW_SHAPE). */
  newShapes: number;
  /** Keys that are array indices (digits only). */
  indexKeys: number;
  /** Characters inside strings, keys' included: one byte each in a one-byte string, two in a two-byte one. */
  stringBytes: number;
  /** estimateOf this structure. */
  estimate: number;
};

/** The bytes a structure's parse is estimated to retain, the text itself included: see the weights above. */
export function estimateOf(s: Omit<JsonStructure, "estimate">): number {
  return (
    s.bytes +
    s.containers * WEIGHT_CONTAINER +
    s.elements * WEIGHT_ELEMENT +
    s.newShapes * WEIGHT_NEW_SHAPE +
    s.indexKeys * WEIGHT_INDEX_KEY +
    s.stringBytes
  );
}

// ── The scan ──
//
// One pass over the text: O(n) time, no regular expression, nothing kept of the text. Its memory is fixed: the
// shapes seen (SHAPE_SLOTS hashes, at most half of them held) and, per nesting level up to SHAPE_DEPTH, the shape of
// the object open there. A key past those (a text of more distinct shapes, or one nested deeper) counts as a new shape,
// which only raises the estimate. The tables are this module's, one per process, reused by each scan (the scan is
// synchronous: no two run at once).
//
// A shape is the order of keys an object has had so far, as a hash: an object's first key from the empty shape, each
// next one from the shape before it. V8 gives each such order a hidden class of its own, shared by every object that
// has it, so a key costs a new class only where its shape is new. The hash is seeded per process
// (crypto.getRandomValues) and two lanes wide, so a text cannot be written to make new shapes read as seen.
//
// A string's escapes are honoured: a backslash escapes the one byte after it ('"', '\\', the 'u' of \uXXXX, whose four
// hex digits are never a quote), so a string's own braces, brackets, commas and colons are never counted. A key is a
// string that a ':' follows. An element is counted by the comma before it, or as the first of its container:
// elements = commas + the containers that hold one. Every byte at or past 0x80 is inside a string in a JSON text.
// Of a text that is not JSON, what JSON.parse builds before it fails lies before the first byte the two read
// differently, where these counts are exact; past it they only grow.
export const SHAPE_SLOTS = 1 << 14;
export const SHAPE_DEPTH = 1024;
const SHAPE_MAX_HELD = SHAPE_SLOTS >> 1;
const shapeA = new Int32Array(SHAPE_SLOTS);
const shapeB = new Int32Array(SHAPE_SLOTS);
const shapeGen = new Int32Array(SHAPE_SLOTS);
const openShape = new Int32Array(SHAPE_DEPTH);
const openShapeB = new Int32Array(SHAPE_DEPTH);
const openIsObject = new Uint8Array(SHAPE_DEPTH);
let generation = 0;
const SEED = new Int32Array(4);
randomFillSync(SEED);

// fmix32 (MurmurHash3's finalizer): every input bit reaches every output bit.
function fmix(h: number): number {
  h ^= h >>> 16;
  h = Math.imul(h, 0x85ebca6b);
  h ^= h >>> 13;
  h = Math.imul(h, 0xc2b2ae35);
  return h ^ (h >>> 16);
}

/**
 * Counts a JSON text (a body's bytes, or a string a tool parses) and estimates what its parse retains: see the
 * section comment. `src` is read as bytes (UTF-8) or as a string's UTF-16 code units; either way only ASCII is
 * structural.
 */
export function scanJson(src: Uint8Array | string): JsonStructure {
  const isString = typeof src === "string";
  const n = src.length;
  if (++generation === 0x7fffffff) {
    generation = 1;
    shapeGen.fill(0);
  }
  const gen = generation;
  let held = 0;
  let containers = 0;
  let commas = 0;
  let holding = 0;
  let keys = 0;
  let newShapes = 0;
  let indexKeys = 0;
  let stringBytes = 0;
  let depth = 0;
  let opened = false;
  // The last string read: its hash (two lanes), length, whether it is all digits, and whether it holds a character
  // past U+00FF.
  let hashA = 0;
  let hashB = 0;
  let len = 0;
  let digits = false;
  let twoByte = false;
  let afterString = false;
  for (let i = 0; i < n; i++) {
    let b = isString ? (src as string).charCodeAt(i) : (src as Uint8Array)[i];
    if (b === 0x22) {
      // A string: read to its closing quote here.
      hashA = SEED[0];
      hashB = SEED[1];
      len = 0;
      digits = true;
      twoByte = false;
      if (opened) {
        opened = false;
        holding++;
      }
      for (i++; i < n; i++) {
        b = isString ? (src as string).charCodeAt(i) : (src as Uint8Array)[i];
        if (b === 0x22) break;
        if (b === 0x5c) {
          // An escape: the byte after it is the string's, whatever it is. \u past 00FF makes the string two-byte.
          digits = false;
          hashA = Math.imul(hashA ^ b, 0x01000193);
          hashB = Math.imul(hashB ^ b, 0x5bd1e995);
          i++;
          if (i >= n) break;
          b = isString ? (src as string).charCodeAt(i) : (src as Uint8Array)[i];
          if (b === 0x75 && i + 2 < n) {
            const h0 = isString ? (src as string).charCodeAt(i + 1) : (src as Uint8Array)[i + 1];
            const h1 = isString ? (src as string).charCodeAt(i + 2) : (src as Uint8Array)[i + 2];
            if (h0 !== 0x30 || h1 !== 0x30) twoByte = true;
          }
        } else if (b < 0x30 || b > 0x39) {
          digits = false;
          // UTF-8: a lead byte of U+0100 or past; a string's code unit past U+00FF.
          if (isString ? b > 0xff : b >= 0xc4 && b < 0xf8) twoByte = true;
        }
        hashA = Math.imul(hashA ^ b, 0x01000193);
        hashB = Math.imul(hashB ^ b, 0x5bd1e995);
        len++;
      }
      stringBytes += twoByte ? 2 * len : len;
      afterString = true;
      continue;
    }
    if (b === 0x20 || b === 0x0a || b === 0x0d || b === 0x09) continue;
    if (opened) {
      opened = false;
      if (b !== 0x7d && b !== 0x5d) holding++;
    }
    if (b === 0x3a) {
      // A key: the string before this colon.
      if (afterString) {
        keys++;
        if (digits && len > 0 && len <= 10) indexKeys++;
        const inObject = depth > 0 && depth <= SHAPE_DEPTH && openIsObject[depth - 1] === 1;
        if (!inObject || held >= SHAPE_MAX_HELD) {
          newShapes++;
        } else {
          const a = fmix(Math.imul(openShape[depth - 1] ^ fmix(hashA ^ len), 0x9e3779b1) ^ SEED[2]);
          const c = fmix(Math.imul(openShapeB[depth - 1] ^ fmix(hashB + len), 0x85ebca77) ^ SEED[3]);
          let slot = a & (SHAPE_SLOTS - 1);
          for (;;) {
            if (shapeGen[slot] !== gen) {
              shapeGen[slot] = gen;
              shapeA[slot] = a;
              shapeB[slot] = c;
              held++;
              newShapes++;
              break;
            }
            if (shapeA[slot] === a && shapeB[slot] === c) break;
            slot = (slot + 1) & (SHAPE_SLOTS - 1);
          }
          openShape[depth - 1] = a;
          openShapeB[depth - 1] = c;
        }
      }
      afterString = false;
      continue;
    }
    afterString = false;
    if (b === 0x7b || b === 0x5b) {
      containers++;
      opened = true;
      if (depth < SHAPE_DEPTH) {
        openIsObject[depth] = b === 0x7b ? 1 : 0;
        openShape[depth] = SEED[0];
        openShapeB[depth] = SEED[1];
      }
      depth++;
    } else if (b === 0x7d || b === 0x5d) {
      if (depth > 0) depth--;
    } else if (b === 0x2c) commas++;
  }
  const s = { bytes: n, containers, elements: commas + holding, keys, newShapes, indexKeys, stringBytes };
  return { ...s, estimate: estimateOf(s) };
}

/** What parsing a JSON document from a string already held would retain beside it: scanJson's estimate without the
 *  text, which its holder has counted already (a request's body holds an sbom passed as text, or a lockfile). check_sbom
 *  and scan_manifest refuse such a document past PARSE_BUDGET_BYTES before parsing it, and reserve this first. */
export type DocumentCost = { structure: JsonStructure; bytes: number };
export function documentCost(text: string): DocumentCost {
  const structure = scanJson(text);
  return { structure, bytes: structure.estimate - structure.bytes };
}

// ── The budgets (#3381), a share of the heap they protect ──
//
// PARSE_BUDGET_BYTES: the most one text's parse may be estimated to retain (a request body, or a document a tool reads
// from a string), refused past it unparsed. INFLIGHT_BUDGET_BYTES: the most the requests in flight on the hosted
// endpoint may hold reserved at once (ParseBudget, http.ts): each its body's estimate from before its body is parsed
// until the request has stopped, what its tool parses from a string from before it parses it until it has read it,
// then what the answer keeps of it, and (#3381's round-4 review) what the API's answers for its purls hold, from before
// the first batch is sent until the request has stopped (WEIGHT_BATCH_ROW, below) (runtime.ts reserveParse,
// Reservation). A request that does not fit waits for room as a request waits for a place (http.ts), and is refused 503
// when that wait runs out. On stdio there is no in-flight budget (reserveParse); one text's bound applies there too, and
// so do #3434's per-call bounds on what a call's readers take (manifests/common.ts).
//
// Each is a share of the heap V8 may grow to (heap_size_limit), measured where the heap is smallest: the hosted image.
// Measured 2026-10-29 on dist/http.js started with Dockerfile.http's CMD flags (heap limit 152 MiB, IMAGE_HEAP_LIMIT),
// the heap read after a full collection: the idle process holds 18.7 MB; each request held at the API holds about
// 0.45 MB more beside what is reserved for it (64 at once, the most the admission serves: +26 MB; httpPolicy.ts
// "Requests in flight per instance"), and what its parsed body holds besides (64 KiB of empty objects: 1.8 to 1.9 MB a
// request in all). #3381's round-4 review: that 0.45 MB was a cve_summary's; a check_sbom or scan_manifest call holds
// the API's answers for its purls besides (a 2,000-purl call 1.1 to 1.8 MB, measured), which through round 4 nothing
// reserved, and 64 such calls ended the process with the budget showing room: those are reserved now. V8
// ended the process once the heap reached about 104 MB (held tools/call bodies of 64 KiB of empty objects, the 44th to
// 48th). So what the budget may reserve is what is left beside the idle process and 64 requests' own: 104 - 18.7 - 29 =
// 56 MB at the edge. The in-flight budget there is 40 MiB (42 MB), 0.75 of it, the estimate itself an upper bound on
// each shape measured (the weights above). One text's is 28 MiB (29.4 MB): a real document of the cap passes it (Juice
// Shop 11.1.2's CycloneDX components cycled to a 6,290,935-byte check_sbom body, passed as an object, are estimated at
// 23.8 MB, a Syft-shaped one at 22.0 MB; #2773's 5,000,000-character document, passed as text, at 10.5 MB in its body
// and 8.3 MB more as the document check_sbom parses), and two such bodies fit the in-flight budget only one after the
// other, never at once.
//
// On another heap each is the same share of it (budgetsFor): a local server, whose heap Node sizes from the machine's
// memory (several GiB), takes proportionally more than the hosted image, never less. The share is the safe direction on
// a larger heap: the idle process and each request's own hold do not grow with it, so what is left grows faster than
// the share does. The heap is clamped first: to at least MIN_BUDGET_HEAP, a quarter of the image's (7 MiB and 10 MiB),
// so a heap reported smaller, or not at all, still answers a real lockfile and a small document; and to at most
// MAX_BUDGET_HEAP, 4 GiB (754 MiB and 1,077 MiB), so a larger heap does not let one call's parse grow without end: a
// parse of that estimate is seconds in which the process answers nothing else. Each is rounded down to a whole MiB, so
// the image's are exactly 28 MiB and 40 MiB (test/parse-budget.test.mjs starts node with Dockerfile.http's flags and
// reads them). #3381 through round 5 held a call's lines and entries to a share of the heap as well (MAX_MANIFEST_ITEMS,
// 20,000 at the image); #3434 (3.1.3) bounds them per call (manifests/common.ts MAX_MANIFEST_LINES and the rest), on
// both transports alike, past what a real call holds, so that share is gone and those bounds are the ones in force.
const MiB = 1024 * 1024;
export const IMAGE_HEAP_LIMIT = 152 * MiB;
export const MIN_BUDGET_HEAP = IMAGE_HEAP_LIMIT / 4;
export const MAX_BUDGET_HEAP = 4096 * MiB;
// What each is at IMAGE_HEAP_LIMIT, in MiB.
const PARSE_MIB_AT_IMAGE = 28;
const INFLIGHT_MIB_AT_IMAGE = 40;

/** The bounds a process holds itself to, from the heap they protect. */
export type Budgets = {
  /** The heap they are a share of: heap_size_limit, clamped to [MIN_BUDGET_HEAP, MAX_BUDGET_HEAP]. */
  heapLimit: number;
  /** PARSE_BUDGET_BYTES. */
  parseBytes: number;
  /** INFLIGHT_BUDGET_BYTES. */
  inflightBytes: number;
};

/** The budgets for a heap of `heapLimit` bytes (v8.getHeapStatistics().heap_size_limit): each the share of it it is
 *  of IMAGE_HEAP_LIMIT, the heap clamped to [MIN_BUDGET_HEAP, MAX_BUDGET_HEAP] first (a limit not a positive finite
 *  number is MIN_BUDGET_HEAP), rounded down. */
export function budgetsFor(heapLimit: number): Budgets {
  const h = Number.isFinite(heapLimit) && heapLimit > 0 ? Math.min(Math.max(heapLimit, MIN_BUDGET_HEAP), MAX_BUDGET_HEAP) : MIN_BUDGET_HEAP;
  const share = (atImage: number): number => Math.floor((atImage * h) / IMAGE_HEAP_LIMIT);
  return {
    heapLimit: h,
    parseBytes: share(PARSE_MIB_AT_IMAGE) * MiB,
    inflightBytes: share(INFLIGHT_MIB_AT_IMAGE) * MiB,
  };
}

/** This process's: from its own heap limit, as it was started (Dockerfile.http's flags on the hosted endpoint; Node's
 *  own sizing, from the machine's memory, for a local server). */
export const BUDGETS: Budgets = budgetsFor(v8.getHeapStatistics().heap_size_limit);
export const PARSE_BUDGET_BYTES = BUDGETS.parseBytes;
export const INFLIGHT_BUDGET_BYTES = BUDGETS.inflightBytes;

/** One reservation: given back once, by ParseBudget.release(); made smaller by ParseBudget.shrink(), and larger, past
 *  the room if need be, by ParseBudget.grow() or resize() (what it stands for is built already). */
export type BudgetHold = { readonly bytes: number };
/** #3381's round-6 verification (R6V-1.1): a request's holdings, kept live by the budget. Each hold taken with it
 *  adds to bytes, and what it gives back, grows or shrinks moves bytes with it; queued counts its reservations that
 *  wait. Made once per request (newGroup) and passed with each of its reservations. */
export type BudgetGroup = { readonly bytes: number; readonly queued: number };
/** small: a reservation of a request whose body is within the general body cap (httpPolicy.ts DEFAULT_MAX_BODY_BYTES),
 *  its body's or its tool's, which never waits behind a large one while the small ones fit their share (ParseBudget).
 *  group: the reserving request's holdings (BudgetGroup): what it holds already is group's bytes, as they are now.
 *  own: what the reserving request already holds, as a number, where no group is given (it is then not kept live).
 *  since: when the reserving request began (Date.now()), which places it among the waiters; now, if not given.
 *  lane: a request's body's reservation, which alone may take the tiny lane (R7V-1.1, below). */
export type ReserveOptions = { small?: boolean; lane?: boolean; group?: BudgetGroup; own?: number; since?: number };
type Group = { bytes: number; queued: number };

// ParseBudget's order of admission (#3381's review). A reservation that fits is taken at once, ahead of any that wait
// and do not fit: through round 3 the budget was first come, first served, and one large waiter that did not fit held
// every request behind it, a tools/list of a few hundred bytes included, until it was let in or gave up (9 s and more).
// What bounds how long a waiter can be passed: once the oldest waiter has waited BUDGET_STARVE_MS, a reservation that is
// not small is taken only if the room that waiter needs is left beside it, so as those holding the budget give it back,
// the room comes to the waiter. A small reservation (ReserveOptions) is taken whenever it fits, whatever waits, while
// all the small ones together hold at most a quarter of the budget (smallShare): so a waiter of up to three quarters of
// the budget (every body's estimate: PARSE_BUDGET_BYTES is 0.7 of INFLIGHT_BUDGET_BYTES at every heap) is let in once
// the large holders before it end, however many small ones come meanwhile.
//
// #3381's round-4 review. A tool's reservation (a document it reads, its answer) comes from a request that already
// holds its body's: the waiter's own room is then its body's and its document's together, which http.ts keeps to three
// quarters of the budget (max - smallShare: it answers too_large past it, F4), what this guarantee covers; through round
// 4 one of up to the whole budget waited, and small bodies passed it until it gave up. Such a reservation takes the
// place of its request among the waiters (since: when the request began, F3): a waiter that came after the request
// began never holds up its tool's reservation, and one that came before does only while it could be let in beside what
// the waiting requests hold, this one's among them (they give nothing back while they wait); through round 4 a request
// holding its body waited for a later waiter that needed that body's room, until one of them gave up. A reservation of
// a request with a small body is small too (F2), and one of 0 bytes is taken whenever it fits: through round 4 a
// scan_manifest of a few hundred bytes waited behind a large waiter as the tools/list of round 3 had.
export const BUDGET_STARVE_MS = 1000;
// #3381's round-5 review (B1): `share`, the part of a hold taken within the small share, which is all smallUsed counts.
// Through round 5 a small hold counted its bytes in the share whichever path let it in, so two ordinary small requests
// past the share closed the fast path for every small one (a tools/list waited behind a starved large waiter again).
// Now a small one taken by the ordinary path (it did not fit the share) counts nothing in it. A hold taken within the
// share grows within it (grow: the API's answers past their reservation, built already): what the small holds hold
// together is what a starved waiter of max - smallShare waits to fit beside, so their growth closes the share's way in
// as their taking does (its verifier: a steady flow of small holds grown outside the share kept such a waiter out past
// its wait; ParseBudget's test of it). So that growth is rare, a tool reserves the most its kept part can be, and keeps
// no more (check_sbom.ts, scan_manifest.ts): through round 5 check_sbom grew its document's hold to what it kept.
//
// #3381's round-6 verification (R6V-1.2): growth within the share can take it past smallShare, and every small
// reservation then took the ordinary way, a tools/list behind a starved waiter. So a tiny one (at most tinyBytes: a
// 640th of the budget, 64 KiB of estimate at the hosted 40 MiB, which a tools/list, initialize or ping body is far
// within) has a lane of its own, open whatever the share holds, while the tiny ones in it hold at most tinyLane together
// (a tenth of the budget: 4 MiB at the hosted 40, a tiny body for each of DEFAULT_MAX_IN_FLIGHT's 64 requests), within
// max + overdraft. What the lane takes is counted in the share too (smallUsed), so it closes the share's way in to the
// others as their growth does, and the starved waiter's room still comes as the small holds end. #3381's round-7
// verification (R7V-1.1): only a request's body takes the lane (ReserveOptions.lane, which http.ts passes for the body
// alone), so it holds at most one hold of a request, as its size assumes: through round 7 a tool's small reservation
// took it too (the answers to 51 purls are 65,280 bytes), and a few batched requests' calls could fill it and the share
// together, a tools/list behind a starved waiter again.
//
// #3381's round-6 verification (R6V-1.1): what a waiting request holds (its own) is read from its group as it is now.
// Through round 6 it was a number taken when the reservation queued, and a batch sibling's answers charged after it
// (grow) or its kept part (shrink) left queuedOwn stale: too low, a waiter the waiting requests kept out was waited for
// (the round-4 F3 hold-and-wait, through a batch); too high, a waiter that could be let in beside them was passed.
// queuedOwn is now the sum of the groups' bytes with a reservation waiting, kept as they change, and a change while one
// waits drains (a rise can let a waiter pass a starved one it could not).
type Hold = { bytes: number; small: boolean; share: number; tiny: number; group?: Group };
type Waiter = { bytes: number; small: boolean; lane: boolean; own: number; group?: Group; since: number; waitingSince: number; admit: (h: Hold) => void };

/**
 * A process-wide budget of bytes, reserved and given back. tryReserve answers at once; acquire waits for room, up to
 * waitMs and with at most maxWaiting waiting (past that it answers undefined at once), never without bound, and at once
 * undefined for more than the whole budget. Which reservation is taken first: see BUDGET_STARVE_MS. Each reservation is
 * its own hold: a second release of one frees nothing, so no holder can free another's bytes.
 */
export class ParseBudget {
  private readonly holds = new Set<Hold>();
  private readonly queue: Waiter[] = [];
  private used = 0;
  private smallUsed = 0;
  private tinyUsed = 0;
  // What the requests whose reservations wait already hold (their own): they give it back only once they are let in.
  // A group's bytes count once however many of its reservations wait, and as they are now (R6V-1.1, above).
  private queuedOwn = 0;
  readonly starveMs: number;
  readonly smallShare: number;
  readonly overdraft: number;
  readonly tinyBytes: number;
  readonly tinyLane: number;
  private readonly now: () => number;
  constructor(
    readonly max: number,
    readonly maxWaiting = 0,
    opts: { starveMs?: number; smallShare?: number; overdraft?: number; tinyBytes?: number; tinyLane?: number; now?: () => number } = {},
  ) {
    this.starveMs = opts.starveMs ?? BUDGET_STARVE_MS;
    this.smallShare = opts.smallShare ?? Math.floor(max / 4);
    this.overdraft = opts.overdraft ?? Math.floor(max / 4);
    this.tinyBytes = opts.tinyBytes ?? Math.floor(max / 640);
    this.tinyLane = opts.tinyLane ?? Math.floor(max / 10);
    this.now = opts.now ?? Date.now;
  }
  /** A request's holdings, to pass with each of its reservations (ReserveOptions.group). */
  newGroup(): BudgetGroup {
    return { bytes: 0, queued: 0 };
  }
  // A group's bytes moved by `delta`: counted in queuedOwn while one of its reservations waits. Answers whether it was.
  private moved(group: Group | undefined, delta: number): boolean {
    if (group === undefined || delta === 0) return false;
    group.bytes += delta;
    if (group.queued === 0) return false;
    this.queuedOwn += delta;
    return true;
  }
  private enqueued(w: Waiter): void {
    if (w.group === undefined) this.queuedOwn += w.own;
    else if (w.group.queued++ === 0) this.queuedOwn += w.group.bytes;
  }
  private dequeued(w: Waiter): void {
    if (w.group === undefined) this.queuedOwn -= w.own;
    else if (--w.group.queued === 0) this.queuedOwn -= w.group.bytes;
  }
  private ownOf(o: { own: number; group?: Group }): number {
    return o.group === undefined ? o.own : o.group.bytes;
  }
  private take(bytes: number, small: boolean, lane: boolean, group?: Group): Hold {
    // Within the share, or the tiny lane, exactly when fits() let it in by it (it is called right after).
    const share = small && bytes > 0 && this.smallUsed + bytes <= this.smallShare ? bytes : 0;
    const tiny = share === 0 && small && lane && bytes > 0 && bytes <= this.tinyBytes && this.tinyUsed + bytes <= this.tinyLane ? bytes : 0;
    const hold: Hold = { bytes, small, share: share + tiny, tiny, group };
    this.holds.add(hold);
    this.used += bytes;
    this.smallUsed += share + tiny;
    this.tinyUsed += tiny;
    this.moved(group, bytes);
    return hold;
  }
  // Whether `bytes` may be taken now, with the first `ahead` waiters before it, by a request holding `own` (`queued`:
  // its own is counted in queuedOwn already, a reservation of it among the waiters).
  private fits(bytes: number, small: boolean, lane: boolean, ahead: number, own: number, queued: boolean): boolean {
    if (bytes === 0) return true;
    // A small one within the share fits within the overdraft too: the API's answers (grow) can take the budget past
    // max, and a tools/list does not wait for them to end.
    if (small && this.smallUsed + bytes <= this.smallShare) return this.used + bytes <= this.max + this.overdraft;
    // A tiny one, its lane open whatever the share holds (R6V-1.2, above).
    if (small && lane && bytes <= this.tinyBytes && this.tinyUsed + bytes <= this.tinyLane) return this.used + bytes <= this.max + this.overdraft;
    if (this.used + bytes > this.max) return false;
    const now = this.now();
    for (let i = 0; i < ahead; i++) {
      const w = this.queue[i];
      if (now - w.waitingSince < this.starveMs) continue;
      // A waiter the waiting requests keep out (this one's among them) until one of them is let in and ends: waiting
      // for it would be waiting for itself.
      if (own > 0 && this.queuedOwn + (queued ? 0 : own) + w.bytes > this.max) continue;
      return this.used + bytes + w.bytes <= this.max;
    }
    return true;
  }
  // Where a reservation of a request begun at `since` goes among the waiters: after those whose requests began first.
  private placeOf(since: number): number {
    let i = this.queue.length;
    while (i > 0 && this.queue[i - 1].since > since) i--;
    return i;
  }
  /** A hold of `bytes` if they may be taken now (see BUDGET_STARVE_MS); else undefined. */
  tryReserve(bytes: number, opts: ReserveOptions = {}): BudgetHold | undefined {
    const b = Math.max(0, Math.ceil(bytes));
    const small = opts.small === true;
    const group = opts.group as Group | undefined;
    const own = this.ownOf({ own: Math.max(0, opts.own ?? 0), group });
    const lane = opts.lane === true;
    if (!this.fits(b, small, lane, this.placeOf(opts.since ?? this.now()), own, group !== undefined && group.queued > 0)) return undefined;
    const hold = this.take(b, small, lane, group);
    // A request with a reservation waiting holds more now: one before it may now pass a starved waiter.
    if (group !== undefined && group.queued > 0 && b > 0) this.drain();
    return hold;
  }
  /** A hold of `bytes` once they may be taken, waiting up to waitMs; undefined if they never can (more than max), the
   *  wait runs out, `signal` aborts, or maxWaiting already wait. */
  acquire(bytes: number, waitMs: number, signal?: AbortSignal, opts: ReserveOptions = {}): Promise<BudgetHold | undefined> {
    const b = Math.max(0, Math.ceil(bytes));
    const small = opts.small === true;
    const own = Math.max(0, opts.own ?? 0);
    if (b > this.max) return Promise.resolve(undefined);
    const since = opts.since ?? this.now();
    const now = this.tryReserve(b, { ...opts, since });
    if (now) return Promise.resolve(now);
    if (signal?.aborted || waitMs <= 0 || this.queue.length >= this.maxWaiting) return Promise.resolve(undefined);
    return new Promise((resolve) => {
      const entry: Waiter = {
        bytes: b,
        small,
        lane: opts.lane === true,
        own,
        group: opts.group as Group | undefined,
        since,
        waitingSince: this.now(),
        admit: (h: Hold): void => {
          done();
          resolve(h);
        },
      };
      const giveUp = (): void => {
        const i = this.queue.indexOf(entry);
        if (i >= 0) {
          this.queue.splice(i, 1);
          this.dequeued(entry);
        }
        done();
        resolve(undefined);
        // The one that gave up may have held up those behind it.
        this.drain();
      };
      const timer = setTimeout(giveUp, waitMs);
      const done = (): void => {
        clearTimeout(timer);
        signal?.removeEventListener("abort", giveUp);
      };
      signal?.addEventListener("abort", giveUp, { once: true });
      this.queue.splice(this.placeOf(since), 0, entry);
      const before = this.queuedOwn;
      this.enqueued(entry);
      // #3381's round-5 review (B2): what the waiting requests hold has grown, which can let a waiter before this one
      // pass a starved waiter it could not (fits' skip rule): through round 5 it stayed queued until an unrelated
      // release, or the starved waiter's wait ran out.
      if (this.queuedOwn > before) this.drain();
    });
  }
  /** Gives `hold` back, once, and lets in those waiting that may now be taken. */
  release(hold: BudgetHold | undefined): void {
    const h = hold as Hold | undefined;
    if (h === undefined || !this.holds.delete(h)) return;
    this.used -= h.bytes;
    this.smallUsed -= h.share;
    this.tinyUsed -= h.tiny;
    this.moved(h.group, -h.bytes);
    this.drain();
  }
  /** Makes `hold` hold `bytes` (never more than it holds): what it stands for now holds less. A hold given back, or
   *  one of no more than `bytes`, is left as it is. */
  shrink(hold: BudgetHold | undefined, bytes: number): void {
    const h = hold as Hold | undefined;
    const to = Math.max(0, Math.ceil(bytes));
    if (h === undefined || !this.holds.has(h) || to >= h.bytes) return;
    const freed = h.bytes - to;
    h.bytes = to;
    this.used -= freed;
    // What it holds of the share, and of the tiny lane, is at most what it holds.
    const out = Math.max(0, h.share - to);
    h.share -= out;
    this.smallUsed -= out;
    const tinyOut = Math.max(0, h.tiny - to);
    h.tiny -= tinyOut;
    this.tinyUsed -= tinyOut;
    this.moved(h.group, -freed);
    this.drain();
  }
  /** #3381's round-4 review: makes `hold` hold `bytes` more, room or no room: what it stands for has been built already
   *  (an answer the API sent), so it is counted, and what waits waits for it. Answers whether the budget still holds
   *  all it has taken within its overdraft (in use at most max + overdraft: a quarter of max, which with max is still
   *  inside what the heap leaves at its edge, parseBudget.ts "The budgets"): a caller told no adds no more. A hold given
   *  back is left as it is. */
  grow(hold: BudgetHold | undefined, bytes: number): boolean {
    const h = hold as Hold | undefined;
    const by = Math.max(0, Math.ceil(bytes));
    if (h !== undefined && this.holds.has(h) && by > 0) {
      h.bytes += by;
      this.used += by;
      // A hold within the share grows within it (B1, above); one taken the ordinary way grows outside it.
      if (h.share > 0) {
        h.share += by;
        this.smallUsed += by;
      }
      // Its request holds more: while one of its reservations waits, so do the waiting requests (R6V-1.1).
      if (this.moved(h.group, by)) this.drain();
    }
    return this.used <= this.max + this.overdraft;
  }
  /** Makes `hold` hold `bytes`: shrink() below what it holds, grow() above it. */
  resize(hold: BudgetHold | undefined, bytes: number): void {
    const h = hold as Hold | undefined;
    if (h === undefined) return;
    const to = Math.max(0, Math.ceil(bytes));
    if (to < h.bytes) this.shrink(h, to);
    else this.grow(h, to - h.bytes);
  }
  // In order of their requests' arrival, each waiter that may now be taken, the ones before it still waiting. Taking
  // one only adds to what is used, and takes its own out of what the waiting hold, which lets a later one pass a waiter
  // it could not before: so again from the start after each one let in.
  private drain(): void {
    for (let i = 0; i < this.queue.length; ) {
      const w = this.queue[i];
      if (this.fits(w.bytes, w.small, w.lane, i, this.ownOf(w), true)) {
        this.queue.splice(i, 1);
        this.dequeued(w);
        w.admit(this.take(w.bytes, w.small, w.lane, w.group));
        i = 0;
      } else i++;
    }
  }
  get inUse(): number {
    return this.used;
  }
  /** What smallShare's holds hold of it, their growth and the tiny lane's included (B1, R6V-1.2). */
  get smallInUse(): number {
    return this.smallUsed;
  }
  /** What the requests whose reservations wait hold (R6V-1.1). */
  get waitingOwn(): number {
    return this.queuedOwn;
  }
  get waiting(): number {
    return this.queue.length;
  }
}

// ── What the API's answers for a call's purls hold (#3381's round-4 review) ──
//
// check_sbom and scan_manifest send their purls in batches (tools/match_batch.ts) and keep every batch's answer until
// the call answers, merged, as its data and its text. Through round 4 nothing reserved that: 64 calls of 2,000 purls
// (each a small body, estimated at 157 KB) ended the process, with the budget at 10 MB of 40. Measured under the image's
// flags, the heap read after full collections, 16 calls of 2,000 purls each held at their last batch and then answered:
// 540 B a purl where every row is not affected, 710 B held and 875 B answered where one in 20 is affected with two
// matches (a batch answer of 405 B a row not affected, about 1.4 KB a match); 4 calls of rows half affected with five
// matches each held 1.06 B and answered 2.9 B for every byte of the API's answers. So before its first batch is sent a
// call reserves WEIGHT_BATCH_ROW for each purl, and once each batch is answered, what its answers so far come to at
// WEIGHT_ANSWER_BYTE for each byte, past what was reserved for the purls they answer, is added (ParseBudget.grow: what
// came is held, room or no room), and no further batch is sent while the budget is past its overdraft (match_batch.ts
// sendBatches: not_sent_reason server_busy). 64 calls of 2,000 purls, one row in 20 affected: answered, the most V8 found
// live after a full collection 52 MB (64 at once ended the process through round 4).
export const WEIGHT_BATCH_ROW = 1280;
export const WEIGHT_ANSWER_BYTE = 3;
// #3381's round-10 verification (R10-M1, R10-B1): three bytes a byte holds for a row's own fields, not for its matches.
// Measured 2026-11-03 under Dockerfile.http's flags, one check_sbom of 200 purls on an idle instance, each row affected
// with K matches of core-backend's shape (test/fixtures/fixed-in-dispute-wire.json's, 1.06 KB each; its match_reason's em
// dash makes every string of the answer two bytes a character), the most V8 found live after a full collection while the
// call was answered: 14.9 MB at K=0, 57.3 at K=20 (4.3 MB of answer), 71.3 at K=30, 85.5 at K=40 (8.6 MB): 6.6 to 8.3 MB
// a MB of matches, the answer's own parse 1.23 of it and its text 2; at K=50 (10.7 MB) the process ended (heap out of
// memory), and so did 2,000 purls of K=10 at their fifth batch (11 MB in all), each charged within the budget at three
// bytes a byte. So a batch's answer is charged WEIGHT_ANSWER_BYTE for each byte up to ROW_ANSWER_BYTES a row (a row not
// affected is about 410 B), and WEIGHT_MATCH_BYTE for each byte past that (its matches), and is read only to what that
// leaves room for (match_batch.ts answerCost, mostBytes).
export const ROW_ANSWER_BYTES = 512;
export const WEIGHT_MATCH_BYTE = 10;
/** What a batch's answer of `bytes` for `rows` rows is charged: WEIGHT_ANSWER_BYTE for each byte up to ROW_ANSWER_BYTES a
 *  row, WEIGHT_MATCH_BYTE for each past them. */
export const answerCost = (bytes: number, rows: number): number =>
  Math.ceil(WEIGHT_ANSWER_BYTE * bytes + (WEIGHT_MATCH_BYTE - WEIGHT_ANSWER_BYTE) * Math.max(0, bytes - rows * ROW_ANSWER_BYTES));
/** The most bytes a batch's answer for `rows` rows may be for answerCost to be at most `room`. */
export function mostAnswerBytes(room: number, rows: number): number {
  const light = rows * ROW_ANSWER_BYTES;
  if (room <= 0) return 0;
  return room <= WEIGHT_ANSWER_BYTE * light ? Math.floor(room / WEIGHT_ANSWER_BYTE) : Math.floor(light + (room - WEIGHT_ANSWER_BYTE * light) / WEIGHT_MATCH_BYTE);
}
// A small request's reservation for the answers to at most one batch of purls (200, match_batch.ts MAX_COMPONENTS) is
// small (ReserveOptions): a scan_manifest of a few lines does not wait behind a large waiter (F2). One for more is not:
// 64 calls of 2,000 purls would hold the small share, and a tools/list would wait behind a large waiter again.
export const SMALL_ANSWERS_BYTES = 200 * WEIGHT_BATCH_ROW;

/** What a call refused for its size on the hosted endpoint can do instead. */
export const LOCAL_INSTEAD = "run this server locally (npx -y echelongraph-mcp), whose bounds are a share of its own machine's memory, not this endpoint's";

/** #3381's review: why a tool's document is not read when its request could never hold what reading it takes
 *  (runtime.ts Reservation too_large): named, with the bound, and that the same call will not be read on a retry.
 *  #3381's round-5 review (B3): what its request holds is its body's and, in a JSON-RPC batch, its other calls'.
 *  #3381's round-5 review (C1): the bound in plain words, as the hosted endpoint's (only it reserves), and that the
 *  server run locally holds a call to its own machine's memory instead. `plain`: what that bound is in files, where
 *  it was measured (scan_manifest.ts HOSTED_READS). */
export function tooLargeToHold(what: string, bytes: number, heldBytes: number, maxBytes: number, instead: string, plain?: string): string {
  return `reading ${what} would take an estimated ${Math.ceil(bytes)} bytes of this server's memory beside the ${heldBytes} bytes its request already holds (its body, and its JSON-RPC batch's other calls), more than the ${maxBytes} bytes (${mib(maxBytes)} MiB) one request may hold at once on the hosted endpoint, its body and what reading it holds together${plain ? ` (${plain})` : ""}, so it is not read, and retrying the same call will not change that: ${instead}; or ${LOCAL_INSTEAD}`;
}
const mib = (bytes: number): string => (Math.floor((bytes / (1024 * 1024)) * 10) / 10).toString();

// ── What a manifest reader may build (#3381) ──
//
// scan_manifest reads a call's files into entries: each pinned purl, and each entry not checked with its file, line,
// spec and reason, kept to the answer. What the answer carries of them is the API's answers to the purls (reserved on
// their own: WEIGHT_BATCH_ROW, below) and the entries not checked that data.not_checked lists, at most NOT_CHECKED_MAX
// (#3434: the rest are counted only). So each entry a call's readers will take (counted before they read:
// lockfileEntries, tomlPackages, nonBlankLines, each kind at most #3434's per-call bound for it) is reserved as
// WEIGHT_MANIFEST_ENTRY bytes on the hosted endpoint, and as many of them as the answer can list WEIGHT_MANIFEST_ITEM more
// (scan_manifest.ts manifestEstimate). #3381's round-5 review (C1), measured 2026-11-01 on 3.1.3's readers under
// Dockerfile.http's flags, the heap read after full collections: what readFiles keeps a pinned entry 186 B (40,000
// requirements.txt pins), 215 B (40,000 Gemfile.lock specs), 210 to 298 B (each of 24 real package-lock.json files of
// 155 KB to 1.8 MB); 2,000 entries listed of 40,000 unpinned lines 339 KB in all. Through round 5 every entry was
// reserved 768 B, the answer's listing of each included, so 40,000 lines (#3434's bound, and 3.1.3's own test of it)
// came to 30.7 MB, beside its body past what one request may hold: refused, where 3.1.5 reads them. At 384 B they come
// to 16.9 MB. #3381's round-6 verification (R6V-2.1): beside a body of 40,000 lines near the 5,000,000-character cap
// that is still past it where the text holds one character past U+00FF (the body's string is then two bytes a
// character: 4,959,999 characters, 14.9 MB estimated), and within it in ASCII (10.0 MB): the hosted endpoint refuses
// such a call within #3434's bounds, as scan_manifest's description and rate-limits.md say.
export const WEIGHT_MANIFEST_ENTRY = 384;
export const WEIGHT_MANIFEST_ITEM = 768;

// TOML (Cargo.lock, poetry.lock) is read by manifests/toml.ts into tables. What that reader retains, measured under the
// same flags: an inline table {} 107 B, one of a key no other has 252 B, a [table] header 185 B, [[x]] 107 B, a dotted
// key a.b.c = 0 283 B, a key = 0 87 B, an empty array 41 B, an integer 9 B, a short string 33 B; a Cargo.lock
// [[package]] of four keys 188 B. tomlEstimate counts, outside strings and comments, each '[' and '{' (a table or an
// array), '=' (a key), '.' (a table a dotted key makes), ',' and newline (a value), and charges each character twice (the
// reader's own copy of the text, and the values it keeps): every shape above costs no more than its estimate.
export const WEIGHT_TOML_OPEN = 150;
export const WEIGHT_TOML_KEY = 160;
export const WEIGHT_TOML_DOT = 160;
export const WEIGHT_TOML_VALUE = 40;

// ── How many entries a reader will take, counted without reading (#3381's review) ──
//
// scan_manifest reserves, before it reads, each entry its readers will take (WEIGHT_MANIFEST_ITEM each). Through round 3
// it counted every line of a TOML lockfile and every JSON element of an npm or Composer one, though the readers take one
// entry per [[package]] table and per package: a real 3.2 MB poetry.lock of 820 packages and 30,306 lines was reserved
// 20,000 entries, and with its body could never fit the in-flight budget. Each count below is never fewer than its
// reader takes (each says how), and close to it.

/** Lines with a character other than space, tab or CR: never fewer than the line readers take (requirements.txt,
 *  go.mod, Gemfile.lock and gradle.lockfile each take one per line they read, and skip blank ones). */
export function nonBlankLines(text: string): number {
  let n = 0;
  let blank = true;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === 0x0a) {
      if (!blank) n++;
      blank = true;
    } else if (c !== 0x20 && c !== 0x09 && c !== 0x0d) blank = false;
  }
  return blank ? n : n + 1;
}

// #3381's round-4 review (F10): and a header whose key is a basic string with an escape ([["\u0070ackage"]] is
// [[package]] to the reader), counted as one. #3381's round-7 verification (R7V-2.1): such a header is counted from its
// key's first escape on, its closing ]] not looked for (a count never fewer than before): through round 7 the pattern
// went on to the line's end and back for each backslash it could stop at, and [^\n]* then [ \t]* overlapped on blanks,
// time quadratic in one line ('[["\' and 40,000 spaces 2.3 s; 300,000 spaces stalled the instance for 81 s). Each
// quantifier is now over a class the next token cannot start with, but for [^"\n]* before \\, which it gives back to
// once, at its last backslash: linear in the line (test/parse-budget.test.mjs, its guard of every estimator's regex).
const TOML_PACKAGE_HEADER = /^[ \t]*\[\[[ \t]*(?:(?:package|"package"|'package')[ \t]*\]\]|"[^"\n]*\\)/gm;
// A root key that could be package other than by a [[package]] header: package = [...] (inline tables), or a quoted
// key with an escape, which could spell it.
const TOML_PACKAGE_KEY = /^[ \t]*(?:package|"package"|'package')[ \t]*=|^[ \t]*"[^"\n]*\\/m;

/** Never fewer than the [[package]] tables manifests/lockfiles.ts takes from a TOML lockfile (root.package's tables):
 *  its [[package]] headers, and, where a line could set package otherwise (TOML_PACKAGE_KEY), every '{' as well. */
export function tomlPackages(text: string): number {
  // A leading byte-order mark is not the reader's (manifests/index.ts readFile drops it): the first header is a header.
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  let n = 0;
  TOML_PACKAGE_HEADER.lastIndex = 0;
  while (TOML_PACKAGE_HEADER.exec(text) !== null) n++;
  if (TOML_PACKAGE_KEY.test(text)) for (let i = text.indexOf("{"); i >= 0; i = text.indexOf("{", i + 1)) n++;
  return n;
}

// lockfileEntries' key classes and container flags.
const K_OTHER = 0;
const K_PACKAGES = 1;
const K_DEPENDENCIES = 2;
const K_PACKAGES_DEV = 3;
const K_ANY = 4; // a key written with an escape: it could be any of them
const F_OBJECT = 1;
const F_NPM_PACKAGES = 2; // its members are npm's packages entries
const F_NPM_DEPS = 4; // its members are entries of npm's version-1 dependencies tree
const F_NPM_ENTRY = 8; // an entry of that tree: its own dependencies object is walked too
const F_COMPOSER = 16; // its elements are Composer's packages
const ENTRY_DEPTH = 256; // deeper than this nothing is counted (readNpmLock stops at 64 levels of the tree)

/**
 * Never fewer than the entries readNpmLock or readComposerLock takes from `text` (manifests/npmlock.ts and
 * lockfiles.ts take once each), counted in one pass without parsing it: npm, the members of the root's
 * packages object, or of its version-1 dependencies tree (the root's dependencies object and each entry's own,
 * nested), whichever is more; Composer, the elements of the root's packages and packages-dev lists. A key written with
 * an escape is taken to be any of those names. Malformed text is counted as far as it goes (it is not read anyway).
 */
export function lockfileEntries(text: string, format: "npm" | "composer"): number {
  // #3381's round-4 review (F10): a leading byte-order mark is not the reader's (readFile drops it); read as the start
  // of a literal, it swallowed the root's '{', and nothing was counted.
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  const flags = new Uint8Array(ENTRY_DEPTH);
  const key = new Uint8Array(ENTRY_DEPTH);
  let depth = 0;
  let expectKey = false;
  let expectValue = true;
  let pkg = 0;
  let deps = 0;
  let comp = 0;
  const n = text.length;
  const top = (): number => (depth > 0 && depth <= ENTRY_DEPTH ? flags[depth - 1] : 0);
  // A value starts: an element of a Composer list counts.
  const value = (): void => {
    if (expectValue && depth > 0 && depth <= ENTRY_DEPTH && (top() & F_OBJECT) === 0 && (top() & F_COMPOSER) !== 0) comp++;
    expectValue = false;
  };
  for (let i = 0; i < n; i++) {
    const c = text.charCodeAt(i);
    if (c === 0x22) {
      let j = i + 1;
      let escaped = false;
      while (j < n) {
        const d = text.charCodeAt(j);
        if (d === 0x5c) {
          escaped = true;
          j += 2;
          continue;
        }
        if (d === 0x22) break;
        j++;
      }
      if (expectKey && depth > 0) {
        expectKey = false;
        if (depth <= ENTRY_DEPTH) {
          const len = j - i - 1;
          let k = K_OTHER;
          if (escaped) k = K_ANY;
          else if (len === 8 && text.startsWith("packages", i + 1)) k = K_PACKAGES;
          else if (len === 12 && text.startsWith("dependencies", i + 1)) k = K_DEPENDENCIES;
          else if (len === 12 && text.startsWith("packages-dev", i + 1)) k = K_PACKAGES_DEV;
          key[depth - 1] = k;
          const f = flags[depth - 1];
          if (f & F_NPM_PACKAGES) pkg++;
          if (f & F_NPM_DEPS) deps++;
        }
      } else value();
      i = j;
      continue;
    }
    if (c === 0x7b || c === 0x5b) {
      const object = c === 0x7b;
      value();
      let f = object ? F_OBJECT : 0;
      if (depth > 0 && depth <= ENTRY_DEPTH && (flags[depth - 1] & F_OBJECT) !== 0) {
        const parent = flags[depth - 1];
        const k = key[depth - 1];
        if (format === "npm" && object) {
          if (depth === 1 && (k === K_PACKAGES || k === K_ANY)) f |= F_NPM_PACKAGES;
          if ((depth === 1 || (parent & F_NPM_ENTRY) !== 0) && (k === K_DEPENDENCIES || k === K_ANY)) f |= F_NPM_DEPS;
          if (parent & F_NPM_DEPS) f |= F_NPM_ENTRY;
        }
        if (format === "composer" && !object && depth === 1 && (k === K_PACKAGES || k === K_PACKAGES_DEV || k === K_ANY)) f |= F_COMPOSER;
      }
      if (depth < ENTRY_DEPTH) {
        flags[depth] = f;
        key[depth] = K_OTHER;
      }
      depth++;
      expectKey = object;
      expectValue = !object;
      continue;
    }
    if (c === 0x7d || c === 0x5d) {
      if (depth > 0) depth--;
      expectKey = false;
      expectValue = false;
      continue;
    }
    if (c === 0x2c) {
      const obj = depth > 0 && depth <= ENTRY_DEPTH && (flags[depth - 1] & F_OBJECT) !== 0;
      expectKey = obj;
      expectValue = !obj;
      continue;
    }
    if (c === 0x3a) {
      expectValue = true;
      continue;
    }
    if (c === 0x20 || c === 0x0a || c === 0x0d || c === 0x09) continue;
    // A number, true, false or null: one value, to its end.
    value();
    while (i + 1 < n) {
      const d = text.charCodeAt(i + 1);
      if (d === 0x2c || d === 0x7d || d === 0x5d || d === 0x20 || d === 0x0a || d === 0x0d || d === 0x09 || d === 0x3a) break;
      i++;
    }
  }
  return format === "npm" ? Math.max(pkg, deps) : comp;
}

/** An upper bound on what manifests/toml.ts retains reading `text`, counted in one pass without reading it. */
export function tomlEstimate(text: string): number {
  let opens = 0;
  let keys = 0;
  let dots = 0;
  let values = 0;
  const n = text.length;
  for (let i = 0; i < n; i++) {
    const c = text.charCodeAt(i);
    if (c === 0x22 || c === 0x27) {
      // A string: """ or ''' to its closing three, else to its closing quote (a basic string's escaped quote is its
      // own) or the line's end. Its characters are charged with the rest. #3381's review (F8): where manifests/toml.ts
      // closes it, so the two agree on what is structure: a multi-line basic string's escaped quote is its own too
      // (\""" does not close it), and a closing three may follow up to two quotes of the string's own (""""" closes at its
      // last three).
      if (text.charCodeAt(i + 1) === c && text.charCodeAt(i + 2) === c) {
        let end = -1;
        if (c === 0x27) {
          end = text.indexOf("'''", i + 3);
          if (end >= 0) while (text.charCodeAt(end + 3) === 0x27) end++;
        } else {
          for (let j = i + 3; j < n; j++) {
            const d = text.charCodeAt(j);
            if (d === 0x5c) j++;
            else if (d === 0x22 && text.charCodeAt(j + 1) === 0x22 && text.charCodeAt(j + 2) === 0x22 && text.charCodeAt(j + 3) !== 0x22) {
              end = j;
              break;
            }
          }
        }
        i = end < 0 ? n : end + 2;
        continue;
      }
      for (i++; i < n; i++) {
        const d = text.charCodeAt(i);
        if (d === 0x0a) {
          values++;
          break;
        }
        if (c === 0x22 && d === 0x5c) i++;
        else if (d === c) break;
      }
      continue;
    }
    if (c === 0x23) {
      // A comment, to the line's end (its newline counted below).
      const end = text.indexOf("\n", i);
      i = end < 0 ? n : end - 1;
      continue;
    }
    if (c === 0x5b || c === 0x7b) opens++;
    else if (c === 0x3d) keys++;
    else if (c === 0x2e) dots++;
    else if (c === 0x2c || c === 0x0a) values++;
  }
  return 2 * n + opens * WEIGHT_TOML_OPEN + keys * WEIGHT_TOML_KEY + dots * WEIGHT_TOML_DOT + values * WEIGHT_TOML_VALUE;
}
