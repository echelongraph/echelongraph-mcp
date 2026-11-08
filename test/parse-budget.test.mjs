// #3381: what parsing a client's text costs, estimated before it is parsed (src/parseBudget.ts), in isolation: the scan
// (scanJson) and its estimate, the process-wide budget (ParseBudget), the TOML pre-count (tomlEstimate), and what
// scan_manifest's readers and check_sbom's document reading do with them. The hosted endpoint with these at the heap's
// edge: test/http-dense-body.test.mjs, http-documents.test.mjs and http-parse-budget.test.mjs.
import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import v8 from "node:v8";
import { PKG_DIR } from "./server-under-test.mjs";
import { execFileSync } from "node:child_process";
import { IMAGE_SKIP, imageBudgets, imageNodeFlags } from "./image-server.mjs";

const B = await import(pathToFileURL(path.join(PKG_DIR, "dist", "parseBudget.js")).href);
const C = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "manifests", "common.js")).href);
const T = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "manifests", "toml.js")).href);
const M = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "manifests", "index.js")).href);
const SM = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "scan_manifest.js")).href);
const S = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "check_sbom.js")).href);

// The bounds are a share of the process's heap (parseBudget.ts budgetsFor): this process's heap is Node's own, sized
// from the machine. The checks below that hold a text to a bound name the hosted image's, which they pass in, so they
// hold the same whatever machine runs them; LOCAL is a local server's on a heap of 4 GiB, which takes what they refuse.
const MiB = 1024 * 1024;
const IMAGE = B.budgetsFor(B.IMAGE_HEAP_LIMIT);
const LOCAL = B.budgetsFor(4096 * MiB);

const count = (text) => B.scanJson(Buffer.from(text, "utf8"));
// #3434's bound on a call's TOML values, for a test of the reader's own counts past it: one that never refuses.
const NO_VALUES_BOUND = { take() {}, count: 0, left: Number.POSITIVE_INFINITY };
// What JSON.parse builds: every object and array, every array entry and object member (the SDK's count), every key.
const reference = (text) => {
  let containers = 0;
  let elements = 0;
  let keys = 0;
  const stack = [JSON.parse(text)];
  while (stack.length > 0) {
    const v = stack.pop();
    if (v === null || typeof v !== "object") continue;
    containers++;
    const children = Array.isArray(v) ? v : Object.values(v);
    if (!Array.isArray(v)) keys += children.length;
    elements += children.length;
    stack.push(...children);
  }
  return { containers, elements, keys };
};
const counts = (s) => ({ containers: s.containers, elements: s.elements, keys: s.keys });
const agrees = (text, note = text) => assert.deepEqual(counts(count(text)), reference(text), note);

describe("#3381: scanJson counts objects, arrays, elements and keys outside strings, in one pass, bytes or string alike", () => {
  it("containers, elements and keys as JSON.parse builds them, at every depth", () => {
    for (const t of ["{}", "[]", "[{}]", "[[]]", "[[0]]", '{"a":{}}', '[{},[],{"a":[1,2,{"b":null}]}]', '{"a":1,"b":[2,3]}', "[[],[[]],[[],[]]]"]) agrees(t);
    assert.deepEqual(counts(count('{"a":1,"b":2}')), { containers: 1, elements: 2, keys: 2 });
    assert.deepEqual(counts(count("[1,2,3]")), { containers: 1, elements: 3, keys: 0 });
    const deep = "[".repeat(10_000) + "0" + "]".repeat(10_000);
    assert.deepEqual(counts(count(deep)), { containers: 10_000, elements: 10_000, keys: 0 });
    agrees('{"a":'.repeat(5_000) + "{}" + "}".repeat(5_000), "5,000 deep");
  });

  it("a top-level value that is no container is no element; numbers, booleans and null are one element each", () => {
    for (const t of ["0", "-1.5e+10", "true", "false", "null", '"x"', '""']) assert.deepEqual(counts(count(t)), { containers: 0, elements: 0, keys: 0 }, t);
    for (const t of ["[0,-1,2.5,1E-2,-0.0e+0,true,false,null]", '{"n":-12.75e3,"t":true,"f":false,"z":null}', "[1e400,-1e400,123456789012345678901234567890]"]) agrees(t);
  });

  it("whitespace anywhere (space, tab, CR, LF) changes nothing, an empty container's included", () => {
    const pad = " \t\r\n";
    for (const t of ["[ ]", "{ }", "[\n]", "{\t}", "[\r\n{ }\r\n, [ ] ,\n\t0 ]", ` ${pad}{ ${pad}"a" ${pad}: ${pad}[ ${pad}1 ${pad}, ${pad}{ ${pad}} ${pad}] ${pad}} ${pad}`]) agrees(t, JSON.stringify(t));
    const v = JSON.parse('{"a":[1,{"b":[[],{}]}],"c":"x"}');
    for (const indent of [0, 1, 2, 4, "\t", " \r\n "]) agrees(JSON.stringify(v, null, indent), `indent ${JSON.stringify(indent)}`);
  });

  it('a string is one element whatever it holds: "{}{}{}" is one, not hundreds', () => {
    assert.deepEqual(counts(count('["{}{}{}"]')), { containers: 1, elements: 1, keys: 0 });
    assert.deepEqual(counts(count(JSON.stringify(["{}".repeat(300)]))), { containers: 1, elements: 1, keys: 0 });
    assert.deepEqual(counts(count(JSON.stringify({ sbom: '[{},{},[],[0]],{"a":1}:'.repeat(1000) }))), { containers: 1, elements: 1, keys: 1 });
    agrees(JSON.stringify(['{"a":[1,2]},[],{}', ":,:,", "\u00e9{}\u4e2d[]\ud83d\ude00,"]));
    agrees('{"{},[]":1,"a,b":{"[":"]"}}');
  });

  it("escapes are honoured: \\\" and \\\\ in every order, \\uXXXX, and a backslash before the closing quote", () => {
    const texts = [
      String.raw`["\"{}\""]`,
      String.raw`["\\"]`,
      String.raw`["\\",{}]`,
      String.raw`["\\\"",{}]`,
      String.raw`["\\\\",[],{}]`,
      String.raw`["a\",{}"]`,
      String.raw`["a\\\",{\"b\":[]}",0]`,
      String.raw`["\u0022{}\u0022","\u005c",{}]`,
      String.raw`["\u007b\u005b\u002c",[]]`,
      String.raw`{"\"":{"\\":["\"\\\"\\"]}}`,
      String.raw`["\/\b\f\n\r\t",{}]`,
      String.raw`{"a\":1":{"b":2}}`,
    ];
    for (const t of texts) agrees(t);
    assert.deepEqual(counts(count(String.raw`["\\",{}]`)), { containers: 2, elements: 2, keys: 0 });
    assert.deepEqual(counts(count(String.raw`["a\",{}"]`)), { containers: 1, elements: 1, keys: 0 });
  });

  it("generated documents: every count agrees with JSON.parse's, as bytes and as a string", () => {
    let seed = 3381;
    const rnd = () => ((seed = (Math.imul(seed, 1103515245) + 12345) >>> 0) / 2 ** 32);
    const ALPHABET = ['"', "\\", "{", "}", "[", "]", ",", ":", " ", "\n", "\t", "a", "0", "\u00e9", "\u4e2d", "\ud83d\ude00", "\u0000", "\u001f", "/", "u"];
    const str = () => Array.from({ length: Math.floor(rnd() * 12) }, () => ALPHABET[Math.floor(rnd() * ALPHABET.length)]).join("");
    const value = (depth) => {
      const r = rnd();
      if (depth > 6 || r < 0.35) return [0, -1.5, 1e21, true, false, null, str(), ""][Math.floor(rnd() * 8)];
      const n = Math.floor(rnd() * 6);
      if (r < 0.7) return Array.from({ length: n }, () => value(depth + 1));
      return Object.fromEntries(Array.from({ length: n }, (_, i) => [`${str()}${i}`, value(depth + 1)]));
    };
    for (let i = 0; i < 1000; i++) {
      const text = JSON.stringify(value(0), null, i % 3 === 0 ? 0 : i % 3 === 1 ? 2 : "\t");
      agrees(text, `document ${i}`);
      assert.deepEqual(counts(B.scanJson(text)), reference(text), `document ${i}, as a string`);
    }
  });

  it("a new shape is counted once per order of keys at its place: repeated objects share one, distinct keys each make one", () => {
    // 10,000 objects of the keys a, b: two new shapes (a; a then b), not 20,000.
    assert.equal(count(JSON.stringify(Array.from({ length: 10_000 }, () => ({ a: 1, b: 2 })))).newShapes, 2);
    // b then a is another order: two more.
    assert.equal(count(JSON.stringify([{ a: 1, b: 2 }, { b: 1, a: 2 }])).newShapes, 4);
    // Every key no other object has: one new shape each.
    assert.equal(count(JSON.stringify(Array.from({ length: 5_000 }, (_, i) => ({ [`k${i}`]: 0 })))).newShapes, 5_000);
    // One object of 3,000 keys no other has: 3,000.
    assert.equal(count(JSON.stringify(Object.fromEntries(Array.from({ length: 3_000 }, (_, i) => [`k${i}`, 0])))).newShapes, 3_000);
    // A nested object's keys do not change its parent's shape: {"x":{"a":1},"y":2} twice is x; a; x then y.
    assert.equal(count('[{"x":{"a":1},"y":2},{"x":{"a":1},"y":2}]').newShapes, 3);
    // Array-index keys (digits only) are counted apart.
    assert.equal(count('[{"0":1},{"7":1},{"12":1},{"a1":1},{"012345678901":1}]').indexKeys, 3);
    // Past the shapes it keeps, every key counts as new: only ever more.
    const many = JSON.stringify(Array.from({ length: B.SHAPE_SLOTS }, (_, i) => ({ [`k${i}`]: 0 })));
    assert.equal(count(many).newShapes, B.SHAPE_SLOTS);
    // Deeper than SHAPE_DEPTH, every key counts as new.
    const deep = '{"a":'.repeat(B.SHAPE_DEPTH + 10) + "0" + "}".repeat(B.SHAPE_DEPTH + 10);
    assert.ok(count(deep).newShapes >= 11, `${count(deep).newShapes}`);
    // The tables are the module's own and reused: a scan sees none of the one before it.
    count(JSON.stringify(Array.from({ length: 100 }, (_, i) => ({ [`z${i}`]: 0 }))));
    assert.equal(count(JSON.stringify(Array.from({ length: 100 }, (_, i) => ({ [`z${i}`]: 0 })))).newShapes, 100);
  });

  it("strings are charged per character, twice where they hold one past U+00FF", () => {
    assert.equal(count('["abcd"]').stringBytes, 4);
    assert.equal(count('["\u00e9t\u00e9"]').stringBytes, 5, "Latin-1 stays one byte a character (UTF-8: 5 bytes)");
    assert.equal(B.scanJson('["\u00e9t\u00e9"]').stringBytes, 3, "as a string: 3 characters, one-byte");
    assert.equal(count('["a\u4e2d"]').stringBytes, 8, "a CJK character makes the string two-byte: 4 UTF-8 bytes, twice");
    assert.equal(count(String.raw`["a\u4e2d"]`).stringBytes, 12, "\\u4e2d as written: 6 characters counted (the backslash is the escape's), twice");
    assert.equal(count(String.raw`["a\u00e9"]`).stringBytes, 6, "\\u00e9 stays one byte: 6 characters counted");
    assert.equal(count('{"key":"v"}').stringBytes, 4, "keys' characters too");
  });

  it("the estimate is the weights' sum over what was counted, the text included", () => {
    const s = count('[{},{"a":"bc"},[1,2]]');
    assert.equal(s.estimate, s.bytes + s.containers * B.WEIGHT_CONTAINER + s.elements * B.WEIGHT_ELEMENT + s.newShapes * B.WEIGHT_NEW_SHAPE + s.indexKeys * B.WEIGHT_INDEX_KEY + s.stringBytes);
    assert.equal(B.estimateOf(s), s.estimate);
    const d = B.documentCost('[{},{"a":"bc"}]');
    assert.equal(d.bytes, d.structure.estimate - d.structure.bytes, "a document's cost leaves out its text, which its holder counted");
  });

  it("real documents: Juice Shop 11.1.2's CycloneDX SBOM and the SPDX 2.3 example, as JSON.parse counts them, and few shapes", () => {
    for (const f of ["juice-shop-11.1.2-50.cdx.json", "SPDXJSONExample-v2.3.spdx.json"]) {
      const text = fs.readFileSync(path.join(PKG_DIR, "test", "fixtures", f), "utf8");
      agrees(text, f);
      assert.ok(count(text).newShapes < 500, `${f}: ${count(text).newShapes} shapes`);
      assert.deepEqual(counts(count(JSON.stringify({ sbom: text }))), { containers: 1, elements: 1, keys: 1 }, `${f} as text`);
    }
  });

  it("never fewer than JSON.parse builds: a repeated key is counted each time, and a text cut short counts no more as it is cut", () => {
    assert.deepEqual(counts(count('{"a":{},"a":{}}')), { containers: 3, elements: 2, keys: 2 });
    const text = JSON.stringify({ a: [1, { b: ["x\\\"{", [], {}] }], c: "}}]]" });
    let last = { containers: 0, elements: 0, keys: 0, estimate: 0 };
    for (let n = 0; n <= text.length; n++) {
      const c = count(text.slice(0, n));
      assert.ok(c.containers >= last.containers && c.elements >= last.elements && c.keys >= last.keys, `prefix ${n}`);
      last = c;
    }
  });

  it("linear in the text, with nothing to backtrack: 6 MiB of the costliest bytes each counts in well under a second", () => {
    const N = 6 * 1024 * 1024;
    for (const [name, b] of [
      ["empty objects", Buffer.from("[" + Array(Math.floor((N - 2) / 3)).fill("{}").join(",") + "]")],
      ["keys no other object has", Buffer.from("[" + Array.from({ length: Math.floor(N / 14) }, (_, i) => `{"${i.toString(36)}":0}`).join(",") + "]")],
      ["backslashes", Buffer.from('"' + "\\".repeat(N - 2) + '"')],
      ["quotes", Buffer.from('"' + '\\"'.repeat((N - 2) / 2) + '"')],
      ["whitespace", Buffer.from("[" + " ".repeat(N - 2) + "]")],
      ["unterminated string", Buffer.from('["' + "{".repeat(N - 2))],
    ]) {
      const t0 = process.hrtime.bigint();
      const c = B.scanJson(b);
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      assert.ok(ms < 1000, `${name}: ${ms} ms`);
      if (name === "unterminated string") assert.deepEqual(counts(c), { containers: 1, elements: 1, keys: 0 });
    }
  });
});

describe("#3381: ParseBudget reserves, lets one that fits pass one that waits, bounds how long a waiter is passed, refuses past its wait, shrinks and gives back once", () => {
  // A clock the test moves, so whether a waiter has waited BUDGET_STARVE_MS is the test's to say.
  const clock = () => {
    let t = 1_000_000;
    return { now: () => t, advance: (ms) => (t += ms) };
  };
  // #3381's round-5 review (T6): a long wait, given up once its case ends, passing or failing: through round 5 a failing
  // case left a waiter of 60 s, and the file waited for it.
  const ends = [];
  afterEach(() => {
    for (const c of ends.splice(0)) c.abort();
  });
  const LONG = 60_000;
  const ended = () => {
    const c = new AbortController();
    ends.push(c);
    return c.signal;
  };
  // A long wait's answer, or undefined after 3 s: a case that fails waiting for a waiter ends then, not at its wait.
  const within = (p) =>
    Promise.race([
      p,
      new Promise((resolve) => {
        const t = setTimeout(resolve, 3000);
        ends.push({ abort: () => clearTimeout(t) });
      }),
    ]);
  it("tryReserve fits or refuses at once; release frees exactly its hold, once", () => {
    const b = new B.ParseBudget(100);
    const a = b.tryReserve(60);
    assert.ok(a);
    assert.equal(b.tryReserve(41), undefined);
    const c = b.tryReserve(40);
    assert.ok(c);
    assert.equal(b.inUse, 100);
    b.release(a);
    b.release(a);
    b.release(undefined);
    assert.equal(b.inUse, 40, "a second release freed another's bytes");
    b.release(c);
    assert.equal(b.inUse, 0);
  });
  it("acquire lets in waiters in order as room comes, gives up at its wait or its signal, never queues past maxWaiting, and never waits for more than the whole budget", async () => {
    const b = new B.ParseBudget(100, 2);
    const first = b.tryReserve(90);
    const order = [];
    const x = b.acquire(50, 5000).then((h) => (order.push("x"), h));
    const y = b.acquire(20, 5000).then((h) => (order.push("y"), h));
    assert.equal(b.waiting, 2);
    assert.equal(await b.acquire(15, 5000), undefined, "a third waiter is refused at once");
    b.release(first);
    const [hx, hy] = await Promise.all([x, y]);
    assert.deepEqual(order, ["x", "y"], "in order of arrival");
    assert.equal(b.inUse, 70);
    const ctl = new AbortController();
    const z = b.acquire(60, 5000, ctl.signal);
    ctl.abort();
    assert.equal(await z, undefined, "an aborted wait gives up");
    const t0 = Date.now();
    assert.equal(await b.acquire(60, 50), undefined, "a wait that runs out gives up");
    assert.ok(Date.now() - t0 >= 45);
    assert.equal(await b.acquire(101, 5000), undefined, "more than the budget never waits");
    b.release(hx);
    b.release(hy);
    assert.equal(b.inUse, 0);
    assert.equal(b.waiting, 0);
  });
  it("no head-of-line block: one that fits now is taken at once, ahead of a waiter that does not fit, and so is a small one", async () => {
    const c = clock();
    const b = new B.ParseBudget(100, 10, { now: c.now });
    const held = b.tryReserve(60);
    const big = b.acquire(60, 5000);
    assert.equal(b.waiting, 1);
    const mid = b.tryReserve(30);
    assert.ok(mid, "a reservation that fits waited behind one that does not");
    assert.ok(b.tryReserve(5, { small: true }), "a small one waited behind one that does not fit");
    b.release(held);
    b.release(mid);
    assert.ok(await big, "the waiter was not let in once room came");
  });
  it("no starvation: once the oldest waiter has waited BUDGET_STARVE_MS, one that is not small is taken only beside its room; small ones only within their share", async () => {
    const c = clock();
    const b = new B.ParseBudget(100, 10, { now: c.now });
    assert.equal(b.starveMs, B.BUDGET_STARVE_MS);
    assert.equal(b.smallShare, 25);
    const held = b.tryReserve(50);
    const waiter = b.acquire(60, LONG, ended());
    c.advance(B.BUDGET_STARVE_MS);
    assert.equal(b.tryReserve(30), undefined, "a large one passed a waiter that had waited its time, taking its room");
    // Small ones still pass, while the small ones together hold at most a quarter of the budget.
    const smalls = [b.tryReserve(10, { small: true }), b.tryReserve(10, { small: true })];
    assert.ok(smalls.every(Boolean));
    assert.equal(b.tryReserve(10, { small: true }), undefined, "the small ones held more than their share, past a waiter");
    // Its room comes as the large holder ends, however many small ones hold their share.
    b.release(held);
    const h = await within(waiter);
    assert.ok(h, "the waiter was starved");
    assert.equal(b.inUse, 80);
    for (const x of [...smalls, h]) b.release(x);
    assert.equal(b.inUse, 0);
  });
  it("before BUDGET_STARVE_MS one that is not small may pass; a waiter behind one that waited its time is let in only beside that one's room", async () => {
    const c = clock();
    const b = new B.ParseBudget(100, 10, { now: c.now });
    const held = b.tryReserve(50);
    const head = b.acquire(60, LONG, ended());
    const passer = b.tryReserve(20);
    assert.ok(passer, "within BUDGET_STARVE_MS one that fits may pass");
    c.advance(B.BUDGET_STARVE_MS);
    const behind = b.acquire(20, LONG, ended());
    b.release(passer);
    assert.equal(b.waiting, 2, "one behind a waiter that waited its time was let in past it");
    b.release(held);
    assert.ok(await within(head));
    assert.ok(await within(behind), "room for both: the second is let in with the first");
    assert.equal(b.inUse, 80);
  });
  // #3381's round-4 review (F2): a reservation of a small request, its body's or its tool's, takes the small share, and
  // one of 0 bytes is taken whatever waits. Through round 4 a scan_manifest of a few hundred bytes (its document 0 or
  // 768 bytes) waited behind a large waiter as round 3's tools/list had.
  it("a small request's tool reservation, and one of 0 bytes, are taken beside a waiter that has waited its time", async () => {
    const c = clock();
    const b = new B.ParseBudget(100, 10, { now: c.now });
    const held = b.tryReserve(60);
    const waiter = b.acquire(50, LONG, ended());
    c.advance(B.BUDGET_STARVE_MS + 500);
    assert.ok(b.tryReserve(0), "a reservation of 0 bytes waited for a waiter");
    assert.ok(b.tryReserve(0, { own: 5, since: c.now() - 2000 }), "a tool's reservation of 0 bytes waited for a waiter");
    assert.ok(b.tryReserve(5, { small: true, own: 1, since: c.now() }), "a small request's tool reservation waited for a waiter");
    assert.equal(b.tryReserve(5, { own: 1, since: c.now() }), undefined, "control: the same not small waits, as one that would take the waiter's room");
    b.release(held);
    assert.ok(await within(waiter));
  });
  // #3381's round-4 review (F3): a request holding its body reserves its document; a waiter that came after the request
  // began, or one the waiting requests keep out until one of them ends (this one among them), no longer holds it up.
  // Through round 4 both stood still until one gave up (10 s): the reviewer's 14 MiB body, 28 MiB waiter, 6 MiB document.
  it("a tool's reservation is not held up by a waiter that came after its request began, nor by one that cannot fit while its request holds what it holds", async () => {
    const c = clock();
    const b = new B.ParseBudget(40, 10, { now: c.now });
    // A waiter that came after the request began.
    const other = b.tryReserve(5);
    const began = c.now();
    const body = b.tryReserve(10, { since: began });
    c.advance(100);
    const later = b.acquire(28, LONG, ended());
    c.advance(1200);
    assert.equal(b.tryReserve(6, { own: 10, since: c.now() }), undefined, "control: a request begun after the waiter waits for it");
    const doc = b.tryReserve(6, { own: 10, since: began });
    assert.ok(doc, "a waiter that came after the request began held up its document");
    for (const h of [doc, body, other]) b.release(h);
    b.release(await within(later));
    assert.equal(b.inUse, 0);
    // A waiter that came first, which cannot fit while this request holds its body (the reviewer's 14 and 28 of 40):
    // waiting for it would be waiting for itself.
    const holder = b.tryReserve(13);
    const first = b.acquire(28, LONG, ended());
    c.advance(10);
    const began2 = c.now();
    const body2 = b.tryReserve(14, { since: began2 });
    assert.ok(body2, "within BUDGET_STARVE_MS a body passes a waiter");
    c.advance(1200);
    assert.equal(b.tryReserve(6, { since: c.now() }), undefined, "control: one holding nothing waits for the waiter");
    const doc2 = b.tryReserve(6, { own: 14, since: began2 });
    assert.ok(doc2, "a document waited for a waiter that could not fit while its own request held its body");
    b.release(holder);
    assert.equal(b.waiting, 1, "the waiter needs the request's room");
    b.release(doc2);
    b.release(body2);
    const w = await within(first);
    assert.ok(w);
    b.release(w);
    assert.equal(b.inUse, 0);
  });
  // #3381's round-4 review (F1): what the API's answers hold is added to a call's reservation as it comes (grow, room or
  // no room), and answers whether the budget still holds it within its overdraft; resize sets a hold either way.
  it("grow adds past the room and says when the overdraft is passed; resize grows or shrinks; a small one within its share fits within the overdraft", async () => {
    const b = new B.ParseBudget(100, 10);
    assert.equal(b.overdraft, 25);
    const h = b.tryReserve(90);
    assert.equal(b.grow(h, 30), true, "120 of 100 is within its overdraft of 25");
    assert.equal(b.inUse, 120);
    assert.equal(b.tryReserve(1), undefined, "a reservation that is not small was taken past max");
    assert.ok(b.tryReserve(5, { small: true }), "a small one within its share was refused within the overdraft");
    assert.equal(b.grow(h, 1), false, "126 of 100 is past its overdraft");
    b.resize(h, 10);
    assert.equal(h.bytes, 10);
    b.resize(h, 50);
    assert.equal(h.bytes, 50);
    assert.equal(b.inUse, 55);
    b.release(h);
    assert.equal(b.grow(h, 1000), true, "a hold given back grew");
    assert.equal(b.inUse, 5);
  });
  it("shrink makes a hold smaller and lets waiters in, never makes one larger, and a hold given back stays given back", async () => {
    const b = new B.ParseBudget(100, 10);
    const h = b.tryReserve(80);
    const waiter = b.acquire(50, 5000);
    b.shrink(h, 200);
    assert.equal(b.inUse, 80, "shrink grew a hold");
    b.shrink(h, 30);
    assert.equal(h.bytes, 30);
    const w = await within(waiter);
    assert.ok(w, "the room shrink gave back was not given to the waiter");
    assert.equal(b.inUse, 80);
    b.release(h);
    assert.equal(b.inUse, 50, "release gave back more or less than the hold held");
    b.shrink(h, 0);
    b.release(h);
    assert.equal(b.inUse, 50, "a released hold was given back twice");
    const s = b.tryReserve(10, { small: true });
    b.shrink(s, 4);
    assert.equal(b.inUse, 54);
    b.release(s);
    b.release(w);
    assert.equal(b.inUse, 0);
  });
  // #3381's round-5 review (B1): smallUsed counts what was taken within the share, and what those holds grow by.
  it("a small one taken past the share counts nothing in it, so a tools/list is still taken beside a starved waiter; a hold within the share grows within it", async () => {
    const c = clock();
    const b = new B.ParseBudget(100, 10, { now: c.now });
    // Two small ones that together pass the share (25): the second fits only the ordinary way, nothing starved yet.
    const s1 = b.tryReserve(20, { small: true });
    const s2 = b.tryReserve(20, { small: true });
    assert.ok(s1 && s2);
    assert.equal(b.smallInUse, 20, "a small one taken the ordinary way was counted in the share");
    const held = b.tryReserve(30);
    const waiter = b.acquire(40, LONG, ended());
    c.advance(B.BUDGET_STARVE_MS);
    // The reviewer's tools/list: 764 bytes, here 4 of 100.
    const tl = b.tryReserve(4, { small: true });
    assert.ok(tl, "a tools/list waited behind a starved waiter: a small one past the share closed it");
    assert.equal(b.tryReserve(4), undefined, "control: one that is not small waits for the starved waiter");
    b.release(tl);
    // A hold within the share grows within it: past the share, the way in is closed until it is given back.
    assert.equal(b.grow(s1, 10), true);
    assert.equal(b.smallInUse, 30);
    assert.equal(b.tryReserve(4, { small: true }), undefined, "a hold's growth past the share left the way in open");
    b.shrink(s1, 15);
    assert.equal(b.smallInUse, 15, "shrink left the share counting more than the hold holds");
    assert.ok(b.tryReserve(4, { small: true }), "shrunk within the share, the way in stayed closed");
    // The ordinary one's growth is not in the share.
    b.grow(s2, 10);
    assert.equal(b.smallInUse, 19);
    for (const h of [s1, s2, held]) b.release(h);
    assert.ok(await within(waiter), "the starved waiter was not let in once the room came");
    assert.equal(b.smallInUse, 4);
  });
  // B1's verifier: a steady flow of small holds, each grown past its reservation. Counted outside the share, they held
  // more than the share at every release, and a waiter of max - smallShare was still waiting at 10 s.
  it("a steady flow of small holds that grow does not keep out a waiter of max less the share", async () => {
    const c = clock();
    const b = new B.ParseBudget(100, 10, { now: c.now });
    const holds = [];
    // A small hold of 5, grown by 5 (its answers past their reservation).
    const add = () => {
      const h = b.tryReserve(5, { small: true });
      if (h) {
        holds.push(h);
        b.grow(h, 5);
      }
      return h;
    };
    for (let i = 0; i < 5; i++) assert.ok(add(), `small hold ${i}`);
    const large = b.tryReserve(50);
    assert.ok(large);
    const waiter = b.acquire(75, LONG, ended());
    c.advance(B.BUDGET_STARVE_MS);
    b.release(large);
    assert.equal(b.waiting, 1, "control: the waiter fit beside the small holds");
    // One ends and another comes, again and again.
    for (let tick = 0; tick < 200 && b.waiting > 0; tick++) {
      b.release(holds.shift());
      add();
    }
    assert.equal(b.waiting, 0, `the waiter of 75 was kept out by small holds of ${b.inUse}, grown past what the share counted (${b.smallInUse})`);
    assert.ok(await within(waiter));
  });
  // #3381's round-5 review (B2): a reservation that queues adds what its request holds to what the waiting hold, which
  // can make one before it pass a starved waiter: it is let in then, not at an unrelated release.
  it("a reservation that queues lets in one before it that may now pass the starved waiter (the reviewer's three requests)", async () => {
    const c = clock();
    const b = new B.ParseBudget(40, 64, { now: c.now });
    // B holds 16 (an active request's body); A's body 8 and C's 12; W, begun before both, wants 21.
    const bh = b.tryReserve(16, { since: c.now() - 100 });
    const w0 = c.now();
    c.advance(10);
    const a = b.tryReserve(8, { since: c.now() });
    const aSince = c.now();
    c.advance(10);
    const cc = b.tryReserve(12, { since: c.now() });
    const cSince = c.now();
    const w = b.acquire(21, LONG, ended(), { since: w0 - 1 });
    c.advance(B.BUDGET_STARVE_MS + 500);
    // A's document (4): 36 + 4 fits, but W is ahead and starved, and A's 8 waiting with W's 21 fit: A waits.
    let aDoc;
    const aP = b.acquire(4, LONG, ended(), { own: 8, since: aSince }).then((h) => (aDoc = h));
    await Promise.resolve();
    assert.equal(aDoc, undefined, "control: A's document passed the starved waiter before C waited");
    // C's document (6) queues: the waiting now hold 20, and 20 + 21 > 40, so W cannot be let in until one of them ends:
    // A's waits for nothing it can be given.
    const cP = b.acquire(6, LONG, ended(), { own: 12, since: cSince });
    await within(aP);
    assert.ok(aDoc, "A's document stayed queued once C's queued");
    assert.equal(b.inUse, 40);
    b.release(aDoc);
    b.release(a);
    b.release(bh);
    assert.ok(await within(cP));
    b.release(cc);
    assert.ok(await within(w));
  });
  // #3381's round-6 verification (R6V-1.1): what a waiting request holds is its group's bytes as they are now. The
  // reviewer's batch: call 1's answers in the share, call 2 waiting behind a starved waiter W, then call 1's batch
  // answered (grow). Through round 6 call 2 kept the request's old own, waited for W, and W for the request.
  const settle = () => new Promise((r) => setImmediate(r));
  it("R6V-1.1: a batch sibling's answers charged while another of its reservations waits count in what the waiting hold, so that one passes a starved waiter they keep out", async () => {
    const c = clock();
    const b = new B.ParseBudget(40, 64, { now: c.now });
    const x = b.tryReserve(12, { since: c.now() });
    const r = b.newGroup();
    const rSince = c.now();
    const body = b.tryReserve(1, { small: true, group: r, since: rSince });
    const c1 = b.tryReserve(2, { small: true, group: r, since: rSince });
    assert.deepEqual([r.bytes, r.queued], [3, 0]);
    c.advance(10);
    const w = b.acquire(26, LONG, ended(), { since: rSince - 5 });
    c.advance(B.BUDGET_STARVE_MS);
    let c2;
    const c2P = b.acquire(8, LONG, ended(), { group: r, since: rSince }).then((h) => (c2 = h));
    await settle();
    assert.equal(c2, undefined, "control: beside what R holds (3) the starved waiter fits once X ends, so R's call waits for it");
    assert.equal(b.waitingOwn, 3);
    // Call 1's batch is answered: its hold grows by 12, room or no room. R now holds 15, and 15 + 26 > 40: the waiter
    // cannot be let in beside R, so R's call passes it, at once (R holds 15 + its 8, and waits for nothing).
    b.grow(c1, 12);
    assert.deepEqual([r.bytes, r.queued, b.waitingOwn], [23, 0, 0]);
    await settle();
    assert.ok(c2, "R's call waited for a waiter that cannot be let in beside what R holds, and the waiter for R");
    await c2P;
    for (const h of [c2, c1, body, x]) b.release(h);
    assert.ok(await within(w), "the waiter was not let in once R and X ended");
    assert.deepEqual([r.bytes, r.queued, b.waitingOwn], [0, 0, 0]);
  });
  it("R6V-1.1, its mirror: a sibling that keeps less (shrink) while another waits counts less, so no one passes a starved waiter the waiting could be let in beside", async () => {
    const c = clock();
    const b = new B.ParseBudget(40, 64, { now: c.now });
    const x = b.tryReserve(15, { since: c.now() });
    const r = b.newGroup();
    const z = b.newGroup();
    const rSince = c.now();
    const body = b.tryReserve(1, { small: true, group: r, since: rSince });
    const c1 = b.tryReserve(9, { small: true, group: r, since: rSince });
    const zBody = b.tryReserve(6, { group: z, since: rSince });
    c.advance(10);
    const w = b.acquire(26, LONG, ended(), { since: rSince - 5 });
    c.advance(B.BUDGET_STARVE_MS);
    const c2P = b.acquire(8, LONG, ended(), { group: r, since: rSince });
    await settle();
    assert.equal(b.waitingOwn, 10);
    // Call 1 keeps 1 of its 9: R holds 2.
    b.shrink(c1, 1);
    assert.deepEqual([r.bytes, b.waitingOwn], [2, 2]);
    assert.equal(b.tryReserve(5, { group: z, since: rSince }), undefined, "Z passed a starved waiter that fits beside the waiting requests once X ends (2 + 6 + 26 of 40)");
    b.release(x);
    const wh = await within(w);
    assert.ok(wh, "the waiter was not let in once X ended");
    for (const h of [wh, zBody]) b.release(h);
    const c2 = await within(c2P);
    assert.ok(c2);
    for (const h of [c2, c1, body]) b.release(h);
    assert.deepEqual([r.bytes, z.bytes, b.waitingOwn, b.inUse], [0, 0, 0, 0]);
  });
  // #3381's round-6 verification (R6V-1.2): the share past smallShare (the answers of the small holds in it grown), a
  // starved waiter: a tools/list's tiny reservation is still taken at once, in its own lane, which is bounded.
  it("R6V-1.2: with the share past smallShare, a tools/list's tiny reservation is taken at once beside a starved waiter; one past tinyBytes waits, and the lane holds at most tinyLane", async () => {
    const c = clock();
    const b = new B.ParseBudget(40 * MiB, 64, { now: c.now });
    assert.deepEqual([b.tinyBytes, b.tinyLane], [64 * 1024, 4 * MiB]);
    const smalls = [b.tryReserve(5 * MiB, { small: true }), b.tryReserve(5 * MiB, { small: true })];
    for (const h of smalls) b.grow(h, MiB);
    const large = b.tryReserve(20 * MiB);
    assert.ok(smalls.every(Boolean) && large);
    const waiter = b.acquire(25 * MiB, LONG, ended());
    c.advance(B.BUDGET_STARVE_MS);
    assert.ok(b.smallInUse > b.smallShare && b.waiting === 1, `${b.smallInUse} of ${b.smallShare}`);
    // A body's reservation (lane: http.ts passes it for the body alone, R7V-1.1).
    const tl = b.tryReserve(764, { small: true, lane: true });
    assert.ok(tl, "a tools/list waited behind a starved waiter while the share's holds were grown past it");
    assert.equal(b.tryReserve(64 * 1024 + 1, { small: true, lane: true }), undefined, "control: a small one past tinyBytes passed the starved waiter");
    assert.equal(b.tryReserve(764, { lane: true }), undefined, "control: one that is not small passed the starved waiter");
    assert.equal(b.tryReserve(764, { small: true }), undefined, "control: a tool's small reservation (no lane) passed the starved waiter");
    const lane = Array.from({ length: 63 }, () => b.tryReserve(64 * 1024, { small: true, lane: true }));
    assert.ok(lane.every(Boolean), "the lane held less than tinyLane");
    assert.equal(b.tryReserve(64 * 1024, { small: true, lane: true }), undefined, "the lane held more than tinyLane");
    for (const h of [...smalls, large]) b.release(h);
    const wh = await within(waiter);
    assert.ok(wh, "the starved waiter was not let in beside the lane once the others ended");
    for (const h of [wh, tl, ...lane]) b.release(h);
    assert.deepEqual([b.inUse, b.smallInUse], [0, 0]);
  });
  // #3381's round-7 verification (R7V-1.1): the reviewer's case. Four batched requests' calls, each answers'
  // reservation of 51 purls (65,280 bytes, small), and a 16 KB document: through round 7 those past the share took the
  // tiny lane too, and once it was full a tools/list waited behind a starved waiter.
  it("R7V-1.1: tools' small reservations past the share do not take the tiny lane: with the share full and a starved waiter, a tools/list is still taken at once", async () => {
    const c = clock();
    const b = new B.ParseBudget(40 * MiB, 64, { now: c.now });
    const holds = [];
    const groups = [];
    for (let g = 0; g < 4; g++) {
      const group = b.newGroup();
      groups.push(group);
      holds.push(b.tryReserve(16 * 1024, { small: true, lane: true, group }));
      for (let k = 0; k < 60; k++) holds.push(b.tryReserve(51 * B.WEIGHT_BATCH_ROW, { small: true, group }));
    }
    holds.push(b.tryReserve(16 * 1024, { small: true }));
    assert.ok(holds.every(Boolean), "a call's reservation was refused before anything waited");
    assert.ok(b.smallInUse + 51 * B.WEIGHT_BATCH_ROW > b.smallShare, `${b.smallInUse} of the share ${b.smallShare}`);
    // What room is left in the share, a document of a fifth request takes, so a tools/list fits only by the lane.
    if (b.smallInUse < b.smallShare) holds.push(b.tryReserve(b.smallShare - b.smallInUse, { small: true }));
    assert.ok(b.smallInUse >= b.smallShare, `${b.smallInUse} of the share ${b.smallShare}`);
    const waiter = b.acquire(28 * MiB, LONG, ended());
    c.advance(B.BUDGET_STARVE_MS + 500);
    assert.equal(b.waiting, 1);
    // The batches' calls go on reserving, each size a tool reserves small (an answers reservation of 51 purls, a 16 KB
    // document, one of 600 bytes), each until one is refused: with the share full and the waiter starved, none fits,
    // and none is taken by the lane. Through round 7 the lane took them until it was full, and the tools/list waited.
    const past = [];
    for (const bytes of [51 * B.WEIGHT_BATCH_ROW, 16 * 1024, 600]) {
      for (let k = 0, h; k < 10_000 && (h = b.tryReserve(bytes, { small: true, group: groups[k % 4] })); k++) past.push(h);
    }
    const tl = b.tryReserve(600, { small: true, lane: true });
    assert.ok(tl, `a tools/list waited behind a starved waiter: the calls' small reservations past the share had filled the tiny lane (${past.length} of them made after the waiter)`);
    assert.equal(past.length, 0, `${past.length} of the calls' small reservations were taken past the share beside a starved waiter`);
    for (const h of [...holds, ...past, tl]) b.release(h);
    const wh = await within(waiter);
    assert.ok(wh);
    b.release(wh);
    assert.deepEqual([b.inUse, b.smallInUse], [0, 0]);
  });
});

describe("#3381: the budgets are a share of the process's heap, the hosted image's exactly as measured, a local server's larger", () => {
  it("under Dockerfile.http's flags: heap_size_limit is IMAGE_HEAP_LIMIT, and the bounds in force are 28 MiB and 40 MiB", { skip: IMAGE_SKIP }, () => {
    const img = imageBudgets();
    assert.equal(img.heap_size_limit, B.IMAGE_HEAP_LIMIT, "the image's flags no longer give the heap the budgets were measured on: re-measure parseBudget.ts");
    assert.equal(img.PARSE_BUDGET_BYTES, 28 * MiB);
    assert.equal(img.INFLIGHT_BUDGET_BYTES, 40 * MiB);
    assert.deepEqual(img.BUDGETS, { heapLimit: 152 * MiB, parseBytes: 28 * MiB, inflightBytes: 40 * MiB });
  });
  it("budgetsFor(152 MiB) is the image's; budgetsFor(4 GiB) is each about 26.9 times it, rounded down", () => {
    assert.deepEqual(IMAGE, { heapLimit: 152 * MiB, parseBytes: 28 * MiB, inflightBytes: 40 * MiB });
    assert.deepEqual(LOCAL, { heapLimit: 4096 * MiB, parseBytes: 754 * MiB, inflightBytes: 1077 * MiB });
    const ratio = 4096 / 152;
    for (const k of ["parseBytes", "inflightBytes"]) {
      const r = LOCAL[k] / IMAGE[k];
      assert.ok(r <= ratio && r > ratio - 0.04, `${k}: ${r}, not ${ratio}`);
    }
  });
  it("proportional between the clamps, never decreasing as the heap grows, each rounded down", () => {
    let prev = B.budgetsFor(0);
    for (let mib = 38; mib <= 4096; mib += 7) {
      const b = B.budgetsFor(mib * MiB);
      assert.equal(b.heapLimit, mib * MiB);
      assert.equal(b.parseBytes, Math.floor((28 * mib) / 152) * MiB, `${mib} MiB`);
      assert.equal(b.inflightBytes, Math.floor((40 * mib) / 152) * MiB, `${mib} MiB`);
      for (const k of ["parseBytes", "inflightBytes"]) assert.ok(b[k] >= prev[k], `${k} fell at ${mib} MiB`);
      assert.ok(b.parseBytes < b.inflightBytes, "one text's bound is below the in-flight budget");
      prev = b;
    }
  });
  it("clamped: a heap below a quarter of the image's (or none, or not a number) is a quarter's; one past 4 GiB is 4 GiB's", () => {
    const floor = { heapLimit: 38 * MiB, parseBytes: 7 * MiB, inflightBytes: 10 * MiB };
    for (const h of [0, -1, 1, 16 * MiB, 38 * MiB, Number.NaN, undefined, null, "152"]) assert.deepEqual(B.budgetsFor(h), floor, String(h));
    for (const h of [4096 * MiB, 4097 * MiB, 8240 * MiB, 64 * 1024 * MiB, Number.POSITIVE_INFINITY]) {
      assert.deepEqual(B.budgetsFor(h), Number.isFinite(h) ? LOCAL : floor, String(h));
    }
  });
  it("this process's bounds in force are budgetsFor its own heap_size_limit", () => {
    const own = B.budgetsFor(v8.getHeapStatistics().heap_size_limit);
    assert.deepEqual(B.BUDGETS, own);
    assert.equal(B.PARSE_BUDGET_BYTES, own.parseBytes);
    assert.equal(B.INFLIGHT_BUDGET_BYTES, own.inflightBytes);
    assert.equal(B.MAX_MANIFEST_ITEMS, undefined, "#3434's per-call bounds replace it");
  });
});

describe("#3381: tomlEstimate counts what manifests/toml.ts would build, outside strings and comments", () => {
  it("a structure character in a string or comment is not counted; out of them it is", () => {
    const base = B.tomlEstimate("");
    assert.equal(base, 0);
    // Each against a string of as many plain characters.
    assert.equal(B.tomlEstimate('x = "[{=.,}]"'), B.tomlEstimate('x = "abcdefg"'), "a basic string's structure characters are its characters");
    assert.equal(B.tomlEstimate("x = '[{=.,}]'"), B.tomlEstimate("x = 'abcdefg'"), "a literal string's too");
    assert.equal(B.tomlEstimate('x = """[{\n=.,}]"""'), B.tomlEstimate('x = """abcdefgh"""'), "a multi-line string's too");
    assert.equal(B.tomlEstimate('x = "a\\"[{"'), B.tomlEstimate('x = "abcde"'), "an escaped quote does not end it");
    assert.equal(B.tomlEstimate("# [[x]] = {}\n"), 2 * 13 + B.WEIGHT_TOML_VALUE, "a comment's are not counted (its newline is)");
    assert.equal(B.tomlEstimate("[a]"), 2 * 3 + B.WEIGHT_TOML_OPEN);
    assert.equal(B.tomlEstimate("a.b.c = {}"), 2 * 10 + 2 * B.WEIGHT_TOML_DOT + B.WEIGHT_TOML_KEY + B.WEIGHT_TOML_OPEN);
  });
  it("readToml refuses, before reading, a text estimated past PARSE_BUDGET_BYTES; one under it reads as before", () => {
    const dense = `x = [${Array(300_000).fill("{}").join(",")}]`;
    assert.ok(B.tomlEstimate(dense) > IMAGE.parseBytes);
    assert.throws(() => T.readToml(dense, undefined, IMAGE.parseBytes), (e) => e instanceof C.Unreadable && /is too dense to read: .* bytes read, past the 29360128 bytes/.test(e.message));
    const ok = `x = [${Array(1000).fill("{}").join(",")}]`;
    assert.equal(T.readToml(ok, undefined, IMAGE.parseBytes).root.x.length, 1000);
    // A local server's bound takes what the image's refuses; with none named, the bound in force is this process's.
    assert.equal(T.readToml(dense, NO_VALUES_BOUND, LOCAL.parseBytes).root.x.length, 300_000);
    assert.equal(B.tomlEstimate(dense) > B.PARSE_BUDGET_BYTES, (() => { try { T.readToml(dense, NO_VALUES_BOUND); return false; } catch { return true; } })());
  });
  // #3381's review (F8): the estimate and the reader disagreed on where two strings ended, and what the reader built
  // between was never counted: 2024-01-01' read as a date where the estimate opened a string to the line's end, and an
  // escaped quote in a multi-line basic string (\""" ends nothing) where the estimate closed it. Each Cargo.lock under
  // 5 MB, estimated at 10 MB, read past the heap.
  it("the estimate closes a string where the reader does: an escaped quote in a \"\"\" string is its own; a closing three may follow two more", () => {
    assert.equal(B.tomlEstimate('a = """q\\""" """\nb = [{},{}]\n'), B.tomlEstimate('a = """qqqqqq"""\nb = [{},{}]\n'), "\\\"\"\" does not close it");
    assert.equal(B.tomlEstimate('a = """q\\\\"""\nb = {}\n'), B.tomlEstimate('a = """qqq"""\nb = {}\n'), "an escaped backslash does not escape the quote after it");
    assert.equal(B.tomlEstimate('a = """x"""""\nb = {}\n'), B.tomlEstimate('a = """xxx"""\nb = {}\n'), "\"\"\"\"\" closes at its last three");
    assert.equal(B.tomlEstimate("a = '''x'''''\nb = {}\n"), B.tomlEstimate("a = '''xxx'''\nb = {}\n"), "''''' too");
    assert.equal(T.readToml('a = """x"""""\n').root.a, 'x""');
    assert.equal(T.readToml("a = '''x'''''\n").root.a, "x''");
  });
  it("a date, a time or a date-time is read only whole: 2024-01-01' is no value", () => {
    const r = T.readToml("a = 1979-05-27\nb = 1979-05-27T07:32:00Z\nc = 1979-05-27 07:32:00.999-07:00\nd = 07:32:00\ne = 07:32\nf = 1979-05-27t07:32\n").root;
    assert.deepEqual(Object.values(r), ["1979-05-27", "1979-05-27T07:32:00Z", "1979-05-27 07:32:00.999-07:00", "07:32:00", "07:32", "1979-05-27t07:32"]);
    for (const bad of ["a = 2024-01-01'x'\n", "a = [2024-01-01',{}]\n", "a = 2024-01-01x\n", "a = 07:32:00'\n", "a = 1979-05-27T07\n"]) {
      assert.throws(() => T.readToml(bad), (e) => e instanceof C.Unreadable && /an unreadable value/.test(e.message), bad);
    }
  });
  it("the reader charges what it builds, and stops, unread, past what was estimated of it", () => {
    const t = `x = [${Array(10_000).fill("{}").join(",")}]\n`;
    const { cost } = T.readToml(t, undefined, IMAGE.parseBytes);
    assert.equal(cost, B.tomlEstimate(t), "where they agree on the strings, it charges what the estimate counted");
    // An estimate that does not see what the reader builds (as the two above did not): the reader stops at it.
    assert.throws(() => T.readToml(t, undefined, IMAGE.parseBytes, cost - 1), (e) => e instanceof C.Unreadable && /^is too dense to read: what reading it built passed the \d+ bytes estimated of it before it was read$/.test(e.message));
    assert.throws(() => T.readToml(t, undefined, IMAGE.parseBytes, 2 * t.length + 10 * B.WEIGHT_TOML_OPEN), /what reading it built passed/);
    assert.equal(T.readToml(t, undefined, IMAGE.parseBytes, cost).root.x.length, 10_000);
  });
  it("a text the reader reads, it reads within its estimate: fixtures, and generated texts", () => {
    const within = (text, what) => {
      let r;
      try {
        r = T.readToml(text, NO_VALUES_BOUND, Infinity, Infinity);
      } catch (e) {
        if (e instanceof C.Unreadable) return false;
        throw e;
      }
      assert.ok(r.cost <= B.tomlEstimate(text), `${what}: read at ${r.cost}, estimated ${B.tomlEstimate(text)}: ${JSON.stringify(text).slice(0, 200)}`);
      return true;
    };
    const dir = path.join(PKG_DIR, "test", "fixtures", "manifests");
    for (const f of ["Cargo.v3.lock", "Cargo.v4.lock", "poetry.lock"]) assert.ok(within(fs.readFileSync(path.join(dir, f), "utf8"), f), f);
    // Fragments a TOML text is made of, the two shapes F8 found among them, joined at random: most are not TOML; each
    // that the reader reads (with no estimate to stop it) must cost it no more than its estimate.
    const FRAGS = ["\n", "\r\n", " ", "a", "b.c", '"k"', "'k'", " = ", "=", ".", ",", "[", "]", "[[", "]]", "{", "}", "[a]\n", "[[p]]\n", "#c", '# """\n',
      '"s"', "'s'", '"\\""', '"\\\\"', '"""', "'''", '"""m\\"""', '"""\n', "'''\n", '\\"', '"', "'", "1", "1.5", "true", "1979-05-27", "07:32:00", "2024-01-01'", "x = ", "y = [", "z = {", 'q = """', "w = '''"];
    let seed = 3381;
    const rnd = (n) => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff), seed % n);
    let read = 0;
    for (let k = 0; k < 20_000; k++) {
      let text = "";
      const len = 1 + rnd(24);
      for (let j = 0; j < len; j++) text += FRAGS[rnd(FRAGS.length)];
      if (within(text, `generated ${k}`)) read++;
    }
    // And TOML that reads: tables of keys whose values are strings of every kind (holding quotes, escapes and
    // structure characters), arrays and inline tables.
    const STRINGS = ['"a[{=.,}]"', '"q\\"[{"', '"\\\\"', '"""m\\""" """', '"""\nx"""""', "'l[{'", "'''\nm'''''", '"""a\\\n  b"""', '"#"'];
    for (let k = 0; k < 2_000; k++) {
      let text = "";
      const tables = 1 + rnd(4);
      for (let t = 0; t < tables; t++) {
        text += rnd(2) ? `[[p${rnd(3)}]]\n` : `[t${k}x${t}]\n`;
        const keys = 1 + rnd(5);
        for (let n = 0; n < keys; n++) {
          const s = () => STRINGS[rnd(STRINGS.length)];
          const v = [s(), "1", "1979-05-27", `[${s()}, {}]`, `{ a = ${s()}, b.c = [1,\n 2] }`][rnd(5)];
          text += `k${n}${rnd(3) ? "" : ".d"} = ${v} ${rnd(3) ? "" : "# c"}\n`;
        }
      }
      assert.ok(within(text, `table text ${k}`), `table text ${k} reads: ${JSON.stringify(text).slice(0, 300)}`);
    }
    assert.ok(read > 100, `${read} of the generated texts read`);
  });
  it("a basic string is read whole (escapes, multi-line, line-ending backslash), and a long one costs its characters, not a node each", () => {
    const r = T.readToml('a = "x\\ty\\u00e9\\"z"\nb = """\nline1\\\n   line2"""\nc = "plain"\n');
    assert.deepEqual([r.root.a, r.root.b, r.root.c], ['x\ty\u00e9"z', "line1line2", "plain"]);
    const big = T.readToml(`x = "${"a".repeat(2_000_000)}"`).root.x;
    assert.equal(big.length, 2_000_000);
  });
});

// #3381, merged onto #3434 (3.1.3): a call's readers are held to #3434's per-call bounds (manifests/common.ts, tested in
// test/manifest-lines.test.mjs), and each JSON and TOML lockfile's parse to the parse bound in force; what is reserved
// for a call's files (manifestEstimate) is their costliest parse and every entry they will take (entriesCost).
// What a reader took of a file: the lines it counted (a line format), else the entries it gave (pinned, counted not
// checked, skipped).
const LINE_FORMATS = new Set(["requirements.txt", "go.mod", "Gemfile.lock", "gradle.lockfile"]);
const takenOf = (format, text) => {
  const bounds = C.callBounds();
  let r;
  try {
    r = M.readFile(format, text, bounds, Number.POSITIVE_INFINITY);
  } catch {
    return 0;
  }
  if (LINE_FORMATS.has(format)) return bounds.lines.count;
  if (r.unreadable) return 0;
  return r.pinned.length + Object.values(r.counted).reduce((n, k) => n + k, 0) + r.skipped;
};
describe("#3381: the manifest readers take one line at a time; each lockfile's parse is bounded; a call's files are reserved what they will hold", () => {
  it("eachLine gives exactly what split gives, without the array", () => {
    for (const text of ["", "a", "a\n", "\n", "a\nb", "a\r\nb\r\n", "a\r\n\r\nb", "\r", "a\rb\n", "x\n\n\ny"]) {
      for (const crlf of [true, false]) {
        const got = [];
        C.eachLine(text, crlf, (raw, i) => got.push([raw, i]));
        assert.deepEqual(got, text.split(crlf ? /\r?\n/ : "\n").map((raw, i) => [raw, i]), `${JSON.stringify(text)} crlf ${crlf}`);
      }
    }
  });
  it("a JSON lockfile estimated past PARSE_BUDGET_BYTES, within #3434's bound on its values, is not read (not parsed), and the note says why", () => {
    // One object of 290,000 members with keys no other has: within MAX_JSON_VALUES (300,000), estimated past 28 MiB.
    const dense = `{"lockfileVersion":1,"dependencies":{${Array.from({ length: 290_000 }, (_, k) => `"${k.toString(36)}":0`).join(",")}}}`;
    assert.ok(C.jsonValues(dense, Infinity) <= C.MAX_JSON_VALUES && B.documentCost(dense).bytes > IMAGE.parseBytes);
    const r = SM.readFiles({ files: [{ filename: "package-lock.json", content: dense }, { filename: "requirements.txt", content: "a==1\n" }] }, IMAGE);
    assert.equal(typeof r, "object", r);
    assert.equal(r.files[0].read, false);
    assert.match(r.files[0].refused, /^read as package-lock\.json, it is too dense to read: its \d+ objects and arrays, \d+ entries and \d+ keys, parsed, are estimated at \d+ bytes, past the 29360128 bytes a file's parse may take$/);
    assert.equal(r.files[1].read, true);
    const comp = SM.readFiles({ files: [{ filename: "composer.lock", content: `{"packages":[],"x":${dense}}` }] }, IMAGE);
    assert.match(comp, /composer\.lock: read as composer\.lock, it is too dense to read/);
    // A local server's bound parses it.
    const local = SM.readFiles({ files: [{ filename: "package-lock.json", content: dense }] }, LOCAL);
    assert.equal(local.files[0].read, true, JSON.stringify(local.files[0]));
  });
  it("manifestEstimate: the costliest file's parse and every entry the readers will take (entriesCost), each kind at most #3434's bound; nothing for a call readFiles refuses", () => {
    assert.equal(SM.manifestEstimate({ files: "x" }), 0);
    assert.equal(SM.manifestEstimate({ files: [{ filename: "requirements.txt", content: "a".repeat(5_000_001) }] }), 0, "a call past the character cap reserves something");
    assert.equal(SM.manifestEstimate({ files: [{ filename: "a\u0001/requirements.txt", content: "a==1\n" }] }), 0, "a call refused for its filename reserves something");
    assert.equal(SM.entriesCost(2), 2 * B.WEIGHT_MANIFEST_ENTRY + 2 * B.WEIGHT_MANIFEST_ITEM);
    assert.equal(SM.entriesCost(5_000, 10), 5_000 * B.WEIGHT_MANIFEST_ENTRY + 10 * B.WEIGHT_MANIFEST_ITEM);
    assert.equal(SM.entriesCost(5_000), 5_000 * B.WEIGHT_MANIFEST_ENTRY + C.NOT_CHECKED_MAX * B.WEIGHT_MANIFEST_ITEM, "the answer lists at most NOT_CHECKED_MAX");
    const small = SM.manifestEstimate({ files: [{ filename: "requirements.txt", content: "a==1\n\n  \nb==2" }] }, IMAGE);
    assert.equal(small, SM.entriesCost(2), "a blank line is reserved as an entry");
    const lock = JSON.stringify({ lockfileVersion: 3, packages: { "": { name: "app" }, "node_modules/a": { version: "1.0.0", dependencies: { b: "^1", c: "^2" } } } });
    const c = B.documentCost(lock);
    assert.equal(SM.manifestEstimate({ files: [{ filename: "package-lock.json", content: lock }] }, IMAGE), c.bytes + SM.entriesCost(2), "an npm lockfile's entries are its packages, not its JSON elements");
    const many = SM.manifestEstimate({ files: [{ filename: "requirements.txt", content: "a\n".repeat(100_000) }] }, IMAGE);
    assert.equal(many, SM.entriesCost(C.MAX_MANIFEST_LINES), "lines past #3434's bound are reserved at the bound, where the readers stop");
  });
  it("#3381's review: a real-shaped poetry.lock of 820 packages and some 30,000 lines is reserved 820 entries, and fits beside its own body", () => {
    // Poetry 2.x's shape: each package with its wheels as inline tables (files = [...]) and its dependencies.
    const pkg = (i) =>
      `[[package]]\nname = "pkg-${i}"\nversion = "1.${i % 50}.0"\ndescription = "${"d".repeat(60)}"\noptional = false\npython-versions = ">=3.9"\ngroups = ["main"]\nfiles = [\n` +
      Array.from({ length: 14 }, (_, w) => `    {file = "pkg_${i}-1.0.0-cp3${w}-manylinux_x86_64.whl", hash = "sha256:${"0123456789abcdef".repeat(4)}"},`).join("\n") +
      `\n]\n\n[package.dependencies]\nother-${i} = {version = ">=1.0", optional = true}\n\n[package.extras]\ntest = ["pytest (>=8)"]\n\n`;
    const text = Array.from({ length: 820 }, (_, i) => pkg(i)).join("");
    assert.ok(text.split("\n").length > 20_000 && text.length < 5_000_000, `${text.length} chars, ${text.split("\n").length} lines`);
    assert.equal(B.tomlPackages(text), 820);
    const est = SM.manifestEstimate({ files: [{ filename: "poetry.lock", content: text }] }, IMAGE);
    assert.equal(est, B.tomlEstimate(text) + SM.entriesCost(820));
    const body = B.scanJson(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "scan_manifest", arguments: { files: [{ filename: "poetry.lock", content: text }] } } })).estimate;
    assert.ok(body + est < IMAGE.inflightBytes, `body ${body} + files ${est} past ${IMAGE.inflightBytes}`);
    assert.equal(takenOf("poetry.lock", text), 820, "the reader takes another count than the estimate reserves");
  });
});

describe("#3381's review: the entry counters are never below what the readers take, and close to it", () => {
  const taken = takenOf;
  const fixture = (f) => fs.readFileSync(path.join(PKG_DIR, "test", "fixtures", "manifests", f), "utf8");
  it("on every lockfile fixture, each count equals what its reader takes, or is just above it", () => {
    const cases = [
      ["tree.v1.package-lock.json", "package-lock.json", (t) => B.lockfileEntries(t, "npm")],
      ["tree.v2.package-lock.json", "package-lock.json", (t) => B.lockfileEntries(t, "npm")],
      ["tree.v3.package-lock.json", "package-lock.json", (t) => B.lockfileEntries(t, "npm")],
      ["lodash-4.17.15.package-lock.json", "package-lock.json", (t) => B.lockfileEntries(t, "npm")],
      ["composer.lock", "composer.lock", (t) => B.lockfileEntries(t, "composer")],
      ["Cargo.v3.lock", "Cargo.lock", B.tomlPackages],
      ["Cargo.v4.lock", "Cargo.lock", B.tomlPackages],
      ["poetry.lock", "poetry.lock", B.tomlPackages],
      ["requirements.txt", "requirements.txt", B.nonBlankLines],
      ["fixture.go.mod", "go.mod", B.nonBlankLines],
      ["Gemfile.lock", "Gemfile.lock", B.nonBlankLines],
      ["gradle.lockfile", "gradle.lockfile", B.nonBlankLines],
    ];
    for (const [f, format, count] of cases) {
      const text = fixture(f);
      const n = count(text);
      const t = taken(format, text);
      assert.ok(t > 0 && n >= t && n <= t + 5, `${f}: counted ${n}, its reader took ${t}`);
    }
  });
  // #3381's round-4 review (F10): a byte-order mark before a lockfile (its reader drops it) left the npm and Composer
  // counts at 0 and the TOML count one short; a [[package]] header written with an escape was not counted.
  it("a byte-order mark, and a TOML header written with an escape, do not make a count fall below what the reader takes, nor manifestEstimate below the mark's absence", () => {
    const BOM = "\uFEFF";
    for (const [f, format, count] of [
      ["tree.v1.package-lock.json", "package-lock.json", (t) => B.lockfileEntries(t, "npm")],
      ["tree.v3.package-lock.json", "package-lock.json", (t) => B.lockfileEntries(t, "npm")],
      ["composer.lock", "composer.lock", (t) => B.lockfileEntries(t, "composer")],
      ["Cargo.v4.lock", "Cargo.lock", B.tomlPackages],
      ["poetry.lock", "poetry.lock", B.tomlPackages],
    ]) {
      for (const text of [BOM + fixture(f), BOM + fixture(f).replace(/\n/g, "\r\n")]) {
        const t = taken(format, text);
        assert.ok(t > 0 && count(text) >= t, `${f} with a byte-order mark: counted ${count(text)}, its reader took ${t}`);
      }
      const files = (c) => ({ files: [{ filename: format, content: c }] });
      assert.equal(SM.manifestEstimate(files(BOM + fixture(f)), IMAGE), SM.manifestEstimate(files(fixture(f)), IMAGE), f);
    }
    const minified = BOM + JSON.stringify(JSON.parse(fixture("tree.v3.package-lock.json")));
    assert.ok(B.lockfileEntries(minified, "npm") >= taken("package-lock.json", minified));
    const escaped = Array.from({ length: 300 }, (_, i) => `[["p\\u0061ckage"]]\nname = "a${i}"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n`).join("\n");
    const t = taken("Cargo.lock", escaped);
    assert.equal(t, 300, "the reader takes [[\"p\\u0061ckage\"]] as [[package]]");
    assert.ok(B.tomlPackages(escaped) >= t, `escaped headers: counted ${B.tomlPackages(escaped)}, the reader took ${t}`);
    assert.ok(B.tomlPackages('[["package"]]\nname = "a"\n') >= 1 && B.tomlPackages('[["pack\\"age"]]\n') >= 1);
  });
  it("text that would mislead a count does not make it fall below what the reader takes", () => {
    const cases = [
      // A key written with an escape is the key it spells.
      ["package-lock.json", JSON.stringify({ lockfileVersion: 3 }).slice(0, -1) + ',"\\u0070ackages":{"node_modules/a":{"version":"1.0.0"},"node_modules/b":{"version":"2.0.0"}}}', (t) => B.lockfileEntries(t, "npm"), 2],
      // Braces, brackets and keys inside strings are text.
      ["package-lock.json", JSON.stringify({ lockfileVersion: 3, x: '{"packages":{"a":1,"b":2}}', packages: { "node_modules/a{": { version: "1.0.0", note: "]}}{[" } } }), (t) => B.lockfileEntries(t, "npm"), 1],
      // Version 1's tree, nested.
      ["package-lock.json", JSON.stringify({ lockfileVersion: 1, dependencies: { a: { version: "1.0.0", dependencies: { b: { version: "1.0.0", dependencies: { c: { version: "1.0.0" } } } } }, d: { version: "1.0.0" } } }), (t) => B.lockfileEntries(t, "npm"), 4],
      // A version-2 lockfile carries both: its packages are read.
      ["package-lock.json", JSON.stringify({ lockfileVersion: 2, packages: { "": {}, "node_modules/a": { version: "1.0.0" } }, dependencies: { a: { version: "1.0.0" } } }), (t) => B.lockfileEntries(t, "npm"), 2],
      // Entries that are not objects are taken too.
      ["package-lock.json", JSON.stringify({ lockfileVersion: 3, packages: { a: 1, b: "x", c: null, d: [] } }), (t) => B.lockfileEntries(t, "npm"), 4],
      // (#3434's reader gives nothing for an element that is not an object; the counter counts all six.)
      ["composer.lock", JSON.stringify({ packages: [{ name: "a/b", version: "1.0.0" }, 7, "x", null, []], "packages-dev": [{ name: "c/d", version: "1.0.0" }] }), (t) => B.lockfileEntries(t, "composer"), 2],
      ["composer.lock", JSON.stringify({ packages: [] }).slice(0, -1) + ',"pack\\u0061ges-dev":[{"name":"a/b","version":"1"}]}', (t) => B.lockfileEntries(t, "composer"), 1],
      // TOML: a quoted header, spaces in it, an inline package array, an escaped key, a [[package]] in a string.
      ["Cargo.lock", '[[ "package" ]]\nname = "a"\nversion = "1.0.0"\n[[package]]\nname = "b"\nversion = "1.0.0"\nx = "[[package]]"\n', B.tomlPackages, 2],
      ["poetry.lock", 'package = [{name = "a", version = "1.0.0"}, {name = "b", version = "2.0.0"}]\n', B.tomlPackages, 2],
      ["Cargo.lock", '"p\\u0061ckage" = [{name = "a", version = "1.0.0"}]\n', B.tomlPackages, 1],
      // Lines: blank, whitespace-only and CRLF lines are not entries; a last line without a newline is.
      ["requirements.txt", "a==1\r\n\r\n \t \r\nb==2", B.nonBlankLines, 2],
      ["gradle.lockfile", "# comment\ng:a:1=c\n\ng:b:2=c\n", B.nonBlankLines, 2],
    ];
    for (const [format, text, count, want] of cases) {
      const t = taken(format, text);
      assert.equal(t, want, `${format} ${JSON.stringify(text).slice(0, 80)}: its reader took ${t}, the case says ${want}`);
      assert.ok(count(text) >= t, `${format} ${JSON.stringify(text).slice(0, 80)}: counted ${count(text)}, its reader took ${t}`);
    }
  });
  it("deeper than the counter's frames, nothing is lost or counted twice, and a text of every depth counts in one pass", () => {
    const deep = (n) => "[".repeat(n) + "]".repeat(n);
    const text = JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/a": { version: "1.0.0" } } }).slice(0, -1) + `,"x":${deep(5000)},"y":{"packages":{"z":1}}}`;
    assert.equal(B.lockfileEntries(text, "npm"), 1, "a nested packages key or a deep structure was counted");
    const t0 = Date.now();
    B.lockfileEntries(deep(2_000_000), "npm");
    B.tomlPackages("[[package]]\n".repeat(400_000));
    B.nonBlankLines("a\n".repeat(2_500_000));
    assert.ok(Date.now() - t0 < 2000, `${Date.now() - t0} ms`);
  });
});

describe("#3381: check_sbom counts an sbom passed as text before it parses it", () => {
  it("one estimated past PARSE_BUDGET_BYTES is refused unparsed, naming what was counted and the bound; a real one is read", () => {
    const dense = JSON.stringify({ bomFormat: "CycloneDX", components: Array(600_000).fill({}) });
    const r = S.extract({ sbom: dense }, undefined, IMAGE.parseBytes);
    assert.equal(typeof r, "string");
    assert.match(r, /^sbom is too dense to read: its \d+ objects and arrays, \d+ entries and \d+ keys, parsed, are estimated at \d+ bytes, past the 29360128 bytes a document's parse may take; pass its purls instead$/);
    const juice = fs.readFileSync(path.join(PKG_DIR, "test", "fixtures", "juice-shop-11.1.2-50.cdx.json"), "utf8");
    const ok = S.extract({ sbom: juice }, undefined, IMAGE.parseBytes);
    assert.equal(typeof ok, "object", ok);
    assert.ok(ok.purls.length > 0);
    // A local server's bound reads the one the image's refuses (a CycloneDX document of 600,000 components, none with a
    // purl).
    const local = S.extract({ sbom: dense }, undefined, LOCAL.parseBytes);
    assert.equal(typeof local, "object", local);
    assert.equal(local.components_in_document, 600_000);
  });
  it("control: the refusal is the estimate's, not the text's size: a sbom of the same size that is one long string is read", () => {
    const sparse = JSON.stringify({ bomFormat: "CycloneDX", components: [{ name: "x".repeat(1_800_000), purl: "pkg:npm/a@1.0.0" }] });
    const r = S.extract({ sbom: sparse }, undefined, IMAGE.parseBytes);
    assert.equal(typeof r, "object", r);
  });
});

// #3381's round-4 review (F5, F16, F17, F12, F13, F14) and #3391's third review (F10): what the docs say of the budget
// and of a disputed match is what the code does. Each was a sentence the code contradicted.
describe("#3381's round-4 review: the docs say what the budget and the relay do", () => {
  const read = (f) => fs.readFileSync(path.join(PKG_DIR, f), "utf8").replace(/\s+/g, " ");
  // The newest entry: "## Unreleased" until the release renames it "## <version> — <date>".
  const unreleased = () => read("CHANGELOG.md").split(/(?:^| )## /).find((s) => s.startsWith("Unreleased") || /^\d/.test(s));
  it("the second a waiter waits before a large body that fits is held back (BUDGET_STARVE_MS), in rate-limits.md and the changelog; no sentence says a body that fits is let in at once", () => {
    assert.equal(B.BUDGET_STARVE_MS, 1000, "the docs say a second");
    for (const [f, t] of [["docs/rate-limits.md", read("docs/rate-limits.md")], ["CHANGELOG.md", unreleased()]]) {
      assert.match(t, /A body that fits is let in ahead of one that waits and does not, until that one has waited a second; from then on a body above the general 64 KiB cap is let in only if the room the waiter needs is left beside it/, f);
      assert.doesNotMatch(t, /A body that fits is let in at once/, f);
      assert.match(t, /three quarters of the budget/, `${f}: the most one request may hold`);
    }
  });
  it("a scan_manifest file past the bound is not read, and the call is invalid_input only when no file could be read, in structured-results.md and the changelog", () => {
    for (const [f, t] of [["docs/structured-results.md", read("docs/structured-results.md")], ["CHANGELOG.md", unreleased()]]) {
      assert.match(t, /`read` false and `refused` saying so, reads the call's other files, and answers `invalid_input` only when no file could be read/, f);
    }
  });
  it("tools.md and the changelog name cna_range_default, call no CNA range the record's own words, and do not take a missing dispute for agreement", () => {
    for (const [f, t] of [["docs/tools.md", read("docs/tools.md")], ["CHANGELOG.md", unreleased()]]) {
      assert.match(t, /`cna_range_default` true, a span no entry writes that the record's `defaultStatus` covers/, f);
      assert.doesNotMatch(t, /as its record writes them|the advisory interval that holds the version/, f);
      assert.match(t, /is not a finding that the CNA agrees/, f);
      for (const k of ["collection_url", "package_url", "dropped_products"]) assert.match(t, new RegExp(`\`${k}\``), `${f} does not name ${k}`);
      // #3381's round-10 review (d4-release R10-3, d5-3391relay F1, F2, F3): #3391's fields are what an answer carries
      // once EchelonGraph's API serves them, never served "today"; lodash's dispute is conditional; a product without
      // stored_form may have been cut unflagged; cna_range is the CNA's range in dispute, not one that holds the version.
      assert.doesNotMatch(t, /today, language-registry|`?advisory`? today\b/, f);
      assert.doesNotMatch(t, /CNA's range that holds the version/, f);
      assert.match(t, /CNA's range in dispute, as the API reads the record/, f);
      assert.match(t, /Once EchelonGraph's API serves (it|them)/, f);
      assert.match(t, /without `stored_form` (comes from an API or a writer that sends none of these|may have)/, f);
    }
    const tools = read("docs/tools.md");
    assert.match(tools, /lodash 4\.17\.15 under CVE-2026-4800 carries `fixed_in` 4\.18\.1, the CNA's bound, where the advisory says 4\.18\.0; until #3391 reached the API, on 2026-11-07, it carried 4\.18\.0 and no dispute/);
    assert.doesNotMatch(tools, /once the field is served/);
    // Since 2026-11-07 the API serves it (#3391, core-backend 95927abe): the page says so, and the lodash example is what
    // the API answers now.
    assert.match(tools, /Since EchelonGraph's API serves it \(#3391, from 2026-11-07\), a registry match carries `fixed_in_dispute`/);
    assert.match(tools, /Since EchelonGraph's API serves them \(#3391, from 2026-11-07\), a product also carries `package_name`/);
  });
  // #3381's round-10 review: the docs say what the per-request bound is (what one request may reserve before it reads,
  // R10-B1), that a batch's answer is read only to the room left (R10-M1), what a local server bounds (R10-m1), and
  // "Through 3.1.5" of what 3.1.5 and every earlier release lacked (d4-release R10-2; 3.1.4 and 3.1.5 shipped these paths unchanged).
  it("R10-B1, R10-M1, R10-m1, R10-2: the per-request bound, the answer read, the local server and the versions, as the code has them", () => {
    const readme = read("README.md");
    const docs = [["CHANGELOG.md", unreleased()], ["docs/rate-limits.md", read("docs/rate-limits.md")], ["docs/structured-results.md", read("docs/structured-results.md")]];
    for (const [f, t] of [...docs, ["README.md", readme]]) assert.doesNotMatch(t, /one request holds at most|holds one request, its body|one request may hold, its body|holds a request, body and reads/, f);
    for (const [f, t] of docs) assert.match(t, /may reserve (at most 31,457,280 bytes \(30 MiB\) of the instance's memory )?before it reads|reserve more than 31,457,280 bytes \(30 MiB\) of its memory before it reads/, f);
    for (const [f, t] of docs.slice(0, 2)) assert.match(t, /read only to (the room left|what the call's reservation still covers of it and what the budget has left)/, f);
    assert.match(read("docs/rate-limits.md"), /A server run locally \(stdio\) holds only a document it parses from text to the same share of its own heap/);
    assert.doesNotMatch(read("docs/rate-limits.md"), /a server run locally holds itself to the same shares of its own heap/);
    const u = unreleased();
    assert.doesNotMatch(u.replace(/### Corrections.*/s, ""), /[Tt]hrough 3\.1\.[2-4]\b/);
    assert.equal((u.match(/Through 3\.1\.5 /g) ?? []).length >= 4, true);
    assert.match(u, /Correction to 3\.1\.2's entry/);
  });
});

// #3381's round-7 verification (R7V-2.1): every regex this release runs on a caller's text before or while it is read
// (the estimators of parseBudget.ts, scan_manifest.ts's, and the readers'), on adversarial single lines of 300,000
// characters and more, each shaped at its own pattern's quantifiers: each call within 100 ms, under the image's flags.
// Through round 7 tomlPackages' header pattern took 10 s on '[["\\' and 120,000 spaces, and 81 s at 300,000, while the
// instance answered nothing.
describe("#3381's round-7 verification: no estimator's or reader's regex is worse than linear in one line", () => {
  const N = 300_000;
  // Each case: a name, a filename, and the text, built in the child from its parts ([string, times]).
  const CASES = [
    // tomlPackages: TOML_PACKAGE_HEADER's escape branch, its blanks before ]], its name branches; TOML_PACKAGE_KEY's two.
    ['[["\\ then spaces', "Cargo.lock", [['[["\\', 1], [" ", N]]],
    ['[[" then backslashes', "Cargo.lock", [['[["', 1], ["\\", N]]],
    ["[[ then spaces and tabs, no name", "poetry.lock", [["[[", 1], [" \t", N / 2]]],
    ["[[package then blanks, no ]]", "Cargo.lock", [["[[package", 1], [" \t", N / 2]]],
    ['[[" then letters, no escape', "poetry.lock", [['[["', 1], ["a", N]]],
    ['" then backslashes (a quoted key with an escape)', "Cargo.lock", [['"', 1], ["\\", N]]],
    ["blanks, package, blanks, no =", "Cargo.lock", [[" \t", N / 2], ["package", 1], [" \t", N / 2]]],
    ['"package" then blanks and a {', "poetry.lock", [['"package"', 1], [" ", N], ["{", 1]]],
    ["''' then quotes", "Cargo.lock", [["a = '''", 1], ["'", N]]],
    ['""" then escaped quotes', "poetry.lock", [['a = """', 1], ['\\"', N / 2]]],
    // lockfileEntries and documentCost: a string of escapes, unterminated; a key of escaped quotes.
    ["a package-lock string of backslashes", "package-lock.json", [['{"packages":{"', 1], ["\\\\", N / 2]]],
    ["a composer key of escaped quotes", "composer.lock", [['{"packages":[{"', 1], ['\\"', N / 2]]],
    // npmlock.ts source(): resolved in the shapes its git, local and tarball patterns scan.
    ["npm resolved: a/b then !", "package-lock.json", [['{"lockfileVersion":1,"dependencies":{"x":{"version":"1.0.0","resolved":"', 1], ["a", N / 2], ["/", 1], ["b", N / 2], ['!"}}}', 1]]],
    ["npm resolved: /-/ runs, no .tgz", "package-lock.json", [['{"lockfileVersion":1,"dependencies":{"x":{"version":"1.0.0","resolved":"https://r/', 1], ["/-/a", N / 4], ['"}}}', 1]]],
    // Gemfile.lock's section and spec patterns; gradle.lockfile's coordinates.
    ["Gemfile specs: then blanks then x", "Gemfile.lock", [["GEM\n  specs:", 1], [" ", N], ["x\n", 1]]],
    ["Gemfile spec: a name, (, no )", "Gemfile.lock", [["GEM\n  specs:\n    a (", 1], ["b", N], ["\n", 1]]],
    ["Gemfile spec: a long name, (1), blanks, x", "Gemfile.lock", [["GEM\n  specs:\n    ", 1], ["a", N / 2], [" (1) ", 1], [" ", N / 2], ["x\n", 1]]],
    ["gradle: colons", "gradle.lockfile", [["a:", N / 2], ["\n", 1]]],
    ["gradle: a:b: then letters then a blank", "gradle.lockfile", [["a:b:", 1], ["c", N], [" x\n", 1]]],
    // The line readers' own patterns, past their LINE_MAX, are 3.1.3's (test/manifest-lines.test.mjs); one each here.
    ["requirements: a name then blanks then #", "requirements.txt", [["a", 1], [" ", N], ["#\n", 1]]],
    ["go.mod: require then a path", "go.mod", [["module m\nrequire ", 1], ["a", N], [" v1\n", 1]]],
  ];
  const url = (f) => pathToFileURL(path.join(PKG_DIR, "dist", f)).href;
  const CHILD = `
const B = await import(${JSON.stringify(url("parseBudget.js"))});
const SM = await import(${JSON.stringify(url("tools/scan_manifest.js"))});
const M = await import(${JSON.stringify(url("tools/manifests/index.js"))});
const C = await import(${JSON.stringify(url("tools/manifests/common.js"))});
const cases = JSON.parse(process.env.REGEX_CASES);
const IMG = B.budgetsFor(B.IMAGE_HEAP_LIMIT);
const time = (fn) => { const t0 = performance.now(); fn(); return Math.round((performance.now() - t0) * 10) / 10; };
const out = [];
for (const [name, filename, parts] of cases) {
  const text = parts.map(([x, n]) => x.repeat(n)).join("");
  const format = M.detect(filename).format;
  const ms = { chars: text.length };
  if (format === "Cargo.lock" || format === "poetry.lock") { ms.tomlPackages = time(() => B.tomlPackages(text)); ms.tomlEstimate = time(() => B.tomlEstimate(text)); }
  if (format === "package-lock.json" || format === "composer.lock") { ms.lockfileEntries = time(() => B.lockfileEntries(text, format === "composer.lock" ? "composer" : "npm")); ms.documentCost = time(() => B.documentCost(text)); }
  ms.nonBlankLines = time(() => B.nonBlankLines(text));
  ms.manifestEstimate = time(() => SM.manifestEstimate({ files: [{ filename, content: text }] }, IMG));
  ms.readFile = time(() => M.readFile(format, text, C.callBounds(), IMG.parseBytes));
  ms.scanJson = time(() => B.scanJson(Buffer.from(JSON.stringify({ files: [{ filename, content: text }] }))));
  out.push({ name, ...ms });
}
console.log(JSON.stringify(out));
`;
  it("each estimator and reader, on each adversarial line of 300,000 characters or more, within 100 ms", { skip: IMAGE_SKIP }, (t) => {
    const out = JSON.parse(execFileSync(process.execPath, [...imageNodeFlags(), "--input-type=module", "-e", CHILD], { encoding: "utf8", env: { ...process.env, REGEX_CASES: JSON.stringify(CASES) }, timeout: 120_000 }));
    assert.equal(out.length, CASES.length);
    for (const r of out) t.diagnostic(JSON.stringify(r));
    const slow = [];
    for (const r of out) {
      assert.ok(r.chars >= N, `${r.name}: ${r.chars} characters`);
      for (const [k, v] of Object.entries(r)) if (k !== "name" && k !== "chars" && v >= 100) slow.push(`${r.name}: ${k} ${v} ms`);
    }
    assert.deepEqual(slow, [], JSON.stringify(out));
  });
});
