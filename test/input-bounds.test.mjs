// #3345 (CVE-2023-54404, GHSA-mrhx-c7xc-m3w5): every list and every record in every tool's
// inputSchema has an upper bound, and zod checks it before it parses an element (src/inputBounds.ts
// says how). zod 4.6.6 checks a leading .max() first; a container with no bound is still parsed
// whole, however large. Through 3.1.0 three were unbounded: check_sbom's purls and its sbom object,
// and scan_manifest's files.
//
// The walk reads every tool's inputSchema as tools/list publishes it (the JSON Schema the SDK makes
// of the zod object, so every container zod parses is in it) and fails on:
//   - a list (type array, items or prefixItems) without maxItems, unless it is a closed tuple
//     (prefixItems with items: false);
//   - a record (an object whose additionalProperties is a schema, or with patternProperties or
//     propertyNames) without maxProperties.
// An object with only its declared properties is bounded by them: zod strips any other key without
// reading it. A node that takes any value ({}, z.unknown()) is not a container zod parses; what it
// holds is bounded by the call's element limit (index.ts MAX_TOOL_INPUT_ELEMENTS).
//
// Then each bound found is sent one over, filled with elements of the wrong type: the refusal must
// name the bound and no element, which holds that the bound is checked before any element is.
//
// purls' bound counts entries, repeats included (check_sbom.ts MAX_PURL_ENTRIES, 10,000), not the
// 2,000 distinct purls check_sbom documents and checks (MAX_PURLS), which it refuses past itself:
// a list within both, however many repeats, is checked, as 3.1.0 checked it (#3345's review).
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { modernMeta } from "./mcp-http-client.mjs";
import { PKG_DIR, serverCommand } from "./server-under-test.mjs";
import { BATCH_PATH, ROWS, batchAnswer } from "./fixtures/match-batch.mjs";

const isNode = (n) => n !== null && typeof n === "object" && !Array.isArray(n);
const types = (n) => [].concat(n.type ?? []);

// Every unbounded list or record under `node`, by its path from `at`.
export function unboundedContainers(node, at = "") {
  const out = [];
  const walk = (n, p) => {
    if (Array.isArray(n)) return n.forEach((x, i) => walk(x, `${p}/${i}`));
    if (!isNode(n)) return;
    const isList = types(n).includes("array") || "items" in n || "prefixItems" in n;
    if (isList) {
      const closedTuple = Array.isArray(n.prefixItems) && n.items === false;
      if (!closedTuple && typeof n.maxItems !== "number") out.push(`${p || "(root)"}: a list without maxItems`);
    }
    const isRecord = isNode(n.additionalProperties) || n.additionalProperties === true || "patternProperties" in n || "propertyNames" in n;
    if (isRecord && typeof n.maxProperties !== "number") out.push(`${p || "(root)"}: a record without maxProperties`);
    for (const [k, v] of Object.entries(n)) if (isNode(v) || Array.isArray(v)) walk(v, `${p}/${k}`);
  };
  walk(node, at);
  return out;
}

// Every bounded container one level under a tool's arguments (directly, or as a branch of a
// union), as [argument, kind, bound]: the ones these tools have.
function boundsOf(inputSchema) {
  const out = [];
  for (const [arg, s] of Object.entries(inputSchema.properties ?? {})) {
    for (const b of [s, ...(s.anyOf ?? []), ...(s.oneOf ?? [])]) {
      if (typeof b.maxItems === "number") out.push([arg, "list", b.maxItems]);
      if (typeof b.maxProperties === "number") out.push([arg, "record", b.maxProperties]);
    }
  }
  return out;
}

// The stub answers the batch route (each purl not_affected) and 404 to anything else; it counts
// every request and keeps each batch's purls, in order.
let stub;
let requests = 0;
const batches = [];
before(async () => {
  stub = http.createServer((req, res) => {
    requests++;
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (req.url === BATCH_PATH && req.method === "POST") {
        const purls = JSON.parse(b).components.map((c) => c.purl);
        batches.push(purls);
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(batchAnswer(purls.map((p, i) => ROWS.notAffected(i, p, "bounds", "1.0.0")))));
        return;
      }
      res.writeHead(404, { "content-type": "application/json" });
      res.end('{"error":"not found"}');
    });
  });
  await new Promise((r) => stub.listen(0, "127.0.0.1", r));
});
after(() => new Promise((r) => stub.close(r)));

describe("#3345: every list and record in every tool's inputSchema is bounded, and the bound is checked before any element", () => {
  let client, tools;
  before(async () => {
    client = await connect({ era: MODERN, ...serverCommand(), env: { ...process.env, ECHELONGRAPH_API_BASE: `http://127.0.0.1:${stub.address().port}`, ECHELONGRAPH_API_TIMEOUT_MS: "2000" }, stderr: "ignore" });
    ({ tools } = await client.listTools());
  });
  after(() => client?.close());

  it("no tool's inputSchema holds an unbounded list or record (tools/list)", () => {
    assert.equal(tools.length, 16);
    const found = tools.flatMap((t) => unboundedContainers(t.inputSchema, t.name));
    assert.deepEqual(found, []);
  });

  // purls' bound is its entries, repeats included (MAX_PURL_ENTRIES), not the 2,000 distinct purls
  // check_sbom checks (MAX_PURLS), which check_sbom refuses past itself (#3345's review).
  it("the bounds are the tools' documented limits: check_sbom 10,000 purls entries and 64 top-level sbom members, scan_manifest 20 files", async () => {
    const { MAX_PURLS, MAX_PURL_ENTRIES, MAX_SBOM_MEMBERS } = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "check_sbom.js")).href);
    const { MAX_FILES } = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "scan_manifest.js")).href);
    const all = Object.fromEntries(tools.map((t) => [t.name, boundsOf(t.inputSchema)]).filter(([, b]) => b.length));
    assert.deepEqual(all, {
      check_sbom: [
        ["purls", "list", MAX_PURL_ENTRIES],
        ["sbom", "record", MAX_SBOM_MEMBERS],
      ],
      scan_manifest: [["files", "list", MAX_FILES]],
    });
    assert.deepEqual([MAX_PURL_ENTRIES, MAX_PURLS, MAX_SBOM_MEMBERS, MAX_FILES], [10000, 2000, 64, 20]);
  });

  it("each bound, one over and filled with elements of the wrong type, is refused by the bound alone: no element was parsed, and nothing was sent", async () => {
    const seen = requests;
    let cases = 0;
    for (const t of tools) {
      for (const [arg, kind, max] of boundsOf(t.inputSchema)) {
        const over = kind === "list" ? new Array(max + 1).fill(null) : Object.fromEntries(Array.from({ length: max + 1 }, (_, i) => [`m${i}`, null]));
        const res = await client.callTool({ name: t.name, arguments: { [arg]: over } });
        const shown = JSON.stringify(res.structuredContent ?? res).slice(0, 400);
        assert.equal(res.structuredContent?.state, "invalid_input", `${t.name}.${arg}: ${shown}`);
        const want = `${arg} must hold at most ${max} ${kind === "list" ? "entries" : "members"}`;
        assert.ok(res.structuredContent.error.message.includes(want), `${t.name}.${arg}: ${shown} lacks ${want}`);
        assert.doesNotMatch(res.structuredContent.error.message, new RegExp(`${arg}(\\[\\d+\\]|\\.m\\d+)`), `${t.name}.${arg}: an element was parsed: ${shown}`);
        cases++;
      }
    }
    assert.equal(cases, 3);
    assert.equal(requests, seen, "a refused call reached the API");
  });

  it("at each bound the arguments pass the inputSchema (the tool itself answers them)", async () => {
    const { MAX_PURL_ENTRIES } = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "check_sbom.js")).href);
    const atBound = {
      check_sbom: { purls: Array.from({ length: MAX_PURL_ENTRIES }, () => "  ") },
      scan_manifest: { files: Array.from({ length: 20 }, (_, i) => ({ filename: `package${i}.json`, content: "{}" })) },
    };
    for (const [name, args] of Object.entries(atBound)) {
      const res = await client.callTool({ name, arguments: args });
      assert.equal(res.structuredContent?.state, "invalid_input", JSON.stringify(res).slice(0, 300));
      assert.doesNotMatch(res.structuredContent.error.message, /inputSchema/, `${name}: refused by the inputSchema at its bound`);
    }
    const sbom = Object.fromEntries(Array.from({ length: 64 }, (_, i) => [`m${i}`, i]));
    const res = await client.callTool({ name: "check_sbom", arguments: { sbom } });
    assert.match(res.structuredContent.error.message, /sbom is neither a CycloneDX JSON document/);
  });

  // #3345's review: purls' bound counts entries, and check_sbom's documented 2,000 counts distinct
  // purls (MAX_PURLS, after trimming and dedupe). A list may repeat a purl, as a flattened SBOM
  // does once per install path, and 3.1.0 checked such a list with each purl sent once; a bound of
  // 2,000 entries refused it ("purls must hold at most 2000 entries").
  it("2,001 entries holding 1,000 distinct purls pass the inputSchema and are checked, each distinct purl sent once (as 3.1.0 checked them)", async () => {
    const distinct = Array.from({ length: 1000 }, (_, i) => `pkg:npm/repeated-${i}@1.0.${i % 10}`);
    const purls = Array.from({ length: 2001 }, (_, i) => distinct[i % distinct.length]);
    const from = batches.length;
    const res = await client.callTool({ name: "check_sbom", arguments: { purls } });
    const shown = JSON.stringify(res.structuredContent ?? res).slice(0, 400);
    assert.notEqual(res.isError, true, shown);
    assert.equal(res.structuredContent.state, "measured", shown);
    const c = res.structuredContent.coverage;
    assert.deepEqual([c.input, c.with_purl, c.duplicates_removed, c.distinct_purls, c.sent, c.not_sent], ["purls", 2001, 1001, 1000, 1000, 0]);
    assert.deepEqual(batches.slice(from).flat(), distinct, "each distinct purl is sent once, at its first place");
  });

  it("at both bounds, MAX_PURL_ENTRIES entries holding MAX_PURLS distinct purls are checked; one distinct purl more is refused by check_sbom itself", async () => {
    const { MAX_PURLS, MAX_PURL_ENTRIES } = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "check_sbom.js")).href);
    const distinct = Array.from({ length: MAX_PURLS + 1 }, (_, i) => `pkg:npm/bound-${i}@1.0.${i % 10}`);
    const from = batches.length;
    const at = Array.from({ length: MAX_PURL_ENTRIES }, (_, i) => distinct[i % MAX_PURLS]);
    const res = await client.callTool({ name: "check_sbom", arguments: { purls: at } });
    assert.equal(res.structuredContent?.state, "measured", JSON.stringify(res.structuredContent ?? res).slice(0, 400));
    const c = res.structuredContent.coverage;
    assert.deepEqual([c.with_purl, c.duplicates_removed, c.distinct_purls, c.sent, c.not_sent], [MAX_PURL_ENTRIES, MAX_PURL_ENTRIES - MAX_PURLS, MAX_PURLS, MAX_PURLS, 0]);
    assert.deepEqual(batches.slice(from).flat(), distinct.slice(0, MAX_PURLS));
    // The same number of entries, one of them a 2,001st distinct purl: past the documented rule.
    const seen = requests;
    const over = [...at.slice(0, -1), distinct[MAX_PURLS]];
    const refused = await client.callTool({ name: "check_sbom", arguments: { purls: over } });
    assert.equal(refused.structuredContent?.state, "invalid_input", JSON.stringify(refused).slice(0, 400));
    assert.match(refused.structuredContent.error.message, new RegExp(`^${MAX_PURLS + 1} distinct purls; at most ${MAX_PURLS} are checked per call`));
    assert.equal(requests, seen, "a refused call reached the API");
  });
});

// #3345's review: over the hosted endpoint a check_sbom call is admitted as a large body (up to
// DEFAULT_MAX_SBOM_BODY_BYTES, httpPolicy.ts LARGE_BODY_TARGETS), so a purls list at its entry
// bound is reachable there too, and not only on stdio: MAX_PURL_ENTRIES entries of the longest purl
// the backend takes (MAX_PURL_LEN characters) are a body under that cap (check_sbom.ts says what
// realistic purls weigh).
describe("#3345: a purls list at its entry bound fits a hosted check_sbom body", () => {
  it("MAX_PURL_ENTRIES entries of MAX_PURL_LEN characters are a tools/call body under the large-body cap, and past the 64 KiB one", async () => {
    const { MAX_PURL_ENTRIES } = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "check_sbom.js")).href);
    const { MAX_PURL_LEN } = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "match_batch.js")).href);
    const { DEFAULT_MAX_BODY_BYTES, DEFAULT_MAX_SBOM_BODY_BYTES, LARGE_BODY_TARGETS } = await import(pathToFileURL(path.join(PKG_DIR, "dist", "httpPolicy.js")).href);
    assert.ok(LARGE_BODY_TARGETS["tools/call"].includes("check_sbom"), "check_sbom is no longer a large-body target: re-aim this check");
    const longest = (i) => `pkg:npm/p${i}@1.0.0?q=`.padEnd(MAX_PURL_LEN, "a");
    assert.equal(longest(0).length, MAX_PURL_LEN);
    const purls = Array.from({ length: MAX_PURL_ENTRIES }, (_, i) => longest(i));
    const bytes = Buffer.byteLength(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "check_sbom", arguments: { purls, full: true }, _meta: modernMeta() } }));
    assert.ok(bytes < DEFAULT_MAX_SBOM_BODY_BYTES, `${bytes} bytes, past the ${DEFAULT_MAX_SBOM_BODY_BYTES}-byte cap`);
    assert.ok(bytes > DEFAULT_MAX_BODY_BYTES, `${bytes} bytes: re-aim this check`);
  });
});

describe("#3345: the walk and boundedRecord can fail (controls)", () => {
  it("a list, a record, a nested list and a union branch without a bound are each found; a closed tuple, a fixed object and {} are not", () => {
    assert.deepEqual(unboundedContainers({ type: "object", properties: { p: { type: "array", items: { type: "string" } } } }, "t"), ["t/properties/p: a list without maxItems"]);
    assert.deepEqual(unboundedContainers({ type: "object", properties: { s: { anyOf: [{ type: "string" }, { type: "object", propertyNames: { type: "string" }, additionalProperties: {} }] } } }, "t"), [
      "t/properties/s/anyOf/1: a record without maxProperties",
    ]);
    assert.deepEqual(unboundedContainers({ type: "object", properties: { f: { type: "array", maxItems: 2, items: { type: "object", properties: { n: { type: "array", items: {} } } } } } }, "t"), [
      "t/properties/f/items/properties/n: a list without maxItems",
    ]);
    assert.deepEqual(unboundedContainers({ type: "object", additionalProperties: true }, "t"), ["t: a record without maxProperties"]);
    assert.deepEqual(unboundedContainers({ type: "array", prefixItems: [{ type: "string" }], items: false }, "t"), []);
    assert.deepEqual(unboundedContainers({ type: "array", prefixItems: [{ type: "string" }], items: { type: "number" } }, "t"), ["t: a list without maxItems"]);
    assert.deepEqual(unboundedContainers({ type: "object", properties: { a: { type: "string" }, b: {} } }, "t"), []);
    assert.deepEqual(unboundedContainers({ type: "array", maxItems: 3, items: { type: "string" } }, "t"), []);
  });

  it("each tool's published schema with one bound removed is found", async () => {
    const client = await connect({ era: MODERN, ...serverCommand(), env: { ...process.env, ECHELONGRAPH_API_BASE: "http://127.0.0.1:9" }, stderr: "ignore" });
    try {
      const { tools } = await client.listTools();
      const sbom = structuredClone(tools.find((t) => t.name === "check_sbom").inputSchema);
      delete sbom.properties.purls.maxItems;
      assert.deepEqual(unboundedContainers(sbom, "check_sbom"), ["check_sbom/properties/purls: a list without maxItems"]);
      const record = structuredClone(tools.find((t) => t.name === "check_sbom").inputSchema);
      for (const b of record.properties.sbom.anyOf) delete b.maxProperties;
      assert.deepEqual(unboundedContainers(record, "check_sbom"), ["check_sbom/properties/sbom/anyOf/1: a record without maxProperties"]);
      const files = structuredClone(tools.find((t) => t.name === "scan_manifest").inputSchema);
      delete files.properties.files.maxItems;
      assert.deepEqual(unboundedContainers(files, "scan_manifest"), ["scan_manifest/properties/files: a list without maxItems"]);
    } finally {
      await client.close();
    }
  });

  it("boundedRecord refuses past its bound before it parses a key or a value, and parses every one within it", async () => {
    const { boundedRecord } = await import(pathToFileURL(path.join(PKG_DIR, "dist", "inputBounds.js")).href);
    const z = await import("zod");
    let parsed = 0;
    const r = boundedRecord(z.string().transform((v) => (parsed++, v)), 3);
    assert.equal(r.safeParse({ a: "1", b: "2", c: "3" }).success, true);
    assert.equal(parsed, 3);
    parsed = 0;
    const big = Object.fromEntries(Array.from({ length: 100_000 }, (_, i) => [`k${i}`, "v"]));
    const res = r.safeParse(big);
    assert.equal(res.success, false);
    assert.equal(parsed, 0, "a value was parsed past the bound");
    assert.deepEqual(res.error.issues.map((i) => [i.code, i.origin, i.maximum]), [["too_big", "object", 3]]);
    // The same, unguarded, parses every value: the bound is what stops it.
    parsed = 0;
    z.record(z.string(), z.string().transform((v) => (parsed++, v))).safeParse(big);
    assert.equal(parsed, 100_000);
    // Published as the record with maxProperties.
    assert.deepEqual(z.toJSONSchema(r, { io: "input" }).maxProperties, 3);
  });
});
