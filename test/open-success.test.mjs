// #3268: the release check that every tool's published success branch is open at EVERY level.
//
// #3121 opened only the success branch's root. 3.0.2 still published 86 objects below it with
// additionalProperties false (exposure_radar 32 in data and 6 in freshness, a coverage in 14 tools,
// truncated's entry in all 16, ...) and string enums with no fallback (scan_manifest's
// manifest.files[].format and not_checked[].reason, exposure_radar's newest_kev[].exposure_state,
// ...). A client validates every answer against the outputSchema it listed, and the hosted
// endpoint never tells it to list again, so a field added under any of those objects, or a value
// added to any of those enums, fails every call of that tool for every client that listed the
// release before, until it reconnects. 2.6.2 to 2.6.3 and 2.6.5 to 2.7.0 each did that, and the
// suite could not see it: it validates answers against the build's own schemas, and the synthetic
// lists the tools afresh in every session.
//
// Decision: a success is published open at every level (src/index.ts openSuccess), its `state`
// aside, which tells a success from a failure; the failure branch stays closed at every level
// (#3121's decision). This server still holds its own answers to the closed schema it built
// (checked(), STRICT), and so does the suite (strict-output.mjs, closedOutputSchema), so a field it
// sends without naming it still fails here. This file:
//   - walks tools/list in two protocol eras and fails on any closed object, closed enum or nested
//     oneOf in a success branch, or any open object in a failure branch, with controls that close
//     one object, close one enum and open one failure;
//   - shows with ajv, the validator a client runs, the four cases the issue measured on 3.0.2:
//     accepted by the published schema, refused by the closed copy the server checks against;
//   - holds the opened schema to being built once per process (the hosted endpoint builds a
//     server for every request, #3132), frozen and shared;
//   - runs the old-against-new comparison (schema-compat.mjs) on this build, with controls.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import * as z from "zod";
import { AjvJsonSchemaValidator } from "@modelcontextprotocol/server/validators/ajv";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { PKG_DIR, serverCommand } from "./server-under-test.mjs";
import { strictOutputSchema } from "./strict-output.mjs";
import { branchesOf, closedInSuccess, isFailureBranch, isNode, isSuccessBranch, openInFailure, successStateClosed } from "./schema-openness.mjs";
import { allowedFindings, compatProblems } from "./schema-compat.mjs";

const TOOLS = 16;
const ajv = new AjvJsonSchemaValidator();
const successOf = (schema) => branchesOf(schema).find((b) => b.properties.state.enum.includes("measured"));
const failureOf = (schema) => branchesOf(schema).find(isFailureBranch);
// The node at a path such as data.manifest.files[].format, stepping through nullable unions.
function nodeAt(branch, at) {
  let n = branch;
  const into = (x) => {
    while (isNode(x) && !x.properties && !x.items && Array.isArray(x.anyOf)) x = x.anyOf.find((b) => isNode(b) && (b.properties || b.items || b.anyOf)) ?? x.anyOf[0];
    return x;
  };
  for (const part of at.split(".")) {
    const [name, ...brackets] = part.split("[]");
    n = into(n);
    if (name === "*") n = n.additionalProperties;
    else n = n.properties?.[name];
    assert.ok(isNode(n), `no ${name} at ${at}`);
    for (const _ of brackets) n = into(n).items;
  }
  return n;
}
// A smallest value the node admits: its required fields, each its first value.
function exampleOf(n) {
  if (!isNode(n)) return null;
  if ("const" in n) return n.const;
  if (Array.isArray(n.enum)) return n.enum[0];
  for (const k of ["anyOf", "oneOf"]) if (Array.isArray(n[k])) return exampleOf(n[k][0]);
  const t = [].concat(n.type ?? (n.properties ? "object" : []))[0];
  if (t === "object") return Object.fromEntries((n.required ?? []).map((k) => [k, exampleOf(n.properties?.[k])]));
  return { array: [], string: "x", integer: n.minimum ?? 0, number: n.minimum ?? 0, boolean: true, null: null }[t] ?? null;
}
const validates = (schema, node, value) => ajv.getValidator({ ...(schema.$schema ? { $schema: schema.$schema } : {}), ...node })(value);

for (const era of [MODERN, "2025-06-18"]) {
  describe(`#3268: every tool's published success branch is open at every level [${era}]`, () => {
    let client;
    let tools;
    before(async () => {
      client = await connect({ era, ...serverCommand(), env: { ...process.env, ECHELONGRAPH_API_BASE: "http://127.0.0.1:9" }, stderr: "ignore" });
      ({ tools } = await client.listTools());
    });
    after(() => client?.close());

    it("no object in a success branch has additionalProperties false, and no string enum or const there is closed but state", () => {
      assert.equal(tools.length, TOOLS);
      const closed = tools.flatMap((t) => closedInSuccess(t.outputSchema).map((c) => `${t.name} ${c}`));
      assert.deepEqual(closed, [], `closed in a published success branch, so a field or value added there fails a client that listed this release:\n${closed.join("\n")}`);
      for (const t of tools) assert.ok(successStateClosed(t.outputSchema), `${t.name}: its success branch's state is open, so a failure no longer reads apart from a success`);
    });

    it("every failure branch is closed at every level (#3121's decision)", () => {
      const open = tools.flatMap((t) => openInFailure(t.outputSchema).map((c) => `${t.name} ${c}`));
      assert.deepEqual(open, []);
      for (const t of tools) assert.ok(failureOf(t.outputSchema), `${t.name} has no failure branch`);
    });

    it("the closed copy this server and the suite check answers against still closes what each tool closed", () => {
      let total = 0;
      for (const t of tools) {
        const strict = strictOutputSchema(t.outputSchema);
        assert.notEqual(strict, t.outputSchema, `${t.name}: no closed copy of its published schema in this build`);
        const closed = closedInSuccess(strict);
        assert.ok(closed.includes("(root): additionalProperties false"), `${t.name}: the closed copy's success root admits fields it does not name`);
        assert.ok(closed.some((c) => c.startsWith("truncated.*: additionalProperties false")), `${t.name}: ${closed.join("; ")}`);
        total += closed.length;
        assert.deepEqual(openInFailure(strict), [], `${t.name}: the closed copy's failure branch`);
      }
      const radar = closedInSuccess(strictOutputSchema(tools.find((t) => t.name === "exposure_radar").outputSchema));
      assert.ok(radar.includes("data.kev_exposure.newest_kev[]: additionalProperties false"), radar.join("\n"));
      assert.ok(radar.some((c) => c.startsWith("data.kev_exposure.newest_kev[].exposure_state: closed enum")), radar.join("\n"));
      const manifest = closedInSuccess(strictOutputSchema(tools.find((t) => t.name === "scan_manifest").outputSchema));
      assert.ok(manifest.some((c) => c.startsWith("data.manifest.files[].format: closed enum")), manifest.join("\n"));
      assert.ok(manifest.some((c) => c.startsWith("data.not_checked[].reason: closed enum")), manifest.join("\n"));
      // 3.0.2 published 86 closed objects and 12 closed string enums below the 16 roots.
      assert.ok(total >= TOOLS + 86 + 12, `${total} closed places in the closed copies`);
    });

    it("control: one object re-closed, one enum re-closed, a nested oneOf or one failure opened is each found, and nothing else", () => {
      const radar = tools.find((t) => t.name === "exposure_radar");
      const reclosed = structuredClone(radar.outputSchema);
      nodeAt(successOf(reclosed), "data.kev_exposure.newest_kev[]").additionalProperties = false;
      assert.deepEqual(closedInSuccess(reclosed), ["data.kev_exposure.newest_kev[]: additionalProperties false"]);

      const manifest = tools.find((t) => t.name === "scan_manifest");
      const enumClosed = structuredClone(manifest.outputSchema);
      const format = nodeAt(successOf(enumClosed), "data.manifest.files[].format");
      const known = format.anyOf.find((b) => b.anyOf)?.anyOf.find((b) => b.enum);
      assert.ok(known, JSON.stringify(format).slice(0, 300));
      format.anyOf = format.anyOf.map((b) => (b.anyOf ? known : b));
      assert.deepEqual(closedInSuccess(enumClosed), [`data.manifest.files[].format: closed enum ${JSON.stringify(known.enum)}`]);

      const nested = structuredClone(manifest.outputSchema);
      const f = nodeAt(successOf(nested), "data.manifest.files[].format");
      f.oneOf = f.anyOf;
      delete f.anyOf;
      assert.deepEqual(closedInSuccess(nested), ["data.manifest.files[].format: oneOf"]);

      const failureOpened = structuredClone(radar.outputSchema);
      failureOf(failureOpened).properties.error.additionalProperties = {};
      assert.deepEqual(openInFailure(failureOpened), ["error: admits fields it does not name"]);

      // #3268's review: a slot put back to null alone, as 3.0.2 published 14 freshness and 2
      // coverage slots, is found; the open slot, and null inside a union, are not.
      const cwe = tools.find((t) => t.name === "get_cwe");
      const slotClosed = structuredClone(cwe.outputSchema);
      successOf(slotClosed).properties.freshness = { type: "null", description: "x" };
      assert.deepEqual(closedInSuccess(slotClosed), ["freshness: admits only null"]);
      assert.deepEqual(closedInSuccess(cwe.outputSchema), []);
    });

    it("#3268's review: each success branch's freshness and coverage admit an open object beside null, while this server still answers null there", () => {
      const nullOnly = (n) => isNode(n) && n.type === "null" && !n.anyOf;
      const opened = [];
      for (const t of tools) {
        const strict = strictOutputSchema(t.outputSchema);
        for (const slot of ["coverage", "freshness"]) {
          const pub = successOf(t.outputSchema).properties[slot];
          assert.ok(!nullOnly(pub), `${t.name} ${slot}: published null-only in the success branch`);
          // The failure branch keeps its slot as built: null where the tool has none.
          assert.deepEqual(failureOf(t.outputSchema).properties[slot], failureOf(strict).properties[slot], `${t.name} ${slot}: the failure branch changed`);
          const closed = successOf(strict).properties[slot];
          if (!nullOnly(closed)) continue;
          opened.push(`${t.name} ${slot}`);
          // What a client holding this list runs admits the object a later release may put there...
          assert.ok(validates(t.outputSchema, pub, { a_field_added_later: 1 }).valid, `${t.name} ${slot}: the published slot refuses an object`);
          assert.ok(validates(t.outputSchema, pub, null).valid);
          // ...and the closed copy this server checks its answers against still admits only null.
          assert.equal(validates(strict, closed, { a_field_added_later: 1 }).valid, false, `${t.name} ${slot}: the closed copy admits an object`);
        }
      }
      // 13 freshness slots (all but cve_summary's, #3276, and exposure_radar's and kev_recent's) and cve_summary's and get_cve's coverage.
      assert.equal(opened.length, 15, opened.join("\n"));
      assert.ok(opened.includes("cve_summary coverage") && opened.includes("get_cve coverage") && opened.includes("get_cwe freshness"), opened.join("\n"));
    });

    it("ajv, as a client runs it: what the issue measured on 3.0.2 is accepted by the published schema and refused by the closed copy", () => {
      const of = (name) => tools.find((t) => t.name === name).outputSchema;
      const cases = [
        ["exposure_radar", "data.kev_exposure.newest_kev[]", (n) => ({ ...exampleOf(n), a_field_added_later: true }), /must NOT have additional properties/],
        ["exposure_radar", "data.kev_exposure.newest_kev[].exposure_state", () => "an_exposure_state_added_later", /must be equal to one of the allowed values/],
        ["cve_summary", "truncated.*", (n) => ({ ...exampleOf(n), a_field_added_later: true }), /must NOT have additional properties/],
        ["scan_manifest", "data.not_checked[].reason", () => "a_reason_added_later", /must be equal to one of the allowed values/],
        ["scan_manifest", "data.manifest.files[].format", () => "pnpm-lock.yaml", /must be equal to one of the allowed values/],
        ["search_cves", "coverage", (n) => ({ ...exampleOf(n), a_field_added_later: true }), /must NOT have additional properties/],
      ];
      for (const [name, at, value, refused] of cases) {
        const published = of(name);
        const strict = strictOutputSchema(published);
        const pub = nodeAt(successOf(published), at);
        const v = value(pub);
        const r = validates(published, pub, v);
        assert.ok(r.valid, `${name} ${at}: the published schema refuses ${JSON.stringify(v)}: ${r.errorMessage}`);
        const s = validates(strict, nodeAt(successOf(strict), at), v);
        assert.equal(s.valid, false, `${name} ${at}: the closed copy admits ${JSON.stringify(v)}`);
        assert.match(s.errorMessage, refused, `${name} ${at}`);
        // The known values stay listed beside the fallback.
        if (typeof v === "string") assert.ok(JSON.stringify(pub).includes('"enum":['), `${name} ${at}: the open enum no longer lists its values`);
      }
    });

    it("the old-against-new comparison finds nothing this build adds under what its closed copy closes, and finds a field or value added (controls)", () => {
      const closedTools = tools.map((t) => ({ ...t, outputSchema: strictOutputSchema(t.outputSchema) }));
      // Against its own closed copy, the published schema adds no field and no value; it widens
      // each null-only freshness and coverage slot to null or an object (#3268's review), and nothing else.
      const againstClosed = compatProblems(closedTools, tools);
      assert.equal(againstClosed.length, 15, againstClosed.join("\n"));
      for (const f of againstClosed) assert.match(f, /^\w+: (coverage|freshness): widens its type from null to null\|object$/);
      assert.deepEqual(compatProblems(tools, tools), []);
      const beyondSlots = (xs) => xs.filter((x) => !againstClosed.includes(x));
      const edit = (name, f) => tools.map((t) => (t.name === name ? { ...t, outputSchema: f(structuredClone(t.outputSchema)) } : t));
      const withField = edit("exposure_radar", (s) => {
        const row = nodeAt(successOf(s), "data.kev_exposure.newest_kev[]");
        row.properties.a_field_added_later = { type: "boolean" };
        return s;
      });
      assert.deepEqual(beyondSlots(compatProblems(closedTools, withField)), ["exposure_radar: data.kev_exposure.newest_kev[]: adds a_field_added_later under an object the old release closed"]);
      // Against this build, which publishes that object open, the same field is not a finding: #3268.
      assert.deepEqual(compatProblems(tools, withField), []);
      const withValue = edit("scan_manifest", (s) => {
        const format = nodeAt(successOf(s), "data.manifest.files[].format");
        format.anyOf.find((b) => b.anyOf).anyOf.find((b) => b.enum).enum.push("pnpm-lock.yaml");
        return s;
      });
      assert.deepEqual(beyondSlots(compatProblems(closedTools, withValue)), ['scan_manifest: data.manifest.files[].format: adds "pnpm-lock.yaml" to an enum the old release closed']);
      assert.deepEqual(compatProblems(tools, withValue), []);
      // The failure branch is closed in this build too, so a field added to it is a finding against this build.
      const withFailureField = edit("exposure_radar", (s) => {
        failureOf(s).properties.error.properties.retry_after = { type: "number" };
        return s;
      });
      assert.deepEqual(compatProblems(tools, withFailureField), ["exposure_radar: error: adds retry_after under an object the old release closed"]);
      // #3268's review: a widened type is a finding at any node, open or closed, success or failure:
      // null to null|object (3.0.2's freshness to #3276's cve_summary freshness), a field made
      // nullable, an integer made a number. A narrowed or unchanged type is not.
      const cwe = (f) => edit("get_cwe", (s) => (f(s), s));
      const was302 = cwe((s) => (successOf(s).properties.freshness = { type: "null" }));
      assert.deepEqual(compatProblems(was302, tools), ["get_cwe: freshness: widens its type from null to null|object"]);
      assert.deepEqual(compatProblems(tools, was302), [], "a narrowed type read as a widening");
      const radarRow = (s) => nodeAt(successOf(s), "data.kev_exposure.newest_kev[]");
      const nullable = edit("exposure_radar", (s) => {
        const row = radarRow(s);
        const [k] = Object.entries(row.properties).find(([, v]) => v.type === "string") ?? [];
        assert.ok(k, "no plain string field in newest_kev[]");
        row.properties[k] = { anyOf: [row.properties[k], { type: "null" }] };
        return s;
      });
      const [nk] = Object.entries(radarRow(radar0()).properties).find(([, v]) => v.type === "string");
      assert.deepEqual(compatProblems(tools, nullable), [`exposure_radar: data.kev_exposure.newest_kev[].${nk}: widens its type from string to null|string`]);
      const failureNumber = edit("get_cwe", (s) => {
        failureOf(s).properties.error.properties.status = { type: ["number", "null"] };
        return s;
      });
      const failureInteger = edit("get_cwe", (s) => {
        failureOf(s).properties.error.properties.status = { type: ["integer", "null"] };
        return s;
      });
      assert.deepEqual(compatProblems(failureInteger, failureNumber), ["get_cwe: error.status: widens its type from integer|null to null|number"]);
      assert.deepEqual(compatProblems(failureNumber, failureInteger), []);
      function radar0() {
        return structuredClone(tools.find((t) => t.name === "exposure_radar").outputSchema);
      }
    });

    it("#3268's review: the publish dry run's allow-list is read per old version, and an entry without a reason is refused", () => {
      const file = { accepted: [{ against: "3.0.2", finding: "a: b: c", reason: "why" }, { against: "3.0.1", finding: "d: e: f", reason: "why not" }] };
      assert.deepEqual([...allowedFindings(file, "3.0.2")], [["a: b: c", "why"]]);
      assert.deepEqual([...allowedFindings(file, "3.1.0")], []);
      assert.throws(() => allowedFindings({ accepted: [{ against: "3.0.2", finding: "a: b: c", reason: " " }] }, "3.0.2"), /entry 0 has no reason/);
      assert.throws(() => allowedFindings({ findings: [] }, "3.0.2"), /an allow-list is/);
      // The file the dry run passes is one, and every entry in it says why.
      const shipped = JSON.parse(fs.readFileSync(new URL("./schema-compat-allow.json", import.meta.url), "utf8"));
      assert.ok(allowedFindings(shipped, "3.0.2").size > 0);
    });
  });
}

// The opened schema is made once per process: the hosted endpoint builds a server per request
// (#3132), and the SDK converts every registered tool's outputSchema for each one.
describe("#3268: the opened schema is built once per process, frozen, and the server's own check stays closed", () => {
  const dist = (f) => pathToFileURL(path.join(PKG_DIR, "dist", f)).href;
  let I;
  before(async () => {
    (await import(dist("runtime.js"))).markHttpEntrypoint();
    I = await import(dist("index.js"));
  });
  const build = () =>
    I.envelopeSchema({ data: z.strictObject({ row: z.strictObject({ kind: z.enum(["a", "b"]) }) }), coverage: z.strictObject({ n: z.number() }), freshness: null });
  const ok = { state: "measured", measured_at: null, method: "x", coverage: { n: 1 }, freshness: null, notes: [], data: { row: { kind: "a" } }, data_truncated: false };

  it("the JSON Schema the SDK reads is the same frozen object on every call, open below the root", () => {
    const s = build();
    const std = s["~standard"].jsonSchema;
    const a = std.output({ target: "draft-2020-12" });
    assert.equal(std.output({ target: "draft-2020-12" }), a, "made again on the second call");
    assert.ok(Object.isFrozen(a) && Object.isFrozen(successOf(a).properties.data.properties.row), "not frozen, so one server could change what every other one serves");
    assert.deepEqual(closedInSuccess(a), []);
    assert.deepEqual(openInFailure(a), []);
  });

  it("checked() still refuses a field or a value the closed schema does not name, at any depth", () => {
    const s = build();
    assert.notEqual(I.checked("t", s, { content: [], structuredContent: ok }).isError, true);
    for (const bad of [
      { ...ok, data: { row: { kind: "a", a_field_added_later: 1 } } },
      { ...ok, data: { row: { kind: "c" } } },
      { ...ok, coverage: { n: 1, a_field_added_later: 1 } },
    ]) {
      const r = I.checked("t", s, { content: [], structuredContent: bad });
      assert.equal(r.isError, true, JSON.stringify(bad.data));
      assert.equal(r.structuredContent.error.kind, "unexpected_shape");
    }
    // The published one admits them (what a client holding this list runs).
    const json = s["~standard"].jsonSchema.output({ target: "draft-2020-12" });
    for (const v of [{ row: { kind: "a", a_field_added_later: 1 } }, { row: { kind: "c" } }]) assert.ok(validates(json, successOf(json).properties.data, v).valid, JSON.stringify(v));
  });

  it("closedOutputSchema gives this process's closed copy for a published schema, and nothing for one it did not publish", () => {
    const s = build();
    const published = { type: "object", ...s["~standard"].jsonSchema.output({ target: "draft-2020-12" }) };
    const closed = I.closedOutputSchema(JSON.parse(JSON.stringify(published)));
    assert.ok(closed, "no closed copy found");
    assert.ok(closedInSuccess(closed).includes("data.row: additionalProperties false"), closedInSuccess(closed).join("\n"));
    assert.equal(I.closedOutputSchema({ oneOf: [{ type: "object" }] }), undefined);
    assert.ok(isSuccessBranch(successOf(closed)));
  });
});
