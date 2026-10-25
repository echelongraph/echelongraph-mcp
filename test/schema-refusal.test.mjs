// #3015: arguments that break a tool's inputSchema are answered with the full envelope, state
// invalid_input, isError true, notes naming the argument and the rule, like every other refusal, in
// both protocol eras and on both transports (the npm package's stdio, the hosted endpoint's
// Streamable HTTP). Through 3.0.2 the SDK answered them itself, before any handler ran:
// {content:[{type:'text', text:'Input validation error: Invalid arguments for tool search_cves: limit:
// Too big: expected number to be <=50'}], isError:true}, no structuredContent, so no state.
//
// And tools/list is unchanged by it: every tool's inputSchema is byte-identical to the one published
// before the change (test/fixtures/tools-input-schemas.json, recorded from development at 3a747ea3).
// Against what 3.0.2 published, 15 of the 16 are: get_vendor_advisory's differs in its advisory_id
// description, which #3011 (432239b2) rewrote to name vendor_advisory_id and warn off a row's UUID,
// and re-recorded here. A later change to an inputSchema re-records it, on purpose:
// UPDATE_INPUT_SCHEMA_SNAPSHOT=1, and review the diff. 3.1.1 (#3345) re-recorded it for its three
// bounds (check_sbom purls maxItems and sbom maxProperties 64, scan_manifest files maxItems 20);
// nothing else changed. Then #3345's review re-recorded check_sbom's purls: maxItems 2000 became
// 10000 (MAX_PURL_ENTRIES, entries; the 2,000 is distinct purls, check_sbom's own rule), and its
// description says both.
//
// Every API request goes to a stub on 127.0.0.1, which counts them: a refusal makes none.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { StrictOutputValidator } from "./strict-output.mjs";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { connectHttp } from "./mcp-http-client.mjs";
import { PKG_DIR, serverCommand } from "./server-under-test.mjs";

const LEGACY = "2025-06-18";
const SNAPSHOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures", "tools-input-schemas.json");
const UPDATE = process.env.UPDATE_INPUT_SCHEMA_SNAPSHOT === "1";
const validator = new StrictOutputValidator();
const SECRET = "zz3015secretvalue";

// [tool, arguments, the clause the note must carry]: the issue's two (an out-of-range number, a bad
// enum value), a wrong type, a non-integer, a missing required argument, a nested one, a union.
const CASES = [
  ["search_cves", { limit: 500 }, "limit must be at most 50"],
  ["search_vendor_advisories", { severity: "Severe" }, 'severity must be one of "Critical", "High", "Medium" or "Low"'],
  ["search_cves", { limit: "5" }, "limit must be a number, not a string"],
  ["search_cves", { min_cvss: -1 }, "min_cvss must be at least 0"],
  ["kev_recent", { limit: 2.5 }, "limit must be an integer"],
  ["get_cve", {}, "cve_id is required (a string)"],
  ["get_vendor_advisory", { vendor: "redhat" }, "advisory_id is required (a string)"],
  ["scan_manifest", { files: [{ filename: 3 }] }, "files[0].filename must be a string, not an integer; files[0].content is required (a string)"],
  ["check_sbom", { sbom: 5 }, "sbom must be a string or an object, not an integer"],
  // A value of the wrong type is named by its JSON type, never quoted.
  ["vendor_advisories_for_cve", { cve_id: [SECRET] }, "cve_id must be a string, not an array"],
];

let stub;
const requests = [];
before(async () => {
  stub = http.createServer((req, res) => {
    requests.push(req.url);
    res.writeHead(404, { "content-type": "application/json" });
    res.end('{"error":"not found"}');
  });
  await new Promise((resolve) => stub.listen(0, "127.0.0.1", resolve));
});
after(() => new Promise((resolve) => stub.close(resolve)));
const env = () => ({ ...process.env, ECHELONGRAPH_API_BASE: `http://127.0.0.1:${stub.address().port}`, ECHELONGRAPH_API_TIMEOUT_MS: "2000" });

const textOf = (res) => res.content.map((c) => c.text).join("\n");

// What every refusal must be, whatever the transport and era.
function assertRefusal(res, tool, clause, schemas) {
  const shown = JSON.stringify(res).slice(0, 600);
  assert.equal(res.isError, true, shown);
  assert.ok(res.structuredContent && typeof res.structuredContent === "object", `no structuredContent: ${shown}`);
  const sc = res.structuredContent;
  assert.equal(sc.state, "invalid_input", shown);
  assert.deepEqual([sc.measured_at, sc.method, sc.coverage, sc.freshness], [null, null, null, null]);
  assert.equal(sc.error.kind, "invalid_input");
  assert.ok(sc.error.message.includes(clause), `error.message ${JSON.stringify(sc.error.message)} lacks ${JSON.stringify(clause)}`);
  // The notes name the argument and the rule, and say nothing was looked up.
  assert.ok(sc.notes[0].startsWith(`${tool} FAILED (state: invalid_input): the arguments do not fit this tool's inputSchema (tools/list): `), sc.notes[0]);
  assert.ok(sc.notes.some((n) => n.includes(clause)), `notes ${JSON.stringify(sc.notes)} lack ${JSON.stringify(clause)}`);
  assert.ok(sc.notes.includes("Nothing was looked up, so this is not a finding."), JSON.stringify(sc.notes));
  // The envelope in the last text block, key for key (less the notes the message carries).
  const last = JSON.parse(res.content[res.content.length - 1].text);
  assert.deepEqual(last, { state: "invalid_input", measured_at: null, method: null, coverage: null, freshness: null, error: sc.error });
  assert.ok(res.content[0].text.includes(clause), res.content[0].text);
  assert.doesNotMatch(textOf(res), /Input validation error/);
  assert.ok(!JSON.stringify(res).includes(SECRET), "a value the caller sent was quoted");
  const v = validator.getValidator(schemas[tool])(sc);
  assert.ok(v.valid, `${tool}: ${v.errorMessage}`);
}

const published = (tools) => Object.fromEntries(tools.map((t) => [t.name, t.inputSchema]));

describe("#3015: tools/list's inputSchemas are the ones published before the change, byte for byte", () => {
  it("the snapshot holds every tool's inputSchema (UPDATE_INPUT_SCHEMA_SNAPSHOT=1 re-records it)", async () => {
    const client = await connect({ era: MODERN, ...serverCommand(), env: env(), stderr: "ignore" });
    try {
      const { tools } = await client.listTools();
      if (UPDATE) fs.writeFileSync(SNAPSHOT, `${JSON.stringify(published(tools), null, 2)}\n`);
      const want = JSON.parse(fs.readFileSync(SNAPSHOT, "utf8"));
      assert.deepEqual(tools.map((t) => t.name), Object.keys(want));
      for (const t of tools) assert.equal(JSON.stringify(t.inputSchema), JSON.stringify(want[t.name]), `${t.name}'s inputSchema changed`);
    } finally {
      await client.close();
    }
  });
});

for (const era of [MODERN, LEGACY]) {
  describe(`#3015: a schema-level refusal is the invalid_input envelope over stdio [${era}]`, () => {
    let client, tools, schemas;
    before(async () => {
      client = await connect({ era, ...serverCommand(), env: env(), stderr: "ignore" });
      ({ tools } = await client.listTools());
      schemas = Object.fromEntries(tools.map((t) => [t.name, t.outputSchema]));
    });
    after(() => client?.close());

    it("tools/list's inputSchemas are the snapshot's in this era too", () => {
      const want = JSON.parse(fs.readFileSync(SNAPSHOT, "utf8"));
      for (const t of tools) assert.equal(JSON.stringify(t.inputSchema), JSON.stringify(want[t.name]), t.name);
    });

    for (const [tool, args, clause] of CASES) {
      it(`${tool} ${JSON.stringify(args).replace(SECRET, "…")}: ${clause}`, async () => {
        const before = requests.length;
        const res = await client.callTool({ name: tool, arguments: args });
        assertRefusal(res, tool, clause, schemas);
        assert.equal(requests.length, before, "a refused call reached the API");
      });
    }

    it("every tool answers the envelope for an argument of the wrong type (full: 'yes')", async () => {
      assert.equal(tools.length, 16);
      for (const t of tools) {
        assert.ok(t.inputSchema.properties?.full, `${t.name} has no full argument`);
        const res = await client.callTool({ name: t.name, arguments: { full: "yes" } });
        assert.equal(res.structuredContent?.state, "invalid_input", `${t.name}: ${JSON.stringify(res).slice(0, 300)}`);
        assert.ok(res.structuredContent.notes.some((n) => n.includes("full must be a boolean, not a string")), `${t.name}: ${JSON.stringify(res.structuredContent.notes)}`);
        const v = validator.getValidator(schemas[t.name])(res.structuredContent);
        assert.ok(v.valid, `${t.name}: ${v.errorMessage}`);
      }
    });

    it("several broken arguments are each named, in the inputSchema's order", async () => {
      const res = await client.callTool({ name: "search_cves", arguments: { severity: "Severe", min_cvss: 11, limit: 0, offset: -1 } });
      assertRefusal(res, "search_cves", 'severity must be one of "CRITICAL", "HIGH", "MEDIUM" or "LOW"; min_cvss must be at most 10; limit must be at least 1; offset must be at least 0', schemas);
    });

    it("an unknown property is not refused: no tool's inputSchema forbids one, and the call still runs", async () => {
      for (const t of tools) assert.notEqual(t.inputSchema.additionalProperties, false, t.name);
      const before = requests.length;
      const res = await client.callTool({ name: "search_cves", arguments: { limit: 2, bogus: 1 } });
      // The stub answers 404, so the call ran and failed at the API, not at its arguments.
      assert.equal(res.structuredContent.state, "failed", JSON.stringify(res).slice(0, 300));
      assert.equal(requests.length, before + 1);
      assert.match(requests.at(-1), /^\/api\/v1\/public\/cves\?/);
      assert.doesNotMatch(requests.at(-1), /bogus/);
    });

    it("arguments the inputSchema accepts reach the handler as zod parsed them (search_cves limit 2 is sent as limit=2)", async () => {
      const before = requests.length;
      await client.callTool({ name: "search_cves", arguments: { search: "tomcat", limit: 2 } });
      assert.equal(requests.length, before + 1);
      assert.match(requests.at(-1), /limit=2/);
    });
  });
}

// The hosted endpoint builds the same server (createServer) per request.
describe("#3015: a schema-level refusal is the invalid_input envelope over the hosted endpoint (Streamable HTTP)", () => {
  let proc, url, exited;
  before(async () => {
    proc = spawn(process.execPath, [path.join(PKG_DIR, "dist", "http.js")], { env: { ...env(), PORT: "0", MCP_RATE_LIMIT_PER_MIN: "1000" }, stdio: ["ignore", "pipe", "pipe"] });
    exited = new Promise((resolve) => proc.once("exit", resolve));
    url = await new Promise((resolve, reject) => {
      let buf = "";
      let err = "";
      const timer = setTimeout(() => reject(new Error(`http.js did not start: ${err}`)), 15_000);
      proc.stderr.setEncoding("utf8").on("data", (d) => (err += d));
      proc.stdout.setEncoding("utf8").on("data", (d) => {
        buf += d;
        for (const line of buf.split("\n")) {
          try {
            const j = JSON.parse(line);
            if (j.message === "mcp_remote_listening") {
              clearTimeout(timer);
              resolve(`http://127.0.0.1:${j.port}/mcp`);
            }
          } catch {
            // a partial or non-JSON line
          }
        }
      });
    });
  });
  after(async () => {
    proc?.kill("SIGTERM");
    await exited;
  });

  for (const era of [MODERN, LEGACY]) {
    it(`[${era}] tools/list's inputSchemas are the snapshot's, and search_cves {limit:500} and search_vendor_advisories {severity:'Severe'} answer the envelope`, async () => {
      const client = await connectHttp({ era, url });
      const { tools } = await client.listTools();
      const want = JSON.parse(fs.readFileSync(SNAPSHOT, "utf8"));
      for (const t of tools) assert.equal(JSON.stringify(t.inputSchema), JSON.stringify(want[t.name]), t.name);
      const schemas = Object.fromEntries(tools.map((t) => [t.name, t.outputSchema]));
      const before = requests.length;
      for (const [tool, args, clause] of CASES.slice(0, 2)) assertRefusal(await client.callTool({ name: tool, arguments: args }), tool, clause, schemas);
      assert.equal(requests.length, before);
    });
  }
});

// The wrapper itself, against schemas no tool has yet: a closed object (an unknown property refused),
// a default, an async refinement.
describe("#3015: lenientSchema and refusalReason (dist/schemaRefusal.js)", () => {
  let S, z;
  before(async () => {
    S = await import(pathToFileURL(path.join(PKG_DIR, "dist", "schemaRefusal.js")).href);
    z = await import("zod");
  });
  const target = { target: "draft-2020-12" };

  it("publishes the original's JSON Schema, both directions, byte for byte", () => {
    const schemas = [
      z.object({ a: z.string().describe("an a"), n: z.number().int().min(1).max(50).optional(), e: z.enum(["X", "Y"]).optional() }),
      z.strictObject({ a: z.string() }),
      z.object({ files: z.array(z.object({ filename: z.string(), format: z.enum(["p", "q"]).optional() })), d: z.boolean().default(false) }),
    ];
    for (const s of schemas) {
      const w = S.lenientSchema(s);
      for (const io of ["input", "output"]) assert.equal(JSON.stringify(w["~standard"].jsonSchema[io](target)), JSON.stringify(s["~standard"].jsonSchema[io](target)));
      assert.equal(w["~standard"].vendor, "zod");
      assert.equal(w["~standard"].version, 1);
    }
  });

  it("answers the original's value for arguments it accepts (a default applied), and no issues for arguments it refuses", async () => {
    const s = z.object({ a: z.string(), d: z.boolean().default(false) });
    const w = S.lenientSchema(s);
    assert.deepEqual(await w["~standard"].validate({ a: "x" }), await s["~standard"].validate({ a: "x" }));
    assert.deepEqual((await w["~standard"].validate({ a: "x" })).value, { a: "x", d: false });
    const refused = await w["~standard"].validate({ a: 1 });
    assert.equal(refused.issues, undefined);
    assert.equal(typeof refused.value, "object");
    assert.deepEqual(Object.keys(refused.value), [], "the marker is a symbol key, never an argument name");
    // An async refinement settles the same way.
    const a = S.lenientSchema(z.object({ a: z.string().refine(async (v) => v === "ok") }));
    assert.deepEqual((await a["~standard"].validate({ a: "ok" })).value, { a: "ok" });
    assert.equal((await a["~standard"].validate({ a: "no" })).issues, undefined);
  });

  it("names an unknown property of a closed object, and a nested one", () => {
    const s = z.strictObject({ a: z.string(), inner: z.strictObject({ b: z.number() }).optional() });
    const input = { a: "x", extra: 1, inner: { b: 1, c: 2 } };
    const issues = s.safeParse(input).error.issues;
    // zod reports the nested object's issue first, then the top level's.
    assert.equal(S.refusalReason(issues, input), "the arguments do not fit this tool's inputSchema (tools/list): inner.c is not an argument this tool takes; extra is not an argument this tool takes");
  });

  it("names five issues and counts the rest", () => {
    const s = z.object(Object.fromEntries(["a", "b", "c", "d", "e", "f", "g"].map((k) => [k, z.string()])));
    const issues = s.safeParse({}).error.issues;
    assert.equal(issues.length, 7);
    assert.match(S.refusalReason(issues, {}), /a is required \(a string\); b is required \(a string\); c is required \(a string\); d is required \(a string\); e is required \(a string\); and 2 more issues$/);
  });

  it("a string or a list out of bounds is named in characters or entries", () => {
    const s = z.object({ q: z.string().max(3), l: z.array(z.string()).min(1) });
    const input = { q: "abcd", l: [] };
    assert.equal(S.refusalReason(s.safeParse(input).error.issues, input), "the arguments do not fit this tool's inputSchema (tools/list): q must be at most 3 characters long; l must hold at least 1 entry");
  });
});
