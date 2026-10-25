// #3345 (CVE-2026-111768): createServer sets the SDK's maxToolInputElements (index.ts
// MAX_TOOL_INPUT_ELEMENTS), the most array elements and object members one tools/call's arguments
// may hold, counted before any inputSchema runs. Through 3.1.0 nothing bounded it on stdio, and on
// the hosted endpoint only the 6 MiB body cap did, the advisory's stopgap.
//
// The limit is the largest input any tool accepts (index.ts derives it): check_sbom's sbom object
// at its 5,000,000-character cap holds at most 2,499,998 elements, 2,500,000 with sbom and full. So:
//   - a call AT the limit passes it and is answered by the tool: here an sbom of exactly 5,000,000
//     characters ({"":[0,0,…]}), which check_sbom refuses in its own envelope as not an SBOM;
//   - a call ONE OVER is refused by the SDK, before any schema or handler runs and before any API
//     request: isError true and the SDK's own text naming the limit. The SDK's tools/call handler
//     offers no hook to answer it in badInput's envelope, so it carries no structuredContent; this
//     holds that shape, so a later SDK that changes it is seen;
//   - a large real SBOM (2,000 components, each with licences, a hash and properties, as Syft
//     writes them) is far below the limit and is checked.
// Both eras over stdio, and the hosted endpoint, each against a stub API on 127.0.0.1.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import path from "node:path";
import { spawn } from "node:child_process";
import { pathToFileURL } from "node:url";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { post, modernHeaders, modernMeta } from "./mcp-http-client.mjs";
import { PKG_DIR, serverCommand } from "./server-under-test.mjs";
import { BATCH_PATH, ROWS, batchAnswer } from "./fixtures/match-batch.mjs";

const LEGACY = "2025-06-18";
const { MAX_SBOM_CHARS, MAX_PURL_ENTRIES } = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "check_sbom.js")).href);
const { MAX_FILES } = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "scan_manifest.js")).href);

// The limit, derived here from the tools' own limits as index.ts derives it.
const LIMIT = Math.max(2 + Math.floor((MAX_SBOM_CHARS - 4) / 2), 2 + MAX_PURL_ENTRIES, 2 + MAX_FILES * 4);

// What the SDK counts: every array element and every own object member, at every depth.
export function elements(v) {
  let n = 0;
  const stack = [v];
  while (stack.length) {
    const x = stack.pop();
    if (x === null || typeof x !== "object") continue;
    for (const c of Array.isArray(x) ? x : Object.values(x)) {
      n++;
      if (c !== null && typeof c === "object") stack.push(c);
    }
  }
  return n;
}

// check_sbom's arguments holding exactly `total` elements: { sbom: { "": [0, …] }, full: true }.
const flat = (total) => ({ sbom: { "": new Array(total - 3).fill(0) }, full: true });

// A CycloneDX document of `n` components shaped as Syft writes them.
const component = (i) => ({
  type: "library",
  "bom-ref": `pkg:npm/elements-${i}@1.0.${i % 10}?package-id=${i.toString(16)}`,
  name: `elements-${i}`,
  version: `1.0.${i % 10}`,
  purl: `pkg:npm/elements-${i}@1.0.${i % 10}`,
  licenses: [{ license: { id: "MIT" } }],
  hashes: [{ alg: "SHA-256", content: "0123456789abcdef".repeat(4) }],
  properties: Array.from({ length: 8 }, (_, k) => ({ name: `syft:location:${k}:path`, value: `/usr/lib/node_modules/elements-${i}/package.json` })),
});
const realSbom = (n) => ({
  bomFormat: "CycloneDX",
  specVersion: "1.6",
  serialNumber: "urn:uuid:3345e1e0-0000-4000-8000-000000003345",
  version: 1,
  metadata: { timestamp: "2026-10-25T00:00:00Z", component: { type: "container", name: "app" } },
  components: Array.from({ length: n }, (_, i) => component(i)),
  dependencies: Array.from({ length: n }, (_, i) => ({ ref: component(i)["bom-ref"], dependsOn: i + 1 < n ? [component(i + 1)["bom-ref"]] : [] })),
});

let stub;
const requests = [];
before(async () => {
  stub = http.createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      requests.push(req.url);
      if (req.url === BATCH_PATH && req.method === "POST") {
        const { components } = JSON.parse(b);
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(batchAnswer(components.map((c, i) => ROWS.notAffected(i, c.purl, "elements", "1.0.0")))));
        return;
      }
      res.writeHead(404, { "content-type": "application/json" });
      res.end('{"error":"not found"}');
    });
  });
  await new Promise((r) => stub.listen(0, "127.0.0.1", r));
});
after(() => new Promise((r) => stub.close(r)));
const env = () => ({ ...process.env, ECHELONGRAPH_API_BASE: `http://127.0.0.1:${stub.address().port}`, ECHELONGRAPH_API_TIMEOUT_MS: "10000" });

const OVER_TEXT = new RegExp(`^Invalid arguments for tool check_sbom: arguments contain more than the maximum of ${LIMIT} elements$`);

function assertOver(res) {
  const shown = JSON.stringify(res).slice(0, 400);
  assert.equal(res.isError, true, shown);
  assert.equal(res.content.length, 1, shown);
  assert.match(res.content[0].text, OVER_TEXT);
  // The SDK's own result: no envelope (index.ts says why).
  assert.equal(res.structuredContent, undefined, shown);
}
function assertAtLimit(res) {
  const shown = JSON.stringify(res).slice(0, 400);
  assert.equal(res.isError, true, shown);
  assert.doesNotMatch(JSON.stringify(res.content), /maximum of \d+ elements/);
  // check_sbom's own refusal, in badInput's envelope: the tool ran.
  assert.equal(res.structuredContent?.state, "invalid_input", shown);
  assert.match(res.structuredContent.error.message, /sbom is neither a CycloneDX JSON document/);
}

describe("#3345: the arguments' element limit (MAX_TOOL_INPUT_ELEMENTS) and how it was derived", () => {
  it(`is ${LIMIT.toLocaleString("en")}, check_sbom's sbom object at its ${MAX_SBOM_CHARS.toLocaleString("en")}-character cap, and the derivation is tight`, () => {
    assert.equal(LIMIT, 2_500_000);
    // At the limit, the densest document is exactly the character cap; one element more is over it.
    assert.equal(elements(flat(LIMIT)), LIMIT);
    assert.equal(JSON.stringify(flat(LIMIT).sbom).length, MAX_SBOM_CHARS);
    assert.equal(JSON.stringify(flat(LIMIT + 1).sbom).length, MAX_SBOM_CHARS + 2);
    // The other tools' largest inputs are far below it.
    // check_sbom's purls at its inputSchema bound (entries, repeats included; #3345's review).
    assert.equal(elements({ purls: new Array(MAX_PURL_ENTRIES).fill("pkg:npm/a@1"), full: true }), 2 + MAX_PURL_ENTRIES);
    assert.equal(elements({ files: Array.from({ length: MAX_FILES }, () => ({ filename: "a", content: "x\n".repeat(1000), format: "requirements.txt" })), full: true }), 2 + MAX_FILES * 4);
  });
});

for (const era of [MODERN, LEGACY]) {
  describe(`#3345: check_sbom over stdio at, over and well below the element limit [${era}]`, { timeout: 180_000 }, () => {
    let client;
    before(async () => {
      client = await connect({ era, ...serverCommand(), env: env(), stderr: "ignore", requestTimeoutMs: 60_000 });
    });
    after(() => client?.close());

    it(`one over the limit (${(LIMIT + 1).toLocaleString("en")} elements): the SDK's isError result naming the limit, before any API request`, async () => {
      const before = requests.length;
      assertOver(await client.callTool({ name: "check_sbom", arguments: flat(LIMIT + 1) }));
      assert.equal(requests.length, before, "a call over the limit reached the API");
    });

    it(`at the limit (${LIMIT.toLocaleString("en")} elements, a ${MAX_SBOM_CHARS.toLocaleString("en")}-character sbom): past the limit, answered by check_sbom itself in its envelope`, async () => {
      assertAtLimit(await client.callTool({ name: "check_sbom", arguments: flat(LIMIT) }));
    });

    it("a 2,000-component CycloneDX object, as Syft writes one, is checked: measured, every purl sent", async () => {
      const sbom = realSbom(2000);
      assert.ok(elements({ sbom }) < LIMIT / 10, `${elements({ sbom })} elements`);
      const before = requests.length;
      const res = await client.callTool({ name: "check_sbom", arguments: { sbom } });
      assert.notEqual(res.isError, true, JSON.stringify(res).slice(0, 400));
      assert.equal(res.structuredContent.state, "measured");
      assert.equal(res.structuredContent.coverage.with_purl, 2000);
      assert.equal(requests.length - before, 10, "2,000 purls are 10 batches of 200");
    });
  });
}

describe("#3345: the hosted endpoint applies the same limit (Streamable HTTP, both eras)", { timeout: 180_000 }, () => {
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

  const call = async (era, args) => {
    const params = { name: "check_sbom", arguments: args };
    const r =
      era === MODERN
        ? await post(url, { jsonrpc: "2.0", id: 1, method: "tools/call", params: { ...params, _meta: modernMeta() } }, modernHeaders("tools/call", params))
        : await post(url, { jsonrpc: "2.0", id: 1, method: "tools/call", params }, { "MCP-Protocol-Version": LEGACY });
    assert.equal(r.status, 200, r.text.slice(0, 300));
    return r.message.result;
  };

  for (const era of [MODERN, LEGACY]) {
    it(`[${era}] one over the limit is the SDK's isError result; at the limit check_sbom answers it`, async () => {
      const before = requests.length;
      assertOver(await call(era, flat(LIMIT + 1)));
      assert.equal(requests.length, before, "a call over the limit reached the API");
      assertAtLimit(await call(era, flat(LIMIT)));
    });
  }
});
