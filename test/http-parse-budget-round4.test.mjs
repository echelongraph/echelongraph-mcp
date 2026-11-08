// #3381's round-4 review: the hosted endpoint's parse budget, started as its image starts it (test/image-server.mjs),
// on each way the fourth review found it failing.
//   F1. The API's answers to a call's purls were outside the budget: 64 check_sbom calls of 2,000 purls (each a small
//       body, estimated at 157 KB), one row in 20 affected, ended the process ("JavaScript heap out of memory"), and so
//       did 63 of them beside one valid 4.95 MB SBOM, with the budget showing room. Now each call reserves what its
//       answers will hold before its first batch, and adds what they hold past that as they come: the process lives,
//       every call is answered (checked, or "server busy"), and V8's live heap stays under the edge.
//   F2. A small request's tool reservation waited behind a large waiter that had waited its time, as round 3's tools/list
//       had: a scan_manifest of a few hundred bytes 8.5 s. Now it takes the small share.
//   F3. A request holding its body, reserving its document, waited for a later waiter that needed the body's room, until
//       the waiter gave up (10 s, 503) and the request was answered 8 s late. Now neither waits for the other.
//   F4. A document whose read, with its body, came to between three quarters of the budget and all of it waited, and
//       under a steady flow of small requests was answered busy on every retry. Now it is refused at once, as one past
//       the budget is (too_large), and one below that is answered under the same flow.
// #3381's round-5 review, below them:
//   T2. F1 now holds what the up-front reservation buys: a call checked is checked whole (at most a few are cut short by
//       the overdraft, and say so), and a call answered "server busy" sent no batch.
//   T4. F1's heavier case again over h2c, one session of 64 streams, as production serves it (MCP_H2C=1).
//   B1. A small request's reservation taken the ordinary way, past the small share, no longer counts in it: a tools/list
//       is answered at once beside a starved large waiter after two such scan_manifest calls.
//   B3. A JSON-RPC batch's calls reserve one after another, each counting what the ones before it hold, so the batch
//       waits as one request: through round 5 each of its calls that waited counted the request again, and the batch's
//       later calls passed a starved large waiter, which was answered 503 once its wait ran out.
// Skipped in the published-tarball run.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { PKG_DIR } from "./server-under-test.mjs";
import { IMAGE_SKIP, SUMMARY, assertAlive, h2cSession, health, imageBudgets, post, resultOf as resultOfAnswer, sleep, startServer, stubApi, toolCall } from "./image-server.mjs";
import { BATCH_PATH, ROWS, batchAnswer } from "./fixtures/match-batch.mjs";

const P = await import(pathToFileURL(path.join(PKG_DIR, "dist", "httpPolicy.js")).href);
const B = await import(pathToFileURL(path.join(PKG_DIR, "dist", "parseBudget.js")).href);
const SM = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "scan_manifest.js")).href);
const IMAGE = IMAGE_SKIP ? B : imageBudgets();
// An answer's result; a long call's SSE answer can open with keep-alive comments.
const resultOf = (r) => resultOfAnswer({ ...r, text: typeof r.text === "string" ? r.text.replace(/^(: keepalive\n\n)+/, "") : r.text });
const IMG = B.budgetsFor(B.IMAGE_HEAP_LIMIT);
const MOST = IMAGE.INFLIGHT_BUDGET_BYTES - Math.floor(IMAGE.INFLIGHT_BUDGET_BYTES / 4);
// V8 ended the process near 104 MB live (parseBudget.ts "The budgets"); what the budget allows stays well under it.
const EDGE_MB = 95;

// A real match's fields, as core-backend sends them (test/fixtures/fixed-in-dispute-wire.json), without a dispute.
const WIRE = JSON.parse(fs.readFileSync(path.join(PKG_DIR, "test", "fixtures", "fixed-in-dispute-wire.json"), "utf8")).cases;
const { fixed_in_dispute: _, ...REAL_MATCH } = WIRE.cna_fixed_advisory_interval.match.matches[0];

// The API for F1: every batch answered after `delayMs`; a purl whose number is a multiple of `every` affected, with
// `cves` real matches; anything else a summary.
async function rowsApi(delayMs, every, cves) {
  // T2: the calls (purlCall's k) whose purls reached the API.
  const calls = new Set();
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const send = (o) => {
        if (res.destroyed) return;
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(o));
      };
      if (req.url !== BATCH_PATH) return send(SUMMARY);
      const { components } = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      for (const c of components) {
        const k = /^pkg:npm\/p(\d+)x/.exec(c.purl)?.[1];
        if (k !== undefined) calls.add(Number(k));
      }
      const rows = components.map((c, i) => {
        const m = /pkg:npm\/([^@]+)@(.*)/.exec(c.purl);
        const k = Number(/(\d+)@/.exec(c.purl)?.[1] ?? 1);
        if (k % every !== 0) return ROWS.notAffected(i, c.purl, m[1], m[2]);
        const ids = Array.from({ length: cves }, (_, j) => `CVE-2024-${10000 + ((k * 7 + j) % 9000)}`);
        return { ...ROWS.affected(i, c.purl, m[1], m[2], ids), matches: ids.map((id) => ({ ...REAL_MATCH, cve_id: id })) };
      });
      setTimeout(() => send(batchAnswer(rows)), delayMs);
    });
  });
  // The server's keep-alive outlasts the client's, so a connection the server under test reuses is never closed under it
  // by this stub (under the full suite's load the default 5 s raced it: "fetch failed", UND_ERR_SOCKET).
  server.keepAliveTimeout = 120_000;
  server.headersTimeout = 125_000;
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return {
    base: `http://127.0.0.1:${server.address().port}`,
    calls,
    close: () => {
      server.closeAllConnections();
      return new Promise((r) => server.close(r));
    },
  };
}
const purlCall = (k, n) => toolCall("check_sbom", { purls: Array.from({ length: n }, (_, i) => `pkg:npm/p${k}x${i}@1.0.${i % 10}`) });
// A Syft-shaped CycloneDX document of `n` components over 2,000 purls, passed as an object (the reviewer's 4.95 MB).
const syftObject = (n) =>
  toolCall("check_sbom", {
    sbom: {
      bomFormat: "CycloneDX", specVersion: "1.5",
      components: Array.from({ length: n }, (_, i) => {
        const k = i % 2000;
        return {
          type: "library", "bom-ref": `pkg:npm/elements-${k}@1.0.${k % 10}?package-id=${i.toString(16)}`, name: `elements-${k}`, version: `1.0.${k % 10}`, purl: `pkg:npm/elements-${k}@1.0.${k % 10}`,
          licenses: [{ license: { id: "MIT" } }], hashes: [{ alg: "SHA-256", content: "0123456789abcdef".repeat(4) }],
          properties: Array.from({ length: 8 }, (_, j) => ({ name: `syft:location:${j}:path`, value: `/usr/lib/node_modules/elements-${k}/package.json` })),
        };
      }),
    },
  });
// What each answer was: checked (measured), "server busy" (failed 503, a reservation that found no room), or a
// refused body (HTTP 503); anything else is the failure under test.
function tally(rs) {
  const out = {};
  for (const r of rs) {
    const sc = resultOf(r)?.structuredContent;
    const key = r.status !== 200 ? `http ${r.status}` : sc?.state === "failed" ? `failed: ${sc.error?.message?.slice(0, 40)}` : sc?.state;
    out[key] = (out[key] ?? 0) + 1;
  }
  return out;
}
const heldOf = (mb, tag) =>
  toolCall("check_sbom", { sbom: { bomFormat: "CycloneDX", specVersion: "1.5", components: [{ type: "library", name: `a${tag}`, version: "1.0.0", purl: `pkg:npm/a${tag}@1.0.0` }, ...Array(Math.floor((mb * 1e6) / 67)).fill({})] } });
function smallDense() {
  const head = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cve_summary","arguments":{"junk":[';
  const tail = "]}}}";
  const room = P.DEFAULT_MAX_BODY_BYTES - head.length - tail.length;
  const list = Array(Math.floor((room + 1) / 3)).fill("{}").join(",");
  return head + list + " ".repeat(room - list.length) + tail;
}
// An npm lockfile of `n` packages over `distinct` names, each nested under one of its own, as npm 10 writes one.
const nestedLock = (n, distinct) =>
  JSON.stringify(
    {
      name: "app", version: "1.0.0", lockfileVersion: 3, requires: true,
      packages: Object.fromEntries([
        ["", { name: "app", version: "1.0.0" }],
        ...Array.from({ length: n }, (_, i) => [
          `node_modules/a${i}/node_modules/pkg-${i % distinct}`,
          {
            version: `1.${(i % distinct) % 40}.0`, resolved: `https://registry.npmjs.org/pkg-${i % distinct}/-/pkg-1.0.0.tgz`, integrity: `sha512-${"A".repeat(86)}==`, license: "MIT",
            dependencies: Object.fromEntries(Array.from({ length: 8 }, (_, j) => [`pkg-${(i + j + 1) % distinct}`, "^1.0.0"])), funding: { url: `https://github.com/sponsors/pkg-${i}` }, engines: { node: ">=14" },
          },
        ]),
      ]),
    },
    null,
    2,
  );

describe("#3381's round-4 review: the parse budget, on each way the fourth review found it failing", { skip: IMAGE_SKIP, concurrency: false, timeout: 900_000 }, () => {
  let stub;
  before(async () => {
    stub = await stubApi();
  });
  after(async () => {
    await stub?.close();
  });

  for (const [name, big, h2c] of [
    ["64 check_sbom calls of 2,000 purls each, one row in 20 affected", 0, false],
    ["63 such calls beside one valid 4.95 MB CycloneDX document of 4,800 components", 4800, false],
    // T4: production serves h2c.
    ["63 such calls beside the 4.95 MB document, as 64 streams of one h2c session", 4800, true],
  ]) {
    it(`F1. ${name}, the API answering each batch after 500 ms: the process lives, every call is answered (checked or busy), the live heap under ${EDGE_MB} MB`, async () => {
      const api = await rowsApi(500, 20, 2);
      const srv = await startServer(api.base, h2c ? { MCP_H2C: "1" } : {}, { nodeFlags: ["--trace-gc"] });
      const session = h2c ? h2cSession(srv.port) : null;
      try {
        const bodies = [];
        if (big) {
          const b = syftObject(big);
          assert.ok(b.length > 4_900_000 && b.length <= P.DEFAULT_MAX_SBOM_BODY_BYTES && B.scanJson(Buffer.from(b)).estimate <= IMAGE.PARSE_BUDGET_BYTES, `${b.length}`);
          bodies.push(b);
        }
        while (bodies.length < 64) bodies.push(purlCall(bodies.length, 2000));
        assert.ok(bodies.at(-1).length <= P.DEFAULT_MAX_BODY_BYTES, "each purl list is a small body");
        const rs = await Promise.all(bodies.map((b) => (session ? session.post(b) : post(srv.port, b))));
        await assertAlive(srv, name);
        const t = tally(rs);
        for (const k of Object.keys(t)) assert.ok(k === "measured" || k.startsWith("failed: server busy") || k === "http 503", `${name}: ${JSON.stringify(t)}`);
        assert.ok((t.measured ?? 0) >= 8, `${name}: too few checked: ${JSON.stringify(t)}`);
        assert.ok(srv.maxLiveMb() > 0 && srv.maxLiveMb() < EDGE_MB, `${name}: ${srv.maxLiveMb()} MB live after a full collection (${JSON.stringify(t)})`);
        // Each call checked was checked whole or says which purls it did not send; none answered clean what it did not send.
        for (const r of rs) {
          const sc = resultOf(r)?.structuredContent;
          if (sc?.state === "measured") assert.ok(sc.coverage.sent + sc.coverage.not_sent === sc.coverage.distinct_purls, JSON.stringify(sc.coverage));
        }
        // T2: what reserving the answers before the first batch buys. A call checked is checked whole: but for the few
        // the overdraft stops mid-way (not_sent_reason server_busy), which the reservation keeps to a few (without it,
        // 46 of 64 here were cut short, and none answered busy). A call answered "server busy" found no room before
        // its first batch, so none of its purls reached the API.
        const cut = rs.map((r) => resultOf(r)?.structuredContent).filter((sc) => sc?.state === "measured" && sc.coverage.not_sent > 0);
        assert.ok(cut.length <= 3, `${name}: ${cut.length} calls checked in part: ${JSON.stringify(cut.map((sc) => [sc.coverage.not_sent, sc.coverage.not_sent_reason]))} (${JSON.stringify(t)})`);
        for (const sc of cut) assert.equal(sc.coverage.not_sent_reason, "server_busy", JSON.stringify(sc.coverage));
        rs.forEach((r, k) => {
          const sc = resultOf(r)?.structuredContent;
          if (sc?.state === "failed" && /^server busy/.test(sc.error?.message ?? "")) assert.ok(!api.calls.has(k), `${name}: call ${k} answered server busy after its purls reached the API`);
        });
        assert.ok(api.calls.size >= 8, `${name}: ${api.calls.size} calls reached the API`);
      } finally {
        await session?.close();
        await srv.stop();
        await api.close();
      }
    });
  }

  it("F2. a scan_manifest of one requirements line, and a check_sbom of a small sbom passed as text, reach the API at once beside a large waiter that has waited its time; one that reads nothing is answered at once", async () => {
    const srv = await startServer(stub.base);
    stub.hold();
    const waiters = [];
    try {
      const batches = stub.state.batches;
      const holder = post(srv.port, heldOf(24, "h"));
      for (const t = Date.now(); stub.state.batches === batches && Date.now() - t < 10_000; ) await sleep(20);
      waiters.push(post(srv.port, heldOf(24, "w")));
      await sleep(B.BUDGET_STARVE_MS + 500);
      const from = srv.lines.length;
      const t0 = Date.now();
      const nothing = post(srv.port, toolCall("scan_manifest", { files: [{ filename: "README.md", content: "x" }] }));
      const req = post(srv.port, toolCall("scan_manifest", { files: [{ filename: "requirements.txt", content: "requests==2.31.0\n" }] }));
      const sbom = post(srv.port, toolCall("check_sbom", { sbom: JSON.stringify({ bomFormat: "CycloneDX", components: [{ name: "s", version: "1", purl: "pkg:npm/smalltext@1.0.0" }] }) }));
      const r0 = await nothing;
      assert.ok(Date.now() - t0 < 2000, `the call that reads nothing was answered after ${Date.now() - t0} ms`);
      assert.equal(resultOf(r0)?.structuredContent?.state, "invalid_input");
      for (const t = Date.now(); !(stub.state.purls.includes("pkg:pypi/requests@2.31.0") && stub.state.purls.includes("pkg:npm/smalltext@1.0.0")) && Date.now() - t < 6000; ) await sleep(20);
      assert.ok(stub.state.purls.includes("pkg:pypi/requests@2.31.0") && stub.state.purls.includes("pkg:npm/smalltext@1.0.0"), `the small calls had not reached the API ${Date.now() - t0} ms after they were sent`);
      assert.ok(Date.now() - t0 < 2000, `the small calls reached the API ${Date.now() - t0} ms after they were sent`);
      stub.release();
      await Promise.all([req, sbom, holder, ...waiters]);
      await sleep(100);
      for (const l of srv.access(from).filter((x) => x.body_bytes < 1000 && x.tool)) assert.ok(l.queued_ms < 1000 && l.refused === "", JSON.stringify(l));
      await assertAlive(srv, "after the small calls");
    } finally {
      stub.release();
      await Promise.all(waiters);
      await srv.stop();
    }
  });

  it("F3. a request holding its body reserves its document while a later waiter that needs that body's room waits: both are answered once the places free, neither waits out the other", async () => {
    const srv = await startServer(stub.base);
    stub.hold();
    try {
      // The instance serving 64 requests, held at the API.
      const fill = Array.from({ length: 64 }, () => post(srv.port, toolCall("cve_summary", {})));
      for (const t = Date.now(); stub.state.open < 64 && Date.now() - t < 20_000; ) await sleep(20);
      // R: an sbom passed as text (its body's estimate X, its document Y); W: a check_sbom that does not fit beside X.
      const doc = JSON.stringify({ bomFormat: "CycloneDX", metadata: { component: { name: "app – 1", description: "p".repeat(4_500_000) } }, components: [{ name: "r", version: "1", purl: "pkg:npm/r@1.0.0" }, ...Array(20_000).fill({})] });
      const rBody = toolCall("check_sbom", { sbom: doc });
      const wBody = heldOf(29, "w");
      const X = B.scanJson(Buffer.from(rBody)).estimate;
      const Y = B.documentCost(doc).bytes;
      const W = B.scanJson(Buffer.from(wBody)).estimate;
      assert.ok(X + Y <= MOST && X + W > IMAGE.INFLIGHT_BUDGET_BYTES && W <= IMAGE.PARSE_BUDGET_BYTES, `X ${X}, Y ${Y}, W ${W}`);
      const t0 = Date.now();
      let rAt;
      let wAt;
      const r = post(srv.port, rBody).then((x) => ((rAt = Date.now() - t0), x));
      await sleep(400);
      const w = post(srv.port, wBody).then((x) => ((wAt = Date.now() - t0), x));
      await sleep(B.BUDGET_STARVE_MS + 800);
      const released = Date.now() - t0;
      stub.release();
      await Promise.all(fill);
      const [rr, wr] = await Promise.all([r, w]);
      assert.equal(resultOf(rr)?.structuredContent?.state, "measured", rr.text?.slice(0, 300));
      assert.equal(wr.status, 200, `W: ${wr.text?.slice(0, 200)}`);
      assert.equal(resultOf(wr)?.structuredContent?.state, "measured");
      assert.ok(rAt - released < 4000 && wAt - released < 4000, `answered ${rAt - released} and ${wAt - released} ms after the places freed`);
      await assertAlive(srv, "after R and W");
    } finally {
      stub.release();
      await srv.stop();
    }
  });

  it("F4. a lockfile whose read with its body passes three quarters of the budget is refused at once, idle and under a steady flow of small requests; one below that is answered under the same flow", async () => {
    // The API: batches answered at once, anything else after 800 ms, so each small request is held that long.
    const api = http.createServer((req, res) => {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        const send = (o) => {
          if (res.destroyed) return;
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify(o));
        };
        if (req.url === BATCH_PATH) return send(batchAnswer(JSON.parse(Buffer.concat(chunks).toString("utf8")).components.map((c, i) => ROWS.notAffected(i, c.purl, "x", "1"))));
        setTimeout(() => send(SUMMARY), 800);
      });
    });
    await new Promise((r) => api.listen(0, "127.0.0.1", r));
    const srv = await startServer(`http://127.0.0.1:${api.address().port}`);
    let stop = false;
    let smallOk = 0;
    const small = smallDense();
    try {
      const callOf = (n) => {
        const args = { files: [{ filename: "package-lock.json", content: nestedLock(n, 1500) }] };
        const body = toolCall("scan_manifest", args);
        return { body, X: B.scanJson(Buffer.from(body)).estimate, Y: SM.manifestEstimate(args, IMG) };
      };
      const band = callOf(6500);
      const below = callOf(5000);
      assert.ok(band.X + band.Y > MOST && band.X + band.Y <= IMAGE.INFLIGHT_BUDGET_BYTES, `band: ${band.X} + ${band.Y}`);
      assert.ok(below.X + below.Y <= MOST, `below: ${below.X} + ${below.Y}`);
      const attempt = async (c, label) => {
        const from = srv.lines.length;
        const t0 = Date.now();
        const r = await post(srv.port, c.body);
        const ms = Date.now() - t0;
        await sleep(100);
        return { sc: resultOf(r)?.structuredContent, ms, line: srv.access(from).find((l) => l.tool === "scan_manifest"), label };
      };
      const idle = await attempt(band, "idle");
      assert.equal(idle.sc?.state, "invalid_input", JSON.stringify(idle.sc?.error));
      assert.match(idle.sc.error.message, new RegExp(`more than the ${MOST} bytes \\(30 MiB\\) one request may hold at once on the hosted endpoint, its body and what reading it holds together .*, so it is not read, and retrying the same call will not change that: .*; or run this server locally \\(npx -y echelongraph-mcp\\)`));
      assert.ok(idle.ms < 3000 && idle.line?.refused === "doc_too_large", JSON.stringify(idle.line));
      // 8 clients, each keeping one 64 KiB request in flight.
      const loops = Array.from({ length: 8 }, async (_, k) => {
        await sleep(k * 100);
        while (!stop) if ((await post(srv.port, small)).status === 200) smallOk++;
      });
      await sleep(1500);
      for (let i = 1; i <= 3; i++) {
        const a = await attempt(band, `band ${i}`);
        assert.ok(a.sc?.state === "invalid_input" && a.ms < 3000 && a.line?.refused === "doc_too_large", `${a.label}: ${a.ms} ms, ${JSON.stringify(a.line)}`);
        const b = await attempt(below, `below ${i}`);
        assert.ok(b.sc && b.sc.state !== "failed" && b.sc.state !== "invalid_input" && b.line?.refused === "", `${b.label}: ${b.ms} ms, ${JSON.stringify(b.sc?.error)} ${JSON.stringify(b.line)}`);
      }
      stop = true;
      await Promise.all(loops);
      assert.ok(smallOk > 10, `${smallOk} small requests answered`);
      await assertAlive(srv, "after the lockfiles");
    } finally {
      stop = true;
      await srv.stop();
      api.closeAllConnections();
      await new Promise((r) => api.close(r));
    }
  });
});

describe("#3381's round-5 review: the small share counts what it took, and a JSON-RPC batch waits as one request", { skip: IMAGE_SKIP, concurrency: false, timeout: 300_000 }, () => {
  // B1: the reviewer's scan_manifest calls (a requirements.txt of 2,000 pins and 8,000 unpinned lines, each a small body
  // reserved some 5.4 MB before it is read, and the 3.1 MB it keeps after: its purls and the 2,000 entries it lists),
  // four of them, what they keep together past the small share, held at the API; a large body that cannot fit beside
  // them and one more holder waits past BUDGET_STARVE_MS; then a tools/list. Through round 5 the calls' reservations
  // taken the ordinary way were counted in the share, so the tools/list waited behind the waiter (8.8 s for two).
  it("B1. after small calls whose reservations together pass the small share, a tools/list is answered at once beside a starved large waiter", async () => {
    const api = await stubApi();
    const srv = await startServer(api.base);
    try {
      api.hold();
      const content = `${Array.from({ length: 2000 }, (_, i) => `p${i}==1`).join("\n")}\n${Array(8000).fill("a").join("\n")}\n`;
      const args = { files: [{ filename: "requirements.txt", content }] };
      const doc = SM.manifestEstimate(args, IMG);
      const kept = SM.entriesCost(2000 + 2000, 2000);
      const share = Math.floor(IMAGE.INFLIGHT_BUDGET_BYTES / 4);
      const body = B.scanJson(Buffer.from(toolCall("scan_manifest", args))).estimate;
      assert.ok(doc <= share && 4 * kept > share && 4 * body + 3 * kept <= share, `each reserved ${doc} and kept ${kept}, its body ${body}, the share ${share}`);
      const calls = Array.from({ length: 4 }, () => post(srv.port, toolCall("scan_manifest", args)));
      for (const t = Date.now(); api.state.batches < 4 && Date.now() - t < 10_000; ) await sleep(20);
      assert.equal(api.state.batches, 4, "the four calls did not reach the API");
      const holder = post(srv.port, heldOf(10, "h"));
      for (const t = Date.now(); api.state.batches < 5 && Date.now() - t < 10_000; ) await sleep(20);
      const waiter = post(srv.port, heldOf(25, "w"));
      await sleep(B.BUDGET_STARVE_MS + 500);
      const from = srv.lines.length;
      const t0 = Date.now();
      const tl = await post(srv.port, JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }));
      const ms = Date.now() - t0;
      assert.equal(tl.status, 200);
      assert.ok(ms < 1500, `the tools/list was answered after ${ms} ms`);
      await sleep(100);
      const line = srv.access(from).find((l) => l.rpc_method === "tools/list");
      assert.ok(line && line.queued_ms < 500, JSON.stringify(line));
      // #3381's round-6 verification: a tools/list is tiny, and has a lane of its own (R6V-1.2) whatever the share holds.
      // A small call past that lane's bound (its document 230 KB, its answers 256 KB) is let in only within the share:
      // through round 5 the calls above, counted in it, kept it out as well.
      const pins = { files: [{ filename: "requirements.txt", content: `${Array.from({ length: 200 }, (_, i) => `q${i}==1`).join("\n")}\n` }] };
      assert.ok(SM.manifestEstimate(pins, IMG) > 64 * 1024, "the small call is within the tiny lane: re-aim this case");
      const t1 = Date.now();
      const small = post(srv.port, toolCall("scan_manifest", pins));
      for (; !api.state.purls.includes("pkg:pypi/q0@1") && Date.now() - t1 < 6000; ) await sleep(20);
      assert.ok(api.state.purls.includes("pkg:pypi/q0@1") && Date.now() - t1 < 1500, `the small call reached the API after ${Date.now() - t1} ms`);
      api.release();
      await Promise.all([...calls, holder, waiter, small]);
      await assertAlive(srv, "after the tools/list");
    } finally {
      api.release();
      await srv.stop();
      await api.close();
    }
  });

  // R6V-1.3: the reviewer's batch. Two large bodies held at the API leave under 1 MB of room; a JSON-RPC batch's first
  // call (900 purls, its answers 1.15 MB, not small) waits and is refused busy; its second (150 purls, 192 KB, small)
  // fits at once. Through round 6 the second was answered busy too, without a try, because the first had been.
  it("R6V-1.3. after a batch's call is refused busy, its later call that fits at once is taken, not refused with it", async () => {
    const api = await stubApi();
    const srv = await startServer(api.base);
    const at = (p) => api.state.purls.includes(p);
    try {
      api.hold();
      const holders = ["a1", "a2"].map((t) => post(srv.port, heldOf(20.47, t)));
      for (const t = Date.now(); !(at("pkg:npm/aa1@1.0.0") && at("pkg:npm/aa2@1.0.0")) && Date.now() - t < 10_000; ) await sleep(20);
      const call = (id, n) => ({ jsonrpc: "2.0", id, method: "tools/call", params: { name: "check_sbom", arguments: { purls: Array.from({ length: n }, (_, i) => `pkg:npm/r${id}x${i}@1`) } } });
      const body = JSON.stringify([call(1, 900), call(2, 150)]);
      const room = IMAGE.INFLIGHT_BUDGET_BYTES - 2 * B.scanJson(Buffer.from(heldOf(20.47, "a1"))).estimate - B.scanJson(Buffer.from(body)).estimate;
      assert.ok(900 * B.WEIGHT_BATCH_ROW > room && 150 * B.WEIGHT_BATCH_ROW <= Math.min(room, B.SMALL_ANSWERS_BYTES), `room ${room}`);
      // The second call's batch is answered at once; the holders stay held.
      const r = post(srv.port, body);
      for (const t = Date.now(); !at("pkg:npm/r2x0@1") && Date.now() - t < 15_000; ) await sleep(20);
      assert.ok(at("pkg:npm/r2x0@1"), "the batch's second call never reached the API");
      api.release();
      const rr = await r;
      assert.equal(rr.status, 200);
      const answers = rr.text.startsWith("event:") ? rr.text.split("\n").filter((l) => l.startsWith("data: ")).map((l) => JSON.parse(l.slice(6))) : [JSON.parse(rr.text)].flat();
      const byId = Object.fromEntries(answers.map((a) => [a.id, a.result?.structuredContent]));
      assert.ok(byId[1]?.state === "failed" && /^server busy/.test(byId[1].error?.message ?? ""), JSON.stringify(byId[1]).slice(0, 300));
      assert.equal(byId[2]?.state, "measured", JSON.stringify(byId[2]).slice(0, 300));
      assert.equal(byId[2].coverage.sent, 150);
      await Promise.all(holders);
      await assertAlive(srv, "after the batch");
    } finally {
      api.release();
      await srv.stop();
      await api.close();
    }
  });

  // B3: the verifier's consequence. W, a large body that cannot fit beside H (another large body) and K (four calls of
  // 2,000 purls, their answers reserved), waits past BUDGET_STARVE_MS; then R, one JSON-RPC batch of 30 scan_manifest
  // calls of 201 pins (their documents small, their answers' reservations not), and H goes. W fits beside K and what R
  // holds while its answers wait behind W. Through round 5 each of R's calls that waited counted R's holdings again, so
  // past the sixth they passed W (the skip rule), and W, kept out by them, was answered 503 after its 10 s wait.
  it("B3. a JSON-RPC batch's reservations wait as one request's: a starved large waiter is let in once a holder ends, not passed by the batch's calls", async () => {
    const api = await stubApi();
    const srv = await startServer(api.base);
    const at = (p) => api.state.purls.includes(p);
    try {
      api.hold();
      const hBody = heldOf(13, "h");
      const wBody = heldOf(25, "w");
      const kCalls = Array.from({ length: 4 }, (_, k) => toolCall("check_sbom", { purls: Array.from({ length: 2000 }, (_, i) => `pkg:npm/k${k}x${i}@1`) }));
      const pins = `${Array.from({ length: 201 }, (_, i) => `p${i}==1`).join("\n")}\n`;
      const rArgs = { files: [{ filename: "requirements.txt", content: pins }] };
      const rBody = JSON.stringify(Array.from({ length: 30 }, (_, k) => ({ jsonrpc: "2.0", id: k + 1, method: "tools/call", params: { name: "scan_manifest", arguments: rArgs } })));
      const est = (b) => B.scanJson(Buffer.from(b)).estimate;
      const K = kCalls.reduce((n, b) => n + est(b) + 2000 * B.WEIGHT_BATCH_ROW, 0);
      const R = est(rBody) + 30 * SM.entriesCost(201, 0);
      const max = IMAGE.INFLIGHT_BUDGET_BYTES;
      assert.ok(Buffer.byteLength(rBody) <= P.DEFAULT_MAX_BODY_BYTES && 201 * B.WEIGHT_BATCH_ROW > B.SMALL_ANSWERS_BYTES, "R is one small body, its answers not small");
      assert.ok(est(hBody) + K + est(wBody) > max && K + R + est(wBody) + 30 * 201 * B.WEIGHT_BATCH_ROW > max && K + R + est(wBody) <= max, `H ${est(hBody)}, K ${K}, R ${R}, W ${est(wBody)}`);
      const hc = new AbortController();
      const h = post(srv.port, hBody, { signal: hc.signal });
      const k = Promise.all(kCalls.map((b) => post(srv.port, b)));
      for (const t = Date.now(); !(at("pkg:npm/ah@1.0.0") && [0, 1, 2, 3].every((i) => at(`pkg:npm/k${i}x0@1`))) && Date.now() - t < 10_000; ) await sleep(20);
      const w = post(srv.port, wBody);
      await sleep(B.BUDGET_STARVE_MS + 500);
      assert.ok(!at("pkg:npm/aw@1.0.0"), "W fit at once: re-aim this test");
      const r = post(srv.port, rBody);
      await sleep(1000);
      const passed = api.state.purls.filter((p) => p?.startsWith("pkg:pypi/p0@")).length;
      hc.abort();
      const t0 = Date.now();
      for (; !at("pkg:npm/aw@1.0.0") && Date.now() - t0 < 6000; ) await sleep(20);
      const ms = Date.now() - t0;
      assert.ok(at("pkg:npm/aw@1.0.0"), `W was not let in once H ended (${passed} of R's calls had passed it)`);
      assert.ok(ms < 3000, `W was let in ${ms} ms after H ended`);
      api.release();
      const [wr, rr] = await Promise.all([w, r, h, k]);
      assert.equal(wr.status, 200, wr.text?.slice(0, 200));
      assert.equal(resultOf(wr)?.structuredContent?.state, "measured");
      assert.equal(rr.status, 200);
      await assertAlive(srv, "after the batch");
    } finally {
      api.release();
      await srv.stop();
      await api.close();
    }
  });
});

// #3381's round-7 verification (R7V-2.1): a scan_manifest call's estimate (parseBudget.ts tomlPackages) runs on the
// caller's text on the event loop, before anything is read. Through round 7 its header pattern backtracked
// quadratically on one Cargo.lock line, '[["\' and 120,000 spaces: some 10 s in which the instance answered nothing,
// /health included, so Cloud Run's probe failed on one small request. Now /health answers within 1 s throughout: while
// the call is estimated, read, and held at the API.
describe("#3381's round-7 verification: /health answers while a call with an adversarial Cargo.lock line is served", { skip: IMAGE_SKIP, concurrency: false, timeout: 300_000 }, () => {
  it("R7V-2.1. /health within 1 s on every probe while a Cargo.lock of '[[\"\\' and 120,000 spaces is served", async () => {
    const api = await stubApi();
    const srv = await startServer(api.base);
    try {
      api.hold();
      // A pin beside it, so the call reaches the API and is held there: the call is still being served once read.
      const args = { files: [{ filename: "Cargo.lock", content: `[["\\${" ".repeat(120_000)}\n` }, { filename: "requirements.txt", content: "a==1\n" }] };
      const at = () => api.state.purls.includes("pkg:pypi/a@1");
      const call = post(srv.port, toolCall("scan_manifest", args));
      const probes = [];
      const probe = async () => {
        const t = Date.now();
        const status = await health(srv.port);
        probes.push({ status, ms: Date.now() - t, held: at() });
      };
      for (const t = Date.now(); !at() && Date.now() - t < 30_000; ) {
        await probe();
        await sleep(50);
      }
      for (let i = 0; i < 3; i++) await probe();
      const slow = probes.filter((p) => p.status !== 200 || p.ms >= 1000);
      assert.deepEqual(slow, [], `/health probes past 1 s or not 200: ${JSON.stringify(slow)} of ${probes.length}`);
      assert.ok(at(), "the call did not reach the API within 30 s");
      assert.ok(probes.filter((p) => p.held).length >= 3, "no probe while the call was held at the API");
      api.release();
      const r = await call;
      assert.equal(r.status, 200, r.text?.slice(0, 200));
      const sc = resultOf(r)?.structuredContent;
      assert.ok(sc, r.text?.slice(0, 300));
      await assertAlive(srv, "after the call");
    } finally {
      api.release();
      await srv.stop();
      await api.close();
    }
  });
});

// #3381's round-10 review, started as its image starts it:
//   R10-B1. One check_sbom of 2,000 purls whose rows hold ten matches of about 1.05 KB each (production's are about 1.3
//           KB) held 52.9 MB of the budget by its own accounting, its answers charged past the most one request may
//           reserve (31,457,280 bytes), and was cut only by the instance's overdraft; with the answers charged as they
//           cost (parseBudget.ts answerCost), the process ended at its fifth batch, within that budget. Now the call
//           sends no further batch once its own request holds more than that bound, and the process lives.
//   R10-M1. A batch's answer was read and parsed whole, whatever its size: one of 26 MB ended the process. Now it is read
//           only to the room the call has, and past that it is not read: that batch's purls and the rest are not sent
//           (server_busy), or, on the first batch, the call is answered "server busy". The process lives.
// The API answers batch n (0-based, in the order they come) with answer(n, components).
async function answerApi(answer) {
  let n = 0;
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.socket.on("error", () => {});
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      res.writeHead(200, { "content-type": "application/json" });
      if (req.url !== BATCH_PATH) return res.end(JSON.stringify(SUMMARY));
      res.end(answer(n++, JSON.parse(Buffer.concat(chunks).toString("utf8")).components));
    });
  });
  server.keepAliveTimeout = 120_000;
  server.headersTimeout = 125_000;
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return {
    base: `http://127.0.0.1:${server.address().port}`,
    batches: () => n,
    close: () => {
      server.closeAllConnections();
      return new Promise((r) => server.close(r));
    },
  };
}
// Each row affected, with `k` real matches of about 1.05 KB each.
const heavyRows = (components, k) =>
  JSON.stringify(
    batchAnswer(
      components.map((c, i) => {
        const ids = Array.from({ length: k }, (_, j) => `CVE-2024-${10000 + j}`);
        return { ...ROWS.affected(i, c.purl, "p", "1.0.0", ids), matches: ids.map((id) => ({ ...REAL_MATCH, cve_id: id, description: "d".repeat(170) })) };
      }),
    ),
  );
const lightRows = (components) => JSON.stringify(batchAnswer(components.map((c, i) => ROWS.notAffected(i, c.purl, "p", "1.0.0"))));
describe("#3381's round-10 review: a request's answers held to what one request may reserve, and a batch's answer read to the room left", { skip: IMAGE_SKIP, concurrency: false, timeout: 300_000 }, () => {
  it("R10-B1. one check_sbom of 2,000 purls whose rows hold ten matches each: it stops once its request is past 31,457,280 bytes, server_busy, and the process lives", async () => {
    const api = await answerApi((_n, cs) => heavyRows(cs, 10));
    const srv = await startServer(api.base);
    try {
      const r = await post(srv.port, purlCall(0, 2000));
      assert.equal(r.status, 200, String(r.text).slice(0, 300));
      const sc = resultOf(r)?.structuredContent;
      assert.equal(sc?.state, "measured", String(r.text).slice(0, 300));
      const c = sc.coverage;
      assert.equal(c.not_sent_reason, "server_busy", JSON.stringify(c));
      assert.ok(c.sent >= 200 && c.sent < 2000, JSON.stringify(c));
      assert.match(sc.notes.join(" "), new RegExp(`after ${c.batches_sent} of 10 batches the API's answers took this call's request past the ${MOST} bytes one request may reserve, so no further batch was sent`));
      await assertAlive(srv, "after the call");
    } finally {
      await srv.stop();
      await api.close();
    }
  });
  it("R10-M1. a batch's answer of about 40 MB, past the room left: as the second batch, its purls are not sent (server_busy); as the first, the call is answered server busy; the process lives, tools/list answered", async () => {
    // 200 rows of 190 matches: about 40 MB. Through round 10 it was read whole, and the process ended; so did one of 50
    // matches a row (10.7 MB), below the 17 MB three bytes a byte left room for, which is cut too.
    const api = await answerApi((n, cs) => (n === 0 ? lightRows(cs) : n === 1 ? heavyRows(cs, 190) : heavyRows(cs, 50)));
    const srv = await startServer(api.base);
    try {
      const two = await post(srv.port, purlCall(1, 400));
      assert.equal(two.status, 200, String(two.text).slice(0, 300));
      const sc = resultOf(two)?.structuredContent;
      assert.equal(sc?.state, "measured", String(two.text).slice(0, 300));
      assert.deepEqual([sc.coverage.batches_sent, sc.coverage.sent, sc.coverage.not_sent, sc.coverage.not_sent_reason], [1, 200, 200, "server_busy"]);
      assert.match(sc.notes.join(" "), /the API's answer to batch 2 of 2 came to more than the \d+ bytes this instance's memory had room for, so it was not read, and no further batch was sent/);
      await assertAlive(srv, "after the second batch's answer");
      const one = await post(srv.port, purlCall(2, 200));
      const failed = resultOf(one)?.structuredContent;
      assert.equal(failed?.state, "failed", String(one.text).slice(0, 300));
      assert.deepEqual([failed.coverage, failed.error.kind, failed.error.path, failed.error.status], [null, "internal", BATCH_PATH, 200]);
      assert.match(failed.error.message, /^server busy: the API's answer to batch 1 of 1 came to more than the \d+ bytes this instance's memory had room for, so it was not read; retry in a few seconds, or pass fewer purls per call$/);
      await assertAlive(srv, "after the first batch's answer");
      const list = await post(srv.port, JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }));
      assert.equal(resultOf(list)?.tools?.length, 16, String(list.text).slice(0, 300));
    } finally {
      await srv.stop();
      await api.close();
    }
  });
});
