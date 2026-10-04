// #2717: kev_recent, the CISA KEV additions tool, against a stub of GET /api/v1/public/kev/recent.
//
// Runs once per protocol era (2026-07-28 server/discover, and a 2025-06-18 initialize), and every
// result it receives is validated against the tool's advertised outputSchema with ajv, as the SDK
// ships it (what an MCP client runs over structuredContent). The properties under test:
//   - every input travels as an X-EG-* header, and the request URL is the bare path (#1983);
//   - a bad input is refused here, with nothing requested, as invalid_input; a 400 from the API is
//     invalid_input too;
//   - a failure (404, an HTML 200, a refused connection) is an error result, never an empty list;
//   - a genuine empty answer is a measured success that says so;
//   - measured_at and freshness are our last successful fetch of CISA's feed, and null, with a
//     note, when the API does not give it — never filled in;
//   - the text blocks together are structuredContent (#2440, #2467).
// Every API request goes to a stub on 127.0.0.1; nothing leaves the machine.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import { AjvJsonSchemaValidator } from "@modelcontextprotocol/server/validators/ajv";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { serverCommand } from "./server-under-test.mjs";

const PATH = "/api/v1/public/kev/recent";
const FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const FETCHED = "2026-10-03T11:55:01Z";
const row = (cve_id, kev_added_date, extra = {}) => ({
  cve_id,
  kev_added_date,
  kev_due_date: "2026-10-23",
  kev_vendor: "Ivanti",
  kev_product: "Connect Secure",
  kev_vuln_name: "Ivanti Connect Secure Authentication Bypass",
  kev_ransomware: false,
  severity: "CRITICAL",
  cvss_v3_score: 9.8,
  epss_score: 0.42,
  epss_percentile: 0.97,
  eg_kev_tier: 1,
  our_first_seen_kev: "2026-10-02T17:04:12Z",
  ...extra,
});
const catalog = (over = {}) => ({ source: "CISA KEV catalog", feed_url: FEED, last_successful_fetch_at: FETCHED, catalog_version: "2026.10.02", date_released: "2026-10-02T17:00:41.1622Z", catalog_count: 1452, ...over });
// The API's answer, every field core-backend kevrecent's response struct sends.
const answer = (over = {}) => ({
  kev: [row("CVE-2026-0002", "2026-10-02"), row("CVE-2026-0010", "2026-10-02", { kev_vendor: "Microsoft", kev_ransomware: true, kev_due_date: null, severity: null, cvss_v3_score: null, epss_score: null, epss_percentile: null, eg_kev_tier: null, our_first_seen_kev: null })],
  count: 2,
  total: 40,
  kev_listed_total: 1452,
  limit: 2,
  next_cursor: "MjAyNi0xMC0wMnxDVkUtMjAyNi0wMDEw",
  order: "kev_added_date DESC, cve_id ASC",
  filters: { since: null, until: null, ransomware: null, vendor: null },
  catalog: catalog(),
  method: "EchelonGraph polls CISA's known_exploited_vulnerabilities.json every 5 minutes with a conditional GET.",
  notes: ["CISA's requiredAction and shortDescription are not stored, so they are not served."],
  generated_at: "2026-10-03T12:00:00Z",
  ...over,
});

const REMOVED_CLAIMS = /passive|no other|unique|real-?time|\blive\b|right now/i;
const HOST_UNIT = /\bhosts\b|\bhost\(s\)/i;

// The stub: answers PATH with state.body (a { status, body } or { raw } for other shapes), and
// records each request's URL and X-EG-* headers.
async function startStub() {
  const state = { body: answer(), seen: [] };
  const server = http.createServer((req, res) => {
    const eg = Object.fromEntries(Object.entries(req.headers).filter(([k]) => k.startsWith("x-eg-")));
    state.seen.push({ url: req.url, eg, ua: req.headers["user-agent"] });
    if (new URL(req.url, "http://stub").pathname !== PATH) {
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("404 page not found\n");
      return;
    }
    const b = state.body;
    if (b && typeof b.raw === "string") {
      res.writeHead(b.status ?? 200, { "content-type": b.type ?? "text/html" });
      res.end(b.raw);
      return;
    }
    const status = b?.status ?? 200;
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(b?.status ? b.body : b));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { state, base: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((r) => server.close(r)) };
}

async function refusedPort() {
  const probe = net.createServer();
  await new Promise((resolve) => probe.listen(0, "127.0.0.1", resolve));
  const { port } = probe.address();
  await new Promise((resolve) => probe.close(resolve));
  return port;
}

const validator = new AjvJsonSchemaValidator();
const textBlocks = (res) => (res.content ?? []).filter((c) => c.type === "text").map((c) => c.text);
const sentencesOf = (t) => t.replace(/\s+/g, " ").trim().split(/(?<=[.!?])\s+/).filter(Boolean);

// #2440/#2467: the text blocks together are structuredContent: data first (on a success), then the
// note, then the envelope less both.
function assertEnvelopeInText(where, res) {
  const sc = res.structuredContent;
  const blocks = textBlocks(res);
  assert.equal(blocks.length, res.isError ? 2 : 3, `${where}: ${blocks.length} text blocks`);
  const text = JSON.parse(blocks.at(-1));
  const said = blocks.at(-2);
  const before = sentencesOf(said);
  const own = text.notes ?? [];
  assert.deepEqual(own.filter((s) => before.includes(s)), [], `${where}: the envelope block repeats the note`);
  assert.deepEqual(sc.notes, [...own, ...before], `${where}: notes`);
  const { data, ...envelope } = sc;
  assert.deepEqual({ ...text, method: sc.method, notes: sc.notes }, envelope, where);
  if (typeof sc.method === "string") assert.ok("method" in text || said.includes(sc.method), `${where}: no block carries method`);
  if (!res.isError) assert.deepEqual(JSON.parse(blocks[0]), data, `${where}: the first block is not data`);
}

for (const era of [MODERN, "2025-06-18"]) {
  describe(`#2717 kev_recent [${era}]`, () => {
    let stub, client, schema, description;
    const received = [];
    const call = async (args = {}) => {
      const res = await client.callTool({ name: "kev_recent", arguments: args });
      received.push([args, res]);
      return res;
    };
    before(async () => {
      stub = await startStub();
      client = await connect({ era, ...serverCommand(), env: { ...process.env, ECHELONGRAPH_API_BASE: stub.base, ECHELONGRAPH_API_TIMEOUT_MS: "2000" }, stderr: "ignore" });
      const { tools } = await client.listTools();
      const t = tools.find((x) => x.name === "kev_recent");
      assert.ok(t, "kev_recent is not listed");
      schema = t.outputSchema;
      description = t.description;
      assert.equal(t.title, "Recent CISA KEV additions");
      assert.deepEqual(t.annotations, { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true });
    });
    after(async () => {
      await client?.close();
      await stub?.close();
    });

    it("sends every input as an X-EG-* header and none in the URL", async () => {
      stub.state.body = answer();
      stub.state.seen.length = 0;
      const marker = "Zzmarkervendor2717";
      const res = await call({ since: "2026-09-01", until: "2026-10-03", ransomware: true, vendor: marker, limit: 2, cursor: "MjAyNi0xMC0wMnxDVkUtMjAyNi0wMDEw" });
      assert.notEqual(res.isError, true, JSON.stringify(res));
      assert.equal(stub.state.seen.length, 1);
      const [req] = stub.state.seen;
      assert.equal(req.url, PATH, "the request URL must be the bare path");
      assert.deepEqual(req.eg, {
        "x-eg-since": "2026-09-01",
        "x-eg-until": "2026-10-03",
        "x-eg-ransomware": "true",
        "x-eg-vendor": marker,
        "x-eg-limit": "2",
        "x-eg-cursor": "MjAyNi0xMC0wMnxDVkUtMjAyNi0wMDEw",
      });
      assert.match(req.ua, /^echelongraph-mcp\//);
      // No input means no header at all, and ransomware false is sent as false, not dropped.
      stub.state.seen.length = 0;
      await call({});
      await call({ ransomware: false });
      assert.deepEqual(stub.state.seen.map((s) => s.eg), [{}, { "x-eg-ransomware": "false" }]);
    });

    // #2736: get_cve gives kev_added_date as RFC 3339; since and until take that too, as the date written
    // in it. kev_added_date is a calendar date, so an offset never moves it to the UTC day either side.
    it("an RFC 3339 since or until is sent as the date written in it", async () => {
      stub.state.body = answer();
      for (const [since, until, want] of [
        ["2024-04-12T00:00:00Z", "2024-04-12T00:00:00Z", ["2024-04-12", "2024-04-12"]],
        ["2026-09-01T23:30:00-05:00", "2026-10-03T00:00:00.123z", ["2026-09-01", "2026-10-03"]],
        ["2026-09-01T01:00:00+02:00", "2026-10-03", ["2026-09-01", "2026-10-03"]],
        // #2755: measured on 2.6.1: UTC conversion sent 2024-04-11 and 2024-04-13
        ["2024-04-12T00:00:00+02:00", "2024-04-12T23:30:00-05:00", ["2024-04-12", "2024-04-12"]],
      ]) {
        stub.state.seen.length = 0;
        const res = await call({ since, until });
        assert.notEqual(res.isError, true, `${since} ${until}: ${res.content[0].text}`);
        assert.equal(res.structuredContent.state, "measured");
        assert.deepEqual([stub.state.seen[0].eg["x-eg-since"], stub.state.seen[0].eg["x-eg-until"]], want, `${since} ${until}`);
        assert.equal(stub.state.seen[0].url, PATH);
      }
    });

    it("a page with more rows: measured, dated by our last fetch, with coverage and freshness from the answer", async () => {
      stub.state.body = answer();
      const res = await call({ limit: 2 });
      assert.notEqual(res.isError, true);
      const sc = res.structuredContent;
      assert.equal(sc.state, "measured");
      assert.equal(sc.measured_at, FETCHED);
      assert.deepEqual(sc.freshness, { last_successful_fetch_at: FETCHED, catalog_version: "2026.10.02", date_released: "2026-10-02T17:00:41.1622Z" });
      assert.deepEqual(sc.coverage, { catalog: "CISA KEV catalog", total: 40, returned: 2, kev_listed_total: 1452, catalog_count: 1452, limit: 2, has_more: true });
      assert.deepEqual(sc.data, answer());
      assert.deepEqual(JSON.parse(res.content[0].text), answer());
      const note = res.content[1].text;
      assert.match(note, /^kev_recent OK: EchelonGraph answered HTTP 200 from /);
      assert.match(note, /40 CVEs in EchelonGraph's copy of the CISA KEV catalog match; 2 are in this page/);
      assert.match(note, /The first is CVE-2026-0002, added by CISA on 2026-10-02\./);
      assert.match(note, /call again with cursor set to next_cursor/);
      assert.match(note, new RegExp(`last fetched CISA's feed successfully at ${FETCHED}, catalog version 2026\\.10\\.02\\.`));
      assert.doesNotMatch(note, /not in its CVE table/, "no gap: catalog_count equals kev_listed_total");
    });

    it("the last page says so, and a gap between CISA's count and ours is named", async () => {
      stub.state.body = answer({ next_cursor: null, total: 2, kev_listed_total: 1449 });
      const res = await call({});
      assert.equal(res.structuredContent.coverage.has_more, false);
      assert.match(res.content[1].text, /This is the last page\./);
      assert.match(res.content[1].text, /counts 1452 entries and EchelonGraph holds 1449 CVEs as KEV-listed, so 3 are not in its CVE table yet/);
    });

    it("no match is a measured empty result, in words, not a failure", async () => {
      stub.state.body = answer({ kev: [], count: 0, total: 0, next_cursor: null });
      const res = await call({ vendor: "Nobody" });
      assert.notEqual(res.isError, true);
      assert.equal(res.structuredContent.state, "measured");
      assert.match(res.content[1].text, /matched these filters: a measured empty result, not a lookup failure\./);
      assert.equal(res.structuredContent.coverage.returned, 0);
    });

    it("no fetch record: measured_at and freshness null, and the note says freshness is unknown", async () => {
      stub.state.body = answer({ catalog: catalog({ last_successful_fetch_at: null, catalog_version: null, date_released: null, catalog_count: null }) });
      const res = await call({});
      const sc = res.structuredContent;
      assert.equal(sc.measured_at, null);
      assert.deepEqual(sc.freshness, { last_successful_fetch_at: null, catalog_version: null, date_released: null });
      assert.match(res.content[1].text, /how fresh this list is is unknown, not stale\./);
      assert.ok(sc.notes.some((n) => /^measured_at is null/.test(n)), JSON.stringify(sc.notes));
    });

    it("the Go zero time is not a fetch time", async () => {
      stub.state.body = answer({ catalog: catalog({ last_successful_fetch_at: "0001-01-01T00:00:00Z" }) });
      const res = await call({});
      assert.equal(res.structuredContent.measured_at, null);
      assert.equal(res.structuredContent.freshness.last_successful_fetch_at, null);
    });

    it("refuses bad input here, as invalid_input, and requests nothing", async () => {
      stub.state.seen.length = 0;
      for (const args of [
        { since: "2026-9-1" },
        { until: "2026-02-30" },
        { since: "2024-04-12T00:00:00" },
        { since: "2024-04-12 00:00:00Z" },
        { since: "2024-04-12T24:00:00Z" },
        { until: "2026-02-30T00:00:00Z" },
        { until: "2024-04-12Tnoon" },
        { since: "April 12, 2024" },
        { since: "2024-04-13T00:00:00Z", until: "2024-04-12" },
        { since: "2026-10-02", until: "2026-10-01" },
        { vendor: "x".repeat(129) },
        { vendor: "Micro\nsoft" },
        { vendor: "Siemensé" },
        { cursor: "not a cursor!" },
      ]) {
        const res = await call(args);
        assert.equal(res.isError, true, JSON.stringify(args));
        assert.equal(res.structuredContent.state, "invalid_input", JSON.stringify(args));
        assert.match(res.content[0].text, /Nothing was looked up, so this is not a finding\./);
      }
      assert.equal(stub.state.seen.length, 0, "a refused input reached the API");
    });

    it("the API's 400 is invalid_input; a 404, an HTML 200 and a refused connection are failures, never an empty list", async () => {
      stub.state.body = { status: 400, body: { error: "cursor: cursor is not one this API returned", field: "cursor" } };
      let res = await call({ cursor: "abc" });
      assert.equal(res.isError, true);
      assert.equal(res.structuredContent.state, "invalid_input");
      assert.match(res.content[0].text, /cursor is not one this API returned/);

      stub.state.body = { status: 404, body: { error: "Cannot GET" } };
      res = await call({});
      assert.equal(res.structuredContent.state, "failed");

      stub.state.body = { raw: "<!doctype html><html><body>shell</body></html>" };
      res = await call({});
      assert.equal(res.structuredContent.state, "failed");
      assert.equal(res.structuredContent.error.kind, "not_json");
      assert.doesNotMatch(textBlocks(res).join("\n"), /OK:|found nothing|empty result/);

      const port = await refusedPort();
      const down = await connect({ era, ...serverCommand(), env: { ...process.env, ECHELONGRAPH_API_BASE: `http://127.0.0.1:${port}`, ECHELONGRAPH_API_TIMEOUT_MS: "2000" }, stderr: "ignore" });
      try {
        res = await down.callTool({ name: "kev_recent", arguments: {} });
        received.push([{}, res]);
        assert.equal(res.isError, true);
        assert.equal(res.structuredContent.state, "failed");
        assert.equal(res.structuredContent.error.kind, "network");
        assert.match(res.content[0].text, /not a finding: do not report it as zero, none found, absent, or unexposed/);
      } finally {
        await down.close();
      }
    });

    it("an answer whose fields have the wrong types is a failure, not relayed", async () => {
      stub.state.body = answer({ total: "forty" });
      const res = await call({});
      assert.equal(res.isError, true);
      assert.equal(res.structuredContent.error.kind, "unexpected_shape");
    });

    it("the description makes none of the removed claims, calls nothing hosts, and names only fields its outputSchema holds", () => {
      assert.doesNotMatch(description, REMOVED_CLAIMS);
      assert.doesNotMatch(description, HOST_UNIT);
      const names = new Set();
      const walk = (s) => {
        if (!s || typeof s !== "object") return;
        if (Array.isArray(s)) return s.forEach(walk);
        for (const [k, v] of Object.entries(s)) {
          if (k === "properties") for (const p of Object.keys(v)) names.add(p);
          if (k === "enum" || k === "const") [].concat(v).forEach((x) => typeof x === "string" && names.add(x));
          walk(v);
        }
      };
      walk(schema);
      const tokens = [...new Set(description.match(/\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b/g) ?? [])];
      assert.ok(tokens.length >= 10, tokens.join(","));
      assert.deepEqual(tokens.filter((x) => !names.has(x)), []);
    });

    // Runs last: everything above, through ajv and the text-envelope check.
    it("every result above validates against the advertised outputSchema, and its text rebuilds to its structuredContent", () => {
      assert.ok(received.length >= 20, `only ${received.length} results`);
      const states = new Set();
      for (const [args, res] of received) {
        const where = `kev_recent(${JSON.stringify(args)})`;
        const v = validator.getValidator(schema)(res.structuredContent);
        assert.ok(v.valid, `${where}: ${v.errorMessage}\n${JSON.stringify(res.structuredContent).slice(0, 600)}`);
        assertEnvelopeInText(where, res);
        states.add(res.structuredContent.state);
      }
      assert.deepEqual([...states].sort(), ["failed", "invalid_input", "measured"]);
      // The validator is not vacuous: a success without its method fails it.
      const ok = received.find(([, r]) => !r.isError)[1].structuredContent;
      assert.equal(validator.getValidator(schema)({ ...ok, method: null }).valid, false);
      assert.equal(validator.getValidator(schema)({ ...ok, coverage: { ...ok.coverage, catalog: "something else" } }).valid, false);
    });
  });
}
