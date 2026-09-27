// Behavioural tests for the five MCP tools against a stub EchelonGraph API (#1874).
//
// The property under test: an upstream failure — unreachable host, connection refused,
// non-2xx, timeout, or a 200 whose body is not JSON — must come back as an MCP error result
// (isError: true), never as a successful result whose fields are null. A model that is
// handed a well-formed success with empty fields tells its user "no exposure found", so an
// outage must not read as an all-clear.
//
// The control: a genuine empty answer (HTTP 200, zero rows) must stay a SUCCESS whose note
// says so in words — the fix must not over-correct into "every empty answer is an error".
// "We could not look" and "we looked and found nothing" have to stay distinguishable.
//
// Runs against dist/index.js, so build first — `npm test` does. No framework beyond node:test.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const PKG_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DIST = path.join(PKG_DIR, "dist", "index.js");
const readPkgFile = (name) => fs.readFileSync(path.join(PKG_DIR, name), "utf8");
const PKG = JSON.parse(readPkgFile("package.json"));
const CVE = "CVE-2023-44487";
// cve_exposure fixtures for the contract of GET /api/v1/public/kev-exposure/cve/:id.
const CVE_UNTRACKED = "CVE-2099-10001"; // tracked:false, 0 hosts
const CVE_OLD_API = "CVE-2099-10002"; // an API older than `tracked`: 0 hosts, Go zero last_seen
const CVE_REJECTED = "CVE-2099-10003"; // the API answers 400 invalid CVE id
const CVE_UNTRACKED_STALE = "CVE-2099-10004"; // tracked:false, but hosts left from earlier scans
// A method sentence with no closing full stop (the note must supply one).
const METHOD = "Shodan banner match on tracked products; up to 100 ip:port services per product query; searched every 12 h when Shodan query credits allow";
// The sentence the backend actually sends: kevexposure.exposureMethod (poller.go), verbatim.
// The note quotes it word for word, so the #2306 guard below must see THIS string, not an
// example. core-backend's TestExposureMethod_IsTheStringTheMCPServerTestsGuard fails until
// this literal is updated whenever that sentence changes.
const BACKEND_METHOD = "Shodan banner match over the radar's 22 tracked product queries, reading at most 100 ip:port services per query (the first results page); a service counts only when its banner version falls in the CVE's vulnerable CPE range and the CVE is CISA-KEV-listed or has EPSS >= 0.50. Searched every 12 h when Shodan query credits allow. last_seen is when a service was last seen listening on its port, not when its vulnerable version was last confirmed: a re-check that finds the port still listed by Shodan InternetDB refreshes it without re-reading the banner, so a patched service can stay counted while its port stays open. A service not seen on its port for 21 days is dropped.";
// A follower instance's poller block from an API older than fleet freshness: what the
// shadow-AI stats answer carried when the request landed on an instance not running the
// poller (#2307).
const FOLLOWER_POLLER = { running: false, interval_seconds: 3600, last_run_at: "0001-01-01T00:00:00Z", last_new_inserts: 0, skipped_as_follower: 14, source_health: "healthy", consecutive_fails: 0, shodan_enabled: true, shodan_last_new: 0 };
// The same block from the fleet-freshness API (core-backend shadowctlog Poller.Status):
// running and last_run_at describe the fleet, last_run_at is when the leader last COMPLETED a
// crt.sh cycle, running is true only within 30 minutes of that, and both are omitted when
// unknown. Instance fields are sent only by a process that has run a cycle itself.
const FLEET_RUNNING = { running: true, interval_seconds: 60, last_run_at: "2026-09-26T10:00:00Z", shodan_enabled: true };
const FLEET_STOPPED = { running: false, interval_seconds: 60, last_run_at: "2026-09-26T08:15:00Z", shodan_enabled: true };
const FLEET_UNKNOWN = { interval_seconds: 60, shodan_enabled: true };
// The shadow-AI stats answer shaped as production sent it on 2026-09-27 (#2307, reopened):
// total 36,222 against 2,000 confirmed exposed (the sum of visible_by_category); top_products
// ranking LiteLLM at 6,813 observations while 1,395 LLM-PROXY services are confirmed exposed;
// last_24h_count 1,569 against 201 confirmed; auth_confirmed 8,065 and auth_undetermined
// 9,307. Every field core-backend shadowctlog store.go Stats sends is here, the rankings and
// the 30-day series included, so the fixture is no kinder than production.
const TREND_30D = Array.from({ length: 30 }, (_, i) => ({
  date: new Date(Date.UTC(2026, 7, 28 + i)).toISOString().slice(0, 10),
  count: 1100 + 7 * i,
}));
const PROD_SHADOW_STATS = {
  total: 36222,
  by_category: { "LLM-PROXY": 14000, "VECTOR-DB": 8000, NOTEBOOK: 6000, "AI-WORKFLOW": 4222, "INFERENCE-SRV": 2500, "MCP-SERVER": 1500 },
  visible_by_category: { "LLM-PROXY": 1395, "VECTOR-DB": 300, NOTEBOOK: 150, "AI-WORKFLOW": 100, "INFERENCE-SRV": 40, "MCP-SERVER": 15 },
  last_observation: "2026-09-26T11:02:00Z",
  last_24h_count: 1569,
  last_24h_visible_count: 201,
  auth_confirmed: 8065,
  auth_undetermined: 9307,
  top_products: [
    { product: "LiteLLM", count: 6813 },
    { product: "Ollama", count: 5210 },
    { product: "Qdrant", count: 3120 },
    { product: "Jupyter Notebook", count: 2704 },
    { product: "n8n", count: 1988 },
  ],
  top_countries: [
    { country: "United States", count: 9800 },
    { country: "China", count: 7400 },
    { country: "Germany", count: 3100 },
  ],
  top_issuers: [
    { issuer: "Let's Encrypt", count: 15800 },
    { issuer: "Tencent Cloud Computing (Beijing) Co., Ltd (China)", count: 3500 },
    { issuer: "Google Trust Services", count: 2900 },
  ],
  trend_30d: TREND_30D,
};
// What exposure_radar must relay for it: the same numbers, grouped by what each one counts.
const PROD_SHADOW_RELAYED = {
  confirmed_exposed: { total: 2000, by_category: PROD_SHADOW_STATS.visible_by_category, last_24h: 201 },
  observed: {
    total: 36222,
    by_category: PROD_SHADOW_STATS.by_category,
    last_24h: 1569,
    trend_30d: TREND_30D,
    top_products: PROD_SHADOW_STATS.top_products,
    top_countries: PROD_SHADOW_STATS.top_countries,
    top_issuers: PROD_SHADOW_STATS.top_issuers,
    last_observation: "2026-09-26T11:02:00Z",
  },
  authentication: { observed: 8065, not_determined: 9307 },
};
// Shodan's terms ask that materials based on Shodan information "clearly indicate Shodan's
// ownership and copyright" (#2306, reopened). The package's exact sentence, pinned here.
const SHODAN_OWNERSHIP = "Shodan data is owned by Shodan, which holds its copyright (© Shodan).";
// Claims the package's own copy must not make (#2306): the exposure data is Shodan-derived
// and the other radars send active probes (nothing is passive); every figure refreshes on a
// schedule (nothing is live or real-time); others also map CVEs to exposure (not unique).
const REMOVED_CLAIMS = /passive|no other|unique|real-?time|\blive\b|right now/i;
// Every radar count is of distinct ip:port services (the backend keys an observation on
// ip:port, one Shodan banner per port), so a machine answering on two ports counts twice.
// The package's own words must not call that number hosts. Field names such as
// exposed_hosts are not matched: `_` is a word character.
const HOST_UNIT = /\bhosts\b|\bhost\(s\)/i;

// One representative call per tool. Every describe block below exercises all five.
const CALLS = {
  cve_summary: {},
  search_cves: { search: "tomcat", limit: 2 },
  get_cve: { cve_id: CVE },
  cve_exposure: { cve_id: CVE },
  exposure_radar: {},
};
const TOOLS = Object.keys(CALLS);

// Stub bodies shaped like the live API answered on 2026-09-15, trimmed to the fields the
// tests assert on. `ok` is a populated answer; `empty` is the genuine-nothing answer.
const BODIES = {
  "/api/v1/public/cves/summary": {
    ok: { poller: { last_poll_at: "2026-09-15T04:45:07Z" }, summary: { critical: 42038, high: 148562, medium: 166226, low: 14192, none: 2487, total: 373505, last_updated: "2026-09-15T04:47:02.406Z" } },
    empty: { poller: { last_poll_at: "2026-09-15T04:45:07Z" }, summary: { critical: 0, high: 0, medium: 0, low: 0, none: 0, total: 0, last_updated: "2026-09-15T04:47:02.406Z" } },
  },
  "/api/v1/public/cves": {
    ok: { cves: [{ cve_id: CVE, severity: "HIGH", cvss_v3_score: 7.5, echelongraph_score: 9, kev_listed: true }], limit: 2, offset: 0, total: 1 },
    empty: { cves: [], limit: 2, offset: 0, total: 0 },
  },
  [`/api/v1/public/cves/${CVE}`]: {
    ok: { cve_id: CVE, severity: "HIGH", cvss_v3_score: 7.5, echelongraph_score: 9, score_confidence: "HIGH", epss_score: 0.99999, kev_listed: true, kev_ransomware: false },
    // The live API answers an unknown CVE with HTTP 404 and its own JSON message.
    empty: { status: 404, body: { error: `CVE not found: ${CVE}` } },
  },
  // The contract shape: the old fields plus tracked, kev_catalog_listed,
  // kev_seen_in_observations, method, and last_seen null when there is no observation.
  [`/api/v1/public/kev-exposure/cve/${CVE}`]: {
    ok: { cve_id: CVE, exposed_hosts: 6213, countries: 107, kev_listed: true, kev_seen_in_observations: true, kev_catalog_listed: true, tracked: true, method: BACKEND_METHOD, ransomware: false, top_countries: [{ country: "United States", hosts: 1888 }], top_products: [{ product: "http_server", hosts: 2668 }], last_seen: "2026-09-15T04:02:09Z", generated_at: "2026-09-15T05:00:00Z" },
    empty: { cve_id: CVE, exposed_hosts: 0, countries: 0, kev_listed: false, kev_seen_in_observations: false, kev_catalog_listed: true, tracked: true, method: BACKEND_METHOD, ransomware: false, top_countries: [], top_products: [], last_seen: null, generated_at: "2026-09-15T05:00:00Z" },
  },
  [`/api/v1/public/kev-exposure/cve/${CVE_UNTRACKED}`]: {
    ok: { cve_id: CVE_UNTRACKED, exposed_hosts: 0, countries: 0, kev_listed: false, kev_seen_in_observations: false, kev_catalog_listed: false, tracked: false, method: BACKEND_METHOD, ransomware: false, top_countries: [], top_products: [], last_seen: null, generated_at: "2026-09-15T05:00:00Z" },
  },
  [`/api/v1/public/kev-exposure/cve/${CVE_UNTRACKED_STALE}`]: {
    ok: { cve_id: CVE_UNTRACKED_STALE, exposed_hosts: 3, countries: 2, kev_listed: true, kev_seen_in_observations: true, kev_catalog_listed: true, tracked: false, method: `${METHOD}.`, ransomware: false, top_countries: [], top_products: [], last_seen: "2026-09-01T00:00:00Z", generated_at: "2026-09-15T05:00:00Z" },
  },
  // What the API answered before the contract: no tracked, no method, the Go zero time.
  [`/api/v1/public/kev-exposure/cve/${CVE_OLD_API}`]: {
    ok: { cve_id: CVE_OLD_API, exposed_hosts: 0, countries: 0, kev_listed: false, ransomware: false, top_countries: [], top_products: [], last_seen: "0001-01-01T00:00:00Z", generated_at: "2026-09-15T05:00:00Z" },
  },
  [`/api/v1/public/kev-exposure/cve/${CVE_REJECTED}`]: {
    ok: { status: 400, body: { error: "invalid CVE id", cve_id: CVE_REJECTED } },
  },
  "/api/v1/public/kev-exposure/stats": {
    ok: { distinct_hosts: 25113, kev_cves_exposed: 54, ransomware_hosts: 6655 },
    empty: { distinct_hosts: 0, kev_cves_exposed: 0, ransomware_hosts: 0 },
  },
  "/api/v1/public/exposed-databases/stats": {
    ok: { distinct_hosts: 7380, engines: 10 },
    empty: { distinct_hosts: 0, engines: 0 },
  },
  "/api/v1/public/leaked-credentials/stats": {
    ok: { distinct_repos: 303, distinct_secrets: 507, total: 531 },
    empty: { distinct_repos: 0, distinct_secrets: 0, total: 0 },
  },
  // stats.total counts every observation; the confirmed-exposed count is the sum of
  // visible_by_category (2,000 here, as on 2026-09-27 against a total of 36,222).
  "/api/v1/public/shadow-ai-radar/stats": {
    ok: { stats: PROD_SHADOW_STATS, poller: FOLLOWER_POLLER },
    empty: { stats: { total: 0, by_category: {}, visible_by_category: {}, last_24h_count: 0, last_24h_visible_count: 0, auth_confirmed: 0, auth_undetermined: 0 }, poller: FOLLOWER_POLLER },
  },
};

// A stub API whose behaviour is switched per describe block. Modes:
//   ok / empty  — HTTP 200 with the matching body above (get_cve's `empty` is the API's 404;
//                 a body with a `status` is answered with that status)
//   403         — HTTP 403 with an HTML body, the shape an edge block produces
//   html        — HTTP 200 with an HTML body (an SPA shell or a wrong path)
//   null        — HTTP 200 whose JSON body is the literal `null`
//   hang        — accept the request and never answer
async function startStub() {
  // overrides: pathname -> body, consulted before BODIES in the ok/empty modes.
  const state = { mode: "ok", seen: [], userAgents: [], overrides: {} };
  const pending = new Set();
  const server = http.createServer((req, res) => {
    state.seen.push(req.url);
    state.userAgents.push(req.headers["user-agent"]);
    const { pathname } = new URL(req.url, "http://stub");
    switch (state.mode) {
      case "403":
        res.writeHead(403, { "content-type": "text/html" });
        res.end("<html><head><title>Just a moment...</title></head><body>Forbidden</body></html>");
        return;
      case "html":
        res.writeHead(200, { "content-type": "text/html" });
        res.end("<!doctype html><html><body><div id=app></div></body></html>");
        return;
      case "null":
        res.writeHead(200, { "content-type": "application/json" });
        res.end("null");
        return;
      case "hang":
        pending.add(res);
        req.on("close", () => pending.delete(res));
        return;
      default: {
        const entry = state.overrides[pathname] ?? BODIES[pathname]?.[state.mode];
        if (entry === undefined) {
          // What the Go router does for a path it does not know.
          res.writeHead(404, { "content-type": "text/plain" });
          res.end("404 page not found\n");
          return;
        }
        const status = entry.status ?? 200;
        const body = entry.status ? entry.body : entry;
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify(body));
      }
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    state,
    base: `http://127.0.0.1:${server.address().port}`,
    close: () => {
      for (const res of pending) res.destroy();
      server.closeAllConnections();
      return new Promise((resolve) => server.close(resolve));
    },
  };
}

// A port nothing listens on, so a connection to it is refused rather than blocked.
async function refusedPort() {
  const probe = net.createServer();
  await new Promise((resolve) => probe.listen(0, "127.0.0.1", resolve));
  const { port } = probe.address();
  await new Promise((resolve) => probe.close(resolve));
  return port;
}

async function spawnServer(env) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [DIST],
    env: { ...process.env, ...env },
    stderr: "inherit",
  });
  const client = new Client({ name: "echelongraph-mcp-tools-test", version: "0.0.0" });
  await client.connect(transport);
  return client;
}

async function callAll(client) {
  const out = {};
  for (const name of TOOLS) out[name] = await client.callTool({ name, arguments: CALLS[name] });
  return out;
}

const textOf = (res) => (res.content ?? []).filter((c) => c.type === "text").map((c) => c.text).join("\n");
// The server's own words: every block of an error, every block after the API's JSON otherwise.
const noteOf = (res) => (res.content ?? []).filter((c) => c.type === "text").slice(res.isError ? 0 : 1).map((c) => c.text).join("\n");
const brief = (res) => JSON.stringify(res).replace(/\s+/g, " ").slice(0, 300);

// #2307: every numeric field exposure_radar may relay under shadow_ai, by normalised path
// ([] = any array element, * = any key of a category map), mapped to the name the note, the
// description and the README label it by. The group in the name is the label: observed (every
// Certificate Transparency or Shodan observation), confirmed_exposed (liveness active or
// rechecking), authentication (probe outcomes). A numeric field outside this set fails the
// enumeration test, so a field the backend adds later cannot reach a model unlabelled.
const SHADOW_AI_LABELLED = {
  "confirmed_exposed.total": "confirmed_exposed.total",
  "confirmed_exposed.by_category.*": "confirmed_exposed.by_category",
  "confirmed_exposed.last_24h": "confirmed_exposed.last_24h",
  "observed.total": "observed.total",
  "observed.by_category.*": "observed.by_category",
  "observed.last_24h": "observed.last_24h",
  "observed.trend_30d[].count": "observed.trend_30d",
  "observed.top_products[].count": "observed.top_products",
  "observed.top_countries[].count": "observed.top_countries",
  "observed.top_issuers[].count": "observed.top_issuers",
  "authentication.observed": "authentication.observed",
  "authentication.not_determined": "authentication.not_determined",
};
// The objects whose keys are data (category names), not field names.
const SHADOW_AI_MAPS = new Set(["observed.by_category", "confirmed_exposed.by_category"]);
const childPath = (p, k) => (SHADOW_AI_MAPS.has(p) ? `${p}.*` : p ? `${p}.${k}` : k);
// Every path to a number, and every field-name path, under a relayed value.
function numericPaths(v, p = "", out = new Set()) {
  if (typeof v === "number") out.add(p);
  else if (Array.isArray(v)) for (const x of v) numericPaths(x, `${p}[]`, out);
  else if (v !== null && typeof v === "object") for (const [k, x] of Object.entries(v)) numericPaths(x, childPath(p, k), out);
  return out;
}
function keyPaths(v, p = "", out = new Set()) {
  if (Array.isArray(v)) for (const x of v) keyPaths(x, `${p}[]`, out);
  else if (v !== null && typeof v === "object") {
    for (const [k, x] of Object.entries(v)) {
      const c = childPath(p, k);
      out.add(c);
      keyPaths(x, c, out);
    }
  }
  return out;
}
const numbersUnder = (v) => {
  const out = new Set();
  const walk = (x) => {
    if (typeof x === "number") out.add(x);
    else if (x !== null && typeof x === "object") for (const y of Object.values(x)) walk(y);
  };
  walk(v);
  return out;
};
// A reader's unit of text: a sentence. Field names (observed.total, crt.sh) carry no space
// after their dot, so they do not split one.
const sentencesOf = (t) => t.replace(/\s+/g, " ").split(/(?<=[.!?])\s+/);
// The README read the same way, except that each table row is its own unit.
const readmeUnits = (md) =>
  md.split(/\n\s*\n/).flatMap((block) => {
    const lines = block.split("\n").filter((l) => l.trim());
    return lines.length && lines.every((l) => l.trim().startsWith("|")) ? lines : sentencesOf(block);
  });
// "exposed" said of an observed thing is allowed only as a denial: "not" within the 30
// characters before it ("observed, not exposed", "not a count of exposed services").
const denied = (s, i) => /\bnot\b/.test(s.slice(Math.max(0, i - 30), i));
// Any sentence of `text` carrying a number that exists only under observed or authentication
// (not also a confirmed_exposed number) must not call it exposed. Returns how many such
// numbers it found in the text, so a caller can prove it was not vacuous.
function assertNoObservedNumberCalledExposed(where, text, shadowAI) {
  const confirmed = numbersUnder(shadowAI.confirmed_exposed);
  const observedOnly = [...numbersUnder([shadowAI.observed, shadowAI.authentication])].filter((n) => !confirmed.has(n));
  let checked = 0;
  for (const s of sentencesOf(text)) {
    const carried = observedOnly.filter((n) =>
      new RegExp(`(?<![\\d.,])(?:${n}|${n.toLocaleString("en-US")})(?![\\d]|,\\d)`).test(s),
    );
    if (!carried.length) continue;
    checked += carried.length;
    for (const m of s.matchAll(/exposed/gi)) {
      assert.ok(denied(s, m.index), `${where}: observed number(s) ${carried.join(", ")} called exposed in: "${s}"`);
    }
  }
  return checked;
}
// A sentence that names an observed or authentication field may use "exposed" only as a
// denial or in the name of the other group, confirmed_exposed.
const OBSERVED_FIELD = /\bshadow_ai\.(?:observed|authentication)\b|\bobserved\.[a-z_0-9]+|\bauthentication\.(?:observed|not_determined)\b/;
function assertObservedFieldsNotCalledExposed(where, units) {
  let checked = 0;
  for (const u of units) {
    if (!OBSERVED_FIELD.test(u)) continue;
    checked++;
    for (const m of u.matchAll(/exposed/gi)) {
      if (/confirmed_$/.test(u.slice(0, m.index))) continue;
      assert.ok(denied(u, m.index), `${where}: an observed field called exposed in: "${u}"`);
    }
  }
  return checked;
}

// The P1 property. Asserted on its own so a pre-fix run shows exactly which tools answer a
// failure with a success.
function assertErrorResult(name, res) {
  assert.equal(res.isError, true, `${name}: expected isError=true, got ${brief(res)}`);
}

// The wording property: an error must say which tool, what failed, and where it looked.
function assertNames(name, res, base, ...phrases) {
  const t = textOf(res);
  assert.match(t, new RegExp(`\\b${name}\\b`), `${name}: error text does not name the tool: ${t}`);
  assert.ok(t.includes(base), `${name}: error text does not name the base URL ${base}: ${t}`);
  for (const p of phrases) assert.match(t, p, `${name}: error text lacks ${p}: ${t}`);
}

describe("failure polarity: unreachable base (ECHELONGRAPH_API_BASE=http://127.0.0.1:1)", () => {
  const base = "http://127.0.0.1:1";
  let client, results;
  before(async () => {
    client = await spawnServer({ ECHELONGRAPH_API_BASE: base, ECHELONGRAPH_API_TIMEOUT_MS: "2000" });
    results = await callAll(client);
  });
  after(() => client.close());
  for (const name of TOOLS) {
    it(`${name} returns an error result, not a success with null fields`, () => assertErrorResult(name, results[name]));
    it(`${name} error text names the tool, the failure and the base URL`, () =>
      assertNames(name, results[name], base, /could not be reached/));
  }
});

describe("failure polarity: connection refused", () => {
  let client, results, base;
  before(async () => {
    base = `http://127.0.0.1:${await refusedPort()}`;
    client = await spawnServer({ ECHELONGRAPH_API_BASE: base, ECHELONGRAPH_API_TIMEOUT_MS: "2000" });
    results = await callAll(client);
  });
  after(() => client.close());
  for (const name of TOOLS) {
    it(`${name} returns an error result`, () => assertErrorResult(name, results[name]));
    it(`${name} error text names ECONNREFUSED and the base URL`, () =>
      assertNames(name, results[name], base, /could not be reached/, /ECONNREFUSED/));
  }
});

describe("against a stub API", () => {
  let stub, client;
  before(async () => {
    stub = await startStub();
    client = await spawnServer({ ECHELONGRAPH_API_BASE: stub.base, ECHELONGRAPH_API_TIMEOUT_MS: "500" });
  });
  after(async () => {
    await client.close();
    await stub.close();
  });

  describe("failure polarity: upstream answers HTTP 403", () => {
    let results;
    before(async () => { stub.state.mode = "403"; results = await callAll(client); });
    for (const name of TOOLS) {
      it(`${name} returns an error result`, () => assertErrorResult(name, results[name]));
      it(`${name} error text names HTTP 403 and the base URL`, () =>
        assertNames(name, results[name], stub.base, /HTTP 403/));
    }
  });

  describe("failure polarity: upstream hangs past the timeout", () => {
    let results;
    before(async () => { stub.state.mode = "hang"; results = await callAll(client); });
    for (const name of TOOLS) {
      it(`${name} returns an error result`, () => assertErrorResult(name, results[name]));
      it(`${name} error text names the timeout and the base URL`, () =>
        assertNames(name, results[name], stub.base, /did not answer/, /within 500 ms/));
    }
  });

  describe("failure polarity: upstream answers 200 with a non-JSON body", () => {
    let results;
    before(async () => { stub.state.mode = "html"; results = await callAll(client); });
    for (const name of TOOLS) {
      it(`${name} returns an error result`, () => assertErrorResult(name, results[name]));
      it(`${name} error text says the body was not JSON`, () =>
        assertNames(name, results[name], stub.base, /was not JSON/));
    }
  });

  describe("failure polarity: upstream answers 200 with JSON null", () => {
    let results;
    before(async () => { stub.state.mode = "null"; results = await callAll(client); });
    for (const name of TOOLS) {
      it(`${name} returns an error result`, () => assertErrorResult(name, results[name]));
      it(`${name} error text says the body was not a JSON object`, () =>
        assertNames(name, results[name], stub.base, /was not a JSON object/));
    }
  });

  describe("success polarity: upstream answers 200 with data", () => {
    let results;
    before(async () => { stub.state.mode = "ok"; stub.state.seen.length = 0; results = await callAll(client); });
    for (const name of TOOLS) {
      it(`${name} is not an error and its first block is the API's JSON`, () => {
        const res = results[name];
        assert.notEqual(res.isError, true, `${name}: unexpected error: ${brief(res)}`);
        assert.doesNotThrow(() => JSON.parse(res.content[0].text), `${name}: first block is not JSON`);
      });
      it(`${name} carries a note that says it succeeded, and where`, () => {
        const t = textOf(results[name]);
        assert.match(t, new RegExp(`\\b${name} OK\\b`), `${name}: no OK note: ${t}`);
        assert.ok(t.includes(stub.base), `${name}: note does not name the base URL: ${t}`);
        assert.doesNotMatch(t, /found nothing/, `${name}: a populated answer must not read as empty: ${t}`);
      });
    }
    it("cve_summary returns the feed totals", () => {
      assert.equal(JSON.parse(results.cve_summary.content[0].text).summary.total, 373505);
    });
    it("search_cves forwards the filters and returns the rows", () => {
      assert.ok(stub.state.seen.includes("/api/v1/public/cves?search=tomcat&limit=2"), `seen: ${stub.state.seen}`);
      const data = JSON.parse(results.search_cves.content[0].text);
      assert.equal(data.total, 1);
      assert.equal(data.cves[0].cve_id, CVE);
    });
    it("get_cve returns the record", () => {
      const data = JSON.parse(results.get_cve.content[0].text);
      assert.equal(data.cve_id, CVE);
      assert.equal(data.echelongraph_score, 9);
    });
    it("cve_exposure returns the footprint", () => {
      const data = JSON.parse(results.cve_exposure.content[0].text);
      assert.equal(data.exposed_hosts, 6213);
      assert.equal(data.countries, 107);
    });
    it("exposure_radar returns all four radars, none null", () => {
      const data = JSON.parse(results.exposure_radar.content[0].text);
      assert.equal(data.kev_exposure.distinct_hosts, 25113);
      assert.equal(data.exposed_databases.distinct_hosts, 7380);
      assert.equal(data.leaked_credentials.total, 531);
      assert.equal(data.shadow_ai.observed.total, 36222);
      assert.equal(data.shadow_ai.confirmed_exposed.total, 2000);
    });
  });

  // The control that keeps the fix honest: an empty answer is a measurement, not a failure.
  describe("genuine-empty control: upstream answers 200 with zero rows", () => {
    let results;
    before(async () => { stub.state.mode = "empty"; results = await callAll(client); });
    for (const name of ["cve_summary", "search_cves", "cve_exposure", "exposure_radar"]) {
      it(`${name} is a SUCCESS, not an error`, () => {
        const res = results[name];
        assert.notEqual(res.isError, true, `${name}: an empty answer was rendered as an error: ${brief(res)}`);
        assert.doesNotThrow(() => JSON.parse(res.content[0].text), `${name}: first block is not JSON`);
      });
    }
    for (const name of ["cve_summary", "search_cves", "cve_exposure"]) {
      it(`${name} says in words that it looked and found nothing`, () => {
        const t = textOf(results[name]);
        assert.match(t, new RegExp(`\\b${name} OK\\b`), `${name}: no OK note: ${t}`);
        assert.match(t, /found nothing/, `${name}: empty answer is not worded as such: ${t}`);
        assert.match(t, /not a lookup failure/, `${name}: empty answer does not rule out a failure: ${t}`);
        assert.doesNotMatch(t, /FAILED/, `${name}: empty answer reads as a failure: ${t}`);
      });
    }
    it("search_cves reports zero matches", () => {
      assert.equal(JSON.parse(results.search_cves.content[0].text).total, 0);
    });
    it("cve_exposure reports a measured zero", () => {
      assert.equal(JSON.parse(results.cve_exposure.content[0].text).exposed_hosts, 0);
    });
    // The live API answers an unknown CVE with 404 + its own message. That is not a 200 with
    // zero rows, so it stays an error result — but the API's message must be quoted verbatim
    // so the model sees the backend's own words, not a bare status code.
    it("get_cve on the API's 404 is an error result that quotes the API's message", () => {
      const res = results.get_cve;
      assertErrorResult("get_cve", res);
      assertNames("get_cve", res, stub.base, /HTTP 404/, new RegExp(`CVE not found: ${CVE}`));
    });
  });

  // #2306: the package's own copy makes no claim the data cannot back. Both polarities: the
  // claims are absent from every description, note and packaged text, and what replaces them
  // (the method, the Shodan attribution) is present.
  describe("#2306: no removed claim in any tool text, and the method is named", () => {
    let tools;
    const notes = [];
    before(async () => {
      ({ tools } = await client.listTools());
      for (const mode of ["ok", "empty", "403"]) {
        stub.state.mode = mode;
        const results = await callAll(client);
        for (const name of TOOLS) notes.push([`${name}/${mode}`, noteOf(results[name])]);
      }
      stub.state.mode = "ok";
      for (const id of [CVE_UNTRACKED, CVE_UNTRACKED_STALE, CVE_OLD_API, CVE_REJECTED, "not-a-cve"]) {
        notes.push([`cve_exposure/${id}`, noteOf(await client.callTool({ name: "cve_exposure", arguments: { cve_id: id } }))]);
      }
    });
    it("no tool description or argument description makes a removed claim", () => {
      for (const t of tools) {
        assert.doesNotMatch(t.description, REMOVED_CLAIMS, `${t.name} description: ${t.description}`);
        for (const [arg, schema] of Object.entries(t.inputSchema?.properties ?? {})) {
          assert.doesNotMatch(schema.description ?? "", REMOVED_CLAIMS, `${t.name}.${arg}: ${schema.description}`);
        }
      }
    });
    it("no result note or failure text makes a removed claim", () => {
      assert.ok(notes.length >= 20, `only ${notes.length} notes collected`);
      for (const [where, note] of notes) assert.doesNotMatch(note, REMOVED_CLAIMS, `${where}: ${note}`);
    });
    // The note quotes the API's method sentence verbatim, so the guard above only covers
    // what the API really sends if the notes it read carried that sentence.
    it("the notes checked above include the backend's own method sentence, quoted once", () => {
      const quoting = notes.filter(([, n]) => n.includes(`Method: ${BACKEND_METHOD} Exposure counts`));
      assert.ok(quoting.length >= 3, `only ${quoting.length} notes quote BACKEND_METHOD: ${notes.map(([w]) => w).join(", ")}`);
    });
    it("every count is worded as ip:port services, never as hosts", () => {
      for (const t of tools) assert.doesNotMatch(t.description, HOST_UNIT, `${t.name} description: ${t.description}`);
      for (const [where, note] of notes) assert.doesNotMatch(note, HOST_UNIT, `${where}: ${note}`);
      assert.doesNotMatch(readPkgFile("README.md"), HOST_UNIT);
      assert.doesNotMatch(PKG.description, HOST_UNIT);
      assert.match(tools.find((t) => t.name === "cve_exposure").description, /distinct ip:port/);
      assert.match(tools.find((t) => t.name === "exposure_radar").description, /distinct ip:port/);
    });
    it("README, package.json description and server.json description make no removed claim", () => {
      assert.doesNotMatch(readPkgFile("README.md"), REMOVED_CLAIMS);
      assert.doesNotMatch(PKG.description, REMOVED_CLAIMS);
      assert.doesNotMatch(JSON.parse(readPkgFile("server.json")).description, REMOVED_CLAIMS);
    });
    it("cve_exposure's description names the method and attributes Shodan", () => {
      const d = tools.find((t) => t.name === "cve_exposure").description;
      assert.match(d, /derived from Shodan data/);
      assert.match(d, /up to 100 ip:port services per query/);
      assert.match(d, /Every 12 h/);
      assert.match(d, /NOT ASSESSED/);
    });
    it("every cve_exposure success note names the method and attributes Shodan", () => {
      const successes = notes.filter(([where, n]) => where.startsWith("cve_exposure/") && /\bcve_exposure OK\b/.test(n));
      assert.ok(successes.length >= 4, `only ${successes.length} cve_exposure successes`);
      for (const [where, n] of successes) {
        assert.match(n, /Method: /, `${where}: ${n}`);
        assert.match(n, /Exposure counts are derived from Shodan data\./, `${where}: ${n}`);
      }
    });
    it("README and package.json attribute the exposure data to Shodan", () => {
      assert.match(readPkgFile("README.md"), /derived from Shodan data/);
      assert.match(PKG.description, /derived from Shodan data/);
    });

    // The wording rules below were each checked against the backend's code before they were
    // written; the comment on each names what it holds the text to.
    const flat = (s) => s.replace(/\s+/g, " ");
    // Every package-authored text a user or a model reads, README reflowed onto one line.
    const shipped = () => [
      ...tools.map((t) => [`${t.name} description`, t.description]),
      ...notes,
      ["README.md", flat(readPkgFile("README.md"))],
      ["package.json description", PKG.description],
      ["server.json description", JSON.parse(readPkgFile("server.json")).description],
    ];

    // kevexposure/poller.go runOnce skips the Shodan search when shodan.HasQueryBudget says
    // fewer than SHODAN_MIN_QUERY_BUDGET credits remain, so the cadence is never unconditional.
    it("every statement of the 12 h search cadence says it runs only when Shodan query credits allow", () => {
      let checked = 0;
      for (const [where, t] of shipped()) {
        for (const m of t.matchAll(/every 12 (?:h|hours)\b/gi)) {
          checked++;
          const after = t.slice(m.index + m[0].length, m.index + m[0].length + 40);
          assert.match(after, /^,? when Shodan query credits allow/, `${where}: "${t.slice(m.index, m.index + 80)}"`);
        }
      }
      // The description, the README, and the notes quoting both the backend's method and the
      // fallback one: a guard that matched nothing would pass on nothing.
      assert.ok(checked >= 6, `only ${checked} cadence statements checked`);
    });

    // kevexposure/poller.go reconcileStale Touches last_seen when InternetDB still lists the
    // PORT, without re-reading the version, so last_seen is no re-sighting of the vulnerable
    // banner and a patched service can stay counted.
    it("last_seen is described as port presence, never as a re-sighting of the vulnerable version", () => {
      for (const [where, t] of shipped()) assert.doesNotMatch(t, /re-seen|most recently seen/i, `${where}: ${t}`);
      const rule = /last seen listening on its port, not when its vulnerable version was last confirmed/;
      assert.match(tools.find((t) => t.name === "cve_exposure").description, rule);
      assert.match(flat(readPkgFile("README.md")), rule);
      assert.match(BACKEND_METHOD, rule, "the fixture no longer carries the backend's qualifier");
    });

    // The KEV fetcher (internal/cve/kev/fetcher.go) only UPDATEs existing cves rows, and the
    // API answers kev_catalog_listed:false when there is no row, so false is not a statement
    // about the CISA catalog.
    it("no note states CISA-KEV catalog membership as fact; it says what EchelonGraph's record holds", () => {
      let checked = 0;
      for (const [where, n] of notes) {
        assert.doesNotMatch(n, /is (?:not )?listed in the CISA-KEV catalog/, `${where}: ${n}`);
        if (/EchelonGraph's CVE (?:record|data) (?:marks|does not mark)/.test(n)) checked++;
      }
      assert.ok(checked >= 3, `only ${checked} notes carry a KEV sentence`);
    });

    // The backend omits `tracked` on purpose when it cannot decide (store.go trackedVerdict),
    // not only on an older API.
    it("the README's absent-tracked row does not blame an older API alone", () => {
      const readme = flat(readPkgFile("README.md"));
      assert.doesNotMatch(readme, /no `tracked` field \(older API\)/);
      assert.match(readme, /no `tracked` field \| The API did not say whether the CVE is in the tracked set: an older API, or the radar cannot decide/);
    });

    // A count over at most 100 Shodan results per product query is not a census, so no text
    // may invite reading it as one.
    it("no text or suggested prompt invites an internet-wide census reading", () => {
      for (const [where, t] of shipped()) {
        assert.doesNotMatch(t, /how exposed is the internet|how much of the internet|internet is exposed/i, `${where}: ${t}`);
      }
      assert.match(flat(readPkgFile("README.md")), /how many exposed services does EchelonGraph's radar have on record for it\?/);
    });

    // #2306 reopened: Shodan's terms require materials based on Shodan information to
    // "clearly indicate Shodan's ownership and copyright in the applicable Shodan materials".
    // Attribution alone is half of it. Both polarities: the ownership sentence sits beside the
    // attribution, and nothing claims EchelonGraph copyright over Shodan-derived data.
    it("cve_exposure's description indicates Shodan's ownership and copyright beside the attribution", () => {
      const d = tools.find((t) => t.name === "cve_exposure").description;
      assert.ok(d.includes(`exposure counts are derived from Shodan data. ${SHODAN_OWNERSHIP}`), d);
    });
    it("every cve_exposure success note indicates Shodan's ownership and copyright beside the attribution", () => {
      const successes = notes.filter(([where, n]) => where.startsWith("cve_exposure/") && /\bcve_exposure OK\b/.test(n));
      assert.ok(successes.length >= 4, `only ${successes.length} cve_exposure successes`);
      for (const [where, n] of successes) {
        assert.ok(n.includes(`Exposure counts are derived from Shodan data. ${SHODAN_OWNERSHIP}`), `${where}: ${n}`);
      }
    });
    it("README indicates Shodan's ownership and copyright beside the attribution, and in its License section", () => {
      const intro = flat(readPkgFile("README.md").split(/^## Tools$/m)[0]);
      assert.ok(intro.includes(`Exposure counts are derived from Shodan data. ${SHODAN_OWNERSHIP}`), `README intro: ${intro}`);
      const license = flat(readPkgFile("README.md").split(/^## License$/m)[1] ?? "");
      assert.ok(license.includes(`Exposure counts are derived from Shodan data. ${SHODAN_OWNERSHIP}`), `License section: ${license}`);
    });
    it("every shipped text that names Shodan indicates Shodan's ownership and copyright", () => {
      let checked = 0;
      for (const [where, t] of shipped()) {
        if (!/Shodan/.test(t)) continue;
        checked++;
        // server.json's description is capped at 100 characters by the registry schema, so
        // it carries the short form; the README it points to carries the sentence.
        if (where === "server.json description") assert.match(t, /Shodan data \(© Shodan\)/, `${where}: ${t}`);
        else assert.ok(t.includes(SHODAN_OWNERSHIP), `${where}: ${t}`);
      }
      // Two tool descriptions, the cve_exposure and exposure_radar success notes, the README,
      // package.json and server.json: a guard that matched nothing would pass on nothing.
      assert.ok(checked >= 12, `only ${checked} texts naming Shodan checked`);
    });
    it("nothing claims EchelonGraph copyright over the data: © EchelonGraph covers only the CVE Pulse compilation", () => {
      const readme = flat(readPkgFile("README.md"));
      assert.doesNotMatch(readme, /Data © EchelonGraph/, "the README still asserts EchelonGraph copyright over all data");
      let owned = 0;
      for (const [where, t] of shipped()) {
        for (const m of t.matchAll(/© EchelonGraph/g)) {
          owned++;
          const lead = t.slice(Math.max(0, m.index - 160), m.index);
          assert.match(lead, /The CVE Pulse compilation \([^)]*\) is $/, `${where}: "${t.slice(Math.max(0, m.index - 160), m.index + 20)}"`);
        }
      }
      assert.equal(owned, 1, "the README's License section names what EchelonGraph owns, once");
      assert.match(readme, /EchelonGraph claims no ownership of it or copyright in it\./);
    });
    it("the MIT licence still covers the code", () => {
      assert.equal(PKG.license, "MIT");
      assert.match(flat(readPkgFile("README.md")), /## License The code is MIT-licensed\./);
    });
  });

  // The contract of GET /api/v1/public/kev-exposure/cve/:id, as the tool must read it.
  describe("cve_exposure: tracked, not assessed, measured zero, and invalid input", () => {
    const call = (cve_id) => client.callTool({ name: "cve_exposure", arguments: { cve_id } });
    before(() => { stub.state.mode = "ok"; });

    it("a malformed id is refused as invalid_input without a request", async () => {
      stub.state.seen.length = 0;
      for (const id of ["not-a-cve", "CVE-2023-123", "2023-44487", "CVE-2023-44487; DROP"]) {
        const res = await call(id);
        assertErrorResult("cve_exposure", res);
        const t = textOf(res);
        assert.match(t, /invalid_input/, `${id}: ${t}`);
        assert.match(t, /Nothing was looked up/, `${id}: ${t}`);
        assert.doesNotMatch(t, /measured|found nothing/, `${id}: ${t}`);
      }
      assert.deepEqual(stub.state.seen, [], "a malformed id reached the API");
    });
    it("a lower-case id is accepted and sent in canonical upper case", async () => {
      stub.state.seen.length = 0;
      const res = await call(` ${CVE.toLowerCase()} `);
      assert.notEqual(res.isError, true, brief(res));
      assert.deepEqual(stub.state.seen, [`/api/v1/public/kev-exposure/cve/${CVE}`]);
    });
    it("HTTP 400 from the API is an error tagged invalid_input, never a measured zero", async () => {
      const res = await call(CVE_REJECTED);
      assertErrorResult("cve_exposure", res);
      assertNames("cve_exposure", res, stub.base, /invalid_input/, /HTTP 400/, /invalid CVE id/);
      assert.doesNotMatch(textOf(res), /measured|found nothing|0 exposed/, textOf(res));
    });
    it("tracked:false is NOT ASSESSED: outside the tracked set, and 0 is not a measurement", async () => {
      const res = await call(CVE_UNTRACKED);
      assert.notEqual(res.isError, true, brief(res));
      const n = noteOf(res);
      assert.doesNotMatch(n, /measured zero|found nothing/, n);
      assert.match(n, /NOT ASSESSED/);
      assert.match(n, /outside the radar's tracked set; 0 is not a measurement/);
      assert.match(n, /\bcve_exposure OK\b/);
      assert.match(n, /state: not_assessed/);
      // kev_catalog_listed:false is also the answer when EchelonGraph has no cves row (the KEV
      // fetcher only UPDATEs), so it is worded as what EchelonGraph's data says.
      assert.match(n, new RegExp(`EchelonGraph's CVE data does not mark ${CVE_UNTRACKED} as CISA-KEV-listed \\(kev_catalog_listed is false, which it also is when EchelonGraph holds no record of ${CVE_UNTRACKED}\\)`));
      assert.doesNotMatch(n, /listed in the CISA-KEV catalog/, n);
    });
    it("tracked:false with hosts on record is still NOT ASSESSED, not a current count", async () => {
      const n = noteOf(await call(CVE_UNTRACKED_STALE));
      assert.match(n, /NOT ASSESSED/);
      assert.match(n, /3 service\(s\) \(distinct ip:port\) on record are left from earlier scans and are not a current measurement/);
      assert.ok(n.includes(`Method: ${METHOD}. Exposure counts`), `an API method ending in a full stop is quoted once: ${n}`);
    });
    // The radar reads at most the first 100 Shodan results per product query, so even a
    // tracked zero is a zero in that sample, not "the tracked products as Shodan sees them".
    it("tracked:true with 0 hosts is a measured zero in the radar's sample, not an internet-wide zero", async () => {
      stub.state.mode = "empty";
      const res = await call(CVE);
      stub.state.mode = "ok";
      assert.notEqual(res.isError, true, brief(res));
      const n = noteOf(res);
      assert.match(n, /state: measured_zero/);
      assert.match(n, /a measured zero in the radar's sample/);
      assert.match(n, /It is a zero in a sample, not an internet-wide zero: the radar reads at most the first 100 Shodan results per tracked-product query/);
      assert.doesNotMatch(n, /as Shodan sees them|among the radar's tracked products/, n);
      assert.match(n, /not a lookup failure/);
      assert.match(n, new RegExp(`EchelonGraph's CVE record marks ${CVE} as CISA-KEV-listed\\.`));
      assert.doesNotMatch(n, /NOT ASSESSED/);
    });
    it("tracked absent (an older API, or one that could not decide) makes no claim that the zero was measured", async () => {
      const res = await call(CVE_OLD_API);
      assert.notEqual(res.isError, true, brief(res));
      const n = noteOf(res);
      assert.doesNotMatch(n, /measured/, n);
      assert.doesNotMatch(n, /found nothing|NOT ASSESSED/, n);
      assert.match(n, /\bcve_exposure OK\b/);
      assert.match(n, /state: tracking_unknown/);
      assert.match(n, /does not say whether .* is in the radar's tracked set/);
      // The backend also omits `tracked` on purpose when it cannot decide, so "older API"
      // must not be the only reason given.
      assert.match(n, /an API older than that field, or the radar cannot decide for this CVE/);
      assert.match(n, /not evidence either way/);
      assert.match(n, /kev_listed field reflects the radar's own observations, not the CISA-KEV catalog/);
      assert.doesNotMatch(n, /0001-01-01/);
    });
    it("a populated footprint names its count, the method the API reports, and Shodan", async () => {
      const n = noteOf(await call(CVE));
      assert.match(n, /state: exposed/);
      assert.match(n, new RegExp(`6213 internet-facing services \\(distinct ip:port, the exposed_hosts field\\) on record whose banner version maps to ${CVE} across 107 countries`));
      assert.ok(n.includes(`Method: ${BACKEND_METHOD} Exposure counts`), `the API's method, which ends in a full stop, is quoted once: ${n}`);
      // last_seen is refreshed on port presence alone, so it is not a fresh sighting of the
      // vulnerable version and must not read as one.
      assert.match(n, /Their latest last_seen is 2026-09-15T04:02:09Z: when one of them was last seen listening on its port, not when its vulnerable version was last confirmed\./);
      assert.doesNotMatch(n, /most recently seen/, n);
    });
  });

  // #2307: exposure_radar relays shadow-ai-radar/stats, whose total counts every observation.
  describe("#2307: exposure_radar labels shadow AI observed vs confirmed exposed", () => {
    let tools, res, data, note;
    before(async () => {
      stub.state.mode = "ok";
      ({ tools } = await client.listTools());
      res = await client.callTool({ name: "exposure_radar", arguments: {} });
      data = JSON.parse(res.content[0].text);
      note = noteOf(res);
    });
    it("the description no longer calls the total exposed AI services", () => {
      const d = tools.find((t) => t.name === "exposure_radar").description;
      assert.doesNotMatch(d, /exposed AI services/, d);
      assert.match(d, /shadow_ai\.observed counts every Certificate Transparency or Shodan observation on record, whatever its verification state: its numbers are observed, not exposed\./, d);
      assert.match(d, /confirmed_exposed\.total is the sum of confirmed_exposed\.by_category/, d);
      assert.match(d, /Only confirmed_exposed counts exposed services\./, d);
    });
    it("the note calls confirmed_exposed.total (the sum of the API's visible_by_category) confirmed exposed", () => {
      assert.match(note, /Shadow AI confirmed exposed: 2000 \(confirmed_exposed\.total, the sum of confirmed_exposed\.by_category: services EchelonGraph's probes found answering without an authentication gate/, note);
      assert.match(note, /, 201 of them first recorded in the last 24 h \(confirmed_exposed\.last_24h\)\./, note);
      assert.match(note, /Only confirmed_exposed counts exposed services\./, note);
      assert.equal(data.shadow_ai.confirmed_exposed.total, 2000);
    });
    it("the note never calls observed.total exposed", () => {
      assert.match(note, /Shadow AI observed: 36222 \(observed\.total\) counts every Certificate Transparency or Shodan observation on record/, note);
      assert.match(note, /that many observed, not that many exposed/, note);
      assert.doesNotMatch(note, /36,?222 (?:internet-)?exposed|exposed[^.:;]{0,40}\b36,?222\b/, note);
    });
    it("a follower's zero-time poller block is never presented as freshness", () => {
      const all = textOf(res);
      assert.doesNotMatch(all, /0001-01-01/, "a Go zero time reached the result");
      assert.doesNotMatch(all, /"running": false/, "a follower's running:false reached the result");
      assert.equal(data.shadow_ai.poller, undefined);
      assert.equal(data.shadow_ai.observed.total, 36222, "the stats themselves must still be relayed");
      assert.match(note, /Shadow-AI radar freshness is unknown/, note);
      assert.match(note, /Latest shadow-AI observation on record: 2026-09-26T11:02:00Z/, note);
    });

    // #2307 reopened: body item 1 asks that EVERY number be labelled observed vs confirmed,
    // and 1.0.2 relayed eight observation counts under the API's names with no label. What
    // each group counts, from core-backend/internal/shadowctlog:
    //   confirmed_exposed  store.go Stats: visible_by_category and last_24h_visible_count,
    //                      liveness IN ('active','rechecking')
    //   observed           store.go Stats: total, by_category, last_24h_count (no liveness
    //                      filter); TopProducts, TopCountries, TopIssuers, DailyTrend (the same)
    //   authentication     store.go Stats: auth_confirmed = liveness 'authenticated',
    //                      auth_undetermined = liveness 'inconclusive' (verifier.go)
    it("the relayed shadow_ai is regrouped as confirmed_exposed, observed and authentication", () => {
      assert.deepEqual(data.shadow_ai, PROD_SHADOW_RELAYED);
      assert.equal(data.shadow_ai.stats, undefined, "the API's ungrouped stats are not relayed beside the groups");
    });
    it("every numeric field reachable in shadow_ai is a labelled one, and every labelled one is there", () => {
      const found = [...numericPaths(data.shadow_ai)].sort();
      const unlabelled = found.filter((p) => !(p in SHADOW_AI_LABELLED));
      assert.deepEqual(unlabelled, [], `numeric fields relayed with no label: ${unlabelled.join(", ")}`);
      // Not vacuous: the production-shaped answer reaches every labelled field.
      assert.deepEqual(found, Object.keys(SHADOW_AI_LABELLED).sort());
    });
    it("each labelled field is named in the note, the tool description and the README", () => {
      const d = tools.find((t) => t.name === "exposure_radar").description;
      const readme = readPkgFile("README.md");
      for (const name of new Set(Object.values(SHADOW_AI_LABELLED))) {
        assert.ok(note.includes(name), `the note does not label ${name}: ${note}`);
        assert.ok(d.includes(name), `the description does not label ${name}: ${d}`);
        assert.ok(readme.includes(name), `the README does not label ${name}`);
      }
    });
    it("the note labels each observed ranking and series as counts of observations", () => {
      assert.match(note, /Every other number under observed counts the same observations, not exposed services: /, note);
      assert.match(note, /observed\.last_24h \(1569\) counts those first recorded in the last 24 h/, note);
      assert.match(note, /observed\.trend_30d counts them per UTC day over the last 30 days/, note);
      assert.match(note, /observed\.top_products ranks up to ten products by observations \(first: LiteLLM, 6813 observations\)/, note);
      assert.match(note, /observed\.top_countries ranks up to ten countries by observations \(first: United States, 9800 observations\)/, note);
      assert.match(note, /observed\.top_issuers ranks up to ten issuers by observations, an issuer being the certificate's CA for a Certificate Transparency observation and the hosting operator Shodan reports for a Shodan one \(first: Let's Encrypt, 15800 observations\)/, note);
    });
    it("the note labels the authentication counts as probe outcomes, neither exposed nor secured", () => {
      assert.match(note, /authentication\.observed \(8065\) counts observations where a probe observed an authentication gate/, note);
      assert.match(note, /authentication\.not_determined \(9307\) counts observations whose service answered but where no probe could tell/, note);
      assert.match(note, /Neither authentication count is part of confirmed_exposed, and observed\.total minus confirmed_exposed\.total is not a count of secured services/, note);
      assert.doesNotMatch(note, /\bsecured\b(?! services:)/, note);
    });
    // The auditor's mutant added "Headline: 36222 AI services exposed on the internet." to the
    // note and 1.0.2's suite still passed 136/136: its guard knew two word orders. This one
    // reads sentences: any sentence carrying a number from observed or authentication may use
    // "exposed" only as "not … exposed".
    it("no number under observed or authentication is called exposed in the note", () => {
      const checked = assertNoObservedNumberCalledExposed("exposure_radar note", note, data.shadow_ai);
      // 36222, 1569, 6813, 9800, 15800, 8065 and 9307 are each in the note.
      assert.ok(checked >= 7, `only ${checked} observed numbers found in the note`);
    });
    it("the guard above rejects the auditor's two mutants (an in-suite control)", () => {
      for (const mutant of ["Headline: 36222 AI services exposed on the internet.", "Shadow AI has 36222 internet-facing services exposed."]) {
        assert.throws(() => assertNoObservedNumberCalledExposed("mutant", `${note} ${mutant}`, data.shadow_ai), /called exposed/, mutant);
      }
    });
    it("no sentence that names an observed or authentication field calls it exposed: note, description, README", () => {
      const d = tools.find((t) => t.name === "exposure_radar").description;
      const n = assertObservedFieldsNotCalledExposed("note", sentencesOf(note));
      const dn = assertObservedFieldsNotCalledExposed("description", sentencesOf(d));
      const rn = assertObservedFieldsNotCalledExposed("README.md", readmeUnits(readPkgFile("README.md")));
      assert.ok(n >= 4 && dn >= 4 && rn >= 6, `too few sentences checked: note ${n}, description ${dn}, README ${rn}`);
    });
    it("no field name under shadow_ai says exposed, outside confirmed_exposed", () => {
      const named = [...keyPaths(data.shadow_ai)].filter((p) => !p.startsWith("confirmed_exposed"));
      assert.ok(named.length >= 12, `only ${named.length} field names checked`);
      for (const p of named) assert.doesNotMatch(p, /expos/i, p);
    });
    // Every quadrant but leaked credentials is found through Shodan; exposed databases fall
    // back to LeakIX, and that quadrant holds observability UIs as well as data stores.
    it("the description attributes the exposed-databases quadrant to Shodan and LeakIX, and names what it holds", () => {
      const d = tools.find((t) => t.name === "exposure_radar").description;
      assert.doesNotMatch(d, /unauthenticated databases/, d);
      assert.match(d, /unauthenticated data stores and observability UIs, found through Shodan \(LeakIX when Shodan query credits run low\)/, d);
      // Not "read-only": exposeddb names its client on Redis (CLIENT SETNAME) and its ClickHouse
      // SELECT lands in the target's query_log (exposeddb/probewrites_guard_test.go).
      assert.match(d, /confirmed by EchelonGraph's own identified check \(not a pure read/, d);
      assert.doesNotMatch(d, /read-only check/, d);
    });
    it("the note attributes Shodan to every quadrant that uses it, not only KEV-exposure", () => {
      assert.match(note, /KEV-exposure, exposed-database and shadow-AI discovery use Shodan data/, note);
      assert.match(note, /exposed databases fall back to LeakIX when Shodan query credits run low/, note);
      assert.doesNotMatch(note, /KEV-exposure counts are derived from Shodan data/, note);
    });
    // The fleet-freshness block (core-backend shadowctlog Poller.Status). Three cases, and the
    // note must tell them apart: running since a real completion, stopped since one, unknown.
    const SA_PATH = "/api/v1/public/shadow-ai-radar/stats";
    // poller: the block the stub answers with; undefined answers with no poller key at all.
    const radarWith = async (poller) => {
      const { poller: _dropped, ...rest } = BODIES[SA_PATH].ok;
      stub.state.overrides[SA_PATH] = poller === undefined ? rest : { ...rest, poller };
      try {
        const r = await client.callTool({ name: "exposure_radar", arguments: {} });
        assert.notEqual(r.isError, true, brief(r));
        return { relayed: JSON.parse(r.content[0].text).shadow_ai, n: noteOf(r) };
      } finally {
        delete stub.state.overrides[SA_PATH];
      }
    };
    // Freshness is the fleet's, never the answering instance's: the old wording must be gone.
    const noInstanceWording = (n) => assert.doesNotMatch(n, /server instance that answered|last ran the shadow-AI poller/, n);

    it("running:true with a real last_run_at: the radar's leader last completed a cycle at that time; the block is kept", async () => {
      const { relayed, n } = await radarWith(FLEET_RUNNING);
      assert.match(n, /Shadow-AI radar freshness: the radar's leader last completed a Certificate Transparency \(crt\.sh\) discovery cycle at 2026-09-26T10:00:00Z \(poller\.running is true: that was within 30 minutes of the API's answer\)\./, n);
      assert.doesNotMatch(n, /freshness is unknown|has completed since|may be stale/, n);
      noInstanceWording(n);
      // Only the two fleet fields the note explains; interval_seconds and shodan_enabled are the
      // answering instance's own settings (Poller.Status).
      assert.deepEqual(relayed.poller, { running: true, last_run_at: FLEET_RUNNING.last_run_at }, "a fleet block with a real completion time is relayed as running and last_run_at");
    });
    it("running:false with a real last_run_at: no cycle has completed since that time; the block is kept", async () => {
      const { relayed, n } = await radarWith(FLEET_STOPPED);
      assert.match(n, /Shadow-AI radar freshness: no Certificate Transparency \(crt\.sh\) discovery cycle has completed since 2026-09-26T08:15:00Z, when the radar's leader last completed one \(poller\.running is false: that was more than 30 minutes before the API's answer\), so the shadow-AI figures may be stale\./, n);
      assert.doesNotMatch(n, /freshness is unknown|last completed a Certificate Transparency \(crt\.sh\) discovery cycle at/, n);
      noInstanceWording(n);
      assert.deepEqual(relayed.poller, { running: false, last_run_at: FLEET_STOPPED.last_run_at }, "a stopped radar's real completion time is a finding, relayed as running and last_run_at");
    });
    it("last_run_at absent (the API cannot tell): freshness is unknown and the block is left out", async () => {
      const { relayed, n } = await radarWith(FLEET_UNKNOWN);
      assert.match(n, /Shadow-AI radar freshness is unknown: the answer's poller block does not give both a real time at which the radar's leader last completed a cycle \(poller\.last_run_at\) and a running verdict \(poller\.running\), so that block was left out of the data above\./, n);
      assert.doesNotMatch(n, /has completed since|last completed a Certificate Transparency/, n);
      assert.equal(relayed.poller, undefined);
      assert.equal(relayed.observed.total, 36222, "the stats themselves must still be relayed");
    });
    // An older API, or a malformed block: a zero or missing time, or a time without a verdict,
    // is never presented as the radar running or stopped.
    for (const [label, poller] of [
      ["an older API's follower (running:false, zero time)", FOLLOWER_POLLER],
      ["running:true with the zero time", { ...FLEET_RUNNING, last_run_at: "0001-01-01T00:00:00Z" }],
      ["running:true with no last_run_at", { running: true, interval_seconds: 60 }],
      ["a real last_run_at with no running verdict", { interval_seconds: 60, last_run_at: "2026-09-26T10:00:00Z" }],
    ]) {
      it(`${label}: freshness is unknown, and no running flag or zero time is relayed`, async () => {
        const { relayed, n } = await radarWith(poller);
        assert.match(n, /Shadow-AI radar freshness is unknown/, n);
        assert.doesNotMatch(n, /has completed since|last completed a Certificate Transparency|0001-01-01/, n);
        assert.equal(relayed.poller, undefined);
      });
    }
    it("no poller block at all: freshness is unknown, said in words", async () => {
      const { relayed, n } = await radarWith(undefined);
      assert.match(n, /Shadow-AI radar freshness is unknown: the answer carries no poller block\./, n);
      assert.equal(relayed.poller, undefined);
    });
    it("the description says what running and last_run_at mean", () => {
      const d = tools.find((t) => t.name === "exposure_radar").description;
      assert.match(d, /last_run_at is when the radar's leader last completed a Certificate Transparency \(crt\.sh\) cycle, and its running is true only when that was within 30 minutes of the answer/, d);
    });

    // What a later backend may add: a new stats count (one named as if exposed), a new count in
    // a ranked row, a new map, a new top-level block, and a polling instance's own counters in
    // the poller block. None may be relayed, since none is labelled; each top-level one is
    // named in the note, so the omission is visible.
    const radarAnswering = async (body) => {
      stub.state.overrides[SA_PATH] = body;
      try {
        const r = await client.callTool({ name: "exposure_radar", arguments: {} });
        assert.notEqual(r.isError, true, brief(r));
        return { relayed: JSON.parse(r.content[0].text).shadow_ai, n: noteOf(r) };
      } finally {
        delete stub.state.overrides[SA_PATH];
      }
    };
    it("a numeric field the backend adds later is left out, never relayed unlabelled, and the note names it", async () => {
      const { relayed, n } = await radarAnswering({
        stats: {
          ...PROD_SHADOW_STATS,
          exposed_total: 36222,
          new_count: 777,
          visible_by_country: { "United States": 400 },
          top_products: PROD_SHADOW_STATS.top_products.map((r) => ({ ...r, visible: 12 })),
          trend_30d: TREND_30D.map((r) => ({ ...r, visible: 3 })),
        },
        coverage: { probes: 5 },
        poller: { ...FLEET_RUNNING, last_new_inserts: 12, skipped_as_follower: 3, consecutive_fails: 0, shodan_last_new: 4 },
      });
      const found = [...numericPaths(relayed)].sort();
      const unlabelled = found.filter((p) => !(p in SHADOW_AI_LABELLED));
      assert.deepEqual(unlabelled, [], `numeric fields relayed with no label: ${unlabelled.join(", ")}`);
      assert.deepEqual(found, Object.keys(SHADOW_AI_LABELLED).sort(), "the labelled fields are still all relayed");
      assert.deepEqual(relayed.poller, { running: true, last_run_at: FLEET_RUNNING.last_run_at });
      assert.match(n, /Left out of shadow_ai because this version of the tool cannot label them: coverage, stats\.exposed_total, stats\.new_count, stats\.visible_by_country\./, n);
      assert.equal(assertNoObservedNumberCalledExposed("note", n, relayed) >= 7, true);
    });
    it("a count in an unexpected shape is left out whole and named, never relayed partly", async () => {
      const { relayed, n } = await radarAnswering({
        stats: {
          ...PROD_SHADOW_STATS,
          by_category: { ...PROD_SHADOW_STATS.by_category, NOTEBOOK: "6000" },
          top_products: [...PROD_SHADOW_STATS.top_products, { product: "vLLM" }],
          auth_undetermined: "9307",
        },
        poller: FLEET_RUNNING,
      });
      assert.equal(relayed.observed.by_category, undefined, "a partial category map is an undercount that reads as a measurement");
      assert.equal(relayed.observed.top_products, undefined);
      assert.equal(relayed.authentication.not_determined, undefined);
      assert.match(n, /Left out of shadow_ai because they were not in the expected shape: stats\.by_category, stats\.auth_undetermined, stats\.top_products\./, n);
      assert.doesNotMatch(n, /observed\.by_category counts|observed\.top_products ranks|authentication\.not_determined \(/, n);
      const unlabelled = [...numericPaths(relayed)].filter((p) => !(p in SHADOW_AI_LABELLED));
      assert.deepEqual(unlabelled, []);
    });
    it("without visible_by_category nothing is called confirmed exposed, and observed.total is still labelled observed", async () => {
      const { visible_by_category: _v, ...stats } = PROD_SHADOW_STATS;
      const { relayed, n } = await radarAnswering({ stats, poller: FLEET_RUNNING });
      assert.equal(relayed.confirmed_exposed.total, undefined);
      assert.match(n, /Shadow AI: the answer carries no usable stats\.visible_by_category, so it does not say how many services are confirmed exposed; confirmed_exposed\.last_24h \(201\) counts confirmed-exposed services first recorded in the last 24 h\./, n);
      assert.match(n, /Shadow AI observed: 36222 \(observed\.total\)/, n);
      assertNoObservedNumberCalledExposed("note", n, relayed);
    });
  });

  // 1.0.1: the version is read from package.json, so adoption per release is countable.
  describe("package identity: version, User-Agent, tool order, registry metadata", () => {
    it("the MCP handshake reports package.json's version", () => {
      assert.equal(client.getServerVersion()?.version, PKG.version);
    });
    it("every API request carries a User-Agent naming package.json's version", async () => {
      stub.state.mode = "ok";
      stub.state.userAgents.length = 0;
      await callAll(client);
      assert.ok(stub.state.userAgents.length >= TOOLS.length, "no requests seen");
      for (const ua of stub.state.userAgents) {
        assert.equal(ua, `echelongraph-mcp/${PKG.version} (+https://echelongraph.io/pulse/mcp)`);
      }
    });
    it("tools/list answers the five tools in a fixed order", async () => {
      const { tools } = await client.listTools();
      assert.deepEqual(tools.map((t) => t.name), TOOLS);
    });
    it("server.json and package.json agree for the MCP registry's npm ownership check", () => {
      const sj = JSON.parse(readPkgFile("server.json"));
      assert.equal(PKG.mcpName, sj.name, "package.json mcpName must equal server.json name");
      assert.match(sj.name, /^io\.echelongraph\/[a-zA-Z0-9._-]+$/);
      assert.equal(sj.version, PKG.version);
      assert.equal(sj.packages.length, 1);
      const [p] = sj.packages;
      assert.equal(p.registryType, "npm");
      assert.equal(p.identifier, PKG.name);
      assert.equal(p.version, PKG.version);
      assert.deepEqual(p.transport, { type: "stdio" });
      assert.ok(sj.description.length <= 100, `server.json description is ${sj.description.length} chars; the schema allows 100`);
    });
    // A repo check: npm never packs package-lock.json, so a run against the extracted tarball
    // has none to read and says so instead of failing.
    const hasLock = fs.existsSync(path.join(PKG_DIR, "package-lock.json"));
    it("package-lock.json's root carries package.json's version", { skip: hasLock ? false : "no package-lock.json here (npm does not pack it)" }, () => {
      const lock = JSON.parse(readPkgFile("package-lock.json"));
      assert.equal(lock.version, PKG.version, "package-lock.json version");
      assert.equal(lock.packages[""].version, PKG.version, 'package-lock.json packages[""].version');
    });
  });
});

// A control on the fix itself: the error path quotes what fetch reported, and fetch quotes
// the URL when it refuses one that carries a credential. Nothing configured into
// ECHELONGRAPH_API_BASE may come back out through a tool result.
describe("a credential in ECHELONGRAPH_API_BASE never reaches a result", () => {
  const base = "http://user:s3cretvalue@127.0.0.1:1";
  let client, results;
  before(async () => {
    client = await spawnServer({ ECHELONGRAPH_API_BASE: base, ECHELONGRAPH_API_TIMEOUT_MS: "2000" });
    results = await callAll(client);
  });
  after(() => client.close());
  for (const name of TOOLS) {
    it(`${name} is an error result whose text masks the credential`, () => {
      const res = results[name];
      assertErrorResult(name, res);
      const t = textOf(res);
      assert.doesNotMatch(t, /s3cretvalue/, `${name}: credential leaked into the result: ${t}`);
      assert.ok(t.includes("***@127.0.0.1:1"), `${name}: masked base not shown: ${t}`);
    });
  }
});
