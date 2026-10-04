// #2722: MCP prompts and resources, on both protocol eras, asked on the wire through the stdio
// client. Every API request goes to a stub on 127.0.0.1; nothing leaves the machine.
//
// The prompt texts are snapshot-tested (test/fixtures/prompts/*.txt): a wording change is a
// reviewed change. To rewrite the snapshots after an intended change, run this file with
// UPDATE_PROMPT_SNAPSHOTS=1 and review the diff. Every prompt text, title and description, every
// resource description and the resources' texts are held to the package's claim rules (the
// REMOVED_CLAIMS and HOST_UNIT rules of tools.test.mjs, plus "only", which a prompt never uses).
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { connect, MODERN, RpcError } from "./mcp-stdio-client.mjs";
import { serverCommand } from "./server-under-test.mjs";

const ERAS = [MODERN, "2025-06-18"];
const PROMPTS = ["triage_cve", "kev_weekly_brief", "am_i_affected", "sbom_review"];
const RESOURCES = ["echelongraph://methodology", "echelongraph://sources"];
const SNAPSHOTS = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures", "prompts");
const UPDATE = process.env.UPDATE_PROMPT_SNAPSHOTS === "1";

// The claim rules of tools.test.mjs (REMOVED_CLAIMS, HOST_UNIT), and "only" for prompt texts.
const REMOVED_CLAIMS = /passive|no other|unique|real-?time|\blive\b|right now/i;
const HOST_UNIT = /\bhosts\b|\bhost\(s\)/i;
const PROMPT_WORDS = /\bonly\b/i;
const noClaims = (where, t) => {
  assert.doesNotMatch(t, REMOVED_CLAIMS, `${where}: ${t}`);
  assert.doesNotMatch(t, HOST_UNIT, `${where}: ${t}`);
};

const CVE = "CVE-2024-3400";
const RECORD = {
  cve_id: CVE,
  description: "A command injection vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS.",
  severity: "CRITICAL",
  cvss_v3_score: 10,
  echelongraph_score: 9.9,
  score_assessed: true,
  kev_listed: true,
  // As core-backend serves it (store.go KEVAddedDate is a *time.Time): RFC 3339, not a bare date.
  kev_added_date: "2024-04-12T00:00:00Z",
  kev_due_date: "2024-04-19T00:00:00Z",
  updated_at: "2026-10-01T08:00:00Z",
};
const POLLER = { poll_count: 12, cves_ingested: 40, cves_skipped: 0, poll_errors: 0, http_retries: 0, interval: "2h0m0s", last_poll_dur_ms: 900, last_poll_at: "2026-10-03T10:00:00Z" };
const SUMMARY = { summary: { critical: 1, high: 2, medium: 3, low: 4, none: 0, total: 10, last_updated: "2026-09-27T01:00:00Z" }, poller: POLLER };
const KEV_METHOD = "EchelonGraph polls CISA's known_exploited_vulnerabilities.json every 5 minutes with a conditional GET.";
const CATALOG = { source: "CISA KEV catalog", feed_url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", last_successful_fetch_at: "2026-10-03T11:55:01Z", catalog_version: "2026.10.02", date_released: "2026-10-02T17:00:41.1622Z", catalog_count: 1452 };
const KEV = { kev: [], count: 0, total: 0, kev_listed_total: 1452, limit: 1, next_cursor: null, catalog: CATALOG, method: KEV_METHOD, generated_at: "2026-10-03T12:00:00Z" };
// kev_recent's answer for since = until = 2024-04-12 (#2736): the one row CISA added that day.
const KEV_ROW_3400 = { cve_id: CVE, kev_added_date: "2024-04-12", kev_due_date: "2024-04-19", kev_vendor: "Palo Alto Networks", kev_product: "PAN-OS", kev_vuln_name: "Palo Alto Networks PAN-OS Command Injection Vulnerability", kev_ransomware: false, severity: "CRITICAL", cvss_v3_score: 10, epss_score: 0.94, epss_percentile: 0.99, eg_kev_tier: 1, our_first_seen_kev: null };
const KEV_3400 = { ...KEV, kev: [KEV_ROW_3400], count: 1, total: 1, limit: 50 };
const SBOM = JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.5", components: [{ type: "library", name: "lodash", version: "4.17.20", purl: "pkg:npm/lodash@4.17.20" }] });

// The stub: `mode` switches the feed answers so one running server can be read healthy and down.
let mode = "up";
const seen = [];
let stub;
let env;
before(async () => {
  stub = http.createServer((req, res) => {
    const url = new URL(req.url, "http://stub");
    seen.push({ path: url.pathname, search: url.search, limit: req.headers["x-eg-limit"], since: req.headers["x-eg-since"], until: req.headers["x-eg-until"] });
    const day3400 = req.headers["x-eg-since"] === "2024-04-12" && req.headers["x-eg-until"] === "2024-04-12";
    const answers = {
      "/api/v1/public/cves/summary": mode === "up" ? SUMMARY : mode === "no-poller" ? { summary: SUMMARY.summary } : null,
      "/api/v1/public/kev/recent": mode === "up" || mode === "no-poller" ? (day3400 ? KEV_3400 : KEV) : null,
      [`/api/v1/public/cves/${CVE}`]: RECORD,
    };
    const answer = answers[url.pathname];
    if (url.pathname === "/api/v1/public/cves/CVE-2024-9999") {
      res.writeHead(503, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "upstream unavailable" }));
      return;
    }
    if (answer) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(answer));
      return;
    }
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not found" }));
  });
  await new Promise((resolve) => stub.listen(0, "127.0.0.1", resolve));
  env = { ...process.env, ECHELONGRAPH_API_BASE: `http://127.0.0.1:${stub.address().port}`, ECHELONGRAPH_API_TIMEOUT_MS: "2000" };
});
after(() => new Promise((resolve) => stub.close(resolve)));

const textOf = (r) => {
  assert.equal(r.messages.length, 1, JSON.stringify(r));
  assert.equal(r.messages[0].role, "user");
  assert.equal(r.messages[0].content.type, "text");
  return r.messages[0].content.text;
};
const invalidParams = (re) => (e) => e instanceof RpcError && e.code === -32602 && (re === undefined || re.test(e.message));

function snapshot(name, t) {
  const file = path.join(SNAPSHOTS, `${name}.txt`);
  if (UPDATE) {
    fs.mkdirSync(SNAPSHOTS, { recursive: true });
    fs.writeFileSync(file, t);
    return;
  }
  assert.ok(fs.existsSync(file), `no snapshot ${file}: run with UPDATE_PROMPT_SNAPSHOTS=1 and review it`);
  assert.equal(t, fs.readFileSync(file, "utf8"), `${name} differs from its snapshot`);
}

// The envelope rules every prompt must carry.
function envelopeRules(where, t) {
  for (const f of ["state", "measured_at", "method", "coverage", "freshness", "notes"]) assert.match(t, new RegExp(`\\b${f}\\b`), `${where} names ${f}`);
  assert.match(t, /Report not_assessed as not assessed: never as clean/, where);
  assert.match(t, /A count of 0 in a result whose coverage says assessed: false is not a finding of "not affected"/, where);
  assert.match(t, /Cite the measured_at date/, where);
  assert.match(t, /failed and invalid_input mean nothing was looked up/, where);
}

// Where each named tool first appears: the prompt must name them in this order.
function inOrder(where, t, tools) {
  const at = tools.map((tool) => {
    const i = t.search(new RegExp(`\\b${tool}\\b`));
    assert.ok(i >= 0, `${where} does not name ${tool}`);
    return i;
  });
  assert.deepEqual([...at].sort((a, b) => a - b), at, `${where} names ${tools.join(", ")} out of order`);
}

for (const era of ERAS) {
  describe(`#2722 prompts and resources, era ${era}`, () => {
    let client;
    let tools;
    before(async () => {
      client = await connect({ era, ...serverCommand(), env, stderr: "ignore" });
      tools = new Set((await client.listTools()).tools.map((t) => t.name));
    });
    after(() => client?.close());

    it("the opening advertises the prompts and resources capabilities, list fixed", () => {
      assert.deepEqual(client.opening.capabilities.prompts, { listChanged: false });
      assert.deepEqual(client.opening.capabilities.resources, { listChanged: false });
      assert.ok(client.opening.capabilities.tools);
    });

    it("prompts/list lists the four prompts with their arguments", async () => {
      const { prompts } = await client.listPrompts();
      assert.deepEqual(prompts.map((p) => p.name), PROMPTS);
      const args = Object.fromEntries(prompts.map((p) => [p.name, p.arguments.map((a) => [a.name, a.required])]));
      assert.deepEqual(args, {
        triage_cve: [["cve_id", true]],
        kev_weekly_brief: [["days", false]],
        am_i_affected: [["product", false], ["ecosystem", false], ["package", false], ["version", true]],
        sbom_review: [["sbom", true]],
      });
      for (const p of prompts) {
        assert.ok(p.title && p.description, p.name);
        noClaims(`${p.name} description`, `${p.title} ${p.description}`);
        assert.doesNotMatch(p.description, PROMPT_WORDS, `${p.name} description`);
        for (const a of p.arguments) {
          assert.ok(a.description, `${p.name}.${a.name}`);
          noClaims(`${p.name}.${a.name}`, a.description);
          assert.doesNotMatch(a.description, PROMPT_WORDS, `${p.name}.${a.name}`);
        }
      }
    });

    const GETS = [
      ["triage_cve", { cve_id: "cve-2024-3400" }, ["get_cve", "cve_intel", "vendor_advisories_for_cve", "epss_history", "cve_exposure", "kev_recent"]],
      ["kev_weekly_brief", undefined, ["kev_recent"]],
      ["kev_weekly_brief_30", { days: "30" }, ["kev_recent"]],
      ["am_i_affected_product", { product: "openssl", version: "3.0.0" }, ["check_affected"]],
      ["am_i_affected_registry", { ecosystem: "npm", package: "lodash", version: "4.17.20" }, ["check_affected"]],
      ["sbom_review", { sbom: SBOM }, ["check_sbom", "get_cve"]],
    ];
    for (const [snap, args, named] of GETS) {
      it(`prompts/get ${snap}: names ${named.join(", ")} in order, carries the envelope rules, matches its snapshot`, async () => {
        const name = snap.replace(/_(30|product|registry)$/, "");
        const t = textOf(await client.getPrompt({ name, arguments: args }));
        for (const tool of named) assert.ok(tools.has(tool), `${snap} names ${tool}, which tools/list does not list`);
        inOrder(snap, t, named);
        envelopeRules(snap, t);
        // The SBOM is the caller's text, embedded as given; the rules apply to ours.
        const ours = name === "sbom_review" ? t.slice(0, t.indexOf("SBOM:\n")) : t;
        noClaims(snap, ours);
        assert.doesNotMatch(ours, PROMPT_WORDS, snap);
        snapshot(snap, t);
      });
    }

    it("triage_cve names the CVE, upper-cased, and the decision template", async () => {
      const t = textOf(await client.getPrompt({ name: "triage_cve", arguments: { cve_id: " cve-2024-3400 " } }));
      assert.match(t, /each with cve_id CVE-2024-3400:/);
      for (const line of ["Exploited?", "Likelihood:", "Reachable?", "Patch:", "Deadline:", "Decision:"]) assert.ok(t.includes(`- ${line}`), line);
    });
    it("kev_weekly_brief defaults days to 7 and tells the model to compute since from it", async () => {
      const t = textOf(await client.getPrompt({ name: "kev_weekly_brief", arguments: {} }));
      assert.match(t, /in the last 7 days/);
      assert.match(t, /Compute since: today's date in UTC minus 7 days, as YYYY-MM-DD/);
      assert.match(t, /RANSOMWARE where kev_ransomware is true/);
      assert.match(t, /kev_due_date/);
    });
    it("am_i_affected passes the arguments to check_affected as given, and carries the not-assessed wording", async () => {
      const t = textOf(await client.getPrompt({ name: "am_i_affected", arguments: { ecosystem: "npm", package: "lodash", version: "4.17.20" } }));
      assert.ok(t.includes(`check_affected with these arguments: {"ecosystem":"npm","package":"lodash","version":"4.17.20"}`), t);
      assert.match(t, /assessed false: NOT ASSESSED/);
      assert.match(t, /never report it as not affected or clean/);
    });
    it("sbom_review passes the document to check_sbom and states each ordering key", async () => {
      const t = textOf(await client.getPrompt({ name: "sbom_review", arguments: { sbom: SBOM } }));
      assert.ok(t.includes(`\`\`\`json\n${SBOM}\n\`\`\``));
      assert.match(t, /Call check_sbom with sbom set to the document below/);
      assert.match(t, /1\. CISA-KEV listed \(kev_listed true\) first; 2\. then EPSS score, highest first; 3\. then echelongraph_score/);
    });

    const BAD = [
      ["triage_cve with no arguments", "triage_cve", undefined],
      ["triage_cve with no cve_id", "triage_cve", {}],
      ["triage_cve with a cve_id that is not a CVE ID", "triage_cve", { cve_id: "log4shell" }],
      ["kev_weekly_brief with days 0", "kev_weekly_brief", { days: "0" }],
      ["kev_weekly_brief with days 366", "kev_weekly_brief", { days: "366" }],
      ["kev_weekly_brief with days that is not a number", "kev_weekly_brief", { days: "a week" }],
      ["am_i_affected with no version", "am_i_affected", { product: "openssl" }],
      ["am_i_affected with neither product nor package", "am_i_affected", { version: "1.0.0" }],
      ["am_i_affected with product and package both", "am_i_affected", { product: "openssl", ecosystem: "npm", package: "lodash", version: "1.0.0" }],
      ["am_i_affected with ecosystem but no package", "am_i_affected", { ecosystem: "npm", version: "1.0.0" }],
      ["sbom_review with no sbom", "sbom_review", {}],
      ["sbom_review with an empty sbom", "sbom_review", { sbom: "" }],
      ["a prompt that does not exist", "no_such_prompt", {}],
    ];
    for (const [what, name, args] of BAD) {
      it(`prompts/get ${what} is refused with InvalidParams`, async () => {
        await assert.rejects(client.getPrompt({ name, arguments: args }), invalidParams());
      });
    }
    it("prompts/get sbom_review with an sbom over check_sbom's 5,000,000-character cap is refused", async () => {
      await assert.rejects(client.getPrompt({ name: "sbom_review", arguments: { sbom: "x".repeat(5_000_001) } }), invalidParams(/check_sbom's cap/));
    });

    it("resources/list lists methodology and sources; resources/templates/list lists cve://{cve_id}", async () => {
      const { resources } = await client.listResources();
      assert.deepEqual(resources.map((r) => r.uri), RESOURCES);
      assert.deepEqual(resources.map((r) => r.mimeType), ["text/markdown", "application/json"]);
      const { resourceTemplates } = await client.listResourceTemplates();
      assert.deepEqual(resourceTemplates.map((r) => [r.name, r.uriTemplate, r.mimeType]), [["cve", "cve://{cve_id}", "application/json"]]);
      for (const r of [...resources, ...resourceTemplates]) {
        assert.ok(r.title && r.description, r.name);
        noClaims(r.name, `${r.title} ${r.description}`);
      }
    });

    it("resources/read echelongraph://methodology: every envelope field, every state, every tool", async () => {
      const r = await client.readResource({ uri: "echelongraph://methodology" });
      assert.equal(r.contents.length, 1);
      assert.equal(r.contents[0].uri, "echelongraph://methodology");
      assert.equal(r.contents[0].mimeType, "text/markdown");
      const t = r.contents[0].text;
      for (const f of ["state", "measured_at", "method", "coverage", "freshness", "notes", "data", "error"]) assert.ok(t.includes(`| ${f} |`), f);
      for (const s of ["measured", "not_assessed", "failed", "invalid_input"]) assert.ok(t.includes(`| ${s} |`), s);
      for (const tool of tools) assert.match(t, new RegExp(`\\b${tool}\\b`), `methodology does not say how ${tool} measures`);
      noClaims("methodology", t);
    });

    it("resources/read echelongraph://sources relays what the API reports, read at request time", async () => {
      mode = "up";
      seen.length = 0;
      const r = await client.readResource({ uri: "echelongraph://sources" });
      assert.equal(r.contents[0].mimeType, "application/json");
      const s = JSON.parse(r.contents[0].text);
      assert.equal(s.uri, "echelongraph://sources");
      assert.equal(s.api_base, env.ECHELONGRAPH_API_BASE);
      assert.ok(Date.parse(s.read_at) > 0);
      const [nvd, cisa] = s.sources;
      assert.equal(nvd.state, "reported");
      assert.deepEqual(nvd.reported, { interval: "2h0m0s", last_poll_at: "2026-10-03T10:00:00Z", poll_count: 12, poll_errors: 0 });
      assert.equal(cisa.state, "reported");
      assert.deepEqual(cisa.reported, { catalog: CATALOG, method: KEV_METHOD });
      assert.ok(s.not_reported.length > 0);
      noClaims("sources", r.contents[0].text);
      // #1983: the limit travels in a header, and nothing in a URL.
      const kev = seen.find((x) => x.path === "/api/v1/public/kev/recent");
      assert.deepEqual([kev.search, kev.limit], ["", "1"]);
      assert.ok(seen.some((x) => x.path === "/api/v1/public/cves/summary"));
    });
    it("echelongraph://sources hard-codes no cadence: a changed API answer changes the resource", async () => {
      mode = "no-poller";
      const s = JSON.parse((await client.readResource({ uri: "echelongraph://sources" })).contents[0].text);
      assert.equal(s.sources[0].state, "not_reported");
      assert.equal(s.sources[0].reported, null);
      assert.doesNotMatch(JSON.stringify(s.sources[0]), /2h0m0s|every/);
      mode = "down";
      const d = JSON.parse((await client.readResource({ uri: "echelongraph://sources" })).contents[0].text);
      assert.deepEqual(d.sources.map((x) => [x.state, x.error?.status]), [["failed", 404], ["failed", 404]]);
      mode = "up";
    });

    it(`resources/read cve://${CVE}: get_cve's structured result, as JSON`, async () => {
      const r = await client.readResource({ uri: `cve://${CVE}` });
      assert.equal(r.contents[0].uri, `cve://${CVE}`);
      assert.equal(r.contents[0].mimeType, "application/json");
      const s = JSON.parse(r.contents[0].text);
      assert.equal(s.state, "measured");
      assert.equal(s.measured_at, RECORD.updated_at);
      assert.deepEqual(s.data, RECORD);
      const call = await client.callTool({ name: "get_cve", arguments: { cve_id: CVE } });
      assert.deepEqual(s, call.structuredContent);
    });
    // #2736: triage_cve's step 6 feeds get_cve's kev_added_date to kev_recent. get_cve gives it as
    // RFC 3339; the prompt says to pass its date part, and kev_recent reads either as the same date.
    it("triage_cve step 6 composes: get_cve's kev_added_date, as given and as its date part, gets kev_recent's measured row and due date", async () => {
      const added = (await client.callTool({ name: "get_cve", arguments: { cve_id: CVE } })).structuredContent.data.kev_added_date;
      assert.equal(added, "2024-04-12T00:00:00Z");
      for (const v of [added, added.slice(0, 10)]) {
        seen.length = 0;
        const r = await client.callTool({ name: "kev_recent", arguments: { since: v, until: v } });
        assert.notEqual(r.isError, true, r.content[0].text);
        assert.equal(r.structuredContent.state, "measured");
        const req = seen.find((x) => x.path === "/api/v1/public/kev/recent");
        assert.deepEqual([req.since, req.until, req.search], ["2024-04-12", "2024-04-12", ""], v);
        assert.equal(r.structuredContent.data.kev.find((x) => x.cve_id === CVE)?.kev_due_date, "2024-04-19");
      }
    });
    it("cve:// upper-cases a lower-case CVE ID", async () => {
      const s = JSON.parse((await client.readResource({ uri: "cve://cve-2024-3400" })).contents[0].text);
      assert.deepEqual(s.data, RECORD);
    });
    for (const bad of ["cve://log4shell", "cve://CVE-2024", "cve://CVE-2024-3400x", "cve://CVE-2024-3400%2F..%2Fsummary"]) {
      it(`resources/read ${bad} is refused with InvalidParams, before any request`, async () => {
        seen.length = 0;
        await assert.rejects(client.readResource({ uri: bad }), invalidParams(/CVE ID/));
        assert.deepEqual(seen, []);
      });
    }
    it("cve:// for a CVE the API has no record of is ResourceNotFound, not an empty record", async () => {
      await assert.rejects(client.readResource({ uri: "cve://CVE-2024-0001" }), (e) => e instanceof RpcError && e.code === -32602 && /not found/i.test(e.message));
    });
    it("cve:// whose lookup fails is an error naming the failure, never a record", async () => {
      await assert.rejects(client.readResource({ uri: "cve://CVE-2024-9999" }), (e) => e instanceof RpcError && e.code === -32603 && /get_cve/.test(e.message) && e.data?.state === "failed");
    });
    it("a URI no resource serves is ResourceNotFound", async () => {
      await assert.rejects(client.readResource({ uri: "echelongraph://nothing" }), (e) => e instanceof RpcError);
    });
  });
}
