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
import { fileURLToPath, pathToFileURL } from "node:url";
import { connect, MODERN, RpcError } from "./mcp-stdio-client.mjs";
import { PKG_DIR, serverCommand } from "./server-under-test.mjs";

const ERAS = [MODERN, "2025-06-18"];
const PROMPTS = ["triage_cve", "kev_weekly_brief", "am_i_affected", "sbom_review", "workload_triage"];
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
// #2770: poller blocks carrying neither counter, or one of the two, served under their own modes.
const POLLER_MODES = {
  "poller-no-counters": { interval: "2h0m0s", last_poll_at: "2026-10-03T10:00:00Z" },
  "poller-errors-only": { interval: "2h0m0s", poll_errors: 3 },
  "poller-count-only": { last_poll_at: "2026-10-03T10:00:00Z", poll_count: 7 },
  // #2770's review: a poller of another JSON type (cve_summary leaves it out and names it, #2771),
  // and a JSON null one.
  "poller-array": [POLLER],
  "poller-string": "20m0s",
  "poller-null": null,
};
// #2770: what echelongraph://sources says of poll_count and poll_errors whenever it relays either.
// 2.6.3's resource relayed them with a note on interval and last_poll_at alone (production,
// 2026-10-04T12:09:45Z: poll_count 5, poll_errors 0, and that one note).
const POLLER_COUNTERS_NOTE =
  "poll_count and poll_errors, where reported carries them, are that one instance's counters since it last started, zeroed on every restart: they count that instance's polls and failed polls, never the feed's reliability.";
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
      "/api/v1/public/cves/summary": mode === "up" ? SUMMARY : mode === "no-poller" ? { summary: SUMMARY.summary } : Object.hasOwn(POLLER_MODES, mode) ? { summary: SUMMARY.summary, poller: POLLER_MODES[mode] } : null,
      "/api/v1/public/kev/recent": mode === "up" || mode === "no-poller" || Object.hasOwn(POLLER_MODES, mode) ? (day3400 ? KEV_3400 : KEV) : null,
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

// #2846: what workload_triage must say, as a list of what its text lacks or carries wrongly, so a
// control can hand it a changed copy. Exposure is the agent's, labelled caller-asserted, and
// EchelonGraph measured none of it; not_assessed rows are counted and never clean; the order is
// KEV, then exposure (exposed, unknown, not exposed), then EPSS, then score; check_sbom is sent
// purls, not the document; and no EchelonGraph internet-exposure tool is named, since its counts are
// not about the user's workloads and are no ranking input.
const SBOM_TOOLS = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "check_sbom.js")).href);
const WORKLOAD_MUST = [
  ["caller-asserted exposure", /label it caller-asserted/],
  ["EchelonGraph measured none of it", /EchelonGraph measured none of (this|it)/],
  ["the closing caller-asserted statement", /Say plainly that every exposure label is caller-asserted: it came from the user's own cluster or CI data, read by you, and EchelonGraph measured none of it\./],
  ["not_assessed is never clean", /not_assessed are not clean/],
  ["the OS-package not_assessed count", /state how many of its OS-package rows are not_assessed, and never count them as clean/],
  ["the upstream qualifier", /a deb or apk purl without an upstream qualifier/],
  ["the order", /1\. a workload with a KEV-listed CVE \(kev_listed true\) first; 2\. then exposure: exposed, then unknown, then not exposed; 3\. then the highest epss_score, highest first; 4\. then the highest score/],
  ["unknown is never not exposed", /Unknown is never treated as not exposed\./],
  ["purls, not the document", /Pass purls, not the SBOM document/],
  ["no workload data in arguments", /put no workload, namespace, image or registry name, no credential and no exposure label into any argument of any EchelonGraph tool/],
  ["the call", /Call check_sbom with purls set to/],
];
const WORKLOAD_MUST_NOT = [
  ["an EchelonGraph exposure tool as a ranking input", /\b(cve_exposure|exposure_radar)\b/],
  ["the SBOM document passed to check_sbom", /check_sbom with sbom set to/],
  ["the match_reason prose", /match_reason/],
];
// Where check_sbom's routing sentence ends in a description: past the cut, or Infinity where it is
// not there, fails the head check.
const routingEnd = (d) => {
  const at = d.indexOf(SBOM_TOOLS.CHECK_SBOM_ROUTING);
  return at < 0 ? Infinity : at + SBOM_TOOLS.CHECK_SBOM_ROUTING.length;
};
const CLIENT_CUT = 2048;
function workloadProblems(t) {
  return [
    ...WORKLOAD_MUST.filter(([, re]) => !re.test(t)).map(([what]) => `lacks ${what}`),
    ...WORKLOAD_MUST_NOT.filter(([, re]) => re.test(t)).map(([what]) => `carries ${what}`),
  ];
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

    it("prompts/list lists the five prompts with their arguments", async () => {
      const { prompts } = await client.listPrompts();
      assert.deepEqual(prompts.map((p) => p.name), PROMPTS);
      const args = Object.fromEntries(prompts.map((p) => [p.name, p.arguments.map((a) => [a.name, a.required])]));
      assert.deepEqual(args, {
        triage_cve: [["cve_id", true]],
        kev_weekly_brief: [["days", false]],
        am_i_affected: [["product", false], ["ecosystem", false], ["package", false], ["version", true]],
        sbom_review: [["sbom", true]],
        workload_triage: [["source", false]],
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
      ["triage_cve", { cve_id: "cve-2024-3400" }, ["get_cve", "cve_intel", "cve_remediation", "vendor_advisories_for_cve", "epss_history", "cve_exposure"]],
      ["kev_weekly_brief", undefined, ["kev_recent"]],
      ["kev_weekly_brief_30", { days: "30" }, ["kev_recent"]],
      ["am_i_affected_product", { product: "openssl", version: "3.0.0" }, ["check_affected"]],
      ["am_i_affected_registry", { ecosystem: "npm", package: "lodash", version: "4.17.20" }, ["check_affected"]],
      ["sbom_review", { sbom: SBOM }, ["check_sbom", "get_cve", "cve_intel", "cve_remediation"]],
      ["workload_triage", undefined, ["check_sbom", "get_cve"]],
      ["workload_triage_kubernetes", { source: "kubernetes" }, ["check_sbom", "get_cve"]],
      ["workload_triage_github_actions", { source: "github_actions" }, ["check_sbom", "get_cve"]],
      ["workload_triage_images", { source: "images" }, ["check_sbom", "get_cve"]],
    ];
    for (const [snap, args, named] of GETS) {
      it(`prompts/get ${snap}: names ${named.join(", ")} in order, carries the envelope rules, matches its snapshot`, async () => {
        const name = snap.replace(/_(30|product|registry|kubernetes|github_actions|images)$/, "");
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

    it("#2834: am_i_affected's registry text reads each match's fixed_in, and its product text, whose CPE matches carry none, names none", async () => {
      const reg = textOf(await client.getPrompt({ name: "am_i_affected", arguments: { ecosystem: "Maven", package: "org.apache.logging.log4j:log4j-core", version: "2.14.1" } }));
      assert.match(reg, /For each match, give its fixed_in where it is a version: the fixed bound of the advisory interval that holds this version\. Where fixed_in is null or absent, write that the result gives no fixed version for this version's range, which is not a finding that no fix exists\./);
      const cpe = textOf(await client.getPrompt({ name: "am_i_affected", arguments: { product: "openssl", version: "3.0.0" } }));
      assert.doesNotMatch(cpe, /fixed_in/);
    });
    it("#2834: sbom_review reads fixed_in first, null as no fix on that branch, and the match_reason and cve_intel rule where a match carries none", async () => {
      const own = textOf(await client.getPrompt({ name: "sbom_review", arguments: { sbom: SBOM } })).split("\nSBOM:\n")[0];
      const rule = own.split("\n").find((l) => l.startsWith("For each line give the component"));
      const at = (re) => rule.search(re);
      assert.ok(at(/First, where the text keeps the component's match for the CVE and the match carries fixed_in: a version there is the fixed bound of the advisory interval that holds the installed version, so give it as the fixed version; null says the advisory records no fixed version for the installed version's range, so give none for that CVE on that component/) >= 0, rule);
      assert.ok(at(/Where the match has no fixed_in field, or the text keeps no match for the component, the rest of this rule applies\./) >= 0, rule);
      // fixed_in comes before the match_reason prose and cve_intel's values.
      assert.ok(at(/carries fixed_in/) < at(/Prefer the match's match_reason/) && at(/carries fixed_in/) < at(/fixed_branches/), rule);
    });
    it("#2841: triage_cve and sbom_review read cve_remediation's vendor remediation as the vendor's, untested, and not_parsed and none_in_source as no finding of no fix", async () => {
      const triage = textOf(await client.getPrompt({ name: "triage_cve", arguments: { cve_id: CVE } }));
      const patch = triage.split("\n").find((l) => l.startsWith("- Patch:"));
      const review = textOf(await client.getPrompt({ name: "sbom_review", arguments: { sbom: SBOM } })).split("\nSBOM:\n")[0];
      for (const [where, t] of [["triage_cve's Patch line", patch], ["sbom_review", review]]) {
        assert.match(t, /a workaround or mitigation as the step that vendor states, which EchelonGraph has not tested and which is not a fix/, where);
        assert.match(t, /a remediation_state of not_parsed or none_in_source is not a finding that the vendor lists no fix/, where);
      }
      assert.match(triage, /^3\. cve_remediation: how it is fixed, as its sources state it/m);
      assert.match(review, /Then, for the first 5 CVEs of the list \(fewer if it has fewer\), call cve_remediation with the CVE's cve_id/);
    });
    it("#2846: workload_triage says each thing it must, in every source's text, and names no EchelonGraph exposure tool", async () => {
      for (const args of [undefined, {}, { source: "kubernetes" }, { source: "github_actions" }, { source: "images" }]) {
        const t = textOf(await client.getPrompt({ name: "workload_triage", arguments: args }));
        assert.deepEqual(workloadProblems(t), [], JSON.stringify(args));
        // Exposure is never sourced from EchelonGraph: the text names neither of its exposure tools.
        for (const tool of ["cve_exposure", "exposure_radar"]) assert.ok(tools.has(tool) && !t.includes(tool), tool);
      }
      const k8s = textOf(await client.getPrompt({ name: "workload_triage", arguments: { source: "kubernetes" } }));
      assert.match(k8s, /kubectl get pods -A -o json/);
      assert.match(k8s, /\.status\.containerStatuses\[\]\.imageID/);
      assert.match(k8s, /hostNetwork: true/);
      assert.doesNotMatch(k8s, /\.github\/workflows/, "a kubernetes text lists another source");
      const gha = textOf(await client.getPrompt({ name: "workload_triage", arguments: { source: "github_actions" } }));
      assert.match(gha, /container: and services:/);
      assert.doesNotMatch(gha, /kubectl/, "a github_actions text lists another source");
      // With no source, every way of listing is described.
      const all = textOf(await client.getPrompt({ name: "workload_triage" }));
      for (const re of [/kubectl get pods/, /\.github\/workflows/, /the image references the user gives you/]) assert.match(all, re);
    });
    it("#2846: check_sbom's description carries its container-image routing sentence inside the client cut", async () => {
      const d = (await client.listTools()).tools.find((t) => t.name === "check_sbom").description;
      assert.match(SBOM_TOOLS.CHECK_SBOM_ROUTING, /container images and Kubernetes pods/);
      assert.ok(routingEnd(d) <= CLIENT_CUT, `the routing sentence ends at ${routingEnd(d)}: ${d}`);
      assert.ok(d.length <= CLIENT_CUT, `check_sbom's description is ${d.length} characters`);
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
      ["workload_triage with a source it does not know", "workload_triage", { source: "docker" }],
      ["workload_triage with an empty source", "workload_triage", { source: "" }],
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
      // #2771's review: cve_summary's data is the API's JSON less a poller field of another JSON
      // type, so the data row names it beside the tools that relay a selection.
      const dataRow = t.split("\n").find((l) => l.startsWith("| data |"));
      assert.equal(
        dataRow,
        "| data | On a success: the API's JSON (exposure_radar and cve_intel relay a labelled selection, and cve_summary leaves out a poller field of another JSON type, named in the note). |",
      );
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
    it("#2770: whenever reported carries poll_count or poll_errors, notes says they are that one instance's counters since it last started, zeroed on every restart, never the feed's reliability", async () => {
      const nvdIn = async (m) => {
        mode = m;
        try {
          return JSON.parse((await client.readResource({ uri: "echelongraph://sources" })).contents[0].text).sources[0];
        } finally {
          mode = "up";
        }
      };
      for (const [m, counters] of [
        ["up", { poll_count: 12, poll_errors: 0 }],
        ["poller-errors-only", { poll_errors: 3 }],
        ["poller-count-only", { poll_count: 7 }],
      ]) {
        const nvd = await nvdIn(m);
        assert.equal(nvd.state, "reported", m);
        for (const [k, v] of Object.entries(counters)) assert.equal(nvd.reported[k], v, `${m}: ${k}`);
        assert.ok(nvd.notes.includes(POLLER_COUNTERS_NOTE), `${m}: the counters are relayed without the sentence saying whose they are: ${nvd.notes.join(" | ")}`);
      }
      // The other polarity: a block carrying neither counter gets no sentence about them.
      const bare = await nvdIn("poller-no-counters");
      assert.deepEqual(bare.reported, POLLER_MODES["poller-no-counters"]);
      assert.equal(bare.notes.length, 1, bare.notes.join(" | "));
      assert.doesNotMatch(bare.notes.join(" "), /poll_count|poll_errors/);
    });
    it("#2770: a poller the answer sends as an array or a string is named as such, never as a missing block; a null one carries no block", async () => {
      const nvdIn = async (m) => {
        mode = m;
        try {
          return JSON.parse((await client.readResource({ uri: "echelongraph://sources" })).contents[0].text).sources[0];
        } finally {
          mode = "up";
        }
      };
      for (const [m, kind] of [
        ["poller-array", "an array"],
        ["poller-string", "a string"],
      ]) {
        const nvd = await nvdIn(m);
        assert.equal(nvd.state, "not_reported", m);
        assert.equal(nvd.reported, null, m);
        assert.deepEqual(nvd.notes, [`The answer carries poller as ${kind}, where a JSON object was expected, so it reports neither a poll interval nor a last poll time.`], m);
      }
      const none = await nvdIn("poller-null");
      assert.equal(none.state, "not_reported");
      assert.deepEqual(none.notes, ["The answer carries no poller block, so it reports neither a poll interval nor a last poll time."]);
    });
    it("#2770: the sources resource's description names what reported carries, its counters as the one instance's", async () => {
      const { resources } = await client.listResources();
      const d = resources.find((r) => r.uri === "echelongraph://sources").description;
      for (const f of ["interval", "last poll", "poll_count", "poll_errors"]) assert.ok(d.includes(f), `the description does not name ${f}: ${d}`);
      assert.match(d, /the one instance that answered \(the two counts since that instance last started, zeroed on every restart, never the feed's reliability\)/, d);
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
      // #2801: a record that fits is the structured result pretty-printed, character for character
      // as through 2.6.3; past 30,000 characters data is cut (text-bound.test.mjs).
      assert.equal(r.contents[0].text, JSON.stringify(call.structuredContent, null, 2));
    });
    // #2736: get_cve's kev_added_date, fed to kev_recent, as triage_cve's step 6 did through 2.6.3.
    // get_cve gives it as RFC 3339, and kev_recent reads it, or its date part, as the same date.
    it("kev_recent reads get_cve's kev_added_date, as given and as its date part, and answers that day's row and due date", async () => {
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
    // #2799 review: triage_cve reads the due date from get_cve's record, not from a kev_recent page
    // of one day, which on a day of more than a page (2021-11-03: 287) need not hold the CVE's row.
    it("triage_cve reads kev_due_date from get_cve, whose record carries it, and calls no kev_recent", async () => {
      const t = textOf(await client.getPrompt({ name: "triage_cve", arguments: { cve_id: CVE } }));
      assert.match(t, /1\. get_cve: .*the CISA-KEV fields kev_listed, kev_added_date, kev_due_date and kev_ransomware, and, where the record carries it, kev_required_action, CISA's own text\./);
      assert.match(t, /- Deadline: get_cve's kev_due_date when the CVE is KEV-listed/);
      // #2839: CISA's required action is quoted as CISA's, never as EchelonGraph's advice.
      assert.match(t, /Where get_cve carries kev_required_action, quote it, attributed to CISA, as the action CISA requires of those agencies, not as EchelonGraph's advice\./);
      assert.doesNotMatch(t, /kev_recent/);
      const call = await client.callTool({ name: "get_cve", arguments: { cve_id: CVE } });
      assert.equal(JSON.parse(call.content[0].text).kev_due_date, RECORD.kev_due_date);
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

// #2846 controls: each clause workloadProblems reads, taken out of (or put into) the served text,
// fails it; and the routing check fails with the sentence moved past the cut.
describe("#2846 controls: workload_triage's checker and check_sbom's routing head", () => {
  let base;
  before(async () => {
    const P = await import(pathToFileURL(path.join(PKG_DIR, "dist", "prompts.js")).href);
    base = P.workloadTriageText("kubernetes");
    assert.deepEqual(workloadProblems(base), []);
  });
  const without = (re) => {
    assert.ok(re.test(base), `re-aim this control: the text no longer holds ${re}`);
    return base.replace(re, "");
  };
  it("dropping the caller-asserted label fails it", () => {
    assert.ok(workloadProblems(without(/label it caller-asserted/)).includes("lacks caller-asserted exposure"));
  });
  it("dropping 'EchelonGraph measured none of' fails it", () => {
    assert.ok(workloadProblems(base.replaceAll(/EchelonGraph measured none of (this|it)/g, "")).includes("lacks EchelonGraph measured none of it"));
  });
  it("dropping the not_assessed clauses fails it", () => {
    assert.ok(workloadProblems(without(/not_assessed are not clean/)).includes("lacks not_assessed is never clean"));
    assert.ok(workloadProblems(without(/state how many of its OS-package rows are not_assessed, and never count them as clean/)).includes("lacks the OS-package not_assessed count"));
  });
  it("exposure sorted before KEV, or unknown after not exposed, fails it", () => {
    const swapped = base.replace("1. a workload with a KEV-listed CVE (kev_listed true) first; 2. then exposure: exposed, then unknown, then not exposed;", "1. exposure: exposed, then unknown, then not exposed; 2. then a workload with a KEV-listed CVE (kev_listed true);");
    assert.notEqual(swapped, base);
    assert.ok(workloadProblems(swapped).includes("lacks the order"));
    const unsafe = base.replace("exposed, then unknown, then not exposed", "exposed, then not exposed, then unknown");
    assert.notEqual(unsafe, base);
    assert.ok(workloadProblems(unsafe).includes("lacks the order"));
  });
  it("naming cve_exposure or exposure_radar, or passing the document, fails it", () => {
    assert.ok(workloadProblems(`${base}\nRank exposure by cve_exposure's exposed_hosts.`).includes("carries an EchelonGraph exposure tool as a ranking input"));
    assert.ok(workloadProblems(`${base}\nUse exposure_radar for the totals.`).includes("carries an EchelonGraph exposure tool as a ranking input"));
    assert.ok(workloadProblems(base.replace("Call check_sbom with purls set to", "Call check_sbom with sbom set to")).length >= 2);
  });
  it("the routing sentence moved past 2,048 characters is out of the head", () => {
    const r = SBOM_TOOLS.CHECK_SBOM_ROUTING;
    const d = SBOM_TOOLS.CHECK_SBOM_DESCRIPTION;
    assert.ok(routingEnd(d) <= CLIENT_CUT);
    assert.ok(routingEnd(`${d.replace(r, "")} ${"x".repeat(CLIENT_CUT)} ${r}`) > CLIENT_CUT, "moved past the cut, the sentence still reads as in the head");
    assert.equal(routingEnd(d.replace(r, "")), Infinity, "dropped, the sentence still reads as in the head");
  });
});
