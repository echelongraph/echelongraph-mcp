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
  // #3269's review: at the leanest cut matches_truncated keeps total and returned alone.
  ["matches_truncated without its lists", /where it has total and returned and neither list \(the leanest cut\), nothing in the answer names the row's KEV-listed or ransomware CVEs, and the get_cve calls below read them/],
  // #3269's second review: the counts are data.summary's (a call per image where several images'
  // rows were left out); a left-out not_affected or not_assessed row is not checked again; only the
  // affected and undetermined rows the DATA CUT names by index are, in calls of those purls alone,
  // and past a few calls the rest are reported unchecked. Round 2 checked every purl left out
  // again at the page size: 332 calls on a realistic Debian SBOM.
  ["the counts from data.summary", /6\. data\.summary counts every row of a call whatever the cut: affected, not_affected, undetermined and not_assessed, and not_assessed_by_reason\. Take each image's counts from it, and a workload's from its images'/],
  ["a call per image for its counts", /and the call carried several images' purls, call check_sbom with one image's purls per call for its counts\./],
  ["clean rows left out are not checked again", /A row left out whose verdict is not_affected or not_assessed is not checked again: data\.summary counts it, and it holds no CVE;/],
  // #3269's third review: the note names the rows with a KEV-listed or ransomware match first and
  // apart, and step 6 checks them again first (round 3 checked them in index order, and on old
  // unpatched images 119 of 255 were in view after its 5 calls); its calls are of the sizes the
  // note's re-check sentence gives, counted for those rows, never of the page sentence's N, which
  // holds for the first N purls sent (round 3's calls of N dropped 504 of 2,540 rows).
  ["the affected rows named by index, KEV-bearing first", /The affected and undetermined rows that left data are the ones checked again: the DATA CUT sentence names them by index, those with a KEV-listed or ransomware match first and apart \("affected or undetermined rows: the K with a KEV-listed or ransomware match at index …; the other K at index …"\), each index the position, from 0, of a purl among the distinct purls you sent, in the order you sent them\./],
  ["re-checked KEV-bearing first", /Call check_sbom again with those purls alone as purls, in the order the note names them, so those with a KEV-listed or ransomware match first,/],
  ["the re-check sentence's sizes, not N", /in calls of the sizes its re-check sentence gives \("Re-check these K purls in this order, in calls of …"; a purl it sends to a call of its own goes alone\), not of the page sentence's N, which holds for the first N purls you sent and not for these;/],
  ["a few calls, then report", /If that takes more than 5 calls, stop after 5 and report the affected and undetermined rows not checked again, by purl where the note names them and by count, as unchecked, never as clean\./],
  // #3269's fourth review: the first text block leaves rows out from the end, in input order, while
  // data keeps the KEV-bearing rows first, and workload_triage had no step for the rows the text
  // left out, so a client reading the text alone lost them, KEV-bearing ones among them, unsaid.
  ["the rows left out of the first text block, in structuredContent.data or counted as unchecked", /Where the note says that rows of data\.results are left out of the first text block, those rows are in structuredContent\.data, .*?: where you can read it, read them there as in steps 5 and 6\. Where you read the text alone, list the rows it carries, say how many affected rows it leaves out \(data\.summary\.affected, less those listed\), and give the undetermined and not_assessed rows it leaves out as data\.summary\.undetermined and data\.summary\.not_assessed \(by not_assessed_by_reason\), less those listed, as unchecked, never as clean\./],
  // 3.1.0's phase B review: where a DATA CUT applies too (the large-image case the line is for),
  // the rows the text leaves out need not be in default data: the note names those that left data
  // by index, for step 6's re-check. 700 affected purls, KEV-listed late: 458 of the 514 rows the
  // text left out were not in default data, 44 of them with a KEV-listed match.
  ["the rows a DATA CUT leaves out of data too, named by index for step 6", /those rows are in structuredContent\.data, or, where a DATA CUT leaves rows out of data too, named there by index for step 6's re-check \(the note says data holds them whole with full: true\): where you can read it, read them there as in steps 5 and 6\./],
  // #3284: the first text block keeps the KEV-bearing rows last to leave and names by index each
  // of them it leaves out; read from the text alone, those are listed as KEV-bearing, unchecked.
  ["the KEV-bearing rows the text leaves out, named by index", /The rows with a KEV-listed or ransomware match leave the text last, and the note names by index each of them it leaves out \("Of the rows left out of it, K have a KEV-listed or ransomware match: at index …"\): list those as KEV-bearing rows not checked, by index, never as clean\./],
];
const WORKLOAD_MUST_NOT = [
  ["an EchelonGraph exposure tool as a ranking input", /\b(cve_exposure|exposure_radar)\b/],
  // #3269's second review: round 2's step 6, every purl left out checked again at the page size.
  ["every purl left out checked again", /the purls you sent that no row you read carries/],
  ["round 2's page sentence", /check N or fewer purls per call/],
  // #3269's third review: round 3's step 6 sized its calls by the page sentence.
  ["round 3's re-check size", /at most as many per call as the note's page sentence names/],
  ["the SBOM document passed to check_sbom", /check_sbom with sbom set to/],
  ["the match_reason prose", /match_reason/],
  // 3.1.0's phase B review: d42d4697's line said the rows the text leaves out are in data, read as in step 5.
  ["the rows left out of the text said to be in data, whatever the DATA CUT", /those rows are in structuredContent\.data: where you can read it, read them there as in step 5\./],
  // 3.1.0's phase B review: data.summary's counts include the undetermined and not_assessed rows
  // the text still lists, so "as data.summary's counts" over-counts the rows it leaves out.
  ["the undetermined and not_assessed rows left out counted as data.summary's whole counts", /rows it leaves out as data\.summary's counts/],
  // #3284: d42d4697's line said a row the text leaves out can hold a KEV-listed CVE it does not name.
  ["a KEV-bearing row left out of the text unnamed", /a row it leaves out can hold a KEV-listed CVE that the text does not name/],
];
// Where check_sbom's routing sentence ends in a description: past the cut, or Infinity where it is
// not there, fails the head check.
const routingEnd = (d) => {
  const at = d.indexOf(SBOM_TOOLS.CHECK_SBOM_ROUTING);
  return at < 0 ? Infinity : at + SBOM_TOOLS.CHECK_SBOM_ROUTING.length;
};
const CLIENT_CUT = 2048;
// #2924: every tool description keeps DESCRIPTION_HEADROOM characters under the cut, so a wording
// fix (such as one the #1880 field guard forces) lands without a rewrite under pressure. Through
// 2.7.0 check_affected was 2 characters under it, check_sbom 5 and vendor_advisories_for_cve 10.
const DESCRIPTION_HEADROOM = 100;
const headroomProblems = (tools) =>
  tools
    .filter((t) => (t.description ?? "").length > CLIENT_CUT - DESCRIPTION_HEADROOM)
    .map((t) => `${t.name}: ${t.description.length} characters, ${CLIENT_CUT - t.description.length} under the ${CLIENT_CUT}-character cut; the floor is ${DESCRIPTION_HEADROOM}`);
// #3269's fourth review: what sbom_review's steps 1 and 3 must say, as a list of what they lack.
function sbomRound4Problems(own) {
  const lines = own.split("\n");
  const step1 = lines.find((l) => l.startsWith("1. ")) ?? "";
  const step3 = lines.find((l) => l.startsWith("3. ")) ?? "";
  const out = [];
  if (!/metadata\.component, the document's own subject, is not counted, so its purl, such as an image's pkg:oci, has no index/.test(step1)) out.push("step 1 counts metadata.component or does not say");
  if (!/check your mapping against the rows data keeps, each of which carries its index and its purl, before you send these calls/.test(step1)) out.push("step 1 does not check its mapping against data's rows");
  // 3.1.0's phase B review: fromSPDX counts every package with a purl, an SPDX document's root
  // (image) package among them; "the document's own subject is not counted", read as general,
  // had an agent skip that package's index.
  if (!/has no index; an SPDX document has no metadata\.component: each of its packages with a purl is counted, its root package among them;/.test(step1)) out.push("step 1 does not say an SPDX document's root package is counted");
  if (!/If there are more than 30 distinct CVEs, do this for 30 of them, chosen KEV-listed first: those whose check_sbom matches carry kev_listed true, or that a row's matches_truncated\.kev_listed_cve_ids names, then the others by highest epss_score/.test(step3)) out.push("step 3 does not take the KEV-listed CVEs first past 30");
  if (!/each read for this choice from the check_sbom matches where the text or data keeps them, not from a get_cve call per CVE/.test(step3)) out.push("step 3 does not read the choice from the matches");
  return out;
}
// 3.1.0's phase B review: sbom_review's text-alone line gives the undetermined and not_assessed
// components the first text block leaves out as data.summary's counts less those listed, as it
// gives the affected count; data.summary counts every row, the listed ones among them.
function sbomTextAloneProblems(own) {
  const line = own.split("\n").find((l) => l.startsWith("Where the note says that rows of data.results are left out of the first text block")) ?? "";
  const out = [];
  if (!/say how many affected components the text leaves out \(data\.summary\.affected, less those listed\), and give the undetermined and not_assessed components it leaves out as data\.summary\.undetermined and data\.summary\.not_assessed \(by not_assessed_by_reason\), less those listed, as not checked, never as clean\./.test(line)) out.push("the undetermined and not_assessed components left out are not counted less those listed");
  if (/components it leaves out as data\.summary's counts/.test(line)) out.push("the undetermined and not_assessed components left out are counted as data.summary's whole counts");
  // #3284: the KEV-bearing rows the first text block leaves out, named by index in its note.
  if (!/The components with a KEV-listed or ransomware match leave the text last, and the note names by index each of them it leaves out \("Of the rows left out of it, K have a KEV-listed or ransomware match: at index …"\): list those as KEV-bearing components not checked, by index, never as clean\./.test(line)) out.push("the KEV-bearing components the text leaves out are not listed by index");
  return out;
}
// #3285 (3.1.0's lane P): sbom_review's fixed_branches rule, applied as it reads to cve_intel's
// affected_packages rows: the row for the component's ecosystem and package, or, where the rule
// says a Packagist or Maven component's rows of its package_name, bare and with a repository URL
// after ":", are one row, all of those rows; then the walk from the range that holds the installed
// version. Versions here are plain release numbers. CVE-2025-48013's rows for
// drupal/quick_node_block (Packagist:https://packages.drupal.org/8 [0, 2.0.1), Packagist [0, 2.0.0))
// are the fixture's.
const DRUPAL_ROWS = JSON.parse(fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures", "cve_remediation-CVE-2025-48013.json"), "utf8")).data.fixed_branches;
const SBOM_ONE_ROW = /for a Packagist or Maven component, the rows of its package_name under that ecosystem, bare and with a repository URL after ":", such as Packagist and Packagist:https:\/\/packages\.drupal\.org\/8, are one row, their ranges all together, as cve_intel's note says; rows of two releases, such as Debian:11 and Debian:12, never are/;
const TRIAGE_ONE_PACKAGE = /cve_intel rows of one package_name under Packagist or Maven, bare or with a repository URL after ":" \(such as Packagist and Packagist:https:\/\/packages\.drupal\.org\/8\), are one package, as cve_intel's note says: give their ranges together, and never a range's fixed that another of those ranges still holds as a fix, since that version is still affected; rows of two releases \(Debian:11 and Debian:12\) are two packages\./;
const relNum = (a, b) => {
  const [pa, pb] = [a, b].map((v) => v.split(".").map(Number));
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) < (pb[i] ?? 0) ? -1 : 1;
  return 0;
};
const rangeHolds = (r, v) => relNum(v, r.introduced) >= 0 && (r.fixed ? relNum(v, r.fixed) < 0 : r.last_affected ? relNum(v, r.last_affected) <= 0 : true);
function fixBySbomRule(rule, rows, { ecosystem, pkg, installed }) {
  const base = (e) => e.toLowerCase().split(":")[0];
  const grouped = SBOM_ONE_ROW.test(rule) && ["packagist", "maven"].includes(base(ecosystem));
  const mine = rows.filter((e) => e.package_name.toLowerCase() === pkg.toLowerCase() && (grouped ? base(e.ecosystem) === base(ecosystem) : e.ecosystem === ecosystem));
  const ranges = mine.flatMap((e) => e.fixed_branches ?? []);
  let r = ranges.find((x) => rangeHolds(x, installed));
  const walked = new Set();
  while (r) {
    if (!r.fixed || walked.has(r)) return null;
    walked.add(r);
    const v = r.fixed;
    r = ranges.find((x) => rangeHolds(x, v));
    if (!r) return v;
  }
  return null;
}
// #3283: what the kubernetes exposure rule must say (the kubernetes text, and the text with no
// source, which describes all three): a container hostPort and a Service's externalIPs reach a
// pod as the paths it listed do, and "not exposed" requires having read both. Through 3.0.2 it
// named neither, so a hostPort DaemonSet or a ClusterIP Service with externalIPs read not exposed.
const K8S_EXPOSURE_MUST = [
  ["a container hostPort as exposed", /a container of the pod sets a hostPort \(spec\.containers\[\]\.ports\[\]\.hostPort, which binds that port on the node's IP\)/],
  ["a Service's externalIPs as exposed", /a Service that selects it lists externalIPs \(spec\.externalIPs, on which nodes accept its traffic whatever its type, ClusterIP included\)/],
  ["the listed paths as exposed", /exposed means a Service of type LoadBalancer or NodePort selects the pod, .*an Ingress \(or a Gateway route\) sends traffic to a Service that selects it, .*or the pod sets hostNetwork: true;/],
  ["not exposed only after reading the ports and the externalIPs", /not exposed means you read the pod's spec, its containers' ports among it, and the cluster's Services, with their type and externalIPs, Ingresses and routes, and none of these holds/],
];
const k8sExposureProblems = (t) => K8S_EXPOSURE_MUST.filter(([, re]) => !re.test(t)).map(([what]) => `lacks ${what}`);
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
      ["sbom_review", { sbom: SBOM }, ["check_sbom", "get_cve", "cve_intel", "cve_remediation", "get_vendor_advisory"]],
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
    // #3221: a github_checker row (a GitHub repository named or described as a checker or scanner,
    // #3040) is a detection check like a Nuclei template; the Exploited? line's "GitHub or vendor
    // proofs of concept" alone read as taking one in.
    it("#3221: triage_cve reads a github_checker row as a detection check, given apart from exploit code", async () => {
      const t = textOf(await client.getPrompt({ name: "triage_cve", arguments: { cve_id: "CVE-2020-35489" } }));
      const step = t.split("\n").find((l) => l.startsWith("2. cve_intel:"));
      assert.ok(step.includes("a github_checker row a GitHub repository named or described as a checker or scanner: each checks whether a system is affected and is not necessarily exploit code"), step);
      const exploited = t.split("\n").find((l) => l.startsWith("- Exploited?"));
      assert.ok(exploited.endsWith("give Nuclei detection templates and GitHub checker repositories apart, as detection checks, never as exploit code."), exploited);
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

    // #3269's third review (F3): sbom_review had no step for the affected and undetermined rows a
    // DATA CUT leaves out of data, so a cut SBOM's fix list lacked them unsaid (Claude Code reads
    // structuredContent, not the text). Step 1 now checks them again by index, those with a
    // KEV-listed or ransomware match first, in calls of the sizes the note's re-check sentence
    // gives, at most 5 calls, and lists the rest as unchecked. Control: 9f97d479's text lacks it.
    it("#3269's third review: sbom_review checks again the affected rows a DATA CUT leaves out, KEV-bearing first, at the note's re-check sizes, in at most 5 calls, and lists the rest as unchecked", async () => {
      const own = textOf(await client.getPrompt({ name: "sbom_review", arguments: { sbom: SBOM } })).split("\nSBOM:\n")[0];
      const step = own.split("\n").find((l) => l.startsWith("1. "));
      assert.ok(
        step.includes(
          "Where a DATA CUT sentence names affected or undetermined rows of results left out of data, by index, those with a KEV-listed or ransomware match first and apart, call check_sbom again with purls set to the purls at those indices (each index the position, from 0, of a purl among the document's distinct purls, counted in the order check_sbom reads them: components or packages in document order, each component's nested components right after it, each purl at its first place; metadata.component, the document's own subject, is not counted, so its purl, such as an image's pkg:oci, has no index; an SPDX document has no metadata.component: each of its packages with a purl is counted, its root package among them; check your mapping against the rows data keeps, each of which carries its index and its purl, before you send these calls), in the order the note names them and in calls of the sizes its re-check sentence gives (\"Re-check these K purls in this order, in calls of …\"; a purl it sends to a call of its own goes alone), at most 5 such calls, and review their rows with the others; list the affected and undetermined rows not checked again, by index and by count, as unchecked, never as clean.",
        ),
        step,
      );
      assert.doesNotMatch(own, /page sentence's N|A call of the first N of these purls/, "sbom_review sizes its re-check calls by the page sentence");
    });

    // #3269's fourth review: step 1's index rule said nothing of metadata.component, which
    // check_sbom does not read (fromCycloneDX walks doc.components alone; Trivy's metadata.component
    // carries the image's pkg:oci purl), so an agent counting it sent every re-check purl one off;
    // and past 30 distinct CVEs step 3 looked up any 30, so the KEV-listed ones could be among those
    // not looked up, although the matches say which they are. Controls: 0bb8b2d3's steps 1 and 3.
    it("#3269's fourth review: sbom_review's index rule leaves metadata.component out (an SPDX document's root package is counted) and checks the mapping against data's rows; past 30 CVEs it looks up the KEV-listed ones first, read from the matches", async () => {
      const own = textOf(await client.getPrompt({ name: "sbom_review", arguments: { sbom: SBOM } })).split("\nSBOM:\n")[0];
      assert.deepEqual(sbomRound4Problems(own), []);
      const step1 = own.split("\n").find((l) => l.startsWith("1. "));
      const step3 = own.split("\n").find((l) => l.startsWith("3. "));
      const old1 = step1.replace("; metadata.component, the document's own subject, is not counted, so its purl, such as an image's pkg:oci, has no index; an SPDX document has no metadata.component: each of its packages with a purl is counted, its root package among them; check your mapping against the rows data keeps, each of which carries its index and its purl, before you send these calls)", ")");
      // 3.1.0's phase B review: d42d4697's step 1, without the SPDX clause.
      const spdx = "; an SPDX document has no metadata.component: each of its packages with a purl is counted, its root package among them";
      const oldB = step1.replace(spdx, "");
      const old3 = step3.replace(/, chosen KEV-listed first: .*?; list the rest as not looked up, unranked\./, " and list the rest as not looked up, unranked.");
      assert.notEqual(old1, step1, "re-aim this control: step 1 no longer holds the clause");
      assert.notEqual(old3, step3, "re-aim this control: step 3 no longer holds the clause");
      assert.ok(old3.endsWith("If there are more than 30 distinct CVEs, do this for 30 of them and list the rest as not looked up, unranked."), old3);
      assert.notEqual(oldB, step1, "re-aim this control: step 1 no longer holds the SPDX clause");
      assert.deepEqual(sbomRound4Problems(own.replace(step1, old1)), ["step 1 counts metadata.component or does not say", "step 1 does not check its mapping against data's rows", "step 1 does not say an SPDX document's root package is counted"]);
      assert.deepEqual(sbomRound4Problems(own.replace(step1, oldB)), ["step 1 does not say an SPDX document's root package is counted"]);
      assert.deepEqual(sbomRound4Problems(own.replace(step3, old3)), ["step 3 does not take the KEV-listed CVEs first past 30", "step 3 does not read the choice from the matches"]);
    });

    // 3.1.0's phase B review: read from the text alone, sbom_review gave the undetermined and
    // not_assessed components the text leaves out as data.summary's counts, which count the ones
    // the text still lists too. Control: d42d4697's line.
    it("3.1.0's phase B review: sbom_review counts the undetermined and not_assessed components the first text block leaves out less those listed", async () => {
      const own = textOf(await client.getPrompt({ name: "sbom_review", arguments: { sbom: SBOM } })).split("\nSBOM:\n")[0];
      assert.deepEqual(sbomTextAloneProblems(own), []);
      const now = "as data.summary.undetermined and data.summary.not_assessed (by not_assessed_by_reason), less those listed, as not checked, never as clean.";
      assert.ok(own.includes(now), "re-aim this control: sbom_review no longer holds the clause");
      // #3284: without the sentence on the KEV-bearing components the text leaves out (d42d4697).
      const kev = " The components with a KEV-listed or ransomware match leave the text last, and the note names by index each of them it leaves out (\"Of the rows left out of it, K have a KEV-listed or ransomware match: at index …\"): list those as KEV-bearing components not checked, by index, never as clean.";
      assert.ok(own.includes(kev), "re-aim this control: sbom_review no longer holds the sentence");
      assert.deepEqual(sbomTextAloneProblems(own.replace(kev, "")), ["the KEV-bearing components the text leaves out are not listed by index"]);
      assert.deepEqual(sbomTextAloneProblems(own.replace(now, "as data.summary's counts, by not_assessed_reason, as not checked, never as clean.")), [
        "the undetermined and not_assessed components left out are not counted less those listed",
        "the undetermined and not_assessed components left out are counted as data.summary's whole counts",
      ]);
    });

    // 3.1.0's phase B review: what step 1 says of the two formats is what check_sbom reads
    // (check_sbom.ts fromCycloneDX, fromSPDX): CycloneDX's metadata.component has no index, and an
    // SPDX document's root package, which carries the image's purl in an image SBOM, has one.
    it("3.1.0's phase B review: sbom_review's index rule matches check_sbom's reading: metadata.component is not counted, an SPDX root package is", () => {
      const image = "pkg:oci/app@sha256%3Aabc?repository_url=registry.example%2Fapp";
      const libs = ["pkg:deb/debian/libc6@2.36-9?distro=debian-12", "pkg:npm/lodash@4.17.20"];
      const cdx = SBOM_TOOLS.extract({ sbom: { bomFormat: "CycloneDX", specVersion: "1.5", metadata: { component: { type: "container", name: "app", purl: image } }, components: libs.map((purl, i) => ({ type: "library", name: `l${i}`, purl })) } });
      assert.deepEqual(cdx.purls, libs);
      const pkg = (id, purl) => ({ SPDXID: id, name: id, externalRefs: [{ referenceCategory: "PACKAGE-MANAGER", referenceType: "purl", referenceLocator: purl }] });
      const spdx = SBOM_TOOLS.extract({ sbom: { spdxVersion: "SPDX-2.3", SPDXID: "SPDXRef-DOCUMENT", documentDescribes: ["SPDXRef-image"], packages: [pkg("SPDXRef-image", image), ...libs.map((p, i) => pkg(`SPDXRef-l${i}`, p))] } });
      assert.deepEqual(spdx.purls, [image, ...libs], "the SPDX root package is counted, at index 0");
    });

    // #3285 follow-up (3.1.0's lane P): cve_intel lists a package once per stored ecosystem
    // string, and sbom_review's rule took "the row for the component's ecosystem and package", so a
    // Packagist drupal/quick_node_block 1.0.0 under CVE-2025-48013 got its Packagist row's 2.0.0,
    // which the Packagist:https://packages.drupal.org/8 row still holds affected; the matcher reads
    // both rows as one package and gives 2.0.1. triage_cve gave each row's ranges apart. Controls:
    // d42d4697's rule gives 2.0.0, and its Patch line lacks the clause.
    it("#3285: sbom_review's fix rule reads CVE-2025-48013's two Packagist rows as one: 1.0.0's fix is 2.0.1, not 2.0.0; triage_cve gives their ranges together", async () => {
      const own = textOf(await client.getPrompt({ name: "sbom_review", arguments: { sbom: SBOM } })).split("\nSBOM:\n")[0];
      const rule = own.split("\n").find((l) => l.startsWith("For each line give the component"));
      assert.match(rule, SBOM_ONE_ROW);
      const component = { ecosystem: "Packagist", pkg: "drupal/quick_node_block", installed: "1.0.0" };
      assert.equal(fixBySbomRule(rule, DRUPAL_ROWS, component), "2.0.1");
      const old = rule.replace(/ \(for a Packagist or Maven component, .*? never are\)/, "");
      assert.notEqual(old, rule, "re-aim this control: the rule no longer holds the clause");
      assert.ok(old.includes("Where cve_intel's affected_packages row for the component's ecosystem and package carries fixed_branches, give the fixed of the range that holds the installed version:"), old);
      assert.equal(fixBySbomRule(old, DRUPAL_ROWS, component), "2.0.0", "control: d42d4697's rule, row by row, gives the still-affected 2.0.0");
      // A release suffix is never read so: Debian:12's own row alone.
      const deb = [{ ecosystem: "Debian:11", package_name: "openssl", fixed_branches: [{ introduced: "0", fixed: "1.1.1" }] }, { ecosystem: "Debian:12", package_name: "openssl", fixed_branches: [{ introduced: "0", fixed: "3.0.1" }] }];
      assert.equal(fixBySbomRule(rule, deb, { ecosystem: "Debian:12", pkg: "openssl", installed: "1.0.0" }), "3.0.1");
      const triage = textOf(await client.getPrompt({ name: "triage_cve", arguments: { cve_id: "CVE-2025-48013" } }));
      const patch = triage.split("\n").find((l) => l.startsWith("- Patch:"));
      assert.match(patch, TRIAGE_ONE_PACKAGE);
      assert.doesNotMatch(patch.replace(TRIAGE_ONE_PACKAGE, ""), TRIAGE_ONE_PACKAGE, "control: d42d4697's Patch line lacks the clause");
    });

    it("#2834: am_i_affected's registry text reads each match's fixed_in, and its product text, whose CPE matches carry none, names none", async () => {
      const reg = textOf(await client.getPrompt({ name: "am_i_affected", arguments: { ecosystem: "Maven", package: "org.apache.logging.log4j:log4j-core", version: "2.14.1" } }));
      assert.match(reg, /For each match, give its fixed_in where it is a version: the first version above this one that no affected interval of the advisory holds\. Where fixed_in is null or absent, write that the result gives no fixed version for this version's range, which is not a finding that no fix exists\./);
      const cpe = textOf(await client.getPrompt({ name: "am_i_affected", arguments: { product: "openssl", version: "3.0.0" } }));
      assert.doesNotMatch(cpe, /fixed_in/);
    });
    // #2834's last review (2026-10-11): the rule still fell back to the advisory interval in the
    // match's match_reason, prose read by its brackets. It reads fixed_in alone wherever the text
    // keeps the match, and cve_intel only where it keeps none or the match has no fixed_in.
    it("#2834: sbom_review reads fixed_in alone where the text keeps the match, null as no fix on record, and cve_intel only where it keeps none", async () => {
      const own = textOf(await client.getPrompt({ name: "sbom_review", arguments: { sbom: SBOM } })).split("\nSBOM:\n")[0];
      const rule = own.split("\n").find((l) => l.startsWith("For each line give the component"));
      const at = (re) => rule.search(re);
      // #3074: fixed_in is the first version above the installed one that no affected interval holds.
      assert.ok(at(/Where the text keeps the component's match for the CVE and the match carries fixed_in, read fixed_in alone: a version there is the first version above the installed one that no affected interval of the advisory holds, so give it as the fixed version; null says no fixed version is on record for the installed version's range, so give none for that CVE on that component: where the match carries fixed_in_reason, write "no fix on record" and that fixed_in_reason, which says why, as given \(a version it names is not a fix\); this is not a finding that no fix exists\./) >= 0, rule);
      assert.ok(at(/Where the text or data keeps no match for that CVE on the component \(a cut can keep a row's cve_ids alone, or fewer matches than cve_ids\), or the match has no fixed_in field, the rest of this rule applies\./) >= 0, rule);
      // fixed_in comes before cve_intel's values, and nothing reads match_reason.
      assert.ok(at(/carries fixed_in/) >= 0 && at(/carries fixed_in/) < at(/fixed_branches/), rule);
      assert.doesNotMatch(own, /match_reason|advisory interval \[A, B/, "sbom_review still reads a fixed version from match_reason's prose");
    });
    it("#2834 control: the rule as it read through 2.7.2, with its match_reason fallback, fails the check above", () => {
      const OLD = "Prefer the match's match_reason where the text keeps it: \"falls inside the advisory interval [A, B)\", closed by a parenthesis, says B is the advisory's fixed version for the range that holds the installed version, so give B as the fixed version, quoting it";
      assert.match(OLD, /match_reason|advisory interval \[A, B/);
    });
    // #2836: an upstream row is matched by the source package its purl's upstream qualifier names;
    // the fix list names matched_package beside the purl, and step 2 reads package and version so.
    it("#2836: sbom_review names matched_package where matched_via is upstream, and step 2 reads an upstream purl as its source package", async () => {
      const own = textOf(await client.getPrompt({ name: "sbom_review", arguments: { sbom: SBOM } })).split("\nSBOM:\n")[0];
      const rule = own.split("\n").find((l) => l.startsWith("For each line give the component"));
      assert.match(rule, /^For each line give the component \(its purl, and, where its row's matched_via is upstream, its matched_package: the source package its CVEs were matched by\)/);
      const step2 = own.split("\n").find((l) => l.startsWith("2. Read each component's ecosystem"));
      assert.match(step2, /A deb, apk or alpine purl with an upstream qualifier \(upstream=name, or upstream=name@version\) is checked as the source package it names, which is how Debian and Alpine file advisories: its package is that name, and its version is the qualifier's where it gives one, else the purl's, and its row says matched_via upstream, with that name as matched_package/);
      assert.match(step2, /pkg:apk\/alpine\/libcrypto3@3\.3\.6-r0\?distro=alpine-3\.20&upstream=openssl is openssl in Alpine:v3\.20, at 3\.3\.6-r0/);
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
    // #3013's review: cve_remediation's cut can leave each item's text, the vendor's own wording of a
    // workaround or mitigation, out of data (and shorten or drop it in the text); no string is
    // shortened in data, so both prompts that have the model state that step say where to read it.
    it("#3013's review: triage_cve and sbom_review read a vendor's step from get_vendor_advisory where cve_remediation's cut leaves its text out", async () => {
      const triage = textOf(await client.getPrompt({ name: "triage_cve", arguments: { cve_id: CVE } }));
      const patch = triage.split("\n").find((l) => l.startsWith("- Patch:"));
      const review = textOf(await client.getPrompt({ name: "sbom_review", arguments: { sbom: SBOM } })).split("\nSBOM:\n")[0];
      const remediationLine = review.split("\n").find((l) => l.startsWith("Then, for the first 5 CVEs"));
      const STEP = /a workaround or mitigation as the step that vendor states, .*Where cve_remediation's note says its data or its text leaves out or shortens an item's text \(DATA CUT, TEXT CUT\), read that step in full from get_vendor_advisory for that advisory \(its vendor and vendor_advisory_id\)\./;
      for (const [where, t] of [["triage_cve's Patch line", patch], ["sbom_review's remediation line", remediationLine]]) assert.match(t ?? "", STEP, where);
      assert.ok(tools.has("get_vendor_advisory"));
    });
    it("#2846: workload_triage says each thing it must, in every source's text, and names no EchelonGraph exposure tool", async () => {
      for (const args of [undefined, {}, { source: "kubernetes" }, { source: "github_actions" }, { source: "images" }]) {
        const t = textOf(await client.getPrompt({ name: "workload_triage", arguments: args }));
        assert.deepEqual(workloadProblems(t), [], JSON.stringify(args));
        // Exposure is never sourced from EchelonGraph: the text names neither of its exposure tools.
        for (const tool of ["cve_exposure", "exposure_radar"]) assert.ok(tools.has(tool) && !t.includes(tool), tool);
      }
      const k8s = textOf(await client.getPrompt({ name: "workload_triage", arguments: { source: "kubernetes" } }));
      assert.deepEqual(k8sExposureProblems(k8s), [], "kubernetes");
      assert.deepEqual(k8sExposureProblems(textOf(await client.getPrompt({ name: "workload_triage" }))), [], "no source");
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
    it(`#2924: every tool description in tools/list keeps ${DESCRIPTION_HEADROOM} characters of headroom under the ${CLIENT_CUT}-character client cut`, async () => {
      const { tools: listed } = await client.listTools();
      assert.ok(listed.length > 0 && listed.every((t) => typeof t.description === "string" && t.description.length > 0), "tools/list serves no descriptions: re-aim this check");
      assert.deepEqual(headroomProblems(listed), []);
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
      for (const f of ["state", "measured_at", "method", "coverage", "freshness", "notes", "data_truncated", "truncated", "data", "error"]) assert.ok(t.includes(`| ${f} |`), f);
      for (const s of ["measured", "not_assessed", "failed", "invalid_input"]) assert.ok(t.includes(`| ${s} |`), s);
      for (const tool of tools) assert.match(t, new RegExp(`\\b${tool}\\b`), `methodology does not say how ${tool} measures`);
      noClaims("methodology", t);
      // #2771's review: cve_summary's data is the API's JSON less a poller field of another JSON
      // type, so the data row names it beside the tools that relay a selection.
      const dataRow = t.split("\n").find((l) => l.startsWith("| data |"));
      assert.equal(
        dataRow,
        "| data | On a success: the API's JSON (exposure_radar and cve_intel relay a labelled selection, and cve_summary leaves out a poller field of another JSON type, named in the note), its lists cut when data_truncated is true. |",
      );
    });

    // #2834 and #2836's last review (2026-10-11): the methodology said how check_affected and
    // check_sbom measure, but not what a match carries for a fix, that a CPE range's end is not one,
    // or that an upstream qualifier matches a binary package as its source package.
    it("#2834/#2836: methodology says what fixed_in and a CPE range end are, and how an upstream purl is matched", async () => {
      const t = (await client.readResource({ uri: "echelongraph://methodology" })).contents[0].text;
      const line = (tool) => t.split("\n").find((l) => l.startsWith(`- ${tool}:`)) ?? "";
      const affected = line("check_affected");
      assert.match(affected, /A registry match carries fixed_in, [^.]*, or null with fixed_in_reason, which is not a finding that no fix exists\./, affected);
      assert.match(affected, /A CPE match carries no fixed_in: the end of the NVD range it matched, cpe_version_end_excluding or cpe_version_end_including, is not a fix\./, affected);
      const sbom = line("check_sbom");
      assert.match(sbom, /Each match carries fixed_in, or null with fixed_in_reason/, sbom);
      assert.match(sbom, /A deb, apk or alpine purl with an upstream qualifier \(upstream=name, or upstream=name@version\) is checked as the source package it names, which is how Debian and Alpine file advisories: its row says matched_via upstream, with that name as matched_package\./, sbom);
      assert.match(sbom, /comes back not_assessed \(package_not_in_advisory_corpus\), never clean\./, sbom);
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
      // #3013's review: the resource cut nothing, so its envelope says so (text-bound.test.mjs holds
      // the other polarity, data_truncated true with truncated, on CVE-2021-44228's record).
      assert.equal(s.data_truncated, false);
      assert.ok(!Object.hasOwn(s, "truncated"));
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
  // #3269's third review: round 3's step 6 checked the rows left out again in index order, at the
  // page sentence's N; that text fails the checker.
  it("round 3's step 6 (the rows left out in index order, the page sentence's N a call) fails it", () => {
    const r3 =
      'The affected and undetermined rows that left data are the ones checked again, and the DATA CUT sentence names them by index ("K affected or undetermined rows at index …"), each the position, from 0, of a purl among the distinct purls you sent, in the order you sent them. Call check_sbom again with those purls alone as purls, at most as many per call as the note\'s page sentence names ("A call of the first N of these purls"), and read their rows as in step 5;';
    const got = base.replace(/The affected and undetermined rows that left data are the ones checked again: .*? read their rows as in step 5;/, r3);
    assert.notEqual(got, base);
    const p = workloadProblems(got);
    for (const w of ["lacks the affected rows named by index, KEV-bearing first", "lacks re-checked KEV-bearing first", "lacks the re-check sentence's sizes, not N", "carries round 3's re-check size"]) assert.ok(p.includes(w), `${w}: ${JSON.stringify(p)}`);
  });
  // #3269's fourth review: 0bb8b2d3's text, which had no line for the rows the first text block
  // leaves out, fails the checker.
  it("the text without its line for the rows left out of the first text block (0bb8b2d3) fails it", () => {
    const line = base.split("\n").find((l) => l.startsWith("Where the note says that rows of data.results are left out of the first text block"));
    assert.ok(line, "re-aim this control: the text no longer holds the line");
    const old = base.split("\n").filter((l) => l !== line).join("\n");
    assert.deepEqual(workloadProblems(old), ["lacks the rows left out of the first text block, in structuredContent.data or counted as unchecked", "lacks the rows a DATA CUT leaves out of data too, named by index for step 6", "lacks the KEV-bearing rows the text leaves out, named by index"]);
  });
  // 3.1.0's phase B review: d42d4697's line, which said the rows the text leaves out are in
  // structuredContent.data, read as in step 5, whatever the DATA CUT, fails the checker.
  it("the line as d42d4697 had it (the rows the text leaves out are in data, read as in step 5) fails it", () => {
    const now = "those rows are in structuredContent.data, or, where a DATA CUT leaves rows out of data too, named there by index for step 6's re-check (the note says data holds them whole with full: true): where you can read it, read them there as in steps 5 and 6.";
    assert.ok(base.includes(now), "re-aim this control: the text no longer holds the clause");
    const old = base.replace(now, "those rows are in structuredContent.data: where you can read it, read them there as in step 5.");
    assert.deepEqual(workloadProblems(old), [
      "lacks the rows left out of the first text block, in structuredContent.data or counted as unchecked",
      "lacks the rows a DATA CUT leaves out of data too, named by index for step 6",
      "carries the rows left out of the text said to be in data, whatever the DATA CUT",
    ]);
  });
  // 3.1.0's phase B review: d42d4697's count of the undetermined and not_assessed rows the text
  // leaves out, data.summary's whole counts, fails the checker.
  it("the undetermined and not_assessed rows left out counted as data.summary's whole counts (d42d4697) fails it", () => {
    const now = "as data.summary.undetermined and data.summary.not_assessed (by not_assessed_by_reason), less those listed, as unchecked, never as clean.";
    assert.ok(base.includes(now), "re-aim this control: the text no longer holds the clause");
    assert.deepEqual(workloadProblems(base.replace(now, "as data.summary's counts, by not_assessed_reason, as unchecked, never as clean.")), [
      "lacks the rows left out of the first text block, in structuredContent.data or counted as unchecked",
      "carries the undetermined and not_assessed rows left out counted as data.summary's whole counts",
    ]);
  });
  // #3284: d42d4697's text-alone clause, a KEV-bearing row left out of the text unnamed, fails it.
  it("the text-alone line as d42d4697 had it (a row left out can hold a KEV-listed CVE the text does not name) fails it", () => {
    const kev = " The rows with a KEV-listed or ransomware match leave the text last, and the note names by index each of them it leaves out (\"Of the rows left out of it, K have a KEV-listed or ransomware match: at index …\"): list those as KEV-bearing rows not checked, by index, never as clean.";
    assert.ok(base.includes(kev), "re-aim this control: the text no longer holds the sentence");
    const old = base.replace(kev, "").replace("(data.summary.affected, less those listed)", "(data.summary.affected, less those listed; a row it leaves out can hold a KEV-listed CVE that the text does not name)");
    assert.deepEqual(workloadProblems(old), ["lacks the rows left out of the first text block, in structuredContent.data or counted as unchecked", "lacks the KEV-bearing rows the text leaves out, named by index", "carries a KEV-bearing row left out of the text unnamed"]);
  });
  // #3283: the kubernetes rule without the hostPort clause, or without the externalIPs clause, or
  // with d42d4697's "not exposed" (the pod's spec and the Services, nothing of their ports and
  // externalIPs), fails the checker.
  it("the kubernetes exposure rule without hostPort, without externalIPs, or with d42d4697's not-exposed clause fails it", () => {
    assert.deepEqual(k8sExposureProblems(base), []);
    const hostPort = ", a container of the pod sets a hostPort (spec.containers[].ports[].hostPort, which binds that port on the node's IP)";
    const externalIPs = ", a Service that selects it lists externalIPs (spec.externalIPs, on which nodes accept its traffic whatever its type, ClusterIP included)";
    const notExposed = "not exposed means you read the pod's spec, its containers' ports among it, and the cluster's Services, with their type and externalIPs, Ingresses and routes";
    for (const x of [hostPort, externalIPs, notExposed]) assert.ok(base.includes(x), `re-aim this control: ${x}`);
    assert.deepEqual(k8sExposureProblems(base.replace(hostPort, "")), ["lacks a container hostPort as exposed"]);
    assert.deepEqual(k8sExposureProblems(base.replace(externalIPs, "")), ["lacks a Service's externalIPs as exposed"]);
    assert.deepEqual(k8sExposureProblems(base.replace(notExposed, "not exposed means you read the pod's spec and the cluster's Services, Ingresses and routes")), ["lacks not exposed only after reading the ports and the externalIPs"]);
    // d42d4697's rule whole: all three missing.
    const old = base.replace(hostPort, "").replace(externalIPs, "").replace(notExposed, "not exposed means you read the pod's spec and the cluster's Services, Ingresses and routes");
    assert.equal(k8sExposureProblems(old).length, 3);
  });
  it("the routing sentence moved past 2,048 characters is out of the head", () => {
    const r = SBOM_TOOLS.CHECK_SBOM_ROUTING;
    const d = SBOM_TOOLS.CHECK_SBOM_DESCRIPTION;
    assert.ok(routingEnd(d) <= CLIENT_CUT);
    assert.ok(routingEnd(`${d.replace(r, "")} ${"x".repeat(CLIENT_CUT)} ${r}`) > CLIENT_CUT, "moved past the cut, the sentence still reads as in the head");
    assert.equal(routingEnd(d.replace(r, "")), Infinity, "dropped, the sentence still reads as in the head");
  });
});

describe("#2924 controls: the description headroom check", () => {
  const tool = (n) => ({ name: "dummy_tool", description: "d".repeat(n) });
  it(`a description ${CLIENT_CUT - DESCRIPTION_HEADROOM} characters long passes; one character more fails, naming the tool`, () => {
    assert.deepEqual(headroomProblems([tool(CLIENT_CUT - DESCRIPTION_HEADROOM)]), []);
    assert.deepEqual(headroomProblems([tool(CLIENT_CUT - DESCRIPTION_HEADROOM + 1)]), [`dummy_tool: ${CLIENT_CUT - DESCRIPTION_HEADROOM + 1} characters, ${DESCRIPTION_HEADROOM - 1} under the ${CLIENT_CUT}-character cut; the floor is ${DESCRIPTION_HEADROOM}`]);
  });
  it("2.7.0's check_affected description length (2,046) fails it", () => {
    assert.equal(headroomProblems([tool(2046)]).length, 1);
  });
});
