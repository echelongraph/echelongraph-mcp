// What a tool's result costs in the channel a model reads, measured one way everywhere: the suite's
// per-case bounds (tools.test.mjs, #2467/#2531), the ceiling they sit under (#2617), every tool on
// production-shaped answers (text-bound.test.mjs, #2783), and the operator check that measures
// production's answers (text-bound-live.mjs, #2616, #2783) all import this.
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

// #2467's trip-wire, named once (#2617): "P2 the moment any tool's text exceeds 60,000 chars". A
// per-case bound is resolved by re-measuring and raising it; nothing here may be raised past this,
// and a bound that would be is the moment #2467 said to stop and look, not a number to edit.
export const CEILING = 60_000;
// #2617's trip-wire, 75% of the ceiling: past it, the run says so on every case.
export const TRIP_WIRE = 45_000;
// How far a measurement may move from its recorded size: one changed word, never a sentence.
export const MARGIN = 50;
// The base URL a result is counted against, so a stub's address costs what production's does.
export const PROD_BASE = "https://app.echelongraph.io";

/** Every text block of a result (or text of a resource read, #2801), with `stubBase` counted as production's, summed; and each block's size. */
export function textSize(res, stubBase) {
  const texts = res.contents ? res.contents.filter((c) => typeof c.text === "string") : (res.content ?? []).filter((c) => c.type === "text");
  const blocks = texts.map((c) => (stubBase ? c.text.split(stubBase).join(PROD_BASE) : c.text));
  return { total: blocks.reduce((n, t) => n + t.length, 0), blocks: blocks.map((t) => t.length), envelope: blocks.at(-1)?.length ?? 0 };
}

/** "exposure_radar: 30,949 / 60,000 = 52%", the share a size is of the ceiling. */
export function shareOfCeiling(label, n) {
  const pct = Math.round((n / CEILING) * 100);
  return `${label}: ${n.toLocaleString("en-US")} / ${CEILING.toLocaleString("en-US")} = ${pct}%${n > TRIP_WIRE ? ` (past #2617's trip-wire of ${TRIP_WIRE.toLocaleString("en-US")})` : ""}`;
}

/** Throws when a bound (a measured size plus MARGIN) is past the ceiling (#2617). */
export function assertBoundUnderCeiling(label, size) {
  const bound = size + MARGIN;
  if (bound > CEILING) {
    throw new Error(`${label}: its bound of ${bound} (${size} measured, plus ${MARGIN}) is past #2467's ceiling of ${CEILING} characters. Do not raise the ceiling to pass: cut the text, or reopen #2467.`);
  }
  return bound;
}

// ── Production's measured text (#2616) ──
//
// The suite's bounds are measured on fixtures; production's answers grow (radar rows, a new
// radar, a new field), and what a production client receives is what costs it context. The record
// below is production's own: each tool's text measured on production's answers, replayed from
// localhost by text-bound-live.mjs so the package's User-Agent never reaches production as
// adoption. The answers themselves are kept beside it (fixtures/prod-answers/), so the suite
// measures the same tool on them (tools.test.mjs) and the record cannot drift from the code
// without a red test; text-bound-live.mjs is the red signal when production drifts from the record.
const HERE = path.dirname(fileURLToPath(import.meta.url));
export const LIVE_RECORD = path.join(HERE, "fixtures", "text-bound-live.json");
export const PROD_ANSWERS = path.join(HERE, "fixtures", "prod-answers");
// #2822: the source text-bound-live.mjs writes when it re-measures the answers kept here
// (--answers test/fixtures/prod-answers): probe-prod's answers, read when they were kept.
export const KEPT_SOURCE = "probe-prod answers kept in fixtures/prod-answers";
// Every source text-bound-live.mjs writes into the record, and nothing else: a source written by
// hand is not one of these (#2822).
export const RECORD_SOURCE = /^(probe-prod|probe-prod answers kept in fixtures\/prod-answers|answers in \S.*|hosted https?:\/\/\S+, its data replayed to this checkout's server|the hosted endpoint's own text \(.+\), not this checkout's)$/;

/** The tools whose answer is production-wide (no input), measured live, and the API paths each one reads. */
export const LIVE_TOOLS = {
  exposure_radar: [
    "/api/v1/public/kev-exposure/stats",
    "/api/v1/public/exposed-databases/stats",
    "/api/v1/public/leaked-credentials/stats",
    "/api/v1/public/shadow-ai-radar/stats",
    "/api/v1/public/ai-exposure/stats?service=mcp",
  ],
  cve_summary: ["/api/v1/public/cves/summary"],
};

/** The file a production answer for `apiPath` is kept in. */
export const answerFile = (apiPath) => path.join(PROD_ANSWERS, `${apiPath.replace(/^\/api\/v1\/public\//, "").replace(/[^A-Za-z0-9.-]+/g, "_")}.json`);

export function readLiveRecord() {
  return JSON.parse(fs.readFileSync(LIVE_RECORD, "utf8"));
}

/**
 * #2822: each SHAPED case measured on kept production answers (`kept`) whose size is more than
 * MARGIN from the record's total for that tool, with the size to set. The suite measures those
 * answers on every run and holds the text within MARGIN of the case's size, so a re-record that
 * moves the total without moving the size fails the release; text-bound-live.mjs --record names
 * them and exits 1, and text-bound.test.mjs fails on them, each saying what to set.
 */
export function keptSizesOffRecord(record = readLiveRecord()) {
  return SHAPED.filter((c) => c.kept && record.tools?.[c.kept] && Math.abs(c.size - record.tools[c.kept].total) > MARGIN).map((c) => ({
    label: c.label,
    size: c.size,
    total: record.tools[c.kept].total,
    measured_at: record.tools[c.kept].measured_at,
  }));
}

/** What to do about one keptSizesOffRecord entry. */
export const setKeptSize = (o) =>
  `${o.label}: SHAPED's size is ${o.size}, but the record (${o.measured_at}) measured ${o.total}, more than MARGIN ${MARGIN} away: set its size to ${o.total} in test/text-bound.mjs, run npm test, and commit it with the record`;

/** The kept production answers for `tool`, as stub overrides (request URL -> body); undefined when any is missing. */
export function keptAnswers(tool) {
  const out = {};
  for (const p of LIVE_TOOLS[tool]) {
    const f = answerFile(p);
    if (!fs.existsSync(f)) return undefined;
    out[p] = JSON.parse(fs.readFileSync(f, "utf8"));
  }
  return out;
}

// ── Production-shaped answers, for every tool (#2783) ──
//
// Through 2.6.2 the ceiling was checked against the stub fixtures of tools.test.mjs alone: one
// search_cves row of 6 fields printed "search_cves: 1,115 / 60,000 = 2%" while production's default
// search_cves answer was 133,298 characters, and 9 of the 14 tools printed nothing. SHAPED is one
// case per tool at its default call and, for a tool with a page size, one at its largest page, each
// on production's own answer read through the hosted endpoint (fixtures/prod-shaped/, the capture
// and production's text at the time in each file) or kept by #2616 (fixtures/prod-answers/). A file
// keeps a few of production's rows, every k-th, and a case repeats them to its page size
// (`repeat`), so the rows the text is measured on are production's rows, field for field, without
// keeping megabytes. `size` is the case's text measured on it, which text-bound.test.mjs holds it
// to within MARGIN either way (#2800: a text that shrinks is re-measured, as one that grows is);
// `production` in the file is what production's 2.6.2 text was for the same call.
//   page     "default": the call as a client makes it first; "max": the largest page the
//            tool's inputSchema allows (limit at its maximum; check_sbom's 2,000 purls);
//            "forced": production's rows made longer (`stretch`) so that a tool whose every
//            production answer fits is cut, and its cut level is checked (#2800 review).
//   answers  the file's answers this case serves; the stub answers each request by its path.
//   set      top-level fields of the answer this case sets (the page size the API echoes).
//   recount  check_sbom: summary recounted from the repeated rows, as the API counts them.
//   stretch  a forced case's longer rows: {list: {field: n}}, each row's string `field` n times
//            over, joined by a space (after `repeat`).
//   limited  the API's component budget as production spends it: the stub answers the first
//            `after` requests and every later one 429 with Retry-After `retryAfter` seconds.
//   resource a resource read instead of a tool call (cve://{cve_id}, #2801): its text is measured,
//            under the same ceiling; `tool` is then the tool whose answer it reads.
//   live     set: text-bound-live.mjs does not measure it on production, and why.
//   annotate {list: {key, values, otherwise}}: fields set on each row of `list` by the value of its
//            field `key` (values[row[key]], else otherwise): an answer field production does not
//            serve yet, on production's rows (#2817).
export const SHAPED_DIR = path.join(HERE, "fixtures", "prod-shaped");
// #2817: the ranges of OSV GHSA-jfh8-c2jp-5v3q (CVE-2021-44228) per package, as core-backend's
// fixed_branches serves them (cve/fixed_branches.go: fixed and last_affected kept apart, each null
// when absent, and each range naming the OSV record that published it, advisory_id and source).
// log4j-core's are in the record's order; the order of the others does not change the size.
const range = (introduced, fixed, last_affected = null) => ({ introduced, fixed, last_affected, source: "osv_bulk", advisory_id: "GHSA-jfh8-c2jp-5v3q" });
export const LOG4SHELL_FIXED_BRANCHES = {
  "org.apache.logging.log4j:log4j-core": { fixed_branches: [range("2.13.0", "2.15.0"), range("2.0-beta9", "2.3.1"), range("2.4", "2.12.2")] },
  "org.ops4j.pax.logging:pax-logging-log4j2": { fixed_branches: [range("1.8.0", "1.9.2"), range("1.10.0", "1.10.8"), range("1.11.0", "1.11.10"), range("2.0.0", "2.0.11")] },
  "com.guicedee.services:log4j-core": { fixed_branches: [range("0", null, "1.2.1.2-jre17")] },
  "org.xbib.elasticsearch:log4j": { fixed_branches: [] },
  "uk.co.nichesolutions.logging.log4j:log4j-core": { fixed_branches: [] },
};
// #2839: CISA's KEV text for CVE-2021-44228 as core-backend serves it on the record
// (kev_required_action, kev_short_description, kev_notes_urls), copied verbatim from CISA's
// known_exploited_vulnerabilities.json, catalogVersion 2026.10.04 (read 2026-10-05). Production's
// get_cve answer kept in fixtures/prod-shaped/ predates the fields, so the get_cve cases `set` them
// on it until that answer is re-captured from production after core-backend ships them.
export const LOG4SHELL_KEV_TEXT = {
  kev_required_action:
    "For all affected software assets for which updates exist, the only acceptable remediation actions are: 1) Apply updates; OR 2) remove affected assets from agency networks. Temporary mitigations using one of the measures provided at https://www.cisa.gov/uscert/ed-22-02-apache-log4j-recommended-mitigation-measures are only acceptable until updates are available.",
  kev_short_description:
    "Apache Log4j2 contains a vulnerability where JNDI features do not protect against attacker-controlled JNDI-related endpoints, allowing for remote code execution.",
  kev_notes_urls: ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
};
const JUICE_SHOP = path.join(HERE, "fixtures", "juice-shop-11.1.2-50.cdx.json");
// 2,000 distinct purls, check_sbom's most per call (MAX_PURLS).
export const SBOM_MAX_PURLS = 2000;
const manyPurls = () => Array.from({ length: SBOM_MAX_PURLS }, (_, i) => `pkg:npm/shaped-${i}@1.0.${i % 10}`);
// #2835: scan_manifest's files. A real package-lock (fixtures/manifests/tree.v3.package-lock.json,
// npm 10, 64 registry packages and 3 entries not checked), and the same file's registry entries
// cycled under new names to a 1,500-entry lockfile, 100 of them installed from git (not checked):
// 1,400 distinct purls, seven batches of 200.
const MANIFESTS = path.join(HERE, "fixtures", "manifests");
export const TREE_LOCK = () => fs.readFileSync(path.join(MANIFESTS, "tree.v3.package-lock.json"), "utf8");
export function bigLock(entries = 1500, git = 100) {
  const tree = JSON.parse(TREE_LOCK());
  const registry = Object.entries(tree.packages).filter(([k, e]) => k.startsWith("node_modules/") && !e.link && String(e.resolved ?? "").startsWith("https://registry.npmjs.org/"));
  const packages = { "": tree.packages[""] };
  for (let i = 0; i < entries; i++) {
    const [key, e] = registry[i % registry.length];
    const name = `${key.split("node_modules/").pop().replace("@", "")}-r${i}`;
    packages[`node_modules/${name}`] = i < git ? { ...e, name: undefined, resolved: `git+ssh://git@github.com/example/${name}.git#${String(i).padStart(40, "0")}` } : { ...e, name: undefined };
  }
  return JSON.stringify({ ...tree, packages }, null, 2);
}
export const SHAPED = [
  { label: "cve_summary", tool: "cve_summary", page: "default", args: {}, kept: "cve_summary", size: 2_708 },
  { label: "search_cves, default page (search openssl)", tool: "search_cves", page: "default", args: { search: "openssl" }, fixture: "search_cves", answers: ["openssl"], repeat: { cves: 20 }, set: { limit: 20 }, size: 13_621 },
  { label: "search_cves, largest page (search openssl, limit 50)", tool: "search_cves", page: "max", args: { search: "openssl", limit: 50 }, fixture: "search_cves", answers: ["openssl"], repeat: { cves: 50 }, set: { limit: 50 }, size: 30_904 },
  { label: "get_cve, CVE-2021-44228", tool: "get_cve", page: "default", args: { cve_id: "CVE-2021-44228" }, fixture: "get_cve", answers: ["CVE-2021-44228"], repeat: { cpe_match: 396, references: 103 }, set: LOG4SHELL_KEV_TEXT, size: 24_216 },
  // #2801: the cve:// resource reads get_cve's answer; through 2.6.3 it was that answer's structured
  // result pretty-printed whole, 86,559 characters for this CVE on the hosted endpoint (2026-10-04).
  {
    label: "cve://CVE-2021-44228, the resource",
    resource: "cve://CVE-2021-44228",
    tool: "get_cve",
    page: "default",
    args: { cve_id: "CVE-2021-44228" },
    fixture: "get_cve",
    answers: ["CVE-2021-44228"],
    repeat: { cpe_match: 396, references: 103 },
    set: LOG4SHELL_KEV_TEXT,
    live: "it reads get_cve's answer for the same CVE, which the get_cve case measures on production; text-bound-live.mjs reads tools only",
    size: 24_639,
  },
  { label: "cve_exposure, CVE-2023-44487", tool: "cve_exposure", page: "default", args: { cve_id: "CVE-2023-44487" }, fixture: "cve_exposure", answers: ["CVE-2023-44487"], size: 4_365 },
  { label: "exposure_radar", tool: "exposure_radar", page: "default", args: {}, kept: "exposure_radar", size: 41_315 },
  { label: "kev_recent, default page (limit 50)", tool: "kev_recent", page: "default", args: {}, fixture: "kev_recent", answers: ["recent"], repeat: { kev: 50 }, set: { limit: 50, count: 50 }, size: 29_160 },
  { label: "kev_recent, largest page (limit 200)", tool: "kev_recent", page: "max", args: { limit: 200 }, fixture: "kev_recent", answers: ["recent"], repeat: { kev: 200 }, set: { limit: 200, count: 200 }, size: 31_854 },
  // #2867: 2,379 through 2.6.8. The fixture is production's answer from before core-backend served
  // complete_since and coverage, so the note now says the answer does not say from when the record
  // is complete, and the envelope's coverage carries the completeness fields (null / []).
  { label: "epss_history, CVE-2021-44228", tool: "epss_history", page: "default", args: { cve_id: "CVE-2021-44228" }, fixture: "epss_history", answers: ["CVE-2021-44228"], size: 2_771 },
  { label: "check_affected, openssl 3.0.0", tool: "check_affected", page: "default", args: { product: "openssl", version: "3.0.0" }, fixture: "check_affected", answers: ["openssl"], repeat: { matches: 71 }, size: 26_152 },
  { label: "check_affected, linux_kernel 5.10.0 (200 matches, the API's cap)", tool: "check_affected", page: "max", args: { product: "linux_kernel", version: "5.10.0" }, fixture: "check_affected", answers: ["linux_kernel"], repeat: { matches: 200 }, size: 29_694 },
  // The cap with the CPE path's excluded sample beside it: 50 entries, each with a sentence of detail.
  {
    label: "check_affected, flash_player 10.0.0 (200 matches and an excluded sample of 50)",
    tool: "check_affected",
    page: "max",
    args: { product: "flash_player", version: "10.0.0" },
    fixture: "check_affected",
    answers: ["flash_player"],
    repeat: { matches: 200, excluded: 50 },
    size: 30_116,
  },
  { label: "check_affected, PyPI django 1.11.0 (the registry path)", tool: "check_affected", page: "default", args: { ecosystem: "PyPI", package: "django", version: "1.11.0" }, fixture: "check_affected", answers: ["django"], repeat: { matches: 29 }, size: 23_937 },
  { label: "check_sbom, Juice Shop 11.1.2 (50 components)", tool: "check_sbom", page: "default", args: () => ({ sbom: JSON.parse(fs.readFileSync(JUICE_SHOP, "utf8")) }), fixture: "check_sbom", answers: ["batch"], repeat: { results: 50 }, recount: true, size: 30_568 },
  {
    label: "check_sbom, 2,000 purls (10 batches of 200)",
    tool: "check_sbom",
    page: "max",
    args: () => ({ purls: manyPurls() }),
    fixture: "check_sbom",
    answers: ["batch"],
    repeat: { results: 200 },
    recount: true,
    live: "2,000 lookups would pass production's 1,200 components a minute per caller; the suite measures the same rows, repeated",
    size: 35_614,
  },
  // What production answers the same call from a fresh budget (src/tools/check_sbom.ts MAX_PURLS):
  // six batches, then 429 asking for a wait past the call's 50 s, so 1,200 rows and 800 purls in
  // data.not_sent_purls.
  {
    label: "check_sbom, 2,000 purls, rate-limited after 6 batches (production's answer from a fresh budget)",
    tool: "check_sbom",
    page: "max",
    args: () => ({ purls: manyPurls() }),
    fixture: "check_sbom",
    answers: ["batch"],
    repeat: { results: 200 },
    recount: true,
    limited: { after: 6, retryAfter: 60 },
    live: "it spends production's whole budget of 1,200 components a minute per caller and is then refused; the suite measures the same rows, repeated, and the 429",
    size: 36_534,
  },
  // #2817: production's answer after core-backend with #2817 was deployed and before the OSV
  // backfill has run (prod-shaped/cve_intel.json, read again 2026-10-05T07:38Z): every
  // affected_packages row carries fixed_branches, each range with source and advisory_id null
  // (log4j-core: [2.0-beta9, 2.3.1), [2.4, 2.12.2), [2.13.0, 2.15.0)), and the answer carries
  // failed_sections []. 17,355 characters, production's own text for the call (text-bound-live.mjs,
  // 2026-10-05T07:37:21Z); through the 2026-10-04 read, with no fixed_branches and no
  // failed_sections, it was 14,693.
  // #2835: production's batch rows (prod-shaped/check_sbom.json), one per distinct purl.
  { label: "scan_manifest, package-lock.json (64 packages)", tool: "scan_manifest", page: "default", args: () => ({ files: [{ filename: "package-lock.json", content: TREE_LOCK() }] }), fixture: "check_sbom", answers: ["batch"], repeat: { results: 64 }, recount: true, live: "not recorded yet: the batch route it calls is deployed, but text-bound-live.mjs --record has not been run with this checkout (#2835's release step); run it, and drop this", size: 15_665 },
  {
    label: "scan_manifest, package-lock.json of 1,500 entries (1,400 distinct purls, 100 from git)",
    tool: "scan_manifest",
    page: "max",
    args: () => ({ files: [{ filename: "package-lock.json", content: bigLock() }] }),
    fixture: "check_sbom",
    answers: ["batch"],
    repeat: { results: 200 },
    recount: true,
    live: "1,400 lookups would pass production's 1,200 components a minute per caller; the suite measures the same rows, repeated",
    size: 36_439,
  },
  { label: "cve_intel, CVE-2021-44228", tool: "cve_intel", page: "default", args: { cve_id: "CVE-2021-44228" }, fixture: "cve_intel", answers: ["CVE-2021-44228"], repeat: { timeline: 100 }, size: 17_355 },
  // #2817: the same rows once the OSV backfill (BACKFILL_OSV_PACKAGES_FORCE, pending) has filled
  // each range's record: the ranges of GHSA-jfh8-c2jp-5v3q (api.osv.dev, 2026-10-05) with
  // advisory_id and source, log4j-core's three in the record's order, pax-logging-log4j2's four,
  // guicedee's one range with a last_affected bound, and [] for the two packages the record gives no
  // range; the Debian rows keep production's own ranges (otherwise {}), source and advisory_id null,
  // since this case does not know their record. 17,539 characters, under the 30,000 ceiling (17,001
  // when built on the 2026-10-04 read, the Debian rows then set to null). Not measured on production
  // (live) until the backfill has run: re-measure there then (text-bound-live.mjs).
  {
    label: "cve_intel, CVE-2021-44228, with fixed_branches (#2817)",
    tool: "cve_intel",
    page: "default",
    args: { cve_id: "CVE-2021-44228" },
    fixture: "cve_intel",
    answers: ["CVE-2021-44228"],
    repeat: { timeline: 100 },
    annotate: { affected_packages: { key: "package_name", values: LOG4SHELL_FIXED_BRANCHES, otherwise: {} } },
    live: "production's rows with each range's advisory_id and source, which production serves only once the OSV backfill (BACKFILL_OSV_PACKAGES_FORCE) has run",
    size: 17_539,
  },
  // #2841: cve_remediation for Log4Shell on production's data (prod-shaped/cve_remediation.json,
  // assembled 2026-10-05 from the stored advisories by the parsers, before the route is live): 20
  // vendor advisories, 19 of them Red Hat's with their vendor_fix and workaround texts, the
  // packages' fixed_branches, CISA's text and the Patch/Mitigation references. Its JSON is past the
  // 30,000-character budget, so the cut is measured: texts shortened first, kinds, states and URLs kept.
  {
    label: "cve_remediation, CVE-2021-44228",
    tool: "cve_remediation",
    page: "default",
    args: { cve_id: "CVE-2021-44228" },
    fixture: "cve_remediation",
    answers: ["CVE-2021-44228"],
    live: "the route (GET /cves/:id/remediation) is not deployed yet: measure it there once it is (text-bound-live.mjs)",
    size: 20_644,
  },
  { label: "get_cwe, CWE-79", tool: "get_cwe", page: "default", args: { cwe_id: "CWE-79" }, fixture: "get_cwe", answers: ["CWE-79"], repeat: { cves: 50 }, size: 28_716 },
  // #2800 review: no answer the API serves reaches get_cwe's cut. It cuts each row's description to
  // 240 characters (core-backend cve/cwe_landing_store.go ListCVEsByCWE) in pages of 50, so a page
  // fits whole: CWE-79's is 26,907 characters, and CWE-416's first, hosted on 2026-10-04, 27,073.
  // So the cut's level was checked by no case, and dropping a field the description names from it
  // left the suite green. Forced: CWE-79's rows, each description four times over.
  {
    label: "get_cwe, CWE-79, each description four times over (a forced cut)",
    tool: "get_cwe",
    page: "forced",
    args: { cwe_id: "CWE-79" },
    fixture: "get_cwe",
    answers: ["CWE-79"],
    repeat: { cves: 50 },
    stretch: { cves: { description: 4 } },
    live: "a forced cut: no page the API serves reaches it (each row's description is cut to 240 characters at the source)",
    size: 20_018,
  },
  { label: "vendor_advisories_for_cve, CVE-2021-44228", tool: "vendor_advisories_for_cve", page: "default", args: { cve_id: "CVE-2021-44228" }, fixture: "vendor_advisories_for_cve", answers: ["CVE-2021-44228"], extra: ["coverage"], size: 15_405 },
  // #2800 review: nor does any answer reach vendor_advisories_for_cve's cut: the API sends at most 20
  // advisories for a CVE (core-backend vendoradv/store.go ListAdvisoriesByCVE, LIMIT 20), each
  // without summary, affected_products or cve_ids: CVE-2021-44228's 20 are 9,753 characters of
  // pretty JSON.
  // Its cut levels are search_vendor_advisories' (ROW_CUT_LEVELS), but its TextCut is its own.
  // #2803: re-measured for held_since. The coverage answer in the fixture is 2.6.4's API, which has
  // no held_since, so each vendor with no complete history read is written "not known to be
  // without a gap" and relayed with held_since null (the two search cases below likewise).
  // Forced: CVE-2021-44228's rows, each title twenty times over.
  {
    label: "vendor_advisories_for_cve, CVE-2021-44228, each title twenty times over (a forced cut)",
    tool: "vendor_advisories_for_cve",
    page: "forced",
    args: { cve_id: "CVE-2021-44228" },
    fixture: "vendor_advisories_for_cve",
    answers: ["CVE-2021-44228"],
    stretch: { advisories: { title: 20 } },
    extra: ["coverage"],
    live: "a forced cut: no answer the API serves reaches it (at most 20 advisories, each a few hundred characters)",
    size: 14_845,
  },
  { label: "get_vendor_advisory, aws 2026-098-AWS", tool: "get_vendor_advisory", page: "default", args: { vendor: "aws", advisory_id: "2026-098-AWS" }, fixture: "get_vendor_advisory", answers: ["aws 2026-098-AWS"], extra: ["coverage"], size: 3_038 },
  { label: "search_vendor_advisories, default page (query log4j)", tool: "search_vendor_advisories", page: "default", args: { query: "log4j" }, fixture: "search_vendor_advisories", answers: ["log4j"], repeat: { advisories: 20 }, set: { limit: 20 }, extra: ["coverage"], size: 33_676 },
  { label: "search_vendor_advisories, largest page (query log4j, limit 50)", tool: "search_vendor_advisories", page: "max", args: { query: "log4j", limit: 50 }, fixture: "search_vendor_advisories", answers: ["log4j"], repeat: { advisories: 50 }, set: { limit: 50 }, extra: ["coverage"], size: 22_548 },
];

// How far a case's size may be from production's text for the same call, as text-bound-live.mjs
// last recorded it, as a fraction of production's (#2783). A fixture keeps every k-th of
// production's rows, and its pretty JSON was held to within a few percent of production's; but the
// cut works in levels, so rows a little longer than production's average can be cut one level
// further than production's page is, and the bound is then not production's: kev_recent's page of
// 200, sampled from row 4, was 25,286 characters against production's 31,588. Held only where both
// sizes are this checkout's server's text (not where the record is the hosted endpoint's own).
export const SHAPED_DRIFT = 0.1;

/** A case's arguments. */
export const argsOf = (c) => (typeof c.args === "function" ? c.args() : c.args);

export function readShaped(name) {
  return JSON.parse(fs.readFileSync(path.join(SHAPED_DIR, `${name}.json`), "utf8"));
}

// The rows of `list` repeated in order to n.
const cycled = (list, n) => Array.from({ length: n }, (_, i) => list[i % list.length]);
// A row with each string field named in `fields` n times over, joined by a space.
const stretched = (row, fields) => ({ ...row, ...Object.fromEntries(Object.entries(fields).filter(([f]) => typeof row[f] === "string").map(([f, n]) => [f, Array(n).fill(row[f]).join(" ")])) });
// check_sbom's summary and components, counted from the rows as the API counts them.
function recounted(body) {
  const rows = body.results ?? [];
  const v = { affected: 0, not_affected: 0, undetermined: 0, not_assessed: 0 };
  const by = {};
  for (const r of rows) {
    if (r.verdict in v) v[r.verdict]++;
    if (r.verdict === "not_assessed" && r.not_assessed_reason) by[r.not_assessed_reason] = (by[r.not_assessed_reason] ?? 0) + 1;
  }
  return { ...body, components: rows.length, results: rows.map((r, i) => ({ ...r, index: i })), summary: { ...body.summary, ...v, components: rows.length, lookups: rows.length, not_assessed_by_reason: by } };
}

/** The API answers a case is measured on, as stub overrides (request path -> body). */
export function shapedAnswers(c) {
  if (c.kept) return keptAnswers(c.kept);
  const f = readShaped(c.fixture);
  const out = {};
  for (const name of c.answers) {
    const a = f.answers[name];
    let body = { ...a.body, ...(c.set ?? {}) };
    for (const [key, n] of Object.entries(c.repeat ?? {})) body[key] = cycled(a.body[key], n);
    for (const [key, fields] of Object.entries(c.stretch ?? {})) body[key] = body[key].map((r) => stretched(r, fields));
    for (const [key, { key: by, values, otherwise }] of Object.entries(c.annotate ?? {})) body[key] = body[key].map((r) => ({ ...r, ...(values[r[by]] ?? otherwise) }));
    if (c.recount) body = recounted(body);
    out[a.path] = body;
  }
  // Answers the tool reads beside the one it relays (the vendor tools' /coverage, #2729), served as
  // production gave them: no set, repeat or recount, and after the relayed answer.
  for (const name of c.extra ?? []) out[f.answers[name].path] = f.answers[name].body;
  return out;
}

/** Production's text for a case's call where it was measured: {total, blocks, version, at}. */
export function productionText(c) {
  if (c.kept) {
    const r = readLiveRecord().tools?.[c.kept];
    return r && { total: r.total, blocks: r.blocks, version: `${r.package_version} on its kept answers`, at: r.measured_at };
  }
  const f = readShaped(c.fixture);
  const p = f.production?.[c.label];
  return p && { total: p.total, blocks: p.blocks, version: `${f.captured.server_version}, through the hosted endpoint`, at: f.captured.at };
}

// ── The stub and the cut check, shared by text-bound.test.mjs and prompt-fields.test.mjs ──

// The API's answer when a caller's component budget is spent (core-backend internal/waf/weighted.go).
export const RATE_LIMITED = { error: "component budget exceeded: this batch costs 200 components and this address has 0 left in the window. Nothing was looked up", code: "RATE_LIMIT_EXCEEDED", cost: 200, limit: 1200 };

// A stub API answering each request with the case's answer for its path (whole URL first), and,
// for a case with `limited`, every request after the first `after` with 429 and its Retry-After.
export async function startStub() {
  const state = { answers: {}, limited: undefined, requests: 0 };
  const server = http.createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      const { pathname } = new URL(req.url, "http://stub");
      state.requests++;
      if (state.limited && state.requests > state.limited.after) {
        res.writeHead(429, { "content-type": "application/json", "retry-after": String(state.limited.retryAfter) });
        res.end(JSON.stringify(RATE_LIMITED));
        return;
      }
      const body = state.answers[req.url] ?? state.answers[pathname];
      res.writeHead(body ? 200 : 404, { "content-type": body ? "application/json" : "text/plain" });
      res.end(body ? JSON.stringify(body) : "404 page not found\n");
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return {
    state,
    base: `http://127.0.0.1:${server.address().port}`,
    close: () => {
      server.closeAllConnections();
      return new Promise((r) => server.close(r));
    },
  };
}

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/**
 * Whether `t`, read from a first text block, is a cut of `d`, structuredContent.data: every key it
 * has, `d` has; a string is equal or `d`'s first characters and "…"; a list is some of `d`'s
 * entries, in `d`'s order; anything else is equal. Throws, naming where, when it is not. Each pair
 * of objects it matched (`t`'s object and the object of `d` it is a cut of) is handed to `visit`.
 */
export function assertCutOf(t, d, at = "data", visit = undefined) {
  if (typeof t === "string" && typeof d === "string") {
    if (t === d) return;
    assert.ok(t.endsWith("…") && d.startsWith(t.slice(0, -1)) && t.length <= d.length, `${at}: ${JSON.stringify(t.slice(0, 80))} is neither the answer's string nor its start and "…"`);
    return;
  }
  if (Array.isArray(t)) {
    assert.ok(Array.isArray(d), `${at}: a list in the text where the answer has ${typeof d}`);
    let j = 0;
    for (const [i, x] of t.entries()) {
      while (j < d.length && !isCut(x, d[j])) j++;
      assert.ok(j < d.length, `${at}[${i}]: not one of the answer's entries, in the answer's order`);
      if (visit) assertCutOf(x, d[j], `${at}[${i}]`, visit);
      j++;
    }
    return;
  }
  if (isObj(t)) {
    assert.ok(isObj(d), `${at}: an object in the text where the answer has ${JSON.stringify(d)?.slice(0, 40)}`);
    for (const k of Object.keys(t)) {
      assert.ok(Object.hasOwn(d, k), `${at}.${k}: in the text, not in the answer`);
      assertCutOf(t[k], d[k], `${at}.${k}`, visit);
    }
    visit?.(t, d, at);
    return;
  }
  assert.deepEqual(t, d, at);
}
export function isCut(t, d) {
  try {
    assertCutOf(t, d);
    return true;
  } catch {
    return false;
  }
}

/**
 * Every object of the text paired with the object of the answer it is a cut of, with its path in
 * the text (`data.cves[3]`): a list's entries are paired in order, as assertCutOf matches them.
 */
export function cutPairs(t, d) {
  const out = [];
  assertCutOf(t, d, "data", (x, y, at) => out.push({ text: x, answer: y, at }));
  return out;
}
