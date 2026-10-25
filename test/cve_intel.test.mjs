// #2720: cve_intel, get_cwe, and get_cve's cpe_configurations, against a stub EchelonGraph API,
// in both protocol eras (2026-07-28 server/discover and the 2025-06-18 initialize), with every
// structuredContent validated against the tool's advertised outputSchema by ajv, as the SDK
// ships it (the same validator tools.test.mjs uses).
//
// What is under test, per tool:
//   cve_intel  the relayed cut (cwes, exploits and their counts, affected_packages,
//              fixed_versions, timeline), exploits_total past the 10-row cap, a section the API
//              could not read left out and named (never relayed as an empty list), an answer
//              without failed_sections or exploits_total (an API older than #2720) worded as
//              such, an empty exploits list never worded as "no exploit exists", no request but
//              /enrichment (never /blast-radius), and invalid input refused before any request.
//              #2876: each exploit's source_published_at (null where the source gives none) and
//              eg_first_seen_at relayed as sent, validated, and never rendered as a made-up date.
//   get_cwe    the API's JSON relayed as sent, the order repeated only when the answer states it,
//              a served page that differs from the asked one, the pageable cap, a measured empty
//              CWE, rows NOT YET SCORED, and input normalised (79 -> CWE-79) or refused.
//   get_cve    cpe_configurations relayed, and its absence said in the envelope as "not stored",
//              not "no product affected".
//
// Runs against dist/index.js (npm test builds first), or an installed bin (server-under-test.mjs).
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
// #3121: answers are validated against the closed success branch (strict-output.mjs).
import { StrictOutputValidator } from "./strict-output.mjs";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { serverCommand } from "./server-under-test.mjs";

const ERAS = [MODERN, "2025-06-18"];
const LOG4SHELL = "CVE-2021-44228";
const ENRICH = (id) => `/api/v1/public/cves/${id}/enrichment`;

// Claims the package's copy must not make (tools.test.mjs REMOVED_CLAIMS, HOST_UNIT).
const REMOVED_CLAIMS = /passive|no other|unique|real-?time|\blive\b|right now/i;
const HOST_UNIT = /\bhosts\b|\bhost\(s\)/i;
const FIELD_TOKEN = /\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b/g;

// ── Fixtures: core-backend's wire shapes at #2720 ──
const exploit = (i, kind, status, day) => ({
  kind,
  source_name: `${kind}/${i}`,
  source_url: `https://example.test/${kind}/${i}`,
  first_seen_at: `2021-12-${String(day).padStart(2, "0")}T00:00:00Z`,
  verified_status: status,
});
const TIMELINE = Array.from({ length: 25 }, (_, i) => ({
  enriched_at: new Date(Date.UTC(2026, 8, 30 - i)).toISOString(),
  enrichment_kind: "epss",
  fields_changed: { epss_score: { from: 0.9, to: 0.97 } },
}));
// What handler_enrichment.go serves for a widely-weaponised CVE: two CWEs, 12 references (2
// verified Metasploit modules first, then GitHub PoCs), every section read.
const LOG4SHELL_ENRICHMENT = {
  vendor_advisories: [{ vendor: "apache", advisory_id: "LOG4J2-3201", url: "https://logging.apache.org/log4j/2.x/security.html" }],
  patches: [{ vendor: "apache", patch_url: "https://example.test/patch", source: "nvd" }],
  fixed_versions: [{ ecosystem: "Maven", package_name: "org.apache.logging.log4j:log4j-core", vulnerable_range: ">=2.0-beta9 <2.15.0", fixed_version: "2.15.0", source: "osv" }],
  affected_packages: [{ ecosystem: "Maven", package_name: "org.apache.logging.log4j:log4j-core", version_range: ">=2.0-beta9 <2.15.0", fixed_version: "2.15.0", dependents_count: 7000, source: "ghsa" }],
  cwes: [
    { cwe_id: "CWE-502", name: "Deserialization of Untrusted Data", source: "nvd" },
    { cwe_id: "CWE-917", name: "Improper Neutralization of Special Elements Used in an Expression Language Statement (EL Injection)", source: "nvd" },
  ],
  timeline: TIMELINE,
  timeline_count_7d: 3,
  timeline_count_30d: 9,
  timeline_total: 140,
  ai: { plain_summary: { content_kind: "plain_summary", content_md: "generated text", model: "m", generated_at: "2026-09-01T00:00:00Z" }, risk_narrative: null, remediation_playbook: null },
  trending: { is_trending: false, recent_source_count: 0, kev_recent: false, patch_recent: false },
  historical_incidents: [],
  exploits: [exploit(0, "metasploit", "verified", 14), exploit(1, "metasploit", "verified", 13), ...Array.from({ length: 8 }, (_, i) => exploit(i, "github_poc", "reported", 20 - i))],
  exploits_total: 12,
  exploits_capped: true,
  exploits_by_kind: { metasploit: 2, github_poc: 10 },
  exploits_by_status: { verified: 2, reported: 10 },
  failed_sections: [],
};
const EMPTY_ENRICHMENT = {
  ...LOG4SHELL_ENRICHMENT,
  vendor_advisories: [],
  patches: [],
  fixed_versions: [],
  affected_packages: [],
  cwes: [],
  timeline: [],
  timeline_total: 0,
  timeline_count_7d: 0,
  timeline_count_30d: 0,
  exploits: [],
  exploits_total: 0,
  exploits_capped: false,
  exploits_by_kind: {},
  exploits_by_status: {},
  failed_sections: [],
};
// The same CVE as an API older than #2720 serves it: no counts, no failed_sections, and the
// sections that timed out silently empty.
const { exploits_total: _t, exploits_capped: _c, exploits_by_kind: _k, exploits_by_status: _s, failed_sections: _f, ...OLDER } = LOG4SHELL_ENRICHMENT;
const OLDER_EMPTY = { ...OLDER, cwes: [], exploits: [] };
// Sections the API could not read (#2720): served empty, and named.
const PARTIAL = { ...LOG4SHELL_ENRICHMENT, cwes: [], exploits: [], exploits_total: null, exploits_capped: false, exploits_by_kind: {}, exploits_by_status: {}, failed_sections: ["cwes", "exploits", "exploits_total"] };
const ALL_FAILED = { ...EMPTY_ENRICHMENT, failed_sections: ["affected_packages", "cwes", "exploits", "exploits_total", "fixed_versions", "timeline", "timeline_stats"] };
// #2817: the affected_packages rows core-backend serves since #2817 for CVE-2021-44228: one row per
// package, fixed_version one range's fix (log4j-core's 2.12.2, production's on 2026-10-04), and
// fixed_branches every range of the OSV record (GHSA-jfh8-c2jp-5v3q), in the record's order, each
// naming that record; a last_affected bound kept out of fixed; null for a row never structurally
// loaded; [] beside a fixed_version where no version range is on record (only commit ranges).
const RANGE = (introduced, fixed, last_affected = null) => ({ introduced, fixed, last_affected, source: "osv_bulk", advisory_id: "GHSA-jfh8-c2jp-5v3q" });
const LOG4J_CORE_BRANCHES = [RANGE("2.13.0", "2.15.0"), RANGE("2.0-beta9", "2.3.1"), RANGE("2.4", "2.12.2")];
const BRANCHES = {
  ...LOG4SHELL_ENRICHMENT,
  affected_packages: [
    { ecosystem: "Maven", package_name: "org.apache.logging.log4j:log4j-core", version_range: "2.10.0 ... 2.9.1 (18 versions)", fixed_version: "2.12.2", fixed_branches: LOG4J_CORE_BRANCHES, dependents_count: 0, source: "osv" },
    { ecosystem: "Maven", package_name: "com.guicedee.services:log4j-core", version_range: "1.0.10.0 ... 1.2.1.2-jre17 (362 versions)", fixed_branches: [RANGE("0", null, "1.2.1.2-jre17")], dependents_count: 0, source: "osv" },
    { ecosystem: "Debian:12", package_name: "apache-log4j2", fixed_version: "2.15.0-1", fixed_branches: null, dependents_count: 0, source: "osv_bulk" },
    { ecosystem: "Go", package_name: "example.test/commit-ranges-only", fixed_version: "8a5e1f0d3c2b", fixed_branches: [], dependents_count: 0, source: "osv_bulk" },
  ],
};
// #3285 (3.1.0's lane P): CVE-2025-48013's two rows for drupal/quick_node_block, as the public API
// served them (test/fixtures/cve_remediation-CVE-2025-48013.json, the same rows the remediation
// route lists in fixed_branches): under Packagist:https://packages.drupal.org/8 [0, 2.0.1) and
// under Packagist [0, 2.0.0). The matcher reads them as one package (core-backend
// registryRecordKey) and gives 1.0.0 fixed_in 2.0.1.
const DRUPAL_ROWS = JSON.parse(fs.readFileSync(new URL("./fixtures/cve_remediation-CVE-2025-48013.json", import.meta.url), "utf8")).data.fixed_branches;
const DRUPAL_48013 = { ...EMPTY_ENRICHMENT, affected_packages: DRUPAL_ROWS };
// A release suffix is never folded (Debian:11 and Debian:12 stay two packages); Maven with a
// repository URL is, as Packagist is.
const FOLD_OR_NOT = {
  ...EMPTY_ENRICHMENT,
  affected_packages: [
    { ecosystem: "Debian:11", package_name: "openssl", fixed_version: "1.1.1", fixed_branches: [RANGE("0", "1.1.1")] },
    { ecosystem: "Debian:12", package_name: "openssl", fixed_version: "3.0.1", fixed_branches: [RANGE("0", "3.0.1")] },
    { ecosystem: "Maven:https://repo.spring.io/release", package_name: "org.example:lib", fixed_version: "1.2.0", fixed_branches: [RANGE("0", "1.2.0")] },
    { ecosystem: "Maven", package_name: "org.example:lib", fixed_version: "1.1.0", fixed_branches: [RANGE("0", "1.1.0")] },
  ],
};
// The note's rule, applied as it reads: an installed version's fix is the first fixed above it
// that no range of its row holds, walked from the range that holds it; where the note says rows of
// one package_name under Packagist or Maven, bare or with a repository URL, are one package, the
// ranges of all those rows. Versions here are plain release numbers.
const ONE_PACKAGE_ROWS = 'Rows of one package_name under Packagist or Maven, bare or with a repository URL after ":", are one package, its ranges all of theirs together';
const relNum = (a, b) => {
  const [pa, pb] = [a, b].map((v) => v.split(".").map(Number));
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) < (pb[i] ?? 0) ? -1 : 1;
  return 0;
};
const rangeHolds = (r, v) => relNum(v, r.introduced) >= 0 && (r.fixed ? relNum(v, r.fixed) < 0 : r.last_affected ? relNum(v, r.last_affected) <= 0 : true);
function fixByIntelNote(note, rows, { ecosystem, pkg, installed }) {
  const base = (e) => e.toLowerCase().split(":")[0];
  const grouped = note.includes(ONE_PACKAGE_ROWS) && ["packagist", "maven"].includes(base(ecosystem));
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
// #2876: the exploit rows core-backend serves since #2876 (cve/enrichment_store.go ExploitRow), in
// its order (verified first, then COALESCE(source_published_at, eg_first_seen_at's UTC date)
// newest first). An Exploit-DB entry dated by Exploit-DB, as an API past the deprecation cycle
// serves it (no first_seen_at); a nuclei template whose source gives no date (source_published_at
// null, and first_seen_at null with it, where it was 1 January of the CVE's year before #2876); and
// a GitHub proof of concept dated by its repository's created_at, with all three fields.
const DATED_EXPLOITS = [
  { kind: "exploit_db", source_name: "Apache Log4j 2 - Remote Code Execution (RCE)", source_url: "https://www.exploit-db.com/exploits/50592", source_published_at: "2021-12-14T00:00:00Z", eg_first_seen_at: "2026-10-10T03:12:45.123456Z", verified_status: "verified" },
  { kind: "nuclei_template", source_name: "CVE-2021-44228", source_url: "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44228.yaml", source_published_at: null, eg_first_seen_at: "2026-10-10T03:12:46Z", first_seen_at: null, verified_status: "reported" },
  { kind: "github_poc", source_name: "kozmer/log4j-shell-poc", source_url: "https://github.com/kozmer/log4j-shell-poc", source_published_at: "2021-12-10T00:00:00Z", eg_first_seen_at: "2026-09-30T11:00:00Z", first_seen_at: "2021-12-10T00:00:00Z", verified_status: "reported" },
];
const DATED = {
  ...LOG4SHELL_ENRICHMENT,
  exploits: DATED_EXPLOITS,
  exploits_total: 3,
  exploits_capped: false,
  exploits_by_kind: { exploit_db: 1, nuclei_template: 1, github_poc: 1 },
  exploits_by_status: { verified: 1, reported: 2 },
};
// #3039: a CVE EchelonGraph holds only a Nuclei detection template for (CVE-2026-42018 on the
// hosted endpoint, 2026-10-10: its one reference is http/cves/2026/CVE-2026-42018.yaml), as an
// answer with counts serves it and as an API older than exploits_total serves it.
const NUCLEI_ROW = { kind: "nuclei_template", source_name: "http/cves/2026/CVE-2026-42018.yaml", source_url: "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-42018.yaml", source_published_at: null, eg_first_seen_at: "2026-09-18T04:00:00Z", verified_status: "reported" };
const NUCLEI_ONLY = { ...EMPTY_ENRICHMENT, exploits: [NUCLEI_ROW], exploits_total: 1, exploits_by_kind: { nuclei_template: 1 }, exploits_by_status: { reported: 1 } };
const { exploits_total: _nt, exploits_capped: _nc, exploits_by_kind: _nk, exploits_by_status: _ns, failed_sections: _nf, ...NUCLEI_ONLY_OLDER } = NUCLEI_ONLY;
// The positive claims #3039 removes for a template: "public exploit reference(s)", and "exploit
// code" anywhere but in "not necessarily exploit code".
const CODE_CLAIM = /public exploit references?|(?<!not necessarily )exploit code/;
// #3221: GitHub checker repositories (exploit_kind github_checker, #3040), from the list core-backend
// and /pulse share: core-backend/internal/cve/exploits/testdata/github_repository_kinds.json, each
// repository with the kind exploits.GitHubRepositoryKind gives it (the kind #3040's poller stores a
// new row as, and its reclassification re-kinds a stored github_poc row to) and /pulse shows it as
// (isCheckerRepository). In the monorepo the rows are read from that list. The npm tarball and the
// public repository carry mcp-server alone, so CVE-2020-35489's four, as /pulse showed them on
// 2026-10-11 (1 PoC and 3 checkers), are copied here for them, and a test below holds the copy to
// the list wherever the list is there. These are the kinds the API serves once a reclassification
// pass has re-kinded the rows; CVE_2020_35489_AS_STORED below is the answer before one has.
const HERE = path.dirname(fileURLToPath(import.meta.url));
const CORE = path.resolve(HERE, "..", "..", "core-backend");
const IN_MONOREPO = path.basename(path.resolve(HERE, "..")) === "mcp-server" || fs.existsSync(CORE);
const OUTSIDE = "no core-backend beside this package (the npm tarball or the public repository): the shared list is not here, and the copy of its CVE-2020-35489 rows runs instead";
const SHARED_KINDS_FILE = path.join(CORE, "internal", "cve", "exploits", "testdata", "github_repository_kinds.json");
function sharedRepositories() {
  // In the monorepo the list must be there: a move fails here, it is never skipped.
  assert.ok(fs.existsSync(SHARED_KINDS_FILE), `${SHARED_KINDS_FILE} is gone: find where #3040's shared list lives now and re-aim this test`);
  return JSON.parse(fs.readFileSync(SHARED_KINDS_FILE, "utf8")).repositories.map(({ source_name, description, kind }) => ({ source_name, description, kind }));
}
const SHARED = IN_MONOREPO ? sharedRepositories() : null;
const CVE_2020_35489_COPY = [
  { source_name: "Cappricio-Securities/CVE-2020-35489", description: "WordPress Contact Form 7 - Unrestricted File Upload", kind: "github_poc" },
  { source_name: "reneoliveirajr/wp_CVE-2020-35489_checker", description: 'WordPress Sites Vulnerability Checker for CVE-2020-35489 - "Educational Use Only"', kind: "github_checker" },
  { source_name: "X0UCYB3R/Check-WP-CVE-2020-35489", description: "", kind: "github_checker" },
  { source_name: "dn9uy3n/Check-WP-CVE-2020-35489", description: "The (WordPress) website test script can be exploited for Unlimited File Upload via CVE-2020-35489", kind: "github_checker" },
];
const CVE_2020_35489_REPOS = SHARED ? SHARED.filter((r) => r.source_name.includes("CVE-2020-35489")) : CVE_2020_35489_COPY;
// A repository as /enrichment serves it (core-backend cve/enrichment_store.go ExploitRow): the kind
// as stored, every GitHub row reported, dated by the repository's created_at where GitHub gives one.
const servedRepository = (r) => ({
  kind: r.kind,
  source_name: r.source_name,
  source_url: `https://github.com/${r.source_name}`,
  description: r.description,
  source_published_at: null,
  eg_first_seen_at: "2026-10-12T04:00:00Z",
  verified_status: "reported",
});
const kindCounts = (rows) => rows.reduce((m, r) => ({ ...m, [r.kind]: (m[r.kind] ?? 0) + 1 }), {});
const withExploits = (rows, listed = rows) => ({
  ...EMPTY_ENRICHMENT,
  exploits: listed,
  exploits_total: rows.length,
  exploits_capped: listed.length < rows.length,
  exploits_by_kind: kindCounts(rows),
  exploits_by_status: { reported: rows.length },
});
const CVE_2020_35489_ROWS = CVE_2020_35489_REPOS.map(servedRepository);
const CVE_2020_35489 = withExploits(CVE_2020_35489_ROWS);
const { exploits_total: _gt, exploits_capped: _gc, exploits_by_kind: _gk, exploits_by_status: _gs, failed_sections: _gf, ...CVE_2020_35489_OLDER } = CVE_2020_35489;
// The same four as the API serves them while every row is still stored as github_poc, as every
// GitHub row stored before #3040 is until a reclassification pass re-kinds it (none wrote in
// production from 2026-10-12 to 2026-10-16, a76c06c4): exploits_by_kind { github_poc: 4 }.
const CVE_2020_35489_AS_STORED = withExploits(CVE_2020_35489_ROWS.map((r) => ({ ...r, kind: "github_poc" })));
const CHECKERS_ONLY = withExploits(CVE_2020_35489_ROWS.filter((r) => r.kind === "github_checker"));
const CODE_NUCLEI_CHECKERS = withExploits([...CVE_2020_35489_ROWS, NUCLEI_ROW]);
const { exploits_total: _ot, exploits_capped: _oc, exploits_by_kind: _ok, exploits_by_status: _os, failed_sections: _of, ...CODE_NUCLEI_CHECKERS_OLDER } = CODE_NUCLEI_CHECKERS;
// 12 references counted, 10 listed, no exploits_by_kind: how many are detection checks is unknown.
const TWELVE_NO_BY_KIND = (() => {
  const { exploits_by_kind: _, ...rest } = withExploits([...CVE_2020_35489_ROWS, ...CVE_2020_35489_ROWS, ...CVE_2020_35489_ROWS], [...CVE_2020_35489_ROWS, ...CVE_2020_35489_ROWS, NUCLEI_ROW, NUCLEI_ROW]);
  return rest;
})();
// Every repository on the shared list, as one CVE's answer: the first 10 listed, all counted.
const SHARED_ROWS = SHARED ? SHARED.map(servedRepository) : null;
// The page's nouns and notes for a checker repository and a detection template (marketing-site
// components/ExploitWatch.tsx CHECKER_REPOSITORY_NOTE and DETECTION_TEMPLATE_NOTE), lower-cased and
// without the period, as the note quotes them inside its own sentence.
const CHECKER_NOTE = "a GitHub repository named or described as a checker or scanner checks whether a system is affected; it is not necessarily exploit code";
const TEMPLATE_NOTE = "a detection template checks whether a system is affected; it is not necessarily exploit code";
const capitalized = (s) => `${s[0].toUpperCase()}${s.slice(1)}`;
// Both kinds: /pulse prints its two notes in turn; this note does the same.
const BOTH_NOTES = `${TEMPLATE_NOTE}. ${capitalized(CHECKER_NOTE)}`;
// The one sentence for both kinds this tool printed before #3221's review; /pulse never prints it.
const MERGED_NOTE = /a detection template or a GitHub repository/;
// The sentence before #3221: every reference but a Nuclei template counted as exploit code.
const PRE_3221 = "EchelonGraph holds 4 public exploit references for CVE-2020-35489 (exploits_total).";
// What a date renderer gets wrong: a null printed as text, a null or a placeholder read as a time.
const BAD_DATE_TEXT = /"null"|Invalid Date|1970|first seen null|-01-01T00:00:00/i;

// #3267: a kind this server does not classify. Until #3267 this tool counted every kind but its
// two detection kinds as exploit code, so a kind core-backend added (another scanner or template
// source) reached every client as "N public exploit references", the claim #3039 removed, while
// core-backend fails closed on such a kind (egkev/backfill_exploit_poc_available.sql raises on a
// kind egkev.ExploitCodeKinds does not classify). It now counts the exploit-code kinds by name and
// reports any other kind as one it does not classify, never as exploit code.
const UNKNOWN_KIND = "foo_check";
const kindRow = (kind, i = 1) => ({ ...servedRepository({ source_name: `example/${kind}-${i}`, description: "", kind }), source_url: `https://example.test/${kind}/${i}` });
const UNCLASSIFIED_NOTE = `the kind ${UNKNOWN_KIND} is one this server does not classify: it is counted as neither exploit code nor a detection check, and a newer release of this server may classify it`;
const UNKNOWN_BESIDE_CODE = withExploits([kindRow("github_poc"), kindRow(UNKNOWN_KIND)]);
const UNKNOWN_ONLY = withExploits([kindRow(UNKNOWN_KIND, 1), kindRow(UNKNOWN_KIND, 2)]);
const { exploits_total: _ut, exploits_capped: _uc, exploits_by_kind: _uk, exploits_by_status: _us, failed_sections: _uf, ...UNKNOWN_BESIDE_TEMPLATE_OLDER } = withExploits([NUCLEI_ROW, kindRow(UNKNOWN_KIND)]);
// What #3267 removes for a kind this server does not classify: any count of it as exploit code,
// and the claim that the CVE holds no exploit code, which only a CVE whose every kind is known can
// carry.
const UNKNOWN_AS_CODE = /public exploit references?|holds no Metasploit module/;

// #3267's parity guard: core-backend's kinds, read from its source in the monorepo. The kinds are
// the exploits package's Kind* constants (exploits/types.go), and the exploit-code kinds are
// egkev.exploitCodeKinds (egkev/exploitkinds.go, "the one definition of exploit code"), which also
// names vendor_poc, the curated seed's kind, that no constant names. Every other kind is a
// detection kind there, as egkev reads it. The npm tarball and the public repository carry
// mcp-server alone, so this part is skipped there; the kind-field test below runs everywhere.
const OUTSIDE_GO = "no core-backend beside this package (the npm tarball or the public repository): its exploits Kind* constants and egkev.exploitCodeKinds are not here, and the kind-field test runs instead";
const GO_EXPLOITS_DIR = path.join(CORE, "internal", "cve", "exploits");
const GO_CODE_KINDS_FILE = path.join(CORE, "internal", "cve", "egkev", "exploitkinds.go");
// The Go package's non-test source files, as [name, text]; in the monorepo they must be there.
function goExploitsSources() {
  assert.ok(fs.existsSync(path.join(GO_EXPLOITS_DIR, "types.go")), `${GO_EXPLOITS_DIR}/types.go is gone: find where the exploit Kind* constants live now and re-aim this test`);
  return fs.readdirSync(GO_EXPLOITS_DIR).filter((f) => f.endsWith(".go") && !f.endsWith("_test.go")).sort().map((f) => [f, fs.readFileSync(path.join(GO_EXPLOITS_DIR, f), "utf8")]);
}
function goCodeKindsSource() {
  assert.ok(fs.existsSync(GO_CODE_KINDS_FILE), `${GO_CODE_KINDS_FILE} is gone: find egkev.exploitCodeKinds and re-aim this test`);
  return fs.readFileSync(GO_CODE_KINDS_FILE, "utf8");
}
// A Kind* constant in any shape Go allows on one line: in a const block (KindX = "x"), typed
// (KindX ExploitKind = "x", or KindX string = "x"), or alone (const KindX = "x"). #3267's review:
// the first version read only the untyped block shape, so a typed or a single-line constant would
// have been a kind core-backend holds that this test never saw.
const GO_KIND_CONST = /^\s*(?:const\s+)?(Kind[A-Z]\w*)(?:\s+\w+)?\s*=\s*"([^"]*)"/gm;
// The Kind* names (*Exploit).Validate() accepts: its `switch e.Kind` case list, which is what the
// pollers' rows are held to before they are stored.
function goValidatedKinds(sources) {
  const names = new Set();
  for (const [, text] of sources) {
    const fn = text.match(/^func \(e \*Exploit\) Validate\(\) error \{([\s\S]*?)^\}/m);
    if (!fn) continue;
    const sw = fn[1].match(/switch e\.Kind \{([\s\S]*?)default:/);
    assert.ok(sw, "(*Exploit).Validate() no longer switches on e.Kind before a default: re-aim this test");
    for (const c of sw[1].matchAll(/case ([^:]+):/g)) for (const n of c[1].split(",")) names.add(n.trim());
  }
  assert.ok(names.size > 0, "no (*Exploit).Validate() kind case list in core-backend/internal/cve/exploits: re-aim this test");
  return [...names].sort();
}
// { constants: {KindX: "x"}, validated: [KindX, ...], code: [...exploitCodeKinds], all: every kind, detection: all but code }.
function goKinds(sources, codeKindsSrc) {
  const constants = {};
  for (const [, text] of sources) for (const m of text.matchAll(GO_KIND_CONST)) constants[m[1]] = m[2];
  assert.ok(Object.keys(constants).length > 0, "no Kind* constant in core-backend/internal/cve/exploits: re-aim this test");
  const validated = goValidatedKinds(sources);
  const block = codeKindsSrc.match(/^var exploitCodeKinds = \[\.\.\.\]string\{([^}]*)\}/m);
  assert.ok(block, "egkev/exploitkinds.go no longer declares exploitCodeKinds as a [...]string literal: re-aim this test");
  const code = [...block[1].matchAll(/"([^"]*)"/g)].map((m) => m[1]);
  assert.ok(code.length > 0, "egkev.exploitCodeKinds is empty: re-aim this test");
  const all = [...new Set([...Object.values(constants), ...code])].sort();
  return { constants, validated, code: [...code].sort(), all, detection: all.filter((k) => !code.includes(k)) };
}
// The kinds this server's kind field names (outputSchema exploits[].kind): "Exploit code: a, b or
// c." and "A detection check, …: d (gloss) or e (gloss)."
function advertisedKinds(kindDescription) {
  const code = kindDescription.match(/^Exploit code: ([^.]+)\./);
  const detection = kindDescription.match(/A detection check, [^:]*: (.+?\))\./);
  assert.ok(code && detection, `the kind field's text no longer lists the kinds as "Exploit code: …. A detection check, …: … (…)." — re-aim this test: ${kindDescription}`);
  return {
    code: code[1].split(/, | or /).map((s) => s.trim()).sort(),
    detection: [...detection[1].matchAll(/(?:^|, | or )([a-z][a-z0-9_]*) \(/g)].map((m) => m[1]).sort(),
  };
}
// What is wrong between core-backend's kinds and this server's, as sentences: `classified` is how
// this server's note counts one reference of each kind ("code", "detection" or "unclassified").
function kindParityProblems(go, advertised, classified) {
  const out = [];
  const mcpKnows = new Set([...advertised.code, ...advertised.detection]);
  for (const k of go.all) {
    const want = go.code.includes(k) ? "code" : "detection";
    const where = go.code.includes(k) ? "egkev.exploitCodeKinds lists it" : `core-backend holds it (${Object.keys(go.constants).find((c) => go.constants[c] === k)}) and egkev.exploitCodeKinds does not list it, so it is a detection kind there`;
    const said = want === "code" ? advertised.code.includes(k) : advertised.detection.includes(k);
    if (!said) out.push(`${k}: ${where}, and this server's kind field does not name it ${want === "code" ? "as exploit code" : "as a detection check"}`);
    if (classified[k] !== want) out.push(`${k}: ${where}, and this server's note counts it as ${classified[k] ?? "nothing (not probed)"}`);
  }
  for (const k of mcpKnows) if (!go.all.includes(k)) out.push(`${k}: this server classifies it (${advertised.code.includes(k) ? "exploit code" : "a detection check"}), and core-backend holds no such kind (no exploits Kind* constant, not in egkev.exploitCodeKinds)`);
  // The constants and Validate()'s case list name the same kinds: a constant Validate() refuses is
  // never stored, and a case no constant this test read declares is a kind it missed.
  for (const name of Object.keys(go.constants)) if (!go.validated.includes(name)) out.push(`${go.constants[name]}: core-backend declares ${name}, and (*Exploit).Validate() does not accept it`);
  for (const name of go.validated) if (!Object.hasOwn(go.constants, name)) out.push(`${name}: (*Exploit).Validate() accepts it, and this test read no Kind* constant of that name`);
  return out;
}
// One reference of `kind` per answer, under its own CVE id, as the API serves it with counts.
const PROBED = new Map();
const probeCve = (kind) => {
  if (!PROBED.has(kind)) PROBED.set(kind, `CVE-2099-${3267000 + PROBED.size + 1}`);
  return PROBED.get(kind);
};

const CWE79_ROWS = [
  { cve_id: "CVE-2024-27204", severity: "MEDIUM", cvss_v3_score: 6.1, echelongraph_score: 7.2, echelongraph_severity: "HIGH", score_assessed: true, published: "2024-03-01T00:00:00Z", description: "XSS", kev_listed: true },
  { cve_id: "CVE-2010-27203", severity: "MEDIUM", cvss_v3_score: 6.1, echelongraph_score: 6.0, echelongraph_severity: "MEDIUM", score_assessed: true, published: "2010-03-01T00:00:00Z", description: "XSS", kev_listed: false },
  { cve_id: "CVE-2026-27205", severity: "NONE", score_assessed: false, published: "2026-09-01T00:00:00Z", description: "XSS", kev_listed: false },
];
const CWE79 = {
  cwe_id: "CWE-79",
  name: "Cross-site Scripting",
  description: "The product does not neutralize or incorrectly neutralizes user-controllable input.",
  total: 38512,
  cves: CWE79_ROWS,
  page: 1,
  page_size: 50,
  max_page: 200,
  order: "kev_listed desc, echelongraph_score desc (CVEs not yet scored last), cvss_v3_score desc (nulls last), published desc (nulls last), cve_id",
  catalog_version: "4.17",
};
const { order: _o, max_page: _m, catalog_version: _v, ...CWE79_OLDER } = CWE79;

const CFG = [
  {
    operator: "AND",
    nodes: [
      { operator: "OR", negate: false, cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:o:acme:fw:*:*:*:*:*:*:*:*", versionStartExcluding: "2.0", versionEndExcluding: "2.4.1", matchCriteriaId: "11111111-2222-3333-4444-555555555555" }] },
      { operator: "OR", negate: false, cpeMatch: [{ vulnerable: false, criteria: "cpe:2.3:h:acme:x100:-:*:*:*:*:*:*:*", matchCriteriaId: "66666666-7777-8888-9999-000000000000" }] },
    ],
  },
];
const CVE_RECORD = (id, extra = {}) => ({
  cve_id: id,
  description: "d",
  severity: "HIGH",
  cvss_v3_score: 8.1,
  score_assessed: true,
  echelongraph_score: 8,
  cpe_match: [{ criteria: "cpe:2.3:o:acme:fw:*:*:*:*:*:*:*:*", vulnerable: true }],
  updated_at: "2026-10-01T00:00:00Z",
  ...extra,
});

const ANSWERS = {
  [ENRICH(LOG4SHELL)]: LOG4SHELL_ENRICHMENT,
  [ENRICH("CVE-2099-27300")]: EMPTY_ENRICHMENT,
  [ENRICH("CVE-2099-27301")]: OLDER,
  [ENRICH("CVE-2099-27302")]: OLDER_EMPTY,
  [ENRICH("CVE-2099-27303")]: PARTIAL,
  [ENRICH("CVE-2099-27304")]: ALL_FAILED,
  [ENRICH("CVE-2099-27305")]: { status: 500, body: { error: "boom" } },
  [ENRICH("CVE-2099-28170")]: BRANCHES,
  [ENRICH("CVE-2025-48013")]: DRUPAL_48013,
  [ENRICH("CVE-2099-48014")]: FOLD_OR_NOT,
  [ENRICH("CVE-2099-28760")]: DATED,
  [ENRICH("CVE-2026-42018")]: NUCLEI_ONLY,
  [ENRICH("CVE-2099-30390")]: NUCLEI_ONLY_OLDER,
  [ENRICH("CVE-2020-35489")]: CVE_2020_35489,
  [ENRICH("CVE-2099-32210")]: CVE_2020_35489_OLDER,
  [ENRICH("CVE-2099-32211")]: CHECKERS_ONLY,
  [ENRICH("CVE-2099-32212")]: CODE_NUCLEI_CHECKERS,
  [ENRICH("CVE-2099-32214")]: CVE_2020_35489_AS_STORED,
  [ENRICH("CVE-2099-32215")]: TWELVE_NO_BY_KIND,
  ...(SHARED_ROWS ? { [ENRICH("CVE-2099-32213")]: withExploits(SHARED_ROWS, SHARED_ROWS.slice(0, 10)) } : {}),
  [ENRICH("CVE-2099-32216")]: CODE_NUCLEI_CHECKERS_OLDER,
  [ENRICH("CVE-2099-32670")]: UNKNOWN_BESIDE_CODE,
  [ENRICH("CVE-2099-32671")]: UNKNOWN_ONLY,
  [ENRICH("CVE-2099-32672")]: UNKNOWN_BESIDE_TEMPLATE_OLDER,
  "/api/v1/public/cwes/CWE-79": CWE79,
  "/api/v1/public/cwes/CWE-79?page=3": { ...CWE79, page: 3 },
  "/api/v1/public/cwes/CWE-79?page=200": { ...CWE79, page: 200, cves: [] },
  "/api/v1/public/cwes/CWE-80": { ...CWE79_OLDER, cwe_id: "CWE-80", name: "Basic XSS", total: 3 },
  "/api/v1/public/cwes/CWE-99999": { cwe_id: "CWE-99999", total: 0, cves: [], page: 1, page_size: 50, max_page: 200, order: CWE79.order },
  // The API clamps a page past its last to the last page it serves.
  "/api/v1/public/cwes/CWE-81?page=7": { ...CWE79, cwe_id: "CWE-81", total: 120, page: 3 },
  "/api/v1/public/cves/CVE-2099-27310": CVE_RECORD("CVE-2099-27310", { cpe_configurations: CFG }),
  "/api/v1/public/cves/CVE-2099-27311": CVE_RECORD("CVE-2099-27311"),
};

let stub;
const seen = [];
before(async () => {
  stub = http.createServer((req, res) => {
    seen.push(req.url);
    const a = ANSWERS[req.url];
    if (a === undefined) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: `not found: ${new URL(req.url, "http://stub").pathname}` }));
      return;
    }
    res.writeHead(a.status ?? 200, { "content-type": "application/json" });
    res.end(JSON.stringify(a.status ? a.body : a));
  });
  await new Promise((resolve) => stub.listen(0, "127.0.0.1", resolve));
});
after(() => new Promise((resolve) => stub.close(resolve)));

const validator = new StrictOutputValidator();
const textBlocks = (res) => (res.content ?? []).filter((c) => c.type === "text").map((c) => c.text);
const noteOf = (res) => textBlocks(res)[res.isError ? 0 : 1] ?? "";
const sentences = (t) => t.replace(/\s+/g, " ").trim().split(/(?<=[.!?])\s+/).filter(Boolean);
function schemaNames(s, out = new Set()) {
  if (s === null || typeof s !== "object") return out;
  if (Array.isArray(s)) {
    for (const x of s) schemaNames(x, out);
    return out;
  }
  for (const e of s.enum ?? []) if (typeof e === "string") out.add(e);
  if (s.properties) for (const k of Object.keys(s.properties)) out.add(k);
  for (const [k, x] of Object.entries(s)) if (k !== "enum" && k !== "description") schemaNames(x, out);
  return out;
}
// Every description string a schema holds, at any depth.
function schemaDescriptions(s, out = []) {
  if (Array.isArray(s)) for (const x of s) schemaDescriptions(x, out);
  else if (s !== null && typeof s === "object") {
    for (const [k, x] of Object.entries(s)) {
      if (k === "description" && typeof x === "string") out.push(x);
      else schemaDescriptions(x, out);
    }
  }
  return out;
}

for (const era of ERAS) {
  describe(`#2720 cve_intel, get_cwe and get_cve's cpe_configurations [${era}]`, () => {
    let client;
    let tools;
    const results = [];
    const call = async (name, args) => {
      const res = await client.callTool({ name, arguments: args });
      results.push([name, args, res]);
      return res;
    };
    before(async () => {
      client = await connect({
        era,
        ...serverCommand(),
        env: { ...process.env, ECHELONGRAPH_API_BASE: `http://127.0.0.1:${stub.address().port}`, ECHELONGRAPH_API_TIMEOUT_MS: "2000" },
        stderr: "ignore",
      });
      ({ tools } = await client.listTools());
    });
    after(() => client?.close());
    const schemaOf = (name) => tools.find((t) => t.name === name).outputSchema;

    // Every result's text is its structuredContent: data, then the note, then the rest.
    function assertTextIsStructure(where, res) {
      const sc = res.structuredContent;
      const blocks = textBlocks(res);
      assert.equal(blocks.length, res.isError ? 2 : 3, `${where}: text blocks`);
      const env = JSON.parse(blocks.at(-1));
      for (const k of ["state", "measured_at", "coverage", "freshness"]) assert.deepEqual(env[k], sc[k], `${where}: envelope block ${k}`);
      if (!res.isError) assert.deepEqual(JSON.parse(blocks[0]), sc.data, `${where}: data`);
      const said = sentences(blocks.at(-2));
      assert.deepEqual(sc.notes.slice(-said.length), said, `${where}: notes end with the note's sentences`);
    }

    it("tools/list: both tools registered after check_sbom, with titles, annotations and an outputSchema", () => {
      // The full order is tools.test.mjs's LISTED; here, the two together, where createServer registers them.
      const names = tools.map((t) => t.name);
      const at = names.indexOf("check_sbom");
      // #2841: cve_remediation is registered between them (cve_remediation.test.mjs); #2835:
      // scan_manifest right after check_sbom (scan_manifest.test.mjs).
      assert.deepEqual(names.slice(at, at + 5), ["check_sbom", "scan_manifest", "cve_intel", "cve_remediation", "get_cwe"]);
      for (const name of ["cve_intel", "get_cwe"]) {
        const t = tools.find((x) => x.name === name);
        assert.ok(t.title, name);
        assert.deepEqual(t.annotations, { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true });
        assert.equal(t.outputSchema.type, "object");
        const ok = t.outputSchema.oneOf.find((b) => b.properties.state.enum.includes("measured"));
        // #3121: published open to fields it does not name; the suite validates with it closed.
        assert.notEqual(ok.additionalProperties, false);
        for (const k of ["state", "measured_at", "method", "coverage", "freshness", "notes", "data"]) assert.ok(ok.required.includes(k), `${name}: ${k}`);
      }
    });

    it("#1880 rule: every field a description names is in that tool's outputSchema; no removed claim; no hosts", () => {
      for (const name of ["cve_intel", "get_cwe", "get_cve"]) {
        const t = tools.find((x) => x.name === name);
        const names = schemaNames(t.outputSchema);
        const unknown = [...new Set(t.description.match(FIELD_TOKEN) ?? [])].filter((x) => !names.has(x));
        assert.deepEqual(unknown, [], `${name}: description names fields its outputSchema lacks`);
        assert.doesNotMatch(t.description, REMOVED_CLAIMS, name);
        assert.doesNotMatch(t.description, HOST_UNIT, name);
      }
      assert.match(tools.find((t) => t.name === "get_cve").description, /cpe_configurations \(NVD's configurations as NVD sent them, with each AND\/OR operator/);
      assert.doesNotMatch(tools.find((t) => t.name === "get_cve").description, /\bCWE\b/, "get_cve returns no CWE");
    });

    it("cve_intel: Log4Shell-shaped answer — CWE-502 and CWE-917, 12 references past the cap, verified first, a labelled cut", async () => {
      seen.length = 0;
      const res = await call("cve_intel", { cve_id: LOG4SHELL.toLowerCase() });
      assert.ok(!res.isError, noteOf(res));
      assert.deepEqual(seen, [ENRICH(LOG4SHELL)], "only /enrichment, canonical id; never /blast-radius");
      const sc = res.structuredContent;
      assert.equal(sc.state, "measured");
      assert.equal(sc.measured_at, null);
      assert.equal(sc.freshness, null);
      assert.deepEqual(
        Object.keys(sc.data).sort(),
        ["affected_packages", "cve_id", "cwes", "exploits", "exploits_by_kind", "exploits_by_status", "exploits_capped", "exploits_total", "fixed_versions", "timeline", "timeline_count_30d", "timeline_count_7d", "timeline_total"].sort(),
      );
      assert.deepEqual(sc.data.cwes.map((c) => c.cwe_id), ["CWE-502", "CWE-917"]);
      assert.deepEqual(sc.data.exploits, LOG4SHELL_ENRICHMENT.exploits, "exploits relayed as sent");
      assert.equal(sc.data.exploits[0].verified_status, "verified");
      assert.equal(sc.data.exploits_total, 12);
      assert.equal(sc.data.timeline.length, 20);
      assert.deepEqual(sc.data.timeline, TIMELINE.slice(0, 20), "the newest 20, as sent");
      assert.deepEqual(sc.coverage.sections_failed, []);
      assert.deepEqual(sc.coverage.sections_left_out, ["vendor_advisories", "patches", "ai", "trending", "historical_incidents"]);
      assert.deepEqual(sc.coverage.exploits, { returned: 10, api_row_limit: 10 });
      assert.deepEqual(sc.coverage.timeline, { returned: 25, relayed: 20, api_row_limit: 100 });
      const n = noteOf(res);
      assert.match(n, /^cve_intel OK: EchelonGraph answered HTTP 200 from /);
      assert.ok(n.includes("CVE-2021-44228 is classified under CWE-502 (Deserialization of Untrusted Data) and CWE-917 (Improper Neutralization"), n);
      assert.ok(n.includes("EchelonGraph holds 12 public exploit references for CVE-2021-44228 (exploits_total), 2 of them with verified_status verified. exploits_capped is true: exploits lists 10 of the 12, verified first."), n);
      assert.ok(n.includes("timeline relays the 20 newest of the 25 enrichment-history rows the API returned (timeline_total 140)."), n);
      assert.ok(n.includes("Not relayed from the answer: vendor_advisories, patches, ai, trending and historical_incidents."), n);
      assert.doesNotMatch(JSON.stringify(res), /generated text/, "the ai section is not relayed");
      // #3221: the detection checks are Nuclei templates and GitHub checker repositories.
      assert.match(sc.method, /public exploit code, namely Metasploit modules \(metasploit\), Exploit-DB entries \(exploit_db\), GitHub proof-of-concept repositories \(github_poc\) and vendor proofs of concept \(vendor_poc\), and detection checks, namely Nuclei detection templates \(nuclei_template\) and GitHub checker repositories \(github_checker: GitHub repositories named or described as a checker or scanner\), which check whether a system is affected and are not necessarily exploit code/);
      assert.match(sc.method, /each run only where it is enabled, so which sources are current depends on the deployment/);
      // #3267's review: built from the note's two lists, the method says what any other kind is, and
      // names exactly the kinds the kind field names, exploit code before detection.
      assert.match(sc.method, /depends on the deployment\. A kind on neither list is one this server does not classify: the note counts it as neither\./);
      const [methodCode, methodDetection] = sc.method.split("and detection checks, namely");
      const kindsIn = (t) => [...t.matchAll(/\(([a-z][a-z0-9_]*)[):]/g)].map((m) => m[1]).sort();
      const field = advertisedKinds(tools.find((t) => t.name === "cve_intel").outputSchema.oneOf.find((b) => b.properties.state.enum.includes("measured")).properties.data.properties.exploits.items.properties.kind.description);
      assert.deepEqual([kindsIn(methodCode.slice(methodCode.indexOf("exploits:"))), kindsIn(methodDetection.split(", which check")[0])], [field.code, field.detection]);
      assert.doesNotMatch(sc.method, /\bpolled (daily|every)\b/i, "method claims no source is polled");
      assertTextIsStructure("cve_intel ok", res);
    });

    it("#3039 cve_intel: a Nuclei-only CVE is one detection template, never exploit code or a public exploit reference", async () => {
      for (const [cve, want] of [
        ["CVE-2026-42018", "EchelonGraph holds 1 Nuclei detection template for CVE-2026-42018 and nothing else in exploits (exploits_total 1): a detection template checks whether a system is affected; it is not necessarily exploit code. It holds no Metasploit module, Exploit-DB entry or proof of concept for CVE-2026-42018, which is not evidence that none exists."],
        ["CVE-2099-30390", "exploits lists 1 Nuclei detection template and nothing else (a detection template checks whether a system is affected; it is not necessarily exploit code) for CVE-2099-30390, 0 with verified_status verified; the answer carries no exploits_total, so it does not say how many are on record."],
      ]) {
        const res = await call("cve_intel", { cve_id: cve });
        assert.ok(!res.isError, noteOf(res));
        const n = noteOf(res);
        assert.ok(n.includes(want), n);
        for (const note of res.structuredContent.notes) assert.doesNotMatch(note, CODE_CLAIM, `${cve}: ${note}`);
        assertTextIsStructure(`cve_intel nuclei-only ${cve}`, res);
      }
      // The description and the method name the template as a detection check.
      const d = tools.find((t) => t.name === "cve_intel").description;
      // #3221: "detection checks", templates and GitHub checker repositories together.
      assert.match(d, /^Weakness, exploit code, detection checks, affected packages and fixed versions for one CVE/);
      assert.doesNotMatch(d, /public exploit code/, "the description calls the whole list public exploit code");
      assert.ok(d.length <= 1948, `${d.length} characters: the budget is 1,948`);
      const [, , ok] = results.find(([n, a]) => n === "cve_intel" && a.cve_id === "CVE-2026-42018");
      assert.match(ok.structuredContent.method, /Nuclei detection templates \(nuclei_template\) and GitHub checker repositories \(github_checker: [^)]*\), which check whether a system is affected and are not necessarily exploit code/);
    });

    it("#3039 control: the pre-#3039 wording is caught by the claim check", () => {
      for (const old of [
        "EchelonGraph holds 1 public exploit reference for CVE-2026-42018 (exploits_total).",
        "exploits lists 1 public exploit reference for CVE-2099-30390, 0 with verified_status verified",
        "public exploit code on record.",
      ]) assert.match(old, CODE_CLAIM, old);
      assert.doesNotMatch("it is not necessarily exploit code.", CODE_CLAIM);
    });

    // #3221: CVE-2020-35489 on /pulse (2026-10-11) is 1 GitHub PoC and 3 GitHub checker
    // repositories. Served with the 3 as github_checker (the kinds the shared list gives), this
    // note counts them apart; until #3221 it said "4 public exploit references" for that answer.
    it("#3221 cve_intel: CVE-2020-35489's 3 GitHub checker repositories are counted apart, never as exploit code", async () => {
      assert.deepEqual(kindCounts(CVE_2020_35489_ROWS), { github_poc: 1, github_checker: 3 }, "re-aim this test: CVE-2020-35489's rows are no longer 1 PoC and 3 checkers");
      const res = await call("cve_intel", { cve_id: "CVE-2020-35489" });
      assert.ok(!res.isError, noteOf(res));
      const sc = res.structuredContent;
      // Relayed as sent: each row keeps the kind the API gave it, and the counts are the API's.
      assert.deepEqual(sc.data.exploits, CVE_2020_35489_ROWS);
      assert.deepEqual(sc.data.exploits_by_kind, { github_poc: 1, github_checker: 3 });
      const n = noteOf(res);
      assert.ok(n.includes(`EchelonGraph holds 4 references for CVE-2020-35489 (exploits_total): 1 public exploit reference and 3 GitHub checker repositories; ${CHECKER_NOTE}.`), n);
      assert.ok(!n.includes(PRE_3221), n);
      assert.doesNotMatch(n, /\b[2-9] public exploit references\b/, "a checker repository is counted as exploit code");
      assertTextIsStructure("cve_intel CVE-2020-35489", res);
    });

    it("#3221 cve_intel: checker repositories alone, beside a template, and in an answer older than exploits_total", async () => {
      for (const [cve, want] of [
        [
          "CVE-2099-32211",
          `EchelonGraph holds 3 GitHub checker repositories for CVE-2099-32211 and nothing else in exploits (exploits_total 3): ${CHECKER_NOTE}. It holds no Metasploit module, Exploit-DB entry or proof of concept for CVE-2099-32211, which is not evidence that none exists.`,
        ],
        [
          "CVE-2099-32212",
          // Both kinds: /pulse's two notes in turn (#3221's review), never one merged sentence.
          `EchelonGraph holds 5 references for CVE-2099-32212 (exploits_total): 1 public exploit reference, 1 Nuclei detection template and 3 GitHub checker repositories; ${BOTH_NOTES}.`,
        ],
        [
          "CVE-2099-32210",
          `exploits lists 4 references: 1 public exploit reference and 3 GitHub checker repositories (${CHECKER_NOTE}) for CVE-2099-32210, 0 with verified_status verified; the answer carries no exploits_total, so it does not say how many are on record.`,
        ],
      ]) {
        const res = await call("cve_intel", { cve_id: cve });
        assert.ok(!res.isError, noteOf(res));
        const n = noteOf(res);
        assert.ok(n.includes(want), `${cve}: ${n}`);
        assertTextIsStructure(`cve_intel ${cve}`, res);
      }
      // A checker-only CVE claims no exploit code anywhere in its notes, as a Nuclei-only one does (#3039).
      const [, , only] = results.find(([name, a]) => name === "cve_intel" && a.cve_id === "CVE-2099-32211");
      for (const note of only.structuredContent.notes) assert.doesNotMatch(note, CODE_CLAIM, note);
    });

    // #3221's review: /pulse prints DETECTION_TEMPLATE_NOTE and then CHECKER_REPOSITORY_NOTE where
    // both kinds are present (ExploitWatch.tsx exploitWatchSummary's notes), and the issue asks for
    // the page's wording. Every sentence that names both kinds gives the two notes in turn: with
    // counts, from the listed rows of an answer older than exploits_total, and where the answer
    // carries no exploits_by_kind, so which kinds are present is unknown.
    it("#3221 cve_intel: a template beside checker repositories, or kinds unknown, gets /pulse's two notes in turn, never one merged sentence", async () => {
      const wrong = [];
      for (const [cve, want] of [
        ["CVE-2099-32212", `1 public exploit reference, 1 Nuclei detection template and 3 GitHub checker repositories; ${BOTH_NOTES}.`],
        ["CVE-2099-32216", `exploits lists 5 references: 1 public exploit reference, 1 Nuclei detection template and 3 GitHub checker repositories (${BOTH_NOTES}) for CVE-2099-32216,`],
        [
          "CVE-2099-32215",
          `(exploits_total); the answer carries no exploits_by_kind, so it does not say how many are exploit code and how many detection checks, Nuclei detection templates or GitHub checker repositories (${BOTH_NOTES}). exploits_capped is true: exploits lists 10 of the 12, verified first.`,
        ],
      ]) {
        const res = await call("cve_intel", { cve_id: cve });
        assert.ok(!res.isError, noteOf(res));
        const n = noteOf(res);
        // Every case is read before any fails, so a failure names each sentence that is wrong.
        if (!n.includes(want) || MERGED_NOTE.test(n)) wrong.push(`${cve}: ${n}`);
        assertTextIsStructure(`cve_intel ${cve}`, res);
      }
      assert.deepEqual(wrong, [], "a sentence naming both kinds does not give /pulse's two notes in turn");
    });

    // The counts are the kinds the API serves, never re-read from a repository's name. While the
    // API serves CVE-2020-35489's four rows as github_poc, as it does a row stored before #3040
    // until a reclassification pass re-kinds it, this note counts all four as public exploit
    // references, checker-named or not. So the MCP release alone does not change that CVE's
    // answer: the API serving the 3 checkers as github_checker does.
    it("#3221 cve_intel: a repository the API serves as github_poc is a public exploit reference, whatever its name says", async () => {
      const res = await call("cve_intel", { cve_id: "CVE-2099-32214" });
      assert.ok(!res.isError, noteOf(res));
      const sc = res.structuredContent;
      assert.deepEqual(sc.data.exploits_by_kind, { github_poc: 4 });
      assert.ok(sc.data.exploits.some((r) => /_checker$/.test(r.source_name)), "re-aim this test: the rows hold no checker-named repository");
      const n = noteOf(res);
      assert.ok(n.includes("EchelonGraph holds 4 public exploit references for CVE-2099-32214 (exploits_total)."), n);
      assert.doesNotMatch(n, /GitHub checker repositor/, n);
      assertTextIsStructure("cve_intel CVE-2099-32214", res);
    });

    it("#3221 cve_intel: every repository on core-backend's shared list is counted under the kind it is stored as", { skip: SHARED_ROWS ? false : OUTSIDE }, async () => {
      const kinds = kindCounts(SHARED_ROWS);
      assert.deepEqual(Object.keys(kinds).sort(), ["github_checker", "github_poc"], "re-aim this test: the shared list holds a kind past the two GitHub ones");
      const res = await call("cve_intel", { cve_id: "CVE-2099-32213" });
      assert.ok(!res.isError, noteOf(res));
      const total = SHARED_ROWS.length;
      const n = noteOf(res);
      assert.ok(
        n.includes(
          `EchelonGraph holds ${total} references for CVE-2099-32213 (exploits_total): ${kinds.github_poc} public exploit references and ${kinds.github_checker} GitHub checker repositories; ${CHECKER_NOTE}. exploits_capped is true: exploits lists 10 of the ${total}, verified first.`,
        ),
        n,
      );
      assertTextIsStructure("cve_intel shared list", res);
    });

    it("#3221: the CVE-2020-35489 rows copied for the tarball are the shared list's", { skip: SHARED ? false : OUTSIDE }, () => {
      assert.deepEqual(SHARED.filter((r) => r.source_name.includes("CVE-2020-35489")), CVE_2020_35489_COPY);
    });

    it("#3221: the kind field's text names github_checker a detection check, and the description says detection checks", () => {
      const intel = tools.find((t) => t.name === "cve_intel");
      const items = intel.outputSchema.oneOf.find((b) => b.properties.state.enum.includes("measured")).properties.data.properties;
      const kind = items.exploits.items.properties.kind.description;
      const [code, detection] = kind.split("A detection check");
      assert.ok(detection, kind);
      for (const k of ["metasploit", "exploit_db", "github_poc", "vendor_poc"]) assert.match(code, new RegExp(`\\b${k}\\b`), kind);
      for (const k of ["nuclei_template", "github_checker"]) {
        assert.doesNotMatch(code, new RegExp(`\\b${k}\\b`), `${k} is listed with the exploit-code kinds: ${kind}`);
        assert.match(detection, new RegExp(`\\b${k}\\b`), kind);
      }
      assert.match(detection, /github_checker \(a GitHub repository named or described as a checker or scanner\)/);
      assert.match(items.exploits_by_kind.description, /the counts under nuclei_template and github_checker are detection checks, not exploit code/);
      // #3267's review: built from the note's two lists, it names the exploit-code kinds and what any other kind is.
      assert.match(items.exploits_by_kind.description, /those under metasploit, exploit_db, github_poc and vendor_poc are exploit code, and those under any other kind are of a kind this server does not classify, counted as neither\./);
      assert.match(items.exploits.items.properties.verified_status.description, /GitHub proofs of concept and checker repositories/);
      assert.doesNotMatch(intel.description, /detection templates/, "a GitHub checker repository is not a detection template");
    });

    // /pulse's wording, read from the page's own source: its nouns for a github_checker and a
    // nuclei_template reference and its note on each, which this tool's note repeats.
    it("#3221: the checker's and the template's nouns and notes are /pulse's (marketing-site components/ExploitWatch.tsx)", { skip: IN_MONOREPO ? false : OUTSIDE }, () => {
      const page = path.resolve(CORE, "..", "marketing-site", "components", "ExploitWatch.tsx");
      assert.ok(fs.existsSync(page), `${page} is gone: re-aim this test`);
      const src = fs.readFileSync(page, "utf8").replace(/\s+/g, " ");
      assert.ok(src.includes('github_checker: ["GitHub checker repository", "GitHub checker repositories"]'), "/pulse's KIND_NOUN for github_checker changed");
      assert.ok(src.includes('nuclei_template: ["Nuclei detection template", "Nuclei detection templates"]'), "/pulse's KIND_NOUN for nuclei_template changed");
      assert.ok(src.includes(`CHECKER_REPOSITORY_NOTE = "${capitalized(CHECKER_NOTE)}."`), "/pulse's CHECKER_REPOSITORY_NOTE changed");
      assert.ok(src.includes(`DETECTION_TEMPLATE_NOTE = "${capitalized(TEMPLATE_NOTE)}."`), "/pulse's DETECTION_TEMPLATE_NOTE changed");
      // Both kinds: the template's note, then the checker's (exploitWatchSummary's notes).
      assert.ok(src.includes("${hasNuclei ? ` ${DETECTION_TEMPLATE_NOTE}` : \"\"}${hasChecker ? ` ${CHECKER_REPOSITORY_NOTE}` : \"\"}"), "/pulse no longer prints the template's note and then the checker's");
    });

    // #3267: how this server's note counts one reference of `kind`, served with its counts.
    const classify = async (kind) => {
      const cve = probeCve(kind);
      ANSWERS[ENRICH(cve)] = withExploits([kindRow(kind)]);
      const res = await call("cve_intel", { cve_id: cve });
      assert.ok(!res.isError, noteOf(res));
      const n = noteOf(res);
      if (n.includes(`EchelonGraph holds 1 public exploit reference for ${cve} (exploits_total).`)) return "code";
      if (n.includes(`for ${cve} and nothing else in exploits (exploits_total 1)`) && !UNKNOWN_AS_CODE.test(n.replace(/It holds no Metasploit module[^.]*\./, ""))) return "detection";
      if (n.includes(`1 reference of a kind this server does not classify`) && !UNKNOWN_AS_CODE.test(n)) return "unclassified";
      return `a note this test does not read: ${n}`;
    };
    const kindField = () => tools.find((t) => t.name === "cve_intel").outputSchema.oneOf.find((b) => b.properties.state.enum.includes("measured")).properties.data.properties.exploits.items.properties.kind.description;

    it("#3267 cve_intel: a kind this server does not classify is counted as neither exploit code nor a detection check", async () => {
      const wrong = [];
      for (const [cve, want] of [
        ["CVE-2099-32670", `EchelonGraph holds 2 references for CVE-2099-32670 (exploits_total): 1 public exploit reference and 1 reference of a kind this server does not classify; ${UNCLASSIFIED_NOTE}.`],
        ["CVE-2099-32671", `EchelonGraph holds 2 references for CVE-2099-32671 (exploits_total): 2 references of a kind this server does not classify; ${UNCLASSIFIED_NOTE}.`],
        [
          "CVE-2099-32672",
          `exploits lists 2 references: 1 Nuclei detection template and 1 reference of a kind this server does not classify (${TEMPLATE_NOTE}. ${capitalized(UNCLASSIFIED_NOTE)}) for CVE-2099-32672, 0 with verified_status verified; the answer carries no exploits_total, so it does not say how many are on record.`,
        ],
      ]) {
        const res = await call("cve_intel", { cve_id: cve });
        assert.ok(!res.isError, noteOf(res));
        const n = noteOf(res);
        // Every case is read before any fails, so a failure names each sentence that is wrong.
        if (!n.includes(want)) wrong.push(`${cve}: ${n}`);
        assertTextIsStructure(`cve_intel ${cve}`, res);
      }
      assert.deepEqual(wrong, [], "a reference of a kind this server does not classify is counted as something");
      // Relayed as sent: the kind and the counts are the API's.
      const [, , only] = results.find(([name, a]) => name === "cve_intel" && a.cve_id === "CVE-2099-32671");
      assert.deepEqual(only.structuredContent.data.exploits_by_kind, { [UNKNOWN_KIND]: 2 });
      assert.ok(only.structuredContent.data.exploits.every((r) => r.kind === UNKNOWN_KIND));
      // Nothing of a CVE whose every reference is of an unknown kind calls one exploit code, or says
      // the CVE holds none.
      for (const note of only.structuredContent.notes) assert.doesNotMatch(note, UNKNOWN_AS_CODE, note);
      const [, , beside] = results.find(([name, a]) => name === "cve_intel" && a.cve_id === "CVE-2099-32670");
      assert.doesNotMatch(noteOf(beside), /\b2 public exploit references\b/, "the unknown kind is counted as exploit code");
    });

    it("#3267: the kind field names exploit code and detection kinds apart, and the note counts each as the field says and any other kind as neither", async () => {
      const kinds = advertisedKinds(kindField());
      assert.ok(kinds.code.length > 0 && kinds.detection.length > 0, JSON.stringify(kinds));
      assert.deepEqual(kinds.code.filter((k) => kinds.detection.includes(k)), [], "a kind is named both exploit code and a detection check");
      assert.match(kindField(), /A kind not named here is one this server does not classify/);
      const got = {};
      for (const k of [...kinds.code, ...kinds.detection, UNKNOWN_KIND]) got[k] = await classify(k);
      const want = Object.fromEntries([...kinds.code.map((k) => [k, "code"]), ...kinds.detection.map((k) => [k, "detection"]), [UNKNOWN_KIND, "unclassified"]]);
      assert.deepEqual(got, want);
    });

    // core-backend's kinds and this server's are the same two lists: a kind either side adds alone
    // fails here, before any client is told about it.
    it("#3267: every core-backend exploit kind is classified here as egkev.ExploitCodeKinds classifies it, and this server names no other", { skip: IN_MONOREPO ? false : OUTSIDE_GO }, async () => {
      const go = goKinds(goExploitsSources(), goCodeKindsSource());
      const advertised = advertisedKinds(kindField());
      const classified = {};
      for (const k of new Set([...go.all, ...advertised.code, ...advertised.detection])) classified[k] = await classify(k);
      assert.deepEqual(kindParityProblems(go, advertised, classified), [], `core-backend: exploit code ${go.code.join(", ")}; detection ${go.detection.join(", ")}`);
    });

    it("#3267 control: a kind added alone to core-backend's constants or exploitCodeKinds, or to this server's lists, fails the parity check", { skip: IN_MONOREPO ? false : OUTSIDE_GO }, async () => {
      const sources = goExploitsSources();
      const codeSrc = goCodeKindsSource();
      const advertised = advertisedKinds(kindField());
      const probe = async (go, adv = advertised) => {
        const classified = {};
        for (const k of new Set([...go.all, ...adv.code, ...adv.detection])) classified[k] = await classify(k);
        return kindParityProblems(go, adv, classified);
      };
      // A new Kind* constant (#3267's control: KindFoo = "foo_check" in types.go).
      const withConstant = sources.map(([f, t]) => [f, f === "types.go" ? t.replace(/^(\s*KindGitHubPoC\s*=\s*"github_poc")$/m, `$1\n\tKindFoo = "${UNKNOWN_KIND}"`) : t]);
      assert.notDeepEqual(withConstant, sources, "types.go no longer declares KindGitHubPoC: re-aim this control");
      const constantProblems = await probe(goKinds(withConstant, codeSrc));
      assert.ok(constantProblems.some((p) => p.startsWith(`${UNKNOWN_KIND}: core-backend holds it (KindFoo)`) && p.includes("counts it as unclassified")), constantProblems.join("\n"));
      // #3267's review: the two shapes the first regex missed, each alone in a copy of types.go: a
      // single-line constant and a typed one in the const block. Each must turn the check red, and the
      // first version's regex reads neither (so this control is the one that catches the miss).
      const firstRegex = /^\s*(Kind[A-Z]\w*)(?:\s+string)?\s*=\s*"([^"]*)"/gm;
      for (const [shape, edit, name, kind] of [
        ["single-line const", (t) => `${t}\nconst KindSingle = "single_check"\n`, "KindSingle", "single_check"],
        ["typed in the block", (t) => t.replace(/^(\s*KindGitHubPoC\s*=\s*"github_poc")$/m, `$1\n\tKindTyped ExploitKind = "typed_check"`), "KindTyped", "typed_check"],
      ]) {
        const copy = sources.map(([f, t]) => [f, f === "types.go" ? edit(t) : t]);
        assert.notDeepEqual(copy, sources, `${shape}: the copy of types.go did not change: re-aim this control`);
        const text = copy.find(([f]) => f === "types.go")[1];
        assert.ok(![...text.matchAll(firstRegex)].some((m) => m[1] === name), `${shape}: the first version's regex reads ${name}, so this control proves nothing`);
        const go = goKinds(copy, codeSrc);
        assert.equal(go.constants[name], kind, `${shape}: goKinds does not read ${name}`);
        const shapeProblems = await probe(go);
        assert.ok(shapeProblems.some((p) => p.startsWith(`${kind}: core-backend holds it (${name})`) && p.includes("counts it as unclassified")), `${shape}: ${shapeProblems.join("\n")}`);
        assert.ok(shapeProblems.includes(`${kind}: core-backend declares ${name}, and (*Exploit).Validate() does not accept it`), `${shape}: ${shapeProblems.join("\n")}`);
      }
      // Validate()'s case list drifting from the constants: a constant dropped from it, a case added.
      const dropped = sources.map(([f, t]) => [f, f === "types.go" ? t.replace(/case (KindMetasploit, [^:]*), KindGitHubChecker:/, "case $1:") : t]);
      assert.notDeepEqual(dropped, sources, "Validate()'s case list no longer ends with KindGitHubChecker: re-aim this control");
      assert.ok((await probe(goKinds(dropped, codeSrc))).includes("github_checker: core-backend declares KindGitHubChecker, and (*Exploit).Validate() does not accept it"));
      const added = sources.map(([f, t]) => [f, f === "types.go" ? t.replace(/(case KindMetasploit, [^:]*):/, "$1, KindNotDeclaredHere:") : t]);
      assert.ok((await probe(goKinds(added, codeSrc))).includes("KindNotDeclaredHere: (*Exploit).Validate() accepts it, and this test read no Kind* constant of that name"));
      // A new exploit-code kind in egkev.exploitCodeKinds.
      const withCode = codeSrc.replace(/("vendor_poc")\}/, '$1, "bar_exploit"}');
      assert.notEqual(withCode, codeSrc, "exploitCodeKinds no longer ends with vendor_poc: re-aim this control");
      const codeProblems = await probe(goKinds(sources, withCode));
      assert.ok(codeProblems.some((p) => p.startsWith("bar_exploit: egkev.exploitCodeKinds lists it") && p.includes("counts it as unclassified")), codeProblems.join("\n"));
      // A kind this server names that core-backend does not hold.
      const extra = await probe(goKinds(sources, codeSrc), { ...advertised, detection: [...advertised.detection, "baz_scanner"].sort() });
      assert.ok(extra.some((p) => p.startsWith("baz_scanner: this server classifies it")), extra.join("\n"));
      // A kind core-backend moves between the lists (github_checker into exploitCodeKinds).
      const moved = await probe(goKinds(sources, codeSrc.replace(/("vendor_poc")\}/, '$1, "github_checker"}')));
      assert.ok(moved.some((p) => p.startsWith("github_checker: egkev.exploitCodeKinds lists it") && p.includes("counts it as detection")), moved.join("\n"));
    });

    it("cve_intel: zero references is a counted zero, never 'no exploit exists'", async () => {
      const res = await call("cve_intel", { cve_id: "CVE-2099-27300" });
      const n = noteOf(res);
      assert.ok(n.includes("EchelonGraph holds no public exploit reference for CVE-2099-27300 (exploits_total 0). That is not evidence that no public exploit exists"), n);
      assert.ok(n.includes("No CWE classification is on record for CVE-2099-27300 (cwes is empty)"), n);
      assert.ok(n.includes("which is not a finding that the CVE has no weakness class"), n);
      assert.ok(n.includes("affected_packages is empty"), n);
      assert.doesNotMatch(n, /older than that field/);
      assertTextIsStructure("cve_intel empty", res);
    });

    it("#2817 cve_intel: fixed_branches relayed as sent, every range of log4j-core; the note and description say fixed_version is one range's", async () => {
      const res = await call("cve_intel", { cve_id: "CVE-2099-28170" });
      assert.ok(!res.isError, noteOf(res));
      const rows = res.structuredContent.data.affected_packages;
      assert.deepEqual(rows, BRANCHES.affected_packages, "affected_packages relayed as sent");
      const core = rows.find((r) => r.package_name === "org.apache.logging.log4j:log4j-core");
      assert.deepEqual(core.fixed_branches, LOG4J_CORE_BRANCHES);
      // The range holding 2.14.1 is fixed in 2.15.0; fixed_version alone says 2.12.2.
      assert.equal(core.fixed_branches.find((b) => b.introduced === "2.13.0").fixed, "2.15.0");
      assert.equal(core.fixed_version, "2.12.2");
      // The first text block (what a client without structuredContent shows) carries them whole.
      assert.deepEqual(JSON.parse(textBlocks(res)[0]).affected_packages[0].fixed_branches, LOG4J_CORE_BRANCHES);
      const n = noteOf(res);
      assert.ok(n.includes("1 affected_packages row lists more than one affected range in fixed_branches (org.apache.logging.log4j:log4j-core (Maven)): there, fixed_version is one range's fix, and an installed version's fix is the first fixed above it that no range of the row holds: the fixed of the range that holds it, or, while another range still holds that version, that range's fixed (none where a range on the way has no fixed)."), n);
      assert.ok(n.includes("1 affected_packages row carries fixed_branches null (apache-log4j2 (Debian:12)): its ranges are not on record, so fixed_version, one range's fix, is all the answer holds"), n);
      // [] is "no version range on record", not "no fix": the row's fixed_version is named as such.
      assert.ok(n.includes("1 affected_packages row carries fixed_branches [] and a fixed_version (example.test/commit-ranges-only (Go)): no version range is on record there, which is not a finding that no fix exists"), n);
      // Each range names the OSV record that published it, relayed as sent.
      assert.equal(core.fixed_branches[0].advisory_id, "GHSA-jfh8-c2jp-5v3q");
      assert.equal(core.fixed_branches[0].source, "osv_bulk");
      assertTextIsStructure("cve_intel fixed_branches", res);

      // The description says how to pick the range for an installed version, and what fixed_version is;
      // since #2842 the rule in full is the outputSchema's description of fixed_branches, beside the
      // description's head, which keeps the rule within the client cut.
      const intel = tools.find((t) => t.name === "cve_intel");
      const d = [intel.description, ...schemaDescriptions(intel.outputSchema)].join(" ");
      // #3013's review: the description's head states #3074's walk, as the schema description and
      // the note do: the fix is the first fixed above the version that no range of its row holds,
      // never simply the fixed of the range that holds it (lodash 4.17.15, CVE-2026-4800: ranges
      // [0, 4.17.21) and [4.0.0, 4.18.0), fixed in 4.18.0, not 4.17.21). Control: the rule it said
      // through the review, "that range's fixed is the fix for it", is gone from every description.
      assert.match(intel.description, /fixed_branches lists each affected range on record \(from introduced \("0" is the first version\) to below fixed, or through last_affected, with advisory_id \(its OSV record\) and source\); in the ecosystem's version order, an affected version's fix is the first fixed above it that no range of its row holds \(none past a range with no fixed\)\./);
      assert.doesNotMatch(d, /that range's fixed is the fix for it/);
      assert.match(intel.description, /fixed_version is one range's fix, kept for compatibility, not the fix for every affected range/);
      assert.match(d, /affected_packages \(ecosystem, package_name, version_range, fixed_version, fixed_branches\)/);
      assert.match(d, /To pick the range for an installed version, compare in the ecosystem's version order/);
      assert.match(d, /at or above introduced \("0" is the first version\) and below fixed, or at or below last_affected; its fix is that range's fixed, or, while another range still holds that, the other range's fixed \(none past a range without one\)/);
      assert.match(d, /fixed_version is one range's fix, kept for compatibility/);
      assert.match(d, /with advisory_id \(the OSV record that published the range\) and source/);
      assert.match(d, /Ranges with an advisory_id are in the order their record lists them/);
      assert.match(d, /\[\] where no version range is on record \(the advisory gives none, only commit ranges, or more than are stored\), which is not a finding that no fix exists/);
      assert.match(d, /not the fix for every affected range/);
      // #2817 trip-wire: nothing calls fixed_version the version to upgrade to.
      assert.doesNotMatch(d, /fixed_version[^.]*(the version to upgrade to|upgrade to)/i);

      // An answer older than #2817 (no fixed_branches on any row) is worded as such.
      const older = await call("cve_intel", { cve_id: LOG4SHELL });
      assert.ok(noteOf(older).includes("No affected_packages row carries fixed_branches (an API older than that field): each row's fixed_version is one range's fix, which need not be the fix for a given installed version."), noteOf(older));
    });

    // #3285 follow-up (3.1.0's lane P): cve_intel's affected_packages lists a package once per
    // stored ecosystem string, as cve_remediation's fixed_branches does, and its note's rule, "no
    // range of the row holds", read row by row gave a Packagist drupal/quick_node_block 1.0.0 the
    // Packagist row's 2.0.0, which the Drupal row ([0, 2.0.1)) still holds affected. The note now
    // says rows of one package_name under Packagist or Maven, bare or with a repository URL, are one
    // package, as the matcher reads them. Control: the note as it read at d42d4697 (no such
    // sentence; each row has one range, so it said nothing of the walk), applied the same way,
    // gives 2.0.0.
    it("#3285: cve_intel's note reads CVE-2025-48013's two Packagist rows for drupal/quick_node_block as one package: 1.0.0's fix is 2.0.1, not 2.0.0", async () => {
      const res = await call("cve_intel", { cve_id: "CVE-2025-48013" });
      assert.ok(!res.isError, noteOf(res));
      assert.deepEqual(res.structuredContent.data.affected_packages, DRUPAL_ROWS, "affected_packages relayed as sent");
      const note = noteOf(res);
      const said = `2 affected_packages rows are 1 package (drupal/quick_node_block (Packagist:https://packages.drupal.org/8 and Packagist)): ${ONE_PACKAGE_ROWS}, so there an installed version's fix is the first fixed above it that no range of those rows holds: the fixed of the range that holds it, or, while another range of them still holds that version, that range's fixed (none where a range on the way has no fixed); each row's fixed_version is one range's fix.`;
      assert.ok(note.includes(said), note);
      const component = { ecosystem: "Packagist", pkg: "drupal/quick_node_block", installed: "1.0.0" };
      assert.equal(fixByIntelNote(note, DRUPAL_ROWS, component), "2.0.1");
      // Control: without the sentence, the same rule read row by row gives the still-affected 2.0.0.
      assert.equal(fixByIntelNote(note.replace(said, ""), DRUPAL_ROWS, component), "2.0.0");
      assertTextIsStructure("cve_intel CVE-2025-48013", res);
    });
    it("#3285: cve_intel folds Maven with a repository URL onto Maven, and never a release suffix (Debian:11, Debian:12)", async () => {
      const res = await call("cve_intel", { cve_id: "CVE-2099-48014" });
      const note = noteOf(res);
      assert.ok(note.includes("2 affected_packages rows are 1 package (org.example:lib (Maven:https://repo.spring.io/release and Maven)):"), note);
      assert.doesNotMatch(note, /openssl \(Debian/, "a release suffix is folded");
      const rows = FOLD_OR_NOT.affected_packages;
      assert.equal(fixByIntelNote(note, rows, { ecosystem: "Maven", pkg: "org.example:lib", installed: "1.0.0" }), "1.2.0");
      assert.equal(fixByIntelNote(note, rows, { ecosystem: "Debian:12", pkg: "openssl", installed: "1.1.1" }), "3.0.1");
      assert.equal(fixByIntelNote(note, rows, { ecosystem: "Debian:11", pkg: "openssl", installed: "1.0.0" }), "1.1.1");
    });

    it("#2876 cve_intel: source_published_at (null where the source gives none) and eg_first_seen_at relayed as sent, validated, and never rendered as a made-up date", async () => {
      const res = await call("cve_intel", { cve_id: "CVE-2099-28760" });
      assert.ok(!res.isError, noteOf(res));
      const sc = res.structuredContent;
      assert.equal(sc.state, "measured");
      // Relayed as sent: the null stays a JSON null (not dropped, not "null", not a stand-in date).
      assert.deepEqual(sc.data.exploits, DATED_EXPLOITS);
      const nuclei = sc.data.exploits.find((x) => x.kind === "nuclei_template");
      assert.ok("source_published_at" in nuclei && nuclei.source_published_at === null);
      assert.ok("first_seen_at" in nuclei && nuclei.first_seen_at === null);
      assert.equal(nuclei.eg_first_seen_at, "2026-10-10T03:12:46Z");
      assert.ok(!("first_seen_at" in sc.data.exploits[0]), "a row without the deprecated key is relayed without it");

      // The advertised outputSchema names each date, says what it is, and lets the source's date be null.
      const items = schemaOf("cve_intel").oneOf.find((b) => b.properties.state.enum.includes("measured")).properties.data.properties.exploits.items;
      assert.deepEqual(items.properties.source_published_at.type, ["string", "null"]);
      assert.deepEqual(items.properties.first_seen_at.type, ["string", "null"]);
      assert.equal(items.properties.eg_first_seen_at.type, "string");
      assert.ok(!(items.required ?? []).includes("eg_first_seen_at"), "eg_first_seen_at is optional: an API older than #2876 leaves it out");
      assert.match(items.properties.source_published_at.description, /^The source's own date for the reference \(.*\); null where the source gives none, and EchelonGraph supplies no stand-in date\.$/);
      assert.match(items.properties.eg_first_seen_at.description, /^When EchelonGraph first recorded the reference/);
      assert.equal(items.properties.first_seen_at.description, "Deprecated: the same value as source_published_at, null when that is.");

      // What an MCP client does with structuredContent: validate it against the advertised outputSchema.
      const v = validator.getValidator(schemaOf("cve_intel"))(sc);
      assert.ok(v.valid, v.errorMessage);

      // No text block renders a date that is not there: the data block is the JSON (null as null),
      // and no block prints "null" as a value, Invalid Date, the epoch, or a 1 January placeholder.
      const blocks = textBlocks(res);
      assert.equal(JSON.parse(blocks[0]).exploits[1].source_published_at, null);
      for (const [i, b] of blocks.entries()) assert.doesNotMatch(b, BAD_DATE_TEXT, `text block ${i}`);
      assert.doesNotMatch(noteOf(res), /\bnull\b/, "the note says nothing about a null date");
      // #3039: the template is counted apart from the two references to exploit code.
      assert.ok(noteOf(res).includes("EchelonGraph holds 3 references for CVE-2099-28760 (exploits_total), 1 of them with verified_status verified: 2 public exploit references and 1 Nuclei detection template; a detection template checks whether a system is affected; it is not necessarily exploit code."), noteOf(res));
      assert.ok(sc.notes.includes("measured_at is null: the answer has no single observation time; each row carries its own (source_published_at and eg_first_seen_at, enriched_at)."), JSON.stringify(sc.notes));
      assertTextIsStructure("cve_intel #2876 dates", res);

      // The description names the two honest dates, not the deprecated key, and keeps its caveats.
      const d = tools.find((t) => t.name === "cve_intel").description;
      assert.match(d, /exploits \(each with kind, source_name, source_url, source_published_at \(the source's date, null if none\), eg_first_seen_at \(when EchelonGraph recorded it\) and verified_status; at most 10, verified first\)/);
      assert.doesNotMatch(d, /\bfirst_seen_at\b/, "the description names the deprecated first_seen_at");
      assert.match(d, /verified_status is the source's label, not a guarantee the exploit works on a given system\./);
      assert.match(d, /An empty exploits list is not evidence that no public exploit exists: it covers only the sources EchelonGraph ingests, and which are polled depends on the deployment\./);
      assert.match(d, /A section the API could not read is named in coverage\.sections_failed and left out of data, never relayed as an empty list\./);
      assert.match(d, /fixed_branches \[\] is not a finding that no fix exists\./);
      // The input hint left the description for the room (#2876); inputSchema carries it.
      assert.equal(tools.find((t) => t.name === "cve_intel").inputSchema.properties.cve_id.description, "a CVE ID, e.g. CVE-2021-44228");
    });

    it("#2876 control: an outputSchema whose source_published_at or first_seen_at is a plain string rejects the nuclei row's null", () => {
      const [, , res] = results.find(([n, a]) => n === "cve_intel" && a.cve_id === "CVE-2099-28760");
      const real = schemaOf("cve_intel");
      assert.ok(validator.getValidator(real)(res.structuredContent).valid, "GREEN: the advertised schema accepts the null");
      for (const key of ["source_published_at", "first_seen_at"]) {
        // A copy of the advertised schema, the one date made non-nullable; the advertised one is untouched.
        const strict = structuredClone(real);
        const ok = strict.oneOf.find((b) => b.properties.state.enum.includes("measured"));
        ok.properties.data.properties.exploits.items.properties[key] = { type: "string" };
        const v = validator.getValidator(strict)(res.structuredContent);
        assert.equal(v.valid, false, `RED expected: ${key} as a plain string still accepted the null`);
        assert.match(v.errorMessage, new RegExp(`exploits/1/${key}`), v.errorMessage);
      }
      assert.deepEqual(real.oneOf.find((b) => b.properties.state.enum.includes("measured")).properties.data.properties.exploits.items.properties.first_seen_at.type, ["string", "null"], "the control left the advertised schema as it was");
      // The text check catches what it was written for, and passes the JSON null it must allow.
      for (const bad of ['"source_published_at": "null"', "first seen Invalid Date", "1970-01-01T00:00:00.000Z", '"first_seen_at": "2021-01-01T00:00:00Z"', "first seen null"]) assert.match(bad, BAD_DATE_TEXT, bad);
      assert.doesNotMatch(JSON.stringify({ source_published_at: null }, null, 2), BAD_DATE_TEXT);
    });

    it("cve_intel: a section the API could not read is left out of data and named, not relayed as empty", async () => {
      const res = await call("cve_intel", { cve_id: "CVE-2099-27303" });
      const sc = res.structuredContent;
      assert.equal(sc.state, "measured");
      for (const k of ["cwes", "exploits", "exploits_total", "exploits_capped", "exploits_by_kind", "exploits_by_status"]) assert.ok(!(k in sc.data), `${k} relayed though it failed`);
      assert.deepEqual(sc.coverage.sections_failed, ["cwes", "exploits", "exploits_total"]);
      assert.deepEqual(sc.coverage.sections_relayed, ["affected_packages", "fixed_versions", "timeline"]);
      assert.deepEqual(sc.coverage.exploits, { returned: null, api_row_limit: 10 });
      const n = noteOf(res);
      assert.ok(n.includes("The API could not read cwes, exploits and exploits_total (failed_sections): they are left out of data, and the absence is not a finding of none."), n);
      assert.doesNotMatch(n, /No CWE classification|no public exploit reference/, n);
      assertTextIsStructure("cve_intel partial", res);
    });

    it("cve_intel: an API older than #2720 — no exploits_total, no failed_sections — is worded as such", async () => {
      const full = await call("cve_intel", { cve_id: "CVE-2099-27301" });
      assert.equal(full.structuredContent.coverage.sections_failed, null);
      assert.ok(noteOf(full).includes("exploits lists 10 public exploit references for CVE-2099-27301, 2 with verified_status verified; the answer carries no exploits_total, so it does not say how many are on record. The API lists at most 10 references, so there may be more."), noteOf(full));
      const empty = await call("cve_intel", { cve_id: "CVE-2099-27302" });
      const n = noteOf(empty);
      assert.ok(n.includes("exploits is empty and the answer carries no exploits_total"), n);
      assert.ok(n.includes("an empty list is not evidence that no public exploit exists"), n);
      assert.ok(n.includes("The answer carries no failed_sections (an API older than that field), so it does not say whether cwes and exploits were read"), n);
      assertTextIsStructure("cve_intel older", empty);
    });

    it("cve_intel: every relayed section failed — a failure, not an empty success", async () => {
      const res = await call("cve_intel", { cve_id: "CVE-2099-27304" });
      assert.equal(res.isError, true);
      assert.equal(res.structuredContent.state, "failed");
      assert.equal(res.structuredContent.error.kind, "unexpected_shape");
      assert.match(noteOf(res), /could not read any section this tool relays/);
      assert.match(noteOf(res), /this is not a finding/);
      assertTextIsStructure("cve_intel all failed", res);
    });

    it("cve_intel: HTTP 500 and 404 are failures; a malformed or blank id is refused with no request", async () => {
      const r500 = await call("cve_intel", { cve_id: "CVE-2099-27305" });
      assert.equal(r500.structuredContent.state, "failed");
      assert.match(noteOf(r500), /HTTP 500 .* the API said: boom/);
      const r404 = await call("cve_intel", { cve_id: "CVE-2099-27399" });
      assert.equal(r404.structuredContent.state, "failed");
      assert.match(noteOf(r404), /returned no record/);
      seen.length = 0;
      for (const bad of ["", "  ", "log4shell", "CVE-21-1", "../summary"]) {
        const res = await call("cve_intel", { cve_id: bad });
        assert.equal(res.structuredContent.state, "invalid_input", bad);
        assertTextIsStructure(`cve_intel ${JSON.stringify(bad)}`, res);
      }
      assert.deepEqual(seen, [], "an invalid id reached the API");
    });

    it("get_cwe: CWE-79 relayed as sent, the stated order repeated, KEV rows counted, NOT YET SCORED labelled, the pageable cap said", async () => {
      seen.length = 0;
      const res = await call("get_cwe", { cwe_id: "79" });
      assert.deepEqual(seen, ["/api/v1/public/cwes/CWE-79"]);
      const sc = res.structuredContent;
      assert.equal(sc.state, "measured");
      assert.deepEqual(sc.data, CWE79);
      assert.deepEqual(sc.coverage, { total: 38512, returned: 3, page: 1, page_requested: 1, page_size: 50, max_page: 200 });
      const n = noteOf(res);
      assert.ok(n.includes("CWE-79 is Cross-site Scripting in the MITRE CWE catalog (version 4.17)."), n);
      assert.ok(n.includes("EchelonGraph's feed holds 38512 active CVEs classified under CWE-79 (total, rejected and reserved records left out); this page lists 3 (page 1 of at most 200)."), n);
      assert.ok(n.includes("Only the first 10000 of them can be paged to: the API serves no page past max_page 200."), n);
      assert.ok(n.includes(`The rows are sorted by ${CWE79.order}, as the answer states (order); 1 of the 3 on this page are CISA-KEV-listed (kev_listed).`), n);
      assert.match(n, /NOT YET SCORED: 1 of the 3 CVEs in this page is not yet scored by EchelonGraph: CVE-2026-27205\./);
      assertTextIsStructure("get_cwe ok", res);
    });

    it("get_cwe: page passed through; a served page that differs from the asked one is said", async () => {
      seen.length = 0;
      const p3 = await call("get_cwe", { cwe_id: "cwe-79", page: 3 });
      assert.deepEqual(seen, ["/api/v1/public/cwes/CWE-79?page=3"]);
      assert.equal(p3.structuredContent.coverage.page, 3);
      assert.doesNotMatch(noteOf(p3), /was asked for/);
      const clamped = await call("get_cwe", { cwe_id: "CWE-81", page: 7 });
      assert.equal(clamped.structuredContent.coverage.page_requested, 7);
      assert.ok(noteOf(clamped).includes("Page 7 was asked for and the API served page 3."), noteOf(clamped));
    });

    it("get_cwe: an answer without order is not called KEV-first", async () => {
      const res = await call("get_cwe", { cwe_id: "CWE-80" });
      const n = noteOf(res);
      assert.ok(n.includes("The answer does not state how its rows are sorted (no order field; an API older than it sorted them by CVE id), so the first rows are not necessarily the CISA-KEV-listed or highest-scored ones"), n);
      assert.doesNotMatch(n, /\(version /, "no catalog version claimed");
      assert.equal(res.structuredContent.coverage.max_page, null);
      assertTextIsStructure("get_cwe older", res);
    });

    it("get_cwe: total 0 is a measured empty result, scoped to EchelonGraph's feed", async () => {
      const res = await call("get_cwe", { cwe_id: "CWE-99999" });
      const n = noteOf(res);
      assert.ok(n.includes("The answer carries no name for CWE-99999"), n);
      assert.ok(n.includes("No active CVE in EchelonGraph's feed is classified under CWE-99999 (total 0): a measured empty result (we looked and found nothing), which says only that no NVD, GitHub or CVE.org record EchelonGraph holds puts a CVE in this class, not that none exists."), n);
    });

    it("get_cwe: a malformed id is refused with no request", async () => {
      seen.length = 0;
      for (const bad of ["", "XSS", "CWE-", "CWE-79a", "79/../../cves"]) {
        const res = await call("get_cwe", { cwe_id: bad });
        assert.equal(res.structuredContent.state, "invalid_input", bad);
      }
      assert.deepEqual(seen, []);
    });

    it("get_cve: cpe_configurations relayed as sent; its absence said as 'not stored', not 'no product affected'", async () => {
      const withCfg = await call("get_cve", { cve_id: "CVE-2099-27310" });
      assert.deepEqual(withCfg.structuredContent.data.cpe_configurations, CFG);
      assert.ok(withCfg.structuredContent.notes.some((s) => s.startsWith("cpe_configurations is NVD's configurations array as sent (1)")));
      const without = await call("get_cve", { cve_id: "CVE-2099-27311" });
      assert.ok(!("cpe_configurations" in without.structuredContent.data));
      const said = without.structuredContent.notes.find((s) => s.startsWith("No cpe_configurations in the answer"));
      assert.ok(said, JSON.stringify(without.structuredContent.notes));
      assert.match(said, /which does not mean no product is affected/);
      // The note in content[1] is unchanged (tools.test.mjs pins it word for word).
      assert.match(noteOf(without), /^get_cve OK: EchelonGraph answered HTTP 200 from .*\. Returned the record for CVE-2099-27311\.$/);
      assertTextIsStructure("get_cve with", withCfg);
      assertTextIsStructure("get_cve without", without);
    });

    it("every result validates against its tool's outputSchema (ajv), and none makes a removed claim", () => {
      assert.ok(results.length >= 25, `only ${results.length} results`);
      const tried = new Set();
      for (const [name, args, res] of results) {
        tried.add(`${name}:${res.structuredContent.state}`);
        const v = validator.getValidator(schemaOf(name))(res.structuredContent);
        assert.ok(v.valid, `${name} ${JSON.stringify(args)}: ${v.errorMessage}`);
        assert.doesNotMatch(textBlocks(res).slice(1).join(" "), REMOVED_CLAIMS, `${name} ${JSON.stringify(args)}`);
        assert.doesNotMatch(textBlocks(res).slice(1).join(" "), HOST_UNIT, `${name} ${JSON.stringify(args)}`);
      }
      for (const k of ["cve_intel:measured", "cve_intel:failed", "cve_intel:invalid_input", "get_cwe:measured", "get_cwe:invalid_input", "get_cve:measured"]) assert.ok(tried.has(k), `no ${k} result validated`);
    });

    it("control: the validator rejects a cve_intel result that relays a field the schema does not name", () => {
      const [, , res] = results.find(([n, , r]) => n === "cve_intel" && r.structuredContent.state === "measured");
      const bad = { ...res.structuredContent, data: { ...res.structuredContent.data, vendor_advisories: [] } };
      assert.equal(validator.getValidator(schemaOf("cve_intel"))(bad).valid, false);
    });
  });
}
