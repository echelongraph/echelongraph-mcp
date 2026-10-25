// The production synthetic's probe table (#2724): one known-good input per tool, keyed by the
// tool's name as tools/list advertises it.
//
// HOW A TOOL IS PICKED UP. The runner probes every tool the published package lists, in the
// order it lists them, plus every tool named here that it does not list:
//   - named here and listed     → called with the first candidate below that validates against
//                                  the tool's own advertised inputSchema;
//   - named here, not listed    → reported not_published, never failed. A tool is named here
//                                  before the release that publishes it, so that release is
//                                  probed on the first run after it, with no change to this job;
//   - listed, not named here    → called with {} when {} validates against its inputSchema (a
//                                  tool with no required argument needs no entry); otherwise a
//                                  failure, reason no_probe_input: a tool the synthetic cannot
//                                  call is a gap in "every tool", and it is said, not skipped.
//
// THE INPUTS ARE THE TOOLS' OWN. Every entry uses the argument names of the tool's inputSchema as
// src/index.ts and src/tools/*.ts declare it. A candidate is still checked against the advertised
// inputSchema before it is sent, so an argument a later release renames is reported as failure,
// reason no_valid_probe_input (this table's defect, named), and never sent blind. check_affected
// has two candidates, one per lookup path.
//
// A candidate is an object, or a function of the results already received in this era
// (name → structuredContent) that returns an object or undefined: get_vendor_advisory takes its
// vendor and advisory ID from vendor_advisories_for_cve's answer, so it never probes an advisory
// that has aged out of the store.
//
// The values are fixed and public (well-known CVE ids, a public package). Nothing a visitor
// typed is ever here, and the runner logs which candidate it used by index, not by value.
//
// THE HOSTED LEG'S OWN INPUTS (#2774). HTTP_PROBES replaces an entry for the hosted leg only, and
// HTTP_EXPECT adds to what its answer must show; the stdio legs keep PROBES and EXPECT.
import { createHash } from "node:crypto";

// Log4Shell: CISA-KEV listed, EPSS-scored, with vendor advisories, CWE and exploits on record.
const CVE = "CVE-2021-44228";
// HTTP/2 Rapid Reset: the CVE the package's own smoke test and README use for exposure.
const EXPOSURE_CVE = "CVE-2023-44487";

// get_vendor_advisory's input from vendor_advisories_for_cve's structuredContent: the first row's
// vendor slug and the vendor's own advisory ID (vendor_advisory_id, e.g. RHSA-2024:1234). A row's
// advisory_id is EchelonGraph's internal id, which the detail route does not take.
export function advisoryFrom(sc) {
  const rows = sc?.data?.advisories;
  if (!Array.isArray(rows)) return undefined;
  for (const row of rows) {
    if (row && typeof row.vendor === "string" && row.vendor && typeof row.vendor_advisory_id === "string" && row.vendor_advisory_id) {
      return { vendor: row.vendor, advisory_id: row.vendor_advisory_id };
    }
  }
  return undefined;
}

// check_sbom's input (#2757): 201 distinct purls, one more than the API takes per request
// (cveBatchMaxComponents, 200), so every probe sends two batches and the multi-batch path runs
// against production on every run; EXPECT below fails the probe when it did not. The first two are
// the known-vulnerable pair the probe always sent; the third is an Alpine binary package that only
// its upstream qualifier names the source of (#2836, below); the other 198 are versions of one
// package (lodash 4.17.22 through 4.17.219, version numbers made up for the probe), so the batches
// read one package's advisories. The budget it costs: 201 components of the API's 1,200 a minute per
// caller (waf CVEMatchBatchComponentsPerWindow), 2 requests, on each of the run's four legs (two eras,
// over stdio and over the hosted endpoint): 804 components and 8 requests every 15 minutes.
//   LOG4J_CORE_PURL (#2834)  log4j-core 2.14.1: its CVE-2021-44228 match must carry fixed_in
//                       "2.15.0", the fixed bound of [2.13.0, 2.15.0), the GHSA-jfh8-c2jp-5v3q
//                       interval that holds 2.14.1. The same answer under #3074's rule (the lowest
//                       version inside none of the advisory's affected ranges: [2.0-beta9, 2.3.1),
//                       [2.4, 2.12.2), [2.13.0, 2.15.0) leave 2.15.0 first above 2.14.1), so the
//                       EXPECT holds across that change. Live 2026-10-11 (hosted check_sbom): fixed_in
//                       "2.15.0", interval {introduced 2.13.0, fixed 2.15.0}.
//   UPSTREAM_PURL (#2836)  Alpine 3.20's libcrypto3 3.3.6-r0 is filed under its source package,
//                       openssl, which only the upstream qualifier names: the row must be affected,
//                       matched_via upstream, matched_package openssl (#63's pair: 3.3.7-r0 is not
//                       affected). Live 2026-10-11 (hosted check_sbom): affected, 6 CVEs, openssl,
//                       upstream.
export const LOG4J_CORE_PURL = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1";
export const UPSTREAM_PURL = "pkg:apk/alpine/libcrypto3@3.3.6-r0?distro=alpine-3.20&upstream=openssl";
export const SBOM_PROBE_PURLS = [
  "pkg:npm/lodash@4.17.20",
  LOG4J_CORE_PURL,
  UPSTREAM_PURL,
  ...Array.from({ length: 198 }, (_, i) => `pkg:npm/lodash@4.17.${22 + i}`),
];

// scan_manifest's input (#2835): one package-lock.json (lockfileVersion 3), as npm writes it, past
// the hosted endpoint's general 64 KiB body cap on every leg, so the large-body admission that
// scan_manifest shares with check_sbom (httpPolicy.ts LARGE_BODY_TARGETS) is probed on every run.
// Its 20 top-level packages are real packages at real versions, lodash 4.17.15 first (production
// lists CVE-2020-8203 against it); each of the 20 is also installed nested under every other one
// at the same version (node_modules/a/node_modules/b), which npm writes when hoisting is blocked,
// so the file holds 400 entries and 112,923 characters but only 20 distinct purls: 20 components
// of the API's 1,200 a minute per caller on each of the run's four legs. resolved is the
// registry's tarball URL; integrity is the SHA-512 of the purl (the probe's own, so the document
// is fixed), not the tarball's.
export const MANIFEST_PROBE_PACKAGES = [
  ["lodash", "4.17.15"], ["minimist", "1.2.5"], ["axios", "0.21.0"], ["node-fetch", "2.6.0"], ["qs", "6.5.2"],
  ["ws", "7.4.5"], ["semver", "7.3.5"], ["glob-parent", "5.1.1"], ["ansi-regex", "5.0.0"], ["y18n", "4.0.0"],
  ["path-parse", "1.0.6"], ["hosted-git-info", "2.8.8"], ["trim-newlines", "3.0.0"], ["normalize-url", "4.5.0"], ["ini", "1.3.5"],
  ["kind-of", "6.0.2"], ["dot-prop", "4.2.0"], ["handlebars", "4.7.6"], ["underscore", "1.12.0"], ["moment", "2.29.1"],
];
function packageLockOf(pkgs) {
  const entry = (name, version) => ({
    version,
    resolved: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`,
    integrity: `sha512-${createHash("sha512").update(`pkg:npm/${name}@${version}`).digest("base64")}`,
  });
  const packages = { "": { name: "echelongraph-mcp-synthetic-probe", version: "1.0.0", dependencies: Object.fromEntries(pkgs.map(([n, v]) => [n, v])) } };
  for (const [n, v] of pkgs) packages[`node_modules/${n}`] = entry(n, v);
  for (const [parent] of pkgs) for (const [n, v] of pkgs) if (n !== parent) packages[`node_modules/${parent}/node_modules/${n}`] = entry(n, v);
  return { name: "echelongraph-mcp-synthetic-probe", version: "1.0.0", lockfileVersion: 3, requires: true, packages };
}
export const MANIFEST_PROBE_LOCK = JSON.stringify(packageLockOf(MANIFEST_PROBE_PACKAGES), null, 2);

// In createServer()'s registration order, which is tools/list's.
export const PROBES = {
  cve_summary: [{}],
  search_cves: [{ search: "log4j", limit: 2 }],
  get_cve: [{ cve_id: CVE }],
  cve_exposure: [{ cve_id: EXPOSURE_CVE }],
  exposure_radar: [{}],
  // #2742: the heavy, filtered shape that timed out (limit 200 with a filter, read cold), not the
  // warm default page that hid the 503s.
  kev_recent: [{ limit: 200, ransomware: true }],
  epss_history: [{ cve_id: CVE }],
  // The registry path (ecosystem, package, version), then the CPE path (product, version).
  check_affected: [
    { ecosystem: "npm", package: "lodash", version: "4.17.20" },
    { product: "openssl", version: "3.0.0" },
  ],
  check_sbom: [{ purls: SBOM_PROBE_PURLS }],
  // #2835: the package-lock above, past 64 KiB on every leg.
  scan_manifest: [{ files: [{ filename: "package-lock.json", content: MANIFEST_PROBE_LOCK }] }],
  cve_intel: [{ cve_id: CVE }],
  // #2841: how Log4Shell is fixed, as its sources state it.
  cve_remediation: [{ cve_id: CVE }],
  get_cwe: [{ cwe_id: "CWE-79" }],
  vendor_advisories_for_cve: [{ cve_id: CVE }],
  get_vendor_advisory: [(seen) => advisoryFrom(seen.vendor_advisories_for_cve)],
  search_vendor_advisories: [{ query: "log4j", limit: 2 }],
};

// Probes that read another tool's answer run after it: get_vendor_advisory after
// vendor_advisories_for_cve.
export const AFTER = { get_vendor_advisory: ["vendor_advisories_for_cve"] };

// What a probe's answer must also show, beyond a result its outputSchema accepts: tool name →
// a function of the structuredContent that returns undefined when it holds, else what it saw
// (logged as the line's detail; the reason is expectation_unmet). A fixed string, never an input.
//   check_sbom (#2757)  coverage.batches_sent at least 2: the 201 purls went as two batches and
//                       the API answered both. One batch answered means the second was not: a 429
//                       the call could not wait out (the per-minute budget spent; rate_limited or
//                       time_budget), the call's 50 s budget ending while it was unanswered
//                       (time_budget), or a request failure (request_failed); its purls came back
//                       not sent, and detail quotes not_sent_reason. A lowered batch cap is NOT
//                       this: the first batch of 200 is refused (400 TOO_MANY_COMPONENTS), nothing
//                       is answered, and the probe fails as state_invalid_input (a 400 is the API
//                       refusing the input, index.ts failed()). Then, from the first batch's rows
//                       (both purls are in it, so a partial answer still holds them):
//                       LOG4J_CORE_PURL's CVE-2021-44228 match carries fixed_in "2.15.0" (#2834;
//                       unmet: core-backend without #2834 (fixed_in absent), the interval lookup
//                       skipped on the exact-list path (null, with fixed_in_reason), or the bound
//                       read from the stored fixed_version ("2.3.1"), and detail says which); and
//                       UPSTREAM_PURL's row is affected, matched_via upstream, matched_package
//                       openssl (#2836; unmet: the upstream qualifier ignored (not_assessed,
//                       package_not_in_advisory_corpus, matched_via purl_name), or Alpine 3.20's
//                       openssl advisories gone from the corpus (not_affected)).
//   get_cve (#2839)     for CVE-2021-44228, data.kev_listed is true and data.kev_required_action
//                       is CISA's text. Unmet means the record serves no KEV text: core-backend
//                       without #2839, the KEV text columns not written (the KEV monitoring's
//                       "KEV rows missing required action" alert says so too), or a package
//                       release that drops the field from its CVERecord.
//   cve_intel (#2817)   for CVE-2021-44228, the org.apache.logging.log4j:log4j-core row of
//                       data.affected_packages carries fixed_branches with at least 3 ranges, one
//                       of them fixed in 2.15.0 (GHSA-jfh8-c2jp-5v3q lists [2.13.0, 2.15.0),
//                       [2.0-beta9, 2.3.1), [2.4, 2.12.2)). Before #2817 production served one
//                       fixed_version, 2.12.2, older than an affected 2.14.1. Unmet means the
//                       per-range fixes are not served: core-backend without #2817, the row's
//                       version_intervals not loaded (null), the row gone, or fewer ranges
//                       (detail says which). advisory_id is deliberately NOT held here: it is
//                       null on every range until the founder-timed OSV backfill rerun
//                       (docs/RUNBOOK_MIGRATION_099_VERSION_INTERVALS.md 4c), and this image is
//                       rebuilt by any later infrastructure/mcp-synthetic/deploy.sh, so holding it
//                       would page every 15 minutes until that write ran. 4c checks it instead.
//   cve_remediation (#2840, #2841)  for CVE-2021-44228, data.cisa.required_action is CISA's text
//                       (Log4Shell is KEV-listed), and every row of data.vendor_remediations
//                       carries a remediation_state. Unmet means the route serves no KEV text
//                       (core-backend without #2839, or the KEV poll has not written it) or a
//                       vendor row without its state (core-backend without #2840); detail says
//                       which. It does not hold a parsed Red Hat row: that needs the remediation
//                       backfill to have run, which the backfill's own log line reports.
//   scan_manifest (#2835)  the package-lock was read (coverage.files_read 1, its 400 entries
//                       pinned, 20 distinct purls), every purl was sent (not_sent 0), and at least
//                       one component is affected (summary.affected >= 1: lodash 4.17.15). Unmet
//                       means the file was not read as a package-lock (a reader regression), the
//                       batch route did not answer every purl (detail quotes not_sent_reason), or
//                       production no longer finds lodash 4.17.15 affected (the corpus lost its
//                       lodash advisories, or the matcher regressed).
//   cve_summary (#3276)  where data.nvd_poll is present, freshness.nvd_poll.last_run_at equals its
//                       last_completed_at (the fleet's last completed NVD poll, core-backend #3242);
//                       where it is absent (the API could not read that time), freshness is null.
//                       Unmet means the package answers freshness null beside the block, as
//                       echelongraph-mcp 3.0.2 and every version before #3276 do (so this job must
//                       not be redeployed with this entry before a release with #3276 is on npm
//                       and the hosted endpoint, or every run fails), or a freshness without the
//                       block; or the API served a last_completed_at that is not a real RFC 3339
//                       time (the package leaves freshness null then, and detail quotes both).
export const LOG4J_CORE = "org.apache.logging.log4j:log4j-core";
// The fixed_in the log4j-core 2.14.1 probe row must carry for CVE-2021-44228 (#2834).
export const LOG4J_FIXED_IN = "2.15.0";
const rowFor = (rows, purl) => rows.find((r) => r?.purl === purl);
export const EXPECT = {
  check_sbom: (sc) => {
    const sent = sc?.coverage?.batches_sent;
    if (typeof sent !== "number" || sent < 2) {
      return `coverage.batches_sent ${JSON.stringify(sent ?? null)}, want at least 2 (not_sent_reason ${JSON.stringify(sc?.coverage?.not_sent_reason ?? null)})`;
    }
    const rows = sc?.data?.results;
    if (!Array.isArray(rows)) return `data.results ${rows === undefined ? "absent" : "not a list"}; want a row per purl sent`;
    // #2834: fixed_in on the registry path's exact-list match.
    const log4j = rowFor(rows, LOG4J_CORE_PURL);
    if (!log4j) return `no row for ${LOG4J_CORE_PURL} among ${rows.length} results`;
    const m = Array.isArray(log4j.matches) ? log4j.matches.find((x) => x?.cve_id === CVE) : undefined;
    if (!m) return `${LOG4J_CORE_PURL}: verdict ${JSON.stringify(log4j.verdict ?? null)}, no ${CVE} match (cve_ids ${JSON.stringify((log4j.cve_ids ?? []).slice(0, 8))})`;
    if (m.fixed_in !== LOG4J_FIXED_IN) {
      return `${LOG4J_CORE_PURL} ${CVE} fixed_in ${m.fixed_in === undefined ? "absent" : JSON.stringify(m.fixed_in)} (fixed_in_reason ${JSON.stringify(m.fixed_in_reason ?? null)}, interval ${JSON.stringify(m.interval ?? null)}); want "${LOG4J_FIXED_IN}"`;
    }
    // #2836: the upstream qualifier names the package the advisories are filed under.
    const up = rowFor(rows, UPSTREAM_PURL);
    if (!up) return `no row for ${UPSTREAM_PURL} among ${rows.length} results`;
    if (up.verdict !== "affected" || up.matched_via !== "upstream" || up.matched_package !== "openssl") {
      return `${UPSTREAM_PURL}: verdict ${JSON.stringify(up.verdict ?? null)}, matched_via ${JSON.stringify(up.matched_via ?? null)}, matched_package ${JSON.stringify(up.matched_package ?? null)} (not_assessed_reason ${JSON.stringify(up.not_assessed_reason || null)}); want affected, upstream, openssl`;
    }
    return undefined;
  },
  get_cve: (sc) => {
    const d = sc?.data;
    if (d?.kev_listed !== true) return `data.kev_listed ${JSON.stringify(d?.kev_listed ?? null)}; want true for ${CVE}`;
    const action = d.kev_required_action;
    if (typeof action !== "string" || !action.trim()) return `data.kev_required_action ${action === undefined ? "absent" : JSON.stringify(action)}; want CISA's text for ${CVE}`;
    return undefined;
  },
  cve_intel: (sc) => {
    const rows = sc?.data?.affected_packages;
    if (!Array.isArray(rows)) return `data.affected_packages ${rows === undefined ? "absent" : "not a list"}; want the ${LOG4J_CORE} row with fixed_branches`;
    const row = rows.find((r) => r?.ecosystem === "Maven" && r?.package_name === LOG4J_CORE);
    if (!row) return `no Maven ${LOG4J_CORE} row among ${rows.length} affected_packages rows`;
    const fb = row.fixed_branches;
    if (!Array.isArray(fb)) return `${LOG4J_CORE} fixed_branches ${fb === undefined ? "absent" : JSON.stringify(fb)} (fixed_version ${JSON.stringify(row.fixed_version ?? null)}); want at least 3 ranges, one fixed in 2.15.0`;
    const fixes = fb.map((b) => b?.fixed ?? null);
    if (fb.length < 3 || !fixes.includes("2.15.0")) return `${LOG4J_CORE} fixed_branches has ${fb.length} ranges, fixes ${JSON.stringify(fixes)}; want at least 3, one fixed in 2.15.0`;
    return undefined;
  },
  scan_manifest: (sc) => {
    const c = sc?.coverage;
    const want = MANIFEST_PROBE_PACKAGES.length;
    if (c?.files_read !== 1 || c?.entries_pinned !== want * want || c?.distinct_purls !== want) {
      return `coverage.files_read ${JSON.stringify(c?.files_read ?? null)}, entries_pinned ${JSON.stringify(c?.entries_pinned ?? null)}, distinct_purls ${JSON.stringify(c?.distinct_purls ?? null)}; want 1, ${want * want}, ${want}`;
    }
    if (c.not_sent !== 0) return `coverage.not_sent ${c.not_sent} (not_sent_reason ${JSON.stringify(c.not_sent_reason ?? null)}); want 0`;
    const affected = sc?.data?.summary?.affected;
    if (typeof affected !== "number" || affected < 1) return `data.summary.affected ${JSON.stringify(affected ?? null)}; want at least 1 (lodash 4.17.15)`;
    return undefined;
  },
  cve_summary: (sc) => {
    const poll = sc?.data?.nvd_poll;
    const fresh = sc?.freshness ?? null;
    if (poll === undefined || poll === null) return fresh === null ? undefined : `freshness ${JSON.stringify(fresh)} with no data.nvd_poll; want null`;
    const at = poll?.last_completed_at;
    const got = fresh?.nvd_poll?.last_run_at;
    if (typeof at !== "string" || got !== at) {
      return `freshness.nvd_poll.last_run_at ${JSON.stringify(got ?? null)}, data.nvd_poll.last_completed_at ${JSON.stringify(at ?? null)}; want them equal (freshness ${JSON.stringify(fresh)})`;
    }
    return undefined;
  },
  cve_remediation: (sc) => {
    const action = sc?.data?.cisa?.required_action;
    if (typeof action !== "string" || !action.trim()) return `data.cisa.required_action ${JSON.stringify(action ?? null)}; want CISA's text for CVE-2021-44228`;
    const rows = sc?.data?.vendor_remediations;
    if (!Array.isArray(rows)) return `data.vendor_remediations ${rows === undefined ? "absent" : "not a list"} (failed_sections ${JSON.stringify(sc?.data?.failed_sections ?? null)})`;
    const without = rows.filter((r) => typeof r?.remediation_state !== "string").length;
    if (without) return `${without} of ${rows.length} vendor_remediations rows carry no remediation_state`;
    return undefined;
  },
};

// #2774: the hosted endpoint takes a request body over 64 KiB only for httpPolicy.ts's LARGE_BODY_TARGETS: tools/call
// check_sbom and scan_manifest, and prompts/get sbom_review (#2747, #2835, #3149), and a
// 2-purl list never tested that: a return of the 413 would have left every probe green. So the
// hosted leg sends check_sbom the SAME 201 purls as a CycloneDX 1.5 document, pretty-printed as an
// SBOM tool writes it, each component with its name, version, purl, licence and a SHA-512 (the
// purl's own, so the document is fixed): 125,011 characters, a ~138,000-byte request body, twice
// the 64 KiB cap. Same purls, so the same API budget as before (201 components, two batches per
// era); the components' other fields never leave the endpoint.
function cyclonedxOf(purls) {
  const components = purls.map((purl) => {
    // The qualifiers (?distro=…&upstream=…) stay on the purl only, as syft writes an apk component.
    const [, type, rest] = /^pkg:([^/]+)\/([^?]+)/.exec(purl);
    const at = rest.lastIndexOf("@");
    const path = rest.slice(0, at).split("/");
    const name = path.pop();
    return {
      type: "library",
      "bom-ref": purl,
      ...(path.length ? { group: path.join(".") } : {}),
      name,
      version: rest.slice(at + 1),
      description: `${name}: a component of the EchelonGraph MCP synthetic's probe document (issue 2774).`,
      licenses: [{ license: { id: type === "npm" ? "MIT" : "Apache-2.0" } }],
      hashes: [{ alg: "SHA-512", content: createHash("sha512").update(purl).digest("hex") }],
      purl,
    };
  });
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: "urn:uuid:3b9f2c64-2774-4c5e-9a1d-0e6c2a7f2774",
    version: 1,
    metadata: {
      timestamp: "2026-10-04T00:00:00Z",
      tools: { components: [{ type: "application", name: "echelongraph-mcp-synthetic", version: "1.0" }] },
      component: { type: "application", "bom-ref": "echelongraph-mcp-synthetic-probe", name: "echelongraph-mcp-synthetic-probe", version: "1.0" },
    },
    components,
  };
}
export const SBOM_PROBE_DOCUMENT = JSON.stringify(cyclonedxOf(SBOM_PROBE_PURLS), null, 2);

export const HTTP_PROBES = {
  check_sbom: [{ sbom: SBOM_PROBE_DOCUMENT }],
};

// On the hosted leg check_sbom must have read the DOCUMENT (coverage.input cyclonedx, all 201
// components) and measured something, beside EXPECT's two batches. A refused body never gets
// here: the 413 is a JSON-RPC error, reason rpc_error with rpc_code -32600 (-32030 when the
// instance's large-body slots were all busy).
export const HTTP_EXPECT = {
  check_sbom: (sc) => {
    const c = sc?.coverage;
    if (sc?.state !== "measured" || c?.input !== "cyclonedx" || c?.components_in_document !== SBOM_PROBE_PURLS.length) {
      return `state ${JSON.stringify(sc?.state ?? null)}, coverage.input ${JSON.stringify(c?.input ?? null)}, components_in_document ${JSON.stringify(c?.components_in_document ?? null)}; want measured, cyclonedx, ${SBOM_PROBE_PURLS.length}`;
    }
    return EXPECT.check_sbom(sc);
  },
};

// THE MATCHER'S VERDICTS (#3135). check_affected's probe above (lodash 4.17.20, openssl 3.0.0) holds
// under any version comparator and either fixed_in rule, so a core-backend that brought back the
// per-range fixed_in (#3074) or ordered the number inside an identifier as text (#3101 on the registry
// rung, #3131 on the CPE rung) answered it green. These are the answers that tell the old rules from
// the new, one call each, on the hosted leg after its tools and before its prompts, each its own line
// labelled with its fixed `label` (the metric's tool label, so it is bounded and never renamed), judged
// as a tools/call (judge(), against the endpoint's outputSchema) and then by its `expect`. A tool the
// endpoint does not list is not_published; arguments its inputSchema refuses are no_valid_probe_input,
// never sent. A label in EXPECT_PENDING (below) is not called at all. The hosted leg only: the
// verdict is core-backend's, and the stdio leg reaches the same API; up to five more calls per era
// (ten per run) on a route with no per-minute component budget.
//   verdict:pypi/mayan-edms@4.9.0 (#3074)  CVE-2025-14692 matches with a fixed_in whose release is
//                       strictly above 4.9.7 and a non-empty fixed_in_detail: 4.9.0 sits in
//                       [4.9.0, 4.9.7), whose bound 4.9.7 is inside [0, 4.10.2) of the same record.
//                       The per-range rule says "4.9.7", the holding interval's own bound and a version
//                       still affected, with no detail. Not pinned to "4.10.2": a later advisory that
//                       overlaps [0, 4.10.2) moves the correct walk past it, and that is no regression to
//                       page on (#3135's decision). Live 2026-10-11 (hosted 3.0.0): fixed_in "4.10.2",
//                       interval {introduced 4.9.0, fixed 4.9.7}, fixed_in_detail "fixed_in moved past
//                       the overlapping interval [0, 4.10.2) …"; 3 matches.
//   verdict:packagist/magento/community-edition@2.4.4-p13 (#3101)  CVE-2024-34102 (CosmicSting, KEV)
//                       does NOT match: it is fixed in 2.4.4-p9, and p13 is above p9 only when 13 is
//                       read as a number. Absent is a finding only of an answer that looked: assessed
//                       true, neither list capped, not degraded, and the CVE in neither matches,
//                       cve_ids (which names every match even when matches is cut) nor undetermined.
//                       Live 2026-10-11: assessed, 26 matches, 327 not affected, uncapped, absent.
//   verdict:packagist/magento/community-edition@2.4.5-p2 (#3101)  CVE-2025-54236 (SessionReaper, KEV)
//                       matches: 2.4.5-p2 is below last_affected 2.4.5-p14 only when 2 < 14. Live
//                       2026-10-11: present among 124 matches (fixed_in null: the range records only
//                       last_affected).
//   verdict:cpe/midgard_gpu_kernel_driver@r20p0 (#3131)  the CPE path: CVE-2022-38181 (KEV) matches,
//                       NVD's range [r4p0, r31p0] holding r20p0 once r20p0 is read as r 20 p 0.
//                       Absent before #3131 (2026-10-11: 7 matches, compareVersions("r4p0", "r31p0")
//                       = +1, so the range held nothing); present since #3131 reached production in
//                       core-backend (2026-10-12 03:19Z: 14 matches, all four KEV
//                       CVEs), when its EXPECT_PENDING entry was removed.
//   verdict:maven/org.apache.logging.log4j/log4j-core@2.14.1 (#2834)  GET /cves/match, the route
//                       check_affected and /am-i-affected read: CVE-2021-44228 matches with fixed_in
//                       "2.15.0", the fixed bound of [2.13.0, 2.15.0), the interval that holds 2.14.1.
//                       2.14.1 is also listed verbatim in the advisory's affected versions, the
//                       exact-list path, which read no interval and so named no fix before #2834.
//                       check_sbom's EXPECT holds the same answer on POST /cves/match/batch; this one
//                       holds the GET route. Pinned to "2.15.0", as the check_sbom EXPECT is: #3074's
//                       walk gives it too ([2.0-beta9, 2.3.1), [2.4, 2.12.2), [2.13.0, 2.15.0) leave
//                       2.15.0 first above 2.14.1). Unmet: fixed_in absent (core-backend without
//                       #2834), null with fixed_in_reason (the interval lookup skipped on the
//                       exact-list path), or another version (the bound read from the stored
//                       fixed_version, "2.3.1"), and detail says which. Live 2026-10-11 (the API, and
//                       hosted and stdio check_affected at 2.7.1, #2834's review): fixed_in "2.15.0",
//                       interval {introduced 2.13.0, fixed 2.15.0}.
// An unmet `expect` is expectation_unmet with what it saw as detail (create-mcp-synthetic-monitoring.sh's
// runbook says how to read each).
export const MAYAN_CVE = "CVE-2025-14692";
// The bound of the interval that holds 4.9.0, [4.9.0, 4.9.7): the per-range rule's answer. fixed_in
// must be strictly above it; 4.10.2 is what the walk said live on 2026-10-11.
export const MAYAN_HOLDING_FIXED = "4.9.7";
export const MAGENTO = "magento/community-edition";
export const COSMICSTING_CVE = "CVE-2024-34102";
export const SESSIONREAPER_CVE = "CVE-2025-54236";
export const MALI_CVE = "CVE-2022-38181";
export const MALI_LABEL = "verdict:cpe/midgard_gpu_kernel_driver@r20p0";
export const LOG4J_VERDICT_LABEL = "verdict:maven/org.apache.logging.log4j/log4j-core@2.14.1";
// VERDICT_PROBES labels held back, each with why: run.mjs skips them (no call, no line, so nothing
// to page on). Empty: every verdict probe is called on every run (the Mali one since c0f58d5d, once
// #3131 reached production). To hold one back while the core-backend change its `expect` needs is
// not yet in production, add its label here with the reason ({ [MALI_LABEL]: "#3131 not yet
// deployed" } was the last entry); to call it again, once a live check shows production answers as
// the `expect` wants (for the Mali probe: curl -sS https://app.echelongraph.io/api/v1/public/cves/match
// -H 'X-EG-Product: midgard_gpu_kernel_driver' -H 'X-EG-Version: r20p0' | jq '[.matches[].cve_id] |
// index("CVE-2022-38181")' answers a number, not null), delete the entry; either way redeploy the
// job (infrastructure/mcp-synthetic/deploy.sh). Nothing else changes: run.test.mjs judges whichever
// state this table is in (held back: no line for the label; called: a line, judged) and tests the
// other too.
export const EXPECT_PENDING = {};
// a's dotted numeric release is strictly above b's (missing components are 0); undefined when either
// does not begin with one. The release alone: "4.9.7.post1" is not above "4.9.7" here, which can only
// err toward a line that fails, never toward one that passes the per-range rule's answer.
export function releaseAbove(a, b) {
  const rel = (v) => (typeof v === "string" ? /^v?(\d+(?:\.\d+)*)/.exec(v.trim())?.[1]?.split(".").map(Number) : undefined);
  const x = rel(a), y = rel(b);
  if (!x || !y) return undefined;
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d !== 0) return d > 0;
  }
  return false;
}
// What an answer says about one CVE: its match (matches, else cve_ids), its undetermined entry, and
// whether the answer looked at everything (an absence is read only from one that did).
function verdictFor(sc, cve) {
  const d = sc?.data ?? {};
  const matches = Array.isArray(d.matches) ? d.matches : [];
  const match = matches.find((m) => m?.cve_id === cve);
  const listed = match !== undefined || (Array.isArray(d.cve_ids) && d.cve_ids.includes(cve));
  const undetermined = Array.isArray(d.undetermined) ? d.undetermined.find((u) => u?.cve_id === cve) : undefined;
  const whole = d.assessed === true && d.capped !== true && d.candidates_capped !== true && d.degraded !== true;
  const seen = `assessed ${JSON.stringify(d.assessed ?? null)}, match_layer ${JSON.stringify(d.match_layer ?? null)}, count ${JSON.stringify(d.count ?? null)}, capped ${JSON.stringify(d.capped ?? null)}, candidates_capped ${JSON.stringify(d.candidates_capped ?? null)}, degraded ${JSON.stringify(d.degraded ?? null)}, not_assessed_reason ${JSON.stringify(d.not_assessed_reason || null)}`;
  return { match, listed, undetermined, whole, assessed: d.assessed === true, seen };
}
const present = (what, cve) => (sc) => {
  const v = verdictFor(sc, cve);
  if (!v.assessed) return `${what}: not assessed (${v.seen}); want ${cve} matched`;
  if (!v.listed) return `${what}: ${cve} not matched${v.undetermined ? `, undetermined (${JSON.stringify(v.undetermined.reason ?? null)})` : ""} (${v.seen}); want it matched`;
  return undefined;
};
const absent = (what, cve) => (sc) => {
  const v = verdictFor(sc, cve);
  if (!v.whole) return `${what}: the answer did not look at every candidate (${v.seen}), so ${cve}'s absence is not a finding`;
  if (v.listed) return `${what}: ${cve} matched (fixed_in ${JSON.stringify(v.match?.fixed_in ?? null)}, interval ${JSON.stringify(v.match?.interval ?? null)}); want it not affected`;
  if (v.undetermined) return `${what}: ${cve} undetermined (${JSON.stringify(v.undetermined.reason ?? null)}); want it not affected`;
  return undefined;
};
export const VERDICT_PROBES = [
  {
    label: "verdict:pypi/mayan-edms@4.9.0",
    tool: "check_affected",
    arguments: { ecosystem: "PyPI", package: "mayan-edms", version: "4.9.0" },
    expect: (sc) => {
      const what = "PyPI mayan-edms 4.9.0";
      const unmet = present(what, MAYAN_CVE)(sc);
      if (unmet) return unmet;
      const m = verdictFor(sc, MAYAN_CVE).match;
      if (!m) return `${what}: ${MAYAN_CVE} is in cve_ids but not in matches (cut from structuredContent); want its match with fixed_in`;
      const detail = typeof m.fixed_in_detail === "string" ? m.fixed_in_detail.trim() : "";
      if (releaseAbove(m.fixed_in, MAYAN_HOLDING_FIXED) !== true || !detail) {
        // The interval before the reason: the detail is cut at 300 characters (judge()).
        return `${what} ${MAYAN_CVE} fixed_in ${m.fixed_in === undefined ? "absent" : JSON.stringify(m.fixed_in)}, fixed_in_detail ${detail ? "set" : JSON.stringify(m.fixed_in_detail ?? null)} (interval ${JSON.stringify(m.interval ?? null)}, fixed_in_reason ${JSON.stringify(m.fixed_in_reason ?? null)}); want a version above ${MAYAN_HOLDING_FIXED} with fixed_in_detail (#3074)`;
      }
      return undefined;
    },
  },
  {
    label: `verdict:packagist/${MAGENTO}@2.4.4-p13`,
    tool: "check_affected",
    arguments: { ecosystem: "Packagist", package: MAGENTO, version: "2.4.4-p13" },
    expect: absent(`Packagist ${MAGENTO} 2.4.4-p13`, COSMICSTING_CVE),
  },
  {
    label: `verdict:packagist/${MAGENTO}@2.4.5-p2`,
    tool: "check_affected",
    arguments: { ecosystem: "Packagist", package: MAGENTO, version: "2.4.5-p2" },
    expect: present(`Packagist ${MAGENTO} 2.4.5-p2`, SESSIONREAPER_CVE),
  },
  // #3131's CPE comparator: called on every run since c0f58d5d; an EXPECT_PENDING entry (above) for
  // its label would hold it back.
  {
    label: MALI_LABEL,
    tool: "check_affected",
    arguments: { product: "midgard_gpu_kernel_driver", version: "r20p0" },
    expect: present("midgard_gpu_kernel_driver r20p0", MALI_CVE),
  },
  // #2834: fixed_in on the GET route's exact-list match.
  {
    label: LOG4J_VERDICT_LABEL,
    tool: "check_affected",
    arguments: { ecosystem: "Maven", package: LOG4J_CORE, version: "2.14.1" },
    expect: (sc) => {
      const what = "Maven log4j-core 2.14.1";
      const unmet = present(what, CVE)(sc);
      if (unmet) return unmet;
      const m = verdictFor(sc, CVE).match;
      if (!m) return `${what}: ${CVE} is in cve_ids but not in matches (cut from structuredContent); want its match with fixed_in`;
      if (m.fixed_in !== LOG4J_FIXED_IN) {
        return `${what} ${CVE} fixed_in ${m.fixed_in === undefined ? "absent" : JSON.stringify(m.fixed_in)} (fixed_in_reason ${JSON.stringify(m.fixed_in_reason ?? null)}, interval ${JSON.stringify(m.interval ?? null)}, version_evidence ${JSON.stringify(m.version_evidence ?? null)}); want "${LOG4J_FIXED_IN}" (#2834)`;
      }
      return undefined;
    },
  },
];

// THE CHAINING MISTAKE (#3011), made on purpose. A vendor_advisories_for_cve row carries two IDs:
// advisory_id, EchelonGraph's internal UUID, and vendor_advisory_id, the vendor's own. The
// get_vendor_advisory probe above passes vendor_advisory_id; a model that chains the two tools by
// the shared name passes advisory_id, which the API's detail route does not take (it is keyed on
// vendor_advisory_id and has no route by the UUID). Through 3.0.2 that answered state failed, worded
// as the API holding no record, for an advisory it holds (CVE-2024-3400's Palo Alto row, live
// 2026-10-10), and no probe saw it. This one passes the first row's vendor and advisory_id, on the
// hosted leg after the verdicts, and must get back what #3011 specifies: the advisory itself
// (measured, its advisory_id the one sent), or invalid_input whose error names vendor_advisory_id.
// failed, the 404 relayed as no record, fails it (state_failed). One call per era, two API requests
// (the detail's 404 and the vendors' windows), no per-minute component budget.
//   published  only an endpoint that advertises the fix is judged: its get_vendor_advisory
//              inputSchema says advisory_id is a row's vendor_advisory_id (3.0.2's says only "the
//              vendor's advisory ID"). Before that the line is not_published, so the job can deploy
//              ahead of the endpoint and page on nothing; after it the probe runs with no change here.
//              run.test.mjs holds this package's own tools/list to being detected.
export const CHAIN_LABEL = "chain:get_vendor_advisory@row.advisory_id";
const INTERNAL_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// The first row's vendor and its advisory_id, the internal UUID, from vendor_advisories_for_cve's
// structuredContent; undefined when no row carries both (no_valid_probe_input).
export function internalIdFrom(sc) {
  const rows = sc?.data?.advisories;
  if (!Array.isArray(rows)) return undefined;
  const row = rows.find((r) => r && typeof r.vendor === "string" && r.vendor && typeof r.advisory_id === "string" && INTERNAL_ID.test(r.advisory_id));
  return row ? { vendor: row.vendor, advisory_id: row.advisory_id } : undefined;
}
export const CHAIN_PROBES = [
  {
    label: CHAIN_LABEL,
    tool: "get_vendor_advisory",
    arguments: (seen) => internalIdFrom(seen.vendor_advisories_for_cve),
    published: (tool) => /vendor_advisory_id/.test(tool?.inputSchema?.properties?.advisory_id?.description ?? ""),
    // A success: the advisory the UUID names.
    expect: (sc, args) =>
      sc?.state === "measured" && sc?.data?.advisory_id === args.advisory_id
        ? undefined
        : `state ${JSON.stringify(sc?.state ?? null)}, data.advisory_id ${JSON.stringify(sc?.data?.advisory_id ?? null)}; want the advisory whose advisory_id was sent, or invalid_input naming vendor_advisory_id`,
    // A refusal: invalid_input whose error names the field to pass instead.
    refusal: (sc) =>
      sc?.error?.kind === "invalid_input" && /vendor_advisory_id/.test(sc?.error?.message ?? "")
        ? undefined
        : `invalid_input with error.kind ${JSON.stringify(sc?.error?.kind ?? null)} whose message does not name vendor_advisory_id`,
  },
];

// The hosted leg's prompt and resource probes (#2737), one line each per era, after the tools, the
// prompts in this order. `label` is the line's `tool` (the metric label): a fixed string, so it
// stays bounded, and never renamed, so its series continues. A prompt or resource the endpoint
// does not list is not_published, as a planned tool is. A prompt's answer must be messages with a
// non-blank text (else prompt_empty) that names `expect`; one that does not is reason `unmet`.
//   triage_cve           prompts/get with a CVE: the text must name that CVE, which proves the
//                        argument reached the prompt (prompt_argument_not_applied).
//   workload_triage      prompts/get with source kubernetes, one of its three values (#2846): the
//                        text must name check_sbom, the one tool it routes the agent's purls to
//                        (prompt_tool_not_named).
//   echelongraph://methodology  resources/read: the answer must carry that URI with a non-empty text.
export const PROMPT_PROBES = [
  { label: "prompt:triage_cve", name: "triage_cve", arguments: { cve_id: CVE }, expect: CVE, unmet: "prompt_argument_not_applied" },
  { label: "prompt:workload_triage", name: "workload_triage", arguments: { source: "kubernetes" }, expect: "check_sbom", unmet: "prompt_tool_not_named" },
];
export const RESOURCE_PROBE = { label: "resource:methodology", uri: "echelongraph://methodology" };

// #3282: the release each probed tool, prompt and resource first shipped in, by the line's `tool`
// (a tool's name; a prompt or resource probe's label; a verdict or chain probe reads its tool's).
// An endpoint whose handshake reports this version or a later one and does not list it is a
// failure, reason not_listed (run.mjs unlisted): a hosted revision built from an older tag, one
// deploy over another, or a hosted-only registration regression drops it, and through 3.0.2 that
// read not_published on every run and paged nobody. Before that version, or with no version to
// read, it is not_published, as a planned tool is (one with no entry here). From the CHANGELOG:
// the five tools before 2.4.0 are given 2.4.0, the first release with the hosted entry
// (dist/http.js), which the hosted leg is the only one to reach at an old version; 2.4.0's nine
// (#2726); 2.5.0's prompts and resources (#2722); 2.7.0's cve_remediation (#2841), scan_manifest
// (#2835) and workload_triage (#2846). A tool or probe added to this file is given its release
// here (run.test.mjs holds every probe to an entry).
export const SHIPPED_IN = {
  cve_summary: "2.4.0",
  search_cves: "2.4.0",
  get_cve: "2.4.0",
  cve_exposure: "2.4.0",
  exposure_radar: "2.4.0",
  kev_recent: "2.4.0",
  epss_history: "2.4.0",
  check_affected: "2.4.0",
  check_sbom: "2.4.0",
  scan_manifest: "2.7.0",
  cve_intel: "2.4.0",
  cve_remediation: "2.7.0",
  get_cwe: "2.4.0",
  vendor_advisories_for_cve: "2.4.0",
  get_vendor_advisory: "2.4.0",
  search_vendor_advisories: "2.4.0",
  "prompt:triage_cve": "2.5.0",
  "prompt:workload_triage": "2.7.0",
  "resource:methodology": "2.5.0",
};
