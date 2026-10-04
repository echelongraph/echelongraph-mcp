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

// In createServer()'s registration order, which is tools/list's.
export const PROBES = {
  cve_summary: [{}],
  search_cves: [{ search: "log4j", limit: 2 }],
  get_cve: [{ cve_id: CVE }],
  cve_exposure: [{ cve_id: EXPOSURE_CVE }],
  exposure_radar: [{}],
  kev_recent: [{ limit: 5 }],
  epss_history: [{ cve_id: CVE }],
  // The registry path (ecosystem, package, version), then the CPE path (product, version).
  check_affected: [
    { ecosystem: "npm", package: "lodash", version: "4.17.20" },
    { product: "openssl", version: "3.0.0" },
  ],
  check_sbom: [{ purls: ["pkg:npm/lodash@4.17.20", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"] }],
  cve_intel: [{ cve_id: CVE }],
  get_cwe: [{ cwe_id: "CWE-79" }],
  vendor_advisories_for_cve: [{ cve_id: CVE }],
  get_vendor_advisory: [(seen) => advisoryFrom(seen.vendor_advisories_for_cve)],
  search_vendor_advisories: [{ query: "log4j", limit: 2 }],
};

// Probes that read another tool's answer run after it: get_vendor_advisory after
// vendor_advisories_for_cve.
export const AFTER = { get_vendor_advisory: ["vendor_advisories_for_cve"] };
