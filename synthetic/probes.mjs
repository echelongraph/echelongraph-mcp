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
// the known-vulnerable pair the probe always sent; the other 199 are versions of one package
// (lodash 4.17.22 through 4.17.220, version numbers made up for the probe), so the batches read one
// package's advisories. The budget it costs: 201 components of the API's 1,200 a minute per caller
// (waf CVEMatchBatchComponentsPerWindow), 2 requests, on each of the run's four legs (two eras, over
// stdio and over the hosted endpoint): 804 components and 8 requests every 15 minutes.
export const SBOM_PROBE_PURLS = [
  "pkg:npm/lodash@4.17.20",
  "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
  ...Array.from({ length: 199 }, (_, i) => `pkg:npm/lodash@4.17.${22 + i}`),
];

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
  cve_intel: [{ cve_id: CVE }],
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
//                       refusing the input, index.ts failed()).
export const EXPECT = {
  check_sbom: (sc) => {
    const sent = sc?.coverage?.batches_sent;
    if (typeof sent === "number" && sent >= 2) return undefined;
    return `coverage.batches_sent ${JSON.stringify(sent ?? null)}, want at least 2 (not_sent_reason ${JSON.stringify(sc?.coverage?.not_sent_reason ?? null)})`;
  },
};

// #2774: the hosted endpoint takes a request body over 64 KiB for check_sbom alone (#2747), and a
// 2-purl list never tested that: a return of the 413 would have left every probe green. So the
// hosted leg sends check_sbom the SAME 201 purls as a CycloneDX 1.5 document, pretty-printed as an
// SBOM tool writes it, each component with its name, version, purl, licence and a SHA-512 (the
// purl's own, so the document is fixed): 124,877 characters, a ~138,000-byte request body, twice
// the 64 KiB cap. Same purls, so the same API budget as before (201 components, two batches per
// era); the components' other fields never leave the endpoint.
function cyclonedxOf(purls) {
  const components = purls.map((purl) => {
    const [, type, rest] = /^pkg:([^/]+)\/(.+)$/.exec(purl);
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
      licenses: [{ license: { id: type === "maven" ? "Apache-2.0" : "MIT" } }],
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

// The hosted leg's prompt and resource probes (#2737), one each per era, after the tools. `label`
// is the line's `tool` (the metric label): a fixed string, so it stays bounded. A prompt or
// resource the endpoint does not list is not_published, as a planned tool is.
//   triage_cve           prompts/get with a CVE: the answer must be messages whose text names that
//                        CVE, which proves the argument reached the prompt.
//   echelongraph://methodology  resources/read: the answer must carry that URI with a non-empty text.
export const PROMPT_PROBE = { label: "prompt:triage_cve", name: "triage_cve", arguments: { cve_id: CVE }, expect: CVE };
export const RESOURCE_PROBE = { label: "resource:methodology", uri: "echelongraph://methodology" };
