// What every client must hand the model whole (#2842): the server instructions and each tool
// description fit CLIENT_DESCRIPTION_CUT, and the sentences REQUIRED_IN_HEAD names sit inside it.
// test/tools.test.mjs ("client 2,048-character cut") holds both, for every tool tools/list serves:
// a description or the instructions grown past the cut, a required sentence moved past it or
// dropped, a head naming Shodan without SHODAN_OWNERSHIP, or a tool registered with no entry here
// fails it. A tool added later adds its entry here.
//
// The cut. Claude Code sends each MCP tool description and each server's instructions to the model
// cut at 2,048 characters, with "… [truncated]" appended:
//   - Claude Code docs, environment variables (code.claude.com/docs/en/env-vars, read 2026-10-05):
//     CLAUDE_CODE_MAX_MCP_DESCRIPTION_LENGTH, "Maximum length in characters of each MCP tool
//     description and each MCP server's instructions that Claude Code sends to the model (default:
//     2048)", v2.1.280 or later;
//   - anthropics/claude-code#87650 (closed, not planned): the minified constant Tpe=2048 gates the
//     cut in v2.1.234; /mcp shows the whole text while the model receives the cut one, and only the
//     instructions' cut is logged ("Server instructions truncated from X to 2048 chars").
// The other clients looked at cut later or not at all: Cursor cuts tool descriptions at 6,500
// characters (Cursor staff, forum.cursor.com/t/147465); VS Code and Claude Desktop document no
// description cap (VS Code caps a tool's name at 64 characters and a request at 128 tools). So
// Claude Code's default is the budget: text that fits it reaches every one of them whole.
//
// Kept under src/ so marketing-site lib/mcpToolClaims.test.ts's resolver can fold the two Shodan
// sentences, which the descriptions and notes take from here.
export const CLIENT_DESCRIPTION_CUT = 2048;

export const SHODAN_ATTRIBUTION = "Exposure counts are derived from Shodan data.";
// Shodan's terms (https://static.shodan.io/legal/terms.html, read 2026-09-27) ask for two
// things: "You must attribute such usage to Shodan", and materials "referencing, including or
// otherwise based on Shodan information or materials, must clearly indicate Shodan's ownership
// and copyright in the applicable Shodan materials" (#2306). The attribution above does the
// first; this sentence, placed beside it wherever Shodan data is named, does the second.
export const SHODAN_OWNERSHIP = "Shodan data is owned by Shodan, which holds its copyright (© Shodan).";

// Sentences the instructions must carry inside the cut: the licence condition, and the rules that
// keep a zero or a failure from reading as a finding.
export const REQUIRED_IN_INSTRUCTIONS: readonly string[] = [
  `${SHODAN_ATTRIBUTION} ${SHODAN_OWNERSHIP}`,
  "not_assessed means the answer holds no dated measurement of what was asked, so no count in it is presented as one.",
  "A zero is not a finding of no exposure where the answer holds no measurement for that CVE",
  "failed and invalid_input mean nothing was measured",
];

// Per tool, the sentences its description must carry inside the cut: attribution and ownership
// where it names Shodan data, the rule that keeps a 0 or a false from reading as a finding, the
// score_assessed rule, and what leaves the caller's machine.
export const REQUIRED_IN_HEAD: Readonly<Record<string, readonly string[]>> = {
  cve_summary: [
    "summary.none is not a severity rating of None",
    "provenance, never EchelonGraph's severity band",
    "they are withdrawn records, none of them a vulnerability",
    "they describe that instance, never the feed's size, intake, reliability or freshness",
  ],
  search_cves: [
    "echelongraph_score, echelongraph_severity and echelongraph_risk are EchelonGraph's score only when score_assessed is true.",
    "With score_assessed false the CVE is NOT YET SCORED, not scored 0",
    "patch_available false means no fix evidence is on record, which is not a finding that no fix exists.",
  ],
  get_cve: [
    "echelongraph_score, echelongraph_severity and echelongraph_risk are EchelonGraph's score only when score_assessed is true.",
    "With score_assessed false the CVE is NOT YET SCORED, not scored 0",
    "patch_available false means no fix evidence is on record, which is not a finding that no fix exists.",
    "which is not a finding that no product is affected",
    "CISA's own text relayed verbatim (kev_required_action, not EchelonGraph's advice",
  ],
  cve_exposure: [
    "exposure counts are derived from Shodan data.",
    SHODAN_OWNERSHIP,
    "for a CVE outside that set the note says NOT ASSESSED (exposure_state not_assessed), and its 0 is not a measurement.",
  ],
  exposure_radar: [
    "derived from Shodan data",
    SHODAN_OWNERSHIP,
    "(no Shodan data)",
    "its 0 is not one",
  ],
  kev_recent: ["catalog.catalog_count is CISA's own count"],
  epss_history: [
    "a day without a point is not a recorded value",
    "Between series_starts_at and complete_since the record misses changes, so a missing point there does not mean unchanged either",
  ],
  check_affected: [
    "a count of 0 there is not a finding of not affected",
    "never as safe",
    "travel in request headers, never in the URL",
  ],
  check_sbom: [
    "only they are sent to the API",
    "over the hosted endpoint (mcp.echelongraph.io) it is EchelonGraph's",
    "not_affected is the only clean verdict",
    "is refused, not truncated",
  ],
  // #2835: what leaves the caller's machine, the hosted endpoint's part, and the rules that keep
  // an entry not checked, or a refused go.sum, from reading as clean.
  scan_manifest: [
    "only the purls are sent to the API",
    "over the hosted endpoint (mcp.echelongraph.io) it is EchelonGraph's",
    "filenames and file contents are not sent on",
    "not_affected is the only clean verdict",
    "not_checked entries are not clean",
    "go.sum is refused",
  ],
  // #2841: the untested-source sentence, the not-a-zero rule and whose action CISA's is.
  cve_remediation: [
    "Every text is relayed as stated by its source; EchelonGraph has not tested it.",
    "An empty list or a remediation_state of none_in_source or not_parsed is not a finding that no fix exists.",
    "CISA's required_action is directed at US federal civilian agencies (BOD 22-01) and is not EchelonGraph's advice.",
  ],
  cve_intel: [
    "An empty exploits list is not evidence that no public exploit exists",
    "not the fix for every affected range",
  ],
  get_cwe: ["echelongraph_score is EchelonGraph's score only when score_assessed is true", "not that none exists"],
  vendor_advisories_for_cve: [
    "not that no vendor published one",
    "no advisory from a vendor is not a finding that it published none",
    "rejected_cve_ids: the CVE IDs it names whose CVE record was rejected (withdrawn) by its numbering authority, which are not active vulnerabilities",
    "cve_rejected is true when the CVE record of the CVE asked for was rejected",
  ],
  get_vendor_advisory: ["withdrawn (true: the vendor rescinded it", "which are not active vulnerabilities"],
  search_vendor_advisories: ["never exactly 1,000", "The query is sent in a request header, never in the URL.", "which are not active vulnerabilities"],
};
