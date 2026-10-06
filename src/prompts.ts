// MCP prompts (#2722): ready-made workflows a client shows as slash commands. Each prompt's text
// names the exact tools to call, in order, and tells the model how to read every result's
// evidence envelope: not_assessed is never clean, a count of 0 under assessed false is never "not
// affected", failed and invalid_input are never zero, and every figure is cited with its
// measured_at. The texts are held to the package's claim rules (test/prompts-resources.test.mjs)
// and snapshot-tested, so a wording change is a reviewed change.
//
// Prompt arguments arrive as strings (MCP PromptArgument); a missing or invalid one is refused by
// the SDK as InvalidParams (-32602) before any text is built. A prompt makes no API request.
import type { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod";
import { MAX_COMPONENTS, MAX_PURLS, MAX_SBOM_CHARS } from "./tools/check_sbom.js";

// What the prompts are handed by createServer: the CVE ID pattern the CVE tools validate with.
export type PromptKit = { cveId: RegExp };

export const KEV_BRIEF_DEFAULT_DAYS = 7;
export const KEV_BRIEF_MAX_DAYS = 365;
// The page the brief reads kev_recent in (#2799). The brief puts kev_vuln_name and kev_due_date on
// every line, and a model whose client passes only `content` reads them from the first text block,
// which past 30,000 characters keeps fewer fields a row (src/tools/kev_recent.ts kevText). Through
// 2.6.3 the brief asked for limit 200: on 2026-10-04 the hosted endpoint's text for 365 days at 200
// (306 matching) kept cve_id, kev_added_date, kev_vendor, kev_product and kev_ransomware a row, and
// neither field. A page of 50, kev_recent's default, is sent whole (27,514 characters of production's
// 50 newest), and its first cut level, which keeps both, fits 85 production-shaped rows in the
// budget, so at 50 rows three quarters longer than production's still keep them.
// test/prompt-fields.test.mjs runs the brief's call at this limit.
export const KEV_BRIEF_LIMIT = 50;

// The envelope rules every prompt carries, word for word.
export const ENVELOPE_RULES = [
  "Before you use any figure, read that result's evidence envelope: its structuredContent (where your client shows text blocks alone, the last text block) carries state, measured_at, method, coverage, freshness and notes.",
  "state is measured, not_assessed, failed or invalid_input.",
  "Report not_assessed as not assessed: never as clean, safe, unaffected or none found.",
  'A count of 0 in a result whose coverage says assessed: false is not a finding of "not affected": say the lookup did not evaluate it, and give its not_assessed_reason.',
  "failed and invalid_input mean nothing was looked up: say the lookup did not complete, never zero, none found or unexposed.",
  "Cite the measured_at date behind each figure you report, and say so where measured_at is null.",
  "Quote the notes that qualify a figure, and keep each field's meaning as the result's notes give it.",
  "Do not add facts the results do not carry: where a result says nothing about a point, write that it does not say.",
].join(" ");

const text = (t: string) => ({ messages: [{ role: "user" as const, content: { type: "text" as const, text: t } }] });

// triage_cve reads kev_due_date from get_cve's record (#2799 review). Through 2.6.3 its step 6 read
// it from kev_recent with since and until set to the CVE's kev_added_date, with no limit and no
// paging, so on a day CISA added more than a page the CVE's row could be on no page it read: on the
// hosted endpoint (2.6.3, 2026-10-04) that call for 2021-11-03 answered total 287, 50 rows from
// CVE-2010-5326 to CVE-2019-0797 and has_more true, without CVE-2021-40444, added that day; get_cve
// for CVE-2021-40444 carried kev_due_date 2021-11-17T00:00:00Z in its first text block. The record
// carries kev_due_date wherever CISA gives one (core-backend cve/store.go, omitempty), and get_cve's
// first text block keeps every field of it.
//
// Its Patch line (#2817): cve_intel's fixed_version is one value per (CVE, ecosystem, package), the
// advisory's last range's (core-backend cve/advisory.go UpsertAffectedPackages), and triage_cve has
// no installed version to hold it against: for CVE-2021-44228 production's cve_intel gives
// log4j-core 2.12.2 (2026-10-04, 2.6.3), below an affected 2.14.1. Since #2817 each
// affected_packages row also carries fixed_branches, every range with its fix (core-backend
// cve/fixed_branches.go), so the line gives those, range by range, and gives fixed_version only
// where a row has no fixed_branches, as what cve_intel records for the package, never as the fix
// for every affected branch, sending the reader to get_cve's references tagged Vendor Advisory or
// Patch for a branch's fix.
//
// Its remediation (#2840, #2841): cve_remediation gives, for one CVE, each vendor advisory's
// remediation as the vendor categorises it (remediation_kinds, remediation_state) and the record's
// references tagged Patch or Mitigation, each text relayed as its source states it. The Patch line
// gives them as the vendor's, untested, and a not_parsed or none_in_source state as no finding that
// the vendor lists no fix. vendor_advisories_for_cve rows carry remediation_kinds too, so step 4
// sends the model to get_vendor_advisory where a row lists a workaround or a mitigation.
export function triageCveText(cve: string): string {
  return [
    `Triage ${cve} using the EchelonGraph MCP tools. Call them in this order, each with cve_id ${cve}:`,
    "1. get_cve: the record. Read score_assessed before echelongraph_score (false: not yet scored, which is not a score of 0); read severity, cvss_v3_score, epss_score and epss_percentile, and the CISA-KEV fields kev_listed, kev_added_date, kev_due_date and kev_ransomware, and, where the record carries it, kev_required_action, CISA's own text.",
    "2. cve_intel: weaknesses (cwes), public exploit code (exploits and exploits_total; verified_status is the label stored with each reference, not a guarantee that it works, and an empty list is not evidence that no exploit exists), affected_packages (each package's affected ranges with their fixes in fixed_branches) and fixed_versions.",
    "3. cve_remediation: how it is fixed, as its sources state it: fixed_branches (each affected package's ranges with their fixes), vendor_remediations (each vendor advisory naming the CVE, with its vendor, vendor_advisory_id, remediation_state and remediation_kinds, each kind the vendor's own category) and fix_references (the record's references tagged Patch or Mitigation).",
    "4. vendor_advisories_for_cve: the vendor advisories that name it, with remediation_kinds and remediation_state where a row carries them. Call get_vendor_advisory for one whose remediation you need in full, such as one whose remediation_kinds include workaround or mitigation.",
    "5. epss_history: how its EPSS score changed, one point per recorded change (series_kind change_only): before series_starts_at a missing point means not recorded, not unchanged.",
    "6. cve_exposure: internet exposure on record. exposure_state says what the count is; exposed_hosts counts distinct ip:port services, not machines; the result is not_assessed with measured_at null, so present any count as undated and on record, and exposure_state not_assessed as not assessed.",
    ENVELOPE_RULES,
    "Then answer with this template, one line each, naming the tool and the measured_at behind every line:",
    "- Exploited? CISA-KEV listing and its date, known ransomware use, and public exploit code on record.",
    "- Likelihood: EPSS score and percentile, and how it has moved.",
    "- Reachable? exposure_state and the count on record, or not assessed.",
    `- Patch: fixed versions, vendor remediation and fix references; where the results hold none, write "none on record", which is not a finding that no fix exists. For each affected package whose cve_intel row carries fixed_branches, give every range with its fix: from introduced ("0" is the first version) up to its fixed, or up to and including last_affected, where no fix is on record for that range; never one range's fix as the fix for every affected branch or the version every install should move to. cve_intel keeps one fixed_version per ecosystem and package, its advisory's last range's as a rule, which need not be the fix for every affected version of the package: where a row has no fixed_branches (null or absent), give fixed_version as the fixed version cve_intel records for that package, never as the fix for every affected branch, and for the fix on a given branch point to get_cve's references tagged Vendor Advisory or Patch, where it has them, and to the vendor advisories. From cve_remediation, give each vendor_remediations advisory by vendor and vendor_advisory_id with its remediation_kinds, a workaround or mitigation as the step that vendor states, which EchelonGraph has not tested and which is not a fix, and its fix_references; a remediation_state of not_parsed or none_in_source is not a finding that the vendor lists no fix.`,
    "- Deadline: get_cve's kev_due_date when the CVE is KEV-listed (CISA's due date for US federal civilian agencies); otherwise write that the results give no CISA deadline. Where get_cve carries kev_required_action, quote it, attributed to CISA, as the action CISA requires of those agencies, not as EchelonGraph's advice.",
    "- Decision: patch now, schedule, or monitor, with a one-line reason drawn from the lines above.",
  ].join("\n");
}

export function kevWeeklyBriefText(days: number): string {
  return [
    `Write a brief of the CVEs CISA added to its Known Exploited Vulnerabilities (KEV) catalog in the last ${days} days, using the EchelonGraph MCP tools.`,
    `1. Compute since: today's date in UTC minus ${days} days, as YYYY-MM-DD. State the since date you used, and today's date.`,
    `2. Call kev_recent with since set to that date and limit ${KEV_BRIEF_LIMIT}. While its coverage.has_more is true, call kev_recent again with the same since and limit and cursor set to the previous answer's next_cursor.`,
    ENVELOPE_RULES,
    "Then write the brief:",
    "- Header: the date range, the number of CVEs added (total), and measured_at, EchelonGraph's last successful fetch of CISA's feed, with catalog_version.",
    "- One section per kev_vendor, vendors in alphabetical order. Under each, one line per CVE: cve_id, kev_product, kev_vuln_name, kev_added_date, kev_due_date, and RANSOMWARE where kev_ransomware is true.",
    "- A closing section listing again the CVEs with kev_ransomware true, and every kev_due_date in the range, earliest first.",
    "- If total is 0, write that no CVE was added in that range in the catalog copy fetched at measured_at. If kev_recent failed, write that the catalog could not be read: never that nothing was added.",
  ].join("\n");
}

export type AffectedArgs = { product?: string; ecosystem?: string; package?: string; version: string };

// am_i_affected (#2834): a registry match carries fixed_in, the fixed bound of the advisory interval
// that holds the version asked about (core-backend cve/pkgmatch.go; check_affected keeps it at every
// cut level), so the registry text gives it, and a null or absent one as no fixed version on record
// for that range. A CPE match carries none, so the product text names none.
export function amIAffectedText(a: AffectedArgs): string {
  const subject = a.product ? `the product ${JSON.stringify(a.product)} (an NVD CPE product token)` : `the package ${JSON.stringify(a.package)} in the ${JSON.stringify(a.ecosystem)} ecosystem`;
  const args = a.product ? { product: a.product, version: a.version } : { ecosystem: a.ecosystem, package: a.package, version: a.version };
  return [
    `Check whether ${subject} at version ${JSON.stringify(a.version)} is affected by known CVEs, using the EchelonGraph MCP tools.`,
    `1. Call check_affected with these arguments: ${JSON.stringify(args)}.`,
    ENVELOPE_RULES,
    "Read coverage.assessed before count, and answer with the case that applies:",
    "- assessed true and count above 0: affected. List each match's cve_id with kev_listed, ransomware, epss_score and effective_score (score_assessed false: not yet scored, not a score of 0), CISA-KEV-listed CVEs first.",
    ...(a.product
      ? []
      : [
          "  For each match, give its fixed_in where it is a version: the fixed bound of the advisory interval that holds this version. Where fixed_in is null or absent, write that the result gives no fixed version for this version's range, which is not a finding that no fix exists.",
        ]),
    "- assessed true and count 0: no matching CVE in EchelonGraph's data at this version. Give undetermined_count too: an advisory that could not be decided at this version is not safe.",
    "- assessed false: NOT ASSESSED. Write that the lookup did not evaluate this version, give not_assessed_reason, and never report it as not affected or clean.",
    "- failed or invalid_input: the check did not run. Say why, from the result.",
    "Where capped, candidates_capped or degraded is true, say the list may be incomplete and why.",
  ].join("\n");
}

// sbom_review (#2799). The purls a call did not send: data.not_sent_purls lists them, and where the
// first text block cuts that list to its first entries (check_sbom's TEXT CUT says so), the model
// rebuilds them from the document, from the position check_sbom's note gives, in the order it
// gives (check_sbom.ts READ_ORDER).
//
// Fixed versions (#2799 review, #2817, #2830). cve_intel's fixed_version is one value per (CVE, ecosystem,
// package), the advisory's last range's (core-backend cve/advisory.go UpsertAffectedPackages), so
// it need not be the fix for the installed version's branch: for CVE-2021-44228, production's
// cve_intel gives log4j-core 2.12.2 (2026-10-04, 2.6.3), older than an installed 2.14.1, and
// check_sbom's matches for 2.14.1 say it "is listed verbatim in the advisory's affected versions",
// which names no fix. So a fixed version is given only where it is strictly greater than the
// installed version, and otherwise the line says the results give none for the component's branch
// and points to the advisory. The advisory interval in a match's match_reason (core-backend
// cve/pkgmatch.go renderInterval) is preferred where the text keeps it (its first cut level;
// a Juice Shop SBOM of 50 components is cut past it). Since #2830 its closing bracket carries the
// bound's meaning: "[A, B)" is a fixed bound, B the first version not affected, so B is given as
// the fix; "[A, B] (B is the last affected version, not a fix)" is an OSV last_affected bound,
// B still affected, so B (or any version at or below it) is never given as a fix; "[A, ∞)" has no
// end on record; a text clipped before the closing bracket ("[A, B…") gives no fix from it.
// Through 2.6.5 core-backend rendered a last_affected bound as "[A, B)" too, and the prompt
// hedged B as "the end of that interval". Since #2817 cve_intel's affected_packages rows carry
// fixed_branches, every range with its fix, so after the match_reason interval the rule reads the
// range that holds the installed version (2.14.1: [2.13.0, 2.15.0), so 2.15.0), and falls back to
// fixed_version only for a row without fixed_branches.
// A cut text keeps index, purl, verdict, not_assessed_reason and cve_ids on a row, not its
// ecosystem, package or version, so the model reads those from the purl, as core-backend's
// matcher does (cve/matchbatch.go purlNameVersion, shared/pkg/purlosv): step 2 lists every type
// purlosv maps (its unversioned table, and deb, apk, alpine and rpm by the distro qualifier, of
// the three kinds osvDistro reads, Alpine cut to major.minor and Debian to its major), the types
// purlNameVersion names with their namespace, and says any other is unknown, with no fixed version.
// test/prompt-fields.test.mjs fromPurl holds the same tables.
//
// fixed_in (#2834): each check_sbom match carries fixed_in, the fixed bound of the advisory
// interval that holds the component's version, which core-backend asserts is above it, or null
// where that interval records no fix (it ends at last_affected, or has no end) or no interval holds
// the version. check_sbom's text keeps fixed_in on every match it keeps, and keeps fewer fields than
// match_reason's 200 characters, so the rule reads fixed_in first. The match_reason and cve_intel
// rules below it are for a match without fixed_in (an API before #2834) and for a component whose
// matches the cut text leaves out (its leanest level keeps cve_ids, not matches).
//
// Remediation (#2841): for the first CVEs of the list, cve_remediation gives each vendor's own
// remediation, as the vendor categorises it; the list gives it as the vendor's, untested.
export function sbomReviewText(sbom: string): string {
  return [
    "Review the SBOM below for known vulnerabilities, using the EchelonGraph MCP tools.",
    `1. Call check_sbom with sbom set to the document below, as given. It reads the document's purls and checks up to ${MAX_PURLS} distinct purls per call, sending them in batches of ${MAX_COMPONENTS}; a document with more is refused, not truncated. If it is refused, say why from the result and do not guess at the components. If coverage.not_sent is above 0, the API's rate limit or the call's time budget stopped it early: say how many purls were not sent and coverage.not_sent_reason, and that they are not checked (never clean). After a minute, call check_sbom once more with purls set to the purls not sent, and merge what it returns. data.not_sent_purls lists them; where the note says the first text block cuts not_sent_purls to its first entries, rebuild the list from the document instead, as the note says: the document's distinct purls from the position the note gives on, counted in the order it gives.`,
    "2. Read each component's ecosystem, package and version from its purl, which every row of data.results in the text carries (the leanest cut of the text leaves out the row's own ecosystem, package and version), as check_sbom maps them. A purl is pkg:type/namespace/name@version?qualifiers, each part percent-decoded (%40 is @), its type and distro qualifier in any case. The version is what follows the last @, up to any ? or #. The ecosystem follows from the type: npm is npm, pypi PyPI, maven Maven, golang Go, cargo crates.io, gem RubyGems, nuget NuGet, composer Packagist, hex Hex, pub Pub, swift SwiftURL, hackage Hackage, cran CRAN, bitnami Bitnami, conan ConanCenter and githubact GitHub Actions. For deb, apk, alpine and rpm it is the release the distro qualifier names, which must be one of these three kinds: distro=debian-N is Debian:N, the major release alone (debian-12 and debian-12.5 are Debian:12); distro=ubuntu-V is Ubuntu:V as given (ubuntu-22.04 is Ubuntu:22.04); distro=alpine-X.Y is Alpine:vX.Y, cut to major.minor (alpine-3.20 and alpine-3.20.10 are Alpine:v3.20; alpine-3 names none). For any other type, and a deb, apk, alpine or rpm purl without such a qualifier, the ecosystem is unknown: check_sbom does not check the component (not_assessed, never clean), and the fix list gives no version for it. The package is namespace:name for maven (pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1 is the package org.apache.logging.log4j:log4j-core in Maven, at version 2.14.1), namespace/name for npm, golang, composer, swift and githubact, and the name alone for every other type (pkg:deb/debian/openssl@3.0.15-1~deb12u1?distro=debian-12 is openssl in Debian:12).",
    "3. For each distinct cve_id on a component whose verdict is affected, call get_cve, to read kev_listed, epss_score, score_assessed, echelongraph_score and cvss_v3_score, and cve_intel, to read fixed_branches and fixed_version from its affected_packages rows, and fixed_version from its fixed_versions rows, for the component's ecosystem and package (package_name). If there are more than 30 distinct CVEs, do this for 30 of them and list the rest as not looked up, unranked.",
    ENVELOPE_RULES,
    "Read each component's verdict: not_affected is the one clean verdict; undetermined and not_assessed are not clean, and not_assessed_reason says why (for example distro_release_unknown: a deb, apk or rpm purl without a distro qualifier, which EchelonGraph does not guess).",
    "Then write a prioritised fix list of the affected components. State the ordering keys, in this order: 1. CISA-KEV listed (kev_listed true) first; 2. then EPSS score, highest first; 3. then echelongraph_score where score_assessed is true, else cvss_v3_score, highest first. A CVE with no value for a key sorts after those with one, and its line says which key was missing.",
    "For each line give the component (purl), its cve_ids, the key values used, and for each CVE a fixed version where the results support one, by this rule. First, where the text keeps the component's match for the CVE and the match carries fixed_in: a version there is the fixed bound of the advisory interval that holds the installed version, so give it as the fixed version; null says the advisory records no fixed version for the installed version's range, so give none for that CVE on that component, and write that the results give no fixed version for its branch, which is not a finding that no fix exists. Where the match has no fixed_in field, or the text keeps no match for the component, the rest of this rule applies. Never give a fixed version that is not strictly greater than the component's installed version (the version in its purl), compared in the ecosystem's version order: release numbers part by part, as numbers, not as text (2.9.1 is below 2.12.2, and 2.12.2 is below 2.14.1); where you are not sure of the order (pre-releases, qualifiers and distro revisions have their own rules), say so and do not give it. Prefer the match's match_reason where the text keeps it: \"falls inside the advisory interval [A, B)\", closed by a parenthesis, says B is the advisory's fixed version for the range that holds the installed version, so give B as the fixed version, quoting it (\"[A, ∞)\": the range has no end on record and names no fixed version). \"falls inside the advisory interval [A, B]\", closed by a square bracket, says B is the range's last affected version, still affected, and the range records no fix (core-backend adds \"(B is the last affected version, not a fix)\", which a cut text can clip, so the bracket alone decides): never give B, or any version at or below it, as a fixed version. Where the text is cut before the interval's closing bracket (\"[A, B…\", neither \")\" nor \"]\"), it does not say which bound B is: give no fixed version from that match_reason. Otherwise, where cve_intel's affected_packages row for the component's ecosystem and package carries fixed_branches, give the fixed of the range that holds the installed version: at or above its introduced (\"0\" is the first version) and below its fixed, or at or below its last_affected, in the same version order; a range with last_affected and no fixed has no fix on record, and a version in no range is given no fixed version from them; where fixed_branches is there, fixed_version is not used. Where it is not (null or absent), give cve_intel's fixed_version for the component's ecosystem and package (or the recorded fix a match_reason names, the same value): cve_intel keeps one fixed_version per package, its advisory's last range's, which need not be the fix on the component's branch, so say so beside it. Where no version meets the rule (\"listed verbatim in the advisory's affected versions\" names none), write that the results give no fixed version for the component's branch, which is not a finding that no fix exists, and point to the CVE's advisory for it: get_cve's references tagged Vendor Advisory or Patch, where it has them.",
    "Then, for the first 5 CVEs of the list (fewer if it has fewer), call cve_remediation with the CVE's cve_id, and under the CVE's line give each vendor_remediations advisory by vendor and vendor_advisory_id with its remediation_kinds, a workaround or mitigation as the step that vendor states, which EchelonGraph has not tested and which is not a fix; a remediation_state of not_parsed or none_in_source is not a finding that the vendor lists no fix.",
    "After the list, give data.summary's counts, and list the undetermined and not_assessed components with their reasons as not checked, never as clean.",
    "Where the note says that rows of data.results are left out of the first text block, list the components its rows carry, say how many affected components the text leaves out (data.summary.affected, less those listed), and give the undetermined and not_assessed components it leaves out as data.summary's counts, by not_assessed_reason, as not checked, never as clean.",
    "",
    "SBOM:",
    "```json",
    sbom,
    "```",
  ].join("\n");
}

// workload_triage (#2846): the agent's own pods or images, ranked against the advisory corpus and
// CISA's KEV catalog, exposed workloads first. The prompt takes no workload data (its one argument
// says where the workloads are listed), and has the agent send check_sbom purls alone: no workload,
// namespace, image or registry name, no credential and no exposure label goes into any argument,
// and the image's own purl (pkg:oci, pkg:docker), which names it, is left out. Exposure is the
// agent's reading of the user's own cluster or CI data, labelled caller-asserted, never an
// EchelonGraph measurement; the prompt names none of EchelonGraph's internet-exposure tools, whose
// counts are not about the user's workloads (test/prompts-resources.test.mjs holds both). The order
// is KEV, then exposure (unknown is never sorted with not exposed, #644), then EPSS, then score.
//
// What it reads is what check_sbom's text keeps: kev_listed, ransomware, epss_score,
// effective_score, score_assessed and fixed_in on each match while matches are kept; past its
// leanest cut a row keeps cve_ids alone, so the agent reads those CVEs from get_cve
// (test/prompt-fields.test.mjs). OS packages: a deb or apk purl without an upstream qualifier is
// looked up by its binary name while Debian and Alpine file advisories under the source package, so
// such rows can come back not_assessed (production, 2026-10-05: libssl3 at Debian:12 answers
// package_not_in_advisory_corpus); the prompt has the agent count and state them, never as clean.
export const WORKLOAD_SOURCES = ["kubernetes", "github_actions", "images"] as const;
export type WorkloadSource = (typeof WORKLOAD_SOURCES)[number];
// A CVE count past which the agent stops calling get_cve, as in sbom_review.
const WORKLOAD_GET_CVE_MAX = 30;

const WORKLOAD_LIST: Record<WorkloadSource, string> = {
  kubernetes:
    "Kubernetes: kubectl get pods -A -o json (or a Kubernetes MCP server). Each pod's .status.containerStatuses[].imageID, and .status.initContainerStatuses[].imageID, holds the digest of the image the container runs (…@sha256:…). Keep each pod's namespace, name and owner (its Deployment, StatefulSet, DaemonSet or Job) for your own table.",
  github_actions:
    "GitHub Actions: the repository's workflow files (.github/workflows/*.yml), read with the GitHub MCP server or a checkout. Each job's container: and services: entries name the images it runs. Where an entry gives a tag, resolve it to its digest (for example crane digest, skopeo inspect or docker buildx imagetools inspect) and say that you did.",
  images:
    "Images: the image references the user gives you. Resolve each tag to its digest (for example crane digest or skopeo inspect), and say that you did.",
};
const WORKLOAD_EXPOSURE: Record<WorkloadSource, string> = {
  kubernetes:
    "In a cluster, exposed means a Service of type LoadBalancer or NodePort selects the pod, an Ingress (or a Gateway route) sends traffic to a Service that selects it, or the pod sets hostNetwork: true; not exposed means you read the pod's spec and the cluster's Services, Ingresses and routes, and none of these holds; unknown means you could not read them, or the user tells you of a path you cannot see (a load balancer outside the cluster, for example).",
  github_actions:
    "For a CI job's container and services, exposure is unknown unless the user tells you otherwise; write what the user told you, as caller-asserted.",
  images:
    "For an image the user names, exposure is unknown unless the user tells you how it is reached; write what the user told you, as caller-asserted.",
};
const WORKLOAD_ROW: Record<WorkloadSource, string> = {
  kubernetes: "for a pod, its namespace and owner, or the pod where it has no owner",
  github_actions: "for a CI job, its workflow and job",
  images: "for an image the user names, the image",
};

export function workloadTriageText(source?: WorkloadSource): string {
  const sources = source ? [source] : WORKLOAD_SOURCES;
  const each = (m: Record<WorkloadSource, string>) => sources.map((k) => m[k]).join(" ");
  return [
    "Triage the container workloads you can reach with your own tools against EchelonGraph's advisory corpus and CISA's Known Exploited Vulnerabilities (KEV) catalog, using the EchelonGraph MCP tools, and rank them by CISA-KEV listing, then exposure.",
    "What you send EchelonGraph is package URLs (purls) and CVE IDs: put no workload, namespace, image or registry name, no credential and no exposure label into any argument of any EchelonGraph tool.",
    `1. List the workloads and the digest of each image they run, with your own tools. ${each(WORKLOAD_LIST)} An image you cannot resolve to a digest is listed with its tag as not pinned: a tag can later point at another image.`,
    `2. Decide each workload's exposure yourself, from the same data, as exposed, not exposed or unknown, and label it caller-asserted. ${each(WORKLOAD_EXPOSURE)} Unknown is never treated as not exposed. EchelonGraph measured none of this: no EchelonGraph tool reports the exposure of your workloads.`,
    "3. Make an SBOM of each distinct digest with your own tools, for example syft <image>@sha256:<digest> -o cyclonedx-json, or trivy image --format cyclonedx <image>@sha256:<digest>. Take the purls of its components, leave out the purl of the image itself (pkg:oci or pkg:docker), and keep your own map from each purl to the images that carry it.",
    `4. Call check_sbom with purls set to one image's purls, or to several images' purls together, up to ${MAX_PURLS} distinct purls per call. Pass purls, not the SBOM document: a document's metadata can name the image. data.results holds one row per purl sent, each with its purl, which your map ties to its images. If coverage.not_sent is above 0, say how many purls were not sent and coverage.not_sent_reason, and that they are not checked (never clean); after a minute, call check_sbom once more with purls set to the purls not sent: data.not_sent_purls, or, where the note says the first text block cuts that list, the distinct purls you sent from the position the note gives on, in the order you sent them.`,
    `5. For each affected row, read kev_listed, ransomware, epss_score, effective_score, score_assessed and fixed_in from its matches where the text keeps them. Where the text keeps a row's cve_ids without its matches, call get_cve for each of those CVEs, to read kev_listed, kev_ransomware, epss_score, score_assessed, echelongraph_score and cvss_v3_score; past ${WORKLOAD_GET_CVE_MAX} such CVEs, list the rest as not looked up, unranked.`,
    ENVELOPE_RULES,
    "Read each row's verdict: not_affected is the one clean verdict; undetermined and not_assessed are not clean, and not_assessed_reason says why. Packages from an image's operating system (deb, apk and rpm purls) can come back not_assessed: one without a distro qualifier (distro_release_unknown), and a deb or apk purl without an upstream qualifier, which is looked up by its binary package name while Debian and Alpine file advisories under the source package. For each image, state how many of its OS-package rows are not_assessed, and never count them as clean.",
    `Then write one row per workload (${sources.map((k) => WORKLOAD_ROW[k]).join("; ")}), with: the image digests it runs; its KEV-listed CVEs, each with RANSOMWARE where ransomware (or get_cve's kev_ransomware) is true, and the match's fixed_in where it is a version (null or absent: the results give no fixed version for that branch, which is not a finding that no fix exists); its highest epss_score; its exposure, labelled caller-asserted, with the line of the user's data you read it from; and its counts of affected, undetermined and not_assessed rows.`,
    "Order the rows by these keys, and state them: 1. a workload with a KEV-listed CVE (kev_listed true) first; 2. then exposure: exposed, then unknown, then not exposed; 3. then the highest epss_score, highest first; 4. then the highest score: effective_score, or get_cve's echelongraph_score, where score_assessed is true, else cvss_v3_score, highest first. A workload with no value for a key sorts after those with one, and its row says which key was missing.",
    "Say plainly that every exposure label is caller-asserted: it came from the user's own cluster or CI data, read by you, and EchelonGraph measured none of it. List the images you could not resolve, scan or check, with why, as not checked, never as clean.",
  ].join("\n");
}

export function registerPrompts(server: McpServer, kit: PromptKit): void {
  server.registerPrompt(
    "triage_cve",
    {
      title: "Triage a CVE",
      description:
        "Triage one CVE: get_cve (with CISA's due date when the CVE is KEV-listed), cve_intel, cve_remediation, vendor_advisories_for_cve, epss_history and cve_exposure, then a decision template: exploited, likelihood, reachable, patch, deadline. Each line cites its tool and measured_at, and not_assessed is never reported as clean.",
      argsSchema: z.object({
        cve_id: z
          .string()
          .trim()
          .regex(kit.cveId, "cve_id must be a CVE ID such as CVE-2024-3400")
          .describe("a CVE ID, e.g. CVE-2024-3400"),
      }),
    },
    ({ cve_id }) => text(triageCveText(cve_id.toUpperCase())),
  );

  server.registerPrompt(
    "kev_weekly_brief",
    {
      title: "CISA KEV brief",
      description:
        "A brief of the CVEs CISA added to its KEV catalog in the last N days (default 7): kev_recent from a since date the model computes from days, grouped by vendor, with ransomware flags and due dates, dated by EchelonGraph's last successful fetch of CISA's feed.",
      // A client may send no arguments at all for a prompt whose arguments are all optional.
      argsSchema: z.preprocess((v) => v ?? {}, z.object({
        days: z
          .string()
          .trim()
          .regex(/^\d{1,3}$/, `days must be a whole number from 1 to ${KEV_BRIEF_MAX_DAYS}`)
          .refine((v) => Number(v) >= 1 && Number(v) <= KEV_BRIEF_MAX_DAYS, `days must be a whole number from 1 to ${KEV_BRIEF_MAX_DAYS}`)
          .optional()
          .describe(`how many days back to cover, 1 to ${KEV_BRIEF_MAX_DAYS} (default ${KEV_BRIEF_DEFAULT_DAYS})`),
      })),
    },
    ({ days }) => text(kevWeeklyBriefText(days === undefined || days === "" ? KEV_BRIEF_DEFAULT_DAYS : Number(days))),
  );

  server.registerPrompt(
    "am_i_affected",
    {
      title: "Am I affected?",
      description:
        "Whether a product (its NVD CPE product token) or a registry package (ecosystem and package) at a version is affected by known CVEs: check_affected, read assessed before count, with the not-assessed wording: a count of 0 under assessed false is never reported as not affected.",
      argsSchema: z
        .object({
          product: z.string().trim().min(1).optional().describe("CPE path: the NVD CPE product token, such as openssl or nginx. Leave out for the registry path."),
          ecosystem: z.string().trim().min(1).optional().describe("Registry path: the package's ecosystem, such as npm, PyPI or Maven. Give with package."),
          package: z.string().trim().min(1).optional().describe("Registry path: the package name, such as lodash. Give with ecosystem."),
          version: z.string().trim().min(1).describe("The version to check, such as 3.0.0."),
        })
        .superRefine((a, ctx) => {
          const registry = a.ecosystem !== undefined || a.package !== undefined;
          if (a.product !== undefined && registry) {
            ctx.addIssue({ code: "custom", message: "give product, or ecosystem and package, not both" });
          } else if (a.product === undefined && (a.ecosystem === undefined || a.package === undefined)) {
            ctx.addIssue({ code: "custom", message: "give product, or both ecosystem and package" });
          }
        }),
    },
    (a) => text(amIAffectedText(a)),
  );

  server.registerPrompt(
    "sbom_review",
    {
      title: "SBOM review",
      description: `Review an SBOM (CycloneDX JSON or SPDX JSON text, up to ${MAX_SBOM_CHARS} characters): it is passed to check_sbom, which checks up to ${MAX_PURLS} distinct purls per call in batches of ${MAX_COMPONENTS}, then get_cve and cve_intel for each affected CVE, and a prioritised fix list ordered by CISA-KEV listing, then EPSS, then score, each key stated, with each fixed version read from check_sbom's fixed_in where a match carries it, and cve_remediation's vendor remediation for the first 5 CVEs. undetermined and not_assessed components are listed as not checked, never as clean.`,
      argsSchema: z.object({
        sbom: z
          .string()
          .min(1, "sbom is required")
          .max(MAX_SBOM_CHARS, `sbom is longer than ${MAX_SBOM_CHARS} characters, check_sbom's cap`)
          .describe(`a CycloneDX JSON or SPDX JSON document, as JSON text, up to ${MAX_SBOM_CHARS} characters; it is passed to check_sbom`),
      }),
    },
    ({ sbom }) => text(sbomReviewText(sbom)),
  );

  server.registerPrompt(
    "workload_triage",
    {
      title: "Triage my workloads",
      description:
        "Rank your own pods, CI job containers or images against EchelonGraph's advisory corpus and CISA's KEV catalog: you list the workloads and decide their exposure with your own tools, make an SBOM of each image digest, and pass check_sbom the purls alone; rows are ordered by CISA-KEV listing, then caller-asserted exposure, then EPSS, then score. not_assessed rows are counted and never reported as clean. The prompt takes no workload data.",
      // A client may send no arguments at all for a prompt whose arguments are all optional.
      argsSchema: z.preprocess((v) => v ?? {}, z.object({
        source: z
          .enum(WORKLOAD_SOURCES)
          .optional()
          .describe("where the workloads are listed: kubernetes, github_actions or images (default: all three ways are described)"),
      })),
    },
    ({ source }) => text(workloadTriageText(source)),
  );
}
