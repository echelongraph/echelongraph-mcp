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
export function triageCveText(cve: string): string {
  return [
    `Triage ${cve} using the EchelonGraph MCP tools. Call them in this order, each with cve_id ${cve}:`,
    "1. get_cve: the record. Read score_assessed before echelongraph_score (false: not yet scored, which is not a score of 0); read severity, cvss_v3_score, epss_score and epss_percentile, and the CISA-KEV fields kev_listed, kev_added_date, kev_due_date and kev_ransomware.",
    "2. cve_intel: weaknesses (cwes), public exploit code (exploits and exploits_total; verified_status is the label stored with each reference, not a guarantee that it works, and an empty list is not evidence that no exploit exists), affected_packages (each package's affected ranges with their fixes in fixed_branches) and fixed_versions.",
    "3. vendor_advisories_for_cve: the vendor advisories that name it. Call get_vendor_advisory for one whose remediation you need in full.",
    "4. epss_history: how its EPSS score changed, one point per recorded change (series_kind change_only): before series_starts_at a missing point means not recorded, not unchanged.",
    "5. cve_exposure: internet exposure on record. exposure_state says what the count is; exposed_hosts counts distinct ip:port services, not machines; the result is not_assessed with measured_at null, so present any count as undated and on record, and exposure_state not_assessed as not assessed.",
    ENVELOPE_RULES,
    "Then answer with this template, one line each, naming the tool and the measured_at behind every line:",
    "- Exploited? CISA-KEV listing and its date, known ransomware use, and public exploit code on record.",
    "- Likelihood: EPSS score and percentile, and how it has moved.",
    "- Reachable? exposure_state and the count on record, or not assessed.",
    `- Patch: fixed versions and vendor advisories; where the results hold none, write "none on record", which is not a finding that no fix exists. For each affected package whose cve_intel row carries fixed_branches, give every range with its fix: from introduced ("0" is the first version) up to its fixed, or up to and including last_affected, where no fix is on record for that range; never one range's fix as the fix for every affected branch or the version every install should move to. cve_intel keeps one fixed_version per ecosystem and package, its advisory's last range's as a rule, which need not be the fix for every affected version of the package: where a row has no fixed_branches (null or absent), give fixed_version as the fixed version cve_intel records for that package, never as the fix for every affected branch, and for the fix on a given branch point to get_cve's references tagged Vendor Advisory or Patch, where it has them, and to the vendor advisories.`,
    "- Deadline: get_cve's kev_due_date when the CVE is KEV-listed (CISA's due date for US federal civilian agencies); otherwise write that the results give no CISA deadline.",
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

export function amIAffectedText(a: AffectedArgs): string {
  const subject = a.product ? `the product ${JSON.stringify(a.product)} (an NVD CPE product token)` : `the package ${JSON.stringify(a.package)} in the ${JSON.stringify(a.ecosystem)} ecosystem`;
  const args = a.product ? { product: a.product, version: a.version } : { ecosystem: a.ecosystem, package: a.package, version: a.version };
  return [
    `Check whether ${subject} at version ${JSON.stringify(a.version)} is affected by known CVEs, using the EchelonGraph MCP tools.`,
    `1. Call check_affected with these arguments: ${JSON.stringify(args)}.`,
    ENVELOPE_RULES,
    "Read coverage.assessed before count, and answer with the case that applies:",
    "- assessed true and count above 0: affected. List each match's cve_id with kev_listed, ransomware, epss_score and effective_score (score_assessed false: not yet scored, not a score of 0), CISA-KEV-listed CVEs first.",
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
export function sbomReviewText(sbom: string): string {
  return [
    "Review the SBOM below for known vulnerabilities, using the EchelonGraph MCP tools.",
    `1. Call check_sbom with sbom set to the document below, as given. It reads the document's purls and checks up to ${MAX_PURLS} distinct purls per call, sending them in batches of ${MAX_COMPONENTS}; a document with more is refused, not truncated. If it is refused, say why from the result and do not guess at the components. If coverage.not_sent is above 0, the API's rate limit or the call's time budget stopped it early: say how many purls were not sent and coverage.not_sent_reason, and that they are not checked (never clean). After a minute, call check_sbom once more with purls set to the purls not sent, and merge what it returns. data.not_sent_purls lists them; where the note says the first text block cuts not_sent_purls to its first entries, rebuild the list from the document instead, as the note says: the document's distinct purls from the position the note gives on, counted in the order it gives.`,
    "2. Read each component's ecosystem, package and version from its purl, which every row of data.results in the text carries (the leanest cut of the text leaves out the row's own ecosystem, package and version), as check_sbom maps them. A purl is pkg:type/namespace/name@version?qualifiers, each part percent-decoded (%40 is @), its type and distro qualifier in any case. The version is what follows the last @, up to any ? or #. The ecosystem follows from the type: npm is npm, pypi PyPI, maven Maven, golang Go, cargo crates.io, gem RubyGems, nuget NuGet, composer Packagist, hex Hex, pub Pub, swift SwiftURL, hackage Hackage, cran CRAN, bitnami Bitnami, conan ConanCenter and githubact GitHub Actions. For deb, apk, alpine and rpm it is the release the distro qualifier names, which must be one of these three kinds: distro=debian-N is Debian:N, the major release alone (debian-12 and debian-12.5 are Debian:12); distro=ubuntu-V is Ubuntu:V as given (ubuntu-22.04 is Ubuntu:22.04); distro=alpine-X.Y is Alpine:vX.Y, cut to major.minor (alpine-3.20 and alpine-3.20.10 are Alpine:v3.20; alpine-3 names none). For any other type, and a deb, apk, alpine or rpm purl without such a qualifier, the ecosystem is unknown: check_sbom does not check the component (not_assessed, never clean), and the fix list gives no version for it. The package is namespace:name for maven (pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1 is the package org.apache.logging.log4j:log4j-core in Maven, at version 2.14.1), namespace/name for npm, golang, composer, swift and githubact, and the name alone for every other type (pkg:deb/debian/openssl@3.0.15-1~deb12u1?distro=debian-12 is openssl in Debian:12).",
    "3. For each distinct cve_id on a component whose verdict is affected, call get_cve, to read kev_listed, epss_score, score_assessed, echelongraph_score and cvss_v3_score, and cve_intel, to read fixed_branches and fixed_version from its affected_packages rows, and fixed_version from its fixed_versions rows, for the component's ecosystem and package (package_name). If there are more than 30 distinct CVEs, do this for 30 of them and list the rest as not looked up, unranked.",
    ENVELOPE_RULES,
    "Read each component's verdict: not_affected is the one clean verdict; undetermined and not_assessed are not clean, and not_assessed_reason says why (for example distro_release_unknown: a deb, apk or rpm purl without a distro qualifier, which EchelonGraph does not guess).",
    "Then write a prioritised fix list of the affected components. State the ordering keys, in this order: 1. CISA-KEV listed (kev_listed true) first; 2. then EPSS score, highest first; 3. then echelongraph_score where score_assessed is true, else cvss_v3_score, highest first. A CVE with no value for a key sorts after those with one, and its line says which key was missing.",
    "For each line give the component (purl), its cve_ids, the key values used, and for each CVE a fixed version where the results support one, by this rule. Never give a fixed version that is not strictly greater than the component's installed version (the version in its purl), compared in the ecosystem's version order: release numbers part by part, as numbers, not as text (2.9.1 is below 2.12.2, and 2.12.2 is below 2.14.1); where you are not sure of the order (pre-releases, qualifiers and distro revisions have their own rules), say so and do not give it. Prefer the match's match_reason where the text keeps it: \"falls inside the advisory interval [A, B)\", closed by a parenthesis, says B is the advisory's fixed version for the range that holds the installed version, so give B as the fixed version, quoting it (\"[A, ∞)\": the range has no end on record and names no fixed version). \"falls inside the advisory interval [A, B]\", closed by a square bracket, says B is the range's last affected version, still affected, and the range records no fix (core-backend adds \"(B is the last affected version, not a fix)\", which a cut text can clip, so the bracket alone decides): never give B, or any version at or below it, as a fixed version. Where the text is cut before the interval's closing bracket (\"[A, B…\", neither \")\" nor \"]\"), it does not say which bound B is: give no fixed version from that match_reason. Otherwise, where cve_intel's affected_packages row for the component's ecosystem and package carries fixed_branches, give the fixed of the range that holds the installed version: at or above its introduced (\"0\" is the first version) and below its fixed, or at or below its last_affected, in the same version order; a range with last_affected and no fixed has no fix on record, and a version in no range is given no fixed version from them; where fixed_branches is there, fixed_version is not used. Where it is not (null or absent), give cve_intel's fixed_version for the component's ecosystem and package (or the recorded fix a match_reason names, the same value): cve_intel keeps one fixed_version per package, its advisory's last range's, which need not be the fix on the component's branch, so say so beside it. Where no version meets the rule (\"listed verbatim in the advisory's affected versions\" names none), write that the results give no fixed version for the component's branch, which is not a finding that no fix exists, and point to the CVE's advisory for it: get_cve's references tagged Vendor Advisory or Patch, where it has them.",
    "After the list, give data.summary's counts, and list the undetermined and not_assessed components with their reasons as not checked, never as clean.",
    "Where the note says that rows of data.results are left out of the first text block, list the components its rows carry, say how many affected components the text leaves out (data.summary.affected, less those listed), and give the undetermined and not_assessed components it leaves out as data.summary's counts, by not_assessed_reason, as not checked, never as clean.",
    "",
    "SBOM:",
    "```json",
    sbom,
    "```",
  ].join("\n");
}

export function registerPrompts(server: McpServer, kit: PromptKit): void {
  server.registerPrompt(
    "triage_cve",
    {
      title: "Triage a CVE",
      description:
        "Triage one CVE: get_cve (with CISA's due date when the CVE is KEV-listed), cve_intel, vendor_advisories_for_cve, epss_history and cve_exposure, then a decision template: exploited, likelihood, reachable, patch, deadline. Each line cites its tool and measured_at, and not_assessed is never reported as clean.",
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
      description: `Review an SBOM (CycloneDX JSON or SPDX JSON text, up to ${MAX_SBOM_CHARS} characters): it is passed to check_sbom, which checks up to ${MAX_PURLS} distinct purls per call in batches of ${MAX_COMPONENTS}, then get_cve and cve_intel for each affected CVE, and a prioritised fix list ordered by CISA-KEV listing, then EPSS, then score, each key stated. undetermined and not_assessed components are listed as not checked, never as clean.`,
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
}
