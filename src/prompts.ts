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

export function triageCveText(cve: string): string {
  return [
    `Triage ${cve} using the EchelonGraph MCP tools. Call them in this order, each with cve_id ${cve}:`,
    "1. get_cve: the record. Read score_assessed before echelongraph_score (false: not yet scored, which is not a score of 0); read severity, cvss_v3_score, epss_score and epss_percentile, and the CISA-KEV fields kev_listed, kev_added_date and kev_ransomware.",
    "2. cve_intel: weaknesses (cwes), public exploit code (exploits and exploits_total; verified_status is the label stored with each reference, not a guarantee that it works, and an empty list is not evidence that no exploit exists), affected_packages and fixed_versions.",
    "3. vendor_advisories_for_cve: the vendor advisories that name it. Call get_vendor_advisory for one whose remediation you need in full.",
    "4. epss_history: how its EPSS score changed, one point per recorded change (series_kind change_only): before series_starts_at a missing point means not recorded, not unchanged.",
    "5. cve_exposure: internet exposure on record. exposure_state says what the count is; exposed_hosts counts distinct ip:port services, not machines; the result is not_assessed with measured_at null, so present any count as undated and on record, and exposure_state not_assessed as not assessed.",
    `6. If get_cve says kev_listed is true: kev_recent with since and until both set to the date part (YYYY-MM-DD) of its kev_added_date (for 2024-04-12T00:00:00Z, 2024-04-12), to read kev_due_date from the row for ${cve}.`,
    ENVELOPE_RULES,
    "Then answer with this template, one line each, naming the tool and the measured_at behind every line:",
    "- Exploited? CISA-KEV listing and its date, known ransomware use, and public exploit code on record.",
    "- Likelihood: EPSS score and percentile, and how it has moved.",
    "- Reachable? exposure_state and the count on record, or not assessed.",
    '- Patch: fixed versions and vendor advisories; where the results hold none, write "none on record", which is not a finding that no fix exists.',
    "- Deadline: kev_due_date when the CVE is KEV-listed (CISA's due date for US federal civilian agencies); otherwise write that the results give no CISA deadline.",
    "- Decision: patch now, schedule, or monitor, with a one-line reason drawn from the lines above.",
  ].join("\n");
}

export function kevWeeklyBriefText(days: number): string {
  return [
    `Write a brief of the CVEs CISA added to its Known Exploited Vulnerabilities (KEV) catalog in the last ${days} days, using the EchelonGraph MCP tools.`,
    `1. Compute since: today's date in UTC minus ${days} days, as YYYY-MM-DD. State the since date you used, and today's date.`,
    "2. Call kev_recent with since set to that date and limit 200. While its coverage.has_more is true, call kev_recent again with the same since and cursor set to the previous answer's next_cursor.",
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

export function sbomReviewText(sbom: string): string {
  return [
    "Review the SBOM below for known vulnerabilities, using the EchelonGraph MCP tools.",
    `1. Call check_sbom with sbom set to the document below, as given. It reads the document's purls and checks up to ${MAX_PURLS} distinct purls per call, sending them in batches of ${MAX_COMPONENTS}; a document with more is refused, not truncated. If it is refused, say why from the result and do not guess at the components. If coverage.not_sent is above 0, the API's rate limit or the call's time budget stopped it early: say how many purls were not sent and coverage.not_sent_reason, list them as not checked (never as clean), and call check_sbom again with purls set to data.not_sent_purls once, after a minute, merging what it returns.`,
    "2. For each distinct cve_id on a component whose verdict is affected, call get_cve, to read kev_listed, epss_score, score_assessed, echelongraph_score and cvss_v3_score. If there are more than 30 distinct CVEs, do this for 30 of them and list the rest as not looked up, unranked.",
    ENVELOPE_RULES,
    "Read each component's verdict: not_affected is the one clean verdict; undetermined and not_assessed are not clean, and not_assessed_reason says why (for example distro_release_unknown: a deb, apk or rpm purl without a distro qualifier, which EchelonGraph does not guess).",
    "Then write a prioritised fix list of the affected components. State the ordering keys, in this order: 1. CISA-KEV listed (kev_listed true) first; 2. then EPSS score, highest first; 3. then echelongraph_score where score_assessed is true, else cvss_v3_score, highest first. A CVE with no value for a key sorts after those with one, and its line says which key was missing.",
    "For each line give the component (purl), its cve_ids, the key values used, and fixed versions where a result gives them. After the list, give data.summary's counts, and list the undetermined and not_assessed components with their reasons as not checked, never as clean.",
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
        "Triage one CVE: get_cve, cve_intel, vendor_advisories_for_cve, epss_history and cve_exposure (and kev_recent for the due date when the CVE is KEV-listed), then a decision template: exploited, likelihood, reachable, patch, deadline. Each line cites its tool and measured_at, and not_assessed is never reported as clean.",
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
      description: `Review an SBOM (CycloneDX JSON or SPDX JSON text, up to ${MAX_SBOM_CHARS} characters): it is passed to check_sbom, which checks up to ${MAX_PURLS} distinct purls per call in batches of ${MAX_COMPONENTS}, then get_cve for each affected CVE, and a prioritised fix list ordered by CISA-KEV listing, then EPSS, then score, each key stated. undetermined and not_assessed components are listed as not checked, never as clean.`,
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
