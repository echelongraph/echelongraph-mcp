// cve_remediation (#2841): how one CVE is fixed, as its sources state it, from GET
// /api/v1/public/cves/:id/remediation (core-backend cve/remediation.go). Nothing here is
// generated: every text and URL is relayed as the API sends it, and the API's own texts are its
// sources' (CISA's KEV catalog, the OSV ranges #2817 loads, the vendors' advisories #2840 parses,
// the CVE record's references as NVD tagged them).
//
// What the answer holds:
//   cisa                 CISA KEV's required_action, due_date, short_description and notes_urls
//                        for a KEV-listed CVE. CISA directs the action at US federal civilian
//                        agencies (under BOD 26-04, which replaced BOD 22-01 on
//                        10 June 2026); it is not EchelonGraph's advice.
//   fixed_branches       each affected package with every affected range and its fix.
//   vendor_remediations  each vendor advisory naming the CVE (at most 20, newest first), with its
//                        remediation_state and the items it lists for the CVE, each with the
//                        vendor's own category (kind): vendor_fix, workaround, mitigation,
//                        no_fix_planned, none_available or other.
//   fix_references       the record's references tagged Patch or Mitigation, by NVD, or patch or
//                        mitigation, by the CNA (#2841: the API matches the tag in either case).
//   patches              cve_patches rows.
//   coverage             parsed_vendors, vendors_not_parsed and the caps.
//   failed_sections      the sections the API could not read.
//
// The rules the note keeps: not_parsed is not "no remediation"; none_in_source is what the
// advisory lists, not a finding that no fix exists; an empty section is "none on record", never
// "no fix"; a failed section is named, never relayed as empty. A REJECTED CVE is not_assessed.
//
// fix_status (#2841, #2518 item 3) is the API's fix-status rule (core-backend cve/fixstatus.go,
// the rule /pulse pages render), relayed: this file derives nothing from it.
//
// The installed version (#2841): ecosystem, package and version, all three or none. They travel
// in the X-EG-Ecosystem, X-EG-Package and X-EG-Version request headers, percent-encoded as
// check_affected sends them, and never in the URL (#1983: Cloud Run's request log records the URL
// and no request header). The API answers installed (what was asked and its verdict) and fixed_in,
// the first version above it that no affected range on record holds (the fixed bound of the range
// holding it, moved past any overlapping range, with fixed_in_detail naming it, #3074), or null
// with fixed_in_reason, from the registry matcher check_affected's registry path runs; that answer
// is private, no-store.
import * as z from "zod";
import type { McpServer } from "@modelcontextprotocol/server";
import { ANNOTATIONS, CVE_ID, SHOWN_BASE, api, badInput, checked, crashed, envelopeSchema, failed, failure, field, NOT_A_FINDING, okHead, opt, strAt, succeeded, type ToolResult } from "../index.js";
import { answering, FULL_ARG, TEXT_BUDGET_DESCRIPTION, type DataCut, type RowKeep, type TextCut } from "../textBudget.js";
import { fixStatusSchema } from "../fixStatus.js";
import { MATCH_HEADERS } from "./check_affected.js";

const TOOL = "cve_remediation";
const SECTIONS = ["cisa", "fixed_branches", "vendor_remediations", "fix_references", "patches"] as const;
const KINDS = ["vendor_fix", "workaround", "mitigation", "no_fix_planned", "none_available", "other"] as const;
const STATES = ["parsed", "none_in_source", "not_parsed", "withdrawn"] as const;
// core-backend cve/pkgmatch_fixedin.go InstalledFix's verdicts.
const VERDICTS = ["affected", "not_affected", "undetermined", "not_assessed"] as const;
// The installed version's arguments, in the order the headers are named.
const INSTALLED = ["ecosystem", "package", "version"] as const;

// Required in the description's head (src/requiredText.ts REQUIRED_IN_HEAD.cve_remediation).
export const REMEDIATION_UNTESTED = "Every text is relayed as stated by its source; EchelonGraph has not tested it.";
export const REMEDIATION_NOT_A_ZERO =
  "An empty list or a remediation_state of none_in_source or not_parsed is not a finding that no fix exists.";
export const REMEDIATION_CISA = "CISA's required_action is directed at US federal civilian agencies (under BOD 26-04, which replaced BOD 22-01 on 10 June 2026) and is not EchelonGraph's advice.";

const METHOD =
  "EchelonGraph's stored sources for one CVE (GET /api/v1/public/cves/:id/remediation): CISA's Known Exploited Vulnerabilities catalog text; the affected ranges and fixes of OSV advisories; the remediation each vendor advisory lists, categorised by the vendor's own category (Red Hat CSAF remediations, MSRC CVRF Workaround, Mitigation and Vendor Fix rows, Palo Alto's solution and work_around sections); the CVE record's references tagged Patch or Mitigation by NVD, or patch or mitigation by the CNA; and cve_patches. Nothing is generated or tested.";

// #3084 (merged from 24dad5eb): REMEDIATION_CISA names BOD 26-04, which replaced BOD 22-01, 48 characters
// longer, which left this description 71 under the 2048-character cut (#2924's floor is 100); the
// remediation_state parentheses and the failed_sections sentence are said shorter, every claim kept.
export const CVE_REMEDIATION_DESCRIPTION = `How one CVE is fixed, as its sources state it, in one answer. ${REMEDIATION_UNTESTED} ${REMEDIATION_NOT_A_ZERO} Returns fix_status (the API's fix-status rule, as CVE Pulse shows it: state and basis), cisa (for a KEV-listed CVE CISA's required_action, due_date, short_description and notes_urls, verbatim; ${REMEDIATION_CISA}), fixed_branches (each affected package with fixed_branches: every affected range, introduced and fixed or last_affected, and fixed_version, one range's fix), vendor_remediations (each vendor advisory naming the CVE, newest first, at most 20, with remediation_state, remediation_kinds and items, each with kind, source_category, text and url), fix_references (references NVD or the CNA tagged Patch or Mitigation), patches, coverage and failed_sections. kind is the vendor's own category, never read from the text: vendor_fix, workaround, mitigation, no_fix_planned, none_available or other. remediation_state is parsed, none_in_source (none listed for this CVE), not_parsed (that vendor's remediation is not read) or withdrawn. ecosystem, package and version (all three or none, sent in request headers, never in the URL) add installed, the verdict at that version, and fixed_in, the lowest unaffected version above it, or null with fixed_in_reason. A section the API could not read is named in failed_sections, not relayed as empty. A REJECTED CVE answers not_assessed. ${TEXT_BUDGET_DESCRIPTION} Cut, vendor texts are shortened first; kinds, states and URLs are kept.`;

// ── outputSchema ──
// Built on first use: index.ts imports this file, so its exports are not initialised while this
// module's top level runs.
function schemas() {
  const Kind = z.union([z.enum(KINDS), z.string()]);
  const State = z.union([z.enum(STATES), z.string()]);
  const Item = z.looseObject({
    kind: opt(Kind).describe("The vendor's own category: vendor_fix, workaround, mitigation, no_fix_planned, none_available or other."),
    source_category: opt(z.string()).describe("The vendor's own name for the category (CSAF vendor_fix, MSRC Vendor Fix, Palo Alto work_around)."),
    source_subcategory: opt(z.string()).describe("MSRC's SubType, e.g. Security Update; null elsewhere."),
    text: opt(z.string()).describe("The vendor's text, verbatim but for HTML markup removed, cut at coverage.item_text_cap characters (text_truncated)."),
    text_truncated: opt(z.boolean()),
    text_chars: opt(z.number()).describe("The length of the vendor's text in characters."),
    url: opt(z.string()),
    fixed_build: opt(z.string()).describe("MSRC's FixedBuild; null elsewhere."),
    product_ids: opt(z.array(z.string())).describe("The vendor's own product identifiers the item applies to, the first 16."),
    product_count: opt(z.number()),
  });
  const VendorAdvisory = z.looseObject({
    vendor: opt(z.string()),
    vendor_display_name: opt(z.string()),
    vendor_advisory_id: opt(z.string()),
    vendor_published_at: opt(z.string()),
    withdrawn: opt(z.boolean()),
    remediation_state: opt(State).describe(
      "parsed; none_in_source (parsed, and the advisory lists no remediation for this CVE, which is not a finding that no fix exists); not_parsed (EchelonGraph does not read this vendor's remediation, or has not yet read this advisory); withdrawn (the vendor rescinded it).",
    ),
    remediation_kinds: opt(z.array(Kind)),
    items: opt(z.array(Item)),
    items_total: opt(z.number()),
  });
  const data = z.looseObject({
    cve_id: opt(z.string()),
    state: opt(z.string()).describe("assessed, or not_assessed for a CVE record rejected by its numbering authority."),
    not_assessed_reason: opt(z.string()),
    fix_status: fixStatusSchema(),
    installed: opt(
      z.looseObject({
        ecosystem: opt(z.string()).describe("The ecosystem asked for, in its canonical OSV spelling."),
        ecosystem_recognised: opt(z.boolean()),
        package: opt(z.string()),
        version: opt(z.string()),
        verdict: opt(z.union([z.enum(VERDICTS), z.string()])).describe(
          "affected (a range on record holds the version), not_affected (no range on record holds it), undetermined (a range could not be decided at it) or not_assessed (the record names no such package for this CVE, or the lookup did not run).",
        ),
        version_evidence: opt(z.string()),
        interval: opt(z.looseObject({ introduced: opt(z.string()), fixed: opt(z.string()), last_affected: opt(z.string()) })).describe(
          "The affected range holding the version (fixed is exclusive, last_affected inclusive); absent when none holds it.",
        ),
      }),
    ).describe("The installed version asked for, as the API read it from the request headers, and its verdict against this CVE; absent when none was asked."),
    fixed_in: opt(z.string()).describe(
      "With an installed version: the first version above it that no affected range on record holds, always above it, as the advisory states it: the fixed bound of the range holding it, moved past any overlapping range that still holds that bound (fixed_in_detail then names it). null when no range on record holds it, no fix is on record past the ranges holding it, or the version was not assessed, with fixed_in_reason saying which. Absent when no installed version was asked.",
    ),
    fixed_in_reason: opt(z.string()).describe("Why fixed_in is null; absent when fixed_in is a version."),
    fixed_in_detail: opt(z.string()).describe(
      "Set when fixed_in is not the fixed bound of the range holding the installed version: the overlapping ranges of the same record it moved past, which still hold that bound.",
    ),
    cisa: z
      .looseObject({
        kev_listed: opt(z.boolean()),
        required_action: opt(z.string()).describe(`CISA's requiredAction, verbatim. ${REMEDIATION_CISA}`),
        due_date: opt(z.string()),
        short_description: opt(z.string()),
        notes_urls: opt(z.array(z.string())),
      })
      .nullable()
      .optional(),
    fixed_branches: opt(
      z.array(
        z.looseObject({
          ecosystem: opt(z.string()),
          package_name: opt(z.string()),
          fixed_version: opt(z.string()).describe("One range's fix, kept for compatibility; not the fix for every affected range."),
          fixed_branches: opt(
            z.array(
              z.looseObject({
                introduced: opt(z.string()),
                fixed: opt(z.string()),
                last_affected: opt(z.string()).describe("The range's last affected version, where no fix is on record; never a fix."),
                advisory_id: opt(z.string()),
                source: opt(z.string()),
              }),
            ),
          ),
          fixed_branches_truncated: z
            .object({ total: z.number().int(), returned: z.number().int() })
            .optional()
            .describe(
              "Present only where the structured result's cut (DATA CUT) kept this package's first ranges, not all: total, its ranges in the answer; returned, the ones data keeps. The same call with full: true returns every range.",
            ),
        }),
      ),
    ),
    vendor_remediations: opt(z.array(VendorAdvisory)),
    fix_references: opt(z.array(z.looseObject({ url: opt(z.string()), tags: opt(z.array(z.string())), source: opt(z.string()) }))),
    patches: opt(z.array(z.unknown())),
    coverage: z.unknown().optional(),
    failed_sections: opt(z.array(z.string())),
  });
  const coverage = z.strictObject({
    sections_relayed: z.array(z.string()),
    sections_failed: z.array(z.string()).nullable().describe("The sections the API could not read (its failed_sections); null when the answer does not say."),
    parsed_vendors: z.array(z.string()).nullable().describe("The vendors whose remediation EchelonGraph parses."),
    vendors_not_parsed: z.array(z.string()).nullable().describe("The vendors in this answer whose remediation EchelonGraph does not parse."),
    vendor_advisory_limit: z.number().nullable(),
    item_text_cap: z.number().nullable(),
    items_per_advisory_cap: z.number().nullable(),
    installed_asked: z
      .strictObject({ ecosystem: z.string(), package: z.string(), version: z.string() })
      .nullable()
      .describe("The installed version this call sent (in request headers), as given; null when none."),
  });
  return { output: envelopeSchema({ data, coverage, freshness: null }) };
}
let built: ReturnType<typeof schemas> | undefined;
const schemasOnce = () => (built ??= schemas());

// The text cut: vendor texts go first, the kinds, states and URLs stay.
const CUT: TextCut = {
  rows: "vendor_remediations",
  levels: [
    { keep: ["vendor", "vendor_advisory_id", "withdrawn", "remediation_state", "remediation_kinds", "items_total", ["items", ["kind", "source_category", "text", "url", "fixed_build"]]], clip: 400, cap: 16 },
    { keep: ["vendor", "vendor_advisory_id", "remediation_state", "remediation_kinds", ["items", ["kind", "url"]]], clip: 2048, cap: 8 },
  ],
  whole:
    "get_vendor_advisory returns any one of these advisories by its vendor and vendor_advisory_id, whole in its structuredContent.data with full: true, with every remediation item it lists.",
};
// #3013: the structured result's cut. CVE-2021-44228's answer is 75,963 characters of structured
// result, 61,248 of them its 20 vendor_remediations, whose items carry the vendor's text (about 550
// characters an item, the payload) and its product_ids (about 550, the vendor's own identifiers).
// Before any advisory leaves, every advisory's items are thinned: product_ids first, keeping each
// text; then the texts, keeping each item's kind, source_category, url and fixed_build, so every
// advisory stays named with its state, kinds and links (get_vendor_advisory returns one whole).
// fix_status and fixed_in (#2841) are not lists, and installed is an object, so none of them is
// ever cut.
//
// #3139: through 3.0.0 advisories then left from the end, before patches, and fixed_branches had no
// step, so CVE-2023-44487 (KEV-listed) kept 2 of its 20 advisories at 29,704 characters while
// fixed_branches (13,581 characters, 50 rows) and patches (7,471, 30) stayed whole, and the note
// named no tool that lists the other 18 (measured on hosted 3.0.0, 2026-10-11; also CVE-2018-12126
// 6/20, CVE-2019-11135 2/3, CVE-2018-3639 16/20). Now vendor_remediations is a keepAll step: every
// advisory stays, thinned, while patches (each to its vendor, patch_url and published_at: the
// erratum, which vendor_remediations names again for Red Hat) and then fixed_branches (each to its
// package, range, fixed_version and its ranges' introduced, fixed and last_affected, what the
// sbom_review prompt walks; the per-range source, advisory_id and dependents_count go) are thinned
// and then lose rows from the end, and then any other list at the top of data (fix_references).
// Only when all of that is cut and the result is still past the budget do advisories leave, from
// the end; whenever one does, the note names vendor_advisories_for_cve, which lists every vendor
// advisory naming the CVE, as where the rest are.
// #3139's review: that order dropped 2 of CVE-2023-44487's 30 patches while its 50 fixed_branches
// rows stayed whole (13,581 characters). Decided (2026-10-11): fixed_branches is thinned before any
// patch row leaves. The order is now:
//   1. vendor_remediations thinned, as above, every advisory kept (keepAll);
//   2. fixed_branches thinned (each package to its ecosystem, package_name, version_range,
//      fixed_version and its ranges' introduced, fixed and last_affected: each range's source and
//      advisory_id go, and the package's dependents_count and source), then each package's ranges
//      capped at one number, the most that fit (at least 1), a package with more carrying
//      fixed_branches_truncated with its total and returned; every package kept (keepAll);
//   3. patches thinned (vendor, patch_url and published_at), every patch kept (keepAll);
//   4. any other list at the top of data (fix_references), cut from the end;
//   5. then patch rows leave from the end, then fixed_branches rows, and only then advisories
//      (textBudget.ts: the last keepAll step's entries leave first);
//   6. the room left goes back to each package's ranges, in the order of fixed_branches (giveBack):
//      step 2 caps them before the patches are cut, and a cap that held while every patch was
//      whole would otherwise stay after the patches are thinned.
// Round 2 replayed CVE-2023-44487 at 28 of 30 patches: fix_references (2,191 characters) were cut
// after patch rows left, and the 30 thinned were about 240 characters past the budget beside them.
// Round 3 (#3139's second review, 2026-10-11): patches is a keepAll step, so fix_references are cut
// first and CVE-2023-44487 keeps all 20 advisories, all 50 fixed_branches and all 30 patches, each
// thinned (test/cve_remediation.test.mjs); round 1 (patches cut before fixed_branches was thinned)
// kept 11 patches without fix_references.
//
// #3013's review: the second level leaves every item's text out of data, and the text is the
// vendor's step itself (a workaround's or mitigation's wording), which the triage_cve and
// sbom_review prompts have the model quote. No string is shortened (the cut's rule), so the note
// says the text is gone and where each one is: get_vendor_advisory, by the advisory's vendor and
// vendor_advisory_id, returns that advisory's remediations with their texts, and the same call
// with full: true returns this data whole; the prompts send the model there when it is cut.
const ADVISORY_FIELDS = ["vendor", "vendor_display_name", "vendor_advisory_id", "vendor_published_at", "withdrawn", "remediation_state", "remediation_kinds", "items_total"] as const;
const ITEM_TEXT_ELSEWHERE =
  "No item in data keeps its text, the vendor's own wording of the step (a workaround or mitigation among them): get_vendor_advisory, given an advisory's vendor and its vendor_advisory_id as advisory_id, returns it among that advisory's remediations, whole in its structuredContent.data with full: true.";
const FIXED_BRANCHES_THIN: RowKeep = ["ecosystem", "package_name", "version_range", "fixed_version", ["fixed_branches", ["introduced", "fixed", "last_affected"]]];
const CVE_REMEDIATION_DATA: DataCut = {
  steps: [
    {
      lists: ["vendor_remediations"],
      thin: [
        [...ADVISORY_FIELDS, ["items", ["kind", "source_category", "source_subcategory", "text", "text_truncated", "text_chars", "url", "fixed_build", "product_count"]]],
        [...ADVISORY_FIELDS, ["items", ["kind", "source_category", "url", "fixed_build"]]],
      ],
      keepAll: true,
    },
    {
      lists: ["fixed_branches"],
      thin: [
        FIXED_BRANCHES_THIN,
        {
          keep: FIXED_BRANCHES_THIN,
          capped: "fixed_branches",
          least: 1,
          mark: (row, cap) => {
            const n = Array.isArray(row.fixed_branches) ? row.fixed_branches.length : 0;
            return n > cap ? { fixed_branches_truncated: { total: n, returned: cap } } : {};
          },
          said: (cap) => `each package's fixed_branches keeping at most its first ${cap} ranges, a package with more carrying fixed_branches_truncated with its total and returned`,
        },
      ],
      keepAll: true,
      giveBack: true,
    },
    // #3139 round 3: every patch row stays, thinned (keepAll), while the step after it (any other
    // list at the top of data: fix_references) is cut; patch rows leave only after that, and
    // before any fixed_branches row or advisory (the last keepAll step's entries leave first).
    { lists: ["patches"], thin: [["vendor", "patch_url", "published_at"]], keepAll: true },
  ],
  // Said where the advisories kept are thinned to a level whose items keep no text, and (#3139)
  // wherever an advisory is left out.
  page: (t, _d, at) => {
    const items = at.keeps.vendor_remediations?.find((x): x is readonly [string, readonly string[]] => typeof x !== "string" && x[0] === "items");
    const v = t.vendor_remediations;
    return [items && !items[1].includes("text") ? ITEM_TEXT_ELSEWHERE : "", v && v.returned < v.total ? advisoriesElsewhere(v.total - v.returned) : ""].filter(Boolean).join(" ");
  },
};
// #3139: where the advisories a cut leaves out are read. vendor_advisories_for_cve lists every one
// naming the CVE, with its vendor and vendor_advisory_id (CVE-2023-44487's 20 at 15,505
// characters on hosted 3.0.0), and get_vendor_advisory then returns any one whole.
const advisoriesElsewhere = (n: number): string =>
  `vendor_advisories_for_cve, given this CVE, lists every vendor advisory naming it, the ${n} left out of data among them, each with its vendor and vendor_advisory_id.`;

const listed = (xs: readonly string[]): string => (xs.length <= 1 ? (xs[0] ?? "") : `${xs.slice(0, -1).join(", ")} and ${xs.at(-1)}`);
const arr = (v: unknown): unknown[] | null => (Array.isArray(v) ? v : null);
const strs = (v: unknown): string[] | null => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : null);

function vendorSentences(cve: string, rows: unknown[]): string[] {
  if (rows.length === 0) {
    return [`No vendor advisory on record names ${cve}, which is not a finding that no vendor published a fix.`];
  }
  const out: string[] = [];
  const byKind = new Map<string, string[]>();
  const states: Record<string, string[]> = {};
  for (const r of rows) {
    const who = `${strAt(r, "vendor") ?? "?"} ${strAt(r, "vendor_advisory_id") ?? "?"}`;
    const st = strAt(r, "remediation_state") ?? "unknown";
    (states[st] ??= []).push(who);
    for (const k of strs(field(r, "remediation_kinds")) ?? []) {
      if (!byKind.has(k)) byKind.set(k, []);
      byKind.get(k)!.push(who);
    }
  }
  const few = (xs: string[]) => (xs.length <= 4 ? listed(xs) : `${xs.slice(0, 4).join(", ")} and ${xs.length - 4} more`);
  const kinds = [...KINDS.filter((k) => byKind.has(k)), ...[...byKind.keys()].filter((k) => !(KINDS as readonly string[]).includes(k))];
  if (kinds.length) {
    out.push(`Vendor remediation for ${cve}, by the vendor's own category: ${kinds.map((k) => `${k} from ${few(byKind.get(k)!)}`).join("; ")}. Each is the vendor's text as stated; EchelonGraph has not tested it.`);
  }
  if (states.none_in_source) out.push(`${few(states.none_in_source)} ${states.none_in_source.length === 1 ? "lists" : "list"} no remediation for ${cve} (none_in_source), which is not a finding that no fix exists.`);
  if (states.not_parsed) out.push(`EchelonGraph does not read the remediation of ${few(states.not_parsed)} (not_parsed): read ${states.not_parsed.length === 1 ? "it" : "each"} with get_vendor_advisory; not_parsed is not "no remediation".`);
  if (states.withdrawn) out.push(`${few(states.withdrawn)} ${states.withdrawn.length === 1 ? "was" : "were"} withdrawn by ${states.withdrawn.length === 1 ? "its" : "their"} vendor: ${states.withdrawn.length === 1 ? "its" : "their"} remediation is not relayed.`);
  return out;
}

function branchSentence(rows: unknown[]): string {
  if (rows.length === 0) return "fixed_branches is empty: no affected package range is on record, which is not a finding that no fix exists.";
  let ranges = 0;
  let fixed = 0;
  for (const r of rows) {
    for (const b of arr(field(r, "fixed_branches")) ?? []) {
      ranges++;
      if (strAt(b, "fixed")) fixed++;
    }
  }
  return `fixed_branches lists ${rows.length} affected package${rows.length === 1 ? "" : "s"} with ${ranges} affected range${ranges === 1 ? "" : "s"}, ${fixed} with a fix on record; an installed version's fix is the first fixed above it that no range of its package holds (the fixed of the range that holds it, or, while another range still holds that version, that range's fixed), compared in the ecosystem's version order.`;
}

// fix_status's sentence: what the API's rule says, relayed. Nothing about the fix is inferred here.
function fixStatusSentence(cve: string, fs: unknown): string | null {
  if (fs === null || fs === undefined) return null;
  const state = strAt(fs, "state");
  if (!state) return null;
  const basis = strAt(fs, "basis");
  const unread = Array.isArray(field(fs, "unread_inputs")) ? (field(fs, "unread_inputs") as unknown[]).filter((x): x is string => typeof x === "string") : [];
  const why = state === "none_confirmed" ? ", which is not a finding that no fix exists" : "";
  const notRead = unread.length ? `; it rests without ${listed(unread)}, which the API could not read (unread_inputs)` : "";
  // #3076, third pass: what vendor_fix_released evidence is, so "available" is not read as more
  // than it says. Relayed from the field the API set, nothing inferred.
  const released = field(fs, "vendor_released");
  const qualifier =
    released !== null && released !== undefined && typeof released === "object"
      ? `; the vendor states a fix is released, but the CVE record names no fixed version (vendor_released), so the fixed release is the vendor advisory's to name`
      : "";
  return `fix_status for ${cve} is ${state}${basis ? ` (basis ${basis})` : ""}, the API's fix-status rule${why}${qualifier}${notRead}.`;
}

// The sentence on the installed version asked: what the API answered for it, relayed.
function installedSentence(asked: { ecosystem: string; package: string; version: string }, d: object): string {
  const who = `${asked.ecosystem} ${asked.package} ${asked.version}`;
  if (!("fixed_in" in d)) {
    return `The answer carries no fixed_in for the installed version asked (${who}): the API did not assess it, which is not a finding either way.`;
  }
  const inst = field(d, "installed");
  const verdict = strAt(inst, "verdict");
  const fixedIn = strAt(d, "fixed_in");
  if (fixedIn) {
    // #3074: fixed_in moved past an overlapping range, so it is not the holding range's bound.
    const detail = strAt(d, "fixed_in_detail");
    if (detail) {
      return `For the installed version asked (${who}), installed.verdict is ${verdict ?? "not given"} and fixed_in is ${fixedIn}: the first version above it that no affected range on record holds (${detail}), as the advisory states it; EchelonGraph has not tested it.`;
    }
    const lo = strAt(field(inst, "interval"), "introduced");
    const range = lo ? ` [${lo}, ${fixedIn})` : "";
    return `For the installed version asked (${who}), installed.verdict is ${verdict ?? "not given"} and fixed_in is ${fixedIn}: the fixed bound of the affected range${range} that holds it, as the advisory states it; EchelonGraph has not tested it.`;
  }
  const reason = strAt(d, "fixed_in_reason") ?? "the answer gives no fixed_in_reason";
  return `For the installed version asked (${who}), installed.verdict is ${verdict ?? "not given"} and fixed_in is null: ${reason}.`;
}

export type CveRemediationArgs = { cve_id: string; ecosystem?: string; package?: string; version?: string };

export async function cveRemediation(args: CveRemediationArgs): Promise<ToolResult> {
  const id = (args.cve_id ?? "").trim();
  if (!id) return badInput(TOOL, "cve_id is required");
  if (!CVE_ID.test(id)) return badInput(TOOL, `cve_id ${JSON.stringify(id.slice(0, 32))} is not a CVE id (expected the form CVE-2021-44228)`);
  // The installed version: all three or none.
  const given = { ecosystem: (args.ecosystem ?? "").trim(), package: (args.package ?? "").trim(), version: (args.version ?? "").trim() };
  const present = INSTALLED.filter((k) => given[k] !== "");
  const missing = INSTALLED.filter((k) => given[k] === "");
  if (present.length > 0 && missing.length > 0) {
    return badInput(TOOL, `ecosystem, package and version go together, all three or none: ${listed([...missing])} ${missing.length === 1 ? "is" : "are"} missing (given: ${listed([...present])})`);
  }
  const asked = present.length === INSTALLED.length ? given : null;
  const cve = id.toUpperCase();
  const path = `/api/v1/public/cves/${encodeURIComponent(cve)}/remediation`;
  // #1983: percent-encoded, as the backend's matchHeaderValue decodes them; never in the URL.
  const enc = encodeURIComponent;
  const headers = asked ? { [MATCH_HEADERS.ecosystem]: enc(asked.ecosystem), [MATCH_HEADERS.package]: enc(asked.package), [MATCH_HEADERS.version]: enc(asked.version) } : undefined;
  try {
    const r = await api(path, headers ? { headers } : undefined);
    if (!r.ok) return failed(TOOL, r);
    const d = r.data;
    const state = strAt(d, "state");
    if (state !== "assessed" && state !== "not_assessed") {
      const why = "the answer carries no state (assessed or not_assessed)";
      return failure("failed", `${TOOL} FAILED: EchelonGraph answered HTTP ${r.status} from ${SHOWN_BASE} for GET ${path}, but ${why}. ${NOT_A_FINDING}`, {
        kind: "unexpected_shape",
        path,
        status: r.status,
        message: why,
      });
    }
    const reported = strs(field(d, "failed_sections"));
    const cov = field(d, "coverage");
    const coverage = {
      sections_relayed: SECTIONS.filter((k) => field(d, k) !== undefined && !(reported ?? []).includes(k)),
      sections_failed: reported,
      parsed_vendors: strs(field(cov, "parsed_vendors")),
      vendors_not_parsed: strs(field(cov, "vendors_not_parsed")),
      vendor_advisory_limit: typeof field(cov, "vendor_advisory_limit") === "number" ? (field(cov, "vendor_advisory_limit") as number) : null,
      item_text_cap: typeof field(cov, "item_text_cap") === "number" ? (field(cov, "item_text_cap") as number) : null,
      items_per_advisory_cap: typeof field(cov, "items_per_advisory_cap") === "number" ? (field(cov, "items_per_advisory_cap") as number) : null,
      installed_asked: asked,
    };
    const head = okHead(TOOL, r.status);
    if (state === "not_assessed") {
      const reason = strAt(d, "not_assessed_reason") ?? "the API gives no reason";
      const inst = asked ? ` ${installedSentence(asked, d)}` : "";
      return succeeded(d, `${head} NOT ASSESSED: ${cve}'s remediation is not assessed (${reason}). A rejected CVE record is not an active vulnerability, so no fix is relayed for it.${inst}`, {
        state: "not_assessed",
        measured_at: null,
        method: METHOD,
        coverage,
        freshness: null,
        notes: ["measured_at is null: the answer dates no observation.", "freshness is null: the answer carries no poll-completion time."],
      });
    }

    const said: string[] = [];
    const fixSaid = fixStatusSentence(cve, field(d, "fix_status"));
    if (fixSaid) said.push(fixSaid);
    if (asked) said.push(installedSentence(asked, d));
    const cisa = field(d, "cisa");
    const action = strAt(cisa, "required_action");
    if (field(cisa, "kev_listed") === true) {
      said.push(
        action
          ? `${cve} is in CISA's KEV catalog; cisa.required_action is CISA's text, verbatim${strAt(cisa, "due_date") ? `, due ${strAt(cisa, "due_date")}` : ""}: ${REMEDIATION_CISA}`
          : `${cve} is in CISA's KEV catalog, and no required_action is on record for it.`,
      );
    }
    const pkgs = arr(field(d, "fixed_branches"));
    if (pkgs && !(reported ?? []).includes("fixed_branches")) said.push(branchSentence(pkgs));
    const vendors = arr(field(d, "vendor_remediations"));
    if (vendors && !(reported ?? []).includes("vendor_remediations")) said.push(...vendorSentences(cve, vendors));
    const refs = arr(field(d, "fix_references"));
    // #2841: the API keeps both spellings, NVD's (Patch, Mitigation) and a CNA's (patch, mitigation).
    if (refs) {
      said.push(
        refs.length
          ? `fix_references lists ${refs.length} reference${refs.length === 1 ? "" : "s"} the CVE record tags as a patch or mitigation (NVD's Patch or Mitigation, or the CNA's patch or mitigation), each with the tags as written.`
          : "No reference of the CVE record is tagged as a patch or mitigation, in NVD's spelling (Patch, Mitigation) or the CNA's (patch, mitigation).",
      );
    }
    if (reported === null) said.push("The answer carries no failed_sections, so an empty section may be one the API could not read, not a finding of none.");
    else if (reported.length) said.push(`The API could not read ${listed(reported)} (failed_sections): an empty value there is not a finding of none.`);
    said.push(REMEDIATION_UNTESTED);

    return succeeded(
      d,
      `${head} ${said.join(" ")}`,
      {
        state: "measured",
        measured_at: null,
        method: METHOD,
        coverage,
        freshness: null,
        notes: ["measured_at is null: the answer has no single observation time.", "freshness is null: the answer carries no poll-completion time."],
      },
      CUT,
    );
  } catch (e) {
    return crashed(TOOL, e);
  }
}

export function registerCveRemediation(server: McpServer): void {
  const { output } = schemasOnce();
  server.registerTool(
    TOOL,
    {
      title: "How one CVE is fixed",
      description: CVE_REMEDIATION_DESCRIPTION,
      inputSchema: CVE_REMEDIATION_INPUT,
      outputSchema: output,
      annotations: ANNOTATIONS,
    },
    async (args) => checked(TOOL, output, await answering(args.full, CVE_REMEDIATION_DATA, () => cveRemediation(args))),
  );
}

// The installed version is optional and all-or-none (cveRemediation refuses a partial set).
export const CVE_REMEDIATION_INPUT = z.object({
  cve_id: z.string().describe("a CVE ID, e.g. CVE-2021-44228"),
  ecosystem: z.string().optional().describe("Installed version, with package and version: the package's ecosystem, such as npm, PyPI or Maven. Sent in a request header."),
  package: z.string().optional().describe("Installed version, with ecosystem and version: the package name in that ecosystem, such as org.apache.logging.log4j:log4j-core. Sent in a request header."),
  version: z.string().optional().describe("Installed version, with ecosystem and package: the version installed, such as 2.14.1. Sent in a request header."),
  full: FULL_ARG,
});
