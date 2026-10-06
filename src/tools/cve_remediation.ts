// cve_remediation (#2841): how one CVE is fixed, as its sources state it, from GET
// /api/v1/public/cves/:id/remediation (core-backend cve/remediation.go). Nothing here is
// generated: every text and URL is relayed as the API sends it, and the API's own texts are its
// sources' (CISA's KEV catalog, the OSV ranges #2817 loads, the vendors' advisories #2840 parses,
// the CVE record's references as NVD tagged them).
//
// What the answer holds:
//   cisa                 CISA KEV's required_action, due_date, short_description and notes_urls
//                        for a KEV-listed CVE. CISA directs the action at US federal civilian
//                        agencies (BOD 22-01); it is not EchelonGraph's advice.
//   fixed_branches       each affected package with every affected range and its fix.
//   vendor_remediations  each vendor advisory naming the CVE (at most 20, newest first), with its
//                        remediation_state and the items it lists for the CVE, each with the
//                        vendor's own category (kind): vendor_fix, workaround, mitigation,
//                        no_fix_planned, none_available or other.
//   fix_references       the record's references tagged Patch or Mitigation.
//   patches              cve_patches rows.
//   coverage             parsed_vendors, vendors_not_parsed and the caps.
//   failed_sections      the sections the API could not read.
//
// The rules the note keeps: not_parsed is not "no remediation"; none_in_source is what the
// advisory lists, not a finding that no fix exists; an empty section is "none on record", never
// "no fix"; a failed section is named, never relayed as empty. A REJECTED CVE is not_assessed.
import * as z from "zod";
import type { McpServer } from "@modelcontextprotocol/server";
import { ANNOTATIONS, CVE_ID, SHOWN_BASE, api, badInput, checked, crashed, envelopeSchema, failed, failure, field, NOT_A_FINDING, okHead, opt, strAt, succeeded, type ToolResult } from "../index.js";
import { TEXT_BUDGET_DESCRIPTION, type TextCut } from "../textBudget.js";

const TOOL = "cve_remediation";
const SECTIONS = ["cisa", "fixed_branches", "vendor_remediations", "fix_references", "patches"] as const;
const KINDS = ["vendor_fix", "workaround", "mitigation", "no_fix_planned", "none_available", "other"] as const;
const STATES = ["parsed", "none_in_source", "not_parsed", "withdrawn"] as const;

// Required in the description's head (src/requiredText.ts REQUIRED_IN_HEAD.cve_remediation).
export const REMEDIATION_UNTESTED = "Every text is relayed as stated by its source; EchelonGraph has not tested it.";
export const REMEDIATION_NOT_A_ZERO =
  "An empty list or a remediation_state of none_in_source or not_parsed is not a finding that no fix exists.";
export const REMEDIATION_CISA = "CISA's required_action is directed at US federal civilian agencies (BOD 22-01) and is not EchelonGraph's advice.";

const METHOD =
  "EchelonGraph's stored sources for one CVE (GET /api/v1/public/cves/:id/remediation): CISA's Known Exploited Vulnerabilities catalog text; the affected ranges and fixes of OSV advisories; the remediation each vendor advisory lists, categorised by the vendor's own category (Red Hat CSAF remediations, MSRC CVRF Workaround, Mitigation and Vendor Fix rows, Palo Alto's solution and work_around sections); the CVE record's references NVD tagged Patch or Mitigation; and cve_patches. Nothing is generated or tested.";

export const CVE_REMEDIATION_DESCRIPTION = `How one CVE is fixed, as its sources state it, in one answer. ${REMEDIATION_UNTESTED} ${REMEDIATION_NOT_A_ZERO} Returns cisa (kev_listed, and for a KEV-listed CVE CISA's required_action, due_date, short_description and notes_urls, verbatim; ${REMEDIATION_CISA}), fixed_branches (each affected package with fixed_branches: every affected range, introduced and fixed or last_affected, and fixed_version, one range's fix), vendor_remediations (each vendor advisory naming the CVE, newest first, at most 20: vendor, vendor_advisory_id, remediation_state, remediation_kinds and items, each item with kind, source_category, text, url, fixed_build, product_ids and product_count), fix_references (the record's references NVD tagged Patch or Mitigation), patches, coverage (parsed_vendors, vendors_not_parsed and the caps) and failed_sections. kind is the vendor's own category, never read from the text: vendor_fix, workaround, mitigation, no_fix_planned, none_available, or other with the vendor's name for it in source_category. remediation_state is parsed, none_in_source (parsed; the advisory lists none for this CVE), not_parsed (EchelonGraph does not read that vendor's remediation) or withdrawn. A section the API could not read is named in failed_sections and coverage.sections_failed, never relayed as empty. A REJECTED CVE answers not_assessed. Pass a CVE ID like CVE-2021-44228. ${TEXT_BUDGET_DESCRIPTION} Cut, vendor texts are shortened first; kinds, states and URLs are kept.`;

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
    "get_vendor_advisory returns any one of these advisories by its vendor and vendor_advisory_id, whole in its structuredContent.data, with every remediation item it lists.",
};

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
  return `fixed_branches lists ${rows.length} affected package${rows.length === 1 ? "" : "s"} with ${ranges} affected range${ranges === 1 ? "" : "s"}, ${fixed} with a fix on record; an installed version's fix is the fixed of the range that holds it, compared in the ecosystem's version order.`;
}

export async function cveRemediation(cve_id: string): Promise<ToolResult> {
  const id = cve_id.trim();
  if (!id) return badInput(TOOL, "cve_id is required");
  if (!CVE_ID.test(id)) return badInput(TOOL, `cve_id ${JSON.stringify(id.slice(0, 32))} is not a CVE id (expected the form CVE-2021-44228)`);
  const cve = id.toUpperCase();
  const path = `/api/v1/public/cves/${encodeURIComponent(cve)}/remediation`;
  try {
    const r = await api(path);
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
    };
    const head = okHead(TOOL, r.status);
    if (state === "not_assessed") {
      const reason = strAt(d, "not_assessed_reason") ?? "the API gives no reason";
      return succeeded(d, `${head} NOT ASSESSED: ${cve}'s remediation is not assessed (${reason}). A rejected CVE record is not an active vulnerability, so no fix is relayed for it.`, {
        state: "not_assessed",
        measured_at: null,
        method: METHOD,
        coverage,
        freshness: null,
        notes: ["measured_at is null: the answer dates no observation.", "freshness is null: the answer carries no poll-completion time."],
      });
    }

    const said: string[] = [];
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
    if (refs) said.push(refs.length ? `fix_references lists ${refs.length} reference${refs.length === 1 ? "" : "s"} the CVE record tags Patch or Mitigation.` : "No reference of the CVE record is tagged Patch or Mitigation.");
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
      inputSchema: z.object({ cve_id: z.string().describe("a CVE ID, e.g. CVE-2021-44228") }),
      outputSchema: output,
      annotations: ANNOTATIONS,
    },
    async ({ cve_id }) => checked(TOOL, output, await cveRemediation(cve_id)),
  );
}
