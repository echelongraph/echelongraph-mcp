// cve_intel (#2720): what weakness a CVE is, whether public exploit code for it is on record,
// and which packages and versions it affects and fixes — from GET
// /api/v1/public/cves/:id/enrichment (core-backend cve/handler_enrichment.go).
//
// Not /blast-radius: that GET can trigger a live OSV fetch and a database upsert
// (core-backend cve/handler.go GetBlastRadius), and this server makes no request but a read.
//
// The relay is a cut, like exposure_radar's. /enrichment also serves vendor_advisories, patches,
// ai (generated summaries), trending and historical_incidents; this tool relays only the sections
// it can label — cwes, exploits with their counts, affected_packages, fixed_versions and timeline —
// and the note names what it left out. Within those, nothing is rewritten: each relayed section is
// the API's own value, except timeline, cut to its TIMELINE_RELAYED newest rows (the API's are
// newest first) with the cut in coverage.
//
// An empty section is not "none" unless the answer says it was read. /enrichment fills a section
// that failed or ran out of its time budget with its empty value. Since #2720 it names each such
// section in failed_sections; this tool then leaves that section out of data and says so. An
// answer without failed_sections (an API older than #2720) cannot tell an empty section from a
// failed one, and the note says so for each empty section it relays.
//
// Exploit coverage. cve_exploits is filled by a curated seed and by four pollers (Metasploit,
// Exploit-DB, nuclei templates, GitHub PoCs), each behind its own environment flag
// (EXPLOIT_INTEL_ENABLED plus EXPLOIT_METASPLOIT_ENABLED, EXPLOIT_EXPLOITDB_ENABLED,
// EXPLOIT_NUCLEI_ENABLED, EXPLOIT_POCGITHUB_ENABLED; core-backend cmd/server/main.go). The answer
// does not say which ran, so no text here says a source is polled: it names the sources the data
// model holds, and says coverage depends on which pollers run.
//
// Fixed versions (#2817). /enrichment keeps one affected_packages row per (CVE, ecosystem,
// package), and its fixed_version is one range's fix: the last range's as the advisory was read
// (core-backend cve/backfill_osv_packages.go summariseAffected). For CVE-2021-44228 production
// served log4j-core 2.12.2 alone (2026-10-04), the fix for 2.4-2.12.1, below an affected 2.14.1.
// Since #2817 each row also carries fixed_branches, the fix for every range (core-backend
// cve/fixed_branches.go, from the version_intervals the matcher evaluates): this tool relays it as
// sent, its description says how to pick the range for an installed version, and the note counts
// the rows where fixed_version is not the whole answer.
import * as z from "zod";
import type { McpServer } from "@modelcontextprotocol/server";
import {
  ANNOTATIONS,
  CVE_ID,
  NOT_A_FINDING,
  SHOWN_BASE,
  api,
  badInput,
  boolAt,
  checked,
  crashed,
  envelopeSchema,
  failed,
  failure,
  field,
  numAt,
  okHead,
  opt,
  strAt,
  succeeded,
  type ToolResult,
} from "../index.js";
import { TEXT_BUDGET_DESCRIPTION } from "../textBudget.js";

const TOOL = "cve_intel";

// The sections relayed, in the answer's order, and the keys each failed_sections name covers.
const LISTS = ["cwes", "exploits", "affected_packages", "fixed_versions", "timeline"] as const;
type ListName = (typeof LISTS)[number];
const SECTION_KEYS: Record<string, readonly string[]> = {
  cwes: ["cwes"],
  exploits: ["exploits"],
  exploits_total: ["exploits_total", "exploits_capped", "exploits_by_kind", "exploits_by_status"],
  affected_packages: ["affected_packages"],
  fixed_versions: ["fixed_versions"],
  timeline: ["timeline"],
  timeline_stats: ["timeline_total", "timeline_count_7d", "timeline_count_30d"],
};
const RELAYED_KEYS = [
  "cwes",
  "exploits",
  "exploits_total",
  "exploits_capped",
  "exploits_by_kind",
  "exploits_by_status",
  "affected_packages",
  "fixed_versions",
  "timeline",
  "timeline_total",
  "timeline_count_7d",
  "timeline_count_30d",
] as const;
// The /enrichment sections this tool does not relay, named in every note.
const LEFT_OUT = ["vendor_advisories", "patches", "ai", "trending", "historical_incidents"] as const;
// Per-CVE row limits of the API (core-backend cve/enrichment_store.go): a list this long may be cut.
const API_ROW_LIMIT: Partial<Record<ListName, number>> = { exploits: 10, affected_packages: 50, fixed_versions: 200, timeline: 100 };
const TIMELINE_RELAYED = 20;

const CVE_INTEL_METHOD =
  "EchelonGraph's per-CVE enrichment (GET /api/v1/public/cves/:id/enrichment). cwes: CWE classifications stored from NVD, GitHub (GHSA) and CVE.org records, each with the source that gave it, named from the MITRE CWE catalog EchelonGraph embeds. exploits: public exploit references from EchelonGraph's cve_exploits records, whose data model holds Metasploit modules (metasploit), Exploit-DB entries (exploit_db), nuclei templates (nuclei_template), GitHub proof-of-concept repositories (github_poc) and vendor proofs of concept (vendor_poc), filled by a curated seed and by one poller per automated source, each run only where it is enabled, so which sources are current depends on the deployment. affected_packages and fixed_versions: package-ecosystem advisory data, each row naming its source. timeline: EchelonGraph's enrichment history for the CVE, newest first.";

const VERIFIED_STATUS_DESCRIPTION =
  "verified_status is the label stored with each reference: verified for a Metasploit module, for an Exploit-DB entry Exploit-DB marks verified, and for curated seed rows marked so; reported for a public artefact nothing has confirmed works (nuclei templates, GitHub proofs of concept, unverified Exploit-DB entries); unconfirmed where a curated row says so. It is a label from the source, not a guarantee that the exploit works against a given system.";

const FIXED_BRANCHES_DESCRIPTION =
  'fixed_branches lists each affected range of the package on record: introduced, and fixed (the range\'s fix) or last_affected (its last affected version, where no fix is on record), each null when absent, with advisory_id (the OSV record that published the range) and source (the loader\'s label for that record), both null on a row loaded before they were stored. Ranges with an advisory_id are in the order their record lists them (records in id order); ranges without one are oldest first. To pick the range for an installed version, compare in the ecosystem\'s version order (release numbers part by part, as numbers: 2.4 is below 2.13.0): the version is in a range when it is at or above introduced ("0" is the first version) and below fixed, or at or below last_affected; that range\'s fixed is the fix for it, and a version in no range is outside every range on record. fixed_branches is null where the package\'s ranges were never loaded, and [] where no version range is on record (the advisory gives none, only commit ranges, or more than are stored), which is not a finding that no fix exists: fixed_version can still name one. fixed_version is one range\'s fix, kept for compatibility (one per package: the range the loader kept, the advisory\'s last as a rule), not the fix for every affected range: for CVE-2021-44228, its advisory gives log4j-core three ranges, and fixed_version 2.12.2 is the fix for the one from 2.4, while the range holding 2.14.1 (from 2.13.0) is fixed in 2.15.0.';

export const CVE_INTEL_DESCRIPTION = `Weakness, public exploit code, affected packages and fixed versions for one CVE, from EchelonGraph's per-CVE enrichment. Returns cwes (each cwe_id with its name and source), exploits (each with kind, source_name, source_url, first_seen_at and verified_status; at most 10, verified first) with exploits_total (every reference on record), exploits_capped (true when exploits lists fewer than exploits_total), exploits_by_kind and exploits_by_status, affected_packages (ecosystem, package_name, version_range, fixed_version, fixed_branches), fixed_versions (ecosystem, package_name, vulnerable_range, fixed_version: one row per fixed version, with the vulnerable_range it fixes where the source gives one) and timeline (the newest enrichment-history rows, with timeline_total). ${FIXED_BRANCHES_DESCRIPTION} ${VERIFIED_STATUS_DESCRIPTION} An empty exploits list is not evidence that no public exploit exists: it covers only the sources EchelonGraph ingests, and which of them are polled depends on the deployment. A section the API could not read is named in coverage.sections_failed and left out of data, never relayed as an empty list. Vendor advisories, patches, generated summaries, trending signals and historical incidents are not relayed. Pass a CVE ID like CVE-2021-44228. Its structured result carries state (measured), measured_at (null: each row carries its own time), method, coverage (the sections relayed, failed and left out, and per-list counts), freshness (null) and notes, with data, which the first text block holds whole up to 30,000 characters; the result's last text block repeats it without data and without the note's sentences (the text block before it), with which notes ends. ${TEXT_BUDGET_DESCRIPTION}`;

// ── outputSchema ──
const Rows = (shape: Record<string, z.ZodType>) => z.array(z.looseObject(shape));
const CountMap = z.record(z.string(), z.number());
const ListCount = z.strictObject({
  returned: z.number().int().nullable().describe("Rows the API returned; null when the section was not read."),
  api_row_limit: z.number().int().describe("The most rows the API returns for this list per CVE: a list this long may be cut."),
});

function schemas() {
  const data = z.strictObject({
    cve_id: z.string(),
    cwes: Rows({ cwe_id: opt(z.string()), name: opt(z.string()), source: opt(z.string()) }).optional(),
    exploits: Rows({
      kind: opt(z.string()).describe("metasploit, exploit_db, nuclei_template, github_poc or vendor_poc."),
      source_name: opt(z.string()),
      source_url: opt(z.string()),
      description: opt(z.string()),
      first_seen_at: opt(z.string()),
      verified_status: opt(z.string()).describe(VERIFIED_STATUS_DESCRIPTION),
    }).optional(),
    exploits_total: z.number().int().nullable().optional().describe("Every exploit reference on record for the CVE, not only those listed in exploits."),
    exploits_capped: z.boolean().optional().describe("true: exploits lists fewer references than exploits_total."),
    exploits_by_kind: CountMap.optional(),
    exploits_by_status: CountMap.optional(),
    affected_packages: Rows({
      ecosystem: opt(z.string()),
      package_name: opt(z.string()),
      version_range: opt(z.string()),
      fixed_version: opt(z.string()).describe("One range's fix, kept for compatibility; not the fix for every affected range: read fixed_branches."),
      fixed_branches: z
        .array(
          z.looseObject({
            introduced: opt(z.string()).describe('The range\'s lower bound, inclusive; "0" is the first version.'),
            fixed: opt(z.string()).describe("The range's fix: the first version past it. null where no fix is on record."),
            last_affected: opt(z.string()).describe("The range's last affected version, inclusive, where no fix is on record; never a fix."),
            advisory_id: opt(z.string()).describe("The OSV record that published the range (GHSA-…, PYSEC-…, CVE-…); null on a row loaded before it was stored."),
            source: opt(z.string()).describe("The loader's label for that record (osv_bulk, osv); null on a row loaded before it was stored."),
          }),
        )
        .nullable()
        .optional()
        .describe(FIXED_BRANCHES_DESCRIPTION),
      dependents_count: opt(z.number()),
      source: opt(z.string()),
    }).optional(),
    fixed_versions: Rows({
      ecosystem: opt(z.string()),
      package_name: opt(z.string()),
      vulnerable_range: opt(z.string()),
      fixed_version: opt(z.string()),
      source: opt(z.string()),
    }).optional(),
    timeline: Rows({ enriched_at: opt(z.string()), enrichment_kind: opt(z.string()), fields_changed: z.unknown().optional(), score_delta: opt(z.number()) }).optional(),
    timeline_total: z.number().int().optional(),
    timeline_count_7d: z.number().int().optional(),
    timeline_count_30d: z.number().int().optional(),
  });
  const coverage = z.strictObject({
    sections_relayed: z.array(z.string()).describe("The sections of the answer relayed in data."),
    sections_failed: z
      .array(z.string())
      .nullable()
      .describe("The sections the API says it could not read (its failed_sections), left out of data; null when the answer does not say (an API older than failed_sections), so an empty list may be an unread section."),
    sections_left_out: z.array(z.string()).describe("The sections of the answer this tool does not relay."),
    exploits: ListCount,
    affected_packages: ListCount,
    fixed_versions: ListCount,
    timeline: z.strictObject({
      returned: z.number().int().nullable(),
      relayed: z.number().int().nullable().describe("The newest rows relayed in data.timeline."),
      api_row_limit: z.number().int(),
    }),
  });
  return { output: envelopeSchema({ data, coverage, freshness: null }) };
}
let built: ReturnType<typeof schemas> | undefined;
// Built on first use: this file is imported by index.ts, so index.ts's own exports are not
// initialised while this module's top level runs.
const schemasOnce = () => (built ??= schemas());

// ── The note ──
const listed = (xs: readonly string[]): string => (xs.length <= 1 ? (xs[0] ?? "") : `${xs.slice(0, -1).join(", ")} and ${xs.at(-1)}`);

function cweSentence(cve: string, cwes: unknown[]): string {
  if (cwes.length === 0) {
    return `No CWE classification is on record for ${cve} (cwes is empty): no NVD, GitHub or CVE.org record EchelonGraph holds names one, which is not a finding that the CVE has no weakness class.`;
  }
  const named = cwes.map((c, i) => {
    const id = strAt(c, "cwe_id") ?? `cwes[${i}]`;
    const name = strAt(c, "name");
    return name ? `${id} (${name})` : id;
  });
  return `${cve} is classified under ${listed(named)}.`;
}

function exploitSentences(cve: string, d: object, rows: unknown[]): string[] {
  const total = numAt(d, "exploits_total");
  const verified = numAt(d, "exploits_by_status", "verified");
  const capped = boolAt(d, "exploits_capped");
  const verifiedRows = rows.filter((r) => strAt(r, "verified_status") === "verified").length;
  if (total === undefined) {
    // An API older than exploits_total, or the count could not be read.
    const cut = rows.length >= (API_ROW_LIMIT.exploits ?? 10) ? ` The API lists at most ${API_ROW_LIMIT.exploits} references, so there may be more.` : "";
    if (rows.length === 0) {
      return [
        `exploits is empty and the answer carries no exploits_total, so it does not count the references on record for ${cve}; an empty list is not evidence that no public exploit exists.`,
      ];
    }
    return [`exploits lists ${rows.length} public exploit reference${rows.length === 1 ? "" : "s"} for ${cve}, ${verifiedRows} with verified_status verified; the answer carries no exploits_total, so it does not say how many are on record.${cut}`];
  }
  if (total === 0) {
    return [
      `EchelonGraph holds no public exploit reference for ${cve} (exploits_total 0). That is not evidence that no public exploit exists: references come only from the sources EchelonGraph ingests, and which of them are polled depends on the deployment.`,
    ];
  }
  const v = verified === undefined ? "" : `, ${verified} of them with verified_status verified`;
  const cut = capped === true ? ` exploits_capped is true: exploits lists ${rows.length} of the ${total}, verified first.` : "";
  return [`EchelonGraph holds ${total} public exploit reference${total === 1 ? "" : "s"} for ${cve} (exploits_total)${v}.${cut}`];
}

function listSentence(name: "affected_packages" | "fixed_versions", rows: unknown[]): string {
  const limit = API_ROW_LIMIT[name] ?? 0;
  if (rows.length === 0) return `${name} is empty: EchelonGraph holds no ${name === "affected_packages" ? "affected package" : "fixed version"} row for this CVE, which is not a finding that no package is affected or fixed.`;
  const cut = rows.length >= limit ? `, the most the API returns per CVE, so there may be more` : "";
  return `${name} lists ${rows.length} row${rows.length === 1 ? "" : "s"}${cut}.`;
}

// #2817: where fixed_version is not the whole answer. A row with more than one range in
// fixed_branches has a fix per range; a row with fixed_branches null has only fixed_version on
// record, and so does a row with fixed_branches [] and a fixed_version (no version range on
// record: none in the advisory, only commit ranges, or more than core-backend stores); an answer
// whose rows carry no fixed_branches is an API older than #2817.
function branchSentences(rows: unknown[]): string[] {
  if (rows.length === 0) return [];
  const named = (r: unknown, i: number) => {
    const eco = strAt(r, "ecosystem");
    const pkg = strAt(r, "package_name") ?? `affected_packages[${i}]`;
    return eco ? `${pkg} (${eco})` : pkg;
  };
  const withField = rows.filter((r) => field(r, "fixed_branches") !== undefined);
  if (withField.length === 0) {
    return [
      "No affected_packages row carries fixed_branches (an API older than that field): each row's fixed_version is one range's fix, which need not be the fix for a given installed version.",
    ];
  }
  const out: string[] = [];
  const multi: string[] = [];
  const unknown: string[] = [];
  const noRange: string[] = [];
  rows.forEach((r, i) => {
    const fb = field(r, "fixed_branches");
    if (Array.isArray(fb) && fb.length > 1) multi.push(named(r, i));
    if (fb === null) unknown.push(named(r, i));
    if (Array.isArray(fb) && fb.length === 0 && strAt(r, "fixed_version")) noRange.push(named(r, i));
  });
  const few = (xs: string[]) => (xs.length <= 3 ? listed(xs) : `${xs.slice(0, 3).join(", ")} and ${xs.length - 3} more`);
  if (multi.length) {
    out.push(
      `${multi.length} affected_packages row${multi.length === 1 ? " lists" : "s list"} more than one affected range in fixed_branches (${few(multi)}): there, fixed_version is one range's fix, and an installed version's fix is the fixed of the range that holds it.`,
    );
  }
  if (unknown.length) {
    out.push(
      `${unknown.length} affected_packages row${unknown.length === 1 ? " carries" : "s carry"} fixed_branches null (${few(unknown)}): ${unknown.length === 1 ? "its" : "their"} ranges are not on record, so fixed_version, one range's fix, is all the answer holds, and it need not be the fix for a given installed version.`,
    );
  }
  if (noRange.length) {
    out.push(
      `${noRange.length} affected_packages row${noRange.length === 1 ? " carries" : "s carry"} fixed_branches [] and a fixed_version (${few(noRange)}): no version range is on record there, which is not a finding that no fix exists, so fixed_version, one range's fix, is all the answer holds, and it need not be the fix for a given installed version.`,
    );
  }
  return out;
}

// ── The tool ──
export async function cveIntel(cve_id: string): Promise<ToolResult> {
  const id = cve_id.trim();
  if (!id) return badInput(TOOL, "cve_id is required");
  if (!CVE_ID.test(id)) return badInput(TOOL, `cve_id ${JSON.stringify(id.slice(0, 32))} is not a CVE id (expected the form CVE-2021-44228)`);
  const cve = id.toUpperCase();
  try {
    const r = await api(`/api/v1/public/cves/${encodeURIComponent(cve)}/enrichment`);
    if (!r.ok) return failed(TOOL, r);
    const d = r.data;
    const reported = field(d, "failed_sections");
    const sectionsFailed = Array.isArray(reported) ? reported.filter((x): x is string => typeof x === "string") : null;
    const failedKeys = new Set((sectionsFailed ?? []).flatMap((s) => SECTION_KEYS[s] ?? [s]));

    const data: Record<string, unknown> = { cve_id: cve };
    for (const k of RELAYED_KEYS) {
      const v = field(d, k);
      if (v === undefined || failedKeys.has(k)) continue;
      data[k] = k === "timeline" && Array.isArray(v) ? v.slice(0, TIMELINE_RELAYED) : v;
    }
    const relayed = LISTS.filter((k) => k in data);
    // Every list this tool relays could not be read: nothing was measured.
    if (relayed.length === 0) {
      const why = sectionsFailed?.length
        ? `the API answered but could not read any section this tool relays (failed_sections: ${sectionsFailed.join(", ")})`
        : "the answer carries none of the sections this tool relays (cwes, exploits, affected_packages, fixed_versions, timeline)";
      return failure("failed", `${TOOL} FAILED: EchelonGraph answered HTTP ${r.status} from ${SHOWN_BASE} for GET /api/v1/public/cves/${cve}/enrichment, but ${why}. ${NOT_A_FINDING}`, {
        kind: "unexpected_shape",
        path: `/api/v1/public/cves/${cve}/enrichment`,
        status: r.status,
        message: why,
      });
    }

    const rows = (k: ListName): unknown[] | null => (Array.isArray(data[k]) ? (data[k] as unknown[]) : null);
    const said: string[] = [];
    const cwes = rows("cwes");
    if (cwes) said.push(cweSentence(cve, cwes));
    const exploits = rows("exploits");
    if (exploits) said.push(...exploitSentences(cve, data, exploits));
    for (const k of ["affected_packages", "fixed_versions"] as const) {
      const xs = rows(k);
      if (xs) said.push(listSentence(k, xs));
      if (xs && k === "affected_packages") said.push(...branchSentences(xs));
    }
    const timeline = rows("timeline");
    const apiTimeline = field(d, "timeline");
    const timelineReturned = Array.isArray(apiTimeline) ? apiTimeline.length : null;
    const timelineTotal = numAt(data, "timeline_total");
    if (timeline && timelineReturned !== null && timelineReturned > timeline.length) {
      said.push(`timeline relays the ${timeline.length} newest of the ${timelineReturned} enrichment-history rows the API returned${timelineTotal === undefined ? "" : ` (timeline_total ${timelineTotal})`}.`);
    }
    if (sectionsFailed === null) {
      const empty = relayed.filter((k) => rows(k)?.length === 0);
      if (empty.length) {
        said.push(
          `The answer carries no failed_sections (an API older than that field), so it does not say whether ${listed(empty)} ${empty.length === 1 ? "was" : "were"} read: an empty list there may be a section the API could not read within its time budget, not a finding of none.`,
        );
      }
    } else if (sectionsFailed.length) {
      said.push(`The API could not read ${listed(sectionsFailed)} (failed_sections): ${sectionsFailed.length === 1 ? "it is" : "they are"} left out of data, and the absence is not a finding of none.`);
    }
    said.push(`Not relayed from the answer: ${listed(LEFT_OUT)}.`);

    const count = (k: ListName) => {
      const v = field(d, k);
      return Array.isArray(v) && !failedKeys.has(k) ? v.length : null;
    };
    const coverage = {
      sections_relayed: relayed,
      sections_failed: sectionsFailed,
      sections_left_out: [...LEFT_OUT],
      exploits: { returned: count("exploits"), api_row_limit: API_ROW_LIMIT.exploits as number },
      affected_packages: { returned: count("affected_packages"), api_row_limit: API_ROW_LIMIT.affected_packages as number },
      fixed_versions: { returned: count("fixed_versions"), api_row_limit: API_ROW_LIMIT.fixed_versions as number },
      timeline: { returned: count("timeline"), relayed: timeline ? timeline.length : null, api_row_limit: API_ROW_LIMIT.timeline as number },
    };
    return succeeded(data, `${okHead(TOOL, r.status)} ${said.join(" ")}`, {
      state: "measured",
      measured_at: null,
      method: CVE_INTEL_METHOD,
      coverage,
      freshness: null,
      notes: [
        "measured_at is null: the answer has no single observation time; each row carries its own (first_seen_at, enriched_at).",
        "freshness is null: the answer does not say when each source was last polled.",
      ],
    });
  } catch (e) {
    return crashed(TOOL, e);
  }
}

export function registerCveIntel(server: McpServer): void {
  const { output } = schemasOnce();
  server.registerTool(
    "cve_intel",
    {
      title: "CVE weakness, exploits and packages",
      description: CVE_INTEL_DESCRIPTION,
      inputSchema: z.object({ cve_id: z.string().describe("a CVE ID, e.g. CVE-2021-44228") }),
      outputSchema: output,
      annotations: ANNOTATIONS,
    },
    async ({ cve_id }) => checked(TOOL, output, await cveIntel(cve_id)),
  );
}
