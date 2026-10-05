// get_cwe (#2720): one CWE's name and description, and a page of the active CVEs classified
// under it, from GET /api/v1/public/cwes/:cwe_id?page=N (core-backend cve/handler_cwe.go
// GetCWELanding, cwe_landing_store.go). The JSON is relayed as the API sent it.
//
// The order is the API's to state. Since #2720 the answer carries `order` (KEV-listed first);
// before it, a DISTINCT ON put cve_id first in the sort, so page 1 was the oldest CVE ids. So the
// note repeats `order` when the answer has it, and otherwise says the answer does not state its
// order, rather than calling the rows KEV-first.
//
// The API answers a page past max_page as max_page, and an id it does not know with total 0, so
// the note compares the page asked for with the page served, and says when total counts CVEs no
// page lists. Each page is cached by the API for up to an hour (cweLandingTTL) behind a CDN, so
// the note says it can lag the feed.
import * as z from "zod";
import type { McpServer } from "@modelcontextprotocol/server";
import {
  ANNOTATIONS,
  api,
  badInput,
  checked,
  crashed,
  envelopeSchema,
  failed,
  field,
  lenAt,
  numAt,
  okHead,
  opt,
  rowsScoreNote,
  strAt,
  succeeded,
  type ToolResult,
} from "../index.js";
import { GET_CVE_WHOLE, TEXT_BUDGET_DESCRIPTION, type TextCut } from "../textBudget.js";

const TOOL = "get_cwe";
const CWE_ARG = /^(?:CWE-)?0*(\d{1,6})$/i;
const MAX_PAGE = 200;

const GET_CWE_METHOD =
  "EchelonGraph's per-CWE listing (GET /api/v1/public/cwes/:cwe_id): the CWE's name and description from the MITRE CWE catalog EchelonGraph embeds (catalog_version), and the active CVEs in EchelonGraph's CVE feed that an NVD, GitHub (GHSA) or CVE.org record classifies under it, rejected and reserved records left out, 50 to a page.";

export const GET_CWE_DESCRIPTION = `One CWE (weakness class) and the CVEs classified under it. Returns cwe_id, name and description (from the MITRE CWE catalog EchelonGraph embeds, version catalog_version), total (the active CVEs in EchelonGraph's feed that an NVD, GitHub or CVE.org record classifies under it, rejected and reserved records left out), and cves, one page of 50: each with cve_id, severity, cvss_v3_score, echelongraph_score, echelongraph_severity, score_assessed, kev_listed, published and a shortened description. order says how the rows are sorted (CISA-KEV-listed first, then EchelonGraph score); an answer without order does not state its order, and the note says so. page is the page served, page_size its size and max_page the last page the API serves: a later page is answered as max_page, so past max_page pages total counts CVEs no page lists. echelongraph_score is EchelonGraph's score only when score_assessed is true; the note labels each row that is NOT YET SCORED. A total of 0 says that no CVE in EchelonGraph's feed is classified under that CWE, not that none exists. Pass cwe_id like CWE-79 (or 79) and an optional page (1-${MAX_PAGE}). Its structured result carries state (measured), measured_at (null), method, coverage (total, returned, page, page_requested, page_size, max_page), freshness (null) and notes, with data equal to the API's JSON; the result's last text block repeats it without data (the first text block) and without the note's sentences (the text block before it), with which notes ends. ${TEXT_BUDGET_DESCRIPTION}`;

// #2783: a page of 50 production rows is about 27,000 characters as pretty JSON (CWE-79, page 1),
// under the budget once each row is on a line of its own. Past it, each row keeps the fields the
// description names with its description cut to 120 characters, then rows are left out.
const GET_CWE_TEXT: TextCut = {
  rows: "cves",
  levels: [{ keep: ["cve_id", "severity", "cvss_v3_score", "echelongraph_score", "echelongraph_severity", "score_assessed", "score_unassessed_reason", "kev_listed", "published", "description"], clip: 120 }],
  whole: `${GET_CVE_WHOLE}.`,
};

function schemas() {
  const row = z.looseObject({
    cve_id: opt(z.string()),
    severity: opt(z.string()),
    cvss_v3_score: opt(z.number()),
    cvss_v2_score: opt(z.number()),
    cvss_v2_severity: opt(z.string()),
    echelongraph_score: opt(z.number()).describe("EchelonGraph's 0-10 score: a score only when score_assessed is true."),
    echelongraph_severity: opt(z.string()),
    score_assessed: opt(z.boolean()).describe("Whether EchelonGraph has scored the CVE; false: NOT YET SCORED, not scored 0."),
    kev_listed: opt(z.boolean()),
    published: opt(z.string()),
    description: opt(z.string()),
  });
  const data = z.looseObject({
    cwe_id: opt(z.string()),
    name: opt(z.string()),
    description: opt(z.string()),
    catalog_version: opt(z.string()).describe("The version of the MITRE CWE catalog name and description come from."),
    total: opt(z.number()).describe("The active CVEs classified under the CWE, rejected and reserved records left out."),
    cves: z.array(row).optional(),
    page: opt(z.number()),
    page_size: opt(z.number()),
    max_page: opt(z.number()).describe("The last page the API serves; a later page is answered as this one."),
    order: opt(z.string()).describe("How cves is sorted, as the API states it; absent from an API older than the field, which sorted by CVE id."),
  });
  const coverage = z.strictObject({
    total: z.number().nullable(),
    returned: z.number().nullable(),
    page: z.number().nullable().describe("The page served."),
    page_requested: z.number().describe("The page asked for."),
    page_size: z.number().nullable(),
    max_page: z.number().nullable(),
  });
  return { output: envelopeSchema({ data, coverage, freshness: null }) };
}
let built: ReturnType<typeof schemas> | undefined;
// Built on first use: index.ts imports this file, so its exports are not initialised while this
// module's top level runs.
const schemasOnce = () => (built ??= schemas());

export async function getCwe(cwe_id: string, page?: number): Promise<ToolResult> {
  const raw = cwe_id.trim();
  if (!raw) return badInput(TOOL, "cwe_id is required");
  const m = CWE_ARG.exec(raw);
  if (!m) return badInput(TOOL, `cwe_id ${JSON.stringify(raw.slice(0, 32))} is not a CWE id (expected the form CWE-79)`);
  const asked = page ?? 1;
  if (!Number.isInteger(asked) || asked < 1 || asked > MAX_PAGE) return badInput(TOOL, `page must be a whole number from 1 to ${MAX_PAGE}`);
  const cwe = `CWE-${Number(m[1])}`;
  try {
    const r = await api(`/api/v1/public/cwes/${encodeURIComponent(cwe)}${asked > 1 ? `?page=${asked}` : ""}`);
    if (!r.ok) return failed(TOOL, r);
    const d = r.data;
    const id = strAt(d, "cwe_id") ?? cwe;
    const total = numAt(d, "total");
    const returned = lenAt(d, "cves");
    const served = numAt(d, "page");
    const size = numAt(d, "page_size");
    const maxPage = numAt(d, "max_page");
    const order = strAt(d, "order");
    const name = strAt(d, "name");
    const version = strAt(d, "catalog_version");
    const said: string[] = [];

    said.push(
      name
        ? `${id} is ${name} in the MITRE CWE catalog${version ? ` (version ${version})` : ""}.`
        : `The answer carries no name for ${id}: the MITRE CWE catalog EchelonGraph embeds has no entry for it, or the API sent none.`,
    );
    if (total === 0) {
      said.push(
        `No active CVE in EchelonGraph's feed is classified under ${id} (total 0): a measured empty result (we looked and found nothing), which says only that no NVD, GitHub or CVE.org record EchelonGraph holds puts a CVE in this class, not that none exists.`,
      );
    } else if (total !== undefined) {
      const of = returned === undefined ? "" : `; this page lists ${returned}`;
      const pg = served === undefined ? "" : ` (page ${served}${maxPage === undefined ? "" : ` of at most ${maxPage}`})`;
      said.push(`EchelonGraph's feed holds ${total} active CVEs classified under ${id} (total, rejected and reserved records left out)${of}${pg}.`);
      if (maxPage !== undefined && size !== undefined && total > maxPage * size) {
        said.push(`Only the first ${maxPage * size} of them can be paged to: the API serves no page past max_page ${maxPage}.`);
      }
    }
    if (served !== undefined && served !== asked) {
      said.push(`Page ${asked} was asked for and the API served page ${served}.`);
    }
    if (returned) {
      const rows = field(d, "cves");
      const kev = Array.isArray(rows) ? rows.filter((c) => field(c, "kev_listed") === true).length : 0;
      said.push(
        order
          ? `The rows are sorted by ${order}, as the answer states (order); ${kev} of the ${returned} on this page are CISA-KEV-listed (kev_listed).`
          : `The answer does not state how its rows are sorted (no order field; an API older than it sorted them by CVE id), so the first rows are not necessarily the CISA-KEV-listed or highest-scored ones; ${kev} of the ${returned} on this page are CISA-KEV-listed (kev_listed).`,
      );
    }
    said.push("The API serves each page from a cache refreshed at most hourly, behind a CDN, so it can lag the feed by an hour or more.");
    const scores = rowsScoreNote(d);

    return succeeded(d, `${okHead(TOOL, r.status)} ${said.join(" ")}${scores}`, {
      state: "measured",
      measured_at: null,
      method: GET_CWE_METHOD,
      coverage: {
        total: total ?? null,
        returned: returned ?? null,
        page: served ?? null,
        page_requested: asked,
        page_size: size ?? null,
        max_page: maxPage ?? null,
      },
      freshness: null,
      notes: [
        "measured_at is null: a page of CVEs has no single observation time; each row carries its own published date.",
        "freshness is null: the answer does not say when its cached page was computed.",
      ],
    }, GET_CWE_TEXT);
  } catch (e) {
    return crashed(TOOL, e);
  }
}

export function registerGetCwe(server: McpServer): void {
  const { output } = schemasOnce();
  server.registerTool(
    "get_cwe",
    {
      title: "CWE and its CVEs",
      description: GET_CWE_DESCRIPTION,
      inputSchema: z.object({
        cwe_id: z.string().describe("a CWE ID, e.g. CWE-79 (or 79)"),
        page: z.number().int().min(1).max(MAX_PAGE).optional().describe(`page of 50 CVEs (default 1, max ${MAX_PAGE})`),
      }),
      outputSchema: output,
      annotations: ANNOTATIONS,
    },
    async ({ cwe_id, page }) => checked(TOOL, output, await getCwe(cwe_id, page)),
  );
}
