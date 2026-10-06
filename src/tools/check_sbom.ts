// check_sbom (#2721): a dependency list checked against EchelonGraph's advisory corpus, one
// verdict per component, through POST /api/v1/public/cves/match/batch.
//
// Where the SBOM is parsed: HERE, in this MCP server — on the caller's machine when it runs from
// npm, on EchelonGraph's hosted endpoint when it is called there (http.ts, whose body cap admits
// a document only for this tool and scan_manifest, #2747, #2835). The backend accepts only a list
// of components ({purl} or {ecosystem, package, version}); a CycloneDX or SPDX document posted to it
// whole is refused. So this tool reads the document, takes each component's purl, and sends only
// those, in a POST body (never a URL, #1983). The document's metadata, licences, hashes and free
// text never leave the machine, and the public route parses nothing but a flat list
// (core-backend internal/cve/matchbatch.go says the same from its side).
//
// What it is not: a ranking. It is not the rejected prioritize_cves (#2304, "Considered and
// rejected"); it relays each component's own verdict, assessed / not_assessed_reason included,
// and orders nothing.
//
// The note never renders not_assessed or undetermined as clean, and always says why a deb, apk or
// rpm purl without a distro release is not assessed.
import type { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod";
import { TEXT_BUDGET_DESCRIPTION, type TextCut } from "../textBudget.js";
import {
  CLEAN_NOTE,
  DISTRO_NOTE,
  FRESHNESS_NOTE,
  MAX_PURLS,
  MEASURED_AT_NOTE,
  METHOD,
  batchDataShape,
  dedupe,
  field,
  isObj,
  plural,
  purlsRefusal,
  sendBatches,
  sendingCoverage,
  sendingCoverageShape,
  sendingSentences,
  verdictSentences,
  type FailureLike,
  type MatchBatchDeps,
  type Sending,
  type ToolResult,
} from "./match_batch.js";

// #2835: the batch loop, its constants and the row schema moved to match_batch.ts, which
// scan_manifest shares; re-exported here, where the tests and prompts.ts import them.
export { API_COMPONENTS_PER_MINUTE, BATCH_PATH, MAX_COMPONENTS, MAX_PURLS, TIME_BUDGET_MS, mergeAnswers, type ToolResult } from "./match_batch.js";

// What index.ts hands this module, so the tool uses the server's one api(), envelope and failure
// contract instead of a copy (and index.ts stays the only place that defines them). The batch
// loop's part is match_batch.ts's MatchBatchDeps.
export type CheckSbomDeps<F extends FailureLike> = MatchBatchDeps<F> & {
  // #2775: on the hosted endpoint, runtime.ts holdRequest: the request's admission and large-body
  // slot are held until the call has stopped. Absent, the call runs unheld.
  hold?: <T>(p: Promise<T>) => Promise<T>;
  badInput: (tool: string, why: string) => ToolResult;
  crashed: (tool: string, e: unknown) => ToolResult;
  checked: (tool: string, schema: z.ZodType, r: ToolResult) => ToolResult;
  succeeded: (
    data: object,
    note: string,
    env: { state: "measured" | "not_assessed"; measured_at: string | null; method: string; coverage: Record<string, unknown> | null; freshness: null; notes?: string[] },
    cut?: TextCut,
  ) => ToolResult;
  okHead: (tool: string, status?: number) => string;
  envelopeSchema: (o: { data: z.ZodType; coverage: z.ZodType | null; freshness: z.ZodType | null }) => z.ZodType;
  annotations: Record<string, boolean>;
};

export const CHECK_SBOM = "check_sbom";
// The document's size cap, as JSON text. OWASP Juice Shop 11.1.2's full CycloneDX SBOM (840
// components) is 0.74 MB; this leaves room for a much larger one while bounding what this process
// parses.
export const MAX_SBOM_CHARS = 5_000_000;
// CycloneDX nests components; this bounds the walk.
const MAX_DEPTH = 32;
// The order in which extract() reads and counts the distinct purls (#2799 review): purls as listed;
// a CycloneDX document's components depth first, each one's nested components right after it
// (fromCycloneDX); an SPDX document's packages as listed; each purl trimmed and kept at its first
// place (dedupe). The note says it beside the position from which the purls not sent run, so a
// second call can rebuild them from its own input whether or not the text cuts not_sent_purls.
const READ_ORDER =
  "counted in the order this tool read them (the order of purls, or of the document's components or packages, each component's nested components right after it and before its next sibling, each purl at its first place)";

export const CHECK_SBOM_TITLE = "Check an SBOM against the advisory corpus";
// #2846: the routing sentence for the pods-and-images question, inside the description's first
// 2,048 characters (test/prompts-resources.test.mjs holds it there, with a control). The workload
// itself never reaches this tool: the workload_triage prompt has the agent build each image's SBOM
// with its own tools and pass the purls.
export const CHECK_SBOM_ROUTING =
  "For container images and Kubernetes pods, the input is an SBOM of each image, or its purls.";
export const CHECK_SBOM_DESCRIPTION =
  "Check a dependency list against EchelonGraph's advisory corpus, one verdict per component. " +
  CHECK_SBOM_ROUTING +
  " Pass purls (package URLs, up to 2,000 distinct) or sbom (a CycloneDX or SPDX JSON document, up to 5,000,000 characters). This server reads the purls from the document; only they are sent to the API, in POST bodies of at most 200, never in a URL; the document itself is not sent on. Run from npm, this server is on your machine; over the hosted endpoint (mcp.echelongraph.io) it is EchelonGraph's, and the document is the request body, accepted up to 6 MiB. data.results holds one row per component sent, in order, with verdict (affected, not_affected, undetermined or not_assessed), not_assessed_reason, cve_ids, matched_package and matched_via (a deb or apk purl's upstream qualifier matches as its source package); each match carries fixed_in (its interval's fixed bound) or null with fixed_in_reason. data.summary counts the verdicts. not_affected is the only clean verdict: not_assessed (no verdict, as for a deb, apk or rpm purl without a distro qualifier naming its release, which EchelonGraph does not guess) and undetermined are not, and the note counts both. The API allows 1,200 components a minute per caller; on a 429 the tool waits out Retry-After, up to 50 seconds a call, then answers what it has, the rest in data.not_sent_purls, unchecked and not clean. Input with more than 2,000 distinct purls is refused, not truncated." +
  " " +
  TEXT_BUDGET_DESCRIPTION +
  " Cut, each row keeps index, purl, verdict, not_assessed_reason and cve_ids at least, each match its fixed_in while kept; not_affected rows leave the text first, then not_assessed ones; not_sent_purls keeps its first 10.";

// #2783: a production row is about 2,200 characters as pretty JSON, most of it its matches, each
// a CVE with its description, so the 50-component Juice Shop document was 112,820 characters of
// text, and 2,000 purls about 1,200,000. Past DATA_TEXT_BUDGET each row in the first text block
// keeps its verdict, counts, cve_ids, matched_package and matched_via (#2836), and each match its
// scores, flags, fixed_in (#2834) and match_reason (the
// advisory interval the version falls inside: "[A, B)" names the fixed version B, "[A, B]" the last
// affected one, #2830) without the
// description; then the same without match_reason; then only index, purl, verdict,
// not_assessed_reason and cve_ids. When rows must still go, the clean ones (not_affected) leave
// first, then the not_assessed ones, both counted in data.summary and the note, so the affected
// and undetermined rows are the last to leave the text.
// A call that stops early (a 2,000-purl call from a fresh budget answers 1,200 and is refused the
// rest with a 429) lists the purls not sent in data.not_sent_purls: 800 of them are some 20,000
// to 60,000 characters, which the text cannot hold beside the rows. Once the first level does not
// fit with that list whole, the text keeps its first 10 and the note says which they are: the
// input's distinct purls from position `sent` + 1 on, in input order, which is how check_sbom read
// them (x.purls.slice(answers.length * MAX_COMPONENTS)), so a second call can send them without
// reading the list. noteFor gives that order (READ_ORDER) beside the position, so this sentence
// points to it.
export function sbomText(sent: number): TextCut {
  const matches = ["cve_id", "severity", "effective_severity", "effective_score", "kev_listed", "ransomware", "epss_score", "score_assessed", "fixed_in"];
  const row = [
    "index", "purl", "ecosystem", "package", "version", "verdict", "assessed", "not_assessed_reason", "count", "not_affected_count", "undetermined_count", "cve_ids", "matched_package", "matched_via",
  ];
  return {
    rows: "results",
    levels: [
      { keep: [...row, ["matches", [...matches, "match_reason"]]], clip: 200 },
      { keep: [...row, ["matches", matches]], clip: 200 },
      { keep: ["index", "purl", "verdict", "not_assessed_reason", "cve_ids"], clip: 100 },
    ],
    sides: [
      {
        list: "not_sent_purls",
        cap: 10,
        said: (_inText, total) =>
          `The ${total} purls not sent are the input's distinct purls from position ${sent + 1} on, counted in the order the note gives for them, so a second call can send them without reading the list.`,
      },
    ],
    leaveOutFirst: { field: "verdict", values: ["not_affected", "not_assessed"], why: "data.summary counts every verdict" },
    // check_affected cuts its text too past the budget (#2802): only its structuredContent.data is
    // a component's matches whole.
    whole:
      "check_affected, given a row's ecosystem, package and version, returns that component's matches, whole in its structuredContent.data, and cve_intel a CVE's affected packages and fixed versions.",
    page: (shown) => `To read every row in the text, check ${shown} or fewer purls per call.`,
  };
}

// ── Reading the input ──

export type Extracted = {
  input: "purls" | "cyclonedx" | "spdx";
  // Components (CycloneDX) or packages (SPDX) in the document; null for a plain purl list.
  components_in_document: number | null;
  with_purl: number;
  without_purl: number;
  duplicates_removed: number;
  purls: string[];
};

// The purls of a CycloneDX JSON document: every components[] entry, nested ones included.
// metadata.component (the subject of the SBOM, not a dependency of it) is not checked.
function fromCycloneDX(doc: Record<string, unknown>): Extracted | string {
  if (doc.components !== undefined && !Array.isArray(doc.components)) return "its components is not an array";
  let total = 0;
  let without = 0;
  const found: string[] = [];
  const walk = (cs: unknown, depth: number): string | null => {
    if (!Array.isArray(cs)) return null;
    if (depth > MAX_DEPTH) return `its components nest deeper than ${MAX_DEPTH} levels`;
    for (const c of cs) {
      if (!isObj(c)) continue;
      total++;
      const p = typeof c.purl === "string" ? c.purl.trim() : "";
      if (p) found.push(p);
      else without++;
      const err = walk(c.components, depth + 1);
      if (err) return err;
    }
    return null;
  };
  const err = walk(doc.components, 0);
  if (err) return err;
  const { purls, removed } = dedupe(found);
  return { input: "cyclonedx", components_in_document: total, with_purl: found.length, without_purl: without, duplicates_removed: removed, purls };
}

// The purls of an SPDX JSON document: each package's externalRefs entry of referenceType purl
// (referenceCategory PACKAGE-MANAGER, spelled PACKAGE_MANAGER by some tools; the type decides).
function fromSPDX(doc: Record<string, unknown>): Extracted | string {
  if (doc.packages !== undefined && !Array.isArray(doc.packages)) return "its packages is not an array";
  const pkgs = Array.isArray(doc.packages) ? doc.packages : [];
  let total = 0;
  let without = 0;
  const found: string[] = [];
  for (const p of pkgs) {
    if (!isObj(p)) continue;
    total++;
    const refs = Array.isArray(p.externalRefs) ? p.externalRefs : [];
    const ref = refs.find((r) => isObj(r) && typeof r.referenceType === "string" && r.referenceType.toLowerCase() === "purl" && typeof r.referenceLocator === "string" && r.referenceLocator.trim());
    if (ref && isObj(ref)) found.push(String(ref.referenceLocator).trim());
    else without++;
  }
  const { purls, removed } = dedupe(found);
  return { input: "spdx", components_in_document: total, with_purl: found.length, without_purl: without, duplicates_removed: removed, purls };
}

// Reads the tool's arguments into the purls to send, or says why it cannot.
export function extract(a: { purls?: unknown; sbom?: unknown }): Extracted | string {
  const hasPurls = a.purls !== undefined;
  const hasSbom = a.sbom !== undefined;
  if (hasPurls === hasSbom) return "pass exactly one of purls (a list of package URLs) or sbom (a CycloneDX JSON or SPDX JSON document)";
  if (hasPurls) {
    if (!Array.isArray(a.purls) || a.purls.some((p) => typeof p !== "string")) return "purls must be a list of strings";
    const trimmed = (a.purls as string[]).map((p) => p.trim()).filter(Boolean);
    const { purls, removed } = dedupe(trimmed);
    return { input: "purls", components_in_document: null, with_purl: trimmed.length, without_purl: (a.purls as string[]).length - trimmed.length, duplicates_removed: removed, purls };
  }
  let doc: unknown = a.sbom;
  if (typeof doc === "string") {
    if (doc.length > MAX_SBOM_CHARS) return `sbom is ${doc.length} characters; at most ${MAX_SBOM_CHARS} are read`;
    try {
      doc = JSON.parse(doc);
    } catch {
      return "sbom is not JSON: pass a CycloneDX JSON or SPDX JSON document (XML and SPDX tag-value are not read)";
    }
  } else {
    let size = 0;
    try {
      size = JSON.stringify(doc)?.length ?? 0;
    } catch {
      return "sbom could not be serialised as JSON";
    }
    if (size > MAX_SBOM_CHARS) return `sbom is ${size} characters as JSON; at most ${MAX_SBOM_CHARS} are read`;
  }
  if (!isObj(doc)) return "sbom must be a JSON object: a CycloneDX JSON or SPDX JSON document";
  if (typeof doc.bomFormat === "string" && doc.bomFormat.toLowerCase() === "cyclonedx") {
    const r = fromCycloneDX(doc);
    return typeof r === "string" ? `the CycloneDX document cannot be read: ${r}` : r;
  }
  if (typeof doc.spdxVersion === "string" && doc.spdxVersion.toUpperCase().startsWith("SPDX-")) {
    const r = fromSPDX(doc);
    return typeof r === "string" ? `the SPDX document cannot be read: ${r}` : r;
  }
  return 'sbom is neither a CycloneDX JSON document (bomFormat "CycloneDX") nor an SPDX JSON document (spdxVersion "SPDX-…")';
}

// ── The answer ──

function noteFor(head: string, x: Extracted, d: object, g: Sending): { note: string; assessed: number } {
  const out: string[] = [head];

  if (x.input === "purls") {
    out.push(`Sent ${plural(g.sent, "purl", "purls")}${x.duplicates_removed ? ` (${plural(x.duplicates_removed, "duplicate was", "duplicates were")} sent once)` : ""}.`);
  } else {
    const kind = x.input === "cyclonedx" ? "CycloneDX" : "SPDX";
    const unit = x.input === "cyclonedx" ? "component" : "package";
    out.push(
      `Read ${plural(x.components_in_document ?? 0, unit, `${unit}s`)} from the ${kind} document: ${x.with_purl} with a purl${x.without_purl ? `, and ${x.without_purl} without one, which ${x.without_purl === 1 ? "was" : "were"} not checked and ${x.without_purl === 1 ? "is" : "are"} not clean` : ""}${x.duplicates_removed ? `; ${plural(x.duplicates_removed, "duplicate purl was", "duplicate purls were")} sent once` : ""}; sent ${g.sent}.`,
    );
  }
  // The batches, the waits and the purls not sent, at their position in READ_ORDER (#2799).
  out.push(...sendingSentences(g, x.purls.length, READ_ORDER, "check_sbom again with purls set to"));
  const v = verdictSentences(d, g);
  out.push(...v.sentences);
  return { note: out.join(" "), assessed: v.assessed };
}

export async function checkSbom<F extends FailureLike>(deps: CheckSbomDeps<F>, a: { purls?: unknown; sbom?: unknown }): Promise<ToolResult> {
  const tool = CHECK_SBOM;
  try {
    const x = extract(a);
    if (typeof x === "string") return deps.badInput(tool, x);
    if (x.purls.length === 0) {
      return deps.badInput(tool, x.input === "purls" ? "purls holds no package URL" : `the document holds ${x.components_in_document ?? 0} components and none carries a purl, so there is nothing to check`);
    }
    const refused = purlsRefusal(x.purls, `split the list into calls of ${MAX_PURLS} or fewer`);
    if (refused) return deps.badInput(tool, refused);

    // match_batch.ts: one batch at a time, Retry-After waited out within the budget (#2734,
    // #2756), stopped on cancellation (#2775).
    const run = await sendBatches(deps, tool, x.purls);
    if (!run.ok) return run.result;
    const { data, status, sending: g } = run;
    const { note, assessed } = noteFor(deps.okHead(tool, status), x, data, g);
    return deps.succeeded(data, note, {
      state: assessed > 0 ? "measured" : "not_assessed",
      measured_at: null,
      method: METHOD,
      coverage: {
        input: x.input,
        components_in_document: x.components_in_document,
        with_purl: x.with_purl,
        without_purl: x.without_purl,
        duplicates_removed: x.duplicates_removed,
        ...sendingCoverage(g, x.purls.length, field(data, "summary")),
      },
      freshness: null,
      notes: [DISTRO_NOTE, CLEAN_NOTE, MEASURED_AT_NOTE, FRESHNESS_NOTE],
    }, sbomText(g.sent));
  } catch (e) {
    return deps.crashed(tool, e);
  }
}

// ── Schemas ──

export function checkSbomOutput(envelopeSchema: CheckSbomDeps<FailureLike>["envelopeSchema"]): z.ZodType {
  return envelopeSchema({
    // match_batch.ts batchDataShape: the batch route's answer, merged over the batches.
    data: z.looseObject(batchDataShape),
    coverage: z.strictObject({
      input: z.enum(["purls", "cyclonedx", "spdx"]).describe("What was passed: a purl list, a CycloneDX JSON document or an SPDX JSON document."),
      components_in_document: z.number().int().nullable().describe("Components (CycloneDX) or packages (SPDX) in the document; null for a purl list."),
      with_purl: z.number().int().describe("Of those, the ones carrying a purl."),
      without_purl: z.number().int().describe("The ones without a purl: not checked, and not clean."),
      duplicates_removed: z.number().int().describe("Purls that appeared more than once and were sent once."),
      ...sendingCoverageShape,
    }),
    freshness: null,
  });
}

// A literal server.registerTool(name, { title, description, … }) call with constant strings:
// marketing-site lib/mcpToolClaims.test.ts reads it here (it follows index.ts's call to this
// function) and holds the /pulse/mcp row to this title and description.
export function registerCheckSbom<F extends FailureLike>(server: McpServer, deps: CheckSbomDeps<F>): void {
  const output = checkSbomOutput(deps.envelopeSchema as CheckSbomDeps<FailureLike>["envelopeSchema"]);
  server.registerTool(
    CHECK_SBOM,
    {
      title: CHECK_SBOM_TITLE,
      description: CHECK_SBOM_DESCRIPTION,
      inputSchema: z.object({
        purls: z.array(z.string()).optional().describe("package URLs to check, e.g. pkg:npm/lodash@4.17.20 or pkg:deb/debian/openssl@3.0.11-1~deb12u1?distro=debian-12 (up to 2,000 distinct, sent in batches of 200)"),
        sbom: z
          .union([z.string(), z.record(z.string(), z.unknown())])
          .optional()
          .describe(
            "a CycloneDX JSON or SPDX JSON document, as JSON text or as an object; its purls are read by this MCP server and only they are sent to the API; over the hosted endpoint (mcp.echelongraph.io) the document is the request body",
          ),
      }),
      outputSchema: output as z.ZodObject,
      annotations: deps.annotations,
    },
    async (a: { purls?: string[]; sbom?: unknown }, ctx: { mcpReq: { signal: AbortSignal } }) => {
      const run = checkSbom({ ...deps, signal: ctx.mcpReq.signal }, a);
      return deps.checked(CHECK_SBOM, output, await (deps.hold ? deps.hold(run) : run)) as never;
    },
  );
}
