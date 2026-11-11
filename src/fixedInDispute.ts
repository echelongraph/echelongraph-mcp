// fixed_in_dispute (#3391): where the CVE record's CNA and the advisory disagree on the range that holds a version.
// core-backend's match answers carry it beside fixed_in, on a registry match (check_affected; check_sbom's and
// scan_manifest's rows' matches) and on cve_remediation's installed version, and a match whose version only the CNA's
// range holds says version_evidence cna_affected_range. Relayed as the API sends it, never derived or decided here.
// #3381's review: nothing here says which record fixed_in is: core-backend's answer follows the source named in higher
// (the more conservative one), so with higher cna, fixed_in is past the advisory's own bound. What the notes say of a
// dispute is the API's note, quoted verbatim; any sentence of ours is true of every kind and every higher, a value a
// later API adds among them (test/fixed-in-dispute.test.mjs holds each to core-backend's wire, for every combination).
// #3381's round-4 review: a match is disputed where it carries a fixed_in_dispute object, with a note or without one
// (isDispute), the same test in every tool; no sentence of ours rests on the wording of the API's note, nor on which
// fields of the object are set.
//
// A module of its own, importing only zod, as fixStatus.ts is (index.ts and tools/cve_remediation.ts import each other).
import * as z from "zod";

const opt = <T extends z.ZodType>(t: T) => t.nullable().optional();
// A value the API names today, listed; any other string relayed as well (index.ts openSuccess: an enum beside a plain
// string is open as it is), so a value a later API adds is never a failed call.
const open = <const V extends readonly [string, ...string[]]>(values: V) => opt(z.union([z.enum(values), z.string()]));

// How a registry match's version was decided (core-backend cve/pkgmatch.go VersionEvidence*), and #3391's
// cna_affected_range: the version only the CVE's own record (its CNA's range) holds.
export const VERSION_EVIDENCE = ["exact_version_list", "advisory_interval", "fix_boundary_only", "no_version_supplied", "cna_affected_range"] as const;
// #3381's round-10 review (d4-release R10-3, d5-3391relay F1, F2, F3): what #3391's API lane adds is described as what an
// answer carries once EchelonGraph's API serves it, never as what it serves: this release ships before that lane, and
// through round 10 these said it was served ("today, language-registry packages").
// #3767: since #3757 a cna_affected_range match is also one no advisory record names the package for at all (match_method
// cna package url), and the sentence says so.
export const VERSION_EVIDENCE_FIELD =
  "Registry match: how the version was decided: exact_version_list (named in the advisory's list of affected versions), advisory_interval (inside one of its intervals), fix_boundary_only (below its only stored fix, its lower bound assumed), no_version_supplied (no version given, so no claim about it), or, once EchelonGraph's API serves it, cna_affected_range (held by the CVE record's CNA range, where no advisory statement holds it: interval is the CNA's range, and fixed_in_dispute, where the API publishes one, says how the two differ; such a match may carry none; on a match whose match_method is cna package url, no advisory record names the package for the CVE at all, and the CNA's statement is the only source). Relayed as the API sends it; a later value is relayed too.";
export const versionEvidenceSchema = () => open(VERSION_EVIDENCE).describe(VERSION_EVIDENCE_FIELD);

// #3767: core-backend's registry matcher (cve/pkgmatch_cnapurl.go MatchMethodCNAPackageURL, #3757) also decides a CVE that
// no OSV advisory record names the package for, where the CVE record's CNA names the package by its package
// URL: such a match says match_method "cna package url", version_evidence cna_affected_range, matched_criteria the CNA's
// purl as written, and match_confidence 0.8 (MatchConfidenceCNAPackageURL), below an advisory interval's 0.95. A CNA
// statement alone never clears a package no advisory record names: it stays assessed false
// (package_not_in_advisory_corpus) unless a CNA statement calls the version affected, and cve_remediation's installed
// verdict for such a CVE is affected or not_assessed, never not_affected (installedFixFromRows). Beside advisory records,
// the match path counts such a CVE in not_affected_count where the CNA calls the version unaffected (#3825).
export const CNA_PACKAGE_URL = "cna package url";
export const MATCH_METHOD_FIELD =
  "How the match was made, as the API sends it. Registry path: registry package (an advisory record EchelonGraph holds names the package for the CVE), or cna package url (none does, and the CVE record's CNA names the package by package URL: its statement is the only source, matched_criteria is that purl as the CNA wrote it, version_evidence is cna_affected_range and match_confidence 0.8). CPE path: the CPE matcher's method. A later value is relayed too.";
// The reasons core-backend gives an undetermined CVE (cve/pkgmatch.go Undetermined*, cve/pkgmatch_cnapurl.go): named in
// a description, not an enum, so a reason a later API adds is relayed as it is today. On the CPE path (#3151)
// version_not_comparable comes from a CPE range, not an advisory record, and the sentence says so.
export const UNDETERMINED_REASON_FIELD =
  "Why the CVE could not be decided at this version, as the API sends it: for an advisory record, such as no_version_data, version_not_comparable, git_range_only or collapsed_fix_boundary (on the CPE path, version_not_comparable: a CPE range the version has no order against); where the CVE record's CNA statements could not be read against it, a cna_range_ reason (such as cna_range_truncated, cna_range_unreadable, cna_range_unplaceable or cna_range_conflict). For a CVE no advisory record names the package for, decided on its CNA's statement alone, also cna_range_status_unknown (no statement of the CNA's calls the version affected or unaffected) and cna_range_undecidable_scheme (the CNA states the package's versions in a version scheme the matcher cannot order, such as custom or git). Not a finding of not affected. A later value is relayed too.";

export const FIXED_IN_DISPUTE_FIELD =
  "Once EchelonGraph's API serves it, set where the API found the CVE record's CNA and the advisory disagreeing on the range that holds this version. kind: fixed (they disagree on where the package is fixed) or introduced (the CNA's range starts below where the advisory's does). The advisory's bound in dispute, exactly one of advisory_fixed, advisory_last_affected and advisory_introduced, as the advisory's own statement gives it (advisory_listed: it lists affected versions rather than a range, and the bound is a version it lists), and advisory_id, the advisory. cna (name, short_name), cna_product (what the CNA's entry names, as the API reads it) and cna_range (version, less_than or less_than_or_equal, status, version_type; changes, each {at, status}, where the range's status changes inside it, with changes_truncated where the record held more): the CNA's range in dispute, as the API reads the record (where higher is cna, the CNA's range that reaches past the advisory's bound: on a cna_affected_range match it holds the version, and on an advisory_interval or exact_version_list match it holds the advisory's bound past the version (its fix, or the versions just above its last affected or listed version), so it may start above the version; where higher is advisory, the CNA's range that ends below it, the CNA saying the version is fixed), from an entry the record writes, or, with cna_range_default true, a span no entry writes that the record's defaultStatus covers. higher: the source the answer follows, the more conservative one (cna or advisory). note: the API's sentence on the dispute and what the answer does with it, relayed verbatim. Fields and values a later API adds are relayed. Its absence is not a finding that the CNA agrees: an API that does not serve it yet, or older than the field, sends none; one that serves it reads a CNA's ranges only where it applies them and only from an entry it matches to the package; and a match the CNA's range alone raises may carry none.";

/** A CVE record's affected version entry as core-backend serves it (cna_record.go AffectedRangeVersion): get_cve's
 *  affected_ranges[].versions[], and fixed_in_dispute.cna_range. Tolerant of fields a later API adds. */
export function affectedRangeVersionSchema() {
  return z.looseObject({
    version: opt(z.string()),
    status: opt(z.string()),
    less_than: opt(z.string()),
    less_than_or_equal: opt(z.string()),
    version_type: opt(z.string()),
    changes: opt(z.array(z.looseObject({ at: opt(z.string()), status: opt(z.string()) }))),
    changes_truncated: opt(z.boolean()),
  });
}

/** The object, tolerant of fields and values a later API adds (core-backend pkgmatch_fixedin.go FixedInDispute). */
export function fixedInDisputeSchema() {
  return opt(
    z.looseObject({
      // fixed or introduced. A value a later API adds is relayed, never a failed call.
      kind: open(["fixed", "introduced"]),
      advisory_id: opt(z.string()),
      // Exactly one is set, the bound the advisory's statement gives for kind.
      advisory_fixed: opt(z.string()),
      advisory_last_affected: opt(z.string()),
      advisory_introduced: opt(z.string()),
      advisory_listed: opt(z.boolean()),
      cna: opt(z.looseObject({ name: opt(z.string()), short_name: opt(z.string()) })),
      cna_product: opt(z.string()),
      cna_range: opt(affectedRangeVersionSchema()),
      // #3391's fourth round: cna_range is the span the CNA's defaultStatus covers, not an entry its record writes.
      cna_range_default: opt(z.boolean()),
      // cna or advisory. A value a later API adds is relayed, never a failed call.
      higher: open(["cna", "advisory"]),
      note: opt(z.string()),
    }),
  ).describe(FIXED_IN_DISPUTE_FIELD);
}

/** fixed_in_dispute at a structured cut's leanest level (round 11, the round-10 verify's d5 F6): every field but the
 *  note, which the note block quotes (clipped) and the richer levels keep whole. A note of any length then cannot make
 *  the cut drop the matches, the undisputed ones with it, while fixed_in keeps the dispute whose source it follows. */
export const DISPUTE_THIN: readonly string[] = [
  "kind", "advisory_id", "advisory_fixed", "advisory_last_affected", "advisory_introduced", "advisory_listed", "cna", "cna_product", "cna_range",
  "cna_range_default", "higher",
];
/** A dispute note clipped as the note block clips it (NOTE_DISPUTE_CLIP), marked with an ellipsis. */
export function clipDisputeNote(s: string): string {
  return s.length <= NOTE_DISPUTE_CLIP ? s : `${s.slice(0, NOTE_DISPUTE_CLIP - 1)}…`;
}
// Round 11 (the round-10 verify's d5 F7, and the round-11 review's F1): a fixed_in_dispute this server cannot read (not
// an object, or a field of another type than its schema names) is relayed empty ({}) instead of as sent, so one
// malformed optional annotation cannot fail the call and lose every row with it, and its match stays disputed: every
// sentence that reads a dispute reads it as one sent without a note or a higher, as it already reads those (its fixed_in
// is not called the advisory's). The walk goes at most DISPUTE_WALK_DEPTH objects deep (check_sbom's
// data.results[].matches[] is 4); the note names each match it blanked.
const DISPUTE_WALK_DEPTH = 8;
/** Blanks every fixed_in_dispute in `data` that fixedInDisputeSchema refuses, in place; returns where each was: its
 *  match's cve_id, with the purl of the row holding it where there is one. */
export function blankUnreadableDisputes(data: unknown): string[] {
  const schema = fixedInDisputeSchema();
  const where: string[] = [];
  const walk = (v: unknown, depth: number, purl: string | undefined): void => {
    if (depth > DISPUTE_WALK_DEPTH || v === null || typeof v !== "object") return;
    if (Array.isArray(v)) {
      for (const e of v) walk(e, depth + 1, purl);
      return;
    }
    const o = v as Record<string, unknown>;
    const here = typeof o.purl === "string" ? o.purl : purl;
    if ("fixed_in_dispute" in o && !schema.safeParse(o.fixed_in_dispute).success) {
      const blank = {};
      UNREAD.add(blank);
      o.fixed_in_dispute = blank;
      const id = typeof o.cve_id === "string" && o.cve_id !== "" ? o.cve_id : "the answer";
      where.push(here ? `${id} (${here})` : id);
    }
    for (const k of Object.keys(o)) if (k !== "fixed_in_dispute") walk(o[k], depth + 1, here);
  };
  walk(data, 0, undefined);
  return where;
}
/** The note's sentence for what blankUnreadableDisputes blanked, naming each (at most NOTE_DISPUTES_MAX), or "". `of`
 *  is what carried it: a tool's matches, or (cve_remediation) its one answer. */
export function unreadDisputesSentence(where: readonly string[], of: "match" | "answer" = "match"): string {
  if (where.length === 0) return "";
  const shown = where.slice(0, NOTE_DISPUTES_MAX).join("; ");
  const more = where.length > NOTE_DISPUTES_MAX ? `; and ${where.length - NOTE_DISPUTES_MAX} more` : "";
  const rest = "not in the shape this server reads";
  if (of === "answer") {
    return where.length === 1
      ? ` The fixed_in_dispute the API sent on ${shown} was ${rest}, so it is relayed empty ({}): the answer is still disputed, and its fixed_in may follow the CVE record's CNA, not the advisory.`
      : ` The fixed_in_dispute values the API sent on ${shown}${more} were ${rest}, so each is relayed empty ({}): the answer is still disputed, and its fixed_in may follow the CVE record's CNA, not the advisory.`;
  }
  return where.length === 1
    ? ` The fixed_in_dispute the API sent on ${shown} was ${rest}, so it is relayed empty ({}): the match is still disputed, and its fixed_in may follow the CVE record's CNA, not the advisory.`
    : ` The fixed_in_dispute values the API sent on ${where.length} matches (${shown}${more}) were ${rest}, so each is relayed empty ({}): each match is still disputed, and its fixed_in may follow the CVE record's CNA, not the advisory.`;
}
// The empty objects blankUnreadableDisputes put in place of what it could not read (round 11's final check, F1-a): a
// note sentence says its value was unreadable, never that the API sent no note, since the value it replaced may have
// carried one.
const UNREAD = new WeakSet<object>();
/** Whether `v` is an empty object blankUnreadableDisputes put in place of a value it could not read. */
export function isUnreadDispute(v: unknown): boolean {
  return v !== null && typeof v === "object" && UNREAD.has(v);
}
/** Whether a match's (or an answer's) fixed_in_dispute is set: an object, whatever it holds. */
export function isDispute(v: unknown): v is object {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** The dispute's note, as the API wrote it, or undefined where the value carries none. */
export function disputeNote(v: unknown): string | undefined {
  if (!isDispute(v)) return undefined;
  const note = (v as { note?: unknown }).note;
  return typeof note === "string" && note.trim() !== "" ? note.trim() : undefined;
}

// The note's sentence on the matches that carry one: the first NOTE_DISPUTES_MAX, each named and its note quoted
// verbatim, so a long list cannot grow the note without bound. core-backend's notes are two or three sentences (under
// 300 characters); one past NOTE_DISPUTE_CLIP, which no note of core-backend's reaches, is cut there, marked with an
// ellipsis, and is whole in the match's fixed_in_dispute.
const NOTE_DISPUTES_MAX = 5;
const NOTE_DISPUTE_CLIP = 1000;
export type Disputed = { where: string; note?: string; unread?: boolean };

/** Each match of `matches` carrying a fixed_in_dispute, with its note where it has one, named by its cve_id and, with
 *  `of`, what it matched. */
export function disputedOf(matches: unknown, of?: string): Disputed[] {
  if (!Array.isArray(matches)) return [];
  const out: Disputed[] = [];
  for (const m of matches) {
    if (m === null || typeof m !== "object") continue;
    const v = (m as { fixed_in_dispute?: unknown }).fixed_in_dispute;
    if (!isDispute(v)) continue;
    const note = disputeNote(v);
    const cve = (m as { cve_id?: unknown }).cve_id;
    const id = typeof cve === "string" && cve !== "" ? cve : "a match";
    out.push(isUnreadDispute(v) ? { where: of ? `${id} (${of})` : id, unread: true } : { where: of ? `${id} (${of})` : id, note });
  }
  return out;
}

/** " fixed_in_dispute on N matches: ..." for the note, or "" when none carries one. */
export function disputesSentence(found: readonly Disputed[]): string {
  if (found.length === 0) return "";
  const shown = found.slice(0, NOTE_DISPUTES_MAX).map((d) =>
    d.unread ? `${d.where}: (its value was not in the shape this server reads)` : d.note === undefined ? `${d.where}: (the API sent no note)` : `${d.where}: "${clipDisputeNote(d.note)}"`,
  );
  const more = found.length > NOTE_DISPUTES_MAX ? `; and ${found.length - NOTE_DISPUTES_MAX} more, each in its match's fixed_in_dispute` : "";
  const n = found.length === 1 ? "1 match" : `${found.length} matches`;
  return ` fixed_in_dispute on ${n}: the CVE record's CNA and the advisory disagree on the range that holds the version; the API's note on each, verbatim: ${shown.join("; ")}${more}.`;
}
