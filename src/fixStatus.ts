// fix_status (#2841, #2518 item 3): the API's fix-status rule for a CVE (core-backend
// internal/cve/fixstatus.go, the rule CVE Pulse pages render), as get_cve's remediation summary
// (its first field) and cve_remediation's answer carry it. Relayed, never derived here.
//
// A module of its own, importing only zod: index.ts and tools/cve_remediation.ts import each
// other, so a const shared between them would be read before it is initialised whichever loads
// first.
import * as z from "zod";

export const FIX_STATES = ["available", "fix_referenced", "fix_merged", "none_confirmed", "unknown"] as const;

export const FIX_STATUS_FIELD =
  "The API's fix-status rule for the CVE, the one CVE Pulse pages show: state is available (a fix is on record), fix_referenced (a reference tagged Patch, often a source commit, and no release confirmed), fix_merged (an upstream fix merged, not yet in a tagged release), none_confirmed (no fix evidence on record, which is not a finding that no fix exists) or unknown (an input could not be read). basis is the step of the rule that decided it; described_by is the CVE description's sentence naming the fix, solution_by the CVE record's solution sentence naming it (statement) and the CNA that wrote it (cna), stated_in_record that patch_evidence counts a fix the CVE record states with no sentence to quote, listed_in_patch_table that a fixed version or patch row is on record; unread_inputs names any input the API could not read. vendor_released (basis vendor_fix_released) is the vendor's own statement that a fix is released where the CVE record names no fixed version: its sentence, verbatim (statement, or null), never a version, so the fixed release is the vendor advisory's to name. solution_by's section is workarounds when the fix sentence is the record's workaround, not its solution.";

const opt = <T extends z.ZodType>(t: T) => t.nullable().optional();

export function fixStatusSchema() {
  return z
    .looseObject({
      // A state a later API adds is admitted, never a failed call.
      state: opt(z.union([z.enum(FIX_STATES), z.string()])),
      basis: opt(z.string()),
      described_by: opt(z.string()),
      // #3076 (merged from 24dad5eb): the CVE record's own fix sentence, and its CNA.
      solution_by: opt(z.looseObject({ statement: opt(z.string()), cna: opt(z.string()), section: opt(z.string()) })),
      stated_in_record: opt(z.boolean()),
      listed_in_patch_table: opt(z.boolean()),
      // #3076, third pass: the vendor's released-fix statement with no version (cause G).
      vendor_released: opt(z.looseObject({ statement: opt(z.string()) })),
      unread_inputs: opt(z.array(z.string())),
    })
    .nullable()
    .optional()
    .describe(FIX_STATUS_FIELD);
}
