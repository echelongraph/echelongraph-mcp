// #3345 (CVE-2023-54404, GHSA-mrhx-c7xc-m3w5): every list and every record in a tool's
// inputSchema has an upper bound, checked before any element of it is parsed.
//
// zod through 4.6.5 parsed every element of a container before checking its size, so a huge list
// or object cost its full parse whatever its bound. 4.6.6 checks a leading .max(), .length() or
// .size() of a z.array, z.set or z.map first, and refuses an oversized one before parsing any
// element (core/schemas.ts capSize; only the checks before any other check, so .max() comes first
// in each chain). A container without a bound is still parsed whole, and z.record has no size
// check at all. So each list here is .max()'d first, and a record is boundedRecord(): an identity
// transform whose check counts the object's own members and refuses past `max` before the record
// parses a key or value, piped into the record, the way zod's own fromJSONSchema enforces
// maxProperties (classic/from-json-schema.ts checkObjectGuards). tools/list publishes maxItems and
// maxProperties; test/input-bounds.test.mjs walks every tool's inputSchema and fails on a list or
// record without one.
//
// The SDK's element limit (index.ts MAX_TOOL_INPUT_ELEMENTS, CVE-2026-111768) bounds a call's
// arguments as a whole; these bound each container to what its tool documents.
import * as z from "zod";

/**
 * A z.record(z.string(), value) of at most `max` own members, refused past `max` before any key or
 * value is parsed (as a too_big issue of origin "object"), and published with maxProperties.
 */
export function boundedRecord<V extends z.ZodType>(value: V, max: number) {
  const guard = z.transform((v: unknown) => v).check((payload) => {
    const v = payload.value;
    if (typeof v !== "object" || v === null || Array.isArray(v)) return;
    // Counted up to max + 1 only: an oversized object costs no more than that.
    let n = 0;
    for (const k in v) if (Object.prototype.hasOwnProperty.call(v, k) && ++n > max) break;
    if (n > max) {
      payload.issues.push({ origin: "object", code: "too_big", maximum: max, inclusive: true, message: `Too big: expected object to have <=${max} properties`, input: v, continue: false });
    }
  });
  return guard.pipe(z.record(z.string(), value)).meta({ maxProperties: max });
}
