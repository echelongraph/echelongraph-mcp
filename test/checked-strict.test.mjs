// #3121's review: the published outputSchema's success branch admits top-level fields it does not
// name (a client holding an older tool list then still validates a newer answer), and this
// server's own check, index.ts checked(), holds every answer to the closed branch, so a field this
// server adds without naming it in the schema is caught here and not shipped. The review confirmed
// that at runtime; nothing in the suite pinned it.
//
// Control: checked() with `STRICT.get(schema) ?? schema` replaced by `schema` (the published, open
// branch) passes the unknown field, and the second case fails.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { pathToFileURL } from "node:url";
import * as z from "zod";
import { PKG_DIR } from "./server-under-test.mjs";

const dist = (f) => pathToFileURL(path.join(PKG_DIR, "dist", f)).href;
// As http.ts does before it loads index.ts, so that loading it starts no stdio server in this
// process (whose stdout is the test runner's).
(await import(dist("runtime.js"))).markHttpEntrypoint();
const I = await import(dist("index.js"));

const schema = I.envelopeSchema({ data: z.object({ a: z.number() }), coverage: null, freshness: null });
const ok = { state: "measured", measured_at: null, method: "x", coverage: null, freshness: null, notes: [], data: { a: 1 }, data_truncated: false };

describe("#3121's review: checked() holds this server's answers to the closed success branch", () => {
  it("an answer the schema names passes", () => {
    const r = I.checked("t", schema, { content: [], structuredContent: ok });
    assert.notEqual(r.isError, true, JSON.stringify(r.structuredContent));
  });

  it("an unknown top-level field is refused as unexpected_shape, naming the field", () => {
    const r = I.checked("t", schema, { content: [], structuredContent: { ...ok, a_field_added_later: true } });
    assert.equal(r.isError, true);
    assert.equal(r.structuredContent.state, "failed");
    assert.match(r.structuredContent.notes.join(" "), /did not match this tool's output schema \(.*a_field_added_later/);
  });

  it("the published schema of the same branch admits it: only the server's own check is closed", () => {
    const published = z.toJSONSchema(schema, { io: "output" });
    const measured = (published.oneOf ?? published.anyOf ?? [published]).find((b) => JSON.stringify(b).includes('"measured"'));
    assert.ok(measured, JSON.stringify(published).slice(0, 400));
    assert.notEqual(measured.additionalProperties, false, "the published success branch is closed");
  });
});
