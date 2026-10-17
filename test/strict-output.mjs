// #3121: the suite's own outputSchema check, closed where the published one is open.
//
// Since 3.0.2 every tool's published outputSchema leaves its success branch open to top-level
// fields it does not name (src/index.ts envelopeSchema), so a client that listed the tools before
// an upgrade still validates an answer carrying a field added since: through 3.0.0 the branch was
// closed, and a Claude Code session that listed the tools under 2.7.2 failed every check_sbom call
// once 3.0.0 added data_truncated and truncated, until it reconnected. The suite still wants to know
// when this server sends a field its schema does not name, so every test that validates an answer
// against tools/list's outputSchema does it through StrictOutputValidator: the same schema with the
// success branch closed again (additionalProperties false), which is what 3.0.0 published and what
// the server's own checked() holds its answers to. tools.test.mjs holds the published branch open
// for every tool, with a control that closes it.
import { AjvJsonSchemaValidator } from "@modelcontextprotocol/server/validators/ajv";

const isSuccess = (b) => Array.isArray(b?.properties?.state?.enum) && b.properties.state.enum.some((s) => s === "measured" || s === "not_assessed");

/** `schema` with each success branch of its oneOf closed (additionalProperties false); the same object when none is open. */
export function strictOutputSchema(schema) {
  if (!schema || !Array.isArray(schema.oneOf) || !schema.oneOf.some((b) => isSuccess(b) && b.additionalProperties !== false)) return schema;
  return { ...schema, oneOf: schema.oneOf.map((b) => (isSuccess(b) ? { ...b, additionalProperties: false } : b)) };
}

// One closed copy per published schema object, so the validator compiles each once.
const closed = new WeakMap();

export class StrictOutputValidator extends AjvJsonSchemaValidator {
  getValidator(schema) {
    if (schema === null || typeof schema !== "object") return super.getValidator(schema);
    if (!closed.has(schema)) closed.set(schema, strictOutputSchema(schema));
    return super.getValidator(closed.get(schema));
  }
}
