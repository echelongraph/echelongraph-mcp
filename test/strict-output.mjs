// #3121, #3268: the suite's own outputSchema check, closed where the published one is open.
//
// Since 3.0.2 every tool's published outputSchema leaves its success branch open to top-level
// fields it does not name, and since #3268 open at every level: each object admits fields it does
// not name and each enum any string (src/index.ts envelopeSchema, openSuccess). So a client that
// listed the tools before an upgrade still validates an answer carrying a field or value added
// since: through 3.0.0 the root was closed, and a Claude Code session that listed the tools under
// 2.7.2 failed every check_sbom call once 3.0.0 added data_truncated and truncated, until it
// reconnected. The suite still wants to know when this server sends a field or a value its schema
// does not name, so every test that validates an answer against tools/list's outputSchema does it
// through StrictOutputValidator: the closed copy this server holds its own answers to (checked(),
// STRICT), closed wherever its tool closed it, as index.ts closedOutputSchema gives it for the
// published schema. open-success.test.mjs holds the published branch open at every level, and the
// closed copy closed, for every tool, with controls.
import path from "node:path";
import { pathToFileURL } from "node:url";
import { AjvJsonSchemaValidator } from "@modelcontextprotocol/server/validators/ajv";
import { PKG_DIR } from "./server-under-test.mjs";

const isSuccess = (b) => Array.isArray(b?.properties?.state?.enum) && b.properties.state.enum.some((s) => s === "measured" || s === "not_assessed");

// The build's own schemas, loaded as http.ts loads index.ts (no stdio server in this process), and
// every tool's envelope built: the tool modules build theirs on their first registration.
const dist = (f) => pathToFileURL(path.join(PKG_DIR, "dist", f)).href;
(await import(dist("runtime.js"))).markHttpEntrypoint();
const I = await import(dist("index.js"));
I.createServer();

/**
 * The closed copy of `schema`, a tools/list outputSchema: the one this server checks its own
 * answers against. For a schema this build did not publish (a test's edited copy of one), each
 * success branch closed at its root (additionalProperties false); the same object when it holds
 * no success branch.
 */
export function strictOutputSchema(schema) {
  if (!schema || !Array.isArray(schema.oneOf) || !schema.oneOf.some(isSuccess)) return schema;
  const closed = I.closedOutputSchema?.(schema);
  if (closed) return closed;
  if (!schema.oneOf.some((b) => isSuccess(b) && b.additionalProperties !== false)) return schema;
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
