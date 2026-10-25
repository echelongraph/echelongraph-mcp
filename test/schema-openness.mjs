// #3268, #3257: where a tools/list outputSchema is closed, read off the JSON Schema a client is
// served, for the release check (open-success.test.mjs), the README's Versioning claim
// (readme.test.mjs) and the old-against-new comparison (schema-compat.mjs).
//
// A client validates every answer against the outputSchema it listed, and the hosted endpoint
// never tells it to list again (stateless, listChanged false). So wherever a release's success
// branch is closed, a field added there by a later release (or a value added to a closed enum)
// fails that client on every call, until it reconnects: #3121 at the root, #3268 below it.
//
// "Closed" here is what ajv refuses: an object with additionalProperties false, and a string enum
// or const that no plain { type: "string" } sits beside in an anyOf. A boolean const (truncated's
// thinned: true) is a type, not a list of values, and is not counted.

export const isNode = (x) => x !== null && typeof x === "object" && !Array.isArray(x);
const stateValues = (b) => (isNode(b) && Array.isArray(b.properties?.state?.enum) ? b.properties.state.enum : []);
export const isSuccessBranch = (b) => stateValues(b).some((s) => s === "measured" || s === "not_assessed");
export const isFailureBranch = (b) => stateValues(b).some((s) => s === "failed" || s === "invalid_input");
export const branchesOf = (schema) => [...(schema?.oneOf ?? []), ...(schema?.anyOf ?? [])].filter(isNode);
const isClosedEnum = (n) => (Array.isArray(n.enum) && n.enum.length > 0 && n.enum.every((v) => typeof v === "string")) || typeof n.const === "string";
const isAnyString = (n) => isNode(n) && n.type === "string" && Object.keys(n).every((k) => k === "type" || k === "description");
const isObjectNode = (n) => n.type === "object" || (Array.isArray(n.type) && n.type.includes("object")) || isNode(n.properties);
const isEmpty = (n) => isNode(n) && Object.keys(n).length === 0;

// The JSON types a node admits, its unions' branches included, as a sorted list; undefined where it
// names none (it admits any value). An enum or const counts as its values' types.
export function typeSetOf(n) {
  if (!isNode(n)) return undefined;
  const out = new Set([].concat(n.type ?? []));
  if (!out.size && isNode(n.properties)) out.add("object");
  const jsonType = (v) => (v === null ? "null" : Array.isArray(v) ? "array" : typeof v);
  if (!out.size) for (const v of Array.isArray(n.enum) ? n.enum : "const" in n ? [n.const] : []) out.add(jsonType(v));
  for (const k of ["anyOf", "oneOf"]) {
    if (!Array.isArray(n[k])) continue;
    for (const b of n[k]) {
      const t = typeSetOf(b);
      if (t === undefined) return undefined;
      for (const x of t) out.add(x);
    }
  }
  return out.size ? [...out].sort() : undefined;
}
const onlyNull = (n) => typeSetOf(n)?.join("|") === "null";

// Walks a schema node, calling visit(node, path, { openEnum, branch }) for each, path in the issue's
// notation: data.kev_exposure.newest_kev[].exposure_state, truncated.* for a map's values. A union's
// branches share their parent's path, and are visited with `branch` true. `skipState` leaves out a
// branch's own discriminator.
export function walkSchema(n, visit, p = "", { skipState = false, openEnum = false, branch = false } = {}) {
  if (!isNode(n)) return;
  visit(n, p, { openEnum, branch });
  const at = (k) => (p ? `${p}.${k}` : k);
  if (isNode(n.properties)) for (const [k, s] of Object.entries(n.properties)) if (!(skipState && k === "state")) walkSchema(s, visit, at(k));
  if (isNode(n.items)) walkSchema(n.items, visit, `${p}[]`);
  if (Array.isArray(n.prefixItems)) n.prefixItems.forEach((s, i) => walkSchema(s, visit, `${p}[${i}]`));
  if (isNode(n.additionalProperties) && !isEmpty(n.additionalProperties)) walkSchema(n.additionalProperties, visit, at("*"));
  for (const k of ["anyOf", "oneOf", "allOf"]) {
    if (!Array.isArray(n[k])) continue;
    const open = k === "anyOf" && n[k].some(isAnyString);
    for (const s of n[k]) walkSchema(s, visit, p, { openEnum: open, branch: true });
  }
}

/** Every place a success branch of `schema` is closed, "<path>: ..." each; [] when it is open at every level but its state. */
export function closedInSuccess(schema) {
  const out = new Set();
  for (const b of branchesOf(schema).filter(isSuccessBranch)) {
    walkSchema(
      b,
      (n, p, { openEnum, branch }) => {
        if (n.additionalProperties === false) out.add(`${p || "(root)"}: additionalProperties false`);
        // A slot that admits null alone (3.0.2's freshness and coverage where a tool had neither):
        // the object a later release puts there fails a client holding this list.
        if (!branch && p && onlyNull(n)) out.add(`${p}: admits only null`);
        if (isClosedEnum(n) && !openEnum) out.add(`${p}: closed enum ${JSON.stringify(n.enum ?? [n.const])}`);
        // A union nested in a success must be anyOf: an open discriminator would make oneOf's
        // branches overlap, and an answer matching two of them fails it.
        if (Array.isArray(n.oneOf)) out.add(`${p}: oneOf`);
      },
      "",
      { skipState: true },
    );
  }
  return [...out];
}

/** Whether every success branch's own state is a closed enum (it tells a success from a failure). */
export const successStateClosed = (schema) =>
  branchesOf(schema)
    .filter(isSuccessBranch)
    .every((b) => isClosedEnum(b.properties.state));

/** Every object of a failure branch of `schema` that admits a property it does not name; [] when it is closed at every level. */
export function openInFailure(schema) {
  const out = new Set();
  for (const b of branchesOf(schema).filter(isFailureBranch)) {
    walkSchema(b, (n, p) => {
      const ap = n.additionalProperties;
      if (isObjectNode(n) && (ap === undefined || ap === true || isEmpty(ap))) out.add(`${p || "(root)"}: admits fields it does not name`);
    });
  }
  return [...out];
}

/**
 * Every enum of a failure branch of `schema` that already admits any string beside the values it
 * lists (an enum in an anyOf beside a plain { type: "string" }), by path; [] when every one is closed.
 */
export function openEnumsInFailure(schema) {
  const out = new Set();
  for (const b of branchesOf(schema).filter(isFailureBranch)) {
    walkSchema(b, (n, p) => {
      if (Array.isArray(n.anyOf) && n.anyOf.some(isAnyString) && n.anyOf.some((x) => isNode(x) && isClosedEnum(x))) out.add(p);
    });
  }
  return [...out];
}
const listed = (xs) => (xs.length < 2 ? xs.join("") : `${xs.slice(0, -1).join(", ")} and ${xs[xs.length - 1]}`);

/**
 * #3257: the two sentences of the README's Versioning section that say what is open and what is
 * closed, as the schemas in `tools` (a tools/list answer) bear them out. Through 3.0.2 the README
 * said each tool's `data` schema stays closed, while `data` was open at its root for 14 of 16 tools
 * and 86 objects below a success's root, in and outside `data`, were closed; deriving the sentences
 * from the schemas keeps them from drifting again.
 */
export function versioningClaims(tools) {
  const closed = tools.flatMap((t) => closedInSuccess(t.outputSchema).map((c) => `${t.name} ${c}`));
  const stateClosed = tools.every((t) => successStateClosed(t.outputSchema));
  const open = tools.flatMap((t) => openInFailure(t.outputSchema).map((c) => `${t.name} ${c}`));
  const success = closed.length
    ? `A success's \`outputSchema\` is closed in ${closed.length} place${closed.length === 1 ? "" : "s"}: ${closed.join("; ")}`
    : `A success's \`outputSchema\` is open at every level: each object admits fields it does not name, and each enum ${stateClosed ? "but `state` " : ""}any string beside the values it lists`;
  // Each failure-branch enum that admits any string, as `path` in the tools that publish it there.
  const byPath = new Map();
  for (const t of tools) for (const p of openEnumsInFailure(t.outputSchema)) byPath.set(p, [...(byPath.get(p) ?? []), t.name]);
  const enums = [...byPath].map(([p, names]) => `\`${p}\` (${names.join(", ")})`);
  const count = [...byPath.values()].reduce((a, names) => a + names.length, 0);
  const words = ["no", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"];
  const failure = open.length
    ? `The failure branch admits fields it does not name: ${open.join("; ")}.`
    : count
      ? `The failure branch keeps every object closed, and every enum but ${words[count] ?? count}, which already accept any string: ${listed(enums)}.`
      : "The failure branch stays closed at every level.";
  return [success, failure];
}
