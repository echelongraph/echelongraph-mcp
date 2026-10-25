// #3015: arguments that break a tool's inputSchema are answered like every other refusal: the full
// envelope, state invalid_input, isError true, its notes naming each argument and the rule it broke.
//
// The SDK (@modelcontextprotocol/server 2.1.0, McpServer's tools/call handler) validates the
// arguments against the registered inputSchema before the tool's handler runs, and turns a failure
// into a bare error result of its own: one text block ("Input validation error: Invalid arguments for
// tool search_cves: limit: Too big: expected number to be <=50"), isError true, no structuredContent,
// so no state and no notes. The README's "every result, success or failure, carries
// structuredContent" and the server instructions' "Every result carries state, …" were untrue of it,
// and a client keyed on state never saw invalid_input.
//
// So every tool is registered with its inputSchema wrapped (withSchemaRefusal, called by createServer
// before any tool is registered). The wrapper is the same Standard Schema: its jsonSchema is the
// original's own, so tools/list publishes the inputSchema byte for byte as before
// (test/schema-refusal.test.mjs holds it to the schemas recorded before this change), and on
// arguments the original accepts its validate answers exactly what the original answers (zod's
// parsed value, defaults applied). Only on arguments the original refuses does it differ: it answers
// a Refused marker instead of the issues, so the SDK's check passes, and the handler the wrapper
// registers answers the refusal's envelope for that marker without running the tool. One wrapper for
// both transports and every protocol era: the npm package's stdio and the hosted endpoint build the
// same server (createServer), and the SDK's tools/call handler is the same in every era.
//
// The notes say which argument broke which rule, in the inputSchema's own terms (a bound, the allowed
// values, the JSON type); they never quote a value the caller sent, only its JSON type.
import type { McpServer, StandardSchemaWithJSON } from "@modelcontextprotocol/server";

// What a Standard Schema reports for one issue; zod's issues carry their code and the rule's terms
// beside the message, which is all this reads.
type PathItem = PropertyKey | { key: PropertyKey };
export type Issue = {
  message: string;
  path?: readonly PathItem[];
  code?: string;
  expected?: string;
  origin?: string;
  maximum?: number | bigint;
  minimum?: number | bigint;
  inclusive?: boolean;
  values?: readonly unknown[];
  keys?: readonly string[];
  format?: string;
  // invalid_union: each branch's own issues.
  errors?: readonly (readonly Issue[])[];
};

const REFUSED = Symbol("echelongraph-mcp.schema-refused");
type Refused = { [REFUSED]: { issues: readonly Issue[]; input: unknown } };
const isRefused = (v: unknown): v is Refused => typeof v === "object" && v !== null && REFUSED in v;

// How many issues the note names one by one; the rest are counted.
const ISSUES_NAMED = 5;

const keyOf = (p: PathItem): PropertyKey => (typeof p === "object" && p !== null ? p.key : p);
// files[0].filename, as a model reads an argument path.
function pathText(path: readonly PathItem[] | undefined): string {
  let out = "";
  for (const p of path ?? []) {
    const k = keyOf(p);
    out += typeof k === "number" ? `[${k}]` : out === "" ? String(k) : `.${String(k)}`;
  }
  return out;
}
// The value the caller sent at a path, to name its JSON type (never the value itself).
function valueAt(input: unknown, path: readonly PathItem[] | undefined): unknown {
  let v = input;
  for (const p of path ?? []) {
    if (v === null || typeof v !== "object") return undefined;
    v = (v as Record<PropertyKey, unknown>)[keyOf(p)];
  }
  return v;
}
function jsonType(v: unknown): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "an array";
  if (typeof v === "number") return Number.isInteger(v) ? "an integer" : "a number";
  if (typeof v === "object") return "an object";
  return typeof v === "string" ? "a string" : typeof v === "boolean" ? "a boolean" : typeof v;
}
const TYPE_NAMES: Record<string, string> = {
  string: "a string",
  number: "a number",
  int: "an integer",
  boolean: "a boolean",
  array: "an array",
  object: "an object",
  record: "an object",
  bigint: "an integer",
};
const listOf = (items: string[]): string => (items.length < 2 ? items.join("") : `${items.slice(0, -1).join(", ")} or ${items[items.length - 1]}`);
const bound = (n: number | bigint | undefined) => (typeof n === "bigint" ? n.toString() : typeof n === "number" ? String(n) : "?");

// One issue as "<argument> <rule>": the argument named by its path in the arguments, the rule in the
// inputSchema's terms. An issue this does not know is given in the schema library's own words.
export function issueText(issue: Issue, input: unknown): string {
  const at = pathText(issue.path);
  const name = at === "" ? "the arguments" : at;
  const sent = valueAt(input, issue.path);
  switch (issue.code) {
    case "invalid_type": {
      const want = TYPE_NAMES[issue.expected ?? ""] ?? issue.expected ?? "another type";
      if (sent === undefined) return `${name} is required (${want})`;
      if (issue.expected === "int" && typeof sent === "number") return `${name} must be an integer`;
      return `${name} must be ${want}, not ${jsonType(sent)}`;
    }
    case "too_big":
    case "too_small": {
      const big = issue.code === "too_big";
      const n = bound(big ? issue.maximum : issue.minimum);
      const cmp = issue.inclusive === false ? (big ? "less than" : "more than") : big ? "at most" : "at least";
      if (issue.origin === "string") return `${name} must be ${cmp} ${n} ${n === "1" ? "character" : "characters"} long`;
      if (issue.origin === "array" || issue.origin === "set") return `${name} must hold ${cmp} ${n} ${n === "1" ? "entry" : "entries"}`;
      return `${name} must be ${cmp} ${n}`;
    }
    case "invalid_value":
      return Array.isArray(issue.values) && issue.values.length
        ? `${name} must be ${issue.values.length === 1 ? "" : "one of "}${listOf(issue.values.map((v) => JSON.stringify(v)))}`
        : `${name}: ${issue.message}`;
    case "unrecognized_keys": {
      const keys = (issue.keys ?? []).map((k) => (at === "" ? k : `${at}.${k}`));
      return keys.length ? `${listOf(keys)} ${keys.length === 1 ? "is not an argument" : "are not arguments"} this tool takes` : `${name}: ${issue.message}`;
    }
    case "invalid_format":
      return `${name} must be ${issue.format ? `a valid ${issue.format}` : "in the format the inputSchema gives"}`;
    case "invalid_union": {
      // Each branch refused only the value's type: name the types the branches take.
      const types = (issue.errors ?? []).map((b) => (b.length === 1 && b[0].code === "invalid_type" && !b[0].path?.length ? TYPE_NAMES[b[0].expected ?? ""] : undefined));
      const named = types.length > 0 && types.every((t): t is string => t !== undefined) ? [...new Set(types)] : undefined;
      return named ? `${name} must be ${listOf(named)}, not ${jsonType(sent)}` : `${name} must take one of the forms the inputSchema allows, not ${jsonType(sent)}`;
    }
    default:
      return `${name}: ${issue.message}`;
  }
}

// The reason a refusal gives, as one clause: each issue in turn, then how many more there are.
export function refusalReason(issues: readonly Issue[], input: unknown): string {
  const named = issues.slice(0, ISSUES_NAMED).map((i) => issueText(i, input));
  const more = issues.length - named.length;
  return `the arguments do not fit this tool's inputSchema (tools/list): ${named.join("; ")}${more > 0 ? `; and ${more} more ${more === 1 ? "issue" : "issues"}` : ""}`;
}

type Settled = { value: unknown; issues?: undefined } | { issues: readonly Issue[] };
// The inputSchema a tool is registered with: `schema` itself for tools/list (its own jsonSchema,
// so the published JSON is the original's), and a validate that answers what `schema` answers for
// arguments it accepts, and a Refused marker, not the issues, for arguments it refuses.
export function lenientSchema<S extends StandardSchemaWithJSON>(schema: S): S {
  const std = schema["~standard"];
  const settle = (value: unknown, r: Settled): Settled => (r.issues && r.issues.length ? { value: { [REFUSED]: { issues: r.issues, input: value } } } : r);
  return {
    "~standard": {
      version: std.version,
      vendor: std.vendor,
      jsonSchema: std.jsonSchema,
      validate: (value: unknown) => {
        const r = std.validate(value) as Settled | Promise<Settled>;
        return r instanceof Promise ? r.then((x) => settle(value, x)) : settle(value, r);
      },
    },
  } as unknown as S;
}

type Handler = (args: unknown, ctx: unknown) => unknown;
type Register = (name: string, config: { inputSchema?: unknown } & Record<string, unknown>, cb: Handler) => unknown;
const isStandardSchema = (s: unknown): s is StandardSchemaWithJSON =>
  typeof s === "object" && s !== null && typeof (s as { "~standard"?: { validate?: unknown } })["~standard"]?.validate === "function";

/**
 * Makes every tool `server` registers from now on answer arguments that break its inputSchema with
 * `refuse(tool, reason)` (index.ts badInput: the invalid_input envelope), not the SDK's bare error.
 * Call it before the first registerTool. tools/list is unchanged.
 */
export function withSchemaRefusal<R>(server: McpServer, refuse: (tool: string, reason: string) => R): McpServer {
  const register = server.registerTool.bind(server) as unknown as Register;
  const wrapped: Register = (name, config, cb) => {
    if (!isStandardSchema(config.inputSchema)) return register(name, config, cb);
    return register(name, { ...config, inputSchema: lenientSchema(config.inputSchema) }, (args, ctx) => {
      if (!isRefused(args)) return cb(args, ctx);
      const { issues, input } = args[REFUSED];
      return refuse(name, refusalReason(issues, input));
    });
  };
  (server as unknown as { registerTool: Register }).registerTool = wrapped;
  return server;
}
