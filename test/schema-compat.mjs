#!/usr/bin/env node
// #3268: does a release candidate add anything a client holding the last release's tool list
// refuses? A client validates every answer against the outputSchema it listed, and the hosted
// endpoint never tells it to list again (stateless, listChanged false). So a property added under
// an object the old release published with additionalProperties false, or a value added to an enum
// it published closed, fails every such client on every call of that tool until it reconnects.
// 2.6.2 to 2.6.3 (a patch) added `window` under three closed exposure_radar objects, and 2.6.5 to
// 2.7.0 added fields under epss_history's closed coverage and the vendor tools' vendor_window(s).
//
// Since #3268 every success branch is published open at every level (open-success.test.mjs holds
// it), and since its review the success branch's null-only freshness and coverage slots are null
// or an open object, so against a release with that change an added property or value is a finding
// only in the failure branch, closed by decision (#3121); a widened type (a field made nullable, a
// number where an integer was) is one anywhere. Against 3.0.2 or older (closed below the success
// root) it reads every level.
//
//   node test/schema-compat.mjs [--allow <file>] <old> [<new>]   compare; <new> defaults to this package
//   node test/schema-compat.mjs --dump [<pkg>]                   print a package's tools/list as JSON
//
// A finding is a property added under an object the old release closed, a value added to an enum
// it closed, or a node whose type the candidate widens (the old type set a strict subset of the
// new one's: null to null|object, string to null|string, integer to number).
//
// --allow <file> (scripts/npm-publish-mcp.sh's dry run passes test/schema-compat-allow.json): the
// findings a release accepts, each with why, as { "accepted": [{ "against": "<old version>",
// "finding": "<the line as printed>", "reason": "..." }] }. Only entries whose `against` is the old
// release's version apply. With it the exit is 1 only for a finding the file does not list, and an
// entry without a reason, or a file that cannot be read, is exit 2. A listed finding no longer found
// is printed (remove it) and does not fail.
//
// <old> and <new> are each a tools/list JSON file ({ "tools": [...] }, as --dump prints it), or a
// package directory whose dist/index.js is started over stdio with no API reachable (tools/list
// needs none). For the last published release: `npm pack echelongraph-mcp@latest`, unpack it, and
// `npm install --omit=dev` inside the unpacked package/ directory, then pass that directory.
// Exit 1 naming each finding, unless the candidate's major version is above the old one's (a major
// release may break cached clients, and says so in its CHANGELOG); exit 0 with none; exit 2 when it
// could not run.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { isFailureBranch, isNode, isSuccessBranch, typeSetOf } from "./schema-openness.mjs";

const isClosedEnum = (n) => (Array.isArray(n.enum) && n.enum.length > 0 && n.enum.every((v) => typeof v === "string")) || typeof n.const === "string";
const isAnyString = (n) => isNode(n) && n.type === "string" && Object.keys(n).every((k) => k === "type" || k === "description");
// Every string value a node lists, directly or in the branches of its unions.
function valuesAt(n, out = new Set()) {
  if (!isNode(n)) return out;
  for (const v of n.enum ?? []) if (typeof v === "string") out.add(v);
  if (typeof n.const === "string") out.add(n.const);
  for (const k of ["anyOf", "oneOf"]) for (const b of n[k] ?? []) valuesAt(b, out);
  return out;
}
const typesOf = (n) => (isNode(n) ? [].concat(n.type ?? (n.properties ? "object" : [])).sort().join("|") : "");
// The new branch an old union branch became: by state at an envelope's root, else by type, else by place.
function matchBranch(old, news, i) {
  if (isSuccessBranch(old)) return news.find(isSuccessBranch);
  if (isFailureBranch(old)) return news.find(isFailureBranch);
  const t = typesOf(old);
  const same = news.filter((b) => typesOf(b) === t);
  return same.length === 1 ? same[0] : news[i];
}

// Whether `nt` (undefined: any value) admits every type `ot` does and one more: an integer is a number.
const covers = (set, t) => set.includes(t) || (t === "integer" && set.includes("number"));
const widens = (ot, nt) => (nt === undefined ? true : ot.every((t) => covers(nt, t)) && nt.some((t) => !covers(ot, t)));

function compare(o, n, p, out, openEnum = false) {
  if (!isNode(o) || !isNode(n)) return;
  const where = p || "(root)";
  // A type the old release did not admit at a node (its type set a strict subset of the new one's):
  // a client holding the old list refuses that answer the moment the new release sends it. 3.0.2
  // published freshness as { type: "null" } in 14 tools, and #3276 answers cve_summary's freshness
  // as an object; no property is added under a closed object and no enum value is added, so only
  // this reads it (#3268's review).
  const ot = typeSetOf(o);
  const nt = typeSetOf(n);
  if (ot && widens(ot, nt)) out.push(`${where}: widens its type from ${ot.join("|")} to ${nt ? nt.join("|") : "any value"}`);
  if (o.additionalProperties === false) {
    const had = new Set(Object.keys(o.properties ?? {}));
    const added = Object.keys(n.properties ?? {}).filter((k) => !had.has(k));
    if (added.length) out.push(`${where}: adds ${added.join(", ")} under an object the old release closed`);
  }
  if (isClosedEnum(o) && !openEnum) {
    const had = valuesAt(o);
    const added = [...valuesAt(n)].filter((v) => !had.has(v));
    if (added.length) out.push(`${where}: adds ${added.map((v) => JSON.stringify(v)).join(", ")} to an enum the old release closed`);
  }
  const at = (k) => (p ? `${p}.${k}` : k);
  if (isNode(o.properties) && isNode(n.properties)) for (const [k, s] of Object.entries(o.properties)) compare(s, n.properties[k], at(k), out);
  if (isNode(o.items)) compare(o.items, n.items, `${p}[]`, out);
  if (isNode(o.additionalProperties) && isNode(n.additionalProperties)) compare(o.additionalProperties, n.additionalProperties, at("*"), out);
  for (const k of ["anyOf", "oneOf", "allOf"]) {
    if (!Array.isArray(o[k])) continue;
    const open = k === "anyOf" && o[k].some(isAnyString);
    // A node the new release wrapped in a union (an enum opened, a value made nullable) is read
    // against the old node itself.
    const news = Array.isArray(n[k]) ? n[k] : Array.isArray(n.anyOf) ? n.anyOf : [n];
    o[k].forEach((b, i) => compare(b, matchBranch(b, news, i), p, out, open));
  }
  if (!Array.isArray(o.anyOf) && Array.isArray(n.anyOf) && !isClosedEnum(o)) {
    const t = typesOf(o);
    const b = n.anyOf.find((x) => typesOf(x) === t);
    if (b) compare(o, b, p, out, openEnum);
  }
}

/** What the candidate's tools/list adds that a client holding the old one refuses: "<tool>: <path>: ..." each. */
export function compatProblems(oldTools, newTools) {
  const out = [];
  for (const o of oldTools) {
    const n = newTools.find((t) => t.name === o.name);
    if (!n || !o.outputSchema || !n.outputSchema) continue;
    const found = [];
    compare(o.outputSchema, n.outputSchema, "", found);
    for (const f of new Set(found)) out.push(`${o.name}: ${f}`);
  }
  return out;
}

const HERE = path.dirname(fileURLToPath(import.meta.url));
async function toolsOf(source) {
  const stat = fs.statSync(source);
  if (stat.isFile()) {
    const j = JSON.parse(fs.readFileSync(source, "utf8"));
    const tools = j.tools ?? j.result?.tools;
    if (!Array.isArray(tools)) throw new Error(`${source}: no tools array`);
    return { tools, version: j.version ?? j.serverInfo?.version };
  }
  const entry = path.join(source, "dist", "index.js");
  if (!fs.existsSync(entry)) throw new Error(`${source}: no dist/index.js (build it, or pass a tools/list JSON file)`);
  const { connect } = await import(pathToFileURL(path.join(HERE, "mcp-stdio-client.mjs")).href);
  const client = await connect({ command: process.execPath, args: [entry], cwd: source, env: { ...process.env, ECHELONGRAPH_API_BASE: "http://127.0.0.1:9" }, stderr: "ignore" });
  try {
    const { tools } = await client.listTools();
    const version = JSON.parse(fs.readFileSync(path.join(source, "package.json"), "utf8")).version;
    return { tools, version };
  } finally {
    await client.close();
  }
}
const major = (v) => (typeof v === "string" && /^\d+\./.test(v) ? Number(v.split(".")[0]) : undefined);

// The entries of an allow-list file that apply against `oldVersion`, each with its reason; throws on
// a file that is not one, or an entry that gives no reason (an acceptance nobody explained).
export function allowedFindings(json, oldVersion) {
  const entries = json?.accepted;
  if (!Array.isArray(entries)) throw new Error('an allow-list is { "accepted": [{ "against", "finding", "reason" }] }');
  const out = new Map();
  entries.forEach((e, i) => {
    for (const k of ["against", "finding", "reason"]) if (typeof e?.[k] !== "string" || !e[k].trim()) throw new Error(`allow-list entry ${i} has no ${k}`);
    if (e.against === oldVersion) out.set(e.finding, e.reason);
  });
  return out;
}

async function main(argv) {
  let allowFile;
  if (argv[0] === "--allow") {
    allowFile = argv[1];
    if (!allowFile) {
      console.error("--allow needs a file");
      return 2;
    }
    argv = argv.slice(2);
  }
  if (argv[0] === "--dump") {
    const { tools, version } = await toolsOf(argv[1] ?? path.resolve(HERE, ".."));
    process.stdout.write(`${JSON.stringify({ version, tools }, null, 1)}\n`);
    return 0;
  }
  if (!argv[0]) {
    console.error("usage: node test/schema-compat.mjs <old tools/list JSON or package dir> [<new>]");
    return 2;
  }
  const old = await toolsOf(argv[0]);
  const allowed = allowFile === undefined ? new Map() : allowedFindings(JSON.parse(fs.readFileSync(allowFile, "utf8")), old.version);
  const cand = await toolsOf(argv[1] ?? path.resolve(HERE, ".."));
  const problems = compatProblems(old.tools, cand.tools);
  const label = `${old.version ?? "old"} -> ${cand.version ?? "candidate"}`;
  for (const f of allowed.keys()) if (!problems.includes(f)) console.log(`schema-compat ${label}: ${allowFile} accepts "${f}", which is no longer found: remove the entry.`);
  if (!problems.length) {
    console.log(`schema-compat ${label}: 0 findings: nothing added under an object or to an enum the old release closed, and no type widened (${old.tools.length} tools read).`);
    return 0;
  }
  const majorBump = major(cand.version) !== undefined && major(old.version) !== undefined && major(cand.version) > major(old.version);
  const unlisted = problems.filter((p) => !allowed.has(p));
  console.log(`schema-compat ${label}: ${problems.length} finding(s): a client holding the old tool list may refuse these answers until it reconnects:`);
  for (const p of problems) console.log(`  ${allowed.has(p) ? "accepted" : "NOT ACCEPTED"}  ${p}${allowed.has(p) ? `  (${allowed.get(p)})` : ""}`);
  if (majorBump) {
    console.log("A major release: allowed, if its CHANGELOG tells clients to reconnect.");
    return 0;
  }
  if (allowFile !== undefined && !unlisted.length) {
    console.log(`schema-compat ${label}: every finding is accepted in ${allowFile}, each with its reason; its CHANGELOG must tell clients holding the old list to reconnect.`);
    return 0;
  }
  if (allowFile !== undefined) console.log(`schema-compat ${label}: ${unlisted.length} finding(s) not accepted in ${allowFile}: list each with its reason (and say it in the CHANGELOG), or change the schema.`);
  return 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e) => {
      console.error(`schema-compat could not run: ${e?.message ?? e}`);
      process.exit(2);
    },
  );
}
