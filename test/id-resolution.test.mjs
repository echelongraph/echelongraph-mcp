// #3448 (P4), held to the founder's claim limits of 2026-11-08 (binding): what this server says resolves to a CVE.
// Through 3.2.0 the CVE feed's method said only "ENISA EUVD identifiers resolve to their CVE.", and get_cve's cve_id
// said EchelonGraph resolves an EUVD, GHSA, OSV (PYSEC-, GO-, RUSTSEC-, GSD-, MAL-) or GCVE-0 ID to its CVE: a claim for
// every namespace it named, wider than what EchelonGraph has measured. No OSV rate is claimed (the founder's limit for
// #3448). The limits:
//   - ENISA EUVD and GCVE-0 IDs resolve to their CVE: the only two namespaces that do across the corpus;
//   - GitHub's is said in its measured form alone, GHSA_SENTENCE, verbatim (a probe of production on 2026-11-07:
//     195 of a seeded random 200 reviewed, non-withdrawn GHSA IDs with exactly one CVE alias, of 32,959), and nothing
//     broader is said of GHSA;
//   - an OSV ID may be listed as accepted, never as resolving beyond the alias table: a list that names them says
//     OSV_SENTENCE, verbatim, which is conditional and gives no rate.
// This file holds them, on what the server serves (the instructions; tools/list; the answers' method, notes and
// coverage; each prompt's description and prompts/get text; every resource's description and contents) and on the
// package's pages (README.md, docs/, server.json, package.json's description, every text file under listings/ where
// present, and the CHANGELOG's 3.2.1 section):
//   1. CLAIMS. Each sentence that says an identifier resolves ("resolve", "resolves", "resolved"; not resolved_from)
//      or tells a caller what to pass ("Pass a ...") is read for the namespaces it names, in any letter case and in
//      their common spellings (PyPI, Go, RustSec, Github). The exact GHSA_SENTENCE names GitHub, qualified, and the
//      exact OSV_SENTENCE names OSV, conditionally; any other may name EUVD and GCVE-0 alone. A negative clause ("does
//      not resolve", "maps to no") names no other namespace and states no percentage, and the rest of its sentence is
//      read as any other. A resolve sentence about IDs in general ("all six systems", "each of these") fails, and so
//      does one about IDs that names a namespace this file does not know. "97.5%" appears nowhere but in GHSA_SENTENCE.
//      resolved_from.source's values, where a text lists them ("(source osv)", "enisa_euvd, github or osv"), name what
//      mapped an ID, not a namespace said to resolve.
//   2. THE CLAIM TEXTS. The method of the tools that take an identifier (search_cves' and get_cve's answers, one
//      string), get_cve's cve_id, search_cves' resolved_from and docs/tools.md's section on these IDs each say what
//      resolves: the namespaces they advertise are exactly EUVD and GCVE-0, with GHSA_SENTENCE beside them, and
//      OSV_SENTENCE where they name an OSV ID. In them, and in get_cve's description, a claim in other words
//      ("resolvable", "maps to", "takes", "accepts") is read as one. The method names each one with its own source.
//      cve_summary takes no identifier: its method is the feed's first sentence, and claims nothing of identifiers
//      (through 3.2.0 it carried the EUVD sentence, one constant for the three).
//   3. WHAT THE RESOLVER ACCEPTS. Each namespace these texts name has its source among the values resolved_from.source
//      carries (get_cve's and search_cves' outputSchema), and each source the method names is one of them. In
//      EchelonGraph's repository, core-backend's sources (comments stripped) still carry, as text, a pattern for each
//      namespace named and a Parse that reads it; the examples parse by those patterns; vuln_ids.go keeps its GCVE-0
//      case, which answers by the specification without the table; and vulnalias defines each source. That is a text
//      pin: whether the parser and resolver behave is owned by core-backend's Go tests (vulnid_test.go
//      TestParseCanonicalisesEveryNamespace, vuln_ids_test.go). A source the outputSchema stops carrying fails here.
//   4. THE CHANGELOG. Older entries are not read: they quote what earlier releases said. The 3.2.1 entry, which is
//      also the v3.2.1 GitHub Release body, is held by its heading: "97.5%" only inside GHSA_SENTENCE, word for word,
//      and, outside quotes, no clause saying a GHSA or OSV-family ID resolves.
// What it reads is words, as a reviewer would: "mapped" (search_cves' resolved_from is present when an ID was mapped)
// describes data, and is not read as a claim.
//
// Runs against dist/index.js, so build first — `npm test` does.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { PKG, PKG_DIR, readDocs, readPkgFile, serverCommand } from "./server-under-test.mjs";

// The founder's forms, exactly (the claim limits of 2026-11-08, on #3448): src/index.ts GHSA_RESOLUTION and
// OSV_RESOLUTION.
export const GHSA_SENTENCE = "97.5% of a random 200 reviewed GitHub advisories resolve to their CVE.";
export const OSV_SENTENCE = "An OSV ID resolves only where EchelonGraph's alias table maps it to a CVE.";
// The only namespaces that may be said to resolve without qualification.
const RESOLVE_ACROSS = ["EUVD", "GCVE-0"];
// How each namespace is written where a text names it, in any letter case and its common spellings (Go, the
// language, in its own case only: "go" is a verb), and the source resolved_from names for it (core-backend
// vulnalias: enisa_euvd, github and osv through the alias table; gcve_gna0, the GCVE specification).
const NAMESPACES = [
  ["EUVD", /\bEUVD\b/i, "enisa_euvd"],
  ["GCVE-0", /\bGCVE-0\b/i, "gcve_gna0"],
  ["GHSA", /\bGHSA\b|\bGit ?Hub\b/i, "github"],
  ["OSV", /\bOSV\b/i, "osv"],
  ["PYSEC", /\bPYSEC\b|\bPyPI\b|\bPython\b/i, "osv"],
  ["GO", { test: (s) => /\bGO-/i.test(s) || /\bGo\b/.test(s) }, "osv"],
  ["RUSTSEC", /\bRUSTSEC\b|\bRust\b/i, "osv"],
  ["GSD", /\bGSD\b/i, "osv"],
  ["MAL", /\bMAL-/i, "osv"],
];
const OSV_FAMILY = NAMESPACES.filter(([, , source]) => source === "osv").map(([ns]) => ns);
const SOURCE_OF = Object.fromEntries(NAMESPACES.map(([ns, , source]) => [ns, source]));
const RESOLVE_WORD = /\bresolve[sd]?\b/i;
// Where a text must say what resolves (the claim texts, get_cve's description): a claim in other words. "mapped"
// and resolved_from stay data.
const WIDE_CLAIM = /\bresol(?:ve[sd]?|vable|ving|ution)\b|\bmaps? to\b|\banswer\w*\b.*\bwith (?:its|that|the) CVE|\b(?:takes|accepts)\b/i;
const NEGATIVE = /\bnot resolve\b|\bmaps? to no\b/i;
const PERCENT = /\d+(?:\.\d+)?\s?%/;
// A rate: a percentage, "N of N" ("180 of 180 sampled", "195 of a random 200") or "N/N". The founder gives one rate,
// GitHub's, in GHSA_SENTENCE; no OSV rate is claimed (#3448).
const RATE = /\d+(?:\.\d+)?\s?%|\b\d[\d,]* (?:of|in|out of) (?:a |an |the )?(?:[a-z]+ )*?\d[\d,]*\b|\b\d+\/\d+\b/i;
// A resolve sentence that speaks of IDs in general, naming no namespace: "IDs from all six systems", "each of these
// to its CVE". A quantifier counts beside a CVE only: "resolve each tag to its digest" (workload_triage) is no ID claim.
const UNNAMED_IDS = /\b(?:IDs?|identifiers?|advisor(?:y|ies)|systems?|namespaces?)\b/i;
const QUANTIFIER = /\b(?:all|every|each|any|these|six)\b/i;
const unnamed = (s) => UNNAMED_IDS.test(s) || (QUANTIFIER.test(s) && /\bCVEs?\b/.test(s));
// A sentence's clauses: a positive claim joined to a negative clause is still a claim.
const CLAUSE = /\s*[,;:]\s*|\s+(?:but|though|although|whereas)\s+/i;
// resolved_from.source's values where a text lists them: what mapped an ID, not a namespace said to resolve.
const SOURCE_NAMES = /\(source [a-z][a-z0-9_]*\)|\b(?:enisa_euvd|github|osv|gcve_gna0)(?:(?:,| or| and|, or|, and) (?:enisa_euvd|github|osv|gcve_gna0))+\b(?!\s+(?:IDs?|ids?|identifiers?|advisories)\b)/g;
// Capitalised tokens a sentence about IDs may carry that are no namespace of their own: the CVE, ENISA and the GCVE
// specification, ID, the API that looks an ID up, and each namespace this file knows. Any other (CNVD, JVN) is one
// the resolver is not known to accept: a namespace added for real is added to NAMESPACES and PATTERN_VAR, which
// ties it to vulnid.go and resolved_from.source.
const KNOWN_TOKENS = new Set(["CVE", "ENISA", "GCVE", "ID", "API", ...NAMESPACES.map(([ns]) => ns)]);
const TOKEN = /\b[A-Z][A-Z0-9]+(?:-[A-Z0-9]+)*/g;
const prefixOf = (t) => t.replace(/-(?:\d{4}|YYYY)(?:-[0-9A-Za-z]+)*$/, "");
const unknownTokens = (s) => (s.match(TOKEN) ?? []).map(prefixOf).filter((t) => !KNOWN_TOKENS.has(t));

const flat = (s) => String(s).replace(/`/g, "").replace(/\s+/g, " ").trim();
const sentencesOf = (text) => flat(text).split(/(?<=[.!?]["”]?)\s+(?=["“(]?[A-Z0-9])/);
const namesIn = (s) => NAMESPACES.filter(([, rx]) => rx.test(s)).map(([ns]) => ns);
const bare = (s) => s.replace(SOURCE_NAMES, "");

/**
 * What one text claims: the namespaces it says resolve, whether it carries GHSA_SENTENCE and OSV_SENTENCE, the
 * sources it names, and each claim the limits forbid. wide: a text that must say what resolves, read for a claim in
 * other words too.
 */
export function claimsOf(where, text, wide = false) {
  const out = { advertised: new Set(), ghsa: false, osv: false, sources: new Set(), problems: [] };
  const claimed = (s) => (wide ? WIDE_CLAIM : RESOLVE_WORD).test(s) || /^Pass an? /.test(s);
  let prev = "";
  for (const sentence of sentencesOf(text)) {
    const after = prev;
    prev = sentence;
    if (sentence.includes("97.5%") && sentence !== GHSA_SENTENCE) out.problems.push(`${where}: "97.5%" outside the founder's sentence: ${sentence}`);
    if (sentence === GHSA_SENTENCE) {
      out.ghsa = true;
      continue;
    }
    if (sentence === OSV_SENTENCE) {
      out.osv = true;
      continue;
    }
    // A rate of an OSV-family namespace, one right after the OSV sentence ("180 of 180 sampled do"), or, where a text
    // must say what resolves, any rate but GitHub's: whatever its verb.
    if (RATE.test(sentence)) {
      const osvNames = namesIn(bare(sentence)).filter((ns) => OSV_FAMILY.includes(ns));
      if (osvNames.length || after === OSV_SENTENCE || after === GHSA_SENTENCE || wide) out.problems.push(`${where}: a rate the founder did not give${osvNames.length ? ` (${osvNames.join(", ")})` : ""}: ${sentence}`);
    }
    if (!claimed(sentence)) continue;
    let s = sentence;
    if (NEGATIVE.test(sentence)) {
      if (PERCENT.test(sentence)) out.problems.push(`${where}: a percentage the founder did not give: ${sentence}`);
      const clauses = sentence.split(CLAUSE);
      for (const c of clauses.filter((x) => NEGATIVE.test(x))) {
        for (const ns of namesIn(bare(c)).filter((n) => !RESOLVE_ACROSS.includes(n))) out.problems.push(`${where}: says ${ns} IDs do not resolve, a measure the founder did not give: ${sentence}`);
      }
      // The rest of the sentence is read as any other: "PYSEC IDs resolve, but most do not resolve yet" is a claim.
      s = clauses.filter((x) => !NEGATIVE.test(x)).join(", ");
      if (!claimed(s)) continue;
    }
    const b = bare(s);
    const names = namesIn(b);
    if (names.length === 0 && RESOLVE_WORD.test(s) && unnamed(s)) out.problems.push(`${where}: says IDs resolve without naming the namespace: ${sentence}`);
    for (const ns of names) {
      if (RESOLVE_ACROSS.includes(ns)) out.advertised.add(ns);
      else out.problems.push(`${where}: says a ${ns} ID resolves, outside the founder's sentence: ${sentence}`);
    }
    for (const m of s.matchAll(/\bsource ([a-z][a-z0-9]*_[a-z0-9_]+)/g)) out.sources.add(m[1]);
    if (/\bIDs?\b|\bidentifiers?\b/i.test(b) || names.length) {
      for (const t of unknownTokens(b)) out.problems.push(`${where}: names ${t}, which is no namespace this test knows the resolver accepts: ${sentence}`);
    }
  }
  return out;
}

/**
 * The problems of a text that must say what resolves: exactly EUVD and GCVE-0, GHSA_SENTENCE beside them,
 * OSV_SENTENCE where it names an OSV ID, nothing forbidden.
 */
export function claimTextProblems(where, text) {
  const c = claimsOf(where, text, true);
  const said = [...c.advertised].sort();
  const osvNamed = namesIn(bare(flat(text))).some((ns) => OSV_FAMILY.includes(ns));
  return [
    ...c.problems,
    ...(said.join(",") === [...RESOLVE_ACROSS].sort().join(",") ? [] : [`${where}: advertises ${said.join(", ") || "nothing"} as resolving, not exactly ${RESOLVE_ACROSS.join(" and ")}`]),
    ...(c.ghsa ? [] : [`${where}: lacks the founder's sentence: ${GHSA_SENTENCE}`]),
    ...(osvNamed && !c.osv ? [`${where}: names an OSV ID without the founder's sentence: ${OSV_SENTENCE}`] : []),
  ];
}

/** Each "(source x)" a text gives, held to the namespace named in its own clause; and each of EUVD and GCVE-0 named with its own. */
export function sourcePairProblems(where, text) {
  const out = [];
  const paired = new Set();
  for (const m of flat(text).matchAll(/([^:;,.]*)\(source ([a-z][a-z0-9_]*)\)/g)) {
    const ns = namesIn(m[1]);
    if (ns.length !== 1) out.push(`${where}: "(source ${m[2]})" follows ${ns.length ? ns.join(", ") : "no namespace"}: ${m[0]}`);
    else if (SOURCE_OF[ns[0]] !== m[2]) out.push(`${where}: ${ns[0]} is given source ${m[2]}, not ${SOURCE_OF[ns[0]]}`);
    else paired.add(ns[0]);
  }
  for (const ns of RESOLVE_ACROSS) if (!paired.has(ns)) out.push(`${where}: ${ns} is not named with its source`);
  return out;
}

// The CHANGELOG's 3.2.1 section, by its heading (readme.test.mjs's way for 3.1.0, parse-budget.test.mjs's for 3.2.0).
const CHANGELOG_321 = /^## 3\.2\.1 — \d{4}-\d{2}-\d{2}$/m;
export const changelogSection = (log) => {
  const at = log.search(CHANGELOG_321);
  return at < 0 ? undefined : log.slice(at).split("\n").slice(1).join("\n").split(/^## /m)[0];
};
// A clause saying an ID of a namespace the limits do not let resolve does, in any tense: "<NS> IDs [two words]
// resolve", the verb first ("resolves an EUVD, GitHub GHSA ..."), or IDs in general ("all six namespaces resolve").
// Changelog prose talks about claims, so claimsOf is not used here. Quotes are blanked: what an earlier release said
// is quoted, word for word. Only "no text says" and a negated verb ("does not resolve", "maps to no") exempt a
// clause, and nothing exempts an OSV-family rate.
const CL_NS = String.raw`\b(?:GHSA|GitHub|OSV|PYSEC|GO|RUSTSEC|GSD|MAL)\b`;
const CL_VERB = String.raw`(?:\bresol(?:ve[sd]?|ving)\b|\bmap(?:s|ped)? to\b)`;
const CHANGELOG_CLAIM = new RegExp(
  [
    String.raw`${CL_NS}(?:[- ']\S*)?\s+(?:IDs?|identifiers?|advisories)\s+(?:\S+\s+){0,2}${CL_VERB}`,
    String.raw`\bresol(?:ve[sd]?|ving)\s+(?:(?:an?|the|all|every|each|any|its|their|ENISA|EUVD,?|GCVE-0,?|or|and)\s+)*${CL_NS}`,
    String.raw`\b(?:all|every|each|six)\b(?:\s+\S+){0,2}\s+(?:namespaces?|systems?|IDs?|identifiers?)\s+(?:\S+\s+){0,2}${CL_VERB}`,
  ].join("|"),
  "i",
);
const CL_EXEMPT = /\bno text says\b|\bnot (?:\S+\s+)?(?:resol|map)|\bmaps? to no\b/i;
/** The problems of the CHANGELOG's 3.2.1 section. */
export function changelogProblems(section) {
  const sec = flat(section);
  const out = [];
  if (sec.split("97.5%").length !== sec.split(GHSA_SENTENCE).length) out.push(`CHANGELOG 3.2.1: "97.5%" outside the founder's sentence, word for word: ${GHSA_SENTENCE}`);
  if (PERCENT.test(sec.split(GHSA_SENTENCE).join(""))) out.push("CHANGELOG 3.2.1: a percentage outside the founder's GitHub sentence");
  const unquoted = sec.split(OSV_SENTENCE).join("").replace(/"[^"]*"/g, '""');
  for (const c of unquoted.split(/[.;:](?:\s|$)|\s-\s/)) {
    if (CHANGELOG_CLAIM.test(c) && !CL_EXEMPT.test(c)) out.push(`CHANGELOG 3.2.1: says an ID resolves: ${c.trim()}`);
    if (RATE.test(c) && namesIn(bare(c)).some((ns) => OSV_FAMILY.includes(ns))) out.push(`CHANGELOG 3.2.1: an OSV-family rate the founder did not give: ${c.trim()}`);
  }
  return out;
}

// Every string value an outputSchema node lists, directly or in its unions (schema-compat.mjs's valuesAt).
function valuesAt(n, out = new Set()) {
  if (!n || typeof n !== "object") return out;
  for (const v of n.enum ?? []) if (typeof v === "string") out.add(v);
  if (typeof n.const === "string") out.add(n.const);
  for (const k of ["anyOf", "oneOf"]) for (const b of n[k] ?? []) valuesAt(b, out);
  return out;
}
// The object schemas a node is or unions over.
const objectsOf = (n) => (!n || typeof n !== "object" ? [] : [...(n.properties ? [n] : []), ...["anyOf", "oneOf"].flatMap((k) => (n[k] ?? []).flatMap(objectsOf))]);
const successData = (tool) => (tool?.outputSchema?.oneOf ?? []).find((b) => b.properties?.state?.enum?.includes("measured"))?.properties?.data;
/** The values resolved_from.source carries in a tool's success data (get_cve's record, search_cves' page). */
export function resolvedFromSources(tool) {
  const rf = objectsOf(successData(tool)).map((o) => o.properties.resolved_from).find(Boolean);
  const out = new Set();
  for (const o of objectsOf(rf)) valuesAt(o.properties.source, out);
  return out;
}
/** The namespaces a set of texts names whose source the sources do not carry, and each named source they do not. */
export function acceptedProblems(names, namedSources, sources, where) {
  return [
    ...[...names].filter((ns) => !sources.has(SOURCE_OF[ns])).map((ns) => `${where}: ${ns} is named, and resolved_from.source carries no ${SOURCE_OF[ns]}`),
    ...[...namedSources].filter((s) => !sources.has(s)).map((s) => `${where}: names source ${s}, which resolved_from.source does not carry`),
  ];
}

// core-backend's identifier parser and resolver, read where the package sits in EchelonGraph's repository. The npm
// tarball and the public repository carry mcp-server alone, so that part is skipped there (cve_intel.test.mjs's way).
const HERE = path.dirname(fileURLToPath(import.meta.url));
const CORE = path.resolve(HERE, "..", "..", "core-backend");
const IN_MONOREPO = path.basename(path.resolve(HERE, "..")) === "mcp-server" || fs.existsSync(CORE);
const OUTSIDE = "no core-backend beside this package (the npm tarball or the public repository): its identifier parser is not here, and the resolved_from check runs instead";
const VULNID = path.join(CORE, "internal", "cve", "vulnid", "vulnid.go");
const VULN_IDS = path.join(CORE, "internal", "cve", "vuln_ids.go");
const VULNALIAS_TYPES = path.join(CORE, "internal", "cve", "vulnalias", "types.go");
const readGo = (f) => {
  // In the monorepo the files must be there: a move fails here, it is never skipped.
  assert.ok(fs.existsSync(f), `${f} is gone: find where core-backend parses vulnerability IDs now and re-aim this test`);
  return fs.readFileSync(f, "utf8");
};
/** Go source without its comments, its strings and raw strings kept: a case commented out no longer reads as code. */
export function stripGoComments(src) {
  let out = "";
  for (let i = 0; i < src.length; ) {
    const c = src[i];
    if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < src.length && src[j] !== c && src[j] !== "\n") j += src[j] === "\\" ? 2 : 1;
      out += src.slice(i, j + 1);
      i = j + 1;
    } else if (c === "`") {
      const j = src.indexOf("`", i + 1);
      const end = j < 0 ? src.length : j + 1;
      out += src.slice(i, end);
      i = end;
    } else if (src.startsWith("//", i)) {
      const j = src.indexOf("\n", i);
      i = j < 0 ? src.length : j;
    } else if (src.startsWith("/*", i)) {
      const j = src.indexOf("*/", i + 2);
      const end = j < 0 ? src.length : j + 2;
      out += src.slice(i, end).replace(/[^\n]/g, "");
      i = end;
    } else {
      out += c;
      i++;
    }
  }
  return out;
}
// Each namespace's pattern in vulnid.go, by its variable's name.
const PATTERN_VAR = { EUVD: "euvdPattern", "GCVE-0": "gcvePattern", GHSA: "ghsaPattern", PYSEC: "pysecPattern", GO: "goPattern", RUSTSEC: "rustsecPattern", GSD: "gsdPattern", MAL: "malPattern" };
/** The problems of core-backend's sources (read without their comments) against the namespaces named and the example IDs given. */
export function backendProblems(sources, names, examples) {
  const vulnid = stripGoComments(sources.vulnid);
  const vulnIds = stripGoComments(sources.vulnIds);
  const types = stripGoComments(sources.types);
  const out = [];
  const patterns = Object.fromEntries([...vulnid.matchAll(/^\s*(\w+)\s*=\s*regexp\.MustCompile\(`([^`]+)`\)/gm)].map((m) => [m[1], m[2]]));
  const parse = vulnid.slice(vulnid.indexOf("func Parse("));
  for (const ns of names) {
    if (ns === "OSV") continue; // the family, named by its five prefixes
    const v = PATTERN_VAR[ns];
    if (!v) out.push(`no PATTERN_VAR for ${ns}: name the vulnid.go pattern that parses it`);
    else if (!patterns[v]) out.push(`vulnid.go: no ${v}: core-backend no longer parses ${ns} IDs`);
    else if (!new RegExp(`\\b${v}\\.(MatchString|FindStringSubmatch)\\(s\\)`).test(parse)) out.push(`vulnid.go: Parse no longer reads ${v}: core-backend no longer accepts ${ns} IDs`);
  }
  for (const id of examples) {
    const ns = namesIn(id)[0];
    const rx = patterns[PATTERN_VAR[ns]];
    const m = rx ? id.toUpperCase().match(new RegExp(rx)) : null;
    if (!m) out.push(`vulnid.go: the example ${id} does not parse as ${ns}`);
    else if (ns === "GCVE-0" && (m[1] !== "0" || !new RegExp(patterns.gcve0Number ?? "$^").test(m[3]))) out.push(`vulnid.go: the example ${id} is not a GCVE-0 ID with a CVE number`);
  }
  // GCVE-0 resolves by the specification, with no table read: that is why it resolves across the corpus.
  if (!/case id\.Namespace == vulnid\.NSGCVE && id\.GNA == 0:\s*\n\s*return aliasResolution\{cveIDs: \[\]string\{id\.CVE\}/.test(vulnIds)) out.push("vuln_ids.go: resolveID no longer answers a GCVE-0 ID with its CVE by the specification");
  const consts = new Set([...types.matchAll(/^\s*\w+\s*=\s*"([a-z0-9_]+)"/gm)].map((m) => m[1]));
  for (const ns of names) if (!consts.has(SOURCE_OF[ns])) out.push(`vulnalias/types.go: no source "${SOURCE_OF[ns]}" (${ns})`);
  return out;
}

// The answers the method is read from: get_cve and search_cves for an EUVD ID (the wire contract's bodies,
// fixtures/alias-contract.json); and cve_summary's, from a summary. cve://{cve_id} reads get_cve's record of the CVE
// the EUVD ID names.
const CONTRACT = JSON.parse(fs.readFileSync(path.join(HERE, "fixtures", "alias-contract.json"), "utf8"));
const RECORD_CVE = CONTRACT.get_cve_euvd.body.cve_id;
const ANSWERS = {
  [CONTRACT.get_cve_euvd.path]: CONTRACT.get_cve_euvd.body,
  [CONTRACT.search_cves_euvd.path]: CONTRACT.search_cves_euvd.body,
  [`/api/v1/public/cves/${RECORD_CVE}`]: CONTRACT.get_cve_euvd.body,
  "/api/v1/public/cves/summary": { summary: { total: 1, last_updated: "2026-11-08T00:00:00Z" } },
};
const CALLS = [
  ["search_cves", { search: "EUVD-2026-90503" }],
  ["get_cve", { cve_id: "EUVD-2026-90503" }],
];
const SUMMARY_CALL = ["cve_summary", {}];
// Each prompt's text is read with these arguments: a prompt added without an entry fails, so none goes unread.
const PROMPT_ARGS = {
  triage_cve: [{ cve_id: "CVE-2024-3400" }],
  kev_weekly_brief: [{}],
  am_i_affected: [{ product: "openssl", version: "3.0.0" }, { ecosystem: "npm", package: "lodash", version: "4.17.20" }],
  sbom_review: [{ sbom: JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.5", components: [{ type: "library", name: "lodash", version: "4.17.20", purl: "pkg:npm/lodash@4.17.20" }] }) }],
  workload_triage: [{}],
};
// And each resource template, at this URI.
const TEMPLATE_URIS = { "cve://{cve_id}": `cve://${RECORD_CVE}` };
// The section of docs/tools.md that says how these IDs are taken.
const DOCS_SECTION = /^## How `get_cve` and `search_cves` take an EUVD, GHSA, OSV or GCVE-0 ID$/m;
const docsSection = (text) => {
  const at = text.search(DOCS_SECTION);
  return at < 0 ? undefined : text.slice(at).split("\n").slice(1).join("\n").split(/^## /m)[0];
};
// The descriptions under a schema, with their paths (description-policy.test.mjs's walk).
function schemaDescriptions(node, where, out) {
  if (Array.isArray(node)) node.forEach((x, i) => schemaDescriptions(x, `${where}[${i}]`, out));
  else if (node && typeof node === "object") {
    for (const [k, v] of Object.entries(node)) {
      if (k === "description" && typeof v === "string") out.push([where, v]);
      else schemaDescriptions(v, `${where}.${k}`, out);
    }
  }
  return out;
}
// The strings under a value (an answer's coverage), each once.
const stringsIn = (v) => (typeof v === "string" ? [v] : v && typeof v === "object" ? Object.values(v).flatMap(stringsIn) : []);
// Every text file under listings/, by a walk: a listing added is read without a change here. The bundle's build
// scripts are code, not text a reader is shown.
const LISTINGS = path.join(PKG_DIR, "listings");
const LISTING_CODE = new Set(["listings/mcpb/build.sh", "listings/mcpb/check-bundle.mjs"]);
const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)]));
const listingFiles = () =>
  fs.existsSync(LISTINGS)
    ? walk(LISTINGS)
        .map((f) => path.relative(PKG_DIR, f).split(path.sep).join("/"))
        .filter((f) => /\.(?:md|json|ya?ml)$/.test(f) && !LISTING_CODE.has(f))
        .sort()
    : [];

describe("#3448: what resolves to a CVE is said in the founder's limits, and only of a namespace the resolver accepts", () => {
  let stub;
  let client;
  let tools;
  let served = []; // [where, text] for every text the server serves
  let method;
  let summaryMethod;
  before(async () => {
    stub = http.createServer((req, res) => {
      const a = ANSWERS[req.url.split("?")[0]];
      res.writeHead(a ? 200 : 404, { "content-type": "application/json" });
      res.end(JSON.stringify(a ?? { error: "not found" }));
    });
    await new Promise((resolve) => stub.listen(0, "127.0.0.1", resolve));
    client = await connect({
      era: MODERN,
      ...serverCommand(),
      env: { ...process.env, ECHELONGRAPH_API_BASE: `http://127.0.0.1:${stub.address().port}`, ECHELONGRAPH_API_TIMEOUT_MS: "5000" },
      stderr: "ignore",
    });
    ({ tools } = await client.listTools());
    const methods = [];
    const answerTexts = [];
    for (const [name, args] of [...CALLS, SUMMARY_CALL]) {
      const res = await client.callTool({ name, arguments: args });
      assert.equal(res.structuredContent?.state, "measured", `${name}: ${JSON.stringify(res).slice(0, 400)}`);
      methods.push([name, res.structuredContent.method]);
      answerTexts.push([`${name}'s notes`, (res.structuredContent.notes ?? []).join(" ")], [`${name}'s coverage`, stringsIn(res.structuredContent.coverage).join(" ")]);
    }
    const taking = methods.filter(([name]) => name !== SUMMARY_CALL[0]);
    assert.equal(new Set(taking.map(([, m]) => m)).size, 1, `search_cves and get_cve answer with one method: ${JSON.stringify(taking)}`);
    method = taking[0][1];
    summaryMethod = methods.find(([name]) => name === SUMMARY_CALL[0])[1];
    const { prompts } = await client.listPrompts();
    const { resources } = await client.listResources();
    const { resourceTemplates } = await client.listResourceTemplates();
    const promptTexts = [];
    for (const p of prompts) {
      assert.ok(PROMPT_ARGS[p.name], `prompt ${p.name} has no arguments in PROMPT_ARGS: add some, so its text is read`);
      for (const args of PROMPT_ARGS[p.name]) {
        const got = await client.getPrompt({ name: p.name, arguments: args });
        promptTexts.push([`prompt ${p.name} ${JSON.stringify(args).slice(0, 60)}`, got.messages.map((m) => m.content?.text ?? "").join("\n")]);
      }
    }
    const resourceTexts = [];
    for (const uri of [...resources.map((r) => r.uri), ...resourceTemplates.map((r) => TEMPLATE_URIS[r.uriTemplate])]) {
      assert.ok(uri, `a resource template has no URI in TEMPLATE_URIS: ${JSON.stringify(resourceTemplates.map((r) => r.uriTemplate))}`);
      const { contents } = await client.readResource({ uri });
      for (const c of contents) {
        // A JSON resource is read string by string. In get_cve's envelope (cve://) data is the API's record, not
        // the server's words: the rest is read.
        if (c.mimeType === "application/json") {
          const json = JSON.parse(c.text);
          const { data, ...envelope } = json;
          const own = data !== undefined && typeof envelope.method === "string" ? envelope : json;
          for (const t of stringsIn(own)) resourceTexts.push([`resource ${uri}'s contents`, t]);
        } else resourceTexts.push([`resource ${uri}'s contents`, c.text ?? ""]);
      }
    }
    served = [
      ["the instructions", client.opening.instructions],
      ...methods.map(([name, m]) => [`${name}'s method`, m]),
      ...answerTexts,
      ...tools.flatMap((t) => [
        [`${t.name} title`, t.title ?? ""],
        [`${t.name} description`, t.description],
        ...schemaDescriptions(t.inputSchema, `${t.name} inputSchema`, []),
        ...schemaDescriptions(t.outputSchema, `${t.name} outputSchema`, []),
      ]),
      ...prompts.flatMap((p) => [[`prompt ${p.name}`, p.description ?? ""], ...(p.arguments ?? []).map((a) => [`prompt ${p.name} ${a.name}`, a.description ?? ""])]),
      ...promptTexts,
      ...[...resources, ...resourceTemplates].map((r) => [`resource ${r.uri ?? r.uriTemplate}`, r.description ?? ""]),
      ...resourceTexts,
    ];
  });
  after(async () => {
    await client?.close();
    await new Promise((resolve) => stub?.close(resolve) ?? resolve());
  });

  const tool = (name) => tools.find((t) => t.name === name);
  const cveIdArg = () => tool("get_cve").inputSchema.properties.cve_id.description;
  const searchResolvedFrom = () => successData(tool("search_cves")).properties.resolved_from.description;
  const docsText = () => fs.readFileSync(path.join(PKG_DIR, "docs", "tools.md"), "utf8");
  const pages = () => [
    ...readDocs(),
    ["server.json", readPkgFile("server.json")],
    ["package.json description", PKG.description ?? ""],
    ...listingFiles().map((f) => [f, readPkgFile(f)]),
  ];
  const claimTexts = () => [
    ["the method", method],
    ["get_cve's cve_id", cveIdArg()],
    ["search_cves' resolved_from", searchResolvedFrom()],
    ["docs/tools.md's section on these IDs", docsSection(docsText()) ?? ""],
  ];

  it("1. no served text and no page says a GHSA or OSV ID resolves outside the founder's sentences, or gives 97.5% in other words", () => {
    const problems = [...served, ...pages()].flatMap(([where, text]) => claimsOf(where, text).problems);
    assert.deepEqual(problems, []);
  });

  it("1. what is read reaches every kind of surface: each prompt's text, each resource's contents, the answers' notes, every listings file", () => {
    for (const kind of [/^prompt \w+ \{/, /^resource .+'s contents$/, /'s notes$/, /^package\.json description$/]) assert.ok([...served, ...pages()].some(([w, t]) => kind.test(w) && t.length > 0), `nothing read matches ${kind}`);
    if (fs.existsSync(LISTINGS)) {
      const files = listingFiles();
      for (const f of ["listings/README.md", "listings/github-repo-settings.json", "listings/docker/server.yaml", "listings/docker/remote/server.yaml", "listings/docker/remote/readme.md", "listings/mcpb/manifest.json"]) assert.ok(files.includes(f), `the listings walk no longer reads ${f}: ${files.join(", ")}`);
    }
  });

  it("2. the method, get_cve's cve_id, search_cves' resolved_from and docs/tools.md say exactly EUVD and GCVE-0 resolve, with the founder's GHSA and OSV sentences verbatim", () => {
    assert.ok(docsSection(docsText()), "docs/tools.md has no section on these IDs: re-aim DOCS_SECTION");
    assert.deepEqual(claimTexts().flatMap(([where, text]) => claimTextProblems(where, text)), []);
    for (const [where, text] of claimTexts()) assert.ok(flat(text).includes(GHSA_SENTENCE), `${where} lacks the sentence verbatim (line breaks aside)`);
    for (const [where, text] of claimTexts().slice(1)) assert.ok(flat(text).includes(OSV_SENTENCE), `${where} lacks the OSV sentence verbatim (line breaks aside)`);
    // get_cve's description names what may be passed, EUVD and GCVE-0 alone: it was 6 characters under its #2924
    // floor before #3448, too few for the sentence, which its cve_id carries. It is read for a claim in other words.
    const d = claimsOf("get_cve description", tool("get_cve").description, true);
    assert.deepEqual([d.advertised, d.problems], [new Set(RESOLVE_ACROSS), []]);
  });

  it("2. the method says coverage differs by namespace and names each namespace that resolves with its own source", () => {
    assert.match(method, /differs by namespace/);
    const c = claimsOf("the method", method, true);
    assert.deepEqual([...c.sources].sort(), [SOURCE_OF.EUVD, SOURCE_OF["GCVE-0"]].sort(), `the method names ${[...c.sources].join(", ")}`);
    assert.deepEqual([...sourcePairProblems("the method", method), ...sourcePairProblems("docs/tools.md's section on these IDs", docsSection(docsText()) ?? "")], []);
  });

  it("2. cve_summary's method, the feed's first sentence, claims nothing of identifiers", () => {
    const c = claimsOf("cve_summary's method", summaryMethod, true);
    assert.deepEqual([c.advertised.size, c.ghsa, c.osv, c.problems], [0, false, false, []], summaryMethod);
    assert.ok(method.startsWith(`${summaryMethod} `), `cve_summary's method is not the feed's first sentence: ${summaryMethod}`);
  });

  it("3. every namespace these texts name has its source among the values resolved_from.source carries, on get_cve and on search_cves; cve_id names none this test does not know", () => {
    const named = new Set([...RESOLVE_ACROSS, "GHSA", ...namesIn(cveIdArg())]);
    for (const ns of NAMESPACES.map(([n]) => n)) assert.ok(named.has(ns), `get_cve's cve_id no longer names ${ns}: re-aim this test, or say why it is no longer accepted`);
    // The accepted list says no "resolve", so claimsOf does not read it: each capitalised token in it is held here.
    assert.deepEqual(unknownTokens(flat(cveIdArg())), [], "get_cve's cve_id lists a namespace this test does not know the resolver accepts");
    const sourcesNamed = new Set(claimTexts().flatMap(([w, t]) => [...claimsOf(w, t, true).sources]));
    for (const name of ["get_cve", "search_cves"]) {
      const sources = resolvedFromSources(tool(name));
      assert.ok(sources.size > 0, `${name}: no resolved_from.source values found: re-aim resolvedFromSources`);
      assert.deepEqual(acceptedProblems(named, sourcesNamed, sources, name), []);
    }
  });

  it("3. in EchelonGraph's repository, core-backend's sources still name a parser pattern for each namespace named, the examples given parse, and GCVE-0 resolves by the specification", { skip: IN_MONOREPO ? false : OUTSIDE }, () => {
    const named = new Set([...RESOLVE_ACROSS, "GHSA", ...namesIn(cveIdArg())]);
    const examples = [...new Set(claimTexts().flatMap(([, t]) => [...flat(t).matchAll(/\b(?:EUVD-\d{4}-\d+|GCVE-0-\d{4}-\d+|GHSA(?:-[0-9a-zA-Z]{4}){3})\b/g)].map((m) => m[0])))];
    assert.ok(examples.some((e) => e.startsWith("EUVD-")) && examples.some((e) => e.startsWith("GCVE-0-")), `the texts' examples: ${examples.join(", ")}`);
    assert.deepEqual(backendProblems({ vulnid: readGo(VULNID), vulnIds: readGo(VULN_IDS), types: readGo(VULNALIAS_TYPES) }, named, examples), []);
  });

  it("4. the CHANGELOG's 3.2.1 entry gives 97.5% only in the founder's sentence, word for word, and says no GHSA or OSV ID resolves", () => {
    const sec = changelogSection(readPkgFile("CHANGELOG.md"));
    assert.ok(sec, "CHANGELOG.md has no '## 3.2.1 — <date>' section: re-aim CHANGELOG_321");
    assert.ok(flat(sec).includes(GHSA_SENTENCE), "the 3.2.1 entry no longer quotes the founder's sentence");
    assert.deepEqual(changelogProblems(sec), []);
  });

  // Controls: each check fails on what it was written against, and passes the founder's forms.
  describe("controls", () => {
    const M320 = "EchelonGraph's CVE Pulse feed: CVE records compiled from NVD, MITRE-CNA pre-NVD records, CISA-KEV, EPSS and GitHub GHSA, each polled from its source on a schedule. ENISA EUVD identifiers resolve to their CVE.";
    const CVE_ID_320 = "a CVE ID, e.g. CVE-2023-44487, or an ENISA EUVD (EUVD-2026-90503), GitHub GHSA, OSV (PYSEC-, GO-, RUSTSEC-, GSD-, MAL-) or GCVE-0 (GCVE-0-2024-3094) ID, which EchelonGraph resolves to its CVE";
    const RF_320 = "Present when the search term was an EUVD, GHSA, OSV or GCVE-0 id: what it was, and what mapped it (enisa_euvd, github or osv through EchelonGraph's alias table; gcve_gna0, the GCVE specification), with attribution, Source: ENISA EUVD, when enisa_euvd mapped it. The rows are then exactly the CVEs it names.";
    const METHOD_OK = `Coverage differs by namespace: ENISA EUVD IDs resolve to their CVE (source enisa_euvd), and GCVE-0 IDs by the GCVE specification (source gcve_gna0). ${GHSA_SENTENCE}`;
    const CVE_ID_OK = `a CVE ID, e.g. CVE-2023-44487, or an ENISA EUVD (EUVD-2026-90503), GCVE-0 (GCVE-0-2024-3094), GitHub GHSA or OSV (PYSEC-, GO-, RUSTSEC-, GSD-, MAL-) ID. ENISA EUVD and GCVE-0 IDs resolve to their CVE. ${GHSA_SENTENCE} ${OSV_SENTENCE}`;
    const bad = (s) => claimsOf("x", s).problems.length;
    const badWide = (s) => claimsOf("x", s, true).problems.length;
    it("3.2.0's method fails: it advertises EUVD alone, without the GHSA sentence", () => {
      const p = claimTextProblems("m", M320);
      assert.ok(p.some((x) => /advertises EUVD as resolving, not exactly EUVD and GCVE-0/.test(x)), p.join("\n"));
      assert.ok(p.some((x) => /lacks the founder's sentence/.test(x)), p.join("\n"));
    });
    it("3.2.0's cve_id fails: it says GHSA, OSV, PYSEC, GO, RUSTSEC, GSD and MAL IDs resolve", () => {
      const p = claimsOf("c", CVE_ID_320).problems;
      for (const ns of ["GHSA", "OSV", "PYSEC", "GO", "RUSTSEC", "GSD", "MAL"]) assert.ok(p.some((x) => x.includes(`says a ${ns} ID resolves`)), `${ns}: ${p.join("\n")}`);
    });
    it("3.2.0's search_cves resolved_from and get_cve's \"Pass a CVE, EUVD or GHSA ID.\" fail", () => {
      assert.ok(claimTextProblems("r", RF_320).some((x) => /lacks the founder's sentence/.test(x)));
      assert.ok(claimTextProblems("r", RF_320).some((x) => /names an OSV ID without the founder's sentence/.test(x)));
      assert.ok(claimsOf("d", "One CVE's record. Pass a CVE, EUVD or GHSA ID.").problems.some((x) => x.includes("says a GHSA ID resolves")));
    });
    it("an unqualified or reworded GHSA claim, an OSV claim, and a percentage on a negative one fail; the founder's forms pass", () => {
      assert.ok(bad("GHSA IDs resolve to their CVE."));
      assert.ok(bad("GitHub advisories resolve to their CVE."));
      assert.ok(bad("97.5% of reviewed GitHub advisories resolve to their CVE."));
      assert.ok(bad("EchelonGraph resolves IDs from all six systems: EUVD, GHSA, PYSEC, GO, RUSTSEC and GCVE-0."));
      assert.ok(bad("PYSEC IDs resolve to their CVE."));
      assert.ok(bad("A GO- ID is resolved."));
      assert.ok(bad("About 13% of OSV IDs do not resolve yet."));
      assert.equal(bad(`ENISA EUVD and GCVE-0 IDs resolve to their CVE. ${GHSA_SENTENCE} ${OSV_SENTENCE}`), 0);
      assert.deepEqual(claimTextProblems("ok", METHOD_OK), []);
      assert.deepEqual(claimTextProblems("ok", CVE_ID_OK), []);
      // resolved_from names a field, not a claim; "mapped" describes data.
      assert.equal(bad("resolved_from names a GHSA or OSV ID that EchelonGraph mapped to a CVE."), 0);
    });
    it("the OSV sentence passes only word for word; a rate or a positive OSV claim beside it, or the unmeasured \"most do not\", fails", () => {
      assert.deepEqual(claimsOf("x", OSV_SENTENCE), { advertised: new Set(), ghsa: false, osv: true, sources: new Set(), problems: [] });
      for (const s of [
        OSV_SENTENCE.replace("only ", ""),
        OSV_SENTENCE.replace("An OSV ID", "A PYSEC ID"),
        OSV_SENTENCE.replace(/\.$/, "; 180 of 180 sampled do."),
        `${OSV_SENTENCE} 180 of 180 sampled do.`,
        `${OSV_SENTENCE} 100% of them do.`,
        "An OSV ID resolves to its CVE.",
        "OSV IDs resolve to their CVE.",
        "100% of PYSEC IDs resolve to their CVE.",
        "60 of 60 sampled PYSEC, GO and RUSTSEC IDs map to their CVE.",
        "Most OSV IDs do not resolve yet.",
        "PYSEC, GO and RUSTSEC IDs resolve to their CVE.",
      ]) assert.ok(bad(s), s);
      // Where a text must say what resolves, a rate other than GitHub's fails whatever it counts.
      assert.ok(badWide("Of a seeded sample, 180/180 map to their CVE."));
      // The founder's forms with the numbers the texts give still pass.
      assert.equal(bad(`${OSV_SENTENCE} An ID the table maps to no CVE is the API's 404, one that names several CVEs its 300.`), 0);
      assert.equal(badWide(`${GHSA_SENTENCE} ${OSV_SENTENCE}`), 0);
      // A list of OSV IDs needs the sentence beside it.
      assert.ok(claimTextProblems("c", CVE_ID_OK.replace(` ${OSV_SENTENCE}`, "")).some((x) => /names an OSV ID without the founder's sentence/.test(x)));
    });
    it("a positive claim joined to a negative clause fails (#3448 review T3)", () => {
      for (const s of [
        "PYSEC IDs resolve to their CVE, but most other OSV IDs do not resolve yet.",
        "GHSA IDs resolve to their CVE; only a few OSV IDs do not resolve yet.",
        "EchelonGraph resolves IDs from all six systems: EUVD, GHSA, PYSEC, GO, RUSTSEC and GCVE-0, though some do not resolve yet.",
      ]) assert.ok(bad(s), s);
      // A negative clause that names no namespace, beside a GHSA aside that is no claim, passes.
      assert.equal(badWide("An ID the table maps to no CVE is the API's 404, one that names several CVEs (a GHSA can) its 300 listing them, and an alias table that could not be read its 503: each is a failed result quoting the API's message, never an empty one."), 0);
    });
    it("a resolve claim that names no namespace fails (#3448 review T2)", () => {
      for (const s of ["EchelonGraph resolves IDs from all six systems.", "EchelonGraph resolves each of these to its CVE.", "Every ID get_cve accepts resolves to its CVE.", "Reviewed advisories resolve to their CVE."]) assert.ok(bad(s), s);
      // 3.2.0's blanket claim split off from its list fails too.
      assert.ok(claimTextProblems("c", CVE_ID_OK.replace(" ID. ENISA", " ID. EchelonGraph resolves each of these to its CVE. ENISA")).length);
    });
    it("a namespace this test does not know fails, said to resolve or listed as accepted (#3448 review T1)", () => {
      for (const s of ["ENISA EUVD, GCVE-0 and CNVD IDs resolve to their CVE.", "Pass a CVE, EUVD, GCVE-0 or JVN ID.", "ENISA EUVD IDs resolve to their CVE, and JVN IDs resolve through JPCERT's table."]) assert.ok(bad(s), s);
      assert.deepEqual(unknownTokens(flat(CVE_ID_OK.replace("GitHub GHSA or OSV", "GitHub GHSA, CNVD (CNVD-2024-12345) or OSV"))), ["CNVD", "CNVD"]);
      assert.deepEqual(unknownTokens(flat(CVE_ID_OK)), []);
    });
    it("a namespace spelled in lower case or its common names fails (#3448 review T4)", () => {
      for (const s of ["Pysec IDs resolve to their CVE.", "Github advisories resolve to their CVE.", "Python (PyPI), Go and RustSec advisories resolve to their CVE.", "osv ids resolve to their CVE.", "Any pysec or rustsec id resolves to its CVE.", "github or osv IDs resolve to their CVE."]) assert.ok(bad(s), s);
      // resolved_from.source's values, listed, are no namespace said to resolve.
      assert.equal(bad("Resolved GCVE-0-2024-3094 to CVE-2024-3094 (source gcve_gna0); enisa_euvd, github or osv name the others."), 0);
    });
    it("in a claim text, a claim in other words fails (#3448 review T5)", () => {
      for (const s of ["PYSEC IDs are resolvable to their CVE.", "PYSEC IDs map to their CVE.", "EchelonGraph answers a PYSEC, GO or RUSTSEC ID with its CVE's record.", "It also takes a GHSA ID.", "GHSA IDs have full resolution to their CVE."]) assert.ok(badWide(s), s);
      assert.equal(badWide("resolved_from names a GHSA or OSV ID that EchelonGraph mapped to a CVE."), 0);
    });
    it("a source given to the wrong namespace fails (#3448 review T8)", () => {
      assert.deepEqual(sourcePairProblems("ok", METHOD_OK), []);
      const p = sourcePairProblems("x", "ENISA EUVD IDs resolve to their CVE (source gcve_gna0), and GCVE-0 IDs by the GCVE specification (source enisa_euvd).");
      assert.ok(p.some((x) => x.includes("EUVD is given source gcve_gna0")) && p.some((x) => x.includes("GCVE-0 is given source enisa_euvd")), p.join("\n"));
    });
    it("the CHANGELOG check fails on a word dropped from the founder's sentence and on a claim added to the entry (#3448 review T7)", () => {
      const log = `# Changelog\n\n## 3.2.1 — 2026-11-08\n\n- GitHub's is said in its measured form alone: "${GHSA_SENTENCE}" OSV IDs are\n  still accepted, and \`cve_id\` says "${OSV_SENTENCE}" No text says a GHSA or OSV ID resolves outside them.\n- A correction: it said "EchelonGraph's API resolves it to its CVE" of a GHSA ID.\n\n## 3.2.0 — 2026-11-08\n\n- GHSA IDs resolve to their CVE.\n`;
      const sec = changelogSection(log);
      assert.ok(sec && !sec.includes("3.2.0"), sec);
      assert.deepEqual(changelogProblems(sec), []);
      assert.ok(changelogProblems(sec.replace(GHSA_SENTENCE, GHSA_SENTENCE.replace("random ", ""))).length);
      assert.ok(changelogProblems(`${sec}\n- PYSEC ids resolve to their CVE.\n`).length);
      assert.ok(changelogProblems(`${sec}\n- GHSA IDs resolve to their CVE.\n`).length);
      assert.equal(changelogProblems(`${sec}\n- No text says a GHSA ID resolves.\n`).length, 0);
      for (const s of [
        "About 12 to 14% of PYSEC, GO and RUSTSEC IDs resolved then.",
        "PYSEC IDs resolved to their CVE.",
        "GHSA IDs resolved to their CVE.",
        "180 of 180 sampled PYSEC, GO and RUSTSEC IDs map to their CVE.",
        "OSV IDs now resolve to their CVE.",
        "GHSA identifiers resolve to their CVE.",
        "GitHub's advisories resolve to their CVE.",
        "GHSA IDs all resolve to their CVE.",
        "EchelonGraph resolves GHSA IDs to their CVE.",
        "EchelonGraph resolves an EUVD, GitHub GHSA or OSV ID to its CVE.",
        "All six namespaces resolve to their CVE.",
        "100% of OSV IDs now resolve to their CVE.",
        "180 of 180 sampled OSV IDs map to their CVE.",
        "GHSA IDs resolve to their CVE, not only EUVD.",
        "The OSV family did not bear out the claim (about 12 to 14% of PYSEC, GO and RUSTSEC IDs resolved then).",
      ]) assert.ok(changelogProblems(`${sec}\n- ${s}\n`).length, s);
      // A negated verb, and what an earlier release said, quoted, still pass.
      for (const s of ["GHSA IDs that map to no CVE are the API's 404.", 'It said "EchelonGraph resolves an EUVD, GitHub GHSA or OSV ID to its CVE".']) assert.equal(changelogProblems(`${sec}\n- ${s}\n`).length, 0, s);
    });
    it("a namespace whose source resolved_from.source stops carrying fails, as does a source the method names that it does not carry", () => {
      const all = new Set(["enisa_euvd", "github", "osv", "gcve_gna0"]);
      const named = new Set(["EUVD", "GCVE-0", "GHSA", "PYSEC"]);
      assert.deepEqual(acceptedProblems(named, new Set(["enisa_euvd"]), all, "t"), []);
      for (const gone of all) {
        const p = acceptedProblems(named, new Set(), new Set([...all].filter((s) => s !== gone)), "t");
        assert.ok(p.length > 0 && p.every((x) => x.includes(`no ${gone}`)), `${gone}: ${p.join("\n")}`);
      }
      assert.deepEqual(acceptedProblems(new Set(), new Set(["euvd_mapping"]), all, "t"), ["t: names source euvd_mapping, which resolved_from.source does not carry"]);
      // The schema reader finds the values where get_cve's outputSchema keeps them.
      const shaped = { outputSchema: { oneOf: [{ properties: { state: { enum: ["measured"] }, data: { anyOf: [{ type: "object", properties: { resolved_from: { anyOf: [{ type: "object", properties: { source: { anyOf: [{ anyOf: [{ type: "string", enum: ["enisa_euvd", "gcve_gna0"] }, { type: "string" }] }, { type: "null" }] } } }, { type: "null" }] } } }] } } }] } };
      assert.deepEqual([...resolvedFromSources(shaped)].sort(), ["enisa_euvd", "gcve_gna0"]);
    });
    it("core-backend's parser losing a namespace, a case commented out, an example that no longer parses, or GCVE-0 resolved through the table, fails", { skip: IN_MONOREPO ? false : OUTSIDE }, () => {
      const src = { vulnid: readGo(VULNID), vulnIds: readGo(VULN_IDS), types: readGo(VULNALIAS_TYPES) };
      const named = new Set(["EUVD", "GCVE-0", "GHSA", "PYSEC", "GO", "RUSTSEC", "GSD", "MAL"]);
      const examples = ["EUVD-2026-90503", "GCVE-0-2024-3094"];
      assert.deepEqual(backendProblems(src, named, examples), []);
      const noGhsa = { ...src, vulnid: src.vulnid.replace(/^\s*ghsaPattern\s*=.*$/m, "") };
      assert.ok(backendProblems(noGhsa, named, examples).some((x) => x.includes("no ghsaPattern")));
      const unread = { ...src, vulnid: src.vulnid.replace(/case euvdPattern\.MatchString\(s\):/, "case false:") };
      assert.ok(backendProblems(unread, named, examples).some((x) => x.includes("Parse no longer reads euvdPattern")));
      const commented = { ...src, vulnid: src.vulnid.replace(/case euvdPattern\.MatchString\(s\):/, "// case euvdPattern.MatchString(s):") };
      assert.ok(backendProblems(commented, named, examples).some((x) => x.includes("Parse no longer reads euvdPattern")));
      const narrowed = { ...src, vulnid: src.vulnid.replace(/euvdPattern\s*=\s*regexp\.MustCompile\(`[^`]+`\)/, "euvdPattern = regexp.MustCompile(`^EUVD-\\d{4}-\\d{6,}$`)") };
      assert.ok(backendProblems(narrowed, named, examples).some((x) => x.includes("EUVD-2026-90503 does not parse")));
      const tabled = { ...src, vulnIds: src.vulnIds.replace(/case id\.Namespace == vulnid\.NSGCVE && id\.GNA == 0:/, "case false:") };
      assert.ok(backendProblems(tabled, named, examples).some((x) => x.includes("GCVE-0 ID with its CVE by the specification")));
      const boxed = { ...src, vulnIds: src.vulnIds.replace(/(case id\.Namespace == vulnid\.NSGCVE && id\.GNA == 0:\s*\n\s*return aliasResolution\{cveIDs: \[\]string\{id\.CVE\}[^\n]*)/, "/* $1 */") };
      assert.ok(backendProblems(boxed, named, examples).some((x) => x.includes("GCVE-0 ID with its CVE by the specification")));
      const noOsv = { ...src, types: src.types.replace(/SourceOSV = "osv"/, 'SourceOSV = "osv_dev"') };
      assert.ok(backendProblems(noOsv, named, examples).some((x) => x.includes('no source "osv"')));
      assert.equal(stripGoComments('a := "x // y" // z\nb := `/* w */` /* v */ + 1'), 'a := "x // y" \nb := `/* w */`  + 1');
    });
  });
});
