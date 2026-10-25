// #2799: each prompt's tool calls, made as the prompt says, at the prompt's largest input, on
// production-shaped answers (text-bound.mjs SHAPED): every field the prompt names is in what a
// client that passes only `content` shows the model. That is the result's first text block,
// content[0], for the answer's fields, and its last for the evidence envelope (coverage.*,
// measured_at), which every prompt tells the model to read there (ENVELOPE_RULES). Past 30,000
// characters content[0] is a cut of structuredContent.data (src/textBudget.ts, #2783), and through
// 2.6.3 three prompts asked for what the cut leaves out: kev_weekly_brief read kev_recent at limit
// 200 and put kev_vuln_name and kev_due_date on every line, and the text of a page of 200 keeps
// neither; am_i_affected asked for each match's ransomware and epss_score, which check_affected's
// last cut level left out of all 200 matches at the API's cap; and sbom_review sent the model to
// data.not_sent_purls, of which the text keeps the first 10.
//
// The fields a prompt names are read from its own text, less ENVELOPE_RULES (the same words in
// every prompt) and less the SBOM it embeds: every snake_case word, and the plain words a prompt
// uses as field names (PLAIN). Each must be a field of the answer of some call the prompt makes, or
// a tool's name, or a value (VALUES). For each call, wherever the text holds an object that is a
// cut of one of the answer's objects (a row, the answer itself, a nested object), it keeps each
// named field that object has; and each named field must be in the text, or the envelope block, of
// some call. Every tool a prompt names is called here, so a step that calls another tool is run at
// the prompt's largest input too. A prompt that reads every row (kev_weekly_brief's page,
// am_i_affected's matches) gets every row in the text; sbom_review, at 2,000 purls, is told what to
// do with the rows the text leaves out, and to rebuild the purls not sent from the position and
// order the note gives where the text cuts not_sent_purls.
//
// #2799 review: sbom_review asked for "fixed versions where a result gives them", words the check
// above did not read, and check_sbom's text keeps match_reason, the advisory interval that names
// the fixed version (or, closed "[A, B]", the last affected one: #2830), only at its first level
// (Juice Shop's 50 components are cut past it); it now reads fixed_version from cve_intel.
// triage_cve read kev_due_date from a kev_recent page of one day, unpaged, which on 2021-11-03
// (287 additions) did not hold most of that day's rows; it now reads it from get_cve.
//
// #2799 second review (#2817): cve_intel keeps one fixed_version per (CVE, ecosystem, package), the
// advisory's last range's, and production's for log4j-core under CVE-2021-44228 is 2.12.2, older
// than an installed 2.14.1, which sbom_review then told the model to give. It now gives a fixed
// version strictly greater than the installed one, or says the results give none for the
// component's branch; the test below holds its text to that on production's answers. And
// sbom_review read each component's ecosystem and package, which check_sbom's leanest cut (reached
// at 2,000 purls) leaves out of every row: it now reads them, and the version, from the purl, which
// that cut keeps, and the check below holds each row the text keeps to giving them so (DERIVED).
//
// #2834's last review (2026-10-11): sbom_review still fell back to the advisory interval in a
// match's match_reason, prose read by its brackets. It reads each match's fixed_in alone where the
// text keeps the match, and cve_intel only where it keeps none (or the match has no fixed_in), so
// fixRule below reads no match_reason. #2836: a deb, apk or alpine purl with an upstream qualifier
// is matched by the source package it names; step 2 reads package, version, matched_package and
// matched_via so, and DERIVED holds the rows the text keeps (an upstream row among them) to that.
// #3074: core-backend's fixed_in moves past overlapping intervals, and where fixRule reads
// cve_intel's fixed_branches it walks past them too (fixedBranchesWalk).
//
// Runs against dist/index.js, so build first; `npm test` does.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { PKG_DIR, serverCommand } from "./server-under-test.mjs";
import { SHAPED, argsOf, cutPairs, readShaped, shapedAnswers, startStub } from "./text-bound.mjs";

const blocksOf = (res) => (res.content ?? []).filter((c) => c.type === "text").map((c) => c.text);
const caseOf = (label) => {
  const c = SHAPED.find((x) => x.label === label);
  assert.ok(c, `no SHAPED case ${label}`);
  return c;
};
const textOf = (r) => r.messages[0].content.text;

// The plain words each prompt uses as field names, where its text uses them so.
const PLAIN = {
  kev_weekly_brief: ["total"],
  am_i_affected: ["count", "assessed", "capped", "degraded", "ransomware"],
  sbom_review: ["verdict", "purl", "summary", "ecosystem", "package", "version", "references"],
  triage_cve: ["severity", "cwes", "exploits", "references"],
  workload_triage: ["verdict", "purl", "ransomware"],
};
// Snake_case words a prompt uses as values, not fields. purl_name is matched_via's value for a purl
// matched by its own name (sbom_review's step 2); an upstream row also carries a purl_name field,
// which heldTo still holds to the text wherever the answer has it. github_checker is a value of an
// exploit's kind (#3221), named by triage_cve's step 2 beside nuclei_template; production's
// CVE-2021-44228 answer (prod-shaped/cve_intel.json) holds no such row, so no call here carries it.
const VALUES = new Set(["change_only", "not_assessed", "distro_release_unknown", "invalid_input", "not_parsed", "none_in_source", "purl_name", "github_checker"]);

// sbom_review's step 2: a component's ecosystem, package and version read from its purl, as the
// prompt says (and as core-backend's matcher maps a purl: cve/matchbatch.go purlNameVersion,
// shared/pkg/purlosv). The fields it gives may be left out of a row whose text keeps its purl.
const DERIVE_STEP = /2\. Read each component's ecosystem, package and version from its purl, which every row of data\.results in the text carries/;
// purlosv's unversioned table (in the order step 2 gives), the types purlNameVersion names with their namespace,
// and the distro types, as of 2026-10-04. #2817 review: step 2 had listed eight types and named
// three with their namespace, where the matcher maps sixteen and names five so.
const PURL_ECOSYSTEM = { npm: "npm", pypi: "PyPI", maven: "Maven", golang: "Go", cargo: "crates.io", gem: "RubyGems", nuget: "NuGet", composer: "Packagist", hex: "Hex", pub: "Pub", swift: "SwiftURL", hackage: "Hackage", cran: "CRAN", bitnami: "Bitnami", conan: "ConanCenter", githubact: "GitHub Actions" };
const NAMESPACED = ["npm", "golang", "composer", "swift", "githubact"];
const DISTRO_TYPES = ["deb", "apk", "alpine", "rpm"];
// purlosv osvDistro: alpine-X.Y[.Z] is Alpine:vX.Y, debian-N[.M] Debian:N, ubuntu-V Ubuntu:V; any
// other distro, or alpine without a minor release, none.
function distroEcosystem(distro) {
  const d = (distro ?? "").trim().toLowerCase();
  const cut = d.indexOf("-");
  const [name, ver] = cut < 0 ? [d, ""] : [d.slice(0, cut), d.slice(cut + 1)];
  if (!ver) return undefined;
  const [major, minor] = ver.split(".");
  if (name === "debian") return major ? `Debian:${major}` : undefined;
  if (name === "ubuntu") return `Ubuntu:${ver}`;
  if (name === "alpine") return major && minor ? `Alpine:v${major}.${minor}` : undefined;
  return undefined;
}
// #2836: core-backend cve/matchbatch.go purlUpstream reads the upstream qualifier of these types
// alone (upstreamPurlTypes), as name or name@version, and matches by that name, at that version
// where it gives one; every other purl it checks is matched by its own name (matched_via purl_name).
const UPSTREAM_TYPES = ["deb", "apk", "alpine"];
function fromPurl(purl) {
  let s = purl.trim().replace(/^pkg:/, "");
  const query = s.includes("?") ? s.slice(s.indexOf("?") + 1).split("#")[0] : "";
  s = s.split("#")[0].split("?")[0];
  let version;
  const at = s.lastIndexOf("@");
  if (at >= 0 && !s.slice(at).includes("/")) [s, version] = [s.slice(0, at), decodeURIComponent(s.slice(at + 1))];
  const [type, ...parts] = s.split("/").filter(Boolean).map(decodeURIComponent);
  const t = type.toLowerCase();
  const name = parts.at(-1);
  const ns = parts.slice(0, -1).join("/");
  let pkg = !ns ? name : t === "maven" ? `${ns}:${name}` : NAMESPACED.includes(t) ? `${ns}/${name}` : name;
  const ecosystem = PURL_ECOSYSTEM[t] ?? (DISTRO_TYPES.includes(t) ? distroEcosystem(new URLSearchParams(query).get("distro")) : undefined);
  const upstream = UPSTREAM_TYPES.includes(t) ? (new URLSearchParams(query).get("upstream") ?? "").trim() : "";
  if (!upstream) return { ecosystem, package: pkg, version, matched_package: pkg, matched_via: "purl_name" };
  const [source, sourceVersion] = upstream.split("@").map((x) => x.trim());
  pkg = source;
  if (sourceVersion) version = sourceVersion;
  return { ecosystem, package: pkg, version, matched_package: pkg, matched_via: "upstream" };
}

// The lines (steps, template lines, paragraphs) of a prompt's own text, before "SBOM:", that
// mention a fixed version, as fixed_version, fixed_versions or the plain words: #2817 review, so a
// sentence added on another line that gives cve_intel's fixed_version unconditionally fails here,
// not only in the byte snapshot.
const fixedVersionLines = (prompt) =>
  prompt
    .split("\nSBOM:\n")[0]
    .split("\n")
    .filter((l) => /fixed[_ ]versions?/i.test(l));
// The fields a prompt reads from another field the text keeps, where its text says so, on the
// objects it reads them on (sbom_review: the affected components, whose CVEs it looks up).
// #2836: step 2's upstream sentence, which says how matched_package and matched_via are read from
// the purl where the leanest cut leaves them out of a row.
const UPSTREAM_STEP = /A deb, apk or alpine purl with an upstream qualifier \(upstream=name, or upstream=name@version\) is checked as the source package it names[^\n]*For any other purl check_sbom checks, matched_via is purl_name and matched_package is the package read as above\./;
const DERIVED = {
  sbom_review: (prompt) =>
    DERIVE_STEP.test(prompt)
      ? {
          from: "purl",
          fields: ["ecosystem", "package", "version", ...(UPSTREAM_STEP.test(prompt) ? ["matched_package", "matched_via"] : [])],
          derive: fromPurl,
          where: (row) => row.verdict === "affected",
        }
      : undefined,
};

// Production's check_sbom answer for log4j-core 2.14.1, read through the hosted endpoint
// (prod-shaped/check_sbom-log4j-core.json): one row, whole in the text.
// #2817: cve_intel on production's rows with the fixed_branches core-backend serves since #2817
// (text-bound.mjs SHAPED), which the prompts now read.
const INTEL_2817 = "cve_intel, CVE-2021-44228, with fixed_branches (#2817)";
const LOG4J = { label:"check_sbom, log4j-core 2.14.1 (one purl)", args: { purls: ["pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"] }, fixture: "check_sbom-log4j-core", answers: ["batch"] };
// #2834: LOG4J's answer with the fields core-backend adds to each registry match since #2834
// (cve/pkgmatch.go): fixed_in, the fixed bound of the interval that holds 2.14.1, and interval; or
// fixed_in null with fixed_in_reason. Production's answer (2026-10-05) does not carry them yet, so
// these are set here: the Log4Shell family's fixes for the 2.13.0 branch, and null for the rest.
const LOG4J_FIXED_IN = {
  "CVE-2021-44228": "2.15.0",
  "CVE-2021-45046": "2.16.0",
  "CVE-2021-45105": "2.17.0",
  "CVE-2021-44832": "2.17.1",
};
const withFixedIn = (answers, fixes = LOG4J_FIXED_IN) =>
  Object.fromEntries(
    Object.entries(answers).map(([path, body]) => [
      path,
      {
        ...body,
        results: body.results.map((r) => ({
          ...r,
          matches: (r.matches ?? []).map((m) =>
            Object.hasOwn(fixes, m.cve_id)
              ? { ...m, fixed_in: fixes[m.cve_id], interval: { introduced: "2.13.0", fixed: fixes[m.cve_id] } }
              : { ...m, fixed_in: null, fixed_in_reason: "no fixed version is recorded for the interval that holds this version" },
          ),
        })),
      },
    ]),
  );
const LOG4J_2834 = { ...LOG4J, label: "check_sbom, log4j-core 2.14.1, with fixed_in (#2834)" };
// #2836: core-backend names on every row its lookup ran for the package it was matched by
// (matched_package, the lookup's package, which the row's package field carries too) and how
// (matched_via): purl_name for a purl matched by its own name (cve/matchbatch.go). The shaped
// answers predate the fields, so they are set here from each row's own package, as core-backend
// sets them.
const withMatched = (answers) =>
  Object.fromEntries(
    Object.entries(answers).map(([p, body]) => [
      p,
      {
        ...body,
        results: body.results.map((r) => (typeof r.package === "string" ? { ...r, matched_package: r.package, matched_via: "purl_name" } : r)),
      },
    ]),
  );
// #2836: an upstream row, shaped as core-backend answered one on 2026-10-11 (#2836's verification:
// libcrypto3 3.3.6-r0 with upstream=openssl on Alpine 3.20, affected, matched_package openssl,
// matched_via upstream): the lookup's package and version are the source package's, and the row
// keeps the purl's own name as purl_name. One match of LOG4J's answer stands in for its CVEs, with
// fixed_in set as core-backend sets it since #2834.
const UPSTREAM_PURL = "pkg:apk/alpine/libcrypto3@3.3.6-r0?distro=alpine-3.20&upstream=openssl";
const upstreamAnswers = (answers) =>
  Object.fromEntries(
    Object.entries(answers).map(([p, body]) => {
      const [row] = body.results;
      const [m] = row.matches;
      return [
        p,
        {
          ...body,
          results: [
            {
              ...row,
              index: 0,
              purl: UPSTREAM_PURL,
              ecosystem: "Alpine:v3.20",
              package: "openssl",
              version: "3.3.6-r0",
              matched_package: "openssl",
              matched_via: "upstream",
              purl_name: "libcrypto3",
              matched_version_from: "purl",
              matches: [{ ...m, match_reason: `${m.match_reason ?? ""} [matched by the purl's upstream qualifier: source package openssl, purl name libcrypto3]`, fixed_in: "3.3.7-r0", interval: { introduced: "3.3.0-r0", fixed: "3.3.7-r0" } }],
              cve_ids: [m.cve_id],
              count: 1,
            },
          ],
        },
      ];
    }),
  );
const UPSTREAM = { label: "check_sbom, an upstream row: libcrypto3 3.3.6-r0, upstream=openssl (#2836)", args: { purls: [UPSTREAM_PURL] } };

// a < b, a = b or a > b (-1, 0, 1) for release versions of dot-separated numbers; undefined for
// any other (a pre-release, a qualifier, a revision), which the prompt says not to give.
function releaseOrder(a, b) {
  const nums = (v) => (/^\d+(\.\d+)*$/.test(v) ? v.split(".").map(Number) : undefined);
  const [x, y] = [nums(a), nums(b)];
  if (!x || !y) return undefined;
  for (let i = 0; i < Math.max(x.length, y.length); i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) < (y[i] ?? 0) ? -1 : 1;
  return 0;
}

// sbom_review's fix rule, as its text states it, on what the model is shown for one CVE on one
// component: a match's fixed_in where the text keeps the match and it carries one (#2834), else the
// fixed of the cve_intel fixed_branches range that holds the installed version (#2817), moved on
// while another range holds it (#3074, fixedBranchesWalk), else, for a package without
// fixed_branches, cve_intel's fixed_version for the component's ecosystem and package; offered, the
// ones strictly greater than the installed version. No match_reason is read (#2834's last review):
// through 2.7.2 the rule first read the advisory interval in it, "[A, B)" a fix and "[A, B]" a last
// affected version (#2830), and fixed_in now says the same where it decides (and, since #3074, past
// any overlapping interval, which a "[A, B)" of one interval does not show).
// A fixed_branches range holds v: at or above its introduced ("0" is the first version) and below
// its fixed, or at or below its last_affected, or with no end.
function branchHolds(b, v) {
  const from = b.introduced === "0" ? -1 : releaseOrder(b.introduced, v);
  if (from === undefined || from > 0) return false;
  if (b.fixed) return releaseOrder(v, b.fixed) === -1;
  if (b.last_affected) return [-1, 0].includes(releaseOrder(v, b.last_affected));
  return true;
}
// #3074, the rule's walk over one row's ranges: from the ranges holding the installed version, move
// to the highest fixed while another range still holds it; a range on the way with no fixed (its
// last_affected at or past every fixed, or no end) ends it with none. undefined: no fix given.
function fixedBranchesWalk(branches, installed) {
  let point = installed;
  for (let step = 0; step <= branches.length; step++) {
    const holders = branches.filter((b) => branchHolds(b, point));
    if (holders.length === 0) return point === installed ? undefined : point;
    if (holders.some((b) => !b.fixed && !b.last_affected)) return undefined;
    const max = (xs) => xs.reduce((a, x) => (a === undefined || releaseOrder(x, a) === 1 ? x : a), undefined);
    const top = max(holders.filter((b) => b.fixed).map((b) => b.fixed));
    const last = max(holders.filter((b) => !b.fixed).map((b) => b.last_affected));
    if (top === undefined || (last !== undefined && releaseOrder(last, top) !== -1)) return undefined;
    point = top;
  }
  return undefined;
}
// #3285 (3.1.0's lane P): for a Packagist or Maven component, the rule reads the rows of its
// package_name under that ecosystem, bare and with a repository URL after ":", as one row, their
// ranges together, as the matcher does (core-backend registryRecordKey); a release suffix is never
// folded. oneRow false is the rule as it read through d42d4697: the row of the component's own
// ecosystem string alone.
const REPOSITORY_BASES = ["packagist", "maven"];
const ecoBase = (e) => e.trim().toLowerCase().split(":")[0];
function fixRule(row, cve, intel, { ecosystem, pkg, installed }, { oneRow = true } = {}) {
  const above = (v, floor) => releaseOrder(v, floor) === 1;
  // #2834: a match that has a fixed_in field decides: a version is the fix, null is none, and the
  // rest of the rule is not read for that CVE.
  const decided = (row.matches ?? []).filter((x) => x.cve_id === cve && Object.hasOwn(x, "fixed_in"));
  if (decided.length) {
    const fromFixedIn = decided.filter((m) => typeof m.fixed_in === "string").map((m) => ({ from: "fixed_in", version: m.fixed_in }));
    return { candidates: fromFixedIn, offered: fromFixedIn.filter((c) => above(c.version, installed)) };
  }
  const candidates = [];
  // #2817: the fixed of the cve_intel range (fixed_branches) that holds the installed version,
  // walked past any range that still holds it (#3074); a range closed by last_affected has no fix
  // on record.
  const folds = oneRow && REPOSITORY_BASES.includes(ecoBase(ecosystem));
  const ofComponent = (r) => (folds ? ecoBase(r.ecosystem) === ecoBase(ecosystem) && r.package_name.toLowerCase() === pkg.toLowerCase() : r.ecosystem === ecosystem && r.package_name === pkg);
  const branchRows = (intel.affected_packages ?? []).filter((r) => ofComponent(r) && Array.isArray(r.fixed_branches));
  for (const branches of folds && branchRows.length ? [branchRows.flatMap((r) => r.fixed_branches)] : branchRows.map((r) => r.fixed_branches)) {
    const fix = fixedBranchesWalk(branches, installed);
    if (fix !== undefined) candidates.push({ from: "fixed_branches", version: fix });
  }
  if (candidates.length === 0 && branchRows.length === 0) {
    for (const r of [...(intel.affected_packages ?? []), ...(intel.fixed_versions ?? [])]) {
      if (r.ecosystem === ecosystem && r.package_name === pkg && r.fixed_version) candidates.push({ from: "cve_intel", version: r.fixed_version });
    }
  }
  return { candidates, offered: candidates.filter((c) => above(c.version, installed)) };
}

/** The fields prompt `name` names: its snake_case words and PLAIN words, less ENVELOPE_RULES' line and the embedded SBOM. */
function namedFields(name, prompt) {
  const own = prompt
    .split("\nSBOM:\n")[0]
    .split("\n")
    .filter((l) => !l.startsWith("Before you use any figure"))
    .join("\n");
  const plain = PLAIN[name].filter((w) => new RegExp(`\\b${w}\\b`).test(own));
  assert.deepEqual(plain, PLAIN[name], `${name} no longer uses ${PLAIN[name].filter((w) => !plain.includes(w)).join(", ")} as a field name`);
  return [...new Set([...(own.match(/\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b/g) ?? []), ...plain])];
}

// #3013's review: the fields prompt `name` reads from a check_sbom or scan_manifest match: the
// snake_case and PLAIN field words of each sentence of its own text (less ENVELOPE_RULES' line and
// the embedded SBOM) that reads from a match ("its matches", "the match's", "the match carries")
// and calls no tool but those two (workload_triage's step 5 sends a row without matches to get_cve
// for the same fields), that are fields of some match (`matchKeys`).
const MATCH_WORD = /\bmatch(?:es|'s)?\b/;
function matchFieldsRead(name, prompt, toolNames, matchKeys) {
  const own = prompt
    .split("\nSBOM:\n")[0]
    .split("\n")
    .filter((l) => !l.startsWith("Before you use any figure"))
    .join("\n");
  const out = [];
  for (const sentence of own.split(/(?<=[.!?])\s+/)) {
    if (!MATCH_WORD.test(sentence)) continue;
    const words = [...(sentence.match(/\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b/g) ?? []), ...PLAIN[name].filter((w) => new RegExp(`\\b${w}\\b`).test(sentence))];
    if (words.some((w) => toolNames.has(w) && w !== "check_sbom" && w !== "scan_manifest")) continue;
    for (const w of words) if (matchKeys.has(w) && !out.includes(w)) out.push(w);
  }
  return out;
}
// The fields of `fields` a thinned row's matches leave out, given a thinning level (SBOM_ROW_THIN).
function thinProblems(fields, rowThin) {
  const kept = rowThin.find((k) => Array.isArray(k) && k[0] === "matches")?.[1] ?? [];
  return fields.filter((f) => !kept.includes(f));
}

/**
 * Holds one call's result to the fields named: wherever the text keeps an object the answer has,
 * it keeps each named field that object has, or (`derived`, DERIVED) the field it is read from,
 * which then gives the answer's value. Returns the named fields the text (or the envelope block)
 * carries.
 */
function heldTo(label, res, named, derived = undefined) {
  assert.notEqual(res.isError, true, `${label}: ${blocksOf(res)[0]?.slice(0, 300)}`);
  const blocks = blocksOf(res);
  const pairs = cutPairs(JSON.parse(blocks[0]), res.structuredContent.data);
  const envelope = JSON.parse(blocks.at(-1));
  const carried = new Set();
  // A field the prompt reads from another: true where the text's object lets the model read it as
  // the answer has it, or the prompt does not read it on that object.
  const read = (p, f) => {
    if (!derived?.fields.includes(f) || typeof p.text[derived.from] !== "string") return false;
    if (!derived.where(p.answer)) return true;
    assert.equal(derived.derive(p.text[derived.from])[f], p.answer[f], `${label}: ${f} read from ${derived.from} ${p.text[derived.from]} as the prompt says is not the answer's (${p.at})`);
    return true;
  };
  // Where the text keeps the field as well, reading it the prompt's way gives the same value.
  for (const p of pairs) for (const f of derived?.fields ?? []) if (Object.hasOwn(p.text, f)) read(p, f);
  for (const f of named) {
    const lost = pairs.filter((p) => Object.hasOwn(p.answer, f) && !Object.hasOwn(p.text, f) && !read(p, f));
    assert.equal(lost.length, 0, `${label}: the prompt names ${f}, and ${lost.length} objects in the first text block leave it out (first ${lost[0]?.at}) although the answer's have it`);
    if (pairs.some((p) => Object.hasOwn(p.text, f))) carried.add(f);
    if ([envelope, envelope.coverage, envelope.freshness].some((o) => o !== null && typeof o === "object" && Object.hasOwn(o, f))) carried.add(f);
  }
  return carried;
}

describe("#2799: what each prompt names is in the text its tools return, at the prompt's largest input", () => {
  let stub;
  let client;
  let toolNames;
  before(async () => {
    stub = await startStub();
    client = await connect({ era: MODERN, ...serverCommand(), env: { ...process.env, ECHELONGRAPH_API_BASE: stub.base, ECHELONGRAPH_API_TIMEOUT_MS: "10000" }, stderr: "inherit" });
    toolNames = new Set((await client.listTools()).tools.map((t) => t.name));
  });
  after(async () => {
    await client?.close();
    await stub?.close();
  });

  // One call on `answers` (stub overrides), as `limited` says. With full: true (#3013): the text,
  // which is what this file holds, is the same either way, and structuredContent.data is then the
  // answer whole that the text is a cut of.
  const call = async (name, args, answers, limited = undefined) => {
    stub.state.answers = answers;
    stub.state.limited = limited;
    stub.state.requests = 0;
    return client.callTool({ name, arguments: { ...args, full: true } });
  };
  // Every named field is carried by some call, a tool's name, or a value; and every tool the prompt
  // names is one this test called.
  const allCarried = (t, prompt, named, carried, called) => {
    t.diagnostic(`${prompt} names ${named.join(", ")}`);
    for (const f of named) assert.ok(carried.has(f) || toolNames.has(f) || VALUES.has(f), `${prompt} names ${f}, and no call's text carries it`);
    const tools = named.filter((f) => toolNames.has(f)).sort();
    assert.deepEqual(tools, [...new Set(called)].sort(), `${prompt} names the tools ${tools.join(", ")}; this test called ${[...new Set(called)].sort().join(", ")}: run each tool the prompt calls at its largest input`);
  };

  it("kev_weekly_brief, 365 days: the page it asks kev_recent for keeps every row and, on each, every field a brief line names", async (t) => {
    const prompt = textOf(await client.getPrompt({ name: "kev_weekly_brief", arguments: { days: "365" } }));
    const named = namedFields("kev_weekly_brief", prompt);
    const limit = Number(prompt.match(/Call kev_recent with since set to that date and limit (\d+)\./)?.[1]);
    assert.ok(limit >= 1 && limit <= 200, `the brief's kev_recent limit: ${limit}`);
    for (const f of ["kev_vendor", "cve_id", "kev_product", "kev_vuln_name", "kev_added_date", "kev_due_date", "kev_ransomware"]) assert.ok(named.includes(f), `the brief no longer names ${f}`);
    // A full page: 365 days held 306 KEV additions on the hosted endpoint on 2026-10-04, more than any page.
    const since = new Date(Date.now() - 365 * 864e5).toISOString().slice(0, 10);
    const answers = shapedAnswers({ fixture: "kev_recent", answers: ["recent"], repeat: { kev: limit }, set: { limit, count: limit, total: 306, next_cursor: "MjAyNS0xMC0wNHxDVkUtMjAyNS0wMDAwMQ" } });
    const res = await call("kev_recent", { since, limit }, answers);
    const shown = JSON.parse(blocksOf(res)[0]);
    t.diagnostic(`limit ${limit}: first text block ${blocksOf(res)[0].length} characters, ${shown.kev.length} rows, each with ${Object.keys(shown.kev[0]).join(", ")}`);
    // next_cursor continues after the page's last row: a row left out of the text is skipped by the brief.
    assert.equal(shown.kev.length, res.structuredContent.data.kev.length, "rows of the page left out of the text, which the brief's next_cursor would skip");
    allCarried(t, "kev_weekly_brief", named, heldTo(`kev_recent, limit ${limit}`, res, named), ["kev_recent"]);
  });

  // The API caps matches at 200: the CPE path at its cap, with and without the excluded sample
  // beside the matches, and the registry path at its cap with 50 undetermined beside them.
  it("am_i_affected, at check_affected's cap of 200 matches: every match keeps each field the prompt lists per match", async (t) => {
    const django = caseOf("check_affected, PyPI django 1.11.0 (the registry path)");
    const [[djangoPath, djangoBody]] = Object.entries(shapedAnswers(django));
    const matches = Array.from({ length: 200 }, (_, i) => ({ ...djangoBody.matches[i % djangoBody.matches.length], cve_id: `CVE-2026-${String(20000 + i)}` }));
    // #2834: registry matches carry fixed_in (a version, or null with fixed_in_reason), which the
    // registry text names; production's django answer (2026-10-04) predates it, so it is set here,
    // on django's own 29 matches. At the cap of 200 beside 50 undetermined, fixed_in costs about
    // 22 characters a match and pushes 15 matches out of check_affected's text (29,871 characters,
    // 185 of 200, measured 2026-10-05). No field of check_affected's last level can go, so its
    // description says a registry list near the cap can leave its last matches out, and the note
    // says how many (text-bound.test.mjs holds that case at the cap); the 200-match case below is
    // held as production answered it before fixed_in.
    const withFixedIn = Object.fromEntries(
      Object.entries(shapedAnswers(django)).map(([p, body]) => [
        p,
        { ...body, matches: body.matches.map((m, i) => ({ ...m, ...(i % 4 === 3 ? { fixed_in: null, fixed_in_reason: "no fixed version is recorded for the interval that holds this version" } : { fixed_in: "2.2.28", interval: { introduced: "0", fixed: "2.2.28" } }) })) },
      ]),
    );
    const undetermined = Array.from({ length: 50 }, (_, i) => ({ cve_id: `CVE-2025-${String(30000 + i)}`, package: "django", ecosystem: "PyPI", reason: "collapsed_fix_boundary", detail: "the advisory's affected range collapses to its fix boundary" }));
    const inputs = [
      [{ product: "linux_kernel", version: "5.10.0" }, shapedAnswers(caseOf("check_affected, linux_kernel 5.10.0 (200 matches, the API's cap)"))],
      [{ product: "flash_player", version: "10.0.0" }, shapedAnswers(caseOf("check_affected, flash_player 10.0.0 (200 matches and an excluded sample of 50)"))],
      [{ ecosystem: "PyPI", package: "django", version: "1.11.0" }, { [djangoPath]: { ...djangoBody, matches, cve_ids: matches.map((m) => m.cve_id), count: 200, capped: true, undetermined, undetermined_count: 73 } }],
      [{ ecosystem: "PyPI", package: "django", version: "1.11.0" }, withFixedIn],
    ];
    const carried = new Set();
    let named;
    for (const [args, answers] of inputs) {
      const prompt = textOf(await client.getPrompt({ name: "am_i_affected", arguments: args }));
      named = namedFields("am_i_affected", prompt);
      for (const f of ["cve_id", "kev_listed", "ransomware", "epss_score", "effective_score", "score_assessed"]) assert.ok(named.includes(f), `am_i_affected no longer names ${f}`);
      // #2834: the registry text names fixed_in; the CPE text, whose matches carry none, does not.
      assert.equal(named.includes("fixed_in"), args.product === undefined, `${JSON.stringify(args)}: fixed_in named ${named.includes("fixed_in")}`);
      const asked = JSON.parse(prompt.match(/1\. Call check_affected with these arguments: (\{.*\})\.\n/)?.[1] ?? "null");
      assert.deepEqual(asked, args);
      const res = await call("check_affected", asked, answers);
      const shown = JSON.parse(blocksOf(res)[0]);
      t.diagnostic(`${JSON.stringify(args)}: first text block ${blocksOf(res)[0].length} characters, ${shown.matches.length} matches, each with ${Object.keys(shown.matches[0]).join(", ")}`);
      assert.equal(shown.matches.length, res.structuredContent.data.matches.length, `${JSON.stringify(args)}: matches left out of the text`);
      assert.ok(shown.matches.length === 200 || answers === withFixedIn, `${JSON.stringify(args)}: ${shown.matches.length} matches, not the cap of 200`);
      for (const f of heldTo(`check_affected ${JSON.stringify(args)}`, res, named)) carried.add(f);
    }
    allCarried(t, "am_i_affected", named, carried, ["check_affected"]);
  });

  // check_sbom's most per call: 2,000 distinct purls, as a CycloneDX document whose components nest
  // (each fifth one the parent of the next four, a duplicate purl and a component without one among
  // them), answered in full and as production answers it from a fresh budget (1,200 answered, 800
  // not sent); and get_cve and cve_intel, which the prompt calls for each affected CVE, on the
  // longest record.
  it("sbom_review, a 2,000-purl SBOM: each row the text keeps carries what the fix list reads, and the purls not sent are rebuilt from the note's position and order", async (t) => {
    const full = caseOf("check_sbom, 2,000 purls (10 batches of 200)");
    const limited = caseOf("check_sbom, 2,000 purls, rate-limited after 6 batches (production's answer from a fresh budget)");
    const purls = argsOf(full).purls;
    const component = (purl, i) => ({ type: "library", name: `shaped-${i}`, purl });
    const components = Array.from({ length: purls.length / 5 }, (_, j) => ({
      ...component(purls[5 * j], 5 * j),
      components: [1, 2, 3, 4].map((k) => ({
        ...component(purls[5 * j + k], 5 * j + k),
        // A grandchild repeating its grandparent's purl, and one without a purl.
        ...(k === 2 ? { components: [component(purls[5 * j], 5 * j), { type: "library", name: `no-purl-${j}` }] } : {}),
      })),
    }));
    const doc = { bomFormat: "CycloneDX", specVersion: "1.5", components };
    const sbom = JSON.stringify(doc);
    const prompt = textOf(await client.getPrompt({ name: "sbom_review", arguments: { sbom } }));
    const named = namedFields("sbom_review", prompt);
    for (const f of ["verdict", "purl", "cve_ids", "not_assessed_reason", "summary", "not_sent", "not_sent_reason", "not_sent_purls", "fixed_in", "fixed_version", "ecosystem", "package", "version", "vendor_remediations", "remediation_kinds", "matched_package", "matched_via", "fixed_in_reason"]) assert.ok(named.includes(f), `sbom_review no longer names ${f}`);
    // #2834's last review: no fixed version is read from match_reason's prose.
    assert.ok(!named.includes("match_reason"), "sbom_review names match_reason again");
    // The prompt passes the document as given.
    assert.ok(prompt.includes(`\`\`\`json\n${sbom}\n\`\`\``));
    assert.match(prompt, /data\.not_sent_purls lists them whole with full: true; where the note says the first text block cuts not_sent_purls to its first entries, or a DATA CUT cuts that list in data, rebuild the list from the document instead, as the note says: the document's distinct purls from the position the note gives on, counted in the order it gives\./);
    assert.match(prompt, /Where the note says that rows of data\.results are left out of the first text block/);
    // A component's ecosystem, package and version, which the leanest cut leaves out of each row,
    // are read from its purl, which it keeps.
    assert.match(prompt, DERIVE_STEP);
    const derived = DERIVED.sbom_review(prompt);
    const carried = new Set();
    for (const c of [full, limited]) {
      // #2836: each row as core-backend answers since #2836, with matched_package and matched_via.
      const res = await call("check_sbom", { sbom }, withMatched(shapedAnswers(c)), c.limited);
      const [first, note] = blocksOf(res);
      const shown = JSON.parse(first);
      const data = res.structuredContent.data;
      t.diagnostic(`${c.label}: first text block ${first.length} characters, ${shown.results.length} of ${data.results.length} rows, each with ${Object.keys(shown.results[0]).join(", ")}`);
      // This input reaches the cut that leaves the row's own ecosystem, package and version out.
      assert.ok(shown.results.every((r) => typeof r.purl === "string" && !Object.hasOwn(r, "ecosystem") && !Object.hasOwn(r, "package") && !Object.hasOwn(r, "version")), `${c.label}: the text keeps a row's ecosystem, package or version, so this case does not test reading them from the purl`);
      // ... and matched_package and matched_via, which the answer's affected rows carry.
      assert.ok(data.results.some((r) => r.verdict === "affected" && r.matched_via === "purl_name"), `${c.label}: no affected row carries matched_via, so this case does not test reading it from the purl`);
      assert.ok(shown.results.every((r) => !Object.hasOwn(r, "matched_package") && !Object.hasOwn(r, "matched_via")), `${c.label}: the text keeps matched_package or matched_via, so this case does not test reading them from the purl`);
      for (const f of heldTo(c.label, res, named, derived)) carried.add(f);
      // Rows the text leaves out: the note says how many, as the prompt's last instruction reads it.
      if (shown.results.length < data.results.length) assert.match(note, new RegExp(`Only ${shown.results.length} of the ${data.results.length} rows of results are in it`));
      if (!c.limited) continue;
      // The purls not sent, read as the prompt says: where the note says the text keeps the first
      // entries of not_sent_purls, rebuilt from the document from the note's position, in the order
      // the note's own sentence on them gives: depth first, each component's nested components right
      // after it and before its next sibling, each purl at its first place.
      const m = note.match(/they are the input's distinct purls from position (\d+) on, counted in the order this tool read them \(the order of purls, or of the document's components or packages, each component's nested components right after it and before its next sibling, each purl at its first place\)/);
      assert.ok(m, note);
      assert.match(note, new RegExp(`In it, not_sent_purls keeps its first ${shown.not_sent_purls.length} of ${data.not_sent_purls.length} entries`), "the text cuts not_sent_purls and the note does not say so");
      assert.ok(shown.not_sent_purls.length < data.not_sent_purls.length, "the text keeps every purl not sent, so this case does not test the cut");
      const read = [];
      const walk = (cs) => {
        for (const x of cs ?? []) {
          if (typeof x.purl === "string" && x.purl.trim()) read.push(x.purl.trim());
          walk(x.components);
        }
      };
      walk(doc.components);
      const rebuilt = [...new Set(read)].slice(Number(m[1]) - 1);
      assert.deepEqual(rebuilt, data.not_sent_purls, "the purls rebuilt from the note's position and order are not the purls not sent");
      // Read top-level components first, the nested ones after them, they are not.
      const flat = [...new Set([...components.map((x) => x.purl), ...read])].slice(Number(m[1]) - 1);
      assert.notDeepEqual(flat, data.not_sent_purls, "this document's nesting does not test the order");
    }
    // A small SBOM, whose text keeps each row whole: production's answer for log4j-core 2.14.1
    // (LOG4J).
    const small = await call("check_sbom", LOG4J.args, shapedAnswers(LOG4J));
    for (const f of heldTo(LOG4J.label, small, named, derived)) carried.add(f);
    // #2834, #2836: the same, as core-backend answers since both, each match with fixed_in and the
    // row with matched_package and matched_via.
    const small2834 = await call("check_sbom", LOG4J.args, withMatched(withFixedIn(shapedAnswers(LOG4J))));
    for (const f of heldTo(LOG4J_2834.label, small2834, named, derived)) carried.add(f);
    // #2836: an upstream row, whole in the text: step 2's reading of its purl (openssl at 3.3.6-r0,
    // matched_via upstream) is held to the row's own package, version, matched_package and
    // matched_via (heldTo reads every derived field the text keeps on an affected row).
    const upstream = await call("check_sbom", UPSTREAM.args, upstreamAnswers(shapedAnswers(LOG4J)));
    const [upRow] = JSON.parse(blocksOf(upstream)[0]).results;
    assert.deepEqual([upRow.purl, upRow.verdict, upRow.package, upRow.matched_package, upRow.matched_via], [UPSTREAM_PURL, "affected", "openssl", "openssl", "upstream"], "the upstream case is not shown as core-backend answers it");
    for (const f of heldTo(UPSTREAM.label, upstream, named, derived)) carried.add(f);
    // #2841: cve_remediation for the first CVEs of the list, on its longest production-shaped answer;
    // and (#3013's review) get_vendor_advisory, which the list reads a vendor's step from where
    // cve_remediation's data or text leaves out that item's text.
    for (const label of ["get_cve, CVE-2021-44228", "cve_intel, CVE-2021-44228", INTEL_2817, "cve_remediation, CVE-2021-44228", "get_vendor_advisory, aws 2026-098-AWS"]) {
      const c = caseOf(label);
      for (const f of heldTo(label, await call(c.tool, argsOf(c), shapedAnswers(c)), named, derived)) carried.add(f);
    }
    // #3269's fourth review: past 30 CVEs, step 3 takes the KEV-listed ones first, read from the
    // matches and from matches_truncated's kev_listed_cve_ids, which only the structured result's
    // data carries, on a row whose matches its cut capped: a default call (no full) on Juice Shop
    // 11.1.2 with magento/community-edition 2.3.0, as workload_triage's case below.
    for (const f of ["matches_truncated", "kev_listed_cve_ids"]) assert.ok(named.includes(f), `sbom_review no longer names ${f}`);
    const capped = JSON.parse(fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures", "check_sbom-large-rows.json"), "utf8")).juiceShopMagento;
    stub.state.answers = { "/api/v1/public/cves/match/batch": capped };
    stub.state.limited = undefined;
    stub.state.requests = 0;
    const sc = (await client.callTool({ name: "check_sbom", arguments: { purls: capped.results.map((r) => r.purl) } })).structuredContent;
    const marks = sc.data.results.filter((r) => r.matches_truncated).map((r) => r.matches_truncated);
    assert.ok(marks.some((m) => Array.isArray(m.kev_listed_cve_ids)), "the default call capped no row's matches with kev_listed_cve_ids, so this case holds nothing");
    for (const f of named) if (marks.some((m) => Object.hasOwn(m, f))) carried.add(f);
    carried.add("matches_truncated");
    allCarried(t, "sbom_review", named, carried, ["check_sbom", "get_cve", "cve_intel", "cve_remediation", "get_vendor_advisory"]);
  });

  // #2817: production's cve_intel for CVE-2021-44228 (prod-shaped/cve_intel.json, read again on the
  // hosted endpoint at 2026-10-05T07:38:23Z, after #2817's deploy) keeps one fixed_version for
  // log4j-core, 2.12.2, the advisory's last range's, beside fixed_branches; production's check_sbom
  // for log4j-core 2.14.1 (LOG4J) says each match is "listed verbatim in the advisory's affected
  // versions", which names no fix. Read as the prompt's rule says, what the model is shown offers
  // 2.15.0, the fix of the range holding 2.14.1, and on the same rows without fixed_branches (the
  // API's of 2026-10-04) no fixed version, which the prompt says to write so: never 2.12.2. Through
  // bab4e868 the prompt asked for "each fixed_version cve_intel gives for the component's package".
  it("sbom_review on production's answers for log4j-core 2.14.1 and CVE-2021-44228: its fix rule gives no fixed version older than the installed one, 2.12.2 among them", async (t) => {
    const [purl] = LOG4J.args.purls;
    const sbom = JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.5", components: [{ type: "library", name: "log4j-core", version: "2.14.1", purl }] });
    const prompt = textOf(await client.getPrompt({ name: "sbom_review", arguments: { sbom } }));
    const own = prompt.split("\nSBOM:\n")[0];
    // The rule, word for word: fixed_in alone where the text keeps the match; otherwise strictly
    // greater than the installed version, in the ecosystem's order, not as text; cve_intel's one value
    // per package named as such; and otherwise no fixed version for the branch, pointing to the
    // advisory.
    assert.ok(own.includes("Where the text keeps the component's match for the CVE and the match carries fixed_in, read fixed_in alone"), own);
    assert.ok(own.includes("Never give a fixed version that is not strictly greater than the component's installed version (its version, as step 2 reads it from the purl), compared in the ecosystem's version order: release numbers part by part, as numbers, not as text (2.9.1 is below 2.12.2, and 2.12.2 is below 2.14.1); where you are not sure of the order (pre-releases, qualifiers and distro revisions have their own rules), say so and do not give it."), own);
    // #2834's last review: no fixed version is read from match_reason's advisory interval, the
    // prose fixed_in replaced (through 2.7.2 the rule read "[A, B)" as a fix and "[A, B]" as a last
    // affected version, #2830); nor is its bound hedged, as through 2.6.5.
    assert.doesNotMatch(own, /match_reason|advisory interval \[A, B/, "sbom_review still reads a fixed version from match_reason");
    assert.doesNotMatch(own, /does not say is a fixed version rather than|give B as the end of that interval/, "sbom_review still hedges the [A, B) bound");
    assert.match(own, /cve_intel keeps one fixed_version per package, its advisory's last range's, which need not be the fix on the component's branch/);
    assert.match(own, /Where no version meets the rule, write that the results give no fixed version for the component's branch, which is not a finding that no fix exists, and point to the CVE's advisory for it: get_cve's references tagged Vendor Advisory or Patch/);
    assert.doesNotMatch(own, /each fixed_version cve_intel gives/, "the prompt still asks for every fixed_version cve_intel gives, whatever the installed version");
    // A fixed version is spoken of in step 3 (where fixed_version is read) and the rule's
    // paragraph, nowhere else: a line elsewhere telling the model to give fixed versions would
    // stand beside the rule, not under it.
    const fixedLines = fixedVersionLines(prompt);
    assert.deepEqual(
      fixedLines.map((l) => (l.startsWith("3. For each distinct cve_id") ? "step 3" : l.startsWith("For each line give the component") ? "rule" : l)),
      ["step 3", "rule"],
      "a fixed version is spoken of outside step 3 and the fix rule's paragraph",
    );

    // Step 2 maps a purl as core-backend's matcher does: every type purlosv maps, the types named
    // with their namespace, the distro qualifiers it reads (Alpine cut to major.minor, Debian to its
    // major), and any other ecosystem unknown, given no version.
    const step2 = own.split("\n").find((l) => DERIVE_STEP.test(l));
    const ecosystems = Object.entries(PURL_ECOSYSTEM).map(([t, e]) => `${t} ${t === "npm" ? "is npm" : e}`);
    for (const pair of ecosystems) assert.ok(step2.includes(pair), `step 2 does not map ${pair}`);
    assert.ok(step2.includes(`The ecosystem follows from the type: ${ecosystems.slice(0, -1).join(", ")} and ${ecosystems.at(-1)}. For deb, apk, alpine and rpm`), "step 2 maps another type, or these in another order");
    assert.ok(step2.includes(`namespace/name for ${NAMESPACED.slice(0, -1).join(", ")} and ${NAMESPACED.at(-1)}, and the name alone for every other type`), "step 2 names other types with their namespace than the matcher does");
    for (const [distro, eco] of [["debian-12", "Debian:12"], ["debian-12.5", "Debian:12"], ["ubuntu-22.04", "Ubuntu:22.04"], ["alpine-3.20", "Alpine:v3.20"], ["alpine-3.20.10", "Alpine:v3.20"]]) {
      assert.equal(distroEcosystem(distro), eco);
      assert.match(step2, new RegExp(`${distro.replace(/\./g, "\\.")}[^;]*? (is|are) ${eco.replace(/\./g, "\\.")}\\b`), `step 2 does not map distro=${distro} to ${eco}`);
    }
    assert.equal(distroEcosystem("alpine-3"), undefined);
    assert.match(step2, /alpine-3 names none/);
    assert.match(step2, /For any other type, and a deb, apk, alpine or rpm purl without such a qualifier, the ecosystem is unknown: check_sbom does not check the component \(not_assessed, never clean\), and the fix list gives no version for it\./);
    assert.deepEqual(fromPurl("pkg:deb/debian/openssl@3.0.15-1~deb12u1?distro=debian-12"), { ecosystem: "Debian:12", package: "openssl", version: "3.0.15-1~deb12u1", matched_package: "openssl", matched_via: "purl_name" });
    assert.ok(step2.includes("pkg:deb/debian/openssl@3.0.15-1~deb12u1?distro=debian-12 is openssl in Debian:12"));
    assert.deepEqual(fromPurl("pkg:githubact/actions/checkout@v4"), { ecosystem: "GitHub Actions", package: "actions/checkout", version: "v4", matched_package: "actions/checkout", matched_via: "purl_name" });
    assert.deepEqual(fromPurl("pkg:rpm/redhat/openssl@3.0.7?distro=rhel-9"), { ecosystem: undefined, package: "openssl", version: "3.0.7", matched_package: "openssl", matched_via: "purl_name" });
    // #2836: an upstream qualifier on a deb, apk or alpine purl names the package, and its version
    // where it gives one; on any other type it is ignored, as core-backend ignores it.
    assert.deepEqual(fromPurl(UPSTREAM_PURL), { ecosystem: "Alpine:v3.20", package: "openssl", version: "3.3.6-r0", matched_package: "openssl", matched_via: "upstream" });
    assert.deepEqual(fromPurl("pkg:deb/debian/libssl3@3.0.11-1~deb12u2?distro=debian-12&upstream=openssl%403.0.11-1~deb12u2"), { ecosystem: "Debian:12", package: "openssl", version: "3.0.11-1~deb12u2", matched_package: "openssl", matched_via: "upstream" });
    assert.deepEqual(fromPurl("pkg:npm/lodash@4.17.19?upstream=other"), { ecosystem: "npm", package: "lodash", version: "4.17.19", matched_package: "lodash", matched_via: "purl_name" });
    assert.match(step2, /pkg:apk\/alpine\/libcrypto3@3\.3\.6-r0\?distro=alpine-3\.20&upstream=openssl is openssl in Alpine:v3\.20, at 3\.3\.6-r0/);

    // What the model is shown: check_sbom's and cve_intel's first text blocks.
    const sbomRes = await call("check_sbom", { sbom }, shapedAnswers(LOG4J));
    assert.notEqual(sbomRes.isError, true, blocksOf(sbomRes)[0]);
    const [row] = JSON.parse(blocksOf(sbomRes)[0]).results;
    assert.equal(row.purl, purl);
    assert.equal(row.verdict, "affected");
    const { ecosystem, package: pkg, version: installed } = fromPurl(row.purl);
    assert.deepEqual([ecosystem, pkg, installed], ["Maven", "org.apache.logging.log4j:log4j-core", "2.14.1"]);
    const intelCase = caseOf("cve_intel, CVE-2021-44228");
    const intel = JSON.parse(blocksOf(await call("cve_intel", argsOf(intelCase), shapedAnswers(intelCase)))[0]);
    const cve = "CVE-2021-44228";
    assert.ok(row.cve_ids.includes(cve));

    assert.ok(row.matches.filter((m) => m.cve_id === cve).every((m) => /listed verbatim in the advisory's affected versions/.test(m.match_reason)));
    // Production's rows since #2817's deploy (prod-shaped/cve_intel.json, read 2026-10-05) carry
    // fixed_branches: the rule gives the fixed of the range holding 2.14.1, 2.15.0, never 2.12.2.
    const core = intel.affected_packages.find((r) => r.ecosystem === ecosystem && r.package_name === pkg);
    assert.equal(core.fixed_version, "2.12.2", "cve_intel no longer gives log4j-core 2.12.2 for CVE-2021-44228, so this case does not test the rule");
    const now = fixRule(row, cve, intel, { ecosystem, pkg, installed });
    t.diagnostic(`${cve} on ${purl}: candidates ${JSON.stringify(now.candidates)}, offered ${JSON.stringify(now.offered)}`);
    assert.deepEqual(now.offered, [{ from: "fixed_branches", version: "2.15.0" }]);
    assert.ok(!now.candidates.some((c) => c.version === "2.12.2"), "the rule reads fixed_version where fixed_branches is there");
    // The same rows from an API older than #2817 (production's of 2026-10-04): no fixed_branches,
    // and the hazard is in what the model is shown, cve_intel's 2.12.2 for this package.
    const older = { ...intel, affected_packages: intel.affected_packages.map(({ fixed_branches, ...r }) => r) };
    const { candidates, offered } = fixRule(row, cve, older, { ecosystem, pkg, installed });
    t.diagnostic(`${cve} on ${purl}, rows without fixed_branches: candidates ${JSON.stringify(candidates)}, offered ${JSON.stringify(offered)}`);
    assert.ok(candidates.some((c) => c.from === "cve_intel" && c.version === "2.12.2"), "without fixed_branches the rule no longer meets cve_intel's 2.12.2, so this case does not test the rule");
    assert.deepEqual(offered, [], "the rule offers a fixed version that is not above the installed 2.14.1");

    // The other polarity, on production's Juice Shop answer: lodash 4.17.19 falls inside
    // [0, 4.17.21) for CVE-2021-23337, and as core-backend answers since #2834 the match carries that
    // interval's fixed bound as fixed_in, which the rule gives.
    const lodash = readShaped("check_sbom").answers.batch.body.results.find((r) => r.purl === "pkg:npm/lodash@4.17.19");
    assert.ok(lodash.matches.some((m) => m.cve_id === "CVE-2021-23337" && m.match_reason.endsWith("falls inside the advisory interval [0, 4.17.21)")), "the Juice Shop row no longer falls inside [0, 4.17.21): re-aim this polarity");
    const l = fromPurl(lodash.purl);
    const lodash2834 = { ...lodash, matches: lodash.matches.map((m) => (m.cve_id === "CVE-2021-23337" ? { ...m, fixed_in: "4.17.21", interval: { introduced: "0", fixed: "4.17.21" } } : m)) };
    assert.deepEqual(fixRule(lodash2834, "CVE-2021-23337", { affected_packages: [], fixed_versions: [] }, { ecosystem: l.ecosystem, pkg: l.package, installed: l.version }).offered, [{ from: "fixed_in", version: "4.17.21" }]);
  });

  // #2830: core-backend's match_reason rendered an OSV last_affected bound L as "[A, L)", the same
  // as a fixed bound, so a reader took L, a version still affected, as the fix. It renders it
  // "[A, L] (L is the last affected version, not a fix)" since (core-backend cve/pkgmatch.go
  // renderInterval; LAST_AFFECTED_REASON below is the string its
  // TestEvaluateRegistryRow_IntervalBoundRendering pins), and through 2.7.2 sbom_review read that
  // bracket. Since #2834 each registry match also carries fixed_in, the interval's fixed bound, or
  // null for a last_affected interval, and the rule reads fixed_in alone (#2834's last review): a
  // last_affected interval gives no fix, and no cve_intel value is offered beside it. Here the
  // production Juice Shop row for lodash 4.17.19 is shown to the model with CVE-2021-23337's interval
  // as each kind of bound, as core-backend answers since #2834, through check_sbom's text.
  const LAST_AFFECTED_REASON = "registry package (confidence 0.95): npm/lodash — version 4.17.19 falls inside the advisory interval [0, 4.17.20] (4.17.20 is the last affected version, not a fix)";
  const LAST_AFFECTED_FIXED_IN = { fixed_in: null, fixed_in_reason: "the interval that holds this version ends at last_affected; no fixed version is recorded" };
  it("sbom_review's fix rule on check_sbom's text (#2830, #2834): a fixed bound's fixed_in is the fix; a last_affected interval's null gives none, nor any cve_intel version; match_reason is not read", async () => {
    const batch = readShaped("check_sbom").answers.batch;
    const lodash = batch.body.results.find((r) => r.purl === "pkg:npm/lodash@4.17.19");
    const cve = "CVE-2021-23337";
    const shown = async (row) => {
      const res = await call("check_sbom", { purls: [row.purl] }, { [batch.path]: { ...batch.body, results: [{ ...row, index: 0 }] } });
      assert.notEqual(res.isError, true, blocksOf(res)[0]);
      const [r] = JSON.parse(blocksOf(res)[0]).results;
      assert.equal(r.purl, row.purl);
      return r;
    };
    const target = { ecosystem: "npm", pkg: "lodash", installed: "4.17.19" };
    const noIntel = { affected_packages: [], fixed_versions: [] };
    const intelAt = (v) => ({ affected_packages: [{ ecosystem: "npm", package_name: "lodash", fixed_version: v }], fixed_versions: [] });
    const withCve = (extra) => ({ ...lodash, matches: lodash.matches.map((m) => (m.cve_id === cve ? { ...m, ...extra } : m)) });

    // A fixed bound: "[0, 4.17.21)", as production renders it, with fixed_in 4.17.21: the text keeps
    // both, and the rule gives fixed_in.
    const fixedRow = await shown(withCve({ fixed_in: "4.17.21", interval: { introduced: "0", fixed: "4.17.21" } }));
    assert.ok(fixedRow.matches.some((m) => m.cve_id === cve && m.match_reason.endsWith("falls inside the advisory interval [0, 4.17.21)") && m.fixed_in === "4.17.21"));
    assert.deepEqual(fixRule(fixedRow, cve, noIntel, target).offered, [{ from: "fixed_in", version: "4.17.21" }]);

    // A last_affected bound: the text keeps the closed bracket and its words, and fixed_in null;
    // nothing is given, and cve_intel's value is never offered, at the last affected version or above.
    const lastRow = await shown(withCve({ match_reason: LAST_AFFECTED_REASON, ...LAST_AFFECTED_FIXED_IN }));
    const kept = lastRow.matches.filter((m) => m.cve_id === cve);
    assert.deepEqual(kept.map((m) => [m.match_reason, m.fixed_in]), [[LAST_AFFECTED_REASON, null]], "check_sbom's text does not keep the last_affected match as core-backend answers it");
    assert.deepEqual(fixRule(lastRow, cve, noIntel, target), { candidates: [], offered: [] }, "the rule takes a last_affected interval as a fix");
    assert.deepEqual(fixRule(lastRow, cve, intelAt("4.17.20"), target).offered, [], "the rule offers cve_intel's version at the last affected one");
    assert.deepEqual(fixRule(lastRow, cve, intelAt("4.17.21"), target).offered, [], "the rule reads cve_intel where fixed_in is null");

    // match_reason is not read: a "[0, 4.17.21)" interval with no fixed_in field gives nothing from
    // it; only cve_intel's rule applies to that match.
    const proseOnly = await shown(lodash);
    assert.ok(proseOnly.matches.some((m) => m.cve_id === cve && m.match_reason.endsWith("[0, 4.17.21)") && !Object.hasOwn(m, "fixed_in")));
    assert.deepEqual(fixRule(proseOnly, cve, noIntel, target), { candidates: [], offered: [] }, "the rule reads a fixed version from match_reason");
  });

  // #2830 reviews: check_sbom's first cut level clips every string to 200 characters, so a long
  // last_affected match_reason loses the words core-backend adds after the bracket, or the bracket
  // itself ("[A, B…"). Through 2.7.2 the rule read the bracket alone, and gave nothing from a
  // clipped one. Since #2834's last review it reads no match_reason: the cut keeps each kept match's
  // fixed_in (null for a last_affected interval), and nothing is given, however the prose is cut.
  it("sbom_review's fix rule on a cut check_sbom text (#2830, #2834): a long last_affected match is clipped, keeps fixed_in null, and gives no fixed version", async () => {
    const batch = readShaped("check_sbom").answers.batch;
    const lodash = batch.body.results.find((r) => r.purl === "pkg:npm/lodash@4.17.19");
    const cve = "CVE-2021-23337";
    const group = "org.apache.logging.log4j.extended.components";
    const artifact = "log4j-core-extended-artifact";
    const cases = [
      {
        what: "the bracket kept, its words cut",
        purl: "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.10",
        pkg: "com.fasterxml.jackson.core:jackson-databind",
        installed: "2.9.10",
        reason: "registry package (confidence 0.95): Maven/com.fasterxml.jackson.core:jackson-databind — version 2.9.10 falls inside the advisory interval [2.0.0, 2.9.10.7] (2.9.10.7 is the last affected version, not a fix)",
        lastAffected: "2.9.10.7",
        clip: (s) => s.includes("[2.0.0, 2.9.10.7]") && !s.includes("not a fix)"),
      },
      {
        what: "cut before the bracket",
        purl: `pkg:maven/${group}/${artifact}@2.14.1`,
        pkg: `${group}:${artifact}`,
        installed: "2.14.1",
        reason: `registry package (confidence 0.95): Maven/${group}:${artifact} — version 2.14.1 falls inside the advisory interval [2.0.0.20180101.release, 2.15.0.20211212.release] (2.15.0.20211212.release is the last affected version, not a fix)`,
        lastAffected: "2.15.0.20211212.release",
        clip: (s) => {
          const tail = s.slice(s.indexOf("advisory interval ["));
          return !tail.includes(")") && !tail.includes("]");
        },
      },
    ];
    for (const c of cases) {
      assert.ok(c.reason.length > 200, `${c.what}: the reason is ${c.reason.length} characters, so the cut does not clip it`);
      const row = {
        ...lodash,
        index: 0,
        purl: c.purl,
        matches: lodash.matches.filter((m) => m.cve_id === cve).map((m) => ({ ...m, match_reason: c.reason, description: "x".repeat(40_000), ...LAST_AFFECTED_FIXED_IN })),
        cve_ids: [cve],
      };
      const res = await call("check_sbom", { purls: [c.purl] }, { [batch.path]: { ...batch.body, results: [row] } });
      assert.notEqual(res.isError, true, blocksOf(res)[0]);
      assert.match(blocksOf(res)[1], /TEXT CUT/, `${c.what}: the answer is not cut, so the test does not reach the clip`);
      const [r] = JSON.parse(blocksOf(res)[0]).results;
      const [m] = r.matches.filter((x) => x.cve_id === cve);
      assert.equal(m.match_reason, `${c.reason.slice(0, 200)}…`, `${c.what}: check_sbom's first cut level no longer clips match_reason at 200 characters`);
      assert.ok(c.clip(m.match_reason), `${c.what}: ${m.match_reason}`);
      assert.ok(Object.hasOwn(m, "fixed_in") && m.fixed_in === null, `${c.what}: the cut text does not keep fixed_in null: ${JSON.stringify(m)}`);
      const target = { ecosystem: "Maven", pkg: c.pkg, installed: c.installed };
      const intelAt = (v) => ({ affected_packages: [{ ecosystem: "Maven", package_name: c.pkg, fixed_version: v }], fixed_versions: [] });
      assert.deepEqual(fixRule(r, cve, { affected_packages: [], fixed_versions: [] }, target), { candidates: [], offered: [] }, `${c.what}: the rule takes a clipped last_affected interval as a fix`);
      assert.deepEqual(fixRule(r, cve, intelAt(c.lastAffected), target).offered, [], `${c.what}: the rule offers cve_intel's version at the last affected one`);
    }
  });

  // #2817, the fix itself: with fixed_branches (core-backend since #2817), what the model is shown
  // for log4j-core 2.14.1 and CVE-2021-44228 gives, by the prompt's rule, the fix of the range that
  // holds 2.14.1, [2.13.0, 2.15.0): 2.15.0, and never fixed_version's 2.12.2.
  it("sbom_review with fixed_branches: log4j-core 2.14.1 is given 2.15.0, the fix of its range, not 2.12.2", async (t) => {
    const [purl] = LOG4J.args.purls;
    const sbom = JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.5", components: [{ type: "library", name: "log4j-core", version: "2.14.1", purl }] });
    const own = textOf(await client.getPrompt({ name: "sbom_review", arguments: { sbom } })).split("\nSBOM:\n")[0];
    assert.match(own, /cve_intel, to read fixed_branches and fixed_version from its affected_packages rows, and fixed_version from its fixed_versions rows/);
    // #3074: the range's fixed, walked past any other range of the row that still holds it.
    assert.match(own, /Where cve_intel's affected_packages row for the component's ecosystem and package carries fixed_branches \(for a Packagist or Maven component, the rows of its package_name under that ecosystem, bare and with a repository URL after ":", such as Packagist and Packagist:https:\/\/packages\.drupal\.org\/8, are one row, their ranges all together, as cve_intel's note says; rows of two releases, such as Debian:11 and Debian:12, never are\), give the fixed of the range that holds the installed version: at or above its introduced \("0" is the first version\) and below its fixed, or at or below its last_affected, in the same version order; while another range of the row holds that fixed version, it is still affected, so move to that range's fixed; a range on the way with last_affected and no fixed, or with no end, has no fix on record, so give none, and a version in no range is given no fixed version from them; where fixed_branches is there, fixed_version is not used\./);
    const [row] = JSON.parse(blocksOf(await call("check_sbom", { sbom }, shapedAnswers(LOG4J)))[0]).results;
    const { ecosystem, package: pkg, version: installed } = fromPurl(row.purl);
    const c = caseOf(INTEL_2817);
    const intel = JSON.parse(blocksOf(await call("cve_intel", argsOf(c), shapedAnswers(c)))[0]);
    const core = intel.affected_packages.find((r) => r.ecosystem === ecosystem && r.package_name === pkg);
    assert.equal(core.fixed_version, "2.12.2", "the case no longer carries the one-range fixed_version, so it does not test the rule");
    const { candidates, offered } = fixRule(row, "CVE-2021-44228", intel, { ecosystem, pkg, installed });
    t.diagnostic(`candidates ${JSON.stringify(candidates)}, offered ${JSON.stringify(offered)}`);
    assert.deepEqual(offered, [{ from: "fixed_branches", version: "2.15.0" }]);
    assert.ok(!candidates.some((x) => x.version === "2.12.2"), "the rule still reads fixed_version where fixed_branches is there");
    // Another branch, by the same rule: 2.10.0 is fixed in 2.12.2; and a version past every range.
    assert.deepEqual(fixRule(row, "CVE-2021-44228", intel, { ecosystem, pkg, installed: "2.10.0" }).offered, [{ from: "fixed_branches", version: "2.12.2" }]);
    assert.deepEqual(fixRule(row, "CVE-2021-44228", intel, { ecosystem, pkg, installed: "2.15.0" }).offered, [], "2.15.0 is in no range, and is given no fixed version");
  });

  // #3285 follow-up (3.1.0's lane P): cve_intel lists a package once per stored ecosystem string;
  // CVE-2025-48013's rows for drupal/quick_node_block (the fixture the remediation route served,
  // 2026-10-18) are Packagist:https://packages.drupal.org/8 [0, 2.0.1) and Packagist [0, 2.0.0).
  // By the rule, a composer purl at 1.0.0 with no match kept is given 2.0.1, the matcher's
  // fixed_in; control: the row of its own ecosystem string alone (d42d4697's rule) gives the
  // still-affected 2.0.0. A release suffix stays apart.
  it("sbom_review's fix rule reads CVE-2025-48013's Packagist rows as one (#3285): drupal/quick_node_block 1.0.0 is given 2.0.1, never 2.0.0", async () => {
    const own = textOf(await client.getPrompt({ name: "sbom_review", arguments: { sbom: "{}" } })).split("\nSBOM:\n")[0];
    assert.match(own, /for a Packagist or Maven component, the rows of its package_name under that ecosystem, bare and with a repository URL after ":"/);
    const rows = JSON.parse(fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures", "cve_remediation-CVE-2025-48013.json"), "utf8")).data.fixed_branches;
    const { ecosystem, package: pkg, version: installed } = fromPurl("pkg:composer/drupal/quick_node_block@1.0.0");
    assert.deepEqual([ecosystem, pkg, installed], ["Packagist", "drupal/quick_node_block", "1.0.0"]);
    const intel = { affected_packages: rows, fixed_versions: [] };
    const target = { ecosystem, pkg, installed };
    assert.deepEqual(fixRule({ matches: [] }, "CVE-2025-48013", intel, target).offered, [{ from: "fixed_branches", version: "2.0.1" }]);
    assert.deepEqual(fixRule({ matches: [] }, "CVE-2025-48013", intel, target, { oneRow: false }).offered, [{ from: "fixed_branches", version: "2.0.0" }], "control: row by row gives 2.0.0");
    const deb = { affected_packages: [{ ecosystem: "Debian:11", package_name: "openssl", fixed_branches: [{ introduced: "0", fixed: "1.1.1" }] }, { ecosystem: "Debian:12", package_name: "openssl", fixed_branches: [{ introduced: "0", fixed: "3.0.1" }] }], fixed_versions: [] };
    assert.deepEqual(fixRule({ matches: [] }, "CVE-2099-1", deb, { ecosystem: "Debian:12", pkg: "openssl", installed: "1.0.0" }).offered, [{ from: "fixed_branches", version: "3.0.1" }]);
  });

  // #3074: a range's fixed can lie inside another range of the same row. Production's CVE-2026-4800
  // npm/lodash row (2026-10-11) held [0, 4.17.21) and [4.0.0, 4.18.0): for 4.17.15 the fix is
  // 4.18.0, and 4.17.21, the first range's fixed, is still affected. Where the text keeps no match,
  // or a match without fixed_in, the rule walks fixed_branches past it; a match_reason
  // "[0, 4.17.21)" on such a match is not read (#2834's last review), so it gives 4.17.21 neither;
  // a last_affected range on the way gives none.
  it("sbom_review's fix rule walks past an overlapping range (#3074): lodash 4.17.15 under CVE-2026-4800 is given 4.18.0, never the still-affected 4.17.21", async () => {
    const cve = "CVE-2026-4800";
    const target = { ecosystem: "npm", pkg: "lodash", installed: "4.17.15" };
    const branches = [{ introduced: "0", fixed: "4.17.21" }, { introduced: "4.0.0", fixed: "4.18.0" }];
    const intel = { affected_packages: [{ ecosystem: "npm", package_name: "lodash", fixed_version: "4.17.21", fixed_branches: branches }], fixed_versions: [] };
    const noMatch = { matches: [] };
    const reasonRow = { matches: [{ cve_id: cve, match_reason: "registry package (confidence 0.95): npm/lodash — version 4.17.15 falls inside the advisory interval [0, 4.17.21)" }] };
    assert.deepEqual(fixRule(noMatch, cve, intel, target).offered, [{ from: "fixed_branches", version: "4.18.0" }]);
    assert.deepEqual(fixRule(reasonRow, cve, intel, target).offered, [{ from: "fixed_branches", version: "4.18.0" }]);
    // Control: the first range's own fixed, the pre-#3074 reading, is held by the second range.
    assert.ok(branchHolds(branches[1], "4.17.21"), "4.17.21 is not inside [4.0.0, 4.18.0), so the case does not test the walk");
    // Adjacent ranges, chained ranges, and a last_affected range on the way.
    assert.equal(fixedBranchesWalk([{ introduced: "1.0.0", fixed: "2.0.0" }, { introduced: "2.0.0", fixed: "3.0.0" }], "1.5.0"), "3.0.0");
    assert.equal(fixedBranchesWalk([{ introduced: "0", fixed: "2.0.0" }, { introduced: "1.5.0", fixed: "3.0.0" }, { introduced: "2.5.0", fixed: "4.0.0" }], "1.0.0"), "4.0.0");
    const blocked = { ...intel, affected_packages: [{ ...intel.affected_packages[0], fixed_branches: [{ introduced: "0", fixed: "4.17.21" }, { introduced: "4.0.0", last_affected: "4.17.23" }] }] };
    assert.deepEqual(fixRule(noMatch, cve, blocked, target).offered, [], "a last_affected range on the way gives no fixed version");
    // fixed_in, where the match carries it, decides as before.
    const withFixedIn = { matches: [{ cve_id: cve, fixed_in: "4.18.0", fixed_in_detail: "fixed_in moved past the overlapping interval [4.0.0, 4.18.0) of the same record" }] };
    assert.deepEqual(fixRule(withFixedIn, cve, intel, target).offered, [{ from: "fixed_in", version: "4.18.0" }]);
  });

  // #2834: sbom_review reads each match's fixed_in alone where the text keeps the match. On LOG4J
  // as core-backend answers since #2834, CVE-2021-44228's match carries fixed_in 2.15.0, the fix of
  // the interval holding 2.14.1, and the rule gives it; a match whose fixed_in is null gives no fixed
  // version ("no fix on record"), whatever cve_intel holds, where the rule without fixed_in (an API
  // before #2834) would give cve_intel's value.
  it("sbom_review's fix rule with fixed_in (#2834): a version is given, null gives none and stops the rule there", async (t) => {
    const [purl] = LOG4J.args.purls;
    const sbom = JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.5", components: [{ type: "library", name: "log4j-core", version: "2.14.1", purl }] });
    const own = textOf(await client.getPrompt({ name: "sbom_review", arguments: { sbom } })).split("\nSBOM:\n")[0];
    // #3074: fixed_in is the first version above the installed one that no affected interval holds.
    assert.match(own, /Where the text keeps the component's match for the CVE and the match carries fixed_in, read fixed_in alone: a version there is the first version above the installed one that no affected interval of the advisory holds, so give it as the fixed version; null says no fixed version is on record for the installed version's range, so give none for that CVE on that component: where the match carries fixed_in_reason, write "no fix on record" and that fixed_in_reason, which says why, as given \(a version it names is not a fix\); this is not a finding that no fix exists\./);
    assert.match(own, /Where the text or data keeps no match for that CVE on the component \(a cut can keep a row's cve_ids alone, or fewer matches than cve_ids\), or the match has no fixed_in field, the rest of this rule applies\./);
    const shown = async (answers) => JSON.parse(blocksOf(await call("check_sbom", LOG4J.args, answers))[0]).results[0];
    const row = await shown(withFixedIn(shapedAnswers(LOG4J)));
    const { ecosystem, package: pkg, version: installed } = fromPurl(row.purl);
    const target = { ecosystem, pkg, installed };
    const c = caseOf(INTEL_2817);
    const intel = JSON.parse(blocksOf(await call("cve_intel", argsOf(c), shapedAnswers(c)))[0]);
    // A version: given, from fixed_in.
    assert.equal(row.matches.find((m) => m.cve_id === "CVE-2021-44228").fixed_in, "2.15.0", "check_sbom's text does not keep fixed_in");
    assert.deepEqual(fixRule(row, "CVE-2021-44228", intel, target).offered, [{ from: "fixed_in", version: "2.15.0" }]);
    // null: none, though cve_intel would offer one.
    const nulled = await shown(withFixedIn(shapedAnswers(LOG4J), {}));
    const m = nulled.matches.find((x) => x.cve_id === "CVE-2021-44228");
    assert.ok(Object.hasOwn(m, "fixed_in") && m.fixed_in === null, JSON.stringify(m));
    // #2834's last review: the rule gives a null fixed_in's reason, so the text keeps it beside it.
    assert.ok(typeof m.fixed_in_reason === "string" && m.fixed_in_reason.length > 0, `check_sbom's text drops fixed_in_reason beside a null fixed_in: ${JSON.stringify(m)}`);
    t.diagnostic(`fixed_in null: ${JSON.stringify(fixRule(nulled, "CVE-2021-44228", intel, target))}`);
    assert.deepEqual(fixRule(nulled, "CVE-2021-44228", intel, target), { candidates: [], offered: [] }, "a null fixed_in still gives a fixed version");
    // Control: the same row without the fixed_in field reads the rest of the rule, and cve_intel's
    // fixed_branches give 2.15.0, so the null case above is decided by fixed_in, not by the data.
    const absent = { ...nulled, matches: nulled.matches.map(({ fixed_in, fixed_in_reason, interval, ...x }) => x) };
    assert.deepEqual(fixRule(absent, "CVE-2021-44228", intel, target).offered, [{ from: "fixed_branches", version: "2.15.0" }]);
  });

  // #2846: workload_triage on check_sbom at its most per call, the cut that keeps cve_ids without
  // matches among them, on LOG4J with fixed_in, and on get_cve, which it calls for the CVEs of a row
  // whose matches the text leaves out.
  it("workload_triage: each field it names is in the text of check_sbom (at 2,000 purls, and one purl with fixed_in) or get_cve", async (t) => {
    const prompt = textOf(await client.getPrompt({ name: "workload_triage", arguments: {} }));
    const named = namedFields("workload_triage", prompt);
    for (const f of ["kev_listed", "ransomware", "epss_score", "fixed_in", "cve_ids", "kev_ransomware", "not_assessed_reason", "not_sent_purls"]) assert.ok(named.includes(f), `workload_triage no longer names ${f}`);
    const carried = new Set();
    const full = caseOf("check_sbom, 2,000 purls (10 batches of 200)");
    const limited = caseOf("check_sbom, 2,000 purls, rate-limited after 6 batches (production's answer from a fresh budget)");
    for (const c of [full, limited]) {
      const res = await call("check_sbom", { purls: argsOf(full).purls }, shapedAnswers(c), c.limited);
      const shown = JSON.parse(blocksOf(res)[0]);
      // The leanest cut: cve_ids kept, matches left out, as step 5 says to read through get_cve.
      assert.ok(shown.results.some((r) => r.verdict === "affected" && Array.isArray(r.cve_ids) && r.cve_ids.length && !Object.hasOwn(r, "matches")), `${c.label}: no affected row keeps cve_ids without matches`);
      for (const f of heldTo(c.label, res, named)) carried.add(f);
    }
    for (const f of heldTo(LOG4J_2834.label, await call("check_sbom", LOG4J.args, withFixedIn(shapedAnswers(LOG4J))), named)) carried.add(f);
    const g = caseOf("get_cve, CVE-2021-44228");
    for (const f of heldTo(g.label, await call(g.tool, argsOf(g), shapedAnswers(g)), named)) carried.add(f);
    // #3270: step 5 reads matches_truncated's kev_listed_cve_ids and ransomware_cve_ids, which only
    // the structured result's data carries, on a row whose matches its cut capped: a default call
    // (no full) on Juice Shop 11.1.2 with magento/community-edition 2.3.0, whose 200 matches are.
    for (const f of ["matches_truncated", "kev_listed_cve_ids", "ransomware_cve_ids"]) assert.ok(named.includes(f), `workload_triage no longer names ${f}`);
    const capped = JSON.parse(fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures", "check_sbom-large-rows.json"), "utf8")).juiceShopMagento;
    stub.state.answers = { "/api/v1/public/cves/match/batch": capped };
    stub.state.limited = undefined;
    stub.state.requests = 0;
    const sc = (await client.callTool({ name: "check_sbom", arguments: { purls: capped.results.map((r) => r.purl) } })).structuredContent;
    const marks = sc.data.results.filter((r) => r.matches_truncated).map((r) => r.matches_truncated);
    assert.ok(marks.length > 0, "the default call capped no row's matches, so this case holds nothing");
    for (const f of named) if (marks.some((m) => Object.hasOwn(m, f))) carried.add(f);
    carried.add("matches_truncated");
    allCarried(t, "workload_triage", named, carried, ["check_sbom", "get_cve"]);
  });

  // #3269's third review: workload_triage's step 6 and sbom_review's step 1 quote two shapes of
  // check_sbom's DATA CUT note, the clause naming the rows left out (those with a KEV-listed or
  // ransomware match first and apart) and the sentence giving the sizes of the calls that check
  // them again. Each quote (K a count, … the rest) is held to the note of a default call that
  // leaves rows of both kinds out: 24 Debian 12 rows of 50 matches (libssl3's, recorded), every
  // other one with a KEV-listed match. Control: round 3's quotes ("K affected or undetermined rows
  // at index …", "A call of the first N of these purls" as the re-check size) fail it.
  it("#3269's third review: the note shapes workload_triage and sbom_review quote for the rows a DATA CUT leaves out are check_sbom's", async () => {
    const rec = JSON.parse(fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures", "check_sbom-large-rows.json"), "utf8")).debian12;
    const ssl = rec.results.find((r) => r.purl.includes("libssl3"));
    const results = Array.from({ length: 24 }, (_, i) => ({
      ...ssl,
      index: i,
      purl: `pkg:deb/debian/libssl3-${i}@3.0.11-1~deb12u1?arch=amd64&upstream=openssl&distro=debian-12`,
      matches: ssl.matches.map((m, j) => ({ ...m, kev_listed: i % 2 === 1 && j === 3 })),
    }));
    stub.state.answers = { "/api/v1/public/cves/match/batch": { ...rec, results, summary: { ...rec.summary, components: 24, affected: 24 } } };
    stub.state.limited = undefined;
    stub.state.requests = 0;
    const note = (await client.callTool({ name: "check_sbom", arguments: { purls: results.map((r) => r.purl) } })).structuredContent.notes.join(" ");
    assert.match(note, /the \d+ with a KEV-listed or ransomware match at index .*; the other \d+ at index /, "this call leaves out no rows of both kinds, so it holds nothing");
    const quoteOf = (q) => new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\bK\b/g, "\\d+").replace(/…/g, ".*?"));
    for (const name of ["workload_triage", "sbom_review"]) {
      const text = textOf(await client.getPrompt({ name, arguments: name === "sbom_review" ? { sbom: '{"bomFormat":"CycloneDX","components":[]}' } : {} }));
      const quotes = [...text.matchAll(/\("([^"]*…[^"]*)"/g)].map((m) => m[1]).filter((q) => /affected or undetermined rows|Re-check/.test(q));
      assert.ok(quotes.length >= (name === "workload_triage" ? 2 : 1), `${name} quotes ${quotes.length} of the note's shapes`);
      for (const q of quotes) assert.match(note, quoteOf(q), `${name} quotes "${q}", which check_sbom's note does not say`);
    }
    for (const was of ["K affected or undetermined rows at index …", "A call of the first N of these purls, at most as many per call …"]) assert.doesNotMatch(note, quoteOf(was), `round 3's quote "${was}"`);
  });

  // #3284: the first text block keeps the rows with a KEV-listed or ransomware match last to leave
  // and names by index each of them it leaves out; workload_triage's and sbom_review's last lines
  // quote that sentence. The quote (K a count, … the rest) is held to the note of a default call
  // whose text leaves such rows out: 80 Debian 12 rows of 50 matches (libssl3's, recorded), each
  // with a KEV-listed match. Control: the clause d42d4697's workload_triage line had in its place
  // is no shape of that note.
  it("#3284: the note shape workload_triage and sbom_review quote for the KEV-bearing rows the first text block leaves out is check_sbom's", async () => {
    const rec = JSON.parse(fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures", "check_sbom-large-rows.json"), "utf8")).debian12;
    const ssl = rec.results.find((r) => r.purl.includes("libssl3"));
    const results = Array.from({ length: 80 }, (_, i) => ({
      ...ssl,
      index: i,
      purl: `pkg:deb/debian/libssl3-${i}@3.0.11-1~deb12u1?arch=amd64&upstream=openssl&distro=debian-12`,
      matches: ssl.matches.map((m, j) => ({ ...m, kev_listed: j === 3 })),
    }));
    stub.state.answers = { "/api/v1/public/cves/match/batch": { ...rec, results, summary: { ...rec.summary, components: 80, affected: 80 } } };
    stub.state.limited = undefined;
    stub.state.requests = 0;
    const res = await client.callTool({ name: "check_sbom", arguments: { purls: results.map((r) => r.purl) } });
    const note = res.structuredContent.notes.join(" ");
    assert.ok(JSON.parse(res.content[0].text).results.length < 80, "the text keeps every row, so this call holds nothing");
    const quoteOf = (q) => new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\bK\b/g, "\\d+").replace(/…/g, ".*?"));
    for (const name of ["workload_triage", "sbom_review"]) {
      const text = textOf(await client.getPrompt({ name, arguments: name === "sbom_review" ? { sbom: '{"bomFormat":"CycloneDX","components":[]}' } : {} }));
      const quotes = [...text.matchAll(/\("([^"]*…[^"]*)"/g)].map((m) => m[1]).filter((q) => /^Of the rows left out of it/.test(q));
      assert.equal(quotes.length, 1, `${name} quotes ${quotes.length} shapes of the sentence`);
      for (const q of quotes) assert.match(note, quoteOf(q), `${name} quotes "${q}", which check_sbom's note does not say`);
      assert.doesNotMatch(text, /can hold a KEV-listed CVE that the text does not name/, `${name} still says the text leaves KEV-bearing rows out unnamed`);
    }
  });

  // #3013's review: past the budget, check_sbom's and scan_manifest's structured result thins each
  // row's matches to SBOM_ROW_THIN before any row leaves (a client that reads structuredContent,
  // Claude Code among them, reads those), and through the review a thinned match kept cve_id,
  // kev_listed, epss_score, fixed_in and fixed_in_reason, while workload_triage reads ransomware,
  // effective_score and score_assessed from a row's matches too (step 5, and its ordering keys).
  // This file held each prompt's fields to the first text block alone. Here, for every prompt that
  // calls check_sbom or scan_manifest, each field it names in a sentence that reads from a match
  // (matchFieldsRead) is in SBOM_ROW_THIN's matches, and in every thinned match of a default call
  // (Juice Shop's 50 components, every row thinned, and scan_manifest's package-lock of 64).
  // Control: the review's thinned match fails, naming the three fields.
  //
  // #3270: the guard read SBOM_ROW_THIN alone, and 3.0.2 (#3132) added levels after it: its
  // SBOM_ROW_COMPACT kept cve_id, kev_listed, ransomware, fixed_in and effective_score, so the
  // 201-purl probe's default answer kept 54 rows and not one match with epss_score or
  // score_assessed, and this test passed. Now each level of SBOM_ROW_LEVELS that keeps matches is
  // held to every field read; control: 3.0.2's SBOM_ROW_COMPACT fails, naming the two.
  it("#3013's review: every match field a prompt reads from check_sbom's or scan_manifest's matches survives SBOM_ROW_THIN, in the list and in a default call's thinned data", async (t) => {
    const { SBOM_ROW_THIN, SBOM_ROW_LEVELS } = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "check_sbom.js")).href);
    const juice = caseOf("check_sbom, Juice Shop 11.1.2 (50 components)");
    const lockCase = caseOf("scan_manifest, package-lock.json (64 packages)");
    // Every field a check_sbom match carries in the answers this file serves, fixed_in among them.
    const matchKeys = new Set(
      [shapedAnswers(juice), withFixedIn(shapedAnswers(LOG4J))].flatMap((answers) => Object.values(answers).flatMap((b) => b.results.flatMap((r) => (r.matches ?? []).flatMap((m) => Object.keys(m))))),
    );
    const args = {
      triage_cve: [{ cve_id: "CVE-2021-44228" }],
      kev_weekly_brief: [{}],
      am_i_affected: [{ product: "openssl", version: "3.0.0" }, { ecosystem: "npm", package: "lodash", version: "4.17.15" }],
      sbom_review: [{ sbom: JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.5", components: [] }) }],
      workload_triage: [{}, ...["kubernetes", "github_actions", "images"].map((source) => ({ source }))],
    };
    const listed = (await client.listPrompts()).prompts.map((x) => x.name).sort();
    assert.deepEqual(Object.keys(args).sort(), listed, "prompts/list lists another prompt: give it arguments here, so what it reads from a match is held");
    const read = {};
    const said = {};
    for (const [name, list] of Object.entries(args)) {
      for (const a of list) {
        const prompt = textOf(await client.getPrompt({ name, arguments: a }));
        if (!/\b(check_sbom|scan_manifest)\b/.test(prompt.split("\nSBOM:\n")[0])) continue;
        read[name] = [...new Set([...(read[name] ?? []), ...matchFieldsRead(name, prompt, toolNames, matchKeys)])];
        said[name] = `${said[name] ?? ""}\n${prompt.split("\nSBOM:\n")[0]}`;
      }
    }
    t.diagnostic(`match fields read: ${JSON.stringify(read)}`);
    assert.deepEqual(Object.keys(read).sort(), ["sbom_review", "workload_triage"], "the prompts that call check_sbom or scan_manifest changed: check what each reads from a match");
    // Not vacuous: what each prompt's text says it reads from a match is found.
    for (const f of ["kev_listed", "ransomware", "epss_score", "effective_score", "score_assessed", "fixed_in"]) assert.ok(read.workload_triage.includes(f), `workload_triage: ${f} is not found as read from a match`);
    assert.ok(read.sbom_review.includes("fixed_in"), "sbom_review: fixed_in is not found as read from a match");
    for (const [name, fields] of Object.entries(read)) assert.deepEqual(thinProblems(fields, SBOM_ROW_THIN), [], `${name} reads from a match fields SBOM_ROW_THIN leaves out`);
    // #3270: every level of the structured cut that keeps matches (a level that keeps none sends
    // the row's CVEs to get_cve, as workload_triage's step 5 and sbom_review's step 3 say).
    const keeps = SBOM_ROW_LEVELS.map((l) => (Array.isArray(l) ? l : l.keep)).filter((keep) => keep.some((k) => Array.isArray(k) && k[0] === "matches"));
    assert.ok(keeps.length >= 3, `${keeps.length} levels of SBOM_ROW_LEVELS keep matches: the guard holds fewer than it did`);
    // #2834 beside #3269: sbom_review relays a null fixed_in's fixed_in_reason, and SBOM_ROW_COMPACT
    // keeps fixed_in without it (kept, it costs the 201-purl probe a row: check_sbom-large-rows).
    // A level may leave fixed_in_reason out only where the prompt reads it where a match carries it
    // and says what a null fixed_in without it is: a reason the cut left out, never "no fix".
    // Every other field read, and fixed_in_reason at SBOM_ROW_THIN (above), is held as before.
    const READ_WITHOUT = { fixed_in_reason: /where the match carries fixed_in_reason, write "no fix on record" and that fixed_in_reason\b[^]*?A null fixed_in on a match without fixed_in_reason is one whose reason a DATA CUT left out for size \(its matches keep fixed_in, not fixed_in_reason\): never write "no fix" for it/ };
    const leftOut = (name, fields, keep, text = said[name]) => thinProblems(fields, keep).filter((f) => !READ_WITHOUT[f]?.test(text));
    for (const [i, keep] of keeps.entries()) {
      for (const [name, fields] of Object.entries(read)) assert.deepEqual(leftOut(name, fields, keep), [], `${name} reads from a match fields level ${i} of SBOM_ROW_LEVELS (of those keeping matches) leaves out`);
    }
    // Control: before it said so (the #2834 clause as phase A merged it), sbom_review read the
    // compact level's null fixed_in as "no fix on record" with a fixed_in_reason it does not keep.
    const compact = keeps.find((keep) => thinProblems(["fixed_in_reason"], keep).length > 0);
    assert.ok(compact, "no level that keeps matches leaves out fixed_in_reason: this guard's exception is unused");
    const MERGED_2834 = said.sbom_review.replace(/where the match carries fixed_in_reason, write "no fix on record" and that fixed_in_reason, which says why, as given \(a version it names is not a fix\); this is not a finding that no fix exists\. A null fixed_in on a match without fixed_in_reason [^]*?get_cve\./, 'write "no fix on record" and the match\'s fixed_in_reason, which says why, as given (a version it names is not a fix); this is not a finding that no fix exists.');
    assert.notEqual(MERGED_2834, said.sbom_review, "the control did not find sbom_review's clause");
    assert.deepEqual(leftOut("sbom_review", read.sbom_review, compact, MERGED_2834), ["fixed_in_reason"]);
    // Control: the review's thinned match leaves out three of workload_triage's.
    const REVIEWED = ["index", "purl", "verdict", "not_assessed_reason", "cve_ids", "matched_package", "matched_via", ["matches", ["cve_id", "kev_listed", "epss_score", "fixed_in", "fixed_in_reason"]]];
    assert.deepEqual(thinProblems(read.workload_triage, REVIEWED).sort(), ["effective_score", "ransomware", "score_assessed"]);
    // Control (#3270): 3.0.2's compact level leaves out two.
    const COMPACT_302 = ["index", "purl", "verdict", "not_assessed_reason", "cve_ids", "matched_package", "matched_via", "matched_version_from", "purl_name", ["matches", ["cve_id", "kev_listed", "ransomware", "fixed_in", "effective_score"]]];
    assert.deepEqual(thinProblems(read.workload_triage, COMPACT_302).sort(), ["epss_score", "score_assessed"]);
    // And in data: a default call (no full), every row thinned, each match keeping each field read
    // wherever the answer's match has it.
    const all = [...new Set(Object.values(read).flat())];
    for (const [c, tool, a] of [[juice, "check_sbom", argsOf(juice)], [lockCase, "scan_manifest", argsOf(lockCase)]]) {
      stub.state.answers = shapedAnswers(c);
      stub.state.limited = undefined;
      stub.state.requests = 0;
      const res = await client.callTool({ name: tool, arguments: a });
      const sc = res.structuredContent;
      assert.equal(sc.truncated?.results?.thinned, true, `${c.label}: rows are not thinned by default, so this case holds nothing`);
      stub.state.requests = 0;
      const whole = (await client.callTool({ name: tool, arguments: { ...a, full: true } })).structuredContent.data.results;
      const byIndex = new Map(whole.map((r) => [r.index, r]));
      let held = 0;
      for (const r of sc.data.results) {
        for (const [i, m] of (r.matches ?? []).entries()) {
          // #3270: a capped row keeps its KEV-listed matches first: the answer's match by cve_id.
          const am = byIndex.get(r.index).matches.find((x) => x.cve_id === m.cve_id);
          for (const f of all) {
            if (!Object.hasOwn(am, f)) continue;
            assert.ok(Object.hasOwn(m, f), `${c.label}: row ${r.index}, match ${i} (${m.cve_id}): a prompt reads ${f} from it, and the thinned match leaves it out`);
            held++;
          }
        }
      }
      assert.ok(held > 0, `${c.label}: no thinned match carries a field read`);
      t.diagnostic(`${c.label}: ${held} match fields held in ${sc.data.results.length} thinned rows`);
    }
  });

  it("triage_cve: each tool it calls keeps, in its text, every field the prompt reads from it", async (t) => {
    const prompt = textOf(await client.getPrompt({ name: "triage_cve", arguments: { cve_id: "CVE-2021-44228" } }));
    const named = namedFields("triage_cve", prompt);
    // The deadline line's kev_due_date is read from get_cve's record, which its text keeps whole.
    for (const f of ["kev_listed", "kev_added_date", "kev_due_date", "kev_ransomware"]) assert.ok(named.includes(f), `triage_cve no longer names ${f}`);
    const carried = new Set();
    const called = [];
    for (const label of ["get_cve, CVE-2021-44228", "cve_intel, CVE-2021-44228", INTEL_2817, "cve_remediation, CVE-2021-44228", "vendor_advisories_for_cve, CVE-2021-44228", "get_vendor_advisory, aws 2026-098-AWS", "epss_history, CVE-2021-44228", "cve_exposure, CVE-2023-44487"]) {
      const c = caseOf(label);
      const held = heldTo(label, await call(c.tool, argsOf(c), shapedAnswers(c)), named);
      for (const f of held) carried.add(f);
      if (c.tool === "get_cve") assert.ok(held.has("kev_due_date"), "get_cve's text does not carry kev_due_date");
      called.push(c.tool);
    }
    allCarried(t, "triage_cve", named, carried, called);
  });

  // #2817, triage_cve's Patch line: it has no installed version to hold cve_intel's fixed_version
  // against, and production's cve_intel for CVE-2021-44228 (prod-shaped/cve_intel.json) keeps one
  // for log4j-core, 2.12.2, below 2.14.1, which production's check_sbom (LOG4J) finds affected by
  // the CVE. Through 2.6.3 the line asked for "fixed versions" with nothing more, so 2.12.2 could
  // be given as the CVE's patch for log4j-core. It now says the value is one per package and not
  // the fix for every affected branch, and points to get_cve's references tagged Vendor Advisory or
  // Patch, which production's get_cve text carries for this CVE.
  it("triage_cve on production's answers for CVE-2021-44228: cve_intel's one fixed_version for log4j-core, 2.12.2, is not given as the fix for every affected branch", async (t) => {
    const prompt = textOf(await client.getPrompt({ name: "triage_cve", arguments: { cve_id: "CVE-2021-44228" } }));
    const patch = prompt.split("\n").find((l) => l.startsWith("- Patch:"));
    assert.ok(patch, prompt);
    assert.match(patch, /cve_intel keeps one fixed_version per ecosystem and package, its advisory's last range's as a rule, which need not be the fix for every affected version of the package/);
    assert.match(patch, /never one range's fix as the fix for every affected branch or the version every install should move to/);
    // #2817: every range with its fix, from fixed_branches; fixed_version only where a row has none.
    assert.match(patch, /For each affected package whose cve_intel row carries fixed_branches, give every range with its fix: from introduced \("0" is the first version\) up to its fixed, or up to and including last_affected, where no fix is on record for that range/);
    assert.match(patch, /where a row has no fixed_branches \(null or absent\), give fixed_version as the fixed version cve_intel records for that package, never as the fix for every affected branch/);
    assert.match(patch, /for the fix on a given branch point to get_cve's references tagged Vendor Advisory or Patch, where it has them, and to the vendor advisories\./);
    assert.match(patch, /where the results hold none, write "none on record", which is not a finding that no fix exists/);
    // A fixed version is spoken of in step 2 (cve_intel's fields) and the Patch line, nowhere else.
    assert.deepEqual(
      fixedVersionLines(prompt).map((l) => (l.startsWith("2. cve_intel:") ? "step 2" : l.startsWith("- Patch:") ? "patch" : l)),
      ["step 2", "patch"],
      "a fixed version is spoken of outside step 2 and the Patch line",
    );

    // What the model is shown: cve_intel's text keeps one fixed_version for log4j-core, 2.12.2.
    const intelCase = caseOf("cve_intel, CVE-2021-44228");
    const intel = JSON.parse(blocksOf(await call("cve_intel", argsOf(intelCase), shapedAnswers(intelCase)))[0]);
    const pkg = "org.apache.logging.log4j:log4j-core";
    const fixes = [...(intel.affected_packages ?? []), ...(intel.fixed_versions ?? [])].filter((r) => r.ecosystem === "Maven" && r.package_name === pkg && r.fixed_version).map((r) => r.fixed_version);
    t.diagnostic(`cve_intel's text, ${pkg}: fixed_version ${JSON.stringify(fixes)}`);
    assert.deepEqual([...new Set(fixes)], ["2.12.2"], "cve_intel no longer keeps one fixed_version, 2.12.2, for log4j-core, so this case does not test the Patch line");
    // ... below a version production's check_sbom finds affected by the CVE.
    const [row] = JSON.parse(blocksOf(await call("check_sbom", LOG4J.args, shapedAnswers(LOG4J)))[0]).results;
    assert.equal(row.verdict, "affected");
    assert.ok(row.cve_ids.includes("CVE-2021-44228"));
    assert.equal(releaseOrder("2.12.2", fromPurl(row.purl).version), -1, "2.12.2 is not below the affected 2.14.1");
    // The references the line points to are in get_cve's text.
    const getCase = caseOf("get_cve, CVE-2021-44228");
    const record = JSON.parse(blocksOf(await call("get_cve", argsOf(getCase), shapedAnswers(getCase)))[0]);
    const pointed = (record.references ?? []).filter((r) => (r.tags ?? []).some((tag) => tag === "Vendor Advisory" || tag === "Patch"));
    t.diagnostic(`get_cve's text: ${pointed.length} references tagged Vendor Advisory or Patch`);
    assert.ok(pointed.length > 0, "get_cve's text keeps no reference tagged Vendor Advisory or Patch for CVE-2021-44228");
  });
});
