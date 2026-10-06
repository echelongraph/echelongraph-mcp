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
// Runs against dist/index.js, so build first; `npm test` does.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { serverCommand } from "./server-under-test.mjs";
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
// Snake_case words a prompt uses as values, not fields.
const VALUES = new Set(["change_only", "not_assessed", "distro_release_unknown", "invalid_input", "not_parsed", "none_in_source"]);

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
  const pkg = !ns ? name : t === "maven" ? `${ns}:${name}` : NAMESPACED.includes(t) ? `${ns}/${name}` : name;
  const ecosystem = PURL_ECOSYSTEM[t] ?? (DISTRO_TYPES.includes(t) ? distroEcosystem(new URLSearchParams(query).get("distro")) : undefined);
  return { ecosystem, package: pkg, version };
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
const DERIVED = {
  sbom_review: (prompt) =>
    DERIVE_STEP.test(prompt) ? { from: "purl", fields: ["ecosystem", "package", "version"], derive: fromPurl, where: (row) => row.verdict === "affected" } : undefined,
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
// component: the fixed end B of a "[A, B)" advisory interval in the CVE's match_reason, else the
// fixed of the cve_intel fixed_branches range that holds the installed version (#2817), else, for a
// package without fixed_branches, cve_intel's fixed_version for the component's ecosystem and
// package (or the recorded fix a match_reason names); offered, the ones strictly greater than the
// installed version and than the B of any "[A, B]" interval (#2830: a last_affected bound, still
// affected, never a fix).
const HALF_OPEN_END = /falls inside the advisory interval \[[^,\]]*, ([^)\]]+)\)/;
const LAST_AFFECTED = /falls inside the advisory interval \[[^,\]]*, ([^)\]]+)\]/;
function fixRule(row, cve, intel, { ecosystem, pkg, installed }) {
  const above = (v, floor) => releaseOrder(v, floor) === 1;
  // #2834: a match that has a fixed_in field decides: a version is the fix, null is none, and the
  // rest of the rule is not read for that CVE.
  const decided = (row.matches ?? []).filter((x) => x.cve_id === cve && Object.hasOwn(x, "fixed_in"));
  if (decided.length) {
    const fromFixedIn = decided.filter((m) => typeof m.fixed_in === "string").map((m) => ({ from: "fixed_in", version: m.fixed_in }));
    return { candidates: fromFixedIn, offered: fromFixedIn.filter((c) => above(c.version, installed)) };
  }
  const candidates = [];
  const lastAffected = [];
  for (const m of (row.matches ?? []).filter((x) => x.cve_id === cve)) {
    const end = m.match_reason?.match(HALF_OPEN_END)?.[1];
    if (end && end !== "∞") candidates.push({ from: "match_reason", version: end });
    const last = m.match_reason?.match(LAST_AFFECTED)?.[1];
    if (last) lastAffected.push(last);
  }
  // #2817: then the fixed of the cve_intel range (fixed_branches) that holds the installed version;
  // a range closed by last_affected has no fix on record.
  if (candidates.length === 0) {
    for (const r of intel.affected_packages ?? []) {
      if (r.ecosystem !== ecosystem || r.package_name !== pkg || !Array.isArray(r.fixed_branches)) continue;
      for (const b of r.fixed_branches) {
        const from = b.introduced === "0" ? -1 : releaseOrder(b.introduced, installed);
        const below = b.fixed ? releaseOrder(installed, b.fixed) === -1 : b.last_affected ? releaseOrder(installed, b.last_affected) !== 1 : true;
        if (from !== undefined && from <= 0 && below && b.fixed) candidates.push({ from: "fixed_branches", version: b.fixed });
      }
    }
  }
  if (candidates.length === 0 && !(intel.affected_packages ?? []).some((r) => r.ecosystem === ecosystem && r.package_name === pkg && Array.isArray(r.fixed_branches))) {
    for (const m of (row.matches ?? []).filter((x) => x.cve_id === cve)) {
      const fix = m.match_reason?.match(/is below the recorded fix (\S+?)(?: |$)/)?.[1];
      if (fix) candidates.push({ from: "match_reason", version: fix });
    }
    for (const r of [...(intel.affected_packages ?? []), ...(intel.fixed_versions ?? [])]) {
      if (r.ecosystem === ecosystem && r.package_name === pkg && r.fixed_version) candidates.push({ from: "cve_intel", version: r.fixed_version });
    }
  }
  return { candidates, offered: candidates.filter((c) => above(c.version, installed) && lastAffected.every((l) => above(c.version, l))) };
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

  // One call on `answers` (stub overrides), as `limited` says.
  const call = async (name, args, answers, limited = undefined) => {
    stub.state.answers = answers;
    stub.state.limited = limited;
    stub.state.requests = 0;
    return client.callTool({ name, arguments: args });
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
    for (const f of ["verdict", "purl", "cve_ids", "not_assessed_reason", "summary", "not_sent", "not_sent_reason", "not_sent_purls", "fixed_in", "fixed_version", "match_reason", "ecosystem", "package", "version", "vendor_remediations", "remediation_kinds"]) assert.ok(named.includes(f), `sbom_review no longer names ${f}`);
    // The prompt passes the document as given.
    assert.ok(prompt.includes(`\`\`\`json\n${sbom}\n\`\`\``));
    assert.match(prompt, /data\.not_sent_purls lists them; where the note says the first text block cuts not_sent_purls to its first entries, rebuild the list from the document instead, as the note says: the document's distinct purls from the position the note gives on, counted in the order it gives\./);
    assert.match(prompt, /Where the note says that rows of data\.results are left out of the first text block/);
    // A component's ecosystem, package and version, which the leanest cut leaves out of each row,
    // are read from its purl, which it keeps.
    assert.match(prompt, DERIVE_STEP);
    const derived = DERIVED.sbom_review(prompt);
    const carried = new Set();
    for (const c of [full, limited]) {
      const res = await call("check_sbom", { sbom }, shapedAnswers(c), c.limited);
      const [first, note] = blocksOf(res);
      const shown = JSON.parse(first);
      const data = res.structuredContent.data;
      t.diagnostic(`${c.label}: first text block ${first.length} characters, ${shown.results.length} of ${data.results.length} rows, each with ${Object.keys(shown.results[0]).join(", ")}`);
      // This input reaches the cut that leaves the row's own ecosystem, package and version out.
      assert.ok(shown.results.every((r) => typeof r.purl === "string" && !Object.hasOwn(r, "ecosystem") && !Object.hasOwn(r, "package") && !Object.hasOwn(r, "version")), `${c.label}: the text keeps a row's ecosystem, package or version, so this case does not test reading them from the purl`);
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
    // A small SBOM, whose text keeps each row whole, match_reason with it: production's answer for
    // log4j-core 2.14.1 (LOG4J).
    const small = await call("check_sbom", LOG4J.args, shapedAnswers(LOG4J));
    for (const f of heldTo(LOG4J.label, small, named, derived)) carried.add(f);
    // #2834: the same, as core-backend answers since #2834, each match with fixed_in.
    const small2834 = await call("check_sbom", LOG4J.args, withFixedIn(shapedAnswers(LOG4J)));
    for (const f of heldTo(LOG4J_2834.label, small2834, named, derived)) carried.add(f);
    // #2841: cve_remediation for the first CVEs of the list, on its longest production-shaped answer.
    for (const label of ["get_cve, CVE-2021-44228", "cve_intel, CVE-2021-44228", INTEL_2817, "cve_remediation, CVE-2021-44228"]) {
      const c = caseOf(label);
      for (const f of heldTo(label, await call(c.tool, argsOf(c), shapedAnswers(c)), named, derived)) carried.add(f);
    }
    allCarried(t, "sbom_review", named, carried, ["check_sbom", "get_cve", "cve_intel", "cve_remediation"]);
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
    // The rule, word for word: strictly greater than the installed version, in the ecosystem's
    // order, not as text; the advisory interval first; cve_intel's one value per package named as
    // such; and otherwise no fixed version for the branch, pointing to the advisory.
    assert.ok(own.includes("Never give a fixed version that is not strictly greater than the component's installed version (the version in its purl), compared in the ecosystem's version order: release numbers part by part, as numbers, not as text (2.9.1 is below 2.12.2, and 2.12.2 is below 2.14.1); where you are not sure of the order (pre-releases, qualifiers and distro revisions have their own rules), say so and do not give it."), own);
    assert.ok(own.includes("Prefer the match's match_reason where the text keeps it: \"falls inside the advisory interval [A, B)\", closed by a parenthesis, says B is the advisory's fixed version for the range that holds the installed version, so give B as the fixed version, quoting it"), own);
    assert.ok(own.includes("\"falls inside the advisory interval [A, B]\", closed by a square bracket, says B is the range's last affected version, still affected, and the range records no fix (core-backend adds \"(B is the last affected version, not a fix)\", which a cut text can clip, so the bracket alone decides): never give B, or any version at or below it, as a fixed version."), own);
    // #2830: through 2.6.5 the text hedged B, which core-backend rendered alike for a fixed and a
    // last_affected bound; core-backend now tells them apart, and so does the prompt.
    assert.doesNotMatch(own, /does not say is a fixed version rather than|give B as the end of that interval/, "sbom_review still hedges the [A, B) bound");
    assert.match(own, /cve_intel keeps one fixed_version per package, its advisory's last range's, which need not be the fix on the component's branch/);
    assert.match(own, /Where no version meets the rule \("listed verbatim in the advisory's affected versions" names none\), write that the results give no fixed version for the component's branch, which is not a finding that no fix exists, and point to the CVE's advisory for it: get_cve's references tagged Vendor Advisory or Patch/);
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
    assert.deepEqual(fromPurl("pkg:deb/debian/openssl@3.0.15-1~deb12u1?distro=debian-12"), { ecosystem: "Debian:12", package: "openssl", version: "3.0.15-1~deb12u1" });
    assert.ok(step2.includes("pkg:deb/debian/openssl@3.0.15-1~deb12u1?distro=debian-12 is openssl in Debian:12"));
    assert.deepEqual(fromPurl("pkg:githubact/actions/checkout@v4"), { ecosystem: "GitHub Actions", package: "actions/checkout", version: "v4" });
    assert.deepEqual(fromPurl("pkg:rpm/redhat/openssl@3.0.7?distro=rhel-9"), { ecosystem: undefined, package: "openssl", version: "3.0.7" });

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
    // [0, 4.17.21) for CVE-2021-23337, so the rule gives 4.17.21.
    const lodash = readShaped("check_sbom").answers.batch.body.results.find((r) => r.purl === "pkg:npm/lodash@4.17.19");
    const l = fromPurl(lodash.purl);
    assert.deepEqual(fixRule(lodash, "CVE-2021-23337", { affected_packages: [], fixed_versions: [] }, { ecosystem: l.ecosystem, pkg: l.package, installed: l.version }).offered, [{ from: "match_reason", version: "4.17.21" }]);
  });

  // #2830: core-backend's match_reason rendered an OSV last_affected bound L as "[A, L)", the same
  // as a fixed bound, so a reader took L, a version still affected, as the fix. It now renders it
  // "[A, L] (L is the last affected version, not a fix)" (core-backend cve/pkgmatch.go
  // renderInterval; LAST_AFFECTED_REASON below is the string its
  // TestEvaluateRegistryRow_IntervalBoundRendering pins), and sbom_review gives a "[A, B)" B as the
  // fix without a hedge and never gives a "[A, B]" B, or any version at or below it. Here the
  // production Juice Shop row for lodash 4.17.19 is shown to the model with CVE-2021-23337's
  // interval as each kind of bound, through check_sbom's text.
  const LAST_AFFECTED_REASON = "registry package (confidence 0.95): npm/lodash — version 4.17.19 falls inside the advisory interval [0, 4.17.20] (4.17.20 is the last affected version, not a fix)";
  it("sbom_review's fix rule on check_sbom's text (#2830): a [A, B) interval's B is the fix; a [A, B] interval's B is still affected and never given, nor a cve_intel version at or below it", async () => {
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

    // A fixed bound: "[0, 4.17.21)", as production renders it, gives 4.17.21.
    const fixedRow = await shown(lodash);
    assert.ok(fixedRow.matches.some((m) => m.cve_id === cve && m.match_reason.endsWith("falls inside the advisory interval [0, 4.17.21)")));
    assert.deepEqual(fixRule(fixedRow, cve, noIntel, target).offered, [{ from: "match_reason", version: "4.17.21" }]);

    // A last_affected bound: the text keeps the closed bracket and its words, and nothing is given
    // from it: cve_intel's value is offered only above both the installed version and 4.17.20.
    const lastRow = await shown({ ...lodash, matches: lodash.matches.map((m) => (m.cve_id === cve ? { ...m, match_reason: LAST_AFFECTED_REASON } : m)) });
    const reasons = lastRow.matches.filter((m) => m.cve_id === cve).map((m) => m.match_reason);
    assert.deepEqual(reasons, [LAST_AFFECTED_REASON], "check_sbom's text does not keep the last_affected interval as core-backend renders it");
    assert.deepEqual(fixRule(lastRow, cve, noIntel, target), { candidates: [], offered: [] }, "the rule takes a last_affected bound as a fix");
    assert.deepEqual(fixRule(lastRow, cve, intelAt("4.17.20"), target).offered, [], "the rule offers cve_intel's version at the last affected one");
    assert.deepEqual(fixRule(lastRow, cve, intelAt("4.17.21"), target).offered, [{ from: "cve_intel", version: "4.17.21" }]);

    // And the prompt states both readings, unhedged.
    const sbom = JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.5", components: [{ type: "library", name: "lodash", version: "4.17.19", purl: lodash.purl }] });
    const own = textOf(await client.getPrompt({ name: "sbom_review", arguments: { sbom } })).split("\nSBOM:\n")[0];
    assert.match(own, /"falls inside the advisory interval \[A, B\)", closed by a parenthesis, says B is the advisory's fixed version[^.]*, so give B as the fixed version/);
    assert.match(own, /"falls inside the advisory interval \[A, B\]", closed by a square bracket, says B is the range's last affected version, still affected, and the range records no fix \(core-backend adds "\(B is the last affected version, not a fix\)", which a cut text can clip, so the bracket alone decides\): never give B, or any version at or below it, as a fixed version\./);
  });

  // #2830 review: check_sbom's first cut level clips every string to 200 characters, and a
  // last_affected match_reason for a long Maven name runs past it, so the words core-backend adds
  // after the bracket are cut. The closing "]" stays, and the rule reads the bracket alone.
  it("sbom_review's fix rule on a cut check_sbom text (#2830): a long last_affected match_reason clipped at 200 characters keeps its closing bracket, and nothing is given from it", async () => {
    const batch = readShaped("check_sbom").answers.batch;
    const lodash = batch.body.results.find((r) => r.purl === "pkg:npm/lodash@4.17.19");
    const cve = "CVE-2021-23337";
    const purl = "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.10";
    const reason = "registry package (confidence 0.95): Maven/com.fasterxml.jackson.core:jackson-databind — version 2.9.10 falls inside the advisory interval [2.0.0, 2.9.10.7] (2.9.10.7 is the last affected version, not a fix)";
    assert.ok(reason.length > 200, `the reason is ${reason.length} characters, so the cut does not clip it`);
    const row = {
      ...lodash,
      index: 0,
      purl,
      matches: lodash.matches.filter((m) => m.cve_id === cve).map((m) => ({ ...m, match_reason: reason, description: "x".repeat(40_000) })),
      cve_ids: [cve],
    };
    const res = await call("check_sbom", { purls: [purl] }, { [batch.path]: { ...batch.body, results: [row] } });
    assert.notEqual(res.isError, true, blocksOf(res)[0]);
    assert.match(blocksOf(res)[1], /TEXT CUT/, "the answer is not cut, so the test does not reach the clip");
    const [r] = JSON.parse(blocksOf(res)[0]).results;
    const [shownReason] = r.matches.filter((m) => m.cve_id === cve).map((m) => m.match_reason);
    assert.equal(shownReason, `${reason.slice(0, 200)}…`, "check_sbom's first cut level no longer clips match_reason at 200 characters");
    assert.ok(shownReason.includes("[2.0.0, 2.9.10.7]") && !shownReason.includes("not a fix)"), shownReason);
    const target = { ecosystem: "Maven", pkg: "com.fasterxml.jackson.core:jackson-databind", installed: "2.9.10" };
    const intelAt = (v) => ({ affected_packages: [{ ecosystem: "Maven", package_name: target.pkg, fixed_version: v }], fixed_versions: [] });
    assert.deepEqual(fixRule(r, cve, { affected_packages: [], fixed_versions: [] }, target), { candidates: [], offered: [] }, "the rule takes a clipped last_affected bound as a fix");
    assert.deepEqual(fixRule(r, cve, intelAt("2.9.10.7"), target).offered, [], "the rule offers cve_intel's version at the clipped last affected one");
    assert.deepEqual(fixRule(r, cve, intelAt("2.9.10.8"), target).offered, [{ from: "cve_intel", version: "2.9.10.8" }]);
  });

  // #2830 third review: a match_reason long enough is clipped at 200 characters before the
  // interval's closing bracket, "[A, B…", which says neither ")" nor "]". The prompt gives no fixed
  // version from it, and the rule falls back to cve_intel's value.
  it("sbom_review's fix rule on a cut check_sbom text (#2830): a match_reason clipped before the interval's closing bracket gives no fixed version", async () => {
    const batch = readShaped("check_sbom").answers.batch;
    const lodash = batch.body.results.find((r) => r.purl === "pkg:npm/lodash@4.17.19");
    const cve = "CVE-2021-23337";
    const group = "org.apache.logging.log4j.extended.components";
    const artifact = "log4j-core-extended-artifact";
    const installed = "2.14.1";
    const purl = `pkg:maven/${group}/${artifact}@${installed}`;
    const reason = `registry package (confidence 0.95): Maven/${group}:${artifact} — version ${installed} falls inside the advisory interval [2.0.0.20180101.release, 2.15.0.20211212.release] (2.15.0.20211212.release is the last affected version, not a fix)`;
    const open = reason.indexOf("advisory interval [") + "advisory interval [".length;
    assert.ok(open < 200 && reason.indexOf("]", open) >= 200, `the interval opens at ${open} and closes at ${reason.indexOf("]", open)}, so the clip does not fall inside it`);
    const row = {
      ...lodash,
      index: 0,
      purl,
      matches: lodash.matches.filter((m) => m.cve_id === cve).map((m) => ({ ...m, match_reason: reason, description: "x".repeat(40_000) })),
      cve_ids: [cve],
    };
    const res = await call("check_sbom", { purls: [purl] }, { [batch.path]: { ...batch.body, results: [row] } });
    assert.notEqual(res.isError, true, blocksOf(res)[0]);
    assert.match(blocksOf(res)[1], /TEXT CUT/, "the answer is not cut, so the test does not reach the clip");
    const [r] = JSON.parse(blocksOf(res)[0]).results;
    const [shownReason] = r.matches.filter((m) => m.cve_id === cve).map((m) => m.match_reason);
    assert.equal(shownReason, `${reason.slice(0, 200)}…`, "check_sbom's first cut level no longer clips match_reason at 200 characters");
    const tail = shownReason.slice(shownReason.indexOf("advisory interval ["));
    assert.ok(!tail.includes(")") && !tail.includes("]"), shownReason);
    const target = { ecosystem: "Maven", pkg: `${group}:${artifact}`, installed };
    const intelAt = (v) => ({ affected_packages: [{ ecosystem: "Maven", package_name: target.pkg, fixed_version: v }], fixed_versions: [] });
    assert.deepEqual(fixRule(r, cve, { affected_packages: [], fixed_versions: [] }, target), { candidates: [], offered: [] }, "the rule takes an interval clipped before its bracket as a fix");
    assert.deepEqual(fixRule(r, cve, intelAt("2.16.0"), target).offered, [{ from: "cve_intel", version: "2.16.0" }]);

    // And the prompt says so.
    const sbom = JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.5", components: [{ type: "library", name: artifact, version: installed, purl }] });
    const own = textOf(await client.getPrompt({ name: "sbom_review", arguments: { sbom } })).split("\nSBOM:\n")[0];
    assert.ok(own.includes("Where the text is cut before the interval's closing bracket (\"[A, B…\", neither \")\" nor \"]\"), it does not say which bound B is: give no fixed version from that match_reason."), own);
  });

  // #2817, the fix itself: with fixed_branches (core-backend since #2817), what the model is shown
  // for log4j-core 2.14.1 and CVE-2021-44228 gives, by the prompt's rule, the fix of the range that
  // holds 2.14.1, [2.13.0, 2.15.0): 2.15.0, and never fixed_version's 2.12.2.
  it("sbom_review with fixed_branches: log4j-core 2.14.1 is given 2.15.0, the fix of its range, not 2.12.2", async (t) => {
    const [purl] = LOG4J.args.purls;
    const sbom = JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.5", components: [{ type: "library", name: "log4j-core", version: "2.14.1", purl }] });
    const own = textOf(await client.getPrompt({ name: "sbom_review", arguments: { sbom } })).split("\nSBOM:\n")[0];
    assert.match(own, /cve_intel, to read fixed_branches and fixed_version from its affected_packages rows, and fixed_version from its fixed_versions rows/);
    assert.match(own, /Otherwise, where cve_intel's affected_packages row for the component's ecosystem and package carries fixed_branches, give the fixed of the range that holds the installed version: at or above its introduced \("0" is the first version\) and below its fixed, or at or below its last_affected, in the same version order; a range with last_affected and no fixed has no fix on record, and a version in no range is given no fixed version from them; where fixed_branches is there, fixed_version is not used\./);
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

  // #2834: sbom_review reads each match's fixed_in first. On LOG4J as core-backend answers since
  // #2834, CVE-2021-44228's match carries fixed_in 2.15.0, the fix of the interval holding 2.14.1,
  // and the rule gives it; a match whose fixed_in is null gives no fixed version, whatever cve_intel
  // holds, where the rule without fixed_in (an API before #2834) would give cve_intel's value.
  it("sbom_review's fix rule with fixed_in (#2834): a version is given, null gives none and stops the rule there", async (t) => {
    const [purl] = LOG4J.args.purls;
    const sbom = JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.5", components: [{ type: "library", name: "log4j-core", version: "2.14.1", purl }] });
    const own = textOf(await client.getPrompt({ name: "sbom_review", arguments: { sbom } })).split("\nSBOM:\n")[0];
    assert.match(own, /First, where the text keeps the component's match for the CVE and the match carries fixed_in: a version there is the fixed bound of the advisory interval that holds the installed version, so give it as the fixed version; null says the advisory records no fixed version for the installed version's range, so give none for that CVE on that component/);
    assert.match(own, /Where the match has no fixed_in field, or the text keeps no match for the component, the rest of this rule applies\./);
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
    allCarried(t, "workload_triage", named, carried, ["check_sbom", "get_cve"]);
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
