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
// the fixed version, only at its first level (Juice Shop's 50 components are cut past it); it now
// reads fixed_version from cve_intel. triage_cve read kev_due_date from a kev_recent page of one
// day, unpaged, which on 2021-11-03 (287 additions) did not hold most of that day's rows; it now
// reads it from get_cve.
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
};
// Snake_case words a prompt uses as values, not fields.
const VALUES = new Set(["change_only", "not_assessed", "distro_release_unknown", "invalid_input"]);

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
const LOG4J = { label: "check_sbom, log4j-core 2.14.1 (one purl)", args: { purls: ["pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"] }, fixture: "check_sbom-log4j-core", answers: ["batch"] };

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
// component: the advisory interval's end in the CVE's match_reason, else cve_intel's fixed_version
// for the component's ecosystem and package (or the recorded fix a match_reason names); offered,
// the ones strictly greater than the installed version.
function fixRule(row, cve, intel, { ecosystem, pkg, installed }) {
  const candidates = [];
  for (const m of (row.matches ?? []).filter((x) => x.cve_id === cve)) {
    const end = m.match_reason?.match(/falls inside the advisory interval \[[^,\]]*, ([^)\]]+)\)/)?.[1];
    if (end && end !== "∞") candidates.push({ from: "match_reason", version: end });
  }
  if (candidates.length === 0) {
    for (const m of (row.matches ?? []).filter((x) => x.cve_id === cve)) {
      const fix = m.match_reason?.match(/is below the recorded fix (\S+?)(?: |$)/)?.[1];
      if (fix) candidates.push({ from: "match_reason", version: fix });
    }
    for (const r of [...(intel.affected_packages ?? []), ...(intel.fixed_versions ?? [])]) {
      if (r.ecosystem === ecosystem && r.package_name === pkg && r.fixed_version) candidates.push({ from: "cve_intel", version: r.fixed_version });
    }
  }
  return { candidates, offered: candidates.filter((c) => releaseOrder(c.version, installed) === 1) };
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
    const undetermined = Array.from({ length: 50 }, (_, i) => ({ cve_id: `CVE-2025-${String(30000 + i)}`, package: "django", ecosystem: "PyPI", reason: "collapsed_fix_boundary", detail: "the advisory's affected range collapses to its fix boundary" }));
    const inputs = [
      [{ product: "linux_kernel", version: "5.10.0" }, shapedAnswers(caseOf("check_affected, linux_kernel 5.10.0 (200 matches, the API's cap)"))],
      [{ product: "flash_player", version: "10.0.0" }, shapedAnswers(caseOf("check_affected, flash_player 10.0.0 (200 matches and an excluded sample of 50)"))],
      [{ ecosystem: "PyPI", package: "django", version: "1.11.0" }, { [djangoPath]: { ...djangoBody, matches, cve_ids: matches.map((m) => m.cve_id), count: 200, capped: true, undetermined, undetermined_count: 73 } }],
    ];
    const carried = new Set();
    let named;
    for (const [args, answers] of inputs) {
      const prompt = textOf(await client.getPrompt({ name: "am_i_affected", arguments: args }));
      named = namedFields("am_i_affected", prompt);
      for (const f of ["cve_id", "kev_listed", "ransomware", "epss_score", "effective_score", "score_assessed"]) assert.ok(named.includes(f), `am_i_affected no longer names ${f}`);
      const asked = JSON.parse(prompt.match(/1\. Call check_affected with these arguments: (\{.*\})\.\n/)?.[1] ?? "null");
      assert.deepEqual(asked, args);
      const res = await call("check_affected", asked, answers);
      const shown = JSON.parse(blocksOf(res)[0]);
      t.diagnostic(`${JSON.stringify(args)}: first text block ${blocksOf(res)[0].length} characters, ${shown.matches.length} matches, each with ${Object.keys(shown.matches[0]).join(", ")}`);
      assert.equal(shown.matches.length, 200, `${JSON.stringify(args)}: matches left out of the text`);
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
    for (const f of ["verdict", "purl", "cve_ids", "not_assessed_reason", "summary", "not_sent", "not_sent_reason", "not_sent_purls", "fixed_version", "match_reason", "ecosystem", "package", "version"]) assert.ok(named.includes(f), `sbom_review no longer names ${f}`);
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
    for (const label of ["get_cve, CVE-2021-44228", "cve_intel, CVE-2021-44228"]) {
      const c = caseOf(label);
      for (const f of heldTo(label, await call(c.tool, argsOf(c), shapedAnswers(c)), named, derived)) carried.add(f);
    }
    allCarried(t, "sbom_review", named, carried, ["check_sbom", "get_cve", "cve_intel"]);
  });

  // #2817: production's cve_intel for CVE-2021-44228 (prod-shaped/cve_intel.json, read again on the
  // hosted endpoint at 2026-10-04T14:20:45Z) keeps one fixed_version for log4j-core, 2.12.2, the
  // advisory's last range's; production's check_sbom for log4j-core 2.14.1 (LOG4J) says each match
  // is "listed verbatim in the advisory's affected versions", which names no fix. Read as the
  // prompt's rule says, what the model is shown offers no fixed version for 2.14.1, and the prompt
  // says to write so: never 2.12.2. Through bab4e868 the prompt asked for "each fixed_version
  // cve_intel gives for the component's package".
  it("sbom_review on production's answers for log4j-core 2.14.1 and CVE-2021-44228: its fix rule gives no fixed version older than the installed one, 2.12.2 among them", async (t) => {
    const [purl] = LOG4J.args.purls;
    const sbom = JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.5", components: [{ type: "library", name: "log4j-core", version: "2.14.1", purl }] });
    const prompt = textOf(await client.getPrompt({ name: "sbom_review", arguments: { sbom } }));
    const own = prompt.split("\nSBOM:\n")[0];
    // The rule, word for word: strictly greater than the installed version, in the ecosystem's
    // order, not as text; the advisory interval first; cve_intel's one value per package named as
    // such; and otherwise no fixed version for the branch, pointing to the advisory.
    assert.ok(own.includes("Never give a fixed version that is not strictly greater than the component's installed version (the version in its purl), compared in the ecosystem's version order: release numbers part by part, as numbers, not as text (2.9.1 is below 2.12.2, and 2.12.2 is below 2.14.1); where you are not sure of the order (pre-releases, qualifiers and distro revisions have their own rules), say so and do not give it."), own);
    assert.match(own, /Prefer the match's match_reason where the text keeps it: "falls inside the advisory interval \[A, B\)" says the advisory's range that holds the installed version ends at B/);
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

    const { candidates, offered } = fixRule(row, cve, intel, { ecosystem, pkg, installed });
    t.diagnostic(`${cve} on ${purl}: candidates ${JSON.stringify(candidates)}, offered ${JSON.stringify(offered)}`);
    // The hazard is in what the model is shown: cve_intel's 2.12.2 for this package.
    assert.ok(candidates.some((c) => c.from === "cve_intel" && c.version === "2.12.2"), "cve_intel no longer gives log4j-core 2.12.2 for CVE-2021-44228, so this case does not test the rule");
    assert.ok(row.matches.filter((m) => m.cve_id === cve).every((m) => /listed verbatim in the advisory's affected versions/.test(m.match_reason)));
    assert.deepEqual(offered, [], "the rule offers a fixed version that is not above the installed 2.14.1");

    // The other polarity, on production's Juice Shop answer: lodash 4.17.19 falls inside
    // [0, 4.17.21) for CVE-2021-23337, so the rule gives 4.17.21.
    const lodash = readShaped("check_sbom").answers.batch.body.results.find((r) => r.purl === "pkg:npm/lodash@4.17.19");
    const l = fromPurl(lodash.purl);
    assert.deepEqual(fixRule(lodash, "CVE-2021-23337", { affected_packages: [], fixed_versions: [] }, { ecosystem: l.ecosystem, pkg: l.package, installed: l.version }).offered, [{ from: "match_reason", version: "4.17.21" }]);
  });

  it("triage_cve: each tool it calls keeps, in its text, every field the prompt reads from it", async (t) => {
    const prompt = textOf(await client.getPrompt({ name: "triage_cve", arguments: { cve_id: "CVE-2021-44228" } }));
    const named = namedFields("triage_cve", prompt);
    // The deadline line's kev_due_date is read from get_cve's record, which its text keeps whole.
    for (const f of ["kev_listed", "kev_added_date", "kev_due_date", "kev_ransomware"]) assert.ok(named.includes(f), `triage_cve no longer names ${f}`);
    const carried = new Set();
    const called = [];
    for (const label of ["get_cve, CVE-2021-44228", "cve_intel, CVE-2021-44228", "vendor_advisories_for_cve, CVE-2021-44228", "get_vendor_advisory, aws 2026-098-AWS", "epss_history, CVE-2021-44228", "cve_exposure, CVE-2023-44487"]) {
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
    assert.match(patch, /cve_intel keeps one fixed_version per ecosystem and package, its advisory's last range's, which need not be the fix for every affected version of the package/);
    assert.match(patch, /never as the fix for every affected branch or the version every install should move to/);
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
