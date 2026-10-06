// #2783: every tool's text, measured on production-shaped answers, under #2467's ceiling.
//
// Through 2.6.2 the ceiling (#2617) was checked against tools.test.mjs's stub fixtures alone, so a
// one-row search_cves fixture printed "search_cves: 1,115 / 60,000 = 2%" while production's default
// search_cves answer was 133,298 characters (222%), and 9 of the 14 tools printed no share at all.
// Here every tool is measured at its default call and, where it has a page size, at its largest
// page, on production's own rows (text-bound.mjs SHAPED; the answers are fixtures/prod-shaped/ and
// #2616's fixtures/prod-answers/), and each case's text must stay within MARGIN of its measured
// size and under the ceiling. The run prints each case's share beside what production's 2.6.2 text
// was for the same call.
//
// Since #2783 a first text block longer than the budget is cut (src/textBudget.ts), so each case
// also holds what the cut must keep true: structuredContent.data is the API's answer whole, the
// first text block is a cut of it (fields left out, strings shortened ending in "…", entries left
// out, nothing added or changed), the note says TEXT CUT exactly when the block is not data's JSON
// whole, and the envelope block is still structuredContent without data and the note's sentences.
// And each case's size is held within SHAPED_DRIFT of production's text for the same call, as
// text-bound-live.mjs last recorded it, so a fixture cut at another level than production's page
// fails here instead of bounding the wrong text.
//
// Since #2800 each case's size is held within MARGIN of its record in either direction, and the
// fields each description says a cut row keeps "at least" are checked on every row of every case.
// Since #2801 the cve:// resource, which relays get_cve's answer, is a case too, and since #2802 a
// cut's sentences say where an answer is whole: structuredContent.data.
//
// Runs against dist/index.js, so build first; `npm test` does.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { AjvJsonSchemaValidator } from "@modelcontextprotocol/server/validators/ajv";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { PKG_DIR, serverCommand } from "./server-under-test.mjs";
import {
  CEILING,
  MARGIN,
  RECORD_SOURCE,
  SBOM_MAX_PURLS,
  SHAPED,
  SHAPED_DRIFT,
  argsOf,
  assertBoundUnderCeiling,
  assertCutOf,
  cutPairs,
  keptSizesOffRecord,
  productionText,
  readLiveRecord,
  setKeptSize,
  shapedAnswers,
  shareOfCeiling,
  startStub,
  textSize,
} from "./text-bound.mjs";

// The cut itself, from the package under test (dist/textBudget.js loads nothing else and starts no server).
const { DATA_TEXT_BUDGET, TEXT_BUDGET_DESCRIPTION, dataText } = await import(pathToFileURL(path.join(PKG_DIR, "dist", "textBudget.js")).href);

// The budget the server cuts the first text block to: half the ceiling, so the note and the
// envelope after it, and a release's growth, have the other half.
const BUDGET = DATA_TEXT_BUDGET;
const blocksOf = (res) => (res.content ?? []).filter((c) => c.type === "text").map((c) => c.text);
const LIMITED = "check_sbom, 2,000 purls, rate-limited after 6 batches (production's answer from a fresh budget)";
const noteSentences = (t) => t.replace(/\s+/g, " ").trim().split(/(?<=[.!?])\s+/).filter(Boolean);
// The tool cases, and the resource cases (#2801), of SHAPED.
const TOOL_CASES = SHAPED.filter((c) => !c.resource);
const RESOURCE_CASES = SHAPED.filter((c) => c.resource);

// What every result of a case must be, besides its size: the cut's contract above.
function assertTextIsACut(label, res) {
  const blocks = blocksOf(res);
  assert.equal(blocks.length, 3, `${label}: ${blocks.length} text blocks, expected 3`);
  const [first, note, env] = blocks;
  const sc = res.structuredContent;
  const shown = JSON.parse(first);
  const whole = JSON.stringify(shown) === JSON.stringify(sc.data);
  assertCutOf(shown, sc.data);
  assert.ok(first.length <= BUDGET || whole, `${label}: the first text block is ${first.length} characters, past the budget of ${BUDGET}, and cut`);
  if (whole) assert.doesNotMatch(note, /TEXT CUT/, `${label}: the note says TEXT CUT, but the first text block is data whole`);
  else assert.match(note, /TEXT CUT: the API's answer is \d+ characters of JSON, more than the 30000 the first text block holds, so that block is cut, and structuredContent\.data carries the answer whole\./, `${label}: the first text block is cut and the note does not say so`);
  // The envelope block: structuredContent without data, its notes the envelope's own sentences,
  // the note's following them, and method left out only where the note quotes it.
  const e = JSON.parse(env);
  const said = noteSentences(note);
  const own = e.notes ?? [];
  assert.deepEqual(sc.notes, [...own, ...said], `${label}: structuredContent.notes is not the envelope's own notes and then the note's sentences`);
  const { data: _data, ...rest } = sc;
  assert.deepEqual({ ...e, notes: sc.notes, ...(Object.hasOwn(e, "method") ? {} : { method: sc.method }) }, rest, `${label}: the envelope block is not structuredContent without data`);
}

// What a cve:// read must be (#2801): get_cve's structured result with data cut as get_cve's first
// text block is, laid out as that block lays it out, and notes that say nothing of a text block:
// get_cve's TEXT CUT sentence is replaced by the resource's own (DATA CUT), and the sentences after
// it, on what the cut leaves out, are the same.
function assertResourceIsACut(label, res, tool) {
  const [{ text, mimeType }] = res.contents;
  assert.equal(mimeType, "application/json", label);
  const s = JSON.parse(text);
  const sc = tool.structuredContent;
  assertCutOf(s.data, sc.data);
  const block = blocksOf(tool)[0];
  assert.ok(text.includes(`"data": ${block.replace(/\n/g, "\n  ")}\n}`), `${label}: data is not laid out as get_cve's first text block lays it out`);
  const { data: _a, notes: _b, ...envelope } = s;
  const { data: _c, notes: _d, ...toolEnvelope } = sc;
  assert.deepEqual(envelope, toolEnvelope, `${label}: the envelope is not get_cve's`);
  for (const n of s.notes) assert.doesNotMatch(n, /TEXT CUT|text block/, `${label}: a note about a text block the resource does not have: ${n}`);
  const cut = JSON.stringify(s.data) !== JSON.stringify(sc.data);
  const at = s.notes.findIndex((n) => n.startsWith("DATA CUT: "));
  if (!cut) {
    assert.equal(at, -1, `${label}: data is whole and a note says DATA CUT`);
    assert.equal(text, JSON.stringify(sc, null, 2), `${label}: data is whole and the text is not the structured result pretty-printed`);
    return;
  }
  assert.match(s.notes[at] ?? "", /^DATA CUT: the API's answer is \d+ characters of JSON, more than the 30000 this resource's data holds, so data here is cut, and get_cve's structuredContent\.data carries the answer whole\.$/, `${label}: data is cut and no note says so`);
  const toolAt = sc.notes.findIndex((n) => n.startsWith("TEXT CUT: "));
  assert.ok(toolAt >= 0, `${label}: get_cve's first text block is not cut, so this case does not test the resource's cut`);
  assert.deepEqual(s.notes.slice(0, at), sc.notes.slice(0, toolAt), `${label}: the notes before the cut's are not get_cve's`);
  assert.deepEqual(s.notes.slice(at + 1), sc.notes.slice(toolAt + 1), `${label}: the notes on what the cut leaves out are not get_cve's`);
}

describe("#2783: every tool's text on production-shaped answers, under the ceiling", () => {
  let stub;
  let client;
  let tools;
  const measured = {};
  const served = {};
  before(async () => {
    stub = await startStub();
    client = await connect({ era: MODERN, ...serverCommand(), env: { ...process.env, ECHELONGRAPH_API_BASE: stub.base, ECHELONGRAPH_API_TIMEOUT_MS: "10000" }, stderr: "inherit" });
    ({ tools } = await client.listTools());
    for (const c of SHAPED) {
      stub.state.limited = c.limited;
      stub.state.requests = 0;
      stub.state.answers = shapedAnswers(c);
      assert.ok(stub.state.answers, `${c.label}: no answers kept`);
      served[c.label] = stub.state.answers;
      measured[c.label] = c.resource ? await client.readResource({ uri: c.resource }) : await client.callTool({ name: c.tool, arguments: argsOf(c) });
      if (c.resource) measured[`${c.label}: the tool`] = await client.callTool({ name: c.tool, arguments: argsOf(c) });
    }
  });
  after(async () => {
    await client?.close();
    await stub?.close();
  });

  // The ticket's own coverage rule: no tool is bounded only by a stub fixture.
  it("every tool tools/list advertises has a production-shaped case at its default call, and every tool with a page size one at its largest page; every resource template that reads a tool's answer has one too", async () => {
    const names = tools.map((t) => t.name);
    assert.deepEqual([...new Set(TOOL_CASES.map((c) => c.tool))].sort(), [...names].sort(), "SHAPED does not cover exactly the tools tools/list advertises");
    // #2801: cve://{cve_id} relays get_cve's answer, so it is as long as get_cve's.
    const { resourceTemplates } = await client.listResourceTemplates();
    for (const rt of resourceTemplates) {
      const scheme = rt.uriTemplate.slice(0, rt.uriTemplate.indexOf("{"));
      assert.ok(RESOURCE_CASES.some((c) => c.resource.startsWith(scheme)), `${rt.uriTemplate}: no production-shaped case`);
    }
    for (const t of tools) {
      assert.ok(TOOL_CASES.some((c) => c.tool === t.name && c.page === "default"), `${t.name}: no case at its default call`);
      const max = t.inputSchema?.properties?.limit?.maximum;
      if (max !== undefined) {
        const c = SHAPED.find((x) => x.tool === t.name && x.page === "max");
        assert.ok(c, `${t.name}: it takes a limit of up to ${max} and has no case at its largest page`);
        assert.equal(argsOf(c).limit, max, `${t.name}: its largest-page case does not ask for limit ${max}`);
      }
    }
    const sbom = SHAPED.filter((c) => c.tool === "check_sbom" && c.page === "max");
    assert.ok(sbom.some((c) => c.limited), "check_sbom has no largest case answered as production answers it from a fresh budget (rate-limited)");
    for (const c of sbom) assert.equal(new Set(argsOf(c).purls).size, SBOM_MAX_PURLS, `${c.label}: it does not send check_sbom's 2,000 distinct purls`);
  });

  // #2800: the bound is two-sided. One-sided, it let an edit drop severity, cvss_v3_score,
  // echelongraph_score, score_assessed, epss_score and kev_listed from both search_cves cut levels
  // and stay green (13,483 characters to 11,030): a text that shrinks past MARGIN is a change to
  // re-measure and review, as one that grows is.
  for (const c of SHAPED) {
    it(`${c.label}: ${c.size} characters of text, within ${MARGIN} either way, under the ceiling`, (t) => {
      const res = measured[c.label];
      if (c.resource) {
        assert.equal(res.contents?.length, 1, `${c.label}: ${res.contents?.length} contents, expected 1`);
      } else {
        assert.notEqual(res.isError, true, `${c.label}: the production-shaped answer did not produce an answer: ${blocksOf(res)[0]?.slice(0, 300)}`);
        assert.ok(["measured", "not_assessed"].includes(res.structuredContent.state), `${c.label}: state ${res.structuredContent.state}`);
      }
      const { total, blocks } = textSize(res, stub.base);
      const prod = productionText(c);
      t.diagnostic(`${shareOfCeiling(c.label, total)}; blocks ${blocks.join(" + ")}${prod ? `; production's text for this call (${prod.version}, ${prod.at}): ${prod.total} (${prod.blocks.join(" + ")})` : ""}`);
      // What the text says first, then how long it is: a wrong text fails on what is wrong.
      if (c.resource) assertResourceIsACut(c.label, res, measured[`${c.label}: the tool`]);
      else assertTextIsACut(c.label, res);
      assert.ok(total <= c.size + MARGIN, `${c.label}: ${total} characters of text, over its bound of ${c.size + MARGIN} (${c.size} measured, plus ${MARGIN})`);
      assert.ok(total >= c.size - MARGIN, `${c.label}: ${total} characters of text, under ${c.size - MARGIN} (${c.size} measured, less ${MARGIN}): the text lost more than a word; re-measure it and check what it lost`);
      assertBoundUnderCeiling(c.label, c.size);
    });
  }

  it("structuredContent.data is the API's answer whole, never the cut, wherever the tool relays the answer as sent", () => {
    // exposure_radar and cve_intel relay their own cut of the answer (#2307, #2722), check_sbom
    // merges batches, and scan_manifest adds what it read of the files (#2835); every other tool's
    // data is the one answer it read.
    for (const c of TOOL_CASES.filter((x) => !["exposure_radar", "cve_intel"].includes(x.tool) && x.page !== "max" && !["check_sbom", "scan_manifest"].includes(x.tool))) {
      const [body] = Object.values(served[c.label]);
      assert.deepEqual(measured[c.label].structuredContent.data, body, c.label);
    }
    const sbom = measured["check_sbom, 2,000 purls (10 batches of 200)"].structuredContent.data;
    assert.equal(sbom.results.length, SBOM_MAX_PURLS, "check_sbom's data does not hold every row of the 2,000");
    const limited = measured[LIMITED].structuredContent;
    assert.equal(limited.data.results.length, 1200, "the rate-limited call's data does not hold the 1,200 rows answered");
    assert.deepEqual(limited.data.not_sent_purls, argsOf(SHAPED.find((c) => c.label === LIMITED)).purls.slice(1200), "data.not_sent_purls is not the 800 purls not sent, whole and in order");
    assert.deepEqual([limited.coverage.sent, limited.coverage.not_sent, limited.coverage.not_sent_reason], [1200, 800, "time_budget"]);
  });

  // #2783 review: flash_player 10.0.0 is 200 matches and an excluded sample of 50 whose detail
  // sentences are 13,861 characters; kept whole, they pushed 75 matches out of the text, two of
  // them CISA-KEV-listed, while the description says every match stays there. The lists beside
  // the matches are cut first. #2799: each match now keeps ransomware and epss_score too, which the
  // am_i_affected prompt asks for, so the samples keep their first 10 entries: 50 of them beside 200
  // such matches were 120 characters past the budget for flash_player.
  it("check_affected keeps every match in the text, as its description says, the excluded and undetermined samples cut first", () => {
    for (const c of SHAPED.filter((x) => x.tool === "check_affected")) {
      const res = measured[c.label];
      const shown = JSON.parse(blocksOf(res)[0]);
      const data = res.structuredContent.data;
      assert.deepEqual(shown.matches.map((m) => m.cve_id), data.matches.map((m) => m.cve_id), `${c.label}: matches left out of the text`);
      for (const k of ["cve_id", "kev_listed", "ransomware", "epss_score", "effective_score", "score_assessed"]) {
        assert.ok(shown.matches.every((m, i) => Object.hasOwn(m, k) || !Object.hasOwn(data.matches[i], k)), `${c.label}: a match in the text leaves out ${k}, which the description says it keeps`);
      }
      assert.doesNotMatch(blocksOf(res)[1], /Only \d+ of the \d+ rows of matches are in it/, c.label);
    }
    const c = SHAPED.find((x) => x.label.startsWith("check_affected, flash_player"));
    const res = measured[c.label];
    const shown = JSON.parse(blocksOf(res)[0]);
    assert.equal(shown.matches.length, 200);
    assert.deepEqual(shown.excluded, res.structuredContent.data.excluded.slice(0, 10).map(({ cve_id, reason }) => ({ cve_id, reason })), "the excluded sample keeps its first 10 entries, each its cve_id and reason");
    assert.match(blocksOf(res)[1], /In it, excluded keeps its first 10 of 50 entries; each entry of excluded in it leaves out criteria, detail and decisive\./);
  });

  // The registry path's largest answer: 200 matches (the cap), cve_ids naming each, and the
  // undetermined sample at its 50 (core-backend cve/pkgmatch.go maxUndeterminedReported), the
  // django rows repeated and the undetermined entries in the backend's UndeterminedMatch shape.
  // #2834: each match as core-backend serves it from e732f635, with fixed_in, and with
  // fixed_in_reason where fixed_in is null and interval where it is set (every fourth match null,
  // as prompt-fields.test.mjs's am_i_affected case). fixed_in, which every level keeps, puts the last level's
  // 200 rows alone past the budget, so the text keeps 185 of them (29,863 characters, 2026-10-05).
  // The description said every match stays in the text, which held only before fixed_in; it now
  // says a registry list near the cap can leave its last matches out, and the note says how many.
  // Control: the description's earlier sentence ("so that every match stays in the text") fails it.
  it("check_affected at the registry path's largest answer: 200 matches carrying fixed_in, cve_ids and 50 undetermined; the text and the description agree on which matches stay", async () => {
    const c = SHAPED.find((x) => x.label.startsWith("check_affected, PyPI django"));
    const [[path, body]] = Object.entries(shapedAnswers(c));
    const matches = Array.from({ length: 200 }, (_, i) => ({
      ...body.matches[i % body.matches.length],
      cve_id: `CVE-2026-${String(20000 + i)}`,
      ...(i % 4 === 3
        ? { fixed_in: null, fixed_in_reason: "interval ends at last_affected 1.11.29; no fixed version recorded" }
        : { fixed_in: "2.2.28", interval: { introduced: "0", fixed: "2.2.28" } }),
    }));
    const undetermined = Array.from({ length: 50 }, (_, i) => ({
      cve_id: `CVE-2025-${String(30000 + i)}`,
      package: "django",
      ecosystem: "PyPI",
      reason: "collapsed_fix_boundary",
      detail: "the advisory's affected range collapses to its fix boundary, so whether version 1.11.0 is inside it cannot be decided from the record",
    }));
    stub.state.limited = undefined;
    stub.state.answers = { [path]: { ...body, matches, cve_ids: matches.map((m) => m.cve_id), count: 200, capped: true, undetermined, undetermined_count: 73 } };
    const res = await client.callTool({ name: "check_affected", arguments: argsOf(c) });
    assert.notEqual(res.isError, true, blocksOf(res)[0]);
    const [first, note] = blocksOf(res);
    const shown = JSON.parse(first);
    assert.ok(first.length <= DATA_TEXT_BUDGET);
    // The matches in the text are the first of the answer's, in order, each with every field the
    // description says a match keeps, fixed_in among them, null where the answer's is null.
    const n = shown.matches.length;
    assert.ok(n > 0 && n <= 200);
    assert.deepEqual(shown.matches.map((m) => m.cve_id), matches.slice(0, n).map((m) => m.cve_id), "the matches in the text are not the answer's first, in order");
    for (const k of ["cve_id", "kev_listed", "ransomware", "epss_score", "effective_score", "score_assessed", "fixed_in"]) {
      assert.ok(shown.matches.every((m, i) => Object.hasOwn(m, k) && m[k] === matches[i][k]), `a match in the text leaves out or changes ${k}`);
    }
    // What the description says of the text is what the text holds.
    const description = tools.find((x) => x.name === "check_affected").description;
    if (n < 200) {
      assert.doesNotMatch(description, /every match stays in the text/, `the text keeps ${n} of 200 registry matches, and the description says every match stays in the text`);
      assert.match(description, /near the cap, a registry list's last matches can leave it, and the note says how many\./);
      assert.match(note, new RegExp(`Only ${n} of the 200 rows of matches are in it; the other ${200 - n} are in structuredContent\\.data only, the last ${200 - n} in order\\.`));
    } else {
      assert.doesNotMatch(note, /Only \d+ of the \d+ rows of matches are in it/);
    }
    assert.deepEqual(shown.undetermined, undetermined.slice(0, 10).map(({ cve_id, reason }) => ({ cve_id, reason })), "the undetermined sample does not keep its first 10 entries, each its cve_id and reason");
    assert.match(note, /In it, cve_ids keeps its first 10 of 200 entries\. cve_ids lists each match's cve_id, in the order of matches\./);
    assert.match(note, /In it, undetermined keeps its first 10 of 50 entries; each entry of undetermined in it leaves out package, ecosystem and detail\./);
  });

  // #2783 review: a 2,000-purl call from a fresh budget answers 1,200 rows and 800 purls not sent.
  // Kept whole, the 800 left no room for any row, so every list was cut to its first 64 in index
  // order: 14 of 240 affected rows beside 50 clean or unchecked ones, and 64 of the purls the note
  // tells the agent to send again.
  it("check_sbom rate-limited: affected rows stay before clean ones, and the note says which purls to send again", () => {
    const res = measured[LIMITED];
    const [first, note] = blocksOf(res);
    const shown = JSON.parse(first);
    const data = res.structuredContent.data;
    const count = (rows, v) => rows.filter((r) => r.verdict === v).length;
    const affected = count(data.results, "affected");
    assert.ok(affected > 0);
    const keptAffected = count(shown.results, "affected");
    // Rows left out are the clean ones first, then the not-assessed ones, then from the end.
    if (keptAffected < affected) assert.equal(count(shown.results, "not_affected") + count(shown.results, "not_assessed"), 0, `${keptAffected} of ${affected} affected rows kept beside clean or not-assessed ones`);
    assert.ok(keptAffected >= Math.min(affected, 100), `only ${keptAffected} of ${affected} affected rows are in the text`);
    assert.deepEqual(shown.not_sent_purls, data.not_sent_purls.slice(0, shown.not_sent_purls.length), "the text's not_sent_purls are not the first of data's");
    assert.match(note, /In it, not_sent_purls keeps its first 10 of 800 entries\. The 800 purls not sent are the input's distinct purls from position 1201 on, counted in the order the note gives for them, so a second call can send them without reading the list\./);
    // The order is in the note's own sentence on the purls not sent (#2799 review), which a list the
    // text keeps whole is given by too.
    assert.match(note, /they are the input's distinct purls from position 1201 on, counted in the order this tool read them \(the order of purls, or of the document's components or packages, each component's nested components right after it and before its next sibling, each purl at its first place\), and data\.not_sent_purls lists them/);
    assert.match(note, /Only \d+ of the 1200 rows of results are in it; the other \d+ are in structuredContent\.data only: the \d+ whose verdict is not_affected or not_assessed/);
    assert.match(note, /To read every row in the text, check \d+ or fewer purls per call\./);
  });

  // #2783 review: match_reason carries a registry match's advisory interval ("[A, B)" names the
  // fixed version B, "[A, B]" the last affected one, #2830), and get_cve, the tool the note points
  // to, does not carry it.
  it("a cut that fits at its first level keeps each match's match_reason, and the note names cve_intel for fixed versions", () => {
    const c = SHAPED.find((x) => x.label.startsWith("check_affected, PyPI django"));
    const res = measured[c.label];
    const shown = JSON.parse(blocksOf(res)[0]);
    assert.match(blocksOf(res)[1], /TEXT CUT/, "the registry case is not cut, so it does not test the cut");
    assert.ok(shown.matches.length > 0 && shown.matches.every((m) => typeof m.match_reason === "string" && /advisory interval/.test(m.match_reason)), "a match in the text leaves out match_reason");
    for (const label of [c.label, "check_sbom, Juice Shop 11.1.2 (50 components)"]) assert.match(blocksOf(measured[label])[1], /cve_intel a CVE's affected packages and fixed versions\./, label);
  });

  // #2783 review: the hints must not send the agent to rows it already has. kev_recent's
  // next_cursor continues after the page, not the text, so the same page at the text's size comes
  // first, and its next_cursor then; and a page at the size a hint names still has its fields cut.
  // Answers larger than the API serves, so that rows leave the text.
  it("a page that leaves rows out of the text says how to read them without skipping or repeating any", async () => {
    const run = async (answers, name, args) => {
      stub.state.limited = undefined;
      stub.state.answers = answers;
      const res = await client.callTool({ name, arguments: args });
      assert.notEqual(res.isError, true, blocksOf(res)[0]);
      return { shown: JSON.parse(blocksOf(res)[0]), note: blocksOf(res)[1] };
    };
    const cve = (i) => ({ cve_id: `CVE-2026-${10000 + i}`, description: "d".repeat(400), severity: "HIGH", cvss_v3_score: 7.5, echelongraph_score: 7.1, score_assessed: true, epss_score: 0.1, kev_listed: false, published: "2026-01-01T00:00:00Z" });
    const s = await run({ "/api/v1/public/cves": { cves: Array.from({ length: 200 }, (_, i) => cve(i)), total: 5000, limit: 50, offset: 100 } }, "search_cves", { search: "x", offset: 100 });
    assert.ok(s.shown.cves.length < 200);
    assert.ok(
      s.note.includes(`call search_cves again with the same arguments and offset ${100 + s.shown.cves.length}; a page of ${s.shown.cves.length} rows or fewer like these fits the text without leaving rows out.`),
      s.note,
    );
    const kev = (i) => ({ cve_id: `CVE-2026-${10000 + i}`, kev_added_date: "2026-01-01", kev_vendor: "v".repeat(60), kev_product: "p".repeat(60), kev_ransomware: false });
    const k = await run({ "/api/v1/public/kev/recent": { kev: Array.from({ length: 600 }, (_, i) => kev(i)), count: 600, total: 5000, limit: 200, next_cursor: "MjAyNi0wMS0wMXxDVkUtMjAyNi0xMDU5OQ" } }, "kev_recent", { limit: 200 });
    const n = k.shown.kev.length;
    assert.ok(n < 600);
    assert.ok(k.note.includes(`call kev_recent again with the same filters and a limit of ${n}, whose rows are the ones in this text, then with that page's next_cursor and a limit of ${n} or fewer.`), k.note);
    const intel = tools.find((t) => t.name === "cve_intel").description;
    assert.doesNotMatch(intel, /data equal to the first text block/, "cve_intel's data is not the first text block once that block is cut");
    assert.match(intel, /with data, which the first text block holds whole up to 30,000 characters;/);
  });

  it(`every case is within ${SHAPED_DRIFT * 100}% of production's text for the same call, as text-bound-live.mjs recorded it`, (t) => {
    const cases = readLiveRecord().cases ?? {};
    let compared = 0;
    for (const c of SHAPED) {
      const r = cases[c.label];
      if (!r || /own text/.test(r.source)) continue;
      compared++;
      const drift = (c.size - r.total) / r.total;
      t.diagnostic(`${c.label}: ${c.size} here, ${r.total} on production's answers (${r.measured_at}), ${drift >= 0 ? "+" : ""}${(drift * 100).toFixed(1)}%`);
      assert.ok(Math.abs(drift) <= SHAPED_DRIFT, `${c.label}: its size here, ${c.size}, is ${(drift * 100).toFixed(1)}% from production's ${r.total} (${r.measured_at}): its fixture's rows are not cut as production's are; re-sample them`);
    }
    for (const c of SHAPED.filter((x) => !x.live)) assert.ok(cases[c.label], `${c.label}: text-bound-live.mjs has no record of it: run npm run text-bound:live -- --record`);
    assert.ok(compared > 0);
  });

  // #2800: what each description says a row of the first text block keeps, held on every SHAPED
  // case of the tool, at whatever level its cut stops. Through 2.6.3 only check_affected's list was
  // asserted, so removing severity, cvss_v3_score, echelongraph_score, score_assessed, epss_score and
  // kev_listed from both search_cves cut levels (src/index.ts SEARCH_CVES_TEXT) left the suite green.
  // Each list is read from the description (`said`) and must equal `fields`, so neither can change
  // alone; a row keeps a field wherever the answer's row has it. And some case of each tool must be
  // cut (#2800 review): no production-shaped answer reached get_cwe's or vendor_advisories_for_cve's
  // cut, so dropping every field but cve_id and description from get_cwe's level left the suite
  // green; each now has a forced case (SHAPED, page "forced").
  const AT_LEAST = /keeps (?:fewer fields, )?((?:[a-z_]+, )*[a-z_]+ and [a-z_]+) at least/;
  const KEEPS = [
    { tool: "search_cves", rows: "cves", said: /Returns cves, each with (.*?) where the record has them/, fields: ["cve_id", "severity", "cvss_v3_score", "echelongraph_score", "score_assessed", "epss_score", "kev_listed"] },
    { tool: "get_cwe", rows: "cves", said: /and cves, one page of 50: each with (.*?)\. /, fields: ["cve_id", "severity", "cvss_v3_score", "echelongraph_score", "echelongraph_severity", "score_assessed", "kev_listed", "published", "description"] },
    { tool: "kev_recent", rows: "kev", said: AT_LEAST, fields: ["cve_id", "kev_added_date", "kev_vendor", "kev_ransomware"] },
    {
      tool: "check_affected",
      rows: "matches",
      said: AT_LEAST,
      fields: ["cve_id", "kev_listed", "ransomware", "epss_score", "effective_score", "score_assessed", "fixed_in"],
      // #2834: the production-shaped answers were recorded before the API sent fixed_in. Every
      // level keeps it where an answer has it; once production's answers are re-measured with it,
      // it leaves this list and is held present.
      absent: ["fixed_in"],
      sides: { said: /the excluded and undetermined samples keep their first 10 entries, each its cve_id and reason/, lists: ["excluded", "undetermined"], fields: ["cve_id", "reason"] },
    },
    { tool: "check_sbom", rows: "results", said: AT_LEAST, fields: ["index", "purl", "verdict", "not_assessed_reason", "cve_ids"] },
    // Production's by-CVE rows carry no cve_ids: each is an advisory naming the CVE asked for.
    { tool: "vendor_advisories_for_cve", rows: "advisories", said: AT_LEAST, fields: ["vendor", "vendor_advisory_id", "title", "severity", "cve_ids"], absent: ["cve_ids"] },
    { tool: "search_vendor_advisories", rows: "advisories", said: AT_LEAST, fields: ["vendor", "vendor_advisory_id", "title", "severity", "cve_ids"] },
  ];
  for (const k of KEEPS) {
    it(`${k.tool}: every row of ${k.rows} in the first text block keeps ${k.fields.join(", ")}, as its description says, in every production-shaped case, one at least cut`, (t) => {
      const description = tools.find((x) => x.name === k.tool).description;
      const m = description.match(k.said);
      assert.ok(m, `${k.tool}: its description no longer says what a row keeps (${k.said})`);
      const cases = TOOL_CASES.filter((c) => c.tool === k.tool);
      const cut = cases.filter((c) => blocksOf(measured[c.label])[1].includes("TEXT CUT: "));
      assert.ok(cut.length > 0, `${k.tool}: no case cuts its text, so no row is held to a cut level and the fields it keeps are not checked`);
      t.diagnostic(`cut in ${cut.map((c) => c.label).join("; ")}`);
      // An "at least" list is a list of fields; a "named above" one is prose, read for the row's fields.
      const keys = new Set(cases.flatMap((c) => (measured[c.label].structuredContent.data[k.rows] ?? []).flatMap((r) => Object.keys(r))));
      const said = k.said === AT_LEAST ? m[1].split(/, | and /) : m[1].match(/[a-z][a-z0-9_]*/g).filter((w) => keys.has(w));
      assert.deepEqual(said, k.fields, `${k.tool}: the fields its description says a row keeps are not the ones this test holds`);
      if (k.sides) assert.match(description, k.sides.said, `${k.tool}: its description no longer says what the samples keep`);
      for (const c of cases) {
        const res = measured[c.label];
        const data = res.structuredContent.data;
        const pairs = cutPairs(JSON.parse(blocksOf(res)[0]), data);
        const rowAt = new RegExp(`^data\\.${k.rows}\\[\\d+\\]$`);
        const rows = pairs.filter((p) => rowAt.test(p.at));
        assert.ok(rows.length > 0, `${c.label}: no row of ${k.rows} in the text`);
        for (const f of k.fields) {
          const lost = rows.filter((p) => Object.hasOwn(p.answer, f) && !Object.hasOwn(p.text, f));
          assert.equal(lost.length, 0, `${c.label}: ${lost.length} of the ${rows.length} rows in the text leave out ${f}, which the description says each keeps (first at ${lost[0]?.at})`);
        }
        for (const list of k.sides?.lists ?? []) {
          const at = new RegExp(`^data\\.${list}\\[\\d+\\]$`);
          for (const p of pairs.filter((x) => at.test(x.at))) for (const f of k.sides.fields) assert.ok(Object.hasOwn(p.text, f) || !Object.hasOwn(p.answer, f), `${c.label}: ${p.at} leaves out ${f}`);
        }
        t.diagnostic(`${c.label}: ${rows.length} rows in the text, each with ${Object.keys(rows[0].text).length} fields`);
      }
      // Every field is one some case's answer has, so each is held somewhere, not vacuously.
      for (const f of k.fields.filter((x) => !k.absent?.includes(x))) assert.ok(keys.has(f), `${k.tool}: no production-shaped row has ${f}`);
      for (const f of k.absent ?? []) assert.ok(!keys.has(f), `${k.tool}: a production-shaped row has ${f}, so it is no longer absent`);
    });
  }
  // #2857: the loop above checks only the levels the SHAPED cases happen to stop at, and two levels
  // were never reached: search_cves's second and kev_recent's last. Removing score_assessed from the
  // one, or kev_ransomware from the other, left the suite green, though both are on the lists
  // tools/list advertises and a page with slightly fuller rows than the fixtures' goes there. So
  // each tool's page is grown (its production-shaped rows cycled as SHAPED cycles them), from one
  // row until rows have to leave the text, which happens only
  // once no level fits, and every level the cut stops at on the way is found and held to the list.
  // The levels are told apart by what they leave in a row (the text rows' fields, and the longest
  // string, which shows the level's clip); the level a page is cut at only moves on as the page
  // grows, so a range whose two ends are cut at the same level holds no other, and bisecting the
  // ranges whose ends differ finds every level, including one added later. check_sbom is not walked:
  // its rows are merged from many batch answers, and its one level is reached by its own cases.
  const textRows = (res, rows) => {
    const shown = JSON.parse(blocksOf(res)[0]);
    return Array.isArray(shown?.[rows]) ? shown[rows] : [];
  };
  const longest = (v) => (typeof v === "string" ? v.length : v && typeof v === "object" ? Math.max(0, ...Object.values(v).map(longest)) : 0);
  for (const k of KEEPS.filter((x) => x.tool !== "check_sbom")) {
    it(`${k.tool}: every level its text is cut at keeps ${k.fields.join(", ")} on every row, the levels no SHAPED case reaches too (#2857)`, async (t) => {
      const cases = TOOL_CASES.filter((c) => c.tool === k.tool && c.fixture);
      const base = cases.find((c) => c.page === "max") ?? cases.find((c) => c.page === "default") ?? cases[0];
      assert.ok(base, `${k.tool}: no SHAPED case with a fixture to grow`);
      const at = new Map();
      const call = async (n) => {
        if (at.has(n)) return at.get(n);
        const c = { ...base, repeat: { ...(base.repeat ?? {}), [k.rows]: n }, set: { ...(base.set ?? {}), ...(base.set?.count !== undefined ? { count: n } : {}) } };
        stub.state.limited = undefined;
        stub.state.requests = 0;
        stub.state.answers = shapedAnswers(c);
        const res = await client.callTool({ name: k.tool, arguments: argsOf(base) });
        assert.notEqual(res.isError, true, `${k.tool}, ${n} rows: no answer: ${blocksOf(res)[0]?.slice(0, 300)}`);
        const note = blocksOf(res)[1];
        const shown = textRows(res, k.rows);
        const cut = note.includes("TEXT CUT: ");
        const fields = [...new Set(shown.flatMap((r) => (r && typeof r === "object" ? Object.keys(r) : [])))].sort();
        const level = cut ? `${fields.join(",")} | longest string ${Math.max(0, ...shown.map(longest))}` : "not cut";
        const r = { n, res, cut, level, dropped: /Only \d+ of the \d+ rows of /.test(note) };
        at.set(n, r);
        return r;
      };
      // From one row, double until rows leave the text: every level has been passed.
      const start = 1;
      let lo = await call(start);
      let hi = lo;
      while (!hi.dropped) {
        assert.ok(hi.n < 8192, `${k.tool}: ${hi.n} rows and no row has left the text yet; the walk cannot reach the cut's last level`);
        lo = hi;
        hi = await call(hi.n * 2);
      }
      const ranges = [[await call(start), hi]];
      while (ranges.length) {
        const [a, b] = ranges.pop();
        if (a.level === b.level || b.n - a.n < 2) continue;
        const m = await call(Math.floor((a.n + b.n) / 2));
        ranges.push([a, m], [m, b]);
      }
      const levels = new Map();
      for (const r of [...at.values()].sort((x, y) => x.n - y.n)) if (r.cut && !levels.has(r.level)) levels.set(r.level, r);
      assert.ok(levels.size > 0, `${k.tool}: no page was cut`);
      t.diagnostic(`${k.tool}: ${at.size} pages called; cut levels found at ${[...levels.values()].map((r) => `${r.n} rows (${r.level.split(" | ")[0].split(",").length} fields)`).join(", ")}`);
      for (const r of levels.values()) {
        const pairs = cutPairs(JSON.parse(blocksOf(r.res)[0]), r.res.structuredContent.data);
        const rowAt = new RegExp(`^data\\.${k.rows}\\[\\d+\\]$`);
        const rows = pairs.filter((p) => rowAt.test(p.at));
        assert.ok(rows.length > 0, `${k.tool}, ${r.n} rows: no row of ${k.rows} in the text`);
        for (const f of k.fields) {
          const lost = rows.filter((p) => Object.hasOwn(p.answer, f) && !Object.hasOwn(p.text, f));
          assert.equal(lost.length, 0, `${k.tool}, a page of ${r.n} rows: ${lost.length} of the ${rows.length} rows in the text leave out ${f}, which the description says each keeps (the cut level keeping ${r.level})`);
        }
      }
    });
  }
  // #2802: through 2.6.3 the TEXT CUT sentences said "get_cve returns any one of these CVEs' records
  // whole" (search_cves, kev_recent, get_cwe, check_affected) and that check_affected returns a
  // component's matches whole (check_sbom), while get_cve's own text keeps 64 of 396 cpe_match and
  // check_affected's cuts too. Whatever a cut's sentences call whole, they say it is whole in
  // structuredContent.data.
  it("every sentence of a TEXT CUT that calls something whole says it is whole in structuredContent.data", (t) => {
    let checked = 0;
    for (const c of TOOL_CASES) {
      const note = blocksOf(measured[c.label])[1];
      const cut = note.indexOf("TEXT CUT: ");
      if (cut < 0) continue;
      for (const s of noteSentences(note.slice(cut)).filter((x) => /\bwhole\b/.test(x))) {
        assert.match(s, /\bwhole in its structuredContent\.data\b|structuredContent\.data carries the answer whole/, `${c.label}: ${s}`);
        checked++;
      }
    }
    t.diagnostic(`${checked} sentences`);
    assert.ok(checked > 0);
  });

  // get_cve's description says its cut keeps the first entries of each list: every field stays.
  it("get_cve: the first text block keeps every field of the record, as its description says, each list cut to its first entries", () => {
    const description = tools.find((x) => x.name === "get_cve").description;
    // #2802: its structured result's data is the full record; its first text block, past 30,000 characters, is not.
    assert.match(description, /^One CVE's record: /);
    assert.match(description, /Cut, each list in the record keeps its first entries, and the note names each list cut with its full length\./);
    for (const c of TOOL_CASES.filter((x) => x.tool === "get_cve")) {
      const res = measured[c.label];
      const shown = JSON.parse(blocksOf(res)[0]);
      assert.deepEqual(Object.keys(shown), Object.keys(res.structuredContent.data), `${c.label}: a field of the record left the text`);
      for (const [k, v] of Object.entries(res.structuredContent.data)) if (v === null || typeof v !== "object") assert.equal(shown[k], v, `${c.label}: ${k} is not the record's`);
    }
  });

  it("every structured result still validates against the tool's advertised outputSchema", () => {
    const ajv = new AjvJsonSchemaValidator();
    for (const c of TOOL_CASES) {
      const schema = tools.find((t) => t.name === c.tool).outputSchema;
      const r = ajv.getValidator(schema)(measured[c.label].structuredContent);
      assert.ok(r.valid, `${c.label}: ${r.errorMessage}`);
    }
  });

  it("a cut page names the offset or page size at which the rows it leaves out fit, and every description says how the text is cut", () => {
    for (const t of tools) assert.match(t.description, /Past 30,000 characters of JSON, the first text block holds data cut to fit, and the note says what the cut leaves out and where to read it \(TEXT CUT\)/, t.name);
    // The 2,000-purl SBOM cannot fit every row: it leaves the clean ones out first and says how to read the rest.
    const note = blocksOf(measured["check_sbom, 2,000 purls (10 batches of 200)"])[1];
    assert.match(note, /Only \d+ of the 2000 rows of results are in it; the other \d+ are in structuredContent\.data only: the \d+ whose verdict is not_affected or not_assessed \(data\.summary counts every verdict\)/);
    assert.match(note, /To read every row in the text, check \d+ or fewer purls per call\./);
  });

  // The ticket's control: production's 2.6.2 answer to a default search_cves, pretty-printed whole
  // as 2.6.2 sent it, is past the ceiling, so the check fails it; it does not print 2%.
  it("control: search_cves's default page as 2.6.2 sent it, the answer's JSON whole, is past the ceiling and the check fails it", (t) => {
    const c = SHAPED.find((x) => x.label === "search_cves, default page (search openssl)");
    const res = measured[c.label];
    const [, note, env] = blocksOf(res);
    const asSent = JSON.stringify(res.structuredContent.data, null, 2).length + note.replace(/ TEXT CUT: .*$/, "").length + env.length;
    t.diagnostic(shareOfCeiling(`${c.label}, as 2.6.2 sent it`, asSent));
    assert.ok(asSent > CEILING, `2.6.2's text for this answer is ${asSent}, not past the ceiling`);
    assert.throws(() => assertBoundUnderCeiling(c.label, asSent), /past #2467's ceiling of 60000/);
  });

  it("every case text-bound-live.mjs recorded is a case here, under the ceiling, and printed", (t) => {
    const cases = readLiveRecord().cases ?? {};
    for (const [label, r] of Object.entries(cases)) {
      assert.ok(SHAPED.some((c) => c.label === label), `${label} is recorded but is not a SHAPED case`);
      assert.equal(r.blocks.reduce((n, b) => n + b, 0), r.total, `${label}: its blocks do not add up to its total`);
      assert.ok(r.total <= CEILING, `${label}: production's text, ${r.total} characters (${r.measured_at}), is past #2467's ceiling of ${CEILING}`);
      // #2822: the record is written by text-bound-live.mjs --record, so its source is one it writes.
      assert.match(r.source, RECORD_SOURCE, `${label}: source ${JSON.stringify(r.source)} is not one text-bound-live.mjs writes: re-record, do not edit`);
      t.diagnostic(`${shareOfCeiling(`${label}, production ${r.measured_at}`, r.total)}; ${r.source}`);
    }
  });

  // #2822: a re-record of the kept answers moves the record's total; the SHAPED size the suite
  // holds the same answers to must move with it, or the release's own test run fails on them.
  it("each case measured on kept production answers has its size within MARGIN of the record's total for its tool", () => {
    const record = readLiveRecord();
    for (const c of SHAPED.filter((x) => x.kept)) assert.ok(record.tools?.[c.kept], `${c.label}: the record has no tools.${c.kept}`);
    assert.deepEqual(keptSizesOffRecord(record).map(setKeptSize), []);
  });

  it("control: a kept case's size moved past MARGIN from its record is named, with the size to set", () => {
    const record = readLiveRecord();
    // From SHAPED's size, not the record's total, so the control holds whatever the record says.
    const total = SHAPED.find((c) => c.kept === "exposure_radar").size;
    const off = keptSizesOffRecord({ ...record, tools: { ...record.tools, exposure_radar: { ...record.tools.exposure_radar, total: total + MARGIN + 1 } } });
    assert.equal(off.length, 1);
    assert.match(setKeptSize(off[0]), new RegExp(`^exposure_radar: SHAPED's size is \\d+, but the record \\(.+\\) measured ${total + MARGIN + 1}, more than MARGIN ${MARGIN} away: set its size to ${total + MARGIN + 1} in test/text-bound\\.mjs`));
    assert.deepEqual(keptSizesOffRecord({ ...record, tools: { ...record.tools, exposure_radar: { ...record.tools.exposure_radar, total: total + MARGIN } } }).filter((o) => o.label === "exposure_radar"), []);
  });

  // #2822: measured_at is when the record was measured; answers_read_at is when the answers it
  // measured were read from production, which a re-measure of the kept answers does not move.
  it("each tool measured on kept answers says when those answers were read from production, no later than it measured them", () => {
    for (const [tool, r] of Object.entries(readLiveRecord().tools ?? {})) {
      if (!r.answers_kept) continue;
      assert.ok(typeof r.answers_read_at === "string" && !Number.isNaN(Date.parse(r.answers_read_at)), `${tool}: answers_read_at ${JSON.stringify(r.answers_read_at)} is not a time: re-record`);
      assert.ok(Date.parse(r.answers_read_at) <= Date.parse(r.measured_at), `${tool}: its answers were read (${r.answers_read_at}) after they were measured (${r.measured_at})`);
    }
  });

  // The cut's own checks can fail: a value changed in the text, a row the answer does not have,
  // and a string cut without its "…" are caught.
  it("control: the cut check catches a changed value, an added row and a string shortened without its mark", () => {
    const data = { cves: [{ cve_id: "CVE-1", description: "abcdef", score: 1 }, { cve_id: "CVE-2", description: "ghi", score: 2 }] };
    assertCutOf({ cves: [{ cve_id: "CVE-2", description: "gh…" }] }, data);
    for (const [what, text] of [
      ["a changed value", { cves: [{ cve_id: "CVE-1", score: 9 }] }],
      ["a row the answer does not have", { cves: [{ cve_id: "CVE-3" }] }],
      ["rows out of order", { cves: [{ cve_id: "CVE-2" }, { cve_id: "CVE-1" }] }],
      ["a string cut without its mark", { cves: [{ cve_id: "CVE-1", description: "abc" }] }],
    ]) {
      assert.throws(() => assertCutOf(text, data), assert.AssertionError, what);
    }
  });
});

// The cut on its own (src/textBudget.ts dataText), on answers built to reach each step.
// #2861: search_cves's first cut level keeps patch_evidence beside patch_available (src/index.ts
// SEARCH_CVES_TEXT). No production-shaped answer carries patch_evidence yet (core-backend 2d8bb9ce
// is not deployed as these fixtures were read), so a page past the budget whole and inside it at
// the first level is served here: 50 rows with a 1,000-character description, every other row as
// an API older than the field sends it (patch_available alone). The fixtures are not edited.
describe("#2861: a search_cves page cut to its first level keeps patch_evidence", () => {
  let stub;
  let client;
  before(async () => {
    stub = await startStub();
    client = await connect({ era: MODERN, ...serverCommand(), env: { ...process.env, ECHELONGRAPH_API_BASE: stub.base, ECHELONGRAPH_API_TIMEOUT_MS: "10000" }, stderr: "inherit" });
  });
  after(async () => {
    await client?.close();
    await stub?.close();
  });

  it("every row keeps patch_available, and patch_evidence where the answer's row has it; rows from an older API gain none", async () => {
    const base = { severity: "CRITICAL", cvss_v3_score: 9.8, echelongraph_score: 9.1, score_assessed: true, kev_listed: false, description: "x".repeat(1000), cpe_match: ["cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"] };
    const rows = Array.from({ length: 50 }, (_, i) => ({
      cve_id: `CVE-2099-${30000 + i}`,
      ...base,
      ...(i % 2 ? { patch_available: false } : { patch_available: true, patch_evidence: ["fixed_version", "nvd_patch_reference"] }),
    }));
    stub.state.answers = { "/api/v1/public/cves": { cves: rows, limit: 50, offset: 0, total: rows.length } };
    const res = await client.callTool({ name: "search_cves", arguments: { search: "tomcat", limit: 50 } });
    assert.notEqual(res.isError, true, JSON.stringify(res).slice(0, 300));
    assertTextIsACut("search_cves, 50 rows, half with patch_evidence", res);
    assert.deepEqual(res.structuredContent.data.cves, rows);
    const shown = JSON.parse(blocksOf(res)[0]).cves;
    assert.equal(shown.length, 50);
    for (const [i, r] of shown.entries()) {
      assert.ok(!Object.hasOwn(r, "cpe_match"), `row ${i} kept cpe_match: the text is not cut at a level`);
      assert.equal(r.description, `${"x".repeat(200)}…`, `row ${i}: not the first level's clip`);
      assert.equal(r.patch_available, rows[i].patch_available, `row ${i}`);
      if (i % 2) assert.ok(!Object.hasOwn(r, "patch_evidence"), `row ${i}`);
      else assert.deepEqual(r.patch_evidence, ["fixed_version", "nvd_patch_reference"], `row ${i}`);
    }
  });
});

describe("#2783: how a first text block longer than the budget is cut", () => {
  const big = (n, chars) => "x".repeat(chars) + String(n);
  // The one-row-a-line layout dataText uses, for data with `over` replacing some of its fields.
  const lined = (d, over) => {
    const v = { ...d, ...over };
    const entry = (x) => (Array.isArray(x) && x.some((e) => e !== null && typeof e === "object") ? `[\n${x.map((e) => `    ${JSON.stringify(e)}`).join(",\n")}\n  ]` : JSON.stringify(x));
    return `{\n${Object.entries(v).map(([k, x]) => `  ${JSON.stringify(k)}: ${entry(x)}`).join(",\n")}\n}`;
  };
  const rows = (n, f) => Array.from({ length: n }, (_, i) => f(i));

  it("the budget is half the ceiling, and the sentence every description carries states it", () => {
    assert.equal(DATA_TEXT_BUDGET, CEILING / 2);
    assert.ok(TEXT_BUDGET_DESCRIPTION.includes(`${DATA_TEXT_BUDGET.toLocaleString("en-US")} characters`), TEXT_BUDGET_DESCRIPTION);
  });

  it("an answer that fits is pretty-printed whole, as through 2.6.2, and the note says nothing", () => {
    const d = { cves: rows(3, (i) => ({ cve_id: `CVE-2026-${i}`, description: "short" })), total: 3 };
    assert.deepEqual(dataText(d), { text: JSON.stringify(d, null, 2), said: "" });
  });

  it("an answer that fits only with one row a line is that JSON, whole, and the note says nothing", () => {
    const d = { cves: rows(120, (i) => ({ cve_id: `CVE-2026-${i}`, a: [1, 2, { b: "c" }], description: big(i, 150) })) };
    assert.ok(JSON.stringify(d, null, 2).length > DATA_TEXT_BUDGET);
    const { text, said } = dataText(d);
    assert.ok(text.length <= DATA_TEXT_BUDGET);
    assert.deepEqual(JSON.parse(text), d);
    assert.equal(said, "");
  });

  it("each level is tried in order, the first that fits is used, and the note names what it leaves out", () => {
    const d = { cves: rows(60, (i) => ({ cve_id: `CVE-2026-${i}`, description: big(i, 900), severity: "HIGH", refs: rows(3, (j) => `https://x/${j}`) })), total: 60 };
    const cut = {
      rows: "cves",
      levels: [
        { keep: ["cve_id", "description", "severity", "refs"], clip: 800 },
        { keep: ["cve_id", "description", "severity"], clip: 200 },
      ],
      whole: "get_cve returns one whole.",
    };
    const { text, said } = dataText(d, cut);
    const shown = JSON.parse(text);
    assert.ok(text.length <= DATA_TEXT_BUDGET);
    assert.deepEqual(Object.keys(shown.cves[0]), ["cve_id", "description", "severity"], "the second level's fields");
    assert.equal(shown.cves[0].description, `${"x".repeat(200)}…`);
    assert.equal(shown.cves.length, 60);
    assert.equal(shown.total, 60, "a field beside the rows is kept");
    assert.match(said, /^TEXT CUT: the API's answer is \d+ characters of JSON, more than the 30000 the first text block holds, so that block is cut, and structuredContent\.data carries the answer whole\. Each of the 60 rows of cves in it leaves out refs; every string in a row longer than 200 characters keeps its first 200, ending in "…"\. get_cve returns one whole\.$/);
    assert.deepEqual(dataText(d, cut), { text, said }, "the same answer is cut the same way");
  });

  it("when no level fits, rows leave the text, those named first before any other, and the note says which and how to read them", () => {
    const d = {
      results: rows(400, (i) => ({ index: i, purl: `pkg:npm/p${i}@1.0.0`, verdict: i % 4 === 0 ? "affected" : i % 4 === 1 ? "not_assessed" : "not_affected", note: big(i, 120) })),
    };
    const cut = {
      rows: "results",
      levels: [{ keep: ["index", "purl", "verdict", "note"], clip: 150 }],
      leaveOutFirst: { field: "verdict", values: ["not_affected", "not_assessed"], why: "summary counts them" },
      page: (shown) => `Check ${shown} or fewer per call.`,
    };
    const { text, said } = dataText(d, cut);
    const shown = JSON.parse(text).results;
    assert.ok(text.length <= DATA_TEXT_BUDGET);
    const verdicts = new Set(shown.map((r) => r.verdict));
    assert.ok(verdicts.has("affected") && !verdicts.has("not_affected"), "the not_affected rows left first, before any affected one");
    assert.deepEqual(shown.map((r) => r.index), [...shown.map((r) => r.index)].sort((a, b) => a - b), "rows keep their order");
    const m = said.match(/Only (\d+) of the 400 rows of results are in it; the other (\d+) are in structuredContent\.data only: the (\d+) whose verdict is not_affected or not_assessed \(summary counts them\)/);
    assert.ok(m, said);
    assert.equal(Number(m[1]), shown.length);
    assert.equal(Number(m[1]) + Number(m[2]), 400);
    assert.ok(said.endsWith(`Check ${shown.length} or fewer per call.`), said);
  });

  it("a list beside the rows is cut before a leaner level and before any row leaves the text, and the note says how", () => {
    const d = {
      matches: rows(60, (i) => ({ cve_id: `CVE-2026-${i}`, score: 9.8, reason: big(i, 300), extra: big(i, 400) })),
      excluded: rows(50, (i) => ({ cve_id: `CVE-2025-${i}`, reason: "platform_scoped", detail: big(i, 300) })),
    };
    const cut = {
      rows: "matches",
      levels: [
        { keep: ["cve_id", "score", "reason"], clip: 400 },
        { keep: ["cve_id", "score"], clip: 100 },
      ],
      sides: [{ list: "excluded", keep: ["cve_id", "reason"] }],
    };
    // With the excluded sample whole, only the leaner level would fit; cut, the first level does.
    assert.ok(lined(d, { matches: d.matches.map(({ cve_id, score }) => ({ cve_id, score })) }).length <= DATA_TEXT_BUDGET);
    assert.ok(lined(d, { matches: d.matches.map(({ cve_id, score, reason }) => ({ cve_id, score, reason })) }).length > DATA_TEXT_BUDGET);
    const { text, said } = dataText(d, cut);
    const shown = JSON.parse(text);
    assert.deepEqual(Object.keys(shown.matches[0]), ["cve_id", "score", "reason"], "the first level, every match whole");
    assert.equal(shown.matches.length, 60);
    assert.deepEqual(shown.excluded, d.excluded.map(({ cve_id, reason }) => ({ cve_id, reason })));
    assert.match(said, /Each of the 60 rows of matches in it leaves out extra\. Each entry of excluded in it leaves out detail\.$/);
    // An answer that fits at the first level with the list whole keeps it whole.
    const small = { ...d, matches: d.matches.slice(0, 20) };
    assert.ok(JSON.stringify(small, null, 2).length > DATA_TEXT_BUDGET && lined(small, {}).length > DATA_TEXT_BUDGET);
    const fits = dataText(small, cut);
    assert.deepEqual(JSON.parse(fits.text).excluded, small.excluded);
    assert.doesNotMatch(fits.said, /excluded/);
  });

  it("a list beside the rows too long to keep whole is capped, so rows leave in the order the tool names, not by index", () => {
    const d = {
      results: rows(600, (i) => ({ index: i, purl: `pkg:npm/p${i}@1.0.0`, verdict: i % 5 === 0 ? "affected" : "not_affected", cve_ids: i % 5 === 0 ? rows(4, (j) => `CVE-2026-${i}${j}`) : [] })),
      not_sent_purls: rows(800, (i) => `pkg:maven/org.example.component${i}/artifact-with-a-long-name-${i}@1.0.${i}`),
    };
    const cut = {
      rows: "results",
      levels: [{ keep: ["index", "purl", "verdict", "cve_ids"], clip: 100 }],
      sides: [{ list: "not_sent_purls", cap: 10, said: (k, n) => `The ${n} not sent run from position 601; ${k} shown.` }],
      leaveOutFirst: { field: "verdict", values: ["not_affected"], why: "counted" },
    };
    assert.ok(JSON.stringify(d.not_sent_purls).length > DATA_TEXT_BUDGET, "the list alone is past the budget");
    const { text, said } = dataText(d, cut);
    const shown = JSON.parse(text);
    assert.ok(text.length <= DATA_TEXT_BUDGET);
    assert.deepEqual(shown.not_sent_purls, d.not_sent_purls.slice(0, 10));
    assert.equal(shown.results.filter((r) => r.verdict === "affected").length, 120, "every affected row stays");
    assert.match(said, /In it, not_sent_purls keeps its first 10 of 800 entries\. The 800 not sent run from position 601; 10 shown\. Only \d+ of the 600 rows of results are in it; the other \d+ are in structuredContent\.data only: the \d+ whose verdict is not_affected \(counted\)/);
  });

  it("without a TextCut, every list keeps its first entries, halving until it fits, and the note names each with its full length", () => {
    const d = {
      cve_id: "CVE-2021-44228",
      cpe_match: rows(396, (i) => ({ criteria: `cpe:2.3:a:apache:log4j:${i}:*:*:*:*:*:*:*`, vulnerable: true, versionEndExcluding: "2.15.0", matchCriteriaId: `00000000-0000-4000-8000-${String(i).padStart(12, "0")}` })),
      references: rows(103, (i) => ({ url: `https://example.com/advisory/${i}/${"p".repeat(60)}`, tags: ["Vendor Advisory", "Third Party Advisory"], source: "security@apache.org" })),
    };
    assert.ok(JSON.stringify(d).length > DATA_TEXT_BUDGET, "the answer does not reach the last step");
    const { text, said } = dataText(d);
    const shown = JSON.parse(text);
    assert.ok(text.length <= DATA_TEXT_BUDGET);
    assert.equal(shown.cve_id, "CVE-2021-44228");
    assert.deepEqual(shown.cpe_match, d.cpe_match.slice(0, shown.cpe_match.length));
    assert.match(said, /Every list in it keeps at most its first (\d+) entries: cpe_match \(396\) and references \(103\), each named with its full length\./);
  });

  // #2801: the cve:// resource names its own place for the cut; a tool's first text block is the default.
  it("the sentence that opens a cut names the place the caller cuts for, the first text block by default", () => {
    const d = { cpe_match: rows(400, (i) => ({ criteria: `cpe:2.3:a:apache:log4j:${i}:*:*:*:*:*:*:*`, matchCriteriaId: `00000000-0000-4000-8000-${String(i).padStart(12, "0")}` })) };
    const first = dataText(d);
    const there = dataText(d, undefined, { opens: (n) => `DATA CUT: ${n} characters, cut here.` });
    assert.equal(there.text, first.text, "the same answer is cut the same way, wherever it goes");
    assert.match(first.said, /^TEXT CUT: the API's answer is \d+ characters of JSON, more than the 30000 the first text block holds/);
    assert.equal(there.said, first.said.replace(/^TEXT CUT: .*? carries the answer whole\./, `DATA CUT: ${JSON.stringify(d, null, 2).length} characters, cut here.`));
  });

  it("a string is never cut inside a surrogate pair", () => {
    const d = { rows: rows(200, (i) => ({ id: i, s: "😀".repeat(300) })) };
    const { text } = dataText(d, { rows: "rows", levels: [{ keep: ["id", "s"], clip: 101 }] });
    for (const r of JSON.parse(text).rows) assert.ok(!/[\uD800-\uDBFF]…$/.test(r.s) && r.s.endsWith("…"), JSON.stringify(r.s.slice(-4)));
  });
});
