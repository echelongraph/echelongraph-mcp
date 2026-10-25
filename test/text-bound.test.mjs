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
// #3121: answers are validated against the closed success branch (strict-output.mjs).
import { StrictOutputValidator } from "./strict-output.mjs";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { PKG_DIR, serverCommand } from "./server-under-test.mjs";
import {
  CEILING,
  MARGIN,
  RECORD_SOURCE,
  SBOM_MAX_PURLS,
  SHAPED,
  SHAPED_DRIFT,
  STRUCTURED_BUDGET,
  argsOf,
  assertBoundUnderCeiling,
  assertCutOf,
  assertDataCutOf,
  assertStructuredUnderBudget,
  cutPairs,
  isEntryCutOf,
  isThinOf,
  keptSizesOffRecord,
  pickedMatches,
  productionText,
  readLiveRecord,
  setKeptSize,
  shapedAnswers,
  shareOfCeiling,
  startStub,
  structuredSize,
  textSize,
} from "./text-bound.mjs";
// #2782, #3273: read off the module rather than imported by name, so a text-bound.mjs without them
// fails the tests that read them, each by name, instead of failing this whole file at import.
import * as tb from "./text-bound.mjs";
import fs from "node:fs";
import os from "node:os";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

// The cut itself, from the package under test (dist/textBudget.js starts no server and loads nothing but zod).
const textBudget = await import(pathToFileURL(path.join(PKG_DIR, "dist", "textBudget.js")).href);
const { DATA_TEXT_BUDGET, TEXT_BUDGET_DESCRIPTION, dataText } = textBudget;
// The cve:// resource's text (#2801), from dist/resources.js, which imports no server either.
const { cveResourceText } = await import(pathToFileURL(path.join(PKG_DIR, "dist", "resources.js")).href);

// The budget the server cuts the first text block to: half the ceiling, so the note and the
// envelope after it, and a release's growth, have the other half.
const BUDGET = DATA_TEXT_BUDGET;
const blocksOf = (res) => (res.content ?? []).filter((c) => c.type === "text").map((c) => c.text);
const LIMITED = "check_sbom, 2,000 purls, rate-limited after 6 batches (production's answer from a fresh budget)";
const noteSentences = (t) => t.replace(/\s+/g, " ").trim().split(/(?<=[.!?])\s+/).filter(Boolean);
// The tool cases, and the resource cases (#2801), of SHAPED.
const TOOL_CASES = SHAPED.filter((c) => !c.resource);
const RESOURCE_CASES = SHAPED.filter((c) => c.resource);

// The TEXT CUT sentence beside data whole, and beside data cut too (#3013); and the DATA CUT
// sentences, which end the note.
const TEXT_CUT_DATA_WHOLE = /TEXT CUT: the API's answer is \d+ characters of JSON, more than the 30000 the first text block holds, so that block is cut, and structuredContent\.data carries the answer whole\./;
const TEXT_CUT_DATA_CUT =
  /TEXT CUT: the API's answer is \d+ characters of JSON, more than the 30000 the first text block holds, so that block is cut, and structuredContent\.data carries the answer whole with full: true \(DATA CUT, below\)\./;
const DATA_CUT_SAID =
  /DATA CUT: with data whole, this structured result is (\d+) characters of JSON, more than the 30000 it holds unless the call says full: true, so its data is cut: (.+?)\. truncated gives the total and the number returned of each list cut, and thinned where its entries are cut to some of their fields\.(?: .+?)? The same call with full: true returns data whole\.$/;

// What every result of a case must be, besides its size: the cut's contract above. `full` is the
// same call's result with full: true (#3013): its data is the answer whole, which the first text
// block is a cut of, and data is that answer cut as truncated says, the note saying so (DATA CUT).
function assertTextIsACut(label, res, full) {
  const blocks = blocksOf(res);
  assert.equal(blocks.length, 3, `${label}: ${blocks.length} text blocks, expected 3`);
  const [first, note, env] = blocks;
  const sc = res.structuredContent;
  const answer = full.structuredContent.data;
  assert.equal(full.structuredContent.data_truncated, false, `${label}: with full: true, data_truncated is not false`);
  assert.equal(blocksOf(full)[0], first, `${label}: the first text block is not the same with full: true`);
  const shown = JSON.parse(first);
  const whole = JSON.stringify(shown) === JSON.stringify(answer);
  assertCutOf(shown, answer);
  assertDataCutOf(sc, answer, label);
  assert.ok(first.length <= BUDGET || whole, `${label}: the first text block is ${first.length} characters, past the budget of ${BUDGET}, and cut`);
  if (whole) assert.doesNotMatch(note, /TEXT CUT/, `${label}: the note says TEXT CUT, but the first text block is data whole`);
  else assert.match(note, sc.data_truncated ? TEXT_CUT_DATA_CUT : TEXT_CUT_DATA_WHOLE, `${label}: the first text block is cut and the note does not say so, or says data is whole when it is not`);
  if (sc.data_truncated) {
    const m = note.match(DATA_CUT_SAID);
    assert.ok(m, `${label}: data is cut and the note does not end saying so (DATA CUT): ${note.slice(note.indexOf("DATA CUT"))}`);
    // The size it states is the structured result's with data whole: the same call with full: true.
    assert.equal(Number(m[1]), JSON.stringify(full.structuredContent).length, `${label}: the DATA CUT sentence states another size than the structured result with full: true`);
    for (const p of Object.keys(sc.truncated)) assert.ok(m[2].includes(p), `${label}: the DATA CUT sentence does not name ${p}`);
  } else {
    assert.doesNotMatch(note, /DATA CUT/, `${label}: data is whole and the note says DATA CUT`);
  }
  // The envelope block: structuredContent without data, its notes the envelope's own sentences,
  // the note's following them, and method left out only where the note quotes it.
  const e = JSON.parse(env);
  const said = noteSentences(note);
  const own = e.notes ?? [];
  assert.deepEqual(sc.notes, [...own, ...said], `${label}: structuredContent.notes is not the envelope's own notes and then the note's sentences`);
  const { data: _data, ...rest } = sc;
  assert.deepEqual({ ...e, notes: sc.notes, ...(Object.hasOwn(e, "method") ? {} : { method: sc.method }) }, rest, `${label}: the envelope block is not structuredContent without data`);
}

// #3013's review: the lists at a path of the resource's truncated, in `o`: "a.b" is the list at b
// in the object at a; "a[].b" every list at b in the entries of the list at a.
function listsAt(o, path) {
  let at = [o];
  for (const seg of path.split(".")) {
    const each = seg.endsWith("[]");
    const key = each ? seg.slice(0, -2) : seg;
    at = at.map((x) => (x !== null && typeof x === "object" && !Array.isArray(x) ? x[key] : undefined));
    if (each) at = at.flatMap((x) => (Array.isArray(x) ? x : []));
  }
  return at.filter(Array.isArray);
}
// Every list of `o` at an object path (no list on the way), by that path.
function objectLists(o, prefix = "") {
  if (o === null || typeof o !== "object" || Array.isArray(o)) return [];
  return Object.entries(o).flatMap(([k, v]) => (Array.isArray(v) ? [[`${prefix}${k}`, v]] : objectLists(v, `${prefix}${k}.`)));
}
/**
 * #3013's review: a cve:// read's envelope says what the resource cut, as a tool's DATA CUT does.
 * data_truncated false: data is the record whole, and no truncated. true: truncated names every
 * list of the record that data holds fewer entries of (by its path), with total its length and
 * returned the entries data holds; a path through a list ("references[].tags") names the lists in
 * its entries, total the longest and returned the most any keeps. Throws, naming where, when not.
 */
function assertResourceTruncated(label, s, whole) {
  if (!s.data_truncated) {
    assert.equal(s.data_truncated, false, `${label}: data_truncated is ${JSON.stringify(s.data_truncated)}`);
    assert.equal(s.truncated, undefined, `${label}: data_truncated is false and truncated is present`);
    assert.deepEqual(s.data, whole, `${label}: data_truncated is false and data is not the record whole`);
    return;
  }
  assert.ok(s.truncated && typeof s.truncated === "object", `${label}: data_truncated is true and there is no truncated`);
  for (const [p, { total, returned, ...more }] of Object.entries(s.truncated)) {
    assert.deepEqual(more, {}, `${label}: truncated.${p} carries more than total and returned`);
    const all = listsAt(whole, p);
    const kept = listsAt(s.data, p);
    assert.ok(all.length > 0, `${label}: truncated names ${p}, which is no list of the record`);
    assert.equal(total, Math.max(...all.map((l) => l.length)), `${label}: truncated.${p}.total is ${total}`);
    assert.ok(returned < total, `${label}: truncated.${p} keeps ${returned} of ${total}`);
    for (const l of kept) assert.ok(l.length <= returned, `${label}: a list at ${p} keeps ${l.length}, past truncated's ${returned}`);
    if (!p.includes("[]")) assert.equal(kept[0]?.length, returned, `${label}: truncated.${p}.returned is ${returned}, and data's list holds ${kept[0]?.length}`);
  }
  for (const [p, list] of objectLists(whole)) {
    const [mine] = listsAt(s.data, p);
    if (mine && mine.length < list.length) assert.ok(Object.hasOwn(s.truncated, p), `${label}: data keeps ${mine.length} of ${p}'s ${list.length} entries, and truncated does not name it`);
  }
}

// What a cve:// read must be (#2801): get_cve's structured result with data cut as get_cve's first
// text block is, laid out as that block lays it out, and notes that say nothing of a text block:
// get_cve's TEXT CUT sentence is replaced by the resource's own (DATA CUT), and the sentences after
// it, on what the cut leaves out, are the same. `tool` is get_cve's result for the same CVE with
// full: true (#3013), whose data is the record whole, as the resource reads it.
function assertResourceIsACut(label, res, tool) {
  const [{ text, mimeType }] = res.contents;
  assert.equal(mimeType, "application/json", label);
  const s = JSON.parse(text);
  const sc = tool.structuredContent;
  assertCutOf(s.data, sc.data);
  const block = blocksOf(tool)[0];
  assert.ok(text.includes(`"data": ${block.replace(/\n/g, "\n  ")}\n}`), `${label}: data is not laid out as get_cve's first text block lays it out`);
  // #3013's review: the envelope is get_cve's (read with full: true) but for data_truncated and
  // truncated, which say what the resource itself cut.
  const { data: _a, notes: _b, data_truncated: cutSaid, truncated, ...envelope } = s;
  const { data: _c, notes: _d, data_truncated: _e, ...toolEnvelope } = sc;
  assert.deepEqual(envelope, toolEnvelope, `${label}: the envelope is not get_cve's`);
  assert.equal(sc.data_truncated, false, `${label}: get_cve read with full: true says its data is cut`);
  for (const n of s.notes) assert.doesNotMatch(n, /TEXT CUT|text block/, `${label}: a note about a text block the resource does not have: ${n}`);
  const cut = JSON.stringify(s.data) !== JSON.stringify(sc.data);
  assert.equal(cutSaid, cut, `${label}: data is ${cut ? "cut" : "whole"} and the resource's envelope says data_truncated ${cutSaid}`);
  assertResourceTruncated(label, s, sc.data);
  const at = s.notes.findIndex((n) => n.startsWith("DATA CUT: "));
  if (!cut) {
    assert.equal(at, -1, `${label}: data is whole and a note says DATA CUT`);
    assert.equal(text, JSON.stringify(sc, null, 2), `${label}: data is whole and the text is not the structured result pretty-printed`);
    return;
  }
  assert.match(s.notes[at] ?? "", /^DATA CUT: the API's answer is \d+ characters of JSON, more than the 30000 this resource's data holds, so data here is cut, and get_cve's structuredContent\.data carries the answer whole with full: true\.$/, `${label}: data is cut and no note says so`);
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
  // #3013: each tool case called again with full: true, whose data is the answer whole.
  const whole = {};
  const served = {};
  const answerOf = (label) => whole[label].structuredContent.data;
  before(async () => {
    stub = await startStub();
    client = await connect({ era: MODERN, ...serverCommand(), env: { ...process.env, ECHELONGRAPH_API_BASE: stub.base, ECHELONGRAPH_API_TIMEOUT_MS: "10000" }, stderr: "inherit" });
    ({ tools } = await client.listTools());
    const ask = async (c, args) => {
      stub.state.limited = c.limited;
      stub.state.requests = 0;
      return client.callTool({ name: c.tool, arguments: args });
    };
    for (const c of SHAPED) {
      stub.state.answers = shapedAnswers(c);
      assert.ok(stub.state.answers, `${c.label}: no answers kept`);
      served[c.label] = stub.state.answers;
      stub.state.limited = c.limited;
      stub.state.requests = 0;
      measured[c.label] = c.resource ? await client.readResource({ uri: c.resource }) : await ask(c, argsOf(c));
      if (c.resource) measured[`${c.label}: the tool`] = await ask(c, { ...argsOf(c), full: true });
      else whole[c.label] = await ask(c, { ...argsOf(c), full: true });
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
      else assertTextIsACut(c.label, res, whole[c.label]);
      assert.ok(total <= c.size + MARGIN, `${c.label}: ${total} characters of text, over its bound of ${c.size + MARGIN} (${c.size} measured, plus ${MARGIN})`);
      assert.ok(total >= c.size - MARGIN, `${c.label}: ${total} characters of text, under ${c.size - MARGIN} (${c.size} measured, less ${MARGIN}): the text lost more than a word; re-measure it and check what it lost`);
      assertBoundUnderCeiling(c.label, c.size);
    });
  }

  // #3013: Claude Code hands the model structuredContent, and saved get_cve CVE-2021-44228's
  // 65,540 characters of it to a file. Every default answer's structured result, all of it as
  // compact JSON, is under STRUCTURED_BUDGET and within MARGIN of its measured size either way, as
  // its text is; the same call with full: true is printed beside it.
  for (const c of TOOL_CASES) {
    it(`${c.label}: ${c.structured} characters of structuredContent, within ${MARGIN} either way, under the ${STRUCTURED_BUDGET} budget`, (t) => {
      assert.equal(typeof c.structured, "number", `${c.label}: SHAPED records no structured size`);
      const size = structuredSize(measured[c.label], stub.base);
      const asWhole = structuredSize(whole[c.label], stub.base);
      const cut = measured[c.label].structuredContent.truncated;
      t.diagnostic(`${c.label}: structuredContent ${size} / ${STRUCTURED_BUDGET}; with full: true ${asWhole}${cut ? `; truncated ${JSON.stringify(cut)}` : ""}`);
      assertStructuredUnderBudget(c.label, size);
      assert.ok(size <= c.structured + MARGIN, `${c.label}: ${size} characters of structuredContent, over its bound of ${c.structured + MARGIN} (${c.structured} measured, plus ${MARGIN})`);
      assert.ok(size >= c.structured - MARGIN, `${c.label}: ${size} characters of structuredContent, under ${c.structured - MARGIN} (${c.structured} measured, less ${MARGIN}): re-measure it and check what it lost`);
    });
  }

  // #3013's control: with the cut neutralised (full: true is the same call without it), every case
  // the cut holds under the budget is past it, and the check fails it, naming the case and its size.
  it("control: with the cut neutralised (full: true), each case it cuts is past the budget, and the check fails it naming the tool and size", (t) => {
    const cut = TOOL_CASES.filter((c) => measured[c.label].structuredContent.data_truncated);
    assert.ok(cut.length >= 10, `only ${cut.length} cases are cut`);
    for (const c of cut) {
      const size = structuredSize(whole[c.label], stub.base);
      assert.ok(size > STRUCTURED_BUDGET, `${c.label}: with data whole it is ${size} characters, not past the budget, and still cut`);
      assert.throws(() => assertStructuredUnderBudget(c.label, size), new RegExp(`^Error: ${c.label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}: structuredContent is ${size} characters of JSON, past the 30000`));
      t.diagnostic(`${c.label}: ${size} with full: true, ${structuredSize(measured[c.label], stub.base)} by default`);
    }
    // get_cve CVE-2021-44228, the case #3013 reproduced in Claude Code: 65,540 characters there.
    const g = whole["get_cve, CVE-2021-44228"];
    assert.ok(structuredSize(g, stub.base) > 60_000, "get_cve CVE-2021-44228 with full: true is not the 65,540-character structured result #3013 reproduced");
    assert.throws(() => assertStructuredUnderBudget("get_cve, CVE-2021-44228", structuredSize(g, stub.base)), /^Error: get_cve, CVE-2021-44228: structuredContent is \d{5} characters of JSON, past the 30000/);
  });

  // #3013: full: true is the answer whole on every tool, schema-valid, and its text is the default's.
  it("every tool takes full; with full: true data_truncated is false and data is the answer whole, and the default's data is a cut of it", () => {
    for (const t of tools) {
      const p = t.inputSchema?.properties?.full;
      assert.deepEqual(p, { type: "boolean", description: textBudget.FULL_ARG_DESCRIPTION }, `${t.name}: inputSchema.properties.full`);
      assert.ok(!(t.inputSchema.required ?? []).includes("full"), `${t.name}: full is required`);
    }
    for (const c of TOOL_CASES) {
      const w = whole[c.label].structuredContent;
      assert.equal(w.data_truncated, false, c.label);
      assert.equal(w.truncated, undefined, c.label);
      assert.doesNotMatch(blocksOf(whole[c.label])[1], /DATA CUT/, c.label);
      assertDataCutOf(measured[c.label].structuredContent, w.data, c.label);
    }
    assert.equal(STRUCTURED_BUDGET, textBudget.STRUCTURED_BUDGET);
    assert.equal(STRUCTURED_BUDGET, DATA_TEXT_BUDGET, "the structured result's budget is not the first text block's");
  });

  it("with full: true, structuredContent.data is the API's answer whole, never the text's cut, wherever the tool relays the answer as sent", () => {
    // exposure_radar and cve_intel relay their own cut of the answer (#2307, #2722), check_sbom
    // merges batches, and scan_manifest adds what it read of the files (#2835); every other tool's
    // data is the one answer it read. #3013: by default it is that answer, cut as truncated says
    // (assertTextIsACut holds that on every case).
    for (const c of TOOL_CASES.filter((x) => !["exposure_radar", "cve_intel"].includes(x.tool) && x.page !== "max" && !["check_sbom", "scan_manifest"].includes(x.tool))) {
      const [body] = Object.values(served[c.label]);
      assert.deepEqual(answerOf(c.label), body, c.label);
    }
    const sbom = answerOf("check_sbom, 2,000 purls (10 batches of 200)");
    assert.equal(sbom.results.length, SBOM_MAX_PURLS, "check_sbom's data does not hold every row of the 2,000");
    const limited = whole[LIMITED].structuredContent;
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
      const data = answerOf(c.label);
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
    assert.deepEqual(shown.excluded, answerOf(c.label).excluded.slice(0, 10).map(({ cve_id, reason }) => ({ cve_id, reason })), "the excluded sample keeps its first 10 entries, each its cve_id and reason");
    assert.match(blocksOf(res)[1], /In it, excluded keeps its first 10 of 50 entries; each entry of excluded in it leaves out criteria, detail and decisive\./);
    // #3013: the structured result's cut goes in the same order: the sample first, then matches
    // from the end; cve_ids, every match's cve_id, last. Once every match fits thinned, the sample
    // keeps the first of its entries that the room left holds.
    const sc = res.structuredContent;
    assert.deepEqual(Object.keys(sc.truncated), ["excluded", "matches"], JSON.stringify(sc.truncated));
    assert.ok(sc.truncated.excluded.returned < 50, JSON.stringify(sc.truncated.excluded));
    assert.deepEqual(sc.data.excluded, answerOf(c.label).excluded.slice(0, sc.truncated.excluded.returned));
    // Every match stays, thinned (#3013 follow-up), each the answer's match with some of its fields.
    assert.deepEqual(sc.truncated.matches, { total: 200, returned: 200, thinned: true });
    for (const [i, m] of sc.data.matches.entries()) assert.ok(isThinOf(m, answerOf(c.label).matches[i]), `matches[${i}]`);
    const registry = measured["check_affected, PyPI django 1.11.0 (the registry path)"].structuredContent;
    assert.deepEqual(registry.data.cve_ids, answerOf("check_affected, PyPI django 1.11.0 (the registry path)").cve_ids, "cve_ids, which names every match, was cut before the matches");
    assert.ok(registry.truncated.matches.returned > 0 && !registry.truncated.cve_ids);
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
    // full: true (#3013): this case holds the text, which is the same either way, beside data whole.
    const res = await client.callTool({ name: "check_affected", arguments: { ...argsOf(c), full: true } });
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

  // #2899: the same answer at the cap with a CISA-KEV-listed match last (and one with known
  // ransomware use among the last 15). Through 3.0.2 the text kept the first 185 in rank order, so
  // both were in structuredContent.data only and the note said "the last 15 in order". Now they
  // stay in the text while any other match is in it; with every match KEV-listed, the note names
  // each one left out.
  it("#2899: check_affected at the registry cap of 200 with a KEV-listed match last keeps it in the text, and names any KEV-listed match it leaves out", async (t) => {
    const c = SHAPED.find((x) => x.label.startsWith("check_affected, PyPI django"));
    const [[path, body]] = Object.entries(shapedAnswers(c));
    const at = (flag) =>
      Array.from({ length: 200 }, (_, i) => ({
        ...body.matches[i % body.matches.length],
        cve_id: `CVE-2026-${String(20000 + i)}`,
        kev_listed: flag(i),
        ransomware: i === 190,
        ...(i % 4 === 3
          ? { fixed_in: null, fixed_in_reason: "interval ends at last_affected 1.11.29; no fixed version recorded" }
          : { fixed_in: "2.2.28", interval: { introduced: "0", fixed: "2.2.28" } }),
      }));
    const undetermined = Array.from({ length: 50 }, (_, i) => ({ cve_id: `CVE-2025-${String(30000 + i)}`, package: "django", ecosystem: "PyPI", reason: "collapsed_fix_boundary", detail: "the advisory's affected range collapses to its fix boundary, so whether version 1.11.0 is inside it cannot be decided from the record" }));
    const ask = async (matches) => {
      stub.state.limited = undefined;
      stub.state.answers = { [path]: { ...body, matches, cve_ids: matches.map((m) => m.cve_id), count: 200, capped: true, undetermined, undetermined_count: 73 } };
      const res = await client.callTool({ name: "check_affected", arguments: argsOf(c) });
      assert.notEqual(res.isError, true, blocksOf(res)[0]);
      return res;
    };
    const matches = at((i) => i === 199 || i === 190);
    const res = await ask(matches);
    const [first, note] = blocksOf(res);
    assert.ok(first.length <= DATA_TEXT_BUDGET, `${first.length} characters`);
    const shown = JSON.parse(first).matches;
    const n = shown.length;
    t.diagnostic(`${n} of 200 matches in the text, ${first.length} characters; structuredContent.data keeps ${res.structuredContent.data.matches.length}, ${JSON.stringify(res.structuredContent.truncated?.matches)}`);
    assert.ok(n < 200, "the case no longer reaches the cut that leaves matches out");
    for (const i of [190, 199]) {
      const m = shown.find((x) => x.cve_id === matches[i].cve_id);
      assert.ok(m, `${matches[i].cve_id} (kev_listed ${matches[i].kev_listed}, ransomware ${matches[i].ransomware}) left the text while ${n} other matches stayed`);
      assert.deepEqual([m.kev_listed, m.ransomware], [true, i === 190]);
    }
    // The text keeps the first matches in rank order, and the KEV-listed ones after them, in order.
    assert.deepEqual(shown.map((m) => m.cve_id), matches.filter((m, i) => i < n - 2 || i === 190 || i === 199).map((m) => m.cve_id));
    // A default call: structuredContent.data is cut too (DATA CUT), so the text says data holds them with full: true.
    assert.match(note, new RegExp(`Only ${n} of the 200 rows of matches are in it; the other ${200 - n} are left out of it, the last ${200 - n} in order but for any whose kev_listed or ransomware is true \\(known exploited, per CISA-KEV\\), which leave it last, and structuredContent\\.data holds them with full: true\\.`));
    assert.doesNotMatch(note, /Of the rows left out of it/);
    // Every match KEV-listed: the last leave, and the note names each one.
    const all = at(() => true);
    const every = await ask(all);
    const kept = JSON.parse(blocksOf(every)[0]).matches.map((m) => m.cve_id);
    const gone = all.slice(kept.length).map((m) => m.cve_id);
    assert.ok(gone.length > 0 && gone.includes(all[190].cve_id), `${kept.length} kept`);
    assert.deepEqual(kept, all.slice(0, kept.length).map((m) => m.cve_id));
    assert.ok(blocksOf(every)[1].includes(`Of the rows left out of it, ${gone.length} have kev_listed or ransomware true: ${gone.slice(0, -1).join(", ")} and ${gone.at(-1)}.`), blocksOf(every)[1]);
  });

  // #2783 review: a 2,000-purl call from a fresh budget answers 1,200 rows and 800 purls not sent.
  // Kept whole, the 800 left no room for any row, so every list was cut to its first 64 in index
  // order: 14 of 240 affected rows beside 50 clean or unchecked ones, and 64 of the purls the note
  // tells the agent to send again.
  it("check_sbom rate-limited: affected rows stay before clean ones, and the note says which purls to send again", () => {
    const res = measured[LIMITED];
    const [first, note] = blocksOf(res);
    const shown = JSON.parse(first);
    const data = answerOf(LIMITED);
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
    assert.match(note, /they are the input's distinct purls from position 1201 on, counted in the order this tool read them \(the order of purls, or of the document's components or packages, each component's nested components right after it and before its next sibling, each purl at its first place\), and data\.not_sent_purls lists them \(past the structured result's budget it is left out whole by default, never cut short, and those positions are coverage\.sent \+ 1 to coverage\.distinct_purls; with full: true it is always there\)/);
    // #3013: beside a cut data, the rows left out of the text are in data only with full: true.
    assert.match(note, /Only \d+ of the 1200 rows of results are in it; the other \d+ are left out of it: the \d+ whose verdict is not_affected or not_assessed \(data\.summary counts every verdict\), and the last \d+ of the rest, and structuredContent\.data holds them with full: true\./);
    // #3269's second review: the text names no page size ("check N or fewer purls per call", N the
    // rows it kept, was no page size: a call of the first N kept fewer in 34 of 89 mixes).
    assert.doesNotMatch(note, /To read every row in the text/);
    // #3013: the structured result's cut goes in the same order: the purls not sent first (the note
    // says from which position they run), then the rows, clean and not-assessed ones first.
    // #3132's review: the purls not sent are the list a client retries, so data keeps all of them
    // or none (round 1 kept the first 3 of 800); with none, coverage.sent + 1 to
    // coverage.distinct_purls are their positions, exactly. check_sbom-large-rows.test.mjs holds
    // the cut alone to it over several shapes, with its control.
    const sc = res.structuredContent;
    assert.deepEqual(Object.keys(sc.truncated), ["not_sent_purls", "results"]);
    const sent = sc.truncated.not_sent_purls.returned;
    assert.ok(sent === 0 || sent === 800, `data keeps ${sent} of the 800 purls not sent: a list to retry that is not the whole`);
    assert.deepEqual(sc.data.not_sent_purls ?? [], sent === 0 ? [] : data.not_sent_purls);
    const input = [...new Set(argsOf(SHAPED.find((x) => x.label === LIMITED)).purls.map((p) => p.trim()))];
    assert.deepEqual(input.slice(sc.coverage.sent, sc.coverage.distinct_purls), data.not_sent_purls, "coverage's positions are not the purls not sent");
    assert.ok(sc.data.results.length > 0 && sc.data.results.length < affected, `${sc.data.results.length} rows in data`);
    assert.deepEqual(sc.data.results.map((r) => r.verdict).filter((v) => v === "not_affected" || v === "not_assessed"), [], "a clean or not-assessed row stayed in data beside affected rows left out");
    const keptSaid = sent === 0 ? "none of its 800 entries" : "all 800 entries";
    // #3132's review: rows leave only once no level keeps every row, and at the compact level.
    assert.match(note, new RegExp(String.raw`DATA CUT: .* not_sent_purls keeps ${keptSaid}; results keeps \d+ of its 1200 entries, each cut to index, purl, verdict, not_assessed_reason, cve_ids, matched_package, matched_via, matched_version_from, purl_name and matches \(each with cve_id, kev_listed, ransomware, epss_score, effective_score, score_assessed and fixed_in\)(?:, each row's matches keeping at most 10, .*)?, the \d+ left out being the 960 whose verdict is not_affected or not_assessed \(data\.summary counts every verdict\) and \d+ affected or undetermined rows(?:, none with a KEV-listed or ransomware match, at index [\d, toand]+?|: the \d+ with a KEV-listed or ransomware match at index [\d, toand]+?; the other \d+ at index [\d, toand]+?)(?:, and \d+ more past index \d+)?(?: \(kept: rows with one first, then the others, in input order, each that fits\))?(?:; with the room left, \d+ of the entries kept take back detail \(by position among those kept, in their order in data\): .*?)?\. Re-check these \d+ purls in this order, in calls of [\d, and]+(?:, then of at most \d+)?: each such call keeps every row in data\. truncated gives`));
    assert.equal(sc.truncated.results.thinned, true);
    assert.equal(sc.data.summary.affected, data.summary.affected, "data.summary is cut");
  });

  // #3013 follow-up: the first cut kept 3 of Juice Shop's 50 rows whole, so a client reading
  // structuredContent saw 3 affected components of 10. Before any row leaves, every row is thinned
  // to what a triage reads; then the clean rows leave, then the not_assessed ones, and only then
  // affected rows, from the end. Where every affected row fits thinned, every one is in data.
  // #3013's review: and per match every field a prompt reads from it (workload_triage: ransomware,
  // effective_score and score_assessed beside kev_listed, epss_score and fixed_in;
  // prompt-fields.test.mjs holds each prompt's to SBOM_ROW_THIN).
  const SBOM_ROW_FIELDS = ["index", "purl", "verdict", "not_assessed_reason", "cve_ids", "matched_package", "matched_via"];
  const SBOM_ROW_MIN = ["index", "purl", "verdict", "not_assessed_reason", "cve_ids"];
  const SBOM_MATCH_FIELDS = ["cve_id", "kev_listed", "ransomware", "epss_score", "effective_score", "score_assessed", "fixed_in", "fixed_in_reason"];
  // #3132's review: a compact match (check_sbom.ts SBOM_ROW_COMPACT) keeps these; #3270: with
  // epss_score and score_assessed, which workload_triage ranks by (3.0.2's dropped them).
  const SBOM_MATCH_COMPACT = ["cve_id", "kev_listed", "ransomware", "epss_score", "effective_score", "score_assessed", "fixed_in"];
  it("check_sbom and scan_manifest thin every row before one leaves, drop clean and not-assessed rows before affected ones, and keep every affected row that fits", (t) => {
    const rowTools = TOOL_CASES.filter((c) => c.tool === "check_sbom" || c.tool === "scan_manifest");
    for (const c of rowTools) {
      const sc = measured[c.label].structuredContent;
      const answer = answerOf(c.label).results;
      const kept = sc.data.results;
      const tr = sc.truncated?.results;
      const by = (rows) => rows.reduce((m, r) => ((m[r.verdict] = (m[r.verdict] ?? 0) + 1), m), {});
      t.diagnostic(`${c.label}: answer ${JSON.stringify(by(answer))}, data ${JSON.stringify(by(kept))}, ${JSON.stringify(tr)}, ${structuredSize(measured[c.label], stub.base)} characters`);
      assert.ok(tr, `${c.label}: results is not cut, so the case holds nothing`);
      assert.equal(tr.thinned, true, `${c.label}: rows left data (${tr.returned} of ${tr.total}) without being thinned first`);
      const byIndex = new Map(answer.map((r) => [r.index, r]));
      // #3132: a row keeps SBOM_ROW_FIELDS while it keeps matches, and SBOM_ROW_MIN at the leanest
      // levels; a row whose matches are cut says so (matches_truncated, isEntryCutOf); rows leave
      // data only once every row is at the leanest level, with no match left in any of them.
      for (const r of kept) {
        const a = byIndex.get(r.index);
        assert.ok(isEntryCutOf(r, a), `${c.label}: row ${r.index} is not the answer's row, thinned or cut on its own terms`);
        for (const f of Object.hasOwn(r, "matches") ? SBOM_ROW_FIELDS : SBOM_ROW_MIN) assert.ok(Object.hasOwn(r, f) || !Object.hasOwn(a, f), `${c.label}: row ${r.index} leaves out ${f}`);
        // #3270: a capped row keeps its KEV-listed and ransomware matches first, so a kept match is
        // the answer's match of the same cve_id, not the one at its position.
        for (const [i, m] of (r.matches ?? []).entries()) {
          const am = a.matches.find((x) => x.cve_id === m.cve_id);
          const fields = Object.hasOwn(m, "fixed_in_reason") || !Object.hasOwn(am, "fixed_in_reason") ? SBOM_MATCH_FIELDS : SBOM_MATCH_COMPACT;
          for (const f of fields) assert.ok(Object.hasOwn(m, f) || !Object.hasOwn(am, f), `${c.label}: row ${r.index}, match ${i} (${m.cve_id}) leaves out ${f}`);
        }
      }
      // #3132's review: rows leave data at the compact level, so each row kept that had matches
      // keeps its first ones (round 1 left them with cve_ids alone).
      if (tr.returned < tr.total) {
        for (const r of kept.filter((x) => byIndex.get(x.index).matches?.length)) assert.ok(r.matches?.length > 0, `${c.label}: rows left data, and row ${r.index} kept none of its matches`);
      }
      const affected = answer.filter((r) => r.verdict === "affected").length;
      const keptAffected = kept.filter((r) => r.verdict === "affected").length;
      if (keptAffected < affected) {
        assert.deepEqual(kept.filter((r) => r.verdict === "not_affected" || r.verdict === "not_assessed"), [], `${c.label}: an affected row left data while a clean or not-assessed row stayed`);
        // #3269's second review: the rows kept are chosen KEV-listed ones first, then the others,
        // each in input order, each that fits beside those before it, so a row of the others left
        // out is one that does not fit in the room the result leaves (round 2: the first of the
        // others, whatever fit after them). Its size as kept is at least its compact fields and its
        // floor of matches; adding it takes its index out of the note (some 8 characters).
        const keptIdx = new Set(kept.map((r) => r.index));
        const room = STRUCTURED_BUDGET - JSON.stringify(sc).length;
        const floorOf = (r) => Math.min(r.matches?.length ?? 0, (r.matches ?? []).filter((m) => m.kev_listed || m.ransomware).length + 10);
        const least = (r) =>
          JSON.stringify({
            ...Object.fromEntries([...SBOM_ROW_FIELDS, "matched_version_from", "purl_name"].filter((f) => Object.hasOwn(r, f)).map((f) => [f, r[f]])),
            ...(r.matches ? { matches: pickedMatches(r.matches, floorOf(r)).map((j) => Object.fromEntries(SBOM_MATCH_COMPACT.filter((f) => Object.hasOwn(r.matches[j], f)).map((f) => [f, r.matches[j][f]]))) } : {}),
          }).length;
        const fitting = answer.filter((r) => r.verdict !== "not_affected" && r.verdict !== "not_assessed" && !keptIdx.has(r.index) && least(r) + 1 - 8 <= room);
        assert.deepEqual(fitting.map((r) => `${r.index}: ${least(r)}`), [], `${c.label}: rows left data that fit in the ${room} characters left`);
      }
      // #3269: while any other row is cut below SBOM_ROW_THIN (its matches capped, or left out), a
      // clean or not-assessed row is kept at SBOM_ROW_MIN at most (through 3.0.2 they kept every
      // field SBOM_ROW_THIN keeps beside affected rows with no match left).
      const below = kept.filter((r) => r.verdict !== "not_affected" && r.verdict !== "not_assessed" && (Object.hasOwn(r, "matches_truncated") || (byIndex.get(r.index).matches?.length && !r.matches?.length)));
      if (below.length) {
        for (const r of kept.filter((x) => x.verdict === "not_affected" || x.verdict === "not_assessed")) {
          assert.deepEqual(Object.keys(r).filter((k) => !SBOM_ROW_MIN.includes(k)), [], `${c.label}: row ${r.index} (${r.verdict}) keeps more than SBOM_ROW_MIN while row ${below[0].index} is cut below SBOM_ROW_THIN`);
        }
      }
    }
    // The fixtures where every row fits thinned keep every row, every affected one among them.
    for (const label of ["check_sbom, Juice Shop 11.1.2 (50 components)", "scan_manifest, package-lock.json (64 packages)"]) {
      const sc = measured[label].structuredContent;
      assert.equal(sc.data.results.length, answerOf(label).results.length, `${label}: a row left data`);
    }
  });

  // #3013 follow-up: the same principle wherever one row is large: every check_affected match, every
  // cve_remediation advisory and every search_cves row of these pages stays, thinned.
  it("check_affected, cve_remediation and search_cves thin their rows before one leaves: every match, advisory and row of these cases stays", () => {
    const keepAll = TOOL_CASES.filter((c) => ["check_affected", "cve_remediation", "search_cves"].includes(c.tool));
    for (const c of keepAll) {
      const sc = measured[c.label].structuredContent;
      const rows = { check_affected: "matches", cve_remediation: "vendor_remediations", search_cves: "cves" }[c.tool];
      const tr = sc.truncated?.[rows];
      if (!tr) continue;
      assert.equal(tr.thinned, true, `${c.label}: ${rows} cut without being thinned first`);
      assert.equal(tr.returned, tr.total, `${c.label}: ${tr.returned} of ${tr.total} ${rows} kept`);
      for (const [i, r] of sc.data[rows].entries()) assert.ok(isThinOf(r, answerOf(c.label)[rows][i]), `${c.label}: ${rows}[${i}]`);
    }
    // check_affected's leanest level keeps what its description says a match keeps at least.
    for (const c of keepAll.filter((x) => x.tool === "check_affected")) {
      for (const m of measured[c.label].structuredContent.data.matches) {
        for (const f of ["cve_id", "kev_listed", "ransomware", "epss_score", "effective_score", "score_assessed", "fixed_in", "fixed_in_reason"]) {
          const a = answerOf(c.label).matches.find((x) => x.cve_id === m.cve_id);
          assert.ok(Object.hasOwn(m, f) || !Object.hasOwn(a, f), `${c.label}: ${m.cve_id} leaves out ${f}`);
        }
      }
    }
    // cve_remediation: every advisory with its state, kinds and each item's kind and url.
    const rem = measured["cve_remediation, CVE-2021-44228"].structuredContent.data.vendor_remediations;
    for (const a of rem) {
      for (const f of ["vendor", "vendor_advisory_id", "remediation_state", "remediation_kinds"]) assert.ok(Object.hasOwn(a, f), `${a.vendor_advisory_id}: ${f}`);
      for (const it of a.items ?? []) assert.ok(Object.hasOwn(it, "kind") && Object.hasOwn(it, "url"), `${a.vendor_advisory_id}: an item without kind or url`);
    }
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

  // #3013's review: the DATA CUT page sentence of search_cves and search_vendor_advisories named a
  // page size counted on the thinned rows data kept, so a page of that size came back thinned again
  // (data_truncated true) beside a note saying it fit data whole. Now the size is counted on the
  // rows whole: the same call at that size, on rows of the same shape (the page's first rows), is
  // not cut. Production-shaped rows: search_vendor_advisories' largest page (50, of which data keeps
  // some thinned), and search_cves' rows answered 200 to a page, past the API's 50, so that rows
  // leave data. The control is the sentence as it read before the review, whose size (the thinned rows
  // kept) is cut when asked for.
  it("the page size a DATA CUT says fits data whole does: the same call at that size, on rows of the same shape, is not cut (#3013's review)", async (t) => {
    const PAGE = /; a page of (\d+) rows? or fewer like these fits data whole\./;
    for (const [label, rows, n] of [
      ["search_cves, largest page (search openssl, limit 50)", "cves", 200],
      ["search_vendor_advisories, largest page (query log4j, limit 50)", "advisories", 50],
    ]) {
      const base = SHAPED.find((c) => c.label === label);
      const ask = async (size) => {
        stub.state.limited = undefined;
        stub.state.requests = 0;
        stub.state.answers = shapedAnswers({ ...base, repeat: { ...(base.repeat ?? {}), [rows]: size }, set: { ...(base.set ?? {}), limit: Math.min(size, 50) } });
        const res = await client.callTool({ name: base.tool, arguments: { ...argsOf(base), limit: Math.min(size, 50) } });
        assert.notEqual(res.isError, true, `${label}, ${size} rows: ${blocksOf(res)[0]?.slice(0, 300)}`);
        return res;
      };
      const res = await ask(n);
      const sc = res.structuredContent;
      const tr = sc.truncated?.[rows];
      assert.ok(tr && tr.thinned && tr.returned < tr.total, `${label}, ${n} rows: rows do not leave data, so no page sentence is said: ${JSON.stringify(sc.truncated)}`);
      const note = blocksOf(res)[1];
      const m = note.match(PAGE);
      assert.ok(m, `${label}: the DATA CUT names no page size that fits data whole: ${note.slice(note.indexOf("DATA CUT"))}`);
      const size = Number(m[1]);
      t.diagnostic(`${label}, ${n} rows: data keeps ${tr.returned} thinned; the note names a page of ${size}`);
      assert.ok(size > 0 && size < tr.returned, `${label}: the page size named, ${size}, is not below the ${tr.returned} thinned rows data keeps`);
      const page = await ask(size);
      assert.equal(page.structuredContent.data_truncated, false, `${label}: a page of ${size}, the size the note says fits data whole, is cut: ${JSON.stringify(page.structuredContent.truncated)}`);
      assert.equal(page.structuredContent.data[rows].length, size);
      // Control: the size the sentence named before the review, the thinned rows data kept, is cut.
      assert.equal((await ask(tr.returned)).structuredContent.data_truncated, true, `${label}: a page of ${tr.returned} fits data whole, so this case does not test the sentence`);
    }
  });

  // #3013's review: exposure_radar's two series arrive oldest first (prod-answers: kev_exposure.trend
  // by week, shadow_ai.observed.trend_30d by day), and the cut kept their first entries, showing the
  // oldest weeks as the trend. Each keeps its newest entries (keepNewest), the last ones, and the
  // note says so. Control: the same data cut without keepNewest keeps the oldest (below, cutData).
  it("exposure_radar's daily and weekly series keep their newest entries, the last the API sends, and the note says so (#3013's review)", () => {
    const sc = measured.exposure_radar.structuredContent;
    const answer = answerOf("exposure_radar");
    const note = blocksOf(measured.exposure_radar)[1];
    const at = (o, p) => p.split(".").reduce((x, k) => x?.[k], o);
    for (const [p, when] of [["kev_exposure.trend", "week"], ["shadow_ai.observed.trend_30d", "date"]]) {
      const all = at(answer, p);
      const tr = sc.truncated[p];
      assert.ok(tr && tr.returned > 0 && tr.returned < tr.total, `${p}: ${JSON.stringify(tr)}: the series is not cut to some of its entries, so this case holds nothing`);
      assert.deepEqual(all.map((e) => e[when]), [...all.map((e) => e[when])].sort(), `${p}: the answer's series is not oldest first`);
      assert.deepEqual(at(sc.data, p), all.slice(-tr.returned), `${p}: data does not keep the series' last ${tr.returned} entries, its newest`);
    }
    const k = sc.truncated["kev_exposure.trend"].returned;
    assert.equal(sc.truncated["shadow_ai.observed.trend_30d"].returned, k);
    assert.match(note, new RegExp(`DATA CUT: .*shadow_ai\\.observed\\.trend_30d and kev_exposure\\.trend keep their newest ${k} entries each;`));
  });

  // #3013's review: cve_remediation's second thinning level leaves every item's text out of data,
  // the vendor's own wording of a workaround or mitigation, which triage_cve and sbom_review have the
  // model state. No string is shortened, so the note says where each text is: get_vendor_advisory,
  // whose outputSchema carries each remediation's text. Both polarities: Log4Shell's 20 advisories
  // are thinned that far, and its first 6, thinned at the first level, keep their texts, with no
  // such sentence (its first 5 fit whole).
  it("cve_remediation: where the advisories data keeps hold no item text, the note says get_vendor_advisory returns each; where they keep it, it says nothing (#3013's review)", async () => {
    // (src/tools/cve_remediation.ts ITEM_TEXT_ELSEWHERE; that module imports index.ts, which starts the stdio server.)
    const ITEM_TEXT_ELSEWHERE =
      "No item in data keeps its text, the vendor's own wording of the step (a workaround or mitigation among them): get_vendor_advisory, given an advisory's vendor and its vendor_advisory_id as advisory_id, returns it among that advisory's remediations, whole in its structuredContent.data with full: true.";
    const label = "cve_remediation, CVE-2021-44228";
    const textsKept = (sc) => (sc.data.vendor_remediations ?? []).flatMap((a) => a.items ?? []).some((i) => Object.hasOwn(i, "text"));
    const res = measured[label];
    const sc = res.structuredContent;
    assert.ok(sc.truncated?.vendor_remediations?.thinned, JSON.stringify(sc.truncated));
    assert.ok(answerOf(label).vendor_remediations.some((a) => (a.items ?? []).some((i) => typeof i.text === "string")), "the answer's items carry no text, so this case holds nothing");
    assert.equal(textsKept(sc), false, "this case keeps item texts, so it does not reach the level that drops them");
    assert.ok(blocksOf(res)[1].includes(` ${ITEM_TEXT_ELSEWHERE} `), blocksOf(res)[1].slice(blocksOf(res)[1].indexOf("DATA CUT")));
    // get_vendor_advisory returns each remediation's text, as the sentence says.
    const detail = tools.find((x) => x.name === "get_vendor_advisory").outputSchema;
    assert.ok(JSON.stringify(detail).includes('"text":{"description":"The vendor\'s text'), "get_vendor_advisory's outputSchema carries no remediation text");
    // The other polarity: 6 advisories, thinned at the first level, each item's text kept.
    const c = SHAPED.find((x) => x.label === label);
    const [[p, body]] = Object.entries(shapedAnswers(c));
    stub.state.limited = undefined;
    stub.state.answers = { [p]: { ...body, vendor_remediations: body.vendor_remediations.slice(0, 6) } };
    const few = await client.callTool({ name: c.tool, arguments: argsOf(c) });
    assert.equal(few.structuredContent.data_truncated, true, "6 advisories are not cut, so this case holds nothing");
    assert.equal(textsKept(few.structuredContent), true, JSON.stringify(few.structuredContent.truncated));
    assert.ok(!blocksOf(few)[1].includes(ITEM_TEXT_ELSEWHERE), "the note says item texts are left out where data keeps them");
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

  // #3273: the same of the structured result, which #3140 recorded for every case and nothing
  // compared: search_cves' default page was 28,336 characters of structuredContent here against
  // production's 9,064 and passed. Cases recorded as the hosted endpoint's own text are left out, as
  // above; STRUCTURED_DRIFT_KNOWN names the ones past it on the committed record, pinned.
  it(`#3273: every case's structured result is within ${SHAPED_DRIFT * 100}% of production's for the same call, as text-bound-live.mjs recorded it, but the ones STRUCTURED_DRIFT_KNOWN names (pinned)`, (t) => {
    assert.equal(typeof tb.structuredOffRecord, "function", "text-bound.mjs has no structuredOffRecord: SHAPED's structured sizes are held to nothing production measured");
    const record = readLiveRecord();
    let compared = 0;
    for (const c of SHAPED) {
      const r = record.cases?.[c.label];
      if (typeof c.structured !== "number" || typeof r?.structured !== "number" || /own text/.test(r.source)) continue;
      compared++;
      const drift = (c.structured - r.structured) / r.structured;
      t.diagnostic(`${c.label}: structuredContent ${c.structured} here, ${r.structured} on production's answers (${r.measured_at}), ${drift >= 0 ? "+" : ""}${(drift * 100).toFixed(1)}%${tb.STRUCTURED_DRIFT_KNOWN[c.label] ? " (STRUCTURED_DRIFT_KNOWN)" : ""}`);
    }
    // Every case the record measured with this checkout's server on production's data is compared.
    assert.ok(compared >= 15, `only ${compared} cases compared`);
    const off = tb.structuredOffRecord(record);
    assert.deepEqual(off.filter((o) => !o.known).map(tb.structuredDriftMessage), []);
    for (const [label, k] of Object.entries(tb.STRUCTURED_DRIFT_KNOWN)) {
      const c = SHAPED.find((x) => x.label === label);
      const r = record.cases?.[label];
      assert.ok(c && r, `STRUCTURED_DRIFT_KNOWN names ${label}, which is not a recorded SHAPED case`);
      assert.ok(Math.abs(c.structured - k.shaped) <= MARGIN && Math.abs(r.structured - k.recorded) <= MARGIN, `${label}: STRUCTURED_DRIFT_KNOWN pins ${k.shaped} here and ${k.recorded} on record; they are ${c.structured} and ${r.structured} now: look at it again (re-sample, re-record, or re-pin with why), do not let a known drift grow unseen`);
      assert.ok(off.some((o) => o.label === label), `${label}: back within ${SHAPED_DRIFT * 100}% of the record (${c.structured} / ${r.structured}): drop its STRUCTURED_DRIFT_KNOWN entry`);
      assert.ok(typeof k.why === "string" && k.why.length > 40 && typeof k.clears === "string" && k.clears.length > 20, `${label}: a known drift says why and what clears it`);
    }
  });

  it("control (#3273): a case's structured result moved past SHAPED_DRIFT from its record is named, one at it is not, and the hosted endpoint's own text is left out", () => {
    assert.equal(typeof tb.structuredOffRecord, "function", "text-bound.mjs has no structuredOffRecord");
    const record = readLiveRecord();
    const label = "get_cve, CVE-2021-44228";
    const c = SHAPED.find((x) => x.label === label);
    const at = (structured, source = record.cases[label].source) => ({ ...record, cases: { ...record.cases, [label]: { ...record.cases[label], structured, source } } });
    const named = (rec) => tb.structuredOffRecord(rec).filter((o) => o.label === label);
    // Past it either way: production's larger, and production's smaller.
    for (const recorded of [Math.floor(c.structured / (1 + SHAPED_DRIFT)) - 1, Math.ceil(c.structured / (1 - SHAPED_DRIFT)) + 1]) {
      const [o] = named(at(recorded));
      assert.ok(o && !o.known, `${label} with production at ${recorded}: not named`);
      assert.match(tb.structuredDriftMessage(o), new RegExp(`^get_cve, CVE-2021-44228: its structuredContent here, ${c.structured}, is [-+]\\d+\\.\\d% from production's ${recorded} `));
    }
    // At it, either way: not named.
    for (const recorded of [Math.ceil(c.structured / (1 + SHAPED_DRIFT)), Math.floor(c.structured / (1 - SHAPED_DRIFT))]) assert.deepEqual(named(at(recorded)), [], `${label} with production at ${recorded}`);
    // The ticket's own case: the default search_cves page as SHAPED held it through 3.0.2.
    const sc = "search_cves, default page (search openssl)";
    const [old] = tb.structuredOffRecord(record, SHAPED.map((x) => (x.label === sc ? { ...x, structured: 28_336 } : x))).filter((o) => o.label === sc);
    assert.ok(old, "the 28,336-character default page through 3.0.2 is not named");
    assert.match(tb.structuredDriftMessage(old), /is \+212\.6% from production's 9064/);
    // The hosted endpoint's own text is compared with nothing but the ceiling, as for the text.
    assert.deepEqual(named(at(1, "the hosted endpoint's own text (3.0.0), not this checkout's")), []);
  });

  // #3273's trip-wire is any doc that claims what a default search_cves row keeps. Production's cut
  // level for that page is not on record (the record of 2026-10-11 has no truncated): only its size
  // is. So while the record holds none, every sentence of the CHANGELOG's unreleased section and of
  // text-bound.mjs that speaks of production's level for search_cves says it is inferred.
  it("#3273's review: while the record holds no truncated for search_cves' default page, no sentence states production's cut level for it as measured", () => {
    const label = "search_cves, default page (search openssl)";
    const rec = readLiveRecord().cases?.[label];
    assert.ok(rec, `control: the record has ${label}`);
    if (Object.hasOwn(rec, "truncated")) return; // on record: a claim of it can be held to the record
    const changelog = fs.readFileSync(path.join(PKG_DIR, "CHANGELOG.md"), "utf8");
    const heads = [...changelog.matchAll(/^## .*$/gm)];
    const unreleased = changelog.slice(heads[0].index, heads[1]?.index ?? changelog.length);
    // text-bound.mjs's comments, each run of comment lines one passage.
    const source = fs
      .readFileSync(path.join(PKG_DIR, "test", "text-bound.mjs"), "utf8")
      .split("\n")
      .map((l) => (/^\s*\/\//.test(l) ? l.replace(/^\s*\/\/ ?/, "") : "\u0000"))
      .join(" ")
      .split("\u0000")
      .join(". ");
    const sentences = (text) => text.replace(/\s+/g, " ").split(/(?<=[.:;])\s+/);
    const claims = [];
    for (const [where, text] of [["CHANGELOG.md, its newest section", unreleased], ["test/text-bound.mjs", source]]) {
      for (const s of sentences(text)) {
        if (/default page|default search_cves/.test(s) && /production's/.test(s) && /\blevel\b|\bcuts? (?:it )?to\b/.test(s) && !/inferred|not (?:yet )?(?:measured|on record)/.test(s)) claims.push(`${where}: ${s.slice(0, 240)}`);
      }
    }
    assert.deepEqual(claims, [], "production's level for the default search_cves page is inferred, not measured: say so");
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
      const keys = new Set(cases.flatMap((c) => (answerOf(c.label)[k.rows] ?? []).flatMap((r) => Object.keys(r))));
      const said = k.said === AT_LEAST ? m[1].split(/, | and /) : m[1].match(/[a-z][a-z0-9_]*/g).filter((w) => keys.has(w));
      assert.deepEqual(said, k.fields, `${k.tool}: the fields its description says a row keeps are not the ones this test holds`);
      if (k.sides) assert.match(description, k.sides.said, `${k.tool}: its description no longer says what the samples keep`);
      for (const c of cases) {
        const res = measured[c.label];
        const data = answerOf(c.label);
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
        // full: true (#3013): the text is the same either way, and data is the answer it is a cut of.
        const res = await client.callTool({ name: k.tool, arguments: { ...argsOf(base), full: true } });
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
  // #2841: #2800's "at least", for fields inside an answer rather than on its rows. get_cve's
  // remediation summary leads with fix_status, the API's fix-status rule (core-backend
  // cve/fixstatus.go; get_cve's outputSchema says so), and cve_remediation's answer carries it with
  // fixed_in at the top. get_cve's cut keeps every field that is not a list (each list to its first
  // entries, then every string clipped, to 50 characters at its last level); cve_remediation's
  // cuts only its vendor_remediations rows. So each of these must be in the first text block at
  // every level the cut reaches. get_cve's page is grown through the tool, from production's
  // Log4Shell record with a summary set on it: its lists repeated, then a wide object of long
  // strings beside them, until the cut's last level. Control: clipping strings at the last level
  // to 5 characters (src/textBudget.ts CAP_LEVELS) cuts fix_status.state, and this fails.
  // #3013: and in the structured result's data, cut by default at each of those levels (its lists
  // emptied at the widest, the wide object past the budget even so, which the note says): no list
  // the cut empties is inside remediation or is fixed_in, so each is the answer's (the same call
  // with full: true) whole. Control: naming remediation.fix_status.unread_inputs in get_cve's
  // DataCut and setting it non-empty fails this; so does a fallback that walks into objects.
  const FIX_STATUS = { state: "available", basis: "cve_description", described_by: "Users are recommended to upgrade to version 2.16.0, which fixes the issue.", unread_inputs: [] };
  const NESTED_KEEPS = [
    { tool: "get_cve", at: ["remediation", "fix_status"], fields: ["state", "basis"] },
    { tool: "cve_remediation", at: ["fix_status"], fields: ["state", "basis"] },
    { tool: "cve_remediation", at: [], fields: ["fixed_in", "fixed_in_reason"] },
  ];
  const dig = (o, at) => at.reduce((x, k) => (x && typeof x === "object" ? x[k] : undefined), o);
  it(`get_cve's remediation.fix_status and cve_remediation's fix_status and fixed_in stay in the first text block at every level of the cut (#2800, #2841)`, async (t) => {
    const ask = async (base, set, repeat) => {
      const c = { ...base, set: { ...(base.set ?? {}), ...set }, repeat: { ...(base.repeat ?? {}), ...repeat } };
      stub.state.limited = undefined;
      stub.state.requests = 0;
      stub.state.answers = shapedAnswers(c);
      const res = await client.callTool({ name: base.tool, arguments: argsOf(base) });
      assert.notEqual(res.isError, true, `${base.tool}: no answer: ${blocksOf(res)[0]?.slice(0, 300)}`);
      stub.state.requests = 0;
      res.whole = await client.callTool({ name: base.tool, arguments: { ...argsOf(base), full: true } });
      return res;
    };
    const levelOf = (note) => {
      const lists = note.match(/Every list in it keeps at most its first (\d+) entr/);
      const strings = note.match(/Every string in it longer than (\d+) characters/);
      return note.includes("TEXT CUT: ") ? `lists ${lists?.[1] ?? "whole"}, strings ${strings?.[1] ?? "whole"}` : "not cut";
    };
    const held = (res, k, label) => {
      const shown = dig(JSON.parse(blocksOf(res)[0]), k.at);
      const answer = dig(res.whole.structuredContent.data, k.at);
      const inData = dig(res.structuredContent.data, k.at);
      for (const f of k.fields) {
        assert.ok(Object.hasOwn(answer ?? {}, f), `${label}: the answer has no ${[...k.at, f].join(".")}, so the case holds nothing`);
        assert.deepEqual(shown?.[f], answer[f], `${label}: the first text block's ${[...k.at, f].join(".")} is ${JSON.stringify(shown?.[f])}, not the answer's ${JSON.stringify(answer[f])}`);
        assert.deepEqual(inData?.[f], answer[f], `${label}: structuredContent.data's ${[...k.at, f].join(".")} is ${JSON.stringify(inData?.[f])}, not the answer's ${JSON.stringify(answer[f])} (#3013)`);
      }
      // The whole object it is in, not only the fields named: no list in it is cut (at the top of
      // data, the lists are what the cut cuts).
      if (k.at.length) assert.deepEqual(inData, answer, `${label}: structuredContent.data's ${k.at.join(".")} is not the answer's whole (#3013)`);
      const size = JSON.stringify(res.structuredContent).length;
      if (size > STRUCTURED_BUDGET) assert.match(blocksOf(res)[1], /Cut so, the structured result is still past 30000 characters: data holds no other list to cut\./, `${label}: ${size} characters of structured result and the note does not say it is still past the budget`);
    };
    // get_cve, every level.
    const getCve = TOOL_CASES.find((c) => c.tool === "get_cve");
    const summary = { fix_status: FIX_STATUS, vendor_remediation_kinds: { vendor_fix: 1 }, vendor_advisories: 20, vendors_not_parsed: ["cisco"], kev_required_action: getCve.set.kev_required_action, fixed_branches_count: 11, fixed_versions: [], fix_references: [], failed_sections: [], truncated: false, see: "cve_remediation" };
    const wide = (n) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`f${i}`, `${"w".repeat(299)}${i % 10}`]));
    const levels = new Map();
    const structuredLevels = new Set();
    for (const [grow, keys] of [[1, 0], [4, 0], [16, 0], [16, 60], [16, 110], [16, 200]]) {
      const res = await ask(getCve, { remediation: summary, score_factors: wide(keys) }, { cpe_match: 396 * grow, references: 103 * grow });
      const level = levelOf(blocksOf(res)[1]);
      held(res, NESTED_KEEPS[0], `get_cve, lists ×${grow}, ${keys} wide fields (${level})`);
      structuredLevels.add(res.structuredContent.data_truncated ? JSON.stringify(Object.values(res.structuredContent.truncated).map((x) => x.returned)) : "whole");
      const fs = JSON.parse(blocksOf(res)[0]).remediation.fix_status;
      assert.ok(FIX_STATUS.described_by.startsWith(fs.described_by.replace(/…$/, "")), `get_cve (${level}): described_by in the text is not the answer's, cut: ${fs.described_by}`);
      levels.set(level, keys);
    }
    t.diagnostic(`get_cve levels reached: ${[...levels.keys()].join("; ")}; structured result's: ${[...structuredLevels].join("; ")}`);
    assert.ok(structuredLevels.size >= 3, `get_cve: fewer than three levels of the structured result's cut reached: ${[...structuredLevels].join("; ")}`);
    assert.ok(levels.has("lists 0, strings 50"), `get_cve: the walk did not reach the cut's last level (lists emptied, strings to 50 characters): ${[...levels.keys()].join("; ")}`);
    assert.ok([...levels.keys()].filter((l) => l !== "not cut").length >= 3, "get_cve: fewer than three cut levels reached");
    // cve_remediation, its production-shaped answer (cut) with an installed version asked.
    const rem = TOOL_CASES.find((c) => c.tool === "cve_remediation");
    for (const [fixedIn, reason] of [["2.15.0", undefined], [null, "the version is outside every affected range on record for this package, so per the ranges on record it is not affected by this CVE and has no fix to name"]]) {
      const res = await ask(rem, { fix_status: FIX_STATUS, installed: { ecosystem: "Maven", package: "org.apache.logging.log4j:log4j-core", version: "2.14.1", verdict: fixedIn ? "affected" : "not_affected" }, fixed_in: fixedIn, ...(reason ? { fixed_in_reason: reason } : {}) }, {});
      assert.match(blocksOf(res)[1], /TEXT CUT: /, "cve_remediation: the answer is not cut, so the case holds nothing");
      held(res, NESTED_KEEPS[1], `cve_remediation, fixed_in ${fixedIn}`);
      held(res, { ...NESTED_KEEPS[2], fields: reason ? NESTED_KEEPS[2].fields : ["fixed_in"] }, `cve_remediation, fixed_in ${fixedIn}`);
    }
  });
  // #2802: through 2.6.3 the TEXT CUT sentences said "get_cve returns any one of these CVEs' records
  // whole" (search_cves, kev_recent, get_cwe, check_affected) and that check_affected returns a
  // component's matches whole (check_sbom), while get_cve's own text keeps 64 of 396 cpe_match and
  // check_affected's cuts too. Whatever a cut's sentences call whole, they say it is whole in
  // structuredContent.data. #3013: and, since that data is cut too by default, that it is whole
  // there with full: true; a DATA CUT says the same of the call's own data.
  it("every sentence of a TEXT CUT that calls something whole says it is whole in structuredContent.data with full: true", (t) => {
    let checked = 0;
    let dataCuts = 0;
    for (const c of TOOL_CASES) {
      for (const res of [measured[c.label], whole[c.label]]) {
        const note = blocksOf(res)[1];
        const cut = note.indexOf("TEXT CUT: ");
        const dataCut = note.indexOf("DATA CUT: ");
        if (cut >= 0) {
          for (const s of noteSentences(note.slice(cut, dataCut < 0 ? undefined : dataCut)).filter((x) => /\bwhole\b/.test(x))) {
            assert.match(s, /\bwhole in its structuredContent\.data\b|structuredContent\.data carries the answer whole/, `${c.label}: ${s}`);
            // Of another tool's data, or of this call's when it is cut, whole only with full: true.
            if (!/carries the answer whole\.$/.test(s)) assert.match(s, /with full: true/, `${c.label}: ${s}`);
            checked++;
          }
        }
        if (dataCut >= 0) {
          assert.ok(res.structuredContent.data_truncated, `${c.label}: DATA CUT beside data whole`);
          assert.match(note.slice(dataCut), /The same call with full: true returns data whole\.$/, c.label);
          dataCuts++;
        }
      }
    }
    t.diagnostic(`${checked} sentences, ${dataCuts} DATA CUTs`);
    assert.ok(checked > 0 && dataCuts > 0);
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

  // #3013: in both modes, cut and whole.
  it("every structured result still validates against the tool's advertised outputSchema, by default and with full: true", () => {
    const ajv = new StrictOutputValidator();
    for (const c of TOOL_CASES) {
      const schema = tools.find((t) => t.name === c.tool).outputSchema;
      for (const [mode, res] of [["default", measured[c.label]], ["full: true", whole[c.label]]]) {
        // A success, not the unexpected_shape failure checked() turns an invalid one into, whose
        // own envelope validates.
        assert.notEqual(res.isError, true, `${c.label} (${mode}): ${res.content?.[0]?.text?.slice(0, 300)}`);
        assert.equal(typeof res.structuredContent.data_truncated, "boolean", `${c.label} (${mode})`);
        const r = ajv.getValidator(schema)(res.structuredContent);
        assert.ok(r.valid, `${c.label} (${mode}): ${r.errorMessage}`);
      }
    }
  });

  it("a cut page names the offset or page size at which the rows it leaves out fit, and every description says how the text is cut", () => {
    for (const t of tools) assert.match(t.description, /Past 30,000 characters of JSON, the first text block holds data cut to fit, and the note says what the cut leaves out and where to read it \(TEXT CUT\)/, t.name);
    // The 2,000-purl SBOM cannot fit every row: it leaves the clean ones out first and says how to read the rest.
    const note = blocksOf(measured["check_sbom, 2,000 purls (10 batches of 200)"])[1];
    assert.match(note, /Only \d+ of the 2000 rows of results are in it; the other \d+ are left out of it: the \d+ whose verdict is not_affected or not_assessed \(data\.summary counts every verdict\)/);
    // With full: true (#3013), the rows left out of the text are in its data, as through 2.7.x.
    assert.match(blocksOf(whole["check_sbom, 2,000 purls (10 batches of 200)"])[1], /Only \d+ of the 2000 rows of results are in it; the other \d+ are in structuredContent\.data only: the \d+ whose verdict is not_affected or not_assessed \(data\.summary counts every verdict\)/);
    // #3269's second review: and no page size for the text, which none of its sizes was.
    assert.doesNotMatch(note, /To read every row in the text/);
  });

  // The ticket's control: production's 2.6.2 answer to a default search_cves, pretty-printed whole
  // as 2.6.2 sent it, is past the ceiling, so the check fails it; it does not print 2%.
  it("control: search_cves's default page as 2.6.2 sent it, the answer's JSON whole, is past the ceiling and the check fails it", (t) => {
    const c = SHAPED.find((x) => x.label === "search_cves, default page (search openssl)");
    const res = measured[c.label];
    const [, note, env] = blocksOf(res);
    const asSent = JSON.stringify(answerOf(c.label), null, 2).length + note.replace(/ TEXT CUT: .*$/, "").length + env.length;
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
      // #3013: a case recorded since its structured result was measured is under that budget.
      if (r.structured !== undefined) assertStructuredUnderBudget(`${label}, production ${r.measured_at}`, r.structured);
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
    // #3013: and its structured result's, which the record carries since text-bound-live.mjs measures it.
    for (const c of SHAPED.filter((x) => x.kept)) {
      const r = record.tools[c.kept];
      assert.equal(typeof r.structured, "number", `${c.label}: the record has no structured size for ${c.kept}: run node test/text-bound-live.mjs --answers test/fixtures/prod-answers --record`);
      assert.ok(Math.abs(c.structured - r.structured) <= MARGIN, `${c.label}: SHAPED's structured is ${c.structured}, the record (${r.measured_at}) measured ${r.structured}: set it to ${r.structured}`);
      assertStructuredUnderBudget(`${c.label}, production's kept answers`, r.structured);
    }
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

  // ── #2782: the record is dated by the production read, and names the code that measured apart ──
  // Through 3.0.2 `--answers test/fixtures/prod-answers --record` wrote its own time as measured_at:
  // the committed record said 2026-10-11T11:41Z for answers production served at 07:36Z on 10-05.
  it("#2782: each entry measured on the kept answers is dated by the production read: measured_at less each kept answer's own generated_at is the age the read recorded for that answer (answers_age_ms)", (t) => {
    assert.equal(typeof tb.datedAfterAnswers, "function", "text-bound.mjs has no datedAfterAnswers: nothing holds the record's date to the answers it measured");
    assert.equal(typeof tb.generatedAtByFile, "function", "text-bound.mjs has no generatedAtByFile: the record's date is held to a fixed allowance, not to what its own answers say");
    const gens = tb.generatedAtByFile();
    assert.ok(Object.keys(gens).length, "no kept answer carries a generated_at, so the record's date is held to nothing");
    for (const [tool, r] of Object.entries(readLiveRecord().tools ?? {})) {
      if (!r.answers_kept) continue;
      for (const [f, g] of Object.entries(gens)) t.diagnostic(`${tool}: ${f} (generated_at ${g.at}) was ${((Date.parse(r.measured_at) - g.ms) / 1000).toFixed(1)} s old at measured_at ${r.measured_at}; the read recorded ${r.answers_age_ms?.[f]} ms`);
    }
    assert.deepEqual(tb.datedAfterAnswers().map(tb.datedAfterAnswersMessage), []);
  });

  // The fixed 60 s this replaced rested on a false premise: core-backend's cache.SWR serves its last
  // value, of any age, to the first request after the 60 s TTL (and refreshes behind it), and the
  // stats handlers add stale-while-revalidate=300 for the CDN. So an honest read can get answers
  // minutes old: on 2026-10-05 two were. Only the read can say how old each was.
  it("#2782: the committed record carries the ages the 2026-10-05 read saw, and they show why no fixed allowance holds (two kept answers were over 140 s old)", () => {
    assert.equal(typeof tb.answerAges, "function", "text-bound.mjs has no answerAges: the read does not record how old each answer it kept was");
    const want = { "exposed-databases_stats.json": 152_204, "kev-exposure_stats.json": 32_227, "leaked-credentials_stats.json": 146_371, "shadow-ai-radar_stats.json": 46_226 };
    for (const [tool, r] of Object.entries(readLiveRecord().tools ?? {})) {
      if (!r.answers_kept) continue;
      assert.deepEqual(r.answers_age_ms, want, `${tool}: answers_age_ms`);
      assert.deepEqual(tb.answerAges(r.answers_read_at), want, `${tool}: the ages at its answers_read_at`);
    }
    assert.ok(Object.values(want).filter((ms) => ms > 60_000).length >= 2, "control: the read's answers past the stats cache's 60 s TTL");
    assert.equal(tb.answerAges(null), null);
    assert.equal(tb.answerAges("not a time"), null);
  });

  it("control (#2782): a record re-dated past its read is named (the ticket's 9m26s, 14 days, none, 1 ms either way, no ages, an answer the read did not keep); an honest read of answers 10 minutes old is not", () => {
    assert.equal(typeof tb.answerAges, "function", "text-bound.mjs has no answerAges");
    const record = readLiveRecord();
    const dir = tb.PROD_ANSWERS;
    const newest = tb.newestGeneratedAt(dir);
    const iso = (ms) => new Date(ms).toISOString();
    const read = Date.parse(record.tools.exposure_radar.measured_at);
    const ages = record.tools.exposure_radar.answers_age_ms;
    // An entry as the harness writes it at a read at `ms`: that read's time and the ages it saw.
    const honest = (ms) => ({ measured_at: iso(ms), answers_age_ms: tb.answerAges(iso(ms), dir) });
    const entry = (fields, where = "tools") =>
      where === "tools"
        ? { ...record, tools: { ...record.tools, exposure_radar: { ...record.tools.exposure_radar, ...fields } } }
        : { ...record, cases: { ...record.cases, exposure_radar: { ...record.cases.exposure_radar, source: tb.KEPT_SOURCE, ...fields } } };
    const names = (rec) => tb.datedAfterAnswers(rec, dir).map((o) => o.where);
    const message = (rec) => tb.datedAfterAnswers(rec, dir).map(tb.datedAfterAnswersMessage)[0];
    // e20db98c's re-date, 9m26s past the read.
    assert.deepEqual(names(entry({ measured_at: iso(read + 566_000) })), ["tools.exposure_radar"]);
    assert.match(message(entry({ measured_at: iso(read + 566_000) })), /^tools\.exposure_radar: measured_at "[^"]+" is 566\.0 s later than the read that kept these answers says: exposed-databases_stats\.json \(generated_at [^)]+\) would have been 718\.2 s old at it, and the read recorded that answer 152\.2 s old \(answers_age_ms\).* Re-measure with node test\/text-bound-live\.mjs --answers test\/fixtures\/prod-answers --record/);
    // The ticket's 14 days, no date at all, and 1 ms either way.
    assert.deepEqual(names(entry({ measured_at: iso(read + 14 * 86_400_000) })), ["tools.exposure_radar"]);
    assert.deepEqual(names(entry({ measured_at: null })), ["tools.exposure_radar"]);
    assert.deepEqual(names(entry({ measured_at: iso(read + 1) })), ["tools.exposure_radar"]);
    assert.deepEqual(names(entry({ measured_at: iso(read - 1) })), ["tools.exposure_radar"]);
    // An honest read 10 minutes after the newest answer was computed (every radar served stale):
    // not named. The fixed 60 s allowance named it, and turned npm test red on an honest record.
    assert.deepEqual(names(entry(honest(newest.ms + 600_000))), []);
    assert.deepEqual(names(entry({ ...honest(newest.ms + 600_000), read_ms: null })), []);
    // That read re-dated afterwards is named.
    assert.deepEqual(names(entry({ ...honest(newest.ms + 600_000), measured_at: iso(newest.ms + 600_001) })), ["tools.exposure_radar"]);
    // No ages on record (an older harness, a hand edit): the date is held to nothing, so named.
    assert.deepEqual(names(entry({ answers_age_ms: undefined })), ["tools.exposure_radar"]);
    assert.match(message(entry({ answers_age_ms: undefined })), /records no answers_age_ms/);
    // A kept answer the read did not record: the answers were replaced after the read.
    const { ["kev-exposure_stats.json"]: _kev, ...fewer } = ages;
    assert.deepEqual(names(entry({ answers_age_ms: fewer })), ["tools.exposure_radar"]);
    assert.match(message(entry({ answers_age_ms: fewer })), /kev-exposure_stats\.json/);
    // A case measured on the kept answers is held the same way.
    assert.deepEqual(names(entry({ measured_at: iso(read + 566_000), answers_age_ms: ages }, "cases")), ["cases.exposure_radar"]);
    assert.deepEqual(names(entry({ measured_at: iso(read), answers_age_ms: ages }, "cases")), []);
  });

  it("#2782: each tools entry records the code that measured apart from the read: code_measured_at no earlier than measured_at, code_version package.json's version (+unreleased), read_ms a count or null", () => {
    assert.equal(typeof tb.codeVersion, "function", "text-bound.mjs has no codeVersion: the record names package.json's version for unreleased code");
    for (const [tool, r] of Object.entries(readLiveRecord().tools ?? {})) {
      assert.ok(typeof r.code_measured_at === "string" && !Number.isNaN(Date.parse(r.code_measured_at)), `${tool}: code_measured_at ${JSON.stringify(r.code_measured_at)} is not a time: re-measure with node test/text-bound-live.mjs --answers test/fixtures/prod-answers --record`);
      assert.ok(Date.parse(r.code_measured_at) >= Date.parse(r.measured_at), `${tool}: measured by this checkout's server (${r.code_measured_at}) before production was read (${r.measured_at})`);
      assert.match(String(r.code_version), /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?(?:\+unreleased)?$/, `${tool}: code_version ${JSON.stringify(r.code_version)}`);
      assert.ok(r.code_version.startsWith(r.package_version), `${tool}: code_version ${r.code_version} is not package.json's ${r.package_version}`);
      assert.ok(r.read_ms === null || (Number.isInteger(r.read_ms) && r.read_ms >= 0), `${tool}: read_ms ${JSON.stringify(r.read_ms)}`);
      assert.equal(r.answers_read_at, r.measured_at, `${tool}: answers_read_at and measured_at are the same read`);
    }
    // codeVersion: unreleased only where the newest section is unreleased and lists a change.
    const log = (head, body) => `# Changelog\n\nPreamble.\n\n## ${head}\n\n${body}\n## 3.0.2 — 2026-10-17\n\n- released\n`;
    assert.equal(tb.codeVersion("3.0.2", log("Unreleased", "- **a change** (#1).\n")), "3.0.2+unreleased");
    assert.equal(tb.codeVersion("2.7.2", log("2.8.0 — unreleased", "- **Contract change** (#3013).\n")), "2.7.2+unreleased");
    assert.equal(tb.codeVersion("3.0.2", log("Unreleased", "")), "3.0.2");
    assert.equal(tb.codeVersion("3.0.2", "# Changelog\n\n## 3.0.2 — 2026-10-17\n\n- released\n"), "3.0.2");
  });

  it("#2782: the record's about is RECORD_ABOUT, which text-bound-live.mjs writes, and it names every field the record's entries carry", () => {
    assert.equal(typeof tb.RECORD_ABOUT, "string", "text-bound.mjs has no RECORD_ABOUT: the record's about is written by hand and goes stale");
    const record = readLiveRecord();
    assert.equal(record.about, tb.RECORD_ABOUT, "the record's about is not RECORD_ABOUT: re-record, or set it there");
    assert.doesNotMatch(record.about, /moves measured_at|until the first --record/, "the about says what the code no longer does");
    const fields = new Set([...Object.values(record.tools ?? {}), ...Object.values(record.cases ?? {})].flatMap((r) => Object.keys(r)));
    for (const f of [...fields, "read_ms", "code_measured_at", "code_version", "data_truncated", "truncated"]) assert.ok(record.about.includes(f), `the about does not say what ${f} is`);
  });

  // The ticket's done-means, run: the harness itself, on a copy of the record and the kept answers.
  it("#2782: --answers test/fixtures/prod-answers --record keeps measured_at and read_ms, records the code that measured apart, and leaves the kept answers as they are (run on a copy)", async () => {
    const harness = path.join(PKG_DIR, "test", "text-bound-live.mjs");
    const run = promisify(execFile);
    const fixture = (dir, name) => path.join(dir, name);
    const copy = (to, record) => {
      fs.mkdirSync(fixture(to, "prod-answers"), { recursive: true });
      for (const f of fs.readdirSync(tb.PROD_ANSWERS)) fs.copyFileSync(path.join(tb.PROD_ANSWERS, f), path.join(to, "prod-answers", f));
      fs.writeFileSync(fixture(to, "text-bound-live.json"), `${JSON.stringify(record, null, 2)}\n`);
    };
    const remeasure = async (dir, answers = fixture(dir, "prod-answers")) => {
      const started = Date.now();
      const out = await run(process.execPath, [harness, "--answers", answers, "--record", "--fixtures", dir], { encoding: "utf8", maxBuffer: 64 << 20 }).catch((e) => e);
      assert.equal(out.code ?? 0, 0, `the harness exited ${out.code}: ${String(out.stdout).slice(-1500)}`);
      assert.match(out.stdout, /recorded 2 cases and (exposure_radar, cve_summary|cve_summary, exposure_radar)/, out.stdout.slice(-800));
      return { written: JSON.parse(fs.readFileSync(fixture(dir, "text-bound-live.json"), "utf8")), started, ended: Date.now() };
    };
    const record = readLiveRecord();
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "eg-text-bound-live-"));
    try {
      const code = tb.codeVersion(JSON.parse(fs.readFileSync(path.join(PKG_DIR, "package.json"), "utf8")).version, fs.readFileSync(path.join(PKG_DIR, "CHANGELOG.md"), "utf8"));
      // 1. The committed record, re-measured from the answers kept with it.
      const a = path.join(tmp, "a");
      copy(a, record);
      const { written, started, ended } = await remeasure(a);
      for (const tool of ["exposure_radar", "cve_summary"]) {
        const was = record.tools[tool];
        const now = written.tools[tool];
        assert.deepEqual([now.measured_at, now.read_ms, now.answers_read_at, now.answers_age_ms], [was.measured_at, was.read_ms, was.answers_read_at, was.answers_age_ms], `${tool}: the re-measure moved when production was read`);
        assert.ok(Date.parse(now.code_measured_at) >= started - 1000 && Date.parse(now.code_measured_at) <= ended, `${tool}: code_measured_at ${now.code_measured_at} is not this run`);
        assert.equal(now.code_version, code, `${tool}: code_version`);
        assert.ok(Math.abs(now.total - was.total) <= MARGIN, `${tool}: ${now.total} against the record's ${was.total}`);
        const c = written.cases[tool];
        assert.deepEqual([c.source, c.measured_at, c.read_ms, c.answers_age_ms], [tb.KEPT_SOURCE, was.measured_at, was.read_ms, was.answers_age_ms], `cases.${tool}: dated by the read, not the re-measure`);
        assert.equal(typeof c.data_truncated, "boolean", `cases.${tool}: #3273's data_truncated is not on record`);
      }
      assert.equal(written.about, tb.RECORD_ABOUT);
      assert.deepEqual(tb.datedAfterAnswers(written, fixture(a, "prod-answers")).map(tb.datedAfterAnswersMessage), []);
      for (const f of fs.readdirSync(tb.PROD_ANSWERS)) assert.equal(fs.readFileSync(path.join(a, "prod-answers", f), "utf8"), fs.readFileSync(path.join(tb.PROD_ANSWERS, f), "utf8"), `${f}: the re-measure rewrote a kept answer`);
      // 2. A record written before #2782 (measured_at the re-measure's time, as through 3.0.2, and
      //    as an older harness on another branch writes it): the read is its answers_read_at.
      const legacy = structuredClone(record);
      for (const r of Object.values(legacy.tools)) {
        r.measured_at = "2026-10-11T11:41:36.680Z";
        for (const k of ["read_ms", "answers_age_ms", "code_measured_at", "code_version"]) delete r[k];
      }
      assert.deepEqual(tb.datedAfterAnswers(legacy).map((o) => o.where).sort(), ["tools.cve_summary", "tools.exposure_radar"], "control: the pre-#2782 record is not named");
      const b = path.join(tmp, "b");
      copy(b, legacy);
      const { written: migrated } = await remeasure(b);
      for (const tool of ["exposure_radar", "cve_summary"]) {
        assert.equal(migrated.tools[tool].measured_at, record.tools[tool].answers_read_at, `${tool}: a pre-#2782 entry's read is its answers_read_at`);
        assert.deepEqual(migrated.tools[tool].answers_age_ms, record.tools[tool].answers_age_ms, `${tool}: the ages are derived from the read on record (answers_read_at), not from now`);
      }
      assert.deepEqual(tb.datedAfterAnswers(migrated, fixture(b, "prod-answers")).map(tb.datedAfterAnswersMessage), []);
      // 3. Answers from another directory were read at no known time: dated null, never now.
      const c3 = path.join(tmp, "c");
      copy(c3, record);
      fs.cpSync(fixture(c3, "prod-answers"), path.join(tmp, "elsewhere"), { recursive: true });
      const { written: elsewhere } = await remeasure(c3, path.join(tmp, "elsewhere"));
      for (const tool of ["exposure_radar", "cve_summary"]) assert.deepEqual([elsewhere.tools[tool].measured_at, elsewhere.tools[tool].read_ms, elsewhere.tools[tool].answers_read_at, elsewhere.tools[tool].answers_age_ms], [null, null, null, null], tool);
      // 4. A mixed merge (#2782's review): this harness's code_measured_at kept beside another
      //    branch's re-dated measured_at. The suite names it, and the remedy it prints puts measured_at
      //    back to the read (answers_read_at), instead of keeping the re-date and looping.
      const mixed = structuredClone(record);
      for (const r of Object.values(mixed.tools)) r.measured_at = "2026-10-18T09:00:00.000Z";
      assert.deepEqual(tb.datedAfterAnswers(mixed).map((o) => o.where).sort(), ["tools.cve_summary", "tools.exposure_radar"], "control: the mixed record is not named");
      const d = path.join(tmp, "d");
      copy(d, mixed);
      const { written: healed } = await remeasure(d);
      for (const tool of ["exposure_radar", "cve_summary"]) assert.equal(healed.tools[tool].measured_at, record.tools[tool].answers_read_at, `${tool}: the re-measure kept the re-dated measured_at`);
      assert.deepEqual(tb.datedAfterAnswers(healed, fixture(d, "prod-answers")).map(tb.datedAfterAnswersMessage), []);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("#2782: readTimeOf takes a tools entry's read from answers_read_at, which the read writes and nothing re-dates; measured_at only for an entry with no answers_read_at", () => {
    const read = "2026-10-05T07:37:21.576Z";
    const later = "2026-10-18T09:00:00.000Z";
    // A mixed merge: this harness's code_measured_at beside a re-dated measured_at.
    assert.equal(tb.readTimeOf({ measured_at: later, answers_read_at: read, code_measured_at: later }), read);
    // Written before #2782: measured_at was the re-measure's time.
    assert.equal(tb.readTimeOf({ measured_at: later, answers_read_at: read }), read);
    // This harness's entry: the two are the same read.
    assert.equal(tb.readTimeOf({ measured_at: read, answers_read_at: read, code_measured_at: later }), read);
    // No answers_read_at: measured_at where this harness wrote it, else no read on record.
    assert.equal(tb.readTimeOf({ measured_at: read, code_measured_at: later }), read);
    assert.equal(tb.readTimeOf({ measured_at: later }), null);
    assert.equal(tb.readTimeOf(undefined), null);
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

  // #3013: the structured result's check can fail too: a cut that changes an entry, shortens a
  // string, changes a field that is not a list, miscounts, or is not declared is caught.
  it("control: the data-cut check catches a changed entry, a changed field, a miscount and an undeclared cut", () => {
    const answer = { id: "x", rows: [{ i: 0, s: "abc" }, { i: 1, s: "def" }, { i: 2, s: "ghi" }], obj: { list: [1, 2, 3] } };
    const ok = { data_truncated: true, truncated: { rows: { total: 3, returned: 2 } }, data: { ...answer, rows: answer.rows.slice(0, 2) } };
    assertDataCutOf(ok, answer);
    assertDataCutOf({ data_truncated: false, data: answer }, answer);
    for (const [what, sc] of [
      ["an entry changed", { ...ok, data: { ...ok.data, rows: [{ i: 0, s: "abc" }, { i: 1, s: "de…" }] } }],
      ["a field that is not a list changed", { ...ok, data: { ...ok.data, id: "y" } }],
      ["a list inside an object cut without being named", { ...ok, data: { ...ok.data, obj: { list: [1] } } }],
      ["returned miscounted", { ...ok, truncated: { rows: { total: 3, returned: 1 } } }],
      ["total miscounted", { ...ok, truncated: { rows: { total: 4, returned: 2 } } }],
      ["entries out of order", { ...ok, data: { ...ok.data, rows: [answer.rows[1], answer.rows[0]] } }],
      ["a cut with data_truncated false", { data_truncated: false, data: ok.data }],
      ["data_truncated true with nothing named", { data_truncated: true, truncated: {}, data: answer }],
    ]) {
      assert.throws(() => assertDataCutOf(sc, answer), assert.AssertionError, what);
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
    const res = await client.callTool({ name: "search_cves", arguments: { search: "tomcat", limit: 50, full: true } });
    assert.notEqual(res.isError, true, JSON.stringify(res).slice(0, 300));
    assertTextIsACut("search_cves, 50 rows, half with patch_evidence", res, res);
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

  // #3272: through 3.0.2 a list the tool names beside its rows was only thinned or capped, and cut
  // before the rows' leaner levels; once the leanest level did not fit, rows left the text while
  // those lists stayed (cve_remediation's fixed_branches, patches and fix_references beside its
  // advisories, which its structured cut thins and empties first). A list named beforeRows stays
  // whole at every level, is cut as it says once the leanest level does not fit (in the order
  // named), and then loses entries from the end, the last named first, before any row leaves.
  it("#3272: lists named beforeRows stay whole at every level, then are cut, then lose entries from the end, the last named first, before any row leaves the text", () => {
    const d = {
      advisories: rows(20, (i) => ({ id: `A-${i}`, body: big(i, 1200) })),
      branches: rows(40, (i) => ({ pkg: `p${i}`, range: big(i, 150) })),
      patches: rows(40, (i) => ({ url: `https://p/${i}/${big(i, 150)}`, extra: big(i, 60) })),
      refs: rows(20, (i) => ({ url: `https://r/${i}/${big(i, 150)}` })),
    };
    const cut = {
      rows: "advisories",
      levels: [
        { keep: ["id", "body"], clip: 1000 },
        { keep: ["id", "body"], clip: 700 },
      ],
      sides: [
        { list: "branches", beforeRows: true },
        { list: "patches", keep: ["url"], beforeRows: true },
        { list: "refs", beforeRows: true },
      ],
      page: (k, n) => `The other ${n - k} are elsewhere.`,
    };
    const counts = (text) => Object.fromEntries(Object.entries(JSON.parse(text)).map(([k, v]) => [k, v.length]));
    // The leaner level fits with every list whole: no list is cut.
    const few = { ...d, patches: d.patches.slice(0, 10) };
    const whole = dataText(few, cut);
    assert.deepEqual(JSON.parse(whole.text).patches, few.patches, "a list named beforeRows was cut while a leaner level of the rows fit beside it whole");
    assert.equal(JSON.parse(whole.text).advisories[0].body.length, 701);
    assert.doesNotMatch(whole.said, /patches|refs|branches/);
    // The leanest level does not fit: patches are cut to their url, then refs, named last, leave first.
    const fit = dataText(d, cut);
    assert.ok(fit.text.length <= DATA_TEXT_BUDGET);
    assert.deepEqual(counts(fit.text), { advisories: 20, branches: 40, patches: 40, refs: 4 });
    assert.deepEqual(JSON.parse(fit.text).patches, d.patches.map(({ url }) => ({ url })));
    assert.deepEqual(JSON.parse(fit.text).refs, d.refs.slice(0, 4));
    assert.match(fit.said, /Each entry of patches in it leaves out extra\. In it, refs keeps its first 4 of 20 entries, before any row of advisories is left out\.$/);
    // More rows: refs, then patches, are emptied before branches loses any.
    const more = dataText({ ...d, advisories: rows(40, (i) => ({ id: `A-${i}`, body: big(i, 1200) })) }, cut);
    assert.deepEqual(counts(more.text), { advisories: 40, branches: 4, patches: 0, refs: 0 });
    assert.match(more.said, /In it, refs keeps none of its 20 entries, patches keeps none of its 40 entries and branches keeps its first 4 of 40 entries, before any row of advisories is left out\.$/);
    // Every list emptied and still too long: then rows leave, and the page sentence says where.
    const most = dataText({ ...d, advisories: rows(60, (i) => ({ id: `A-${i}`, body: big(i, 1200) })) }, cut);
    const left = counts(most.text);
    assert.deepEqual([left.branches, left.patches, left.refs], [0, 0, 0]);
    assert.ok(left.advisories > 0 && left.advisories < 60);
    assert.match(most.said, new RegExp(`In it, refs keeps none of its 20 entries, patches keeps none of its 40 entries and branches keeps none of its 40 entries, before any row of advisories is left out\\. Only ${left.advisories} of the 60 rows of advisories are in it; the other ${60 - left.advisories} are in structuredContent\\.data only, the last ${60 - left.advisories} in order\\. The other ${60 - left.advisories} are elsewhere\\.$`));
    // Control: without beforeRows (3.0.2's cut), rows leave while every list keeps its entries.
    const old = dataText(d, { ...cut, sides: cut.sides.map(({ beforeRows, ...side }) => side) });
    assert.deepEqual(counts(old.text), { advisories: 16, branches: 40, patches: 40, refs: 20 }, "the control does not show the 3.0.2 cut");
  });

  // #2899: rows leave the text from the end, so a KEV-listed match ranked last left it first.
  it("#2899: rows named leaveOutLast stay while any other row is in the text, and each one left out is named", () => {
    const d = { matches: rows(200, (i) => ({ cve_id: `CVE-2026-${20000 + i}`, kev_listed: i === 199 || i === 150, ransomware: i === 120, score: 9 - i / 100, reason: big(i, 160) })) };
    const cut = {
      rows: "matches",
      levels: [{ keep: ["cve_id", "kev_listed", "ransomware", "score", "reason"], clip: 200 }],
      leaveOutLast: { fields: ["kev_listed", "ransomware"], name: "cve_id", why: "exploited" },
    };
    const { text, said } = dataText(d, cut);
    const shown = JSON.parse(text).matches;
    assert.ok(text.length <= DATA_TEXT_BUDGET && shown.length < 200, `${shown.length} rows`);
    for (const i of [120, 150, 199]) assert.ok(shown.some((m) => m.cve_id === d.matches[i].cve_id), `${d.matches[i].cve_id}, flagged, left the text while other rows stayed`);
    assert.deepEqual(shown.map((m) => m.cve_id), d.matches.filter((m, i) => i < shown.length - 3 || [120, 150, 199].includes(i)).map((m) => m.cve_id), "the rows kept are the first in order and every flagged one, in order");
    assert.match(said, new RegExp(`Only ${shown.length} of the 200 rows of matches are in it; the other ${200 - shown.length} are in structuredContent\\.data only, the last ${200 - shown.length} in order but for any whose kev_listed or ransomware is true \\(exploited\\), which leave it last\\.$`));
    assert.doesNotMatch(said, /Of the rows left out/);
    // Every row flagged: they leave too, from the end, and the note names each one left out.
    const all = { matches: d.matches.map((m) => ({ ...m, kev_listed: true })) };
    const every = dataText(all, cut);
    const kept = JSON.parse(every.text).matches;
    const gone = all.matches.slice(kept.length).map((m) => m.cve_id);
    assert.ok(gone.length > 0);
    assert.deepEqual(kept.map((m) => m.cve_id), all.matches.slice(0, kept.length).map((m) => m.cve_id));
    assert.ok(every.said.includes(`, the last ${gone.length} in order. Of the rows left out of it, ${gone.length} have kev_listed or ransomware true: ${gone.slice(0, -1).join(", ")} and ${gone.at(-1)}.`), every.said);
    // Control: without leaveOutLast the flagged last row leaves first (3.0.2's cut).
    const old = JSON.parse(dataText(d, { ...cut, leaveOutLast: undefined }).text).matches;
    assert.ok(!old.some((m) => m.cve_id === d.matches[199].cve_id), "the control does not show the 3.0.2 cut");
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

// #3013's review: through the review the cve:// resource read get_cve with full: true (data_truncated
// false), cut data itself (CVE-2021-44228: cpe_match 64 of 396) and copied the envelope unchanged,
// so the same JSON said data_truncated false beside its DATA CUT note. Both polarities, on
// cveResourceText itself (src/resources.ts, which starts no server), and the control.
describe("#3013's review: the cve:// resource's envelope says what the resource cut", () => {
  const getCve = SHAPED.find((c) => c.label === "get_cve, CVE-2021-44228");
  const [record] = Object.values(shapedAnswers(getCve));
  const asRead = (data) => ({ state: "measured", measured_at: data.updated_at ?? null, method: "m", coverage: null, freshness: null, notes: ["get_cve OK."], data_truncated: false, data });

  it("cut: data_truncated true, and truncated names cpe_match and references with what the resource keeps of each", () => {
    const s = JSON.parse(cveResourceText(asRead(record), noteSentences));
    assert.equal(s.data_truncated, true);
    assert.deepEqual(s.truncated, { cpe_match: { total: 396, returned: s.data.cpe_match.length }, references: { total: 103, returned: s.data.references.length } });
    assert.ok(s.data.cpe_match.length < 396 && s.data.references.length < 103);
    assertResourceTruncated("cve://CVE-2021-44228", s, record);
    assert.match(s.notes.at(-1), /each named with its full length\.$/);
    // In the envelope's order: data_truncated, then truncated, then data.
    assert.deepEqual(Object.keys(s).slice(-3), ["data_truncated", "truncated", "data"]);
  });
  it("whole: data_truncated false, no truncated, the structured result pretty-printed as read", () => {
    const small = { ...record, cpe_match: record.cpe_match.slice(0, 3), references: record.references.slice(0, 3) };
    const text = cveResourceText(asRead(small), noteSentences);
    assert.equal(text, JSON.stringify(asRead(small), null, 2));
    assertResourceTruncated("cve:// small", JSON.parse(text), small);
  });
  it("a cut of strings alone, no list cut, says data_truncated true with an empty truncated", () => {
    const wide = { cve_id: "CVE-2099-0001", ...Object.fromEntries(Array.from({ length: 200 }, (_, i) => [`f${i}`, "w".repeat(300)])) };
    const s = JSON.parse(cveResourceText(asRead(wide), noteSentences));
    assert.equal(s.data_truncated, true);
    assert.deepEqual(s.truncated, {});
    assert.ok(s.notes.some((n) => /^Every string in it longer than \d+ characters keeps its first \d+/.test(n)), s.notes.join(" "));
  });
  it("control: the envelope as the resource copied it through the review (data_truncated false beside the cut) fails the check", () => {
    const s = JSON.parse(cveResourceText(asRead(record), noteSentences));
    const { truncated: _t, ...old } = { ...s, data_truncated: false };
    assert.throws(() => assertResourceTruncated("cve://CVE-2021-44228, as through the review", old, record), /data_truncated is false and data is not the record whole/);
    // and a truncated that leaves out a list the resource cut.
    assert.throws(() => assertResourceTruncated("cve://, references unnamed", { ...s, truncated: { cpe_match: s.truncated.cpe_match } }, record), /truncated does not name it/);
  });
});

// #3013: the structured result's cut on its own (src/textBudget.ts cutData), on data built to reach
// each step. `structured` is the shape index.ts's succeeded builds: an envelope, its notes ending in
// the DATA CUT sentences, data_truncated, truncated where data is cut, and data.
describe("#3013: how a structured result past the budget is cut", () => {
  const { cutData, STRUCTURED_BUDGET: BUDGET_OF_RESULT } = textBudget;
  const rows = (n, f) => Array.from({ length: n }, (_, i) => f(i));
  const pad = (n) => "p".repeat(n);
  const env = { state: "measured", method: "m", notes: [] };
  const structured = (d, truncated, said) => ({ ...env, notes: said ? [said] : [], data_truncated: truncated !== undefined, ...(truncated ? { truncated } : {}), data: d });
  const cut = (data, dataCut) => {
    const wholeChars = JSON.stringify(structured(data, undefined, "")).length;
    const c = cutData(data, dataCut, wholeChars, structured);
    return c && { ...c, size: JSON.stringify(c.structured).length, wholeChars };
  };

  it("the budget is the first text block's, and a structured result that fits is not cut", () => {
    assert.equal(BUDGET_OF_RESULT, DATA_TEXT_BUDGET);
    assert.equal(cut({ a: rows(10, (i) => i) }, { steps: [{ lists: ["a"] }] }), undefined);
  });

  it("the steps are cut in their order: a step's lists keep at most the same number of their first entries, and a step that cannot fit even empty is emptied before the next is cut", () => {
    const data = {
      id: "x",
      side: rows(50, (i) => ({ i, s: pad(1000) })),
      rows: rows(40, (i) => ({ i, s: pad(1000) })),
      refs: rows(40, (i) => ({ i, s: pad(400) })),
    };
    const c = cut(data, { steps: [{ lists: ["side"] }, { lists: ["rows", "refs"] }] });
    assert.ok(c.size <= BUDGET_OF_RESULT, `${c.size}`);
    assert.deepEqual(c.data.side, []);
    const k = c.truncated.rows.returned;
    assert.ok(k > 0 && k < 40);
    assert.deepEqual(c.truncated, { side: { total: 50, returned: 0 }, rows: { total: 40, returned: k }, refs: { total: 40, returned: k } });
    assert.deepEqual(c.data.rows, data.rows.slice(0, k));
    assert.deepEqual(c.data.refs, data.refs.slice(0, k));
    assert.equal(c.data.id, "x");
    // The most that fit: one more entry each and it does not.
    const more = { ...c.data, rows: data.rows.slice(0, k + 1), refs: data.refs.slice(0, k + 1) };
    assert.ok(JSON.stringify(structured(more, c.truncated, c.said)).length > BUDGET_OF_RESULT);
    assert.match(c.said, new RegExp(`^DATA CUT: with data whole, this structured result is ${c.wholeChars} characters of JSON, more than the 30000 it holds unless the call says full: true, so its data is cut: side keeps none of its 50 entries; rows and refs keep their first ${k} entries each\\. truncated gives the total and the number returned of each list cut, and thinned where its entries are cut to some of their fields\\. The same call with full: true returns data whole\\.$`));
    assert.deepEqual(cut(data, { steps: [{ lists: ["side"] }, { lists: ["rows", "refs"] }] }).data, c.data, "the same data is cut the same way");
  });

  it("the room left once a step fits goes back to the steps emptied before it, each step's lists keeping at most the same number of their first entries", () => {
    const data = {
      a: rows(50, (i) => ({ i, s: pad(60) })),
      b: rows(50, (i) => ({ i, s: pad(60) })),
      rows: rows(40, (i) => ({ i, s: pad(1000) })),
    };
    const c = cut(data, { steps: [{ lists: ["a", "b"] }, { lists: ["rows"] }] });
    assert.ok(c.size <= BUDGET_OF_RESULT, `${c.size}`);
    const k = c.truncated.rows.returned;
    const back = c.truncated.a.returned;
    assert.ok(k > 0 && k < 40 && back > 0 && back < 50, JSON.stringify(c.truncated));
    assert.deepEqual(c.truncated, { a: { total: 50, returned: back }, b: { total: 50, returned: back }, rows: { total: 40, returned: k } });
    assert.deepEqual(c.data.a, data.a.slice(0, back));
    assert.deepEqual(c.data.b, data.b.slice(0, back));
    assert.deepEqual(c.data.rows, data.rows.slice(0, k));
    // The rows come first: with a and b empty, one more row does not fit; then a and b keep the most that fit.
    const moreRows = { ...c.data, a: [], b: [], rows: data.rows.slice(0, k + 1) };
    assert.ok(JSON.stringify(structured(moreRows, c.truncated, c.said)).length > BUDGET_OF_RESULT);
    const more = { ...c.data, a: data.a.slice(0, back + 1), b: data.b.slice(0, back + 1) };
    assert.ok(JSON.stringify(structured(more, c.truncated, c.said)).length > BUDGET_OF_RESULT);
    assert.match(c.said, new RegExp(`so its data is cut: a and b keep their first ${back} entries each; rows keeps its first ${k} of 40 entries\\.`));
  });

  it("a list named with leaveOutFirst leaves those entries first, then the last of the rest, and keeps the others in order", () => {
    const verdict = (i) => (i % 4 === 0 ? "affected" : i % 4 === 1 ? "not_assessed" : "not_affected");
    const data = { results: rows(120, (i) => ({ index: i, verdict: verdict(i), s: pad(1500) })), summary: { n: 120 } };
    const c = cut(data, { steps: [{ lists: ["results"], leaveOutFirst: { field: "verdict", values: ["not_affected", "not_assessed"], why: "summary counts them" } }] });
    const kept = c.data.results;
    assert.ok(kept.length > 0 && kept.length <= 30, `${kept.length}`);
    assert.ok(kept.every((r) => r.verdict === "affected"), "a clean row stayed beside affected rows left out");
    assert.deepEqual(kept.map((r) => r.index), data.results.filter((r) => r.verdict === "affected").slice(0, kept.length).map((r) => r.index), "the affected rows kept are not the first, in order");
    const out = 120 - kept.length;
    assert.match(c.said, new RegExp(`results keeps ${kept.length} of its 120 entries, the ${out} left out being the 90 whose verdict is not_affected or not_assessed \\(summary counts them\\) and the last ${out - 90} of the rest\\.`));
    assert.deepEqual(c.data.summary, data.summary);
  });

  it("a list inside an object is cut only where a step names it, by its path; then every other list at the top of data; no other value changes", () => {
    const data = {
      remediation: { fix_status: { state: "available", unread_inputs: rows(200, (i) => `input-${i}-${pad(40)}`) }, fixed_versions: rows(100, (i) => `v${i}-${pad(80)}`) },
      radar: { trend: rows(60, (i) => ({ i, s: pad(200) })) },
      other: rows(30, (i) => ({ i, s: pad(500) })),
      text: pad(2000),
    };
    const c = cut(data, { steps: [{ lists: ["radar.trend"] }] });
    assert.ok(c.size <= BUDGET_OF_RESULT, `${c.size}`);
    assert.deepEqual(c.data.remediation, data.remediation, "a list inside an object no step names was cut");
    assert.equal(c.data.text, data.text);
    assert.deepEqual(Object.keys(c.truncated), ["radar.trend", "other"]);
    // Emptied before other was cut, radar.trend then keeps the first of its entries the room left holds.
    const trend = c.truncated["radar.trend"].returned;
    assert.ok(trend < 60, `${trend}`);
    assert.deepEqual(c.data.radar.trend, data.radar.trend.slice(0, trend));
    assert.deepEqual(c.data.other, data.other.slice(0, c.truncated.other.returned));
    assert.deepEqual(Object.keys(c.data), Object.keys(data), "data's keys are not in their order");
  });

  // #3013's review: a series the API sends oldest first keeps its newest entries; truncated still
  // gives its total and the number returned, and the note says newest. Control: without keepNewest
  // the same series keeps its first, oldest entries.
  it("a step named keepNewest keeps each list's last entries, the newest, its oldest leaving first, and the note says newest; without it, the first", () => {
    const day = (i) => ({ date: `2026-09-${String(1 + i).padStart(2, "0")}`, count: i, s: pad(1500) });
    const data = { radar: { trend: rows(30, day), weekly: rows(13, (i) => ({ week: i, s: pad(1500) })) }, other: rows(3, (i) => i) };
    const step = { lists: ["radar.trend", "radar.weekly"], keepNewest: true };
    const c = cut(data, { steps: [step] });
    assert.ok(c.size <= BUDGET_OF_RESULT, `${c.size}`);
    const k = c.truncated["radar.trend"].returned;
    assert.ok(k > 0 && k < 13, JSON.stringify(c.truncated));
    assert.deepEqual(c.truncated, { "radar.trend": { total: 30, returned: k }, "radar.weekly": { total: 13, returned: k } });
    assert.deepEqual(c.data.radar.trend, data.radar.trend.slice(-k), "the series does not keep its last entries");
    assert.deepEqual(c.data.radar.weekly, data.radar.weekly.slice(-k));
    assert.equal(c.data.radar.trend.at(-1).date, "2026-09-30", "the newest day left data");
    assert.match(c.said, new RegExp(`so its data is cut: radar\\.trend and radar\\.weekly keep their newest ${k} entries each\\.`));
    // One list alone, emptied, then given back the room a later step leaves: still the newest.
    const small = (i) => ({ date: `2026-09-${String(1 + i).padStart(2, "0")}`, count: i, s: pad(100) });
    const one = cut({ trend: rows(30, small), big: rows(40, (i) => ({ i, s: pad(1000) })) }, { steps: [{ lists: ["trend"], keepNewest: true }, { lists: ["big"] }] });
    const kept = one.truncated.trend.returned;
    assert.ok(kept > 0 && kept < 30, JSON.stringify(one.truncated));
    assert.deepEqual(one.data.trend, rows(30, small).slice(30 - kept));
    assert.match(one.said, new RegExp(`trend keeps its newest ${kept} of 30 entries`));
    // Control: the step without keepNewest keeps the first, oldest entries.
    const old = cut(data, { steps: [{ lists: step.lists }] });
    assert.deepEqual(old.data.radar.trend, data.radar.trend.slice(0, k));
    assert.notDeepEqual(old.data.radar.trend, c.data.radar.trend);
    assert.match(old.said, new RegExp(`radar\\.trend and radar\\.weekly keep their first ${k} entries each\\.`));
  });

  // #3013's review: PageAt.wholeFit, the page size a paging tool's DATA CUT names as fitting data
  // whole, is counted on the entries whole: that many first entries, whole, and no DATA CUT, fit.
  it("PageAt.wholeFit counts a page on the entries whole, not the thinned ones the cut keeps", () => {
    const data = { cves: rows(200, (i) => ({ cve_id: `CVE-${i}`, kev_listed: false, title: pad(200), description: pad(900) })), offset: 0 };
    let said;
    const c = cut(data, { steps: [{ lists: ["cves"], thin: [["cve_id", "kev_listed", "title"]] }], page: (t, _d, at) => (said = { k: t.cves.returned, whole: at.wholeFit("cves"), keeps: at.keeps }) && "" });
    assert.ok(c.truncated.cves.thinned && c.truncated.cves.returned < 200, JSON.stringify(c.truncated));
    assert.deepEqual(said.keeps, { cves: ["cve_id", "kev_listed", "title"] });
    assert.ok(said.whole > 0 && said.whole < said.k, JSON.stringify(said));
    const whole = (n) => JSON.stringify(structured({ ...data, cves: data.cves.slice(0, n) }, undefined, "")).length;
    assert.ok(whole(said.whole) <= BUDGET_OF_RESULT && whole(said.whole + 1) > BUDGET_OF_RESULT, `${whole(said.whole)}, ${whole(said.whole + 1)}`);
    assert.ok(whole(said.k) > BUDGET_OF_RESULT, "a page of the thinned rows kept fits whole, so this case does not test the count");
    assert.equal(textBudget.wholePage(said.whole), `a page of ${said.whole} rows or fewer like these fits data whole.`);
  });

  it("a step with thinning levels cuts every entry to each level's fields in turn, all kept, before any entry leaves at the leanest", () => {
    const row = (i, verdict) => ({ index: i, verdict, purl: `pkg:npm/${pad(100)}${i}@1`, detail: pad(400), matches: rows(3, (j) => ({ cve_id: `CVE-${i}-${j}`, description: pad(300), kev_listed: false })) });
    const step = { lists: ["results"], thin: [["index", "verdict", "purl", ["matches", ["cve_id", "kev_listed"]]], ["index", "verdict", "purl"]], leaveOutFirst: { field: "verdict", values: ["not_affected"], why: "counted" } };
    // Fits at the first level: every row kept, each with its matches thinned.
    const few = cut({ results: rows(40, (i) => row(i, i % 2 ? "not_affected" : "affected")) }, { steps: [step] });
    assert.deepEqual(few.truncated, { results: { total: 40, returned: 40, thinned: true } });
    assert.deepEqual(Object.keys(few.data.results[0]), ["index", "verdict", "purl", "matches"]);
    assert.deepEqual(few.data.results[0].matches[0], { cve_id: "CVE-0-0", kev_listed: false });
    assert.match(few.said, /results keeps all 40 entries, each cut to index, verdict, purl and matches \(each with cve_id and kev_listed\)\./);
    // Past the leanest level: rows leave, the named ones first, each kept row at the leanest level.
    const many = cut({ results: rows(900, (i) => row(i, i % 2 ? "not_affected" : "affected")) }, { steps: [step] });
    const kept = many.data.results;
    assert.ok(many.size <= BUDGET_OF_RESULT && kept.length > 0 && kept.length < 900);
    assert.equal(many.truncated.results.thinned, true);
    assert.deepEqual(Object.keys(kept[0]), ["index", "verdict", "purl"]);
    assert.ok(kept.every((r) => r.verdict === "affected"), "a named row stayed while others left");
    assert.match(many.said, new RegExp(`results keeps ${kept.length} of its 900 entries, each cut to index, verdict and purl, the ${900 - kept.length} left out being the 450 whose verdict is not_affected \\(counted\\) and the last ${450 - kept.length} of the rest\\.`));
  });

  it("when even every list emptied is past the budget, the lists are emptied and the note says what is left is no list", () => {
    const data = { big: pad(40_000), xs: rows(10, (i) => i) };
    const c = cut(data, { steps: [] });
    assert.deepEqual(c.data, { big: data.big, xs: [] });
    assert.ok(c.size > BUDGET_OF_RESULT);
    assert.match(c.said, /xs keeps none of its 10 entries\. truncated gives the total and the number returned of each list cut, and thinned where its entries are cut to some of their fields\. Cut so, the structured result is still past 30000 characters: data holds no other list to cut\. The same call with full: true returns data whole\.$/);
    assert.equal(cut({ big: pad(40_000) }, { steps: [] }), undefined, "data with no list is not cut");
  });
});
