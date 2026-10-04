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
// Runs against dist/index.js, so build first; `npm test` does.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { AjvJsonSchemaValidator } from "@modelcontextprotocol/server/validators/ajv";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { PKG_DIR, serverCommand } from "./server-under-test.mjs";
import { CEILING, MARGIN, SBOM_MAX_PURLS, SHAPED, SHAPED_DRIFT, argsOf, assertBoundUnderCeiling, productionText, readLiveRecord, shapedAnswers, shareOfCeiling, textSize } from "./text-bound.mjs";

// The cut itself, from the package under test (dist/textBudget.js loads nothing else and starts no server).
const { DATA_TEXT_BUDGET, TEXT_BUDGET_DESCRIPTION, dataText } = await import(pathToFileURL(path.join(PKG_DIR, "dist", "textBudget.js")).href);

// The budget the server cuts the first text block to: half the ceiling, so the note and the
// envelope after it, and a release's growth, have the other half.
const BUDGET = DATA_TEXT_BUDGET;
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const blocksOf = (res) => (res.content ?? []).filter((c) => c.type === "text").map((c) => c.text);
const LIMITED = "check_sbom, 2,000 purls, rate-limited after 6 batches (production's answer from a fresh budget)";
const noteSentences = (t) => t.replace(/\s+/g, " ").trim().split(/(?<=[.!?])\s+/).filter(Boolean);

// The API's answer when a caller's component budget is spent (core-backend internal/waf/weighted.go).
const RATE_LIMITED = { error: "component budget exceeded: this batch costs 200 components and this address has 0 left in the window. Nothing was looked up", code: "RATE_LIMIT_EXCEEDED", cost: 200, limit: 1200 };

// A stub API answering each request with the case's answer for its path (whole URL first), and,
// for a case with `limited`, every request after the first `after` with 429 and its Retry-After.
async function startStub() {
  const state = { answers: {}, limited: undefined, requests: 0 };
  const server = http.createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      const { pathname } = new URL(req.url, "http://stub");
      state.requests++;
      if (state.limited && state.requests > state.limited.after) {
        res.writeHead(429, { "content-type": "application/json", "retry-after": String(state.limited.retryAfter) });
        res.end(JSON.stringify(RATE_LIMITED));
        return;
      }
      const body = state.answers[req.url] ?? state.answers[pathname];
      res.writeHead(body ? 200 : 404, { "content-type": body ? "application/json" : "text/plain" });
      res.end(body ? JSON.stringify(body) : "404 page not found\n");
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return {
    state,
    base: `http://127.0.0.1:${server.address().port}`,
    close: () => {
      server.closeAllConnections();
      return new Promise((r) => server.close(r));
    },
  };
}

// Whether `t`, read from the first text block, is a cut of `d`, structuredContent.data: every key
// it has, `d` has; a string is equal or `d`'s first characters and "…"; a list is some of `d`'s
// entries, in `d`'s order; anything else is equal. Throws, naming where, when it is not.
function assertCutOf(t, d, at = "data") {
  if (typeof t === "string" && typeof d === "string") {
    if (t === d) return;
    assert.ok(t.endsWith("…") && d.startsWith(t.slice(0, -1)) && t.length <= d.length, `${at}: ${JSON.stringify(t.slice(0, 80))} is neither the answer's string nor its start and "…"`);
    return;
  }
  if (Array.isArray(t)) {
    assert.ok(Array.isArray(d), `${at}: a list in the text where the answer has ${typeof d}`);
    let j = 0;
    for (const [i, x] of t.entries()) {
      while (j < d.length && !isCut(x, d[j])) j++;
      assert.ok(j < d.length, `${at}[${i}]: not one of the answer's entries, in the answer's order`);
      j++;
    }
    return;
  }
  if (isObj(t)) {
    assert.ok(isObj(d), `${at}: an object in the text where the answer has ${JSON.stringify(d)?.slice(0, 40)}`);
    for (const k of Object.keys(t)) {
      assert.ok(Object.hasOwn(d, k), `${at}.${k}: in the text, not in the answer`);
      assertCutOf(t[k], d[k], `${at}.${k}`);
    }
    return;
  }
  assert.deepEqual(t, d, at);
}
function isCut(t, d) {
  try {
    assertCutOf(t, d);
    return true;
  } catch {
    return false;
  }
}

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
      measured[c.label] = await client.callTool({ name: c.tool, arguments: argsOf(c) });
    }
  });
  after(async () => {
    await client?.close();
    await stub?.close();
  });

  // The ticket's own coverage rule: no tool is bounded only by a stub fixture.
  it("every tool tools/list advertises has a production-shaped case at its default call, and every tool with a page size one at its largest page", () => {
    const names = tools.map((t) => t.name);
    assert.deepEqual([...new Set(SHAPED.map((c) => c.tool))].sort(), [...names].sort(), "SHAPED does not cover exactly the tools tools/list advertises");
    for (const t of tools) {
      assert.ok(SHAPED.some((c) => c.tool === t.name && c.page === "default"), `${t.name}: no case at its default call`);
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

  for (const c of SHAPED) {
    const bound = c.size + MARGIN;
    it(`${c.label}: at most ${bound} characters of text (${c.size} measured, plus ${MARGIN}), under the ceiling`, (t) => {
      const res = measured[c.label];
      assert.notEqual(res.isError, true, `${c.label}: the production-shaped answer did not produce an answer: ${blocksOf(res)[0]?.slice(0, 300)}`);
      assert.ok(["measured", "not_assessed"].includes(res.structuredContent.state), `${c.label}: state ${res.structuredContent.state}`);
      const { total, blocks } = textSize(res, stub.base);
      const prod = productionText(c);
      t.diagnostic(`${shareOfCeiling(c.label, total)}; blocks ${blocks.join(" + ")}${prod ? `; production's text for this call (${prod.version}, ${prod.at}): ${prod.total} (${prod.blocks.join(" + ")})` : ""}`);
      assert.ok(total <= bound, `${c.label}: ${total} characters of text, over its bound of ${bound} (${c.size} measured, plus ${MARGIN})`);
      assertBoundUnderCeiling(c.label, c.size);
      assertTextIsACut(c.label, res);
    });
  }

  it("structuredContent.data is the API's answer whole, never the cut, wherever the tool relays the answer as sent", () => {
    // exposure_radar and cve_intel relay their own cut of the answer (#2307, #2722), and check_sbom
    // merges batches; every other tool's data is the one answer it read.
    for (const c of SHAPED.filter((x) => !["exposure_radar", "cve_intel"].includes(x.tool) && x.page === "default" && x.tool !== "check_sbom")) {
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
  // the matches are cut first.
  it("check_affected keeps every match in the text, as its description says, the excluded and undetermined samples cut first", () => {
    for (const c of SHAPED.filter((x) => x.tool === "check_affected")) {
      const res = measured[c.label];
      const shown = JSON.parse(blocksOf(res)[0]);
      const data = res.structuredContent.data;
      assert.deepEqual(shown.matches.map((m) => m.cve_id), data.matches.map((m) => m.cve_id), `${c.label}: matches left out of the text`);
      for (const k of ["cve_id", "kev_listed", "effective_score", "effective_severity", "score_assessed"]) {
        assert.ok(shown.matches.every((m, i) => Object.hasOwn(m, k) || !Object.hasOwn(data.matches[i], k)), `${c.label}: a match in the text leaves out ${k}, which the description says it keeps`);
      }
      assert.doesNotMatch(blocksOf(res)[1], /Only \d+ of the \d+ rows of matches are in it/, c.label);
    }
    const c = SHAPED.find((x) => x.label.startsWith("check_affected, flash_player"));
    const res = measured[c.label];
    const shown = JSON.parse(blocksOf(res)[0]);
    assert.equal(shown.matches.length, 200);
    assert.equal(shown.excluded.length, 50, "the excluded sample keeps all 50 entries, each cut");
    assert.deepEqual(shown.excluded.map((e) => Object.keys(e)), res.structuredContent.data.excluded.map(() => ["cve_id", "reason"]));
    assert.match(blocksOf(res)[1], /Each entry of excluded in it leaves out criteria, detail and decisive\./);
  });

  // The registry path's largest answer: 200 matches (the cap), cve_ids naming each, and the
  // undetermined sample at its 50 (core-backend cve/pkgmatch.go maxUndeterminedReported), the
  // django rows repeated and the undetermined entries in the backend's UndeterminedMatch shape.
  it("check_affected keeps every match at the registry path's largest answer: 200 matches, cve_ids and 50 undetermined", async () => {
    const c = SHAPED.find((x) => x.label.startsWith("check_affected, PyPI django"));
    const [[path, body]] = Object.entries(shapedAnswers(c));
    const matches = Array.from({ length: 200 }, (_, i) => ({ ...body.matches[i % body.matches.length], cve_id: `CVE-2026-${String(20000 + i)}` }));
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
    assert.deepEqual(shown.matches.map((m) => m.cve_id), matches.map((m) => m.cve_id), "a match left the text");
    assert.deepEqual(shown.undetermined, undetermined.map(({ cve_id, reason }) => ({ cve_id, reason })), "the undetermined sample lost an entry or its reason");
    assert.match(note, /In it, cve_ids keeps its first 10 of 200 entries\. cve_ids lists each match's cve_id, in the order of matches\./);
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
    assert.match(note, /In it, not_sent_purls keeps its first 10 of 800 entries\. The 800 purls not sent are the input's distinct purls from position 1201 on, in the order this tool read them/);
    assert.match(note, /Only \d+ of the 1200 rows of results are in it; the other \d+ are in structuredContent\.data only: the \d+ whose verdict is not_affected or not_assessed/);
    assert.match(note, /To read every row in the text, check \d+ or fewer purls per call\./);
  });

  // #2783 review: match_reason carries a registry match's advisory interval, which names the fixed
  // version, and get_cve, the tool the note points to, does not carry it.
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

  it("every structured result still validates against the tool's advertised outputSchema", () => {
    const ajv = new AjvJsonSchemaValidator();
    for (const c of SHAPED) {
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
      t.diagnostic(`${shareOfCeiling(`${label}, production ${r.measured_at}`, r.total)}; ${r.source}`);
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

  it("a string is never cut inside a surrogate pair", () => {
    const d = { rows: rows(200, (i) => ({ id: i, s: "😀".repeat(300) })) };
    const { text } = dataText(d, { rows: "rows", levels: [{ keep: ["id", "s"], clip: 101 }] });
    for (const r of JSON.parse(text).rows) assert.ok(!/[\uD800-\uDBFF]…$/.test(r.s) && r.s.endsWith("…"), JSON.stringify(r.s.slice(-4)));
  });
});
