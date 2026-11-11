// #3628: every field of the vendor-advisory coverage row is read by this server, or named as not
// relayed with why. Twice in eight days core-backend's GET /api/v1/public/vendor-advisories/coverage
// added fields that narrow what a vendor's window vouches for, and nothing here noticed: history_scope
// and feed_held_since (c7bd59baf, 2026-11-01) were read only from 2026-11-07 (#3472), and
// last_success_at, collection_state, failing_since, held_back and held_back_since (2026-11-08) said
// Cisco's collection had failed since 2026-10-12 while vendors_not_fully_held and the notes still
// read its window as current (#3464). There was no error and no failing test.
//
// What is held, against docs/api/openapi.yaml's vendor item for that route (its properties and its
// required list; core-backend's coverage_openapi_test.go holds the spec to CoverageHandler's wireRow
// and the collection_state enum to feed_state.go, so the chain is wireRow, spec, here):
//   1. each field is either read by windowsOf (src/tools/vendor_advisories.ts), which relays it in a
//      vendor window under its own name, or named in VENDOR_COVERAGE_NOT_RELAYED with a reason, and
//      not both. "Read" is measured, not listed: a row with every field set is passed to windowsOf, and
//      a field is read when the window it returns carries it, not null;
//   2. windowsOf relays no field the row does not carry, and VENDOR_COVERAGE_NOT_RELAYED names none;
//   3. collection_state's values are COLLECTION_STATES, and collectionSentence words each of them (ok
//      with nothing; a value the spec adds is relayed and read as not ok, but its words are a decision
//      here, not the sentence for a state this server does not know).
// The public repository carries mcp-server alone, and the release's test run of the packed tarball
// (scripts/npm-publish-mcp.sh copies test/ beside the unpacked package; the tarball itself ships no
// test/) has no docs/ beside it either, so both read the copy of the vendor item in
// fixtures/vendor-coverage-item.json; in EchelonGraph's repository the copy is held to the spec
// (cve_intel.test.mjs's way). Controls below: a field added to a copy of the spec fails, and
// removed again passes; a reason dropped, a read field also listed, a stale entry and a new state fail.
//
// Runs against dist/ (npm test builds first).
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { PKG_DIR } from "./server-under-test.mjs";

const VA = await import(pathToFileURL(path.join(PKG_DIR, "dist", "tools", "vendor_advisories.js")).href);

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SPEC = path.resolve(HERE, "..", "..", "docs", "api", "openapi.yaml");
const IN_MONOREPO = path.basename(path.resolve(HERE, "..")) === "mcp-server" || fs.existsSync(SPEC);
const OUTSIDE = "no docs/api/openapi.yaml beside this package (the release's run against the packed tarball, or the public repository): the copy of its vendor item runs instead";
const COPY_FILE = path.join(HERE, "fixtures", "vendor-coverage-item.json");
const ROUTE = "  /api/v1/public/vendor-advisories/coverage:";

/**
 * The spec's vendor item for the coverage route, read as text (it is hand-written in one layout, as
 * coverage_openapi_test.go reads it): { properties: {name: {type, enum?}}, required: [...] }, or null
 * when the route is not there. The item's properties sit 24 spaces in, their type and enum 26.
 */
export function coverageItemOf(spec) {
  const lines = spec.split("\n");
  const at = lines.indexOf(ROUTE);
  if (at < 0) return null;
  const block = [];
  for (const l of lines.slice(at + 1)) {
    if (l.trim() !== "" && !l.startsWith("   ")) break;
    block.push(l);
  }
  const properties = {};
  block.forEach((l, i) => {
    const m = l.match(/^ {24}([a-z_]+):(.*)$/);
    if (!m) return;
    let type = m[2].match(/\{\s*type:\s*(\w+)/)?.[1];
    let values;
    for (let j = i + 1; j < block.length && /^ {26}/.test(block[j]); j++) {
      type ??= block[j].match(/^ {26}type: (\w+)/)?.[1];
      const e = block[j].match(/^ {26}enum: \[([^\]]*)\]/);
      if (e) values = e[1].split(",").map((v) => v.trim().replace(/^"(.*)"$/, "$1"));
    }
    properties[m[1]] = values ? { type, enum: values } : { type };
  });
  const req = block.join("\n").match(/required: \[(vendor,[\s\S]*?)\]/);
  return { properties, required: req ? req[1].split(",").map((f) => f.trim()) : [] };
}

// A value of a property's type, so windowsOf can read it: an integer, an enum's first value that is
// not "", or an RFC 3339 instant (the row's strings are dates, slugs and names: an instant is all three).
const probeValue = (p) => (p.type === "integer" || p.type === "number" ? 7 : p.enum ? p.enum.find((v) => v !== "") : "2026-01-02T03:04:05Z");

/** The problems of this server's reading of the coverage row, against a vendor item ({properties, required}). */
export function fieldProblems(item, va) {
  const out = [];
  const fields = [...new Set([...Object.keys(item.properties), ...item.required])].sort();
  if (!fields.includes("vendor")) return ["the vendor item names no vendor field: re-aim coverageItemOf"];
  const row = Object.fromEntries(fields.map((f) => [f, probeValue(item.properties[f] ?? { type: "string" })]));
  const windows = va.windowsOf({ vendors: [row] });
  if (!Array.isArray(windows) || windows.length !== 1) return [`windowsOf read ${JSON.stringify(windows)} from a row with every field set: re-aim this check`];
  const relayed = windows[0];
  const ignored = va.VENDOR_COVERAGE_NOT_RELAYED;
  for (const f of fields) {
    const read = Object.hasOwn(relayed, f) && relayed[f] !== null;
    const named = Object.hasOwn(ignored, f);
    if (!read && !named)
      out.push(`${f}: the coverage row carries it, and windowsOf neither relays it nor does VENDOR_COVERAGE_NOT_RELAYED name it: read it (and say in the notes what it means for what is held), or name it there with why`);
    if (read && named) out.push(`${f}: windowsOf relays it, and VENDOR_COVERAGE_NOT_RELAYED names it as not relayed`);
    if (named && !(typeof ignored[f] === "string" && ignored[f].trim().length >= 20)) out.push(`${f}: VENDOR_COVERAGE_NOT_RELAYED gives no reason`);
  }
  for (const k of Object.keys(relayed)) if (!fields.includes(k)) out.push(`${k}: windowsOf relays it, and the coverage row carries no such field`);
  for (const k of Object.keys(ignored)) if (!fields.includes(k)) out.push(`${k}: VENDOR_COVERAGE_NOT_RELAYED names it, and the coverage row carries no such field: drop the entry`);
  const states = item.properties.collection_state?.enum;
  if (fields.includes("collection_state")) {
    if (!states) out.push("collection_state: the spec gives no enum: re-aim coverageItemOf");
    else {
      for (const s of states) if (!va.COLLECTION_STATES.includes(s)) out.push(`collection_state ${s}: the spec lists it, and COLLECTION_STATES does not: word what it means in collectionSentence, then add it`);
      for (const s of va.COLLECTION_STATES) if (!states.includes(s)) out.push(`collection_state ${s}: COLLECTION_STATES lists it, and the spec does not`);
      // Each state the spec lists is worded: ok says nothing, any other its own sentence, never the
      // one for a state this server does not know.
      for (const s of states) {
        const said = va.collectionSentence({ ...relayed, collection_state: s });
        if (s === "ok" ? said !== "" : said === "" || /this server does not know/.test(said)) out.push(`collection_state ${s}: collectionSentence ${s === "ok" ? "says something of ok" : "has no sentence of its own for it"}: ${JSON.stringify(said)}`);
      }
    }
  }
  return out;
}

const specText = () => {
  // In the monorepo the spec must be there: a move fails here, it is never skipped.
  assert.ok(fs.existsSync(SPEC), `${SPEC} is gone: find where the coverage route's contract lives now and re-aim this test`);
  return fs.readFileSync(SPEC, "utf8");
};
const COPY = JSON.parse(fs.readFileSync(COPY_FILE, "utf8"));

describe("#3628: the vendor-advisory coverage row's fields, read or named", () => {
  it("in EchelonGraph's repository, every field of docs/api/openapi.yaml's coverage vendor item is relayed by windowsOf or named in VENDOR_COVERAGE_NOT_RELAYED, and collection_state's values are COLLECTION_STATES", { skip: IN_MONOREPO ? false : OUTSIDE }, () => {
    const item = coverageItemOf(specText());
    assert.ok(item, `${SPEC}: no ${ROUTE.trim()} path`);
    // The parse found the item: the 16 fields of 2026-11-08 at least, and the required list is the properties.
    assert.ok(Object.keys(item.properties).length >= 16, `only ${Object.keys(item.properties).join(", ")}: re-aim coverageItemOf`);
    assert.deepEqual([...item.required].sort(), Object.keys(item.properties).sort(), "the spec's required list is not its properties (core-backend's coverage_openapi_test.go holds both to wireRow)");
    assert.deepEqual(fieldProblems(item, VA), []);
  });

  it("in EchelonGraph's repository, the copy of the vendor item for the public repository and the tarball's test run is the spec's", { skip: IN_MONOREPO ? false : OUTSIDE }, () => {
    assert.deepEqual(
      { properties: COPY.properties, required: COPY.required },
      coverageItemOf(specText()),
      `fixtures/vendor-coverage-item.json is not docs/api/openapi.yaml's coverage vendor item: copy it again (properties and required as coverageItemOf reads them)`,
    );
  });

  it("the copy of the vendor item: every field is relayed or named, and collection_state's values are COLLECTION_STATES", () => {
    assert.deepEqual(fieldProblems(COPY, VA), []);
  });

  it("each field relayed carries the row's value, and the fields not relayed are not in the window", () => {
    const fields = Object.keys(COPY.properties);
    const row = Object.fromEntries(fields.map((f) => [f, probeValue(COPY.properties[f])]));
    const [w] = VA.windowsOf({ vendors: [row] });
    for (const [k, v] of Object.entries(w)) assert.equal(v, row[k], k);
    for (const k of Object.keys(VA.VENDOR_COVERAGE_NOT_RELAYED)) assert.ok(!Object.hasOwn(w, k), k);
    // Each reason says what the field is and why it bounds no window.
    for (const [k, why] of Object.entries(VA.VENDOR_COVERAGE_NOT_RELAYED)) assert.match(why, /bounds no window/, k);
  });
});

describe("#3628 controls: the field check", () => {
  it("a field added to a copy of the spec fails, naming it; removed again, it passes", { skip: IN_MONOREPO ? false : OUTSIDE }, () => {
    const spec = specText();
    const anchor = "                        held_back_since:\n";
    assert.equal(spec.split(anchor).length, 2, "the control's anchor has drifted: re-aim it");
    const added = spec.replace(anchor, `                        paused_until:\n                          type: string\n                          description: "a field the API adds"\n${anchor}`);
    const item = coverageItemOf(added);
    assert.ok(Object.hasOwn(item.properties, "paused_until"), "the control's field was not read from the spec: re-aim coverageItemOf");
    const problems = fieldProblems(item, VA);
    assert.equal(problems.length, 1, problems.join("\n"));
    assert.match(problems[0], /^paused_until: the coverage row carries it, and windowsOf neither relays it nor does VENDOR_COVERAGE_NOT_RELAYED name it/);
    // On the required list alone it fails too.
    const reqOnly = spec.replace("held_back, held_back_since]", "held_back, held_back_since, paused_until]");
    assert.notEqual(reqOnly, spec, "the control's required-list anchor has drifted: re-aim it");
    assert.match(fieldProblems(coverageItemOf(reqOnly), VA).join("\n"), /^paused_until: the coverage row carries it/m);
    // Removed: as the spec is.
    assert.deepEqual(fieldProblems(coverageItemOf(added.replace(`                        paused_until:\n                          type: string\n                          description: "a field the API adds"\n`, "")), VA), []);
  });

  it("the same on the copy: a field added fails, removed passes; a field dropped from the row is a stale relay", () => {
    const withField = { properties: { ...COPY.properties, paused_until: { type: "string" } }, required: [...COPY.required, "paused_until"] };
    assert.match(fieldProblems(withField, VA).join("\n"), /^paused_until: the coverage row carries it, and windowsOf neither relays it/m);
    assert.deepEqual(fieldProblems({ properties: { ...COPY.properties }, required: [...COPY.required] }, VA), []);
    const { failing_since: _f, ...rest } = COPY.properties;
    const dropped = { properties: rest, required: COPY.required.filter((f) => f !== "failing_since") };
    assert.match(fieldProblems(dropped, VA).join("\n"), /^failing_since: windowsOf relays it, and the coverage row carries no such field$/m);
    const { history_units_done: _h, ...restIgnored } = COPY.properties;
    assert.match(
      fieldProblems({ properties: restIgnored, required: COPY.required.filter((f) => f !== "history_units_done") }, VA).join("\n"),
      /^history_units_done: VENDOR_COVERAGE_NOT_RELAYED names it, and the coverage row carries no such field: drop the entry$/m,
    );
  });

  it("a field named without a reason, a field relayed and named, an unread field windowsOf stops relaying, and a collection_state the spec adds each fail", () => {
    const va = (o) => ({ ...VA, ...o });
    const { history_units_done: _h, ...noUnits } = VA.VENDOR_COVERAGE_NOT_RELAYED;
    assert.match(fieldProblems(COPY, va({ VENDOR_COVERAGE_NOT_RELAYED: noUnits })).join("\n"), /^history_units_done: the coverage row carries it, and windowsOf neither relays it/m);
    assert.match(fieldProblems(COPY, va({ VENDOR_COVERAGE_NOT_RELAYED: { ...VA.VENDOR_COVERAGE_NOT_RELAYED, history_units_done: "" } })).join("\n"), /^history_units_done: VENDOR_COVERAGE_NOT_RELAYED gives no reason$/m);
    assert.match(fieldProblems(COPY, va({ VENDOR_COVERAGE_NOT_RELAYED: { ...VA.VENDOR_COVERAGE_NOT_RELAYED, held_back: "the documents held back bound no window, said for the control" } })).join("\n"), /^held_back: windowsOf relays it, and VENDOR_COVERAGE_NOT_RELAYED names it as not relayed$/m);
    // windowsOf losing a field (as before #3464): the field is unread.
    const before3464 = (d) => VA.windowsOf(d)?.map(({ collection_state: _c, ...w }) => w);
    assert.match(fieldProblems(COPY, va({ windowsOf: before3464 })).join("\n"), /^collection_state: the coverage row carries it, and windowsOf neither relays it/m);
    // A field relayed always null is not read.
    const alwaysNull = (d) => VA.windowsOf(d)?.map((w) => ({ ...w, held_back_since: null }));
    assert.match(fieldProblems(COPY, va({ windowsOf: alwaysNull })).join("\n"), /^held_back_since: the coverage row carries it, and windowsOf neither relays it/m);
    const paused = { ...COPY, properties: { ...COPY.properties, collection_state: { ...COPY.properties.collection_state, enum: [...COPY.properties.collection_state.enum, "paused"] } } };
    assert.match(fieldProblems(paused, VA).join("\n"), /^collection_state paused: the spec lists it, and COLLECTION_STATES does not/m);
    assert.match(fieldProblems(paused, VA).join("\n"), /^collection_state paused: collectionSentence has no sentence of its own for it/m);
    // A state's sentence dropped (failing read as a state this server does not know), or ok given one.
    const unworded = (w) => VA.collectionSentence(w.collection_state === "failing" ? { ...w, collection_state: "failing_" } : w);
    assert.match(fieldProblems(COPY, va({ collectionSentence: unworded })).join("\n"), /^collection_state failing: collectionSentence has no sentence of its own for it/m);
    const okSaid = (w) => (w.collection_state === "ok" ? " ok." : VA.collectionSentence(w));
    assert.match(fieldProblems(COPY, va({ collectionSentence: okSaid })).join("\n"), /^collection_state ok: collectionSentence says something of ok/m);
  });
});
