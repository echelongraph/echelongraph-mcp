// #3434: scan_manifest's readers finish every line of a go.mod, requirements.txt, Cargo.lock or poetry.lock, in time
// linear in the line, reading it or reporting it (unsupported_line), whatever the line holds; and what a call's files
// make it build is bounded, whatever they hold.
//   - go.mod: whitespace is every character \s matches, where the tokenizer skips it and where a bare token ends, so
//     each pass of the tokenizer takes at least one character. A line of more tokens than any directive has
//     (TOKENS_MAX), or of more characters before its comment than any module path, version or directory (LINE_MAX),
//     is reported, not read on. A quoted string is taken from slices of the line.
//   - requirements.txt: a logical line past LINE_MAX characters, or a specifier of more than CLAUSES_MAX clauses, is
//     reported before any of it is split or matched; joining continuation lines stops past LINE_MAX; a comment and a
//     "name @" are found without backtracking.
//   - Cargo.lock and poetry.lock: a string is taken from slices of the text between its escapes, joined in chunks; an
//     escape of no Unicode scalar value, or arrays and inline tables nested past NEST_MAX, make the file unreadable.
//   - not_checked: every string of the file an entry carries (its spec, its name, one its detail names) is a short copy
//     of its own, and a call lists at most NOT_CHECKED_MAX entries, counting the rest; a filename past
//     MAX_FILENAME_CHARS is refused. So the answer is bounded however many entries the files hold.
//   - per call: past MAX_MANIFEST_LINES lines of the line formats, MAX_JSON_VALUES objects, arrays and entries of the
//     JSON lockfiles (counted before they are parsed), or MAX_TOML_VALUES tables, array entries and keys of the TOML
//     ones, the call is refused (invalid_input naming the bound), nothing more read.
//   - #3460 (3.2.0): every name and version a reader takes from a file is bounded (NAME_MAX, 512 characters, the
//     longest purl match_batch.ts sends) before anything splits, matches, encodes or replaces in it; past it the entry
//     is listed not checked (unsupported_line), and the call's other entries are read. Through 3.1.5 a package-lock name
//     of 4.9 million '/' was split into as many strings, and the hosted container ended (heap out of memory).
//   - #3381 (3.2.0), beside them: a Cargo.lock, poetry.lock or JSON lockfile whose read is estimated past the parse
//     bound (parseBudget.ts PARSE_BUDGET_BYTES, 28 MiB in the image) is unreadable before it is read ("too dense to
//     read"), and on the hosted endpoint a call whose body and read are estimated past what one request may hold is
//     refused before it is read. Where a case here is past both, the parse bound refuses it first; each case below
//     says which bound it reaches, and the cases past KEY_PARTS_MAX read with the parse bound lifted as well.
// Each case reads its file in a process of its own, started with the hosted image's node flags (Dockerfile.http's CMD,
// test/image-server.mjs), under a timeout: a reader that does not finish fails its case as a timeout, and one that
// exhausts the heap as an abort, never by holding the suite. Where Dockerfile.http is not in the package (the
// published-tarball run) the cases run with Node's own heap, the timeout still bounding them, and the cases that send
// such files to dist/http.js as the image starts it are skipped.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { PKG_DIR } from "./server-under-test.mjs";
import { IMAGE_SKIP, assertAlive, imageNodeFlags, post, resultOf, startServer, stubApi, toolCall } from "./image-server.mjs";
import * as z from "zod";

const FLAGS = IMAGE_SKIP ? [] : imageNodeFlags();
const dist = (f) => pathToFileURL(path.join(PKG_DIR, "dist", f)).href;
const SCAN_MANIFEST_JS = dist("tools/scan_manifest.js");
const M = await import(dist("tools/manifests/index.js"));
const SM = await import(SCAN_MANIFEST_JS);
const { readToml } = await import(dist("tools/manifests/toml.js"));
const C = await import(dist("tools/manifests/common.js"));
const B = await import(dist("parseBudget.js"));
// index.js's envelopeSchema, for scan_manifest's outputSchema (marked the HTTP entry point, so no stdio server starts).
(await import(dist("runtime.js"))).markHttpEntrypoint();
const I = await import(dist("index.js"));
const fixture = (name) => fs.readFileSync(path.join(PKG_DIR, "test", "fixtures", "manifests", name), "utf8");
// The readers' bounds (gomod.ts, requirements.ts).
const GOMOD_TOKENS_MAX = 16;
const GOMOD_LINE_MAX = 65_536;
const REQ_LINE_MAX = 65_536;
const REQ_CLAUSES_MAX = 64;
// The answer's and the call's bounds (manifests/common.ts, scan_manifest.ts), as the issue sets them.
const SPEC_MAX = 200;
const NOT_CHECKED_MAX = 2_000;
const MAX_FILENAME_CHARS = 1_024;
const MAX_MANIFEST_LINES = 40_000;
const MAX_JSON_VALUES = 300_000;
const MAX_TOML_VALUES = 300_000;
const NEST_MAX = 64;
const KEY_PARTS_MAX = 64;
// A case's process is stopped past this: its reader did not finish.
const CASE_TIMEOUT_MS = 30_000;
// What reading one of these files may take, measured inside its process (a linear read of 5,000,000 characters takes
// well under a second; a reader that is not linear in the line takes far longer, or does not finish).
const READ_MS_MAX = 10_000;
// scan_manifest.ts MAX_MANIFEST_CHARS.
const MAX_CHARS = 5_000_000;

it("the bounds these cases are sized to are the build's", () => {
  assert.deepEqual(
    [M.SPEC_MAX, M.NOT_CHECKED_MAX, SM.MAX_FILENAME_CHARS, M.MAX_MANIFEST_LINES, M.MAX_JSON_VALUES, M.MAX_TOML_VALUES, SM.MAX_MANIFEST_CHARS],
    [SPEC_MAX, NOT_CHECKED_MAX, MAX_FILENAME_CHARS, MAX_MANIFEST_LINES, MAX_JSON_VALUES, MAX_TOML_VALUES, MAX_CHARS],
  );
});

// #3434: the tool's description, its README row and the outputSchema say that data.not_checked lists a call's first
// NOT_CHECKED_MAX and counts all, and which calls are refused, in the build's numbers (the description's are literals,
// as marketing-site's check reads it).
it("the description and the README row say what data.not_checked lists and what a call refuses, in the build's numbers", () => {
  const n = (x) => x.toLocaleString("en-US");
  const d = SM.SCAN_MANIFEST_DESCRIPTION;
  assert.equal(MAX_JSON_VALUES, MAX_TOML_VALUES, "one number names both");
  assert.ok(d.includes(`data.not_checked lists the first ${n(NOT_CHECKED_MAX)} entries not sent (file, line, reason), counting all; not_checked entries are not clean.`), d);
  assert.ok(d.includes(`Refused: over ${n(MAX_MANIFEST_LINES)} lines or ${n(MAX_JSON_VALUES)} JSON/TOML values a call, a filename over ${n(MAX_FILENAME_CHARS)} characters.`), d);
  const readme = fs.readFileSync(path.join(PKG_DIR, "README.md"), "utf8");
  const row = readme.split("\n").find((l) => l.startsWith("| `scan_manifest` |"));
  assert.ok(row.includes(`\`data.not_checked\` lists a call's first ${n(NOT_CHECKED_MAX)} entries not sent`), row);
  assert.ok(row.includes(`A call of over ${n(MAX_MANIFEST_LINES)} lines or ${n(MAX_JSON_VALUES)} JSON or TOML values, or a filename over ${n(MAX_FILENAME_CHARS)} characters, is refused`), row);
  // The outputSchema's data.not_checked, each file's not_checked and coverage.not_checked say the same.
  const out = z.toJSONSchema(SM.scanManifestOutput(I.envelopeSchema), { unrepresentable: "any" }).oneOf[0].properties;
  const fields = [out.data.properties.not_checked, out.data.properties.manifest.properties.files.items.properties.not_checked, out.coverage.anyOf[0].properties.not_checked];
  for (const f of fields) assert.match(f.description, new RegExp(`first ${n(NOT_CHECKED_MAX)}.*(counts them all|every one counted)|every one counted.*first ${n(NOT_CHECKED_MAX)}`), f.description);
  for (const t of [d, row, ...fields.map((f) => f.description)]) assert.doesNotMatch(t, /lists each entry not sent|Every entry not sent is in/);
});

// The child: builds each file from its segments ([text, times] pairs, so no file of millions of characters goes
// through argv or the environment), reads them with readFiles, and prints what it read, each entry's strings cut to
// what a case compares and their lengths beside them.
const CHILD = `
import v8 from "node:v8";
const { readFiles } = await import(process.env.SCAN_MANIFEST_JS);
// #3381: MANIFEST_PARSE_BYTES, where set, is the parse bound the read takes ("Infinity" lifts it).
const budgets = process.env.MANIFEST_PARSE_BYTES ? { ...(await import(process.env.PARSE_BUDGET_JS)).BUDGETS, parseBytes: Number(process.env.MANIFEST_PARSE_BYTES) } : undefined;
const files = JSON.parse(process.env.MANIFEST_CASE).map(({ filename, segments }) => ({ filename, content: segments.map(([s, n]) => s.repeat(n)).join("") }));
const t0 = performance.now();
const r = readFiles({ files }, budgets);
const ms = Math.round(performance.now() - t0);
const used_mb = Math.round(v8.getHeapStatistics().used_heap_size / 1e5) / 10;
const entry = ({ spec, name, detail, ...n }) => ({ ...n, name: name?.slice(0, 60) ?? null, name_chars: name?.length ?? 0, spec: spec.slice(0, 60), spec_chars: spec.length, detail: detail.slice(0, 300), detail_chars: detail.length });
const out = typeof r === "string" ? { refused: r } : {
  files: r.files.map(({ replaced, ...f }) => ({ ...f, replaced: replaced.length, to_chars: Math.max(0, ...replaced.map((x) => x.to.length)) })),
  purls: r.purls,
  not_checked: r.not_checked.map(entry),
  not_checked_total: r.not_checked_total,
  not_checked_by_reason: r.not_checked_by_reason,
  replaced_total: r.replaced_total,
};
console.log(JSON.stringify({ chars: files.reduce((n, f) => n + f.content.length, 0), ms, used_mb, ...out }));
`;

/** readFiles on the files built from their segments, in a process of their own with the image's flags (or `flags`),
 *  under a timeout. `refused`: the call may be refused (else a refusal fails the case). `parseBytes`: the parse bound
 *  the read takes, in place of the process's own (Infinity lifts it). */
function readAllInChild(files, { flags = FLAGS, refused = false, parseBytes } = {}) {
  const chars = files.reduce((n, f) => n + f.segments.reduce((k, [s, times]) => k + s.length * times, 0), 0);
  const what = files.map((f) => f.filename).join(", ");
  assert.ok(chars <= MAX_CHARS, `${what}: the case's files are ${chars} characters, past what scan_manifest reads`);
  const r = spawnSync(process.execPath, [...flags, "--input-type=module", "-e", CHILD], {
    env: { ...process.env, SCAN_MANIFEST_JS, PARSE_BUDGET_JS: dist("parseBudget.js"), MANIFEST_CASE: JSON.stringify(files), ...(parseBytes === undefined ? {} : { MANIFEST_PARSE_BYTES: String(parseBytes) }) },
    encoding: "utf8",
    timeout: CASE_TIMEOUT_MS,
    maxBuffer: 64 * 1024 * 1024,
  });
  const fatal = () => /FATAL ERROR:[^\n]*/.exec(r.stderr ?? "")?.[0] ?? (r.stderr ?? "").split("\n").filter(Boolean).slice(-2).join(" | ");
  if (r.error?.code === "ETIMEDOUT") assert.fail(`${what}: TIMED OUT, no answer within ${CASE_TIMEOUT_MS} ms (the reader did not finish the file)`);
  assert.equal(r.error, undefined, `${what}: ${r.error?.message}`);
  assert.equal(r.signal, null, `${what}: the process was ${r.signal === "SIGABRT" ? "ABORTED (SIGABRT)" : `killed by ${r.signal}`}: ${fatal()}`);
  assert.equal(r.status, 0, `${what}: the process exited ${r.status}: ${fatal()}`);
  const out = JSON.parse(r.stdout.trim().split("\n").at(-1));
  assert.ok(out.ms <= READ_MS_MAX, `${what}: read in ${out.ms} ms, past ${READ_MS_MAX}`);
  if (!refused) assert.equal(out.refused, undefined, `${what}: refused: ${out.refused}`);
  return out;
}
const readInChild = (filename, segments, opts) => readAllInChild([{ filename, segments }], opts);

const reported = (out) => out.not_checked.filter((n) => n.reason === "unsupported_line").map((n) => [n.line, n.detail]);
const GOMOD_OVER = /^more than 16 tokens or 65536 characters before its comment, which no go\.mod directive has: not read$/;
const REQ_LONG = /^a line of more than 65536 characters, which no requirement is: not read$/;
const REQ_CLAUSES = /^a version specifier of more than 64 clauses, which no requirement has: not read$/;
// #3381's round-7 verification (R7V-2.2, 2.3): an entry whose purl, percent-encoded, is past what the API takes.
const LONG_PURL = /^its purl, percent-encoded, is longer than the 512 characters the API takes: not read$/;
const ERRORS = "pkg:golang/github.com/pkg/errors@v0.9.1";
// A string of `n` characters as an entry shows it, past SPEC_MAX: its first SPEC_MAX - 1, then "…".
const clipped = (s) => (s.length > SPEC_MAX ? `${s.slice(0, SPEC_MAX - 1)}…` : s);
// The refusals past each per-call bound, naming it (scan_manifest.ts pastBound).
// #3434: counted per call, each file's count listed, the last the file that passed the bound.
const PAST_LINES = new RegExp(`^the go\\.mod, requirements\\.txt, Gemfile\\.lock and gradle\\.lockfile files hold more than ${MAX_MANIFEST_LINES} lines in all, counted per call \\(blank and comment lines are not counted\\): .+ when the bound was passed; at most ${MAX_MANIFEST_LINES} are read per call, so no file is read`);
const PAST_JSON = new RegExp(`^the package-lock\\.json and composer\\.lock files hold more than ${MAX_JSON_VALUES} objects, arrays and entries in all, counted per call \\(counted before each file is parsed\\): .+ when the bound was passed; at most ${MAX_JSON_VALUES} are read per call`);
const PAST_TOML = new RegExp(`^the Cargo\\.lock and poetry\\.lock files hold more than ${MAX_TOML_VALUES} tables, array entries and keys in all, counted per call: .+ when the bound was passed; at most ${MAX_TOML_VALUES} are read per call`);
// #3381: a TOML lockfile past the parse bound, and on the hosted endpoint what the refusal adds (scan_manifest.ts
// HOSTED_READS): the bound in files, and what to do instead.
const TOML_DENSE = /it is too dense to read: its tables, keys and values are estimated at \d+ bytes read, past the 29360128 bytes a file's read may take/;
const JSON_DENSE = /it is too dense to read: its \d+ objects and arrays, \d+ entries and \d+ keys, parsed, are estimated at \d+ bytes, past the 29360128 bytes a file's parse may take/;
const HOSTED_HINT = /; on this endpoint one file's read may take 29360128 bytes \(28 MiB\) of its memory: run this server locally \(npx -y echelongraph-mcp\), whose bounds are a share of its own machine's memory, not this endpoint's, or pass the lockfile's purls to check_sbom, in calls of 2,000 or fewer$/;
const FILENAME_RULE = /^files\[0\]\.filename must hold no control character \(U\+0000 to U\+001F\), quote or lone surrogate, which a portable path does not hold$/;
const PAST_FILENAME = new RegExp(`^files\\[0\\]\\.filename is ${MAX_FILENAME_CHARS + 1} characters; at most ${MAX_FILENAME_CHARS} are taken`);

// Every character JavaScript's \s matches but space, tab, CR and LF (which go.mod read as whitespace already, LF
// ending the line).
const WHITESPACE = [0x0b, 0x0c, 0xa0, 0x1680, ...Array.from({ length: 11 }, (_, k) => 0x2000 + k), 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff];
const hex = (cp) => `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;

describe("#3434 go.mod: every \\s character is whitespace, and each pass of the tokenizer takes one", () => {
  it("the whitespace set is \\s, less what go.mod read as whitespace before", () => {
    const all = Array.from({ length: 0x10000 }, (_, cp) => cp).filter((cp) => /\s/.test(String.fromCharCode(cp)));
    assert.deepEqual(all.filter((cp) => ![0x09, 0x0a, 0x0d, 0x20].includes(cp)), WHITESPACE);
  });
  for (const cp of WHITESPACE) {
    it(`${hex(cp)} between a require's module path and its version: the require is read, line 6`, () => {
      const ws = String.fromCharCode(cp);
      const out = readInChild("go.mod", [[`module example.com/app\n\ngo 1.21\n\nrequire (\n\tgithub.com/pkg/errors${ws}v0.9.1\n)\n`, 1]]);
      assert.deepEqual(out.purls, [ERRORS]);
      assert.deepEqual(out.not_checked, []);
    });
  }
  it("U+00A0 as a block line's indentation, after the verb and before // indirect: every require is read", () => {
    const nb = "\u00a0";
    const out = readInChild("go.mod", [[`module example.com/app${nb}\n\ngo${nb}1.21\n\nrequire${nb}(\n${nb}${nb}github.com/pkg/errors v0.9.1${nb}// indirect\n${nb})\nrequire${nb}golang.org/x/net${nb}v0.7.0${nb}\n`, 1]]);
    assert.deepEqual(out.purls, [ERRORS, "pkg:golang/golang.org/x/net@v0.7.0"]);
    assert.deepEqual(out.not_checked, []);
  });
});

describe("#3434 go.mod: one line past what any directive holds is reported, not read on", () => {
  const head = "module m\n\ngo 1.22\n\n";
  const tail = `\nrequire github.com/pkg/errors v0.9.1\n`;
  const overOnLine5 = (out) => {
    assert.deepEqual(out.purls, [ERRORS], "the next line is read");
    const r = reported(out);
    assert.equal(r.length, 1, JSON.stringify(out.not_checked));
    assert.equal(r[0][0], 5);
    assert.match(r[0][1], GOMOD_OVER);
  };
  it("a quoted module path of 4,899,950 characters", () => overOnLine5(readInChild("go.mod", [[`${head}require "example.com/`, 1], ["a", 4_899_950], [`" v1.0.0${tail}`, 1]])));
  it("a quoted module path of 2,449,950 escapes", () => overOnLine5(readInChild("go.mod", [[`${head}require "example.com/`, 1], ["\\a", 2_449_950], [`" v1.0.0${tail}`, 1]])));
  it("2,449,990 bare tokens", () => overOnLine5(readInChild("go.mod", [[`${head}require`, 1], [" a", 2_449_990], [tail, 1]])));
  it("4,899,950 parentheses", () => overOnLine5(readInChild("go.mod", [[`${head}require `, 1], ["(", 4_899_950], [tail, 1]])));
  it("1,633,300 empty quoted strings", () => overOnLine5(readInChild("go.mod", [[`${head}require`, 1], [' ""', 1_633_300], [tail, 1]])));
  it("74 lines of 32,760 bare tokens each, every one under LINE_MAX: each is reported", () => {
    const out = readInChild("go.mod", [[head, 1], [`require${" a".repeat(32_760)}\n`, 74], [tail.slice(1), 1]]);
    assert.deepEqual(out.purls, [ERRORS]);
    const r = reported(out);
    assert.equal(r.length, 74);
    assert.deepEqual(r.map(([line]) => line), Array.from({ length: 74 }, (_, k) => 5 + k));
    for (const [, detail] of r) assert.match(detail, GOMOD_OVER);
  });
  it("a comment of 4,899,950 characters is no token: the require before it is read", () => {
    const out = readInChild("go.mod", [[`${head}require github.com/pkg/errors v0.9.1 // `, 1], ["x", 4_899_950], ["\n", 1]]);
    assert.deepEqual(out.purls, [ERRORS]);
    assert.deepEqual(out.not_checked, []);
  });
  it("at the bounds: TOKENS_MAX tokens and LINE_MAX characters are read as before; one more is reported", () => {
    // A require of 16 tokens is read as it was before the bound (not a require line: path, then version); 17 is past it.
    const at = readInChild("go.mod", [[`${head}require a v1.0.0${" x".repeat(GOMOD_TOKENS_MAX - 3)}\n`, 1]]);
    assert.deepEqual(reported(at), [[5, "not a require line this reader can read (module path, then version)"]]);
    const past = readInChild("go.mod", [[`${head}require a v1.0.0${" x".repeat(GOMOD_TOKENS_MAX - 2)}\n`, 1]]);
    assert.deepEqual(reported(past).map(([line]) => line), [5]);
    assert.match(reported(past)[0][1], GOMOD_OVER);
    // From its first token, a line of exactly LINE_MAX characters is read (indentation before it is not counted).
    // #3460: read, its module path (past NAME_MAX, 512 characters) is reported as such, not past the line's bound.
    const path = (n) => `example.com/${"p".repeat(n - "require example.com/ v1.0.0".length)}`;
    const fits = readInChild("go.mod", [[`${head}\t\trequire ${path(GOMOD_LINE_MAX)} v1.0.0\n`, 1]]);
    assert.deepEqual(fits.purls, []);
    assert.deepEqual(reported(fits), [[5, `a name or version of more than ${C.NAME_MAX} characters, which no purl the API checks holds: not read`]]);
    // Control: a path of NAME_MAX characters, on the same line's tokenizer, is within the name's bound, and is listed
    // for its purl instead ("pkg:golang/" and "@v1.0.0" take it past 512 characters, #3381's round-7 verification,
    // R7V-2.2: through round 7 it was kept, and the call refused for it); one whose purl is 512 characters is read.
    const named = readInChild("go.mod", [[`${head}\t\trequire example.com/${"p".repeat(C.NAME_MAX - "example.com/".length)} v1.0.0\n`, 1]]);
    assert.deepEqual([named.purls, reported(named).map(([line, detail]) => [line, LONG_PURL.test(detail)])], [[], [[5, true]]]);
    const atPurl = readInChild("go.mod", [[`${head}\t\trequire example.com/${"p".repeat(C.PURL_MAX - "pkg:golang/example.com/@v1.0.0".length)} v1.0.0\n`, 1]]);
    assert.deepEqual([atPurl.not_checked, atPurl.purls.map((x) => x.length)], [[], [C.PURL_MAX]]);
    const over = readInChild("go.mod", [[`${head}\t\trequire ${path(GOMOD_LINE_MAX + 1)} v1.0.0\n`, 1]]);
    assert.deepEqual(over.purls, []);
    assert.match(reported(over)[0][1], GOMOD_OVER);
  });
});

describe("#3434 requirements.txt: a line past what any requirement holds is reported before it is split or matched", () => {
  const lineOne = (out, detail) => {
    const r = reported(out);
    assert.equal(r.length, 1, JSON.stringify(out.not_checked));
    assert.equal(r[0][0], 1);
    assert.match(r[0][1], detail);
  };
  it("one specifier of 1,224,991 clauses on one line of 4,899,977 characters", () => {
    const out = readInChild("requirements.txt", [["django==4.2.1", 1], [",==1", 1_224_991], ["\nrequests==2.31.0\n", 1]]);
    lineOne(out, REQ_LONG);
    assert.deepEqual(out.purls, ["pkg:pypi/requests@2.31.0"], "the next line is read");
  });
  it("one specifier of 65 clauses, under LINE_MAX: reported, counted by its commas; 64 clauses are a range, as before", () => {
    lineOne(readInChild("requirements.txt", [["django==4.2.1", 1], [",!=1", REQ_CLAUSES_MAX], ["\n", 1]]), REQ_CLAUSES);
    const at = readInChild("requirements.txt", [["django==4.2.1", 1], [",!=1", REQ_CLAUSES_MAX - 1], ["\n", 1]]);
    assert.deepEqual(at.not_checked.map((n) => [n.reason, n.line]), [["version_unpinned", 1]]);
  });
  it("a name, then 4,899,990 spaces", () => lineOne(readInChild("requirements.txt", [["a", 1], [" ", 4_899_990], ["x\n", 1]]), REQ_LONG));
  it("a name, then 4,899,990 semicolons", () => lineOne(readInChild("requirements.txt", [["a", 1], [";", 4_899_990], ["\n", 1]]), REQ_LONG));
  it("one logical line of 1,633,300 continuation lines", () => {
    const out = readInChild("requirements.txt", [["x\\\n", 1_633_300], ["==1\nrequests==2.31.0\n", 1]]);
    lineOne(out, REQ_LONG);
    assert.deepEqual(out.purls, ["pkg:pypi/requests@2.31.0"]);
    assert.equal(out.not_checked[0].line, 1, "reported at its first physical line");
  });
  it("one logical line of 1,633,300 continuation lines that hold only whitespace after its first", () => {
    const out = readInChild("requirements.txt", [["django==4.2.1 \\\n", 1], [" \\\n", 1_633_300], ["\nrequests==2.31.0\n", 1]]);
    assert.deepEqual(out.purls, ["pkg:pypi/django@4.2.1", "pkg:pypi/requests@2.31.0"], "whitespace joined is whitespace: both read");
    assert.deepEqual(out.not_checked, []);
  });
  it("a requirement with 600 --hash options over continuation lines (about 50,000 characters) is read", () => {
    const hash = (k) => k.toString(16).padStart(64, "0");
    const lines = Array.from({ length: 600 }, (_, k) => `    --hash=sha256:${hash(k)}`);
    const out = readInChild("requirements.txt", [[`django==4.2.7 \\\n${lines.join(" \\\n")}\n`, 1]]);
    assert.deepEqual(out.purls, ["pkg:pypi/django@4.2.7"]);
    assert.deepEqual(out.not_checked, []);
  });
});

describe("#3434 requirements.txt: a comment and a \"name @\" are found in time linear in the line", () => {
  // 70 lines each just under LINE_MAX, so each is matched: a scan that backtracks takes seconds a line here, these all
  // of them together milliseconds. Each reads as it did before: a specifier this reader cannot read.
  const each70 = (out) => {
    assert.equal(out.not_checked.length, 70);
    for (const n of out.not_checked) assert.deepEqual([n.reason, n.detail], ["unsupported_line", "a version specifier this reader cannot read"]);
  };
  it("70 lines of a name, 64,000 spaces and no @", () => each70(readInChild("requirements.txt", [[`a${" ".repeat(64_000)}x\n`, 70]])));
  it("70 lines of a pin, 32,000 ' #' and a CR before the line's end", () => each70(readInChild("requirements.txt", [[`a==1${" #".repeat(32_000)}\rx\n`, 70]])));
  it("70 lines of a pin, 32,000 ' #' and a U+2028 before the line's end", () => each70(readInChild("requirements.txt", [[`a==1${" #".repeat(32_000)}\u2028x\n`, 70]])));
  it("a comment is cut where /\\s#.*$/ cut it: the first ' #' that no CR, U+2028 or U+2029 follows", () => {
    const out = readInChild("requirements.txt", [["a==1 #c\nb==2 #c\rc\nc==3\r #c\nd==4 #x\u2029 #y\ne[x] @ https://example.com/e.whl #c\n", 1]]);
    assert.deepEqual(out.purls, ["pkg:pypi/a@1", "pkg:pypi/c@3"]);
    assert.deepEqual(out.not_checked.map((n) => [n.line, n.reason, n.spec]), [
      [2, "unsupported_line", "b==2 #c\rc"],
      [4, "unsupported_line", "d==4 #x"],
      [5, "unsupported_line", "e[x] @ https://example.com/e.whl"],
    ]);
  });
});

describe("#3434 Cargo.lock and poetry.lock: a string is read from slices of the text", () => {
  const cargo = `[[package]]\nname = "smallvec"\nversion = "1.6.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "`;
  it("a Cargo.lock checksum of 4,899,800 characters", () => {
    const out = readInChild("Cargo.lock", [[cargo, 1], ["a", 4_899_800], ['"\n', 1]]);
    assert.deepEqual(out.purls, ["pkg:cargo/smallvec@1.6.0"]);
  });
  it("a Cargo.lock checksum of 2,449,900 escapes", () => {
    const out = readInChild("Cargo.lock", [[cargo, 1], ["\\t", 2_449_900], ['"\n', 1]]);
    assert.deepEqual(out.purls, ["pkg:cargo/smallvec@1.6.0"]);
  });
  it("a poetry.lock multi-line description of 4,899,800 characters", () => {
    const out = readInChild("poetry.lock", [['[[package]]\nname = "django"\nversion = "3.2.0"\ndescription = """', 1], ["a", 4_899_800], ['"""\n', 1]]);
    assert.deepEqual(out.purls, ["pkg:pypi/django@3.2.0"]);
  });
  // An escape every four characters: two parts per escape, joined only at the string's end, held some 20 times the
  // string's length at once; joined in chunks of PARTS_MAX, the string's length and the chunks'.
  const smaller = [...FLAGS.filter((f) => !f.startsWith("--max-old-space-size=")), "--max-old-space-size=40"];
  it("a Cargo.lock checksum of 4,999,000 characters with an escape every 4 is read in a 40 MiB old space", () => {
    const out = readInChild("Cargo.lock", [[cargo, 1], ["\\tab", 1_249_750], ['"\n', 1]], { flags: smaller });
    assert.deepEqual(out.purls, ["pkg:cargo/smallvec@1.6.0"]);
  });
  it("a poetry.lock multi-line description of 4,999,000 characters with an escape every 4 is read in a 40 MiB old space", () => {
    const out = readInChild("poetry.lock", [['[[package]]\nname = "django"\nversion = "3.2.0"\ndescription = """', 1], ["\\tab", 1_249_750], ['"""\n', 1]], { flags: smaller });
    assert.deepEqual(out.purls, ["pkg:pypi/django@3.2.0"]);
  });
  it("a string of many chunks reads as one: escapes and runs across PARTS_MAX joins, every character kept", () => {
    const body = Array.from({ length: 10_000 }, (_, k) => `${k}\\t\\u00e9`).join("");
    const want = Array.from({ length: 10_000 }, (_, k) => `${k}\té`).join("");
    assert.equal(readToml(`a = "${body}"\nb = """${body}"""\n`).root.a, want);
    assert.equal(readToml(`a = "${body}"\nb = """${body}"""\n`).root.b, want);
  });
});

describe("#3434 Cargo.lock and poetry.lock: an escape of no Unicode scalar value, or nesting past NEST_MAX, makes the file unreadable", () => {
  const head = `[[package]]\nname = "smallvec"\nversion = "1.6.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n`;
  const unreadable = (format, text) => M.readFile(format, text).unreadable;
  it("\\U past U+10FFFF, and a \\U or \\u surrogate: a bad unicode escape on its line", () => {
    for (const esc of ["\\UFFFFFFFF", "\\U00110000", "\\U0000D800", "\\uD800", "\\uDFFF"]) {
      assert.equal(unreadable("Cargo.lock", `${head}checksum = "${esc}"\n`), "it is not TOML this reader can read: a bad unicode escape on line 5", esc);
    }
    assert.equal(unreadable("poetry.lock", `[[package]]\nname = "django"\nversion = "3.2.0"\ndescription = "\\U00110000"\n`), "it is not TOML this reader can read: a bad unicode escape on line 4");
  });
  it("control: the scalar values around them are read", () => {
    assert.deepEqual(readToml('a = "\\U0010FFFF\\U0001F600\\uD7FF\\uE000\\u00e9"\n').root.a, "\u{10FFFF}\u{1F600}\uD7FF\uE000é");
  });
  it("arrays or inline tables nested more than 64 deep: unreadable, naming the bound; 64 deep is read", () => {
    const deep = `arrays and inline tables nested more than ${NEST_MAX} deep`;
    for (const [what, at, past] of [
      ["arrays", `x = ${"[".repeat(NEST_MAX)}${"]".repeat(NEST_MAX)}`, `x = ${"[".repeat(NEST_MAX + 1)}${"]".repeat(NEST_MAX + 1)}`],
      ["inline tables", `x = ${"{a=".repeat(NEST_MAX - 1)}{}${"}".repeat(NEST_MAX - 1)}`, `x = ${"{a=".repeat(NEST_MAX)}{}${"}".repeat(NEST_MAX)}`],
    ]) {
      assert.equal(M.readFile("Cargo.lock", `${head}${at}\n`).pinned?.length, 1, `${what}: ${NEST_MAX} deep is read`);
      assert.equal(unreadable("Cargo.lock", `${head}${past}\n`), `it is not TOML this reader can read: ${deep} on line 5`, what);
    }
  });
  it("the reviewer's 30,000-deep array and 15,000-deep inline table, in a call with a go.mod: that file is unreadable, the go.mod read", () => {
    const gomod = { filename: "go.mod", content: `module m\n\ngo 1.21\n\nrequire ${ERRORS.slice("pkg:golang/".length).replace("@", " ")}\n` };
    for (const [filename, x] of [
      ["Cargo.lock", `${"[".repeat(30_000)}${"]".repeat(30_000)}`],
      ["Cargo.lock", `${"{a=".repeat(15_000)}1${"}".repeat(15_000)}`],
      ["poetry.lock", `${"{a=".repeat(15_000)}1${"}".repeat(15_000)}`],
    ]) {
      const r = SM.readFiles({ files: [{ filename, content: `${head}x = ${x}\n` }, gomod] });
      assert.equal(typeof r, "object", r);
      assert.deepEqual(r.files.map((f) => [f.read, f.refused]), [[false, `read as ${filename}, it is not TOML this reader can read: arrays and inline tables nested more than ${NEST_MAX} deep on line 5`], [true, null]]);
      assert.deepEqual(r.purls, [ERRORS]);
    }
  });
  it("a reader's RangeError makes that file unreadable, and the call's other files are read", () => {
    const cargo = M.FORMATS["Cargo.lock"];
    const read = cargo.read;
    cargo.read = () => {
      throw new RangeError("Maximum call stack size exceeded");
    };
    let r;
    try {
      r = SM.readFiles({ files: [{ filename: "Cargo.lock", content: head }, { filename: "requirements.txt", content: "django==4.2.7\n" }] });
    } finally {
      cargo.read = read;
    }
    assert.equal(typeof r, "object", r);
    assert.deepEqual(r.files.map((f) => [f.read, f.refused]), [[false, "read as Cargo.lock, it could not be read: Maximum call stack size exceeded"], [true, null]]);
    assert.deepEqual(r.purls, ["pkg:pypi/django@4.2.7"]);
  });
});

describe("#3434 Cargo.lock and poetry.lock: a dotted key or table header of more than KEY_PARTS_MAX parts is refused, each part counted", () => {
  const parts = (n) => Array.from({ length: n }, (_, k) => `p${k}`).join(".");
  const shapes = [
    ["a key", (k) => `${k} = 1\n`],
    ["a table header", (k) => `[${k}]\n`],
    ["an array-of-tables header", (k) => `[[${k}]]\n`],
    ["an inline table's key", (k) => `x = { ${k} = 1 }\n`],
  ];
  it(`${KEY_PARTS_MAX} parts are read; ${KEY_PARTS_MAX + 1} are "a dotted key of more than ${KEY_PARTS_MAX} parts" on their line, in a key, a header, an array-of-tables header and an inline table`, () => {
    for (const [what, at] of shapes) {
      const ok = M.readFile("Cargo.lock", at(parts(KEY_PARTS_MAX)));
      assert.equal(ok.unreadable, undefined, `${what}: ${ok.unreadable}`);
      assert.equal(M.readFile("Cargo.lock", `a = 1\n${at(parts(KEY_PARTS_MAX + 1))}`).unreadable, `it is not TOML this reader can read: a dotted key of more than ${KEY_PARTS_MAX} parts on line 2`, what);
    }
  });
  it("each part after a key's first is taken from MAX_TOML_VALUES: 4,600 keys of 64 parts are read, 4,700 refused", () => {
    // 63 shared parts make 63 tables, once; each key then takes its 63 further parts and its own assignment: 4,600 x
    // 64 + 63 values are under the bound, 4,700 x 64 + 63 past it.
    const keys = (n) => Array.from({ length: n }, (_, k) => `${"a.".repeat(KEY_PARTS_MAX - 1)}k${k} = 1\n`).join("");
    assert.equal(typeof SM.readFiles({ files: [{ filename: "Cargo.lock", content: keys(4_600) }] }), "object");
    assert.match(SM.readFiles({ files: [{ filename: "Cargo.lock", content: keys(4_700) }] }), PAST_TOML);
  });
  it("a key, a header, an array-of-tables header and an inline table's key of 1,666,000 parts in 5 MB: unreadable at its 65th part, in the image's heap", () => {
    for (const [what, at] of shapes) {
      const [open, close] = at("\0").split("\0");
      const segments = [[open, 1], ["ab.", 1_666_000], [`a${close}`, 1]];
      // #3381: estimated past the parse bound (1,666,000 dots), so unreadable before it is read; with that bound
      // lifted, the reader refuses it at its 65th part, in the image's heap. The image's bound is passed, not taken
      // from this process's heap, so the packed tarball's run (no Dockerfile.http, Node's own heap) asserts the same.
      const imageParse = B.budgetsFor(B.IMAGE_HEAP_LIMIT).parseBytes;
      assert.match(readInChild("Cargo.lock", segments, { refused: true, parseBytes: imageParse }).refused ?? "", new RegExp(`${TOML_DENSE.source}$`), what);
      const out = readInChild("Cargo.lock", segments, { refused: true, parseBytes: Infinity });
      assert.match(out.refused ?? "", new RegExp(`a dotted key of more than ${KEY_PARTS_MAX} parts on line 1$`), what);
    }
  });
});

describe("#3434 not_checked: every string from the file an entry carries is a short copy of its own", () => {
  // 300 strings of 1,000,000 characters, one at a time, each given to specOf or clip and then dropped, the results kept:
  // a result that is a copy of its own keeps 200 characters; one that is a slice of its string keeps all of it, and 300
  // MB of them do not fit the image's heap.
  for (const fn of ["specOf", "clip"]) {
    it(`${fn} returns a copy of its own: 300 strings of 1,000,000 characters given to it are freed`, () => {
      const script = `
import v8 from "node:v8";
const C = await import(${JSON.stringify(dist("tools/manifests/common.js"))});
const kept = [];
for (let i = 0; i < 300; i++) kept.push(C.${fn}(JSON.parse(JSON.stringify(" " + String(i).padEnd(1_000_000, "x") + " "))));
console.log(JSON.stringify({ lengths: [...new Set(kept.map((s) => s.length))], last: kept.at(-1).at(-1), used_mb: Math.round(v8.getHeapStatistics().used_heap_size / 1e6) }));`;
      const r = spawnSync(process.execPath, [...FLAGS, "--input-type=module", "-e", script], { encoding: "utf8", timeout: CASE_TIMEOUT_MS });
      const fatal = /FATAL ERROR:[^\n]*/.exec(r.stderr ?? "")?.[0] ?? (r.stderr ?? "").slice(-300);
      assert.deepEqual([r.signal, r.status], [null, 0], `${fn}: the process ${r.signal === "SIGABRT" ? "ABORTED (SIGABRT)" : `exited ${r.status} (${r.signal})`}: ${fatal}`);
      const out = JSON.parse(r.stdout.trim().split("\n").at(-1));
      assert.deepEqual([out.lengths, out.last], [[SPEC_MAX], "…"], fn);
    });
  }
  const block = (verb, k) => [[`module m\n\ngo 1.21\n\n${verb} (\n`, 1], ["a\n", k], [")\n", 1]];
  it("go.mod: a block whose verb is 30,000 characters, 1,999 lines in it: each detail names the verb clipped", () => {
    const verb = "v".repeat(30_000);
    const out = readInChild("go.mod", block(verb, NOT_CHECKED_MAX - 1));
    assert.equal(out.not_checked.length, NOT_CHECKED_MAX - 1);
    for (const n of out.not_checked) {
      assert.equal(n.detail_chars, `not a go.mod directive (${clipped(verb)})`.length, `line ${n.line}`);
      assert.equal(n.spec, "a");
    }
  });
  it("go.mod: a replace to a 12,000-character local directory, or a 12,000-character path with no version, on each of 1,999 requires: each detail names it clipped", () => {
    for (const [target, detail] of [
      [`./${"d".repeat(12_000)}`, (p) => `replaced by the local directory ${clipped(p)} (replace on line 5), which is not a published module version`],
      [`example.com/${"d".repeat(12_000)}`, (p) => `replaced by ${clipped(p)} without a version (replace on line 5), which this reader cannot resolve`],
    ]) {
      const out = readInChild("go.mod", [[`module m\n\ngo 1.21\n\nreplace a => ${target}\n\nrequire (\n`, 1], ["\ta v1\n", NOT_CHECKED_MAX - 1], [")\n", 1]]);
      assert.equal(out.not_checked.length, NOT_CHECKED_MAX - 1);
      assert.deepEqual([...new Set(out.not_checked.map((n) => n.detail_chars))], [detail(target).length]);
      assert.equal(out.not_checked[0].detail, detail(target).slice(0, 300));
    }
  });
  it("go.mod: a replace with a version, applied to 19,000 requires: data lists 2,000 of the replaces, counts all, and checks the one purl", () => {
    const path = `example.com/${"d".repeat(400)}`;
    const out = readInChild("go.mod", [[`module m\n\ngo 1.21\n\nreplace a => ${path} v1.0.0\n\nrequire (\n`, 1], ["\ta v1\n", 19_000], [")\n", 1]]);
    assert.deepEqual(out.purls, [`pkg:golang/${path}@v1.0.0`]);
    assert.deepEqual([out.files[0].replaced, out.replaced_total, out.files[0].to_chars, out.files[0].purls], [NOT_CHECKED_MAX, 19_000, `${path}@v1.0.0`.length, 19_000]);
  });
  it("Gemfile.lock: a 20,000-character section, 1,999 specs in it: each detail names it clipped", () => {
    const section = "S".repeat(20_000);
    const out = readInChild("Gemfile.lock", [[`${section}\n  specs:\n`, 1], ["    a (1)\n", NOT_CHECKED_MAX - 1]]);
    assert.equal(out.not_checked.length, NOT_CHECKED_MAX - 1);
    for (const n of out.not_checked) assert.equal(n.detail_chars, `a gem from a ${clipped(section)} section, not a RubyGems source`.length);
  });
  it("names are clipped: a 4,900,000-character Cargo.lock package name in a not_checked entry is its first 199 characters and …", () => {
    const out = readInChild("Cargo.lock", [['[[package]]\nname = "', 1], ["n", 4_900_000], ['"\nversion = "1"\n', 1]]);
    // #3460: past NAME_MAX, so reported as such (unsupported_line), before its missing source is looked at.
    assert.deepEqual(out.not_checked.map((n) => [n.reason, n.name_chars, n.spec_chars]), [["unsupported_line", SPEC_MAX, SPEC_MAX]]);
  });
  it("package-lock.json v1: 1,999 dependencies under a 4,900,000-character one: each spec is the first 199 characters of its install path, read in linear time", () => {
    const kids = Array.from({ length: NOT_CHECKED_MAX - 1 }, (_, k) => `"k${k}":{}`).join(",");
    const out = readInChild("package-lock.json", [['{"lockfileVersion":1,"dependencies":{"', 1], ["a", 4_900_000], [`":{"version":"1.0.0","dependencies":{${kids}}}}}`, 1]]);
    // #3460: the parent's name is past NAME_MAX, so it is listed too (unsupported_line), first; its children as before.
    assert.equal(out.not_checked.length, NOT_CHECKED_MAX);
    const spec = clipped(`node_modules/${"a".repeat(SPEC_MAX)}`);
    assert.deepEqual([out.not_checked[0].spec, out.not_checked[0].reason], [spec.slice(0, 60), "unsupported_line"]);
    for (const n of out.not_checked.slice(1)) assert.deepEqual([n.spec, n.spec_chars, n.reason], [spec.slice(0, 60), SPEC_MAX, "version_unresolved"]);
    // Each child's path is built on its parent's first SPEC_MAX characters, never flattened whole: 1,999 flattenings of
    // the 4,900,000-character path take seconds.
    assert.ok(out.ms < 2_000, `read in ${out.ms} ms`);
  });
  it("control: a v1 tree's specs are as a path built whole gives them, at every depth and at the cut", () => {
    for (const len of [1, 40, 85, 86, 87, 100, 172, 173, 174, 185, 186, 187, 188, 199, 200, 201, 260]) {
      const k = "p".repeat(len);
      const doc = { lockfileVersion: 1, dependencies: { [k]: { version: "1", dependencies: { [k]: { version: "file:x", dependencies: { q: { dependencies: { r: {} } } } } } } } };
      const specs = M.readFile("package-lock.json", JSON.stringify(doc)).not_checked.map((n) => n.spec);
      const p2 = `node_modules/${k}/node_modules/${k}`;
      assert.deepEqual(specs, [clipped(`${p2} file:x`), clipped(`${p2}/node_modules/q`), clipped(`${p2}/node_modules/q/node_modules/r`)], `a key of ${len}`);
    }
  });
});

describe("#3434 a call lists at most NOT_CHECKED_MAX entries not checked, and counts them all", () => {
  it("20,000 unpinned lines in two files: data lists the first 2,000 read, the counts are all 20,000's", () => {
    const r = SM.readFiles({ files: [{ filename: "a/requirements.txt", content: "a\n".repeat(1_500) }, { filename: "b/requirements.txt", content: "b\n".repeat(18_500) }] });
    assert.equal(typeof r, "object", r);
    assert.equal(r.not_checked.length, NOT_CHECKED_MAX);
    assert.deepEqual([r.not_checked_total, r.not_checked_by_reason.version_unpinned, r.files.map((f) => f.not_checked)], [20_000, 20_000, [1_500, 18_500]]);
    assert.deepEqual([r.not_checked[1_499].file, r.not_checked[1_500].file, r.not_checked.at(-1).line], ["a/requirements.txt", "b/requirements.txt", 500]);
  });
  it("one reader keeps the first 2,000 and counts the rest by reason", () => {
    const r = M.readFile("requirements.txt", `${"a\n".repeat(1_500)}${"-r x.txt\n".repeat(1_500)}`);
    assert.equal(r.not_checked.length, NOT_CHECKED_MAX);
    assert.deepEqual([r.counted.version_unpinned, r.counted.unsupported_line], [1_500, 1_500]);
  });
  it("at 2,000 or fewer the list is every entry, as before", () => {
    const r = SM.readFiles({ files: [{ filename: "requirements.txt", content: "a\n".repeat(NOT_CHECKED_MAX) }] });
    assert.deepEqual([r.not_checked.length, r.not_checked_total], [NOT_CHECKED_MAX, NOT_CHECKED_MAX]);
  });
});

describe("#3434 filename: one longer than 1,024 characters is refused, naming the bound", () => {
  const named = (n) => `${"x".repeat(n - "requirements.txt".length)}requirements.txt`;
  it("readFiles takes 1,024 characters and refuses 1,025", () => {
    assert.equal(typeof SM.readFiles({ files: [{ filename: named(MAX_FILENAME_CHARS), content: "a==1\n" }] }), "object");
    assert.match(SM.readFiles({ files: [{ filename: named(MAX_FILENAME_CHARS + 1), content: "a==1\n" }] }), PAST_FILENAME);
  });
});

describe("#3434 filename: one holding a character JSON writes as a six-character escape, or a quote, is refused, naming the rule", () => {
  it("readFiles refuses a control character, a quote, and a lone surrogate, high or low, anywhere in the name", () => {
    for (const bad of ["\u0000", "\u0001", "\t", "\n", "\u001f", '"', "\ud800", "\udfff", "x\udbffy", "\udc00\ud800"]) {
      assert.match(SM.readFiles({ files: [{ filename: `a${bad}/requirements.txt`, content: "a==1\n" }] }), FILENAME_RULE, JSON.stringify(bad));
    }
  });
  it("and reads every other: a backslash (a path separator), U+007F, U+2028, é, a surrogate pair, a space", () => {
    for (const ok of ["\\", "\u007f", "\u2028", "é", "😀", " "]) {
      const r = SM.readFiles({ files: [{ filename: `a${ok}b\\requirements.txt`, content: "a==1\n" }] });
      assert.equal(typeof r, "object", `${JSON.stringify(ok)}: ${r}`);
      assert.deepEqual(r.purls, ["pkg:pypi/a@1"]);
    }
  });
});

describe("#3434 not_checked: a string an entry carries is bounded as JSON writes it", () => {
  it("clip counts a six-character escape six: 300 control characters keep 33; quotes, backslashes, tabs and letters keep 199, as by their length", () => {
    assert.equal(C.clip("\u0001".repeat(300)), `${"\u0001".repeat(33)}…`);
    assert.equal(C.clip("\ud800".repeat(300)), `${"\ud800".repeat(33)}…`);
    for (const ch of ['"', "\\", "\t", "x"]) assert.equal(C.clip(ch.repeat(300)), `${ch.repeat(SPEC_MAX - 1)}…`, JSON.stringify(ch));
    assert.equal(C.clip("x".repeat(SPEC_MAX)), "x".repeat(SPEC_MAX));
    assert.equal(C.clip(`${"x".repeat(SPEC_MAX - 2)}😀y`), `${"x".repeat(SPEC_MAX - 2)}…`, "a surrogate pair is never cut");
  });
  it("a go.mod block whose verb and 2,000 lines are 240 control characters each: every spec's JSON at most 200 characters, every detail's 226", () => {
    const ch = "\u0001";
    const r = SM.readFiles({ files: [{ filename: "go.mod", content: `module m\n\n${ch.repeat(240)} (\n${`${ch.repeat(240)}\n`.repeat(NOT_CHECKED_MAX)})\n` }] });
    assert.equal(r.not_checked.length, NOT_CHECKED_MAX);
    const json = (x) => JSON.stringify(x).length - 2;
    assert.ok(Math.max(...r.not_checked.map((e) => json(e.spec))) <= SPEC_MAX, "spec");
    assert.ok(Math.max(...r.not_checked.map((e) => json(e.detail))) <= SPEC_MAX + "not a go.mod directive ()".length + 1, "detail");
  });
});

// 20 Gemfile.locks of a real one's shape (a GEM section's specs, each with a dependency, then PLATFORMS,
// DEPENDENCIES and BUNDLED WITH), 2,000 counted lines each: a call of 20 files at the bound, as a monorepo's are.
const gemfile = (f, gems, extra = 0) =>
  [
    "GEM", "  remote: https://rubygems.org/", "  specs:",
    ...Array.from({ length: gems }, (_, g) => [`    gem${g} (1.${g}.${f % 2})`, `      dep${g} (~> 1.0)`]).flat(),
    ...Array.from({ length: extra }, (_, g) => `    more${g} (1.0)`),
    "", "PLATFORMS", "  ruby", "", "DEPENDENCIES", ...Array.from({ length: gems }, (_, g) => `  gem${g}`), "", "BUNDLED WITH", "   2.5.6", "",
  ].join("\n");
const twenty = (extra = 0) => Array.from({ length: 20 }, (_, f) => ({ filename: `apps/a${f}/Gemfile.lock`, content: gemfile(f, 664, f === 19 ? extra : 0) }));
describe("#3434 the per-call bounds: past one, the call is refused, naming it", () => {
  it(`lines: ${MAX_MANIFEST_LINES} read, one more refused, counted across the call's files of every line format`, () => {
    assert.equal(typeof SM.readFiles({ files: [{ filename: "requirements.txt", content: "a==1\n".repeat(MAX_MANIFEST_LINES) }] }), "object");
    assert.match(SM.readFiles({ files: [{ filename: "requirements.txt", content: "a==1\n".repeat(MAX_MANIFEST_LINES + 1) }] }), PAST_LINES);
    const four = (n) => [
      { filename: "go.mod", content: `module m\n${"require a v1\n".repeat(n - 1)}` },
      { filename: "requirements.txt", content: "a==1\n".repeat(n) },
      { filename: "Gemfile.lock", content: `GEM\n  specs:\n${"    a (1)\n".repeat(n - 2)}` },
      { filename: "gradle.lockfile", content: "a:b:1=c\n".repeat(n) },
    ];
    assert.equal(typeof SM.readFiles({ files: four(MAX_MANIFEST_LINES / 4) }), "object");
    const past = four(MAX_MANIFEST_LINES / 4);
    past[3].content += "a:b:2=c\n";
    const q = MAX_MANIFEST_LINES / 4;
    assert.match(SM.readFiles({ files: past }), new RegExp(`: go\\.mod ${q}, requirements\\.txt ${q}, Gemfile\\.lock ${q}, gradle\\.lockfile ${q + 1} when the bound was passed; at most ${MAX_MANIFEST_LINES}`));
  });
  it(`lines: 20 Gemfile.locks of a real one's shape, ${MAX_MANIFEST_LINES} lines in all, are read; one more line is refused, each file's count named`, () => {
    const r = SM.readFiles({ files: twenty() });
    assert.equal(typeof r, "object", r);
    assert.deepEqual([r.files.length, r.read_purls, r.purls.length, r.files.every((f) => f.read)], [20, 20 * 664, 2 * 664, true]);
    const past = SM.readFiles({ files: twenty(1) });
    assert.match(past, PAST_LINES);
    assert.ok(past.includes(`: ${Array.from({ length: 19 }, (_, f) => `apps/a${f}/Gemfile.lock 2000`).join(", ")}, apps/a19/Gemfile.lock 2001 when the bound was passed;`), past);
  });
  it("lines: blank and comment lines are not counted", () => {
    const content = `${"# c\n\n".repeat(30_000)}${"a==1\n".repeat(MAX_MANIFEST_LINES)}${"   \n\t# x\n".repeat(10)}`;
    const r = SM.readFiles({ files: [{ filename: "requirements.txt", content }] });
    assert.equal(typeof r, "object", r);
    assert.equal(r.files[0].purls, MAX_MANIFEST_LINES);
    assert.equal(typeof SM.readFiles({ files: [{ filename: "go.mod", content: `${"// c\n\n".repeat(30_000)}module m\n${"require a v1\n".repeat(MAX_MANIFEST_LINES - 1)}` }] }), "object");
  });
  it(`JSON: ${MAX_JSON_VALUES} objects, arrays and entries read, one more refused before it is parsed, counted across the call's files`, () => {
    // {"packages":[1,…]}: the object, its member, the array and n entries.
    const composer = (n) => `{"packages":[${"1,".repeat(n - 1)}1]}`;
    assert.equal(typeof SM.readFiles({ files: [{ filename: "composer.lock", content: composer(MAX_JSON_VALUES - 3) }] }), "object");
    assert.match(SM.readFiles({ files: [{ filename: "composer.lock", content: composer(MAX_JSON_VALUES - 2) }] }), PAST_JSON);
    // {"lockfileVersion":1,"dependencies":{"k0":0,…}}: the object, its two members, the object and n entries.
    const npm = (n) => `{"lockfileVersion":1,"dependencies":{${Array.from({ length: n }, (_, k) => `"k${k}":0`).join(",")}}}`;
    const half = MAX_JSON_VALUES / 2;
    assert.equal(typeof SM.readFiles({ files: [{ filename: "package-lock.json", content: npm(half - 4) }, { filename: "composer.lock", content: composer(half - 3) }] }), "object");
    assert.match(SM.readFiles({ files: [{ filename: "package-lock.json", content: npm(half - 4) }, { filename: "composer.lock", content: composer(half - 2) }] }), /composer\.lock 150001 when the bound was passed/);
    // What is inside a string is not counted.
    assert.equal(typeof SM.readFiles({ files: [{ filename: "composer.lock", content: `{"packages":[],"x":"${'{[,\\"'.repeat(MAX_JSON_VALUES)}"}` }] }), "object");
  });
  it(`TOML: ${MAX_TOML_VALUES} tables, array entries and keys read, one more refused, counted across the call's files`, () => {
    // x = [1,…]: the key and n entries.
    const array = (n) => `x = [${"1,".repeat(n - 1)}1]\n`;
    assert.equal(typeof SM.readFiles({ files: [{ filename: "Cargo.lock", content: array(MAX_TOML_VALUES - 1) }] }), "object");
    assert.match(SM.readFiles({ files: [{ filename: "Cargo.lock", content: array(MAX_TOML_VALUES) }] }), PAST_TOML);
    // [[package]] tables: the first makes the array and its table, each next its table.
    const tables = (n) => "[[package]]\n".repeat(n - 1);
    assert.equal(typeof SM.readFiles({ files: [{ filename: "Cargo.lock", content: tables(MAX_TOML_VALUES / 2) }, { filename: "poetry.lock", content: tables(MAX_TOML_VALUES / 2) }] }), "object");
    assert.match(SM.readFiles({ files: [{ filename: "Cargo.lock", content: tables(MAX_TOML_VALUES / 2) }, { filename: "poetry.lock", content: tables(MAX_TOML_VALUES / 2 + 1) }] }), /poetry\.lock 150001 when the bound was passed/);
  });
  it("files of a real lockfile's shape at the 5,000,000-character cap are read whole: a package-lock.json and a Cargo.lock", () => {
    // The fixtures' entries, copied as many times as fit under the cap, each copy's names its own: every copy reads
    // as the one copy does.
    const tree = JSON.parse(fixture("tree.v3.package-lock.json"));
    const entries = Object.entries(tree.packages).filter(([k]) => k.startsWith("node_modules/"));
    const npmLock = (copies) => {
      const packages = { "": tree.packages[""] };
      for (let c = 0; c < copies; c++) for (const [k, v] of entries) packages[k.replace(/node_modules\//g, `node_modules/c${c}-`)] = v.name ? { ...v, name: `c${c}-${v.name}` } : v;
      return JSON.stringify({ ...tree, packages }, null, 2);
    };
    // As many copies as fit: estimated from one copy's length, then fewer while the file is past the cap (a later
    // copy's names are a little longer).
    const fit = (build, one) => {
      let n = Math.floor(MAX_CHARS / one);
      while (build(n).length > MAX_CHARS) n -= Math.ceil((build(n).length - MAX_CHARS) / one);
      return n;
    };
    const npmCopies = fit(npmLock, npmLock(2).length - npmLock(1).length);
    const lock = npmLock(npmCopies);
    assert.ok(lock.length <= MAX_CHARS && lock.length > MAX_CHARS - 100_000, `${lock.length}`);
    const one = M.readFile("package-lock.json", npmLock(1));
    const npm = M.readFile("package-lock.json", lock);
    assert.equal(npm.unreadable, undefined, npm.unreadable);
    assert.deepEqual([npm.pinned.length, npm.counted.local_path, npm.counted.vcs_source], [one.pinned.length * npmCopies, one.counted.local_path * npmCopies, one.counted.vcs_source * npmCopies]);
    const crates = fixture("Cargo.v4.lock").split("\n[[package]]\n").slice(1).map((t) => `[[package]]\n${t.trimEnd()}\n\n`);
    const cargoLock = (copies) => Array.from({ length: copies }, (_, c) => crates.map((t) => t.replace(/^name = "([^"]+)"/m, `name = "$1-c${c}"`)).join("")).join("");
    const cargoCopies = fit(cargoLock, cargoLock(2).length - cargoLock(1).length);
    const cargo = M.readFile("Cargo.lock", cargoLock(cargoCopies));
    const oneCrate = M.readFile("Cargo.lock", cargoLock(1));
    assert.equal(cargo.unreadable, undefined, cargo.unreadable);
    assert.deepEqual([cargo.pinned.length, cargo.counted.local_path, cargo.counted.vcs_source], [oneCrate.pinned.length * cargoCopies, oneCrate.counted.local_path * cargoCopies, oneCrate.counted.vcs_source * cargoCopies]);
  });
});

// #3460: one case per reader, each a name or version of millions of the character its reader split it on (or would
// encode a segment at a time), beside an entry of the same file that is read. N: what fits the 5,000,000-character cap.
const N3460 = 4_900_000;
const LONG = new RegExp(`^a name or version of more than ${C.NAME_MAX} characters, which no purl the API checks holds: not read$`);
const REGISTRY = 'source = "registry+https://github.com/rust-lang/crates.io-index"';
const CASES_3460 = [
  ["package-lock.json v1, a dependency's key of '/'", "package-lock.json", [['{"lockfileVersion":1,"dependencies":{"', 1], ["/", N3460], ['":{"version":"1.0.0"},"ok":{"version":"1.0.0"}}}', 1]], ["pkg:npm/ok@1.0.0"]],
  ["package-lock.json v2, an entry's name of '/'", "package-lock.json", [['{"lockfileVersion":2,"packages":{"node_modules/x":{"name":"', 1], ["/", N3460], ['","version":"1.0.0"},"node_modules/ok":{"version":"1.0.0"}}}', 1]], ["pkg:npm/ok@1.0.0"]],
  ["package-lock.json v3, an install path of '/'", "package-lock.json", [['{"lockfileVersion":3,"packages":{"node_modules/', 1], ["/", N3460], ['":{"version":"1.0.0"},"node_modules/ok":{"version":"1.0.0"}}}', 1]], ["pkg:npm/ok@1.0.0"]],
  ["Cargo.lock, a package name of '/'", "Cargo.lock", [['[[package]]\nname = "', 1], ["/", N3460], [`"\nversion = "1.0.0"\n${REGISTRY}\n\n[[package]]\nname = "ok"\nversion = "1.0.0"\n${REGISTRY}\n`, 1]], ["pkg:cargo/ok@1.0.0"]],
  ["poetry.lock, a package name of '/'", "poetry.lock", [['[[package]]\nname = "', 1], ["/", N3460], ['"\nversion = "1.0.0"\n\n[[package]]\nname = "ok"\nversion = "1.0.0"\n', 1]], ["pkg:pypi/ok@1.0.0"]],
  ["composer.lock, a package name of '/'", "composer.lock", [['{"packages":[{"name":"', 1], ["/", N3460], ['","version":"1.0.0"},{"name":"v/ok","version":"1.0.0"}]}', 1]], ["pkg:composer/v/ok@1.0.0"]],
  ["Gemfile.lock, a version of '-' and a gem name of '/'", "Gemfile.lock", [["GEM\n  remote: https://rubygems.org/\n  specs:\n    a (", 1], ["-", N3460 / 2], [")\n    ", 1], ["/", N3460 / 2], [" (1.0.0)\n    ok (1.0.0)\n", 1]], ["pkg:gem/ok@1.0.0"]],
  ["gradle.lockfile, a line of '=' after its coordinates, and an artifact past the bound", "gradle.lockfile", [["a:b:1.0=", 1], ["=", N3460], [`\ng:${"x".repeat(600)}:1.0=compileClasspath\nc:ok:2.0=compileClasspath\n`, 1]], ["pkg:maven/a/b@1.0", "pkg:maven/c/ok@2.0"]],
];

describe("#3460 every name and version a reader takes from a file is bounded before it is split: a file of millions of the split character is read, in the image's heap", () => {
  it("NAME_MAX is the longest purl match_batch.ts sends (MAX_PURL_LEN)", async () => {
    const MB = await import(dist("tools/match_batch.js"));
    assert.equal(C.NAME_MAX, MB.MAX_PURL_LEN);
  });
  for (const [what, filename, segments, read] of CASES_3460) {
    it(`${what}: that entry not checked (unsupported_line), the others read, quickly`, () => {
      const out = readInChild(filename, segments);
      for (const purl of read) assert.ok(out.purls.includes(purl), `${what}: ${purl} not read: ${JSON.stringify(out.purls)}`);
      const long = out.not_checked.filter((n) => n.reason === "unsupported_line" && LONG.test(n.detail));
      const want = filename === "Gemfile.lock" ? 2 : 1;
      assert.equal(long.length, want, `${what}: ${JSON.stringify(out.not_checked).slice(0, 600)}`);
    });
  }
});

// #3460, end to end: each such file sent to dist/http.js started as its image starts it, an instance of its own for
// each (one that ends does not hide the next): answered, that entry not checked, the instance alive.
describe("#3460 the hosted endpoint, started as its image starts it, answers each format's file of millions of its split character", { skip: IMAGE_SKIP }, () => {
  let api;
  before(async () => {
    api = await stubApi();
  });
  after(async () => {
    await api?.close();
  });
  for (const [what, filename, segments, read] of CASES_3460) {
    it(`${what}: answered, the entry not checked, the instance alive`, async () => {
      const srv = await startServer(api.base);
      try {
        const content = segments.map(([x, n]) => x.repeat(n)).join("");
        const t0 = Date.now();
        const r = await post(srv.port, toolCall("scan_manifest", { files: [{ filename, content }] }));
        const ms = Date.now() - t0;
        assert.equal(r.status, 200, `${what}: ${JSON.stringify(r).slice(0, 300)}`);
        const sc = resultOf(r)?.structuredContent;
        assert.equal(sc?.state, "measured", `${what}: ${String(r.text).slice(0, 300)}`);
        assert.ok(ms < 10_000, `${what}: answered after ${ms} ms`);
        assert.equal(sc.coverage.sent, read.length, what);
        assert.equal(sc.data.not_checked.filter((n) => n.reason === "unsupported_line" && LONG.test(n.detail)).length, filename === "Gemfile.lock" ? 2 : 1, `${what}: ${JSON.stringify(sc.data.not_checked).slice(0, 300)}`);
        await assertAlive(srv, what);
      } finally {
        await srv.stop();
      }
    });
  }
});

// #3381's round-7 verification (R7V-2.2, R7V-2.3): a name and version each within NAME_MAX can still make a purl past
// the 512 characters the API takes, once percent-encoded ('%' is %25, U+4E00 is %E4%B8%80). Through round 7 such a purl
// was kept, what readFiles held of the purls up to some 6 times what was reserved for them, and the whole call was
// refused for it ("purl 2 is longer than 512 characters", an index the caller could not map to a file or line). Now
// that entry is listed not checked (unsupported_line), no purl is kept for it, and the call's other entries are read.
describe("#3381's round-7 verification: an entry whose purl, percent-encoded, is past 512 characters is listed, the rest read", () => {
  it("requirements.txt: a version of 200 '%' between two pins: the two read, it listed on its line", () => {
    const out = readInChild("requirements.txt", [["django==4.2.7\na==", 1], ["%", 200], ["\nflask==2.0.0\n", 1]]);
    assert.deepEqual(out.purls, ["pkg:pypi/django@4.2.7", "pkg:pypi/flask@2.0.0"]);
    assert.deepEqual(reported(out).map(([line, detail]) => [line, LONG_PURL.test(detail)]), [[2, true]]);
  });
  it("requirements.txt: 4,070 versions of 512 x U+4E00 (4,620-character purls) after a pin: each listed, no purl kept for any", () => {
    const out = readInChild("requirements.txt", [["ok==1.0.0\n", 1], [`a==${"一".repeat(512)}\n`, 4070]]);
    assert.deepEqual(out.purls, ["pkg:pypi/ok@1.0.0"]);
    assert.equal(out.not_checked_by_reason.unsupported_line, 4070, JSON.stringify(out.not_checked_by_reason));
    assert.ok(out.not_checked.every((n) => n.reason === "unsupported_line" && LONG_PURL.test(n.detail)), JSON.stringify(out.not_checked[0]));
  });
  it("at the bound: a purl of 512 characters is read, one of 513 listed", () => {
    const v = (n) => "b".repeat(n - "pkg:pypi/a@".length);
    const at = readInChild("requirements.txt", [[`a==${v(C.PURL_MAX)}\n`, 1]]);
    assert.deepEqual([at.not_checked, at.purls.map((x) => x.length)], [[], [C.PURL_MAX]]);
    const past = readInChild("requirements.txt", [[`a==${v(C.PURL_MAX + 1)}\nok==1.0.0\n`, 1]]);
    assert.deepEqual([past.purls, reported(past).map(([line, detail]) => [line, LONG_PURL.test(detail)])], [["pkg:pypi/ok@1.0.0"], [[1, true]]]);
  });
  it("hosted, as its image starts it: the reviewer's call is measured, its two pins sent, the third listed", { skip: IMAGE_SKIP }, async () => {
    const api = await stubApi();
    const srv = await startServer(api.base);
    try {
      for (const [content, sent] of [[`django==4.2.7\na==${"%".repeat(200)}\nflask==2.0.0\n`, 2], [`ok==1.0.0\n${`a==${"一".repeat(512)}\n`.repeat(4070)}`, 1]]) {
        const r = await post(srv.port, toolCall("scan_manifest", { files: [{ filename: "requirements.txt", content }] }));
        assert.equal(r.status, 200, JSON.stringify(r).slice(0, 300));
        const sc = resultOf(r)?.structuredContent;
        assert.equal(sc?.state, "measured", String(r.text).slice(0, 300));
        assert.equal(sc.coverage.sent, sent);
        assert.ok(sc.data.not_checked.length > 0 && sc.data.not_checked.every((n) => n.reason === "unsupported_line" && LONG_PURL.test(n.detail)), JSON.stringify(sc.data.not_checked).slice(0, 300));
        await assertAlive(srv, `${content.length} characters`);
      }
    } finally {
      await srv.stop();
      await api.close();
    }
  });
});

// #3460's round-10 review (d2-3460). F1: a TOML key from the file never reaches Object.prototype (toml.ts table());
// F2: no reason or note repeats a value of the file unbounded; F3, F6, F7: a purl past PURL_MAX is counted, never
// built, and its entry listed by its reader at its own place, with its own name and text (common.ts purlOf); F4: a lone
// surrogate in one entry lists that entry, and the file's other entries are read; F5: a basename of __proto__ or
// constructor is refused as any other unknown name.
const LONE = /^a name or version holding a lone surrogate \(half of a UTF-16 pair\), which no purl can encode: not read$/;
// Reads each file in a process of its own and prints what reading them left on Object.prototype.
const PROTO_CHILD = `
const { readFile } = await import(process.env.MANIFESTS_JS);
const before = Object.getOwnPropertyNames(Object.prototype).sort().join();
const read = JSON.parse(process.env.PROTO_CASE).map(([format, content]) => readFile(format, content));
const after = Object.getOwnPropertyNames(Object.prototype).sort().join();
console.log(JSON.stringify({ read, x: ({}).x, link: ({}).link, hasOwnProperty: typeof Object.prototype.hasOwnProperty, same: before === after }));
`;
function protoInChild(files) {
  const r = spawnSync(process.execPath, ["--input-type=module", "-e", PROTO_CHILD], {
    env: { ...process.env, MANIFESTS_JS: dist("tools/manifests/index.js"), PROTO_CASE: JSON.stringify(files) },
    encoding: "utf8",
    timeout: CASE_TIMEOUT_MS,
  });
  assert.equal(r.status, 0, r.stderr);
  return JSON.parse(r.stdout.trim().split("\n").at(-1));
}
describe("#3460's round-10 review: what a file holds never reaches Object.prototype, a reason or note, or a purl past PURL_MAX", () => {
  it("F1: a Cargo.lock or poetry.lock key named __proto__, as a table header, a dotted key or quoted, is unreadable on its line; Object.prototype is untouched", () => {
    const out = protoInChild([
      ["Cargo.lock", "[__proto__]\nhasOwnProperty = 1\n"],
      ["Cargo.lock", "__proto__.x = 1\n"],
      ["Cargo.lock", "[__proto__]\nlink = true\npackage = \"x\"\n"],
      ["poetry.lock", '[[package]]\nname = "a"\nversion = "1.0"\n\n[package."__proto__"]\nx = 1\n'],
      ["Cargo.lock", "[a]\nb = { __proto__ = { x = 1 } }\n"],
    ]);
    assert.deepEqual([out.x, out.link, out.hasOwnProperty, out.same], [undefined, undefined, "function", true], JSON.stringify(out));
    for (const r of out.read) assert.match(r.unreadable, /^it is not TOML this reader can read: a key named __proto__, which no lockfile writes on line \d+$/, JSON.stringify(r));
  });
  it("F1: keys named constructor and prototype (PyPI holds packages of both names) are read as the table's own, and a [[package]] beside them is checked", () => {
    const poetry = '[[package]]\nname = "app"\nversion = "1.0.0"\n\n[package.dependencies]\nconstructor = ">=3"\nprototype = "*"\nhasOwnProperty = "1"\n\n[metadata.files]\nconstructor = []\nprototype = []\n';
    const out = protoInChild([["poetry.lock", poetry], ["Cargo.lock", '[[package]]\nname = "constructor"\nversion = "0.1.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n\n[constructor]\nprototype = 1\n']]);
    assert.deepEqual([out.x, out.hasOwnProperty, out.same], [undefined, "function", true], JSON.stringify(out));
    assert.deepEqual(out.read.map((r) => r.pinned?.map((p) => p.purl)), [["pkg:pypi/app@1.0.0"], ["pkg:cargo/constructor@0.1.0"]], JSON.stringify(out.read));
  });
  it("F2: a package-lock.json's lockfileVersion of 3,100,000 characters, and a go directive of 65,000, are named in under 1,000 characters", () => {
    const lv = `{"lockfileVersion":"${"\\\\".repeat(1_550_000)}"}`;
    const refused = SM.readFiles({ files: [{ filename: "package-lock.json", content: lv }] });
    assert.equal(typeof refused, "string");
    assert.ok(refused.length < 1_000, `${refused.length} characters: ${refused.slice(0, 200)}`);
    assert.match(refused, /has lockfileVersion "(\\\\){39}…" and no packages object/);
    for (const [v, said] of [[[1, 2], "an array"], [{ a: "b".repeat(100_000) }, "an object"], [2.5, "2.5"], [null, "null"]]) {
      const r = M.readFile("package-lock.json", JSON.stringify({ lockfileVersion: v }));
      assert.equal(r.unreadable, `it has lockfileVersion ${said} and no packages object`);
    }
    const go = M.readFile("go.mod", `module m\n\ngo 1.16${"x".repeat(65_000)}\n\nrequire a v1.0.0\n`);
    assert.equal(go.notes.length, 1);
    assert.ok(go.notes[0].length < 1_000, `${go.notes[0].length} characters`);
    assert.match(go.notes[0], /^Its go directive is 1\.16x{195}…, below 1\.17/);
  });
  // One entry each whose name and version are within NAME_MAX but whose purl is not, between two that are read.
  const C512 = "一".repeat(512);
  const LONG_CASES = [
    ["requirements.txt", `ok==1.0.0\na==${C512}\nflask==2.0.0\n`, 2, "a", ["pkg:pypi/ok@1.0.0", "pkg:pypi/flask@2.0.0"]],
    ["go.mod", `module m\n\ngo 1.21\n\nrequire ok v1.0.0\nrequire ${C512} v1.0.0\nrequire b v1.0.0\n`, 6, C512, ["pkg:golang/ok@v1.0.0", "pkg:golang/b@v1.0.0"]],
    ["package-lock.json", JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/ok": { version: "1.0.0" }, "node_modules/a": { version: C512 }, "node_modules/b": { version: "1.0.0" } } }), null, "a", ["pkg:npm/ok@1.0.0", "pkg:npm/b@1.0.0"]],
    ["package-lock.json", JSON.stringify({ lockfileVersion: 1, dependencies: { ok: { version: "1.0.0" }, a: { version: C512 }, b: { version: "1.0.0" } } }), null, "a", ["pkg:npm/ok@1.0.0", "pkg:npm/b@1.0.0"]],
    ["Cargo.lock", `[[package]]\nname = "ok"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n\n[[package]]\nname = "a"\nversion = "${C512}"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n\n[[package]]\nname = "b"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n`, 6, "a", ["pkg:cargo/ok@1.0.0", "pkg:cargo/b@1.0.0"]],
    ["poetry.lock", `[[package]]\nname = "ok"\nversion = "1.0.0"\n\n[[package]]\nname = "a"\nversion = "${C512}"\n\n[[package]]\nname = "b"\nversion = "1.0.0"\n`, 5, "a", ["pkg:pypi/ok@1.0.0", "pkg:pypi/b@1.0.0"]],
    ["Gemfile.lock", `GEM\n  specs:\n    ok (1.0.0)\n    a (${C512})\n    b (1.0.0)\n`, 4, "a", ["pkg:gem/ok@1.0.0", "pkg:gem/b@1.0.0"]],
    ["composer.lock", JSON.stringify({ packages: [{ name: "v/ok", version: "1.0.0" }, { name: "v/a", version: C512 }, { name: "v/b", version: "1.0.0" }] }), null, "v/a", ["pkg:composer/v/ok@1.0.0", "pkg:composer/v/b@1.0.0"]],
    ["gradle.lockfile", `g:ok:1.0.0=c\ng:a:${C512}=c\ng:b:1.0.0=c\n`, 2, "a", ["pkg:maven/g/ok@1.0.0", "pkg:maven/g/b@1.0.0"]],
  ];
  for (const [format, content, line, name, purls] of LONG_CASES) {
    it(`F3, F7: ${format}${format === "package-lock.json" ? ` v${JSON.parse(content).lockfileVersion}` : ""}: the reader builds no purl past ${C.PURL_MAX} characters, and lists that entry at its own place, with its name and the file's text`, () => {
      const r = M.FORMATS[format].read(content);
      assert.deepEqual(r.pinned.map((p) => p.purl), purls, format);
      assert.equal(r.not_checked.length, 1, JSON.stringify(r.not_checked).slice(0, 300));
      const [n] = r.not_checked;
      assert.deepEqual([n.reason, n.detail, n.line, n.name], ["unsupported_line", C.LONG_PURL_DETAIL, line, M.SPEC_MAX < name.length ? `${name.slice(0, M.SPEC_MAX - 1)}…` : name]);
      assert.ok(!n.spec.startsWith("pkg:"), `${format}: its spec is the purl, not the file's text: ${n.spec.slice(0, 80)}`);
    });
  }
  it("F3: the purl's length is counted as seg() and segPath() build it, for every ASCII character, two- to four-byte UTF-8, and a '/' in a name or a maven segment", () => {
    const cs = [...Array.from({ length: 128 }, (_, c) => String.fromCharCode(c)), "é", "ߧ", "一", "￿", "😀"];
    for (const c of cs) {
      for (const [n, at] of [[Math.floor(400 / 12), "under"], [600, "past"]]) {
        const v = c.repeat(n);
        const b = C.purlOf("npm", `@s/${v}`, v);
        const enc = (x) => encodeURIComponent(x).replace(/%2B/g, "+");
        const built = `pkg:npm/${`@s/${v}`.split("/").map(enc).join("/")}@${enc(v)}`;
        if (built.length <= C.PURL_MAX) assert.deepEqual(b, { purl: built }, `${JSON.stringify(c)} ${at}`);
        else assert.deepEqual(b, { why: C.LONG_PURL_DETAIL }, `${JSON.stringify(c)} ${at}: ${built.length}`);
        const m = C.purlOf("maven", [`g${v}`, `a${v}`], "1");
        const mb = `pkg:maven/${encodeURIComponent(`g${v}`).replace(/%2B/g, "+")}/${encodeURIComponent(`a${v}`).replace(/%2B/g, "+")}@1`;
        assert.deepEqual(m, mb.length <= C.PURL_MAX ? { purl: mb } : { why: C.LONG_PURL_DETAIL }, `maven ${JSON.stringify(c)} ${at}`);
      }
    }
  });
  it("F6: a go.mod replace whose replacement's purl is past PURL_MAX is not listed as applied: the require is listed, naming the replace", () => {
    const r = SM.readFiles({ files: [{ filename: "go.mod", content: `require example.com/a v1.0.0\nrequire golang.org/x/net v0.1.0\nreplace example.com/a => example.com/${"一".repeat(60)} v1.2.3\n` }] });
    assert.deepEqual([r.purls, r.replaced_total, r.files[0].replaced], [["pkg:golang/golang.org/x/net@v0.1.0"], 0, []]);
    assert.equal(r.not_checked.length, 1);
    assert.deepEqual([r.not_checked[0].name, r.not_checked[0].line, r.not_checked[0].reason], ["example.com/a", 1, "unsupported_line"]);
    assert.match(r.not_checked[0].detail, /^replaced by example\.com\/一{60} \(replace on line 3\): its purl, percent-encoded, is longer than the 512 characters the API takes: not read$/);
    // Control: a replacement whose purl fits is applied as before.
    const ok = SM.readFiles({ files: [{ filename: "go.mod", content: `require example.com/a v1.0.0\nreplace example.com/a => example.com/b v1.2.3\n` }] });
    assert.deepEqual([ok.purls, ok.files[0].replaced], [["pkg:golang/example.com/b@v1.2.3"], [{ from: "example.com/a@v1.0.0", to: "example.com/b@v1.2.3" }]]);
  });
  it("F7: a long-purl entry first in a file of 2,000 more is listed first, as the first of the 2,000 read", () => {
    const content = `a==${"%".repeat(200)}\n${Array.from({ length: 2_000 }, (_, i) => `p${i}>=1\n`).join("")}`;
    const r = SM.readFiles({ files: [{ filename: "requirements.txt", content }] });
    assert.deepEqual([r.not_checked.length, r.not_checked_total], [NOT_CHECKED_MAX, 2_001]);
    assert.deepEqual([r.not_checked[0].line, r.not_checked[0].name, r.not_checked[0].detail], [1, "a", C.LONG_PURL_DETAIL]);
    assert.equal(r.not_checked[0].spec, clipped(`a==${"%".repeat(200)}`));
    assert.equal(r.not_checked.at(-1).line, NOT_CHECKED_MAX);
  });
  const LONE_CASES = [
    ["requirements.txt", "django==4.2.7\na==1.0\ud800\nflask==2.0.0\n", "a"],
    ["go.mod", "require ok v1.0.0\nrequire a\ud800 v1.0.0\nrequire b v1.0.0\n", "a\ud800"],
    ["package-lock.json", '{"lockfileVersion":3,"packages":{"node_modules/ok":{"version":"1.0.0"},"node_modules/a":{"name":"\\ud800","version":"1.0.0"},"node_modules/b":{"version":"1.0.0"}}}', "\ud800"],
    ["Cargo.lock", `[[package]]\nname = "ok"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n\n[[package]]\nname = 'a\ud800'\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n`, "a\ud800"],
    ["poetry.lock", '[[package]]\nname = "ok"\nversion = "1.0.0"\n\n[[package]]\nname = "a"\nversion = "1.0\ud800"\n', "a"],
    ["Gemfile.lock", "GEM\n  specs:\n    ok (1.0.0)\n    a\ud800 (1.0.0)\n", "a\ud800"],
    ["composer.lock", '{"packages":[{"name":"v/ok","version":"1.0.0"},{"name":"v/\\udc00","version":"1.0.0"}]}', "v/\udc00"],
    ["gradle.lockfile", "g:ok:1.0.0=c\ng:a\ud800:1.0=c\n", "a\ud800"],
  ];
  for (const [format, content, name] of LONE_CASES) {
    it(`F4: ${format}: an entry holding a lone surrogate is listed unsupported_line, and the file's other entries are read`, () => {
      const r = SM.readFiles({ files: [{ filename: format, content }, { filename: "requirements.txt", content: "requests==2.31.0\n" }] });
      assert.equal(typeof r, "object", String(r));
      assert.equal(r.files[0].read, true, r.files[0].refused);
      assert.ok(r.purls.length >= 2, JSON.stringify(r.purls));
      assert.ok(r.purls.includes("pkg:pypi/requests@2.31.0"));
      assert.equal(r.not_checked.length, 1, JSON.stringify(r.not_checked));
      assert.deepEqual([r.not_checked[0].reason, r.not_checked[0].name], ["unsupported_line", name]);
      assert.match(r.not_checked[0].detail, LONE);
    });
  }
  it("F5: a file whose basename is __proto__, constructor, hasOwnProperty or toString is refused as a name this tool does not read, and the call's other files are read", () => {
    for (const f of ["__proto__", "src/constructor", "a/hasOwnProperty", "toString", "valueOf"]) {
      const d = M.detect(f);
      assert.equal(typeof d.refused, "string", f);
      assert.match(d.refused, /is not a file name this tool reads/, f);
      const r = SM.readFiles({ files: [{ filename: f, content: "x" }, { filename: "requirements.txt", content: "django==4.2.7\n" }] });
      assert.equal(typeof r.files[0].refused, "string", f);
      assert.deepEqual(r.purls, ["pkg:pypi/django@4.2.7"], f);
    }
  });
  it("F1, hosted, as its image starts it: after a Cargo.lock of [__proto__] hasOwnProperty, and one of __proto__.x, tools/list and a package-lock.json are answered as before", { skip: IMAGE_SKIP }, async () => {
    const api = await stubApi();
    const srv = await startServer(api.base);
    try {
      for (const content of ["[__proto__]\nhasOwnProperty = 1\n", "__proto__.x = 1\n", "[__proto__]\nlink = true\npackage = \"x\"\n"]) {
        const r = await post(srv.port, toolCall("scan_manifest", { files: [{ filename: "Cargo.lock", content }] }));
        assert.equal(r.status, 200, JSON.stringify(r).slice(0, 300));
        const sc = resultOf(r)?.structuredContent;
        assert.equal(sc?.state, "invalid_input", String(r.text).slice(0, 300));
        assert.match(sc.error.message, /a key named __proto__/);
      }
      const list = await post(srv.port, JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }));
      assert.equal(list.status, 200, String(list.text).slice(0, 300));
      assert.equal(resultOf(list)?.tools?.length, 16, String(list.text).slice(0, 300));
      const lock = JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/lodash": { version: "4.17.20" } } });
      const r = await post(srv.port, toolCall("scan_manifest", { files: [{ filename: "package-lock.json", content: lock }] }));
      const sc = resultOf(r)?.structuredContent;
      assert.equal(sc?.state, "measured", String(r.text).slice(0, 300));
      assert.deepEqual([sc.coverage.sent, sc.data.not_checked], [1, []]);
      await assertAlive(srv, "after the __proto__ files");
    } finally {
      await srv.stop();
      await api.close();
    }
  });
});

describe("#3434 the hosted endpoint, started as its image starts it, answers each such file and the next request", { skip: IMAGE_SKIP }, () => {
  let api;
  let srv;
  before(async () => {
    api = await stubApi();
    srv = await startServer(api.base);
  });
  after(async () => {
    await srv?.stop();
    await api?.close();
  });
  const answered = (r, what) => {
    assert.equal(r.status, 200, `${what}: ${JSON.stringify(r).slice(0, 300)}`);
    const result = resultOf(r);
    assert.ok(result?.structuredContent, `${what}: no structured result: ${String(r.text).slice(0, 300)}`);
    return result.structuredContent;
  };
  const call = async (files, { full, k = 1 } = {}) => {
    const body = toolCall("scan_manifest", { files, ...(full ? { full: true } : {}) });
    const what = `${files.map((f) => `${f.filename.slice(0, 40)} (${f.content.length} characters)`).join(", ")}${k > 1 ? `, ${k} at once` : ""}`;
    const rs = await Promise.all(Array.from({ length: k }, () => post(srv.port, body)));
    const scs = rs.map((r) => answered(r, what));
    await assertAlive(srv, what);
    return scs;
  };
  const scan = async (filename, content, opts) => (await call([{ filename, content }], opts))[0];
  const refusedWith = (sc, re) => {
    assert.equal(sc.state, "invalid_input", JSON.stringify(sc).slice(0, 300));
    assert.match(sc.error.message, re);
  };
  it("a go.mod with U+00A0, then single-line files of 4.9 million characters, then tools/list", async () => {
    const small = await scan("go.mod", "module example.com/app\n\ngo 1.21\n\nrequire (\n\tgithub.com/pkg/errors\u00a0v0.9.1\n)\n");
    assert.deepEqual(small.data.results.map((x) => x.purl), [ERRORS]);
    assert.deepEqual(small.data.not_checked, []);
    for (const [filename, content, detail] of [
      ["go.mod", `module m\n\ngo 1.22\n\nrequire "example.com/${"a".repeat(4_899_950)}" v1.0.0\n`, GOMOD_OVER],
      ["go.mod", `module m\n\ngo 1.22\n\nrequire${" a".repeat(2_449_990)}\n`, GOMOD_OVER],
      ["requirements.txt", `django==4.2.1${",==1".repeat(1_224_991)}\n`, REQ_LONG],
    ]) {
      const big = await scan(filename, content);
      assert.equal(big.data.not_checked.length, 1, `${filename}: ${JSON.stringify(big.data.not_checked).slice(0, 300)}`);
      assert.equal(big.data.not_checked[0].reason, "unsupported_line");
      assert.match(big.data.not_checked[0].detail, detail);
    }
    const list = await post(srv.port, JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }));
    assert.equal(list.status, 200);
    assert.ok(resultOf(list)?.tools?.some((t) => t.name === "scan_manifest"), String(list.text).slice(0, 300));
    await assertAlive(srv, "tools/list after them");
  });
  it("not_checked entries that would each repeat one long string of the file: a go.mod block's verb, a replace's directory or path, a Gemfile.lock section", async () => {
    for (const [filename, content] of [
      ["go.mod", `module m\n\ngo 1.21\n\n${"v".repeat(30_000)} (\n${"a\n".repeat(3_000)})\n`],
      ["go.mod", `module m\n\ngo 1.21\n\n${"v".repeat(5_500)} (\n${"a\n".repeat(5_500)})\n`],
      ["go.mod", `module m\n\ngo 1.21\n\nreplace a => ./${"d".repeat(12_000)}\n\nrequire (\n${"\ta v1\n".repeat(4_000)})\n`],
      ["go.mod", `module m\n\ngo 1.21\n\nreplace a => example.com/${"d".repeat(12_000)}\n\nrequire (\n${"\ta v1\n".repeat(4_000)})\n`],
      ["Gemfile.lock", `${"S".repeat(20_000)}\n  specs:\n${"    a (1)\n".repeat(2_000)}`],
    ]) {
      const sc = await scan(filename, content, { full: true });
      assert.equal(sc.data.not_checked.length, Math.min(NOT_CHECKED_MAX, sc.coverage.not_checked));
      for (const n of sc.data.not_checked) assert.ok(n.detail.length < 300, n.detail.slice(0, 100));
    }
  });
  // #3460: the issue's call, a package-lock.json whose one name is 4.9 million '/' (the hosted container ended, exit
  // 139), and its control of 'a': each answered, that entry not checked, the instance alive.
  it("#3460: a package-lock.json whose name is 4.9 million '/', and the same of 'a': answered, the entry not checked, the next request answered", async () => {
    for (const ch of ["/", "a"]) {
      const lock = `{"lockfileVersion":3,"packages":{"node_modules/x":{"name":"${ch.repeat(N3460)}","version":"1.0.0"},"node_modules/ok":{"version":"1.0.0"}}}`;
      const t0 = Date.now();
      const sc = await scan("package-lock.json", lock);
      assert.ok(Date.now() - t0 < 10_000, `${ch}: answered after ${Date.now() - t0} ms`);
      assert.equal(sc.state, "measured", `${ch}: ${JSON.stringify(sc).slice(0, 300)}`);
      assert.equal(sc.coverage.sent, 1, ch);
      assert.ok(sc.data.not_checked.some((n) => n.reason === "unsupported_line" && LONG.test(n.detail)), `${ch}: ${JSON.stringify(sc.data.not_checked).slice(0, 300)}`);
    }
  });
  it("a filename past 1,024 characters on 6,000 unpinned lines is refused, naming the bound; at 1,024, 20,000 such lines, two calls at once, are answered", async () => {
    refusedWith(await scan(`requirements-${"x".repeat(8_000)}.txt`, "a\n".repeat(6_000)), new RegExp(`files\\[0\\]\\.filename must be at most ${MAX_FILENAME_CHARS} characters long`));
    const name = `${"é".repeat(MAX_FILENAME_CHARS - "requirements.txt".length)}requirements.txt`;
    // Each entry's name and spec at their clip (240 characters each, shown as 200), its file's name at its bound.
    const lines = 20_000;
    for (const sc of await call([{ filename: name, content: `${"n".repeat(240)}\n`.repeat(lines) }], { full: true, k: 2 })) {
      assert.deepEqual([sc.coverage.not_checked, sc.data.not_checked.length], [lines, NOT_CHECKED_MAX]);
      assert.deepEqual([...new Set(sc.data.not_checked.map((n) => [n.file.length, n.name.length, n.spec.length].join()))], [`${MAX_FILENAME_CHARS},${SPEC_MAX},${SPEC_MAX}`]);
      const note = sc.notes.join(" ");
      assert.ok(note.includes(`data.not_checked lists the first ${NOT_CHECKED_MAX} read`), note.slice(0, 600));
      assert.ok(note.includes(`the other ${lines - NOT_CHECKED_MAX} are counted in coverage.not_checked_by_reason`), note.slice(0, 600));
    }
    const list = resultOf(await post(srv.port, JSON.stringify({ jsonrpc: "2.0", id: 3, method: "tools/list", params: {} })));
    const files = list.tools.find((t) => t.name === "scan_manifest").inputSchema.properties.files;
    assert.equal(files.items.properties.filename.maxLength, MAX_FILENAME_CHARS);
    assert.equal(files.items.properties.filename.pattern, "^[^\\x00-\\x1f\"]*$");
  });
  it("package-lock.json v1: many dependencies under one of a long name", async () => {
    const kids = (k) => Object.fromEntries(Array.from({ length: k }, (_, n) => [n.toString(36), {}]));
    for (const [p, k] of [[26_000, 3_000], [32_000, 3_600]]) {
      const sc = await scan("package-lock.json", JSON.stringify({ lockfileVersion: 1, dependencies: { ["a".repeat(p)]: { version: "1.0.0", dependencies: kids(k) } } }));
      // #3460: the parent's name is past NAME_MAX, so it is listed not checked, after every entry is read; through 3.1.5
      // it was pinned, its purl longer than any the API takes, and the whole call was refused for it.
      assert.equal(sc.state, "not_assessed", JSON.stringify(sc).slice(0, 300));
      assert.equal(sc.coverage.not_checked, k + 1);
      assert.equal(sc.data.not_checked.filter((n) => n.reason === "unsupported_line" && LONG.test(n.detail)).length, 1);
    }
  });
  it("Cargo.lock and poetry.lock strings of 4,999,000 characters with an escape every 4, two calls at once", async () => {
    const cargo = `[[package]]\nname = "smallvec"\nversion = "1.6.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "${"\\tab".repeat(1_249_750)}"\n`;
    for (const sc of await call([{ filename: "Cargo.lock", content: cargo }], { k: 2 })) assert.deepEqual(sc.data.results.map((x) => x.purl), ["pkg:cargo/smallvec@1.6.0"]);
    const poetry = `[[package]]\nname = "django"\nversion = "3.2.0"\ndescription = """${"\\tab".repeat(1_249_750)}"""\n`;
    for (const sc of await call([{ filename: "poetry.lock", content: poetry }], { k: 2 })) assert.deepEqual(sc.data.results.map((x) => x.purl), ["pkg:pypi/django@3.2.0"]);
  });
  it("a Cargo.lock with \\UFFFFFFFF, or arrays nested 30,000 deep, beside a go.mod: the go.mod is read and checked", async () => {
    const head = `[[package]]\nname = "smallvec"\nversion = "1.6.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n`;
    const gomod = { filename: "go.mod", content: "module m\n\ngo 1.21\n\nrequire github.com/pkg/errors v0.9.1\n" };
    for (const [content, why] of [[`${head}checksum = "\\UFFFFFFFF"\n`, "a bad unicode escape on line 5"], [`${head}x = ${"[".repeat(30_000)}${"]".repeat(30_000)}\n`, `arrays and inline tables nested more than ${NEST_MAX} deep on line 5`]]) {
      const [sc] = await call([{ filename: "Cargo.lock", content }, gomod]);
      assert.equal(sc.state, "measured", JSON.stringify(sc).slice(0, 300));
      assert.deepEqual(sc.data.manifest.files.map((f) => [f.read, f.refused]), [[false, `read as Cargo.lock, it is not TOML this reader can read: ${why}`], [true, null]]);
      assert.deepEqual(sc.data.results.map((x) => x.purl), [ERRORS]);
    }
  });
  it("a filename of 1,008 control characters on 2,000 lines, five calls in a row: each refused at the inputSchema; a lone surrogate by readFiles", async () => {
    const name = `${"\u0001".repeat(MAX_FILENAME_CHARS - "requirements.txt".length)}requirements.txt`;
    for (let k = 0; k < 5; k++) refusedWith(await scan(name, `${"n".repeat(240)}\n`.repeat(NOT_CHECKED_MAX)), /files\[0\]\.filename must hold no control character \(U\+0000 to U\+001F\), quote or lone surrogate/);
    refusedWith(await scan("a\ud800/requirements.txt", "a==1\n"), /^files\[0\]\.filename must hold no control character \(U\+0000 to U\+001F\), quote or lone surrogate/);
  });
  it("2,000 entries of control-character specs and verbs under a plain filename, and of quote specs under a filename of backslashes, two calls at once: answered", async () => {
    const ch = "\u0001";
    for (const sc of await call([{ filename: "go.mod", content: `module m\n\n${ch.repeat(240)} (\n${`${ch.repeat(240)}\n`.repeat(NOT_CHECKED_MAX)})\n` }], { full: true, k: 2 })) {
      assert.equal(sc.data.not_checked.length, NOT_CHECKED_MAX);
      for (const n of sc.data.not_checked) assert.ok(JSON.stringify(n.spec).length - 2 <= SPEC_MAX, JSON.stringify(n.spec).length);
    }
    const name = `${"\\".repeat(MAX_FILENAME_CHARS - "requirements.txt".length)}requirements.txt`;
    for (const sc of await call([{ filename: name, content: `${'"'.repeat(240)}\n`.repeat(NOT_CHECKED_MAX) }], { full: true, k: 2 })) assert.equal(sc.data.not_checked.length, NOT_CHECKED_MAX);
  });
  it("a dotted key, a table header and an inline table's key of 1,666,000 parts: unreadable, the process alive", async () => {
    for (const [open, close] of [["", " = 1\n"], ["[", "]\n"], ["[[", "]]\n"], ["x = {", " = 1}\n"]]) {
      // #3381: past the parse bound, so refused before it is read, saying what to do; of KEY_PARTS_MAX + 1 parts,
      // under it, refused at its 65th part.
      refusedWith(await scan("Cargo.lock", `${open}${"ab.".repeat(1_666_000)}a${close}`), new RegExp(`${TOML_DENSE.source}${HOSTED_HINT.source}`));
      refusedWith(await scan("Cargo.lock", `${open}${"ab.".repeat(KEY_PARTS_MAX)}a${close}`), new RegExp(`a dotted key of more than ${KEY_PARTS_MAX} parts on line 1$`));
    }
  });
  it(`20 Gemfile.locks of a real one's shape, ${MAX_MANIFEST_LINES} lines in all, two calls at once: answered, every purl checked`, async () => {
    for (const sc of await call(twenty(), { full: true, k: 2 })) assert.deepEqual([sc.state, sc.coverage.files_read, sc.data.results.length], ["measured", 20, 2 * 664]);
  });
  it("files past each per-call bound are refused, naming it", async () => {
    refusedWith(await scan("requirements.txt", "a==1\n".repeat(980_000)), PAST_LINES);
    refusedWith(await scan("go.mod", `module m\n\ngo 1.21\n\n${"require a v1.0.0\n".repeat(288_000)}`), PAST_LINES);
    refusedWith(await scan("Gemfile.lock", `PATH\n  specs:\n${"    a (1)\n".repeat(400_000)}`), PAST_LINES);
    refusedWith(await scan("package-lock.json", `{"lockfileVersion":1,"dependencies":{${Array.from({ length: 540_000 }, (_, k) => `"${k.toString(36)}":0`).join(",")}}}`), PAST_JSON);
    refusedWith(await scan("composer.lock", `{"packages":[${"{},".repeat(1_600_000)}{}]}`), PAST_JSON);
    // #3381: a TOML lockfile past MAX_TOML_VALUES under the parse bound is refused naming it; 3.1.3's own shapes past
    // it are past the parse bound too, which refuses them first (TOML values are counted as they are read).
    refusedWith(await scan("Cargo.lock", `x = [${"1,".repeat(MAX_TOML_VALUES)}1]\n`), PAST_TOML);
    refusedWith(await scan("poetry.lock", `x = [${"1,".repeat(MAX_TOML_VALUES)}1]\n`), PAST_TOML);
    refusedWith(await scan("Cargo.lock", "[[package]]\n".repeat(415_000)), new RegExp(`${TOML_DENSE.source}${HOSTED_HINT.source}`));
    refusedWith(await scan("poetry.lock", `x = [${"{},".repeat(1_600_000)}]\n`), new RegExp(`${TOML_DENSE.source}${HOSTED_HINT.source}`));
  });
  // #3381: the JSON and TOML shapes at the per-call bounds (the files 3.1.5 answered) are past the parse bound, so
  // unreadable before they are read, saying what to do; each is answered, two calls at once, at the most entries the
  // endpoint's reservation takes (the body's estimate and the read's, together at most what one request may hold,
  // the parse within the parse bound), and refused from a twentieth more. What bounds them is the estimate: their parse
  // is estimated at 1.5 to 8.5 times what it retains (each of 3.1.3's at-bound shapes 10 to 27 MB measured), and each
  // entry is reserved as a purl kept though these are not checked, of which the answer keeps 2,000; every real
  // lockfile measured is read (parseBudget.ts WEIGHT_MANIFEST_ENTRY, scan_manifest.ts HOSTED_READS).
  const dense = [
    ["package-lock.json", (n) => `{"lockfileVersion":1,"dependencies":{${Array.from({ length: n }, (_, k) => `"${k.toString(36)}":0`).join(",")}}}`, MAX_JSON_VALUES - 4, 51_000],
    ["package-lock.json", (n) => `{"lockfileVersion":3,"packages":{${Array.from({ length: n }, (_, k) => `"node_modules/${k.toString(36)}":{}`).join(",")}}}`, Math.floor((MAX_JSON_VALUES - 5) / 2), 46_000],
    ["Cargo.lock", (n) => '[[package]]\nname="a"\n'.repeat(n), MAX_TOML_VALUES / 2 - 1, 28_500],
    ["poetry.lock", (n) => `x = [${"{},".repeat(n)}]\n`, MAX_TOML_VALUES - 2, 145_000],
  ];
  const IMAGE = B.budgetsFor(B.IMAGE_HEAP_LIMIT);
  const MOST = IMAGE.inflightBytes - Math.floor(IMAGE.inflightBytes / 4);
  const reserved = (filename, content) => {
    const args = { files: [{ filename, content }] };
    const parse = filename.endsWith(".json") ? B.documentCost(content).bytes : B.tomlEstimate(content);
    return { parse, held: B.scanJson(Buffer.from(toolCall("scan_manifest", args))).estimate + SM.manifestEstimate(args, IMAGE) };
  };
  it("files at each per-call bound, two calls at once, are answered: the line formats'; the JSON and TOML ones are past the parse bound, and are answered at the most the endpoint holds", async () => {
    const at = [
      ["requirements.txt", "a\n".repeat(MAX_MANIFEST_LINES)],
      ["go.mod", `module m\n\ngo 1.21\n\nreplace a => example.com/${"d".repeat(400)} v1.0.0\n\nrequire (\n${"\ta v1\n".repeat(MAX_MANIFEST_LINES - 6)})\n`],
    ];
    for (const [filename, content] of at) for (const sc of await call([{ filename, content }], { k: 2 })) assert.notEqual(sc.state, "invalid_input", `${filename}: ${sc.error?.message}`);
    for (const [filename, build, atBound, most] of dense) {
      assert.ok(reserved(filename, build(atBound)).parse > IMAGE.parseBytes, `${filename} at the bound: under the parse bound`);
      for (const sc of await call([{ filename, content: build(atBound) }], { k: 2 })) refusedWith(sc, new RegExp(`${(filename.endsWith(".json") ? JSON_DENSE : TOML_DENSE).source}${HOSTED_HINT.source}`));
      const r = reserved(filename, build(most));
      assert.ok(r.parse <= IMAGE.parseBytes && r.held <= MOST, `${filename} of ${most}: ${JSON.stringify(r)}, past ${MOST}`);
      const past = reserved(filename, build(Math.ceil(most * 1.05)));
      assert.ok(past.parse > IMAGE.parseBytes || past.held > MOST, `${filename} of ${Math.ceil(most * 1.05)}: ${JSON.stringify(past)}, within the bounds`);
      for (const sc of await call([{ filename, content: build(most) }], { k: 2 })) assert.notEqual(sc.state, "invalid_input", `${filename} of ${most}: ${sc.error?.message}`);
    }
  });
});

// Round 11 (the round-10 verify's d2 F8, N1, N2).
describe("round 11: blank requirements.txt lines, a Gemfile.lock's long version, a lockfileVersion past a double", () => {
  it("requirements.txt: blank lines are passed over before any pattern runs, and read as they did", () => {
    const body = "requests==2.31.0\n\n   \n\t\nflask==3.0.0 \\\n\n  # c\ndjango==5.0\n";
    const out = M.readFile("requirements.txt", body);
    // As round 10 read it (the same output with the early return taken out): each entry at its own line, the
    // continuation's blank line joined to it, the comment line nothing.
    assert.deepEqual(out.pinned, [{ purl: "pkg:pypi/requests@2.31.0", line: 1 }, { purl: "pkg:pypi/flask@3.0.0", line: 5 }, { purl: "pkg:pypi/django@5.0", line: 8 }]);
    assert.deepEqual(out.not_checked, []);
    // Millions of blank lines cost within twenty times what as many characters on one line do, not a hundredfold
    // (measured: 2,000,000 blank lines about 20 ms, one line of as many characters about 1.5 ms; round 10 about 200 ms).
    const time = (t) => { let best = Infinity; for (let k = 0; k < 3; k++) { const t0 = process.hrtime.bigint(); M.readFile("requirements.txt", t); best = Math.min(best, Number(process.hrtime.bigint() - t0) / 1e6); } return best; };
    const blank = time("\n".repeat(2_000_000));
    const oneLine = time(`a${" ".repeat(1_999_999)}`);
    assert.ok(blank < 20 * oneLine + 50, `2,000,000 blank lines took ${blank.toFixed(1)} ms, one line of as many characters ${oneLine.toFixed(1)} ms`);
  });
  it("Gemfile.lock: a spec whose version is past NAME_MAX is listed by its name, clipped as other readers clip it", () => {
    const out = M.readFile("Gemfile.lock", `GEM\n  specs:\n    rails (${"1".repeat(600)})\n`);
    const nc = out.not_checked.find((n) => n.reason === "unsupported_line");
    assert.equal(nc?.name, "rails", JSON.stringify(nc));
  });
  it("package-lock.json: a lockfileVersion of 1e400 is named as a number past what a double holds, not as null", () => {
    for (const lv of ["1e400", "-1e400"]) {
      const u = M.readFile("package-lock.json", `{"lockfileVersion":${lv}}`).unreadable;
      assert.match(u ?? "", /has lockfileVersion a number past what a double holds and no packages object/, lv);
      assert.doesNotMatch(u ?? "", /lockfileVersion null/, lv);
    }
    assert.match(M.readFile("package-lock.json", '{"lockfileVersion":null}').unreadable ?? "", /has lockfileVersion null and no packages object/);
  });
});
