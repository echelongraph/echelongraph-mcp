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
const files = JSON.parse(process.env.MANIFEST_CASE).map(({ filename, segments }) => ({ filename, content: segments.map(([s, n]) => s.repeat(n)).join("") }));
const t0 = performance.now();
const r = readFiles({ files });
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
 *  under a timeout. `refused`: the call may be refused (else a refusal fails the case). */
function readAllInChild(files, { flags = FLAGS, refused = false } = {}) {
  const chars = files.reduce((n, f) => n + f.segments.reduce((k, [s, times]) => k + s.length * times, 0), 0);
  const what = files.map((f) => f.filename).join(", ");
  assert.ok(chars <= MAX_CHARS, `${what}: the case's files are ${chars} characters, past what scan_manifest reads`);
  const r = spawnSync(process.execPath, [...flags, "--input-type=module", "-e", CHILD], {
    env: { ...process.env, SCAN_MANIFEST_JS, MANIFEST_CASE: JSON.stringify(files) },
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
const ERRORS = "pkg:golang/github.com/pkg/errors@v0.9.1";
// A string of `n` characters as an entry shows it, past SPEC_MAX: its first SPEC_MAX - 1, then "…".
const clipped = (s) => (s.length > SPEC_MAX ? `${s.slice(0, SPEC_MAX - 1)}…` : s);
// The refusals past each per-call bound, naming it (scan_manifest.ts pastBound).
// #3434: counted per call, each file's count listed, the last the file that passed the bound.
const PAST_LINES = new RegExp(`^the go\\.mod, requirements\\.txt, Gemfile\\.lock and gradle\\.lockfile files hold more than ${MAX_MANIFEST_LINES} lines in all, counted per call \\(blank and comment lines are not counted\\): .+ when the bound was passed; at most ${MAX_MANIFEST_LINES} are read per call, so no file is read`);
const PAST_JSON = new RegExp(`^the package-lock\\.json and composer\\.lock files hold more than ${MAX_JSON_VALUES} objects, arrays and entries in all, counted per call \\(counted before each file is parsed\\): .+ when the bound was passed; at most ${MAX_JSON_VALUES} are read per call`);
const PAST_TOML = new RegExp(`^the Cargo\\.lock and poetry\\.lock files hold more than ${MAX_TOML_VALUES} tables, array entries and keys in all, counted per call: .+ when the bound was passed; at most ${MAX_TOML_VALUES} are read per call`);
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
    const path = (n) => `example.com/${"p".repeat(n - "require example.com/ v1.0.0".length)}`;
    const fits = readInChild("go.mod", [[`${head}\t\trequire ${path(GOMOD_LINE_MAX)} v1.0.0\n`, 1]]);
    assert.deepEqual(fits.not_checked, []);
    assert.equal(fits.purls.length, 1);
    assert.equal(fits.purls[0].length, `pkg:golang/${path(GOMOD_LINE_MAX)}@v1.0.0`.length);
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
      const out = readInChild("Cargo.lock", [[open, 1], ["ab.", 1_666_000], [`a${close}`, 1]], { refused: true });
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
    assert.deepEqual(out.not_checked.map((n) => [n.reason, n.name_chars, n.spec_chars]), [["local_path", SPEC_MAX, SPEC_MAX]]);
  });
  it("package-lock.json v1: 1,999 dependencies under a 4,900,000-character one: each spec is the first 199 characters of its install path, read in linear time", () => {
    const kids = Array.from({ length: NOT_CHECKED_MAX - 1 }, (_, k) => `"k${k}":{}`).join(",");
    const out = readInChild("package-lock.json", [['{"lockfileVersion":1,"dependencies":{"', 1], ["a", 4_900_000], [`":{"version":"1.0.0","dependencies":{${kids}}}}}`, 1]]);
    assert.equal(out.not_checked.length, NOT_CHECKED_MAX - 1);
    const spec = clipped(`node_modules/${"a".repeat(SPEC_MAX)}`);
    for (const n of out.not_checked) assert.deepEqual([n.spec, n.spec_chars, n.reason], [spec.slice(0, 60), SPEC_MAX, "version_unresolved"]);
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
      // The parent itself is pinned, its purl longer than any the API takes: the call says so, after reading every entry.
      refusedWith(sc, /^purl 1 is longer than 512 characters/);
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
      refusedWith(await scan("Cargo.lock", `${open}${"ab.".repeat(1_666_000)}a${close}`), new RegExp(`a dotted key of more than ${KEY_PARTS_MAX} parts on line 1$`));
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
    refusedWith(await scan("Cargo.lock", "[[package]]\n".repeat(415_000)), PAST_TOML);
    refusedWith(await scan("poetry.lock", `x = [${"{},".repeat(1_600_000)}]\n`), PAST_TOML);
  });
  it("files at each per-call bound, two calls at once, are answered", async () => {
    const at = [
      ["requirements.txt", "a\n".repeat(MAX_MANIFEST_LINES)],
      ["go.mod", `module m\n\ngo 1.21\n\nreplace a => example.com/${"d".repeat(400)} v1.0.0\n\nrequire (\n${"\ta v1\n".repeat(MAX_MANIFEST_LINES - 6)})\n`],
      ["package-lock.json", `{"lockfileVersion":1,"dependencies":{${Array.from({ length: MAX_JSON_VALUES - 4 }, (_, k) => `"${k.toString(36)}":0`).join(",")}}}`],
      ["package-lock.json", `{"lockfileVersion":3,"packages":{${Array.from({ length: Math.floor((MAX_JSON_VALUES - 5) / 2) }, (_, k) => `"node_modules/${k.toString(36)}":{}`).join(",")}}}`],
      ["Cargo.lock", '[[package]]\nname="a"\n'.repeat(MAX_TOML_VALUES / 2 - 1)],
      ["poetry.lock", `x = [${"{},".repeat(MAX_TOML_VALUES - 2)}]\n`],
    ];
    for (const [filename, content] of at) for (const sc of await call([{ filename, content }], { k: 2 })) assert.notEqual(sc.state, "invalid_input", `${filename}: ${sc.error?.message}`);
  });
});
