// scan_manifest (#2835): each manifest reader on real lockfiles, then the tool end to end against a
// stub of POST /api/v1/public/cves/match/batch, over both protocol eras, every structured result
// validated against the tool's advertised outputSchema by ajv.
//
// Fixtures (fixtures/manifests/), each written by the ecosystem's own tool on 2026-10-05 into a
// scratch project (lock-only: nothing was installed), except where noted:
//   tree.v{1,2,3}.package-lock.json  npm 10.9.4 `npm install --package-lock-only --lockfile-version N`
//       of one package.json: lodash 4.17.15, express 4.17.1 (ms nested under send), @babel/code-frame
//       7.12.13, the alias lodash-latest = npm:lodash@4.17.21, a file: dependency (local-pkg) and a
//       github: one (is-number). The same tree in all three versions.
//   lodash-4.17.15.package-lock.json, lodash-4.17.21.package-lock.json  the same, lodash alone.
//   fixture.go.mod  go 1.24 `go mod init`, `go get golang.org/x/net@v0.7.0 github.com/pkg/errors@v0.9.1`,
//       then `go mod edit`: a single-line require replaced by ./localmod, a tab-indented require of
//       golang.org/x/crypto with no comment that an exclude names, and github.com/pkg/errors replaced
//       by github.com/go-errors/errors v1.4.2.
//   Cargo.v3.lock, Cargo.v4.lock  cargo 1.97 `cargo generate-lockfile` (v3 with rust-version 1.70):
//       smallvec =1.6.0, time =0.1.43 (and their dependencies), a path crate and a git crate.
//   poetry.lock  Poetry 2.1.1 `poetry lock`: django 3.2.0, requests 2.31.0, attrs from git, and a
//       directory dependency.
//   Gemfile.lock  Bundler 4.0.17 `bundle lock` for x86_64-linux and five other platforms:
//       nokogiri 1.16.2 (one spec per platform), rack 2.2.3, a PATH gem and a GIT gem.
//   composer.lock  Composer `composer update --no-install`: guzzlehttp/psr7 1.8.2, symfony/polyfill-ctype
//       v1.27.0, doctrine/instantiator 1.5.0 (require-dev) and a path repository package.
//   gradle.lockfile  Gradle `gradle dependencies --write-locks`: log4j-core 2.14.1, junit 4.13.1.
//   requirements.txt  written by hand in pip's requirements file format, one line per case.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { AjvJsonSchemaValidator } from "@modelcontextprotocol/server/validators/ajv";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { PKG_DIR, serverCommand } from "./server-under-test.mjs";
import { BATCH_PATH, ROWS, batchAnswer } from "./fixtures/match-batch.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name) => fs.readFileSync(path.join(HERE, "fixtures", "manifests", name), "utf8");
const dist = (f) => pathToFileURL(path.join(PKG_DIR, "dist", f)).href;
const M = await import(dist("tools/manifests/index.js"));
const { readToml } = await import(dist("tools/manifests/toml.js"));
const SM = await import(dist("tools/scan_manifest.js"));
const TOOL = "scan_manifest";

const read = (format, text) => {
  const r = M.readFile(format, text);
  assert.ok(!("unreadable" in r), `${format}: ${r.unreadable}`);
  return r;
};
const purls = (r) => r.pinned.map((p) => p.purl);
const distinct = (r) => [...new Set(purls(r))].sort();
const missed = (r) => r.not_checked.map((n) => `${n.reason}:${n.name}`);

// ── The readers ──

describe("#2835 package-lock.json and npm-shrinkwrap.json", () => {
  const v = [1, 2, 3].map((n) => read("package-lock.json", fixture(`tree.v${n}.package-lock.json`)));
  it("lockfileVersion 1, 2 and 3 of the same tree give the same purls", () => {
    assert.equal(distinct(v[0]).length, 64);
    assert.deepEqual(distinct(v[0]), distinct(v[1]));
    assert.deepEqual(distinct(v[1]), distinct(v[2]));
  });
  it("the name is what follows the last node_modules/ (a nested ms), or the entry's own (an alias), scopes encoded", () => {
    const p = distinct(v[2]);
    for (const want of ["pkg:npm/lodash@4.17.15", "pkg:npm/lodash@4.17.21", "pkg:npm/ms@2.0.0", "pkg:npm/ms@2.1.1", "pkg:npm/%40babel/code-frame@7.12.13", "pkg:npm/express@4.17.1"]) assert.ok(p.includes(want), want);
    assert.ok(!p.some((x) => x.includes("lodash-latest")), "the alias's folder name is not a package");
    assert.ok(!p.some((x) => x.includes("send/node_modules")));
  });
  it("the root entry is skipped and counted; a link, a workspace member and a git dependency are listed, never sent", () => {
    assert.deepEqual([v[1].skipped, v[2].skipped], [1, 1]);
    assert.deepEqual(missed(v[2]).sort(), ["local_path:local-pkg", "local_path:local-pkg", "vcs_source:is-number"]);
    assert.deepEqual(missed(v[0]).sort(), ["local_path:local-pkg", "vcs_source:is-number"]);
    for (const r of v) assert.ok(!purls(r).some((x) => /is-number|local-pkg/.test(x)));
  });
  it("an entry without a version is version_unresolved; text that is not JSON is unreadable, not empty", () => {
    const r = read("package-lock.json", JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/x": { resolved: "https://registry.npmjs.org/x/-/x-1.0.0.tgz" } } }));
    assert.deepEqual(missed(r), ["version_unresolved:x"]);
    assert.match(M.readFile("package-lock.json", "{ not json").unreadable, /is not JSON/);
    assert.match(M.readFile("package-lock.json", JSON.stringify({ lockfileVersion: 3 })).unreadable, /no packages object/);
  });
  it("a byte-order mark and CRLF line ends, as Windows editors write them, read the same", () => {
    const text = fixture("lodash-4.17.15.package-lock.json");
    assert.deepEqual(purls(read("package-lock.json", `\uFEFF${text.replace(/\n/g, "\r\n")}`)), ["pkg:npm/lodash@4.17.15"]);
    assert.deepEqual(purls(read("requirements.txt", "\uFEFFDjango==3.2.0\r\nflask\r\n")), ["pkg:pypi/django@3.2.0"]);
    assert.deepEqual(purls(read("Cargo.lock", fixture("Cargo.v4.lock").replace(/\n/g, "\r\n"))), purls(read("Cargo.lock", fixture("Cargo.v4.lock"))));
  });
  it("both polarities: lodash 4.17.15's lock pins lodash@4.17.15, and 4.17.21's does not", () => {
    assert.deepEqual(purls(read("package-lock.json", fixture("lodash-4.17.15.package-lock.json"))), ["pkg:npm/lodash@4.17.15"]);
    assert.deepEqual(purls(read("package-lock.json", fixture("lodash-4.17.21.package-lock.json"))), ["pkg:npm/lodash@4.17.21"]);
  });
});

describe("#2835 go.mod", () => {
  const r = read("go.mod", fixture("fixture.go.mod"));
  it("block and single-line requires, // indirect included, a tab-indented one with no comment read", () => {
    assert.ok(purls(r).includes("pkg:golang/golang.org/x/net@v0.7.0"), "an indirect require in a block");
    assert.equal(r.pinned.find((p) => p.purl === "pkg:golang/golang.org/x/net@v0.7.0").line, 10);
  });
  it("replace to a module checks the replacement, never the module required", () => {
    assert.ok(purls(r).includes("pkg:golang/github.com/go-errors/errors@v1.4.2"));
    assert.ok(!purls(r).some((p) => p.includes("pkg/errors")), "the replaced module was sent");
    assert.deepEqual(r.replaced, [{ from: "github.com/pkg/errors@v0.9.1", to: "github.com/go-errors/errors@v1.4.2" }]);
  });
  it("replace to a local path is local_path; a require of an excluded version is version_unresolved", () => {
    assert.deepEqual(missed(r).sort(), ["local_path:example.com/localmod", "version_unresolved:golang.org/x/crypto"]);
    assert.deepEqual(purls(r).sort(), ["pkg:golang/github.com/go-errors/errors@v1.4.2", "pkg:golang/golang.org/x/net@v0.7.0"]);
    assert.deepEqual(r.notes, [], "go 1.24 needs no partial-coverage note");
  });
  it("a version-specific replace wins over one for every version, and applies to that version only", () => {
    const g = read("go.mod", "module m\n\ngo 1.21\n\nrequire (\n\ta.example/x v1.0.0\n\tb.example/y v2.0.0\n)\n\nreplace a.example/x => c.example/x v1.1.0\nreplace a.example/x v1.0.0 => d.example/x v1.2.0\nreplace b.example/y v1.0.0 => ../y\n");
    assert.deepEqual(purls(g), ["pkg:golang/d.example/x@v1.2.0", "pkg:golang/b.example/y@v2.0.0"]);
  });
  it("a go directive below 1.17, or none, carries the partial-coverage note; quoted paths and +incompatible are read", () => {
    const old = read("go.mod", 'module m\ngo 1.16\nrequire "github.com/Azure/go-autorest" v14.2.0+incompatible\n');
    assert.deepEqual(purls(old), ["pkg:golang/github.com/Azure/go-autorest@v14.2.0+incompatible"]);
    assert.match(old.notes[0], /go directive is 1\.16, below 1\.17/);
    assert.match(read("go.mod", "module m\nrequire a.example/x v1.0.0\n").notes[0], /no go directive, which the go command reads as go 1\.16/);
  });
  it("go.sum is refused by name; its text read as go.mod sends nothing", () => {
    assert.match(M.detect("svc/go.sum").refused, /^go\.sum is refused: .*not the version the build selects: pass go\.mod$/);
    const sum = read("go.mod", "golang.org/x/sys v0.1.0 h1:kunALQeHf1/185U1i0GOB/textB6sWxTV7rJeFEgaF3MI=\ngolang.org/x/sys v0.1.0/go.mod h1:oPkhp1MJrh7nUepCBck5+mAzfO9JrbApNNgaTdGDITg=\n");
    assert.deepEqual(purls(sum), []);
    assert.deepEqual(sum.not_checked.map((n) => n.reason), ["unsupported_line", "unsupported_line"]);
  });
  it("both polarities: x/net v0.7.0 is sent at v0.7.0, and a go.mod at v0.17.0 sends v0.17.0", () => {
    assert.ok(purls(read("go.mod", fixture("fixture.go.mod").replace("golang.org/x/net v0.7.0", "golang.org/x/net v0.17.0"))).includes("pkg:golang/golang.org/x/net@v0.17.0"));
  });
});

describe("#2835 requirements.txt", () => {
  const r = read("requirements.txt", fixture("requirements.txt"));
  const by = Object.fromEntries(r.not_checked.map((n) => [n.spec.split(/\s/)[0], n]));
  it("only == and === pins are sent: extras and markers stripped, --hash ignored, names PEP 503-normalised", () => {
    assert.deepEqual(purls(r), ["pkg:pypi/django@3.2.0", "pkg:pypi/requests@2.31.0", "pkg:pypi/urllib3@1.26.5", "pkg:pypi/typing-extensions@4.7.1"]);
    assert.equal(r.pinned[0].line, 7, "a continued line is numbered by its first line");
  });
  it("ranges, wildcards and a bare name are version_unpinned, and no bound is ever sent as a version", () => {
    for (const spec of ["django-filter>=4", "celery~=5.3.0", "pyyaml==6.0.*", "numpy>=1.24,<2", "flask"]) assert.equal(by[spec]?.reason, "version_unpinned", spec);
    for (const bad of ["pkg:pypi/django-filter@4", "pkg:pypi/celery@5.3.0", "pkg:pypi/numpy@1.24", "pkg:pypi/pyyaml@6.0.*"]) assert.ok(!purls(r).includes(bad), bad);
  });
  it("-r and -c are unsupported_line; -e, VCS, file and URL requirements are vcs_source, local_path or unsupported_line", () => {
    assert.deepEqual(
      r.not_checked.map((n) => `${n.line}:${n.reason}:${n.name}`),
      [
        "4:unsupported_line:null", "5:unsupported_line:null", "12:version_unpinned:django-filter", "13:version_unpinned:celery", "14:version_unpinned:pyyaml", "15:version_unpinned:numpy",
        "16:vcs_source:click", "17:local_path:null", "18:vcs_source:attrs", "19:local_path:mytool", "20:unsupported_line:null", "21:local_path:null", "22:version_unpinned:flask",
      ],
    );
  });
  it("control: django>=4 alone sends nothing and lists the line", () => {
    const d = read("requirements.txt", "django>=4\n");
    assert.deepEqual([purls(d), missed(d)], [[], ["version_unpinned:django"]]);
  });
});

describe("#2835 Cargo.lock", () => {
  const v3 = read("Cargo.lock", fixture("Cargo.v3.lock"));
  const v4 = read("Cargo.lock", fixture("Cargo.v4.lock"));
  it("v3 and v4 give the same purls, each crate read from its own [[package]] table", () => {
    assert.deepEqual(purls(v3), purls(v4));
    assert.ok(purls(v4).includes("pkg:cargo/smallvec@1.6.0"));
    assert.ok(purls(v4).includes("pkg:cargo/time@0.1.43"));
    for (const p of purls(v4)) assert.match(p, /^pkg:cargo\/[a-z0-9_-]+@\d+\.\d+\.\d+$/);
  });
  it("a crate without a source (the project, a path crate) is local_path, a git crate vcs_source", () => {
    assert.deepEqual(missed(v4).sort(), ["local_path:localcrate", "local_path:scan-manifest-fixture", "vcs_source:semver"]);
  });
  it("control (docs/SBOM_COVERAGE_PROGRAM.md row 46): a [[package]] without a version is not paired with the next one's", () => {
    const r = read("Cargo.lock", 'version = 4\n\n[[package]]\nname = "a"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n\n[[package]]\nname = "b"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n');
    assert.deepEqual([purls(r), missed(r)], [["pkg:cargo/b@1.0.0"], ["version_unresolved:a"]]);
  });
});

describe("#2835 poetry.lock, Gemfile.lock, composer.lock, gradle.lockfile", () => {
  it("poetry.lock: PyPI packages sent, a git source vcs_source, a directory local_path", () => {
    const r = read("poetry.lock", fixture("poetry.lock"));
    assert.ok(purls(r).includes("pkg:pypi/django@3.2"));
    assert.ok(purls(r).includes("pkg:pypi/requests@2.31.0"));
    assert.deepEqual(missed(r).sort(), ["local_path:localpkg", "vcs_source:attrs"]);
  });
  it("Gemfile.lock: one purl per gem whatever its platforms, PATH local_path, GIT vcs_source", () => {
    const r = read("Gemfile.lock", fixture("Gemfile.lock"));
    assert.equal(purls(r).filter((p) => p === "pkg:gem/nokogiri@1.16.2").length, 6, "one spec per platform, each its suffix stripped");
    assert.deepEqual(distinct(r), ["pkg:gem/nokogiri@1.16.2", "pkg:gem/racc@1.8.1", "pkg:gem/rack@2.2.3"]);
    assert.deepEqual(missed(r).sort(), ["local_path:localgem", "vcs_source:rainbow"]);
  });
  it("composer.lock: packages and packages-dev, the leading v stripped, a path package local_path, a branch version_unresolved", () => {
    const r = read("composer.lock", fixture("composer.lock"));
    assert.deepEqual(distinct(r), ["pkg:composer/doctrine/instantiator@1.5.0", "pkg:composer/guzzlehttp/psr7@1.8.2", "pkg:composer/psr/http-message@1.1", "pkg:composer/ralouphie/getallheaders@3.0.3", "pkg:composer/symfony/polyfill-ctype@1.27.0"]);
    assert.deepEqual(missed(r), ["local_path:fixture/local-lib"]);
    assert.deepEqual(missed(read("composer.lock", JSON.stringify({ packages: [{ name: "a/b", version: "dev-main" }, { name: "a/c", version: "2.x-dev" }] }))), ["version_unresolved:a/b", "version_unresolved:a/c"]);
  });
  it("gradle.lockfile: group:artifact:version lines as Maven purls, empty= skipped; the older per-configuration lockfile too", () => {
    const r = read("gradle.lockfile", fixture("gradle.lockfile"));
    assert.deepEqual(purls(r), ["pkg:maven/junit/junit@4.13.1", "pkg:maven/org.apache.logging.log4j/log4j-api@2.14.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "pkg:maven/org.hamcrest/hamcrest-core@1.3"]);
    assert.deepEqual(r.not_checked, []);
    assert.equal(M.detect("gradle/dependency-locks/compileClasspath.lockfile").format, "gradle.lockfile");
    assert.deepEqual(purls(read("gradle.lockfile", "# c\norg.yaml:snakeyaml:1.33\n")), ["pkg:maven/org.yaml/snakeyaml@1.33"]);
  });
});

describe("#2835 the TOML reader", () => {
  it("reads strings with escapes, multi-line strings, inline tables, arrays across lines and dotted headers", () => {
    const { root } = readToml(
      [
        'a = "x\\ty\\u00e9"', "b = 'C:\\path'", 'c = """', 'one\\', '   two""""', "d = [", '  "p", # comment', "  'q',", "]", "e = { f = 1, g.h = true }",
        "[t.u]", "v = 1_000", "[[arr]]", "w = 1979-05-27T07:32:00Z", "[[arr]]", "w = -2.5e3", "[arr.sub]", 'x = "in last"',
      ].join("\n"),
    );
    assert.deepEqual(root, { a: "x\tyé", b: "C:\\path", c: 'onetwo"', d: ["p", "q"], e: { f: 1, g: { h: true } }, t: { u: { v: 1000 } }, arr: [{ w: "1979-05-27T07:32:00Z" }, { w: -2500, sub: { x: "in last" } }] });
  });
  it("text it cannot read is refused with its line, never read as holding no package", () => {
    assert.match(M.readFile("Cargo.lock", '[[package]]\nname = "a"\nversion = \n').unreadable, /is not TOML this reader can read: .* on line 3/);
    assert.match(M.readFile("poetry.lock", '[[package]\nname = "a"\n').unreadable, /an unclosed table header on line 1/);
  });
});

describe("#2835 which reader a file goes to", () => {
  it("by basename, wherever the file sits", () => {
    const cases = {
      "requirements.txt": "requirements.txt", "requirements/dev.txt": undefined, "requirements-dev.txt": "requirements.txt", "svc/go.mod": "go.mod",
      "npm-shrinkwrap.json": "package-lock.json", "C:\\app\\package-lock.json": "package-lock.json", "Cargo.lock": "Cargo.lock", "gems.locked": "Gemfile.lock",
      "composer.lock": "composer.lock", "poetry.lock": "poetry.lock", "gradle.lockfile": "gradle.lockfile",
    };
    for (const [f, want] of Object.entries(cases)) assert.equal(M.detect(f).format, want, f);
  });
  it("a manifest of ranges is refused with the lockfile to pass; a format not read yet says so", () => {
    const want = {
      "package.json": /pass package-lock\.json/, "pyproject.toml": /pass poetry\.lock/, Pipfile: /pipenv requirements/, Gemfile: /pass Gemfile\.lock/, "Cargo.toml": /pass Cargo\.lock/,
      "composer.json": /pass composer\.lock/, "build.gradle": /pass gradle\.lockfile/, "build.gradle.kts": /pass gradle\.lockfile/, "go.sum": /^go\.sum is refused/,
      "pom.xml": /effective POM/, "yarn.lock": /not read yet/, "pnpm-lock.yaml": /not read yet/, "notes.md": /not a file name this tool reads/,
    };
    for (const [f, re] of Object.entries(want)) assert.match(M.detect(f).refused, re, f);
  });
});

// ── The tool, end to end ──

// The stub's verdicts, by purl: the ticket's two pairs, each in both polarities.
const STUB = {
  "pkg:npm/lodash@4.17.15": ["CVE-2020-8203", "CVE-2021-23337"],
  "pkg:golang/golang.org/x/net@v0.7.0": ["CVE-2023-44487"],
};
function answerFor(list) {
  return batchAnswer(list.map((p, i) => (STUB[p] ? ROWS.affected(i, p, p.split("/").pop().split("@")[0], p.split("@").pop(), STUB[p]) : ROWS.notAffected(i, p, "x", "1"))));
}

async function startStub() {
  const state = { requests: [], plan: {} };
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      state.requests.push({ method: req.method, url: req.url, headers: req.headers, body });
      const planned = state.plan[state.requests.length];
      if (planned) {
        res.writeHead(planned.status, { "content-type": "application/json", ...(planned.headers ?? {}) });
        return res.end(JSON.stringify(planned.body ?? {}));
      }
      if (req.url !== BATCH_PATH || req.method !== "POST") {
        res.writeHead(404, { "content-type": "text/plain" });
        return res.end("404 page not found\n");
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(answerFor(JSON.parse(body).components.map((c) => c.purl))));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { state, base: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((r) => server.close(r)) };
}

const textBlocks = (res) => (res.content ?? []).filter((c) => c.type === "text").map((c) => c.text);
const noteOf = (res) => textBlocks(res)[res.isError ? 0 : 1] ?? "";
const validator = new AjvJsonSchemaValidator();
const lock = (name) => ({ filename: "package-lock.json", content: fixture(name) });

for (const era of [MODERN, "2025-06-18"]) {
  describe(`#2835 scan_manifest [${era}]`, () => {
    let stub, client, tool;
    const collected = [];
    const call = async (args) => {
      const res = await client.callTool({ name: TOOL, arguments: args });
      collected.push([args, res]);
      return res;
    };
    const fresh = (plan = {}) => {
      stub.state.requests.length = 0;
      stub.state.plan = plan;
    };
    const sentPurls = () => stub.state.requests.flatMap((r) => JSON.parse(r.body).components.map((c) => c.purl));
    before(async () => {
      stub = await startStub();
      client = await connect({ era, ...serverCommand(), env: { ...process.env, ECHELONGRAPH_API_BASE: stub.base, ECHELONGRAPH_API_TIMEOUT_MS: "1500" }, stderr: "inherit" });
      tool = (await client.listTools()).tools.find((t) => t.name === TOOL);
    });
    after(async () => {
      try {
        await client?.close();
      } finally {
        await stub?.close();
      }
    });

    it("is listed right after check_sbom, with its title, read-only annotations, an inputSchema and an outputSchema", async () => {
      const names = (await client.listTools()).tools.map((t) => t.name);
      assert.equal(names[names.indexOf("check_sbom") + 1], TOOL);
      assert.equal(tool.title, SM.SCAN_MANIFEST_TITLE);
      assert.equal(tool.annotations.readOnlyHint, true);
      assert.ok(tool.inputSchema.properties.files);
      assert.ok(tool.outputSchema);
      assert.ok(tool.description.length <= 2048, `${tool.description.length}`);
    });

    it("both polarities on npm: lodash 4.17.15's lock is affected with CVE-2020-8203; 4.17.21's is not", async () => {
      fresh();
      const bad = await call({ files: [lock("lodash-4.17.15.package-lock.json")] });
      assert.notEqual(bad.isError, true, textBlocks(bad)[0]);
      const row = bad.structuredContent.data.results[0];
      assert.deepEqual([row.purl, row.verdict], ["pkg:npm/lodash@4.17.15", "affected"]);
      assert.ok(row.cve_ids.includes("CVE-2020-8203"));
      assert.equal(bad.structuredContent.state, "measured");
      assert.match(noteOf(bad), /Affected: pkg:npm\/lodash@4\.17\.15 \(CVE-2020-8203, CVE-2021-23337\)/);
      fresh();
      const good = await call({ files: [lock("lodash-4.17.21.package-lock.json")] });
      const r2 = good.structuredContent.data.results[0];
      assert.deepEqual([r2.purl, r2.verdict], ["pkg:npm/lodash@4.17.21", "not_affected"]);
      assert.ok(!JSON.stringify(good.structuredContent.data.results).includes("CVE-2020-8203"));
    });

    it("both polarities on Go: golang.org/x/net v0.7.0 is affected with CVE-2023-44487; at v0.17.0 it is absent", async () => {
      fresh();
      const bad = await call({ files: [{ filename: "go.mod", content: fixture("fixture.go.mod") }] });
      const row = bad.structuredContent.data.results.find((r) => r.purl === "pkg:golang/golang.org/x/net@v0.7.0");
      assert.deepEqual([row.verdict, row.cve_ids], ["affected", ["CVE-2023-44487"]]);
      fresh();
      const good = await call({ files: [{ filename: "go.mod", content: fixture("fixture.go.mod").replace("golang.org/x/net v0.7.0", "golang.org/x/net v0.17.0") }] });
      assert.ok(!JSON.stringify(good.structuredContent.data.results).includes("CVE-2023-44487"));
      assert.match(noteOf(bad), /1 go\.mod replace was applied/);
      assert.deepEqual(bad.structuredContent.data.manifest.files[0].replaced, [{ from: "github.com/pkg/errors@v0.9.1", to: "github.com/go-errors/errors@v1.4.2" }]);
    });

    it("control: django>=4 answers not_assessed, version_unpinned, and nothing is sent", async () => {
      fresh();
      const res = await call({ files: [{ filename: "requirements.txt", content: "django>=4\n" }] });
      assert.notEqual(res.isError, true, textBlocks(res)[0]);
      const sc = res.structuredContent;
      assert.equal(sc.state, "not_assessed");
      assert.deepEqual(sc.data.not_checked, [{ file: "requirements.txt", name: "django", spec: "django>=4", reason: "version_unpinned", line: 1, detail: sc.data.not_checked[0].detail }]);
      assert.deepEqual(sc.data.results, []);
      assert.equal(sc.coverage.not_checked_by_reason.version_unpinned, 1);
      assert.equal(stub.state.requests.length, 0, "a request was made");
      assert.match(noteOf(res), /nothing was sent to EchelonGraph/);
      assert.match(noteOf(res), /1 entry was NOT checked and is not clean \(version_unpinned 1\)/);
    });

    it("only purls reach the API: no filename, no file text, no line not checked, nothing in a URL", async () => {
      fresh();
      const files = [
        { filename: "services/secret-name/requirements.txt", content: fixture("requirements.txt") },
        { filename: "frontend/package-lock.json", content: fixture("tree.v3.package-lock.json") },
      ];
      const res = await call({ files });
      assert.notEqual(res.isError, true, textBlocks(res)[0]);
      assert.ok(stub.state.requests.length > 0);
      for (const r of stub.state.requests) {
        assert.equal(r.url, BATCH_PATH);
        const body = JSON.parse(r.body);
        assert.deepEqual(Object.keys(body), ["components"]);
        for (const c of body.components) assert.deepEqual(Object.keys(c), ["purl"]);
        for (const leak of ["secret-name", "requirements.txt", "package-lock", "--hash", "sha256", "node_modules", "django-filter", "is-number", "local-pkg", "integrity", "scan-manifest-fixture"]) {
          assert.ok(!r.body.includes(leak), `the API was sent ${leak}`);
        }
      }
      assert.deepEqual(sentPurls().sort(), [...new Set([...purls(read("requirements.txt", files[0].content)), ...purls(read("package-lock.json", files[1].content))])].sort());
    });

    it("several files: duplicates sent once, a refused file named NOT READ, every not_checked entry with its file", async () => {
      fresh();
      const res = await call({
        files: [
          lock("lodash-4.17.15.package-lock.json"),
          { filename: "web/package-lock.json", content: fixture("tree.v1.package-lock.json") },
          { filename: "package.json", content: '{"dependencies":{"lodash":"^4.17.0"}}' },
          { filename: "go.sum", content: "golang.org/x/sys v0.1.0 h1:x=\n" },
        ],
      });
      const sc = res.structuredContent;
      assert.equal(sc.coverage.files, 4);
      assert.deepEqual([sc.coverage.files_read, sc.coverage.files_not_read], [2, 2]);
      assert.deepEqual([sc.coverage.entries_pinned, sc.coverage.duplicates_removed, sc.coverage.distinct_purls], [65, 1, 64]);
      assert.equal(new Set(sentPurls()).size, sentPurls().length, "a purl was sent twice");
      assert.match(noteOf(res), /NOT READ, so nothing in it is checked: package\.json: package\.json holds version ranges, not installed versions: pass package-lock\.json/);
      assert.match(noteOf(res), /NOT READ, so nothing in it is checked: go\.sum: go\.sum is refused/);
      assert.deepEqual(sc.data.manifest.files.map((f) => [f.filename, f.read, f.format]), [["package-lock.json", true, "package-lock.json"], ["web/package-lock.json", true, "package-lock.json"], ["package.json", false, null], ["go.sum", false, null]]);
      assert.ok(sc.data.not_checked.every((n) => n.file === "web/package-lock.json"));
    });

    it("format overrides the filename", async () => {
      fresh();
      const res = await call({ files: [{ filename: "deps.lock", content: fixture("gradle.lockfile"), format: "gradle.lockfile" }] });
      assert.deepEqual(res.structuredContent.data.manifest.files[0].format, "gradle.lockfile");
      assert.equal(res.structuredContent.coverage.distinct_purls, 4);
    });

    it("refusals are invalid_input, before any request: no file read, too many files, too much text, more than 2,000 purls, a bad format", async () => {
      fresh();
      const cases = [
        [{ files: [{ filename: "package.json", content: "{}" }] }, /no file could be read: package\.json: package\.json holds version ranges/],
        [{ files: [] }, /files holds no file/],
        [{ files: Array.from({ length: 21 }, () => lock("lodash-4.17.15.package-lock.json")) }, /21 files; at most 20 are read per call/],
        [{ files: [{ filename: "requirements.txt", content: "x".repeat(5_000_001) }] }, /5000001 characters in all; at most 5000000/],
        [{ files: [{ filename: "requirements.txt", content: Array.from({ length: 2001 }, (_, i) => `pkg${i}==1.0.0`).join("\n") }] }, /2001 distinct purls; at most 2000 are checked per call .* pass fewer files per call \(requirements\.txt: 2001\)/],
      ];
      for (const [args, re] of cases) {
        const res = await call(args);
        assert.equal(res.isError, true, JSON.stringify(args).slice(0, 80));
        assert.equal(res.structuredContent.state, "invalid_input");
        assert.match(textBlocks(res)[0], re);
      }
      assert.equal(stub.state.requests.length, 0);
    });

    it("a format the tool does not read is refused by the advertised inputSchema", async () => {
      fresh();
      const res = await client.callTool({ name: TOOL, arguments: { files: [{ filename: "a", content: "", format: "pom.xml" }] } });
      assert.equal(res.isError, true);
      assert.match(textBlocks(res)[0], /format/);
      assert.equal(stub.state.requests.length, 0);
    });

    it("a 429 the budget cannot wait out leaves the rest not sent, named for check_sbom, never clean", async () => {
      // 1,400 distinct purls: seven batches; the second is refused with a wait past the budget.
      fresh({ 2: { status: 429, headers: { "retry-after": "60" }, body: { error: "component budget exceeded" } } });
      const content = Array.from({ length: 1400 }, (_, i) => `pkg${i}==1.0.${i}`).join("\n");
      const res = await call({ files: [{ filename: "requirements.txt", content }] });
      const sc = res.structuredContent;
      assert.deepEqual([sc.coverage.sent, sc.coverage.not_sent, sc.coverage.not_sent_reason, sc.coverage.partial], [200, 1200, "time_budget", true]);
      assert.equal(sc.data.not_sent_purls[0], "pkg:pypi/pkg200@1.0.200");
      assert.match(noteOf(res), /1200 purls were NOT sent .* from position 201 on, counted in the order this tool read them \(the files in the order given, each file's entries in the order the file lists them, each purl at its first place\), and data\.not_sent_purls lists them: call check_sbom with purls set to them after a minute\./);
    });

    it("a long answer's text keeps not_checked's first 20 and says where the rest are", async () => {
      fresh();
      const lines = [...Array.from({ length: 300 }, (_, i) => `pinned-${i}==1.0.0`), ...Array.from({ length: 60 }, (_, i) => `ranged-${i}>=1`)];
      const res = await call({ files: [{ filename: "requirements.txt", content: lines.join("\n") }] });
      const shown = JSON.parse(textBlocks(res)[0]);
      assert.equal(res.structuredContent.data.not_checked.length, 60);
      assert.equal(shown.not_checked.length, 20);
      assert.match(noteOf(res), /coverage\.not_checked_by_reason counts all 60 entries not checked, 20 of them in the text\./);
    });

    it("every result validates against the advertised outputSchema", () => {
      const validate = validator.getValidator(tool.outputSchema);
      for (const [args, res] of collected) {
        const v = validate(res.structuredContent);
        assert.ok(v.valid, `${JSON.stringify(args).slice(0, 80)}: ${v.errorMessage}`);
      }
    });
  });
}

// ── Cancellation (#2775), as check_sbom-cancel.test.mjs holds it for check_sbom ──
describe("#2835: a cancelled scan_manifest call sends no further batch", () => {
  const kit = {
    failed: (tool, f) => ({ isError: true, content: [{ type: "text", text: `${tool} FAILED: ${f.kind}` }], structuredContent: { state: "failed", error: f } }),
    describeFailure: (f) => `${f.kind}.`,
    badInput: (tool, why) => ({ isError: true, content: [{ type: "text", text: why }], structuredContent: { state: "invalid_input" } }),
    crashed: (tool, e) => ({ isError: true, content: [{ type: "text", text: String(e) }], structuredContent: { state: "failed" } }),
    checked: (_t, _s, r) => r,
    succeeded: (data, note, env) => ({ content: [{ type: "text", text: JSON.stringify(data) }, { type: "text", text: note }], structuredContent: { ...env, data } }),
    okHead: (tool, status) => `${tool} OK: HTTP ${status}.`,
    envelopeSchema: () => null,
    annotations: {},
  };
  it("the signal aborts during the first batch: that batch is cut off and the other six are never sent", async () => {
    const ac = new AbortController();
    const requests = [];
    const api = async (_p, init) => {
      requests.push(JSON.parse(init.body).components.length);
      ac.abort();
      return { ok: false, kind: "aborted", path: _p, method: "POST" };
    };
    const content = Array.from({ length: 1400 }, (_, i) => `pkg${i}==1.0.0`).join("\n");
    const res = await SM.scanManifest({ ...kit, api, signal: ac.signal }, { files: [{ filename: "requirements.txt", content }] });
    assert.equal(res.isError, true);
    assert.deepEqual(requests, [200], "a batch was sent after the call was cancelled");
  });
  it("control: unaborted, the same call sends all seven batches", async () => {
    const requests = [];
    const api = async (_p, init) => {
      const list = JSON.parse(init.body).components.map((c) => c.purl);
      requests.push(list.length);
      return { ok: true, status: 200, data: answerFor(list) };
    };
    const content = Array.from({ length: 1400 }, (_, i) => `pkg${i}==1.0.0`).join("\n");
    const res = await SM.scanManifest({ ...kit, api }, { files: [{ filename: "requirements.txt", content }] });
    assert.notEqual(res.isError, true);
    assert.deepEqual(requests, [200, 200, 200, 200, 200, 200, 200]);
  });
});
