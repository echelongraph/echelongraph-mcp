// #3084: CISA's BOD 26-04 (10 June 2026) "supersedes and hereby revokes BOD 19-02 … and BOD 22-01"
// (https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk).
// No sentence EchelonGraph writes may present BOD 22-01 as the CURRENT basis of KEV's required
// action. A mention is allowed only where the same sentence says it was replaced. CISA's own KEV
// catalog text (kev_required_action, relayed verbatim) can still say "BOD 22-01" and is not ours,
// so this scans our source files, not relayed data.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
// The packed tarball ships dist/ and no src/ (npm-publish-mcp.sh runs this suite inside it), and has no
// marketing-site beside it: scan src/ where it exists, else the compiled dist/, whose sentences are the
// same string literals, and leave out a root that is not there.
const pkg = join(here, "..");
const roots = [existsSync(join(pkg, "src")) ? join(pkg, "src") : join(pkg, "dist"), join(pkg, "..", "marketing-site", "app", "pulse", "mcp")].filter((r) => existsSync(r));
const MENTION = /\b(?:BOD|Binding Operational Directive)\s*22-01\b/g;
const ALLOWED = /replaced BOD 22-01|revokes BOD 19-02 and BOD 22-01|BOD 22-01 was superseded/;

function files(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...files(p));
    else if (/\.(ts|tsx|mts|mjs|js)$/.test(name)) out.push(p);
  }
  return out;
}

export function staleMentions(src) {
  const out = [];
  for (const m of src.matchAll(MENTION)) {
    const around = src.slice(Math.max(0, m.index - 120), m.index + 60);
    if (!ALLOWED.test(around)) out.push(around.replace(/\s+/g, " "));
  }
  return out;
}

test("#3084: no EchelonGraph sentence names BOD 22-01 as the current basis of KEV's required action", () => {
  const scanned = roots.flatMap(files);
  assert.ok(scanned.length >= 10, `scanned only ${scanned.length} files — re-aim the roots`);
  const problems = scanned.flatMap((f) => staleMentions(readFileSync(f, "utf8")).map((s) => `${f}: …${s}…`));
  assert.deepEqual(problems, [], problems.join("\n"));
});

test("#3084 control: the sentence this ticket removed is caught, and the replacement is not", () => {
  const old = "CISA's required_action is directed at US federal civilian agencies (BOD 22-01) and is not EchelonGraph's advice.";
  const fixed = "CISA's required_action is directed at US federal civilian agencies (under BOD 26-04, which replaced BOD 22-01 on 10 June 2026) and is not EchelonGraph's advice.";
  assert.equal(staleMentions(old).length, 1);
  assert.equal(staleMentions(fixed).length, 0);
});
