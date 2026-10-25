// Two sentences no surface of the MCP server may carry again, and the one place their wording is kept (#3246).
//
//   #3010: "each radar refreshes on its own". A radar refreshes only while it runs, and every Discovery Radar but
//          the KEV-Exposure Radar was stopped on 2026-10-08 while the README, /pulse/mcp and every exposure_radar
//          answer said they refreshed. A package README ships to npm and cannot follow a pause, so what it says
//          must be true either way ("Each radar has its own schedule and refreshes only while it runs").
//   #2739: the hosted endpoint "is being rolled out", "use npx until https://mcp.echelongraph.io/health
//          answers". It is in service, and server.json lists it as the package's remote (README changed in 2.6.0).
//
// Through 3.0.2 each was held on the README alone (test/readme.test.mjs, test/readme-setup.test.mjs,
// marketing-site/lib/scanningPause.test.ts), and #3012 had moved the exposure_radar and rate-limit reference to
// docs/*.md, which also ships. They are now held, from here, on every text the package ships or serves
// (test/barred-claims.test.mjs: docs/, package.json, server.json, the server instructions, every tool, prompt and
// resource text, the directory listings) and, in the monorepo, on /pulse/mcp, the mcp-server-explained post and
// /llms.txt (scanningPause.test.ts imports this file). CHANGELOG.md is not held: its dated entries quote what was
// withdrawn, and say when.
//
// Dependency-free, so a marketing-site test can import it from the monorepo.

/** A claim that the radars refresh, with no condition: true of a radar only while it runs (#3010). */
export const UNCONDITIONAL_REFRESH = /\beach radar refreshes on its own\b|\brefresh(?:es|ed)? on (?:its|their) own\b|\bradars?,? each refreshed on its own\b/i;
/** The radars' sentence that is true whether or not a radar runs: what replaced the claim. */
export const BOTH_STATES = "Each radar has its own schedule and refreshes only while it runs";
/** A claim that the hosted endpoint is not yet in service (#2739). */
export const HOSTED_ROLLING_OUT = /\bbeing rolled out\b/i;
// A dot inside a URL ("mcp.echelongraph.io") is not the sentence's end: through 3.0.2 the README's [^.]* stopped there,
// so "use npx until https://mcp.echelongraph.io/health answers" passed it.
export const WAIT_FOR_HEALTH = /\buntil (?:[^.]|\.(?=\S))*\/health(?:[^.]|\.(?=\S))* answers\b/i;

export const BARRED = [
  ["#3010", "says the radars refresh on their own, which a stopped radar makes false", UNCONDITIONAL_REFRESH],
  ["#2739", "says the hosted endpoint is being rolled out", HOSTED_ROLLING_OUT],
  ["#2739", "tells readers to wait until /health answers", WAIT_FOR_HEALTH],
];

/** What `text` (at `where`) says that BARRED bars: one problem per claim found, [] when none. */
export function barredClaimProblems(where, text) {
  const flat = String(text).replace(/\s+/g, " ");
  const out = [];
  for (const [issue, what, re] of BARRED) {
    const m = flat.match(re);
    if (m) out.push(`${where} ${what} (${issue}): "${flat.slice(Math.max(0, m.index - 60), m.index + m[0].length + 40).trim()}"`);
  }
  return out;
}

/** The barred sentences as they were published, one per claim: each control inserts them. */
export const BARRED_SENTENCES = [
  "Every figure is as fresh as the schedule that refreshes it: the CVE feed is polled from its sources on a schedule, and each radar refreshes on its own.",
  "The hosted endpoint is being rolled out.",
  "Use npx until https://mcp.echelongraph.io/health answers.",
];
