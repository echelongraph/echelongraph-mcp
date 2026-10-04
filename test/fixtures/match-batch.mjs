// Answers of POST /api/v1/public/cves/match/batch (#2721), shaped field for field as
// core-backend internal/cve/matchbatch.go writes them: each row is the single GET's registry answer
// (packageMatchBody) plus index, input_kind, purl, verdict, and code/error on a refused component.
export const BATCH_PATH = "/api/v1/public/cves/match/batch";

const base = (index, purl, o) => ({
  ecosystem: "",
  ecosystem_recognised: false,
  package: "",
  version: "",
  match_layer: "registry",
  assessed: false,
  not_assessed_reason: "",
  cve_ids: [],
  matches: [],
  count: 0,
  advisories_considered: 0,
  not_affected_count: 0,
  undetermined_count: 0,
  undetermined: [],
  capped: false,
  candidates_capped: false,
  index,
  input_kind: "purl",
  purl,
  ...o,
});

const match = (cve, severity, score) => ({
  cve_id: cve,
  severity,
  cvss_v3_score: score,
  description: `Synthetic description for ${cve}.`,
  version_range: "< fixed",
  match_kind: "registry",
});

// One row per verdict and refusal the route produces, by name.
export const ROWS = {
  affected: (i, purl, name, version, cves) =>
    base(i, purl, {
      ecosystem: "npm",
      ecosystem_recognised: true,
      package: name,
      version,
      assessed: true,
      cve_ids: cves,
      matches: cves.map((c) => match(c, "HIGH", 7.5)),
      count: cves.length,
      advisories_considered: cves.length + 1,
      not_affected_count: 1,
      verdict: "affected",
    }),
  notAffected: (i, purl, name, version) =>
    base(i, purl, { ecosystem: "npm", ecosystem_recognised: true, package: name, version, assessed: true, advisories_considered: 2, not_affected_count: 2, verdict: "not_affected" }),
  undetermined: (i, purl, name, version) =>
    base(i, purl, {
      ecosystem: "npm",
      ecosystem_recognised: true,
      package: name,
      version,
      not_assessed_reason: "no_decidable_advisory",
      advisories_considered: 1,
      undetermined_count: 1,
      undetermined: [{ cve_id: "CVE-2099-0002", package: name, ecosystem: "npm", reason: "collapsed_fix_boundary" }],
      verdict: "undetermined",
    }),
  unknown: (i, purl, name, version) =>
    base(i, purl, { ecosystem: "npm", ecosystem_recognised: true, package: name, version, not_assessed_reason: "package_not_in_advisory_corpus", verdict: "not_assessed" }),
  distro: (i, purl) =>
    base(i, purl, {
      not_assessed_reason: "distro_release_unknown",
      code: "DISTRO_RELEASE_UNKNOWN",
      error:
        "a deb, apk or rpm purl needs a distro qualifier naming the release (e.g. ?distro=debian-12, ?distro=alpine-3.20, ?distro=ubuntu-22.04); the advisory corpus is keyed per release and EchelonGraph does not guess one",
      verdict: "not_assessed",
    }),
  malformed: (i, purl) =>
    base(i, purl, { not_assessed_reason: "invalid_component", code: "INVALID_PURL", error: "not a parseable purl (pkg:type/namespace/name@version)", verdict: "not_assessed" }),
  timeBudget: (i, purl, name, version) =>
    base(i, purl, { ecosystem: "npm", ecosystem_recognised: true, package: name, version, not_assessed_reason: "time_budget", verdict: "not_assessed" }),
};

// The whole answer for rows, with the summary the route computes from them.
export function batchAnswer(rows, { budgetMs = 10000, elapsedMs = 412 } = {}) {
  const by = {};
  const s = { affected: 0, not_affected: 0, undetermined: 0, not_assessed: 0 };
  for (const r of rows) {
    s[r.verdict]++;
    if (r.verdict === "not_assessed") by[r.not_assessed_reason] = (by[r.not_assessed_reason] ?? 0) + 1;
  }
  return {
    match_layer: "registry",
    components: rows.length,
    summary: {
      components: rows.length,
      ...s,
      not_assessed_by_reason: by,
      lookups: rows.filter((r) => !r.code).length,
      partial: (by.time_budget ?? 0) > 0,
      time_budget_ms: budgetMs,
      elapsed_ms: elapsedMs,
      corpus_cache_max_age_ms: 7200000,
    },
    answered_at: "2026-10-03T23:00:00Z",
    results: rows,
  };
}

// The answer to tools.test.mjs's representative call (CALLS.check_sbom).
export const LODASH = "pkg:npm/lodash@4.17.20";
export const DEB_NO_DISTRO = "pkg:deb/debian/openssl@3.0.11-1~deb12u1";
export const CALL_ANSWER = batchAnswer([ROWS.affected(0, LODASH, "lodash", "4.17.20", ["CVE-2021-23337", "CVE-2020-28500"]), ROWS.distro(1, DEB_NO_DISTRO)]);
export const CALL_ANSWER_EMPTY = batchAnswer([ROWS.unknown(0, LODASH, "lodash", "4.17.20"), ROWS.distro(1, DEB_NO_DISTRO)]);
