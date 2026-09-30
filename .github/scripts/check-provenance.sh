#!/usr/bin/env bash
# .github/scripts/check-provenance.sh <version> [<commit>]
#
# Does npm serve echelongraph-mcp@<version> with a SLSA v1 provenance attestation saying this
# repository's release.yml built it at refs/tags/v<version>? One predicate, called by:
#   release.yml           for a tag whose version npm already has (publish and verify are skipped
#                         then, so without this a green run proved nothing: 2.3.2's was green, and
#                         2.3.2 has no attestation), and by the verify job after every publish;
#   published-tarball.yml daily, for latest, with the commit its tag points at now.
# The maintainers' release script (scripts/npm-publish-mcp.sh in their tracker) applies the same
# predicate after the Release run it starts; change the two together.
#
# All of these must hold:
#   1. the registry's version document has dist.attestations, with provenance.predicateType
#      https://slsa.dev/provenance/v1 and url .../-/npm/v1/attestations/echelongraph-mcp@<version>;
#   2. that url answers with exactly one https://slsa.dev/provenance/v1 attestation, whose in-toto
#      statement (the DSSE payload) has:
#        - subject pkg:npm/echelongraph-mcp@<version>, with a sha512 equal to the registry's
#          dist.integrity, so it is about the tarball npm serves and not some other build;
#        - buildType https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1;
#        - workflow repository https://github.com/echelongraph/echelongraph-mcp, path
#          .github/workflows/release.yml, ref refs/tags/v<version>;
#        - a resolved source commit for that tag, equal to <commit> when one is given.
#
# It reads what the registry serves; it does not verify the Sigstore signature over it. That is
# `npm audit signatures`, which the verify job runs after every publish.
#
# Exit: 0 it holds · 1 it does not, with every reason printed · 2 misuse, or a registry answer
# that is neither a document nor a 404, so nothing was decided either way.
set -euo pipefail

PACKAGE_NAME="echelongraph-mcp"
REGISTRY="https://registry.npmjs.org"
REPO_URL="https://github.com/echelongraph/echelongraph-mcp"
WORKFLOW=".github/workflows/release.yml"

usage() { echo "usage: $0 <MAJOR.MINOR.PATCH> [<40-hex commit>]" >&2; exit 2; }
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then usage; fi
VERSION="$1"
COMMIT="${2:-}"
[[ "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || usage
[ -z "$COMMIT" ] || [[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || usage

ERR=""; [ "${GITHUB_ACTIONS:-}" = "true" ] && ERR="::error::"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

# GET $1 into $2; prints the HTTP status ("000" when nothing answered). Transient failures
# (timeouts, 429, 5xx) are retried, so a registry hiccup is not reported as missing provenance.
get() {
  local code
  code="$(curl -sS --retry 3 --retry-delay 5 --max-time 30 -H 'Accept: application/json' \
    -o "$2" -w '%{http_code}' "$1" 2>"$T/curl.err")" || true
  echo "${code:-000}"
}

DOC_URL="$REGISTRY/$PACKAGE_NAME/$VERSION"
CODE="$(get "$DOC_URL" "$T/doc.json")"
case "$CODE" in
  200) echo "GET $DOC_URL: 200" ;;
  404) echo "${ERR}FAIL: $PACKAGE_NAME@$VERSION is not on the registry ($DOC_URL answered 404)"; exit 1 ;;
  *)   echo "${ERR}UNCLEAR: $DOC_URL answered $CODE; nothing decided"; sed 's/^/  /' "$T/curl.err"; exit 2 ;;
esac

ATT_URL="$REGISTRY/-/npm/v1/attestations/$PACKAGE_NAME@$VERSION"
ATT_FILE="$T/attestations.json"
CODE="$(get "$ATT_URL" "$ATT_FILE")"
case "$CODE" in
  200) echo "GET $ATT_URL: 200" ;;
  404) echo "GET $ATT_URL: 404"; ATT_FILE="" ;;
  *)   echo "${ERR}UNCLEAR: $ATT_URL answered $CODE; nothing decided"; sed 's/^/  /' "$T/curl.err"; exit 2 ;;
esac

# The predicate. The same JavaScript is in the maintainers' release script; keep them identical.
# Arguments: version document file, attestations file ("" when the registry answered 404), name,
# version, repository URL, workflow path, expected commit ("" for any).
PROVENANCE_JS="$(cat <<'JS'
const fs = require("fs");
const [docFile, attFile, name, version, repo, workflow, commit] = process.argv.slice(1);
const SLSA = "https://slsa.dev/provenance/v1";
const BUILD_TYPE = "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1";
const REF = `refs/tags/v${version}`;
const ATT_URL = `https://registry.npmjs.org/-/npm/v1/attestations/${name}@${version}`;
const E = process.env.GITHUB_ACTIONS === "true" ? "::error::" : "";
const unclear = (s) => { console.log(`${E}UNCLEAR: ${s}; nothing decided`); process.exit(2); };
const read = (f, what) => { try { return JSON.parse(fs.readFileSync(f, "utf8")); } catch (e) { return unclear(`${what} is not readable JSON (${e.message})`); } };
const bad = [];

const doc = read(docFile, "the version document");
if (!doc || doc.name !== name || doc.version !== version)
  unclear(`the version document is not ${name}@${version}'s (name ${JSON.stringify(doc && doc.name)}, version ${JSON.stringify(doc && doc.version)})`);
const dist = doc.dist || {};
const a = dist.attestations;
if (!a) bad.push(`${name}@${version} has no dist.attestations: it was published without provenance`);
else {
  if (a.provenance?.predicateType !== SLSA) bad.push(`dist.attestations.provenance.predicateType is ${JSON.stringify(a.provenance?.predicateType)}, not ${SLSA}`);
  if (a.url !== ATT_URL) bad.push(`dist.attestations.url is ${JSON.stringify(a.url)}, not ${ATT_URL}`);
}
const m = /^sha512-([A-Za-z0-9+/]+={0,2})$/.exec(dist.integrity || "");
const want512 = m ? Buffer.from(m[1], "base64").toString("hex") : "";
if (!want512) bad.push(`dist.integrity ${JSON.stringify(dist.integrity)} is not a sha512`);

let got = null;
if (!attFile) bad.push(`${ATT_URL} answered 404: the registry holds no attestation for ${name}@${version}`);
else {
  const all = read(attFile, "the attestations document").attestations;
  const slsa = Array.isArray(all) ? all.filter((x) => x && x.predicateType === SLSA) : [];
  if (slsa.length !== 1) bad.push(`the attestations document has ${slsa.length} ${SLSA} attestations, not exactly 1`);
  else {
    const env = slsa[0].bundle?.dsseEnvelope || {};
    let st = null;
    if (env.payloadType !== "application/vnd.in-toto+json") bad.push(`its DSSE payloadType is ${JSON.stringify(env.payloadType)}, not application/vnd.in-toto+json`);
    else { try { st = JSON.parse(Buffer.from(env.payload || "", "base64").toString("utf8")); } catch (e) { bad.push(`its DSSE payload is not JSON (${e.message})`); } }
    if (st) {
      if (st.predicateType !== SLSA) bad.push(`its statement's predicateType is ${JSON.stringify(st.predicateType)}, not ${SLSA}`);
      const subj = `pkg:npm/${name}@${version}`;
      const s = (Array.isArray(st.subject) ? st.subject : []).find((x) => x && x.name === subj);
      if (!s) bad.push(`its subject does not name ${subj}`);
      else if (want512 && s.digest?.sha512 !== want512) bad.push(`its subject's sha512 ${s.digest?.sha512} is not the registry's dist.integrity (${want512})`);
      const bd = st.predicate?.buildDefinition || {};
      if (bd.buildType !== BUILD_TYPE) bad.push(`its buildType is ${JSON.stringify(bd.buildType)}, not ${BUILD_TYPE}`);
      const w = bd.externalParameters?.workflow || {};
      if (w.repository !== repo) bad.push(`it names workflow repository ${JSON.stringify(w.repository)}, not ${repo}`);
      if (w.path !== workflow) bad.push(`it names workflow ${JSON.stringify(w.path)}, not ${workflow}`);
      if (w.ref !== REF) bad.push(`it names ref ${JSON.stringify(w.ref)}, not ${REF}`);
      const dep = (Array.isArray(bd.resolvedDependencies) ? bd.resolvedDependencies : []).find((d) => d && d.uri === `git+${repo}@${REF}`);
      const gitCommit = dep?.digest?.gitCommit;
      if (!gitCommit) bad.push(`it resolves no source commit for git+${repo}@${REF}`);
      else if (commit && gitCommit !== commit) bad.push(`it was built from commit ${gitCommit}, not ${commit}`);
      got = { gitCommit, run: st.predicate?.runDetails?.metadata?.invocationId };
    }
  }
}
if (bad.length) { for (const b of bad) console.log(`${E}FAIL: ${b}`); process.exit(1); }
console.log(`OK: ${name}@${version} has SLSA v1 provenance from ${repo}/${workflow} at ${REF}, built from commit ${got.gitCommit}${commit ? " (the one expected)" : ""} by ${got.run || "an unnamed run"}; its subject's sha512 is the registry's dist.integrity`);
JS
)"
node -e "$PROVENANCE_JS" -- "$T/doc.json" "$ATT_FILE" "$PACKAGE_NAME" "$VERSION" "$REPO_URL" "$WORKFLOW" "$COMMIT"
