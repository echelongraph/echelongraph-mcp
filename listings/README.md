# Directory listings for echelongraph-mcp

Prepared for #2723. Nothing here has been submitted. Every submission below is a step for the
founder (or someone the founder names), done by hand on the directory's own site or repo.

One source of truth: `server.json` (its `title` and `description`) and `README.md`. Every paste
block below uses their words. Rules from #2304: no "live", no "only", nothing comparative without
a dated measurement. `test/listings.test.mjs` checks the paste blocks, `mcpb/manifest.json` and
`docker/server.yaml` against `REMOVED_CLAIMS` in `test/tools.test.mjs`, and checks that they
carry `server.json`'s description and `package.json`'s version.

Research for each directory was fetched 2026-10-03 to 2026-10-04 (UTC); sources are under each
directory. Directory requirements change; re-read the source before you submit.

| Directory | State on 2026-10-03 | What it takes | Blocked by |
|---|---|---|---|
| Official MCP Registry | listed: `io.echelongraph/echelongraph-mcp` 2.3.4, `isLatest: true` | nothing | none |
| Smithery | not listed | upload an MCPB bundle (`mcpb/`); founder signs in | the next release (for the version to match) |
| mcp.so | not listed | a GitHub issue on `chatmcp/mcpso` (free) or a $39 form | founder's choice of route |
| PulseMCP | not listed; submissions paused | nothing to submit: it ingests the official registry | PulseMCP reopening |
| Docker MCP Catalog | not listed | a PR to `docker/mcp-registry` (`docker/server.yaml`) | the next release (the Dockerfile must be in the public repo) |
| Anthropic connector directory | not listed | a remote HTTPS server, submitted in the developer portal | #2316 |
| Glama | listed; shows release v1.0.3, not 2.3.4 | claim through `glama.json`, then edit the listing | the next release (the file must be in the public repo) |

## Files

| File | Where it ends up | For |
|---|---|---|
| `../Dockerfile`, `../.dockerignore` | root of github.com/echelongraph/echelongraph-mcp | Docker MCP Catalog build |
| `../glama.json` | root of the public repo | Glama ownership claim |
| `mcpb/manifest.json`, `mcpb/icon.png`, `mcpb/build.sh` | public repo, `listings/mcpb/` | the `.mcpb` bundle for Smithery |
| `docker/server.yaml` | copied into a `docker/mcp-registry` fork as `servers/echelongraph/server.yaml` | Docker MCP Catalog entry |

None of these is in the npm package: `package.json` `files` is `dist`, `README.md`,
`CHANGELOG.md` and `server.json`, and `test/listings.test.mjs` checks `npm pack --dry-run` for
that.

**Releasing these files.** `mcp-server/` is published as the public repo's tree, so these files
change that tree. Commit them with a version bump: `scripts/npm-publish-mcp.sh --check-public`
compares the public tag `v<latest>` with `mcp-server/` at HEAD, and fails while HEAD carries a
tree that version was not published from.

## Paste text

Use these blocks as they are. Where a form has a length limit, the limit is noted.

Name (up to 100 characters):

```text
EchelonGraph CVE & Exposure
```

One-line description (up to 200 characters):

```text
CVE, KEV, EPSS, SBOM and advisory lookups; per-CVE exposure from Shodan data (© Shodan). Keyless.
```

Long description (up to 2,000 characters):

```text
CVE and internet-exposure data for Claude, Cursor, Cline, and any MCP client, from EchelonGraph's free public feed: NVD, MITRE-CNA pre-NVD records, CISA-KEV, EPSS and GitHub GHSA, plus a per-CVE internet-exposure footprint: how many internet-facing services (distinct ip:port) EchelonGraph's KEV-exposure radar has on record running a version that maps to the CVE. Exposure counts are derived from Shodan data. Shodan data is owned by Shodan, which holds its copyright (© Shodan).

Free and keyless: no API key, no auth, read-only. The server makes no request other than the API call a tool needs to answer. Every result carries a structured envelope (state, measured_at, method, coverage, freshness, notes), and a CVE outside the exposure radar's tracked set is reported as not assessed, not as zero.

14 read-only tools: cve_summary (CVE feed summary), search_cves (Search CVEs), get_cve (CVE detail), cve_exposure (Internet exposure for one CVE), exposure_radar (Exposure radar totals), kev_recent (Recent CISA KEV additions), epss_history (EPSS change history for one CVE), check_affected (Am I affected? (product or package at a version)), check_sbom (Check an SBOM against the advisory corpus), cve_intel (CVE weakness, exploits and packages), get_cwe (CWE and its CVEs), vendor_advisories_for_cve (Vendor advisories for one CVE), get_vendor_advisory (Vendor advisory detail), search_vendor_advisories (Search vendor advisories).

Install: npx -y echelongraph-mcp (Node.js 20 or later), or connect a Streamable HTTP client to https://mcp.echelongraph.io/mcp with no install.
```

Install configuration (for forms that ask for "connection information"):

```text
{
  "mcpServers": {
    "echelongraph": {
      "command": "npx",
      "args": ["-y", "echelongraph-mcp"]
    }
  }
}
```

Remote server URL (for forms that take a remote MCP server; Streamable HTTP, no auth). It
serves once `https://mcp.echelongraph.io/health` answers `{"status":"ok",…}`; submit it only
after that:

```text
https://mcp.echelongraph.io/mcp
```

Links:

| Field | Value |
|---|---|
| Repository | https://github.com/echelongraph/echelongraph-mcp |
| npm | https://www.npmjs.com/package/echelongraph-mcp |
| Website / documentation | https://echelongraph.io/pulse/mcp |
| Privacy policy | https://echelongraph.io/privacy |
| Support / security contact | support@echelongraph.io |
| Icon (512x512 PNG) | https://echelongraph.io/logo-mark.png (also `mcpb/icon.png`) |
| License | MIT |
| Categories | Security; Open Data (where offered) |

## Smithery

**Status:** not listed. `https://registry.smithery.ai/servers?q=echelongraph` returned no
EchelonGraph server on 2026-10-03.

**What changed.** Smithery's publish docs no longer describe `smithery.yaml`. A stdio server is
published as an MCPB bundle (`.mcpb`, a zip with `manifest.json`); a remote server is published by
its HTTPS URL. So this directory has `mcpb/manifest.json` in place of a `smithery.yaml`.

**Steps**

1. After the release that carries `listings/mcpb/` (so `manifest.json` is at the npm version):
   `mcp-server/listings/mcpb/build.sh` builds `listings/mcpb/out/echelongraph-mcp-<version>.mcpb`
   (it builds `dist/`, installs production dependencies from `package-lock.json`, validates the
   manifest and packs with `@anthropic-ai/mcpb@2.1.2`).
2. **Founder, signed in:** `npx -y @smithery/cli@4.11.1 auth login` (opens a browser sign-in).
3. **Founder, signed in:** `npx -y @smithery/cli@4.11.1 namespace create echelongraph`. Namespace
   names are global; if `echelongraph` is taken, stop and decide the name before publishing.
4. **Founder, signed in:** `npx -y @smithery/cli@4.11.1 mcp publish ./listings/mcpb/out/echelongraph-mcp-<version>.mcpb -n echelongraph/echelongraph-mcp`
5. **Founder, signed in:** on the server's page, paste the one-line and long descriptions above
   where the page offers them, then open **Settings → Verification** and complete the checklist.
6. Every release: rebuild the bundle and repeat step 4. Smithery does not read npm.
7. Remote (once `https://mcp.echelongraph.io/health` answers): `smithery mcp publish https://mcp.echelongraph.io/mcp -n echelongraph/echelongraph-mcp`
   or smithery.ai/new. Smithery scans with User-Agent `SmitheryBot/1.0 (+https://smithery.ai)` from
   Cloudflare Workers; the edge in front of the remote must let that through.

**Check after:** `https://smithery.ai/servers/echelongraph/echelongraph-mcp` shows the server,
the text above, and the npm version.

Sources (fetched 2026-10-03): https://smithery.ai/docs/build/publish.md ,
https://smithery.ai/docs/build/session-config.md , https://smithery.ai/docs/concepts/namespaces.md ,
`smithery mcp publish --help` from `@smithery/cli@4.11.1`, MCPB spec
https://github.com/modelcontextprotocol/mcpb/blob/main/MANIFEST.md (commit 70fe3b3, spec 0.3).

## mcp.so

**Status:** not listed (`https://mcp.so/search?q=echelongraph`: "No servers match", 2026-10-03).

**Routes.** The form at https://mcp.so/submit takes a type, a repository URL and a name, and its
button is a $39 paid submission ("Publish immediately without review", a "Verified badge",
"Featured and priority placement"). The site's FAQ gives a free route: a new issue in its GitHub
repository, `chatmcp/mcpso`. Paying a directory is a money decision for the founder (#2304); the
free route is the default here. Recent issues there (for example #4506, 2026-09-29) were open with
no maintainer reply when checked, so a listing can take a while.

**Steps (free route)**

1. **Founder, signed in to GitHub:** open https://github.com/chatmcp/mcpso/issues/new with the
   title and body below.
2. **Founder, signed in to mcp.so** (once listed): claim or edit the page if mcp.so offers it, and
   make its text match the one-line description above.

Issue title:

```text
Submit MCP Server: EchelonGraph CVE & Exposure (stdio, npm echelongraph-mcp)
```

Issue body:

```text
Name: EchelonGraph CVE & Exposure
Repository: https://github.com/echelongraph/echelongraph-mcp
npm: https://www.npmjs.com/package/echelongraph-mcp (MIT)
Official MCP Registry: io.echelongraph/echelongraph-mcp
Website: https://echelongraph.io/pulse/mcp

Description: CVE, KEV, EPSS, SBOM and advisory lookups; per-CVE exposure from Shodan data (© Shodan). Keyless.

Tools (14, all read-only): cve_summary, search_cves, get_cve, cve_exposure, exposure_radar, kev_recent, epss_history, check_affected, check_sbom, cve_intel, get_cwe, vendor_advisories_for_cve, get_vendor_advisory, search_vendor_advisories.

Remote (Streamable HTTP, no install): https://mcp.echelongraph.io/mcp

Install (stdio, Node.js 20 or later):
{
  "mcpServers": {
    "echelongraph": {
      "command": "npx",
      "args": ["-y", "echelongraph-mcp"]
    }
  }
}

Contact: support@echelongraph.io
```

**Check after:** the mcp.so page shows the server, the description above and no other wording.

Sources (fetched 2026-10-03): https://mcp.so/submit , https://mcp.so/ (FAQ: "How can I submit my
MCP Server to mcp.so?"), https://github.com/chatmcp/mcpso/issues/4506 .

## PulseMCP

**Status:** not listed (search for "echelongraph": 0 servers, 2026-10-03). Submissions are
paused. The submit page reads: "We are not accepting new MCP server or client submissions right
now, and we are not making changes to existing listings", and asks servers to publish to the
official MCP Registry, from which PulseMCP picks them up.

**Steps:** none to take. We are in the official registry. Re-check PulseMCP weekly; when a
listing appears, compare its text with the one-line description above, and if it differs, ask
PulseMCP through whatever channel the reopened site gives.

Sources (fetched 2026-10-03): https://www.pulsemcp.com/submit ,
https://www.pulsemcp.com/servers?q=echelongraph .

## Docker MCP Catalog

**Status:** not listed (`hub.docker.com/v2/repositories/mcp/echelongraph/` → 404, 2026-10-03).

**How it works.** A PR to `docker/mcp-registry` adds `servers/<name>/server.yaml` pointing at a
public GitHub repo and a pinned commit. Docker builds the image from that repo's `Dockerfile`
and publishes it as `mcp/<name>` on Docker Hub "with cryptographic signatures, provenance
tracking, SBOMs, and automatic security updates". So the image signature is Docker's: we do not
run cosign for this listing. Docker review is required; after approval the server appears within
24 hours.

`docker/server.yaml` is the draft entry. It passes the registry's validator
(`go run ./cmd/validate --name echelongraph`, registry commit 49b643c, 2026-09-16) on name, title,
YAML formatting, pinned commit, secrets, config env and icon, when `source.commit` is a real
SHA; the license check needs the GitHub API and was not run (the public repo's LICENSE is MIT).
With the placeholder commit, the validator refuses it, as intended. `run.allowHosts` limits the
container to `app.echelongraph.io:443`, so `ECHELONGRAPH_API_BASE` is not offered as a setting
there.

**Steps**

1. Release the next version, so the public repo's root holds `Dockerfile`. Note the public commit
   of that release (`git ls-remote https://github.com/echelongraph/echelongraph-mcp refs/tags/v<version>^{}`).
2. **Founder, signed in to GitHub:** fork https://github.com/docker/mcp-registry .
3. In the fork: copy `docker/server.yaml` to `servers/echelongraph/server.yaml`, delete its
   leading comment block, and set `source.commit` to the commit from step 1.
4. In the fork: `task validate -- --name echelongraph` and `task build -- --tools echelongraph`
   (needs Go 1.24+, Docker and Task). The build lists the tools by running the server; it needs
   no configuration and no network for `tools/list`.
5. **Founder, signed in to GitHub:** open the PR with the title and body below.
6. Every release: a PR that moves `source.commit` to the new release's commit.

PR title:

```text
Add EchelonGraph CVE & Exposure (echelongraph)
```

PR body:

```text
Adds echelongraph: EchelonGraph CVE & Exposure.

CVE, KEV, EPSS, SBOM and advisory lookups; per-CVE exposure from Shodan data (© Shodan). Keyless.

- Source: https://github.com/echelongraph/echelongraph-mcp (MIT), pinned commit in server.yaml
- Dockerfile at the repo root; the image runs the stdio server as uid 1000
- No secrets or configuration; the server calls https://app.echelongraph.io (allowHosts)
- 14 tools, all annotated readOnlyHint: cve_summary, search_cves, get_cve, cve_exposure, exposure_radar, kev_recent, epss_history, check_affected, check_sbom, cve_intel, get_cwe, vendor_advisories_for_cve, get_vendor_advisory, search_vendor_advisories
- Also in the official MCP Registry as io.echelongraph/echelongraph-mcp
```

**Check after:** https://hub.docker.com/mcp and Docker Desktop's MCP Toolkit show the server
with the description above; the image's `org.opencontainers.image.revision` label is the
release commit.

Sources (fetched 2026-10-03): https://github.com/docker/mcp-registry/blob/main/CONTRIBUTING.md
(commit 49b643c), its `cmd/validate/main.go` and `pkg/servers/types.go`,
https://docs.docker.com/ai/mcp-catalog-and-toolkit/catalog/ .

## Anthropic connector directory

**Status:** not listed. Waits for the hosted endpoint, `https://mcp.echelongraph.io/mcp` (#2316), to
answer.

**Why blocked.** The directory takes remote MCP servers over HTTPS, submitted in the developer
portal. It "no longer accepts local servers packaged as MCP Bundles (MCPB)"; a local server can be
listed only inside a plugin, and #2304 rejected a plugin. So the listing waits for the hosted
endpoint (#2316).

**Requirements that apply** (from the submission page): every tool has a `title` and a
`readOnlyHint` or `destructiveHint` (every tool carries a title and `readOnlyHint: true`;
checked in `tools/list` on 2026-10-04); no authentication is a supported mode for public data; a
documentation URL, a privacy policy URL, a support contact and an icon; a paid Claude plan
(Pro, Max, Team or Enterprise; on Team and Enterprise, an Owner submits); seven policy
acknowledgments; and the Software Directory Terms and Policy.

**Steps (once `https://mcp.echelongraph.io/health` answers)**

1. **Founder, signed in to claude.ai:** add the remote URL as a custom connector and call every
   tool from a conversation (the portal asks you to confirm this).
2. **Founder, signed in:** https://claude.ai/directory/manage → **Submit new** → **MCP connector**.
3. Connection: `https://mcp.echelongraph.io/mcp`. Tools sync from the server.
4. Listing: name, one-line description and long description from "Paste text" above; categories
   Security (and Open Data if offered); the links table above. The URL slug is permanent:
   `echelongraph`.
5. Use cases: paste the block below. What users need before connecting: nothing. Reads data;
   writes nothing.
6. Company: EchelonGraph, https://echelongraph.io , contact support@echelongraph.io (or the
   founder's address).
7. Authentication: no authentication.
8. Data handling: the underlying API is our own (app.echelongraph.io). No personal health data,
   no sponsored content.
9. Test & launch: paste the block below.
10. Compliance: read and tick the seven acknowledgments.

Use cases:

```text
Look up one CVE's record: CVSS, the EchelonGraph score and whether it has been scored, EPSS, CISA-KEV status and known ransomware use, and the GitHub GHSA id. Read its weakness (CWE), public exploit code, affected packages, fixed versions, EPSS history and the vendor advisories that name it. List the CVEs CISA has added to its KEV catalog, newest first. Check whether a product or package at a version is affected by known CVEs, or check an SBOM's components against the advisory corpus. Search and filter CVEs and vendor advisories. Count active CVEs by severity band. See how many internet-facing services (distinct ip:port) EchelonGraph's KEV-exposure radar has on record running a version that maps to a CVE; exposure counts are derived from Shodan data (© Shodan).
```

Test & launch:

```text
No account is needed: the server is keyless and read-only. Connect the URL and call each tool, for example get_cve, cve_exposure, epss_history, cve_intel and vendor_advisories_for_cve with CVE-2023-44487, cve_summary, exposure_radar and kev_recent with no arguments, search_cves with search "tomcat", check_affected with product "openssl" and version "3.0.0", get_cwe with CWE-79, and check_sbom with purls ["pkg:npm/lodash@4.17.15"].
```

**Check after:** the listing page at claude.ai/directory shows the text above.

Sources (fetched 2026-10-03): https://claude.com/docs/connectors/building/submission.md ,
https://claude.com/docs/directory/publish.md , https://claude.com/docs/connectors/building/mcpb.md .

## Glama

**Status:** listed at https://glama.ai/mcp/servers/echelongraph/echelongraph-mcp , marked
"Official", not claimed by us.

**#2706, re-checked 2026-10-03 23:50 UTC.** The listing's own text no longer carries a
`REMOVED_CLAIMS` term. "live" appears on the page in two other places: Glama's own tool-grading
notes (for example "whether external lookups are cached or live"), which ask a question and claim
nothing about the product; and the summary of a different server, `purify-feeds-mcp` by
`eason4kim-rocket`, in the page's "Related Servers" list ("MCP server for querying live CISA KEV,
EPSS, and enriched vulnerability feeds with full provenance"). That is the sentence #2706 quoted;
it now sits under another author's server. What is still wrong: the page's latest release is
v1.0.3 (observed 2026-09-27), not 2.3.4, and its generated summary says the server "distinguishes
verified zeros from unassessed or failed lookups", which is Glama's wording, not ours.

**How claiming works.** `glama.json` at the repo root, with `$schema`
`https://glama.ai/mcp/schemas/server.json`, lists the GitHub usernames allowed to maintain the
listing (that schema defines `maintainers` and nothing else; re-read 2026-10-04, unchanged).
For the hosted endpoint Glama also offers a domain claim: `https://glama.ai/mcp/schemas/connector.json`
describes a `/.well-known/glama.json` served from a domain you control (`claim`, a token from
Glama's claim panel, or `maintainers`). Not prepared here: it needs that token, and a file
served on `mcp.echelongraph.io`. `../glama.json` names
`AkshayDubey29`; change it before the release if someone else should hold the listing.

**Steps**

1. Release the next version, so the public repo's root holds `glama.json`.
2. **Founder, signed in to Glama with GitHub:** open
   https://glama.ai/mcp/servers/echelongraph/echelongraph-mcp/admin and claim the server.
3. **Founder, signed in:** set the description to the one-line description above, and turn on
   "Use Glama listing details as the source of truth" if the page offers it, so a registry update
   does not overwrite the text. Ask for the release list to be refreshed if it still shows v1.0.3.
4. Record the outcome on #2706.

Sources (fetched 2026-10-03): the listing page above, https://glama.ai/mcp/schemas/server.json ,
https://glama.ai/mcp/faq .

## Public repo settings

`github-repo-settings.json` holds the description, homepage and topics for
github.com/echelongraph/echelongraph-mcp, which directories (Glama among them) read from the
repo. To apply them, someone with admin on the repo runs:

```bash
gh api -X PATCH repos/echelongraph/echelongraph-mcp \
  -f description="$(jq -r .description listings/github-repo-settings.json)" \
  -f homepage="$(jq -r .homepage listings/github-repo-settings.json)"
jq '{names: .topics}' listings/github-repo-settings.json \
  | gh api -X PUT repos/echelongraph/echelongraph-mcp/topics --input -
```

Check after: `gh api repos/echelongraph/echelongraph-mcp --jq '.description, .homepage, .topics'`
prints the same values. The description follows the rules above (no "live", no "only"), and
`test/listings.test.mjs` checks it.

## Version lag

#2723's Done means asks for a check that reports any directory whose version lags npm `latest`.
Not built here. Where each directory exposes a version:

| Directory | Read |
|---|---|
| Official registry | `https://registry.modelcontextprotocol.io/v0/servers?search=io.echelongraph/echelongraph-mcp` (`server.version`, `isLatest`) |
| Smithery | `https://registry.smithery.ai/servers/echelongraph/echelongraph-mcp` (after publishing) |
| Docker | the `org.opencontainers.image.revision` label of `mcp/echelongraph`, against the release tag's commit |
| Glama | the listing page's latest release |
| mcp.so, PulseMCP | no version field seen; compare the description text |
