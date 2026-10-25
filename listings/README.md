# Directory listings for echelongraph-mcp

Prepared for #2723. Every submission below is a step for the founder (or someone the founder
names), done by hand, signed in, on the directory's own site or repo; the status table says which
were made and where each stands. Steps that need no third-party account are marked **Parent**.

One source of truth: `server.json` (its `title` and `description`) and `README.md`. Every paste
block below uses their words. Rules from #2304: no "live", no "only", nothing comparative without
a dated measurement. `test/listings.test.mjs` checks the paste blocks, `mcpb/manifest.json`,
`docker/server.yaml` and `docker/remote/server.yaml` against `REMOVED_CLAIMS` in
`test/tools.test.mjs`, and checks that they carry `server.json`'s description and
`package.json`'s version, that every count of tools or prompts they (or
`github-repo-settings.json`) state is `tools/list`'s or `prompts/list`'s, and that the manifest
declares exactly the server's tools and prompts.

Every directory's rules were re-read on 2026-10-04 (UTC); each section quotes the rules it relies
on and names the source. Directory requirements change: re-read the source before you submit.

## Status on 2026-10-18

A dated record: it says what was read on the dates it gives, and a release does not change it. Release
step 8 below re-runs the check after each release, and the next commit to this directory replaces
this table with that run's (this file is in the public repo's tree, so it changes with a release,
never between a tag and the next). Earlier tables (2026-10-04, 2026-10-11) are in this file's history.

Measured with `scripts/check-mcp-listings.mjs` (in the EchelonGraph repo; see "Listing check"
below) at 2026-10-17 19:21 UTC, after the 3.0.2 release (npm `latest` 3.0.2, published 2026-10-17
17:14Z); its one finding was Glama's lag. npm, the official registry and the hosted endpoint were
read again on 2026-10-18 (3.0.2 each). A row the check does not read, or a fact it does not
measure, says when it was read.

| Directory | Listed | Version shown | What it takes | Who |
|---|---|---|---|---|
| Official MCP Registry | yes, `io.echelongraph/echelongraph-mcp`, active | 3.0.2, `isLatest` (published to it 2026-10-17 17:20Z; read 2026-10-18) | nothing: each release publishes it (release step 2) | release script |
| Hosted endpoint `https://mcp.echelongraph.io/mcp` | in service | 3.0.2 (`/health`, 2026-10-18) | nothing | deploy |
| Glama | yes, **claimed 2026-10-05** (Admin as AkshayDubey29, Auto-Release on) | 2.7.0 on 2026-10-17, **behind** npm's 3.0.2: it has shown 2.7.0 since a manual Admin → Sync Server on 2026-10-06, and Auto-Release has picked up none of 2.7.1, 2.7.2, 3.0.0 and 3.0.2 (nor 2.6.7, 2.6.8 or 2.7.0 before them) | Admin → Repository → Sync Server after each release; the one-line description in "Paste text", if Glama's own differs (recorded on #2723 on 2026-10-05 as still to be set, and not recorded as set since) | founder (GitHub sign-in) |
| Smithery | yes, **published 2026-10-05** as `echelongraph/echelongraph-mcp` (hosted URL); display name and description set (recorded 2026-10-10) | proxies the hosted endpoint: its scan after the 3.0.2 release read 16 tools from it (2026-10-17) | re-publish after each release (release step 5); Settings → Verification, not recorded as done | release step 5; founder (Smithery sign-in) for Verification |
| mcp.so | **submitted, not listed:** chatmcp/mcpso#4699, the free route the founder chose (the $39 form was declined), opened 2026-10-04 12:14Z; no reply on record (0 comments when read on 2026-10-10), and the check found no listing on 2026-10-17 | shows none | mcp.so's review of #4699. Do not open a second issue or pay the form | mcp.so |
| PulseMCP | no | shows none | nothing: submissions paused (since 2026-09-03); it reads the official registry when it reopens | nobody |
| Docker MCP Catalog, local | **PR open:** docker/mcp-registry#5429 (from the `echelongraph` fork; branch `add-echelongraph`), pinned to v3.0.2 (commit `3193362066d3`, the commit `v3.0.2^{}` names, not the tag object `47bd1ffb`; moved 2026-10-17 with the 3.0.2 release, validate and build passing). `docker/server.yaml` here still carries v2.7.2's commit `1a0965ea`: release step 6 mirrors the pin, in the next commit to this directory. No review on record; Docker's own CI has never run: both workflows sit at `action_required` (first-time contributor) until a Docker maintainer approves them | n/a until merged | Docker's review; move the pin on each release while open | Docker |
| Docker MCP Catalog, remote | **PR open:** docker/mcp-registry#5428; validate passed in our local runs (Docker's CI held at `action_required` for maintainer approval); tools are dynamic, so no pin to move; no review on record | serves the hosted endpoint | Docker's review | Docker |
| awesome-mcp-servers (punkpeye) | **yes**: punkpeye/awesome-mcp-servers#15955 merged by punkpeye 2026-10-08T07:01:56Z (merge commit `89b9a3f946`); one line in 🔒 Security (README line 3769 at merge), with the Glama score badge | no version shown (links the repo; the Glama badge tracks Glama's score) | nothing; the line points at the public repo, so it stays current | maintainer |
| Public repo About (github.com/echelongraph/echelongraph-mcp) | description, homepage and topics equal to `github-repo-settings.json` (the check's `github-repo` row, read 2026-10-18 07:03Z; #3289) | no version shown | apply the file after each release that changes it (release step 7) | someone with admin on the repo |
| Anthropic connector directory | **submitted 2026-10-05, in review** (developer portal; hosted URL, no auth; when submitted, the endpoint served 2.6.7, with its 14 read-only tools). Not edited while in review: an edit resubmits it (founder, 2026-10-10) | shows none | Anthropic's review; reply at the founder's contact email | Anthropic |

Docker's remote entry and Anthropic's directory connect to the hosted endpoint, and Smithery's
entry names it (until 2026-10-31 Smithery's gateway proxied it), so the version they serve is the
hosted endpoint's.

**Smithery from 2026-10-31 (#3356), read 2026-10-25.** Smithery's notice
(https://smithery.ai/future, read 2026-10-25): on 2026-10-31 it shuts "Server URLs on run.tools and
server.smithery.ai", the "Smithery API, Connect, and Toolbox", "Smithery accounts and API keys" and
"The Smithery CLI and SDKs", and "Smithery will remain as a public (non-proxied) MCP registry". From
that day our listing is a registry entry for `https://mcp.echelongraph.io/mcp`, and nothing can be
published there: the Smithery row's "re-publish after each release" above ends on 2026-10-31, and
release step 5 becomes a read-only check of the page. On 2026-10-25 the page's HTML named
`https://mcp.echelongraph.io/mcp` (our record's `upstreamUrl`) beside the proxy
`https://echelongraph-mcp--echelongraph.run.tools` (`mcpUrl`), and the Markdown view Smithery serves
agents (and curl) gave only the proxy, under "Direct MCP Connection": the listing check reports that
as a `wrong-url` finding until Smithery's page gives agents our URL. "Smithery" below says what the
founder can still do before 2026-10-31.

## Who does what

**Founder, signed in, in this order** (each section below has the exact text). Steps 3 to 5 were
done on 2026-10-04 and 2026-10-05; step 2's publish on 2026-10-05, with its text recorded as set on
2026-10-10; and step 1 in part: Glama's listing was claimed on 2026-10-05 and synced on 2026-10-06, while its one-line description was recorded on 2026-10-05 as still to be set,
if Glama's own differs. What is left of them is in the status table (Glama's description and its
Sync Server after each release, Smithery's Settings → Verification):

1. Glama: claim the listing, paste the one-line description, resync.
2. Smithery: `smithery mcp publish https://mcp.echelongraph.io/mcp`, then paste the text. Smithery's
   CLI, API and accounts stop on 2026-10-31 (#3356), so none of this can be redone from that day.
3. Docker: fork `docker/mcp-registry`, copy the two prepared entries, open the PR(s).
4. Anthropic: the developer portal form at https://claude.ai/directory/manage .
5. mcp.so: one GitHub issue on `chatmcp/mcpso`.

**Parent, no third-party account:** keep these drafts at each release's version (the tests fail
otherwise); run `node scripts/check-mcp-listings.mjs` after each founder step and again a week
later (#2723's Done means); set that script's row to `listed` once a listing is up, so a later
delisting is a finding. Every production deploy also runs the check, as a warning (below).

## Files

| File | Where it ends up | For |
|---|---|---|
| `../Dockerfile`, `../.dockerignore` | root of github.com/echelongraph/echelongraph-mcp (there since v2.4.0) | the Docker MCP Catalog's local build |
| `../glama.json` | root of the public repo (there since v2.4.0) | Glama ownership claim |
| `docker/server.yaml` | `servers/echelongraph/server.yaml` in a `docker/mcp-registry` fork | Docker MCP Catalog, local entry |
| `docker/remote/server.yaml`, `tools.json`, `readme.md` | `servers/echelongraph-remote/` in the same fork | Docker MCP Catalog, remote entry |
| `mcpb/manifest.json`, `mcpb/icon.png`, `mcpb/build.sh`, `mcpb/check-bundle.mjs` | public repo, `listings/mcpb/`; the built `echelongraph-mcp.mcpb` is attached, signed, to every new GitHub release (releases up to 2.6.5 have none) by the public repo's `release.yml` (#2815) | the one-click Claude Desktop install the README links as "Install in Claude Desktop"; also the bundle a stdio listing on Smithery would have taken until its publishing closed on 2026-10-31 |
| `scripts/check-mcp-listings.mjs` (EchelonGraph repo, not mirrored) | nowhere | the listing check |

None of these is in the npm package: `package.json` `files` is `dist`, `docs` (the README's
reference pages, Markdown only), `README.md`, `CHANGELOG.md` and `server.json`, and
`test/listings.test.mjs` checks `npm pack --dry-run` for that.

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

16 read-only tools: cve_summary (CVE feed summary), search_cves (Search CVEs), get_cve (CVE detail), cve_exposure (Internet exposure for one CVE), exposure_radar (Exposure radar totals), kev_recent (Recent CISA KEV additions), epss_history (EPSS change history for one CVE), check_affected (Am I affected? (product or package at a version)), check_sbom (Check an SBOM against the advisory corpus), scan_manifest (Check a lockfile against the advisory corpus), cve_intel (CVE weakness, exploits and packages), cve_remediation (How one CVE is fixed), get_cwe (CWE and its CVEs), vendor_advisories_for_cve (Vendor advisories for one CVE), get_vendor_advisory (Vendor advisory detail), search_vendor_advisories (Search vendor advisories).

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

Remote server URL (for forms that take a remote MCP server; Streamable HTTP, no auth). In
service: `https://mcp.echelongraph.io/health` answered `{"status":"ok",…,"version":"2.6.2"}` on
2026-10-04. Check it again before you submit:

```text
https://mcp.echelongraph.io/mcp
```

Links:

| Field | Value |
|---|---|
| Repository | https://github.com/echelongraph/echelongraph-mcp |
| npm | https://www.npmjs.com/package/echelongraph-mcp |
| Website / documentation | https://echelongraph.io/pulse/mcp |
| Privacy policy | https://echelongraph.io/privacy (Section 11, https://echelongraph.io/privacy#hosted-mcp-endpoint , covers the MCP server and the hosted endpoint) |
| What the server and the hosted endpoint send and log | https://github.com/echelongraph/echelongraph-mcp#privacy-what-is-sent-where |
| Support / security contact | support@echelongraph.io |
| Icon (512x512 PNG) | https://echelongraph.io/logo-mark.png (also `mcpb/icon.png`) |
| License | MIT |
| Categories | Security; Open Data (where offered) |

## Smithery

**From 2026-10-31: a registry entry, nothing to publish (#3356).** Smithery's notice
(https://smithery.ai/future, read 2026-10-25) shuts its proxy (server URLs on `run.tools` and
`server.smithery.ai`), its API, Connect and Toolbox, its accounts and API keys, and its CLI and SDKs
on 2026-10-31; it stays "a public (non-proxied) MCP registry", and "A curated set of verified
servers, whose registry pages will show direct MCP URLs". So from that day:

- Our listing is https://smithery.ai/servers/echelongraph/echelongraph-mcp , a registry entry for
  `https://mcp.echelongraph.io/mcp`. Anyone who connected through a Smithery URL
  (`https://echelongraph-mcp--echelongraph.run.tools`) loses the connection that day and must connect
  to `https://mcp.echelongraph.io/mcp` itself; the README says so beside its Smithery link.
- Nothing is published: from 2026-10-31 release step 5 (`scripts/publish-smithery.sh`) neither
  reads Smithery's API nor runs its CLI, whatever the API still answers (the accounts and API keys
  a publish needs stop that day, and the registry that stays is read from the same API host, so
  its public reads may well outlive the shutdown). Before that day it reads the API first; while
  it answers, the step publishes as before; once it is gone, the step reads the page read-only.
  Read-only, it never fails the release on what the page says: a page that sends users to a URL
  that is not ours is a FINDING, the step's last line, with exit 0, since no release can change
  Smithery's page and the release runners would only retry a failure for the same answer; the
  listing check reports it as `wrong-url` on every production deploy. The listing check
  reads the page (HTML and the agent view) before the API; a page that no longer lists us, with the
  API gone, is not measured (exit 2), not a finding, and never put down to the shutdown: the
  registry stays public, so Smithery dropped us or moved the page, and only its API could have told
  which. If it dropped us, the README's "Also listed on: Smithery" link is false: remove the link
  (and its pin in `test/listings.test.mjs`) and the check's `smithery` row. A Smithery outage cannot
  fail or hold a deploy (`infrastructure/cloudrun/deploy-all-listing-check.test.sh` holds that).
- The Markdown view Smithery serves agents gave, on 2026-10-25, only the proxy as "Direct MCP
  Connection", and its Quick Start uses the Smithery CLI (`npx -y smithery mcp add …`), which stops
  that day: that page is Smithery's, and only Smithery can change it. What the founder can do, signed
  in, before 2026-10-31: finish step 4 below (Settings → Verification, not recorded as done), since
  the notice gives direct URLs on verified servers' pages; whether that puts our page among them is
  Smithery's call, and is not known. After 2026-10-31 the account and the secret
  `smithery-api-key` in the deployment's secret store are of no use and can be deleted.
- Steps 1 to 5 below are a record: from 2026-10-31 none of them can be run.

**Status as of 2026-10-05** (a dated record; the status table above has the latest): listed at
https://smithery.ai/servers/echelongraph/echelongraph-mcp , published by the founder through the CLI after
`smithery namespace create echelongraph` (the namespace did not exist; publishing to it first answered
`404 {"error":"Namespace not found"}`). Smithery's scan reached the hosted endpoint and read `echelongraph-mcp`
2.6.4 with 14 tools and 4 prompts. Its display name was then `echelongraph-mcp`, with an empty description,
until step 3 below was done (display name and description, recorded 2026-10-10); step 4,
Verification, is not recorded as done. The listing check's row has been `listed` since.

**Status (2026-10-04, before publishing):** not listed. `GET https://api.smithery.ai/servers/echelongraph/echelongraph-mcp`
answers 404 `{"error":"Server not found"}`, and `?repoOwner=echelongraph&repoName=echelongraph-mcp`
lists 0 servers.

**No `smithery.yaml`.** Smithery's publish page and its documentation index no longer mention
one. The publish page offers two routes:

- **URL:** "**Bring your own hosting** — Smithery Gateway proxies to your upstream server."
  Requirements: "Streamable HTTP transport" and "OAuth support (if auth required)". Scanning:
  "**Public servers**: Scan completes automatically".
- **Local (MCPB Bundle):** "**For local stdio servers** — Smithery distributes a pre-built MCPB
  bundle that clients download and run locally."

**Route: the hosted URL.** Our endpoint is Streamable HTTP and keyless, so it meets both
requirements and Smithery needs no config schema. A URL listing cannot fall behind npm: Smithery
proxies to whatever the hosted endpoint runs. A bundle would have to be uploaded at every release,
because Smithery does not read npm. Since #2815 the release workflow builds and signs one for
every new release (the GitHub release's `echelongraph-mcp.mcpb`), so that route would need only the
upload, but it is not the recommendation. Checked 2026-10-04: an `initialize` sent with User-Agent
`SmitheryBot/1.0 (+https://smithery.ai)` got a 200 from `https://mcp.echelongraph.io/mcp`. That
request came from a cloud sandbox, not from the Cloudflare Workers that Smithery scans from; the
endpoint is served by Google Frontend (Cloud Run), with no Cloudflare WAF in front of it to block
those.

**To know before publishing** (until 2026-10-31, when the gateway shuts). Because "Smithery Gateway proxies to your upstream server",
requests from Smithery's users reach the endpoint from Smithery's addresses. The endpoint's
per-client limit (120 requests a minute, keyed on the client's public address;
`src/httpPolicy.ts`) then counts Smithery's egress addresses, not each user. Not measured. After
listing, watch the hosted endpoint's rate-limited responses.

**Steps**

1. **Founder, signed in:** `npx -y @smithery/cli@4.11.1 auth login` (a browser sign-in).
2. **Founder:** `npx -y @smithery/cli@4.11.1 mcp publish https://mcp.echelongraph.io/mcp -n echelongraph/echelongraph-mcp`
   (or https://smithery.ai/new → enter the URL). On 2026-10-04 the namespace `echelongraph` held
   no server (`api.smithery.ai/servers?namespace=echelongraph`: 0). Namespace names are global:
   if `echelongraph` is taken, stop and choose the name before publishing, then change
   `URLS.smithery` in `scripts/check-mcp-listings.mjs`.
3. **Founder:** on the server's page, set the display name to the Name and the description to the
   one-line description in "Paste text". Or, with a Smithery API key, send the JSON below as
   `PATCH https://api.smithery.ai/servers/echelongraph/echelongraph-mcp` with
   `Authorization: Bearer <key>` and `Content-Type: application/json`.
4. **Founder:** open the server's **Settings → Verification**. The publish page: "Once your server
   is published, open the server's Settings → Verification page to complete the automatic
   official-vendor verification checklist."
5. If the scan fails: the publish page's fallback is a static server card at
   `/.well-known/mcp/server-card.json`. The endpoint answers 404 there today; it is not built,
   because it is needed only if the scan fails.
6. **Parent:** `node scripts/check-mcp-listings.mjs --only=smithery`; when it reads LISTED, set the
   `smithery` row to `listed`.

Smithery update body:

```text
{
  "displayName": "EchelonGraph CVE & Exposure",
  "description": "CVE, KEV, EPSS, SBOM and advisory lookups; per-CVE exposure from Shodan data (© Shodan). Keyless.",
  "homepage": "https://echelongraph.io/pulse/mcp",
  "repositoryUrl": "https://github.com/echelongraph/echelongraph-mcp",
  "license": "MIT",
  "iconUrl": "https://echelongraph.io/logo-mark.png"
}
```

Sources (fetched 2026-10-04): https://smithery.ai/docs/build/publish.md ,
https://smithery.ai/docs/llms.txt ,
https://smithery.ai/docs/api-reference/servers/update-a-server.md ,
https://smithery.ai/docs/api-reference/servers/list-all-servers.md , and
`smithery mcp publish --help` from `@smithery/cli@4.11.1` (npm's latest that day): "Publish an MCP
server URL or bundle to Smithery".

## mcp.so

**Submitted 2026-10-04** through the free route, as chatmcp/mcpso#4699 (opened 12:14Z, with the
title and body below as they stood that day, at 2.6.3's 14 tools); no reply on record when read on
2026-10-10, and still not listed on 2026-10-17 (the status table). Step 1 below is done: do not
open a second issue.

**Status (2026-10-04, before submitting):** not listed. https://mcp.so/search?q=echelongraph :
"No servers match "echelongraph"".

**Routes.**

- Free: the site's FAQ, "How can I submit my MCP Server to mcp.so?": "You can submit your MCP
  Server by creating a new issue in our GitHub repository. … Please provide details about your
  server including its name, description, features, and connection information." The site links
  github.com/chatmcp/mcp-directory, which GitHub serves as `chatmcp/mcpso`. Recent submissions
  there are titled "Submit MCP server: <name>" or "Submit Remote MCP Server: <name>" (#4686 to
  #4695, all opened 2026-10-04).
- Paid: the form at https://mcp.so/submit has the types "MCP Server", "Remote Server", "MCP
  Client" and "AI Agent", the fields "Repository URL*" and "Name", and "Paid submission $39
  one-time publishing fee": "Publish immediately without review", "Verified badge", "Featured and
  priority placement", "Dofollow project link"; its button is "Pay and submit automatically". The
  page's description reads "Choose free review or publish immediately with Premium"; signed out,
  only the paid button shows.

Paying a directory is a money decision for the founder (#2304). The free route is the default.

**Steps (free route)**

1. **Founder, signed in to GitHub:** open https://github.com/chatmcp/mcpso/issues/new with the
   title and body below.
2. **Founder, signed in to mcp.so** (once listed): claim or edit the page if mcp.so offers it, and
   make its text match the one-line description.
3. **Parent:** `node scripts/check-mcp-listings.mjs --only=mcpso`; when LISTED, set the row to
   `listed`.

Issue title:

```text
Submit MCP server: EchelonGraph CVE & Exposure (npm echelongraph-mcp, remote https://mcp.echelongraph.io/mcp)
```

Issue body:

```text
Name: EchelonGraph CVE & Exposure
Repository: https://github.com/echelongraph/echelongraph-mcp
npm: https://www.npmjs.com/package/echelongraph-mcp (MIT)
Official MCP Registry: io.echelongraph/echelongraph-mcp
Website: https://echelongraph.io/pulse/mcp

Description: CVE, KEV, EPSS, SBOM and advisory lookups; per-CVE exposure from Shodan data (© Shodan). Keyless.

Tools (16, all read-only): cve_summary, search_cves, get_cve, cve_exposure, exposure_radar, kev_recent, epss_history, check_affected, check_sbom, scan_manifest, cve_intel, cve_remediation, get_cwe, vendor_advisories_for_cve, get_vendor_advisory, search_vendor_advisories.

Remote (Streamable HTTP, no install, no key): https://mcp.echelongraph.io/mcp

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

If the founder chooses the form instead: type "MCP Server", Repository URL
`https://github.com/echelongraph/echelongraph-mcp`, Name `EchelonGraph CVE & Exposure`.

Sources (fetched 2026-10-04): https://mcp.so/submit , https://mcp.so/ (FAQ),
https://github.com/chatmcp/mcpso/issues .

## PulseMCP

**Status (2026-10-04):** not listed. https://www.pulsemcp.com/servers?q=echelongraph : "Showing
0 - 0 of 0 servers for "echelongraph"", "No servers found."

**Nothing to submit.** https://www.pulsemcp.com/submit ("Last updated: September 3, 2026"): "We are
not accepting new MCP server or client submissions right now, and we are not making changes to
existing listings." It asks servers to "Publish it to the Official MCP Registry. That is the best
first step even when we are not paused", and says "We will pick it up automatically once we are
back." We are in the official registry (14 active versions, 2.7.2 latest, on 2026-10-11).

**Steps:** none. **Parent:** the listing check reads PulseMCP's search on every run. When a listing
appears, compare its text with the one-line description; if it differs, ask PulseMCP through
whatever channel the reopened site gives.

How the check reads it: PulseMCP's API is not usable for this. `v0beta` answers 410
`API_SUNSET` ("September 2026: Fully sunset (100%)"), and `v0.1` requires `X-API-Key` and
`X-Tenant-ID`. So the check reads the public search page. On 2026-10-04 PulseMCP's edge answered
curl from a cloud sandbox with a Cloudflare challenge, and Node's fetch from the same sandbox with
the page. The check reports a challenge as "not measured", never as "not listed".

Sources (fetched 2026-10-04): https://www.pulsemcp.com/submit ,
https://www.pulsemcp.com/servers?q=echelongraph , https://www.pulsemcp.com/api/docs/v0.1 .

## Docker MCP Catalog

**Status (2026-10-04):** not listed. Docker's published catalog,
https://desktop.docker.com/mcp/catalog/v3/catalog.yaml , has no `echelongraph` entry.

**How it works** (`CONTRIBUTING.md` at `docker/mcp-registry` commit 49b643c, which is still `main`
on 2026-10-04). There are two kinds of entry:

- Local: "Require a Dockerfile in the source repository". "If you don't provide a Docker image, we
  will build the image for you and host it in Docker Hub's `mcp` namespace, the benefits are:
  image will include cryptographic signatures, provenance tracking, SBOMs, and automatic security
  updates."
- Remote: "Don't require a Dockerfile (already deployed somewhere)". The directory holds
  `server.yaml`, `tools.json` ("Always [] for remote servers") and `readme.md` ("Documentation
  link (required)").

Review: "Every pull request requires a review from the Docker team before merging." "Upon approval
your entry will be processed and it will be available in 24 hours".

**Signing is Docker's.** #2723 asked for an image "built reproducibly and signed (cosign)". Docker
builds the local entry's image from our Dockerfile and signs it. Each Docker-built `mcp/*` image
page names the check, for example `mcp/duckduckgo`'s: "COSIGN_REPOSITORY=mcp/signatures cosign
verify mcp/duckduckgo --key https://raw.githubusercontent.com/docker/keyring/refs/heads/main/public/mcp/latest.pub".
We sign nothing for this listing. `../Dockerfile` pins its base image by digest and installs
exactly `package-lock.json`; it is byte-identical at the public tag `v2.6.2` (blob `dc99f10a`).

**No PR per release.** The registry's daily "Update MCP Server Version Pins" workflow
(`.github/workflows/update-pins.yaml`, `cmd/ci/update_pins.go`) moves every local server's
`source.commit` to the head of its tracked branch (default `main`) and opens one PR per server,
which `auto-merge-pins.yaml` merges when its checks pass. The public repo's `main` moves only at a
release, so the image follows releases without a PR from us.

**Two entries.** A local one (`echelongraph`, Docker builds and signs the image, stdio) and a
remote one (`echelongraph-remote`, the hosted URL, no image). The registry has seven such
`<name>` and `<name>-remote` pairs; five of them (`atlassian`, `notion`, `pulumi`, `stripe`,
`webflow`) give both entries the same title, as ours do.

**Validated 2026-10-04** with the registry's own `go run ./cmd/validate --name <name>` at 49b643c:

- `echelongraph` (this directory's `docker/server.yaml`, pinned at `ccb1a7b8…`, the public commit of
  `v2.6.2`): name, directory, title, YAML formatting, "✅ Commit is pinned", secrets, config env,
  "✅ License is valid", "✅ Icon is valid", remote skipped, OAuth. Every check passed.
- `echelongraph-remote` (`docker/remote/`): every check passed, with "✅ Dynamic tools are valid".
  Run without `dynamic`, Docker's own client listed our tools from the URL: "✅ Remote tools are
  valid. Found 14 tools."
- Not run when this section was written (2026-10-04): `task build -- --tools echelongraph` (that
  sandbox had no Docker daemon and no Task); first run that day on the devbox, and passing again on
  2026-10-17, when #5429's pin moved to v3.0.2 (the status table). It builds `../Dockerfile`, and `tools/list` needs no configuration and no network:
  `test/listings.test.mjs` lists the tools exactly that way.

**Steps**

1. **Founder, signed in to GitHub:** fork https://github.com/docker/mcp-registry and clone the fork.
2. Copy `docker/server.yaml` to `servers/echelongraph/server.yaml`, and `docker/remote/server.yaml`,
   `tools.json` and `readme.md` to `servers/echelongraph-remote/`. Both copy as they are. If npm's
   latest is past the release `docker/server.yaml` pins, you may set `source.commit` to
   `git ls-remote https://github.com/echelongraph/echelongraph-mcp 'refs/tags/v<latest>^{}'`'s
   commit. The pin workflow moves it after the merge in any case.
3. In the fork: `task validate -- --name echelongraph`, `task validate -- --name echelongraph-remote`
   and `task build -- --tools echelongraph` (Go 1.24+, Docker and Task).
4. **Founder:** open one PR per entry with the titles and bodies below, remote first (no build).
   Docker's CI builds every server a PR changes, and each entry gets its own review.
5. No test credentials: the server is keyless. Docker's form for sharing test credentials is for
   servers that need them.
6. **Parent:** `node scripts/check-mcp-listings.mjs --only=docker,docker-remote`; set each row to
   `listed` when it reads LISTED.

Remote PR title:

```text
Add EchelonGraph CVE & Exposure remote (echelongraph-remote)
```

Remote PR body:

```text
Adds echelongraph-remote: EchelonGraph CVE & Exposure, hosted.

CVE, KEV, EPSS, SBOM and advisory lookups; per-CVE exposure from Shodan data (© Shodan). Keyless.

- Remote: https://mcp.echelongraph.io/mcp (streamable-http), no authentication, no secrets
- tools.json is [] and dynamic tools are on; `go run ./cmd/validate` without dynamic lists 16 tools from the URL
- 16 tools, all annotated readOnlyHint
- Docs: https://github.com/echelongraph/echelongraph-mcp#readme (MIT)
- Also in the official MCP Registry as io.echelongraph/echelongraph-mcp, with this remote
```

Local PR title:

```text
Add EchelonGraph CVE & Exposure (echelongraph)
```

Local PR body:

```text
Adds echelongraph: EchelonGraph CVE & Exposure.

CVE, KEV, EPSS, SBOM and advisory lookups; per-CVE exposure from Shodan data (© Shodan). Keyless.

- Source: https://github.com/echelongraph/echelongraph-mcp (MIT), pinned commit in server.yaml
- Dockerfile at the repo root; base image pinned by digest, npm ci from the lockfile, runs the stdio server as uid 1000
- No secrets or configuration; the server calls https://app.echelongraph.io (allowHosts)
- 16 tools, all annotated readOnlyHint: cve_summary, search_cves, get_cve, cve_exposure, exposure_radar, kev_recent, epss_history, check_affected, check_sbom, scan_manifest, cve_intel, cve_remediation, get_cwe, vendor_advisories_for_cve, get_vendor_advisory, search_vendor_advisories
- Also in the official MCP Registry as io.echelongraph/echelongraph-mcp
```

Sources (fetched 2026-10-04): https://github.com/docker/mcp-registry/blob/main/CONTRIBUTING.md
(49b643c), its `cmd/validate/main.go`, `cmd/ci/update_pins.go`, `.github/workflows/ci.yaml`,
`update-pins.yaml` and `auto-merge-pins.yaml`, `servers/excalidraw-remote/` and
`servers/cloudflare-docs/`; https://desktop.docker.com/mcp/catalog/v3/catalog.yaml ;
https://hub.docker.com/v2/repositories/mcp/duckduckgo/ .

## Anthropic connector directory

**Status (2026-10-04):** not listed. https://claude.com/connectors/echelongraph redirects to
https://claude.com/marketplace/connectors/echelongraph , which answers 404. A listed connector
answers 200 at the same path (Semrush's, the same day).

**What it takes, and whether we qualify.** The directory takes remote servers, submitted in the
developer portal. Checked against each requirement on the submission page:

| Requirement (quoted) | Us |
|---|---|
| "Your server is remote and reachable over HTTPS" | yes: `https://mcp.echelongraph.io/mcp` |
| "Authentication works for Claude's client: OAuth 2.0 if your tools act on a user's account, or no authentication for public data". The authentication page lists `none`, "No authentication (authless server)", as "Supported by default". | yes: no authentication, public data |
| "Every tool has a `title` and a `readOnlyHint` or `destructiveHint` annotation" | yes: all 16 have a title and `readOnlyHint: true` (`test/listings.test.mjs`, both protocol eras) |
| "You've tested it in Claude" | founder: add it as a custom connector and call each tool |
| "documentation URL, privacy policy URL, support contact, an icon" | yes, in "Paste text"; the privacy policy URL is `/privacy`, whose Section 11 covers the hosted endpoint (below) |
| "You have a test account for reviewers: credentials for a fully populated account". The review checklist: "Test credentials: required". | **no account exists**: the server is keyless. Say so in Test & launch (block below). A reviewer may ask about it. |
| "Your account can submit: any paid Claude plan". The publish page: "Plan: Pro, Max, Team, or Enterprise. Free accounts can't submit". On Team and Enterprise, "an Owner can submit". | founder's plan |
| Review checklist, API ownership: "Your server must call your own first-party APIs, or APIs you legitimately proxy. The MCP server domain should match your service." | yes: `mcp.echelongraph.io` calls `app.echelongraph.io` |
| "the directory no longer accepts local servers packaged as MCP Bundles (MCPB)" | the hosted URL is what we submit |

After submitting: "Anthropic scans your submission automatically for policy compliance and, by
default, lists it as a Community connector". Escalations: `mcp-review@anthropic.com`.

**Privacy policy.** Give https://echelongraph.io/privacy as the privacy policy URL. Its Section 11,
"MCP Server and Hosted MCP Endpoint" (anchor `#hosted-mcp-endpoint`,
`marketing-site/app/privacy/PrivacyContent.tsx`, #2797), says what the hosted endpoint receives
(tool arguments, and whole files, documents and labels among them: SBOM documents up to 6 MiB, and,
as tools that take them are added, manifests and lockfiles, package-database text and workload
labels), that it processes them in memory and neither logs nor stores them, what its access line
records, what the API logs of the calls it makes for the user (each under the user's address, with
its URL path), and that the npm package runs on the user's machine. `marketing-site/lib/privacyMcpEndpoint.test.ts`
holds that section to `src/http.ts`'s log lines and `src/httpPolicy.ts`'s caps: a field added to a
log line fails it until the section names it. The server's README section, "Privacy: what is sent
where" (https://github.com/echelongraph/echelongraph-mcp#privacy-what-is-sent-where), stays the
per-tool detail. (`/privacy` answers 403 to the sandbox, as the marketing edge challenges datacenter
clients, #2304: read the served Section 11 from a browser before submitting.)

**Steps** (first check that `https://mcp.echelongraph.io/health` answers `{"status":"ok",…}`)

1. **Founder, signed in to claude.ai:** add the remote URL as a custom connector and call every
   tool from a conversation (the portal asks you to confirm this).
2. **Founder:** https://claude.ai/directory/manage → **Submit new** → **MCP connector**.
3. Connection: `https://mcp.echelongraph.io/mcp`. Tools sync from the server, grouped as read-only.
4. Listing: the Name, one-line description and long description from "Paste text"; categories
   Security (and Open Data if offered); the links table. The URL slug is permanent: `echelongraph`.
   The listing check reads `claude.com/marketplace/connectors/echelongraph`, on the assumption that
   the public page follows the portal's slug (Semrush's page is at `…/connectors/semrush`); if the
   published page is elsewhere, change `URLS.anthropic` in the script.
5. Use cases: paste the block below. What users need before connecting: nothing. Reads data;
   writes nothing.
6. Company: EchelonGraph, https://echelongraph.io , contact support@echelongraph.io (or the
   founder's address).
7. Authentication: no authentication.
8. Data handling: the underlying API is our own (app.echelongraph.io). No personal health data,
   no sponsored content.
9. Test & launch: paste the block below.
10. Compliance: read and tick the seven acknowledgments.
11. **Parent:** `node scripts/check-mcp-listings.mjs --only=anthropic`; set the row to `listed`
    when it reads LISTED.

Use cases:

Do not paste until the 2026-10-05 submission's review completes (founder's rule); the submitted copy said 'public exploit code', which cve_intel no longer claims.

```text
Look up one CVE's record: CVSS, the EchelonGraph score and whether it has been scored, EPSS, CISA-KEV status and known ransomware use, and the GitHub GHSA id. Read its weakness (CWE), exploit code and detection checks, affected packages, fixed versions, EPSS history and the vendor advisories that name it. List the CVEs CISA has added to its KEV catalog, newest first. Check whether a product or package at a version is affected by known CVEs, or check an SBOM's components or a project's lockfiles (package-lock.json, go.mod, requirements.txt and others) against the advisory corpus. Search and filter CVEs and vendor advisories. Count active CVEs by severity band. See how many internet-facing services (distinct ip:port) EchelonGraph's KEV-exposure radar has on record running a version that maps to a CVE; exposure counts are derived from Shodan data (© Shodan).
```

Use cases as submitted on 2026-10-05, kept as the record of what Anthropic is reviewing (not
paste text). It is this block as the submission found it: EchelonGraph commit 981e6dbf, which
recorded the submission, and the public repository's tag v2.6.8 (read 2026-10-18). The founder's
rule: the in-review submission is not edited, because a change resubmits the listing, so the
corrected block above waits for the review to complete. #3266 retired its "public exploit code":
since #3039, cve_intel's exploits list holds exploit code and detection checks (Nuclei templates,
GitHub checker repositories), and its description says so. The block above also names lockfiles,
which scan_manifest added after the submission. The other blocks as submitted are in this file at
the same commit and tag.

```
Look up one CVE's record: CVSS, the EchelonGraph score and whether it has been scored, EPSS, CISA-KEV status and known ransomware use, and the GitHub GHSA id. Read its weakness (CWE), public exploit code, affected packages, fixed versions, EPSS history and the vendor advisories that name it. List the CVEs CISA has added to its KEV catalog, newest first. Check whether a product or package at a version is affected by known CVEs, or check an SBOM's components against the advisory corpus. Search and filter CVEs and vendor advisories. Count active CVEs by severity band. See how many internet-facing services (distinct ip:port) EchelonGraph's KEV-exposure radar has on record running a version that maps to a CVE; exposure counts are derived from Shodan data (© Shodan).
```

Test & launch:

```text
No test account exists, and none is needed: the server is keyless and read-only, so there are no credentials to give. Connect https://mcp.echelongraph.io/mcp with no authentication and call each tool, for example get_cve, cve_exposure, epss_history, cve_intel, cve_remediation and vendor_advisories_for_cve with CVE-2023-44487, cve_summary, exposure_radar and kev_recent with no arguments, search_cves with search "tomcat", check_affected with product "openssl" and version "3.0.0", get_cwe with CWE-79, check_sbom with purls ["pkg:npm/lodash@4.17.15"], scan_manifest with a requirements.txt whose text is "django==3.2.0", search_vendor_advisories with search "openssl", and get_vendor_advisory with a vendor and advisory id from that result. Each client may send up to 120 requests a minute.
```

Sources (fetched 2026-10-04): https://claude.com/docs/connectors/building/submission.md ,
https://claude.com/docs/directory/publish.md ,
https://claude.com/docs/connectors/building/authentication.md ,
https://claude.com/docs/connectors/building/review-criteria.md .

## Glama

**Status as of 2026-10-04** (a dated record; the status table above has the latest): listed at
https://glama.ai/mcp/servers/echelongraph/echelongraph-mcp , marked "Official", not claimed then
(it was claimed on 2026-10-05). The page's latest release was **v1.0.3**, recorded by Glama on
2026-09-27, while npm was at 2.6.2: the one finding of that day's listing check.

**Our card's text is clean.** The page's description of this server (Glama's own, generated from
the repo: "Enables any MCP client to look up CVE intelligence …") matches no `REMOVED_CLAIMS` term.
The "live CISA KEV" sentence #2706 quoted belongs to another server, `purify-feeds-mcp` by
`eason4kim-rocket`, in the page's "Related Servers" list (corrected by #2706's post-close review;
a first re-check had misread it as `Agam-S/Vulnary-MCP`'s). Glama's tool-grading notes also use
"live" ("whether external lookups are cached or live"), as a question, not a claim about us. The
listing check reads our card only (the head's title and description), so a word elsewhere on the
page is never reported as ours, and its self-test holds that with the real page. Glama generates
the description from the repo and could bring a barred word back with no change on our side; the
check reads it on every run.

**How claiming works.** The claim page says "Login with GitHub to claim"; "If you own the
repository: Sign in as that GitHub account and this page becomes yours immediately"; "If owned by
an organization: Add `glama.json` to the root of the repository with your GitHub username under
`maintainers`, then sign in", and "Glama recognises you on the next sync". The public repo's root
has held `glama.json` since v2.4.0, naming `AkshayDubey29` (its schema,
https://glama.ai/mcp/schemas/server.json , defines `maintainers` and nothing else). Change
`../glama.json` before a release if someone else should hold the listing.

**Steps**

1. **Founder, signed in to Glama with GitHub as `AkshayDubey29`:** open
   https://glama.ai/mcp/servers/echelongraph/echelongraph-mcp/admin and claim the server.
2. **Founder:** set the description to the one-line description in "Paste text", and turn on "Use
   Glama listing details as the source of truth" if the page offers it, so a registry update does
   not overwrite the text. Run the admin page's repository sync if it offers one; otherwise ask
   Glama to refresh the release list (it showed v1.0.3 on 2026-10-04, and 2.7.0 from the
   2026-10-06 sync: the status table).
3. **Parent:** `node scripts/check-mcp-listings.mjs --only=glama` must read npm's latest (current),
   with no barred claim. Record the outcome on #2723.

Sources (fetched 2026-10-04): the listing page and its `/admin` page above,
https://glama.ai/mcp/schemas/server.json .

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
prints the same values (GitHub lists topics sorted), and `node scripts/check-mcp-listings.mjs
--only=github-repo` (in the EchelonGraph repo, see "Listing check") reports no finding: its row
compares the live description, homepage and topics with this file, and every production deploy
runs it with the other rows, as a warning (#3289). The description follows the rules above (no
"live", no "only"), and `test/listings.test.mjs` checks it, its counts against `tools/list`
included; nothing but the commands above changes the live About.

## Release notes

Every GitHub Release body of github.com/echelongraph/echelongraph-mcp, and every changelog entry,
that cites issue numbers carries this sentence, word for word, as `CHANGELOG.md`'s preamble does:

> Issue numbers (#NNNN) refer to EchelonGraph's internal issue tracker, which is not public: they are not issues of the public repository, and cannot be followed from it.

`scripts/npm-publish-mcp.sh` does not write Release bodies, so this is a step of the release
checklist: when a Release is created or edited, paste the sentence above its first `#NNNN`, or
leave the numbers out. `test/readme.test.mjs` holds `CHANGELOG.md`'s preamble and this section
to the same sentence.

## Release steps

A release is done when all of these hold, in this order (2026-10-05). Each step names what proves it.

1. `scripts/npm-publish-mcp.sh --publish "<summary>"`: npm serves the version with SLSA provenance,
   and public main plus tag `vX.Y.Z` carry exactly `mcp-server/`.
2. `scripts/npm-publish-mcp.sh --publish-mcp-registry`: the official registry lists it as latest.
3. `DEPLOY_ENV=production bash infrastructure/cloudrun/deploy-all.sh mcp-remote`: the hosted
   endpoint's `/health` reports the version.
4. **GitHub Release** for `vX.Y.Z`, titled `echelongraph-mcp X.Y.Z`, marked Latest. Its body is the
   CHANGELOG section, preceded by the sentence in "Release notes" above. The script does not
   create it. Glama's Auto-Release builds from it, and it is what "Watch → Releases" emails.
5. `scripts/publish-smithery.sh`. Before 2026-10-31 (https://smithery.ai/future), while Smithery's
   API answers: Smithery re-scans the hosted endpoint, so its listing shows this release's tools
   and descriptions; it refuses until step 3 holds, reads the publisher's Smithery API key from the
   deployment's secret store and checks that Smithery's API lists the release's tool count. From
   2026-10-31 (the UTC day), whatever the API still answers, since accounts and API keys stop that
   day; before it, once the API is gone, as observed (refused, no such host, 410, an HTML page), or
   the CLI cannot be installed (#3356): it publishes nothing and reads no key (from 2026-10-31 it
   does not read the API at all); it reads Smithery's public page (as HTML and as the Markdown agent view)
   and exits 0 where the page names `https://mcp.echelongraph.io/mcp`, lists us without a URL, no
   longer lists us, or cannot be read (each a dated note, "Smithery retired its API (2026-10-31…)"),
   and where it sends users to another URL or only to Smithery's proxy: a FINDING, the last line,
   with exit 0 all the same, since no release can change Smithery's page and the runners would retry
   it 3 times for the same answer (the listing check reports it as `wrong-url`). Read-only, it exits
   2 only for a bug of ours (a reader in `scripts/check-mcp-listings.mjs` failing). From 2026-10-31,
   and before it once the API is observed gone or the CLI cannot be installed, nothing Smithery does
   fails the release. Before 2026-10-31 an API that answers a 5xx or times out tells nothing, so the
   step publishes as before, and a publish or read-back that fails is FAILED (exit 1), as it always
   was (the runners retry it). Self-test: `scripts/publish-smithery-selftest.sh` (it also runs
   the release runners' loop: "smithery ok try 1", no retry, with the API live, gone, and still
   answering on 2026-11-05, and on a FINDING).
6. docker/mcp-registry#5429, while it is open: move `servers/echelongraph/server.yaml`'s
   `source.commit` to the tag's commit, then re-run `go run ./cmd/validate --name echelongraph` and
   `go run ./cmd/build --tools echelongraph`. Mirror the commit in `docker/server.yaml` here.
7. **Public repo About**, by someone with admin on github.com/echelongraph/echelongraph-mcp: apply
   `github-repo-settings.json` with the `gh api -X PATCH` and `PUT …/topics` commands in "Public
   repo settings" above, then check it: `node scripts/check-mcp-listings.mjs --only=github-repo`
   reports no finding. `test/listings.test.mjs` holds the file's counts to `tools/list`, so a
   release that changes the tool count changes the file; only this step changes the live About,
   which directories (Glama among them) read (#3289).
8. `node scripts/check-mcp-listings.mjs`: no finding. Glama can lag behind step 4 (its
   Auto-Release did not pick up 2.6.5, 2.6.7, 2.6.8, 2.7.0 or any release since: the founder's
   Admin → Sync Server). Then replace "Status on <date>" at the top of this file with that run's
   table, in the next commit to this directory: this file ships in the release's tree, so it
   cannot change between a tag and the next.

## Listing check

`scripts/check-mcp-listings.mjs` lives in the EchelonGraph repo, not in this directory, so it is
not mirrored to the public repo. It reads each directory's public page or API for this server, one
request at a time, and reports per row: listed or not; the version shown against npm's `latest`
(or "not shown"); and any `REMOVED_CLAIMS` term in our own card's text.

| Row | Reads | Our card | Version |
|---|---|---|---|
| Official MCP Registry | `registry.modelcontextprotocol.io/v0.1/servers?search=…&version=latest` | title, description | the active `isLatest` entry |
| Hosted endpoint | `mcp.echelongraph.io/health` | none | `version` |
| Glama | the listing page | `<title>`, meta description | `releaseVersion` in the page's data |
| Smithery (#3356) | `smithery.ai/servers/echelongraph/echelongraph-mcp`, as HTML (our server record, by `qualifiedName`) and as the Markdown it serves agents; `api.smithery.ai/servers/echelongraph/echelongraph-mcp` only where the page does not decide | display name, description | none (the entry names the hosted endpoint) |
| mcp.so | `mcp.so/search?q=echelongraph` (its embedded results) | name, tagline | shows none |
| PulseMCP | `pulsemcp.com/servers?q=echelongraph`, then our server page | `<title>`, meta description | shows none |
| Docker, local and remote | `desktop.docker.com/mcp/catalog/v3/catalog.yaml` | title, description | local: the release tag whose commit Docker built (`source …/tree/<commit>` against the public repo's tags); remote: none |
| Anthropic | `claude.com/marketplace/connectors/echelongraph` | `<title>`, meta description | shows none |
| Public repo About (`github-repo`, #3289) | `api.github.com/repos/echelongraph/echelongraph-mcp` | description; its description, homepage and topics are compared with `github-repo-settings.json` (topics as a set) | shows none |

Exit codes: 0 every row measured, no finding; 1 at least one finding (`missing` where the table
says listed, `version-lags`, `barred-claim`, `differs` where the public repo's About is not
`github-repo-settings.json`, one per field, and `wrong-url` where Smithery's page sends users to a
URL that is not `https://mcp.echelongraph.io/mcp`, or only to its proxy, #3356); 2 no finding, but something could not be measured
(a directory unreachable or challenged, a page whose shape changed, npm unreadable, a Docker build
commit no release tag points at). A finding outranks could-not-measure, and both are printed.
A row the script's table marks `pending` that does not list us is printed as PENDING and is not a
finding. Once a listing is up, set its row to `listed`. Where Smithery's API is observed gone and
its page no longer lists us, the Smithery row is NOT MEASURED (exit 2), not a finding and not put
down to the shutdown (#3356): its registry stays public, so Smithery dropped us or moved the page,
and the row says that the README's Smithery link is then false. The API is read only where the page does not decide, and keeps its old
verdicts while it answers; an answer that tells nothing (a timeout, a 5xx) reads as the API gone
only from 2026-10-31.

`node scripts/check-mcp-listings.mjs --self-test` runs 44 cases offline against
`scripts/fixtures/mcp-listings/`: responses saved 2026-10-04 (several trimmed, in served order),
Smithery's page (HTML and the agent view), its not-found answers and its API document saved
2026-10-25 (#3356: the API live and listed, gone five ways, the page naming our URL, another URL or
only the proxy, a related server's URL that is not ours, at a fixed clock either side of 2026-10-31, and our URL quoted in a tool description, which is not a URL to connect to),
the public repo's About as `api.github.com` served it on 2026-10-18 beside a copy of this
directory's `github-repo-settings.json` (identical: passes; one word of the description changed,
or the homepage and a topic: fails as `differs`; a 404: `missing`; a 403: not measured),
plus labelled synthetic ones where no directory can serve a listed page yet. It covers both
polarities of each finding, the control that passes when every row is listed, current and clean,
and the control of the real 2026-10-04 responses (exit 1: Glama's lag, and PulseMCP's challenge
as curl got it). The real Glama page carries "live" in another server's card, and that must not be
flagged. It passes with no network (run in a namespace with none), and every one of nine
deliberate breaks of the checker made it fail.

**How it is wired (2026-10-18):**

- **Deploy-time warning, wired:** every production run of `infrastructure/cloudrun/deploy-all.sh`
  runs `node scripts/check-mcp-listings.mjs --self-test && node scripts/check-mcp-listings.mjs`,
  after the official registry guard (`--check-mcp-registry`) and the `--check-public` guards. It
  warns, never fails: a deploy cannot fix a third party's page, and Glama's lag alone would block
  every deploy. Each run is bounded by `MCP_LISTING_CHECK_SECONDS` (default 120) through
  `timeout(1)`, and without `timeout(1)` the check is not run, so a slow directory never holds a
  deploy or a release; a check whose self-test fails is not run; `SKIP_MCP_LISTING_CHECK=1` skips
  it, with a warning. `infrastructure/cloudrun/deploy-all-listing-check.test.sh` drives that block
  as shipped (each exit, a hang past the bound, a failed self-test, a missing script, no
  `timeout(1)`), with a control, in every production deploy's preflight. The preflight stops the
  deploy only where that warning path fails; where the only failure is the real `--self-test`, it
  warns and the deploy goes on, its listing check then warning that the self-test failed.
- **Weekly schedule, not wired yet** (#2723: "re-checked a week later"): a scheduled CI job or
  Routine that runs `--self-test` and then the check, and alerts on exit 1 or 2. It needs egress to
  the nine hostnames in the table, plus `registry.npmjs.org` and `api.github.com`.
- **CI, wired (#3356):** `.github/workflows/ci.yml`'s npm-publish-mcp-selftest job runs `--self-test`
  and `scripts/publish-smithery-selftest.sh` when the script, its fixtures or
  `scripts/publish-smithery*.sh` change (offline; Actions is off for the repository, #233).
