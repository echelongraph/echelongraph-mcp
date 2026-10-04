# Changelog

Every version of `echelongraph-mcp` published to npm, newest first. Dates are the npm publish
dates (UTC). Issue numbers (#NNNN) refer to EchelonGraph's internal issue tracker, which is not public: they are not issues of the public repository, and cannot be followed from it. Since 2.3.3 each version is published
with a provenance attestation by the release workflow of
[github.com/echelongraph/echelongraph-mcp](https://github.com/echelongraph/echelongraph-mcp),
from the commit tagged `v<version>`.

## 2.6.1 — 2026-10-04

- Hosted endpoint only: when the production synthetic calls `https://mcp.echelongraph.io/mcp`, the
  endpoint marks its own API calls with a fixed `echelongraph-mcp-synthetic/1.0` token, so the
  synthetic is never counted as hosted use. The client's own text is never passed through. The
  `mcp_request` log line gains `client_public` (#2737).
- stdio behaviour is unchanged.

## 2.6.0 — 2026-10-04

- `check_sbom` checks up to 2,000 distinct purls per call, instead of refusing more than 200: it
  sends them as consecutive batches of at most 200, merges the answers (rows in input order with
  `index` counted across batches; summary counts and `not_assessed_by_reason` summed; `partial`
  true when any batch's was), and waits out a 429's `Retry-After` within 50 seconds per call.
  When a wait would pass that, or a batch after the first fails, it answers what it has, with the
  purls not sent counted in `coverage.not_sent`, the reason in `coverage.not_sent_reason`, and
  the list in `data.not_sent_purls`, never dropped silently. More than 2,000 is refused. New
  coverage fields: `distinct_purls`, `batch_size`, `batches`, `batches_sent`, `not_sent`,
  `not_sent_reason`, `rate_limit_waits`, `waited_ms`. The `sbom_review` prompt says so (#2734).
- `kev_recent` reads an RFC 3339 timestamp for `since` or `until` (such as the
  `kev_added_date` `get_cve` returns, `2024-04-12T00:00:00Z`) as its UTC date; other text is still
  refused. The `triage_cve` prompt's step 6 says to pass the date part of `kev_added_date` (#2736).
- README: the hosted endpoint, `https://mcp.echelongraph.io/mcp`, is described as in service,
  no longer as being rolled out (#2739).
- This changelog's preamble says the issue numbers refer to EchelonGraph's internal tracker,
  which is not public (#2740).

## 2.5.1 — 2026-10-04

- `search_cves` sends its search text in the `X-EG-Search` request header instead of the URL
  query string, so the text is kept out of request URLs, which the hosting platform's tracing
  records (#1983). Severity, minimum CVSS, sort and limit stay in the query string.

## 2.5.0 — 2026-10-04

- Four prompts (`triage_cve`, `kev_weekly_brief`, `am_i_affected`, `sbom_review`) and three
  resources (`echelongraph://methodology`, `echelongraph://sources`, `cve://{cve_id}`), in both
  protocol eras (#2722).
- README: a quick start for Claude Desktop, Claude Code, Cursor, VS Code, Windsurf and Cline,
  and for the hosted endpoint; a title and an example question per tool; what is sent where;
  the API's and the hosted endpoint's rate limits; the HTTP entrypoint's settings.
- This changelog, now in the npm package.
- `server.json`: a description covering the 14 tools, and the icon.

## 2.4.0 — 2026-10-04

Nine new tools, 14 in all (#2726):

- `kev_recent`: the CVEs CISA has added to its KEV catalog, newest first, with due date,
  ransomware use, EPSS and when EchelonGraph first saw each in the catalog; filter by date
  range, ransomware and vendor, and page with a cursor (#2717).
- `epss_history`: how one CVE's EPSS score has changed, as EchelonGraph recorded it, change-only
  and never a daily series (#2718).
- `check_affected`: whether a product (CPE path) or a registry package at a version is affected
  by known CVEs; `assessed` false is never "not affected" (#2716).
- `check_sbom`: up to 200 purls, or a CycloneDX or SPDX JSON document read on your machine,
  checked against the advisory corpus, one verdict per component (#2721).
- `cve_intel`: weakness (CWE), public exploit code, affected packages and fixed versions for one
  CVE (#2720).
- `get_cwe`: one CWE and the CVEs classified under it, CISA-KEV-listed first (#2720).
- `vendor_advisories_for_cve`, `get_vendor_advisory`, `search_vendor_advisories`: the
  vendor-published advisories that name a CVE, one advisory in full, and search (#2719).

Also:

- An HTTP entrypoint, `dist/http.js` (`npm run start:http`): the same tools over stateless
  Streamable HTTP on `POST /mcp`, in both protocol eras, with an Origin policy, a per-client limit
  and a body cap. It is what EchelonGraph's hosted endpoint, `https://mcp.echelongraph.io/mcp`,
  runs (#2316).
- `ECHELONGRAPH_MCP_UA`: one product token put ahead of the package's User-Agent, so an
  automated caller such as a monitor is told apart from people using the server (#2724).
- Inputs a user types for `check_affected`, `kev_recent` and `search_vendor_advisories` travel in
  `X-EG-*` request headers, never in the URL (#1983).
- `get_cve` relays NVD's configuration tree (`cpe_configurations`) when the API serves it, and
  says when it does not; a missing tree does not mean no product is affected (#2720).
- A failure message names the HTTP method of a request that is not a GET (`check_sbom`'s POST).
- Listing files for directories (`glama.json`, a `Dockerfile`, an MCPB manifest); none of them is
  in the npm package (#2723).

## 2.3.4 — 2026-09-30

- `cve_summary` says what `summary.nvd_critical` … `summary.nvd_none` count (the same active
  CVEs by NVD's severity label, as provenance, never EchelonGraph's severity) and what
  `summary.rejected` counts (withdrawn records, outside the total) (#2641).

## 2.3.3 — 2026-09-30

- The first release published by the public repo's release workflow, with npm provenance. No
  change to the server beyond the version (#2317).

## 2.3.2 — 2026-09-30

- `cve_summary`: `summary.none` is labelled as CVEs not yet scored, never as a severity rating of
  None (#2610).

## 2.3.1 — 2026-09-30

- `get_cve` and `search_cves` label a CVE EchelonGraph has not scored NOT YET SCORED (a rejected
  record NOT SCORED), never as an EchelonGraph score of 0 (#2535).

## 2.3.0 — 2026-09-30

- `exposure_radar` reads a fifth radar, `mcp_servers`: hostnames named like an MCP server in
  EchelonGraph's own Certificate Transparency feed, by their latest verdict on record (RFC 9728
  protected, pending re-adjudication, or not assessed by reason), with the protocol era and
  transport splits. An answer that does not say `service` `mcp` is refused, never relayed (#2315).

## 2.2.0 — 2026-09-28

- `not_assessed` no longer says its numbers are not findings: a count it relays is what the
  source holds on record, undated (#2465).
- The last text block stops repeating what an earlier block already says (#2467).

## 2.1.0 — 2026-09-27

- `cve_exposure` answers `not_assessed`, with `measured_at` null: its `last_seen` is when
  EchelonGraph last wrote a row, not when a service was observed (#2439).
- Every result's last text block carries the structured result, for clients that pass only
  `content` to the model (#2440).

## 2.0.0 — 2026-09-27

- Both MCP protocol eras on stdio: `server/discover` (2026-07-28) and `initialize` (2025-11-25
  and earlier) (#2311).
- Every tool has a title, annotations (`readOnlyHint` and the rest) and an `outputSchema`; every
  result carries `structuredContent` with `state`, `measured_at`, `method`, `coverage`,
  `freshness` and `notes` (#2313).
- `@modelcontextprotocol/server` 2.1.0 replaces `@modelcontextprotocol/sdk` 1.x; Node.js 20 or
  later (Node.js 18 dropped).

## 1.0.4 — 2026-09-27

- `exposure_radar` labels every number of every radar by what it counts, leaves out and names a
  field it cannot label, and never relays a CVE the radar does not track as "0 exposed" (#2313).
- `exposure_radar` relays each radar's `last_run_at`, its last completed check (#2335).
- The MIT `LICENSE` file ships in the package.

## 1.0.3 — 2026-09-27

- `exposure_radar` regroups the shadow-AI radar's numbers by what each counts
  (`confirmed_exposed`, `observed`, `authentication`) and relays no number unlabelled (#2307).

## 1.0.2 — 2026-09-27

- Freshness is the radar's last completed cycle, not a follower instance's zero time (#2307).
- Every Shodan-derived field states Shodan's ownership and copyright (#2306).

## 1.0.1 — 2026-09-27

- An API failure is an error result, never a success with empty data (#1874).
- Wording: no claim the code does not support; exposure counts are internet-facing services
  (distinct ip:port), attributed as derived from Shodan data (#2306).
- `cve_exposure` refuses an id that is not a CVE ID, and reports a CVE outside the radar's
  tracked set as not assessed, not 0 (#2313).
- `mcpName` and `server.json` for the official MCP Registry (#1879); the handshake and the
  User-Agent carry the package version.

## 1.0.0 — 2026-06-25

- First release: `cve_summary`, `search_cves`, `get_cve`, `cve_exposure` and `exposure_radar`
  over stdio.
