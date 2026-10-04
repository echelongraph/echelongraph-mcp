# Changelog

Every version of `echelongraph-mcp` published to npm, newest first. Dates are the npm publish
dates (UTC). Issue numbers (#NNNN) refer to EchelonGraph's internal issue tracker, which is not public: they are not issues of the public repository, and cannot be followed from it. Since 2.3.3 each version is published
with a provenance attestation by the release workflow of
[github.com/echelongraph/echelongraph-mcp](https://github.com/echelongraph/echelongraph-mcp),
from the commit tagged `v<version>`.

## 2.6.3 — 2026-10-04

- `exposure_radar` relays the observation window each count was measured over, where the API now
  serves one: `exposed_databases.window` (when our verifier last confirmed each host),
  `leaked_credentials.window` (when each key was last seen) and `shadow_ai.confirmed_exposed.window`
  (when our verifier's deciding probe ran). A window is relayed only when no counted row is undated;
  otherwise the note says how many are, and a malformed window is left out and named. KEV-exposure
  carries no observation time yet. `exposure_radar` stays `not_assessed` with `measured_at` null:
  a window's end is not one observation time (#2438).
- `vendor_advisories_for_cve`, `search_vendor_advisories` and `get_vendor_advisory` read each
  vendor's window from `GET /api/v1/public/vendor-advisories/coverage` beside their own request,
  and relay it in `coverage` (`vendor_windows`, or `vendor_window` for the detail): the advisories
  held, `earliest_vendor_published_at`, `latest_vendor_published_at` and `history_backfill`.
  `vendor_advisories_for_cve` adds `cve_year` and `vendors_not_fully_held`, the vendors with no
  advisory in the answer of which EchelonGraph holds none, whose earliest held advisory is dated
  after 1 January of the year in the CVE ID, or whose history is still being read, and its note
  names each with its window: an empty answer for CVE-2024-3400 can no longer be read as Palo Alto
  having published none. Its description no longer says an empty answer means none of the polled
  feeds names the CVE: it means none of the advisories EchelonGraph holds does. The search
  and the detail name the vendors whose history is still being read. When the windows cannot be
  read, the answer is still relayed, measured, with the windows null and a note saying so (#2729).
- `search_vendor_advisories`: a query of 1 or 2 characters matches whole words only
  (`search_match` `word`), as the API now answers it, and the description and the note say so; a
  search's total is counted to at most 1,000, and a capped total (`total_capped` true) is written
  "1,000+" in the note, never as a count. `coverage` gains `total_capped` and `search_match`
  (#2728).
- `check_sbom`'s 50-second budget bounds the whole call, not only when a batch may start: each
  batch's request may take only what is left of it, and a batch still unanswered when the budget
  runs out is cut off and its purls answered as not sent (`not_sent_reason` `time_budget`). Before,
  a batch started at 49.9 s could run for the 15-second request timeout, past the 60-second limits
  of the SDK's client and the hosted endpoint, which then answered nothing at all. A Retry-After
  wait that ends at the budget's end, before any batch was answered, answers that 429 instead of
  sending a request with no time left (#2756).
- Repository only, not in the package: the production synthetic probes `check_sbom` with 201
  purls, so every run sends two batches, and fails the probe (`expectation_unmet`) unless both
  were answered; core-backend's tests fail when `MAX_COMPONENTS`, `MAX_PURL_LEN` or
  `API_COMPONENTS_PER_MINUTE` disagree with the API's own values, and every core-backend deploy runs
  them before it builds (`scripts/check-outbound-identity.sh`'s table), refusing on drift (#2757).
- A success's first text block is cut to fit 30,000 characters when the API's JSON is longer, and
  `structuredContent.data` still carries the answer whole. Through 2.6.2 that block was the JSON
  whatever its size: on production's answers of 2026-10-04 a default `search_cves` for "openssl"
  was 133,300 characters of text, `get_cve` CVE-2021-44228 80,897, `check_affected` openssl 3.0.0
  156,058 (the Linux kernel at 5.10.0, 364,408), `check_sbom` on a 50-component SBOM 112,820,
  `kev_recent` at limit 200 105,925 and `search_vendor_advisories` at limit 50 103,147, against
  the 60,000-character ceiling; the same calls now measure 13,513, 22,960, 25,951 (27,717),
  28,733, 31,588 and 19,917. The JSON is first laid out one row a line, which loses nothing; past
  that, a list tool cuts each row to the fields it names (the description cut to 200 characters,
  every long string ending in "…"), then to fewer, and leaves rows out only when its leanest cut
  is still too long (`check_sbom` leaves out `not_affected` rows first); `get_cve` keeps the first
  entries of `cpe_match` and `references`. The note then ends with a sentence starting
  `TEXT CUT` that names what the first text block leaves out, which tool returns a row whole, and,
  when rows are left out, the `offset` or page size at which they fit. An answer that fits is sent
  as before. Every tool description, the server instructions and the methodology resource say so
  (#2783).
- `search_cves` takes `offset` (0 to 10,000), so the next page a cut text names can be read (#2783).
- A list beside the rows is cut before the rows are: `check_affected`'s `excluded` and
  `undetermined` samples keep each entry's `cve_id` and `reason`, and `cve_ids` (each match's
  `cve_id`, in order) its first 10, so every match stays in the text (`flash_player` 10.0.0, 200
  matches and 50 excluded entries, had 75 matches left out of it, two of them KEV-listed), and `check_sbom`'s `not_sent_purls` keeps its first 10, with the note
  saying from which position of the input the purls not sent run. A 2,000-purl `check_sbom` call
  that the API's budget stops after 1,200 now keeps the affected rows before the clean ones in the
  text. A cut `check_affected` match keeps `match_reason` (a registry match's advisory interval,
  which names the fixed version) where it fits, and the note names `cve_intel` for fixed versions
  (#2783).

## 2.6.2 — 2026-10-04

- `kev_recent` reads an RFC 3339 `since` or `until` as the date written in it, dropping the time
  and offset. It used to convert the timestamp to UTC first, so `2024-04-12T00:00:00+02:00` was
  answered for 2024-04-11, and `2024-04-12T23:30:00-05:00` for 2024-04-13, while still reporting
  a measured result. `kev_added_date` is a calendar date, so the written date is the one meant.
  `Z` timestamps, such as those `get_cve` returns, are unaffected (#2755).
- Hosted endpoint only: a `tools/call` of `check_sbom`, or a `prompts/get` of `sbom_review`, may
  now send a request body of up to 6 MiB, so a real CycloneDX or SPDX document (up to the tool's
  5,000,000-character cap) is accepted over `https://mcp.echelongraph.io/mcp`; before, any body
  over 64 KiB was refused, and only a purl list fit. Every other request keeps the 64 KiB cap.
  Each server instance serves at most two such large bodies at once; a third is answered HTTP 503
  with `Retry-After` and JSON-RPC error `-32030`. The per-client limit is unchanged (120 requests
  a minute). New settings `MCP_MAX_SBOM_BODY_BYTES` and `MCP_LARGE_BODY_SLOTS`. The `check_sbom`
  description and the README say that over the hosted endpoint the document reaches
  EchelonGraph's server, which reads the purls from it and neither logs nor keeps it (#2747).
- `cve_summary` says what the answer's `poller` block is: the in-memory counters of the NVD
  poller of the one API instance that answered, since it last started, zeroed on every restart,
  never the feed's size, intake, reliability or freshness. The note says so whenever the block is
  present, quoting `cves_ingested`, `poll_count` and `poll_errors`; the description and the
  outputSchema describe the block and each counter. The JSON is still relayed as sent (#2647).

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
