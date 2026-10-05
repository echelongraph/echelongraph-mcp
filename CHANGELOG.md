# Changelog

Every version of `echelongraph-mcp` published to npm, newest first. Dates are the npm publish
dates (UTC). Issue numbers (#NNNN) refer to EchelonGraph's internal issue tracker, which is not public: they are not issues of the public repository, and cannot be followed from it. Since 2.3.3 each version is published
with a provenance attestation by the release workflow of
[github.com/echelongraph/echelongraph-mcp](https://github.com/echelongraph/echelongraph-mcp),
from the commit tagged `v<version>`.

## 2.6.7 — 2026-10-05

- Tool descriptions now state facts only: no reporting instructions to the model and no references
  to other tools, for the Anthropic MCP Directory policy ("Tool descriptions contain no
  instructions about model behavior, other tools, or external instruction sources, and no hidden
  or encoded text"). Tool behavior, results and their notes are unchanged. Reworded:
  - get_cve, search_cves: "The note labels each such CVE NOT YET SCORED: report it that way, never
    as a score of 0." now reads "The note labels each such CVE NOT YET SCORED, which is not a score
    of 0."
  - cve_summary: summary.rejected's "report them as withdrawn records, never as vulnerabilities"
    now reads "they are withdrawn records, none of them a vulnerability"; summary.none's "report
    those CVEs as not yet scored, not as CVEs rated None" now reads "and names those CVEs not yet
    scored, not CVEs rated None".
  - get_vendor_advisory: "(the vendor and vendor_advisory_id fields of a row from
    search_vendor_advisories or vendor_advisories_for_cve)" now reads "(the vendor and
    vendor_advisory_id of a vendor advisory row)".
  - exposure_radar: "and cve_exposure says per CVE whether the radar tracks it" now reads "and this
    answer does not say whether the radar tracks that CVE: tracking is answered per CVE".
  - epss_history: "Never interpolate it into a daily series." now reads "A daily series
    interpolated from it holds values EchelonGraph never recorded, so the series is never a daily
    series."
  - check_affected: "Read assessed before count: … a count of 0 there must never be reported as
    not affected" now reads "count depends on assessed: … a count of 0 there is not a finding of
    not affected"; the outputSchema description of assessed, "Read first.", now reads "count
    depends on it.".
  - vendor_advisories_for_cve, get_vendor_advisory, search_vendor_advisories: the outputSchema
    description of withdrawn, "report it as withdrawn", now reads "so it is a withdrawn advisory,
    not a current one".
- test/description-policy.test.mjs lists the tools over stdio and fails if any title, description
  or input/output schema description names another tool, matches a model-directed imperative
  pattern, or carries zero-width, bidi or control characters or a base64-looking run.

## 2.6.6 — 2026-10-05

- Correction to 2.6.5 (#2775). Its entry says: "On the hosted endpoint it is the client going away
  (its own timeout, a closed tab): every API call of that request is cancelled". That was not true
  of the hosted endpoint. Cloud Run does not pass a client's disconnect on to a container it
  speaks HTTP/1.1 to ("When you use HTTP/1.1 on Cloud Run, client disconnect events are not
  propagated to the Cloud Run container",
  <https://docs.cloud.google.com/run/docs/troubleshooting>). In production on 2026-10-05, four
  `check_sbom` calls had their client abort after 0.4 s or 1.5 s. Each was logged `status` 200
  with `client_closed` false and ran to its end, 2.0 to 5.3 s. Together they held both large-body
  slots, so a large body sent 1 s later was answered 503. The same page says HTTP/2 does pass the
  disconnect on. So `dist/http.js` now serves HTTP/2 cleartext (h2c) when `MCP_H2C=1`, and the
  hosted deployment sets it together with Cloud Run's `--use-http2`. With that flag, Cloud Run
  speaks only h2c to the container. The server acts on a reset stream the moment it arrives, with
  any error code including `NO_ERROR`: the API calls are cancelled, `check_sbom` sends no further
  batch and ends a `Retry-After` wait, the large-body slot is freed, and the `mcp_request` line
  says `status` 499 with `client_closed` true. What Cloud Run forwards is only partly measured.
  On test deployments with `--use-http2` on 2026-10-05, ordinary calls, sessions and `/health`
  were all answered over h2c. A client that stopped reading a streamed answer had its stream reset
  by Cloud Run 15 s in (`rst_code` 2), and that was logged 499. A client that aborts mid-call
  before any answer was not observed, because every probe call was answered first, so whether
  Cloud Run forwards that reset at once is not yet shown. Until it is, an abandoned call may still
  run to its end, a `check_sbom` call for at most its 50-second budget, holding its slot. A new line, `mcp_client_gone`,
  records when the server learned the client went: `after_ms` from the request's start, whether
  the answer had started (`answer_started`), and an HTTP/2 stream's `rst_code`. It holds nothing
  of the request. Run yourself, `dist/http.js` speaks HTTP/1.1 as before. With `MCP_H2C=1` it
  speaks h2c with prior knowledge only, and an HTTP/1.1 request gets no answer.
- README, "Privacy: what is sent where": the hosted endpoint's paragraph now also says what the API logs
  of the calls it makes for you (#2797): each under your address, with its URL path (for a CVE, CWE or
  advisory lookup, the ID), and not its query string, the header-carried terms or which purls. The
  privacy policy's new Section 11, https://echelongraph.io/privacy#hosted-mcp-endpoint , says the same.
- `exposure_radar` relays and labels `mcp_servers.withheld_opted_out` (#2822): how many hostnames
  whose owner opted out of scanning the API left out of every other `mcp_servers` number. Such a
  hostname is not checked again while the opt-out stands, so its last verdict cannot be re-checked;
  the API now withholds it from the MCP-server counts as its unparameterised AI-exposure answer
  already did. An answer without the field, from an API that predates it, counted those hostnames,
  and the note says so instead of reading the absence as 0; a value that is not a whole number is
  left out and named.
- Claude Desktop in one click (#2815). From this release on, every GitHub release of
  [github.com/echelongraph/echelongraph-mcp](https://github.com/echelongraph/echelongraph-mcp/releases)
  carries `echelongraph-mcp.mcpb`, a Claude Desktop extension: open it and choose Install. It needs
  no Node.js on your machine, since Claude Desktop runs it with the Node.js it ships, and no JSON to edit.
  The README's Claude Desktop section links it as "Install in Claude Desktop", ahead of the custom
  connector and the `npx` setup. The release workflow builds it from the release tag, the same tag
  the npm package is published from: `listings/mcpb/build.sh` validates the manifest with the pinned
  MCPB CLI and packs. Then, on a separate read-only runner that never ran the MCPB CLI,
  `listings/mcpb/check-bundle.mjs` refuses a bundle that holds a top-level file `build.sh` does not
  stage, a symlink, or a file where `build.sh` stages a directory; that lacks the icon or entry point
  its manifest names, or `node_modules/`; whose `package.json`, `LICENSE`, `README.md` or `dist/` is not the tested npm
  tarball's, byte for byte (a file changed, missing or added); whose `node_modules/` adds or changes
  a file a production install from the lockfile does not have; that is at another version; or whose
  own server, started with `PATH`, `HOME` and `ECHELONGRAPH_API_BASE` only (none of the caller's
  `NODE_PATH`, `NODE_OPTIONS` or other variables), does not list the
  manifest's 14 tools with their titles. npm publishes only after that check passes, so a manifest
  or bundle defect stops the release before npm has the version. A separate job, which runs no
  dependency code, signs the checked bundle with a SLSA build-provenance attestation (Sigstore,
  keyless), attaches it and its Sigstore bundle to the release, each on its own, and checks the
  file the release serves with `gh attestation verify`. To check a download yourself:
  `gh attestation verify echelongraph-mcp.mcpb --repo echelongraph/echelongraph-mcp`.
  Releases up to 2.6.5 carry no bundle.
- Repository only, not in the package: `listings/mcpb/check-bundle.mjs` and
  `test/mcpb-release.test.mjs`; `test/mcp-stdio-client.mjs` takes a `cwd`.
- `sbom_review` reads the advisory interval in `check_sbom`'s `match_reason` by its closing
  bracket, without the hedge of 2.6.5 and earlier. `[A, B)` is a fixed bound: B, the first version the advisory
  records as not affected, is given as the fixed version (`[A, ∞)` names none). `[A, B] (B is the
  last affected version, not a fix)` is an OSV `last_affected` bound: B is still affected and the
  range records no fix, so neither B nor any version at or below it is given as a fixed version.
  The bracket alone decides: a cut text clips `match_reason` to 200 characters, which can drop the
  words after it for a long package name, and where it is clipped before the closing bracket
  (`[A, B…`), no fixed version is taken from that `match_reason`.
  Through 2.6.5 core-backend rendered both bounds as `[A, B)`, so the prompt gave B only as "the
  end of that interval"; core-backend now renders a `last_affected` bound closed (#2830). This
  wording assumes the API serves the new rendering: it is released after core-backend is deployed.
- `cve_intel` relays `fixed_branches` on each `affected_packages` row: every affected range of the
  package on record, each with `introduced` and `fixed` (the range's fix) or, where no fix is on
  record, `last_affected` (never in a field named fixed), and with `advisory_id` (the OSV record that
  published the range) and `source` (the loader's label for that record), from core-backend's
  `/api/v1/public/cves/:id/enrichment` since #2817. Ranges that name their record are in the order
  the record lists them; ranges loaded before the record was stored (both null) are oldest first.
  `fixed_branches` is null where a package's ranges were never loaded, and `[]` where no version
  range is on record (none in the advisory, only commit ranges, or more than are stored), which is
  not a finding that no fix exists. `fixed_version` is one range's fix per package,
  kept for compatibility: for CVE-2021-44228 production served log4j-core 2.12.2 alone (2026-10-04),
  the fix for 2.4 to 2.12.1, older than an affected 2.14.1, while the advisory
  (GHSA-jfh8-c2jp-5v3q) gives three ranges, fixed in 2.3.1, 2.12.2 and 2.15.0. The description says
  how to pick the range for an installed version, and the note counts the rows with more than one
  range, and those with no range on record (`fixed_branches` null, or `[]` beside a `fixed_version`),
  where `fixed_version` is all the answer holds. An API older than #2817 is said to be one (#2817).
- `triage_cve`'s patch line gives each affected range with its fix from `fixed_branches`, and
  `fixed_version` only for a package without them; `sbom_review` gives a component the fix of the
  `fixed_branches` range that holds its installed version (log4j-core 2.14.1: 2.15.0), after the
  advisory interval in `check_sbom`'s `match_reason`, and `fixed_version` only for a package without
  `fixed_branches` (#2817).
- `vendor_advisories_for_cve`, `search_vendor_advisories` and `get_vendor_advisory` relay each
  vendor's `held_since`, which the coverage API now serves: the start of the window EchelonGraph has
  read the vendor's advisories from, before which an advisory may not be held.
  `vendors_not_fully_held` reads it, not the earliest held advisory. For a vendor with no history read
  the earliest held advisory is not where its window begins: Cisco's poller first read the advisories
  Cisco had changed in the last 90 days, Red Hat's and GitHub's the last 7, so an older advisory the
  vendor revised later is held while the ones published beside it are not. Cisco's earliest held
  advisory is dated 2024-10-23 and Red Hat's 2009-02-04, so CVE-2025-20188 left out Cisco and
  CVE-2014-0160 left out Red Hat, and their empty answers read as the vendor having published nothing;
  both are listed now. GitHub is now listed too for any CVE ID year that begins before the start of
  its first poll's 7-day window (`held_since`), not only for years up to that of its earliest held
  advisory (2017). Against an API without `held_since`, a vendor is taken as held from its earliest
  advisory only when its history read is complete, and otherwise listed, its window written "not known
  to be without a gap" (#2803).

## 2.6.5 — 2026-10-05

2.6.4 was tagged and never published: its Release run failed `test/http-memory.test.mjs` on Node 24,
where `--max-old-space-size=128` alone allowed a 320 MiB heap in a 256 MiB instance. 2.6.5 is 2.6.4
plus the fix below; the `v2.6.4` tag stays, unpublished, because a tag is never moved.

- Hosted endpoint only: `Dockerfile.http` also passes `--max-semi-space-size=16`, so V8's heap limit is
  176 MiB on Node 22 (unchanged: the production image) and on Node 24 (was 320 MiB). The memory cap of
  #2773 now holds whichever Node the image uses.

- README: the header links the directories that list this server, Smithery and Glama (#2723). Smithery's
  verification looks for that link; `test/listings.test.mjs` pins it.

- Hosted endpoint only: an instance serves at most 64 requests at once (`MCP_MAX_IN_FLIGHT`); the
  next, its body read first (so a slow upload holds no place), waits up to 10 seconds
  (`MCP_ADMISSION_WAIT_MS`) for one to finish, and is then answered HTTP 503 with `Retry-After` and
  JSON-RPC error `-32030`. A 2026-07-28 `subscriptions/listen` stream is not counted: it stays open
  until its client leaves, carrying only keepalives (the server announces no list changes), so 64
  idle ones would leave every other request waiting 10 s for a 503; the SDK refuses a stream past
  1,024 open per process. The image runs Node with V8's heap capped at 128 MiB, half the
  instance's memory. Measured in a 256 MiB cgroup on a 16 GB host: two maximum-size SBOM documents
  beside 125 or more other requests got the server killed with every request on it, and holding
  that took both bounds. Node sized V8's heap from the host's memory, so garbage piled up until
  the kernel killed the process (whether Cloud Run's instance reports more than its 256 MiB is not
  verified), and 250 requests live at once exhausted even the capped heap. With both, 250 sent as
  they come are all served (the last after waiting about 9 s), peaking at 82-84% of the memory,
  and 250 at once are 64 served and 186 answered 503 after 10 s, peaking at 75-77%. The `mcp_request` line gains `in_flight` and
  `queued_ms`, the start-up line `heap_limit_mb` and `memory_limit_mb`, and a process started
  without the cap logs `mcp_remote_heap_unbounded`, where Node can read the container's limit
  (`memory_limit_mb` not null) (#2773).
- `check_sbom` stops when its call is cancelled: no further batch is sent, the batch in flight is
  cut off, and a `Retry-After` wait ends. Over stdio that is the client's
  `notifications/cancelled`, which before left the call sending its batches to the end. On the
  hosted endpoint it is the client going away (its own timeout, a closed tab): every API call of
  that request is cancelled, a `check_sbom` call holds its large-body slot until it has stopped,
  not only until its client has gone, and the `mcp_request` line says `status` 499 with
  `client_closed` true. Before, an abandoned call ran its batches to the end, spending the
  client's API budget, and was logged as 200 (#2775).
- Repository only, not in the package: the production synthetic's hosted leg sends `check_sbom`
  its 201 purls as a CycloneDX document, a ~138,000-byte request body, twice the endpoint's
  64 KiB general cap, and fails the probe unless the answer is `measured` from the document; a
  return of the 413 that #2747 removed now fails it (`rpc_error`, `-32600`). The synthetic's alert
  runbook says how to read that failure, and a memory alert on the hosted endpoint is written
  beside its uptime check (#2774, #2773).
- The prompts ask only for what their tools' first text block keeps, at their largest input. In
  2.6.3 each of the four asked for something that text leaves out of a large answer, or that the
  call it made did not return, so a client that passes only `content` to the model never showed
  it (#2799):
  - `kev_weekly_brief` reads `kev_recent` 50 rows a page, not 200. Each line of the brief names
    `kev_vuln_name` and `kev_due_date`. Read through the hosted endpoint on 2026-10-04 (2.6.3),
    365 days at limit 200 (306 CVEs) kept 5 fields a row in the text, neither of those two among
    them. A page of 50 comes back whole: 27,514 characters for production's 50 newest.
  - `check_affected` keeps `ransomware` and `epss_score` on every match at every cut level, the
    two fields `am_i_affected` lists for each match. In 2.6.3 a list at the API's cap of 200
    matches kept `cve_id`, `kev_listed`, `effective_score`, `effective_severity` and
    `score_assessed`: hosted, `linux_kernel` 5.10.0 had 20 CISA-KEV-listed matches and 1 with
    known ransomware use, named nowhere in the text. Since 200 such matches with
    `effective_severity` as well come to 33,240 characters, past the budget on their own, the
    leanest level leaves `effective_severity` out. The `excluded` and `undetermined` samples now
    keep their first 10 entries in the text (`excluded_count` and `undetermined_count` count every
    entry), so every match still stays in the text. The description's "at least" list says so.
  - `sbom_review` sends the purls not sent again from `data.not_sent_purls` only where the text
    holds that list whole. Where the note says the text cuts it (to its first 10), the model
    rebuilds the purls from the document instead: its distinct purls from the position the note
    gives, in the order the note gives. `check_sbom`'s note now gives that position, and the order
    it counts the input's purls in (a CycloneDX document's components depth first, each one's
    nested components right after it, each purl at its first place), whenever purls are not sent,
    not only when the text cuts the list. The prompt also says what to do when the note says rows
    are left out of the text: list the rows the text carries, and give the rest as
    `data.summary`'s counts.
  - `sbom_review` reads each affected CVE's fixed versions from `cve_intel`, called beside
    `get_cve` (`fixed_version` of its `affected_packages` and `fixed_versions` rows for the
    component's package). In 2.6.3 it asked for "fixed versions where a result gives them", and
    `check_sbom`'s text keeps `match_reason`, the advisory interval that names the fixed version,
    only at its first cut level: the 50 components of a Juice Shop SBOM are cut past it.
  - `sbom_review` never gives a fixed version that is not strictly greater than the component's
    installed version, compared in the ecosystem's version order (where the model is not sure of
    the order, it says so and gives none). It takes the end of the advisory interval in
    `match_reason` first, where the text keeps it, and otherwise `cve_intel`'s `fixed_version`,
    said to be one value per package, the advisory's last range's, which need not be the fix on
    the component's branch (#2817). Where no version qualifies, the line says the results give no
    fixed version for the component's branch and points to the CVE's advisory (`get_cve`'s
    references). Read through the hosted endpoint on 2026-10-04 (2.6.3), `cve_intel` gives
    log4j-core 2.12.2 for CVE-2021-44228, and `check_sbom`'s matches for 2.14.1 say it "is listed
    verbatim in the advisory's affected versions", so the entry above alone had the model give
    2.12.2 as the fix for 2.14.1. The prompt also reads each component's ecosystem, package and version
    from its purl, which every row the text keeps carries; the leanest cut, reached at 2,000 purls,
    leaves the row's own fields out.
    It maps a purl as `check_sbom`'s matcher does: the sixteen purl types with an ecosystem (`hex`,
    `pub`, `swift`, `hackage`, `cran`, `bitnami`, `conan` and `githubact` among them, which the
    first wording left out), `swift` and `githubact` named with their namespace as `npm`, `golang`
    and `composer` are, and `deb`, `apk`, `alpine` and `rpm` by a `distro` qualifier of
    `debian-N` (its major release), `ubuntu-V` or `alpine-X.Y` (cut to major.minor); for any other
    the ecosystem is unknown, and the fix list gives no version for it.
  - `triage_cve`'s patch line says that `cve_intel`'s `fixed_version` is one value per package, the
    advisory's last range's, and is given as what `cve_intel` records for that package, never as
    the fix for every affected branch; for a branch's fix it points to `get_cve`'s references
    tagged Vendor Advisory or Patch and to the vendor advisories (#2817). The line had asked for
    "fixed versions" alone, with no installed version to hold them against, so for CVE-2021-44228
    it could give log4j-core 2.12.2, `cve_intel`'s one value on 2026-10-04, as the patch, below the
    affected 2.14.1.
  - `triage_cve` reads CISA's due date, `kev_due_date`, from `get_cve`'s record and no longer calls
    `kev_recent`. Its step 6 read it from a `kev_recent` page of the CVE's `kev_added_date`, with no
    limit and no paging. Read through the hosted endpoint on 2026-10-04 (2.6.3), the page for
    2021-11-03 held 50 of the 287 CVEs CISA added that day, and not CVE-2021-40444, one of them;
    `get_cve` for CVE-2021-40444 carried its `kev_due_date` in its first text block.
- `cve://{cve_id}` stays under the 60,000-character ceiling. Its `data` is cut as `get_cve`'s
  first text block is, laid out the same way, after the envelope. In 2.6.3 it was `get_cve`'s
  structured result pretty-printed whole: 86,559 characters for CVE-2021-44228 on the hosted
  endpoint, against 23,705 now on the suite's production-shaped answer. Its notes no longer carry
  `get_cve`'s `TEXT CUT` sentences, which describe a first text block the resource does not have
  (they said `cpe_match` kept 64 entries while the resource carried all 396). When `data` is cut,
  the notes end with the resource's own sentence instead, starting `DATA CUT`, which names
  `get_cve`'s `structuredContent.data` as the record whole. A record that fits is unchanged,
  character for character. The resource's description and the methodology say so (#2801).
- No note promises a record or a component's matches "whole" from a tool whose text is cut too.
  The `TEXT CUT` sentences of `search_cves`, `kev_recent`, `get_cwe` and `check_affected` say that
  `get_cve` returns a record whole in its `structuredContent.data` and, in its first text block,
  with every field, each list cut to its first entries past 30,000 characters. `check_sbom`'s
  sentence says the same of `check_affected` and a component's matches, and the vendor-advisory
  tools' of `get_vendor_advisory`. `get_cve`'s description and the README begin "One CVE's
  record", no longer "Full record for one CVE". The source comments and the README no longer say
  that `content[0]` always equals `data`. The 2.6.3 entry below gives the sizes production's record
  holds for that release (26,011, 27,777, 28,793, 31,583 and 23,028), measured after #2729, in
  place of the 25,951, 27,717, 28,733, 31,588 and 19,917 measured before it (#2802).
- Repository only, not in the package (#2800, #2799):
  - Every production-shaped case's text is held within 50 characters of its recorded size, in
    either direction. A text that shrinks is re-measured as one that grows is.
  - The fields each description says a cut row keeps "at least" are read from the description
    and checked on every row of every production-shaped case, for `search_cves`, `get_cwe`,
    `kev_recent`, `check_affected` (its samples too), `check_sbom` and the vendor-advisory lists,
    and at least one case of each tool must be cut. No answer the API serves reaches the cut of
    `get_cwe` (each row's description is cut to 240 characters at the source) or of
    `vendor_advisories_for_cve` (at most 20 short rows), so each has a forced case: production's
    rows made longer. `get_cve` is held to keep every field. Removing `severity`, `cvss_v3_score`,
    `echelongraph_score`, `score_assessed`, `epss_score` and `kev_listed` from `search_cves`'s
    cut levels, which left 2.6.3's suite green, now fails it, as does dropping a field from
    `get_cwe`'s.
  - Each prompt's tool calls are made as the prompt says, at its largest input, on
    production-shaped answers, and every field the prompt names must be in the text a client
    that passes only `content` shows the model. Every tool a prompt names must be one of those
    calls.
  - A new test makes each prompt's tool calls as the prompt says, at its largest input, on
    production-shaped answers, and checks every field the prompt names in the text: 365 days of
    KEV additions, `check_affected` at its cap of 200 matches (both lookup paths), a 2,000-purl
    SBOM answered in full and rate-limited, and `triage_cve`'s six tools.
  - That test reads `sbom_review`'s `ecosystem`, `package` and `version` as fields: on a row whose
    text leaves them out, reading them from the purl as the prompt says must give the answer's.
    On production's `cve_intel` for CVE-2021-44228 and production's `check_sbom` answer for
    log4j-core 2.14.1 (captured 2026-10-04), the prompt's fix rule must offer no fixed version,
    2.12.2 among the candidates, and on Juice Shop's lodash 4.17.19 it must offer 4.17.21 (#2817).
- `cve_summary` no longer fails when the `poller` block changes JSON type: a poller field the
  answer sends in a type other than the one its outputSchema describes (`interval` as a Go
  duration such as 1200000000000, `last_poll_at` as unix seconds, `cves_ingested` as a string) is
  left out of `data` and named in the note, and a `poller` that is neither a JSON object nor null
  is left out whole. `summary` and the rest of the answer are relayed as sent, measured. From
  2.6.2 one such field failed the whole call with `unexpected_shape` and withheld `summary.total`,
  and an installed 2.6.2 or 2.6.3 still does: upgrade. The tool's description, the
  `echelongraph://methodology` resource and the README say that `cve_summary`'s `data` is the
  API's JSON less what the note names as left out (#2771).
- `echelongraph://sources` says what the NVD poller's `poll_count` and `poll_errors` are whenever
  it relays either: that one instance's counters since it last started, zeroed on every restart,
  never the feed's reliability. The resource's description and the README name all four fields it
  relays. A `poller` the answer sends as something other than a JSON object is named as such,
  never as a missing block (#2770).
- package.json's `description` fits the 255 characters npm's registry serves, so npm search,
  `npm view` and the package page show it whole, with the per-CVE exposure footprint, its Shodan
  attribution and Shodan's ownership sentence; through 2.6.3 npm cut the 443-character text
  mid-phrase. A test holds it to 255 characters and whole sentences (#2779).
- package.json's `keywords`, and the public repository's GitHub topics, are held to the
  description's wording rules by a test: no claim the package's own copy is barred from, no
  ip:port service count named as machines, and nothing exclusive or comparative (#2780).
- Tests: check_sbom's description and the README's privacy section are pinned to saying that over
  the hosted endpoint the document is the request body and reaches EchelonGraph's server, which
  neither logs nor keeps it, and to never denying that the document is sent (#2796). The denials
  are one list, `test/document-denials.mjs`, that the monorepo's /pulse/mcp check reads too, in
  every noun `check_sbom` uses for its input; the README check's own list had passed "The server
  never sends the document.", "The document is processed locally." and "Only the purls are sent."
  (#2796, #2795).
- `check_sbom`'s `sbom` argument said "its purls are read here and only they are sent", which over
  the hosted endpoint is not so: there the whole document is the request body. It now says the
  purls are read by this MCP server and only they are sent to the API, and that over the hosted
  endpoint (mcp.echelongraph.io) the document is the request body, in the description's own words.
  The README Tools table's `check_sbom` row, which ended "the document is not.", says the same.
  Tests: every string of `check_sbom`'s tools/list entry, its argument and output descriptions
  among them, and that README row are now held to the denial list, which also reads "not sent on"
  as true only when the clause ends there, and catches more wordings of where the document stays
  or is processed (#2796).

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
  the 60,000-character ceiling; the same calls now measure 13,513, 22,960, 26,011 (27,777),
  28,793, 31,583 and 23,028. The JSON is first laid out one row a line, which loses nothing; past
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
