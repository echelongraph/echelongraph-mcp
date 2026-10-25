# echelongraph-mcp: how each tool reads its answer

Part of the [README](../README.md), whose Tools table says what each tool answers. This page says,
field by field, how `cve_summary`, `get_cve`, `search_cves`, `cve_exposure` and `check_affected`
read the API's answer, and how `check_sbom` and `scan_manifest` cut their rows past the
structured result's budget; `exposure_radar` has [a page of its own](exposure-radar.md). It is kept out
of the README because npm keeps only the first 65,536 characters of a package's README, and the
package ships it in `docs/`. Exposure counts are derived from Shodan data. Shodan data is owned by
Shodan, which holds its copyright (© Shodan).

## How `cve_summary` reads its counts

`summary.critical`, `summary.high`, `summary.medium` and `summary.low` count the active CVEs by
severity band, and `summary.total` counts them all. `summary.none` counts the active CVEs with no
severity band from any source: CVEs not yet scored, not CVEs rated None. The answer sends the same
count again as `summary.unscored`.

`summary.nvd_critical`, `summary.nvd_high`, `summary.nvd_medium`, `summary.nvd_low` and
`summary.nvd_none` count the same active CVEs a second time, by NVD's CVSS severity label (v3.x,
else v4.0). Before NVD's record arrives, or where it gives none, a pre-NVD label from the CVE.org
record or a GitHub advisory can stand in. They are provenance, never EchelonGraph's severity band. `summary.nvd_none` counts the active CVEs with no
Critical, High, Medium or Low label there, and many of those carry an NVD CVSS v2 score instead, so
it is neither a count of CVEs rated None nor the count of CVEs with no severity, which is
`summary.none`.

`summary.rejected` counts the CVE records rejected (withdrawn) by their numbering authority.
`summary.total` and the other counts leave them out, and they are withdrawn records, never
vulnerabilities.

`poller` holds the in-memory counters of the NVD poller of the one API instance that answered,
counted since that instance last started and zeroed on every restart: they describe that instance,
never the feed's size, intake, reliability or freshness, and the note says so whenever the answer
carries `poller`. A `poller` field the answer sends in a JSON type other than the one the
outputSchema describes is left out and named in the note, and a `poller` that is neither a JSON
object nor null is left out whole; `summary` is relayed either way, so a change to that diagnostic
block never withholds the counts.

`nvd_poll` is when the fleet of API instances last completed an NVD poll: `last_completed_at` (the
end of the last window fetched and stored without an error), with `scope` `fleet` and the poll's
`interval`. The API leaves it out when that time is unknown, and never puts the answering
instance's counters in its place. It is the result's `freshness` (`freshness.nvd_poll`, its time as
`last_run_at`) where `last_completed_at` is a real RFC 3339 time at most 5 minutes after this
server's clock and `scope` is `fleet`. Otherwise `freshness` is `null`, and the note says whether
the answer carries no `nvd_poll` or one without such a time. `poller.last_poll_at` is never the
feed's freshness.

The tool relays the API's JSON as it was sent, less a `poller` field left out as above. When
`summary.none`, `summary.nvd_none` or `summary.rejected` is above zero, the note says what it
counts, with the number from the answer.
The note says the five NVD counts add up to `summary.total` only when the answer's do, and says
nothing about a field the answer does not carry.

## How `get_cve` and `search_cves` read the EchelonGraph score

`echelongraph_score` (0 to 10), its band `echelongraph_severity` and the risk priority
`echelongraph_risk` (0 to 100) are EchelonGraph's score only when the record's
`score_assessed` is `true`. A CVE EchelonGraph has not scored carries `score_assessed: false`,
and it is **not yet scored**, not scored 0. The API leaves those three fields out on it, or (an
API before that change) sends `0`, `NONE` and `0` as placeholders, which are not a rating and do
not mean the CVE is harmless. Its `score_confidence` is `NONE`, and `score_unassessed_reason`
says why: no source has yet published severity data EchelonGraph can score, or the record was
rejected (withdrawn) by its numbering authority, and a rejected record is never scored.

Both tools relay the API's JSON as it was sent, and the note says what the score is, for
`get_cve` per CVE and for `search_cves` per row, naming each CVE it is about:

| API answer | What the note says |
|---|---|
| `score_assessed: true` | Nothing more: the score is a score. |
| `score_assessed: false` | **NOT YET SCORED**, tagged "(score_assessed: false)": report the CVE as not yet scored, never as a zero or low score. Each of `echelongraph_score`, `echelongraph_severity` and `echelongraph_risk` it carries is named as a placeholder. A rejected record is **NOT SCORED** instead. |
| no `score_assessed` field | The answer does not say whether the CVE was scored (an API older than the field), and a zero `echelongraph_score` in it is not a rating. |

## How `get_cve` and `search_cves` take an EUVD, GHSA, OSV or GCVE-0 ID

`get_cve`'s `cve_id` may be a CVE ID or another identifier of the same vulnerability: an ENISA
EUVD ID (`EUVD-2026-90503`), a GitHub Security Advisory ID (`GHSA-xxxx-xxxx-xxxx`), an OSV ID
that aliases a CVE (`PYSEC-`, `GO-`, `RUSTSEC-`, `GSD-`, `MAL-`) or a GCVE-0 ID
(`GCVE-0-2024-3094`), in any letter case. The server sends it as asked; EchelonGraph's API
resolves it to its CVE and answers with that CVE's record, carrying `resolved_from`: the ID asked
for, its `namespace`, and the `source` that mapped it — `enisa_euvd`, `github` or `osv` through
EchelonGraph's alias table, or `gcve_gna0`, the GCVE specification itself, under which
GCVE-0-YYYY-N is CVE-YYYY-N. The note says so: "Resolved EUVD-2026-90503 (euvd) to
CVE-2026-80276 through EchelonGraph's alias table (source enisa_euvd). Source: ENISA EUVD." An ID the table maps to
no CVE is the API's 404, one that names several CVEs (a GHSA can) its 300 listing them, and an
alias table that could not be read its 503: each is a failed result quoting the API's message,
never an empty one.

A `search_cves` search for such an ID lists exactly the CVEs it names, and the page carries
`resolved_from` too; the note says the rows are exactly those CVEs.

The record's `aliases` lists the CVE's other identifiers with their sources. Its `eu_kev`, where
present, is the CVE's listing on ENISA's EU Known Exploited Vulnerabilities catalogue: ENISA's
date (`date_added`), the reporting source as ENISA records it (`reported_by`), and ENISA's
attribution on every listing. EUVD IDs in `aliases` and `eu_kev` are served only while
EchelonGraph displays ENISA's data; the note names an EU KEV listing as ENISA's data. `kev_listed`
remains CISA's catalog.

Every value of ENISA's EUVD carries the attribution "Source: ENISA EUVD": each EUVD ID in
`aliases`, a `resolved_from` whose `source` is `enisa_euvd`, and the `eu_kev` listing, whose
attribution begins with it. Each sentence of the note that names ENISA's data ends with that
attribution, and says it even where an older API answer carries no `attribution` field. GitHub's and
OSV's values carry none.

## What `patch_available` says

`patch_available` is `true` when EchelonGraph holds, or once held, evidence of a fix for the CVE,
and `patch_evidence` lists the sources it holds now, strongest first: `vendor_patch` (a vendor
patch on record, from Ubuntu or Red Hat), `fixed_version` (a fixed version recorded for an
affected package, or the fixed bound of an affected version range), `release_reference` (a
reference that EchelonGraph confirmed through the GitHub API is a published release containing
the fix, or a pull request or commit that a published release contains), `vendor_advisory_fix` (a
vendor advisory that lists a fix for the CVE under the vendor's own structured category: Red Hat's
CSAF `vendor_fix`, Microsoft's Vendor Fix), `nvd_patch_reference` (an NVD reference tagged Patch),
`cna_patch_reference` (a reference the CVE's CNA tagged `patch` in its CVE record), `cna_solution`
(a sentence of the CVE record's solutions, written by its CNA, that names a fixed version) and
`description_fix` (a sentence of the CVE description that names a fixed version). A reference page
that only mentions a patch, and a CVE's presence in CISA's KEV catalog, are not evidence.
`get_cve` relays the CNA's own sentence as `cna_solution`, which section of the record it is as
`cna_solution_section` (`solution` or `workaround`: a workaround's sentence is the record's
workaround, never its solution), its date for when the vulnerability was made public as
`date_public` (with `date_public_source` `cna`), and the CNA as `cna`, each only where the CVE
record has it. `false` means no fix evidence is on record, which is **not** a
finding that no fix exists. Once `true`, `patch_available` is not set back to `false`, so it can be
`true` beside an empty `patch_evidence`: evidence of a fix once held has since been withdrawn, and
`remediation.fix_status` in the CVE's record is the current reading, not `patch_available` (since
3.0.2 the field's outputSchema text says so). An answer with no `patch_evidence` (an API older than that
field) does not name the evidence, and a `false` there is not a finding that no fix exists either.
Both tools relay the two fields as the API sends them.

## How `cve_exposure` counts

Every 12 hours, when Shodan query credits allow, the KEV-exposure radar runs one Shodan query
per tracked product, reads up to 100 ip:port services per query, and keeps a service when its
banner version matches a CISA-KEV or high-EPSS (>= 0.5) CVE. A service whose row has not been
written or refreshed for 21 days is dropped. A count is therefore a banner-version inference
over a sample: not an exploit test, and not an internet-wide census.

`last_seen` is when EchelonGraph last wrote or refreshed a service's row, not when the service
was observed, and not when its vulnerable version was last confirmed. It is set to the time of
the write when a search matches the banner, and again when a re-check finds the port still
listed by Shodan InternetDB, without re-reading the banner, so a patched service can stay
counted while its port stays open. Shodan's own time for the banner is not stored. So
`last_seen` dates the write, never the sighting, and it is never `measured_at` (see
[Structured results](../README.md#structured-results)).

The unit is a service, not a machine. Shodan returns one banner per port and the radar keys
each observation on ip:port, so a machine answering on two ports counts twice. The API's field
names are kept (`exposed_hosts` here; `distinct_hosts`, `ransomware_hosts` and each ranked
row's count in `exposure_radar`), but every one of them counts ip:port services.

The radar only looks for its **tracked** set of CVEs, so a zero means different things. The
note tags each case with its `exposure_state`, as "(exposure_state: …)"; that tag says what the
count is, and is not the result's `state`:

| API answer | What the tool says |
|---|---|
| `tracked: true`, `exposed_hosts` above 0 | `exposure_state` `exposed`: the count of services the radar has on record for the CVE. |
| `tracked: false` | `exposure_state` `not_assessed`, **NOT ASSESSED**: outside the radar's tracked set; 0 is not a measurement. |
| `tracked: true`, `exposed_hosts: 0` | `exposure_state` `measured_zero`, a zero in the radar's sample: none of the up to 100 services it read per tracked-product query matched. Not an internet-wide zero, and undated: the answer does not say when the radar looked. The backend does not send this answer today. |
| no `tracked` field | The API did not say whether the CVE is in the tracked set: an older API, or the radar cannot decide (for example a CISA-KEV or high-EPSS CVE in a tracked product with 0 services on record). 0 exposed services on record, with no claim either way (`exposure_state` `tracking_unknown`). |
| HTTP 400, or an id that is not `CVE-YYYY-NNNN…` | An error result tagged `invalid_input`; nothing was looked up. |

Whatever the `exposure_state`, the result's `state` is `not_assessed` with `measured_at` `null`:
the answer does not say when any service it counts was observed (see [Structured results](../README.md#structured-results)).

## How `check_affected` decides

`check_affected` asks the matcher behind
[echelongraph.io/am-i-affected](https://echelongraph.io/am-i-affected) whether a version is
affected, by one of two lookup paths:

- **CPE path** — `product` and `version`. `product` is the NVD CPE product token (`openssl`,
  `nginx`), which can differ from a package name. It returns the CVEs whose NVD CPE match
  criteria name that product with a version range that includes the version. It matches the
  token across vendors, so each match carries `cpe_vendor` and `vendor_unknown`: a match with
  `vendor_unknown` true is real, but its vendor is not verified to be yours.
- **Registry path** — `ecosystem` (`npm`, `PyPI`, `Maven`, …), `package` and `version`. Each CVE
  named by the OSV advisory records EchelonGraph holds for the package is decided against the
  version once, as affected (one match), not affected (`not_affected_count`) or undetermined
  (`undetermined_count`). When OSV publishes one CVE for the package in several records (a GHSA
  and a package repository's own advisory, say), EchelonGraph stores a row for each and decides
  them together, so the two counts count CVEs, while `advisories_considered` counts the stored
  rows: a CVE stored as two rows and cleared counts 2 in `advisories_considered` and 1 in
  `not_affected_count`.

Read `assessed` before `count`. `assessed` false means the lookup did not evaluate the
component, and `not_assessed_reason` says why: `product_not_in_cpe_corpus`,
`package_not_cpe_nameable`, `candidate_load_pending` (with `degraded` true),
`candidate_window_truncated`, `package_not_in_advisory_corpus` or `no_decidable_advisory`. The
result's `state` is then `not_assessed`, and its `count` of 0 never means "not affected". An
advisory whose version range cannot be decided at this version is counted in
`undetermined_count` (up to 50 listed in `undetermined`) and is never reported as safe. `capped`
says the match list stopped at its cap, and `candidates_capped` that not every candidate CVE was
loaded. A failed advisory lookup (`advisory_lookup_failed`) comes back as a failure. Each match
keeps `kev_listed`, `ransomware`, `epss_score`, `effective_score`, `effective_severity` and
`score_assessed` as the API sent them.

A registry match also carries `interval`, the advisory interval that holds the version
(`introduced`, and `fixed`, exclusive, or `last_affected`, inclusive), and `fixed_in`, the lowest
version above the one asked about that no affected interval of the same record holds: the
holding interval's fixed bound, moved past any overlapping interval that still holds that bound,
and `fixed_in_detail` then names the intervals it moved past (#3074). `fixed_in` is always above
the version asked about. It is null where no such version is recorded (the walk reaches an
interval that ends at `last_affected`, or has no end, with none beyond it) or no interval holds
the version, and `fixed_in_reason` then says which: a null is not a finding that no fix exists. When
a CVE is stored as several records (#3137), `fixed_in` is walked over the records that store
intervals. A record of the same CVE that stores none withholds it only when that record's versions
or recorded fix may hold it affected. A record that cannot decide it (no version data, a git commit
range, or one recorded fix that `fixed_in` is at or past) does not, so the same lookup at
`fixed_in` itself can come back undetermined rather than not affected. A CPE
match carries no `fixed_in`, since the end of a CPE version range is not a fix. Once
EchelonGraph's API serves it, a CPE match carries that end in its own field, as NVD states it,
`cpe_version_end_excluding` (the first version the matched range no longer holds) or
`cpe_version_end_including` (the last one it holds), absent where the range sets no end. Only the
first cut level of the text and the first thinned level of `data` keep them, so a CPE answer cut
past those levels, as typical ones are, carries them only with `full: true`. Another range of the
same CVE, or a vendor backport, can sit past it, so it is never given as a fixed version. `check_sbom` and
`scan_manifest` relay the same fields (`interval`, `fixed_in`, `fixed_in_reason` and
`fixed_in_detail`) on each match.

`product`, `version`, `ecosystem` and `package` travel in the `X-EG-Product`, `X-EG-Version`,
`X-EG-Ecosystem` and `X-EG-Package` request headers, never in the URL, so request logs and
trace spans that record URLs do not hold what was looked up. The endpoint reads a CPE vendor
from the URL only, so this tool takes none.

## The client cut

The server instructions and every tool description are held to 2,048 characters
(`CLIENT_DESCRIPTION_CUT`, `src/requiredText.ts`), and the sentences a client must not lose sit in
the first 2,048 characters of each (`REQUIRED_IN_HEAD`). 2,048 is the shortest cut a client is
known to make:

- Claude Code from v2.1.280 sends the model at most `CLAUDE_CODE_MAX_MCP_DESCRIPTION_LENGTH`
  characters of each description and of the instructions. Its documented default was 2,048 when
  this budget was set (read 2026-10-05). On 2026-10-18 its documentation gives 4,096, and 16,384
  for a tool it loads through tool search, and v2.1.302's debug log shows a 4,096 cut ("Tool
  "exposure_radar" description truncated from 11807 to 4096 chars", from 2.6.8's 11,807-character
  description). Builds between v2.1.280 and that change still cut at 2,048.
- Cursor cuts tool descriptions at 6,500 characters. VS Code and Claude Desktop document no cap.

Text that fits 2,048 therefore reaches each of them whole. The tests hold every served text to it
over stdio (`test/tools.test.mjs`) and over the hosted endpoint (`test/http.test.mjs`), and the
synthetic writes an `mcp text cut` line per transport and era that an alert reads.

## How `check_sbom` and `scan_manifest` cut their rows

Past 30,000 characters of structured result, and without `full: true`, `check_sbom` and
`scan_manifest` cut `data` in this order (the note's `DATA CUT` sentences say where each answer
stopped):

1. `scan_manifest`'s `not_checked`, then `not_sent_purls`, which is kept whole or not at all (the
   note gives the positions of the purls not sent, so a second call can send them).
2. Every row is thinned, every row kept: each keeps `index`, `purl`, `verdict`,
   `not_assessed_reason`, `cve_ids`, `matched_package` and `matched_via` (and an upstream row's
   `matched_version_from` and `purl_name`), and each match `cve_id`, `kev_listed`, `ransomware`,
   `epss_score`, `effective_score`, `score_assessed`, `fixed_in` and `fixed_in_reason`: every field
   a prompt reads from a match.
3. Before any other row's matches are cut, the `not_affected` and `not_assessed` rows are cut to
   `index`, `purl`, `verdict`, `not_assessed_reason` and `cve_ids`, and leave, the `not_affected`
   ones first, as many as must for every other row to keep all its matches. `data.summary` counts
   every verdict, and the note says how many left (#3269).
4. Where the other rows' matches must be capped even with all of those rows gone, those rows stay
   instead, cut so, while every other row fits at its floor: its matches used in ransomware or
   KEV-listed, and 10 more (#3269's review). Each row's matches are capped at one number, the most
   that fit, never under 10, and a row whose floor is above that number keeps its floor. A row
   with more keeps the matches chosen used in ransomware first, then its other KEV-listed ones,
   then those of highest `effective_score`, listed in the API's order, and carries
   `matches_truncated`: its total, the number returned, and the KEV-listed and ransomware CVE IDs
   and `fixed_in` versions of all its matches (#3270). Only where even the floor does not fit with
   every one of those rows do they leave, as many as must for it to.
5. Each match is cut to the fields of step 2 less `fixed_in_reason`, still capped as step 4 says:
   every level that keeps matches keeps every field `workload_triage` ranks by. A null `fixed_in`
   there without its `fixed_in_reason` is a reason cut for size, and `sbom_review` never calls it
   no fix: it checks the purl again with `full: true`, or reads the fix from `cve_remediation` or
   `get_cve`. Kept here, the reason cost the 201-purl probe a row (43 to 42).
6. Where even that does not fit with all of those rows gone, no row's matches are cut below its
   floor (#3269's second review): the other rows leave instead, whole, at step 5's level and
   their floor. The rows kept are chosen those with a KEV-listed or ransomware match first, then
   the others, each in input order, each one that fits beside those chosen before it, so a row
   too large to fit beside them leaves and the rows after it can stay. The note names the
   `affected` and `undetermined` rows that left by `index`, those with a KEV-listed or ransomware
   match first and apart from the others (the first 100 indices or runs of them in all), and
   `check_sbom`'s note says how to check them again (#3269's third review): "Re-check these K
   purls in this order, in calls of 7, 5, 8, 8 and 16, then of at most 17: each such call keeps
   every row in data." Each of the first five sizes is the most of the rows left, in that order,
   that the cut's own measure counts as fitting at their floor with `FIRST_FIT_SLACK` (600
   characters) held back, so a lower bound: a real call of them often keeps more. The last is the
   most such that any that many of the rest in a row count so. Each is counted for those rows, as
   the cut would cut such a call, with this call's note longer by what such a call's note names of
   them (its affected components). A call of fewer of them in a row keeps every row too. A row whose floor alone is
   past the budget goes in a call of its own. Where not even one row fits at its floor (one row
   whose KEV-listed matches alone are past the budget), the row chosen first stays alone with the
   most of its matches that fit, chosen as in step 4, and the note says so; where not one match
   fits beside it, with none.
7. Only where no row but the `not_affected` and `not_assessed` ones has a match is each row cut
   further, to `index`, `purl`, `verdict`, `not_assessed_reason` and `cve_ids`, before rows leave.

Once the cut is settled, the rows kept take back detail in input order while room is left, and
then the rows steps 3 and 4 sent out come back, cut as step 3 says, as many as the room left
holds, where every other row stayed.

When rows leave `data`, the note names a page size N: "A call of the first N of these purls, or
of fewer, keeps every row in data; a call of other purls says in its own note what it leaves
out." (`scan_manifest`: a call whose files hold the first N of these purls.) N is counted for this
answer's own rows, as the cut above would cut a call of them, so it can be larger or smaller than
the number of rows this answer keeps; it is not a page size for the rest of the purls, whose rows
can be larger: round 2's "To read every row in data, check N or fewer purls per call" read as
one, and calls of the purls in chunks of N lost rows in 55% of such mixes (#3269's second review).
Nor is it a size for checking the rows left out again, which are the heavy ones: calls of N of
them dropped 504 of 2,540 rows on realistic Debian images (#3269's third review); the re-check
sentence of step 6 gives those sizes. `workload_triage` (its step 6) and `sbom_review` (its step
1) check again the `affected` and `undetermined` rows the note names, those with a KEV-listed or
ransomware match first, in calls of the sizes that sentence gives, at most 5 calls, and report the
rest as unchecked; `workload_triage` takes its counts from `data.summary`, which counts every row
whatever the cut. `scan_manifest` names its rows left out the same way and gives no re-check sizes:
its rows are checked again through `check_sbom`, by purls its note does not give.

The first text block, past its own 30,000 characters, keeps the same priority: before any row is
cut to `index`, `purl`, `verdict`, `not_assessed_reason` and `cve_ids`, the `not_affected` and
`not_assessed` rows are cut to that and leave the text, as many as must, so an affected row keeps
its matches while room allows; only where that cannot fit is every row cut so, and then rows
leave, those two kinds first, and the rows with a KEV-listed or ransomware match last, as `data`
keeps them (#3284: through 3.1.0's review the text left the rest from the end in input order, so a
KEV-bearing row `data` kept could leave the text unnamed; on 36 realistic Debian 12 images a client
reading the text alone missed 95 of 413 such rows). The note names by `index` each of those that
still leaves ("Of the rows left out of it, 30 have a KEV-listed or ransomware match: at index 511
to 513, …"). The note says what those rows leave out, and that each string in
them keeps its first 100 characters where one is longer. The text names no page size (through
#3269's review it said "check N or fewer purls per call", N the rows it kept, and a call of the
first N purls kept fewer in 34 of 89 mixes); its note says how many rows it leaves out, of which
kinds, and that `structuredContent.data` holds them.
