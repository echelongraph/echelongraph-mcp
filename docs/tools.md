# echelongraph-mcp: how each tool reads its answer

Part of the [README](../README.md), whose Tools table says what each tool answers. This page says,
field by field, how `cve_summary`, `get_cve`, `search_cves`, `cve_exposure` and `check_affected`
read the API's answer; `exposure_radar` has [a page of its own](exposure-radar.md). It is kept out
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
`get_cve` relays the CNA's own sentence as `cna_solution`, its date for when the vulnerability was
made public as `date_public` (with `date_public_source` `cna`), and the CNA as `cna`, each only
where the CVE record has it. `false` means no fix evidence is on record, which is **not** a
finding that no fix exists. Once `true`, `patch_available` is not set back to `false`, so it can be
`true` beside an empty `patch_evidence`: evidence of a fix once held has since been withdrawn, and
`remediation.fix_status` in the CVE's record is the current reading, not `patch_available` (since
3.0.1 the field's outputSchema text says so). An answer with no `patch_evidence` (an API older than that
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
- **Registry path** — `ecosystem` (`npm`, `PyPI`, `Maven`, …), `package` and `version`. Each OSV
  advisory record EchelonGraph holds for the package is decided against the version as
  affected (a match), not affected (`not_affected_count`) or undetermined.

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
the version, and `fixed_in_reason` then says which: a null is not a finding that no fix exists. A CPE
match carries no `fixed_in`, since the end of a CPE version range is not a fix. `check_sbom` and
`scan_manifest` relay the same fields (`interval`, `fixed_in`, `fixed_in_reason` and
`fixed_in_detail`) on each match.

`product`, `version`, `ecosystem` and `package` travel in the `X-EG-Product`, `X-EG-Version`,
`X-EG-Ecosystem` and `X-EG-Package` request headers, never in the URL, so request logs and
trace spans that record URLs do not hold what was looked up. The endpoint reads a CPE vendor
from the URL only, so this tool takes none.
