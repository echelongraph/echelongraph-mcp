# How `exposure_radar` counts

Part of the [echelongraph-mcp README](../README.md): every number `exposure_radar` relays, radar by
radar, and what it counts. It is kept out of the README because npm keeps only the first 65,536
characters of a package's README, and the package ships it in `docs/`. Exposure counts are derived
from Shodan data. Shodan data is owned by Shodan, which holds its copyright (© Shodan).

`exposure_radar` relays each radar's answer cut to the fields it can label, and its note labels
every number by what it counts. A field this version does not know is left out and the note
names it, whether it is a total or a field inside a ranked row; so is a known field in an
unexpected shape, and a list with one malformed row is left out whole, since a partial list
reads as a complete one. `kev_exposure`, `exposed_databases` and `leaked_credentials` also
carry `generated_at`, when the API computed their totals, and, when the API can tell,
`last_run_at`: when that radar last completed a check (each table below says what a completed
check is for that radar).

`last_run_at` is a timestamp, not a count. It is recorded for the radar as a whole, not for
the server instance that answered, in UTC to the second. It moves only at the end of a cycle
whose reads succeeded, so a cycle that read nothing leaves it where it was. It is not the time
of every record a radar's numbers count: those cover everything still on record, not only what
the last check found. Nor is it `generated_at`, which is only when the API recomputed the
totals. The API omits `last_run_at` when it has no completed check on record or cannot read
it; the result then carries none, and the note says nothing about it. When it is there, the
note gives it as, for example, "kev_exposure last completed check: 2026-09-27T03:12:44Z".

## `kev_exposure`

Every count is over the services the KEV-exposure radar keeps: a Shodan banner whose version
maps to a CISA-KEV-listed CVE (see [How `cve_exposure` counts](tools.md#how-cve_exposure-counts)).

| Field | What it counts |
|---|---|
| `kev_exposure.distinct_hosts` | Distinct ip:port services, not machines, with at least one CISA-KEV-listed CVE on record. A machine answering on two ports counts twice. |
| `kev_exposure.ransomware_hosts` | The services among them with at least one ransomware-linked KEV CVE (one whose KEV entry notes known use in ransomware campaigns). |
| `kev_exposure.kev_cves_exposed` | Distinct CISA-KEV-listed CVEs with at least one service on record. |
| `kev_exposure.ransomware_cves` | The ransomware-linked CVEs among them. |
| `kev_exposure.correlations` | Service×CVE pairs, not services: a service with three KEV CVEs counts three times. |
| `kev_exposure.top_products`, `kev_exposure.top_countries`, `kev_exposure.top_cves` | Up to 12 products, 10 countries and 12 CVEs, ranked by distinct ip:port services. |
| `kev_exposure.top_cves[].cvss_v3_score`, `kev_exposure.top_cves[].epss_score` | Scores, not counts: the highest CVSS v3 base score and EPSS probability (0 to 1) recorded on that CVE's observations. |
| `kev_exposure.trend` | Service×CVE pairs, not services, by the week (starting Monday) in which each pair was first recorded, over the last 12 weeks. Only pairs still on record are counted, so earlier weeks read low. |
| `kev_exposure.newest_kev` | The 15 CVEs that EchelonGraph's CVE records most recently mark as CISA-KEV-listed (by `added_date`), each with an `exposure_state` (below). |
| `kev_exposure.newest_kev[].exposed_hosts` | Only on a row whose `exposure_state` is `exposed` (or `measured_zero`): distinct ip:port services on record with that CVE. |
| `kev_exposure.newest_kev[].cvss_v3_score`, `kev_exposure.newest_kev[].epss_score` | Scores, not counts: the CVE record's CVSS v3 base score and EPSS probability (0 to 1), absent when the record has none. |
| `kev_exposure.last_run_at` | A timestamp, not a count: when the radar last completed a check, a cycle in which its Shodan search answered at least one query (others may have failed) and its list of services due for a re-check was read. A cycle that skipped the search for want of Shodan query credits, or whose reads failed, does not move it. |
| `kev_exposure.window.from`, `kev_exposure.window.to` | Timestamps, not counts: when Shodan collected the banners of the oldest and the newest of the service×CVE pairs counted, Shodan's own times, not when EchelonGraph stored or re-checked a pair; a span of observations made at different times. Relayed only when every counted pair has such a time; otherwise the note says how many do not. |
| `kev_exposure.dated_window.from`, `kev_exposure.dated_window.to`, `kev_exposure.dated_window.undated` | Relayed instead of the window when some counted pairs have no banner time on record (pairs stored before the banner time was captured stay so while the InternetDB re-check keeps them): from and to are the same Shodan banner times over the dated pairs only, and undated counts the pairs with none. The note gives both numbers; the window does not describe the undated pairs. |

A `newest_kev` row's `exposure_state` says whether its count is a measurement:

| `exposure_state` | What it means |
|---|---|
| `exposed` | The radar has services on record with this CVE, and `exposed_hosts` counts them. |
| `not_assessed` | **NOT ASSESSED**: the answer holds no measurement for this CVE, so no count is relayed. The API answers 0 for every CVE the radar holds no service for, whether or not the radar looks for that CVE at all, and it never marks a CVE as tracked with 0 services, so that 0 is not a measurement. `cve_exposure` says per CVE whether it is in the radar's tracked set. |
| `measured_zero` | Only if the API ever marks a row `tracked: true` with 0 services: a zero in the radar's sample, not an internet-wide zero. If it marks a row `tracked: false`, that row is `not_assessed` whatever its count. |

## `exposed_databases`

| Field | What it counts |
|---|---|
| `exposed_databases.distinct_hosts` | Distinct ip:port services, not machines, that EchelonGraph's check confirmed answering without authentication: data stores and observability UIs alike. |
| `exposed_databases.engines` | Distinct engine types among them (for example `redis` or `grafana`). |
| `exposed_databases.top_engines`, `exposed_databases.top_countries` | Up to 15 engines and 10 countries, ranked by those services. |
| `exposed_databases.pii_likely`, `exposed_databases.pci_likely` | Services whose schema names pass a high-confidence gate for personal data, or for payment-card data. The names are index, database, table or field names in the Shodan or LeakIX banner or in the check's response, never record values; the gate passes one unambiguous term (such as `ssn` or `cardholder`) or two distinct indicators. It is a precision-first schema gate, not a census: a service whose names do not pass it is not counted, whatever it holds, so the other services are not shown to hold no such data. |
| `exposed_databases.window.from`, `exposed_databases.window.to` | Timestamps, not counts: when EchelonGraph's check last confirmed the oldest and the newest of the services counted answering without authentication, a span of checks made at different times. Relayed only when every counted service has such a time; otherwise the note says how many do not. |
| `exposed_databases.dated_window.from`, `exposed_databases.dated_window.to`, `exposed_databases.dated_window.undated` | Relayed instead of the window when some counted services have no such time on record: from and to span the dated services only, and undated counts those with none. |
| `exposed_databases.last_run_at` | A timestamp, not a count: when the radar last completed a check, a cycle in which its Shodan search, or the LeakIX fallback, answered at least one query (others may have failed), its list of services due for a re-check was read, and the scan opt-out register could be consulted. A cycle that searched nothing, or whose reads failed, does not move it. |

## `leaked_credentials`

| Field | What it counts |
|---|---|
| `leaked_credentials.total` | (repository, secret) pairs, not distinct secrets: a secret committed to three repositories counts three times. |
| `leaked_credentials.distinct_secrets` | Each secret once. |
| `leaked_credentials.distinct_repos` | Public GitHub repositories with at least one. |
| `leaked_credentials.top_providers`, `leaked_credentials.top_types` | Up to 15 providers and secret types, ranked by (repository, secret) pairs. |
| `leaked_credentials.window.from`, `leaked_credentials.window.to` | Timestamps, not counts: when EchelonGraph's detector last found the oldest and the newest of the (repository, secret) pairs counted in a public commit. |
| `leaked_credentials.dated_window.from`, `leaked_credentials.dated_window.to`, `leaked_credentials.dated_window.undated` | Relayed instead of the window when some counted pairs have no such time on record: from and to span the dated pairs only, and undated counts those with none. |
| `leaked_credentials.last_run_at` | A timestamp, not a count: when the radar last completed a check, a cycle that read the public GitHub event stream (fetches of some of the commits it lists may have failed). A cycle whose read of that stream failed does not move it. |

None of them is validated. Each is a credential-shaped string in a public commit that passed
EchelonGraph's filters, at most structurally checked (a checksum or format decode), and never
tested against its provider, so none of these is a count of working credentials.

## `shadow_ai`

The shadow-AI radar's answer mixes numbers that count exposed services with numbers that count
every observation. So `exposure_radar` regroups it by what each number counts, and its note
labels each one. Only `shadow_ai.confirmed_exposed` counts exposed services.

| Field | What it counts |
|---|---|
| `confirmed_exposed.total` | Confirmed exposed: services EchelonGraph's probes found answering without an authentication gate (liveness `active`, or `rechecking` during a re-check). It is the sum of `confirmed_exposed.by_category`. |
| `confirmed_exposed.by_category` | The same services, by category. |
| `confirmed_exposed.last_24h` | Confirmed-exposed services first recorded in the last 24 hours. |
| `confirmed_exposed.window.from`, `confirmed_exposed.window.to` | Timestamps, not counts: when EchelonGraph's verifier ran the probe that last decided the oldest and the newest of the confirmed-exposed services, a span of probes made at different times. Relayed only when every one has such a time. |
| `confirmed_exposed.dated_window.from`, `confirmed_exposed.dated_window.to`, `confirmed_exposed.dated_window.undated` | Relayed instead of the window when some confirmed-exposed services have no such time on record: from and to span the dated ones only, and undated counts those with none. |
| `observed.total` | Every Certificate Transparency or Shodan observation on record, whatever its verification state: observed, not exposed. |
| `observed.by_category` | The same observations, by category. |
| `observed.last_24h` | Observations first recorded in the last 24 hours. |
| `observed.trend_30d` | Observations per UTC day over the last 30 days. |
| `observed.top_products`, `observed.top_countries`, `observed.top_issuers` | Up to ten products, countries and issuers, ranked by observations, not by exposed services. An issuer is the certificate's CA for a Certificate Transparency observation, and the hosting operator Shodan reports for a Shodan one. |
| `observed.last_observation` | When the latest observation was recorded. |
| `authentication.observed` | Observations where a probe observed an authentication gate: a 401/403, a login page or an auth marker. |
| `authentication.not_determined` | Observations whose service answered, but where no probe could tell whether it enforces authentication. |

Neither authentication count is part of `confirmed_exposed`, and `observed.total` minus
`confirmed_exposed.total` is not a count of secured services: it also holds observations not
yet verified, whose hostname no longer resolves, or whose service no longer answers openly.

The tool relays no number it cannot label. A stats field this version does not know is left
out, and the note names it; so is a count in an unexpected shape. A ranked row carries only
its name and its count, and a field added to one is named too. The `poller` block's keys are
checked the same way: a key this version does not know is left out and named, while the
instance fields it knows are left out as the README's [What a result means](../README.md#what-a-result-means)
describes.

## `mcp_servers`

The AI-exposure radar's MCP-server verdicts, from `GET /api/v1/public/ai-exposure/stats?service=mcp`.
Every hostname was named like an MCP server in EchelonGraph's own Certificate Transparency
feed, matched by hostname pattern; no Shodan data is used. Each is checked by EchelonGraph's
identified MCP probe: a `server/discover` request, and `initialize` only if that is refused. It
never sends `tools/call`. The answer is counts and timestamps only, with no hostname, version or
server name, and the tool repeats no string it carries but its timestamps. Each hostname is
counted once, by its latest verdict on record. EchelonGraph's own control servers are left
out, and so is every hostname whose owner opted out of scanning, since it is not checked again
while the opt-out stands and its last verdict cannot be re-checked. The unit is a hostname, not an ip:port service.

| Field | What it counts |
|---|---|
| `mcp_servers.total` | Hostnames the radar has checked for an MCP server, each once, by its latest verdict on record. Not every one is an MCP server: see `mcp_servers.not_assessed_by_reason`. It is `mcp_servers.protected` + `mcp_servers.pending_readjudication` + `mcp_servers.not_assessed`. |
| `mcp_servers.protected` | Hostnames whose `/mcp` endpoint asked for credentials (a 401 or 403) and whose OAuth protected-resource metadata validated under RFC 9728: a 200 JSON document whose resource is identical to the server's identifier and that names at least one authorization server. |
| `mcp_servers.prm_via.header`, `mcp_servers.prm_via.wellknown_path`, `mcp_servers.prm_via.wellknown_root` | The protected ones, by where that document was found: the same-origin URL the credential challenge named; `/.well-known/oauth-protected-resource` followed by the endpoint's path; or `/.well-known/oauth-protected-resource` itself. They add up to `mcp_servers.protected`. |
| `mcp_servers.pending_readjudication` | Verdicts decided by a rule EchelonGraph has since replaced and not yet re-checked under the current rules. They are in neither `mcp_servers.protected` nor `mcp_servers.not_assessed`. |
| `mcp_servers.not_assessed` | The rest, whose protection the radar could not assess. Not assessed does not mean unprotected. `mcp_servers.not_assessed_by_reason` puts each of them in exactly one bucket (below). |
| `mcp_servers.own_controls_excluded` | EchelonGraph's own control servers, left out of every other `mcp_servers` number. |
| `mcp_servers.withheld_opted_out` | Hostnames whose owner opted out of scanning, left out of every other `mcp_servers` number. Such a hostname is not checked again while the opt-out stands, so its last verdict cannot be re-checked; the API's unparameterised answer withholds the same hostnames under the same name. An answer that does not carry this field (an API that predates it) counted them, and the note says so. |
| `mcp_servers.window.from`, `mcp_servers.window.to` | Timestamps, not counts: when the oldest and the newest of the verdicts counted were last checked. The counts are each hostname's latest verdict, not one sweep at one time. With no verdict counted there is no window. |
| `mcp_servers.last_run_at` | A timestamp, not a count: when the AI-exposure radar, which checks other AI services as well as MCP servers, last completed a check (a cycle whose reads succeeded and whose scan opt-out register answered). It is not the time of every verdict counted. |
| `mcp_servers.enabled` | Whether the API reports the radar running: true when a check completed within 45 minutes of its answer. |
| `mcp_servers.counted_at` | A timestamp, not a count: when the API read these counts. |

`mcp_servers.not_assessed_by_reason` divides `mcp_servers.not_assessed`:

| Bucket | What it holds |
|---|---|
| `mcp_servers.not_assessed_by_reason.identified_no_challenge` | Servers that identified themselves as MCP servers (a DiscoverResult, an InitializeResult, or the endpoint event of the deprecated HTTP+SSE transport) and did not ask for credentials at the handshake. That is normal in MCP: authorization is optional in the spec, and a server can enforce it at `tools/call` instead, which EchelonGraph never sends. So this bucket is not a finding of exposure. |
| `mcp_servers.not_assessed_by_reason.resource_mismatch` | An endpoint that asked for credentials, whose metadata document's resource is absent or not identical to the server's identifier. |
| `mcp_servers.not_assessed_by_reason.cross_origin_pointer` | An endpoint that asked for credentials, whose challenge named a metadata URL on another origin, which EchelonGraph records and does not request. |
| `mcp_servers.not_assessed_by_reason.bare_challenge_no_prm` | An endpoint that asked for credentials, whose challenge named no metadata URL, and neither well-known URI answered 2xx. |
| `mcp_servers.not_assessed_by_reason.pointer_unreachable` | An endpoint that asked for credentials, whose same-origin metadata URL did not answer 2xx in full. |
| `mcp_servers.not_assessed_by_reason.pointer_invalid` | An endpoint that asked for credentials, whose challenge's metadata pointer is not a URL EchelonGraph will request. |
| `mcp_servers.not_assessed_by_reason.no_authorization_servers` | An endpoint that asked for credentials, whose metadata document names no authorization server. |
| `mcp_servers.not_assessed_by_reason.wellknown_unreachable` | An endpoint that asked for credentials, where a well-known metadata request got no complete HTTP answer. |
| `mcp_servers.not_assessed_by_reason.metadata_invalid` | An endpoint that asked for credentials, whose metadata answer is not a 200 with a JSON object within the size cap. |
| `mcp_servers.not_assessed_by_reason.challenge_unadjudicated` | An endpoint that asked for credentials before EchelonGraph read RFC 9728 metadata, not re-checked since. |
| `mcp_servers.not_assessed_by_reason.no_http_answer` | Hostnames that gave no HTTP answer: DNS, TCP or TLS failed, or the request timed out. Not a count of MCP servers. |
| `mcp_servers.not_assessed_by_reason.not_identified_as_mcp` | Hostnames that answered HTTP with nothing that identified an MCP server: a login or error page, a body that is not JSON-RPC, a 4xx or 5xx. Not a count of MCP servers. |

The eight credential-challenge buckets hold endpoints that asked for credentials: only their
metadata did not validate, so none of them is shown to lack protection.

`mcp_servers.era` and `mcp_servers.transport` each divide every counted hostname, so each adds
up to `mcp_servers.total`:

| Bucket | What it holds |
|---|---|
| `mcp_servers.era.legacy` | An initialize-era server: an InitializeResult, or the endpoint event of the deprecated HTTP+SSE transport. |
| `mcp_servers.era.dual` | A server that answered `server/discover` and itself named an initialize-era version too. A lower bound: a server built on the reference SDK names only modern versions there, and is counted modern. |
| `mcp_servers.era.modern` | A server that answered `server/discover` and named no initialize-era version. Not proven modern-only: EchelonGraph does not send it `initialize` to tell. |
| `mcp_servers.era.unknown` | Nothing identified an era; every credential challenge is here. |
| `mcp_servers.era.not_measured` | A verdict recorded before EchelonGraph's probe began recording the era, not re-checked since. |
| `mcp_servers.transport.streamable_http` | Identified by a POST to `/mcp`. |
| `mcp_servers.transport.legacy_sse` | Identified by the endpoint event of `GET /sse`, the deprecated HTTP+SSE transport. |
| `mcp_servers.transport.unknown` | Nothing identified a transport. |
| `mcp_servers.transport.not_measured` | Recorded before the era probe, not re-checked since. |

The tool refuses the answer, as a failure of that radar and never as zeros, when it does not say
`service` `mcp` (an API older than `?service=mcp` ignores the parameter and answers its counts
over every AI service it checks), when `mcp_servers.total`, `mcp_servers.protected`,
`mcp_servers.pending_readjudication` or `mcp_servers.not_assessed` is missing or not a whole
number, or when they contradict each other. A partition whose buckets are not exactly those
above, each a whole number adding up to the count it divides, is left out whole and named. A
field this version does not know is left out, and named only when its name is shaped like a
field name.
