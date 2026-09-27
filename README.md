# EchelonGraph MCP server

**CVE and internet-exposure data** for Claude, Cursor, Cline, and any
[MCP](https://modelcontextprotocol.io) client, straight from
[EchelonGraph](https://echelongraph.io)'s free public feed.

It exposes EchelonGraph's CVE Pulse (NVD + MITRE-CNA *pre-NVD* + CISA-KEV + EPSS + GitHub
GHSA, fused into one score) **plus a per-CVE internet-exposure footprint**: how many
internet-facing services (distinct ip:port) EchelonGraph's KEV-exposure radar has on record
running a version that maps to the CVE. Exposure counts are derived from Shodan data.
Shodan data is owned by Shodan, which holds its copyright (© Shodan).

Free and keyless: no API key, no auth, read-only. The server makes no request other than the
API call a tool needs to answer.

## Tools

| Tool | What it does |
|---|---|
| `cve_summary` | Counts of active CVEs by severity, and when the feed was last updated. |
| `search_cves` | Search/filter CVEs (severity, min CVSS, text, sort) with EchelonGraph scores. |
| `get_cve` | Full record for one CVE: CVSS v3 and (when scored) v4, the EchelonGraph score and its confidence, EPSS, CISA-KEV status and known ransomware use, the GitHub GHSA id, references, and its published, modified and `updated_at` times. |
| `cve_exposure` | Internet-exposure footprint for a CVE: exposed service count (distinct ip:port, the `exposed_hosts` field) + country/product breakdown, from the KEV-exposure radar. |
| `exposure_radar` | Aggregate totals across the exposure radars: services running CISA-KEV CVEs; unauthenticated data stores and observability UIs, found through Shodan (LeakIX when Shodan query credits run low) and then confirmed by EchelonGraph's own identified check, which is not a pure read (on Redis it names its client; on ClickHouse its query lands in the server's query log); leaked credentials; shadow AI. Every number is labelled by what it counts, and a field the tool cannot label is left out and named. |

Every figure is as fresh as the schedule that refreshes it. The CVE feed is polled from its
sources on a schedule; each radar refreshes on its own.

### How `cve_exposure` counts

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
"Structured results").

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
the answer does not say when any service it counts was observed (see "Structured results").

### How `exposure_radar` counts

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

#### `kev_exposure`

Every count is over the services the KEV-exposure radar keeps: a Shodan banner whose version
maps to a CISA-KEV-listed CVE (see "How `cve_exposure` counts").

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

A `newest_kev` row's `exposure_state` says whether its count is a measurement:

| `exposure_state` | What it means |
|---|---|
| `exposed` | The radar has services on record with this CVE, and `exposed_hosts` counts them. |
| `not_assessed` | **NOT ASSESSED**: the answer holds no measurement for this CVE, so no count is relayed. The API answers 0 for every CVE the radar holds no service for, whether or not the radar looks for that CVE at all, and it never marks a CVE as tracked with 0 services, so that 0 is not a measurement. `cve_exposure` says per CVE whether it is in the radar's tracked set. |
| `measured_zero` | Only if the API ever marks a row `tracked: true` with 0 services: a zero in the radar's sample, not an internet-wide zero. If it marks a row `tracked: false`, that row is `not_assessed` whatever its count. |

#### `exposed_databases`

| Field | What it counts |
|---|---|
| `exposed_databases.distinct_hosts` | Distinct ip:port services, not machines, that EchelonGraph's check confirmed answering without authentication: data stores and observability UIs alike. |
| `exposed_databases.engines` | Distinct engine types among them (for example `redis` or `grafana`). |
| `exposed_databases.top_engines`, `exposed_databases.top_countries` | Up to 15 engines and 10 countries, ranked by those services. |
| `exposed_databases.pii_likely`, `exposed_databases.pci_likely` | Services whose schema names pass a high-confidence gate for personal data, or for payment-card data. The names are index, database, table or field names in the Shodan or LeakIX banner or in the check's response, never record values; the gate passes one unambiguous term (such as `ssn` or `cardholder`) or two distinct indicators. It is a precision-first schema gate, not a census: a service whose names do not pass it is not counted, whatever it holds, so the other services are not shown to hold no such data. |
| `exposed_databases.last_run_at` | A timestamp, not a count: when the radar last completed a check, a cycle in which its Shodan search, or the LeakIX fallback, answered at least one query (others may have failed), its list of services due for a re-check was read, and the scan opt-out register could be consulted. A cycle that searched nothing, or whose reads failed, does not move it. |

#### `leaked_credentials`

| Field | What it counts |
|---|---|
| `leaked_credentials.total` | (repository, secret) pairs, not distinct secrets: a secret committed to three repositories counts three times. |
| `leaked_credentials.distinct_secrets` | Each secret once. |
| `leaked_credentials.distinct_repos` | Public GitHub repositories with at least one. |
| `leaked_credentials.top_providers`, `leaked_credentials.top_types` | Up to 15 providers and secret types, ranked by (repository, secret) pairs. |
| `leaked_credentials.last_run_at` | A timestamp, not a count: when the radar last completed a check, a cycle that read the public GitHub event stream (fetches of some of the commits it lists may have failed). A cycle whose read of that stream failed does not move it. |

None of them is validated. Each is a credential-shaped string in a public commit that passed
EchelonGraph's filters, at most structurally checked (a checksum or format decode), and never
tested against its provider, so none of these is a count of working credentials.

#### `shadow_ai`

The shadow-AI radar's answer mixes numbers that count exposed services with numbers that count
every observation. So `exposure_radar` regroups it by what each number counts, and its note
labels each one. Only `shadow_ai.confirmed_exposed` counts exposed services.

| Field | What it counts |
|---|---|
| `confirmed_exposed.total` | Confirmed exposed: services EchelonGraph's probes found answering without an authentication gate (liveness `active`, or `rechecking` during a re-check). It is the sum of `confirmed_exposed.by_category`. |
| `confirmed_exposed.by_category` | The same services, by category. |
| `confirmed_exposed.last_24h` | Confirmed-exposed services first recorded in the last 24 hours. |
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
instance fields it knows are left out as described below.

## What a result means

Every tool answers in one of two shapes, so a model reading the result cannot mistake an
outage for an all-clear:

- **Success** — the first text block is the API's JSON verbatim; the second is a one-line
  note saying the call succeeded, which base URL answered, and what it found; the third is
  the structured result without `data`, as JSON (below). When the
  feed genuinely holds nothing for the query the note says so in words ("we looked and
  found nothing … not a lookup failure"), because a measured zero is a measurement. The
  exception to verbatim is `exposure_radar`: each radar is cut to the fields listed above, and
  each `kev_exposure.newest_kev` row gains an `exposure_state`. Its `shadow_ai` counts are
  regrouped as above, and its `poller` block carries only `running` and `last_run_at`, or is dropped when it
  carries no real completion time. The block's other fields describe the server instance that
  answered, not the radar. Its `last_run_at` is when the radar's leader last
  completed a Certificate Transparency (crt.sh) cycle, and its `running` is true only when
  that was within 30 minutes of the answer. When `running` is true, the note says the
  radar's leader last completed a cycle at that time; when it is false, the note says no
  cycle has completed since that time; when `last_run_at` is absent, the note says the
  radar's freshness is unknown and the block is left out. An older API answered from
  whichever server instance served the request, and a follower instance sent
  `running: false` with the zero time `0001-01-01T00:00:00Z`; that too is unknown freshness,
  never presented as a stopped radar.
- **Failure** — an MCP error result (`isError: true`) whenever the lookup did not complete:
  the host could not be reached, it answered non-2xx, it took longer than the timeout, or
  it answered 2xx with a body that is not a JSON object. The text names the tool, the
  cause (status code or error kind), the path, and the base URL, and says it is not a
  finding; the second text block is the structured result, as JSON (below). A failure is never
  rendered as a success with null fields.

Both shapes also carry a structured result, below, and repeat it in their last text block, so a
client that passes only `content` to the model still sees how the answer was measured. The
first text block (the API's JSON, or the failure) and the note after it are where 1.x put them.

## Structured results

Since 2.0.0 every result, success or failure, carries `structuredContent`, and every tool
declares its shape as an `outputSchema` in `tools/list`, with a title and the annotations
`readOnlyHint: true`, `destructiveHint: false`, `idempotentHint: true` and
`openWorldHint: true` (hints, which a client treats as untrusted).

| Field | What it holds |
|---|---|
| `state` | `measured`, `not_assessed`, `failed` or `invalid_input` (below). |
| `measured_at` | When the underlying observation was made, as the API states it. `null` when the answer does not say or holds no observation; never the Go zero time. |
| `method` | How the numbers were produced. `null` on a failure. |
| `coverage` | What the answer covers, where the tool can say: `in_scope` for `cve_exposure`, the list's own account of its count for `search_cves`, and the radars that answered for `exposure_radar`. |
| `freshness` | The producing radar's last completed check (`last_run_at`), where the API serves one; `null` where it serves none. |
| `notes` | The caveats, one sentence each: what the envelope itself needs saying, then the note from the text block. |
| `data` | On a success only: the same JSON as the first text block. |
| `error` | On a failure only: `kind`, `path`, `status` and `message`. |

The last text block of every result is this structured result serialized as JSON, without
`data`: the same `state`, `measured_at`, `method`, `coverage`, `freshness` and `notes` (and on
a failure `error`), key for key, since a client may pass only `content` to the model. With
the first text block as `data`, the text carries the whole structured result.

| `state` | What it means |
|---|---|
| `measured` | A measurement of what was asked. An exposure count is `measured` only when the answer says when what it counts was observed (`measured_at`) and how it was produced (`method`). No exposure answer says when today, so neither exposure tool answers `measured`. |
| `not_assessed` | The answer holds no dated measurement of what was asked, so no number in it is a finding: the radar does not look for this CVE, the answer does not say whether it does, or the answer does not say when what it counts was observed. |
| `failed` | The lookup did not complete. Not a finding. |
| `invalid_input` | The input was refused, by this server or by the API, so nothing was looked up. Not a finding. |

Every field comes from what the API sends; where the API does not say, the field is `null` and
a note says so. Per tool:

- `cve_summary` is `measured`, and its `measured_at` is `summary.last_updated`, the newest
  modification time among the active CVE records it counts.
- `search_cves` is `measured`, with `measured_at` `null`: each record carries its own times. Its
  `coverage` repeats the list's `total`, `total_counted`, `total_is_lower_bound`,
  `search_relaxed`, `limit` and `offset`, and adds `returned`, the rows in the page. When
  `total_counted` is false the total is not a count, and the note does not call it one.
- `get_cve` is `measured`, and its `measured_at` is the record's `updated_at`, when EchelonGraph
  last wrote it.
- `cve_exposure` is `not_assessed` with `measured_at` `null`, every answer: the per-CVE answer
  carries no time at which the services it counts were observed. Its `last_seen` is when
  EchelonGraph last wrote or refreshed one of their rows, not when any of them was observed,
  so it is never `measured_at`, and a note says so. A tracked zero is `not_assessed` too, since
  a zero has no observation to date it. The count is still relayed, labelled: `exposure_state`
  is `exposed`, `measured_zero`, `not_assessed` or `tracking_unknown`, the cases of "How
  `cve_exposure` counts", and `coverage.in_scope` is the API's `tracked`. It becomes `measured`
  only when the API serves a time at which the counted services were observed.
- `exposure_radar` is `not_assessed` with `measured_at` `null`: every radar answered, but no
  stats answer says when the services or records it counts were observed, so no count is
  presented as a dated measurement. Its numbers keep the labels above. `freshness` holds each
  radar's `last_run_at` where the API serves one, and for `shadow_ai` also `running`.

The CVE feed tools' `freshness` is `null`: the feed's answers carry no time at which its
pollers last completed a poll for the feed as a whole.

A success whose fields do not fit the tool's `outputSchema` (a field of a type the schema does
not allow) is returned as a failure with `error.kind` `unexpected_shape`, never relayed. A
field the API adds later is still relayed by the four tools that relay the API's JSON, and
`exposure_radar` leaves it out and names it, as above.

## Protocol versions

The server answers both eras of the Model Context Protocol on stdio:

- **2026-07-28**: a client that opens with `server/discover` receives a DiscoverResult listing
  `2026-07-28`, the tools capability and the server instructions, and then sends each request
  with the per-request `_meta` envelope.
- **2025 and earlier**: a client that opens with `initialize`, as every 1.x SDK client does,
  negotiates `2025-11-25`, `2025-06-18`, `2025-03-26` or `2024-11-05`; a version the server does
  not know is answered with `2025-11-25`.

The first message of a connection picks its era. The DiscoverResult lists only `2026-07-28`,
as the SDK builds it: the 2025-era versions are reached through `initialize`. Both handshakes
carry the package's name and version (`serverInfo`), and every API request carries them in its
User-Agent, `echelongraph-mcp/<version>`.

Both handshakes also carry the server instructions: the data is public; what `state`,
`measured_at` and `freshness` mean, and that the last text block repeats them; that exposure
numbers are aggregate counts of ip:port services, not an internet-wide census; and that Shodan
data is Shodan's.

## Install

Requires Node.js 20 or later. Add it to your MCP client's config. It runs via `npx` — no global
install needed.

### Claude Desktop

`claude_desktop_config.json` → `mcpServers`:

```json
{
  "mcpServers": {
    "echelongraph": {
      "command": "npx",
      "args": ["-y", "echelongraph-mcp"]
    }
  }
}
```

### Cursor / Cline / Windsurf

`~/.cursor/mcp.json` (or the client's MCP settings):

```json
{
  "mcpServers": {
    "echelongraph": {
      "command": "npx",
      "args": ["-y", "echelongraph-mcp"]
    }
  }
}
```

Restart the client, then ask: *"Is CVE-2023-44487 actively exploited, and how many exposed
services does EchelonGraph's radar have on record for it?"*

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `ECHELONGRAPH_API_BASE` | `https://app.echelongraph.io` | Override the API base (self-host / proxy). |
| `ECHELONGRAPH_API_TIMEOUT_MS` | `15000` | Per-request timeout. A slower answer is reported as a failed lookup, not as empty data. |

## Develop

```bash
npm install
npm run build      # tsc → dist/
npm test           # build, then the behavioural suite over both protocol eras, against a stub API (no network needed)
npm run smoke      # spawn the server + call cve_exposure against the production API
```

`npm run smoke` calls the production API with this package's User-Agent, so its requests are
counted as external MCP adoption. `npm test` never leaves the machine.

`npm test` runs the suite once over a 2026-07-28 `server/discover` and once over a 2025-06-18
`initialize`, plus the era tests. To run it against an installed package rather than `dist/`,
set `ECHELONGRAPH_MCP_BIN` to that package's `echelongraph-mcp` bin: the tests then run the bin
directly, as `npx` does, and read that package's own files.

## License

The code is MIT-licensed.

The CVE Pulse compilation (how EchelonGraph combines its CVE sources, and the EchelonGraph
score) is © EchelonGraph, served under the CVE Pulse free-access terms; the source records it
compiles stay under their publishers' terms.

Exposure counts are derived from Shodan data. Shodan data is owned by Shodan, which holds its
copyright (© Shodan). EchelonGraph claims no ownership of it or copyright in it.
