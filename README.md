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
| `get_cve` | Full detail for one CVE (CVSS v3/v4, EG score, EPSS, KEV+ransomware, GHSA, CWE, references). |
| `cve_exposure` | Internet-exposure footprint for a CVE: exposed service count (distinct ip:port, the `exposed_hosts` field) + country/product breakdown, from the KEV-exposure radar. |
| `exposure_radar` | Aggregate totals across the exposure radars: shadow AI; services running CISA-KEV CVEs; unauthenticated data stores and observability UIs, found through Shodan (LeakIX when Shodan query credits run low) and then confirmed by EchelonGraph's own identified check, which is not a pure read (on Redis it names its client; on ClickHouse its query lands in the server's query log); leaked credentials. |

Every figure is as fresh as the schedule that refreshes it. The CVE feed is polled from its
sources on a schedule; each radar refreshes on its own.

### How `cve_exposure` counts

Every 12 hours, when Shodan query credits allow, the KEV-exposure radar runs one Shodan query
per tracked product, reads up to 100 ip:port services per query, and keeps a service when its
banner version matches a CISA-KEV or high-EPSS (>= 0.5) CVE. A service not seen on its port
for 21 days is dropped. A count is therefore a banner-version inference over a sample: not an
exploit test, and not an internet-wide census.

`last_seen` is when a service was last seen listening on its port, not when its vulnerable
version was last confirmed. Between searches, a re-check that finds the port still listed by
Shodan InternetDB refreshes `last_seen` without re-reading the banner, so a patched service can
stay counted while its port stays open.

The unit is a service, not a machine. Shodan returns one banner per port and the radar keys
each observation on ip:port, so a machine answering on two ports counts twice. The API field
keeps its name, `exposed_hosts`, and so does `distinct_hosts` in the radar totals.

The radar only looks for its **tracked** set of CVEs, so a zero means different things:

| API answer | What the tool says |
|---|---|
| `tracked: false` | **NOT ASSESSED**: outside the radar's tracked set; 0 is not a measurement. |
| `tracked: true`, `exposed_hosts: 0` | A measured zero in the radar's sample: none of the up to 100 services it read per tracked-product query matched. Not an internet-wide zero. |
| no `tracked` field | The API did not say whether the CVE is in the tracked set: an older API, or the radar cannot decide (for example a CISA-KEV or high-EPSS CVE in a tracked product with 0 services on record). 0 exposed services on record, with no claim either way. |
| HTTP 400, or an id that is not `CVE-YYYY-NNNN…` | An error result tagged `invalid_input`; nothing was looked up. |

### How `exposure_radar` counts shadow AI

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
its name and its count.

## What a result means

Every tool answers in one of two shapes, so a model reading the result cannot mistake an
outage for an all-clear:

- **Success** — the first text block is the API's JSON verbatim; the second is a one-line
  note saying the call succeeded, which base URL answered, and what it found. When the
  feed genuinely holds nothing for the query the note says so in words ("we looked and
  found nothing … not a lookup failure"), because a measured zero is a measurement. The
  exception to verbatim is `exposure_radar`'s `shadow_ai`: its counts are regrouped as above,
  and its `poller` block carries only `running` and `last_run_at`, or is dropped when it
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
  finding. A failure is never rendered as a success with null fields.

## Install

Add it to your MCP client's config. It runs via `npx` — no global install needed.

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
npm test           # build, then behavioural tests against a stub API (no network needed)
npm run smoke      # spawn the server + call cve_exposure against the production API
```

`npm run smoke` calls the production API with this package's User-Agent, so its requests are
counted as external MCP adoption. `npm test` never leaves the machine.

## License

The code is MIT-licensed.

The CVE Pulse compilation (how EchelonGraph combines its CVE sources, and the EchelonGraph
score) is © EchelonGraph, served under the CVE Pulse free-access terms; the source records it
compiles stay under their publishers' terms.

Exposure counts are derived from Shodan data. Shodan data is owned by Shodan, which holds its
copyright (© Shodan). EchelonGraph claims no ownership of it or copyright in it.
