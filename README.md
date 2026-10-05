# EchelonGraph MCP server

**CVE and internet-exposure data** for Claude, Cursor, VS Code, Cline, and any
[MCP](https://modelcontextprotocol.io) client, straight from
[EchelonGraph](https://echelongraph.io)'s free public feed.

It exposes EchelonGraph's CVE Pulse (NVD + MITRE-CNA *pre-NVD* + CISA-KEV + EPSS + GitHub
GHSA, fused into one score) **plus a per-CVE internet-exposure footprint**: how many
internet-facing services (distinct ip:port) EchelonGraph's KEV-exposure radar has on record
running a version that maps to the CVE. Exposure counts are derived from Shodan data.
Shodan data is owned by Shodan, which holds its copyright (© Shodan).

Its 14 tools look up one CVE (record, exploit code and fixed versions, EPSS history, vendor
advisories, exposure footprint), list CISA's newest KEV additions, check whether a product or
package version is affected, check an SBOM, and read a CWE and its CVEs. Every result says how
it was measured (`state`, `measured_at`, `method`, `coverage`, `freshness`, `notes`), so a model
cannot mistake an outage or an unassessed lookup for an all-clear.

It also serves four prompts, ready-made workflows a client can show as slash commands
(`triage_cve`, `kev_weekly_brief`, `am_i_affected`, `sbom_review`; see "Prompts"), and three
resources (`echelongraph://methodology`, `echelongraph://sources` and `cve://{cve_id}`; see
"Resources").

Free and keyless: no API key, no auth, read-only. The server makes no request other than the
API call a tool needs to answer.

- npm: [`echelongraph-mcp`](https://www.npmjs.com/package/echelongraph-mcp) · Official MCP
  Registry: `io.echelongraph/echelongraph-mcp` · Docs: <https://echelongraph.io/pulse/mcp>
- Source: <https://github.com/echelongraph/echelongraph-mcp> · Changes:
  [CHANGELOG.md](CHANGELOG.md) · Security: [SECURITY.md](SECURITY.md)
- Also listed on: [Smithery](https://smithery.ai/servers/echelongraph/echelongraph-mcp) ·
  [Glama](https://glama.ai/mcp/servers/echelongraph/echelongraph-mcp)

## Quick start

The local server runs through `npx` and needs Node.js 20 or later; nothing is installed
globally. Add one of the blocks below to your client, restart it, then ask: *"Is
CVE-2023-44487 actively exploited, and how many exposed services does EchelonGraph's radar
have on record for it?"*

### Claude Desktop

Two ways in. The first needs nothing installed; the second runs the server on your machine.

**1. Custom connector (no install).** Claude Desktop uses your claude.ai account's connectors:
Customize → Connectors → **+ Add** → **Add custom connector**. Name it `EchelonGraph`, paste
`https://mcp.echelongraph.io/mcp`, choose **No sign in**, and add it. No Node.js, no PATH and no
JSON to edit. A connector added on claude.ai shows up in Claude Desktop too, and the plan rules
are claude.ai's (see "Remote (no install)" below).

**2. Local server through `npx`.**

1. **Check Node.js.** In Terminal (macOS) or PowerShell (Windows), run `node -v`. It must print
   `v20` or later. If it prints an older version or `command not found`, install the LTS release
   from <https://nodejs.org>, or on macOS with Homebrew run `brew install node`.
2. **Open the config file in a plain-text editor.** Settings → Developer → Edit Config shows
   `claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`;
   Windows: `%APPDATA%\Claude\claude_desktop_config.json`). Open it in a plain-text editor such as
   VS Code, Notepad or `nano`. TextEdit on macOS turns `"` into curly quotes (`“ ”`) when Smart
   Quotes is on, and the JSON then breaks without an error: turn it off under Edit → Substitutions
   → Smart Quotes, or use another editor.
3. **Merge, do not replace.** The file usually exists already and holds Claude Desktop's own
   settings (for example a `"preferences"` object). Keep everything in it. Add an `"mcpServers"`
   key at the top level, next to the keys already there; if `"mcpServers"` is already there, add
   the `"echelongraph"` entry inside it. Mind the comma between entries. The result looks like
   this, with your own settings where `preferences` is:

   ```json
   {
     "preferences": {
       "…": "the settings already in your file stay as they are"
     },
     "mcpServers": {
       "echelongraph": {
         "command": "npx",
         "args": ["-y", "echelongraph-mcp"]
       }
     }
   }
   ```

   To check that the file parses, run
   `node -e "JSON.parse(require('fs').readFileSync(process.argv[1], 'utf8'))" "<path to the file>"`:
   no output means valid JSON.
4. **Quit fully, then reopen.** Closing the window leaves the old config loaded. On macOS choose
   Claude → Quit Claude (⌘Q); on Windows right-click the Claude icon in the system tray and choose
   Quit. The first start can take longer while `npx` downloads the package.
5. **Check that it worked.** Settings → Developer lists `echelongraph` as running, and the tools
   menu in the chat box lists EchelonGraph's 14 tools. Then ask the question at the top of this
   section.

#### Troubleshooting Claude Desktop

- **`spawn npx ENOENT`** (or the server shows as failed). On macOS, an app opened from the Dock
  does not get your shell's PATH, so Claude Desktop cannot find `npx` where Homebrew (Apple
  silicon: `/opt/homebrew/bin`; Intel: `/usr/local/bin`) or nvm put it. Run `which npx` in
  Terminal, then give Claude Desktop that absolute path as `"command"`, and the folder it is in as
  `PATH` under `"env"` (`npx` starts `node` from that same folder). With Homebrew on Apple silicon:

  ```json
  {
    "mcpServers": {
      "echelongraph": {
        "command": "/opt/homebrew/bin/npx",
        "args": ["-y", "echelongraph-mcp"],
        "env": { "PATH": "/opt/homebrew/bin:/usr/bin:/bin" }
      }
    }
  }
  ```

  With nvm, use the full path `which npx` prints (JSON does not expand `~`). Then quit fully and
  reopen. On Windows, install Node.js with the installer from nodejs.org, which adds `npx` to the
  system PATH, then quit Claude Desktop fully and reopen it.
- **The server does not appear at all.** The file is not valid JSON (a missing comma, or curly
  quotes), or the app was not fully quit: see steps 2 to 4.
- **Logs.** macOS: `~/Library/Logs/Claude/mcp-server-echelongraph.log` (this server's output) and
  `~/Library/Logs/Claude/mcp.log` (connections). Windows: `%APPDATA%\Claude\logs\`, with the same
  file names.

### Claude Code

```bash
claude mcp add --transport stdio echelongraph -- npx -y echelongraph-mcp
```

Add `--scope user` before the `--` to make it available in every project, or `--scope project`
to share it through the project's `.mcp.json`.

### Cursor

`~/.cursor/mcp.json` (every project) or `.cursor/mcp.json` (one project):

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

### VS Code

`.vscode/mcp.json` in the workspace (VS Code's key is `servers`, not `mcpServers`):

```json
{
  "servers": {
    "echelongraph": {
      "command": "npx",
      "args": ["-y", "echelongraph-mcp"]
    }
  }
}
```

or from a terminal:

```bash
code --add-mcp '{"name":"echelongraph","command":"npx","args":["-y","echelongraph-mcp"]}'
```

### Windsurf, Cline and other clients

Clients that read an `mcpServers` block (Windsurf's `mcp_config.json`, Cline's MCP settings,
and most others) take the same block as Cursor above.

### Remote (no install)

The same 14 tools, four prompts and three resources are served over Streamable HTTP at:

```text
https://mcp.echelongraph.io/mcp
```

Keyless, no sign-in, stateless; both protocol eras. The hosted endpoint is in service:
`https://mcp.echelongraph.io/health` answers `{"status":"ok","version":…}` with the package
version it runs.

- **claude.ai** (Free, Pro, Max, Team and Enterprise plans):
  Customize → Connectors → **+ Add** → **Add custom connector**. Name it `EchelonGraph`, paste
  the URL, choose **No sign in**, and add it. On Team and Enterprise an Owner adds it for the
  organization first, and each member then connects it. Free plans allow one custom connector.
- **Claude Code**:

  ```bash
  claude mcp add --transport http echelongraph https://mcp.echelongraph.io/mcp
  ```

- **Cursor** (`mcp.json`):

  ```json
  { "mcpServers": { "echelongraph": { "url": "https://mcp.echelongraph.io/mcp" } } }
  ```

- **VS Code** (`.vscode/mcp.json`):

  ```json
  { "servers": { "echelongraph": { "type": "http", "url": "https://mcp.echelongraph.io/mcp" } } }
  ```

- **Windsurf** (`mcp_config.json`):

  ```json
  { "mcpServers": { "echelongraph": { "serverUrl": "https://mcp.echelongraph.io/mcp" } } }
  ```

The hosted endpoint runs this package's code (`dist/http.js`, below) against the same public
API, so its answers are the npm package's answers. What it sees and logs is under "Privacy",
and its per-client limit under "Rate limits".

## Tools

Every tool is read-only (`readOnlyHint: true`) and declares a title and an `outputSchema`.
The example questions are ones a client can answer with that tool alone.

| Tool | Title | What it answers | Example question |
|---|---|---|---|
| `cve_summary` | CVE feed summary | Counts of active CVEs by severity band, the count with no severity band from any source (`summary.none`, sent again as `summary.unscored`: CVEs not yet scored, not a rating of None), the same CVEs counted by NVD's severity label, as provenance (`summary.nvd_critical` to `summary.nvd_none`), the rejected (withdrawn) records outside the total (`summary.rejected`), and when the feed was last updated. | *How many critical CVEs does the feed hold, and when was it last updated?* |
| `search_cves` | Search CVEs | Search/filter CVEs (severity, min CVSS, text, sort) with EchelonGraph scores and `score_assessed`; page with `limit` and `offset`; the note names each row not yet scored. | *Find critical CVEs that mention Tomcat with a CVSS of 9 or more.* |
| `get_cve` | CVE detail | One CVE's record: CVSS v3 and (when scored) v4, the EchelonGraph score and its confidence, whether EchelonGraph has scored it (`score_assessed`), EPSS, CISA-KEV status and known ransomware use, the GitHub GHSA id, references, and its published, modified and `updated_at` times. | *What are CVE-2024-3094's CVSS, EPSS and CISA-KEV status?* |
| `cve_exposure` | Internet exposure for one CVE | Internet-exposure footprint for a CVE: exposed service count (distinct ip:port, the `exposed_hosts` field) + country/product breakdown, from the KEV-exposure radar. | *How many exposed services does EchelonGraph's radar have on record for CVE-2023-44487?* |
| `exposure_radar` | Exposure radar totals | Aggregate totals across the exposure radars: services running CISA-KEV CVEs; unauthenticated data stores and observability UIs, found through Shodan (LeakIX when Shodan query credits run low) and then confirmed by EchelonGraph's own identified check, which is not a pure read (on Redis it names its client; on ClickHouse its query lands in the server's query log); leaked credentials; shadow AI; and MCP servers found in EchelonGraph's own Certificate Transparency feed, by RFC 9728 verdict, protocol era and transport. Every number is labelled by what it counts, and a field the tool cannot label is left out and named. | *How many unauthenticated data stores has EchelonGraph's radar confirmed?* |
| `kev_recent` | Recent CISA KEV additions | The CVEs CISA has added to its Known Exploited Vulnerabilities catalog, newest first (`kev_added_date`), from EchelonGraph's copy of the catalog, polled from CISA every 5 minutes: due date, vendor, product, known ransomware use, EchelonGraph's severity, CVSS, EPSS and `eg_kev_tier`, and `our_first_seen_kev`. Filter by date range, ransomware and vendor; page with `limit` and `next_cursor`. Dated by `last_successful_fetch_at`, our last successful fetch of CISA's feed; the filters travel as request headers, never in the URL. | *Which CVEs has CISA added to KEV since 1 September, and which have known ransomware use?* |
| `epss_history` | EPSS change history for one CVE | How one CVE's EPSS score has changed, as EchelonGraph recorded it: one point per recorded change (`series_kind` `change_only`), never a daily series, with the value now and `series_starts_at`, when recording began; before it a missing point means not recorded, not unchanged. | *How has CVE-2023-44487's EPSS score changed, as EchelonGraph recorded it?* |
| `check_affected` | Am I affected? (product or package at a version) | Whether a product (its NVD CPE product token) or a registry package (`ecosystem` and `package`) at a given version is affected by known CVEs, from the matcher behind echelongraph.io/am-i-affected: `assessed` first (false: not evaluated, with `not_assessed_reason`, and a count of 0 then is not "not affected"), the matching CVEs with `kev_listed`, `ransomware`, `epss_score`, `effective_score` and `score_assessed`, and advisories it cannot decide counted as `undetermined_count`, never as safe. What you look up travels in request headers, never in the URL. | *Is openssl 3.0.0 affected by known CVEs? Is lodash 4.17.15 on npm?* |
| `check_sbom` | Check an SBOM against the advisory corpus | A dependency list checked against EchelonGraph's advisory corpus (OSV.dev records), one verdict per component: `affected`, `not_affected`, `undetermined` or `not_assessed`, each with its `not_assessed_reason`. Pass up to 2,000 distinct purls, or a CycloneDX JSON or SPDX JSON document: the purls are read from it by the MCP server and only they are sent to the API, in POST bodies of at most 200 each, one after another; the document itself is not sent on. Run from npm, the server is on your machine; over the hosted endpoint (`mcp.echelongraph.io`) it is EchelonGraph's, and the document is the request body. When the API's per-component rate limit answers 429, the tool waits the `Retry-After` it names, within 50 seconds per call; past that it answers what it has, with the purls not sent counted in `coverage.not_sent`, the reason in `coverage.not_sent_reason`, and the list in `data.not_sent_purls`, never dropped silently. A deb, apk or rpm purl without a `distro` qualifier naming its release is not assessed (`distro_release_unknown`): EchelonGraph does not guess a release. Only `not_affected` is clean. No ranking, no score. | *Check this CycloneDX SBOM against the advisory corpus.* |
| `cve_intel` | CVE weakness, exploits and packages | Weakness, public exploit code, affected packages and fixed versions for one CVE, from EchelonGraph's per-CVE enrichment: `cwes`, `exploits` (at most 10, verified first) with `exploits_total`, `exploits_capped`, `exploits_by_kind` and `exploits_by_status`, `affected_packages`, `fixed_versions` and `timeline`. `verified_status` is the label stored with each reference, not a guarantee that the exploit works. An empty `exploits` list is not evidence that no public exploit exists; a section the API could not read is named in `coverage.sections_failed`, never relayed as an empty list. | *Is there public exploit code for CVE-2021-44228, and which versions fix it?* |
| `get_cwe` | CWE and its CVEs | One CWE (weakness class) and the CVEs classified under it: `name` and `description` from the MITRE CWE catalog EchelonGraph embeds, `total`, and one page of 50 `cves`, ordered as `order` states (CISA-KEV-listed first, then EchelonGraph score). A `total` of 0 says that no CVE in EchelonGraph's feed is classified under that CWE, not that none exists. | *Which CVEs are classified under CWE-79, CISA-KEV-listed first?* |
| `vendor_advisories_for_cve` | Vendor advisories for one CVE | The vendor-published advisories (Microsoft MSRC, Red Hat, Cisco, Palo Alto Networks, GitHub GHSA and the other feeds EchelonGraph polls) that name one CVE, newest first, at most 20. | *Which vendor advisories name CVE-2024-3400?* |
| `get_vendor_advisory` | Vendor advisory detail | One vendor advisory in full: description, severity, `cve_ids` and the subset with a CVE record here (`known_cve_ids`), `affected_products`, `remediation` and `references`. | *Show one of those advisories in full: affected products, remediation and references.* |
| `search_vendor_advisories` | Search vendor advisories | Search vendor advisories by text (title, description, vendor, advisory ID, products, CVE IDs), vendor, severity and whether they name a CVE. The search text is sent in a request header, never in the URL. | *Search vendor advisories for FortiOS, critical severity only.* |

The three vendor-advisory tools relay `vendor_published_at` (the vendor's date), `our_first_seen_at`
(when EchelonGraph first recorded the advisory) and `withdrawn` (the vendor rescinded it; the note
names each one, and the search leaves them out).

Every figure is as fresh as the schedule that refreshes it. The CVE feed is polled from its
sources on a schedule; each radar refreshes on its own.

### How `cve_summary` reads its counts

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

### How `get_cve` and `search_cves` read the EchelonGraph score

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
| `exposed_databases.window.from`, `exposed_databases.window.to` | Timestamps, not counts: when EchelonGraph's check last confirmed the oldest and the newest of the services counted answering without authentication, a span of checks made at different times. Relayed only when every counted service has such a time; otherwise the note says how many do not. |
| `exposed_databases.last_run_at` | A timestamp, not a count: when the radar last completed a check, a cycle in which its Shodan search, or the LeakIX fallback, answered at least one query (others may have failed), its list of services due for a re-check was read, and the scan opt-out register could be consulted. A cycle that searched nothing, or whose reads failed, does not move it. |

#### `leaked_credentials`

| Field | What it counts |
|---|---|
| `leaked_credentials.total` | (repository, secret) pairs, not distinct secrets: a secret committed to three repositories counts three times. |
| `leaked_credentials.distinct_secrets` | Each secret once. |
| `leaked_credentials.distinct_repos` | Public GitHub repositories with at least one. |
| `leaked_credentials.top_providers`, `leaked_credentials.top_types` | Up to 15 providers and secret types, ranked by (repository, secret) pairs. |
| `leaked_credentials.window.from`, `leaked_credentials.window.to` | Timestamps, not counts: when EchelonGraph's detector last found the oldest and the newest of the (repository, secret) pairs counted in a public commit. |
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
| `confirmed_exposed.window.from`, `confirmed_exposed.window.to` | Timestamps, not counts: when EchelonGraph's verifier ran the probe that last decided the oldest and the newest of the confirmed-exposed services, a span of probes made at different times. Relayed only when every one has such a time. |
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

#### `mcp_servers`

The AI-exposure radar's MCP-server verdicts, from `GET /api/v1/public/ai-exposure/stats?service=mcp`.
Every hostname was named like an MCP server in EchelonGraph's own Certificate Transparency
feed, matched by hostname pattern; no Shodan data is used. Each is checked by EchelonGraph's
identified MCP probe: a `server/discover` request, and `initialize` only if that is refused. It
never sends `tools/call`. The answer is counts and timestamps only, with no hostname, version or
server name, and the tool repeats no string it carries but its timestamps. Each hostname is
counted once, by its latest verdict on record, and EchelonGraph's own control servers are left
out. The unit is a hostname, not an ip:port service.

| Field | What it counts |
|---|---|
| `mcp_servers.total` | Hostnames the radar has checked for an MCP server, each once, by its latest verdict on record. Not every one is an MCP server: see `mcp_servers.not_assessed_by_reason`. It is `mcp_servers.protected` + `mcp_servers.pending_readjudication` + `mcp_servers.not_assessed`. |
| `mcp_servers.protected` | Hostnames whose `/mcp` endpoint asked for credentials (a 401 or 403) and whose OAuth protected-resource metadata validated under RFC 9728: a 200 JSON document whose resource is identical to the server's identifier and that names at least one authorization server. |
| `mcp_servers.prm_via.header`, `mcp_servers.prm_via.wellknown_path`, `mcp_servers.prm_via.wellknown_root` | The protected ones, by where that document was found: the same-origin URL the credential challenge named; `/.well-known/oauth-protected-resource` followed by the endpoint's path; or `/.well-known/oauth-protected-resource` itself. They add up to `mcp_servers.protected`. |
| `mcp_servers.pending_readjudication` | Verdicts decided by a rule EchelonGraph has since replaced and not yet re-checked under the current rules. They are in neither `mcp_servers.protected` nor `mcp_servers.not_assessed`. |
| `mcp_servers.not_assessed` | The rest, whose protection the radar could not assess. Not assessed does not mean unprotected. `mcp_servers.not_assessed_by_reason` puts each of them in exactly one bucket (below). |
| `mcp_servers.own_controls_excluded` | EchelonGraph's own control servers, left out of every other `mcp_servers` number. |
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

### How `check_affected` decides

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

`product`, `version`, `ecosystem` and `package` travel in the `X-EG-Product`, `X-EG-Version`,
`X-EG-Ecosystem` and `X-EG-Package` request headers, never in the URL, so request logs and
trace spans that record URLs do not hold what was looked up. The endpoint reads a CPE vendor
from the URL only, so this tool takes none.

## Prompts

Ready-made workflows a client can show as slash commands. Each prompt names the tools to call, in
order, and tells the model to read every result's `state`, `measured_at`, `method`, `coverage`
and `notes`: `not_assessed` is never reported as clean, a count of 0 under `assessed: false` is
never "not affected", and each figure cites its `measured_at`. A prompt makes no API request.

| Prompt | Arguments | What it asks the model to do |
|---|---|---|
| `triage_cve` | `cve_id` | `get_cve` (with CISA's due date, `kev_due_date`, when the CVE is KEV-listed), `cve_intel`, `vendor_advisories_for_cve`, `epss_history` and `cve_exposure`, then a decision template: exploited, likelihood, reachable, patch, deadline, decision. The patch line gives `cve_intel`'s `fixed_version` as what it records for the package, one per package (the advisory's last range's), never as the fix for every affected branch, and points to `get_cve`'s references tagged Vendor Advisory or Patch for a branch's fix. |
| `kev_weekly_brief` | `days` (1 to 365, default 7) | Work out the start date from `days`, page through `kev_recent` from it 50 rows a page, and write a brief grouped by vendor with ransomware flags and due dates. |
| `am_i_affected` | `product`, or `ecosystem` and `package`; `version` | `check_affected`, read `assessed` before `count`, with the not-assessed wording. |
| `sbom_review` | `sbom` (CycloneDX or SPDX JSON text, up to 5,000,000 characters) | Pass the document to `check_sbom` (and, once more, the purls a rate limit or the time budget left unsent: `data.not_sent_purls`, or, where the text cuts that list, the document's purls from the position and in the order its note gives), read each component's ecosystem, package and version from its purl, as `check_sbom` maps them (every purl type it maps, and `deb`, `apk`, `alpine` and `rpm` by a `distro` qualifier naming a Debian, Ubuntu or Alpine release; any other is unknown, and given no fixed version), look up each affected CVE with `get_cve` and `cve_intel`, and write a fix list ordered by CISA-KEV listing, then EPSS, then score, each key stated. A fixed version is given where it is above the component's installed version: the advisory interval in `check_sbom`'s `match_reason` first, else `cve_intel`'s `fixed_version`, which is one per package (the advisory's last range's) and need not be the fix on the component's branch; otherwise the line says the results give no fixed version for that branch and points to the CVE's advisory. |

## Resources

| Resource | What it holds |
|---|---|
| `echelongraph://methodology` | What each envelope field and `state` value means, and how each tool measures (Markdown). |
| `echelongraph://sources` | What the API reports about its feeds when the resource is read: the NVD poller's `interval`, `last_poll_at`, `poll_count` and `poll_errors`, all of the one instance that answered (from `/api/v1/public/cves/summary`; the two counts are that instance's since it last started, zeroed on every restart, never the feed's reliability), and the CISA KEV catalog's last successful fetch and method (from `/api/v1/public/kev/recent`). It names the feeds no endpoint reports a schedule for, and states none for them (JSON). |
| `cve://{cve_id}` | One CVE as `get_cve` returns it: the structured result, envelope and record, as JSON. Past 30,000 characters of JSON, `data` is cut as `get_cve`'s first text block is, and a note starting `DATA CUT` says what the cut leaves out; `get_cve`'s `structuredContent.data` holds the record whole. An ID that is not a CVE ID is refused before any request; a CVE the API has no record of is not found. |

## What a result means

Every tool answers in one of two shapes, so a model reading the result cannot mistake an
outage for an all-clear:

- **Success** — the first text block is the API's JSON verbatim (cut to fit 30,000 characters
  when it is longer: see "Long answers" below); the second is a one-line
  note saying the call succeeded, which base URL answered, and what it found; the third is
  the structured result as JSON, less what the first two already say (below). When the
  feed genuinely holds nothing for the query the note says so in words ("we looked and
  found nothing … not a lookup failure"), because a measured zero is a measurement. The
  exceptions to verbatim are `cve_summary`, which leaves out a `poller` field the answer sends
  in a JSON type other than its outputSchema's (or a `poller` that is neither a JSON object nor
  null) and names it in the note, and `exposure_radar`: each radar is cut to the fields listed
  above, and each `kev_exposure.newest_kev` row gains an `exposure_state`. Its `shadow_ai` counts are
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
  finding; the second text block is the structured result as JSON, less the message's
  sentences (below). A failure is never rendered as a success with null fields.

Both shapes also carry a structured result, below, and repeat it in their last text block, less
what an earlier block already says, so a client that passes only `content` to the model still
sees how the answer was measured. The first text block (the API's JSON, or the failure) and the
note after it are where 1.x put them.


### Long answers

A model pays for every character of text it reads, and some clients cap what they pass on:
Claude Code warns past 10,000 tokens of tool output and, past 25,000, saves the result to a
file and hands the model its path instead. Through 2.6.2 the first text block was the API's JSON
whatever its size: on production's answers of 2026-10-04 a default `search_cves` page for
"openssl" was 133,300 characters of text, `get_cve` for CVE-2021-44228 80,897, `check_affected`
for the Linux kernel at 5.10.0 364,408, `kev_recent` at its largest page 105,925 and
`search_vendor_advisories` at its largest page 103,147.

So when the API's JSON is longer than 30,000 characters, the first text block holds it cut to
fit, and `structuredContent`'s `data` still holds it whole. First the same JSON is laid out with
each row on a line of its own, which drops no character of the answer but the indentation. If
that is still too long, a tool that returns a list of rows cuts each row to the fields it names,
most kept first (`search_cves` keeps `cve_id`, `severity`, `cvss_v3_score`, `echelongraph_score`,
`score_assessed`, `epss_score`, `kev_listed` and the first 200 characters of the description,
among others), with every long string ending in "…". A list beside the rows is cut before any
row field the first level keeps, and before any row leaves the text: `check_affected`'s
`excluded` and `undetermined` samples keep their first 10 entries, each its `cve_id` and
`reason`, and its `cve_ids` (each match's `cve_id`, in order) its first 10, so that every match
stays in the text, each with at least `cve_id`, `kev_listed`, `ransomware`, `epss_score`,
`effective_score` and `score_assessed`, and `check_sbom`'s `not_sent_purls` keeps its first 10, the note saying from
which position of the input the purls not sent run, and in what order the input's purls are
counted, so that a second call can send them without reading the list. When even the leanest cut is too long, rows are left out of the text
(`check_sbom` leaves out the `not_affected` rows first, then the `not_assessed` ones), and the
note says how to read them: the `offset` to call next, or a smaller `limit`. Any other answer
keeps the first entries of each of its lists (`get_cve`'s `cpe_match` and `references`). The note
then ends with one sentence starting `TEXT CUT` that says what the first text block leaves out
and which tool returns a row (`get_cve`, `get_vendor_advisory`, `check_affected`, and
`cve_intel` a CVE's fixed versions): whole in that tool's `structuredContent.data`, since its own
first text block is cut past 30,000 characters too. An answer that fits is sent as before,
pretty-printed and whole. The same answer is always cut the same way. The `cve://{cve_id}`
resource cuts its `data` as `get_cve`'s first text block is cut, and says so in a note starting
`DATA CUT`. The prompts ask only for what the text keeps: `kev_weekly_brief` reads `kev_recent`
50 rows a page, which the text holds whole; `triage_cve` reads CISA's due date from `get_cve`;
and `sbom_review` reads fixed versions from `cve_intel`.

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
| `coverage` | What the answer covers, where the tool can say: `in_scope` for `cve_exposure`, the list's own account of its count for `search_cves`, the radars that answered for `exposure_radar`, and `assessed`, `not_assessed_reason`, the lookup path and the match counts for `check_affected`. |
| `freshness` | The producing radar's last completed check (`last_run_at`), where the API serves one; `null` where it serves none. |
| `notes` | The caveats, one sentence each: what the envelope itself needs saying, then the note from the text block. |
| `data` | On a success only: the API's JSON, whole: the first text block carries the same JSON, or, past 30,000 characters, a cut of it that the note names (`TEXT CUT`). |
| `error` | On a failure only: `kind`, `path`, `status` and `message`. |

The last text block of every result is this structured result serialized as JSON, less what
an earlier text block already says verbatim, since a client may pass only `content` to the
model. It carries the same `state`, `measured_at`, `coverage` and `freshness` (and on a failure
`error`), key for key. It leaves out `data`, which is a success's first text block, and the
note's sentences, which are the text block just before it (on a failure, the message) and
with which `notes` ends: its `notes` holds only the sentences the envelope adds about itself,
and is left out when there are none. It leaves out `method` too where that note quotes it verbatim, as
`cve_exposure`'s does ("Method: …"). So the text blocks together carry the whole structured
result, but for what a `TEXT CUT` leaves out of `data` (see "Long answers"), and cannot disagree
with it. Before 2.2.0 this block repeated the whole note, so every note was sent twice.

| `state` | What it means |
|---|---|
| `measured` | A measurement of what was asked. An exposure count is `measured` only when the answer says when what it counts was observed (`measured_at`) and how it was produced (`method`). No exposure answer says when today, so neither exposure tool answers `measured`. |
| `not_assessed` | The answer holds no dated measurement of what was asked, so no count in it is presented as one: the radar does not look for this CVE, the answer does not say whether it does, or the answer does not say when what it counts was observed. It can still relay a count, as what the source holds on record, undated: `cve_exposure`'s `exposed_hosts` when its `exposure_state` is `exposed`, and `exposure_radar`'s labelled totals. The notes, and `exposure_state` where the result carries it, say what each count is. |
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
  answer gives one time at which what it counts was observed, so no count is presented as a
  dated measurement. `mcp_servers` dates its verdicts only by a window, `mcp_servers.window.from`
  to `mcp_servers.window.to`, over checks made at different times, which is not one observation
  time; so, since #2438, do `exposed_databases.window`, `leaked_credentials.window` and
  `shadow_ai.confirmed_exposed.window`. `kev_exposure` gives no observation time at all. Its numbers keep the labels above. `freshness` holds each radar's `last_run_at` where the
  API serves one, for `shadow_ai` also `running`, and for `mcp_servers` also `enabled`.
- `check_affected` is `measured` only when the answer says `assessed` true, and `not_assessed`
  when it says false or does not say. Its `measured_at` and `freshness` are `null`: a match answer
  carries no observation time. Its `coverage` gives `assessed` and `not_assessed_reason` first,
  then `lookup` (`cpe` or `registry`), `match_layer`, `count`, `capped`, `candidates_capped`,
  `excluded_count`, `undetermined_count`, `not_affected_count` and `degraded`.

The CVE feed tools' `freshness` is `null`: the feed's answers carry no time at which its
pollers last completed a poll for the feed as a whole.

A success whose fields do not fit the tool's `outputSchema` (a field of a type the schema does
not allow) is returned as a failure with `error.kind` `unexpected_shape`, never relayed, with one
exception: a `cve_summary` `poller` field of another JSON type is left out of `data` and named in
the note, and the rest of the answer is relayed, `summary` with it. A
field the API adds later is still relayed by every tool that relays the API's JSON as data, and
`exposure_radar` and `cve_intel`, which relay a selection, leave it out and name what they leave out.

## Protocol versions

The server answers both eras of the Model Context Protocol on stdio:

- **2026-07-28**: a client that opens with `server/discover` receives a DiscoverResult listing
  `2026-07-28`, the tools, prompts and resources capabilities and the server instructions, and then sends each request
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

## Privacy: what is sent where

**The npm package (stdio).** The server runs on your machine and sends HTTPS requests to one
host, `ECHELONGRAPH_API_BASE` (default `https://app.echelongraph.io`), one per API call a tool
makes (`exposure_radar` makes five; every other tool makes one). No telemetry: it sends nothing
else, to EchelonGraph or anyone. Every request carries the User-Agent
`echelongraph-mcp/<version> (+https://echelongraph.io/pulse/mcp)`, with the
`ECHELONGRAPH_MCP_UA` token ahead of it when you set one, so the API's access log can count use
per version. Like any HTTPS request, it also reaches the API from your network address.

Where each tool's input travels:

| Input | Where it is sent |
|---|---|
| A CVE ID (`get_cve`, `cve_exposure`, `epss_history`, `cve_intel`, `vendor_advisories_for_cve`), a CWE ID and page (`get_cwe`), a vendor and advisory ID (`get_vendor_advisory`) | The URL path. |
| `search_cves`: `search` | The `X-EG-Search` request header, never the URL. Its severity, minimum CVSS, sort, limit and offset go in the query string. |
| `search_vendor_advisories`: `query` | The `X-EG-Advisory-Search` request header, never the URL. Its vendor, severity, CVE filter, limit and offset go in the query string. |
| `check_affected`: `product`, `version`, `ecosystem`, `package` | The `X-EG-Product`, `X-EG-Version`, `X-EG-Ecosystem` and `X-EG-Package` request headers, never the URL. |
| `kev_recent`: `since`, `until`, `ransomware`, `vendor`, `limit`, `cursor` | The `X-EG-Since`, `X-EG-Until`, `X-EG-Ransomware`, `X-EG-Vendor`, `X-EG-Limit` and `X-EG-Cursor` request headers, never the URL. |
| `check_sbom`: `purls`, or an `sbom` document | The purls, in POST bodies of at most 200 each. A CycloneDX or SPDX document is read on your machine and only the purls in it are sent; the document is not. (Over the hosted endpoint the document goes to EchelonGraph's server instead: see below.) |
| `cve_summary`, `exposure_radar` | No input. |

The API marks its answers to header-carried lookups `no-store`, so no shared cache keeps them,
and request logs and trace spans that record URLs do not hold what was looked up there.

**The hosted endpoint.** A request to `https://mcp.echelongraph.io/mcp` reaches EchelonGraph's
server first, which then calls the same API as above. Per request it logs the HTTP method and
path, the status, the duration, the body size, the JSON-RPC method and (for `tools/call`) the
tool name, the protocol version, whether an `Origin` header was sent, and the family of your
client's User-Agent. It never logs tool arguments or a query string. A `check_sbom` document (or
an `sbom_review` prompt's) is a tool argument like any other here: it is in the request body, so
the whole document reaches EchelonGraph's server, which reads the purls from it in memory, sends
only those to the API, and neither logs nor keeps the document. To keep the document on your
machine, run the npm package, or pass `check_sbom` the purls. When a client passes the
per-client limit it logs that client's address key. It passes your client's public address to
the API, in a header the API trusts only with a token it checks, so the API's rate limit counts
you and not the hosted service.

EchelonGraph's privacy policy: <https://echelongraph.io/privacy>.

## Rate limits

No API key, so the API limits each caller, one IPv4 address or one IPv6 /64 network as its
platform records it. Its WAF counts all your requests together in a 60-second window and
refuses one once the count passes the ceiling for its path:

| Path | Ceiling per minute | Tools |
|---|---|---|
| `/api/v1/public/cves` and every path under it | 12,000 | `cve_summary`, `search_cves`, `get_cve`, `epss_history`, `cve_intel`, `check_affected`, `check_sbom` |
| `/api/v1/public/cwes`, `/api/v1/public/vendor-advisories`, `/api/v1/public/kev/recent`, `/api/v1/public/shadow-ai-radar` | 6,000 | `get_cwe`, the three vendor-advisory tools, `kev_recent`, and one of `exposure_radar`'s five calls |
| any other `/api/v1/public` path | 600 | `cve_exposure`, and the rest of `exposure_radar`'s calls |

Because the count is shared, heavy use of one path also uses up the lower ceilings. On top of
that, 500 requests per second per caller is a burst cap on each serving instance, and
`check_sbom`'s batch route is charged per component: 1,200 components a minute per caller.
Over a limit the API answers 429 with `Retry-After`, and the tool returns a failure
(`state` `failed`, `error.status` 429), never empty data. `check_sbom` is the exception: it
sends a long list as batches of 200, waits out a 429's `Retry-After` and sends the batch again,
within 50 seconds per call (MCP clients time a call out at about 60 s). From a fresh budget a
list of up to 1,200 distinct purls finishes in one call; a longer one (the cap is 2,000) is
checked in two calls a minute apart. When a wait would pass the 50 seconds, it
answers the batches it has as `measured` with `coverage.partial` true and the rest counted in
`coverage.not_sent` (`not_sent_reason` `time_budget`); only a 429 on the first batch is a failure. The API's own documentation of these
limits: <https://echelongraph.io/pulse/api>.

The hosted endpoint adds its own limit before the API's: 120 MCP requests a minute per client
address, counted by each server instance, answered over it with HTTP 429, `Retry-After` and a
JSON-RPC error (code `-32029`) that names the limit and the seconds to wait. A request body over
64 KiB is refused (HTTP 413, code `-32600`), except a `tools/call` of `check_sbom` or a
`prompts/get` of `sbom_review`, which may be up to 6 MiB: enough for a CycloneDX or SPDX document
at the tool's 5,000,000-character cap. Each server instance reads at most two such large bodies at
once; a third is answered HTTP 503 with `Retry-After` and a JSON-RPC error (code `-32030`). Each
instance serves at most 64 requests at once; the next waits up to 10 seconds for one to finish,
and is then answered the same way. A `subscriptions/listen` stream, which stays open until its
client leaves, is not one of the 64.

## Configuration

The npm package (stdio):

| Env var | Default | Purpose |
|---|---|---|
| `ECHELONGRAPH_API_BASE` | `https://app.echelongraph.io` | Override the API base (self-host / proxy). A credential in the URL is masked wherever a result quotes the base. |
| `ECHELONGRAPH_API_TIMEOUT_MS` | `15000` | Per-request timeout. A slower answer is reported as a failed lookup, not as empty data. |
| `ECHELONGRAPH_MCP_UA` | unset | One product token (for example `my-monitor/1.0`) put ahead of this package's own User-Agent, so automated callers such as monitors are told apart from people using the server. A value that is not a single token is ignored. |

The HTTP entrypoint, `dist/http.js` (`npm run start:http`), serves the same tools over
Streamable HTTP on `POST /mcp`, with a liveness check on `GET /health`. In a container with
little memory, start it with V8's heap capped below the container's limit, as EchelonGraph's
hosted deployment does at half of 256 MiB (`node --max-old-space-size=128 --max-semi-space-size=16 dist/http.js`): Node
otherwise sizes its heap from the memory the system reports, which in a container can be the
host's, and the container is then killed before V8 collects.
It reads the three variables above and:

| Env var | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | The port it listens on. |
| `MCP_RATE_LIMIT_PER_MIN` | `120` | MCP requests a minute per client address, per instance. |
| `MCP_MAX_BODY_BYTES` | `65536` | The largest request body it reads, except for an SBOM (below). |
| `MCP_MAX_SBOM_BODY_BYTES` | `6291456` | The largest body of a `tools/call` of `check_sbom` or a `prompts/get` of `sbom_review`. |
| `MCP_LARGE_BODY_SLOTS` | `2` | How many bodies over `MCP_MAX_BODY_BYTES` it reads and serves at once; past that, 503 with `Retry-After`. |
| `MCP_MAX_IN_FLIGHT` | `64` | How many requests it serves at once, not counting `subscriptions/listen` streams; the next, its body read, waits. |
| `MCP_ADMISSION_WAIT_MS` | `10000` | How long a request waits to be served before it is answered 503 with `Retry-After`. |
| `ECHELONGRAPH_FORWARD_TOKEN`, `ECHELONGRAPH_FORWARD_HOST`, `MCP_REQUIRE_FORWARD_TOKEN` | unset | EchelonGraph's hosted deployment only: the token with which it names each client to the API. Leave them unset when you run it yourself; the API then counts every request as coming from your server. |

## Develop

```bash
npm install
npm run build      # tsc → dist/
npm test           # build, then the behavioural suite over both protocol eras, against a stub API (no network needed)
npm run smoke      # spawn the server + call cve_exposure against the production API
```

`npm run smoke` calls the production API with this package's User-Agent. Run from our own
workspace, whose egress address the API recognises as ours, its requests are counted as our own
traffic and appear in no adoption count. Run from any other machine, they are counted as external
MCP adoption unless you set `ECHELONGRAPH_MCP_UA` (for example
`ECHELONGRAPH_MCP_UA=my-smoke/1.0 npm run smoke`), which files them under that token's family
instead. `npm test` never leaves the machine.

`npm test` runs the suite once over a 2026-07-28 `server/discover` and once over a 2025-06-18
`initialize`, plus the era tests. To run it against an installed package rather than `dist/`,
set `ECHELONGRAPH_MCP_BIN` to that package's `echelongraph-mcp` bin: the tests then run the bin
directly, as `npx` does, and read that package's own files.

## Versioning

Semantic versioning: a major version changes protocol behaviour or drops a Node.js version, a
minor version adds tools or fields, a patch fixes wording or behaviour without changing a tool's
shape. Every release is published to npm with a provenance attestation by the public repo's
release workflow, from the commit tagged `v<version>`. Changes per version:
[CHANGELOG.md](CHANGELOG.md).

## Security

Report a vulnerability privately to **support@echelongraph.io**, not in a public issue. The
policy, the supported versions and the scope are in [SECURITY.md](SECURITY.md).

## License

The code is MIT-licensed.

The CVE Pulse compilation (how EchelonGraph combines its CVE sources, and the EchelonGraph
score) is © EchelonGraph, served under the CVE Pulse free-access terms; the source records it
compiles stay under their publishers' terms.

Exposure counts are derived from Shodan data. Shodan data is owned by Shodan, which holds its
copyright (© Shodan). EchelonGraph claims no ownership of it or copyright in it.
