# EchelonGraph MCP server

**CVE and internet-exposure data** for Claude, Cursor, VS Code, Cline, and any
[MCP](https://modelcontextprotocol.io) client, straight from
[EchelonGraph](https://echelongraph.io)'s free public feed.

It exposes EchelonGraph's CVE Pulse (NVD + MITRE-CNA *pre-NVD* + CISA-KEV + EPSS + GitHub
GHSA, fused into one score) **plus a per-CVE internet-exposure footprint**: how many
internet-facing services (distinct ip:port) EchelonGraph's KEV-exposure radar has on record
running a version that maps to the CVE. Exposure counts are derived from Shodan data.
Shodan data is owned by Shodan, which holds its copyright (© Shodan).

Its 16 tools look up one CVE (record, exploit code and fixed versions, how it is fixed as its
sources state it, EPSS history, vendor advisories, exposure footprint), list CISA's newest KEV additions, check whether a product or
package version is affected, check an SBOM or a project's lockfiles, and read a CWE and its CVEs. Every result says how
it was measured (`state`, `measured_at`, `method`, `coverage`, `freshness`, `notes`), so a model
cannot mistake an outage or an unassessed lookup for an all-clear.

It also serves five prompts, ready-made workflows a client can show as slash commands
(`triage_cve`, `kev_weekly_brief`, `am_i_affected`, `sbom_review`, `workload_triage`; see "Prompts"), two resources
(`echelongraph://methodology` and `echelongraph://sources`) and one resource template
(`cve://{cve_id}`; see "Resources").

Free and keyless: no API key, no auth, read-only. The server makes no request other than the
API call a tool needs to answer.

- npm: [`echelongraph-mcp`](https://www.npmjs.com/package/echelongraph-mcp) · Official MCP
  Registry: `io.echelongraph/echelongraph-mcp` · Docs: <https://echelongraph.io/pulse/mcp>
- Source: <https://github.com/echelongraph/echelongraph-mcp> · Changes:
  [CHANGELOG.md](CHANGELOG.md) · Security: [SECURITY.md](SECURITY.md)
- Also listed on: [Smithery](https://smithery.ai/servers/echelongraph/echelongraph-mcp), a registry
  entry for `https://mcp.echelongraph.io/mcp` (its proxy, API and CLI
  [shut down on 2026-10-31](https://smithery.ai/future)) ·
  [Glama](https://glama.ai/mcp/servers/echelongraph/echelongraph-mcp)

## Quick start

The local server runs through `npx` and needs Node.js 20 or later; nothing is installed
globally. Claude Desktop's one-click extension, below, needs neither. Add one of the blocks below
to your client, quit it fully and reopen it, then ask: *"Is CVE-2023-44487 actively exploited, and
how many exposed services does EchelonGraph's radar have on record for it?"*

### Claude Desktop

Three ways in. The first two need no Node.js: a one-click extension that runs the server on your
machine, and a custom connector to the hosted endpoint. The third runs the server through `npx`.

**1. [Install in Claude Desktop](https://github.com/echelongraph/echelongraph-mcp/releases/latest/download/echelongraph-mcp.mcpb)
(one click, no Node.js).** The link downloads `echelongraph-mcp.mcpb`, a Claude Desktop extension.
Open it, or in Claude Desktop choose Settings → Extensions → Advanced settings → Install Extension
and pick it, then choose **Install**. Claude Desktop runs the server with the Node.js it ships and
writes its own configuration: no PATH and no JSON to edit. To update, install the next release's
bundle the same way. Every new release on GitHub carries the bundle (releases up to 2.6.5 do not),
built from the release's tag by the workflow that publishes the npm package, and signed with a SLSA
build-provenance attestation. To check a download:
`gh attestation verify echelongraph-mcp.mcpb --repo echelongraph/echelongraph-mcp`.

**2. Custom connector (no install).** Claude Desktop uses your claude.ai account's connectors:
Customize → Connectors → **+ Add** → **Add custom connector**. Name it `EchelonGraph`, paste
`https://mcp.echelongraph.io/mcp`, choose **No sign in**, and add it. A connector added on
claude.ai shows up in Claude Desktop too, and the plan rules are claude.ai's (see "Remote (no
install)" below).

**3. Local server through `npx`.**

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

   To check that the file parses, run this in Terminal (macOS):

   ```sh
   node -e "JSON.parse(require('fs').readFileSync(process.argv[1], 'utf8'))" "$HOME/Library/Application Support/Claude/claude_desktop_config.json"
   ```

   or this in PowerShell (Windows):

   ```powershell
   node -e "JSON.parse(require('fs').readFileSync(process.argv[1], 'utf8'))" "$env:APPDATA\Claude\claude_desktop_config.json"
   ```

   No output means valid JSON. A `SyntaxError` means the file is broken (often curly quotes or a
   missing comma); `ENOENT` means there is no file at that path yet.
4. **Quit fully, then reopen.** Closing the window leaves the old config loaded. On macOS choose
   Claude → Quit Claude (⌘Q); on Windows right-click the Claude icon in the system tray and choose
   Quit. The first start can take longer while `npx` downloads the package.
5. **Check that it worked.** Settings → Developer lists `echelongraph` as running, and the tools
   menu in the chat box lists EchelonGraph's tools, the ones under "Tools" below. Then ask the
   question at the top of this section.

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
to share it through the project's `.mcp.json`. Claude Code hands the model each result's
`structuredContent`, which this server holds to 30,000 characters unless a call passes `full: true`
(see "Long answers"); `MAX_MCP_OUTPUT_TOKENS` (25,000 tokens by default) is the cap Claude Code
applies to a tool's output, and raising it lets a `full: true` answer through.

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

The same 16 tools, five prompts, two resources and one resource template are served over
Streamable HTTP at:

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
API, so its answers are the npm package's answers ("Privacy" says what it logs).

## Tools

Every tool is read-only (`readOnlyHint: true`) and declares a title and an `outputSchema`.
The example questions are ones a client can answer with that tool alone.

| Tool | Title | What it answers | Example question |
|---|---|---|---|
| `cve_summary` | CVE feed summary | Counts of active CVEs by severity band, the count with no severity band from any source (`summary.none`, sent again as `summary.unscored`: CVEs not yet scored, not a rating of None), the same CVEs counted by NVD's severity label, as provenance (`summary.nvd_critical` to `summary.nvd_none`), the rejected (withdrawn) records outside the total (`summary.rejected`), and when the feed was last updated. | *How many critical CVEs does the feed hold, and when was it last updated?* |
| `search_cves` | Search CVEs | Search/filter CVEs (severity, min CVSS, text, sort) with EchelonGraph scores and `score_assessed`; page with `limit` and `offset`; the note names each row not yet scored. | *Find critical CVEs that mention Tomcat with a CVSS of 9 or more.* |
| `get_cve` | CVE detail | One CVE's record: CVSS v3 and (when scored) v4, the EchelonGraph score and its confidence, whether EchelonGraph has scored it (`score_assessed`), EPSS, CISA-KEV status and known ransomware use and, for a KEV-listed CVE, CISA's own text relayed verbatim (`kev_required_action`, the action CISA requires of US federal civilian agencies, not EchelonGraph's advice; `kev_short_description`; `kev_notes_urls`), the GitHub GHSA id, references, and its published, modified and `updated_at` times. | *What are CVE-2024-3094's CVSS, EPSS and CISA-KEV status?* |
| `cve_exposure` | Internet exposure for one CVE | Internet-exposure footprint for a CVE: exposed service count (distinct ip:port, the `exposed_hosts` field) + country/product breakdown, from the KEV-exposure radar. | *How many exposed services does EchelonGraph's radar have on record for CVE-2023-44487?* |
| `exposure_radar` | Exposure radar totals | Aggregate totals across the exposure radars: services running CISA-KEV CVEs; unauthenticated data stores and observability UIs, found through Shodan (LeakIX when Shodan query credits run low) and then confirmed by EchelonGraph's own identified check, which is not a pure read (on Redis it names its client; on ClickHouse its query lands in the server's query log); leaked credentials; shadow AI; and MCP servers found in EchelonGraph's own Certificate Transparency feed, by RFC 9728 verdict, protocol era and transport. Every number is labelled by what it counts, and a field the tool cannot label is left out and named. | *How many unauthenticated data stores has EchelonGraph's radar confirmed?* |
| `kev_recent` | Recent CISA KEV additions | The CVEs CISA has added to its Known Exploited Vulnerabilities catalog, newest first (`kev_added_date`), from EchelonGraph's copy of the catalog, polled from CISA every 5 minutes: due date, vendor, product, known ransomware use, EchelonGraph's severity, CVSS, EPSS and `eg_kev_tier`, and `our_first_seen_kev`. Filter by date range, ransomware and vendor; page with `limit` and `next_cursor`. Dated by `last_successful_fetch_at`, our last successful fetch of CISA's feed; the filters travel as request headers, never in the URL. | *Which CVEs has CISA added to KEV since 1 September, and which have known ransomware use?* |
| `epss_history` | EPSS change history for one CVE | How one CVE's EPSS score has changed, as EchelonGraph recorded it: one point per recorded change (`series_kind` `change_only`), never a daily series, with the value now; `complete_since`, from when every change is a point (before it the record misses changes, so a missing point there does not mean unchanged, and the series is never called complete); `coverage`, which FIRST score dates the record holds and which it misses (`days_missing`, `days_partial`, `days_in_progress`); and `series_starts_at`, when recording began; before it a missing point means not recorded, not unchanged. | *How has CVE-2023-44487's EPSS score changed, as EchelonGraph recorded it?* |
| `check_affected` | Am I affected? (product or package at a version) | Whether a product (its NVD CPE product token) or a registry package (`ecosystem` and `package`) at a given version is affected by known CVEs, from the matcher behind echelongraph.io/am-i-affected: `assessed` first (false: not evaluated, with `not_assessed_reason`, and a count of 0 then is not "not affected"), the matching CVEs with `kev_listed`, `ransomware`, `epss_score`, `effective_score` and `score_assessed` (a registry match also `fixed_in`, the lowest version above it that no affected interval of the record holds, with `fixed_in_detail` when it moved past an overlapping interval, or null with `fixed_in_reason`, which is not a finding that no fix exists), and advisories it cannot decide counted as `undetermined_count`, never as safe. What you look up travels in request headers, never in the URL. | *Is openssl 3.0.0 affected by known CVEs? Is lodash 4.17.15 on npm?* |
| `check_sbom` | Check an SBOM against the advisory corpus | A dependency list checked against EchelonGraph's advisory corpus (OSV.dev records), one verdict per component: `affected`, `not_affected`, `undetermined` or `not_assessed`, each with its `not_assessed_reason`. Each row names the package its advisories were looked up by (`matched_package`) and how (`matched_via`: `upstream` where a deb, apk or alpine purl's upstream qualifier names the source package, which is how Debian and Alpine file advisories, else `purl_name`), and each match carries `fixed_in`, the lowest version above the component's that no affected interval of the record holds (`fixed_in_detail` names any overlapping interval it moved past), or null with `fixed_in_reason`. Pass up to 2,000 distinct purls, in a list of at most 10,000 entries, or a CycloneDX JSON or SPDX JSON document: the purls are read from it by the MCP server and only they are sent to the API, in POST bodies of at most 200 each, one after another; the document itself is not sent on. Run from npm, the server is on your machine; over the hosted endpoint (`mcp.echelongraph.io`) it is EchelonGraph's, and the document is the request body. At the API's per-component rate limit (429), the tool waits out its `Retry-After`, within 50 seconds a call; past that it answers what it has, with the purls not sent counted in `coverage.not_sent`, the reason in `coverage.not_sent_reason`, and the list in `data.not_sent_purls` (whole with `full: true`; a `DATA CUT` can cut it), never dropped silently. A deb, apk or rpm purl without a `distro` qualifier naming its release is not assessed (`distro_release_unknown`): EchelonGraph does not guess one. Only `not_affected` is clean. No ranking, no score. | *Check this CycloneDX SBOM against the advisory corpus.* |
| `scan_manifest` | Check a lockfile against the advisory corpus | A project's lockfiles or pinned manifests checked against the same advisory corpus, one verdict per dependency, through the same batch route, batches, 50-second budget and `Retry-After` waits as `check_sbom`. Pass `files`, 1 to 20 of `filename` and `content` (the file's text), up to 5,000,000 characters in all; the format is read from the filename, or set by `format`. Read: `requirements.txt` (only `==` and `===` pins; extras and markers stripped), `go.mod` (`require`, single-line and block, `// indirect` included, with `replace` and `exclude` applied), `package-lock.json` and `npm-shrinkwrap.json` (lockfileVersion 1 to 3), `Cargo.lock`, `Gemfile.lock` (platform suffixes stripped), `composer.lock` (a leading `v` stripped), `poetry.lock` and `gradle.lockfile`. `package.json`, `pyproject.toml`, `Pipfile`, `Gemfile`, `Cargo.toml`, `composer.json` and `build.gradle` hold ranges and are refused, each naming the lockfile to pass; `go.sum` is refused, as it lists module versions the build does not select; `pom.xml`, `yarn.lock` and `pnpm-lock.yaml` are not read yet. The MCP server reads the files into purls and only the purls are sent to the API; filenames and file contents are not sent on. Run from npm, the server is on your machine; over the hosted endpoint (`mcp.echelongraph.io`) it is EchelonGraph's, and the files are the request body. `data.results` holds one row per distinct purl, as `check_sbom`'s do, each match with `kev_listed`, `epss_score` and `fixed_in`. Every entry not sent is in `data.not_checked`, with its file, line and `reason`: `version_unpinned` (a range, such as `django>=4`, whose bound is never sent as a version), `version_unresolved`, `local_path`, `vcs_source` or `unsupported_line`, counted in `coverage.not_checked_by_reason`; they are not clean. A file that holds no version this tool can check answers `not_assessed` without calling the API. Only `not_affected` is clean. No ranking, no score. | *Check this package-lock.json against the advisory corpus.* |
| `cve_intel` | CVE weakness, exploits and packages | Weakness, exploit code and detection checks (a Nuclei template, or a GitHub repository the API serves as a checker, checks whether a system is affected; it is not necessarily exploit code, and the note counts them apart), affected packages and fixed versions for one CVE, from EchelonGraph's per-CVE enrichment: `cwes`, `exploits` (at most 10, verified first) with `exploits_total`, `exploits_capped`, `exploits_by_kind` and `exploits_by_status`, `affected_packages`, `fixed_versions` and `timeline`. Each `affected_packages` row carries `fixed_branches`, every affected range of the package with its fix (`introduced`, and `fixed` or, where no fix is on record, `last_affected`), each naming the OSV record that published it (`advisory_id`, `source`) and in that record's order: an installed version's fix is the first `fixed` above it that no range of its row holds (the `fixed` of the range that holds it, moved past any range that still holds that version; none past a range without `fixed`), compared in the ecosystem's version order. `fixed_version` is one range's fix, kept for compatibility, not the fix for every range; `fixed_branches` is null where a package's ranges were never loaded, and `[]` where no version range is on record, which is not a finding that no fix exists. `verified_status` is the label stored with each reference, not a guarantee that the exploit works. An empty `exploits` list is not evidence that no public exploit exists; a section the API could not read is named in `coverage.sections_failed`, never relayed as an empty list. | *Is there public exploit code for CVE-2021-44228, and which versions fix it?* |
| `cve_remediation` | How one CVE is fixed | How one CVE is fixed, as its sources state it, in one answer; every text is relayed as its source states it, untested by EchelonGraph: `cisa` (for a KEV-listed CVE, CISA's `required_action`, `due_date`, `short_description` and `notes_urls`, verbatim; CISA directs the action at US federal civilian agencies, and it is not EchelonGraph's advice), `fixed_branches` (each affected package with every affected range and its fix), `vendor_remediations` (each vendor advisory naming the CVE, at most 20, with its `remediation_state` and the items it lists for the CVE, each with `kind`, the vendor's own category: `vendor_fix`, `workaround`, `mitigation`, `no_fix_planned`, `none_available` or `other`), `fix_references` (references NVD or the CNA tagged Patch or Mitigation), `patches`, `coverage` and `failed_sections`, with `fix_status`, the API's fix-status rule that CVE Pulse pages show. Given the installed `ecosystem`, `package` and `version` (all three or none), it also answers `installed` (that version's verdict) and `fixed_in`: the first version above it that no affected range on record holds, or null with `fixed_in_reason`. `remediation_state` `none_in_source` or `not_parsed`, and an empty list, are not a finding that no fix exists. A REJECTED CVE answers `not_assessed`. | *How is CVE-2021-44228 fixed, as its sources state it?* |
| `get_cwe` | CWE and its CVEs | One CWE (weakness class) and the CVEs classified under it: `name` and `description` from the MITRE CWE catalog EchelonGraph embeds, `total`, and one page of 50 `cves`, ordered as `order` states (CISA-KEV-listed first, then EchelonGraph score). A `total` of 0 says that no CVE in EchelonGraph's feed is classified under that CWE, not that none exists. | *Which CVEs are classified under CWE-79, CISA-KEV-listed first?* |
| `vendor_advisories_for_cve` | Vendor advisories for one CVE | The vendor-published advisories (Microsoft MSRC, Red Hat, Cisco, Palo Alto Networks, GitHub GHSA and the other feeds EchelonGraph polls) that name one CVE, newest first, at most 20, each with `remediation_kinds` and `remediation_state` (`not_parsed`: EchelonGraph does not read that vendor's remediation, which is not a finding of none). | *Which vendor advisories name CVE-2024-3400?* |
| `get_vendor_advisory` | Vendor advisory detail | One vendor advisory in full: description, severity, `cve_ids` and the subset with a CVE record here (`known_cve_ids`), `affected_products`, `remediation` and `references`, and `remediations`, each remediation the vendor lists with its `kind` (the vendor's own category), verbatim text and URL, with `remediation_state`. | *Show one of those advisories in full: affected products, remediation and references.* |
| `search_vendor_advisories` | Search vendor advisories | Search vendor advisories by text (title, description, vendor, advisory ID, products, CVE IDs), vendor, severity and whether they name a CVE. The search text is sent in a request header, never in the URL. | *Search vendor advisories for FortiOS, critical severity only.* |

The three vendor-advisory tools relay `vendor_published_at` (the vendor's date), `our_first_seen_at`
(when EchelonGraph first recorded the advisory) and `withdrawn` (the vendor rescinded it; the note
names each one, and the search leaves them out).

Each also relays every vendor's window in `coverage` (`vendor_windows`, or `vendor_window` for the
detail): the advisories held, the earliest and latest `vendor_published_at` among them,
`held_since` and `history_backfill`. `held_since` is the start of the window EchelonGraph has read the
vendor's advisories from: one published before it may not be held. For a vendor with no history read (`history_backfill`
`not_supported`) it can be years after the earliest advisory held: Cisco's poller first read the
advisories changed in the last 90 days, Red Hat's and GitHub's in the last 7, so an older
advisory revised later is held while those published beside it are not.
`vendor_advisories_for_cve` lists in `vendors_not_fully_held` each vendor with no advisory in the
answer of which EchelonGraph holds none, whose `held_since` is after 1 January of the CVE ID's year
or not known, or whose history is still being read: no advisory from such a vendor is not a finding
that it published none.

Every figure is as fresh as the last check that produced it. The CVE feed is polled from its
sources on a schedule. Each radar has its own schedule and refreshes only while it runs, and
`exposure_radar`'s `freshness` gives each radar's last completed check (`last_run_at`) where the
API serves one.

### How each tool reads its answer

What each tool relays, field by field, and what each number counts, is in the pages below, which
ship in the package's `docs/` folder:

- [How `cve_summary` reads its counts](https://github.com/echelongraph/echelongraph-mcp/blob/main/docs/tools.md#how-cve_summary-reads-its-counts):
  `summary.none` counts CVEs not yet scored, not CVEs rated None, and `summary.nvd_critical` to
  `summary.nvd_none` count by NVD's severity label (or a pre-NVD label standing in), as provenance.
- [How `get_cve` and `search_cves` read the EchelonGraph score](https://github.com/echelongraph/echelongraph-mcp/blob/main/docs/tools.md#how-get_cve-and-search_cves-read-the-echelongraph-score):
  `score_assessed: false` is **not yet scored**, never a score of 0.
- [What `patch_available` says](https://github.com/echelongraph/echelongraph-mcp/blob/main/docs/tools.md#what-patch_available-says),
  and the evidence `patch_evidence` names, the CVE record's own fix statement among it
  (`cna_solution`, `description_fix`): `false` means no fix evidence is on record, not that no fix
  exists.
- [How `cve_exposure` counts](https://github.com/echelongraph/echelongraph-mcp/blob/main/docs/tools.md#how-cve_exposure-counts):
  a count of ip:port services, not machines, inferred from banner versions in a sample of Shodan
  data, and for a CVE outside the radar's tracked set **NOT ASSESSED**: its 0 is not a measurement.
- [How `exposure_radar` counts](https://github.com/echelongraph/echelongraph-mcp/blob/main/docs/exposure-radar.md):
  every number of its five radars, each labelled by what it counts.
- [How `check_affected` decides](https://github.com/echelongraph/echelongraph-mcp/blob/main/docs/tools.md#how-check_affected-decides):
  read `assessed` before `count`; a registry match's `fixed_in` is the lowest version above it that
  no affected interval of the record holds, or null with `fixed_in_reason`.

## Prompts

Ready-made workflows a client can show as slash commands. Each prompt names the tools to call, in
order, and tells the model to read every result's `state`, `measured_at`, `method`, `coverage`
and `notes`: `not_assessed` is never reported as clean, a count of 0 under `assessed: false` is
never "not affected", and each figure cites its `measured_at`. A prompt makes no API request.

| Prompt | Arguments | What it asks the model to do |
|---|---|---|
| `triage_cve` | `cve_id` | `get_cve` (with CISA's due date, `kev_due_date`, when the CVE is KEV-listed), `cve_intel`, `vendor_advisories_for_cve`, `epss_history` and `cve_exposure`, then a decision template: exploited, likelihood, reachable, patch, deadline, decision. The patch line gives each affected range with its fix from `cve_intel`'s `fixed_branches`; where a package has none, it gives `fixed_version` as what `cve_intel` records for the package, one per package (the advisory's last range's as a rule), never as the fix for every affected branch, and points to `get_cve`'s references tagged Vendor Advisory or Patch for a branch's fix. |
| `kev_weekly_brief` | `days` (1 to 365, default 7) | Work out the start date from `days`, page through `kev_recent` from it 50 rows a page, and write a brief grouped by vendor with ransomware flags and due dates. |
| `am_i_affected` | `product`, or `ecosystem` and `package`; `version` | `check_affected`, read `assessed` before `count`, with the not-assessed wording. |
| `sbom_review` | `sbom` (CycloneDX or SPDX JSON text, up to 5,000,000 characters) | Pass the document to `check_sbom` (and, once more, the purls a rate limit or the time budget left unsent: `data.not_sent_purls`, or, where the text or a `DATA CUT` cuts that list, the document's purls from the position and in the order its note gives), read each component's ecosystem, package and version from its purl, as `check_sbom` maps them (every purl type it maps, and `deb`, `apk`, `alpine` and `rpm` by a `distro` qualifier naming a Debian, Ubuntu or Alpine release; any other is unknown, and given no fixed version; a `deb`, `apk` or `alpine` purl with an `upstream` qualifier as the source package that qualifier names, the row's `matched_package` when its `matched_via` is `upstream`, which the fix list names beside the purl), look up each affected CVE with `get_cve` and `cve_intel`, and write a fix list ordered by CISA-KEV listing, then EPSS, then score, each key stated. Where the text keeps a match, its fixed version is the match's `fixed_in` alone, the lowest version above the installed one that no affected interval of the record holds; a null `fixed_in` is written "no fix on record" with its `fixed_in_reason` as given, not a finding that no fix exists (one a `DATA CUT` left without its reason is never called no fix), and no fixed version is read from prose (`match_reason`, `fixed_in_reason`). Where the text keeps no match for the component, or a match has no `fixed_in`, a fixed version is given only above the installed version: the first `fixed` above it that no range of the `cve_intel` row's `fixed_branches` holds, else, for a package without `fixed_branches`, `cve_intel`'s `fixed_version`, one per package (the last range's), which need not be the fix on the component's branch; otherwise the line says the results give no fixed version for that branch and points to the CVE's advisory. |
| `workload_triage` | `source` (optional: `kubernetes`, `github_actions` or `images`; default: all three are described) | Rank your own pods, CI job containers or images: list the workloads and decide their exposure with your own tools, make an SBOM of each image digest, and pass `check_sbom` the purls alone (no workload, namespace, image, registry name, credential or exposure label is sent; the image's own `pkg:oci`/`pkg:docker` purl is left out). Rows are ordered by CISA-KEV listing, then caller-asserted exposure (unknown is never sorted with not exposed), then EPSS, then score, each key stated. A row whose matches a `DATA CUT` capped is read with its `matches_truncated` (its KEV-listed and ransomware CVE IDs), and each CVE kept without its match, or a match without a field it ranks by, is read from `get_cve`; past 30 CVEs it stops calling `get_cve`. `not_assessed` rows are counted and never reported as clean. The prompt takes no workload data. |

## Resources

Two resources, which `resources/list` lists, and one resource template, which
`resources/templates/list` lists (a client reads `cve://CVE-2024-3400`, for example):

| Resource | What it holds |
|---|---|
| `echelongraph://methodology` | What each envelope field and `state` value means, and how each tool measures (Markdown). |
| `echelongraph://sources` | What the API reports about its feeds when the resource is read: the NVD poller's `interval`, `last_poll_at`, `poll_count` and `poll_errors`, all of the one instance that answered (from `/api/v1/public/cves/summary`; the two counts are that instance's since it last started, zeroed on every restart, never the feed's reliability), and the CISA KEV catalog's last successful fetch and method (from `/api/v1/public/kev/recent`). It names the feeds no endpoint reports a schedule for, and states none for them (JSON). |
| `cve://{cve_id}` | One CVE as `get_cve` returns it: the structured result, envelope and record, as JSON. Past 30,000 characters of JSON, `data` is cut as `get_cve`'s first text block is, `data_truncated` is `true`, `truncated` names each list cut, and a note starting `DATA CUT` says what the cut leaves out; `get_cve`'s `structuredContent.data` holds the record whole with `full: true`. An ID that is not a CVE ID is refused before any request; a CVE the API has no record of is not found. |

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
  null) and names it in the note, and `exposure_radar`: each radar is cut to the fields
  [docs/exposure-radar.md](https://github.com/echelongraph/echelongraph-mcp/blob/main/docs/exposure-radar.md)
  lists, and each `kev_exposure.newest_kev` row gains an `exposure_state`. Its `shadow_ai` counts
  are regrouped as that page says, and its `poller` block carries only `running` and
  `last_run_at`, or is dropped when it carries no real completion time. The block's other fields describe the server instance that
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

Both shapes also carry a structured result, below, and repeat it in their last text block, so a
client that passes only `content` to the model still sees how the answer was measured.


### Long answers

A model pays for every character it reads, and clients differ in which part of a result they hand
it, so each part is held to the same budget, 30,000 characters, and each is cut on its own terms:

- **Claude Code** hands the model `structuredContent`, not the text blocks, and sizes it against
  `MAX_MCP_OUTPUT_TOKENS` (25,000 tokens by default): it warns past 10,000 tokens and, past the cap,
  saves the result to a file and hands the model its path instead. Through 2.7.x
  `structuredContent.data` was always the answer whole (`get_cve` CVE-2021-44228: 65,540
  characters on 2026-10-11, which Claude Code saved to a file). Since 3.0.0 it is cut to fit
  (below). `MAX_MCP_OUTPUT_TOKENS`, set in the environment Claude Code starts in, raises its cap.
- **A client that passes only the text blocks** (`content`) reads the first text block, cut to fit
  as described after the next item.
- **A program** that reads `structuredContent.data` and needs the answer whole, however long,
  passes `full: true`: every tool takes it. A client that sizes structured results, as Claude Code
  does, can refuse such an answer past its cap.

The structured result. When the whole of it (the envelope, its notes and `data`, as compact JSON)
would pass 30,000 characters and the call does not say `full: true`, `data` is cut, in an order each
tool states. Where one row is large, every row is first thinned, all rows kept: `check_sbom` and
`scan_manifest` keep each row's verdict and `cve_ids`, and every match field a prompt reads, and
their `not_affected` and `not_assessed` rows leave first where that lets every affected row keep
all its matches ([how](https://github.com/echelongraph/echelongraph-mcp/blob/main/docs/tools.md#how-check_sbom-and-scan_manifest-cut-their-rows));
`check_affected` keeps each
match's scores, flags, criteria and `fixed_in`, then fewer; `cve_remediation` drops each item's
`product_ids`, then its text, keeping every advisory's state, kinds, URLs and fixed builds
(`get_vendor_advisory` returns each text), thins `fixed_branches` (then caps each
package's ranges) and `patches`, then cuts `fix_references`, then `patches`, then
`fixed_branches`, advisories last, the note naming `vendor_advisories_for_cve`, which
lists them all; `search_cves` keeps each row's
description and scores, then the scores alone; the vendor-advisory
tools drop `affected_products`, then `summary`. Only then do rows leave (`check_sbom` and
`scan_manifest`: as that page says); `check_affected` drops its `excluded` and `undetermined` samples first and its
`cve_ids`, which names every match, last; the other row tools drop rows from the end, and those that
page say the `offset` or `limit` to read them from (`search_cves` and `search_vendor_advisories`
also the page size whose rows fit `data` whole, counted on the rows whole). `get_cve` cuts
`cpe_match` and `references`, each to at most the same number of entries, then
`cpe_configurations`; `exposure_radar` cuts its daily and weekly series, each keeping its newest
entries, then every ranking, then `kev_exposure.newest_kev`; then any other list at the top of
`data` is cut the same way. The room left once a list fits goes back to the lists emptied before
it, as many of their entries as fit (their first, a series its newest). No string is shortened and no value changes (a thinned row
keeps some of its fields, each optional in the outputSchema, so `data` still validates;
a cut adds only `matches_truncated` and `fixed_branches_truncated`). The result
then says `data_truncated: true` (`false` on every other success), `truncated` gives each list cut,
by its path in `data`, with its `total`, the number `returned` and, where its entries are thinned,
`thinned: true`, and the note ends with sentences starting `DATA CUT` that say what was cut, how to
read the rest and that the same call with `full: true` returns `data` whole.

The first text block. Through 2.6.2 it was the API's JSON whatever its size. So
when the API's JSON is longer than 30,000 characters, the first text block holds it
cut to fit, cut from the answer whole (not from the cut `data`), the same way with or without
`full: true`. First the same JSON is laid out with
each row on a line of its own, which drops no character of the answer but the indentation. If
that is still too long, a tool that returns a list of rows cuts each row to the fields it names,
most kept first (`search_cves` keeps `cve_id`, `severity`, `cvss_v3_score`, `echelongraph_score`,
`score_assessed`, `epss_score`, `kev_listed` and the first 200 characters of the description,
among others), with every long string ending in "…". A list beside the rows is cut before any
row leaves the text: `check_affected`'s
`excluded` and `undetermined` samples keep their first 10 entries, each its `cve_id` and
`reason`, and its `cve_ids` (each match's `cve_id`, in order) its first 10, so that every CPE
match stays in the text, each with at least `cve_id`, `kev_listed`, `ransomware`, `epss_score`,
`effective_score` and `score_assessed` (and `fixed_in` on a registry match; a registry list near
the cap of 200 can leave its last matches out, KEV-listed and ransomware ones last, and the note
says how many and names any of those), and `check_sbom`'s
`not_sent_purls` keeps its first 10, the note saying from which position of the input the purls
not sent run, and in what order the input's purls are counted, so that a second call can send
them without reading the list. `scan_manifest` cuts its rows as `check_sbom` does, and its
`not_checked` list keeps its first 20 entries. `cve_remediation` thins its advisories, then
`fixed_branches` and `patches`, then caps each package's ranges at the most that fit (a package so
cut carries `fixed_branches_truncated` and is named in the note, which says to read its fix with `full: true`), then drops `fix_references`,
`patches` and `fixed_branches` rows, in `data`'s order. When even the leanest cut is too long, rows are left out of the text
(`check_sbom` and `scan_manifest` leave out the `not_affected` rows first, then the `not_assessed` ones, and rows with a KEV-listed or ransomware match last, naming by `index` any that leave; those two kinds are cut to the leanest level and leave sooner where that lets the other rows keep their matches, and where it does not, every row is cut to that level first: see docs/tools.md), and the
note says how to read them: the `offset` to call next, a smaller `limit`, or, for advisories,
`vendor_advisories_for_cve`. Any other answer
keeps the first entries of each of its lists (`get_cve`'s `cpe_match` and `references`). The note
then ends with one sentence starting `TEXT CUT` that says what the first text block leaves out
and which tool returns a row (`get_cve`, `get_vendor_advisory`, `check_affected`, and
`cve_intel` a CVE's fixed versions): whole in that tool's `structuredContent.data` with
`full: true`, since its own first text block is cut past 30,000 characters too. An answer that
fits is sent as before, pretty-printed and whole. The same answer is always cut the same way. The
`cve://{cve_id}` resource reads `get_cve`'s record whole and cuts its `data` as `get_cve`'s first
text block is cut, and says so: `data_truncated: true`, `truncated` naming each list it cut, and a
note starting `DATA CUT`. The prompts ask only for what the
text keeps: `kev_weekly_brief` reads `kev_recent` 50 rows a page, which the text holds whole;
`triage_cve` reads CISA's due date from `get_cve`; and `sbom_review` reads each match's `fixed_in`,
and `cve_intel`'s `fixed_branches` where the text keeps no match for a component.

## Structured results

Since 2.0.0 every result a tool answers, success or failure, carries `structuredContent`, and every tool
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
| `data_truncated` | On a success only: `true` when `data` is cut (`DATA CUT`, see "Long answers"), `false` when it is the answer whole. |
| `truncated` | When `data_truncated` is true: each list cut, by its path in `data`, with `total`, `returned` and, where its entries keep only some of their fields, `thinned: true`. |
| `data` | On a success only: the API's JSON, whole with `full: true`, and by default cut when the structured result would pass 30,000 characters (`DATA CUT`): the first text block carries the same JSON, or, past 30,000 characters, a cut of the whole answer that the note names (`TEXT CUT`). |
| `error` | On a failure only: `kind`, `path`, `status` and `message`. |

The last text block of every result is this structured result serialized as JSON, less what
an earlier text block already says verbatim, since a client may pass only `content` to the
model. It carries the same `state`, `measured_at`, `coverage` and `freshness` (on a success
`data_truncated` and `truncated`, and on a failure `error`), key for key. It leaves out `data`, which is a success's first text block, and the
note's sentences, which are the text block just before it (on a failure, the message) and
with which `notes` ends: its `notes` holds only the sentences the envelope adds about itself,
and is left out when there are none. It leaves out `method` too where that note quotes it verbatim, as
`cve_exposure`'s does ("Method: …"). So the text blocks together carry the structured result, but
for what a `TEXT CUT` leaves out of the answer (see "Long answers"), and cannot disagree with it;
beside a `DATA CUT`, the first text block is cut from the answer whole, not from the cut `data`.

| `state` | What it means |
|---|---|
| `measured` | A measurement of what was asked. An exposure count is `measured` only when the answer says when what it counts was observed (`measured_at`) and how it was produced (`method`). No exposure answer says when today, so neither exposure tool answers `measured`. |
| `not_assessed` | The answer holds no dated measurement of what was asked, so no count in it is presented as one: the radar does not look for this CVE, the answer does not say whether it does, or the answer does not say when what it counts was observed. It can still relay a count, as what the source holds on record, undated: `cve_exposure`'s `exposed_hosts` when its `exposure_state` is `exposed`, and `exposure_radar`'s labelled totals. The notes, and `exposure_state` where the result carries it, say what each count is. |
| `failed` | The lookup did not complete. Not a finding. |
| `invalid_input` | The input was refused, by this server or by the API, so nothing was looked up. Not a finding. |

What each tool's `state`, `measured_at`, `coverage` and `freshness` hold, tool by tool, is in
[docs/structured-results.md](https://github.com/echelongraph/echelongraph-mcp/blob/main/docs/structured-results.md).
Every field comes from what the API sends; where the API does not say, the field is `null` and a
note says so.

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

The first message of a connection picks its era, which it keeps. Both handshakes
carry the package's name and version (`serverInfo`), and every API request carries them in its
User-Agent, `echelongraph-mcp/<version>`.

Both handshakes also carry the server instructions: the data is public; that Shodan data is
Shodan's; what `state`, `measured_at` and `freshness` mean, and that each result carries them in
its structured result and again in its text; and that exposure numbers are aggregate counts of
ip:port services, not an internet-wide census.

The instructions and every tool description are at most 2,048 characters, the shortest cut a
client is known to make, so no client that cuts there loses a sentence. A description says what its tool
returns and the rules that keep a zero, a `false` or a failure from reading as a finding; what each
field counts, in full, is in the tool's `outputSchema`, and the result's note says it again for the
numbers it relays.

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
| A CVE ID (`get_cve`, `cve_exposure`, `epss_history`, `cve_intel`, `cve_remediation`, `vendor_advisories_for_cve`), a CWE ID and page (`get_cwe`), a vendor and advisory ID (`get_vendor_advisory`) | The URL path. |
| `search_cves`: `search` | The `X-EG-Search` request header, never the URL. Its severity, minimum CVSS, sort, limit and offset go in the query string. |
| `search_vendor_advisories`: `query` | The `X-EG-Advisory-Search` request header, never the URL. Its vendor, severity, CVE filter, limit and offset go in the query string. |
| `check_affected`: `product`, `version`, `ecosystem`, `package` | The `X-EG-Product`, `X-EG-Version`, `X-EG-Ecosystem` and `X-EG-Package` request headers, never the URL. |
| `cve_remediation`: `ecosystem`, `package`, `version` | The `X-EG-Ecosystem`, `X-EG-Package` and `X-EG-Version` request headers, never the URL. The CVE ID goes in the URL path. |
| `kev_recent`: `since`, `until`, `ransomware`, `vendor`, `limit`, `cursor` | The `X-EG-Since`, `X-EG-Until`, `X-EG-Ransomware`, `X-EG-Vendor`, `X-EG-Limit` and `X-EG-Cursor` request headers, never the URL. |
| `check_sbom`: `purls`, or an `sbom` document | The purls, in POST bodies of at most 200 each. A CycloneDX or SPDX document is read on your machine and only the purls in it are sent; the document is not. (Over the hosted endpoint the document goes to EchelonGraph's server instead: see below.) |
| `scan_manifest`: `files` | The purls read from the files, in POST bodies of at most 200 each; the filenames, the files' text and the entries not checked are not sent on to the API. Run from npm, the server that reads them is on your machine; over the hosted endpoint it is EchelonGraph's, and the files are the request body (see below). |
| `cve_summary`, `exposure_radar` | No input. |

The API marks its answers to header-carried lookups `no-store`, so no shared cache keeps them,
and request logs and trace spans that record URLs do not hold what was looked up there.

**The hosted endpoint.** A request to `https://mcp.echelongraph.io/mcp` reaches EchelonGraph's
server first, which then calls the same API as above. Per request it logs the HTTP method (GET,
HEAD, POST, PUT, PATCH, DELETE, OPTIONS, CONNECT or TRACE, else `(other)`) and path, the status,
the duration, its wait for a place (and for a large-body slot), the requests served at once, its
large-body slots held (and the oldest hold's age), the body size, the JSON-RPC method (one MCP
defines, else `(other)`) and the tool or prompt name, the protocol version, whether an `Origin`
header was sent, the first word of your client's User-Agent, whether your address is public (not
the address), whether your client closed early, and whether it was throttled or refused, and why.
When one of its API calls fails, it logs the tool and JSON-RPC method, the call's route without
the ID or query (`/api/v1/public/cves/:id`), what failed (such as a timeout, a reset or the status
the API answered), how long it took, and whether the request was our monitor's. An error it logs
by its type, a fixed cause label and its code, with its request's JSON-RPC method and protocol
version, never by its message. It never logs tool arguments or a query string. A `check_sbom` document (or
an `sbom_review` prompt's) is a tool argument like any other here: it is in the request body, so
the whole document reaches EchelonGraph's server, which reads the purls from it in memory, sends
only those to the API, and neither logs nor keeps the document. To keep the document on your
machine, run the npm package, or pass `check_sbom` the purls. `scan_manifest`'s files are the
same: their whole text is in the request body, read into purls in memory, and only those go to
the API; the files are neither logged nor kept. To keep lockfiles on your machine, run the npm package. Past
the per-client limit it logs that client's address key. It passes your client's public address to
the API, in a header the API trusts only with a token it checks, so the API's rate limit counts
you and not the hosted service. The API's access line then records each of those calls under
your address (an IPv6 address by its /64) with its URL path: for a CVE, CWE or advisory lookup,
the ID you asked about. It does not record the query string or the header-carried terms above
(for `search_cves`, whether a term was given and its length, not the term), and of `check_sbom`'s
and `scan_manifest`'s purls it records how many, not which.

EchelonGraph's privacy policy: <https://echelongraph.io/privacy>.

## Rate limits

No API key, so the API limits each caller, one IPv4 address or one IPv6 /64 network, counting
all its requests together in a 60-second window: 12,000 a minute to `/api/v1/public/cves` and the
paths under it, 6,000 to the CWE, vendor-advisory, KEV and shadow-AI paths, and 600 to any other
public path; `check_sbom`'s and `scan_manifest`'s batch route is charged per component, 1,200
components a minute. Over a limit the tool returns a failure (`state` `failed`, `error.status`
429), never empty data; `check_sbom` and `scan_manifest` wait out a 429's `Retry-After` within
50 seconds a call, and answer what they have, the rest counted in `coverage.not_sent`. The hosted
endpoint adds 120 MCP requests a minute per client address, and refuses a request body over 64 KiB
(6 MiB for a `check_sbom` or `scan_manifest` call, or an `sbom_review` prompt). Every limit, path
by path:
[docs/rate-limits.md](https://github.com/echelongraph/echelongraph-mcp/blob/main/docs/rate-limits.md).

## Configuration

The npm package (stdio):

| Env var | Default | Purpose |
|---|---|---|
| `ECHELONGRAPH_API_BASE` | `https://app.echelongraph.io` | Override the API base (self-host / proxy). A credential in the URL is masked wherever a result quotes the base. |
| `ECHELONGRAPH_API_TIMEOUT_MS` | `15000` | Per-request timeout. A slower answer is reported as a failed lookup, not as empty data. |
| `ECHELONGRAPH_MCP_UA` | unset | One product token (for example `my-monitor/1.0`) put ahead of this package's own User-Agent, so automated callers such as monitors are told apart from people using the server. A value that is not a single token is ignored. |

The HTTP entrypoint, `dist/http.js` (`npm run start:http`), serves the same tools over
Streamable HTTP on `POST /mcp`, with a liveness check on `GET /health`. In a small container, cap
V8's heap (docs/rate-limits.md says how). It reads the three variables above and:

| Env var | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | The port it listens on. |
| `MCP_RATE_LIMIT_PER_MIN` | `120` | MCP requests a minute per client address, per instance. |
| `MCP_MAX_BODY_BYTES` | `65536` | The largest request body it reads, except for an SBOM (below). |
| `MCP_MAX_SBOM_BODY_BYTES` | `6291456` | The largest body of a `tools/call` of `check_sbom` or `scan_manifest`, or a `prompts/get` of `sbom_review`. |
| `MCP_LARGE_BODY_SLOTS` | `2` | How many bodies over `MCP_MAX_BODY_BYTES` it reads and serves at once; past that, two more wait up to `MCP_LARGE_BODY_WAIT_MS` (15000) for one, then 503 with `Retry-After`. |
| `MCP_MAX_IN_FLIGHT` | `64` | How many requests it serves at once, not counting `subscriptions/listen` streams; the next, its body read, waits. |
| `MCP_ADMISSION_WAIT_MS` | `10000` | How long a request waits to be served before it is answered 503 with `Retry-After`. |
| `MCP_BODY_IDLE_MS`, `MCP_REQUEST_TIMEOUT_MS` | `10000`, `60000` | A body that sends nothing that long while it is read is answered 408; a request running that long in all is stopped (docs/rate-limits.md). |
| `MCP_H2C` | unset | `1`: serve HTTP/2 cleartext (h2c, prior knowledge) instead of HTTP/1.1, as Cloud Run's `--use-http2` requires; an HTTP/1.1 request then gets no answer. |
| `ECHELONGRAPH_FORWARD_TOKEN`, `ECHELONGRAPH_FORWARD_HOST`, `MCP_REQUIRE_FORWARD_TOKEN` | unset | EchelonGraph's hosted deployment only: the token with which it names each client to the API. Leave them unset when you run it yourself; the API then counts every request as coming from your server. |

## Develop

```bash
npm install
npm run build      # tsc → dist/
npm test           # build, then the behavioural suite over both protocol eras, against a stub API
npm run smoke      # spawn the server + call cve_exposure against the production API
```

`npm run smoke` calls the production API with this package's User-Agent: from any machine but
our workspace, it counts as MCP adoption unless you set `ECHELONGRAPH_MCP_UA` (see Configuration).
`npm test` never leaves the machine.

`npm test` runs over a 2026-07-28 `server/discover` and a 2025-06-18 `initialize`. To test an
installed package instead of `dist/`, set `ECHELONGRAPH_MCP_BIN` to its `echelongraph-mcp` bin.

## Versioning

Semantic versioning: a major version changes protocol behaviour or drops a Node.js version, a
minor version adds tools or fields, a patch fixes wording or behaviour without changing a tool's
shape. Every release is published to npm with a provenance attestation by the public repo's
release workflow, from the commit tagged `v<version>`. Changes per version:
[CHANGELOG.md](CHANGELOG.md).

Since 3.1.0, a success's `outputSchema` is open at every level: each object admits fields it does
not name, and each enum but `state` any string beside the values it lists; a `coverage` or
`freshness` a tool answers `null` admits an object too, so a field or value added in a minor
release does not fail a client holding a 3.1.0 or later tool list. The failure branch keeps
every object closed, and every enum but four, which already accept any string:
`coverage.not_assessed_reason` (check_affected), `coverage.vendor_windows[].history_backfill`
(vendor_advisories_for_cve, search_vendor_advisories) and `coverage.vendor_window.history_backfill`
(get_vendor_advisory). A client that listed the tools under 3.0.2 or older must reconnect once
(the CHANGELOG names the calls). A client showing "does not match the tool's output schema" holds
an older schema: reconnect it (Claude Code: `/mcp`, then reconnect `echelongraph`) or restart it.

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
