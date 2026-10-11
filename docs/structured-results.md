# echelongraph-mcp: the structured result, tool by tool

Part of the README's [Structured results](../README.md#structured-results), which says what each
envelope field and `state` means: here, tool by tool, what each one's `state`, `measured_at`,
`coverage` and `freshness` hold. It is kept out of the README because npm keeps only the first
65,536 characters of a package's README, and the package ships it in `docs/`. Exposure counts are
derived from Shodan data. Shodan data is owned by Shodan, which holds its copyright (© Shodan).

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
  is `exposed`, `measured_zero`, `not_assessed` or `tracking_unknown`, the cases of [How
  `cve_exposure` counts](tools.md#how-cve_exposure-counts), and `coverage.in_scope` is the API's `tracked`. It becomes `measured`
  only when the API serves a time at which the counted services were observed.
- `exposure_radar` is `not_assessed` with `measured_at` `null`: every radar answered, but no
  answer gives one time at which what it counts was observed, so no count is presented as a
  dated measurement. `mcp_servers` dates its verdicts only by a window, `mcp_servers.window.from`
  to `mcp_servers.window.to`, over checks made at different times, which is not one observation
  time; so, since #2438, do `exposed_databases.window`, `leaked_credentials.window` and
  `shadow_ai.confirmed_exposed.window`, and `kev_exposure.window`, from Shodan's banner
  timestamps, where the API serves it. Its numbers keep the labels [exposure-radar.md](exposure-radar.md) gives them. `freshness` holds each radar's `last_run_at` where the
  API serves one, for `shadow_ai` also `running`, and for `mcp_servers` also `enabled`.
- `check_affected` is `measured` only when the answer says `assessed` true, and `not_assessed`
  when it says false or does not say. Its `measured_at` and `freshness` are `null`: a match answer
  carries no observation time. Its `coverage` gives `assessed` and `not_assessed_reason` first,
  then `lookup` (`cpe` or `registry`), `match_layer`, `count`, `capped`, `candidates_capped`,
  `excluded_count`, `undetermined_count`, `not_affected_count` and `degraded`.

The CVE feed tools' `freshness` is `null`: the feed's answers carry no time at which its
pollers last completed a poll for the feed as a whole.
