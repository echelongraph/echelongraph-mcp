# echelongraph-mcp: rate limits

Part of the README's [Rate limits](../README.md#rate-limits), in full: every limit the API and the
hosted endpoint apply, path by path, and what a tool answers past each. It is kept out of the README
because npm keeps only the first 65,536 characters of a package's README, and the package ships it
in `docs/`.

No API key, so the API limits each caller, one IPv4 address or one IPv6 /64 network as its
platform records it. Its WAF counts all your requests together in a 60-second window and
refuses one once the count passes the ceiling for its path:

| Path | Ceiling per minute | Tools |
|---|---|---|
| `/api/v1/public/cves` and every path under it | 12,000 | `cve_summary`, `search_cves`, `get_cve`, `epss_history`, `cve_intel`, `cve_remediation`, `check_affected`, `check_sbom`, `scan_manifest` |
| `/api/v1/public/cwes`, `/api/v1/public/vendor-advisories`, `/api/v1/public/kev/recent`, `/api/v1/public/shadow-ai-radar` | 6,000 | `get_cwe`, the three vendor-advisory tools, `kev_recent`, and one of `exposure_radar`'s five calls |
| any other `/api/v1/public` path | 600 | `cve_exposure`, and the rest of `exposure_radar`'s calls |

Because the count is shared, heavy use of one path also uses up the lower ceilings. On top of
that, 500 requests per second per caller is a burst cap on each serving instance, and
`check_sbom`'s and `scan_manifest`'s batch route is charged per component: 1,200 components a minute per caller.
Over a limit the API answers 429 with `Retry-After`, and the tool returns a failure
(`state` `failed`, `error.status` 429), never empty data. `check_sbom` and `scan_manifest` are the exception: each
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
64 KiB is refused (HTTP 413, code `-32600`), except a `tools/call` of `check_sbom` or
`scan_manifest`, or a `prompts/get` of `sbom_review`, which may be up to 6 MiB: enough for a
CycloneDX or SPDX document, or a call's lockfiles, at the tools' 5,000,000-character cap. Each server instance reads at most two such large bodies at
once; a third is answered HTTP 503 with `Retry-After` and a JSON-RPC error (code `-32030`). Each
instance serves at most 64 requests at once; the next waits up to 10 seconds for one to finish,
and is then answered the same way. A `subscriptions/listen` stream, which stays open until its
client leaves, is not one of the 64.

A call whose client goes away (its own timeout, a closed tab) is stopped only once the server
learns of it. Its API calls are then cancelled, `check_sbom` and `scan_manifest` send no further batch, and its
large-body slot is freed. Over HTTP/1.1, Cloud Run does not pass a client's disconnect on to the
server at all (<https://docs.cloud.google.com/run/docs/troubleshooting>). The hosted endpoint
speaks HTTP/2 to Cloud Run, where the same page says a disconnect is passed on. Measured on
2026-10-05, Cloud Run reset the stream of a client that stopped reading its answer 15 s in, and the
call was logged as a client that closed. Whether a client that aborts mid-call is passed on at once
has not been observed yet. Until it is, an abandoned `check_sbom` or `scan_manifest` call may run for up to its
50-second budget and hold its slot that long.
