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
CycloneDX or SPDX document, or a call's lockfiles, at the tools' 5,000,000-character cap. Each server
instance reads at most two such large bodies at once; a third waits up to 15 seconds for one to
finish (two may wait at once), and is answered HTTP 503 with `Retry-After` and a JSON-RPC error
(code `-32030`) only when that wait runs out, or at once when two are already waiting. Each
instance serves at most 64 requests at once; the next waits up to 10 seconds for one to finish,
and is then answered the same way. A `subscriptions/listen` stream is not one of the 64: the
server sends no list-change notification, so since 3.1.1 the stream ends right after its
acknowledgement, with a `complete` result (through 3.1.0 it stayed open until its client left).

What parsing a request may hold is bounded too (#3381). Every body, at any size, is read once
before it is parsed, and what parsing it would hold in the instance's memory is estimated from what
it holds: its objects and arrays, list entries and object members, keys, and string bytes. A body
estimated past what one request's parse may take is refused (HTTP 413, code `-32600`), unparsed,
with an error that gives its counts, its estimate and the bound; every real CycloneDX or SPDX
document measured up to 6 MiB is within it. Each body's estimate is then held in one budget for the
instance until its request has stopped (past its deadline, until it has unwound). A body that fits
is let in ahead of one that waits and does not, until that one has waited a second; from then on a
body above the general 64 KiB cap is let in only if the room the waiter needs is left beside it, so
the waiter is let in once the large requests before it end. A body within the cap is let in whatever
waits, and so are its tool's reservations of the document it reads and of the API's answers for up to
200 purls (one batch), while all of those together hold no more than a quarter of the budget; a call
of more purls reserves its answers as a large body does, and waits behind such a waiter, up to the
same 10 seconds. The answers to such a small call's batch can take that quarter past full while the
call answers; a small body or reservation then waits as a large one does, but for a tiny body (at
most 64 KiB of estimate: a `tools/list`, `initialize` or `ping`), which has a lane of its own, open
whatever the quarter holds, of 4 MiB in all; a tool's reservations, however small, do not take it. A JSON-RPC batch is one request: its calls'
reservations are made one after another, each counting what the request holds as it is then, and
once one of them finds no room within the wait the batch's later calls wait no more: each is taken
where it fits at once, and answered "server busy" where it does not. A body that finds no room waits up to 10 seconds, as for a place, and is then answered
HTTP 503 with `Retry-After` and code `-32030`, so two of the largest real documents sent at once
may be parsed one after the other. What `check_sbom` parses from an `sbom` passed as text, and
`scan_manifest` from its lockfiles, is held in the same budget from before it is parsed until it
has been read, and then what the answer keeps of it; and so is what the API's answers to the purls
of a `check_sbom` or `scan_manifest` call hold, from before its first batch is sent (1,280 bytes a
purl, and what the answers hold past that as they come: three bytes a byte of an answer for each
row's first 512 bytes, ten for the rest, its matches) until the call ends. A tool's reservation
takes its request's place among those that wait: one that came after the request began never holds
it up. A call whose reservation finds no room within the wait is answered `failed`, `error.status`
503, "server busy", which is not a finding: the same call can be answered once the instance has
room. One whose reservation, with what its request already holds, would pass three quarters of the
budget (the most a waiter is sure to be let in at, beside the small bodies' quarter: 31,457,280
bytes, 30 MiB, on the hosted endpoint, what one request may reserve before it reads, its body and
what its tools read together) is refused `invalid_input` at once, naming the bound: retrying it
will not help. The API's answers past what was reserved for them are charged as they come, so one
batch's answer can take a request past that bound, within what the instance has room for; the call
then sends no further batch (below). Measured on 38 real
lockfiles of large public repositories (24 `package-lock.json`, 8 `Cargo.lock` and 6 `poetry.lock`,
67 KB to 1.8 MB), each was read, the costliest at 0.40 of that bound. Of files of their shape copied
to larger sizes, a `poetry.lock` past about 3 MB is refused, where 3.1.5 answered one of 2,000
packages or fewer; a `Cargo.lock` or `package-lock.json` that large usually already holds more than the
2,000 distinct purls a call checks, which 3.1.5 refused too (one whose entries repeat a package at
many install paths need not). A call of a line format can be refused within its 40,000-line bound as
well: 40,000 lines near the 5,000,000-character cap pass it where the text holds one character past
U+00FF (the body is then two bytes a character in memory), and not in ASCII. A lockfile can be
checked by passing its purls to `check_sbom`, in calls of 2,000 or fewer, a line format by passing
its lines over more calls, and either by the server run locally (`npx -y echelongraph-mcp`), whose
bounds are a share of its own machine's memory; the refusal says which. Once the
instance's parse budget, which holds the API's answers beside its requests' bodies and documents, is
more than a quarter past its bound, whichever calls took it there, or a call's own request holds more
than what one request may reserve, the call sends no further batch; and a batch's answer is read only
to what the call's reservation still covers of it and what the budget has left when it is sent (at
the weights above), so one larger is read no further and dropped. That bound is each call's own:
calls reading at once each read up to what the budget had left, so their reads together can pass it
(#3603). Each way the purls not sent are listed with `not_sent_reason` `server_busy`, not checked
and not clean; where it is the call's first batch, the call is answered `failed`, "server busy",
with the batch route as `error.path` and the API's 200 as `error.status`. Both bounds are a share of
the memory the instance's deployment gives it. A server run locally (stdio) holds only a document it
parses from text to the same share of its own heap, usually larger, so that bound is proportionally
larger ([structured-results.md](structured-results.md)); it estimates no message before parsing it,
has no in-flight budget, and reads the API's answers whole.

A call whose client goes away (its own timeout, a closed tab) is stopped only once the server
learns of it. Its API calls are then cancelled, `check_sbom` and `scan_manifest` send no further batch, and its
large-body slot is freed. Over HTTP/1.1, Cloud Run does not pass a client's disconnect on to the
server at all (<https://docs.cloud.google.com/run/docs/troubleshooting>). The hosted endpoint
speaks HTTP/2 to Cloud Run, where the same page says a disconnect is passed on. Measured on
2026-10-05, Cloud Run reset the stream of a client that stopped reading its answer 15 s in, and the
call was logged as a client that closed. Whether a client that aborts mid-call is passed on at once
has not been observed yet: on 2026-10-18 two calls aborted 1.5 s in ran on to their answers. So an
abandoned `check_sbom` or `scan_manifest` call may run for up to its 50-second budget and hold its
slot that long, and a retry of it waits for that slot (above) instead of being refused at once.

Two bounds end a request whatever its client does. Through 3.1.1 there were none, and on
2026-10-25 one abandoned `check_sbom` call never ended and held its slot for the life of the
instance. Whether its body had stopped coming with no reset (above: whether Cloud Run passes on an
abort mid-upload, and when, is not known) or its reset arrived and the call ran on is not settled;
each bound ends one of the two. A request body that sends nothing for 10 seconds while it is read
(not while it waits for a slot) is ended, answered HTTP 408 with a JSON-RPC error (code `-32600`),
and its slot is freed. And no request runs past 60 seconds, Cloud Run's own request timeout: it is
then stopped as a client that went is, what it holds is freed, and it is logged once, `refused`
`timeout`. Its status there is 499, its client logged as gone, if it had already gone; else, if its
answer had not ended, 504, a status for the log only: no answer is sent, and its stream (over
HTTP/2) or its connection (over HTTP/1.1) is reset; else the status it was answered with, its
answer left as it was. A server you run yourself reads them from `MCP_BODY_IDLE_MS` (`10000`) and
`MCP_REQUEST_TIMEOUT_MS` (`60000`).

To run the hosted entrypoint yourself in a small container, cap V8's heap below its limit, as
EchelonGraph's hosted deployment does in 256 MiB
(`node --max-old-space-size=104 --max-semi-space-size=16 dist/http.js`): Node can otherwise size
its heap from the host's memory, and the container is killed before V8 collects, with every
request on it.
