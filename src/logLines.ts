// Every line the hosted endpoint (http.ts) writes to stdout, and exactly the keys each carries besides `severity`
// and `message` (#2863). /privacy Section 11 and the README's "Privacy: what is sent where" say what the hosted
// endpoint logs, and through 2.7 only a marketing-site test (privacyMcpEndpoint.test.ts) held http.ts to them: a
// client address and the whole User-Agent added to mcp_request passed this package's tests, its npm publish and
// the mcp-remote deploy.
//
// This list is the one place a line or a key is added:
//   * http.ts's log() is typed against it, so a log call whose message is not here, or whose fields are not
//     exactly its keys, does not compile (npm test builds first);
//   * test/http.test.mjs requires every stdout line its servers write to carry exactly these keys, every line
//     here to be written by them (or to be one of the two it names that no request can make), no other writer of
//     stdout or stderr under dist/, and the README to name every key of the access line.
// A key added here is a change to what EchelonGraph logs about a request: say it in /privacy Section 11 and in the
// README first (marketing-site/lib/privacyMcpEndpoint.test.ts's ACCESS_FIELDS / OTHER_LINES review the same calls).
//
// `optional` keys may be absent from a line: tool and prompt come only with tools/call and prompts/get (BodyFacts),
// and a handler error's error_code only when the error carries a JSON-RPC code (JSON.stringify drops undefined).
export const LOG_LINES = {
  // The access line: one per request (http.ts finish()).
  mcp_request: {
    keys: [
      // The HTTP method, one of httpPolicy.ts HTTP_METHODS (GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, CONNECT,
      // TRACE), else "(other)": over h2c the client's own :method token, never logged (3.1.0's final review).
      "method",
      "path",
      "status",
      "duration_ms",
      // A method MCP defines for a client (httpPolicy.ts MCP_METHODS), else "(other)"; "(none)", "(unparseable)",
      // "(batch)" or "(response)" for a body with no one method. Never the client's own string (#2923's review).
      "rpc_method",
      "protocol_version",
      "origin_present",
      "body_bytes",
      "throttled",
      "refused",
      "ua_family",
      "client_public",
      "client_closed",
      "in_flight",
      "queued_ms",
      // #2775: how long a large body waited for a large-body slot (0 when it found one free, or needed none).
      "slot_wait_ms",
    ],
    optional: ["tool", "prompt"],
  },
  // Start-up, before any request.
  mcp_remote_refusing_to_start: { keys: ["reason"] },
  mcp_remote_heap_unbounded: { keys: ["heap_limit_mb", "memory_limit_mb", "reason"] },
  mcp_remote_listening: {
    keys: [
      "port",
      "protocol",
      "name",
      "version",
      "api_base",
      "api_timeout_ms",
      "forward_token_configured",
      "rate_limit_per_min",
      "max_body_bytes",
      "max_sbom_body_bytes",
      "large_body_slots",
      "large_body_wait_ms",
      "max_in_flight",
      "admission_wait_ms",
      "heap_limit_mb",
      "memory_limit_mb",
    ],
  },
  // #2923: a fixed-vocabulary class and a ProtocolError's numeric code; never the SDK's message. And the request it
  // arose in, by its fixed labels (runtime.ts requestLabels): its JSON-RPC method (httpPolicy.ts MCP_METHODS, else
  // "(other)"), its protocol version.
  mcp_handler_error: { keys: ["error_name", "error_class", "rpc_method", "protocol_version"], optional: ["error_code"] },
  mcp_request_failed: { keys: ["error_name"] },
  mcp_large_body_busy: { keys: ["slots"] },
  mcp_busy: { keys: ["max_in_flight", "waiting"] },
  // The one line that names a client: its rate-limit key (an IPv4 address, or an IPv6 /64), which the README and
  // /privacy Section 11 both say.
  mcp_rate_limited: { keys: ["client", "limit"] },
  // #2775: when the server learned its client went, whether the answer had started, an h2 stream's reset code (one
  // RFC 9113 defines, else "(other)": httpPolicy.ts rstCodeLabel; null over HTTP/1.1).
  mcp_client_gone: { keys: ["after_ms", "answer_started", "rst_code"] },
  // #2948: one per failed API call: the class, the API route as a template (never the path or query), the status,
  // how long the call took, the request's shape-checked tool and its JSON-RPC method (MCP_METHODS or "(other)"), and
  // whether it was the synthetic's.
  mcp_upstream_failed: { keys: ["tool", "rpc_method", "route", "failure_class", "status", "after_ms", "synthetic"] },
} as const satisfies Record<string, { keys: readonly string[]; optional?: readonly string[] }>;

type Lines = typeof LOG_LINES;
export type LogMessage = keyof Lines;
type OptionalKeys<M extends LogMessage> = Lines[M] extends { optional: readonly (infer K extends string)[] } ? K : never;
/** The fields a line's log() call passes: every key, each optional one allowed. */
export type LogFields<M extends LogMessage> = { [K in Lines[M]["keys"][number]]: unknown } & { [K in OptionalKeys<M>]?: unknown };
/** never for `any` (#2863's review: a spread of an any value, `{ ...JSON.parse(x) }`, made the whole object any, which
 *  every key check passes), unknown otherwise: log()'s fields are refused when they are any. */
export type NotAny<T> = 0 extends 1 & T ? never : unknown;
