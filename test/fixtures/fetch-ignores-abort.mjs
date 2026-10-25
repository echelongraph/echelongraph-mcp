// #3362 (test/http.test.mjs): preloaded into dist/http.js, so that an API call does not stop when its request's signal
// aborts. That is the call MCP_REQUEST_TIMEOUT_MS is the backstop for: its client went (mcp_client_gone) and it ran on.
// Every call such a server makes is to its test's stub API, which answers only when the test lets it.
const fetchWithSignal = globalThis.fetch;
globalThis.fetch = (input, init) => fetchWithSignal(input, init === undefined ? undefined : { ...init, signal: undefined });
