// The whole behavioural suite of tools.test.mjs, over the 2025-era opening: an initialize with
// protocolVersion 2025-06-18, the handshake 1.x clients send (#2311). node --test runs each file
// in its own process, so tools.test.mjs itself still runs over the 2026-07-28 opening.
globalThis.MCP_TEST_ERA = "2025-06-18";
await import("./tools.test.mjs");
