// check_affected.test.mjs over the 2025-era opening: an initialize with protocolVersion
// 2025-06-18 (#2311). node --test runs each file in its own process, so check_affected.test.mjs
// itself still runs over the 2026-07-28 opening.
globalThis.MCP_TEST_ERA = "2025-06-18";
await import("./check_affected.test.mjs");
