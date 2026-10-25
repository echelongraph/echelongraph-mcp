// #2923: mcp_handler_error carried only error_name, so 30 of them in 72h had no cause on record.
// The classifier must name a cause from a fixed vocabulary and never echo client input.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { PKG_DIR, readPkgFile } from "./server-under-test.mjs";

const P = await import(pathToFileURL(path.join(PKG_DIR, "dist", "httpPolicy.js")).href);

describe("#2923: mcp_handler_error is classified without the message", () => {
  const cases = [
    ["Not Acceptable: Client must accept both application/json and text/event-stream", "not_acceptable"],
    ["Unsupported Media Type: Content-Type must be application/json", "unsupported_media_type"],
    ["Method not allowed.", "method_not_allowed"],
    ["Invalid Request: Batch must not exceed 100 messages", "batch_too_large"],
    ["Invalid Request: Server already initialized", "already_initialized"],
    ["Parse error: Invalid JSON", "parse_error"],
    ["Received a response for an unknown request id: 7", "unknown_response_id"],
    ["Dropped inbound request 'tools/call': not servable on this connection's protocol era", "dropped_wrong_era"],
    ["Failed to send response: Error: socket hang up", "send_failed"],
  ];
  for (const [msg, cls] of cases) {
    it(`"${msg.slice(0, 40)}…" is ${cls}`, () => {
      assert.equal(P.classifyHandlerError(new Error(msg)).error_class, cls);
    });
  }
  // #2923's 2.7.1 audit: production's 78 lines were all "other". These are the bundled SDK's
  // createMcpHandler messages, read from its dist (@modelcontextprotocol/server/dist/index.mjs and
  // the chunk that defines its errors), each template filled the way the SDK fills it.
  const SDK = path.dirname(fileURLToPath(import.meta.resolve("@modelcontextprotocol/server")));
  const sdkText = fs.readdirSync(SDK).filter((f) => f.endsWith(".mjs")).map((f) => fs.readFileSync(path.join(SDK, f), "utf8")).join("\n");
  const sdkCases = [
    ["`Rejected inbound request (${stdHeaderRejection.cell}): ${stdHeaderRejection.message}`", "Rejected inbound request (headers): Mcp-Method header does not match the body's method", "rejected_inbound_request"],
    ["`Rejected inbound request (${outcome.cell}): ${outcome.message}`", "Rejected inbound request (era-classification): server/discover with protocol_version 1999-01-01", "rejected_inbound_request"],
    ["`Rejected 2025-era request on a modern-only endpoint (${strict.cell}): ${strict.message}`", "Rejected 2025-era request on a modern-only endpoint (legacy): initialize", "rejected_legacy_on_modern_only"],
    ["message = `Unsupported protocol version: ${data.requested}`", "Unsupported protocol version: 1999-01-01", "unsupported_protocol_version"],
    ["`Bad Request: Unsupported protocol version: ${protocolVersion}", "Bad Request: Unsupported protocol version: 1999-01-01 (supported versions: 2025-06-18)", "unsupported_protocol_version"],
    ["message = `Missing required client capabilities: ${", "Missing required client capabilities: sampling", "missing_client_capability"],
  ];
  for (const [template, msg, cls] of sdkCases) {
    it(`the SDK's ${JSON.stringify(template.slice(0, 48))}… is ${cls}`, () => {
      assert.ok(sdkText.includes(template), `the bundled SDK no longer has ${template}`);
      assert.equal(P.classifyHandlerError(new Error(msg)).error_class, cls);
    });
  }
  it("an UnsupportedProtocolVersionError (-32022), as createMcpHandler reports it, keeps its code and is classified", () => {
    const e = Object.assign(new Error("Unsupported protocol version: unknown"), { name: "ProtocolError", code: -32022 });
    assert.deepEqual(P.classifyHandlerError(e), { error_name: "ProtocolError", error_class: "unsupported_protocol_version", error_code: -32022 });
  });
  // #2923, 2026-10-18: a live read since 3.0.2 found one line with error_class "other" and error_code -32022. Each path
  // in the bundled SDK that raises -32022 (httpPolicy.ts lists them), and any error that carries the code, whatever its
  // message (a peer's -32022 response, rebuilt by ProtocolError.fromError, keeps the peer's own), is classified.
  it("every -32022 the SDK raises is unsupported_protocol_version, whatever its message: other with -32022 cannot occur", async () => {
    const { UnsupportedProtocolVersionError, ProtocolError } = await import("@modelcontextprotocol/server");
    const errors = [
      // createMcpHandler serveModern: an unsupported or missing modern revision (index.mjs).
      new UnsupportedProtocolVersionError({ supported: ["2026-07-28"], requested: "1999-01-01" }),
      new UnsupportedProtocolVersionError({ supported: ["2026-07-28"], requested: "unknown" }),
      // modernOnlyStrictRejection, an envelope-less request that names no version.
      new ProtocolError(-32022, "Unsupported protocol version: the request did not name a protocol version", { supported: ["2026-07-28"] }),
      // ProtocolError.fromError: a peer's -32022 error response, with the peer's own message, or none.
      ProtocolError.fromError(-32022, "version 2026-07-28 is not supported by this client", { supported: ["2025-06-18"], requested: "2026-07-28" }),
      ProtocolError.fromError(-32022, "", undefined),
      // Anything else that carries the code: an Error, or a thrown plain object.
      Object.assign(new Error("anything at all"), { code: -32022 }),
      { code: -32022, message: "a thrown object" },
    ];
    for (const e of errors) {
      const out = P.classifyHandlerError(e);
      assert.deepEqual([out.error_class, out.error_code], ["unsupported_protocol_version", -32022], `${e?.message}: ${JSON.stringify(out)}`);
    }
  });
  it("an error whose message no prefix knows is classified by its JSON-RPC code where the code names a cause", () => {
    for (const [code, cls] of [
      [-32021, "missing_client_capability"],
      [-32020, "header_mismatch"],
      [-32700, "parse_error"],
      [-32600, "invalid_request"],
      [-32601, "method_not_found"],
      [-32602, "invalid_params"],
    ]) assert.deepEqual(P.classifyHandlerError(Object.assign(new Error("something new"), { code })), { error_name: "Error", error_class: cls, error_code: code });
    // A code that names no cause, and a message no prefix knows, is still other.
    assert.deepEqual(P.classifyHandlerError(Object.assign(new Error("something new"), { code: -32000 })), { error_name: "Error", error_class: "other", error_code: -32000 });
  });
  it("an unrecognised message is other, and no field holds any of the message", () => {
    const secret = "CVE-2099-0001 pkg:npm/secret-internal@1.0.0";
    const out = P.classifyHandlerError(new Error(`something new: ${secret}`));
    assert.deepEqual(out, { error_name: "Error", error_class: "other" });
    assert.ok(!JSON.stringify(out).includes("secret"));
  });
  it("a ProtocolError keeps its numeric code, and only a number", () => {
    const e = Object.assign(new Error("Invalid Request: whatever the client sent"), { name: "ProtocolError", code: -32600 });
    assert.deepEqual(P.classifyHandlerError(e), { error_name: "ProtocolError", error_class: "invalid_request", error_code: -32600 });
    const s = Object.assign(new Error("x"), { code: "-32600 pkg:npm/leak" });
    assert.equal("error_code" in P.classifyHandlerError(s), false);
  });
  it("a non-Error throw is classified without being stringified", () => {
    assert.deepEqual(P.classifyHandlerError("raw client text"), { error_name: "string", error_class: "other" });
  });
  // dist, not src: the packed tarball ships no src/ (the 2.7.0 publish refused on exactly that).
  it("the served http.js logs the classification, never e.message", () => {
    const src = readPkgFile("dist/http.js");
    // #2923: with the request's fixed labels from its scope (runtime.ts requestLabels), never its params.
    assert.match(src, /log\("WARNING", "mcp_handler_error", \{\s*error_name: e\.name,\s*error_class: handlerErrorClass\(e\),\s*error_code: protocolErrorCode\(e\),\s*rpc_method: labels\.rpcMethod,\s*protocol_version: labels\.protocolVersion,?\s*\}\)/);
    assert.match(src, /const labels = requestLabels\(\);/);
    assert.doesNotMatch(src, /mcp_handler_error[^\n]*e\.message/);
  });
});
