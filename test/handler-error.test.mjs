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
    assert.match(src, /log\("WARNING", "mcp_handler_error", \{ error_name: e\.name, error_class: handlerErrorClass\(e\), error_code: protocolErrorCode\(e\) \}\)/);
    assert.doesNotMatch(src, /mcp_handler_error[^\n]*e\.message/);
  });
});
