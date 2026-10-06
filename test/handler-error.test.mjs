// #2923: mcp_handler_error carried only error_name, so 30 of them in 72h had no cause on record.
// The classifier must name a cause from a fixed vocabulary and never echo client input.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { pathToFileURL } from "node:url";
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
