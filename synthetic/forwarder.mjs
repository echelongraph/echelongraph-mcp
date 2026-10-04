// A loopback forwarder that makes the synthetic's API requests identifiable (#2724).
//
// The synthetic must never count as MCP adoption. core-backend files a request under the
// user-agent's LEADING token (api.uaFamily), and the published package sends
// "echelongraph-mcp/<version> (+https://echelongraph.io/pulse/mcp)", the family the adoption
// metric counts. From the release after 2.3.4 the package puts ECHELONGRAPH_MCP_UA ahead of
// that; every version before it ignores the variable. So the runner points the package's
// ECHELONGRAPH_API_BASE at this forwarder, which sends each request on to the real API with
// the synthetic's token in front of whatever user-agent the package sent:
//
//   echelongraph-mcp-synthetic/1.0 echelongraph-mcp/2.3.4 (+https://echelongraph.io/pulse/mcp)
//
// A request that already leads with the token (a package that honours ECHELONGRAPH_MCP_UA) is
// passed as it came, and counted as identified, so the run summary says which mechanism did it.
//
// Everything else is relayed as is: method, path and query, the X-EG-* headers that carry typed
// values (#1983), the body, the status and the answer. Nothing is logged per request, and no
// header or body value is ever logged.
import http from "node:http";

// Hop-by-hop headers, and the ones fetch sets itself.
const DROP_REQUEST = new Set(["host", "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "te", "trailer", "content-length", "accept-encoding"]);
// fetch has already decoded the body, so its encoding and length no longer describe it.
const DROP_RESPONSE = new Set(["connection", "keep-alive", "transfer-encoding", "content-encoding", "content-length"]);

// The family core-backend reads: the user-agent up to the first '/' or space.
export const uaFamilyOf = (ua) => String(ua ?? "").split(/[ /]/, 1)[0];

// The user-agent the API is sent: the token, then the package's own.
export function identify(ua, token) {
  const family = uaFamilyOf(token);
  if (ua && uaFamilyOf(ua).toLowerCase() === family.toLowerCase()) return { ua, identified: true };
  return { ua: ua ? `${token} ${ua}` : token, identified: false };
}

export async function startForwarder({ upstream, token, timeoutMs = 60_000 }) {
  const base = upstream.replace(/\/+$/, "");
  const stats = { requests: 0, identified: 0, rewritten: 0, upstream_errors: 0 };
  const server = http.createServer(async (req, res) => {
    stats.requests++;
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const headers = {};
    for (const [k, v] of Object.entries(req.headers)) {
      if (!DROP_REQUEST.has(k) && k !== "user-agent" && v !== undefined) headers[k] = Array.isArray(v) ? v.join(", ") : v;
    }
    const who = identify(req.headers["user-agent"], token);
    headers["user-agent"] = who.ua;
    if (who.identified) stats.identified++;
    else stats.rewritten++;
    try {
      const up = await fetch(`${base}${req.url}`, {
        method: req.method,
        headers,
        body: chunks.length && req.method !== "GET" && req.method !== "HEAD" ? Buffer.concat(chunks) : undefined,
        redirect: "manual",
        signal: AbortSignal.timeout(timeoutMs),
      });
      const body = Buffer.from(await up.arrayBuffer());
      const out = {};
      up.headers.forEach((v, k) => {
        if (!DROP_RESPONSE.has(k)) out[k] = v;
      });
      out["content-length"] = String(body.length);
      res.writeHead(up.status, out);
      res.end(body);
    } catch (e) {
      // The package reports a 502 as a failed lookup, which is what an unreachable API is.
      stats.upstream_errors++;
      res.writeHead(502, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: `synthetic forwarder: upstream unreachable (${e?.name ?? "error"})` }));
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    base: `http://127.0.0.1:${server.address().port}`,
    stats,
    close: () => {
      server.closeAllConnections();
      return new Promise((resolve) => server.close(resolve));
    },
  };
}
