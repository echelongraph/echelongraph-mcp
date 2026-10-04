// E2E against the PUBLISHED npm package — spawns `npx -y echelongraph-mcp` exactly like a
// user's Claude Desktop / Cursor would, connects as an MCP client, lists tools, and calls
// cve_exposure against the production API. Proves the published artifact works end to end.
// Its requests carry the package's User-Agent. From our workspace they are our own traffic
// (first_party=true, first_party_by=egress: its egress address is on core-backend's
// firstPartyEgress) and in no adoption panel. From any other machine they count as external MCP
// adoption unless ECHELONGRAPH_MCP_UA names the run (#2760).
// It opens with a 2025-06-18 initialize, the handshake every published version answers (1.x is
// legacy-only; 2.x serves both eras).
import { connect } from "./mcp-stdio-client.mjs";

const client = await connect({
  era: "2025-06-18",
  command: "npx",
  args: ["-y", "echelongraph-mcp"],
  env: process.env,
  clientInfo: { name: "smoke-published", version: "1.0.0" },
});

const { tools } = await client.listTools();
console.log("PUBLISHED tools:", tools.map((t) => t.name).join(", "));
if (tools.length < 5) { console.error(`FAIL: expected >=5 tools, got ${tools.length}`); process.exit(1); }

const res = await client.callTool({ name: "cve_exposure", arguments: { cve_id: "CVE-2023-44487" } });
const txt = res.content?.[0]?.text || "";
const parsed = JSON.parse(txt);
console.log(`cve_exposure(CVE-2023-44487): exposed_hosts=${parsed.exposed_hosts}, countries=${parsed.countries}`);
if (typeof parsed.exposed_hosts !== "number") { console.error("FAIL: no exposed_hosts"); process.exit(1); }
console.log("OK: published package works end to end via npx");
await client.close();
process.exit(0);
