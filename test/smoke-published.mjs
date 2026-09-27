// E2E against the PUBLISHED npm package — spawns `npx -y echelongraph-mcp` exactly like a
// user's Claude Desktop / Cursor would, connects as an MCP client, lists tools, and calls
// cve_exposure against the production API. Proves the published artifact works end to end.
// Its requests carry the package's User-Agent, so they are counted as external MCP adoption.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const transport = new StdioClientTransport({ command: "npx", args: ["-y", "echelongraph-mcp"] });
const client = new Client({ name: "smoke-published", version: "1.0.0" });
await client.connect(transport);

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
