// Smoke test: spawn the built MCP server, list its tools, and call the cve_exposure tool
// against the PRODUCTION EchelonGraph API. Run after `npm run build`: `npm run smoke`.
// Its requests carry this package's User-Agent, so they are counted as external MCP adoption.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const transport = new StdioClientTransport({ command: "node", args: ["dist/index.js"] });
const client = new Client({ name: "echelongraph-mcp-smoke", version: "1.0.0" });
await client.connect(transport);

const { tools } = await client.listTools();
console.log("TOOLS:", tools.map((t) => t.name).join(", "));
if (tools.length < 5) {
  console.error(`FAIL: expected >=5 tools, got ${tools.length}`);
  process.exit(1);
}

const res = await client.callTool({ name: "cve_exposure", arguments: { cve_id: "CVE-2023-44487" } });
const txt = res.content?.[0]?.text || "";
console.log("cve_exposure(CVE-2023-44487):", txt.replace(/\s+/g, " ").slice(0, 200));
let parsed;
try {
  parsed = JSON.parse(txt);
} catch {
  console.error("FAIL: cve_exposure did not return JSON");
  process.exit(1);
}
if (typeof parsed.exposed_hosts !== "number") {
  console.error("FAIL: cve_exposure missing exposed_hosts");
  process.exit(1);
}
console.log(`OK: exposed_hosts=${parsed.exposed_hosts}, countries=${parsed.countries}`);
await client.close();
process.exit(0);
