// Which server the tests spawn, and which package's files they read.
//
// By default: this package's own dist/index.js, run with the current Node, and the files beside
// it. That is also what runs when the suite is copied into an unpacked tarball (the
// published-tarball checks): test/.. is then the unpacked package.
//
// With ECHELONGRAPH_MCP_BIN set to an installed bin (for example
// <project>/node_modules/.bin/echelongraph-mcp after `npm install <tarball>`), the tests execute
// that bin directly, the way `npx echelongraph-mcp` does, and read package.json, README.md and
// server.json from the package the bin belongs to.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const BIN = process.env.ECHELONGRAPH_MCP_BIN || undefined;
export const PKG_DIR = BIN
  ? path.resolve(path.dirname(fs.realpathSync(BIN)), "..")
  : path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
export const DIST = path.join(PKG_DIR, "dist", "index.js");
export const serverCommand = () => (BIN ? { command: BIN, args: [] } : { command: process.execPath, args: [DIST] });
export const readPkgFile = (name) => fs.readFileSync(path.join(PKG_DIR, name), "utf8");
export const PKG = JSON.parse(readPkgFile("package.json"));
