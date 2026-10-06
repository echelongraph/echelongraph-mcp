// #2842: what a client that cuts MCP text at CLIENT_DESCRIPTION_CUT characters still hands the model.
// Claude Code cuts each tool description and the server instructions at 2,048 characters
// (src/requiredText.ts cites where), so the server holds every one of them to that length whole,
// and the sentences src/requiredText.ts names to the head of each.
//
// cutProblems reads what tools/list and the opening exchange serve, and names each way they break:
//   (a) the instructions are longer than the cut, or a REQUIRED_IN_INSTRUCTIONS sentence is not in them;
//   (b) a description is longer than the cut, or a REQUIRED_IN_HEAD sentence of its tool is not
//       within its first `cut` characters;
//   (c) a tool tools/list serves has no REQUIRED_IN_HEAD entry, or an entry names a tool it does not serve;
//   (d) the head of the instructions or of a description names Shodan without SHODAN_OWNERSHIP, or a
//       description in a tool's outputSchema does.
// Pure, so a test can hand it a changed copy and see it fail (the controls in tools.test.mjs).
import path from "node:path";
import { pathToFileURL } from "node:url";
import { PKG_DIR } from "./server-under-test.mjs";

export const REQUIRED = await import(pathToFileURL(path.join(PKG_DIR, "dist", "requiredText.js")).href);

function schemaDescriptions(s, at, out) {
  if (Array.isArray(s)) s.forEach((x, i) => schemaDescriptions(x, `${at}[${i}]`, out));
  else if (s !== null && typeof s === "object") {
    for (const [k, x] of Object.entries(s)) {
      if (k === "description" && typeof x === "string") out.push([at, x]);
      else schemaDescriptions(x, `${at}.${k}`, out);
    }
  }
  return out;
}

export function cutProblems({ instructions, tools }, r = REQUIRED) {
  const cut = r.CLIENT_DESCRIPTION_CUT;
  const own = r.SHODAN_OWNERSHIP;
  const found = [];
  const shodan = (where, text) => {
    if (/Shodan/.test(text) && !text.includes(own)) found.push(`(d) ${where} names Shodan without its ownership sentence`);
  };
  // (a)
  if (typeof instructions !== "string") found.push("(a) the server serves no instructions");
  else {
    if (instructions.length > cut) found.push(`(a) the instructions are ${instructions.length} characters; the cut is ${cut}`);
    const head = instructions.slice(0, cut);
    for (const s of r.REQUIRED_IN_INSTRUCTIONS) if (!head.includes(s)) found.push(`(a) the instructions' first ${cut} characters lack: ${s}`);
    shodan("the instructions' head", head);
  }
  // (b), (d)
  const served = new Set();
  for (const t of tools) {
    served.add(t.name);
    const d = t.description ?? "";
    if (d.length > cut) found.push(`(b) ${t.name}: its description is ${d.length} characters; the cut is ${cut}`);
    const head = d.slice(0, cut);
    for (const s of r.REQUIRED_IN_HEAD[t.name] ?? []) if (!head.includes(s)) found.push(`(b) ${t.name}: its description's first ${cut} characters lack: ${s}`);
    shodan(`${t.name}'s description head`, head);
    for (const [at, x] of schemaDescriptions(t.outputSchema, "outputSchema", [])) shodan(`${t.name} ${at}`, x);
    // (c)
    if (!Object.hasOwn(r.REQUIRED_IN_HEAD, t.name) || !r.REQUIRED_IN_HEAD[t.name].length) found.push(`(c) ${t.name}: no REQUIRED_IN_HEAD entry in src/requiredText.ts`);
  }
  for (const name of Object.keys(r.REQUIRED_IN_HEAD)) if (!served.has(name)) found.push(`(c) REQUIRED_IN_HEAD names ${name}, which tools/list does not serve`);
  return found;
}
