// #3496: get_cve relays JVN iPedia's records of a CVE (authority_records), the products they state
// (stated_affected) and a JVNDB id among its aliases, as core-backend serves them while EchelonGraph
// displays JVN iPedia's data. IPA's text is IPA's: the outputSchema says each record carries its own
// attribution, is in English and is not translated, and states THE GATE word for word
// (JVN_IPEDIA_NOTE in src/index.ts, which is core-backend apacadv.JVNGateStatement: round 9 of
// #3787), and the alias description names the JVNDB id's attribution. A record whose description the
// templates withheld arrives with description_withheld and a derived summary, and relays whole like
// any other.
//
// Both polarities: a record carrying the fields relays them whole, attribution included, in
// structuredContent and content[0]; a record from an API older than the fields validates without
// them. CONTROL: a schema whose description lost the note is caught by the same check.
//
// Runs against dist/index.js, so build first — `npm test` does.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { StrictOutputValidator } from "./strict-output.mjs";
import { connect, MODERN } from "./mcp-stdio-client.mjs";
import { serverCommand } from "./server-under-test.mjs";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const MCP_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

const ERAS = [MODERN, "2025-06-18"];
const ATTRIBUTION = "Source: JVN iPedia (IPA)";
// THE GATE, word for word: core-backend/internal/cve/apacadv/jvn_licence.go JVNGateStatement. No
// text here may say more than the code does (round 6 of #3787).
const THE_GATE =
  "IPA's title, and each sentence or list line of IPA's description, is shown only when it matches, in full, one of a closed list of templates written from IPA's own records: fixed wording, with slots that hold only the record's own product and vendor names as its CPE product data states them, a version, a CVE, CWE or JVN identifier, a number, or one entry of a closed list of weakness and impact phrases (or MITRE's name for one of the record's CWE ids). Every other word of IPA's text is left out, and nothing is cut from a sentence or a title to make it match. A description that lost any of IPA's text ends “[sentences omitted]”; when nothing of it matches, or none of its sentences that say what is vulnerable does, EchelonGraph shows a summary, and in place of a title a title, derived from the record's structured fields, with a link to IPA's text. The structured fields are shown only inside closed grammars (the CVSS version, severity, type, vector and score; the CPE name and its version), and a value outside them is not shown. IPA's product data (each product's vendor and product names and every part of its CPE name) is shown only when it passes one closed check, which a value fails when it holds a character outside ASCII (a no-break or other non-ASCII space included) or a control character other than white space (tab, line feed, carriage return, vertical tab, form feed are collapsed), an at-sign (“@”, “%40”, “(at)”, “[at]” and other written forms, or “at” followed by “dot”), an address or a host name (a scheme such as “https:”, “mailto:” or “skype:”, a double slash, “www.”, a dot written in brackets such as “[.]” or “(dot)”, or as “-dot-” or “_dot_” in lower case or capitals, an IP address outside a CPE name's version and update, or a host on a public suffix or a special-use top-level name, wherever it stands and whether its dots are written plainly, in any of those spellings, as “ dot ” or “ DOT ”, or with a space beside them (an abbreviation's full stop such as “Co. ” is no host's dot before a capitalised word when the abbreviation stands at the value's start or after a space, “(”, an ampersand, “,”, a quote or “/”, and no dot joins it to the word before it); a vendor's name may be a domain alone whose name is its CPE vendor name, or that CPE vendor name followed by organisation words such as “Foundation”), an e-mail address or a telephone number in a shape the rule reads, or a credit cue on a closed list (“reported by”, “thanks to”, “h/t” and others), or, for a part of a CPE name, anything outside the CPE 2.2 grammar. A name that fails is replaced by its CPE name's part, a CPE name with a part that fails is not shown, a record with a vendor or a product no name of which passes is not shown at all, and products shown otherwise than IPA published them are labelled so. The record's CPE vendor and CPE product names are shown as IPA's structured product data names them when they pass that check, even where one is a person's name, and a name read from IPA's free text is never shown. A reference is shown as its address only, and only when it is an authority's address on a closed list (cve.org, nvd.nist.gov, jvn.jp, ipa.go.jp and others) in one of that authority's fixed forms, whose only free part is an identifier, a number or a word of the record's own product data; every other address is left out. This was measured on IPA's feeds with every person's name replaced by an invented one, and on four of IPA's year feeds held out of the build (counts only).";
// The pinned note, word for word: what the description must say of JVN iPedia's records.
const NOTE =
  "JVN iPedia (IPA) records carry their own attribution, Source: JVN iPedia (IPA), and are shown in IPA's English, not translated. " +
  THE_GATE +
  " A withheld description is absent and summary carries the derived text (description_withheld true), and a served description of which no main statement is served (only list lines, CVE lines or auxiliary sentences) carries the summary beside it; a withheld title is the derived one (title_withheld). description_excerpted and title_excerpted say whether the field differs from IPA's in any way.";
const ALIAS_SENTENCE = "and a JVNDB id Source: JVN iPedia (IPA); no other id does.";
// The claims rounds 4 to 6's reviews refuted (#3787): core-backend's refutedPhrasings, for the MCP
// server's texts. None may return to a tool's schema or docs/tools.md. Round 6's own statement was
// refuted by its reviews, and its note "credits omitted" is gone with the rule that wrote it.
const REFUTED = [
  "in a form IPA uses to state a vulnerability",
  "dictionary or technical word",
  "can be shown inside such a sentence",
  "a name that is itself an ordinary English word",
  "credits omitted",
  "or the record's own vendor's",
  "mask version 5",
  "as excerpts: EchelonGraph omits",
  "as an excerpt: EchelonGraph omits",
  "Any name left in a served field is masked",
  "any name left in a served field is masked",
  "a name masked",
  "Sentences that credit a person are dropped first",
  "lost a sentence or a line",
  "mask version 3",
  "mask version 4",
  // Round 8's reviews (the decisions recorded on #3496 on 2026-11-15, round 9).
  "or only its list lines do",
  "a product name that carries a credit, a handle or an address is replaced by the CPE name's product component",
  "of which no statement is served (only list lines)",
  "mask version 7",
  // Round 9's reviews (the decisions recorded on #3496 on 2026-11-15, round 10): the vendor's domain inside its
  // name, "via" as a product-data cue, the version the rule no longer is.
  "a vendor's name may hold a domain whose name is its CPE vendor name",
  "“thanks to”, “via” and others",
  "mask version 8",
  // Round 10's reviews (the decisions recorded on #3496 on 2026-11-15, round 11): the control-character sentence,
  // the IP address only outside a CPE name's version, the version the rule no longer is.
  "or a control character, an at-sign",
  "an IP address outside a CPE name's version, or",
  "mask version 9",
  // Round 11's reviews (the decisions recorded on #3496 on 2026-11-15, round 12): the abbreviation clause
  // without its condition, the version the rule no longer is.
  "such as “Co. ” is no host's dot)",
  "mask version 10",
  // Round 12's correctness review (the decisions recorded on #3496, round 13): the abbreviation clause without
  // the abbreviation's own condition, the version the rule no longer is.
  "is no host's dot before a capitalised word)",
  "mask version 11",
];
/** The refuted claims text states: [] when none. */
const refutedIn = (text) => REFUTED.filter((r) => text.includes(r));
// L8 (licence review F9): resolved_from names jvn_ipedia and its attribution; get_cve's cve_id lists a JVNDB id
// as accepted while EchelonGraph displays JVN iPedia's data.
const RESOLVED_SENTENCE = "with source jvn_ipedia, Source: JVN iPedia (IPA).";
const ARG_SENTENCE = "A JVN iPedia ID (JVNDB-2026-000172) is accepted only while EchelonGraph displays JVN iPedia's data.";

const record = (id, extra = {}) => ({
  cve_id: id,
  description: "test record",
  severity: "HIGH",
  cvss_v3_score: 8.8,
  echelongraph_score: 8.1,
  echelongraph_severity: "HIGH",
  score_assessed: true,
  kev_listed: false,
  published: "2026-09-01T00:00:00Z",
  modified: "2026-09-02T00:00:00Z",
  updated_at: "2026-09-03T00:00:00Z",
  references: [],
  cpe_match: [],
  ...extra,
});
// The shape core-backend's apacadv jvn_read.go serves (AuthorityRecord, StatedAffected); the values
// are illustrative, not a claim about any CVE.
const JVN = {
  aliases: [{ id: "JVNDB-2099-000001", namespace: "jvndb", source: "jvn_ipedia", first_seen_at: "2099-01-02T03:04:05Z", attribution: ATTRIBUTION }],
  authority_records: [
    {
      authority: "jvn_ipedia",
      authority_name: "JVN iPedia (IPA)",
      id: "JVNDB-2099-000001",
      url: "https://jvndb.jvn.jp/en/contents/2099/JVNDB-2099-000001.html",
      title: "Acme Widget vulnerable to OS command injection",
      description: "Acme Widget contains an OS command injection vulnerability.\n[sentences omitted]",
      description_excerpted: true,
      title_excerpted: false,
      language: "en",
      translated: false,
      issued_at: "2099-01-02T03:04:05Z",
      modified_at: "2099-01-02T03:04:05Z",
      cvss: [{ version: "3.0", score: "8.8", severity: "High" }],
      products: [{ vendor: "Acme", product: "Acme Widget", version: "1.0 to 1.4" }],
      references: [],
      cve_count: 1,
      first_seen_at: "2099-01-02T03:04:05Z",
      provenance: { agency: "JVN iPedia (IPA)", surface_url: "https://jvndb.jvn.jp/en/rss/jvndb_new.rdf", fields: {} },
      attribution: ATTRIBUTION,
    },
  ],
  stated_affected: [
    {
      provenance_class: "stated_by_jvn_ipedia",
      stated_by: "JVN iPedia (IPA)",
      source: "jvn_ipedia",
      source_record_id: "JVNDB-2099-000001",
      source_record_url: "https://jvndb.jvn.jp/en/contents/2099/JVNDB-2099-000001.html",
      product: { identity_kind: "vendor_product", vendor: "Acme", product: "Acme Widget" },
      range_state: "unparsed",
      range_text: "1.0 to 1.4",
      rendered: "Acme Widget 1.0 to 1.4 (as JVN iPedia states it)",
      echelongraph_assertion: false,
      attribution: ATTRIBUTION,
    },
  ],
};

// A record whose description and title the gate withheld: no description, a derived summary and a
// derived title, with the flags that say so (core-backend apacadv jvn_read.go).
const JVN_WITHHELD = {
  authority_records: [
    {
      ...JVN.authority_records[0],
      id: "JVNDB-2099-000003",
      url: "https://jvndb.jvn.jp/en/contents/2099/JVNDB-2099-000003.html",
      title: "OS Command Injection in Acme Widget",
      description: undefined,
      summary:
        "From JVN iPedia's record: OS Command Injection in Acme Widget (Acme); CVSS v3.0 8.8; see IPA's description at https://jvndb.jvn.jp/en/contents/2099/JVNDB-2099-000003.html.",
      description_excerpted: true,
      title_excerpted: true,
      description_withheld: true,
      title_withheld: true,
      provenance: {
        agency: "JVN iPedia (IPA)",
        surface_url: "https://jvndb.jvn.jp/en/rss/jvndb_new.rdf",
        fields: { summary: "derived_from_agency_record", title: "derived_from_agency_record" },
      },
    },
  ],
};

// A JVNDB id resolved through JVN iPedia's mapping (resolved_from source jvn_ipedia), one resolved
// through ENISA's, and one through GitHub's, whose note carries no attribution (the control).
const resolved = (cve, id, namespace, source, attribution) =>
  record(cve, { resolved_from: { id, namespace, source, ...(attribution ? { attribution } : {}) } });
const ANSWERS = {
  "/api/v1/public/cves/CVE-2099-30001": record("CVE-2099-30001", JVN),
  "/api/v1/public/cves/CVE-2099-30002": record("CVE-2099-30002"), // an API older than the fields
  "/api/v1/public/cves/CVE-2099-30003": record("CVE-2099-30003", JVN_WITHHELD), // the gate withheld IPA's text
  "/api/v1/public/cves/JVNDB-2099-000001": resolved("CVE-2099-30001", "JVNDB-2099-000001", "jvndb", "jvn_ipedia", ATTRIBUTION),
  // An API that sends no attribution field: the note carries IPA's credit all the same.
  "/api/v1/public/cves/JVNDB-2099-000002": resolved("CVE-2099-30001", "JVNDB-2099-000002", "jvndb", "jvn_ipedia"),
  "/api/v1/public/cves/EUVD-2099-0001": resolved("CVE-2099-30001", "EUVD-2099-0001", "euvd", "enisa_euvd", "Source: ENISA EUVD"),
  "/api/v1/public/cves/GHSA-aaaa-bbbb-cccc": resolved("CVE-2099-30001", "GHSA-aaaa-bbbb-cccc", "ghsa", "github"),
};

let stub;
before(async () => {
  stub = http.createServer((req, res) => {
    const a = ANSWERS[req.url];
    res.writeHead(a ? 200 : 404, { "content-type": "application/json" });
    res.end(JSON.stringify(a ?? { error: "not found" }));
  });
  await new Promise((resolve) => stub.listen(0, "127.0.0.1", resolve));
});
after(() => new Promise((resolve) => stub.close(resolve)));

const validator = new StrictOutputValidator();
const textBlocks = (res) => (res.content ?? []).filter((c) => c.type === "text").map((c) => c.text);

/** The properties of the CVE record within an outputSchema: the first object schema naming cve_id and kev_listed. */
function recordProps(s) {
  if (s === null || typeof s !== "object") return undefined;
  if (s.properties && "cve_id" in s.properties && "kev_listed" in s.properties) return s.properties;
  for (const v of Array.isArray(s) ? s : Object.values(s)) {
    const found = recordProps(v);
    if (found) return found;
  }
  return undefined;
}

/** What an outputSchema's CVE record fails to say of JVN iPedia's data: [] when it says all of it. */
function missingJVNText(outputSchema) {
  const props = recordProps(outputSchema) ?? {};
  const missing = [];
  if (!props.authority_records?.description?.includes(NOTE)) missing.push("authority_records: the note");
  if (!props.stated_affected?.description?.includes("never matched against an inventory and not EchelonGraph's finding")) missing.push("stated_affected: not EchelonGraph's finding");
  if (!props.aliases?.description?.includes(ALIAS_SENTENCE)) missing.push("aliases: the JVNDB attribution");
  if (!props.resolved_from?.description?.includes(RESOLVED_SENTENCE) || !props.resolved_from?.description?.includes("jvn_ipedia through EchelonGraph's alias table"))
    missing.push("resolved_from: jvn_ipedia and its attribution");
  return missing;
}

for (const era of ERAS) {
  describe(`#3496 get_cve relays JVN iPedia's records with IPA's attribution [${era}]`, () => {
    let client;
    let getCve;
    before(async () => {
      client = await connect({
        era,
        ...serverCommand(),
        env: { ...process.env, ECHELONGRAPH_API_BASE: `http://127.0.0.1:${stub.address().port}`, ECHELONGRAPH_API_TIMEOUT_MS: "2000" },
        stderr: "ignore",
      });
      const { tools } = await client.listTools();
      getCve = tools.find((t) => t.name === "get_cve");
    });
    after(() => client?.close());
    const call = (cve_id) => client.callTool({ name: "get_cve", arguments: { cve_id } });
    const valid = (res) => {
      const v = validator.getValidator(getCve.outputSchema)(res.structuredContent);
      assert.ok(v.valid, v.errorMessage);
    };

    it("the outputSchema says JVN iPedia's records carry their own attribution and are shown as published, in English, not translated", () => {
      assert.deepEqual(missingJVNText(getCve.outputSchema), []);
    });

    it("get_cve's cve_id lists a JVNDB id as accepted while EchelonGraph displays JVN iPedia's data", () => {
      assert.ok(getCve.inputSchema.properties.cve_id.description.includes(ARG_SENTENCE), getCve.inputSchema.properties.cve_id.description);
    });

    it("control: a schema whose descriptions lost the note, the statement's rule or the alias sentence is caught", () => {
      for (const [k, cut] of [["authority_records", NOTE], ["stated_affected", "never matched"], ["aliases", ALIAS_SENTENCE], ["resolved_from", RESOLVED_SENTENCE]]) {
        const edited = structuredClone(getCve.outputSchema);
        const p = recordProps(edited)[k];
        p.description = p.description.replace(cut, "");
        assert.notDeepEqual(missingJVNText(edited), [], `${k} without its sentence passes`);
      }
    });

    it("a record with JVN iPedia's data: relayed whole, attribution on every value, in structuredContent and content[0]", async () => {
      const res = await call("CVE-2099-30001");
      assert.notEqual(res.isError, true, JSON.stringify(res.content));
      valid(res);
      const data = res.structuredContent.data;
      assert.deepEqual(data.authority_records, JVN.authority_records);
      assert.deepEqual(data.stated_affected, JVN.stated_affected);
      assert.deepEqual(data.aliases, JVN.aliases);
      const first = textBlocks(res)[0];
      // content[0] is the record as JSON text: the excerpt's line break is written escaped there.
      const desc = JVN.authority_records[0].description;
      assert.ok(first.includes(desc) || first.includes(JSON.stringify(desc).slice(1, -1)), "content[0] lost IPA's description");
      assert.equal(first.split(ATTRIBUTION).length - 1, 3, "content[0] does not carry the attribution on the record, the statement and the alias");
    });

    it("a JVNDB id resolved through JVN iPedia's mapping: the note says so and ends with IPA's credit, attribution field or none", async () => {
      for (const id of ["JVNDB-2099-000001", "JVNDB-2099-000002"]) {
        const res = await call(id);
        assert.notEqual(res.isError, true, JSON.stringify(res.content));
        const text = textBlocks(res).join("\n");
        assert.ok(text.includes(`Resolved ${id} (jvndb) to CVE-2099-30001 through EchelonGraph's alias table (source jvn_ipedia). Source: JVN iPedia (IPA).`), text);
      }
    });

    it("control: an EUVD id's note ends with ENISA's credit, a GHSA id's with none", async () => {
      const euvd = textBlocks(await call("EUVD-2099-0001")).join("\n");
      assert.ok(euvd.includes("(source enisa_euvd). Source: ENISA EUVD.") && !euvd.includes(ATTRIBUTION), euvd);
      const ghsa = textBlocks(await call("GHSA-aaaa-bbbb-cccc")).join("\n");
      assert.ok(ghsa.includes("(source github).") && !ghsa.includes("(source github). Source:"), ghsa);
    });

    it("#3787 round 5: the outputSchema states the gate word for word, and no longer says IPA's text is served as an excerpt", () => {
      const props = recordProps(getCve.outputSchema) ?? {};
      const d = props.authority_records?.description ?? "";
      assert.ok(d.includes(THE_GATE), `the authority_records description does not state the gate: ${d}`);
      for (const gone of ["as excerpts: EchelonGraph omits", "mask version 3"]) {
        assert.ok(!d.includes(gone), `the description still states "${gone}"`);
      }
      // The fields the gate's answer arrives in are named by the description
      // AND declared somewhere in the array's item schema (its exact shape
      // depends on how the optional array is encoded for the era).
      const itemSchema = JSON.stringify(props.authority_records ?? {});
      for (const want of ["summary", "description_withheld", "title_withheld"]) {
        assert.ok(d.includes(want), `the description does not name ${want}`);
        assert.ok(itemSchema.includes(`"${want}"`), `the schema has no ${want} property`);
      }
      // CONTROL: with the gate sentence cut, the check fails.
      assert.ok(!d.replace(THE_GATE, "").includes(THE_GATE));
    });

    it("#3787 round 6: no tool text and no page of docs/ states a claim the reviews refuted", () => {
      const texts = [["get_cve outputSchema", JSON.stringify(getCve.outputSchema)], ["docs/tools.md", readFileSync(join(MCP_ROOT, "docs", "tools.md"), "utf8")]];
      for (const [where, text] of texts) assert.deepEqual(refutedIn(text), [], `${where} states a refuted claim`);
      // CONTROL: each refuted claim, planted, is found.
      for (const r of REFUTED) assert.notDeepEqual(refutedIn(`A text. ${r} More.`), [], `the refuted "${r}" planted is not found`);
    });

    it("#3787 round 5: a record whose text the gate withheld relays whole — no description, the derived summary, the flags", async () => {
      const res = await call("CVE-2099-30003");
      assert.notEqual(res.isError, true, JSON.stringify(res.content));
      valid(res);
      const rec = res.structuredContent.data.authority_records[0];
      assert.equal(rec.description, undefined, "a withheld description was relayed");
      assert.equal(rec.description_withheld, true);
      assert.equal(rec.title_withheld, true);
      assert.ok(rec.summary.startsWith("From JVN iPedia's record:"), rec.summary);
      assert.ok(rec.summary.includes("see IPA's description at https://jvndb.jvn.jp/"), rec.summary);
      const first = textBlocks(res)[0];
      assert.ok(first.includes(rec.summary) || first.includes(JSON.stringify(rec.summary).slice(1, -1)), "content[0] lost the derived summary");
      assert.ok(first.includes(ATTRIBUTION), "content[0] lost IPA's attribution");
    });

    it("control: a record from an API older than the fields validates and carries none of them", async () => {
      const res = await call("CVE-2099-30002");
      assert.notEqual(res.isError, true, JSON.stringify(res.content));
      valid(res);
      const data = res.structuredContent.data;
      assert.equal(data.authority_records, undefined);
      assert.equal(data.stated_affected, undefined);
      assert.ok(!textBlocks(res).join("\n").includes(ATTRIBUTION));
    });
  });
}
