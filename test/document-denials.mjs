// The one list of wordings that deny a check_sbom document is sent (#2795, #2796), shared by the
// two guards that keep such a sentence off a surface offering the hosted endpoint, over which the
// whole document is the request body:
//   * readme.test.mjs, beside this file: every string of check_sbom's tools/list entry, which is
//     served to every agent (its description, and each description of its input and output
//     schemas), the README's privacy section, and the README Tools table's check_sbom row;
//   * marketing-site/lib/mcpToolClaims.test.ts: /pulse/mcp's check_sbom row, while the page's
//     REMOTE_SERVING switch is true. It imports this file at run time.
// It lives here because the public repo and the npm tarball carry no marketing-site. As first
// written each guard kept its own list, and the README's caught three of the page's fifteen
// variants (#2796's review): "The server never sends the document.", "The document is processed
// locally.", "Only the purls are sent." and "The document, once parsed, is never sent." all passed
// it. The page's in turn read only document, SBOM and file as the document, so "The dependency
// list is never sent.", in the row's own noun, passed it (#2795's review).
//
// What stays allowed, because it is true on both transports: a purls-only clause that names the
// API as where the purls go ("only they are sent to the API"), and "the document is not sent on"
// (on to the API), which is check_sbom's own description. Each guard pins its fine cases.

// Every noun check_sbom's description, its sbom argument and the page's row use for the input:
// document, SBOM (or BOM), file, dependency list, JSON text, CycloneDX JSON or SPDX JSON, input;
// and scan_manifest's (#2835): lockfile (lock file), manifest, file contents.
export const DOC = String.raw`(?:documents?|s?boms?|files?|lock ?files?|manifests?|file contents|dependency lists?|json texts?|(?:cyclonedx|spdx) json|inputs?)`;
// A negation, "isn't" and "doesn't" among them (no word boundary inside the contraction).
export const NEG = String.raw`(?:\bnever\b|\bnot\b|n[’']t\b|\bno longer\b|\bwithout\b)`;
// Words between the noun and its negation, within a clause: "The document, once parsed, is never
// sent", "The SBOM, no matter what it holds, is never sent".
const GAP = (n) => String.raw`[^.;!?]{0,${n}}?`;
// A negation that is not the purls' or the components' own: the description says "from which
// position of the input the purls not sent run". Nor a "what was"'s, whose clause has its own
// subject: the description says "coverage (what the input held, what was sent …, and what was not
// sent and why)". As first written GAP refused any "what" between the noun and the negation, and
// "The SBOM, no matter what it holds, is never sent." passed (#2796's third review).
const NOT_THEIRS = String.raw`(?<!\b(?:purls|components|batches|ones)\s)(?<!\bwhat\s+(?:was|were|is|are)\s)`;
export const TO_THE_API = String.raw`(?!\s+(?:on\s+)?to\s+(?:the\s+)?(?:EchelonGraph(?:['’]s)?\s+)?API\b)`;
// "sent on" or "sent onward", or "sent on to the API", with the clause ending right there: what the
// MCP server does not pass on, true on both transports ("the document itself is not sent on"). Not
// when the clause goes on: "not sent on to the API or anywhere else" and "not sent on, nor to
// anyone" passed while a comma, or anything after "the API", still counted (#2796's third review).
const NOT_ONWARD = String.raw`(?!\s+on(?:wards?)?(?:\s+to\s+(?:the\s+)?(?:EchelonGraph(?:['’]s)?\s+)?API)?\s*(?:[.;!?)]|$))`;
// "only the purls", "just those purls", "only the extracted purls", "nothing but the purls", "the
// purls in it alone", "the purls, and only the purls," …
export const PURLS_ONLY = String.raw`(?:\b(?:only|just|nothing but|nothing except|nothing other than|no more than)\s+(?:(?:the|those|these)\s+)?(?:\w+\s+)?(?:purls|package urls)|\b(?:the\s+)?purls\s+alone)(?:\s+(?:in|from)\s+(?:it|them|the\s+\w+))?(?:\s+alone)?,?`;
// "make(s) it" only before "to", which it leaves for TO_THE_API to read: "Only the purls make it to
// the API" is true on both transports, "… make it to EchelonGraph" is not (#2831).
// "received" and "seen" are the same denial from the recipient's side: "Only purls are received by the
// API" (#2856).
const SENT = String.raw`(?:sent|transmitted|uploaded|posted|shared|received|seen|travel(?:s|led)?|go(?:es)?|leaves?|reach(?:es)?|mak(?:es|e) it(?=\s+to\b))\b`;

export const DENIALS = [
  // "never the document", "not the document", "neither the document nor …"
  new RegExp(String.raw`\b(?:never|not|nor|neither)\s+(?:the |your |its |this |that |whole |full |entire |raw |complete )*${DOC}\b`, "i"),
  // "the document (itself) is not / is never / never … sent, leaves, reaches, is uploaded …"
  new RegExp(
    String.raw`\b${DOC}\b${GAP(80)}${NOT_THEIRS}${NEG}[^.;!?]{0,30}?\b(?:sent|send|leaves?|left|leaving|uploaded|upload|transmitted|transmit|posted|shared|forwarded|forward|reach(?:es)?|goes|go|mak(?:es|e) it to|seen|touch(?:es|ed)?|received|arriv(?:es|ed|e)|exposed to|accessed)\b${NOT_ONWARD}`,
    "i",
  ),
  // "…; the document is not." — the clause ends on its negation, the verb left out
  new RegExp(String.raw`\b${DOC}\b${GAP(40)}(?:\b(?:is|are|was|does|do|will)\s+(?:not|never)|\bnever\s+(?:is|does)|\b(?:isn|aren|wasn|doesn|don|won)[’']t)\s*(?:[.;!?,)—–]|$)`, "i"),
  // "the document stays on your machine", "remains within your network", "stays inside your
  // environment", "is kept local", "is processed locally", "parsed client-side", "handled
  // on-device", "read on your machine", "processed offline", "on the client", "on-premises", "on
  // your own infrastructure" (the last six and "within"/"inside": #2796's third review)
  new RegExp(
    String.raw`\b${DOC}\b${GAP(60)}(?:\b(?:stays|stay|remains|remain|is kept|kept)\b[^.;!?]{0,20}?(?:\b(?:on|in|within|inside)\s+(?:your|the)\s+\w+|\blocal\b|\bwith you\b)|\blocally\b|\bclient[- ]side\b|\bon[- ]device\b|\b(?:read|parsed|processed|handled|checked|scanned)\b[^.;!?]{0,20}?(?:\boffline\b|\bon the client\b|\bon-prem\w*|\bon your (?:own )?\w+))`,
    "i",
  ),
  // "never sends the document", "does not upload the SBOM", "without uploading the file"
  new RegExp(String.raw`${NEG}[^.;!?]{0,30}?\b(?:send(?:s|ing)?|upload(?:s|ing)?|transmit(?:s|ting)?|post(?:s|ing)?|shar(?:e|es|ing)|forward(?:s|ing)?)\b[^.;!?]{0,20}?\b${DOC}\b`, "i"),
  // "EchelonGraph never sees the document", "never touches your SBOM" (#2831). Not "stores": the
  // hosted server neither logs nor keeps the document (the README's privacy section), so a denial
  // that it is stored can be true, and is no denial that it is sent.
  new RegExp(String.raw`${NEG}[^.;!?]{0,30}?\b(?:see|sees|seeing|seen|saw|touch(?:es|ed|ing)?)\b[^.;!?]{0,20}?\b${DOC}\b`, "i"),
  // The recipient as the subject (#2856): "EchelonGraph never receives the document", "We don't get
  // your SBOM", "Our servers never get the file", "EchelonGraph never has access to the document".
  // The hosted endpoint receives the whole document as the request body, so each is false beside
  // it. "receive" and "get" were never in the lists above, which name the sender's verbs.
  new RegExp(String.raw`${NEG}[^.;!?]{0,30}?\b(?:receiv(?:e|es|ed|ing)|get|gets|getting|got|(?:has|have|had|gets?|getting)\s+access\s+to|access(?:es|ed|ing)?)\b[^.;!?]{0,20}?\b${DOC}\b`, "i"),
  // "The server receives only the purls", "EchelonGraph sees only the purls", "gets just the
  // purls": the purls-only denial from the recipient's side (#2856)
  new RegExp(String.raw`\b(?:receiv(?:e|es|ed|ing)|gets?|getting|got|sees?|seeing|saw)\s+${PURLS_ONLY}`, "i"),
  // "no document is sent", "no part of the document leaves", "none of the document leaves"
  new RegExp(
    String.raw`\b(?:no|none of)\s+(?:(?:part|copy|portion|byte|bytes) of\s+)?(?:the |your |its |this )*${DOC}\b[^.;!?]{0,40}?\b(?:sent|send|leaves?|uploaded|posted|reach(?:es)?|transmitted|goes|go)\b`,
    "i",
  ),
  // "Only the purls are sent" with no destination, or a destination other than the API
  new RegExp(String.raw`${PURLS_ONLY}\s+(?:(?:are|is|get|gets|ever)\s+)*${SENT}${TO_THE_API}`, "i"),
  // "Nothing else is sent", "no other data is sent", "The purls are all that is sent": the same
  // purls-only denial with the purls named earlier in the text, or not at all (#2831)
  new RegExp(String.raw`(?:\bnothing else|\bno other(?:\s+(?:data|content|information|bytes?))?|\ball that)\s+(?:(?:is|are|gets?|ever)\s+)*${SENT}${TO_THE_API}`, "i"),
  // "The purls are read from it and only they are sent", "… and they alone leave your machine":
  // the purls named earlier in the clause, the same denial in a pronoun
  new RegExp(String.raw`\bpurls\b[^.;!?]{0,120}?(?:\b(?:only|just)\s+(?:they|them|those)|\b(?:they|those)\s+alone)\s+(?:(?:are|is|get|ever)\s+)*${SENT}${TO_THE_API}`, "i"),
  // With no subject: "it never leaves your machine", "it never leaves the premises", "never reaches
  // EchelonGraph", "is not sent to EchelonGraph" (EchelonGraph's API aside: the document never goes
  // there on either transport). Any noun after "leaves your" or "leaves the", not only a machine's:
  // "It never leaves your environment." passed (#2796's third review).
  new RegExp(String.raw`${NEG}[^.;!?]{0,20}?\b(?:leaves?|leaving|left)\s+(?:your|the|this|my)\s+(?:own\s+)?\w+`, "i"),
  new RegExp(
    String.raw`${NEG}[^.;!?]{0,20}?\b(?:reach(?:es)?|go(?:es)? to|mak(?:es|e) it to|(?:be\s+|been\s+)?(?:sent|uploaded|transmitted|posted|shared|forwarded) to)\s+EchelonGraph\b(?!['’]s\s+API\b)`,
    "i",
  ),
];

// The clauses of a text that deny the document is sent: split at ".", ";", "!" or "?" before
// whitespace, so a host name (mcp.echelongraph.io) does not split one.
export const documentDenials = (text) => text.split(/(?<=[.;!?])\s+/).filter((c) => DENIALS.some((re) => re.test(c)));

// Wordings each guard must catch, run by both: the page's (#2747, #2795 and its review), the
// README's (#2796 and its review), and those #2795's and #2796's second reviews named.
export const DENIAL_VARIANTS = [
  // #2747, #2795
  "Only the purls are sent, never the document.",
  "Only the purls are sent and never in a URL.",
  "Only the purls are sent; the document itself is not sent.",
  "Only the purls are sent to the API; the document itself is not sent.",
  "Only the purls are sent to the API, and the document never leaves your machine.",
  "The document is never sent.",
  "Your SBOM is not uploaded anywhere.",
  "The document isn't sent to EchelonGraph.",
  "The server never sends the document.",
  "It checks the SBOM without uploading the document.",
  "No part of the document leaves your machine.",
  "The document stays on your machine.",
  "Only purls go to EchelonGraph.",
  "Only the purls leave your machine.",
  "Only the purls are sent to the API, not the document.",
  "The purls are sent to the API; the document is not.",
  "Only the purls in it are sent to the API; the document isn't.",
  "None of the document leaves your machine.",
  "Your CycloneDX or SPDX file is never uploaded.",
  "The file itself is not sent.",
  "The document is processed locally.",
  "The SBOM is parsed client-side.",
  "Nothing but the purls is sent.",
  "Just the purls are sent.",
  "Purls alone are sent to EchelonGraph.",
  // #2796
  "The purls are read from the document by this MCP server; the document itself is never sent and never leaves your machine.",
  "A `check_sbom` document never reaches EchelonGraph.",
  "The document never leaves the machine.",
  "Over the hosted endpoint the document does not reach EchelonGraph.",
  "A `check_sbom` document is not sent to EchelonGraph.",
  "The purls are read from it and the document is not uploaded.",
  "The SBOM itself isn't sent.",
  "No part of the document leaves your machine.",
  // #2796's second review: words between noun and verb, an active verb, "without", where the
  // document is kept or processed, purls-only, and a pronoun for the document
  "The document, once its purls are read, is never sent.",
  "The SBOM you pass is, by design, not uploaded.",
  "This MCP server does not upload the SBOM.",
  "EchelonGraph never sends the document anywhere.",
  "The server does not forward the file.",
  "It checks your dependencies without sending the file.",
  "The document is handled on-device.",
  "The SBOM is processed on your machine.",
  "The document remains on your laptop.",
  "Your SBOM stays on your own computer.",
  "Only the purls are sent.",
  "Only the purls are uploaded, to EchelonGraph.",
  "The SBOM is parsed in memory; it never leaves your machine.",
  "It is never sent to EchelonGraph.",
  // #2795's second review: every noun check_sbom uses for its input, and the purls as "they"
  "The dependency list is never sent.",
  "Your dependency list stays on your machine.",
  "Your JSON text is not uploaded.",
  "The CycloneDX JSON never leaves your machine.",
  "The SPDX JSON is processed locally.",
  "The input is never sent.",
  "Your input, the whole of it, stays local.",
  "The purls are read from the document and only they are sent.",
  "The purls are read from the document, and only them are sent.",
  "The purls are read here and they alone leave your machine.",
  // #2796's third review: the sbom argument's own former words, "sent on" with the clause going
  // on, a "what" between the noun and its negation, where the document stays or is processed, a
  // subject-less "never leaves" of any noun, and purls-only in more words
  "a CycloneDX JSON or SPDX JSON document, as JSON text or as an object; its purls are read here and only they are sent",
  "The document is not sent on to the API or anywhere else.",
  "The document is not sent on, nor to anyone.",
  "The document is not sent onward, not even to EchelonGraph.",
  "The SBOM, no matter what it holds, is never sent.",
  "The document, and what is in it, never leaves your machine.",
  "Your input, whatever you put in it and what it names, is not uploaded.",
  "The SBOM remains within your network.",
  "The document stays inside your environment.",
  "Your SBOM stays in your workspace.",
  "It never leaves your environment.",
  "It never leaves the premises.",
  "The SBOM is processed offline.",
  "The document is processed on the client.",
  "The SBOM is processed on-premises.",
  "The document is processed on your own infrastructure.",
  "Only the extracted purls are sent.",
  "Just those purls are sent.",
  "Only these purls leave your machine.",
  "The purls, and only the purls, are sent.",
  "The purls, and only the purls, leave your machine.",
  // #2831: one-word edits of the sbom argument's removed sentence, and verbs outside "sent"
  "its purls are read here; nothing else is sent",
  "Nothing else is sent.",
  "The purls are all that is sent.",
  "EchelonGraph never sees the document.",
  "The document never touches our servers.",
  "The document is never POSTed.",
  "The document never makes it to EchelonGraph.",
  "No other data is sent.",
  "The purls are all that gets sent to EchelonGraph.",
  "Only the purls make it to EchelonGraph.",
  // #2831 review: each alternation the rules above added is pinned by a sentence of its own.
  "Only the purls are POSTed.",
  "No part of the document is POSTed.",
  "EchelonGraph never touches your SBOM.",
  "The server never saw the file.",
  "The document never makes it to our servers.",
  "No other content is sent.",
  "It never makes it to EchelonGraph.",
  "It is never POSTed to EchelonGraph.",
  "This MCP server never POSTs the SBOM.",
  "The SBOM is never seen by EchelonGraph.",
  // #2856: the recipient's verbs (receive, get, access, arrive, exposed to), which no rule above had
  "EchelonGraph never receives the document.",
  "We never receive the document.",
  "The API never receives the document.",
  "The document is never received.",
  "We don't get your SBOM.",
  "The server receives only the purls.",
  "Only purls are received by the API.",
  "EchelonGraph sees only the purls.",
  "EchelonGraph never receives your SBOM.",
  "EchelonGraph does not receive the document.",
  "The document is never received by EchelonGraph.",
  "Our servers never get your SBOM.",
  "EchelonGraph never has access to the document.",
  "Your SBOM is never exposed to EchelonGraph.",
  "The document never arrives at EchelonGraph.",
];
