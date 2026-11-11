# Changelog

Every version of `echelongraph-mcp` published to npm, newest first. Dates are the npm publish
dates (UTC). Issue numbers (#NNNN) refer to EchelonGraph's internal issue tracker, which is not public: they are not issues of the public repository, and cannot be followed from it. Since 2.3.3 each version is published
with a provenance attestation by the release workflow of
[github.com/echelongraph/echelongraph-mcp](https://github.com/echelongraph/echelongraph-mcp),
from the commit tagged `v<version>`.

## 3.2.3 — 2026-11-11

The registry tools say where an answer can now come from (#3767). Since 2026-11-11 EchelonGraph's
registry matcher also decides, for a language registry's package (npm, PyPI, Maven, Go, crates.io,
RubyGems, NuGet, Packagist, Hex, Pub, SwiftURL and GitHub Actions; never a Linux distribution's, nor
CRAN, Hackage, CocoaPods, conda or Conan), a CVE that no OSV advisory record names the package for,
where the CVE record's CNA names the package by its package URL (purl) (#3757). Such a match says
`match_method` `cna package url`, its `matched_criteria` is the CNA's purl, its `version_evidence`
is `cna_affected_range` and its `match_confidence` 0.8, below an advisory interval's 0.95. A CNA
statement alone never clears a package no advisory record names: it stays `assessed` false
(`package_not_in_advisory_corpus`) unless a CNA statement calls the version affected, and
`cve_remediation`'s installed verdict for such a CVE is `affected` or `not_assessed`, never
`not_affected`. Known gap (#3825): beside advisory records, `check_affected`, `check_sbom` and
`scan_manifest` count such a CVE in `not_affected_count` where its CNA calls the version unaffected
(production, npm `suneditor` 3.4.0: `not_affected_count` 4, two on VulnCheck's records alone), while
`cve_remediation` answers it `not_assessed`; and a package whose advisory CVEs are all undetermined
answers `assessed` true, not `no_decidable_advisory`, when such a CVE is decided not affected (its
undetermined CVEs are still listed, and the note still says never to report them as safe). The API
reads these CNA records only while its CNA purl index is valid; while it is not (rebuilding, or a
failed build), its answers are the advisory records' alone, as before 2026-11-11, and nothing in an
answer says which. On 2026-11-11 production answered npm `suneditor` 3.3.0 with CVE-2026-124494 and
CVE-2026-124422 so, where it had answered "assessed, 0 matches". The tools relay the API's answers
as sent, so those matches reached every version of this server when the API shipped; 3.2.2's text
still said the registry path decides "each OSV advisory EchelonGraph holds for that package", named
no CNA record as a source, and called such a match's installed `fixed_in` "as the advisory states
it". Only text changes: descriptions, notes, the method strings, one prompt line, and the
descriptions of existing output-schema fields. No field is added, removed, retyped or made
`required`, no enum changes, and no input changes (schema-compat against 3.2.2: no finding). A
client holding 3.2.2's tool list validates every answer; list the tools again (reconnect) to read the
corrected descriptions.

- **`check_affected`** (#3767).
  - Its description's registry sentence reads "decides each OSV advisory EchelonGraph holds for that
    package, and each CVE only its CNA names by purl, as affected, not affected or undetermined" (3.2.2:
    "decides each OSV advisory EchelonGraph holds for that package as affected, not affected or
    undetermined"), and "An advisory undecidable at this version" reads "A CVE undecidable at this
    version".
  - The method of a registry answer names, beside the OSV advisory records, the CVE record's CNA
    statements read beside each for a language registry's package, and each CVE no advisory record
    holds for such a package whose CVE record's CNA names it by package URL, decided on that statement
    alone (`match_method` `cna package url`), for npm, PyPI, Maven "and nine other registries; not a
    Linux distribution's, CRAN's or Hackage's"; it ends "A package only CNA records name is never
    answered clean." 3.2.2's said the CNA statements were read "once its API reads them".
  - `package_not_in_advisory_corpus` no longer says the package "was not located": a CVE record's CNA
    may name it by package URL, but a CNA statement alone never clears a package, and such CVEs are
    counted in `not_affected_count` or listed in `undetermined`, never as a clean answer. Where the
    answer's `advisories_considered` is above 0, every record read is such a CNA statement, and the
    note says so instead of calling the name worth checking: "7 CVE records' CNAs name this package
    by package URL (advisories_considered 7); none calls this version affected, so the name is not in
    doubt, and a CNA statement alone never clears it." (production's Maven
    `org.apache.tomee:openejb-http` 11.0.0; "1 CVE record's CNA names … it does not call …" for one).
  - The note on a registry answer of 0 matches says `not_affected_count` is "one per CVE however many
    of its records are stored" (3.2.2: "of its advisory records"), and adds "a CVE no advisory record
    names the package for counts here where its CNA's purl statement calls this version unaffected, on
    that statement alone, and cve_remediation answers that CVE not_assessed" (#3825, above).
    `no_decidable_advisory` names a CVE no advisory holds whose CNA statement for the package could not
    be decided among what `undetermined` may hold.
  - The note's UNDETERMINED sentence names, on the registry path, the CVEs "whose advisory records
    name this package, or whose CVE record's CNA names it by package URL" (3.2.2: "with advisories
    naming this package"), and on the CPE path the CVEs "whose NVD CPE match criteria name this
    product", where 3.2.2 spoke of advisories on both.
  - A new note sentence names the matches only the CNA makes: "Every match is on the CVE record's CNA
    statement alone (match_method cna package url: CVE-2026-124494, CVE-2026-124422): no OSV advisory
    record names this package for those CVEs, so the CNA is the only source." (or "<n> matches are …",
    with the first 10 named). "OSV": EchelonGraph holds GitHub's GHSA-cm78-x5pp-rjx2 for
    CVE-2026-124494, with no affected package, and `cve_remediation` lists it. Nothing is said where no
    match has that method.
  - The output schema describes `match_method` (`registry package`, `cna package url` and what each
    means; the CPE path's own methods), `undetermined[].reason` (the reasons an advisory record gives,
    the `cna_range_` reasons, and the two only a CVE no advisory record names gives:
    `cna_range_status_unknown`, no CNA statement calls the version affected or unaffected, and
    `cna_range_undecidable_scheme`, the CNA states the versions in a scheme the matcher cannot order,
    such as `custom` or `git`; and, on the CPE path, `version_not_comparable` is a CPE range the
    version has no order against, not an advisory record's), and `not_affected_count` (each CVE only
    its CNA names the package for counts once in `advisories_considered`, decided or not; beside
    `assessed` false the count is CNA records only, and not a clean answer).
- **`check_sbom` and `scan_manifest`** (#3767). The method names the CNA's purl statement for a
  language package's CVE that no advisory record names, "never clean alone"; to keep its length near
  3.2.2's (374 characters to 384: the method is in every answer's text and structured result, and the
  suite's 201-purl call still keeps 43 rows), "registry advisory matcher" reads "registry matcher", "the
  same matcher GET /api/v1/public/cves/match uses when given an ecosystem" reads "as GET .../match
  given an ecosystem", and "No CPE matching, no score, no ranking." reads "No CPE match, score or
  ranking." The note counts the matches only the CNA makes ("2 matches, on 1 component, are on the
  CVE record's CNA statement alone (match_method cna package url): no OSV advisory record names the
  package for those CVEs, …"). The always-present note says a `not_affected` verdict is clean "only
  for the CVEs decided at that version" (3.2.2: "the advisories decided"), and the `verdict` and
  `summary.undetermined` descriptions speak of CVEs, not advisories, that could not be decided.
- **`cve_remediation`** (#3767). The installed `verdict`'s `not_assessed` reads "no advisory record,
  and no CNA package URL, names the package for this CVE; or only the CVE record's CNA names it, by
  package URL, and does not call this version affected, which alone never clears it; or the lookup
  did not run" (3.2.2: "the record names no such package for this CVE, or the lookup did not run"). Where
  `installed.version_evidence` is `cna_affected_range` and the answer carries no `fixed_in_dispute`,
  the note says the installed `fixed_in` is "as the CVE record's CNA states it, not an advisory", where
  3.2.2 said "as the advisory states it" (production's CVE-2026-124494 at npm `suneditor` 3.3.0, whose
  only range is VulnCheck's), and `fixed_in`'s description says so too. An empty `fixed_branches`
  reads "no advisory record's affected package range is on record (the CVE record's own CNA ranges
  are not listed in it)", not "no affected package range is on record". The method adds: "An
  installed version's verdict and fixed_in are decided on the records check_affected's registry path
  reads: the OSV advisory records, with the CVE record's CNA statements read beside them, and, where
  none names the package for the CVE, the CNA's purl statement alone, which gives affected or
  not_assessed here, never not_affected, though check_affected counts such a CVE in
  not_affected_count where the CNA calls the version unaffected." (#3825, above).
- `version_evidence`'s description, in all four tools, says that on a match whose `match_method` is
  `cna package url` no advisory record names the package for the CVE at all.
- Descriptions, against 3.2.2's, measured on each server's tools/list, each within #2924's 100
  characters under the 2,048-character client cut: only `check_affected`'s changes, 1,948 characters
  (1,939 in 3.2.2). To fit its registry sentence (above), "include that product at that version"
  reads "include it at that version", "and whether it was verified (vendor_unknown)" reads ", verified
  or not (vendor_unknown)", and "(false: not yet scored, so echelongraph_score is withheld)" reads
  "(false: not yet scored; echelongraph_score withheld)". Every claim is kept.
- The `am_i_affected` prompt says "a CVE that could not be decided at this version is not safe"
  (3.2.2: "an advisory that could not be decided"), as `check_affected`'s description now does.
- Sizes: `check_affected`'s registry method is 342 characters longer (339 to 681), so PyPI `django`
  1.11.0's answer in the suite is 25,297 characters of text and 14,842 of structured result (24,955
  and 14,500); `cve_remediation`'s method is 438 longer (663 to 1,101), so CVE-2021-44228's is
  22,632 and 26,805 (22,194 and 26,367), each within the suite's text and structured budgets, as are
  the batch tools' cases, whose method grows 10 characters and whose clean note shrinks 6.
- docs/tools.md, "How `check_affected` decides", says which CVEs the registry path decides on a CNA
  statement alone, for which registries, what such a match carries, that a CNA statement alone
  never clears a package no advisory record names, that the API reads the CNA records only while its
  CNA purl index is valid, and the known gap (#3825, above);
  the README's `check_sbom` row names the advisory corpus as "OSV.dev records and CVE records' CNA
  purls", and its `check_affected` row counts the CVEs it cannot decide as `undetermined_count`; to
  stay under the README's 62,000-character ceiling (61,996), the docs link's `fixed_in` sentence
  drops a "that".
- Tests: `test/cna-purl-text.test.mjs` holds the description, the methods, the schema descriptions and
  the notes to the sentences above, each with 3.2.2's wording as its control: the notes on
  production's answers of 2026-11-11 (`test/fixtures/cna-purl-wire.json`) for npm `suneditor` 3.3.0
  and 3.4.0, Maven `org.apache.tomee:openejb-http` 11.0.0 and CVE-2026-124494, and, where production
  served no such answer to read, on answers written in core-backend's shape and not read from
  production: the UNDETERMINED sentence and the two CNA-only reasons (`cna_only_not_assessed`, named
  synthetic in the fixture and the test), `no_decidable_advisory`, and the CPE path's UNDETERMINED
  sentence. One test is a relay check with no 3.2.2 control, named so: `cve_remediation` relays
  production's `not_assessed` for `suneditor` 3.4.0 as 3.2.2 does.

## 3.2.2 — 2026-11-11

The vendor-advisory tools say when a vendor is not being collected (#3464), and declare the fields
EchelonGraph's API now serves for a Microsoft advisory, whose own text it no longer copies (#3642,
#3643). The remediation texts say where a Cisco remediation's `kind` may not be Cisco's own category
(#3663), and `patch_evidence` names Cisco's signed CSAF (#3647). Descriptions, notes and output
schemas change. Five fields are added to each vendor window, and others are declared where the API
serves them. No field already declared changes type or becomes `required`; the five new fields are
`required` (null when the API omits them), and no enum is added. No client needs to reconnect for its
answers to validate (below). A client that listed the tools from 3.2.1 or earlier still holds their
old descriptions, though, which said a remediation's `kind` is the vendor's own category, "never read
from the text": production's answer for CVE-2026-20185 has contradicted that since it began serving
that CVE's Cisco item as `no_fix_planned` (read on 2026-11-11). List the tools again (reconnect) to
read the corrected text.

- **Whether each vendor is being collected** (#3464). A vendor's window (`held_since` to
  `latest_vendor_published_at`) says nothing of whether the vendor is still being collected. Cisco's
  polls were refused from 2026-10-12, and for 20 days its window read as held to 2026-10-07, so
  `vendors_not_fully_held` and the notes read it as current. EchelonGraph's coverage API now serves
  each vendor's `last_success_at` and `collection_state`, by the rule its feed-state alert uses: `ok`;
  `partial`, the vendor's polls succeed but `held_back` of the documents it lists could not be used,
  the oldest since `held_back_since` (those advisories, or those revisions, may not be held, and the
  rest of its feed is); `failing`, it is not being collected, and what it published after
  `failing_since`, its last successful poll, may not be held, whatever its window says; or
  `disabled`, this deployment runs no collector for it (its held advisories are still served), so its
  window ends at `last_success_at`. All three tools relay the five fields in each window, and the
  note names each vendor whose `collection_state` is not `ok`, with its date. For production's Cisco
  from 2026-10-12, docs/api/openapi.yaml's example row, `search_vendor_advisories` says: "Cisco PSIRT
  (cisco) collection has failed since 2026-10-12 (collection_state failing; failing_since
  2026-10-12T12:22:49Z, its last successful poll); advisories Cisco PSIRT published after that may
  not be held, whatever its window says. So no advisory here from that vendor is not a finding that
  it published none." A `partial` vendor reads "<n> Cisco PSIRT (cisco) documents are held back, the
  oldest since <date> (collection_state partial, held_back <n>: EchelonGraph could not use them); some
  Cisco PSIRT advisories may be missing: those advisories, or those revisions, may not be held, and
  the rest of its feed is.", and a `disabled` one "… is not collected in this deployment
  (collection_state disabled): its window ends at its last successful poll, <date> (last_success_at
  <instant>); advisories … published after that may not be held." A vendor with no successful poll on
  record, and a state this server does not know, are said as such, and a state the API adds later is
  relayed as sent and never read as `ok`. Nothing is said of an `ok` vendor.
- `vendor_advisories_for_cve` lists a vendor whose `collection_state` is not `ok` in
  `vendors_not_fully_held` for any CVE year, when the answer holds none of its advisories (in the
  suite, a Palo Alto whose history is read back to 2012 is listed for CVE-2024-3400 while failing,
  and not while `ok`), and names the vendor's failure in its note whether or not the answer holds one
  of its advisories: what it published after its last successful poll may name the CVE too. Its item
  in the list says why: "paloalto (held from 2012-04-27 to 2026-10-02; collection_state failing)".
  The note says once that no advisory from such a vendor is not a finding that it published none: in
  the `vendors_not_fully_held` sentence for a vendor listed there, and after its collection sentence
  only for a vendor the answer holds an advisory from ("So no advisory here from Microsoft is not a
  finding that it published none.").
- Freshness: `freshness` is still null, and its note said the answers "carry no time at which the
  vendor-advisory pollers last completed a poll", which is no longer so once the windows carry
  `last_success_at`. Where a window carries one, the note says "freshness is null: the answer has no
  single poll time; each vendor's last successful poll is its window's last_success_at in coverage,
  and its collection_state says whether it is being collected now, by EchelonGraph's feed-state
  rule."; against an API without the field it reads as before. `get_vendor_advisory`'s description
  said "Its freshness is null: the answer carries no poll-completion time."; it says "freshness is
  null; vendor_window.last_success_at is the last successful poll."
- `outputSchema`: each vendor window (`coverage.vendor_windows[]` of `vendor_advisories_for_cve` and
  `search_vendor_advisories`, `coverage.vendor_window` of `get_vendor_advisory`) adds
  `last_success_at`, `collection_state`, `failing_since` and `held_back_since` (each a string or
  null) and `held_back` (a number or null), each `required` and null from an API without them.
  `collection_state` is a string, as `history_scope` is, its four values named in its description,
  so it adds no enum. The descriptions of the window, `vendor_windows` and `vendors_not_fully_held`
  say what the fields mean. A success's schema is open, so a client holding an older tool list takes
  the added fields. The failure branch's window objects, which stay closed, add them too
  (`test/schema-compat-allow.json`, against 3.2.1), but no failure carries a window: a failure's
  `coverage` is null.
- **Every field of the coverage row is read, or named as not relayed** (#3628).
  `test/vendor-coverage-fields.test.mjs` reads the coverage route's vendor item from
  docs/api/openapi.yaml (which core-backend's coverage_openapi_test.go holds to the API's wire row)
  and fails on a field that the server's `windowsOf` neither relays nor names in
  `VENDOR_COVERAGE_NOT_RELAYED` with a reason (today `history_units_done` and
  `history_completed_at`, the history read's bookkeeping, which bound no window), and on a
  `collection_state` value it has no sentence for. Through 3.2.1 nothing did: `history_scope` and
  `feed_held_since` reached the API on 2026-11-01 and this server on 2026-11-07 (#3472, 3.1.4), and
  the five fields above on 2026-11-08. A field is read when a row with every field set comes back
  with it in the window, not by a list. The public repository carries a copy of the vendor item
  (`test/fixtures/vendor-coverage-item.json`), which the release's test run of the packed tarball
  reads too; in EchelonGraph's repository the copy is held to the spec. Controls: a field added to a
  copy of the spec fails, and removed again passes.
- **Microsoft's advisory pages are not copied, and the schemas say so** (#3642). The API now answers
  every Microsoft advisory with `vendor_text_withheld: true`, a title of EchelonGraph's ("Microsoft
  security update for CVE-2025-29824"), and an empty `description`, `remediation`,
  `withdrawn_reason` and remediation `text` (`text_chars` 0), and with no `summary`; the severity,
  CVSS score, CVE IDs, affected products, dates, references (led by Microsoft's Security Update Guide
  page where the advisory names a CVE ID; an ADV advisory has none) and each remediation's kind,
  category, URL and fixed build are unchanged. Every other vendor's answers say
  `vendor_text_withheld: false` and are unchanged. `vendor_advisories_for_cve`,
  `get_vendor_advisory`, `search_vendor_advisories` and `cve_remediation` relay the API's answer as
  sent, so this reached every version of this server, the installed ones included, when the API
  shipped; this release changes no relayed value. It declares the fields the answers now carry, with
  what they mean: `vendor_text_withheld` on each vendor-advisory row, on the detail and on each
  `cve_remediation` vendor advisory, and `cvss_v3_vector` (the CVSS v3 vector of `cvss_v3_score`
  where the vendor's source carries one, Microsoft's; null otherwise) on `vendor_advisories_for_cve`
  rows and `get_vendor_advisory`.
- **A Microsoft advisory's detail carries EchelonGraph's own facts of its CVEs** (#3642).
  `get_vendor_advisory` relays the API's new `cve_records`: for each of the first `cve_records_cap`
  (5) CVEs a Microsoft advisory names, the CVE record's own description, as the CVE Numbering
  Authority that assigned the CVE (`cna`: its name in the CVE Program's CNA list, else its short
  name, e.g. "Microsoft Corporation", "kernel.org") published it in the CVE record at
  `cve_record_url`, reused under the CVE Program's Terms of Use; for a CVE Microsoft assigned,
  Microsoft wrote that record. The description is null where the record has none, was rejected or is
  still the stub a GitHub advisory seeded, where EchelonGraph holds no record for the CVE (`known`
  false), or where `description_withheld_reason` says it is withheld (below). Beside it,
  EchelonGraph's score as the CVE feed serves it (null unless `score_assessed`), the CISA KEV
  listing, and the fix status by the CVE feed's rule; with `cve_records_total`. Each Microsoft
  remediation item whose URL names a KB article carries it as `kb_article`, and the detail carries
  `content_changed_at`, when the page's content changed with no change to the advisory. The output
  schema declares all of them; the relayed values are the API's, as sent.
- **What a Microsoft advisory's title says, and which IDs count as CVEs** (#3642 review). The API
  titles a Microsoft advisory "Microsoft security update for CVE-…" only when it lists a vendor fix
  and was not withdrawn, and "Microsoft advisory for CVE-…" otherwise; an advisory naming no CVE ID
  (an ADV advisory, or a malformed ID) is "Microsoft advisory ADV160001", gets no `cve_records` entry
  and no CVE-record link, and `cve_records_total` counts CVE IDs only. Relayed as sent; the output
  schema's description of `vendor_text_withheld` says so.
- **Each source's licence, on the field that names the source** (#3643). The `vendor` field of every
  vendor-advisory row, and of each `cve_remediation` vendor advisory, names the licence of that
  vendor's data: Red Hat's security advisories and the GitHub Advisory Database are licensed CC BY
  4.0 (licence and source linked), Microsoft's and every other vendor's stay under that vendor's own
  terms; `cve_records` names the CVE Program's Terms of Use (https://www.cve.org/Legal/TermsOfUse).
  EchelonGraph's terms add no restriction to any of them.
- **A CVE-record description that repeats the advisory's title can be withheld** (#3642). The
  descriptions stay shown, credited to their CNA. A server-side switch, off by default, can withhold
  a `cve_records` description that repeats the advisory's own title: a withheld one is `null`, and
  the new `description_withheld_reason` says `matches_vendor_title`; it is `null` otherwise. It
  changes `get_vendor_advisory` only: `get_cve` keeps the CVE record's description. The output
  schema declares it. Relayed as sent.
- **`get_vendor_advisory`'s description says what a Microsoft advisory's detail carries** (#3642
  reviews). It ends "vendor_text_withheld true (Microsoft): title is EchelonGraph's; description,
  remediation and item texts are empty; cve_records: its first CVEs, each with its CVE-record
  description or null.", and `vendor_text_withheld`'s description says a detail's `cve_records`
  "lists the first cve_records_cap CVEs it names, each with the CVE record's description or null".
  Neither says every CVE's description is there, which is not so where one is null (above) or for a
  CVE past `cve_records_cap`; `cve_records`' own description names each case in which the
  description is null. `cve_records[].known` false reads "EchelonGraph holds no CVE record for it;
  only cve_id and cve_record_url are set", with no guessed cause.
- **A Cisco remediation may be `no_fix_planned` where Cisco's summary says no fix will be
  released** (#3663). Cisco's CSAF for cisco-sa-sg350-snmp-dos-GEFZr2Tj (CVE-2026-20185, the SG350
  switches, past End of Software Maintenance) tags its one remediation `vendor_fix`, with Cisco's
  boilerplate "Cisco has released software updates that address this vulnerability", while its
  Summary says Cisco "has not released and will not release software updates". EchelonGraph's API
  now stores a Cisco `vendor_fix` as `kind` `no_fix_planned` when both hold: the advisory's Summary
  says, in wording its parser reads, that Cisco will not release a fix, and none of its Summary,
  Fixed Software, Recommendations, Details or Affected Products notes says, by the parser's markers,
  that a fix exists. The item's `source_category` stays `vendor_fix` (what Cisco's field holds), its
  `source_subcategory` is the title of the note its text is from (`Summary`), its text is Cisco's
  own Summary sentence, and it carries no URL. Wording the parser does not read leaves `vendor_fix`:
  a Cisco `vendor_fix` is not a finding that a fix was released, and a Cisco advisory whose summary
  says there is no fix is not always `no_fix_planned`. Of the 211 Cisco CSAF advisories EchelonGraph
  held on 2026-11-08, one was stored so, CVE-2026-20185's, which production serves as
  `no_fix_planned` (read on 2026-11-11). The tools relay it as sent, so this reached every version of
  this server when the API shipped. What changes here is the text that said `kind` was the vendor's
  own category, "never read from the text":
  - `cve_remediation`'s and `get_vendor_advisory`'s descriptions, and the README, say `kind` is the
    vendor's own category, or may be `no_fix_planned` if Cisco's summary says none will be released;
  - `get_cve`'s `remediation` field and the `remediation_kinds` fields, the triage prompt's step 3
    and the methodology resource say it may be `no_fix_planned` where Cisco's summary says no fix
    will be released;
  - the `kind` field of each remediation item, in `cve_remediation` and `get_vendor_advisory`, states
    the rule above in full, and `source_subcategory` names the note;
  - where they say the kinds are the vendors' own categories, the notes of `cve_remediation` and
    `vendor_advisories_for_cve` add "(no_fix_planned may also be a Cisco vendor_fix whose summary
    says no fix will be released)" when a Cisco advisory in the answer lists `no_fix_planned` (a Red
    Hat `no_fix_planned`, Red Hat's own category, adds nothing), and `get_cve`'s note when its
    remediation summary counts one, since that summary counts kinds, not vendors;
  - the method of `cve_remediation` names Cisco's CSAF beside Red Hat's among the vendors whose
    remediation is categorised, and says a Cisco `vendor_fix` may be `no_fix_planned` where Cisco's
    summary says no fix will be released.
- **`patch_evidence`'s `vendor_advisory_fix` names Cisco** (#3647). Since EchelonGraph's patch
  evidence rule 9 (2026-11-08), `vendor_advisory_fix` also counts a Cisco signed CSAF `vendor_fix`;
  the `patch_evidence` description of `get_cve` and `search_cves` named Red Hat's CSAF `vendor_fix`
  and Microsoft's Vendor Fix only. It now reads "Red Hat's CSAF vendor_fix, Cisco's signed CSAF
  vendor_fix, Microsoft's Vendor Fix; not a Cisco vendor_fix EchelonGraph stores as
  no_fix_planned", and docs/tools.md, "What `patch_available` says", says the same, with the
  parser's rule.
- Descriptions, against 3.2.1's, measured on each server's tools/list, each within #2924's 100
  characters under the 2,048-character client cut. Three change, and no other:
  - `cve_remediation`, 1,946 characters (1,948 in 3.2.1): the `kind` sentence (above) is 47
    characters longer, so `fix_status` no longer says "as CVE Pulse shows it", which its output
    schema says, and `vendor_remediations` no longer gives its order and cap, which `coverage`
    carries.
  - `get_vendor_advisory`, 1,947 (1,926): it gains the `vendor_text_withheld` sentence and the
    freshness sentence (above), and its `kind` list reads "vendor_fix, workaround, mitigation,
    no_fix_planned, none_available or other: the vendor's category, or may be no_fix_planned if
    Cisco's summary says none will be released". To fit, `remediation_state` names only the two values
    that are not a finding that no fix exists (its output schema names all four); its window names
    `earliest_vendor_published_at` to `feed_held_since` without `vendor` and `advisories`, and is
    null "if unreadable or empty"; `advisory_id` is no longer called EchelonGraph's internal UUID
    there (its output schema says so); and `known_cve_ids` are those "in EchelonGraph's CVE feed".
  - `vendor_advisories_for_cve`, 1,948 (1,944): `vendors_not_fully_held` also lists a vendor "whose
    history is still being read or collection_state is not ok"; to fit, its list of each row's fields
    no longer names `vendor_display_name` (still in every row and in the `outputSchema`), and "each
    vendor's held window" reads "each vendor's window".
- Sizes: each window of the suite's production-shaped coverage answer (an API older than the fields)
  carries the five fields null: `vendor_advisories_for_cve` CVE-2021-44228 is 1,580 characters of
  text and 1,080 of structured result longer (20,906 and 16,503), `get_vendor_advisory` 148 and 108.
  No text cut changes level; the forced by-CVE case keeps 11 of its 20 rows in data where it kept 12,
  and `search_vendor_advisories`' largest page 40 of 50 where it kept 41, each DATA CUT note saying
  how many it left out. Against production's record of 2026-10-25 (3.1.1's server, which relayed 7
  fields per window), the by-CVE case is past the 10% drift bound, pinned in `TEXT_DRIFT_KNOWN` and
  `STRUCTURED_DRIFT_KNOWN` until `text-bound:live --record` re-records it. `cve_remediation`'s
  method is 115 characters longer (548 to 663), in the text's last block (1,377 to 1,492) and in the
  structured result: CVE-2021-44228's answer in the suite is 22,194 characters of text and 26,367 of
  structured result, where it was 22,079 and 26,252.
- README: one sentence on `last_success_at` and `collection_state` (while a vendor's is not `ok`, the
  note names it and says which of its advisories may not be held), and the `cve_remediation` and
  `get_vendor_advisory` rows say `kind` may be `no_fix_planned` if Cisco's summary says none will be
  released; the detail is in docs/tools.md, "How the vendor-advisory tools read each vendor's
  window".

## 3.2.1 — 2026-11-08

What the server says resolves to a CVE now holds to what EchelonGraph has measured, namespace by namespace
(#3448), and a correction to 3.1.2's entry, below. Only descriptions and the CVE feed tools' `method` change: no
type, enum or `required` changes, and no client needs to reconnect.

- **Which identifiers resolve to their CVE, and from what** (#3448). Through 3.2.0 the CVE feed's `method` (in
  `cve_summary`, `search_cves` and `get_cve` answers) said "ENISA EUVD identifiers resolve to their CVE." and
  named no other namespace, while `get_cve`'s `cve_id` description said "a CVE ID, e.g. CVE-2023-44487, or an
  ENISA EUVD (EUVD-2026-90503), GitHub GHSA, OSV (PYSEC-, GO-, RUSTSEC-, GSD-, MAL-) or GCVE-0 (GCVE-0-2024-3094)
  ID, which EchelonGraph resolves to its CVE": a claim for every namespace it named, wider than what EchelonGraph
  has measured. The `method` of `search_cves` and `get_cve` now says that coverage differs by namespace and names
  what resolves with its source: ENISA EUVD IDs resolve to their CVE (source `enisa_euvd`), and GCVE-0 IDs by the
  GCVE specification (source `gcve_gna0`), the only two namespaces that resolve across the corpus. GitHub's is
  said in its measured form alone: "97.5% of a random 200 reviewed GitHub advisories resolve to their CVE." That
  is a probe of production on 2026-11-07: a seeded random draw of 200 reviewed, non-withdrawn GHSA IDs with
  exactly one CVE alias, from a population of 32,959, of which 195 resolved to that CVE (195/200). OSV IDs are
  still accepted, and no text gives a rate for them: `cve_id` lists them as accepted and says "An OSV ID resolves
  only where EchelonGraph's alias table maps it to a CVE." A `search_cves` or `get_cve` answer that carries the
  `method` is 196 characters longer, in its text and in its structured result, unless its data is cut to fit the
  30,000-character structured budget, where it may keep fewer entries and its note gives the counts (`get_cve`
  CVE-2021-44228's structured result, cut, is 29,976 characters of its 30,000 on production's answer of
  2026-10-25 that the suite replays). A failed answer carries none, and is unchanged.
- `cve_summary` takes no identifier, so its `method` is the feed's first sentence alone, without the identifier
  sentences (45 characters shorter than 3.2.0's).
- `get_cve`'s description said "Pass a CVE, EUVD or GHSA ID.", a GitHub claim wider than the measured one; it
  says "Pass a CVE, EUVD or GCVE-0 ID.", and `cve_id`'s description carries GitHub's sentence. The description is
  1,944 characters, 4 under the 1,948 its 100-character headroom under the 2,048-character client cut allows: too
  few for the sentence's 70.
- `search_cves`' top-level `resolved_from` was described as present whenever the search term was an EUVD, GHSA,
  OSV or GCVE-0 ID; it is present only when EchelonGraph mapped that ID to a CVE (the API serves none for an ID
  that maps to nothing, and the page then lists no rows), and its description carries the same sentences as
  `cve_id`'s. docs/tools.md, "How `get_cve` and `search_cves` take an EUVD, GHSA, OSV or GCVE-0 ID", says the
  same, and that an EUVD ID resolves while EchelonGraph displays ENISA's data.
- `test/id-resolution.test.mjs` reads every text the server serves (the instructions, tools/list, the answers'
  `method`, notes and coverage, each prompt's description and `prompts/get` text, every resource's description
  and contents) and the package's pages (README.md, docs/, server.json, package.json's description, every text
  file under listings/, and this entry). It holds them to the limits: the texts that say which identifiers
  resolve carry GitHub's sentence verbatim, and OSV's beside a list of OSV IDs; no text says a GHSA or OSV ID
  resolves outside those sentences; EUVD and GCVE-0 alone are said to resolve, each with its own source; no text
  names a namespace the test does not know. Each namespace named has its source among those `resolved_from`
  carries, and, in EchelonGraph's repository, a pattern in core-backend's identifier parser (core-backend's Go
  tests own how that parser behaves).

### Corrections

- **Correction to 3.1.2's entry** (#3448). It said that, for an ENISA EUVD, GitHub GHSA, OSV or GCVE-0 ID,
  "EchelonGraph's API resolves it to its CVE", and that "`search_cves` with an EUVD, GHSA, OSV or GCVE-0 ID as
  its search lists exactly the CVEs it names, with `resolved_from` on the page". That holds for ENISA EUVD and
  GCVE-0 IDs. For GitHub, what holds is the measured sentence above: "97.5% of a random 200 reviewed GitHub
  advisories resolve to their CVE." OSV IDs are accepted: "An OSV ID resolves only where EchelonGraph's alias
  table maps it to a CVE." A `search_cves` page carries `resolved_from` only when EchelonGraph mapped the ID to a
  CVE.

## 3.2.0 — 2026-11-08

The hosted endpoint bounds what parsing a request may take before it parses it, for each request and for all of
those in flight together, refuses a request that would reserve more than 31,457,280 bytes (30 MiB) of its memory
before it reads, its body and what its tools read together, and reads the API's answers to a call's purls only to
the room it has left, each call (#3381); a document a tool parses from text is estimated before it is parsed, on both transports, beside
3.1.3's per-call bounds, that bound a share of the server's memory, so a local server's is proportionally larger than
the hosted endpoint's (#3381); every name and version `scan_manifest`'s readers take from a file is bounded before it
is split, so what a call's files make the server build is bounded per call, as 3.1.3 said but did not yet hold, and one such file no longer
ends the hosted endpoint's process, nor does a lockfile key named `__proto__` reach the server's shared objects
(#3460, Security, below); once EchelonGraph's API serves it, a match relays where the CVE record's CNA disputes the
advisory's range (#3391); `check_sbom` says where a list of purls goes when one is sent in the wrong shape, and
`cve_exposure`'s note no longer says Shodan's banner time is not stored (#3467); and corrections to 3.1.2's and 3.1.3's
entries, below. One optional `outputSchema` field is added (`fixed_in_dispute`), `get_cve`'s
`affected_ranges`, already relayed, is now named (and so is `search_cves`' rows', which share the record's schema;
a search answer never carries it), `version_evidence` names its values beside any string and is now
named on `check_sbom`'s and `scan_manifest`'s matches too, and a success's `coverage.not_sent_reason` can say
`server_busy`; no `required` changes. A failure carries `coverage` null, and its schema keeps 3.1.5's
`not_sent_reason` values, so a client holding 3.1.5's tool list need not reconnect. Descriptions change: every tool's `error.status` (503 where this server was too busy to make the
call), `coverage.not_sent_reason`, and the registry matches' `interval`, `match_reason` and `fixed_in`
(`check_affected`'s own description with them: a match's interval is the affected one, the advisory's or the CNA's),
and `scan_manifest`'s description, which says a hosted call over 30 MiB with its body is refused, and to make room no
longer says go.mod is read after replace and exclude (the README's row does); `exposure_radar`'s description, and
its outputSchema description of `kev_exposure.window`, say whose clock its times are on and that it spans all
KEV-listed rows together, and to make room the description drops a few words elsewhere, its meaning unchanged
(#3467). One title changes: `check_sbom`'s is now "Check purls or an SBOM against the advisory corpus" (#3467).

### Added

- **A match relays `fixed_in_dispute`, where the CVE record's CNA and the advisory disagree on its range** (#3391).
  EchelonGraph's API serves these fields since 2026-11-07 (#3391, core-backend 95927abe), so against it every "once
  the API serves (or reads) them" in this entry holds now. Once EchelonGraph's API serves it, a match carries `fixed_in_dispute` beside `fixed_in` where the CVE record's
  numbering authority (CNA) and the advisory disagree on the range that holds the version: what differs (`kind`:
  `fixed` or `introduced`), the advisory's bound in dispute (one of `advisory_fixed`, `advisory_last_affected` and
  `advisory_introduced`, with `advisory_listed` where the advisory lists versions rather than a range) and the
  advisory (`advisory_id`), the CNA (`cna`: `name`, `short_name`), what its entry names (`cna_product`) and the
  CNA's range in dispute, as the API reads the record (`cna_range`: `version`, `less_than` or
  `less_than_or_equal`, `status`, `version_type`, and `changes` with `changes_truncated`; where `higher` is `cna`,
  the CNA's range that reaches past the advisory's bound, which holds the version on a `cna_affected_range` match
  and, on an `advisory_interval` or `exact_version_list` match, the advisory's bound past the version (its fix, or
  the versions just above its last affected or listed version), so it may start above the version, and where it is
  `advisory`, the CNA's range that ends below it): an entry the
  record writes or, with `cna_range_default` true, a span no entry writes that the record's `defaultStatus` covers;
  the source the answer follows (`higher`, the more conservative one: `cna` or `advisory`), and the API's sentence
  on the dispute (`note`). `fixed_in` follows the source `higher` names, so where it is `cna`, `fixed_in` need not
  be the advisory's own fix. A match whose version only the CNA's range holds says `version_evidence`
  `cna_affected_range`, and its `interval` is that range; such a match may carry no `fixed_in_dispute` (once it serves
  them, the API raises a version the CNA lists by itself with none, its `fixed_in` null and `fixed_in_reason` saying why), and
  so may an advisory interval's match whose fix the CNA lists as affected. A match without `fixed_in_dispute` is not a finding that
  the CNA agrees: an API that does not serve the field yet sends none, and one that serves it reads a CNA's ranges
  only where it applies them and only from an entry it matches to the package. `check_affected`, `check_sbom`, `scan_manifest`
  (each registry match) and `cve_remediation` (the installed version asked) relay it as sent in `structuredContent`,
  its fields and values open to what a later API adds, keep it on the match in the first text block at every cut
  level that keeps `fixed_in_reason`, and quote its `note` verbatim in the note, naming the match (at most five
  matches; every one in its match). Their notes say `fixed_in` is the first version above the one asked that no
  affected interval of the CVE's record holds (the advisory's, or, once the API serves them, a CNA range it applies), and on a match with
  a dispute that it follows the source `higher` names; a dispute sent without a note is a dispute all the same; the `am_i_affected` and
  `sbom_review` prompts read `fixed_in` the same way and have the agent quote the dispute's note. An API that sends no
  `fixed_in_dispute` is relayed as before. A `fixed_in_dispute` this server cannot read (not an object, or a field of
  another type than its schema names) is relayed empty (`{}`), its match still disputed, and the note names the match
  and says its `fixed_in` may follow the CNA, so one malformed annotation never fails the call or loses its other
  rows. `cve_remediation`
  quotes the note clipped at 1,000 characters, as the other tools do, whole in `data`. Where not even
  `check_affected`'s leanest structured level keeps every match, a level below it keeps every match, each dispute
  without its `note`, before any match leaves (where that does not keep them all either, matches leave as before, each
  dispute whole). `check_affected`'s method names the CVE record's CNA statements the API reads beside each advisory,
  once it reads them, and its `no_decidable_advisory` sentence says no CVE could be decided either way, by its advisory
  or, once the API reads them, by a CNA statement that could not be read against it. `check_affected`'s and `cve_remediation`'s outputSchema now names the
  values `version_evidence` takes (`exact_version_list`, `advisory_interval`, `fix_boundary_only`,
  `no_version_supplied` and, once the API serves it, `cna_affected_range`), beside any other string, as it was: a value a later API adds is
  relayed, never a failed call; `check_sbom`'s and `scan_manifest`'s now name it on each match too, and say a match's
  `interval` and `match_reason` range are the advisory's or, on a `cna_affected_range` match, the CNA's. An
  undetermined CVE the API answers as such (its `reason`, such as `cna_range_open_ended` or `cna_range_other_line`) is relayed undetermined,
  never clean. `get_cve`'s outputSchema now names and describes the record's `affected_ranges`, which it relayed
  already: each product's version entries as the API stores them, each as the record writes it, and, once
  EchelonGraph's API serves them, their `changes` and `changes_truncated`, and each product's `package_name` (the
  entry's `packageName`), `collection_url`, `package_url`, `versions_truncated`, `dropped_products` (with
  `dropped_products_truncated`: the cut products a registry package's answer could read), `dropped_other_products`
  (how many other products were cut, which no registry package's answer reads) and `stored_form`; a product without `stored_form` comes from an API or a writer
  that sends none of these, and may have had versions or products cut with no flag saying so. `search_cves`' rows
  share the record's schema, so its outputSchema names `affected_ranges` too, described as never on a search row.

### Changed

- **On the hosted endpoint, one request may reserve at most 31,457,280 bytes (30 MiB) of the instance's memory
  before it reads, its body, what its tools read and 1,280 bytes a purl for the API's answers together** (#3381):
  three quarters of the budget for all requests in flight, the most a waiter is sure to be let in at (Fixed, below).
  The API's answers past what was reserved for them are charged as they come, and a call sends no further batch once
  they take its request past the bound; one batch's answer can take it past, within what the instance has room for
  (Fixed, below). A call whose reservation would pass it is refused `invalid_input` at once, naming the bound and
  what to do: for a lockfile, pass its purls to `check_sbom`, in calls of 2,000 or fewer; for a line format, its
  lines over more calls; or run the server locally (`npx -y echelongraph-mcp`), whose bounds are a share of its own
  machine's memory. Measured on 38 real lockfiles of large public repositories (24 `package-lock.json`, 8
  `Cargo.lock`, 6 `poetry.lock`, 67 KB to 1.8 MB), each is read, the costliest at 0.40 of the bound. What 3.1.5
  answered and the hosted endpoint now refuses, within every per-call bound 3.1.5 states: a `poetry.lock` of more than
  about 3 MB that holds 2,000 packages or fewer (copied to larger sizes from its own packages, each real poetry.lock
  is refused from 3.1 to 3.9 MB, by its shape); a `package-lock.json` past the bound whose entries repeat packages
  at many install paths, so that it holds 2,000 distinct purls or fewer; and a call of 40,000 lines of a line format
  near the 5,000,000-character cap whose text holds a character past U+00FF (which makes the body two bytes a
  character in memory). A `Cargo.lock` or `package-lock.json` copied to the sizes it is refused at (from 2.4 MB, and
  3.3 to 5 MB) held more than 2,000 distinct purls in every real file measured, which 3.1.5 refused too. The same
  holds for a `check_sbom` call of 2,000 purls whose answers take its request past the 31,457,280 bytes (measured:
  three matches a row, 717 KB a batch answer): it is answered for its first 1,000 purls, the rest `server_busy`,
  where 3.1.5 answered all 2,000. A file estimated past what one file's read may take (28 MiB there) is not read,
  and on the hosted endpoint its refusal says what to do. `scan_manifest`'s description says a hosted call over it
  is refused (#3381).

### Fixed

- **`cve_exposure` no longer says Shodan's banner time is not stored, and `exposure_radar` says whose clock and which
  rows its window is** (#3467). `cve_exposure`'s note on `last_seen` said "Shodan's own banner time is not stored", as
  docs/tools.md did; that was true until #2438's core-backend change, which stores it, reached production
  (2026-10-06T15:09Z; it was committed on 2026-10-05). It now says that the banner time is
  stored, where Shodan gives a usable one, for rows matched since 2026-10-06T15:09Z, that the per-CVE answer does not
  serve it, and that
  `exposure_radar` serves its earliest and latest as `kev_exposure`'s window (or `dated_window`), over all KEV-listed
  rows together, never this CVE's alone, and over no row of a CVE tracked only for its EPSS. `exposure_radar`'s
  description, note and outputSchema, and docs/exposure-radar.md, now call that window's times Shodan's own
  timestamps, on Shodan's clock, over all KEV-listed rows together (the note, of a `dated_window`: "over the dated
  KEV-listed rows together"), not "when Shodan collected the banners", and its
  note, outputSchema and docs/exposure-radar.md add that some run up to 5 minutes ahead of EchelonGraph's
  `last_seen` for the same row: on 2026-11-01 3,648 rows held a banner time later than EchelonGraph's own last write
  of the row, by up to 5 minutes. No count, `state` or `measured_at` changes.
- **`check_sbom` says where a list of purls goes when one is sent in the wrong shape** (#3467). `purls` takes a list
  of package URLs, one included; through 3.1.5 none of the refusals of a purl list sent otherwise named it: a purl
  (or several) as `sbom` was answered "sbom is not JSON: pass a CycloneDX JSON or SPDX JSON document", a JSON array
  as `sbom` "sbom must be a string or an object, not an array" (or, as text, "sbom must be a JSON object"), and one
  purl as a string in `purls` "purls must be an array, not a string". Each now adds "a list of purls goes in purls,
  e.g. purls: ["pkg:npm/lodash@4.17.20"]; one purl still goes in a list", and so does the refusal of an `sbom` of
  neither format that holds a `purls` member; a purl as `sbom` is told so bare, quoted (`"pkg:npm/a@1"`) or in a
  bracketed list (`['pkg:npm/a@1']`). A document of another kind, or an argument of another wrong type, is
  refused as before. A CycloneDX or SPDX JSON text saved with a leading byte-order mark (U+FEFF) is now read, as
  `scan_manifest`'s readers already read one; through 3.1.5 it was refused "sbom is not JSON". The title "Check an SBOM against the advisory corpus" is now "Check purls or an SBOM against
  the advisory corpus"; the description is unchanged.
- **On the hosted endpoint, what parsing a request body would hold in memory is estimated before it is parsed, and a
  body past what one may take is refused** (#3381). Every request body, at any size, is now read once first, without
  being parsed: its objects and arrays, list entries and object members, keys and string bytes are counted, and what
  parsing it would retain is estimated from them, at the most each can cost. A body whose estimate is past what one
  request's parse may take is answered HTTP 413 with a JSON-RPC error (code `-32600`) that gives the counts, the
  estimate and the bound, without being parsed, and its access line says `refused` `body_dense` (and `rpc_method`
  `(unparseable)`: the body was not parsed, so no method is known). Through 3.1.5 a body was parsed whole before
  anything weighed what it would hold, and what that took of the instance's memory had no bound but the body's size.
  A real document passes: each one measured up to the 6 MiB cap is estimated within the bound (Juice Shop's
  CycloneDX components passed as an object, a document shaped as Syft writes one, and #2773's 5,000,000-character
  document passed as text).
- **On the hosted endpoint, what all requests in flight hold parsed is bounded together** (#3381). Each body's
  estimate is held in one budget for the instance from before it is parsed until its request has stopped, however it
  ends: answered, its client gone while it waits or while it is served, or its deadline, where it is given back once
  the request has unwound, not while what it parsed is still in memory. A body that fits is let in ahead of one that
  waits and does not, until that one has waited a second; from then on a body above the general 64 KiB cap is let in
  only if the room the waiter needs is left beside it, so the waiter is let in once the large requests before it end.
  A body within the cap is let in whatever waits, and so are its tool's reservations of the document it reads and of
  the API's answers for up to 200 purls (one batch), while all of those together hold no more than a quarter of the
  budget; a call of more purls reserves its answers as a large body does, waiting behind such a waiter. The answers
  to such a small call's batch can take that quarter past full while the call answers; a small body or reservation
  then waits as a large one does, but for a tiny body (at most 64 KiB of estimate: a `tools/list`, `initialize` or
  `ping`), which has a lane of its own, open whatever the quarter holds, of 4 MiB in all; a tool's reservations,
  however small, do not take it, so they cannot fill it and keep a `tools/list` out. A JSON-RPC batch is one
  request: its calls' reservations are made one after another, each counting what the request holds as it is then
  (its other calls' answers as they are charged, and what they keep as it shrinks), and once one of them finds no
  room within the wait the batch's later calls wait no more: each is taken where it fits at once, and answered
  "server busy" where it does not. A body that finds no room within the admission wait is answered HTTP 503 with
  `Retry-After` and a JSON-RPC
  error (code `-32030`), as a busy instance is, never queued without bound, and its access line says `refused`
  `parse_busy`. An access line's `queued_ms` counts its waits for room in this budget as well as for a place.
  Through 3.1.5 nothing weighed what the requests served at once held together. Two of the largest real documents
  sent at once can now be parsed one after the other rather than side by side: the second waits for the first,
  within the same wait.
- **A document a tool parses from text is estimated before it is parsed** (#3381), on both transports:
  `check_sbom`'s `sbom` passed as a string, and `scan_manifest`'s `package-lock.json`, `npm-shrinkwrap.json` and
  `composer.lock`. One past what a document's parse may take is not read ("too dense to read"), naming its counts,
  its estimate and the bound in force: `check_sbom` refuses the call `invalid_input`; `scan_manifest` lists that file
  in `data.manifest.files` with `read` false and `refused` saying so, reads the call's other files, and answers
  `invalid_input` only when no file could be read. A real SBOM or lockfile is within it, and a local server's bound
  is proportionally larger than the hosted endpoint's (Changed, above). On the hosted endpoint, what its parse would
  hold, and each entry `scan_manifest` will take from it, is held in the same budget from before it is parsed until
  it has been read, and then what the answer keeps of it, until the call ends; a request's tool reservation takes the
  request's place among those that wait, so a request that began first is not held up by a later one, and one of a
  request within the 64 KiB cap takes its share. Two answers say why a document was not read: a call that finds no
  room within the wait is answered `failed`, `error.status` 503 (this server's own: `error.kind` `internal`,
  `error.path` null, and no API call made), "server busy", which is not a finding, and the same call can be read once
  the instance has room (its access line says `refused` `doc_busy`); one whose read, with what its request already
  holds (its body, and in a JSON-RPC batch its other calls), would pass three quarters of the budget (Changed,
  above) is refused `invalid_input` at once, naming the bound and what to do, and retrying it will not help
  (`refused` `doc_too_large`). Through 3.1.5 a document a tool parsed from text was not weighed before
  it was parsed.
- **On the hosted endpoint, what the API's answers to `check_sbom`'s and `scan_manifest`'s purls hold is in the same
  budget, and a batch's answer is read only to the room left** (#3381). A call reserves 1,280 bytes a purl before
  its first batch is sent, and as each batch is answered, what the answers hold past that: three bytes a byte of the
  API's answer for each row's first 512 bytes, and ten bytes a byte for the rest, its matches (as measured: a match
  costs that much by the time the call is answered). Once the instance's parse budget, which holds the API's answers
  beside its requests' bodies and documents, is more than a quarter past its bound, whichever calls took it there, or
  the call's own request holds more than the 31,457,280 bytes one request may reserve (Changed, above), the call sends
  no further batch. A batch's answer is read only to what the call's reservation still covers of it and what the
  budget has left when the batch is sent, at those weights: one larger is read no further, and is dropped. That bound
  is each call's own: calls reading at once each read up to what the budget had left, so their reads together can
  pass it (#3603). Each way, the purls not sent are listed with
  `coverage.not_sent_reason` `server_busy`, not checked and not clean; where it is the call's first batch, the call is
  answered `failed`, "server busy", its `error.path` the batch route and `error.status` the API's 200, which is not a
  finding. A call whose reservation finds no room is answered "server busy" (`refused` `doc_busy`), and one that
  could never be granted is refused `invalid_input`, as a document is. Through 3.1.5 nothing weighed it: 64 calls of
  2,000 purls each, at once, could end the process, and so could one call of 200 purls whose batch answer came to
  about 26 MB, read and parsed whole. Measured under the hosted image's heap flags in a 256 MiB memory cgroup: one
  call of 2,000 purls whose rows hold ten matches each now stops after its second batch, and one of three a row after
  its fifth, once its request passes the bound; a batch answer of 10.7 MB or 40 MB is not read; and 16 or 24 calls at
  once of 4.3 MB answers, the API answering each batch in 0.3 to 3 seconds, are all answered with the process alive
  (3 runs each, peak 224 to 261 MB). Answers that all arrive at the same moment, from 16 or more such calls, can still
  end the instance (1 of 10 runs at 16 where each answer arrives in one write, none of 3 where it arrives in
  pieces; every run at 24): that is #3603.
- **A `Cargo.lock` or `poetry.lock` is estimated before it is read** (#3381), on both transports, beside 3.1.3's
  per-call bounds (#3434): one estimated past what a file's read may take is not read ("too dense to read"), as
  above, and its reader counts what it builds as it builds it and stops, unread, past what was estimated of it. On
  the hosted endpoint each entry `scan_manifest` will take from a call's files is counted before they are read, as
  its reader will read them (its byte-order mark dropped, a TOML header written with an escape counted), and
  reserved with what their parse would hold. Each such count and estimate takes time linear in the text it reads.
  Through 3.1.5 what a TOML lockfile's read held was bounded only by its count of values, #3434's per-call bound.
  Repository only: `test/parse-budget.test.mjs` times every estimate and reader on single lines of 300,000
  characters and more, each shaped at a pattern's own quantifiers, in a process started with the hosted image's heap
  flags (each within 100 ms), and `test/http-parse-budget-round4.test.mjs` probes `/health` while such a Cargo.lock
  is served by `dist/http.js` started as its image starts it (each probe within 1 s).

### Security

- **Every name and version `scan_manifest` takes from a file is bounded before anything is split from it** (#3460).
  Each reader's names and versions (package-lock.json and npm-shrinkwrap.json v1 to v3, Cargo.lock, poetry.lock,
  composer.lock, Gemfile.lock, gradle.lockfile, and those of requirements.txt and go.mod, whose lines 3.1.3 already
  bounds) hold at most 512 characters, the longest purl a call sends, before anything splits, matches, encodes or
  replaces in them; an entry past that is listed in `data.not_checked` as `unsupported_line` ("a name or version of
  more than 512 characters, which no purl the API checks holds: not read"), and the call's other entries are read.
  So is an entry whose name and version are within that but whose purl, percent-encoded, is longer (a `%` is three
  characters there, a CJK character nine): it is listed as `unsupported_line` ("its purl, percent-encoded, is longer
  than the 512 characters the API takes: not read") at its own place, with its name and the file's text for it, its
  purl's length counted and no purl built for it, and the call's other entries are read; a go.mod `replace` whose
  replacement's purl is so is listed at the require it applies to, naming the replace, and not as applied. An entry
  whose name or version holds a lone surrogate (half of a UTF-16 pair, which a JSON lockfile's `\ud800` gives) is
  listed the same way ("a name or version holding a lone surrogate (half of a UTF-16 pair), which no purl can encode:
  not read"); through 3.1.5 it failed the whole call, which blamed the API.
  Through 3.1.5 such a purl was kept and refused the whole call (`invalid_input`, "purl N is longer than 512
  characters", an index no file or line maps to): a requirements.txt pin of 200 `%` between two others did that,
  where now the two are checked.
  Gemfile.lock's version and gradle.lockfile's coordinates are taken by cutting at the first `-` and `=`, not by
  splitting. Through 3.1.5 a package name was split on each `/` with no bound: one keyless call of 4.9 MB, a
  package-lock.json whose one name was about 4.9 million `/`, ended the hosted endpoint's container (heap out of
  memory, exit 139), where the same call of `a` was answered (`invalid_input`: its one purl past 512 characters); a
  composer.lock name of `/` did the same. A Cargo.lock, poetry.lock or Gemfile.lock name of `/` was split into
  millions of strings too, and the call then refused whole for its purl past 512 characters, where now only that entry
  is not read; a Gemfile.lock version of `-` and a gradle.lockfile line of `=` were split the same way. With this, what a call's files make the
  server build is bounded per call, as 3.1.3 said but did not yet hold (Corrections, below): by its per-call line and value bounds, the 2,000 entries
  `data.not_checked` lists, the 200 characters of each string an entry carries, the 200 of the go directive a note
  names and the 40 of a `lockfileVersion` a reason names, and the 512 of each name, version and purl. Through 3.1.5 a
  `package-lock.json`'s `lockfileVersion` was named whole in the reason its file was not read: one of 3,100,000
  characters made an answer of 31 MB, and three such calls whose clients did not read their answers ended a 256 MiB
  instance; now a string is named in at most 40 characters, and an object or an array by its type.
  A blank requirements.txt line outside a continuation is now passed over before any pattern runs on it: 4,999,000
  blank lines take about 50 ms of the event loop, where through 3.1.5 they took about 520 ms (measured under the
  hosted image's heap flags; one line of as many characters takes about 4 ms); a Gemfile.lock spec whose
  version is past the bound is listed by its name, as the other readers list theirs; and a package-lock.json
  `lockfileVersion` past what a double holds (`1e400`) is named so in its refusal, not as `null`.
  Repository only: `test/manifest-lines.test.mjs` reads such a file of each format in a process started with the
  hosted image's heap flags, and sends the 4.9 MB call and its control to `dist/http.js` started as its image starts it.
- **A `Cargo.lock` or `poetry.lock` key never reaches the server's shared objects** (#3460). Through 3.1.5 the TOML
  reader's tables were plain objects: a 30-byte `Cargo.lock` of `[__proto__]` and `hasOwnProperty = 1`, in one keyless
  call, wrote that key onto every object's prototype, and every later request to the hosted instance failed (HTTP
  500) while `/health` answered 200; `link = true` there made every later caller's `package-lock.json` entries
  `local_path`, not checked. Now no table the reader makes has a prototype, each key is looked up as the table's own,
  and a key named `__proto__`, which no crate or PyPI name can be, makes the file unreadable on its line ("a key
  named __proto__, which no lockfile writes"); a key named `constructor` or `prototype` (PyPI has packages of both
  names) is read as any other. A file whose basename is `__proto__` or `constructor`, which failed the whole call
  for its outputSchema, is refused as a name this tool does not read, and the call's other files are read.

### Corrections

- **Correction to 3.1.2's entry** (#3381). It said the bound on a tool call's arguments (CVE-2026-111768) did not
  yet hold for the hosted endpoint, because a hosted request body was parsed whole before that bound counted
  anything and that parse was not bounded, and that a fix was in progress. The fix is above. On the hosted endpoint
  a body's parse is now bounded before it starts, every body's and all of those in flight together, and so is what a
  tool parses or reads from text; so that bound now holds for the hosted endpoint too, more tightly than over stdio:
  a body is refused by what parsing it would hold before the SDK counts its elements, which can refuse a shape the
  SDK's count would admit (docs/structured-results.md).
- **Correction to 3.1.3's entry** (#3460). It said that what a call's files make the server build is bounded per call.
  It was not, through 3.1.5: a name or version a reader took from a file was split with no bound on its length, so one
  keyless call of about 4.9 MB (a package-lock.json name of `/`) ended the hosted endpoint's container (Security,
  above). With this release's bound on every name and version, it holds.

## 3.1.5 — 2026-11-07

The hosted endpoint's image moves to a patched base; the package's code is 3.1.4's, unchanged.

- **The Docker images' base is node 22.23.4 on Alpine 3.24** (`node:22.23.4-alpine3.24@sha256:0e1754758c2d…`,
  in `Dockerfile` and `Dockerfile.http`). The 22.23.3 base carried three HIGH vulnerabilities with fixed
  versions in its own packages (CVE-2026-107891 in musl and musl-utils 1.2.6-r2, fixed in r3;
  CVE-2026-85091 in zlib 1.3.2-r0, fixed in r1), and the hosted deploy's image scan refused it. The
  hosted endpoint is built from a published release's bytes only, so the move is released here. The npm
  package does not ship a Dockerfile: installing 3.1.5 runs exactly 3.1.4's code.

## 3.1.4 — 2026-11-07

`vendor_advisories_for_cve` no longer reads GitHub as fully held for a CVE year from 2018 now that
GitHub's reviewed-only history read is done (#3472). Two `outputSchema` fields are added to each
vendor window and `history_backfill` names one more value; no type or `required` changes, and no
client needs to reconnect (below).

- **A history read that covers only part of a vendor's advisories** (#3472). EchelonGraph's
  coverage API reads GitHub's history back for its reviewed advisories only (#3443): once that read
  is done, GitHub's `history_backfill` is `complete_reviewed_only` and its `held_since` the earliest
  advisory held (2017-10-24 in production's coverage answer of 2026-11-07), while its unreviewed
  advisories, not read back, are held only from the start of its feed's own window,
  `feed_held_since` (2026-05-15). The API serves `history_scope` (`all`, or `reviewed`) and
  `feed_held_since` beside it, and the server read neither: `complete_reviewed_only` was not a
  history still being read and `held_since` was before every year from 2018, so
  `vendor_advisories_for_cve` left GitHub out of `vendors_not_fully_held` for a CVE ID of 2018 or
  later, which said every GitHub advisory for that CVE was held, where an unreviewed one published
  before 2026-05-15 may not be. A vendor whose `history_scope` is a part of its advisories is now
  listed for a CVE ID whose year begins before its `feed_held_since`, or when that is not known, and
  the note gives both dates: "github (reviewed advisories held from 2017-10-24 to …; unreviewed
  advisories held only from 2026-05-15)". The year compared is the CVE ID's: a CVE-2026 ID's year
  begins on 2026-01-01, before 2026-05-15, so GitHub is listed for it too. `search_vendor_advisories`
  and `get_vendor_advisory` name such a vendor in their note, and while its read is in progress the
  note's item says it reads its reviewed advisories only. An answer that says
  `complete_reviewed_only` without `history_scope` is read as `reviewed`, never as a complete read,
  and against an API without the two fields every window reads as before.
- `outputSchema`: each vendor window (`coverage.vendor_windows[]` of `vendor_advisories_for_cve`
  and `search_vendor_advisories`, `coverage.vendor_window` of `get_vendor_advisory`) adds
  `feed_held_since` and `history_scope`, each a string or null (null from an API without them), and
  its `history_backfill` lists `complete_reviewed_only` beside its other values and any string. The
  descriptions of the window, `held_since`, `history_backfill`, `vendor_windows` and
  `vendors_not_fully_held` say what the two fields mean. A success's schema is open, so a client
  holding an older tool list takes the added fields. The failure branch's window objects, which stay
  closed, add them too (`test/schema-compat-allow.json`), but no failure carries a window: a failure's
  `coverage` is null.
- Descriptions: `vendor_advisories_for_cve`'s says `vendors_not_fully_held` also lists a vendor whose
  `feed_held_since` is after 1 January of `cve_year`, outside its `history_scope`;
  `search_vendor_advisories`' and `get_vendor_advisory`'s name `history_scope` and `feed_held_since`
  among a window's fields.
- README: what a vendor window holds is said in brief, with the `history_scope` rule; the detail
  moved to docs/tools.md, "How the vendor-advisory tools read each vendor's window".

## 3.1.3 — 2026-11-01

`scan_manifest`'s go.mod, requirements.txt, Cargo.lock and poetry.lock readers now take time linear in
what they read, and what a call's files make the server build is bounded per call: a call whose files
pass one of the new per-call bounds is refused (`invalid_input`, naming the bound and each file's count),
and none of its files is read (#3434). `inputSchema`: `files[].filename` has `maxLength` 1024 and a
`pattern`. No `outputSchema` type or `required` changes; the descriptions of five of its fields change
(`data.not_checked` and its `name`, each file's `not_checked` and `replaced`, `coverage.not_checked`),
and the tool's description says what `data.not_checked` lists and what a call refuses.

- **go.mod** (#3434). Each line is read in time linear in its length. A line of more than 16 tokens, or
  of more than 65,536 characters from its first token to its comment (no directive holds more than six
  tokens, nor a module path, version or directory near that length), is listed in `data.not_checked` as
  `unsupported_line` with its line number, and the rest of the file is read.
- **requirements.txt** (#3434). A logical line of more than 65,536 characters, its continuation lines
  joined (a requirement with every `--hash` pip-compile writes for a release is some tens of thousands),
  or with a version specifier of more than 64 clauses, is listed as `unsupported_line`; a comment and a
  `name @ url` requirement are found in time linear in the line. Every other line is read as before.
- **Cargo.lock and poetry.lock** (#3434). A string is built from slices of the file, joined in chunks. An
  escape of no Unicode scalar value (past U+10FFFF, or a surrogate), arrays or inline tables nested more
  than 64 deep, and a dotted key or table header of more than 64 parts make the file unreadable: it is
  reported as not read, with the line, and the call's other files are read (real lockfiles nest 1 or 2
  deep and have keys of 1 or 2 parts). A file that meets one of the JavaScript engine's own limits while
  it is read is reported the same way, never failing the whole call.
- **Per-call bounds** (#3434). Counted across all the files of a call: at most 40,000 lines of go.mod,
  requirements.txt, Gemfile.lock and gradle.lockfile files (blank and comment lines not counted), 300,000
  objects, arrays and entries of package-lock.json and composer.lock files (counted before each is
  parsed), and 300,000 tables, array entries and keys of Cargo.lock and poetry.lock files (each part of a
  dotted key one). Past one, the call is refused, `invalid_input` naming the bound and each file's count,
  and nothing more is read. Measured on calls of real files: GitLab's 20 largest Gemfile.locks, 15,535
  lines; 20 Gemfile.locks of five repositories, 20,778; 7 composer.locks, 128,335 values; 5 poetry.locks,
  86,205.
- **`data.not_checked` lists a call's first 2,000 entries, and counts all** (#3434).
  `coverage.not_checked`, `coverage.not_checked_by_reason` and each file's `not_checked` count every one,
  and past 2,000 the note says how many are listed and how many are counted only (the most in one real
  file measured is 598). `data.manifest.files[].replaced` lists a call's first 2,000 go.mod replaces
  applied, and the note counts them all. Every string of a file that an entry carries (its `spec`, its
  `name`, and any its `detail` names) is at most 200 characters, a character JSON writes as a
  six-character escape counted six, ending in "…" where it is cut.
- **Filenames** (#3434). A filename longer than 1,024 characters, or holding a control character (U+0000
  to U+001F), a quote or a lone surrogate, is refused, `invalid_input` naming the rule; a portable
  path holds none (Windows refuses each of them in a file name). A backslash is still read as a path separator.
- Repository only, not in the package: `test/manifest-lines.test.mjs` reads each such file in a process
  started with the hosted image's heap flags, under a timeout, so a reader that does not finish fails its
  case instead of holding the suite; and it sends such files, and files at and past each bound, to
  `dist/http.js` started as its image starts it (`test/image-server.mjs`), which answers each, two at
  once where its two large-body slots allow, and the next `tools/list`.

## 3.1.2 — 2026-10-25

The hosted endpoint no longer loses a large-body slot to a request that never ends (#3362), a TEXT
CUT names a nested list's full length (#3273), `get_cve` takes ENISA EUVD, GHSA, OSV and GCVE-0
IDs (#2868), and two corrections to earlier entries, below. No `outputSchema` type or `required`
changes.

- **`get_cve` takes an ENISA EUVD, GitHub GHSA, OSV or GCVE-0 ID** (#2868). The server sends the
  ID as asked; EchelonGraph's API resolves it to its CVE and answers that CVE's record with
  `resolved_from` (the ID asked for, its namespace, and the source that mapped it: `enisa_euvd`,
  `github` or `osv` through EchelonGraph's alias table, or `gcve_gna0`, the GCVE specification,
  under which GCVE-0-YYYY-N is CVE-YYYY-N), and the note names it. An ID mapped to no CVE is the
  API's 404, one mapped to several its 300 listing them. The record's `aliases` lists the CVE's
  other IDs, and `eu_kev` its listing on ENISA's EU Known Exploited Vulnerabilities catalogue,
  with ENISA's date, the reporting source ENISA records and ENISA's attribution; the note names it as ENISA's
  data. Every value of ENISA's EUVD (an EUVD ID in `aliases`, a `resolved_from` mapped by
  `enisa_euvd`, the `eu_kev` listing) carries the attribution "Source: ENISA EUVD", and each
  sentence of the note that names ENISA's data ends with it, also where an older API answer sent
  no `attribution`. The other CVE tools' `cve_id` stays a CVE ID. get_cve's `inputSchema` changes
  in its `cve_id` description alone, which now names the IDs it takes; its type and `required` are
  unchanged.
- `search_cves` with an EUVD, GHSA, OSV or GCVE-0 ID as its search lists exactly the CVEs it names,
  with `resolved_from` on the page, and the note says so.
- The CVE feed's `method` says that ENISA EUVD identifiers resolve to their CVE.
- **get_cve words ENISA's EU KEV in the score** (#2868, EchelonGraph scorer v4.1). Where ENISA's EU
  Known Exploited Vulnerabilities catalogue lists a CVE CISA's KEV catalog does not, the API's
  score is floored at 9.0 by rule `eu_kev_exploitation`; the note then says the 9.0 comes from that
  listing ("an ENISA EU KEV listing floors it at 9.0 (Source: ENISA EUVD)"), exploitation and not
  impact, as it says of a CISA KEV floor, and an EU-listed CVE with no CVSS reads "exploited (ENISA
  EU KEV; Source: ENISA EUVD) and no CVSS severity is published yet". The outputSchema's
  descriptions of `eg_severity` (`eu_kev_listed_no_cvss`), `eg_likelihood` (`exploited_sources`
  `eu_kev`) and `score_factors` (`eu_kev`, `unknown_eu_kev_most_urgent`) name the listing. No
  type, `required` or `inputSchema` changes; an answer scored before v4.1 reads as it did.
- README: the Smithery link says what the listing is now, a registry entry for
  `https://mcp.echelongraph.io/mcp`. Smithery shuts its proxy (`run.tools`, `server.smithery.ai`), API and
  CLI on 2026-10-31 (https://smithery.ai/future), so anyone who connected through a Smithery URL
  connects to `https://mcp.echelongraph.io/mcp` itself (#3356). To keep the README under its ceiling
  below npm's cut, two details that `docs/` holds in full left it: which clients cut descriptions where
  (docs/tools.md, "The client cut") and the API's own rate-limit page (docs/rate-limits.md). Nothing in
  the server or its tools changes.

- Repository only, not in the package: the production synthetic reads `cve://CVE-2021-44228` on
  both the npm package and the hosted endpoint, once per protocol era, and its probe line
  (`resource:cve`) carries the text's size, `text_chars`, into the size series and the 45,000
  alert (#2781). Its text, get_cve's record cut by the resource's own construction since #2801
  (20,132 characters on 2026-10-25), was read by nothing in production. The line fails on an empty
  read, an error read (the JSON-RPC error the resource answers a failed lookup with) and a text that
  is not the CVE's record, and is `not_listed` where the server's version is 2.5.0 or later and
  `resources/templates/list` does not name `cve://{cve_id}`.
- Repository only, not in the package: the production synthetic also makes each
  `test/text-bound.mjs` SHAPED case's own call that no other probe makes, on the hosted endpoint,
  once per run (lines `size:<tool>/<input>`, `synthetic/probes.mjs` `SIZE_PROBES`, 13 calls). The
  five cases with `live` set are left out: three would pass the API's 1,200 components a minute per
  caller, and two are forced cuts that no answer reaches. These
  are the default and largest pages, the heavier check_affected lookups, the Juice Shop SBOM and
  the 64-package lockfile. The answers that cost a client most now reach the size series and the
  45,000 and 30,000 alerts, not only an operator's `npm run text-bound:live` (#2781's review). On
  hosted 3.1.1 (2026-10-25), kev_recent at limit 200 was 29,965 characters of structuredContent,
  and search_vendor_advisories' default page was 35,029 characters of text. The probes' own small
  inputs measured 29,609 and 11,615. No size probe's body is past 64 KiB, so none takes a
  large-body slot (#3362). The image copies the two files they send (`synthetic/Dockerfile`,
  `.dockerignore`).

- Repository only, not in the package (#3273): the production record
  (`test/fixtures/text-bound-live.json`) is re-read from the hosted endpoint at 3.1.1
  (`text-bound-live.mjs --hosted --record`, 2026-10-25T16:09:36Z) and committed as the harness
  wrote it. Beside each case's `data_truncated` and `truncated` it holds `kept_fields`, the fields
  each thinned list's entries keep, so production's cut level is measured, not read off a size:
  search_cves' default page keeps 12 fields a row and no description, the second level, as the
  case here does, and a new test holds every case whose list production thins to the fields
  production's entries keep. check_sbom's Juice Shop case replays production's own 50 rows
  (`prod-shaped/check_sbom.json`'s `juice_shop`, hosted 3.1.1 with `full: true`): 25,225 characters
  of `structuredContent` against production's 25,223, where it repeated every 5th of them to 50,
  21,262 against 24,884. get_cve's case replays production's answer whole
  (`prod-shaped/get_cve.json`, hosted 3.1.1 with `full: true`, its 20 `cpe_configurations` among
  it): 20,268 characters of text, as on record, where 2.6.2's answer repeated measured 24,876
  (+22.7%). On it, get_cve's text keeps the first 8 of 103 references, none tagged Vendor Advisory
  or Patch, so `triage_cve`'s Patch line points to the vendor advisories for this CVE, which
  prompt-fields.test.mjs now holds (it read the tagged references the old answer's text kept as
  production's). One drift stays open, named and pinned in `TEXT_DRIFT_KNOWN` and
  `STRUCTURED_DRIFT_KNOWN`: cve_summary measures the answer kept from 2026-10-05, 2,725 characters
  of text and 2,565 of `structuredContent` against production's 3,209 and 2,986 on record (-15.1%,
  -14.1%), production's answer now carrying `nvd_poll` and one API instance's poller counters, and
  `npm run text-bound:live -- --hosted` is red on it until the kept answers are re-read with
  `scripts/probe-prod.sh`.

- Repository only, not in the package: the production synthetic's hosted-versus-npm comparison
  (#3097) also compares the resource templates, as `resources/templates/list` gives them, by
  `uriTemplate`. `cve://{cve_id}` is listed only there, never in `resources/list`, so a hosted
  build whose template's description, title or mimeType differs from npm's, or that drops it, was
  read as identical; it now fails the `(hosted-vs-npm)` line (`resource template cve://{cve_id}:
  description differs at character N`), and the line counts `compared_resource_templates`.
- Repository only, not in the package: the stdio client the suite and the production synthetic
  open the npm package with (`test/mcp-stdio-client.mjs`) rejects a request the server can no
  longer read (#3389). A server that had exited, before its exit was noticed, or had closed its
  stdin made the write fail with EPIPE. The client did not handle that error, so it was an uncaught
  exception: it failed whichever test was running (once, in a loaded full run on 2026-10-25), and
  in the synthetic it would crash the run rather than write the `(session)` failure line. The
  request is now rejected at once: with the server's exit where that is already known, else with
  the write's error. It is no longer left to wait for an exit, or the timeout, that may not come.

### Fixed

- **On the hosted endpoint, a request that never ends no longer holds a large-body slot for good**
  (#3362). On 2026-10-25 the hosted endpoint's 3.1.1 revision (its one instance, two slots) lost
  one of its slots and kept serving with the other: of two 2025-era `check_sbom` calls their client
  aborted at 1.5 s, one never wrote its access line, and from then on two large bodies sent together
  ran one after the other (the second's `slot_wait_ms` 788). Through 3.1.1 nothing bounded how long
  a request could take, so a request that never ended held its slot until the instance went. Which
  way that call hung is not settled: an `mcp_client_gone` line was written 56 ms after the other
  call's access line, and it does not say whose it was. Its body may have stopped coming with no
  reset reaching the server (`node:http2` has no request timeout, and on 2026-10-05 the resets of two
  aborted calls reached it behind Cloud Run only when their answers were written), or its reset may
  have arrived and the call run on. Each is now bounded:
  - A body that sends no byte for 10 s while it is read (`MCP_BODY_IDLE_MS`; a wait for a slot is
    not counted) is ended: answered 408 (JSON-RPC -32600), logged `refused` `body_stalled`, its slot
    given back. That is under the 15 s a large body waits for a slot, so a client that retries at
    once is served. Over HTTP/1.1 too, where Node's own `requestTimeout` ended such a socket at 300 s.
  - Every request is over by 60 s (`MCP_REQUEST_TIMEOUT_MS`, Cloud Run's own request timeout). It is
    then stopped as a client's going stops it, its slot and its place are given back, and its one
    access line is written, `refused` `timeout`, whether or not what it was doing ever settles. That
    line's status is 499 with `client_closed` if its client had gone first; else 504 if its answer
    had not ended, a status for the log only (no answer is sent: its stream, or over HTTP/1.1 its
    connection, is reset); else the status it was answered with. What it settles with later is
    neither logged nor given back again: a slot given back twice, while another call held the other
    one, let a third large body in on two slots.
  - `check_sbom`'s and `scan_manifest`'s wait for a 429's `Retry-After` also ends when the hosted
    request's own signal aborts. For a 2025-era request the SDK follows a copy of the request whose
    signal Node holds only weakly, and after a garbage collection it no longer followed the client's
    reset: a call whose client went waited out its `Retry-After` holding its slot (19.5 s of a 20 s
    wait, under forced collection; now its access line comes within 100 ms of the reset).
  - **The access line says how long the oldest large-body slot has been held**: two numbers about
    the instance, not the request. `large_body_held` is the slots held as the line is written, and
    `large_body_oldest_hold_ms` how long the oldest of those has been held (0 when none is). Every
    hold now ends by its request's 60 s, so one far older is a slot no request will give back,
    whether its request was being served or not. The leak wrote no line; had 3.1.1 written these,
    every line on that revision after 13:03Z, `/health`'s and served calls' alike, would have read at
    least 1 and an age that only grew. EchelonGraph's monitoring of the hosted endpoint alerts once
    a line reads past 5 minutes. `mcp_remote_listening` also logs `body_idle_ms` and
    `request_timeout_ms`.

  The npm package (stdio) is unchanged.
- **A TEXT CUT that keeps only the first entries of every list gives a list inside list entries its
  full length** (#3273), as get_cve's does and the `cve://` resource's DATA CUT. Its sentence
  "Every list in it keeps at most its first N entries: …, each named with its full length", and the
  resource's `truncated`, gave such a list the length of the longest in the entries kept, not in the
  answer: CVE-2021-44228's record (2026-10-25) holds a `cpe_configurations[].nodes[].cpeMatch` list
  of 154 entries in its 16th configuration, and 3.1.1 said 63 at 8 kept. It now counts the lists of
  the entries left out too. No schema changes.

### Corrections

- **Correction to 3.1.1's entry** (#3381). It said CVE-2026-111768 is fixed. That holds for the npm
  package, which runs over stdio. It does not yet hold for the hosted endpoint
  (`https://mcp.echelongraph.io/mcp`): a hosted request body is parsed whole before the bound on a
  tool call's arguments counts anything, and that parse is not yet bounded. A fix is in progress
  and is not in 3.1.2. Until it ships, a deployment that must hold that bound runs the npm package.
- **Correction to 3.1.0's entry** (#2923). It said a read of production since 3.0.2 found one
  hosted handler error with code -32022 classed `other`. That read found none on 3.0.2: every such
  line was logged by the hosted 3.0.0 revision, the newest at 2026-10-17T18:16:43Z, before 3.0.2's
  revision went live at 19:08Z, and none of the 142 lines 3.0.2's hosted revision logged was
  `other`. 3.1.0's code fallback is unchanged.

## 3.1.1 — 2026-10-25

A security release (#3345). It moves the runtime dependencies past three advisories, bounds what
a tool call's arguments may hold, and takes npm out of the hosted endpoint's image. The hosted
endpoint's 3.1.0 image was refused by its deploy-time Trivy scan (#3018: 13 HIGH with a fixed
version), so the endpoint kept serving 3.0.2. No `outputSchema` changes, so a client holding
3.1.0's tool list does not need to reconnect; only the three `inputSchema` bounds below are new.

### Security

- **@modelcontextprotocol/server 2.1.0 to 2.3.0** (CVE-2026-111768, CVSS 7.5; CVE-2026-111770,
  CVSS 7.7), with @modelcontextprotocol/core 2.3.0. Both stay exact pins, as does zod below.
  - CVE-2026-111770 (a server or transport shared between connections delivered one client's
    messages to another): **not affected**, on either transport. The hosted endpoint builds a new
    server for each request (`createMcpHandler` with `createServer` as its factory), and stdio one
    per connection (`serveStdio`), which the advisory names as not affected. 2.3.0 refuses a shared
    server outright (`ALREADY_CONNECTED`); a test holds that 30 clients one after another and 30 at
    once, in both protocol eras, over the hosted endpoint and over stdio, are each answered with
    their own record.
  - CVE-2026-111768 (validating an unbounded array or object in a tool call's arguments exhausts
    memory): **mitigated, now fixed**. Through 3.1.0 only the hosted endpoint's request-body cap
    (64 KiB, or 6 MiB for `check_sbom`, `scan_manifest` and `sbom_review`), the advisory's
    stopgap, bounded it, and nothing did on stdio. The server now sets the SDK's new
    `maxToolInputElements` to 2,500,000 list entries and object members per call, counted at every
    depth: the most any tool accepts, a `check_sbom` document passed as an object at its
    5,000,000-character cap, so no call a tool would answer is refused by it. A call over it is
    refused by the SDK before any tool runs, with `isError` true and one text block of the SDK's
    own ("Invalid arguments for tool <name>: arguments contain more than the maximum of 2500000
    elements"), and without `structuredContent`: the SDK offers no way to answer it in the
    envelope (docs/structured-results.md).
  - A third advisory 2.3.0 fixes, GHSA-rvq5-wwqv-78pq (bearer authentication accepted a token
    issued for another service), does not apply: this server uses no authentication.
- **zod 4.6.5 to 4.6.6** (CVE-2023-54404, GHSA-mrhx-c7xc-m3w5, CVSS 7.5). 4.6.6 checks a list's
  bound before it parses an element of it, but only where the list has a bound. Every list and
  record in a tool's `inputSchema` now has one, published in `tools/list` as `maxItems` or
  `maxProperties` and checked before any element is read: `check_sbom`'s `purls` at most 10,000
  entries, its `sbom` passed as an object at most 64 top-level members
  (CycloneDX 1.6 defines 18 and SPDX 2.3 16), and `scan_manifest`'s `files` at most 20 (the
  README's 1 to 20). A call past one is refused with `state` `invalid_input` and a note naming the
  bound: `purls must hold at most 10000 entries`, `sbom must hold at most 64 members`, `files must
  hold at most 20 entries` (through 3.1.0, "21 files; at most 20 are read per call"). The
  `purls` bound counts entries, repeats included, not distinct purls. The README's 2,000 is the
  distinct purls a call checks: that rule is unchanged and still `check_sbom`'s own (more than
  2,000 distinct, in a list or a document, is refused with the same message as through 3.1.0). A
  list may repeat a purl, as a flattened SBOM does once per install path, so the entry bound is
  five times the distinct one. Of `purls` lists, one kind 3.1.0 accepted is newly refused: a list
  of more than 10,000 entries, which 3.1.0 checked when it held at most 2,000 distinct purls, each
  sent once. That is inherent in bounding a list that had no bound. A list of up to 10,000
  entries is answered as through 3.1.0. Over the hosted endpoint a `check_sbom` call may be a 6 MiB body,
  which 10,000 entries of even the longest purl the API takes (512 characters) fit.
- **Hosted endpoint only: its image carries no npm** (#3018). The node base bundles npm, npx and
  corepack, which this server never runs, and its npm carried 10 of the 13 HIGH the scan refused
  3.1.0's image for: brace-expansion 2.0.2 (5), ip-address 10.1.0, pacote 19.0.2 and 20.0.1,
  picomatch 4.0.3 and sigstore 3.1.0; the other 3 were the SDK's two and zod's. The image's
  runtime stage (Dockerfile.http) now removes npm, npx and corepack, and its build fails if any is
  left; its base digest is unchanged. Trivy v0.75.0 (the scan's pinned scanner) finds the 13 on a
  copy of 3.1.0's runtime file system and none on 3.1.1's (2026-10-25). The npm package and the
  stdio image (Dockerfile, for the Docker MCP Catalog) are unchanged by this.

### Changed

- **Hosted endpoint only: a 2026-07-28 `subscriptions/listen` stream ends right after its
  acknowledgement**, with a `complete` result. SDK 2.2.0 ends a listen stream that honours none of
  the notification types asked for, and this server sends none (it declares no `listChanged`).
  Through 3.1.0 the stream stayed open, carrying only keepalives, until the client left. A listen
  still takes none of the 64 places an instance serves at once. Over stdio a listen is unchanged.
- The SDK's packages declare the Apache-2.0 license since 2.3.0 (their LICENSE file carries the
  MIT terms of earlier contributions too); echelongraph-mcp stays MIT.
- **workload_triage's step 4 sends each purl once** (#3345): it has the agent pass several images'
  purls in one `check_sbom` call, and images share packages, so such a list can repeat purls. The
  step now says to send each purl once, and that a list holds at most 10,000 entries, the new
  `purls` bound above.

## 3.1.0 — 2026-10-25

- **cve_summary's `freshness` is the fleet's last completed NVD poll** (#3276). Since #3242 the
  summary answer carries `nvd_poll`: `last_completed_at`, when the fleet of API instances last
  completed an NVD poll, with `scope` `fleet` and the poll's `interval`. cve_summary relayed the
  block in `data` but answered `freshness: null`, and its note, its description and the
  methodology resource said the feed serves no poll-completion time. `freshness.nvd_poll` now
  holds `last_run_at`, the block's `last_completed_at` as sent, `scope` `fleet` and `interval`
  (production, 2026-10-17: `2026-10-17T22:45:09Z`, `fleet`, `20m0s`), and the
  envelope's note says it is the fleet's poll, never the answering instance's
  `poller.last_poll_at`. It is relayed only as a real RFC 3339 time at most 5 minutes after this
  server's clock, on a block whose `scope` is `fleet`; `interval` only as a Go duration, else
  `null`. An answer without `nvd_poll` (an older API, or one holding no fleet poll it could read) keeps
  `freshness` `null`, and the note says this answer carries no `nvd_poll` block, not that the feed
  has no poll time; a block without a usable time keeps it `null` too, says why, and is still
  relayed in `data`. A poll more than three of its intervals old (or more than an hour, with no
  usable `interval`) is said to be old: the note gives its age and says the CVE counts may lag
  NVD by about that much. search_cves' and get_cve's note and description now say their answer carries
  no poll-completion time. The outputSchema's `freshness` admits the new object and still `null`:
  a client that listed the tools under 3.0.2 validates cve_summary against `freshness: null`, so
  it fails cve_summary's answers until it reconnects (Claude Code: `/mcp`, then reconnect).
- **exposure_radar relays the window over the dated rows, when some counted rows have no time**
  (#2438). A radar's observation window was relayed as `window` only when every counted row
  carried an observation time; otherwise nothing was relayed and the note said how many rows
  carried none. On 2026-10-17, 26,855 of kev_exposure's 66,756 counted pairs were undated
  (stored before banner times were captured), and those pairs can stay undated while the InternetDB re-check
  keeps them on record, so its answers gave no observation time at all. `window` keeps its
  meaning. Beside it, `dated_window` `{from, to, undated}` now carries the span over the dated
  rows only, with the count of those without one, for kev_exposure, exposed_databases,
  leaked_credentials and shadow_ai's confirmed_exposed. The note names both numbers (for
  kev_exposure, the dated pairs out of `correlations`) and says the span does not describe the
  undated rows. `state` stays `not_assessed` and `measured_at` `null`, as the 2026-10-04 decision
  requires. Every count is unchanged. `dated_window` is a new field under objects 3.0.2 publishes
  closed, so a client that listed the tools under 3.0.2 needs to reconnect.
- **A success's `outputSchema` is open at every level, not only at its root** (#3268). 3.0.2 opened
  the root alone (#3121). Below it, 86 objects still published `additionalProperties: false`: 40 in
  `data` (exposure_radar's and cve_intel's `data` itself among them), 23 in `coverage`, 7 in
  `freshness`, and each tool's `truncated` entry. 12 string enums admitted no other string, among
  them scan_manifest's `manifest.files[].format` and `not_checked[].reason` and exposure_radar's
  `kev_exposure.newest_kev[].exposure_state`. A client holding a release's tool list refused a field
  added under any of those objects, or a value added to any of those enums, on every call of that
  tool until it reconnected, and 2.6.3 and 2.7.0 each added such fields. A success's `outputSchema`
  is open at every level: each object admits fields it does not name, and each enum but `state` any
  string beside the values it lists. The failure branch keeps every object closed, and every enum
  but four, which already accept any string: `coverage.not_assessed_reason` (check_affected),
  `coverage.vendor_windows[].history_backfill` (vendor_advisories_for_cve, search_vendor_advisories)
  and `coverage.vendor_window.history_backfill` (get_vendor_advisory). The server still checks its
  own answers against the closed schema each tool builds, and so does the test suite.
  `test/open-success.test.mjs` fails the release run on any closed object or enum in a success
  branch of `tools/list`, and `test/schema-compat.mjs <old> [<new>]` lists what a candidate adds
  under an object, or to an enum, that the release before it closed. The opened schema is built
  once per process and shared by every server the hosted endpoint builds per request.
- **A success's null-only `coverage` and `freshness` are published as `null` or an open object**
  (#3268's review). 3.0.2 published `freshness` as `{"type": "null"}` in 14 tools and `coverage` so
  in cve_summary and get_cve, so a client holding a release's list refused the object a later
  release put there, as 3.0.2's clients refuse cve_summary's `freshness` now (#3276). In this
  release those 15 slots (cve_summary's `freshness` now has its own schema) admit an object too,
  while the server still answers `null` in each, as before. `test/open-success.test.mjs` finds a
  success slot that admits only `null`, and `test/schema-compat.mjs` reports a type a candidate
  widens at any node (`null` to `null|object`, a field made nullable, an integer made a number),
  besides a field or value added. `scripts/npm-publish-mcp.sh`'s dry run runs it against npm's
  latest and fails on any finding `test/schema-compat-allow.json` does not accept with a reason.
- **A client that listed the tools under 3.0.2 or older must reconnect once** (Claude Code:
  `/mcp`, then reconnect `echelongraph`), or it refuses these answers, which its list's closed
  schema does not admit: cve_summary's (`freshness.nvd_poll`, #3276), epss_history's (`coverage`'s
  `runs_undated`, `refresh_runs_truncated` and `days_in_progress`, #3143) and exposure_radar's where
  it relays `dated_window` (under `kev_exposure`, `exposed_databases`, `leaked_credentials` and
  `shadow_ai.confirmed_exposed`, #2438). `test/schema-compat.mjs` against npm 3.0.2 finds these and
  the 15 slots above, which are not refused: they are still answered `null`. From 3.1.0 on, a field
  or value added to a success does not need a reconnect.
- README Versioning, and the 3.0.2 entry below, said each tool's `data` schema stays closed
  (#3257). In 3.0.2 `data` was open at its root for 14 of 16 tools (closed for exposure_radar and
  cve_intel), and objects below a success's root were closed in and outside `data`. Versioning now
  says what is open and what is closed, in sentences `test/readme.test.mjs` derives from
  `tools/list`, from "Since 3.1.0": 3.0.2 and older publish their success branches closed below the
  root.
- **cve_intel counts GitHub checker repositories apart from exploit code** (#3221). #3040 defined
  an exploit-reference kind, `github_checker`, for a GitHub repository named or described as a
  checker or scanner and never as an exploit, and EchelonGraph's API does not count a reference of
  that kind as exploit code. cve_intel's note counted every reference but a Nuclei template as a
  public exploit reference, a `github_checker` one included. It now counts each reference the API
  serves as `github_checker` apart, as a GitHub checker repository, with /pulse's note that such a
  repository checks whether a system is affected and is not necessarily exploit code (beside a
  Nuclei template, /pulse's two notes in turn): 1 `github_poc` and 3 `github_checker` references
  read "1 public exploit reference and 3 GitHub checker repositories", where they read "4 public
  exploit references". The counts are the kinds the API serves: a repository it serves as
  `github_poc` is still a public exploit reference here, even where /pulse reads it as a checker.
  So for CVE-2020-35489 (1 proof of concept and 3 checkers on /pulse, 2026-10-11), cve_intel gives
  the 3 as GitHub checker repositories only once the API serves them as `github_checker`. The
  description's head says "detection checks" where it said "detection templates", the `kind`
  field's text splits the exploit-code kinds from `nuclei_template` and `github_checker`, and
  `exploits_by_kind` and the method say the same.
- **cve_intel never counts a kind it does not classify as exploit code** (#3267). It counted every
  reference whose kind was not one of its two detection kinds as a public exploit reference, so a
  kind EchelonGraph's API serves that this release predates (another scanner or template source)
  would have read "N public exploit references", the claim #3039 took out; `github_checker` did
  that from #3040 to #3221. It now counts exploit code by name (`metasploit`, `exploit_db`,
  `github_poc` and `vendor_poc`, the kinds the API counts as exploit code). A reference whose kind
  is neither one of these nor one of the two detection kinds is "of a kind this server does not
  classify": the note names the kind and counts it as neither exploit code nor a detection check.
  2 references of an unknown kind `foo_check` read "2 references of a kind this server does not
  classify", where they read "2 public exploit references", and a CVE holding one is never said to
  hold no Metasploit module, Exploit-DB entry or proof of concept. The `kind` field's text says so,
  and so do `method` and `exploits_by_kind`'s description, each now built from the same two lists
  the note counts by: `method` adds "A kind on neither list is one this server does not classify:
  the note counts it as neither.", and `exploits_by_kind` names the exploit-code kinds and what any
  other kind's count is. The kinds the API serves today are all classified, so no count changes.
- **triage_cve gives GitHub checker repositories apart from exploit code** (#3221). Its step 2
  says a `github_checker` row is a GitHub repository named or described as a checker or scanner,
  which checks whether a system is affected and is not necessarily exploit code, and its
  "Exploited?" line gives them apart, as detection checks, with Nuclei detection templates. It
  named only `nuclei_template`, so "GitHub or vendor proofs of concept" read as taking a checker in.
- **cve_exposure's outputSchema says what each KEV flag is** (#3016). `kev_listed` is deprecated:
  the same value as `kev_seen_in_observations`, the radar's observation flag, not CISA-KEV catalog
  status, so it is false for a CISA-KEV CVE the radar holds no service for (CVE-2024-3400 on
  2026-10-10: `kev_listed` false, `kev_catalog_listed` true). `kev_catalog_listed` is the catalog
  flag: true when EchelonGraph's CVE record marks the CVE as CISA-KEV-listed, and false also where
  EchelonGraph holds no record of it. The three fields had no text. `kev_listed` stays, so no
  reader breaks; the values are unchanged.
- `epss_history` relays `coverage.runs_undated` and `coverage.refresh_runs_truncated` in the
  envelope's `coverage` (#3143), and its note names each when it is not 0 or false. An undated
  refresh is one the run log holds no FIRST score date for: its file named none, or it stopped
  before recording it. The day it applied is not counted (held, partial or in progress), so a day
  the note lists as missing, or does not list, may be held for the CVEs it changed, and its points
  carry no `score_date`. Production has served `runs_undated: 1` since 2026-10-08, when a deploy killed a
  refresh mid-run, and the note said "none missing" without naming it. Both fields are `null` in
  `coverage` when the API does not say, never 0 or false.
- `epss_history` relays `coverage.days_in_progress` (#3143): the FIRST score dates a refresh that
  has not finished is applying, held for some CVEs so far. core-backend now dates a refresh's run
  row as soon as it reads the file's header, so its date is listed while it runs, and not in
  `days_partial`, which means a refresh of the date failed part-way. A retry of a date whose
  earlier refresh failed part-way is in both lists, and the note names it in both. The note never
  says nothing failed: the API reads "not finished" off the row's status and age, so a refresh
  killed minutes ago reads the same. `null` in `coverage` when the API does not say (an API older
  than #3143).
- **check_affected and check_sbom answer each CVE once per component** (#3137). OSV can publish one
  CVE for a package in two records, a GHSA and a package repository's own advisory, and
  EchelonGraph's API stored and answered each: `drupal/quick_node_block` 1.0.0 on Packagist came
  back with 4 matches for 2 CVEs, each CVE's GHSA match naming `fixed_in` 2.0.0, which the CVE's
  Drupal advisory still holds affected. The API now decides all of a CVE's stored records for the
  package together: one match per CVE, `fixed_in` 2.0.1 for both, and cve_remediation's
  installed-version answer agrees. `not_affected_count` and `undetermined_count` count CVEs, not
  advisory records (`advisories_considered` still counts the records), and the notes say so. A
  null `fixed_in` is described as no version above this one shown to be unaffected by the CVE's
  advisory records, which is not a finding that no fix exists. A record of the CVE that cannot
  decide `fixed_in` (no version data, a git commit range, or one recorded fix it is at or past)
  does not withhold it, so the same lookup at `fixed_in` can come back undetermined.
- **get_cve and search_cves type the scorer's three components** (#2879). Scorer v4.0 publishes
  `eg_severity` (the impact severity alone: the CVSS base no KEV listing, EPSS or EG-KEV tier
  raises; `assessed` false, with `unassessed_reason`, where no CVSS is published), `eg_likelihood`
  (FIRST's EPSS probability of exploitation in the next 30 days, not EchelonGraph's own model; null,
  with `null_reason`, where no EPSS is on record; `exploited` reports confirmed exploitation apart,
  never folded in) and `eg_priority` (the SSVC decision, the BOD 26-04 timeline and their inputs).
  The `outputSchema` types all three on get_cve's `data`, where `GET /cves/:id` serves them at the
  top level, and on search_cves' `data.cves[]` rows (the list route carries them in
  `score_factors`, whose description now names them); `echelongraph_score` is described as
  severity escalated by confirmed exploitation, and `echelongraph_risk`'s severity term as
  `eg_severity` from v4.0. get_cve's note adds up to two sentences, each only where the record
  carries what it reads: where the score is above `eg_severity` because a KEV listing floors it at
  9.0 or EPSS lifts it, that the rise is exploitation, not impact (for a KEV-listed CVE with no
  CVSS, that the score is the floor for confirmed exploitation, not an impact rating); and where
  `eg_likelihood.probability` is null, that the likelihood is unknown, not low. A record scored
  before v4.0 reads as before. Additive: 3.0.2 published get_cve's `data` and search_cves' rows
  open (`additionalProperties` `{}`), so a client holding 3.0.2's list accepts the fields.
- **Arguments that break a tool's inputSchema answer the full envelope, `invalid_input`** (#3015).
  The MCP SDK checked a call's arguments against the tool's `inputSchema` before the tool ran, and
  answered a failure itself: `search_cves` `{limit: 500}` came back as one text block, "Input
  validation error: Invalid arguments for tool search_cves: limit: Too big: expected number to be
  <=50", `isError` true, with no `structuredContent`, so no `state` and no notes, although the README
  says every result carries `structuredContent`. Every tool now answers such a call as it answers
  any refusal: `state` `invalid_input`, `error.kind` `invalid_input`, the envelope in the last text
  block, and notes naming each argument and the rule it broke (`limit must be at most 50`,
  `severity must be one of "Critical", "High", "Medium" or "Low"`, `cve_id is required (a string)`),
  by JSON type, never quoting a value sent, over stdio and the hosted endpoint, in both protocol
  eras. Nothing is looked up. This change leaves `tools/list` as it was: it publishes every
  `inputSchema` byte for byte as before it. Against 3.0.2, 15 of the 16 are unchanged;
  get_vendor_advisory's differs in its `advisory_id` description alone, which #3011 (below)
  rewrote to name `vendor_advisory_id` and warn off the row's UUID.
- **get_vendor_advisory says which ID to pass when given a row's `advisory_id`** (#3011). A
  vendor_advisories_for_cve or search_vendor_advisories row carries two IDs: `advisory_id`,
  EchelonGraph's internal UUID, and `vendor_advisory_id`, the vendor's own. get_vendor_advisory's
  argument is named `advisory_id` but takes the vendor's ID, and EchelonGraph's API has no route by
  the UUID, so passing the row's `advisory_id` straight on (CVE-2024-3400's Palo Alto row,
  `a68d033b-…`) answered `failed`, worded as the API holding no record, for an advisory it holds. It
  now answers `invalid_input` naming the field to pass: the row's `vendor_advisory_id`
  (`CVE-2024-3400`) as `advisory_id`. The API is still asked first, so a vendor's own ID shaped like a
  UUID is looked up as before, and any other 404 is still `failed`, as no record. Both list tools'
  `outputSchema` (and get_vendor_advisory's, which echoes it) now describe a row's `advisory_id` and
  `vendor_advisory_id`, get_vendor_advisory's `advisory_id` argument and description name
  `vendor_advisory_id` and warn off the UUID, and triage_cve's step 4 says to call
  get_vendor_advisory with a row's vendor and its `vendor_advisory_id` as `advisory_id`.
- **scan_manifest states the API's per-minute budget, and its batch numbers are checked** (#3100).
  Its description now says that a call takes at most 2,000 distinct purls and 50 seconds, that the
  API allows 1,200 components a minute per caller, and that on a 429 the tool waits out
  `Retry-After` within those 50 seconds, while a later batch cut off at them, refused or failed
  ends the call, the rest in `data.not_sent_purls`, unchecked and not clean (3.1.0's review: the
  first wording bound only the 429 wait by the 50 seconds, which bound the whole call, as 3.0.2's
  "within 50 seconds" said; the room came from shorter wording elsewhere). So from a fresh minute a
  lockfile of 1,201 to 2,000 purls answers partial by design, which the description did not say;
  started later in the API's minute, a call can wait for the next one and check more. Its list of
  `not_checked` reasons gave way to it: each reason is described in the `outputSchema`.
  The description's numbers (200 per POST, 2,000 purls, 50 seconds, 1,200 a minute) were literals
  no test read; they are now held to the constants the tool sends by, and core-backend's guards
  hold scan_manifest's batch size and budget to the API's own, as they did check_sbom's.
- **cve_remediation's first text block keeps every advisory before any list beside them** (#3272).
  #3139 fixed the cut order of `structuredContent.data` only. The first text block, which a client
  that passes only `content` reads, still left advisories out from the end while `fixed_branches`,
  `patches` and `fix_references` stayed whole beside them: on the recorded CVE-2023-44487 answer it
  kept 19 of 20 advisories, and with 1, 5, 10 and 16 more `fixed_branches` packages 18, 13, 8 and 2.
  Its TEXT CUT note named `get_vendor_advisory`, which needs the advisory's ID, and never
  `vendor_advisories_for_cve`. The text now cuts in `data`'s order: each advisory to its leaner
  fields first, then `fixed_branches` and then `patches` thinned to the fields `data` keeps, then
  `fix_references`, `patches` and `fixed_branches` rows leave from the end, each list emptied
  before the next loses one, and only then advisories. The note says what each list keeps and,
  when an advisory is left out, names `vendor_advisories_for_cve`, which lists every one. That
  answer keeps all 20 advisories now, beside every package, patch and reference, with 1 to 18
  more packages too. As `data` does, once `fixed_branches` and `patches` are thinned and the text
  still does not fit, each package's ranges are cut to the most that fit, every package kept: a
  package so cut carries `fixed_branches_truncated` with its total and returned, and the note
  names it and says `structuredContent.data` holds every range; only where even one range per
  package does not fit do references, then patches, then packages leave, the room they leave going
  back to the ranges. The note's fix rule, walked over a capped package's kept ranges alone, can
  name a version a range left out still holds, so the text's note and `data`'s (of a package `data`
  caps) say so and to read that package's fix with `full: true`. Before 3.1.0's review the text
  capped no ranges: with one package of N ranges first among CVE-2023-44487's 51 it kept 11 of 20
  references at 150 ranges, none at 200, no patch at 250, 25 packages at 300 and, from 400, no
  package, patch or reference in 6,347 characters. It now keeps all 51 packages, 30 patches and 20
  references from 50 to 600 ranges, the large package's ranges capped at 133 from 150 on (3.0.2's
  every-list cap kept 32 packages, each to 32 ranges, 30 patches and 20 references). `data` keeps
  all 51 throughout; the longer notes cost it a few references there (10 of 20 from 150 ranges, from
  12 or 13).
- **cve_remediation's fix rule reads a package listed under Packagist and Packagist:<repository
  URL> as one** (#3285). `fixed_branches` lists a package once per stored ecosystem string, so
  CVE-2025-48013 lists `drupal/quick_node_block` under `Packagist:https://packages.drupal.org/8`
  (fixed 2.0.1) and under `Packagist` (fixed 2.0.0). The note's rule, "the first fixed above it
  that no range of its package holds", read entry by entry, gave a Packagist 1.0.0 the fix 2.0.0,
  which the Drupal advisory still holds affected; the matcher reads both entries as one package
  and answers 2.0.1. Where such entries are listed, the note now counts them as one package, says
  that entries of one `package_name` under Packagist or Maven, bare or with a repository URL, are
  one package, and names them. A release suffix (`Debian:12`) is never folded. `data` is
  unchanged.
  - **cve_intel and the prompts read them the same way.** `cve_intel`'s `affected_packages` lists
    a package once per stored ecosystem string too, and its note's rule ("no range of the row
    holds") and the `sbom_review` and `triage_cve` fix rules took one row at a time, so the same
    1.0.0 was given 2.0.0. `cve_intel`'s note now says such rows are one package, names them, and
    states the walk over all their ranges; `sbom_review`'s rule reads a Packagist or Maven
    component's rows of its `package_name`, bare and with a repository URL, as one row, and
    `triage_cve` gives their ranges together, never a fixed that another of them still holds.
    Both give 1.0.0 the fix 2.0.1.
- **check_affected's text keeps KEV-listed and ransomware matches to the last** (#2899). Near the
  cap of 200 registry matches the text left out the last matches by rank (`effective_score`), so
  a KEV-listed match ranked low was in `structuredContent.data` only and the note said only how
  many left. Now a match whose `kev_listed` or `ransomware` is true stays in the text while any
  other match is in it, the note says so, and if one must still leave (every other already out)
  the note names each by its `cve_id`. The structured result's cut rule is unchanged, but by
  default `data` can hold a few entries fewer, because the longer `TEXT CUT` note sits in the same
  envelope budget: at the cap of 200 registry matches check_affected's `data` keeps 131 where 3.0.2
  kept 132 to 133, and cve_remediation's, with 100 packages more than CVE-2023-44487's 50, 78
  `fixed_branches` rows where it kept 80 (and, with one package of 150 to 600 ranges among them, 11
  of 20 `fix_references`, from 12 or 13, since the text names the package whose ranges it caps,
  #3272). `full: true` returns `data` whole, as before.
- **check_sbom's first text block keeps rows with a KEV-listed or ransomware match to the last**
  (#3284). `data` keeps those rows first, while the text left the other affected rows out from the
  end in input order, so a KEV-bearing row could leave the text and be named in no text block and
  in no note (the `DATA CUT` sentence names only rows left out of `data`). On the reviewer's
  text-only client (the first text block and the note, then `workload_triage`'s step 6), the 36
  realistic Debian 12 images had 95 of 413 KEV-bearing rows in neither; the 2,000-purl images and
  image mixes 23 of 119. Now those rows leave the text only after every other row does, the note
  says so ("the last 123 of the rest without a KEV-listed or ransomware match"), and where some
  must still leave it names each by `index` ("Of the rows left out of it, 30 have a KEV-listed or
  ransomware match: at index 511 to 513, …"). On the same sets, a row the note names so counted as
  named: 0 of 413 and 0 of 119, and the KEV-first-sorted images 0 of 374 (1 at d42d4697). `scan_manifest`'s text, cut the same way, does
  the same. `workload_triage` and `sbom_review`, read from the text alone, list the rows so named
  as KEV-bearing and not checked. The 201-purl probe keeps its 43 rows in `data`. As with #2899,
  the longer note sits in the same envelope budget: on the realistic images `data` keeps 489
  affected rows where it kept 491, and after `workload_triage`'s 5 re-check calls 392 KEV-bearing
  rows are in view where 396 were (KEV-first images 352 of 374, from 356); every re-check call
  still keeps every row it sends.
- **workload_triage's Kubernetes exposure rule names a container `hostPort` and a Service's
  `externalIPs`** (#3283). Its rule named a LoadBalancer or NodePort Service, an Ingress or Gateway
  route and `hostNetwork`, and "not exposed" needed only the pod's spec and the Services read, so a
  pod reachable on node IPs through a `hostPort` (an ingress controller or agent DaemonSet) or a
  ClusterIP Service with `externalIPs` was labelled not exposed and sorted below the unknown ones
  of its KEV group. Both are now exposed, and "not exposed" requires having read the containers'
  ports and the Services' `externalIPs`. The MCP post's "Triage your pods" section states the same
  rule, held to the prompt's text by marketing-site's prompt-claims test.
- **sbom_review gives a null `fixed_in`'s reason** (#2834). Where a match's `fixed_in` is null,
  the fix list writes "no fix on record" with the match's `fixed_in_reason`, as given, and reads
  no version from it: a version it names (an interval that ends at `last_affected`) is not a fix.
  It wrote "no fix on record" alone. check_sbom's text keeps `fixed_in_reason` at every level
  that keeps a match. Its structured `data` does not at the compact level (#3269): kept there, the
  reason cost the 201-purl probe a row (43 to 42) and image mixes affected rows at their floor. So
  the clause applies where a match carries `fixed_in_reason`, and a null `fixed_in` without one is
  a reason the cut left out: sbom_review never calls it no fix, and checks the purl again with
  `full: true` or reads the fix from cve_remediation or get_cve.
- **check_affected relays a CPE match's range end in its own field, never as `fixed_in`** (#2834).
  Once EchelonGraph's API serves it, a CPE match carries the end of the NVD range that matched,
  `cpe_version_end_excluding` (the first version the range no longer holds) or
  `cpe_version_end_including` (the last one it holds). The outputSchema types both, and neither is
  ever given as a fixed version: another range of the same CVE, or a vendor backport, can sit past
  it. Only the first cut level of the text and the first thinned level of `data` keep them; every
  later level leaves them out, so a CPE answer cut past its first level, as typical CPE answers
  are, carries them only with `full: true`. A CPE match still carries no `fixed_in`.
- check_sbom's and scan_manifest's `matched_package` and `matched_via` are on each row the lookup
  ran for; a row the API refused has neither (#2836). The methodology resource, /pulse/mcp's
  check_sbom row and the SBOM coverage program say so, where they said every row.
- The `echelongraph://methodology` resource says what check_affected's and check_sbom's matches
  carry for a fix (`fixed_in`, or null with `fixed_in_reason`; a CPE match's range end, which is
  not one), and that a deb, apk or alpine purl's `upstream` qualifier is matched as the source
  package it names (`matched_via` upstream, `matched_package` that name), while a binary package
  sent without it comes back `not_assessed` (#2834, #2836).
- **check_sbom and scan_manifest drop clean rows before they cut an affected row's matches**
  (#3269). 3.0.2's structured cut (#3132) took every row through its levels together, the clean
  ones with the affected, and only at the last did rows leave. On an ordinary image SBOM, where
  most rows are clean, the affected rows lost their matches to keep the clean ones. Replayed on the
  production synthetic's recorded rows, 150 purls with 40 affected kept all 150 rows, and only 2
  of the 40 affected rows kept their matches. 3.0.0 kept 56 rows, all 40 affected with every
  match. Now the `not_affected` and `not_assessed` rows are cut to `index`, `purl`, `verdict`,
  `not_assessed_reason` and `cve_ids`. They then leave, `not_affected` first, as many as must for
  every other row to keep all its matches. `data.summary` counts them, and the note says how many
  left. Once the cut is settled they come back, cut so, as many as the room left holds. On the same
  replays, 150/40 keeps 52 rows, 150/30 keeps 91 and 150/20 keeps 135, and every affected row has
  every match.
- **Where the affected rows must be capped anyway, the clean rows stay** (#3269's review). They
  leave first to keep the other rows' matches whole, not to raise a cap those rows are cut to
  anyway. So where every other row cannot keep all its matches even with every clean row gone,
  the clean rows stay, cut as above, while every affected row keeps at least its floor: each of
  its matches used in ransomware or KEV-listed, and 10 more of highest `effective_score`.
  `linux-libc-dev` 6.1.55-1 (200 matches) with 100 clean Debian 12 purls keeps all 101 rows, as
  3.0.2 did, `linux-libc-dev` with 29 of its matches; sending the clean rows out to raise the cap
  kept 1 row of 101 in testing. Juice Shop 11.1.2 with `magento/community-edition` 2.3.0 keeps all
  51 rows, every one of its 19 affected rows with matches, magento with 19 of its 200, both
  KEV-listed ones among them (3.0.2 kept it 6, without CVE-2025-54236). Only where even the floor does not fit
  with every clean row do they leave, as many as must for it to: five Debian 12 purls with 200
  clean ones keep 69 rows.
- **A capped affected row never goes below its floor; past it, rows leave whole** (#3269's second
  review). Where even the floor did not fit with every clean row gone, the cap went on below it,
  to 1 match a row and then none, every row still kept: five Debian 12 purls beside an image's 150
  (40 affected) kept 45 affected rows, 1 with any match, where 3.0.2 kept 26, 22 with every
  match. Now no row's matches are capped below its floor. The other rows leave instead, whole, at
  the compact level and their floor, and the rows kept are chosen those with a KEV-listed or
  ransomware match first, then the others, each in input order, each one that fits beside those
  chosen before it (a row too large to fit leaves, and the rows after it stay). The note names
  the affected and undetermined rows that left by `index`, so a call of those purls alone checks
  them again (those with a KEV-listed or ransomware match first and apart, below). Where not even
  one row fits at its floor (a row whose KEV-listed matches alone pass the budget), it stays alone
  with the most of its matches that fit, ransomware first, and the note says so: 116 of 200
  KEV-listed matches. Over 40 Debian-image mixes (five Debian 12 purls, or `linux-libc-dev`
  6.1.55-1, beside 100 to 400 more purls, 10 to 60 affected), 820 affected rows keep every match
  or their floor, 720 every match, and none is
  under its floor (round 2: 462 and 408, and 744 rows under it; 3.0.2: 929 and 834, and 116 under
  it). 3.0.2 kept more rows because its compact matches left out `epss_score` and
  `score_assessed` (#3270): with those two fields out, this cut keeps 1,030 and 930. The note's
  list of affected components says that the rest are in `data.results` whole with `full: true`.
- **The trade against 3.0.2, plainly** (#3269, #3270). On heavy images the first call keeps fewer
  affected rows than 3.0.2 did. Each row it keeps is whole at its floor or more, every match with
  every field `workload_triage` ranks by (`epss_score` and `score_assessed` among them), the rows
  with a KEV-listed or ransomware match kept first, and the rest are named by `index` for checking
  again (next item). Measured on 36 realistic Debian 12 images (2026-10-18): 491 affected rows in
  the first call, against 3.0.2's 686; but 367 with every match and all six ranked fields, against
  61; 204 with a KEV-listed or ransomware match, against 39; and no KEV-listed match cut while a
  match without one is kept, against 9 rows on 3.0.2. On three 2,000-purl images: 36 rows against
  86, 28 against 2 with every ranked field, 31 against 4 KEV-bearing. On the 40 image mixes above:
  820 against 1,045, 720 of them with every match and all six ranked fields, against none. After
  `workload_triage`'s checks again, 396 of the realistic images' 413 KEV-bearing rows are in view.
  Since those checks take the KEV-bearing rows first, 48 affected rows that 3.0.2's call showed,
  on 3 of the 36 images (13 on one 2,000-purl image), are past its 5 calls, and it reports them
  by `index` as unchecked.
- **The rows left out are named KEV-bearing first, and checked again in calls that keep every
  row** (#3269's third review).
  - **The order.** The note counted the KEV-bearing rows among those left out, but named all of
    them in one list, in `index` order. `workload_triage` checked them again in that order and
    stopped after 5 calls, so on six old unpatched Debian images, where those rows come late, 119
    of 255 KEV-bearing rows were in view after it. The note now names them first and apart: "95
    affected or undetermined rows: the 32 with a KEV-listed or ransomware match at index 18 to 21,
    …; the other 63 at index 0, 2, 4 to 9, …". Both lists are of runs of indices, 100 parts at
    most in all. `workload_triage` checks them again in that order: 238 of the 255 are in view
    after its 5 calls, against 228 with the input itself sorted KEV-bearing first.
  - **The size of each call.** Step 6 sized its calls by the page sentence's N, which holds for a
    call of the first N purls sent. The rows left out are the heavy ones, so those calls dropped
    504 of 2,540 rows on the realistic images. The note now gives the sizes for these rows, counted
    as the cut would cut a call of them, with that call's own note (the affected components it
    names): "Re-check these 95 purls in this order, in calls of 7, 5, 8, 8 and 16, then of at most
    17: each such call keeps every row in data." Each of the first five calls takes the most of
    the rows left, in that order, that the cut's own measure counts as fitting at their floor with
    600 characters held back, a lower bound (a real call of them often keeps more); after those,
    the number is the most such that any that many of the rest in a row count so, and a call of
    fewer rows in a row keeps them all too. One size for every call (the "at most M" alone) put 201 of the 255 in view in
    testing; even the best single size, found by trying real calls, would put 224. Every call these
    sentences give, made in full, kept every row: 551 calls on the 36 realistic images (15 an
    image), 227 on the three 2,000-purl images, 441 on the 19 KEV-first-sorted ones, 28 on the
    image mixes and 18 on the 16 adversarial ones; within the 5-call cap, 165 calls on the
    realistic images.
  - **A row past the budget alone.** A row whose floor alone does not fit (200 KEV-listed
    matches) is sent to a call of its own, which keeps it under its floor and says so: "The purl
    at index 150 goes in a call of its own: …".
  - **sbom_review** had no step for the affected rows a `DATA CUT` leaves out of `data`, which is
    what Claude Code reads. Its step 1 now checks them again the same way, by `index`, those with a
    KEV-listed or ransomware match first, at most 5 calls, and lists the rest as unchecked.
  - **The note's length.** Over the 36 realistic images the note is 151 characters longer on
    average, 236 on the 2,000-purl images, and 20 shorter on the image mixes, where the order the
    rows were kept in is left unsaid when it is plain. The first call keeps 491 affected rows on the
    realistic images (round 3: 490), 820 on the image mixes (819), 36 on the 2,000-purl images
    (38), and the 201-purl probe's 43.
  - **The guard.** A prompt-fields test holds each shape of the note that `workload_triage` and
    `sbom_review` quote to a real cut's note.
- **What workload_triage and sbom_review do with a cut answer** (#3269's fourth review).
  - **Rows left out of the first text block.** The text leaves rows out from the end, in input
    order, while `data` keeps the KEV-bearing rows first, and `workload_triage` had no step for
    the rows the text left out, so a client reading the text alone lost them unsaid, KEV-bearing
    ones among them. Its last line now says they are in `structuredContent.data`, or, where a
    `DATA CUT` leaves rows out of `data` too, named in its note by index for step 6's re-check,
    and, read from the text alone, counts them from `data.summary` as unchecked, as `sbom_review`
    does.
  - **Indices.** `sbom_review`'s step 1 says that `metadata.component`, which check_sbom does not
    read (Trivy puts the image's `pkg:oci` purl there), is not counted, and has the agent check
    its index-to-purl mapping against the rows `data` keeps, which carry both, before it sends a
    re-check call.
  - **Past 30 CVEs.** `sbom_review`'s step 3 looked up any 30. It now takes the KEV-listed ones
    first (a match with `kev_listed` true, or named in `matches_truncated.kev_listed_cve_ids`),
    then the highest `epss_score`, read from check_sbom's matches, not from a `get_cve` per CVE.
- **The page sentence promises what holds** (#3269's review, and its second review). With clean
  rows leaving first, the number of rows `data` keeps is no longer a page size at which a call
  keeps them all: in testing, Juice Shop with magento named 19, and a call of its first 19 purls
  kept 14. The sentence now names the most purls N such that a call of the first N, or of fewer,
  keeps every row, counted as the cut would cut that call, and says only that: "A call of the
  first N of these purls, or of fewer, keeps every row in data; a call of other purls says in its
  own note what it leaves out." Round 2's opening, "To read every row in data, check N or fewer
  purls per call", read as a page size for the rest, and calls of the purls N at a time lost rows
  in 55% of the paged mixes in its review. On the replays, 150/40 names 99 and the 201-purl probe
  42; a call of the first N, or of fewer, kept every row in each of the replayed cases, in 24
  seeded random mixes (the suite), and in the 158 of 160 more, of up to 2,000 purls, that named
  one, run outside the suite.
- **A capped check_sbom row keeps its KEV-listed matches; every level that keeps matches keeps
  what workload_triage ranks by** (#3270).
  - **Which matches stay.** A row whose matches were capped kept its first ones by
    `effective_score`, so a KEV-listed CVE ranked lower was cut and only
    `matches_truncated.kev_listed_cve_ids` named it. magento's CVE-2025-54236, at position 21 of
    its 200 matches, was cut beside Juice Shop. Such a row now keeps the matches chosen used in
    ransomware first, then its other KEV-listed ones, then those of highest `effective_score`;
    `data` lists them in the API's order, and the note and `matches_truncated`'s text say both.
  - **Which fields stay.** The compact level dropped `epss_score` and `score_assessed`, so the
    201-purl probe kept 54 rows and not one match with either. It now keeps every field a prompt
    ranks by: 43 rows fit, as on 3.0.0, each match with all six.
  - **workload_triage.** Step 5 now reads `matches_truncated`'s `kev_listed_cve_ids` and
    `ransomware_cve_ids`, and says that at the leanest cut neither list is there, so its `get_cve`
    calls read those CVEs. It calls `get_cve` for every CVE kept without its match, and for every
    match that lacks a field it ranks by. A new step 6 takes each image's counts from
    `data.summary`, which counts every row whatever the cut (a call per image where several
    images' rows were left out). A `not_affected` or `not_assessed` row left out is not checked
    again; the affected and undetermined rows that left, which the note names by `index`, are, in
    calls of their purls alone (KEV-bearing first, at the sizes the note gives, since #3269's
    third review), at most 5, the rest reported as unchecked. (#3269's review first had every
    purl left out checked again at the page size: 332 calls on a realistic Debian SBOM,
    nearly all for clean rows.) sbom_review's fix rule now covers a CVE whose match a cut left out.
  - **The guard.** The #3013 prompt-field test now holds every level that keeps matches, not
    `SBOM_ROW_THIN` alone, with a control: 3.0.2's compact level fails it, naming the two fields.
- **check_sbom's and scan_manifest's first text block follows the same priority** (#3269). Its
  clean and not-assessed rows left the text only once every row was cut to `index`, `purl`,
  `verdict`, `not_assessed_reason` and `cve_ids`. So on the same replays the text kept all 150 rows
  of the 150/40 mix and the matches of none of the 40 affected rows, on 3.0.0 and 3.0.2 alike. Now
  those rows are cut to that level and leave the text first, as many as must. The 150/40 text keeps
  58 rows, every affected row with every match. Where that cannot fit, the text is cut as before,
  every row to that level: the 2,000-purl and Juice Shop texts are unchanged, and five Debian 12
  purls with 200 clean ones keep 157 rows. The note says what those rows leave out, and that each
  string in them keeps its first 100 characters where one is longer (a 150-character Maven purl
  with its `repository_url` came back clipped, unsaid, in testing). The text names no page size
  (#3269's second review): "check N or fewer purls per call", N the rows it kept, was none, and a
  call of the first N kept fewer rows in 34 of 89 mixes, on 3.0.2 too. Its note says how many
  rows it left out, of which kinds, and that `structuredContent.data` holds them.
- **A hosted handler error with JSON-RPC code -32022 is never `error_class` `other`** (#2923). A read
  of production since 3.0.2 found one: the bundled SDK rebuilds a peer's -32022 error response with
  the peer's own message (`ProtocolError.fromError`), which no fixed prefix can know. An error whose
  message no prefix knows is now classified by its code where the code names a cause: -32022
  `unsupported_protocol_version`, -32021 `missing_client_capability`, -32020 `header_mismatch`,
  -32700, -32600, -32601 and -32602 `parse_error`, `invalid_request`, `method_not_found` and
  `invalid_params`. The message is still never logged. Each such line now also names the request it
  arose in by the access line's own labels, `rpc_method` and `protocol_version` (the
  `MCP-Protocol-Version` header as a date, `(other)` or `(none)`), read from the request's own
  context, since the SDK hands its `onerror` only the error; never a param. `rpc_method`, on this
  line, the access line and `mcp_upstream_failed`, is now a closed set of labels: a method MCP
  defines for a client to send (the bundled SDK's client requests and notifications, and its task
  methods), or `(other)` for any other string. It was the client's own string, checked only for its
  shape. The access line's `method` is closed the same way: GET, HEAD, POST, PUT, PATCH, DELETE,
  OPTIONS, CONNECT or TRACE, else `(other)`. Over h2c, the hosted endpoint's protocol, it was any
  `:method` token the client sent. So is `mcp_client_gone`'s `rst_code`, the reset code of a stream
  the client reset: a code HTTP/2 defines (0 to 13), else `(other)`. It was any number the client's
  reset carried.
- **On the hosted endpoint, a large body that finds both large-body slots busy waits for one** (#2775).
  Behind Cloud Run's front end a client's close reaches the server too late to free the slot of a
  `check_sbom` call it abandoned (a probe on 2026-10-18: both follow-ups sent 1 s after two aborted
  calls were answered 503 while those calls ran on to 200), so a client that timed out and retried
  was refused for the rest of its own abandoned call. Now a `check_sbom` or `scan_manifest` call or
  an `sbom_review` prompt past 64 KiB that finds every slot taken waits up to 15 seconds for one
  (`MCP_LARGE_BODY_WAIT_MS`), at most two at once, first come first served, and is answered 503 with
  `Retry-After`, as before, only when its wait runs out or two already wait. The access line records
  the wait (`slot_wait_ms`), and `mcp_large_body_busy` is written only for a refusal. A body that
  declares its `Content-Length` waits holding nothing; a chunked body (no `Content-Length`) waits
  holding at most the 64 KiB general cap (`MCP_MAX_BODY_BYTES`) plus the chunk that crossed it, so
  memory stays bounded as before.
- **The hosted endpoint's body reader also reads whether the client had gone before it started**
  (#2775). It learned of a close or an abort only from the listeners it attached, so a reader
  started after the client went would have kept a large body among the waiters to the end of its
  15 seconds, or taken a free slot and held it for good. No request to `http.js` met this: it starts
  reading each body in the request's own event. On Node 20, 22 and 24, a stream reset or a close
  sent in the same write as a large request's headers was logged 499 (`client_closed`) within a few
  milliseconds, holding no slot and no place among the waiters, whether a slot was free or held. The
  reader now reads the request and its response's signal as they are when it starts.
- **The hosted endpoint logs every API call that fails** (#2948). On 2026-10-07 a hosted `get_cve`
  answered "EchelonGraph ... could not be reached" in 460 ms, and the hosted service's only line
  for it was its access line, `status` 200: the cause went to the client and nowhere else, and was
  lost. Each failed API call now writes one `mcp_upstream_failed` line: `failure_class` (`timeout`,
  `dns`, `refused`, `reset`, `connect_timeout`, `unreachable`, `tls` or `network` from the error's
  codes; `http` with its `status`; `not_json` or `not_object`; `unexpected_shape` for a 2xx the tool
  could not use), `route` (core-backend's route template, such as `/api/v1/public/cves/:id`: never
  the path, which holds what was looked up, and never the query string), `tool` and `rpc_method` as
  the access line has them, `after_ms`, and `synthetic`. It is WARNING, but INFO for the API's own
  answer about the input (a 400, or a 404 for a named record), which the tool reports as invalid
  input or no record: a departure from #2948's every-failure-WARNING, so that a mistyped CVE ID is
  no outage (the hosted service's monitoring still counts the INFO lines, so a 404 that is really a
  removed route shows); and ERROR for `output_schema`, the tool's own outputSchema refusing the answer
  it built, which is this server's fault, not the API's (#2948's review: it is no upstream failure,
  so the upstream metric, which counts WARNING, leaves it out). A call cancelled because its client
  went writes none. `exposure_radar` writes
  one per radar that failed. The npm package (stdio) writes nothing: stdout is the protocol.
- README: "Privacy: what is sent where" names every field the hosted endpoint's access line
  records (#2863). It named the method and path, status, duration, body size, JSON-RPC method,
  tool name, protocol version, `Origin` presence and "the family" of the User-Agent; the line also
  records the prompt name for `prompts/get`, how long the request waited for a place and how many
  were served at once, whether the client's address is public (not the address), whether the client
  closed early, and whether the request was throttled or refused, and why, as /privacy Section 11
  says. The User-Agent is described as its first word, which is what is kept. Nothing the endpoint
  logs changed. Each line it writes is now one of `src/logLines.ts`'s, with exactly its keys: a new
  line or key does not build until it is listed there, and the tests hold the README to the list.
- Repository only, not in the package: the production synthetic now writes what each answer costs
  a client on every probe line whose call was answered, on both the npm package and the hosted
  endpoint: `text_chars` (every text block's characters) and, for a tool call, `structured_chars`
  (`structuredContent` as compact JSON), measured as `test/text-bound.mjs` measures them, sizes
  only (#2781). Until now production's size was measured only when someone ran
  `npm run text-bound:live`. Its loopback forwarder serves under a base as long as the API base it
  stands for, because the package quotes its base and the cut fills its budget to the character,
  so the npm leg's sizes are the ones a client of that API receives. The synthetic's monitoring
  script gains two size distributions, two dashboard tiles for each (each tool's mean, and its
  largest answer of the hour to its 1,000-character bucket), and an alert past #2617's 45,000
  characters of text or #3013's 30,000 of `structuredContent`.
- Repository only, not in the package: `test/text-bound-live.mjs --answers
  test/fixtures/prod-answers --record` no longer re-dates the production record (#2782). Through
  3.0.2 it wrote its own time as `measured_at`, so the record said the kept answers were read 6 days
  after production served them. `measured_at` is now when production was read and `read_ms` how
  long that read took, and a re-measure keeps both. The code that measured is recorded apart, as
  `code_measured_at` and `code_version` (package.json's version, `+unreleased` while the CHANGELOG's
  newest section is unreleased). The read also records how old each answer it kept was, by the
  answer's own `generated_at` (`answers_age_ms`): the API serves a radar's aggregate stale past
  its 60-second cache to the first request after it, and the CDN 300 seconds more, so an honest
  read can get answers minutes old (two of 2026-10-05's were over 140 seconds), and no fixed
  allowance holds. The suite fails when `measured_at` less a kept answer's `generated_at` is not
  the age the read recorded for it. The record's `about` is now written by the harness. The suite
  also holds each production-shaped case's `structuredContent` size within 10% of production's
  recorded one, as it held the text (#3273). search_cves' default page now repeats rows of the
  default page itself, and lands where production's size does: 8,927 characters against
  production's 9,064, where it was 28,336. Production's cut level for that call is inferred from
  its size, not measured, until the next `--hosted --record` writes its `truncated`. Two cases
  past 10% are named with what clears each (check_sbom's Juice Shop fixture and
  epss_history's record), and `--record` writes each case's `data_truncated` and `truncated`.
- Hosted endpoint only: `Dockerfile.http` builds both its stages on
  `node:22.23.3-alpine3.24@sha256:0a7108bf…`, pinned by its index digest, the base `Dockerfile`
  (the stdio image) pins (#3018). It named the moving tag `node:22-alpine` (the same image on
  2026-10-18), so two deploys of one commit could ship different base images with no record of
  which. A test holds both files to one pinned base. A production deploy of the hosted endpoint
  (EchelonGraph's deploy-all.sh run for it, or for every service) also scans the image it just built
  for vulnerabilities with Trivy, before the push, and only that run does: no other deploy scans
  it, and CI's scan job for it is not running yet. A HIGH or CRITICAL vulnerability with a fixed
  version refuses the deploy; one with no fixed version is named and does not refuse; a scan that
  did not run or cannot be read refuses. The scanner runs only as a pinned Trivy release's binary
  (v0.75.0, by its sha256), from an empty directory with no `TRIVY_*` variable, its severities (HIGH,
  CRITICAL) and an empty ignore file on its command line, so neither the deployer's environment
  nor a stray `.trivyignore` or `trivy.yaml` narrows the scan. Another binary runs only with a
  reason given (`MCP_REMOTE_TRIVY_OVERRIDE_REASON`), after a warning that names both sha256s and
  its version, and the revision is then labelled `mcp-trivy=override`, never `clean`. A binary
  that reports Trivy 0.69.4, 0.69.5 or 0.69.6 (the releases GHSA-69fq-xp46-6x23 names) is refused.
  An operator can deploy anyway with `MCP_REMOTE_SCAN_OK=1` and a reason, and the revision is then
  labelled `mcp-trivy=overridden`. The scan's summary names the image by its local config ID, not the
  registry digest a deployed revision reports; a release revision records that digest
  (`mcp-release-digest`).
- Repository only, not in the package: the production synthetic compares the hosted endpoint with
  the npm package it runs (#3097). When the endpoint reports the version the npm leg runs, each
  era's tools (every field `tools/list` gives: name, title, description, inputSchema, outputSchema,
  annotations), prompts, resources and instructions are compared, and one more probe line per era,
  tool `(hosted-vs-npm)` on transport `http`, fails naming the first differences (`tool cve_intel:
  description differs at character 221`). On 2026-10-11 the two both reported 2.7.1 and served
  different cve_intel text, and each leg alone passed. When the endpoint reports another version
  than the npm leg runs (a rollback to an older release), it is compared with npm's own package of
  the version it reports, installed once for the run, and an endpoint reporting a version npm does
  not serve fails too (`hosted_version_not_on_npm`); the run-complete line's `hosted_vs_npm` and
  `hosted_vs_npm_at` say what was compared.

## 3.0.2 — 2026-10-17

3.0.1 was tagged but never published to npm: its release run's memory test
(`test/http-memory.test.mjs`) failed. With two 2,000-purl documents and 64 other requests in
flight, the hosted endpoint needed the whole of its image's 128 MiB heap, and V8 aborted. 3.0.2 is
3.0.1's changes with that fixed (the first entry).

- **The hosted image caps V8's old space at 104 MiB, not 128** (#3132, Dockerfile.http). With the
  schemas built once, the memory test's live set fits in 80 MiB, and at 128 V8 let the burst's
  garbage stand until the container peaked at 256-258 MB of its 268 MB. At 104 the peak is
  235-241 MB with about 24 MiB of heap to spare (3.0.0 at 128: 238-252 MB). The start-up line's
  `heap_limit_mb` now reads 152 (104 plus the young generation), not 176.

- **The hosted endpoint builds each tool's output schema once, not once per request** (#3132).
  It serves every request with a server of its own, and 3.0.1's closed copy of each success
  branch, the check behind the open `outputSchema` (below), doubled the output schemas each one
  built: 1,371 KB of heap a server, against 3.0.0's 1,168. The memory test's two SBOMs were still
  at their first batches when V8 aborted, so it was not their cut that ran out. Each schema is now
  built once per process, 611 KB a server, and the memory test passes with an 80 MiB heap, where
  3.0.0 needed 112 and 3.0.1 128. check_sbom's and scan_manifest's structured cut also measures a
  thinned row and lets it go, and thins again only the rows it keeps: on that test's 2,000-row
  answer it allocated 108 MB in 3.0.1, 18 MB in 3.0.0 and 24 MB now. No answer changes: every
  call of the suite returns the same text and `structuredContent` as 3.0.1.
- **check_sbom and scan_manifest keep every row before any row leaves `data`** (#3132). In 3.0.0
  the structured cut had one level for a row, which kept every match, so a row still large once
  thinned left `data`, and every row after it went with it. Hosted 3.0.0 kept 1 of 5 rows for five
  Debian 12 purls, all affected (linux-libc-dev 6.1.55-1 has 200 matches). It kept 2 of 51 rows for
  Juice Shop 11.1.2 with `pkg:composer/magento/community-edition@2.3.0` at index 2. For that purl
  alone it kept no row, and the note said "check 0 or fewer purls per call". Now, past the thinned
  level, every row's matches are capped at the same number, the most that fit. A row with more
  keeps its first matches (highest `effective_score` first) and carries `matches_truncated`: its
  total, the number returned, and the KEV-listed and ransomware CVE IDs and the `fixed_in` versions
  of all its matches. Next, each match is cut to `cve_id`, `kev_listed`, `ransomware`, `fixed_in`
  and `effective_score`, the row keeping `matched_package`, `matched_via` and an upstream row's
  `matched_version_from` and `purl_name`. Only when that cannot keep every row is each row cut to
  `index`, `purl`, `verdict`, `not_assessed_reason` and `cve_ids`. Rows leave only when even that
  cannot keep them all, clean rows first as before, and they leave at the compact match level, at
  most 10 matches a row, so each row kept still says its KEV flags and `fixed_in`. Once the cut is
  settled, the rows kept take back detail in input order while room is left. Replayed on those
  answers, the three cases keep 5 of 5 rows, 51 of 51 and 1 of 1. On the production synthetic's
  201-purl probe, all affected, 3.0.0 kept 43 rows; this release keeps 54 compact ones, the
  log4j-core 2.14.1 row with CVE-2021-44228 (`fixed_in` 2.15.0). The note no longer says
  "0 or fewer".
- **`not_sent_purls` is kept whole or left out, never cut short** (#3132). It is the list a client
  sends again. When a `DATA CUT` leaves it out, check_sbom's note gives the purls not sent as
  positions in the input: `coverage.sent` + 1 to `coverage.distinct_purls`, in the order the note
  states. scan_manifest's positions would count purls read from the files, which a client cannot
  rebuild, so its note says the same call with `full: true` returns the list instead.
- **cve_remediation drops a vendor advisory only after `patches` and `fixed_branches`** (#3139).
  CVE-2023-44487's default answer kept 2 of its 20 advisories, while `fixed_branches` (50 rows) and
  `patches` (30) stayed whole. Now every advisory is kept, thinned. Then `fixed_branches` is thinned
  (to the package, its range, `fixed_version` and each range's `introduced`, `fixed` and
  `last_affected`; each range's `source` and `advisory_id` go), and each package's ranges are
  capped at the most that fit, a package so cut carrying `fixed_branches_truncated` (total and
  returned). Then `patches` are thinned (to `vendor`, `patch_url` and `published_at`), every one
  kept, and `fix_references` is cut. Only then do `patches` rows leave, then `fixed_branches` rows.
  Room left goes back to the capped ranges. Replayed, that answer keeps all 20 advisories, all 50
  `fixed_branches` and all 30 `patches`, each thinned, and 17 of 20 `fix_references`, at 29,931
  characters. When
  advisories do leave, the `DATA CUT` note names `vendor_advisories_for_cve`, which lists every
  one.
- **`patch_available`'s schema text says what `true` beside an empty `patch_evidence` means**
  (#3138). It means evidence of a fix once held has since been withdrawn: the flag is never set
  back to false. `remediation.fix_status` is then the current reading. The text used to say `true`
  means EchelonGraph holds evidence of a fix, while hosted get_cve CVE-2026-1281 answered `true`
  beside `[]` and `none_confirmed`. get_cve's and search_cves' descriptions now say `true` means
  EchelonGraph holds, or once held, fix evidence for the CVE, and `patch_evidence` is what it holds
  now.
- **A success's `outputSchema` admits top-level fields it does not name** (#3121). A client
  validates answers against the tool list it read, and the hosted endpoint never tells it to read
  again. In 3.0.0 a Claude Code session that listed the tools under 2.7.2 failed every tool's
  call: "data must NOT have additional properties", from `data_truncated`, which 3.0.0 added to
  every success. A field added at the top level in a minor release no longer breaks such a client.
  The failure branch stays closed, and the server still checks its own answers against the closed
  success branch (`test/checked-strict.test.mjs`). This entry said each tool's `data` schema stays
  closed too: `data` was open at its root for 14 of 16 tools, and 86 objects below a success's
  root were closed, in and outside `data`, until #3268 (3.1.0). If you see "does not match the tool's output schema" after an upgrade, reconnect
  the client (README, Versioning).
- `test/text-bound-live.mjs --hosted` calls a 3.0.0 or later endpoint with `full: true`. It
  refuses to replay a cut `data` as the API's answer (#3140). Without `full: true`, get_cve
  CVE-2021-44228 replayed 77 of its 396 `cpe_match` entries. The vendor tools' `/coverage` is now
  served from the case's fixture beside the replayed answer, not as that answer. The record
  (`test/fixtures/text-bound-live.json`) was re-measured on hosted 3.0.0 and holds a structured size
  for each of the 23 cases measured; scan_manifest's 64-package lock, cve_remediation and cve_intel
  with `fixed_branches` are measured on production for the first time. Four fixtures were re-read
  where production had moved more than 10% from them (search_cves, epss_history,
  vendor_advisories_for_cve, and scan_manifest's lock, which now replays production's own rows).

- **The hosted endpoint's `mcp_handler_error` log names the cause of createMcpHandler's errors**
  (#2923). 2.7.1's `error_class` matched only the legacy transport's messages, so all 78 production
  lines read from 2026-10-06 were `other`. It now also matches the bundled SDK's "Rejected inbound
  request (", "Rejected 2025-era request on a modern-only endpoint (", "Unsupported protocol
  version" (code -32022, and the legacy transport's "Bad Request: " form) and "Missing required
  client capabilities". As before, only the label and the numeric code are logged, never the
  message.

## 3.0.0 — 2026-10-11

A major version (README, Versioning): the structured result is now held to 30,000 characters by
default (the first entry below), so a program that read `structuredContent.data` whole gets it cut
on a large answer unless it passes `full: true`. A client that hands the model the text or the
structured result needs no change; it gets an answer where 2.7.x gave Claude Code a file path.

- **`fixed_in` is never a version the same CVE still affects** (#3074). `fixed_in`, a match's in
  check_sbom, scan_manifest and check_affected and cve_remediation's for an installed version, is
  the first version above the installed one that no affected range of the advisory holds: the
  fixed bound of the range holding it, moved past any overlapping range of the same record.
  CVE-2026-4800 for lodash 4.17.15 answered `fixed_in` 4.17.21, the bound of `[0, 4.17.21)`, while
  `[4.0.0, 4.18.0)` on the same row still holds 4.17.21; it now answers 4.18.0, and after the #3075
  re-import the row holds only `[4.0.0, 4.18.0)`, CVE-2026-4800's own range. When the bound moved, the API's
  `fixed_in_detail` names the ranges it moved past. The API applies the rule; the server relays
  it. cve_intel carries no `fixed_in`: its description, its `fixed_branches` schema description
  and its note now state the same walk for `fixed_branches` (an affected version's fix is the
  first `fixed` above it that no range of its row holds, none past a range without one), where
  its description had said the `fixed` of the range holding the version is its fix.
- **A GitHub advisory's ranges go to the CVEs GitHub names for them** (#3075). Where GitHub's
  attribution can be read (its own advisory record, then its one NVD advisory reference, then a
  single CVE alias), a GHSA that OSV merged into a group of several CVEs no longer lends its ranges
  to the others. A record none of these settles keeps its alias set, as before, so no CVE loses a
  range it owns. Matches that came only from a range another CVE owned leave
  check_sbom's, scan_manifest's and check_affected's answers.
- `cve_remediation` carries `fix_status`, the API's fix-status rule that CVE Pulse pages show
  (`available`, `fix_referenced`, `fix_merged`, `none_confirmed` or `unknown`, with its `basis`),
  and get_cve's `remediation` summary carries it first. Both relay it; the server derives nothing
  (#2841). The rule reads the CVE record's own fix statement (#3076): a fix the record's solutions
  state is `available` with `basis` `cna_solution` and `solution_by` (the sentence, `statement`,
  and the CNA that wrote it, `cna`); a fix `patch_evidence` counts from the record with no sentence
  to quote is `available` with `basis` `patch_evidence_statement` and `stated_in_record`; and
  `unread_inputs` can name `cna_record`.
- `patch_evidence` has three more labels (#3076, #2518; core-backend): `vendor_advisory_fix` (a
  vendor advisory listing a fix for the CVE under the vendor's own structured category: Red Hat's
  CSAF `vendor_fix`, Microsoft's Vendor Fix), `cna_solution` (a sentence of the CVE record's
  solutions that names a fixed version) and `description_fix` (a sentence of the CVE description
  that does). get_cve's outputSchema names all eight.
- get_cve relays what the CVE record's CNA wrote (#3070, #3076; core-backend): `cna_solution`, the
  sentence of its solutions that names the fixed release, verbatim; `date_public`, when the
  vulnerability was made public as the CNA states it (`date_public_source` `cna`), which is not the
  record's own `published`; and `cna` (`short_name`, `name`). The note names each as the CNA's
  where the record carries it.
- get_cve's note gives `score_factors.bod_26_04` where the scorer wrote it (algorithm v3.4, #2880):
  CISA BOD 26-04's remediation timeline for the CVE if the affected system is publicly exposed and
  if it is not, with each input and its source. Its outputSchema describes
  `echelongraph_ssvc_decision` and `score_factors`.
- CISA's required action is attributed to BOD 26-04, which replaced BOD 22-01 on 10 June 2026
  (#3084): get_cve's note and its `kev_required_action` description, and cve_remediation's note and
  description.
- `cve_remediation` takes the installed version: `ecosystem`, `package` and `version`, all three
  or none, sent in the `X-EG-Ecosystem`, `X-EG-Package` and `X-EG-Version` request headers and
  never in the URL. It then answers `installed` (that version's verdict against the CVE),
  `fixed_in` and, when it is null, `fixed_in_reason`; that answer is private and `no-store`.
  Fix tags on references match in either case (#2841, #3073).
- The `sbom_review` prompt reads a fixed version from `fixed_in` alone, and names the source
  package where a row matched upstream (`matched_via` upstream, `matched_package`) (#2834, #2836).
- README, Claude Desktop: the "check that the file parses" step prints one command per OS with the
  config path filled in (`"$HOME/Library/Application Support/…"` in Terminal,
  `"$env:APPDATA\Claude\…"` in PowerShell). Through 2.7.2 it took a quoted `"<path to the file>"`,
  and the macOS path pasted into it (`~/…`) is not expanded inside quotes, so a valid file answered
  `ENOENT` (#3096).
- README: fits npm's 64 KiB with its Privacy and License sections; the long reference moved to
  `docs/tools.md`, `docs/exposure-radar.md`, `docs/structured-results.md` and
  `docs/rate-limits.md`, linked from it. Every count it states is held by a test (#3012, #2922).

- **Contract change: the structured result is held to 30,000 characters by default; pass
  `full: true` for its data whole.** Claude Code hands the model `structuredContent`, not the text
  blocks, and refuses one past `MAX_MCP_OUTPUT_TOKENS` (25,000 by default), saving it to a file:
  `get_cve` for CVE-2021-44228 was 65,540 characters of `structuredContent` on production beside a
  first text block of 23,759, so the model got a file path, not an answer. Through 2.7.x
  `structuredContent.data` was always the answer whole. Now, when the whole structured result
  (envelope, notes and data, as compact JSON) would pass 30,000 characters, its data is cut, in an
  order each tool states. Where one row is large, every row is first thinned to some of its fields,
  all rows kept, before any row leaves: check_sbom's and scan_manifest's rows to `index`, `purl`,
  `verdict`, `not_assessed_reason`, `cve_ids`, `matched_package` and `matched_via`, each match to
  `cve_id`, `kev_listed`, `ransomware`, `epss_score`, `effective_score`, `score_assessed`,
  `fixed_in` and `fixed_in_reason`, every field the prompts read from a match (all 50 rows of the
  Juice Shop 11.1.2 SBOM stay); check_affected's matches to their scores, flags, criteria and
  `fixed_in`, then fewer; cve_remediation's advisories without each item's `product_ids`, then
  without its text, the note then naming `get_vendor_advisory` as where each text is;
  search_cves' rows to their description and scores, then the scores; the vendor-advisory tools' rows
  without `affected_products`, then without `summary`. Then lists leave entries: get_cve's
  `cpe_match` and `references` first; search_cves', kev_recent's, get_cwe's and the vendor-advisory
  tools' rows from the end; check_affected's `excluded` and `undetermined` samples, then its
  `matches`, `cve_ids` last; check_sbom's and scan_manifest's `not_sent_purls` and `not_checked`, then
  their `results`, the `not_affected` rows leaving first, then the `not_assessed` ones, and only then
  affected rows, from the end; cve_remediation's `vendor_remediations`, then `patches`;
  exposure_radar's daily and weekly series, each keeping its newest entries, then its rankings,
  then `kev_exposure.newest_kev`; then any other list at the top of data. The room left once a
  list fits goes back to the lists emptied before it, as many of their entries as fit, their first
  or a series' newest (scan_manifest's `not_checked` beside 64 thinned rows). No string is shortened and no value changes (a thinned row keeps
  some of its fields, each optional in the outputSchema), so data still validates against the
  outputSchema. Every success now carries `data_truncated` (false when data is whole), and, when it
  is true, `truncated`: each list cut, by its path in data, with `total`, `returned` and, where its
  entries are thinned, `thinned: true`; the note ends with sentences starting `DATA CUT` that say what
  was cut and to which fields, how to read the rest (the offset, limit or page size, where the tool
  pages; a page size said to fit data whole is counted on the rows whole) and that the same call
  with `full: true` returns data whole. Every tool takes `full`
  (boolean, optional). **A program that relied on data whole must pass `full: true`.** The first
  text block is cut from the whole answer exactly as before (TEXT CUT); beside a cut data its TEXT CUT
  sentence says the answer is whole in `structuredContent.data` with `full: true`, and so does each
  sentence that points to another tool's data (#3013).
- check_sbom's and scan_manifest's first text block keeps each match's `fixed_in_reason` beside
  `fixed_in` at every cut level that keeps matches. Their note, and the `sbom_review` and
  `workload_triage` prompts, say `data.not_sent_purls` lists the purls not sent whole with
  `full: true`, since a DATA CUT can cut that list; the position the note gives still rebuilds it.
  scan_manifest's note says the same of `data.not_checked` (#3013).
- The `triage_cve` and `sbom_review` prompts read a vendor's workaround or mitigation step from
  `get_vendor_advisory` where cve_remediation's note says its data or text leaves that item's text
  out or shortens it (#3013).
- scan_manifest answers a file of very many entries: it read each file's entries into its lists as
  the arguments of one call, and a `requirements.txt` of some 170,000 unpinned lines (4.9 million
  characters) failed with "Maximum call stack size exceeded" (#3013).
- The `cve://` resource reads get_cve's record whole (`full: true`) and cuts it as before; its
  DATA CUT note says get_cve's `structuredContent.data` is whole with `full: true`, and, where it
  cuts, its envelope says `data_truncated: true` with `truncated` naming each list it cut (#3013).
- README: Claude Code's setup names `MAX_MCP_OUTPUT_TOKENS`; "Long answers" says which part of a
  result each kind of client reads and how each is cut; the Structured results table gains
  `data_truncated` and `truncated` (#3013).
- `test/text-bound.mjs` records each production-shaped case's structured size beside its text
  size, `text-bound-live.mjs` measures and records it, and the suite fails when any default answer's
  structured result is past the budget (#3013).

## 2.7.2 — 2026-10-11

- exposure_radar flags every radar whose last completed check is past its threshold, not only the
  two whose answer carries a liveness verdict. kev_exposure and exposed_databases (12-hour cycles)
  are flagged after 24 hours, leaked_credentials (a 10-minute cycle) after 1 hour; shadow_ai and
  mcp_servers keep the API's own poller.running and enabled verdicts, and fall back to 30 and 45
  minutes only where the answer gives none. A flagged radar's sentence gives the age and the cycle
  and says its numbers may be stale. The age is taken against the clock when the answer is
  composed, never the stats cache's generated_at. The closing sentence "Each radar refreshes on its
  own schedule." is gone: it said the radars were refreshing while four of the five were stopped.
  It now lists the radars that may be stale, or names each threshold when none is. A test reads
  each radar's cadence from core-backend and fails when a threshold is under twice it (#3010).
- README: the freshness sentence says a radar refreshes only while it runs (#3010). The setup steps
  say to quit the client fully and reopen it, and no longer give a tool count to look for: `npx`
  runs the newest release and a connector the hosted endpoint's, so a number could differ from a
  working install's and read as a failure (#2813).
- cve_intel: each exploits row carries `source_published_at`, the source's own date for the
  reference (null where the source gives none), and `eg_first_seen_at`, when EchelonGraph recorded
  it. `first_seen_at` is kept, deprecated, as `source_published_at` under its old key (#2876).

## 2.7.1 — 2026-10-06

- README: the server serves five prompts, not four; `workload_triage` (added in 2.7.0) is now in
  the intro and in the Prompts table, and a test holds the README's prompt table and every
  "N prompts" count equal to `prompts/list` (#2922).
- Every tool description now keeps at least 100 characters under the 2,048-character cut some
  clients apply. check_affected, check_sbom, vendor_advisories_for_cve, get_cve, scan_manifest,
  kev_recent, cve_intel and cve_summary were reworded for length alone: no field, verdict or
  not-assessed statement was removed. A test holds the headroom (#2924).
- Hosted endpoint: `mcp_handler_error` log lines now carry `error_class`, a label from a fixed list
  matched against the SDK's own error messages, and, for a protocol error, its numeric
  `error_code`, so each can be told apart. The message itself is still never logged, as it can
  quote what a client sent; /privacy Section 11 says so (#2923).

## 2.7.0 — 2026-10-06

- New tool scan_manifest (#2835): a project's lockfiles or pinned manifests checked against the
  advisory corpus, one verdict per dependency, in one call. Pass `files` (1 to 20 of `filename` and
  `content`, up to 5,000,000 characters in all). This server reads them into purls and sends only
  the purls, through the same batch route, batches of 200, 50-second budget, `Retry-After` waits
  and cancellation as check_sbom (that loop now lives in `src/tools/match_batch.ts`, shared by both
  tools, check_sbom's behaviour unchanged). Read: requirements.txt (`==` and `===` pins only),
  go.mod (`require` with `replace` and `exclude` applied), package-lock.json and
  npm-shrinkwrap.json (lockfileVersion 1 to 3), Cargo.lock (v1 to v4), Gemfile.lock,
  composer.lock, poetry.lock and gradle.lockfile, each tested on files written by the ecosystem's
  own tool. Every entry not sent is listed in `data.not_checked` with its file, line and reason
  (`version_unpinned`, `version_unresolved`, `local_path`, `vcs_source`, `unsupported_line`) and is
  not clean: `django>=4` is never sent as `pkg:pypi/django@4`. package.json, pyproject.toml,
  Pipfile, Gemfile, Cargo.toml, composer.json and build.gradle are refused with the lockfile to
  pass; go.sum is refused, as it lists versions the build does not select. No fixed version is
  derived: each match's `fixed_in` is the API's. TOML is read by a small reader in this package
  (`src/tools/manifests/toml.ts`), so no runtime dependency is added. 16 tools.
- The hosted endpoint admits a `tools/call` of scan_manifest up to 6 MiB, as it does check_sbom
  (`LARGE_BODY_TARGETS` now lists names per method); the files are read in memory and neither
  logged nor kept. The 413 and 503 texts name no single tool.
- check_sbom's outputSchema names `kev_listed` and `epss_score` on each match, which the API
  already sent.
- New tool cve_remediation (#2841): how one CVE is fixed, as its sources state it, in one answer:
  CISA's KEV text (its required action is directed at US federal civilian agencies), every
  affected range with its fix, each vendor advisory's remediation categorised by the vendor's own
  category (vendor_fix, workaround, mitigation, no_fix_planned, none_available, other), the
  references NVD tagged Patch or Mitigation, and patches. Nothing is generated; every text is its
  source's, untested by EchelonGraph. none_in_source, not_parsed and an empty list are not a
  finding that no fix exists; a REJECTED CVE answers not_assessed. 15 tools. Its text for
  CVE-2021-44228 on production's data was 20,644 characters, assembled before the route was
  deployed; measured live on 2026-10-18, 22,571 characters on the hosted endpoint and on npm 3.0.2,
  and 18,293 with an installed version (#2841).
- get_cve relays remediation, a capped summary (at most 1,500 characters of JSON) of the same.
- vendor_advisories_for_cve rows carry remediation_kinds and remediation_state, and
  get_vendor_advisory carries remediations, each item with its kind, verbatim text and URL
  (#2840). Red Hat, Microsoft and Palo Alto are parsed; other vendors are not_parsed.
- vendor_advisories_for_cve, get_vendor_advisory and search_vendor_advisories now say when an
  advisory names a CVE ID whose CVE record was rejected (withdrawn) by its numbering authority
  (#2865). Through 2.6.8 such an advisory read as a normal one when its vendor had not withdrawn
  it: measured in production on 2026-10-05, 767 single-CVE advisories that their vendors had not
  withdrawn named a CVE that EchelonGraph holds as REJECTED (GitHub 740, Microsoft 25, Red Hat 2),
  and `vendor_advisories_for_cve` for CVE-2026-7936 returned Microsoft's "Chromium: CVE-2026-7936
  Object lifecycle issue in V8" with nothing saying the CVE was rejected. core-backend now serves
  `rejected_cve_ids` on each advisory: the CVE IDs it names that were rejected, `[]` when none
  was, null when that could not be checked. vendor_advisories_for_cve also gets `cve_rejected`
  for the CVE asked for. The vendor's own `withdrawn` is unchanged: it still says only whether the
  vendor rescinded its advisory. The note opens with `CVE REJECTED` for a rejected CVE, names each
  advisory that names a rejected CVE ID, and says when the state could not be checked. The three
  descriptions and the outputSchema describe both fields. When a row is cut to fit the text, it
  keeps `rejected_cve_ids` at both cut levels.
- GitHub advisories whose text is a CVE rejection notice ("Rejected reason: …") are now served
  with `withdrawn: true` (#2864; core-backend). search_vendor_advisories leaves them out, as it
  does every withdrawn advisory.
- get_cve relays CISA's own KEV text for a KEV-listed CVE (#2839; core-backend):
  `kev_required_action` (CISA's requiredAction), `kev_short_description` and `kev_notes_urls`
  (the https URLs in CISA's notes, at most 10), alongside `kev_due_date`, which the API already
  served. Through 2.6.8 none of the three was stored. The note says the text is CISA's, under BOD
  22-01, and not EchelonGraph's advice. triage_cve quotes the required action, attributed to CISA.
- `patch_evidence` has two more labels (#2889, #2890; core-backend):
  - `release_reference`: EchelonGraph's GitHub release, PR or commit reading found a published,
    non-draft release that contains the fix.
  - `cna_patch_reference`: the CVE's numbering authority tagged one of its references `patch` in
    its CVE record.

  Measured in production on 2026-10-05, 6,395 CVEs held one of these and read
  `patch_available: false`. Among them were CVE-2026-97724, whose fix release worklets-0.12.2
  EchelonGraph had read, and CVE-2026-69486, which Microsoft tagged `patch`. A reference that is
  only marked from page wording, such as an advisory page that mentions a patch, is still not
  counted as evidence.
- epss_history now says where its record becomes complete (#2867; core-backend). Through 2.6.8
  it presented 2026-05-18 onward as a complete record. Measured on 2026-10-05, every FIRST score
  date in that span had been applied. But the old write path dropped many per-CVE changes within
  a night's refresh: on 2026-09-21, 202 of 300 sampled CVEs whose EPSS changed got no history row.
  The answer now carries:
  - `complete_since`: 2026-10-04 23:14:54Z, the first refresh of the new write path;
  - `series_complete`;
  - a `score_date` on each point;
  - a coverage block of days held, partial and missing. It comes from a new per-refresh run log,
    so it is exact from the deploy onward.

  The note names the incomplete stretch. It never calls the record complete without
  `complete_since`.
- check_sbom follows a Debian or Alpine purl's `upstream=` qualifier to the source package it was
  built from (#2836; core-backend). Advisories are keyed by source package. Measured on
  2026-10-05, Debian 12 holds 0 rows for `libssl3` and 262 for `openssl`. Through 2.6.8,
  `pkg:deb/debian/libssl3@…?upstream=openssl` and `pkg:apk/alpine/libcrypto3@…` came back
  not_assessed, while the same version under `openssl` was affected. Each row now says
  `matched_package` and `matched_via` (`purl_name`, `upstream` or `coordinates`), and a match found
  through `upstream=` says so in its `match_reason`. The binary name is never silently tried
  instead.
- check_affected and check_sbom registry matches carry `fixed_in` (#2834; core-backend): the fixed
  bound of the interval that matched the version asked about. For example, log4j-core 2.14.1 →
  2.15.0 and 2.11.0 → 2.12.2. It is `null` with a `fixed_in_reason` when that interval has no fix
  (it ends at last_affected, or has no upper bound). CPE matches carry no `fixed_in`.
  Every cut level of check_affected's text keeps `fixed_in`, so a registry list near the cap of
  200 no longer fits whole: on django's rows at 200 matches beside 50 undetermined, the text keeps
  185 (29,863 characters) and the note says the last 15 are in `structuredContent.data` only. Its
  description said every match stays in the text; it now says that of CPE matches, and that a
  registry list near the cap can leave its last matches out.
- The server instructions and every tool description now fit in 2,048 characters (#2842). Claude
  Code cuts each MCP tool description and each server's instructions at 2,048 characters
  (`CLIENT_DESCRIPTION_CUT`, the strictest limit any client documents). On this release's text before the cut, 13 of 14
  descriptions and the instructions (2,521) were over it, so a model in Claude Code read them cut.
  `exposure_radar` was 11,807 characters. Detail moved into the outputSchema description of the
  field it describes. A test fails if any text grows past the limit, or if a required sentence
  (the Shodan attribution, the hosted-endpoint disclosure, each tool's load-bearing rule) falls
  after it.
- exposure_radar relays an observation window for kev_exposure (#2438; core-backend): the
  Shodan banner times of the oldest and newest service×CVE pairs it counts, as
  `kev_exposure.window`. That is passed through only when every counted pair has such a time.
  Until then the note says how many have none. core-backend stores Shodan's banner `timestamp` as
  `banner_seen_at`, and never our own write time; existing rows get one when a search matches
  them again. `state` stays not_assessed and `measured_at` stays null: a window is a span of
  observations made at different times, not one observation time.
- New prompt `workload_triage` (#2846). It ranks an agent's own pods, images or CI containers by
  CISA-KEV status, caller-asserted exposure and EPSS. The agent lists its workloads and makes an
  SBOM per image digest with its own tools, then sends check_sbom only purls: no workload, image,
  registry or exposure label goes to EchelonGraph. Exposure is labelled caller-asserted, and
  unknown is never treated as not exposed. check_sbom's description says its input for container
  images is an SBOM of each image, or its purls.
- triage_cve, sbom_review and am_i_affected read the 2.7.0 fields (#2834, #2841). sbom_review and
  am_i_affected give a registry match's `fixed_in` first: a null `fixed_in` means no fixed version
  for that version's range, not that no fix exists. triage_cve and sbom_review call
  cve_remediation, and relay a vendor's stated workaround or mitigation as that vendor's, untested
  by EchelonGraph and not a fix.

## 2.6.8 — 2026-10-05

- get_cve and search_cves now say what `patch_available` means, and describe `patch_evidence`
  (#2861). Through 2.6.7 neither tool described `patch_available`, and core-backend set it only
  from Ubuntu and Red Hat patch records, so a `false` read as "no patch": measured in production on
  2026-10-05, 101,725 CVEs read `false` while EchelonGraph held evidence of a fix for them, 48,145
  with a package `fixed_version` and 71,705 with an NVD reference tagged "Patch" (CVE-2017-5651,
  Apache Tomcat, among them, with two package rows carrying a `fixed_version`). core-backend now
  sets `patch_available` true whenever it holds evidence of a fix, and serves `patch_evidence`, the
  list of its sources, strongest first: `vendor_patch` (a vendor patch on record, from Ubuntu or
  Red Hat), `fixed_version` (a package fix version, or the fixed bound of an affected version
  range) and `nvd_patch_reference` (an NVD reference tagged Patch). Both descriptions, and the
  outputSchema descriptions of both fields, now state: `patch_available` is true when EchelonGraph
  holds evidence of a fix; `false` means no fix evidence is on record, which is not a finding that
  no fix exists; once true it is never set back to false, so it can be true beside an empty
  `patch_evidence`; and an answer with no `patch_evidence` (an API older than that field) does not
  name the evidence. Both fields are relayed as the API sends them; a `patch_evidence` label the API
  adds later is relayed, not a failed call.
- search_cves: a page cut to fit the text keeps `patch_evidence` beside `patch_available` in each
  row at the first cut level.

## 2.6.7 — 2026-10-05

- Tool descriptions now state facts only: no reporting instructions to the model and no references
  to other tools, for the Anthropic MCP Directory policy ("Tool descriptions contain no
  instructions about model behavior, other tools, or external instruction sources, and no hidden
  or encoded text"). Tool behavior, results and their notes are unchanged. Reworded:
  - get_cve, search_cves: "The note labels each such CVE NOT YET SCORED: report it that way, never
    as a score of 0." now reads "The note labels each such CVE NOT YET SCORED, which is not a score
    of 0."
  - cve_summary: summary.rejected's "report them as withdrawn records, never as vulnerabilities"
    now reads "they are withdrawn records, none of them a vulnerability"; summary.none's "report
    those CVEs as not yet scored, not as CVEs rated None" now reads "and names those CVEs not yet
    scored, not CVEs rated None".
  - get_vendor_advisory: "(the vendor and vendor_advisory_id fields of a row from
    search_vendor_advisories or vendor_advisories_for_cve)" now reads "(the vendor and
    vendor_advisory_id of a vendor advisory row)".
  - exposure_radar: "and cve_exposure says per CVE whether the radar tracks it" now reads "and this
    answer does not say whether the radar tracks that CVE: tracking is answered per CVE".
  - epss_history: "Never interpolate it into a daily series." now reads "A daily series
    interpolated from it holds values EchelonGraph never recorded, so the series is never a daily
    series."
  - check_affected: "Read assessed before count: … a count of 0 there must never be reported as
    not affected" now reads "count depends on assessed: … a count of 0 there is not a finding of
    not affected"; the outputSchema description of assessed, "Read first.", now reads "count
    depends on it.".
  - vendor_advisories_for_cve, get_vendor_advisory, search_vendor_advisories: the outputSchema
    description of withdrawn, "report it as withdrawn", now reads "so it is a withdrawn advisory,
    not a current one".
- test/description-policy.test.mjs lists the tools over stdio and fails if any title, description
  or input/output schema description names another tool, matches a model-directed imperative
  pattern, or carries zero-width, bidi or control characters or a base64-looking run.

## 2.6.6 — 2026-10-05

- Correction to 2.6.5 (#2775). Its entry says: "On the hosted endpoint it is the client going away
  (its own timeout, a closed tab): every API call of that request is cancelled". That was not true
  of the hosted endpoint. Cloud Run does not pass a client's disconnect on to a container it
  speaks HTTP/1.1 to ("When you use HTTP/1.1 on Cloud Run, client disconnect events are not
  propagated to the Cloud Run container",
  <https://docs.cloud.google.com/run/docs/troubleshooting>). In production on 2026-10-05, four
  `check_sbom` calls had their client abort after 0.4 s or 1.5 s. Each was logged `status` 200
  with `client_closed` false and ran to its end, 2.0 to 5.3 s. Together they held both large-body
  slots, so a large body sent 1 s later was answered 503. The same page says HTTP/2 does pass the
  disconnect on. So `dist/http.js` now serves HTTP/2 cleartext (h2c) when `MCP_H2C=1`, and the
  hosted deployment sets it together with Cloud Run's `--use-http2`. With that flag, Cloud Run
  speaks only h2c to the container. The server acts on a reset stream the moment it arrives, with
  any error code including `NO_ERROR`: the API calls are cancelled, `check_sbom` sends no further
  batch and ends a `Retry-After` wait, the large-body slot is freed, and the `mcp_request` line
  says `status` 499 with `client_closed` true. What Cloud Run forwards is only partly measured.
  On test deployments with `--use-http2` on 2026-10-05, ordinary calls, sessions and `/health`
  were all answered over h2c. A client that stopped reading a streamed answer had its stream reset
  by Cloud Run 15 s in (`rst_code` 2), and that was logged 499. A client that aborts mid-call
  before any answer was not observed, because every probe call was answered first, so whether
  Cloud Run forwards that reset at once is not yet shown. Until it is, an abandoned call may still
  run to its end, a `check_sbom` call for at most its 50-second budget, holding its slot. A new line, `mcp_client_gone`,
  records when the server learned the client went: `after_ms` from the request's start, whether
  the answer had started (`answer_started`), and an HTTP/2 stream's `rst_code`. It holds nothing
  of the request. Run yourself, `dist/http.js` speaks HTTP/1.1 as before. With `MCP_H2C=1` it
  speaks h2c with prior knowledge only, and an HTTP/1.1 request gets no answer.
- README, "Privacy: what is sent where": the hosted endpoint's paragraph now also says what the API logs
  of the calls it makes for you (#2797): each under your address, with its URL path (for a CVE, CWE or
  advisory lookup, the ID), and not its query string, the header-carried terms or which purls. The
  privacy policy's new Section 11, https://echelongraph.io/privacy#hosted-mcp-endpoint , says the same.
- `exposure_radar` relays and labels `mcp_servers.withheld_opted_out` (#2822): how many hostnames
  whose owner opted out of scanning the API left out of every other `mcp_servers` number. Such a
  hostname is not checked again while the opt-out stands, so its last verdict cannot be re-checked;
  the API now withholds it from the MCP-server counts as its unparameterised AI-exposure answer
  already did. An answer without the field, from an API that predates it, counted those hostnames,
  and the note says so instead of reading the absence as 0; a value that is not a whole number is
  left out and named.
- Claude Desktop in one click (#2815). From this release on, every GitHub release of
  [github.com/echelongraph/echelongraph-mcp](https://github.com/echelongraph/echelongraph-mcp/releases)
  carries `echelongraph-mcp.mcpb`, a Claude Desktop extension: open it and choose Install. It needs
  no Node.js on your machine, since Claude Desktop runs it with the Node.js it ships, and no JSON to edit.
  The README's Claude Desktop section links it as "Install in Claude Desktop", ahead of the custom
  connector and the `npx` setup. The release workflow builds it from the release tag, the same tag
  the npm package is published from: `listings/mcpb/build.sh` validates the manifest with the pinned
  MCPB CLI and packs. Then, on a separate read-only runner that never ran the MCPB CLI,
  `listings/mcpb/check-bundle.mjs` refuses a bundle that holds a top-level file `build.sh` does not
  stage, a symlink, or a file where `build.sh` stages a directory; that lacks the icon or entry point
  its manifest names, or `node_modules/`; whose `package.json`, `LICENSE`, `README.md` or `dist/` is not the tested npm
  tarball's, byte for byte (a file changed, missing or added); whose `node_modules/` adds or changes
  a file a production install from the lockfile does not have; that is at another version; or whose
  own server, started with `PATH`, `HOME` and `ECHELONGRAPH_API_BASE` only (none of the caller's
  `NODE_PATH`, `NODE_OPTIONS` or other variables), does not list the
  manifest's 14 tools with their titles. npm publishes only after that check passes, so a manifest
  or bundle defect stops the release before npm has the version. A separate job, which runs no
  dependency code, signs the checked bundle with a SLSA build-provenance attestation (Sigstore,
  keyless), attaches it and its Sigstore bundle to the release, each on its own, and checks the
  file the release serves with `gh attestation verify`. To check a download yourself:
  `gh attestation verify echelongraph-mcp.mcpb --repo echelongraph/echelongraph-mcp`.
  Releases up to 2.6.5 carry no bundle.
- Repository only, not in the package: `listings/mcpb/check-bundle.mjs` and
  `test/mcpb-release.test.mjs`; `test/mcp-stdio-client.mjs` takes a `cwd`.
- `sbom_review` reads the advisory interval in `check_sbom`'s `match_reason` by its closing
  bracket, without the hedge of 2.6.5 and earlier. `[A, B)` is a fixed bound: B, the first version the advisory
  records as not affected, is given as the fixed version (`[A, ∞)` names none). `[A, B] (B is the
  last affected version, not a fix)` is an OSV `last_affected` bound: B is still affected and the
  range records no fix, so neither B nor any version at or below it is given as a fixed version.
  The bracket alone decides: a cut text clips `match_reason` to 200 characters, which can drop the
  words after it for a long package name, and where it is clipped before the closing bracket
  (`[A, B…`), no fixed version is taken from that `match_reason`.
  Through 2.6.5 core-backend rendered both bounds as `[A, B)`, so the prompt gave B only as "the
  end of that interval"; core-backend now renders a `last_affected` bound closed (#2830). This
  wording assumes the API serves the new rendering: it is released after core-backend is deployed.
- `cve_intel` relays `fixed_branches` on each `affected_packages` row: every affected range of the
  package on record, each with `introduced` and `fixed` (the range's fix) or, where no fix is on
  record, `last_affected` (never in a field named fixed), and with `advisory_id` (the OSV record that
  published the range) and `source` (the loader's label for that record), from core-backend's
  `/api/v1/public/cves/:id/enrichment` since #2817. Ranges that name their record are in the order
  the record lists them; ranges loaded before the record was stored (both null) are oldest first.
  `fixed_branches` is null where a package's ranges were never loaded, and `[]` where no version
  range is on record (none in the advisory, only commit ranges, or more than are stored), which is
  not a finding that no fix exists. `fixed_version` is one range's fix per package,
  kept for compatibility: for CVE-2021-44228 production served log4j-core 2.12.2 alone (2026-10-04),
  the fix for 2.4 to 2.12.1, older than an affected 2.14.1, while the advisory
  (GHSA-jfh8-c2jp-5v3q) gives three ranges, fixed in 2.3.1, 2.12.2 and 2.15.0. The description says
  how to pick the range for an installed version, and the note counts the rows with more than one
  range, and those with no range on record (`fixed_branches` null, or `[]` beside a `fixed_version`),
  where `fixed_version` is all the answer holds. An API older than #2817 is said to be one (#2817).
- `triage_cve`'s patch line gives each affected range with its fix from `fixed_branches`, and
  `fixed_version` only for a package without them; `sbom_review` gives a component the fix of the
  `fixed_branches` range that holds its installed version (log4j-core 2.14.1: 2.15.0), after the
  advisory interval in `check_sbom`'s `match_reason`, and `fixed_version` only for a package without
  `fixed_branches` (#2817).
- `vendor_advisories_for_cve`, `search_vendor_advisories` and `get_vendor_advisory` relay each
  vendor's `held_since`, which the coverage API now serves: the start of the window EchelonGraph has
  read the vendor's advisories from, before which an advisory may not be held.
  `vendors_not_fully_held` reads it, not the earliest held advisory. For a vendor with no history read
  the earliest held advisory is not where its window begins: Cisco's poller first read the advisories
  Cisco had changed in the last 90 days, Red Hat's and GitHub's the last 7, so an older advisory the
  vendor revised later is held while the ones published beside it are not. Cisco's earliest held
  advisory is dated 2024-10-23 and Red Hat's 2009-02-04, so CVE-2025-20188 left out Cisco and
  CVE-2014-0160 left out Red Hat, and their empty answers read as the vendor having published nothing;
  both are listed now. GitHub is now listed too for any CVE ID year that begins before the start of
  its first poll's 7-day window (`held_since`), not only for years up to that of its earliest held
  advisory (2017). Against an API without `held_since`, a vendor is taken as held from its earliest
  advisory only when its history read is complete, and otherwise listed, its window written "not known
  to be without a gap" (#2803).

## 2.6.5 — 2026-10-05

2.6.4 was tagged and never published: its Release run failed `test/http-memory.test.mjs` on Node 24,
where `--max-old-space-size=128` alone allowed a 320 MiB heap in a 256 MiB instance. 2.6.5 is 2.6.4
plus the fix below; the `v2.6.4` tag stays, unpublished, because a tag is never moved.

- Hosted endpoint only: `Dockerfile.http` also passes `--max-semi-space-size=16`, so V8's heap limit is
  176 MiB on Node 22 (unchanged: the production image) and on Node 24 (was 320 MiB). The memory cap of
  #2773 now holds whichever Node the image uses.

- README: the header links the directories that list this server, Smithery and Glama (#2723). Smithery's
  verification looks for that link; `test/listings.test.mjs` pins it.

- Hosted endpoint only: an instance serves at most 64 requests at once (`MCP_MAX_IN_FLIGHT`); the
  next, its body read first (so a slow upload holds no place), waits up to 10 seconds
  (`MCP_ADMISSION_WAIT_MS`) for one to finish, and is then answered HTTP 503 with `Retry-After` and
  JSON-RPC error `-32030`. A 2026-07-28 `subscriptions/listen` stream is not counted: it stays open
  until its client leaves, carrying only keepalives (the server announces no list changes), so 64
  idle ones would leave every other request waiting 10 s for a 503; the SDK refuses a stream past
  1,024 open per process. The image runs Node with V8's heap capped at 128 MiB, half the
  instance's memory. Measured in a 256 MiB cgroup on a 16 GB host: two maximum-size SBOM documents
  beside 125 or more other requests got the server killed with every request on it, and holding
  that took both bounds. Node sized V8's heap from the host's memory, so garbage piled up until
  the kernel killed the process (whether Cloud Run's instance reports more than its 256 MiB is not
  verified), and 250 requests live at once exhausted even the capped heap. With both, 250 sent as
  they come are all served (the last after waiting about 9 s), peaking at 82-84% of the memory,
  and 250 at once are 64 served and 186 answered 503 after 10 s, peaking at 75-77%. The `mcp_request` line gains `in_flight` and
  `queued_ms`, the start-up line `heap_limit_mb` and `memory_limit_mb`, and a process started
  without the cap logs `mcp_remote_heap_unbounded`, where Node can read the container's limit
  (`memory_limit_mb` not null) (#2773).
- `check_sbom` stops when its call is cancelled: no further batch is sent, the batch in flight is
  cut off, and a `Retry-After` wait ends. Over stdio that is the client's
  `notifications/cancelled`, which before left the call sending its batches to the end. On the
  hosted endpoint it is the client going away (its own timeout, a closed tab): every API call of
  that request is cancelled, a `check_sbom` call holds its large-body slot until it has stopped,
  not only until its client has gone, and the `mcp_request` line says `status` 499 with
  `client_closed` true. Before, an abandoned call ran its batches to the end, spending the
  client's API budget, and was logged as 200 (#2775).
- Repository only, not in the package: the production synthetic's hosted leg sends `check_sbom`
  its 201 purls as a CycloneDX document, a ~138,000-byte request body, twice the endpoint's
  64 KiB general cap, and fails the probe unless the answer is `measured` from the document; a
  return of the 413 that #2747 removed now fails it (`rpc_error`, `-32600`). The synthetic's alert
  runbook says how to read that failure, and a memory alert on the hosted endpoint is written
  beside its uptime check (#2774, #2773).
- The prompts ask only for what their tools' first text block keeps, at their largest input. In
  2.6.3 each of the four asked for something that text leaves out of a large answer, or that the
  call it made did not return, so a client that passes only `content` to the model never showed
  it (#2799):
  - `kev_weekly_brief` reads `kev_recent` 50 rows a page, not 200. Each line of the brief names
    `kev_vuln_name` and `kev_due_date`. Read through the hosted endpoint on 2026-10-04 (2.6.3),
    365 days at limit 200 (306 CVEs) kept 5 fields a row in the text, neither of those two among
    them. A page of 50 comes back whole: 27,514 characters for production's 50 newest.
  - `check_affected` keeps `ransomware` and `epss_score` on every match at every cut level, the
    two fields `am_i_affected` lists for each match. In 2.6.3 a list at the API's cap of 200
    matches kept `cve_id`, `kev_listed`, `effective_score`, `effective_severity` and
    `score_assessed`: hosted, `linux_kernel` 5.10.0 had 20 CISA-KEV-listed matches and 1 with
    known ransomware use, named nowhere in the text. Since 200 such matches with
    `effective_severity` as well come to 33,240 characters, past the budget on their own, the
    leanest level leaves `effective_severity` out. The `excluded` and `undetermined` samples now
    keep their first 10 entries in the text (`excluded_count` and `undetermined_count` count every
    entry), so every match still stays in the text. The description's "at least" list says so.
  - `sbom_review` sends the purls not sent again from `data.not_sent_purls` only where the text
    holds that list whole. Where the note says the text cuts it (to its first 10), the model
    rebuilds the purls from the document instead: its distinct purls from the position the note
    gives, in the order the note gives. `check_sbom`'s note now gives that position, and the order
    it counts the input's purls in (a CycloneDX document's components depth first, each one's
    nested components right after it, each purl at its first place), whenever purls are not sent,
    not only when the text cuts the list. The prompt also says what to do when the note says rows
    are left out of the text: list the rows the text carries, and give the rest as
    `data.summary`'s counts.
  - `sbom_review` reads each affected CVE's fixed versions from `cve_intel`, called beside
    `get_cve` (`fixed_version` of its `affected_packages` and `fixed_versions` rows for the
    component's package). In 2.6.3 it asked for "fixed versions where a result gives them", and
    `check_sbom`'s text keeps `match_reason`, the advisory interval that names the fixed version,
    only at its first cut level: the 50 components of a Juice Shop SBOM are cut past it.
  - `sbom_review` never gives a fixed version that is not strictly greater than the component's
    installed version, compared in the ecosystem's version order (where the model is not sure of
    the order, it says so and gives none). It takes the end of the advisory interval in
    `match_reason` first, where the text keeps it, and otherwise `cve_intel`'s `fixed_version`,
    said to be one value per package, the advisory's last range's, which need not be the fix on
    the component's branch (#2817). Where no version qualifies, the line says the results give no
    fixed version for the component's branch and points to the CVE's advisory (`get_cve`'s
    references). Read through the hosted endpoint on 2026-10-04 (2.6.3), `cve_intel` gives
    log4j-core 2.12.2 for CVE-2021-44228, and `check_sbom`'s matches for 2.14.1 say it "is listed
    verbatim in the advisory's affected versions", so the entry above alone had the model give
    2.12.2 as the fix for 2.14.1. The prompt also reads each component's ecosystem, package and version
    from its purl, which every row the text keeps carries; the leanest cut, reached at 2,000 purls,
    leaves the row's own fields out.
    It maps a purl as `check_sbom`'s matcher does: the sixteen purl types with an ecosystem (`hex`,
    `pub`, `swift`, `hackage`, `cran`, `bitnami`, `conan` and `githubact` among them, which the
    first wording left out), `swift` and `githubact` named with their namespace as `npm`, `golang`
    and `composer` are, and `deb`, `apk`, `alpine` and `rpm` by a `distro` qualifier of
    `debian-N` (its major release), `ubuntu-V` or `alpine-X.Y` (cut to major.minor); for any other
    the ecosystem is unknown, and the fix list gives no version for it.
  - `triage_cve`'s patch line says that `cve_intel`'s `fixed_version` is one value per package, the
    advisory's last range's, and is given as what `cve_intel` records for that package, never as
    the fix for every affected branch; for a branch's fix it points to `get_cve`'s references
    tagged Vendor Advisory or Patch and to the vendor advisories (#2817). The line had asked for
    "fixed versions" alone, with no installed version to hold them against, so for CVE-2021-44228
    it could give log4j-core 2.12.2, `cve_intel`'s one value on 2026-10-04, as the patch, below the
    affected 2.14.1.
  - `triage_cve` reads CISA's due date, `kev_due_date`, from `get_cve`'s record and no longer calls
    `kev_recent`. Its step 6 read it from a `kev_recent` page of the CVE's `kev_added_date`, with no
    limit and no paging. Read through the hosted endpoint on 2026-10-04 (2.6.3), the page for
    2021-11-03 held 50 of the 287 CVEs CISA added that day, and not CVE-2021-40444, one of them;
    `get_cve` for CVE-2021-40444 carried its `kev_due_date` in its first text block.
- `cve://{cve_id}` stays under the 60,000-character ceiling. Its `data` is cut as `get_cve`'s
  first text block is, laid out the same way, after the envelope. In 2.6.3 it was `get_cve`'s
  structured result pretty-printed whole: 86,559 characters for CVE-2021-44228 on the hosted
  endpoint, against 23,705 now on the suite's production-shaped answer. Its notes no longer carry
  `get_cve`'s `TEXT CUT` sentences, which describe a first text block the resource does not have
  (they said `cpe_match` kept 64 entries while the resource carried all 396). When `data` is cut,
  the notes end with the resource's own sentence instead, starting `DATA CUT`, which names
  `get_cve`'s `structuredContent.data` as the record whole. A record that fits is unchanged,
  character for character. The resource's description and the methodology say so (#2801).
- No note promises a record or a component's matches "whole" from a tool whose text is cut too.
  The `TEXT CUT` sentences of `search_cves`, `kev_recent`, `get_cwe` and `check_affected` say that
  `get_cve` returns a record whole in its `structuredContent.data` and, in its first text block,
  with every field, each list cut to its first entries past 30,000 characters. `check_sbom`'s
  sentence says the same of `check_affected` and a component's matches, and the vendor-advisory
  tools' of `get_vendor_advisory`. `get_cve`'s description and the README begin "One CVE's
  record", no longer "Full record for one CVE". The source comments and the README no longer say
  that `content[0]` always equals `data`. The 2.6.3 entry below gives the sizes production's record
  holds for that release (26,011, 27,777, 28,793, 31,583 and 23,028), measured after #2729, in
  place of the 25,951, 27,717, 28,733, 31,588 and 19,917 measured before it (#2802).
- Repository only, not in the package (#2800, #2799):
  - Every production-shaped case's text is held within 50 characters of its recorded size, in
    either direction. A text that shrinks is re-measured as one that grows is.
  - The fields each description says a cut row keeps "at least" are read from the description
    and checked on every row of every production-shaped case, for `search_cves`, `get_cwe`,
    `kev_recent`, `check_affected` (its samples too), `check_sbom` and the vendor-advisory lists,
    and at least one case of each tool must be cut. No answer the API serves reaches the cut of
    `get_cwe` (each row's description is cut to 240 characters at the source) or of
    `vendor_advisories_for_cve` (at most 20 short rows), so each has a forced case: production's
    rows made longer. `get_cve` is held to keep every field. Removing `severity`, `cvss_v3_score`,
    `echelongraph_score`, `score_assessed`, `epss_score` and `kev_listed` from `search_cves`'s
    cut levels, which left 2.6.3's suite green, now fails it, as does dropping a field from
    `get_cwe`'s.
  - Each prompt's tool calls are made as the prompt says, at its largest input, on
    production-shaped answers, and every field the prompt names must be in the text a client
    that passes only `content` shows the model. Every tool a prompt names must be one of those
    calls.
  - A new test makes each prompt's tool calls as the prompt says, at its largest input, on
    production-shaped answers, and checks every field the prompt names in the text: 365 days of
    KEV additions, `check_affected` at its cap of 200 matches (both lookup paths), a 2,000-purl
    SBOM answered in full and rate-limited, and `triage_cve`'s six tools.
  - That test reads `sbom_review`'s `ecosystem`, `package` and `version` as fields: on a row whose
    text leaves them out, reading them from the purl as the prompt says must give the answer's.
    On production's `cve_intel` for CVE-2021-44228 and production's `check_sbom` answer for
    log4j-core 2.14.1 (captured 2026-10-04), the prompt's fix rule must offer no fixed version,
    2.12.2 among the candidates, and on Juice Shop's lodash 4.17.19 it must offer 4.17.21 (#2817).
- `cve_summary` no longer fails when the `poller` block changes JSON type: a poller field the
  answer sends in a type other than the one its outputSchema describes (`interval` as a Go
  duration such as 1200000000000, `last_poll_at` as unix seconds, `cves_ingested` as a string) is
  left out of `data` and named in the note, and a `poller` that is neither a JSON object nor null
  is left out whole. `summary` and the rest of the answer are relayed as sent, measured. From
  2.6.2 one such field failed the whole call with `unexpected_shape` and withheld `summary.total`,
  and an installed 2.6.2 or 2.6.3 still does: upgrade. The tool's description, the
  `echelongraph://methodology` resource and the README say that `cve_summary`'s `data` is the
  API's JSON less what the note names as left out (#2771).
- `echelongraph://sources` says what the NVD poller's `poll_count` and `poll_errors` are whenever
  it relays either: that one instance's counters since it last started, zeroed on every restart,
  never the feed's reliability. The resource's description and the README name all four fields it
  relays. A `poller` the answer sends as something other than a JSON object is named as such,
  never as a missing block (#2770).
- package.json's `description` fits the 255 characters npm's registry serves, so npm search,
  `npm view` and the package page show it whole, with the per-CVE exposure footprint, its Shodan
  attribution and Shodan's ownership sentence; through 2.6.3 npm cut the 443-character text
  mid-phrase. A test holds it to 255 characters and whole sentences (#2779).
- package.json's `keywords`, and the public repository's GitHub topics, are held to the
  description's wording rules by a test: no claim the package's own copy is barred from, no
  ip:port service count named as machines, and nothing exclusive or comparative (#2780).
- Tests: check_sbom's description and the README's privacy section are pinned to saying that over
  the hosted endpoint the document is the request body and reaches EchelonGraph's server, which
  neither logs nor keeps it, and to never denying that the document is sent (#2796). The denials
  are one list, `test/document-denials.mjs`, that the monorepo's /pulse/mcp check reads too, in
  every noun `check_sbom` uses for its input; the README check's own list had passed "The server
  never sends the document.", "The document is processed locally." and "Only the purls are sent."
  (#2796, #2795).
- `check_sbom`'s `sbom` argument said "its purls are read here and only they are sent", which over
  the hosted endpoint is not so: there the whole document is the request body. It now says the
  purls are read by this MCP server and only they are sent to the API, and that over the hosted
  endpoint (mcp.echelongraph.io) the document is the request body, in the description's own words.
  The README Tools table's `check_sbom` row, which ended "the document is not.", says the same.
  Tests: every string of `check_sbom`'s tools/list entry, its argument and output descriptions
  among them, and that README row are now held to the denial list, which also reads "not sent on"
  as true only when the clause ends there, and catches more wordings of where the document stays
  or is processed (#2796).

## 2.6.3 — 2026-10-04

- `exposure_radar` relays the observation window each count was measured over, where the API now
  serves one: `exposed_databases.window` (when our verifier last confirmed each host),
  `leaked_credentials.window` (when each key was last seen) and `shadow_ai.confirmed_exposed.window`
  (when our verifier's deciding probe ran). A window is relayed only when no counted row is undated;
  otherwise the note says how many are, and a malformed window is left out and named. KEV-exposure
  carries no observation time yet. `exposure_radar` stays `not_assessed` with `measured_at` null:
  a window's end is not one observation time (#2438).
- `vendor_advisories_for_cve`, `search_vendor_advisories` and `get_vendor_advisory` read each
  vendor's window from `GET /api/v1/public/vendor-advisories/coverage` beside their own request,
  and relay it in `coverage` (`vendor_windows`, or `vendor_window` for the detail): the advisories
  held, `earliest_vendor_published_at`, `latest_vendor_published_at` and `history_backfill`.
  `vendor_advisories_for_cve` adds `cve_year` and `vendors_not_fully_held`, the vendors with no
  advisory in the answer of which EchelonGraph holds none, whose earliest held advisory is dated
  after 1 January of the year in the CVE ID, or whose history is still being read, and its note
  names each with its window: an empty answer for CVE-2024-3400 can no longer be read as Palo Alto
  having published none. Its description no longer says an empty answer means none of the polled
  feeds names the CVE: it means none of the advisories EchelonGraph holds does. The search
  and the detail name the vendors whose history is still being read. When the windows cannot be
  read, the answer is still relayed, measured, with the windows null and a note saying so (#2729).
- `search_vendor_advisories`: a query of 1 or 2 characters matches whole words only
  (`search_match` `word`), as the API now answers it, and the description and the note say so; a
  search's total is counted to at most 1,000, and a capped total (`total_capped` true) is written
  "1,000+" in the note, never as a count. `coverage` gains `total_capped` and `search_match`
  (#2728).
- `check_sbom`'s 50-second budget bounds the whole call, not only when a batch may start: each
  batch's request may take only what is left of it, and a batch still unanswered when the budget
  runs out is cut off and its purls answered as not sent (`not_sent_reason` `time_budget`). Before,
  a batch started at 49.9 s could run for the 15-second request timeout, past the 60-second limits
  of the SDK's client and the hosted endpoint, which then answered nothing at all. A Retry-After
  wait that ends at the budget's end, before any batch was answered, answers that 429 instead of
  sending a request with no time left (#2756).
- Repository only, not in the package: the production synthetic probes `check_sbom` with 201
  purls, so every run sends two batches, and fails the probe (`expectation_unmet`) unless both
  were answered; core-backend's tests fail when `MAX_COMPONENTS`, `MAX_PURL_LEN` or
  `API_COMPONENTS_PER_MINUTE` disagree with the API's own values, and every core-backend deploy runs
  them before it builds (`scripts/check-outbound-identity.sh`'s table), refusing on drift (#2757).
- A success's first text block is cut to fit 30,000 characters when the API's JSON is longer, and
  `structuredContent.data` still carries the answer whole. Through 2.6.2 that block was the JSON
  whatever its size: on production's answers of 2026-10-04 a default `search_cves` for "openssl"
  was 133,300 characters of text, `get_cve` CVE-2021-44228 80,897, `check_affected` openssl 3.0.0
  156,058 (the Linux kernel at 5.10.0, 364,408), `check_sbom` on a 50-component SBOM 112,820,
  `kev_recent` at limit 200 105,925 and `search_vendor_advisories` at limit 50 103,147, against
  the 60,000-character ceiling; the same calls now measure 13,513, 22,960, 26,011 (27,777),
  28,793, 31,583 and 23,028. The JSON is first laid out one row a line, which loses nothing; past
  that, a list tool cuts each row to the fields it names (the description cut to 200 characters,
  every long string ending in "…"), then to fewer, and leaves rows out only when its leanest cut
  is still too long (`check_sbom` leaves out `not_affected` rows first); `get_cve` keeps the first
  entries of `cpe_match` and `references`. The note then ends with a sentence starting
  `TEXT CUT` that names what the first text block leaves out, which tool returns a row whole, and,
  when rows are left out, the `offset` or page size at which they fit. An answer that fits is sent
  as before. Every tool description, the server instructions and the methodology resource say so
  (#2783).
- `search_cves` takes `offset` (0 to 10,000), so the next page a cut text names can be read (#2783).
- A list beside the rows is cut before the rows are: `check_affected`'s `excluded` and
  `undetermined` samples keep each entry's `cve_id` and `reason`, and `cve_ids` (each match's
  `cve_id`, in order) its first 10, so every match stays in the text (`flash_player` 10.0.0, 200
  matches and 50 excluded entries, had 75 matches left out of it, two of them KEV-listed), and `check_sbom`'s `not_sent_purls` keeps its first 10, with the note
  saying from which position of the input the purls not sent run. A 2,000-purl `check_sbom` call
  that the API's budget stops after 1,200 now keeps the affected rows before the clean ones in the
  text. A cut `check_affected` match keeps `match_reason` (a registry match's advisory interval,
  which names the fixed version) where it fits, and the note names `cve_intel` for fixed versions
  (#2783).

## 2.6.2 — 2026-10-04

- `kev_recent` reads an RFC 3339 `since` or `until` as the date written in it, dropping the time
  and offset. It used to convert the timestamp to UTC first, so `2024-04-12T00:00:00+02:00` was
  answered for 2024-04-11, and `2024-04-12T23:30:00-05:00` for 2024-04-13, while still reporting
  a measured result. `kev_added_date` is a calendar date, so the written date is the one meant.
  `Z` timestamps, such as those `get_cve` returns, are unaffected (#2755).
- Hosted endpoint only: a `tools/call` of `check_sbom`, or a `prompts/get` of `sbom_review`, may
  now send a request body of up to 6 MiB, so a real CycloneDX or SPDX document (up to the tool's
  5,000,000-character cap) is accepted over `https://mcp.echelongraph.io/mcp`; before, any body
  over 64 KiB was refused, and only a purl list fit. Every other request keeps the 64 KiB cap.
  Each server instance serves at most two such large bodies at once; a third is answered HTTP 503
  with `Retry-After` and JSON-RPC error `-32030`. The per-client limit is unchanged (120 requests
  a minute). New settings `MCP_MAX_SBOM_BODY_BYTES` and `MCP_LARGE_BODY_SLOTS`. The `check_sbom`
  description and the README say that over the hosted endpoint the document reaches
  EchelonGraph's server, which reads the purls from it and neither logs nor keeps it (#2747).
- `cve_summary` says what the answer's `poller` block is: the in-memory counters of the NVD
  poller of the one API instance that answered, since it last started, zeroed on every restart,
  never the feed's size, intake, reliability or freshness. The note says so whenever the block is
  present, quoting `cves_ingested`, `poll_count` and `poll_errors`; the description and the
  outputSchema describe the block and each counter. The JSON is still relayed as sent (#2647).

## 2.6.1 — 2026-10-04

- Hosted endpoint only: when the production synthetic calls `https://mcp.echelongraph.io/mcp`, the
  endpoint marks its own API calls with a fixed `echelongraph-mcp-synthetic/1.0` token, so the
  synthetic is never counted as hosted use. The client's own text is never passed through. The
  `mcp_request` log line gains `client_public` (#2737).
- stdio behaviour is unchanged.

## 2.6.0 — 2026-10-04

- `check_sbom` checks up to 2,000 distinct purls per call, instead of refusing more than 200: it
  sends them as consecutive batches of at most 200, merges the answers (rows in input order with
  `index` counted across batches; summary counts and `not_assessed_by_reason` summed; `partial`
  true when any batch's was), and waits out a 429's `Retry-After` within 50 seconds per call.
  When a wait would pass that, or a batch after the first fails, it answers what it has, with the
  purls not sent counted in `coverage.not_sent`, the reason in `coverage.not_sent_reason`, and
  the list in `data.not_sent_purls`, never dropped silently. More than 2,000 is refused. New
  coverage fields: `distinct_purls`, `batch_size`, `batches`, `batches_sent`, `not_sent`,
  `not_sent_reason`, `rate_limit_waits`, `waited_ms`. The `sbom_review` prompt says so (#2734).
- `kev_recent` reads an RFC 3339 timestamp for `since` or `until` (such as the
  `kev_added_date` `get_cve` returns, `2024-04-12T00:00:00Z`) as its UTC date; other text is still
  refused. The `triage_cve` prompt's step 6 says to pass the date part of `kev_added_date` (#2736).
- README: the hosted endpoint, `https://mcp.echelongraph.io/mcp`, is described as in service,
  no longer as being rolled out (#2739).
- This changelog's preamble says the issue numbers refer to EchelonGraph's internal tracker,
  which is not public (#2740).

## 2.5.1 — 2026-10-04

- `search_cves` sends its search text in the `X-EG-Search` request header instead of the URL
  query string, so the text is kept out of request URLs, which the hosting platform's tracing
  records (#1983). Severity, minimum CVSS, sort and limit stay in the query string.

## 2.5.0 — 2026-10-04

- Four prompts (`triage_cve`, `kev_weekly_brief`, `am_i_affected`, `sbom_review`) and three
  resources (`echelongraph://methodology`, `echelongraph://sources`, `cve://{cve_id}`), in both
  protocol eras (#2722).
- README: a quick start for Claude Desktop, Claude Code, Cursor, VS Code, Windsurf and Cline,
  and for the hosted endpoint; a title and an example question per tool; what is sent where;
  the API's and the hosted endpoint's rate limits; the HTTP entrypoint's settings.
- This changelog, now in the npm package.
- `server.json`: a description covering the 14 tools, and the icon.

## 2.4.0 — 2026-10-04

Nine new tools, 14 in all (#2726):

- `kev_recent`: the CVEs CISA has added to its KEV catalog, newest first, with due date,
  ransomware use, EPSS and when EchelonGraph first saw each in the catalog; filter by date
  range, ransomware and vendor, and page with a cursor (#2717).
- `epss_history`: how one CVE's EPSS score has changed, as EchelonGraph recorded it, change-only
  and never a daily series (#2718).
- `check_affected`: whether a product (CPE path) or a registry package at a version is affected
  by known CVEs; `assessed` false is never "not affected" (#2716).
- `check_sbom`: up to 200 purls, or a CycloneDX or SPDX JSON document read on your machine,
  checked against the advisory corpus, one verdict per component (#2721).
- `cve_intel`: weakness (CWE), public exploit code, affected packages and fixed versions for one
  CVE (#2720).
- `get_cwe`: one CWE and the CVEs classified under it, CISA-KEV-listed first (#2720).
- `vendor_advisories_for_cve`, `get_vendor_advisory`, `search_vendor_advisories`: the
  vendor-published advisories that name a CVE, one advisory in full, and search (#2719).

Also:

- An HTTP entrypoint, `dist/http.js` (`npm run start:http`): the same tools over stateless
  Streamable HTTP on `POST /mcp`, in both protocol eras, with an Origin policy, a per-client limit
  and a body cap. It is what EchelonGraph's hosted endpoint, `https://mcp.echelongraph.io/mcp`,
  runs (#2316).
- `ECHELONGRAPH_MCP_UA`: one product token put ahead of the package's User-Agent, so an
  automated caller such as a monitor is told apart from people using the server (#2724).
- Inputs a user types for `check_affected`, `kev_recent` and `search_vendor_advisories` travel in
  `X-EG-*` request headers, never in the URL (#1983).
- `get_cve` relays NVD's configuration tree (`cpe_configurations`) when the API serves it, and
  says when it does not; a missing tree does not mean no product is affected (#2720).
- A failure message names the HTTP method of a request that is not a GET (`check_sbom`'s POST).
- Listing files for directories (`glama.json`, a `Dockerfile`, an MCPB manifest); none of them is
  in the npm package (#2723).

## 2.3.4 — 2026-09-30

- `cve_summary` says what `summary.nvd_critical` … `summary.nvd_none` count (the same active
  CVEs by NVD's severity label, as provenance, never EchelonGraph's severity) and what
  `summary.rejected` counts (withdrawn records, outside the total) (#2641).

## 2.3.3 — 2026-09-30

- The first release published by the public repo's release workflow, with npm provenance. No
  change to the server beyond the version (#2317).

## 2.3.2 — 2026-09-30

- `cve_summary`: `summary.none` is labelled as CVEs not yet scored, never as a severity rating of
  None (#2610).

## 2.3.1 — 2026-09-30

- `get_cve` and `search_cves` label a CVE EchelonGraph has not scored NOT YET SCORED (a rejected
  record NOT SCORED), never as an EchelonGraph score of 0 (#2535).

## 2.3.0 — 2026-09-30

- `exposure_radar` reads a fifth radar, `mcp_servers`: hostnames named like an MCP server in
  EchelonGraph's own Certificate Transparency feed, by their latest verdict on record (RFC 9728
  protected, pending re-adjudication, or not assessed by reason), with the protocol era and
  transport splits. An answer that does not say `service` `mcp` is refused, never relayed (#2315).

## 2.2.0 — 2026-09-28

- `not_assessed` no longer says its numbers are not findings: a count it relays is what the
  source holds on record, undated (#2465).
- The last text block stops repeating what an earlier block already says (#2467).

## 2.1.0 — 2026-09-27

- `cve_exposure` answers `not_assessed`, with `measured_at` null: its `last_seen` is when
  EchelonGraph last wrote a row, not when a service was observed (#2439).
- Every result's last text block carries the structured result, for clients that pass only
  `content` to the model (#2440).

## 2.0.0 — 2026-09-27

- Both MCP protocol eras on stdio: `server/discover` (2026-07-28) and `initialize` (2025-11-25
  and earlier) (#2311).
- Every tool has a title, annotations (`readOnlyHint` and the rest) and an `outputSchema`; every
  result carries `structuredContent` with `state`, `measured_at`, `method`, `coverage`,
  `freshness` and `notes` (#2313).
- `@modelcontextprotocol/server` 2.1.0 replaces `@modelcontextprotocol/sdk` 1.x; Node.js 20 or
  later (Node.js 18 dropped).

## 1.0.4 — 2026-09-27

- `exposure_radar` labels every number of every radar by what it counts, leaves out and names a
  field it cannot label, and never relays a CVE the radar does not track as "0 exposed" (#2313).
- `exposure_radar` relays each radar's `last_run_at`, its last completed check (#2335).
- The MIT `LICENSE` file ships in the package.

## 1.0.3 — 2026-09-27

- `exposure_radar` regroups the shadow-AI radar's numbers by what each counts
  (`confirmed_exposed`, `observed`, `authentication`) and relays no number unlabelled (#2307).

## 1.0.2 — 2026-09-27

- Freshness is the radar's last completed cycle, not a follower instance's zero time (#2307).
- Every Shodan-derived field states Shodan's ownership and copyright (#2306).

## 1.0.1 — 2026-09-27

- An API failure is an error result, never a success with empty data (#1874).
- Wording: no claim the code does not support; exposure counts are internet-facing services
  (distinct ip:port), attributed as derived from Shodan data (#2306).
- `cve_exposure` refuses an id that is not a CVE ID, and reports a CVE outside the radar's
  tracked set as not assessed, not 0 (#2313).
- `mcpName` and `server.json` for the official MCP Registry (#1879); the handshake and the
  User-Agent carry the package version.

## 1.0.0 — 2026-06-25

- First release: `cve_summary`, `search_cves`, `get_cve`, `cve_exposure` and `exposure_radar`
  over stdio.
