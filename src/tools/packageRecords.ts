// #3285: which rows of a CVE's affected packages are one package, as core-backend's registry
// matcher reads them. A module of its own, with no import, so cve_remediation (fixed_branches) and
// cve_intel (affected_packages) state the same reading.
//
// core-backend cve/pkgecosystem.go: baseTokenMatchableEcosystems names the base tokens whose ":"
// suffix is a repository locator, not a release (Packagist, Maven), and ecosystemBaseToken is the
// lowercased, trimmed token before the first ":". cve/pkgmatch_fixedin.go registryRecordKey folds
// a suffixed ecosystem onto its base only when that base is one of them, so a row of one
// package_name under "Packagist:https://packages.drupal.org/8" and one under "Packagist" are one
// record, whose ranges the matcher walks together; a distro's release suffix (Debian:12,
// Alpine:v3.20) stays in the key and is never folded. CVE-2025-48013 lists drupal/quick_node_block
// under both (fixed 2.0.1 and fixed 2.0.0, each from 0): read row by row, a Packagist 1.0.0 gets
// 2.0.0, which the Drupal advisory still holds affected; as one package it gets 2.0.1, the
// matcher's fixed_in. (registryRecordKey also spells a PyPI name the PEP 503 way; a PyPI row is
// never listed under two ecosystem strings, so that plays no part here.)
export const BASE_MATCHABLE_ECOSYSTEMS: readonly string[] = ["packagist", "maven"];

const isObject = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const str = (v: unknown, k: string): string | undefined => {
  const x = isObject(v) ? v[k] : undefined;
  return typeof x === "string" && x.trim() ? x : undefined;
};

/** core-backend ecosystemBaseToken: the lowercased, trimmed token before the first ":". */
export function ecosystemBaseToken(raw: string): string {
  const t = raw.trim().toLowerCase();
  const i = t.indexOf(":");
  return i > 0 ? t.slice(0, i) : t;
}

/** The ecosystem part of core-backend's registryRecordKey: lowercased, folded onto its base only where the base is base-matchable. */
export function recordEcosystem(raw: string): string {
  const eco = raw.trim().toLowerCase();
  const base = ecosystemBaseToken(eco);
  return base !== eco && BASE_MATCHABLE_ECOSYSTEMS.includes(base) ? base : eco;
}

/** One package the rows list under more than one ecosystem string: its package_name, those strings as stored, and the rows' positions. */
export type ListedTwice = { name: string; ecosystems: string[]; rows: number[] };

/**
 * The packages `rows` (each with ecosystem and package_name) list under more than one ecosystem
 * string that the matcher folds into one record, in the order each was first listed; `folded` is
 * how many rows fold into another so.
 */
export function packagesListedTwice(rows: readonly unknown[]): { twice: ListedTwice[]; folded: number } {
  const groups = new Map<string, ListedTwice>();
  rows.forEach((r, i) => {
    const eco = str(r, "ecosystem");
    const name = str(r, "package_name");
    if (!eco || !name || !BASE_MATCHABLE_ECOSYSTEMS.includes(ecosystemBaseToken(eco))) return;
    const key = `${recordEcosystem(eco)}\u0000${name.trim().toLowerCase()}`;
    const g = groups.get(key) ?? { name, ecosystems: [], rows: [] };
    if (!g.ecosystems.includes(eco)) g.ecosystems.push(eco);
    g.rows.push(i);
    groups.set(key, g);
  });
  const twice = [...groups.values()].filter((g) => g.ecosystems.length > 1);
  return { twice, folded: twice.reduce((t, g) => t + g.rows.length - 1, 0) };
}

// What a note says of such rows, in cve_remediation's entries and cve_intel's rows alike: the rule
// the matcher applies, stated so that an agent walking the ranges reads them as it does.
export const ONE_PACKAGE_RULE = (what: "Entries" | "Rows"): string =>
  `${what} of one package_name under Packagist or Maven, bare or with a repository URL after ":", are one package, its ranges all of theirs together`;
