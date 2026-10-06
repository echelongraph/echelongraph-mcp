// requirements.txt (#2835): pip's requirements file format
// (pip.pypa.io/en/stable/reference/requirements-file-format/), each requirement a PEP 508
// specifier (packaging.python.org/en/latest/specifications/dependency-specifiers/).
//
// Only a requirement pinned to one version by a single == or === clause gives a version
// (django==4.2.7). A range (django>=4, ~=4.2, a == with a wildcard such as ==1.4.*, or several
// clauses) is version_unpinned and its bound is never sent as a version: pkg:pypi/django@4 would
// be checked as if 4 were installed. Extras ([bcrypt]) and environment markers (; python_version
// < "3.8") are stripped; per-requirement options (--hash) are ignored. -r and -c name another
// file, which is not read here (unsupported_line: pass it as its own file); -e, a direct URL
// (name @ https://…) and a bare path or URL are vcs_source, local_path or unsupported_line. Global
// options (--index-url and the rest) are not dependencies and are not counted.
import { emptyParsed, pep503, purlOf, specOf, usableVersion, type NotCheckedReason, type Parsed } from "./common.js";

// The logical lines: comments removed (a line starting with #, or whitespace then #), a trailing
// backslash joining the next line, each with the 1-based number of its first physical line.
function logicalLines(text: string): { text: string; line: number }[] {
  const out: { text: string; line: number }[] = [];
  let buf = "";
  let start = 0;
  text.split(/\r?\n/).forEach((raw, i) => {
    if (buf === "") start = i + 1;
    let l = raw;
    if (/^\s*#/.test(l)) l = "";
    else l = l.replace(/\s#.*$/, "");
    if (/\\$/.test(l)) {
      buf += l.slice(0, -1) + " ";
      return;
    }
    buf += l;
    if (buf.trim()) out.push({ text: buf.trim(), line: start });
    buf = "";
  });
  if (buf.trim()) out.push({ text: buf.trim(), line: start });
  return out;
}

const VCS = /^(git|hg|svn|bzr)\+/i;
const URL = /^[a-z][a-z0-9+.-]*:\/\//i;
// A local archive or path: pip installs it from the file, not from the index.
const LOCAL = /^(\.{1,2}([\\/]|$)|[\\/]|~|[A-Za-z]:[\\/]|file:)|\.(whl|tar\.gz|tgz|zip|tar\.bz2)$/i;

// Where a non-registry source points: VCS, a local path, or another URL.
function sourceReason(target: string): { reason: NotCheckedReason; detail: string } {
  if (VCS.test(target)) return { reason: "vcs_source", detail: "a VCS checkout, whose code need not match the PyPI release of the same version" };
  if (/^file:/i.test(target) || !URL.test(target)) return { reason: "local_path", detail: "a local path or archive, not a PyPI release" };
  return { reason: "unsupported_line", detail: "a direct URL, not a PyPI release" };
}

const NAME = /^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(\[[^\]]*\])?\s*(.*)$/s;
const CLAUSE = /^(===|==|!=|~=|<=|>=|<|>)\s*(\S+)$/;
// Per-requirement options pip takes after a specifier: not part of it.
const PER_REQUIREMENT = /\s--?(hash|global-option|install-option|config-settings)\b.*$/s;

export function readRequirements(text: string): Parsed {
  const p = emptyParsed();
  for (const { text: l, line } of logicalLines(text)) {
    const miss = (name: string | null, reason: NotCheckedReason, detail: string) => p.not_checked.push({ name, spec: specOf(l), reason, line, detail });
    if (l.startsWith("-")) {
      const m = /^(-[a-zA-Z]|--[a-z-]+)(?:\s*=\s*|\s+)?(.*)$/s.exec(l);
      const opt = m?.[1] ?? l;
      const value = (m?.[2] ?? "").trim();
      if (["-r", "--requirement", "-c", "--constraint"].includes(opt)) {
        miss(null, "unsupported_line", `names another file (${opt}), which this tool does not read from here: pass that file's text as its own entry in files`);
      } else if (["-e", "--editable"].includes(opt)) {
        const s = sourceReason(value);
        miss(/[#&]egg=([A-Za-z0-9._-]+)/.exec(value)?.[1] ?? null, s.reason, `an editable install: ${s.detail}`);
      }
      // Any other option (--index-url, --hash on a line of its own, …) names no dependency.
      continue;
    }
    const spec = l.replace(PER_REQUIREMENT, "").trim();
    // A bare path, archive or URL; "name @ url" is a named requirement, read below.
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]*\s*(\[[^\]]*\])?\s*@/.test(spec) && (VCS.test(spec) || URL.test(spec) || LOCAL.test(spec))) {
      const s = sourceReason(spec);
      miss(/[#&]egg=([A-Za-z0-9._-]+)/.exec(spec)?.[1] ?? null, s.reason, s.detail);
      continue;
    }
    // A marker follows ';'; it does not change which version is pinned.
    const req = spec.split(";")[0].trim();
    const m = NAME.exec(req);
    if (!m) {
      miss(null, "unsupported_line", "not a requirement specifier this reader takes (PEP 508 name, then a version specifier)");
      continue;
    }
    const name = m[1];
    let rest = m[3].trim();
    if (rest.startsWith("@")) {
      const s = sourceReason(rest.slice(1).trim());
      miss(name, s.reason, s.detail);
      continue;
    }
    if (rest.startsWith("(") && rest.endsWith(")")) rest = rest.slice(1, -1).trim();
    if (rest === "") {
      miss(name, "version_unpinned", "no version is given, so any release may be installed");
      continue;
    }
    const clauses = rest.split(",").map((c) => c.trim()).filter(Boolean);
    const parsed = clauses.map((c) => CLAUSE.exec(c));
    if (parsed.some((c) => c === null)) {
      miss(name, "unsupported_line", "a version specifier this reader cannot read");
      continue;
    }
    const only = parsed.length === 1 ? parsed[0]! : null;
    const pinned = only && (only[1] === "==" || only[1] === "===") ? only[2] : null;
    if (pinned === null || pinned.includes("*")) {
      miss(name, "version_unpinned", "a range, not one version: pip may install any release it allows, so none is checked");
      continue;
    }
    if (pinned.includes("$")) {
      miss(name, "version_unresolved", "the version is an environment variable, which this tool does not expand");
      continue;
    }
    if (!usableVersion(pinned)) {
      miss(name, "unsupported_line", "the pinned version cannot be read");
      continue;
    }
    p.pinned.push({ purl: purlOf("pypi", pep503(name), pinned), line });
  }
  return p;
}
