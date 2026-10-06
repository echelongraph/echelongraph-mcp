// Which reader a file goes to (#2835): by its format when the caller names one, else by its
// basename. A manifest that holds ranges, not resolved versions, is refused with the lockfile to
// pass instead; formats not read yet are refused as such. Nothing here guesses a format from a
// file's content.
import { Unreadable, type Parsed } from "./common.js";
import { readGoMod } from "./gomod.js";
import { readCargoLock, readComposerLock, readGemfileLock, readGradleLockfile, readPoetryLock } from "./lockfiles.js";
import { readNpmLock } from "./npmlock.js";
import { readRequirements } from "./requirements.js";

export { NOT_CHECKED_REASONS, Unreadable, type NotChecked, type NotCheckedReason, type Parsed, type Pinned } from "./common.js";

// The formats read, by the name the `format` argument takes, each with its purl type's ecosystem.
export const FORMATS = {
  "requirements.txt": { ecosystem: "PyPI", read: readRequirements },
  "go.mod": { ecosystem: "Go", read: readGoMod },
  "package-lock.json": { ecosystem: "npm", read: readNpmLock },
  "Cargo.lock": { ecosystem: "crates.io", read: readCargoLock },
  "Gemfile.lock": { ecosystem: "RubyGems", read: readGemfileLock },
  "composer.lock": { ecosystem: "Packagist", read: readComposerLock },
  "poetry.lock": { ecosystem: "PyPI", read: readPoetryLock },
  "gradle.lockfile": { ecosystem: "Maven", read: readGradleLockfile },
} as const;
export type Format = keyof typeof FORMATS;
export const FORMAT_NAMES = Object.keys(FORMATS) as Format[];

// Files that hold ranges or unselected versions, not what was installed: the file to pass instead.
const REFUSED: Record<string, string> = {
  "package.json": "package.json holds version ranges, not installed versions: pass package-lock.json or npm-shrinkwrap.json",
  "pyproject.toml": "pyproject.toml holds version ranges, not installed versions: pass poetry.lock, or a requirements.txt of == pins (pip freeze)",
  pipfile: "Pipfile holds version ranges, not installed versions: pass a requirements.txt of == pins (pipenv requirements)",
  gemfile: "Gemfile holds version ranges, not installed versions: pass Gemfile.lock",
  "gems.rb": "gems.rb holds version ranges, not installed versions: pass gems.locked",
  "cargo.toml": "Cargo.toml holds version ranges, not installed versions: pass Cargo.lock",
  "composer.json": "composer.json holds version ranges, not installed versions: pass composer.lock",
  "build.gradle": "build.gradle declares dependencies, not the versions resolved: pass gradle.lockfile (gradle dependencies --write-locks)",
  "build.gradle.kts": "build.gradle.kts declares dependencies, not the versions resolved: pass gradle.lockfile (gradle dependencies --write-locks)",
  "go.sum": "go.sum is refused: it lists every module version the module graph mentions, not the version the build selects: pass go.mod",
  "go.work": "go.work names workspace modules, not dependency versions: pass each module's go.mod",
  // Not read yet (#2835's deferred list).
  "pom.xml": "pom.xml is not read: its versions need the effective POM (parents, properties, dependencyManagement), which this tool does not build",
  "yarn.lock": "yarn.lock is not read yet",
  "pnpm-lock.yaml": "pnpm-lock.yaml is not read yet",
  "pipfile.lock": "Pipfile.lock is not read yet: pass a requirements.txt of == pins (pipenv requirements)",
};

const basename = (f: string): string => f.replace(/\\/g, "/").split("/").pop() ?? f;

// The format a filename names, or why it names none.
export function detect(filename: string): { format: Format } | { refused: string } {
  const base = basename(filename.trim());
  const lower = base.toLowerCase();
  if (lower === "go.mod") return { format: "go.mod" };
  if (lower === "package-lock.json" || lower === "npm-shrinkwrap.json") return { format: "package-lock.json" };
  if (lower === "cargo.lock") return { format: "Cargo.lock" };
  if (lower === "gemfile.lock" || lower === "gems.locked") return { format: "Gemfile.lock" };
  if (lower === "composer.lock") return { format: "composer.lock" };
  if (lower === "poetry.lock") return { format: "poetry.lock" };
  // gradle.lockfile, buildscript-gradle.lockfile, and the older per-configuration
  // gradle/dependency-locks/<configuration>.lockfile.
  if (lower.endsWith(".lockfile")) return { format: "gradle.lockfile" };
  if (lower.endsWith(".txt") && /requirements|constraints/.test(lower)) return { format: "requirements.txt" };
  if (REFUSED[lower]) return { refused: REFUSED[lower] };
  return { refused: `${base || "(no filename)"} is not a file name this tool reads; the formats read are ${FORMAT_NAMES.join(", ")} (and npm-shrinkwrap.json, gems.locked): name the file so, or set its format` };
}

// One file read, or why it could not be.
export function readFile(format: Format, content: string): Parsed | { unreadable: string } {
  try {
    // A byte-order mark, which some Windows editors write, is not part of the file's text.
    return FORMATS[format].read(content.replace(/^\uFEFF/, ""));
  } catch (e) {
    if (e instanceof Unreadable) return { unreadable: `it ${e.message}` };
    throw e;
  }
}
