"""Scan the course for pinned facts that have drifted from upstream reality.

Teaching material rots in a specific, boring, mechanical way: it names a model
that got retired, or pins a package below the version its own code now needs.
Nobody notices until a learner hits the error. Answering "which lessons are
broken right now?" is not a lookup - the answer does not exist anywhere until
somebody does the work of checking. That is what makes the output worth
something to a downstream agent: it is *manufactured* data, not scraped data.

Two check families, deliberately different in where their truth comes from:

  * model pins  - matched against `model_catalog.json`, a curated file. The
                  catalog is the human-maintained asset; the scanner is just
                  the thing that applies it at scale.
  * package pins - matched against the live PyPI JSON API (public, no auth).

Package drift severity thresholds (open floors only, i.e. `>=` or `>` with no
upper bound): the currently resolving version exceeding the pin's major
version is `critical` (a fresh install crosses a breaking release boundary);
staying within the same major but drifting 5 or more minor versions ahead is
`warning` (still probably fine, but no longer close to what the lesson was
written against); anything smaller is `info`. Non-open-floor pins (`==`,
`~=`) that PyPI has since moved past are always `info` - they are exact or
compatible-release pins, not the "silently install something newer" shape.
PyPI is queried at most once per distinct package name per run (in-memory
cache) and at most `--max-pypi` times total, since `--include-translations`
can repeat the same package name across up to 55 locale trees.

Run:
    python drift_scan.py --repo-root .. --out findings.json
    python drift_scan.py --offline          # skip PyPI, model checks only
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

# Directories that are copies or renderings of the lessons rather than sources
# of truth. Scanning them would multiply every finding by the translation count.
# "translations" is handled separately (see --include-translations) rather than
# listed here, since whether it is excluded depends on a flag.
EXCLUDED_DIRS = {
    "translated_images",
    "images",
    ".git",
    "node_modules",
    "agent-economy",
}

TRANSLATIONS_DIR = "translations"

SCANNED_SUFFIXES = {".ipynb", ".py", ".md"}

# A model id only counts as a *pin* when something binds it: quotes, backticks,
# or an env-var assignment. Bare prose ("we used gpt-4o for this") is a mention,
# not a pin, and flagging it would bury the real findings. Three forms, because
# the course uses all three and missing any one of them makes the report a lie
# by omission - the env-var form in particular is how lessons actually name a
# Foundry deployment.
MODEL_ID = r"(?:gpt|o|claude|gemini|llama|mistral|phi)-[A-Za-z0-9._-]+"
MODEL_PATTERNS = (
    re.compile(rf"""["']({MODEL_ID})["']"""),          # "gpt-4o" / 'gpt-4o'
    re.compile(rf"`({MODEL_ID})`"),                     # `gpt-4o` in markdown
    re.compile(rf"[A-Z_]*(?:MODEL|DEPLOYMENT)[A-Z_]*\s*=\s*({MODEL_ID})"),
)


def find_model_pins(line: str) -> list[str]:
    """Return every distinct model id pinned on this line."""
    seen: list[str] = []
    for pattern in MODEL_PATTERNS:
        for match in pattern.finditer(line):
            model_id = match.group(1).rstrip(".,;:")
            if model_id not in seen:
                seen.append(model_id)
    return seen

REQUIREMENT_PATTERN = re.compile(
    r"^\s*([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(>=|==|~=|>)\s*([0-9][A-Za-z0-9._-]*)"
)

PYPI_URL = "https://pypi.org/pypi/{package}/json"


# --------------------------------------------------------------------------
# discovery
# --------------------------------------------------------------------------

def iter_source_files(repo_root: Path, include_translations: bool = False):
    """Yield lesson source files, skipping vendored trees.

    Translations are skipped unless `include_translations` is set, matching
    the default (`en`-only) report.
    """
    for path in sorted(repo_root.rglob("*")):
        if path.suffix not in SCANNED_SUFFIXES or not path.is_file():
            continue
        parts = path.relative_to(repo_root).parts
        if any(part in EXCLUDED_DIRS for part in parts):
            continue
        if not include_translations and TRANSLATIONS_DIR in parts:
            continue
        yield path


def locale_for(parts: tuple[str, ...]) -> str:
    """Locale implied by a path's parts: the translation dir name, or `en`."""
    if len(parts) > 1 and parts[0] == TRANSLATIONS_DIR:
        return parts[1]
    return "en"


def notebook_text_lines(path: Path) -> list[str]:
    """Flatten a notebook's source cells into lines.

    Notebook line numbers are reported against this flattened view rather than
    the raw .ipynb JSON, because "cell 4, line 3" is what a reader can act on
    and the JSON line number is not.
    """
    try:
        notebook = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return []
    lines: list[str] = []
    for cell in notebook.get("cells", []):
        source = cell.get("source", [])
        if isinstance(source, str):
            source = source.splitlines(keepends=True)
        lines.extend("".join(source).splitlines())
        lines.append("")
    return lines


def file_lines(path: Path) -> list[str]:
    if path.suffix == ".ipynb":
        return notebook_text_lines(path)
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        return []


# --------------------------------------------------------------------------
# model pin checks
# --------------------------------------------------------------------------

def load_catalog(catalog_path: Path) -> dict:
    return json.loads(catalog_path.read_text(encoding="utf-8"))


def check_model_pins(
    repo_root: Path, catalog: dict, include_translations: bool = False
) -> tuple[list[dict], int]:
    """Flag every quoted model id whose catalog status is not `current`."""
    statuses = catalog.get("models", {})
    findings: list[dict] = []
    scanned = 0

    for path in iter_source_files(repo_root, include_translations):
        scanned += 1
        relative_path = path.relative_to(repo_root)
        relative = relative_path.as_posix()
        locale = locale_for(relative_path.parts) if include_translations else None
        for line_number, line in enumerate(file_lines(path), start=1):
            for model_id in find_model_pins(line):
                entry = statuses.get(model_id)
                if entry is None:
                    finding = {
                        "kind": "model_pin",
                        "severity": "info",
                        "file": relative,
                        "line": line_number,
                        "subject": model_id,
                        "status": "unknown",
                        "detail": (
                            f"`{model_id}` is not in the catalog. Either it is "
                            "new and the catalog is stale, or it is a typo."
                        ),
                        "suggestion": None,
                    }
                    if locale is not None:
                        finding["locale"] = locale
                    findings.append(finding)
                    continue
                if entry.get("status") == "current":
                    continue
                finding = {
                    "kind": "model_pin",
                    "severity": entry.get("severity", "warning"),
                    "file": relative,
                    "line": line_number,
                    "subject": model_id,
                    "status": entry.get("status"),
                    "detail": entry.get("detail", ""),
                    "suggestion": entry.get("replacement"),
                }
                if locale is not None:
                    finding["locale"] = locale
                findings.append(finding)
    return findings, scanned


# --------------------------------------------------------------------------
# package pin checks
# --------------------------------------------------------------------------

def parse_version(version: str) -> tuple:
    """Compare-able tuple from a dotted version, ignoring any suffix.

    Good enough for "is the pin behind the latest release" and honest about
    not being a full PEP 440 implementation - pre-release ordering is not
    something this check needs to get right.
    """
    parts: list[int] = []
    for chunk in version.split("."):
        digits = re.match(r"\d+", chunk)
        if not digits:
            break
        parts.append(int(digits.group()))
    return tuple(parts)


def fetch_latest_version(package: str, timeout: float = 10.0) -> str | None:
    request = urllib.request.Request(
        PYPI_URL.format(package=package),
        headers={"User-Agent": "course-drift-oracle/1.0 (+public PyPI JSON API)"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.load(response)["info"]["version"]
    except (urllib.error.URLError, KeyError, json.JSONDecodeError, TimeoutError):
        return None


class PypiLookup:
    """Per-run cache over the live PyPI JSON API, with a total call budget.

    Multiple requirements.txt files (and, with --include-translations, up to
    55 locale copies of the same file) routinely name the same package. This
    fetches each distinct package at most once per run, and refuses to make
    more than `max_calls` live requests total.
    """

    def __init__(self, max_calls: int | None = None):
        self._cache: dict[str, str | None] = {}
        self.calls = 0
        self.capped: set[str] = set()
        self._max_calls = max_calls

    def latest(self, package: str) -> str | None:
        if package in self._cache:
            return self._cache[package]
        if self._max_calls is not None and self.calls >= self._max_calls:
            self.capped.add(package)
            return None
        self.calls += 1
        version = fetch_latest_version(package)
        self._cache[package] = version
        return version


def check_package_pins(
    repo_root: Path,
    offline: bool,
    include_translations: bool = False,
    pypi: PypiLookup | None = None,
) -> list[dict]:
    if pypi is None:
        pypi = PypiLookup()
    findings: list[dict] = []
    for requirements in sorted(repo_root.rglob("requirements.txt")):
        req_parts = requirements.relative_to(repo_root).parts
        if any(part in EXCLUDED_DIRS for part in req_parts):
            continue
        if not include_translations and TRANSLATIONS_DIR in req_parts:
            continue
        relative = requirements.relative_to(repo_root).as_posix()
        locale = locale_for(req_parts) if include_translations else None
        for line_number, line in enumerate(
            requirements.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if line.lstrip().startswith("#") or not line.strip():
                continue
            match = REQUIREMENT_PATTERN.match(line)
            if not match:
                # An unpinned requirement is itself a finding: the lesson will
                # silently install whatever shipped this morning.
                name = line.strip().split("[")[0].split(";")[0].strip()
                if name and re.fullmatch(r"[A-Za-z0-9._-]+", name):
                    finding = {
                        "kind": "package_pin",
                        "severity": "warning",
                        "file": relative,
                        "line": line_number,
                        "subject": name,
                        "status": "unpinned",
                        "detail": (
                            f"`{name}` has no version constraint, so the lesson "
                            "installs whatever is latest at run time. A breaking "
                            "release upstream breaks the lesson with no diff here."
                        ),
                        "suggestion": None,
                    }
                    if locale is not None:
                        finding["locale"] = locale
                    findings.append(finding)
                continue

            name, operator, pinned = match.group(1), match.group(2), match.group(3)
            if offline:
                continue
            latest = pypi.latest(name)
            if latest is None:
                capped = name in pypi.capped
                finding = {
                    "kind": "package_pin",
                    "severity": "info",
                    "file": relative,
                    "line": line_number,
                    "subject": name,
                    "status": "capped" if capped else "unresolvable",
                    "detail": (
                        f"`{name}` PyPI lookup was skipped: --max-pypi budget "
                        "for this run was already spent."
                        if capped else
                        f"`{name}` could not be resolved on PyPI."
                    ),
                    "suggestion": None,
                }
                if locale is not None:
                    finding["locale"] = locale
                findings.append(finding)
                continue
            latest_parts, pinned_parts = parse_version(latest), parse_version(pinned)
            if latest_parts <= pinned_parts:
                continue

            open_floor = operator in (">=", ">") and latest_parts and pinned_parts
            # A major-version gap under an open floor is the dangerous shape,
            # and it is worth separating from a routine patch bump. `>=1.108.1`
            # resolves to 3.5.0 today: pip is satisfied, the lesson installs a
            # library two majors removed from the one its code was written
            # against, and nothing in the repo records that it happened.
            major_gap = open_floor and latest_parts[0] > pinned_parts[0]
            latest_minor = latest_parts[1] if len(latest_parts) > 1 else 0
            pinned_minor = pinned_parts[1] if len(pinned_parts) > 1 else 0
            minor_gap = (
                open_floor
                and not major_gap
                and latest_parts[0] == pinned_parts[0]
                and (latest_minor - pinned_minor) >= 5
            )
            if major_gap:
                finding = {
                    "kind": "package_pin",
                    "severity": "critical",
                    "file": relative,
                    "line": line_number,
                    "subject": name,
                    "status": "major_drift",
                    "detail": (
                        f"pinned `{operator}{pinned}` but PyPI now serves "
                        f"{latest} - {latest_parts[0] - pinned_parts[0]} major "
                        f"version(s) ahead. An open floor means a fresh install "
                        f"resolves to {latest}, so lesson code written for "
                        f"{pinned_parts[0]}.x runs against {latest_parts[0]}.x."
                    ),
                    "suggestion": f"{name}>={pinned},<{pinned_parts[0] + 1}",
                }
            elif minor_gap:
                finding = {
                    "kind": "package_pin",
                    "severity": "warning",
                    "file": relative,
                    "line": line_number,
                    "subject": name,
                    "status": "minor_drift",
                    "detail": (
                        f"pinned `{operator}{pinned}` but PyPI now serves "
                        f"{latest} - {latest_minor - pinned_minor} minor "
                        f"version(s) ahead within {pinned_parts[0]}.x. Still "
                        "the same major line, but far enough from the pin that "
                        "the lesson is no longer close to what it was written "
                        "against."
                    ),
                    "suggestion": f"{name}>={latest}",
                }
            else:
                finding = {
                    "kind": "package_pin",
                    "severity": "info",
                    "file": relative,
                    "line": line_number,
                    "subject": name,
                    "status": "behind",
                    "detail": (
                        f"pinned `{operator}{pinned}`, latest on PyPI is "
                        f"{latest}."
                    ),
                    "suggestion": f"{name}>={latest}",
                }
            if locale is not None:
                finding["locale"] = locale
            findings.append(finding)
    return findings


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------

def git_commit(repo_root: Path) -> str | None:
    try:
        return subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True, timeout=10,
        ).stdout.strip()
    except (subprocess.SubprocessError, OSError):
        return None


def git_remote_slug(repo_root: Path) -> str | None:
    """owner/repo of the target's origin remote, if it has one."""
    try:
        url = subprocess.run(
            ["git", "-C", str(repo_root), "remote", "get-url", "origin"],
            capture_output=True, text=True, check=True, timeout=10,
        ).stdout.strip()
    except (subprocess.SubprocessError, OSError):
        return None
    match = re.search(r"github\.com[:/]([^/]+/[^/]+?)(?:\.git)?$", url)
    return match.group(1) if match else None


def scan(
    repo_root: Path,
    catalog_path: Path,
    offline: bool,
    include_translations: bool = False,
    max_pypi: int | None = None,
) -> dict:
    catalog = load_catalog(catalog_path)
    model_findings, scanned = check_model_pins(repo_root, catalog, include_translations)
    package_findings = check_package_pins(
        repo_root, offline, include_translations, PypiLookup(max_pypi))

    findings = model_findings + package_findings
    # Stable ordering so the findings hash only changes when findings change,
    # not when the filesystem hands them back in a different order.
    findings.sort(key=lambda f: (f["file"], f["line"], f["subject"]))

    return {
        "meta": {
            "repo": git_remote_slug(repo_root),
            "commit": git_commit(repo_root),
            "scanned_files": scanned,
            "catalog_version": catalog.get("version"),
            "offline": offline,
        },
        "findings": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    here = Path(__file__).resolve().parent
    default_root = os.environ.get("DRIFT_TARGET_REPO")
    parser.add_argument(
        "--repo-root", type=Path,
        default=Path(default_root) if default_root else None,
        help="checkout of the repo to scan (or set DRIFT_TARGET_REPO)")
    parser.add_argument("--catalog", type=Path, default=here / "model_catalog.json")
    parser.add_argument("--out", type=Path, default=here / "findings.json")
    parser.add_argument("--offline", action="store_true",
                        help="skip live PyPI lookups")
    parser.add_argument("--include-translations", action="store_true",
                        help="also scan translations/<locale>/... (default: "
                             "en tree only); adds a 'locale' field to every "
                             "finding")
    parser.add_argument("--max-pypi", type=int, default=200,
                        help="max live PyPI lookups this run may make, after "
                             "the per-package cache (default: 200)")
    parser.add_argument("--summary", action="store_true",
                        help="print a human summary instead of JSON")
    args = parser.parse_args()

    if args.repo_root is None:
        parser.error("no target: pass --repo-root or set DRIFT_TARGET_REPO "
                     "to a local checkout of the repo to scan")
    if not (args.repo_root / ".git").exists():
        parser.error(f"{args.repo_root} does not look like a git checkout")

    result = scan(args.repo_root.resolve(), args.catalog, args.offline,
                  args.include_translations, args.max_pypi)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    findings = result["findings"]
    if args.summary:
        print(f"scanned {result['meta']['scanned_files']} files")
        if args.include_translations:
            # 55 locale directories means 55 per-locale rows would drown the
            # report; en gets its own line since it is the source of truth,
            # everything else rolls up into one combined line.
            en_by_severity: dict[str, int] = {}
            other_by_severity: dict[str, int] = {}
            other_count = 0
            for finding in findings:
                bucket = en_by_severity if finding.get("locale", "en") == "en" \
                    else other_by_severity
                bucket[finding["severity"]] = bucket.get(finding["severity"], 0) + 1
                if finding.get("locale", "en") != "en":
                    other_count += 1
            print(f"findings: {len(findings)} total")
            print(f"  en: {len(findings) - other_count}  {en_by_severity}")
            print(f"  other locales (rolled up): {other_count}  {other_by_severity}")
        else:
            by_severity: dict[str, int] = {}
            for finding in findings:
                by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + 1
            print(f"findings: {len(findings)}  {by_severity}")
        for finding in findings[:15]:
            print(f"  [{finding['severity']:8}] {finding['file']}:{finding['line']} "
                  f"{finding['subject']} ({finding['status']})")
        if len(findings) > 15:
            print(f"  ... and {len(findings) - 15} more")
    else:
        print(json.dumps(result["meta"], indent=2))
        print(f"{len(findings)} finding(s) -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
