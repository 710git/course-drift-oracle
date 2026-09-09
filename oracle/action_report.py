"""Turn a drift_scan.py findings.json into what a GitHub Action run needs.

Three outputs from one findings file, each optional on its own:

  * a markdown table written to $GITHUB_STEP_SUMMARY, so a human looking at
    the run gets a readable table instead of raw JSON.
  * inline annotations on stdout (`::error` / `::warning` workflow commands),
    so GitHub's Checks UI and, when the finding's file/line are part of a
    diff, the PR "Files changed" view surface each finding directly.
  * `critical-count` / `warning-count` / `info-count` written to
    $GITHUB_OUTPUT, so a workflow step can assert on them (the smoke test
    does exactly this) or gate on them downstream.

This script never fails the job itself: it always exits 0. Gating on
severity is drift_scan.py's `--fail-on` job (it already exited 2 before this
script ever ran); this script's job is only to report what happened, even
when the scan step failed, which is why the composite action runs it with
`if: always()`.

$GITHUB_STEP_SUMMARY and $GITHUB_OUTPUT are both no-ops when unset, which is
what lets this run standalone on a laptop:

    python action_report.py --findings findings.json
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

# Step summaries have a real size ceiling (about 1 MiB) on GitHub's side.
# 200 rows of this table is nowhere near that, but it matches drift_scan.py's
# own --summary truncation convention (its top-15-then-"N more" list), so a
# reader who has seen one tool's output recognizes the other's shape.
MAX_TABLE_ROWS = 200

SEVERITIES = ("critical", "warning", "info")


def load_findings(findings_path: Path) -> list[dict]:
    data = json.loads(findings_path.read_text(encoding="utf-8"))
    return data.get("findings", [])


def count_by_severity(findings: list[dict]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        severity = finding.get("severity")
        if severity in counts:
            counts[severity] += 1
    return counts


def build_summary_table(findings: list[dict]) -> str:
    """Markdown table: Severity, File:Line, Subject, Detail.

    Truncated past MAX_TABLE_ROWS rows with an "N more" line, same idea as
    drift_scan.py's --summary output.
    """
    lines = [
        "| Severity | File:Line | Subject | Detail |",
        "| --- | --- | --- | --- |",
    ]
    shown = findings[:MAX_TABLE_ROWS]
    for finding in shown:
        severity = finding.get("severity", "")
        location = f"{finding.get('file', '')}:{finding.get('line', '')}"
        subject = finding.get("subject", "")
        detail = finding.get("detail", "")
        lines.append(f"| {severity} | {location} | {subject} | {detail} |")
    remaining = len(findings) - len(shown)
    if remaining > 0:
        lines.append(f"| | | | ...{remaining} more |")
    return "\n".join(lines)


def write_step_summary(findings: list[dict]) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    table = build_summary_table(findings)
    with open(summary_path, "a", encoding="utf-8") as handle:
        handle.write("## Drift scan findings\n\n")
        if findings:
            handle.write(table + "\n")
        else:
            handle.write("No findings.\n")


def print_annotations(findings: list[dict]) -> None:
    for finding in findings:
        severity = finding.get("severity")
        file_ = finding.get("file", "")
        line = finding.get("line", "")
        subject = finding.get("subject", "")
        detail = finding.get("detail", "")
        message = f"{subject}: {detail}"
        if severity == "critical":
            print(f"::error file={file_},line={line}::{message}")
        elif severity in ("warning", "info"):
            print(f"::warning file={file_},line={line}::{message}")


def write_github_output(counts: dict[str, int]) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    with open(output_path, "a", encoding="utf-8") as handle:
        handle.write(f"critical-count={counts['critical']}\n")
        handle.write(f"warning-count={counts['warning']}\n")
        handle.write(f"info-count={counts['info']}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", type=Path, required=True,
                         help="findings.json produced by drift_scan.py")
    args = parser.parse_args()

    findings = load_findings(args.findings)
    counts = count_by_severity(findings)

    write_step_summary(findings)
    print_annotations(findings)
    write_github_output(counts)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
