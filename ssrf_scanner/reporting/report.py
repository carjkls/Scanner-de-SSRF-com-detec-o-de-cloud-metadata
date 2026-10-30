"""Findings presentation: ANSI console report and JSON export."""

from __future__ import annotations

import dataclasses
import json
import sys

from ..core.detector import Finding

RESET = "\033[0m"
COLORS = {
    "critical": "\033[1;91m",  # bright red
    "high": "\033[1;31m",      # red
    "medium": "\033[0;33m",    # yellow
    "low": "\033[0;36m",       # cyan
    "info": "\033[0;37m",      # gray
}


def _use_color() -> bool:
    return sys.stdout.isatty()


def print_findings(findings: list[Finding], target: str) -> None:
    color = _use_color()
    print()
    print("=" * 72)
    print(f"SSRF scan report — {target}")
    print(f"findings: {len(findings)}")
    print("=" * 72)

    if not findings:
        print("No SSRF indicators found with the current payload set.")
        return

    for index, finding in enumerate(findings, 1):
        badge = f"[{finding.severity.upper()}/{finding.verdict}]"
        if color:
            badge = f"{COLORS.get(finding.severity, '')}{badge}{RESET}"
        print()
        print(f"{index}. {badge} {finding.title}")
        print(f"   param    : {finding.param_location}:{finding.param_name}")
        print(f"   payload  : {finding.payload_value}")
        print(f"   request  : {finding.request_url}")
        print(f"   status   : baseline={finding.baseline_status} probe={finding.result_status}")
        if finding.evidence:
            for line in finding.evidence.splitlines():
                print(f"   evidence : {line}")
    print()


def findings_to_json(findings: list[Finding]) -> str:
    return json.dumps(
        [dataclasses.asdict(f) for f in findings],
        indent=2,
        ensure_ascii=False,
    )


def save_json(findings: list[Finding], path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(findings_to_json(findings))
