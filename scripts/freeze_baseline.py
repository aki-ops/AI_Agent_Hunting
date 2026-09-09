"""Freeze current test results as historical baseline. Not v6 evidence."""
from __future__ import annotations

import json
import shutil
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "baseline_reports"
REPORTS.mkdir(exist_ok=True)

COPIES = [
    (ROOT / "report.md", REPORTS / "report.md"),
    (ROOT / "artifacts" / "test-adaptive-hunt" / "final_report.md", REPORTS / "test-adaptive-hunt.md"),
    (ROOT / "artifacts" / "test-adaptive-hunt-success" / "final_report.md", REPORTS / "test-adaptive-hunt-success.md"),
]


def main() -> None:
    for src, dst in COPIES:
        if src.exists():
            shutil.copy2(src, dst)

    suite = ET.parse(REPORTS / "junit.xml").getroot().find("testsuite")
    if suite is None:
        raise SystemExit("junit.xml missing testsuite")

    failed: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []
    for tc in suite.findall("testcase"):
        name = f"{tc.get('classname')}::{tc.get('name')}"
        fail = tc.find("failure")
        skip = tc.find("skipped")
        if fail is not None:
            failed.append({"name": name, "message": (fail.get("message") or "")[:400]})
        if skip is not None:
            skipped.append({"name": name, "reason": skip.get("message") or ""})

    tests = int(suite.get("tests", 0))
    n_fail = int(suite.get("failures", 0))
    n_skip = int(suite.get("skipped", 0))
    out = {
        "frozen_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "note": "Historical baseline only. Do not use as v6 architecture evidence.",
        "summary": {
            "tests": tests,
            "passed": tests - n_fail - n_skip,
            "failed": n_fail,
            "skipped": n_skip,
            "errors": int(suite.get("errors", 0)),
            "time_s": float(suite.get("time", 0)),
        },
        "failures": failed,
        "skipped": skipped,
        "failure_meaning": {
            "test_deterministic_fallback_on_llm_failure": (
                "v5 keyword branch: evaluator expected hardcoded Tor Browser string"
            ),
            "test_email_case_graph_construction": (
                "v5 is_email graph no longer emits message/recipient/CEO chain from keyword"
            ),
            "test_email_relation_verification": "same email-graph construction gap",
        },
        "keyword_branches": "baseline_keyword_branches.txt",
        "reports": [
            "baseline_reports/baseline_report.md",
            "baseline_reports/report.md",
            "baseline_reports/test-adaptive-hunt.md",
            "baseline_reports/test-adaptive-hunt-success.md",
            "baseline_reports/junit.xml",
        ],
    }
    (ROOT / "baseline_tests.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(out["summary"]))


if __name__ == "__main__":
    main()
