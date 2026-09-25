"""Refine cap and the audit lines a report must carry."""
from __future__ import annotations

from hunting.cli import build_parser
from hunting.reporter.renderer import format_hunt_audit


def test_refine_cap_defaults_to_one_round():
    args = build_parser().parse_args(["--hypothesis", "A service account logs on interactively"])
    assert args.max_refine == 1
    args = build_parser().parse_args([
        "--hypothesis", "A service account logs on interactively",
        "--max-refine", "3",
    ])
    assert args.max_refine == 3


def test_report_audit_records_prepare_llm_and_version():
    lines = format_hunt_audit(
        {"prepare_source": "derived", "package_version": "v9"},
        {"calls_made": 1},
    )
    text = "\n".join(lines)
    assert "Prepare:** `derived`" in text
    assert "Compilation mode:** `llm`" in text
    assert "Version:** `v9`" in text
    skipped = "\n".join(format_hunt_audit({"prepare_source": "skipped"}, {"calls_made": 0}))
    assert "skipped" in skipped
    assert "deterministic" in skipped
