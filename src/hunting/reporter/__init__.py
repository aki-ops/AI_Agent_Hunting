"""Canonical Threat Hunting Reporter module.

Provides:
- build_final_hunt_account: Transforms HuntState and ObservationLedger into immutable FinalHuntAccount.
- render_final_hunt_account: Pure Markdown renderer enforcing epistemic guarantees and gap accounting.
"""
from __future__ import annotations

from hunting.reporter.account_exporter import (
    RunCostAccounting,
    emit_aborted_run_account,
    emit_machine_run_account,
    render_six_part_report,
)
from hunting.reporter.builder import build_final_hunt_account
from hunting.reporter.renderer import render_analyst_report, render_final_hunt_account

__all__ = [
    "build_final_hunt_account",
    "render_final_hunt_account",
    "render_analyst_report",
    "RunCostAccounting",
    "emit_machine_run_account",
    "emit_aborted_run_account",
    "render_six_part_report",
]

