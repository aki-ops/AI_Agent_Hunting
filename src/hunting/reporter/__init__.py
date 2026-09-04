"""Canonical Threat Hunting Reporter module.

Provides:
- build_final_hunt_account: Transforms HuntState and ObservationLedger into immutable FinalHuntAccount.
- render_final_hunt_account: Pure Markdown renderer enforcing epistemic guarantees and gap accounting.
"""
from __future__ import annotations

from hunting.reporter.builder import build_final_hunt_account
from hunting.reporter.renderer import render_final_hunt_account

__all__ = [
    "build_final_hunt_account",
    "render_final_hunt_account",
]
