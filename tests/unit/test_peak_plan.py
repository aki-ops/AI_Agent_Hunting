"""Prepare plan: derive thresholds first, then accept a user override."""
from __future__ import annotations

import pytest

from hunting.peak_plan import (
    PrepareError,
    apply_user_overrides,
    derive_prepare_plan,
    missing_prepare_fields,
)

LOGON = (
    "Tài khoản dịch vụ đang bị dùng để đăng nhập tương tác "
    "(RDP/console) vào Windows server."
)


def test_logon_hypothesis_derives_behavior_thresholds():
    plan = derive_prepare_plan(LOGON, time_window="NOW-14d/NOW")
    assert missing_prepare_fields(plan) == []
    assert plan.actor == ""
    assert plan.max_duration == "14d"
    assert plan.decision_criteria.confirm_when == LOGON
    assert plan.decision_criteria.min_coverage_to_refute == 0.8
    assert plan.decision_criteria.expected_magnitude == "small"
    assert plan.decision_criteria.source == "derived"
    assert plan.research_refs == ("analyst-hypothesis",)


def test_user_override_replaces_only_the_supplied_threshold():
    plan = derive_prepare_plan(LOGON)
    updated = apply_user_overrides(plan, {"decision_criteria": {"min_coverage_to_refute": 0.95}})
    assert updated.decision_criteria.min_coverage_to_refute == 0.95
    assert updated.decision_criteria.confirm_when == LOGON
    assert updated.decision_criteria.expected_magnitude == "small"
    assert updated.decision_criteria.source == "user"
    assert updated.behavior == plan.behavior


def test_explicit_plan_rejects_an_empty_threshold():
    plan = derive_prepare_plan("A named file hash is present on the server.")
    with pytest.raises(PrepareError, match="confirm_when"):
        apply_user_overrides(plan, {"decision_criteria": {"confirm_when": "  "}})


def test_prompt_keeps_derived_threshold_on_empty_input():
    from hunting.peak_plan import prompt_threshold_override
    plan = derive_prepare_plan(LOGON)
    updated = prompt_threshold_override(plan, lambda _prompt: "")
    assert updated.decision_criteria.min_coverage_to_refute == 0.8
    assert updated.decision_criteria.source == "derived"
    edited = prompt_threshold_override(plan, lambda _prompt: "0.7")
    assert edited.decision_criteria.min_coverage_to_refute == 0.7
    assert edited.decision_criteria.source == "user"
    with pytest.raises(PrepareError, match="free-text hypothesis"):
        derive_prepare_plan("  ")
