"""Pha 4: override sourcetype của analyst chỉ thu hẹp, mặc định vẫn tự động."""
from hunting.peak_plan import apply_user_overrides, derive_prepare_plan


def test_sourcetype_override_sets_user_source():
    plan = derive_prepare_plan("mail with zip")
    assert plan.location_source == "derived"
    updated = apply_user_overrides(plan, {"location_override": ["stream:smtp"]})
    assert updated.location_override == ("stream:smtp",)
    assert updated.location_source == "user"
    assert updated.to_dict()["location_source"] == "user"


def test_empty_override_keeps_derived():
    plan = derive_prepare_plan("mail with zip")
    assert apply_user_overrides(plan, {}).location_source == "derived"
