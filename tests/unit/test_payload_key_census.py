"""Counterexamples for bounded nested payload-key census."""

from hunting.capabilities.payload_key_census import discover_payload_fields


def test_key_cap_marks_census_bounded_not_complete() -> None:
    """Hitting max_keys must report BOUNDED even when few rows were scanned.

    Previously compared rows_seen to max_keys (different units), so a single
    dense payload that filled the key cap was wrongly marked COMPLETE.
    """
    payload = "{" + ",".join(f'"k{i}":{i}' for i in range(50)) + "}"
    rows = [{"_raw": payload} for _ in range(5)]

    fields, meta = discover_payload_fields(
        "src-dense",
        rows,
        evidence_query_id="q-bound",
        max_keys=10,
    )

    assert len(fields) == 10
    assert meta["keys_discovered"] == 10
    assert meta["rows_seen"] == 1
    assert meta["status"] == "BOUNDED"
    assert meta["complete"] is False


def test_exhausted_rows_under_key_cap_are_complete() -> None:
    rows = [{"_raw": '{"widget_label":["alpha.dat"]}'}]

    fields, meta = discover_payload_fields(
        "src-small",
        rows,
        evidence_query_id="q-complete",
        max_keys=128,
    )

    assert any(field.name == "widget_label" for field in fields)
    assert meta["status"] == "COMPLETE"
    assert meta["complete"] is True
    assert meta["keys_discovered"] < meta["max_keys"]
