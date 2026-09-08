from types import SimpleNamespace

from hunting.evidence.answer_verifier import verify_answer


def _card(card_id: str, fields: dict) -> SimpleNamespace:
    return SimpleNamespace(id=card_id, field_summary=fields)


def test_answered_without_required_version_field_is_partial():
    result = verify_answer(
        answer={"status": "ANSWERED", "value": "unknown", "card_ids": ["c1"]},
        answer_spec={"answer_type": "software_version", "required_fields": ["ProductVersion"]},
        cards=[_card("c1", {"Path": [r"C:\Tor\firefox.exe"]})],
        query_complete=True,
    )

    assert result["status"] == "PARTIAL"
    assert result["reason"] == "REQUIRED_ANSWER_FIELDS_MISSING"
    assert result["missing_fields"] == ["ProductVersion"]


def test_answered_requires_cited_evidence():
    result = verify_answer(
        answer={"status": "ANSWERED", "value": "13.5", "card_ids": []},
        answer_spec={"answer_type": "software_version", "required_fields": ["ProductVersion"]},
        cards=[_card("c1", {"ProductVersion": ["13.5"]})],
        query_complete=True,
    )

    assert result["status"] == "INCONCLUSIVE"
    assert result["reason"] == "ANSWER_HAS_NO_VALID_EVIDENCE_CITATION"


def test_not_found_is_downgraded_when_query_is_incomplete():
    result = verify_answer(
        answer={"status": "NOT_FOUND", "card_ids": []},
        answer_spec={"answer_type": "domain"},
        cards=[],
        query_complete=False,
    )

    assert result["status"] == "INCONCLUSIVE"
    assert result["reason"] == "COVERAGE_INCOMPLETE"
