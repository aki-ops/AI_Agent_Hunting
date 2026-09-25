"""Pha 1+2: 503 không giết hunt; fallback probe dùng đúng shortlist F1."""
from hunting.capabilities.deterministic_probe import build_fallback_proposals
from hunting.contracts.source_profile import TelemetryFieldProfile, TelemetrySourceProfile


def _profile():
    fields = (
        TelemetryFieldProfile(field_id="f_sender", name="sender", primitive_type="string", origin="flat"),
        TelemetryFieldProfile(field_id="f_recv", name="receiver_email", primitive_type="string", origin="flat"),
        TelemetryFieldProfile(field_id="f_subj", name="subject", primitive_type="string", origin="flat"),
    )
    return TelemetrySourceProfile(
        source_id="splunk:stream_smtp",
        provider_id="splunk",
        partition_id="botsv2",
        native_type="stream:smtp",
        fields=fields,
    )


def test_fallback_builds_probe_only_proposal_from_census_ids():
    req = {"relation": "sent_message", "goal_id": "goal-1"}
    proposals = build_fallback_proposals(_profile(), req)
    assert len(proposals) == 1
    assert proposals[0].proof_mode == "retrieval_only"
    assert set(proposals[0].input_roles.values()) | set(proposals[0].output_roles.values()) <= {"f_sender", "f_recv"}


def test_fallback_returns_nothing_without_message_fields():
    fields = (
        TelemetryFieldProfile(field_id="f_host", name="host", primitive_type="string", origin="flat"),
    )
    prof = TelemetrySourceProfile(
        source_id="splunk:sysmon",
        provider_id="splunk",
        partition_id="botsv2",
        native_type="sysmon",
        fields=fields,
    )
    assert build_fallback_proposals(prof, {"relation": "sent_message", "goal_id": "g"}) == []


def test_fallback_ignores_non_message_relations():
    assert build_fallback_proposals(_profile(), {"relation": "logged_on_to", "goal_id": "g"}) == []
