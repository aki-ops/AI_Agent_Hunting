"""Fallback probe may retrieve the message even when the final answer (file_name) is not a census field."""
from hunting.capabilities.admission import CapabilityAdmissionGate
from hunting.capabilities.deterministic_probe import build_fallback_proposals
from hunting.capabilities.source_mapping_validator import SourceMappingValidator
from hunting.contracts.source_profile import TelemetryFieldProfile, TelemetrySourceProfile


def _smtp():
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


def test_fallback_passes_structural_validation_despite_file_answer():
    profile = _smtp()
    req = {
        "relation": "sent_message",
        "goal_id": "goal-1",
        "subject_type": "person",
        "object_type": "email_address",
        "answer_role": "file_name",
    }
    proposals = build_fallback_proposals(profile, req)
    assert len(proposals) == 1
    valid, reasons, probe = SourceMappingValidator().validate(proposals[0], [profile])
    assert valid, reasons
    assert probe is not None
    admission = CapabilityAdmissionGate().evaluate(proposals[0], profile, req)
    assert admission.admitted
