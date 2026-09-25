"""Fallback must declare nested-field transforms like any C2 proposal."""
from hunting.capabilities.deterministic_probe import build_fallback_proposals
from hunting.capabilities.source_mapping_validator import SourceMappingValidator
from hunting.contracts.source_profile import TelemetryFieldProfile, TelemetrySourceProfile


def _nested_profile():
    fields = (
        TelemetryFieldProfile(field_id="splunk:botsv2:stream:smtp:nested:_raw:sender", name="sender", primitive_type="string", origin="nested_payload", parent_field="_raw", nested_key="sender"),
        TelemetryFieldProfile(field_id="splunk:botsv2:stream:smtp:nested:_raw:receiver_email", name="receiver_email", primitive_type="string", origin="nested_payload", parent_field="_raw", nested_key="receiver_email"),
    )
    return TelemetrySourceProfile(
        source_id="splunk:botsv2:stream:smtp",
        provider_id="splunk",
        partition_id="botsv2",
        native_type="stream:smtp",
        fields=fields,
    )


def test_nested_fields_get_extract_transform():
    proposals = build_fallback_proposals(_nested_profile(), {"relation": "sent_message", "goal_id": "goal-1"})
    assert len(proposals) == 1
    assert proposals[0].field_transforms == {
        "splunk:botsv2:stream:smtp:nested:_raw:sender": "extract_nested_key",
        "splunk:botsv2:stream:smtp:nested:_raw:receiver_email": "extract_nested_key",
    }
    valid, reasons, probe = SourceMappingValidator().validate(proposals[0], [_nested_profile()])
    assert valid, reasons
    assert probe is not None
