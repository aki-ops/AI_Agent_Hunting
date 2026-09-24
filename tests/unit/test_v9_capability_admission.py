from hunting.capabilities.admission import CapabilityAdmissionGate
from hunting.contracts.source_profile import SourceCapabilityProposal, TelemetryFieldProfile, TelemetrySourceProfile


def _profile() -> TelemetrySourceProfile:
    return TelemetrySourceProfile(
        source_id="source-1",
        provider_id="splunk",
        partition_id="botsv2",
        native_type="opaque",
        fields=(TelemetryFieldProfile("f-user", "user"), TelemetryFieldProfile("f-file", "file_path")),
    )


def test_admission_accepts_only_reachable_census_fields():
    profile = _profile()
    proposal = SourceCapabilityProposal(
        source_id="source-1",
        relation="novel_relation",
        input_roles={"person": "f-user"},
        output_roles={"file": "f-file"},
    )
    result = CapabilityAdmissionGate.evaluate(proposal, profile, {"subject_type": "person", "object_type": "file"})
    assert result.admitted is True


def test_admission_rejects_unobserved_native_field():
    profile = _profile()
    proposal = SourceCapabilityProposal(
        source_id="source-1",
        relation="novel_relation",
        input_roles={"person": "f-user"},
        output_roles={"file": "invented-field"},
    )
    result = CapabilityAdmissionGate.evaluate(proposal, profile)
    assert result.admitted is False
    assert "native_field_not_in_census:invented-field" in result.reasons


def test_admission_rejects_unrelated_nested_answer_field():
    profile = TelemetrySourceProfile(
        source_id="source-nested",
        provider_id="splunk",
        partition_id="botsv2",
        native_type="opaque",
        fields=(
            TelemetryFieldProfile(
                "f-payload-name",
                "payload_sender",
                origin="nested_payload",
                parent_field="_raw",
                nested_key="sender_address",
            ),
        ),
    )
    proposal = SourceCapabilityProposal(
        source_id="source-nested",
        relation="find_attachment",
        input_roles={"message": "f-payload-name"},
        output_roles={"message": "f-payload-name"},
    )

    result = CapabilityAdmissionGate.evaluate(
        proposal,
        profile,
        {"subject_type": "message", "object_type": "file", "answer_role": "attachment_name"},
    )

    assert result.admitted is False
    assert "answer_role_not_census_backed:attachment_name" in result.reasons


def test_operation_admission_requires_reachable_types_and_mapping():
    from hunting.contracts.queries import ProviderOperation

    operation = ProviderOperation(
        id="op-file",
        provider_id="mock",
        scope_ids=("scope",),
        input_entity_kinds=("person",),
        output_entity_kinds=("file",),
        output_fields=("file_path",),
        output_value_bindings={"object": ("file_path",)},
    )
    accepted = CapabilityAdmissionGate.evaluate_operation(
        operation,
        {"subject_type": "person", "object_type": "file"},
    )
    rejected = CapabilityAdmissionGate.evaluate_operation(
        operation,
        {"subject_type": "ip", "object_type": "domain"},
    )
    assert accepted.admitted is True
    assert rejected.admitted is False
    assert "input_type_not_reachable" in rejected.reasons
