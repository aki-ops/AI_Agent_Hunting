"""C2 maps only census-backed keys. A claim with no column must not erase the source."""
import json

from hunting.capabilities.source_mapping_validator import SourceMappingValidator
from hunting.capabilities.source_profiler import SourceProfiler, split_mapping_obligations
from hunting.contracts.source_profile import SourceCapabilityProposal, TelemetryFieldProfile, TelemetrySourceProfile


def _profile() -> TelemetrySourceProfile:
    noise = tuple(
        TelemetryFieldProfile(f"n{i}", f"noise_{i}", "string") for i in range(12)
    )
    return TelemetrySourceProfile(
        source_id="splunk:botsv2:stream:smtp",
        provider_id="splunk",
        partition_id="botsv2",
        native_type="stream:smtp",
        fields=noise + (
            TelemetryFieldProfile("f_sender", "sender", "string"),
            TelemetryFieldProfile("f_recv", "receiver", "string"),
            TelemetryFieldProfile("f_file", "filename", "string"),
        ),
    )


def _requirement() -> dict:
    return {
        "goal_id": "rel-sent-message",
        "relation": "sent_message",
        "subject_type": "person",
        "object_type": "email_address",
        "answer_role": "file_name",
        "constraint_keys": ["threat_actor", "email_address", "file_name"],
        "qualifier_hints": [
            {"key": "threat_actor", "value": "Taedonggang", "required": True, "retrieval_terms": []},
            {"key": "attachment_file_type", "value": "zip", "required": True, "retrieval_terms": []},
        ],
    }


def test_unbacked_claim_is_not_a_mapping_obligation():
    split = split_mapping_obligations(_requirement(), [_profile()])
    assert "threat_actor" in split["unmapped_keys"]
    assert "attachment_file_type" in split["unmapped_keys"]
    assert "file_name" in split["mapping_keys"]
    assert "email_address" in split["mapping_keys"]


def test_prompt_keeps_filename_and_does_not_refuse_the_source():
    ctx = SourceProfiler()._context([_profile()], [_requirement()])
    instructions = ctx["instructions"]
    assert "return no proposal" not in instructions
    requirement = ctx["requirements"][0]
    assert "threat_actor" in requirement["unmapped_keys"]
    assert "file_name" in requirement["mapping_keys"]
    names = [field["name"] for field in ctx["sources"][0]["fields"]]
    assert "filename" in names
    assert "sender" in names
    assert len(names) <= 12


def test_empty_proposals_are_malformed_when_a_column_can_be_mapped():
    calls = {"n": 0}

    def caller(_: str) -> str:
        calls["n"] += 1
        return json.dumps({"proposals": []})

    accepted, audit = SourceProfiler(caller).propose([_profile()], [_requirement()])
    assert accepted == []
    assert audit["status"] == "MALFORMED_OUTPUT"
    assert audit["repair_status"] == "REPAIR_ATTEMPTED"
    assert calls["n"] == 2


def test_proposal_without_threat_actor_column_is_accepted():
    payload = {
        "proposals": [{
            "goal_id": "rel-sent-message",
            "source_id": "splunk:botsv2:stream:smtp",
            "relation": "sent_message",
            "input_roles": {"sender": "f_sender"},
            "output_roles": {"receiver": "f_recv", "file_name": "f_file"},
            "proof_mode": "retrieval_only",
            "probe_kind": "cooccurrence",
        }]
    }
    accepted, audit = SourceProfiler(lambda _: json.dumps(payload)).propose(
        [_profile()],
        [_requirement()],
    )
    assert audit["status"] == "VALIDATED_CANDIDATES"
    assert len(accepted) == 1
    assert accepted[0].output_roles["file_name"] == "f_file"
    ok, reasons, _ = SourceMappingValidator().validate(accepted[0], [_profile()])
    assert ok and not reasons


def test_threat_actor_mapping_is_not_required_for_validation():
    proposal = SourceCapabilityProposal(
        source_id="splunk:botsv2:stream:smtp",
        relation="sent_message",
        goal_id="rel-sent-message",
        input_roles={"sender": "f_sender"},
        output_roles={"receiver": "f_recv", "file_name": "f_file"},
        proof_mode="retrieval_only",
    )
    ok, reasons, _ = SourceMappingValidator().validate(proposal, [_profile()])
    assert ok and not reasons
