"""Tests for provider-neutral discovery before typed evidence pivots."""
from __future__ import annotations

from hunting.contracts.hunt_spec import HuntSpec
from hunting.contracts.semantic_intent import (
    RequestedObject,
    SemanticEvidenceRequirement,
    SemanticHuntIntent,
    SubjectEntity,
)
from hunting.m5_adapter.splunk_adapter import SplunkLiveAdapter


def test_hunt_spec_preserves_terms_and_does_not_create_provider_path():
    intent = SemanticHuntIntent(
        original_request="Amber installed Tor Browser",
        question="What version was installed?",
        subject=SubjectEntity(type="person", value="Amber Turing"),
        requested_object=RequestedObject(type="software_version"),
        behavior="installed software",
        evidence_requirements=[
            SemanticEvidenceRequirement(
                semantic_intent="file_artifact",
                description="Find Tor Browser installation metadata",
                necessity="CRITICAL",
            )
        ],
    )
    # Simulate compiler-validated requirement hints without adding SPL.
    req = type("Requirement", (), {
        "search_hints": ["Tor Browser", "tor.exe"],
        "semantic_intent": "file_artifact",
        "evidence_type": "file_modification",
        "description": "Find installation metadata",
        "necessity": "CRITICAL",
        "required_fields": [],
    })()
    spec = HuntSpec.from_semantic(intent, [req], "2017-08-01T00:00:00Z/2017-08-31T23:59:59Z")

    assert [t.value for t in spec.search_terms] == ["Amber Turing", "Tor Browser", "tor.exe"]
    assert spec.answer_contract.answer_type == "software_version"
    assert {p.name for p in spec.alternative_paths} >= {"raw_text_search", "process_telemetry", "file_telemetry"}
    assert all("sourcetype" not in t.value.lower() for t in spec.search_terms)
    assert spec.discovery_groups()[0] == ["Amber Turing", "Amber"]
    assert "Tor Browser" in spec.discovery_groups()[1]


def test_splunk_search_text_is_provider_compiled_and_not_event_code_bound():
    adapter = SplunkLiveAdapter(index="botsv2")
    spl, _, _ = adapter._build_spl(
        "search_text",
        None,
        "2017-08-01T00:00:00Z/2017-08-31T23:59:59Z",
        None,
        100,
        search_terms=["Amber", "Tor Browser"],
    )

    assert 'index="botsv2"' in spl
    assert '"Amber"' in spl and '"Tor Browser"' in spl
    assert "EventCode=1" not in spl and "EventCode=11" not in spl
    assert "sourcetype" in spl


def test_splunk_discovery_groups_use_or_within_role():
    adapter = SplunkLiveAdapter(index="botsv2")
    spl, _, _ = adapter._build_spl(
        "search_text",
        None,
        "2017-08-01T00:00:00Z/2017-08-31T23:59:59Z",
        None,
        100,
        search_groups=[["Amber Turing", "Amber"], ["Tor Browser", "tor.exe"]],
    )
    assert '("Amber Turing" OR "Amber") ("Tor Browser" OR "tor.exe")' in spl


def test_search_text_escapes_native_query_characters():
    adapter = SplunkLiveAdapter(index="botsv2")
    spl, _, _ = adapter._build_spl(
        "search_text",
        None,
        "2017-08-01T00:00:00Z/2017-08-31T23:59:59Z",
        None,
        10,
        search_terms=['foo" | delete', "bar"],
    )
    assert '"foo | delete"' in spl
    assert "| delete" not in spl.replace('"foo | delete"', "")


def test_splunk_schema_and_sample_operations_are_generic():
    adapter = SplunkLiveAdapter(index="botsv2")
    schema_spl, _, _ = adapter._build_spl(
        "discover_schema",
        None,
        "2017-08-01T00:00:00Z/2017-08-31T23:59:59Z",
        None,
        100,
    )
    sample_spl, _, _ = adapter._build_spl(
        "sample_records",
        None,
        "2017-08-01T00:00:00Z/2017-08-31T23:59:59Z",
        None,
        100,
    )

    assert '| fieldsummary' in schema_spl
    assert 'index="botsv2"' in sample_spl
    assert "EventCode" not in schema_spl + sample_spl
