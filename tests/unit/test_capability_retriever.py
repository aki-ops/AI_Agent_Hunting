from hunting.capabilities.retriever import CapabilityBatcher
from hunting.contracts.source_profile import TelemetryFieldProfile, TelemetrySourceProfile


def _profile(source_id: str, native_type: str, *fields: str) -> TelemetrySourceProfile:
    return TelemetrySourceProfile(
        source_id=source_id,
        provider_id="splunk",
        partition_id="splunk_scope",
        native_type=native_type,
        fields=tuple(
            TelemetryFieldProfile(field_id=f"{source_id}:field:{name}", name=name)
            for name in fields
        ),
    )


def test_batcher_includes_every_source_and_orders_only_for_processing() -> None:
    profiles = [
        _profile("splunk:events:auth", "Authentication", "user", "host", "_time"),
        _profile("splunk:events:file", "FileEvents", "file_path", "host", "_time"),
        _profile("splunk:events:noise", "Metrics", "value", "counter"),
    ]

    result = CapabilityBatcher(
        max_profiles_per_batch=2,
        max_fields_per_source_per_batch=2,
    ).batch(
        profiles,
        [{
            "relation": "associated_with",
            "subject_type": "person",
            "object_type": "host",
            "description": "Associate a person with a host",
        }],
    )

    candidates = result.candidates_by_relation["associated_with"]
    assert {candidate.source_id for candidate in candidates} == {item.source_id for item in profiles}
    assert len(result.batches_by_relation["associated_with"]) == 3
    assert result.audit[0]["source_coverage"]["complete"] is True
    assert result.audit[0]["field_coverage"]["complete"] is True
    assert result.audit[0]["ordering_only"] is True
    assert result.audit[0]["candidates"][0]["source_id"] == "splunk:events:auth"


def test_batcher_splits_large_source_fields_without_dropping_them() -> None:
    profile = _profile("source:file", "Native", "f1", "f2", "f3", "f4", "f5")
    result = CapabilityBatcher(
        max_profiles_per_batch=8,
        max_fields_per_source_per_batch=2,
    ).batch(
        [profile],
        [{"relation": "contains", "object_type": "file"}],
    )

    fragments = result.batches_by_relation["contains"]
    field_ids = {
        field.field_id
        for batch in fragments
        for fragment in batch
        for field in fragment.fields
    }
    assert field_ids == {field.field_id for field in profile.fields}
    assert len(fragments) == 1
    assert len(fragments[0]) == 3


def test_batcher_keeps_low_confidence_sources_for_exhaustive_coverage() -> None:
    profiles = [
        _profile("source:a", "NativeA", "alpha"),
        _profile("source:b", "NativeB", "beta"),
        _profile("source:c", "NativeC", "gamma"),
    ]

    result = CapabilityBatcher(max_profiles_per_batch=2).batch(
        profiles,
        [{"relation": "novel_relation", "subject_type": "entity", "object_type": "entity"}],
    )

    candidates = result.candidates_by_relation["novel_relation"]
    assert len(candidates) == 3
    assert all(candidate.low_confidence for candidate in candidates)
    assert result.audit[0]["source_coverage"]["scheduled"] == 3
