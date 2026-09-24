from hunting.capabilities.semantic_index import SemanticCapabilityIndex
from hunting.contracts.capability_query import CapabilityQuery
from hunting.contracts.queries import ProviderOperation
from hunting.contracts.source_profile import TelemetryFieldProfile, TelemetrySourceProfile


def _profile(source_id: str, fields: tuple[str, ...]) -> TelemetrySourceProfile:
    return TelemetrySourceProfile(
        source_id=source_id,
        provider_id="splunk",
        partition_id="botsv2",
        native_type="opaque",
        fields=tuple(TelemetryFieldProfile(f"id-{field}", field) for field in fields),
    )


def test_unknown_relation_still_retrieves_by_types_and_fields():
    profiles = (
        _profile("source-attachment", ("sender", "recipient", "filename", "file_path")),
        _profile("source-process", ("image", "parent_image", "host")),
    )
    query = CapabilityQuery(
        "goal-1", "person", "file", "file_name",
        constraint_keys=("format",), relation_text="delivered_by_unknown_label",
    )
    result = SemanticCapabilityIndex(profiles).retrieve(query, k=1)
    assert len(result.hits) == 1
    assert result.hits[0].source_id == "source-attachment"
    assert result.unexamined_ids == ("source-process",)
    assert result.hits[0].score >= 0


def test_f1_k_is_bounded_and_remainder_is_explicit():
    profiles = tuple(_profile(f"source-{i:02d}", ("host",)) for i in range(10))
    query = CapabilityQuery("goal-1", "person", "host", "host", relation_text="novel")
    result = SemanticCapabilityIndex(profiles).retrieve(query, k=3)
    assert len(result.hits) == 3
    assert len(result.unexamined_ids) == 7
    assert result.to_dict()["proof"] is False


def test_zero_score_shortlist_hit_is_rejected_not_relevant():
    profiles = tuple(_profile(f"telemetry-{i:02d}", ("zzzz_metric",)) for i in range(2))
    query = CapabilityQuery("goal-1", "person", "artifact", "file_name", relation_text="novel")
    result = SemanticCapabilityIndex(profiles).retrieve(query, k=1)

    assert len(result.hits) == 1
    assert result.hits[0].relevant is False
    assert result.deferred_ids == ()
    assert result.to_dict()["complete"] is False


def test_source_identifier_does_not_create_semantic_relevance():
    profile = _profile("email-source", ("unrelated_metric",))
    query = CapabilityQuery("goal-1", "person", "file", "attachment_name", relation_text="sent_message")

    result = SemanticCapabilityIndex((profile,)).retrieve(query, k=1)

    assert result.hits[0].relevant is False
    assert result.hits[0].score == 0.0


def test_f1_indexes_operations_separately_from_sources_and_fields():
    profiles = (
        _profile("source-metrics", ("zzzz_metric",)),
        _profile("source-process", ("host", "image", "cmdline")),
    )
    operation = ProviderOperation(
        id="find_process_from_endpoint",
        provider_id="splunk",
        scope_ids=("scope",),
        input_entity_kinds=("host",),
        output_entity_kinds=("process",),
        output_fields=("host", "image", "cmdline"),
        output_value_bindings={"object": ("image", "cmdline")},
        runtime_source_id="source-process",
    )
    query = CapabilityQuery(
        "goal-1", "host", "process", "process",
        relation_text="unregistered action",
    )

    result = SemanticCapabilityIndex(profiles, operations=(operation,)).retrieve(query, k=2)

    assert result.operation_hits
    assert result.operation_hits[0].operation_id == "find_process_from_endpoint"
    assert result.operation_hits[0].relevant is True
    assert result.operation_hits[0].document_kind == "operation"
    assert result.operation_hits[0].route_class == "EXECUTABLE"
    assert any(hit.document_kind == "source" for hit in result.hits)
    assert result.field_hits
    assert result.to_dict()["index_version"]
    assert result.to_dict()["proof"] is False


def test_f0_exact_label_match_is_executable_without_c2_context():
    operation = ProviderOperation(
        id="resolve_account",
        provider_id="mock",
        scope_ids=("scope",),
        input_entity_kinds=("person",),
        output_entity_kinds=("account",),
        output_fields=("user",),
        output_value_bindings={"object": ("user",)},
        guaranteed_relations=("associated_with",),
    )
    query = CapabilityQuery(
        "goal-1", "person", "account", "account",
        relation_text="associated_with",
        canonical_relation="associated_with",
    )

    result = SemanticCapabilityIndex((), operations=(operation,)).retrieve(query, k=4)

    assert result.operation_hits
    assert result.operation_hits[0].frontier_stage == "F0_CERTIFIED"
    assert result.operation_hits[0].relevant is True
    assert result.operation_hits[0].route_class == "EXECUTABLE"


def test_f1_source_or_field_only_hit_is_not_executable():
    profiles = (_profile("source-file", ("file_path", "filename")),)
    query = CapabilityQuery(
        "goal-1", "person", "file", "file_name",
        relation_text="novel_delivery",
    )

    result = SemanticCapabilityIndex(profiles, operations=()).retrieve(query, k=4)

    assert result.hits
    assert result.hits[0].relevant is True
    assert result.hits[0].route_class in {"MAPPING_REQUIRED", "DISCOVERY_ONLY"}
    assert result.operation_hits == ()
