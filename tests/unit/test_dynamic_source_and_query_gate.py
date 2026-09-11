"""Tests for dynamic source profiling and quarantined native query execution."""
from __future__ import annotations

import json

from hunting.capabilities.probe_executor import BoundedProbeExecutor
from hunting.capabilities.profile_cache import RuntimeCapabilityCache
from hunting.capabilities.runtime_materializer import materialize_runtime_operation
from hunting.capabilities.source_mapping_validator import SourceMappingValidator
from hunting.capabilities.source_profiler import SourceProfiler
from hunting.contracts.entities import Account
from hunting.contracts.native_query import NativeQueryCandidate
from hunting.contracts.query_intent import QueryIntentSpec
from hunting.contracts.source_profile import (
    RuntimeCapability,
    SourceCapabilityProposal,
    TelemetryFieldProfile,
    TelemetrySourceProfile,
)
from hunting.m5_adapter.cdb_adapter import CdbAdapter
from hunting.m5_adapter.splunk_adapter import SplunkLiveAdapter
from hunting.query_safety.native_query_gate import NativeQueryGate


def _profile() -> TelemetrySourceProfile:
    return TelemetrySourceProfile(
        source_id="src-mail-1",
        provider_id="splunk",
        partition_id="index-main",
        native_type="vendor:opaque-events",
        fields=(
            TelemetryFieldProfile("f-user", "actor_name", "string", 0.9, ("Mallory",)),
            TelemetryFieldProfile("f-host", "device_name", "string", 0.8, ("MACLORY-AIR13",)),
            TelemetryFieldProfile("f-file", "object_path", "string", 0.7, ("brief.pptx",)),
        ),
    )


def test_profiler_accepts_only_census_referenced_mapping() -> None:
    def caller(context: dict) -> str:
        context = json.loads(context)
        assert context["component"] == "source_profiler"
        assert "raw_log" not in context
        return json.dumps({
            "proposals": [{
                "source_id": "src-mail-1",
                "relation": "associated_with",
                "input_roles": {"person": "f-user"},
                "output_roles": {"endpoint": "f-host"},
                "proof_mode": "relation_observable",
                "probe_kind": "cooccurrence",
                "rationale_refs": ["f-user", "f-host"],
            }, {
                "source_id": "invented-source",
                "relation": "contains",
                "input_roles": {"file": "invented-field"},
                "output_roles": {},
            }]
        })

    accepted, audit = SourceProfiler(caller).propose([_profile()], [{"relation": "associated_with"}])

    assert len(accepted) == 1
    assert accepted[0].source_id == "src-mail-1"
    assert len(audit["rejected"]) == 1
    assert "source_id_not_in_census" in audit["rejected"][0]["reason"]


def test_profiler_prompt_omits_sample_values() -> None:
    original = _profile()
    profile = TelemetrySourceProfile(
        source_id=original.source_id,
        provider_id=original.provider_id,
        partition_id=original.partition_id,
        native_type=original.native_type,
        fields=tuple(
            TelemetryFieldProfile(
                field_id=field.field_id,
                name=field.name,
                primitive_type=field.primitive_type,
                coverage=field.coverage,
                sample_values=("secret-value",),
            )
            for field in original.fields
        ),
    )
    captured: list[str] = []

    def caller(prompt: str) -> str:
        captured.append(prompt)
        return '{"proposals": []}'

    SourceProfiler(caller).propose([profile], [{"relation": "associated_with"}])
    assert "secret-value" not in captured[0]


def test_successful_probe_is_required_for_validated_capability() -> None:
    profile = _profile()
    proposal = SourceProfiler(lambda _: json.dumps({"proposals": []}))
    del proposal
    from hunting.contracts.source_profile import SourceCapabilityProposal

    candidate = SourceCapabilityProposal(
        source_id="src-mail-1",
        relation="associated_with",
        input_roles={"person": "f-user"},
        output_roles={"endpoint": "f-host"},
        proof_mode="relation_observable",
    )
    validator = SourceMappingValidator()
    ok, reasons, probe = validator.validate(candidate, [profile])
    assert ok and not reasons and probe is not None
    assert validator.materialize(candidate, profile).status == "CANDIDATE"
    assert validator.materialize(candidate, profile, probe_succeeded=True).status == "VALIDATED"


def test_native_query_gate_accepts_bounded_census_bound_spl() -> None:
    result = NativeQueryGate().validate(
        NativeQueryCandidate(
            provider="splunk",
            query_text='search index="main" actor_name="Mallory" | table actor_name device_name | head 20',
            time_window="2026-08-18T00:00:00Z/2026-08-19T00:00:00Z",
            expected_fields=("actor_name", "device_name"),
            max_rows=20,
        ),
        known_sources=["main"],
        known_fields=["actor_name", "device_name"],
    )
    assert result.accepted, result.reasons
    assert result.ast["kind"] == "limited_spl_pipeline"


def test_native_query_gate_rejects_unbounded_or_side_effecting_spl() -> None:
    result = NativeQueryGate().validate(
        NativeQueryCandidate(
            provider="splunk",
            query_text='search index="main" actor_name="Mallory" | outputlookup stolen.csv',
            time_window="2026-08-18T00:00:00Z/2026-08-19T00:00:00Z",
            max_rows=20,
        ),
        known_sources=["main"],
        known_fields=["actor_name"],
    )
    assert not result.accepted
    assert "forbidden_command:outputlookup" in result.reasons
    assert "explicit_head_limit_required" in result.reasons


def test_query_intent_has_no_native_syntax_and_cache_is_schema_scoped() -> None:
    intent = QueryIntentSpec(
        goal_id="goal-file",
        operation_id="runtime-op",
        source_id="src-mail-1",
        relation="contains",
        bindings={"endpoint": "MACLORY-AIR13"},
        predicates=({"role": "file_name", "operator": "contains", "value": ".ppt"},),
        time_window="2026-08-18T00:00:00Z/2026-08-19T00:00:00Z",
        projection_roles=("file_name",),
        expected_output=("file_name",),
    )
    assert "search index" not in str(intent.to_dict()).lower()
    cache = RuntimeCapabilityCache()
    key = cache.key("splunk", "scope", "schema-a", "goal-file")
    cache.put(key, ())
    assert cache.get(key) == ()
    cache.invalidate_schema("schema-b")
    assert cache.get(key) is None


def test_validated_mapping_materializes_typed_runtime_operation() -> None:
    profile = _profile()
    proposal = SourceCapabilityProposal(
        source_id=profile.source_id,
        relation="associated_with",
        input_roles={"subject_identity": "f-user"},
        output_roles={"endpoint_identity": "f-host"},
        proof_mode="relation_observable",
    )
    capability = RuntimeCapability(
        capability_id="runtime:splunk:schema:src-mail-1:associated_with",
        source_id=profile.source_id,
        provider_id="splunk",
        relation="associated_with",
        input_roles=proposal.input_roles,
        output_roles=proposal.output_roles,
        status="VALIDATED",
        proof_mode="relation_observable",
        schema_fingerprint=profile.schema_fingerprint,
        probe_query_id="probe-1",
    )
    operation = materialize_runtime_operation(
        proposal,
        profile,
        {"subject_type": "person", "object_type": "host"},
        capability,
    )
    assert operation is not None
    assert operation.input_entity_kinds == ("person",)
    assert operation.output_binding_entity_kinds["object"] == "host"
    assert operation.native_field_bindings == {"subject_identity": ("actor_name",)}
    assert operation.runtime_source_id == profile.source_id


def test_splunk_runtime_operation_builds_from_profile_fields(monkeypatch) -> None:
    adapter = SplunkLiveAdapter(
        splunk_url="http://offline",
        index="main",
        timeout=5,
    )
    captured: dict[str, str] = {}

    class Response:
        status_code = 200
        text = ""

        def json(self):
            return {"results": [{"actor_name": "Mallory", "device_name": "MAC-01"}]}

    def post(url, data, **kwargs):
        captured["search"] = data["search"]
        return Response()

    monkeypatch.setattr("hunting.m5_adapter.splunk_adapter.requests.post", post)
    result = adapter.execute_query(
        operation_id="runtime:splunk:schema:src-mail-1:associated_with",
        entity=Account(username="Mallory"),
        window="2026-08-18T00:00:00Z/2026-08-19T00:00:00Z",
        limit=20,
        parameters={
            "runtime_capability": {
                "source_id": "splunk:main:vendor:opaque-events",
                "native_field_bindings": {"subject_identity": ["actor_name"]},
                "output_value_bindings": {"object": ["device_name"]},
            }
        },
    )
    assert result.executed_ok
    assert 'index="main" sourcetype="vendor:opaque-events"' in captured["search"]
    assert 'actor_name="Mallory"' in captured["search"]
    assert "device_name" in captured["search"]
    assert "| head 21" in captured["search"]


def test_cdb_runtime_operation_uses_probed_columns() -> None:
    adapter = CdbAdapter()
    adapter.insert_events([{
        "timestamp": "2026-08-18T10:00:00Z",
        "native_type": "opaque",
        "user": "Mallory",
        "host": "MAC-01",
    }])
    result = adapter.execute_query(
        operation_id="runtime:cdb:schema:events:associated_with",
        entity=Account(username="Mallory"),
        window="2026-08-18T00:00:00Z/2026-08-19T00:00:00Z",
        limit=20,
        parameters={
            "runtime_capability": {
                "source_id": "cdb:source:events",
                "native_field_bindings": {"subject_identity": ["user"]},
                "output_value_bindings": {"object": ["host"]},
            }
        },
    )
    assert result.executed_ok and result.complete
    assert result.rows and result.rows[0]["host"] == "MAC-01"
    assert "user = ?" in adapter.last_query_text


def test_cdb_probe_is_bounded_and_observability_only() -> None:
    adapter = CdbAdapter()
    adapter.insert_events([{
        "timestamp": "2026-08-18T10:00:00Z",
        "native_type": "opaque",
        "user": "Mallory",
        "host": "MAC-01",
    }])
    profile = TelemetrySourceProfile(
        source_id="cdb:source:events",
        provider_id="cdb",
        partition_id=adapter.scope.scope_id,
        native_type="opaque",
        fields=(
            TelemetryFieldProfile("f-user", "user"),
            TelemetryFieldProfile("f-host", "host"),
        ),
    )
    from hunting.contracts.source_profile import ProbeSpec

    execution = BoundedProbeExecutor().run(
        adapter,
        profile,
        ProbeSpec("cdb:source:events", "cooccurrence", ("f-user", "f-host"), max_rows=2),
        query_id="probe-cdb-1",
        time_window="2026-08-18T00:00:00Z/2026-08-19T00:00:00Z",
    )
    assert execution.succeeded
    assert execution.result is not None and execution.result.complete
    assert execution.result.row_count <= 2
