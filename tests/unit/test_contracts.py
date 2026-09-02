import pytest

from hunting.contracts.cells import Cell, CellState, ProviderScope
from hunting.contracts.entities import ANY, AnyEntity, EntityKind, Host
from hunting.contracts.expectations import EvidenceRequirement, Expectation
from hunting.contracts.manifest import ReplayManifest, create_replay_manifest
from hunting.contracts.observations import EpistemicType, Observation, SemanticType, Provenance
from hunting.contracts.queries import (
    CONTROL_INTENTS,
    INVESTIGATION_INTENTS,
    CapabilityBinding,
    Diagnostic,
    DiagnosticClass,
    ProviderOperation,
    QueryIntent,
    QueryOutcome,
    QueryResult,
)
from hunting.contracts.capabilities import CapabilityDescriptor, CapabilityMatcher
from hunting.contracts.coverage import CoverageBound, RequirementCoverage
from hunting.contracts.validators import (
    validate_cell,
    validate_observation,
    validate_expectation,
    validate_provider_scope,
    assert_epistemic_transition,
    assert_m2_cannot_mutate_attribution,
)


def test_entity_and_any_contracts():
    host = Host(name="DESKTOP-ABC")
    assert host.kind == EntityKind.HOST
    assert ANY == AnyEntity()
    assert isinstance(ANY, AnyEntity)


def test_cell_uses_provider_scope_and_has_no_event_family():
    scope = ProviderScope("cdb", {"database": "cdb.sqlite", "table": "events"}, "cdb_security")
    cell = Cell(scope, ANY, "2026-09-01T10:00:00Z/2026-09-01T11:00:00Z")

    assert cell.provider_scope == scope
    assert cell.is_wildcard
    assert cell.state is CellState.UNEXPLORED
    assert not hasattr(cell, "event_family")


def test_cell_state_is_mutable():
    scope = ProviderScope("cdb", {"table": "events"}, "scope")
    cell = Cell(scope, Host(name="DESKTOP-A"), "window")
    cell.state = CellState.EXPLORED
    assert cell.state is CellState.EXPLORED


def test_observation_preserves_unknown_native_type():
    scope = ProviderScope("ids", {"stream": "eve.json"}, "sensor-01")
    observation = Observation(
        id="o1",
        provider_scope=scope,
        cell_id="c1",
        timestamp="2026-09-01T10:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type="vendor_new_type",
        semantic_type=None,
    )
    assert observation.native_type == "vendor_new_type"
    assert observation.semantic_type is None
    assert observation.is_unmapped is True
    assert observation.is_unexplained is True


def test_any_is_not_allowed_in_expectation_or_observation_entities():
    with pytest.raises(ValueError):
        Expectation("e", "x", EvidenceRequirement.DNS_ACTIVITY, "dns", ANY, None, None, "window", "not found")

    scope = ProviderScope("ids", {"stream": "eve.json"}, "sensor")
    with pytest.raises(ValueError):
        Observation("o", scope, "c", "timestamp", EpistemicType.OBSERVED, entities=[ANY])


def test_query_controls_are_not_event_family_controls():
    assert CONTROL_INTENTS == {
        QueryIntent.SCOPE_HEALTH_CONTROL,
        QueryIntent.ANY_RECORD_IN_SCOPE,
        QueryIntent.PREDICATE_OBSERVABILITY_CONTROL,
    }
    assert QueryIntent.BROAD_SWEEP in INVESTIGATION_INTENTS
    assert len(CONTROL_INTENTS) == 3
    assert len(INVESTIGATION_INTENTS) == 7


def test_partial_result_cannot_be_valid_negative():
    result = QueryResult("q1", QueryOutcome.UNKNOWN, True, complete=False)
    assert result.outcome is not QueryOutcome.VALID_NEGATIVE


def test_diagnostic_classes():
    assert Diagnostic.QUERY_FAILED.diagnostic_class is DiagnosticClass.RETRYABLE
    assert Diagnostic.PARTIAL_RESULT.diagnostic_class is DiagnosticClass.RETRYABLE
    assert Diagnostic.UNQUERYABLE.diagnostic_class is DiagnosticClass.PERMANENT
    assert Diagnostic.UNSUPPORTED_REQUIREMENT.diagnostic_class is DiagnosticClass.PERMANENT


def test_replay_manifest_contains_git_config_seed():
    manifest = create_replay_manifest(seed=42, config_bytes=b"provider: test\n", git_sha="abc1234")
    assert manifest.git_sha == "abc1234"
    assert len(manifest.config_hash) == 64
    assert manifest.seed == 42

    with pytest.raises(ValueError, match="git_sha"):
        ReplayManifest(git_sha="", config_hash="abcd", seed=1)
    with pytest.raises(ValueError, match="config_hash"):
        ReplayManifest(git_sha="sha", config_hash="", seed=1)


def test_capability_descriptor_and_matcher():
    scope = ProviderScope("splunk", {"index": "sec"}, "sec_scope")
    op_process = ProviderOperation("search_proc", "splunk", ("sec_scope",))
    op_dns = ProviderOperation("search_dns", "splunk", ("sec_scope",))

    binding_proc = CapabilityBinding(EvidenceRequirement.PROCESS_ANCESTRY, "splunk", "search_proc", confidence="EXACT")
    binding_dns = CapabilityBinding(EvidenceRequirement.DNS_ACTIVITY, "splunk", "search_dns", confidence="PARTIAL")

    desc = CapabilityDescriptor(
        provider_id="splunk",
        scopes=(scope,),
        operations=(op_process, op_dns),
        bindings=(binding_proc, binding_dns),
    )
    matcher = CapabilityMatcher([desc])

    # EXACT match
    res_proc = matcher.match(EvidenceRequirement.PROCESS_ANCESTRY)
    assert res_proc.is_supported
    assert res_proc.binding.confidence == "EXACT"
    assert res_proc.operation.id == "search_proc"

    # PARTIAL match
    res_dns = matcher.match(EvidenceRequirement.DNS_ACTIVITY)
    assert res_dns.is_supported
    assert res_dns.binding.confidence == "PARTIAL"

    # UNSUPPORTED_REQUIREMENT when no binding exists
    res_unsupported = matcher.match(EvidenceRequirement.PERSISTENCE_CHANGE)
    assert not res_unsupported.is_supported
    assert res_unsupported.diagnostic == Diagnostic.UNSUPPORTED_REQUIREMENT


def test_unmapped_and_unexplained_handling():
    scope = ProviderScope("cdb", {"table": "events"}, "cdb_sec")
    obs_unmapped = Observation(
        id="obs-1",
        provider_scope=scope,
        cell_id="cell-1",
        timestamp="2026-09-01T10:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type="custom_type_999",
        semantic_type=None,
    )
    assert obs_unmapped.is_unmapped is True
    assert obs_unmapped.is_unexplained is True

    # When attributed
    obs_unmapped.attributed_by.append("exp-1")
    assert obs_unmapped.is_unexplained is False

    # SemanticType with unmapped explicitly
    obs_custom_unmapped = Observation(
        id="obs-2",
        provider_scope=scope,
        cell_id="cell-1",
        timestamp="2026-09-01T10:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        semantic_type=SemanticType("local", "anomaly", mapped_by="unmapped"),
    )
    assert obs_custom_unmapped.is_unmapped is True


def test_coverage_bound_denominator_includes_unqueryable_excludes_unknown_source():
    cb = CoverageBound(
        explored_cells_wildcard=5,
        unexplored_cells_wildcard=10,
        unqueryable_cells_wildcard=2,
        unreachable_cells_wildcard=1,
        explored_cells_instance=3,
        unexplored_cells_instance=4,
        unqueryable_cells_instance=1,
        unknown_sources=["cloudtrail_prod", "zeek_raw"],
        unmapped_observations=7,
    )
    # UNQUERYABLE must be in the denominator: 5+10+2+1 + 3+4+1 = 26
    assert cb.scope_coverage_denominator == 26
    # UNKNOWN_SOURCE is outside the denominator
    assert len(cb.unknown_sources) == 2
    assert cb.unmapped_observations == 7


def test_targeted_query_does_not_mark_whole_provider_scope_explored():
    scope = ProviderScope("cdb", {"table": "events"}, "cdb_sec")
    # A targeted query for an entity
    targeted_cell = Cell(scope, Host(name="host-1"), "window")
    targeted_cell.state = CellState.EXPLORED

    # The scope wildcard cell remains UNEXPLORED
    scope_wildcard_cell = Cell(scope, ANY, "window")
    assert scope_wildcard_cell.state == CellState.UNEXPLORED
    assert scope_wildcard_cell.is_wildcard is True


def test_malformed_contracts_fail_validation_unknown_semantic_does_not():
    scope = ProviderScope("p", {"dataset": "d"}, "s")
    valid_obs = Observation(
        id="o1",
        provider_scope=scope,
        cell_id="c1",
        timestamp="2026-01-01T00:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type="weird_unseen_format",
        semantic_type="completely_unknown_semantic_type",
    )
    # Validating observation with unknown semantic type DOES NOT fail
    validate_observation(valid_obs)

    # Malformed observation (empty ID) FAILS
    with pytest.raises(ValueError, match="Observation.id"):
        Observation(
            id="",
            provider_scope=scope,
            cell_id="c1",
            timestamp="2026-01-01T00:00:00Z",
            epistemic_type=EpistemicType.OBSERVED,
        )

    # Malformed cell (empty time_bucket) FAILS
    with pytest.raises(ValueError, match="time_bucket"):
        Cell(scope, ANY, "")


def test_testimony_cannot_become_observed_and_m2_cannot_mutate():
    scope = ProviderScope("p", {"dataset": "d"}, "s")
    obs = Observation(
        id="o1",
        provider_scope=scope,
        cell_id="c1",
        timestamp="2026-01-01T00:00:00Z",
        epistemic_type=EpistemicType.TESTIMONY,
    )

    with pytest.raises(ValueError, match="TESTIMONY cannot become OBSERVED"):
        obs.elevate_epistemic_type(EpistemicType.OBSERVED)

    with pytest.raises(ValueError, match="TESTIMONY cannot become OBSERVED"):
        assert_epistemic_transition(EpistemicType.TESTIMONY, EpistemicType.OBSERVED)

    with pytest.raises(PermissionError, match="M2"):
        assert_m2_cannot_mutate_attribution("M2")
    with pytest.raises(PermissionError, match="LLM"):
        assert_m2_cannot_mutate_attribution("llm_agent")
