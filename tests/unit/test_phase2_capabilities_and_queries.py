"""Phase 2 — Capabilities and Queries Tests.

Verifies the 6 Phase 2 checklist items from 04-IMPLEMENTATION-CHECKLIST.md:
1. Version deployment-specific capability descriptors.
2. Validate entity, time, fields, permissions and completeness.
3. Try query templates before LLM fallback.
4. Parse, allowlist, dry-run and validate generated queries.
5. Cache validated plans by requirement/provider/schema.
6. Missing capability becomes UNSUPPORTED or UNREACHABLE.
"""
from __future__ import annotations

import pytest

from hunting.capabilities import (
    VersionedCapabilityDescriptor,
    build_default_capability_registry,
)
from hunting.contracts.cells import ProviderScope
from hunting.contracts.entities import ANY, Host, IPAddress
from hunting.contracts.expectations import EvidenceRequirement, FieldOp, FieldPredicate
from hunting.contracts.hunt import EvidenceRequirementV4, QueryPlan
from hunting.contracts.queries import Diagnostic
from hunting.planner import CanonicalQueryPlanner, PlanCache, QueryValidator


def test_1_versioned_capability_descriptors():
    """1. Version deployment-specific capability descriptors."""
    registry = build_default_capability_registry()
    assert "cdb_sqlite" in registry
    assert "splunk" in registry

    cdb_desc = registry["cdb_sqlite"]
    assert cdb_desc.version == "2026.1.0"
    assert cdb_desc.deployment_env == "enterprise-prod"
    assert len(cdb_desc.scopes) >= 1
    assert len(cdb_desc.operations) >= 1
    assert len(cdb_desc.supported_entity_kinds) >= 1
    assert len(cdb_desc.observable_fields) >= 1
    assert cdb_desc.completeness_contract == "complete"

    # Validation: empty provider_id or scopes must fail
    with pytest.raises(ValueError, match="provider_id must not be empty"):
        VersionedCapabilityDescriptor(
            provider_id="",
            version="1.0",
            deployment_env="prod",
            scopes=(),
            operations=(),
            bindings=(),
            supported_entity_kinds=("host",),
            observable_fields=("image",),
        )


def test_2_validate_entity_time_fields_permissions_completeness():
    """2. Validate entity, time, fields, permissions and completeness."""
    registry = build_default_capability_registry()
    validator = QueryValidator(registry)
    scope = registry["cdb_sqlite"].scopes[0]

    plan = QueryPlan(
        id="qp-val-01",
        requirement_id="req-01",
        provider_id="cdb_sqlite",
        scope_id="cdb_native_scope",
        operation_id="cdb_process_lineage",
        parameters={"host": "WEB-01", "window": "NOW-14d/NOW"},
        completeness_contract="complete",
    )

    # Valid execution passes
    valid, diag = validator.validate_plan(plan, Host(name="WEB-01"), scope, "NOW-14d/NOW")
    assert valid is True
    assert diag is None

    # A: Retention Exceeded (scope retention is 90 days, request asks for 180 days)
    valid_ret, diag_ret = validator.validate_plan(plan, Host(name="WEB-01"), scope, "NOW-180d/NOW")
    assert valid_ret is False
    assert diag_ret == Diagnostic.SOURCE_UNAVAILABLE

    # B: Unobservable Field
    bad_field_plan = QueryPlan(
        id="qp-val-02",
        requirement_id="req-01",
        provider_id="cdb_sqlite",
        scope_id="cdb_native_scope",
        operation_id="cdb_process_lineage",
        parameters={"unknown_field_x": "malicious"},
        completeness_contract="complete",
    )
    valid_field, diag_field = validator.validate_plan(bad_field_plan, Host(name="WEB-01"), scope, "NOW-7d/NOW")
    assert valid_field is False
    assert diag_field == Diagnostic.UNSUPPORTED_REQUIREMENT

    # C: Permission Missing
    valid_perm, diag_perm = validator.validate_plan(plan, Host(name="WEB-01"), scope, "NOW-7d/NOW", required_permission="root_admin")
    assert valid_perm is False
    assert diag_perm == Diagnostic.UNQUERYABLE


def test_3_try_query_templates_before_llm_fallback():
    """3. Try query templates before LLM fallback."""
    llm_called = False

    def dummy_llm(prompt: str) -> str:
        nonlocal llm_called
        llm_called = True
        return "custom_field=1"

    planner = CanonicalQueryPlanner(llm_generator=dummy_llm)
    scope = planner.registry["cdb_sqlite"].scopes[0]

    er = EvidenceRequirementV4(
        id="req-proc-01",
        description="Process ancestry execution",
        evidence_type=EvidenceRequirement.PROCESS_ANCESTRY.value,
        falsification_condition="clean baseline",
        source_refs=["MITRE"],
    )

    plan, diag = planner.plan_query(er, Host(name="WEB-01"), scope, "NOW-7d/NOW")
    assert plan is not None
    assert diag is None
    # Template was used, LLM was NEVER called!
    assert llm_called is False
    assert planner.llm_fallback_used is False
    assert plan.operation_id == "cdb_process_lineage"


def test_4_parse_allowlist_dry_run_and_validate_generated_queries():
    """4. Parse, allowlist, dry-run and validate generated queries."""
    registry = build_default_capability_registry()
    validator = QueryValidator(registry)

    clean_plan = QueryPlan(
        id="qp-clean",
        requirement_id="req-01",
        provider_id="cdb_sqlite",
        scope_id="cdb_native_scope",
        operation_id="cdb_process_lineage",
        parameters={"host": "DESKTOP-ABC", "window": "NOW-7d/NOW"},
    )
    assert validator.dry_run(clean_plan) is True

    # Injection attack in parameter values must be blocked during dry-run
    injected_plan = QueryPlan(
        id="qp-evil",
        requirement_id="req-01",
        provider_id="cdb_sqlite",
        scope_id="cdb_native_scope",
        operation_id="cdb_process_lineage",
        parameters={"host": "DESKTOP'; DROP TABLE events; --"},
    )
    assert validator.dry_run(injected_plan) is False


def test_5_cache_validated_plans():
    """5. Cache validated plans by requirement/provider/schema."""
    cache = PlanCache()
    planner = CanonicalQueryPlanner(cache=cache)
    scope = planner.registry["cdb_sqlite"].scopes[0]

    er = EvidenceRequirementV4(
        id="req-net-01",
        description="Network connection check",
        evidence_type=EvidenceRequirement.NETWORK_CONNECTION.value,
        falsification_condition="no network beaconing",
        source_refs=["REF-NET"],
    )

    assert len(cache) == 0
    # First plan execution populates cache
    plan1, _ = planner.plan_query(er, IPAddress(address="192.168.1.50"), scope, "NOW-7d/NOW")
    assert plan1 is not None
    assert len(cache) == 1

    # Second execution hits cache directly
    plan2, _ = planner.plan_query(er, IPAddress(address="10.0.0.1"), scope, "NOW-1d/NOW")
    assert plan2 is not None
    assert plan2.parameters["ip"] == "10.0.0.1"


def test_6_missing_capability_unsupported_or_unreachable():
    """6. Missing capability becomes UNSUPPORTED or UNREACHABLE."""
    planner = CanonicalQueryPlanner()
    scope = planner.registry["cdb_sqlite"].scopes[0]

    # A: Unsupported requirement without template or provider support -> UNSUPPORTED_REQUIREMENT
    er_unsupported = EvidenceRequirementV4(
        id="req-unknown-01",
        description="Novel requirement not supported by provider",
        evidence_type="kernel_driver_hooking_telemetry",
        falsification_condition="driver signature valid",
        source_refs=["NOVEL"],
    )

    plan_unsupported, diag_unsupported = planner.plan_query(er_unsupported, ANY, scope, "NOW-7d/NOW")
    assert plan_unsupported is None
    assert diag_unsupported == Diagnostic.UNSUPPORTED_REQUIREMENT

    # B: Scope with known gap in window -> UNREACHABLE
    gap_scope = ProviderScope(
        provider_id="cdb_sqlite",
        scope_id="cdb_gap_scope",
        native_partition={"table": "events"},
        known_gaps=({"reason": "telemetry partition offline"},),
    )

    er_valid = EvidenceRequirementV4(
        id="req-proc-02",
        description="Process ancestry",
        evidence_type=EvidenceRequirement.PROCESS_ANCESTRY.value,
        falsification_condition="clean",
        source_refs=["MITRE"],
    )

    plan_gap, diag_gap = planner.plan_query(er_valid, ANY, gap_scope, "NOW-7d/NOW")
    assert plan_gap is None
    assert diag_gap == Diagnostic.UNREACHABLE


def test_7_logical_query_plan_generation_and_compilation():
    """7. Test LogicalQueryPlan generation and compilation to NativeQueryPlan."""
    planner = CanonicalQueryPlanner()
    scope = ProviderScope(
        provider_id="splunk",
        scope_id="splunk_botsv1",
        native_partition={"index": "botsv1"},
        retention_days=4000,
    )
    req = EvidenceRequirementV4(
        id="er-web-01",
        description="Web request to compromised site",
        evidence_type="web_request",
        predicate=FieldPredicate(field="uri", op=FieldOp.EXISTS),
        falsification_condition="no web requests",
        source_refs=["MITRE-T1190"],
    )

    # 1. Plan logical query
    lqp, diag = planner.plan_logical_query(
        requirement=req,
        entity=Host(name="we1149srv"),
        scope=scope,
        time_window="2016-08-01T00:00:00Z/2016-08-29T23:59:59Z",
    )
    assert diag is None
    assert lqp is not None
    assert lqp.provider == "splunk"
    assert lqp.is_targeted is True
    assert len(lqp.filters) == 1
    assert lqp.filters[0]["field"] == "uri"

    # 2. Compile to native query plan
    nqp, diag = planner.compile_native_query(lqp)
    assert diag is None
    assert nqp is not None
    assert nqp.provider == "splunk"
    assert "stream:http" in nqp.native_query
    assert 'host="we1149srv"' in nqp.native_query
    assert "| head 101" in nqp.native_query  # L+1 rule
    assert "| table _time" in nqp.native_query


def test_8_compiler_unsupported_evidence_type_validation():
    """8. Test validator rejects logical query plan with unsupported evidence type."""
    from hunting.contracts.capabilities import ProviderCapabilityCatalog

    planner = CanonicalQueryPlanner()
    catalog = ProviderCapabilityCatalog(
        provider_id="splunk",
        status="ONLINE",
        indices=["botsv1"],
        supported_evidence_types=["process_ancestry"],  # only process supported
        observable_fields=["timestamp", "host", "image"],
    )
    scope = ProviderScope(
        provider_id="splunk",
        scope_id="splunk_botsv1",
        native_partition={"index": "botsv1"},
    )
    req = EvidenceRequirementV4(
        id="er-exotic-01",
        description="Exotic hardware bus probe",
        evidence_type="hardware_bus_anomaly",
        falsification_condition="none",
        source_refs=["REF"],
    )

    lqp, diag = planner.plan_logical_query(
        requirement=req,
        entity=None,
        scope=scope,
        time_window="2016-08-01T00:00:00Z/2016-08-29T23:59:59Z",
        catalog=catalog,
    )
    assert lqp is None
    assert diag == Diagnostic.UNSUPPORTED_REQUIREMENT
