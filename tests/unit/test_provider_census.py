"""Provider Census and CapabilityGraph runtime regression tests."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from hunting.capabilities.census import ProviderCensusService
from hunting.compiler.compiler import KnowledgeBehaviorCompiler
from hunting.contracts.capabilities import ProviderCapabilityCatalog
from hunting.contracts.cells import ProviderScope
from hunting.contracts.claim import (
    AcceptanceRule,
    Claim,
    ClaimEvidenceRequirement,
    ClaimGraph,
)
from hunting.contracts.hunt import HuntRequest, HuntRequestKind, StoppingDecision
from hunting.contracts.queries import ProviderOperation, QueryOutcome, QueryResult
from hunting.engine import HypothesisHuntEngine
from hunting.m5_adapter.cdb_adapter import CdbAdapter


class CensusAdapter:
    def __init__(
        self,
        provider_id: str,
        operation: ProviderOperation | None,
        *,
        status: str = "ONLINE",
    ) -> None:
        self.provider_id = provider_id
        self.scope = ProviderScope(
            provider_id=provider_id,
            native_partition={"source": provider_id},
            scope_id=f"{provider_id}-scope",
        )
        self._operation = operation
        self._status = status
        self.executions = 0

    def discover_full_capabilities(self) -> ProviderCapabilityCatalog:
        operations = [self._operation] if self._operation is not None else []
        fields = list(self._operation.output_fields) if self._operation else ["other"]
        return ProviderCapabilityCatalog(
            provider_id=self.provider_id,
            status=self._status,
            observable_fields=fields,
            operations=operations,
            permissions=["read"],
            completeness_semantics="complete only on EOF",
            partitions={
                self.scope.scope_id: {
                    "native_partition": dict(self.scope.native_partition),
                    "retention_days": 30,
                }
            },
            schemas={"events": {"fields": [*fields, "unknown_native_field"]}},
            aliases={"account_name": ("user",)},
        )

    def execute_query(self, **_: Any) -> QueryResult:
        self.executions += 1
        return QueryResult(
            query_id="unexpected-query",
            outcome=QueryOutcome.UNKNOWN,
            executed_ok=True,
            complete=True,
            rows=[],
        )


def _claim_graph(
    fact_kind: str = "identity_binding",
    required_fields: tuple[str, ...] = ("user",),
) -> ClaimGraph:
    return ClaimGraph(
        id="cg-census",
        request_id="req-census",
        objective="Resolve the requested subject attribute",
        claims=[
            Claim(
                id="claim-attribute",
                claim_type="attribute",
                subject="person:Amber",
                predicate="has_requested_attribute",
                provenance="request",
                source_request_id="req-census",
                value_type="account_name",
                observation_requirements=(
                    ClaimEvidenceRequirement(
                        id="req-attribute",
                        fact_kind=fact_kind,
                        required_fields=required_fields,
                    ),
                ),
                acceptance_rule=AcceptanceRule(required_fields=required_fields),
            )
        ],
    )


def _compiler_payload(fact_kind: str, required_fields: list[str]) -> str:
    return json.dumps(
        {
            "id": "cg-runtime",
            "request_id": "req-census",
            "objective": "Resolve the requested subject attribute",
            "answer_contract": {
                "mode": "lookup",
                "answer_type": "account_name",
                "required_fields": required_fields,
                "question": "Resolve the requested subject attribute",
            },
            "claims": [
                {
                    "id": "claim-attribute",
                    "claim_type": "attribute",
                    "subject": "person:Amber",
                    "predicate": "has_requested_attribute",
                    "object_or_value": None,
                    "value_type": "account_name",
                    "provenance": "request",
                    "source_request_id": "req-census",
                    "dependencies": [],
                    "evidence_requirements": [],
                    "observation_requirements": [
                        {
                            "id": "req-attribute",
                            "fact_kind": fact_kind,
                            "required_fields": required_fields,
                            "field_roles": ["account_name"],
                            "completeness_required": False,
                        }
                    ],
                    "acceptance_rule": {
                        "min_observations": 1,
                        "required_fields": required_fields,
                        "requires_query_complete": False,
                        "value_must_match": None,
                    },
                    "refutation_rule": None,
                    "optional": False,
                    "is_prerequisite": False,
                    "reason": "The request asks for this attribute",
                }
            ],
            "metadata": {},
        }
    )


def test_census_records_all_providers_and_rejects_irrelevant_online_provider() -> None:
    useful_operation = ProviderOperation(
        id="resolve_identity",
        provider_id="useful",
        scope_ids=("useful-scope",),
        input_entity_kinds=("person",),
        output_fields=("user",),
        output_fact_kinds=("identity_binding",),
        completeness="cursor EOF proof",
    )
    irrelevant_operation = ProviderOperation(
        id="read_health",
        provider_id="irrelevant",
        scope_ids=("irrelevant-scope",),
        input_entity_kinds=("ANY",),
        output_fields=("sensor_status",),
        output_fact_kinds=("sensor_health",),
        completeness="cursor EOF proof",
    )
    providers = [
        CensusAdapter("useful", useful_operation),
        CensusAdapter("irrelevant", irrelevant_operation),
        CensusAdapter("offline", None, status="UNREACHABLE"),
    ]

    graph = ProviderCensusService().census(providers, _claim_graph())

    assert [provider.provider_id for provider in graph.providers] == [
        "useful",
        "irrelevant",
        "offline",
    ]
    assert graph.selected_providers() == ["useful"]
    rejected = {
        audit.provider_id: audit
        for audit in graph.audit
        if audit.claim_id == "claim-attribute" and not audit.selected
    }
    assert rejected["irrelevant"].status == "UNSUPPORTED"
    assert rejected["offline"].status == "UNREACHABLE"
    serialized = graph.to_dict()
    useful = next(p for p in serialized["providers"] if p["provider_id"] == "useful")
    assert useful["partitions"]["useful-scope"]["native_partition"] == {"source": "useful"}
    assert useful["schemas"]["events"]["fields"][-1] == "unknown_native_field"
    assert useful["aliases"]["account_name"] == ["user"]
    assert serialized["operations"][0]["output_fact_kinds"] == ["identity_binding"]


def test_census_requires_one_operation_to_supply_the_complete_observation_shape() -> None:
    split_fields = CensusAdapter(
        "split",
        ProviderOperation(
            id="resolve_sender_only",
            provider_id="split",
            scope_ids=("split-scope",),
            input_entity_kinds=("account",),
            output_fields=("sender_email",),
            output_fact_kinds=("outbound_message_metadata",),
            completeness="cursor EOF proof",
        ),
    )
    catalog = split_fields.discover_full_capabilities()
    catalog.operations.append(
        ProviderOperation(
            id="resolve_recipient_only",
            provider_id="split",
            scope_ids=("split-scope",),
            input_entity_kinds=("message",),
            output_fields=("receiver_email",),
            output_fact_kinds=("outbound_message_metadata",),
            completeness="cursor EOF proof",
        )
    )
    catalog.observable_fields = ["sender_email", "receiver_email"]
    split_fields.discover_full_capabilities = lambda: catalog  # type: ignore[method-assign]

    graph = ProviderCensusService().census(
        [split_fields],
        _claim_graph(
            fact_kind="outbound_message_metadata",
            required_fields=("sender_email", "receiver_email"),
        ),
    )

    assert graph.selected_providers() == []
    assert graph.audit[0].status == "UNSUPPORTED"


def test_census_keeps_partially_observable_claim_executable() -> None:
    """Missing qualifiers must remain residual unknowns, not block discovery."""
    claim_graph = ClaimGraph(
        id="cg-partial",
        request_id="req-partial",
        objective="Resolve a person attribute with an additional qualifier",
        claims=[
            Claim(
                id="claim-partial",
                claim_type="attribute",
                subject="person:Amber",
                predicate="has_requested_attribute",
                provenance="request",
                source_request_id="req-partial",
                value_type="email_address",
                observation_requirements=(
                    ClaimEvidenceRequirement(
                        id="req-partial-email",
                        fact_kind="identity_binding",
                        field_roles=("subject_identity", "attribute_value", "personal_context"),
                        required_roles=("subject_identity", "attribute_value", "personal_context"),
                    ),
                ),
                acceptance_rule=AcceptanceRule(
                    required_roles=("subject_identity", "attribute_value", "personal_context"),
                ),
            )
        ],
    )
    adapter = CensusAdapter(
        "splunk",
        ProviderOperation(
            id="resolve_person_attribute",
            provider_id="splunk",
            scope_ids=("splunk-scope",),
            input_entity_kinds=("person",),
            output_fields=("user", "sender_email"),
            output_fact_kinds=("identity_binding",),
            output_roles=("subject_identity", "attribute_value"),
            native_field_bindings={
                "subject_identity": ("user",),
                "attribute_value": ("sender_email",),
            },
            completeness="cursor EOF proof",
        ),
    )

    graph = ProviderCensusService().census([adapter], claim_graph)

    assert graph.selected_providers() == ["splunk"]
    assert "partial" in graph.audit[0].reason


def test_engine_stops_before_query_when_online_provider_is_irrelevant(
    tmp_path: Path,
    monkeypatch,
) -> None:
    irrelevant = CensusAdapter(
        "irrelevant",
        ProviderOperation(
            id="read_health",
            provider_id="irrelevant",
            scope_ids=("irrelevant-scope",),
            input_entity_kinds=("ANY",),
            output_fields=("sensor_status",),
            output_fact_kinds=("sensor_health",),
            completeness="cursor EOF proof",
        ),
    )
    compiler = KnowledgeBehaviorCompiler(
        llm_caller=lambda _: _compiler_payload("identity_binding", ["user"])
    )
    engine = HypothesisHuntEngine(compiler=compiler)
    request = HuntRequest(
        id="req-census",
        kind=HuntRequestKind.NL_QUESTION,
        content="Resolve the requested subject attribute",
    )
    monkeypatch.chdir(tmp_path)

    result = engine.execute_hunt(request, adapters=[irrelevant])

    assert result.state.stopping_decision == StoppingDecision.STOP_UNSUPPORTED_CAPABILITY
    assert irrelevant.executions == 0
    assert result.state.capability_graph.rejected_providers() == ["irrelevant"]
    persisted = json.loads(
        (tmp_path / "artifacts" / request.id / "capability_graph.json").read_text(
            encoding="utf-8"
        )
    )
    assert persisted["audit"][0]["selected"] is False
    assert persisted["audit"][0]["status"] == "UNSUPPORTED"
    assert (tmp_path / "artifacts" / request.id / "claim_graph.json").exists()


def test_engine_selects_claim_capable_provider_not_first_configured(
    tmp_path: Path,
    monkeypatch,
) -> None:
    irrelevant = CensusAdapter(
        "irrelevant",
        ProviderOperation(
            id="read_health",
            provider_id="irrelevant",
            scope_ids=("irrelevant-scope",),
            input_entity_kinds=("ANY",),
            output_fields=("sensor_status",),
            output_fact_kinds=("sensor_health",),
            completeness="cursor EOF proof",
        ),
    )
    cdb = CdbAdapter(":memory:")
    compiler = KnowledgeBehaviorCompiler(
        llm_caller=lambda _: _compiler_payload("identity_binding", ["user"])
    )
    engine = HypothesisHuntEngine(compiler=compiler)
    request = HuntRequest(
        id="req-census",
        kind=HuntRequestKind.NL_QUESTION,
        content="Resolve the requested subject attribute",
    )
    monkeypatch.chdir(tmp_path)

    result = engine.execute_hunt(request, adapters=[irrelevant, cdb])

    assert result.state.capability_graph.selected_providers() == ["cdb"]
    assert result.state.capability_catalog.provider_id == "cdb"
    assert irrelevant.executions == 0
