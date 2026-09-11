"""Hypothesis-Driven Threat Hunting Engine (Canonical v4 Vertical Slice).

Coordinates:
- Knowledge & Behavior Compiler: Maps HuntRequest (CVE/TTP/IOC/NL) to HuntObjective, Hypotheses, and EvidenceRequirements.
- Capability Registry & Query Planner: Binds requirements to safe parameterized QueryPlans with PlanCache.
- Telemetry Adapters: Executes queries over CDB SQLite or mock SIEM/EDR/IDS providers.
- ObservationLedger: Ingests raw rows into append-only ledger, preserving native types and unmapped events.
- Evidence Engine: Deterministically extracts facts and compresses repeated telemetry into EvidenceCards.
- Hypothesis Reasoner: Deterministic predicates and temporal correlation, multi-hypothesis compatibility, competing hypothesis retention.
- Action Controller: TEST -> CONTROL -> EXPAND -> DISCOVER -> STOP sequence, budget enforcement.
- FinalHuntAccount & Reporter: Generates auditable FinalHuntAccount and Markdown report with epistemic guarantees.
"""
from __future__ import annotations

import inspect
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from hunting.capabilities.binder import CapabilityBinder
from hunting.capabilities.census import ProviderCensusService
from hunting.capabilities.models import VersionedCapabilityDescriptor
from hunting.capabilities.probe_executor import BoundedProbeExecutor
from hunting.capabilities.profile_cache import RuntimeCapabilityCache
from hunting.capabilities.registry import build_default_capability_registry
from hunting.capabilities.retriever import CapabilityBatcher
from hunting.capabilities.runtime_materializer import materialize_runtime_operation
from hunting.capabilities.source_mapping_validator import SourceMappingValidator
from hunting.capabilities.source_profiler import SourceProfiler
from hunting.compiler.compiler import KnowledgeBehaviorCompiler
from hunting.contracts.case_graph import (
    EvidenceSubgraph,
    RelationStatus,
    build_investigation_case_from_intent,
)
from hunting.contracts.cells import Cell, CellState, ProviderScope
from hunting.contracts.claim import ClaimStatus
from hunting.contracts.entities import Account, AnyEntity, Domain, EntityRef, Host, IPAddress
from hunting.contracts.evidence_state import (
    AnswerAttributeState,
    ArtifactEvidence,
    EvidenceState,
)
from hunting.contracts.expectations import (
    EvidenceRequirement,
    Expectation,
    TestStatus,
    is_entity_compatible_with_requirement,
)
from hunting.contracts.hunt import (
    EvidenceAssessment,
    EvidenceCard,
    FinalHuntAccount,
    HuntRequest,
    HuntState,
    HypothesisStatus,
    QueryPlan,
    RequirementStatus,
    StoppingDecision,
)
from hunting.contracts.hunt_spec import HuntSpec
from hunting.contracts.investigation_model import (
    GraphEdge,
    GraphNode,
    NodeStatus,
    NodeType,
    RelationType,
    build_investigation_model_from_intent,
)
from hunting.contracts.native_query import NativeQueryCandidate
from hunting.contracts.observations import EpistemicType, Observation
from hunting.contracts.queries import QueryResult
from hunting.contracts.semantic_graph import goal_graph_from_claim_graph
from hunting.controller.action_planner import InvestigationAction, InvestigationActionPlanner
from hunting.controller.controller import CanonicalActionController
from hunting.controller.cost import LLMUsageTracker
from hunting.controller.models import HuntAction, HuntBudgetLedger
from hunting.controller.reasoning import HypothesisReasoningEngine
from hunting.evidence.adjudicator import InvestigationAdjudicator
from hunting.evidence.evaluator import EvidenceEvaluator
from hunting.evidence.grouping import EvidenceGroupBuilder
from hunting.evidence.relation_verifier import RelationVerifier
from hunting.m1_ledger.ledger import ObservationLedger
from hunting.m5_adapter.allowlist import validate_time_window_format
from hunting.m5_adapter.cdb_adapter import CdbAdapter
from hunting.m5_adapter.controls import license_valid_negative
from hunting.planner.adaptive import AdaptiveOperationPlanner
from hunting.planner.planner import CanonicalQueryPlanner
from hunting.planner.semantic_executor import SemanticPlanExecutor
from hunting.planner.semantic_goal_planner import SemanticGoalPlanner
from hunting.planner.semantic_query_compiler import query_plan_from_step
from hunting.planner.semantic_readiness import assess_semantic_readiness
from hunting.reporter.builder import build_final_hunt_account
from hunting.reporter.renderer import render_analyst_report
from hunting.validator.investigation_validator import InvestigationValidator

logger = logging.getLogger(__name__)

SYSTEM_USERS = {
    "system", "local service", "network service", "anonymous logon",
    "dwm-1", "dwm-2", "dwm-3", "font driver host", "window manager", "-", "n/a", ""
}


@dataclass(frozen=True)
class HuntExecutionResult:
    """Immutable result of an orchestrated threat hunting execution."""
    account: FinalHuntAccount
    report: str
    state: HuntState
    ledger: ObservationLedger
    budget: HuntBudgetLedger


class HypothesisHuntEngine:
    """Canonical Threat Hunting Engine implementing the v4 hypothesis-driven architecture."""

    def __init__(
        self,
        compiler: KnowledgeBehaviorCompiler | None = None,
        registry: dict[str, Any] | None = None,
        planner: CanonicalQueryPlanner | None = None,
        adaptive_planner: AdaptiveOperationPlanner | None = None,
        cdb_adapter: CdbAdapter | None = None,
        configured_adapters: list[Any] | tuple[Any, ...] | None = None,
        census_service: ProviderCensusService | None = None,
        budget_ledger: HuntBudgetLedger | None = None,
        evaluator: EvidenceEvaluator | None = None,
        llm_tracker: LLMUsageTracker | None = None,
        source_profiler_caller: Callable[[str], str] | None = None,
        runtime_capability_cache: RuntimeCapabilityCache | None = None,
    ) -> None:
        self.compiler = compiler if compiler is not None else KnowledgeBehaviorCompiler()
        self.registry = registry if registry is not None else build_default_capability_registry()
        self.planner = planner if planner is not None else CanonicalQueryPlanner(self.registry)
        self.cdb_adapter = cdb_adapter if cdb_adapter is not None else CdbAdapter()
        self.configured_adapters = tuple(configured_adapters or ())
        self.census_service = census_service if census_service is not None else ProviderCensusService()
        self.budget_ledger = budget_ledger if budget_ledger is not None else HuntBudgetLedger()
        self.llm_tracker = llm_tracker if llm_tracker is not None else LLMUsageTracker()
        self.budget_ledger.llm_tracker = self.llm_tracker
        self.budget_ledger.max_llm_calls = self.llm_tracker.max_calls
        self.source_profiler_caller = source_profiler_caller
        self.runtime_capability_cache = runtime_capability_cache or RuntimeCapabilityCache()
        self.adaptive_planner = (
            adaptive_planner
            if adaptive_planner is not None
            else AdaptiveOperationPlanner(
                llm_generator=getattr(self.planner, "llm_generator", None),
                llm_tracker=self.llm_tracker,
            )
        )
        self.group_builder = EvidenceGroupBuilder()
        self.reasoner = HypothesisReasoningEngine()
        self.evaluator = evaluator if evaluator is not None else EvidenceEvaluator()
        self.controller = CanonicalActionController(budget_ledger=self.budget_ledger)
        self.adjudicator = InvestigationAdjudicator()
        self.inv_validator = InvestigationValidator()
        self.capability_binder = CapabilityBinder()
        self.action_planner = InvestigationActionPlanner(binder=self.capability_binder)
        self.relation_verifier = RelationVerifier()
        # A human decision resumes the same compiled graph.  Cache only the
        # validated compiler result for the exact request identity/content so
        # selecting a candidate cannot trigger a second semantic compilation
        # or produce a different graph on the retry.
        self._semantic_compilation_cache: dict[str, tuple[str, Any, Any, Any]] = {}

    def execute_semantic_plan(
        self,
        state: HuntState,
        active_adapter: Any,
        scope: ProviderScope,
        ledger: ObservationLedger,
        *,
        limit: int = 100,
        # A partial result is retained with a continuation token, but a
        # single semantic plan must not consume the whole hunt query budget by
        # expanding every candidate indefinitely.  Resumption belongs to a
        # bounded controller action, not an unbounded inner loop.
        max_pages: int = 4,
        allow_candidate_inputs: bool = False,
        initial_bindings: dict[str, str | list[str]] | None = None,
    ) -> Any:
        """Execute a fully grounded SemanticGoalGraph plan.

        This is the engine boundary for the new architecture.  It is kept as
        an explicit entry point while migration is in progress so legacy
        ClaimGraph execution cannot accidentally run the same query twice.
        """
        logical_plan = getattr(state, "semantic_logical_plan", None)
        goal_graph = getattr(state, "semantic_goal_graph", None)
        if logical_plan is None or goal_graph is None:
            raise ValueError("A semantic goal graph and logical plan are required")
        # A graph may have a runnable prefix and an unresolved downstream
        # relation.  Execute the prefix so its observations can explain the
        # boundary (and potentially provide evidence for a later refinement),
        # but never promote the unresolved relation to proof.  The final
        # semantic analysis below records the unresolved goals and the caller
        # chooses an explicit inconclusive/unsupported stop.

        initial_variables = {
            variable.id: variable.value
            for variable in goal_graph.variables
            if variable.value not in (None, "") and variable.value_origin == "request"
        }
        initial_variable_sources = {key: "request" for key in initial_variables}
        known_variable_ids = {variable.id for variable in goal_graph.variables}
        for variable_id, values in (initial_bindings or {}).items():
            if variable_id in known_variable_ids:
                initial_variables[variable_id] = values
                initial_variable_sources[variable_id] = "user_selection"
        operations = tuple(getattr(getattr(state, "capability_catalog", None), "operations", ()) or ())
        execution = SemanticPlanExecutor(active_adapter, operations).execute(
            logical_plan,
            scope,
            state.objective.time_window if state.objective else "",
            initial_variables,
            limit=limit,
            max_pages=max_pages,
            variable_types={variable.id: variable.entity_type for variable in goal_graph.variables},
            allow_candidate_inputs=allow_candidate_inputs,
            initial_variable_sources=initial_variable_sources,
        )

        observations_by_query: dict[str, list[Observation]] = {}
        for item in execution.executions:
            # Binding selections are controller/audit events, not provider
            # executions. They have no native query and consume no query budget.
            if item.status == "USER_SELECTED":
                continue
            step = next(step for step in logical_plan.steps if step.id == item.step_id)
            step_for_query = step
            if getattr(item, "operation_id", "") and item.operation_id != step.operation_id:
                from dataclasses import replace
                step_for_query = replace(step, operation_id=item.operation_id)
            operation = next(
                (
                    candidate
                    for candidate in getattr(state.capability_catalog, "operations", ())
                    if candidate.id == item.operation_id
                ),
                None,
            )
            query_plan = query_plan_from_step(
                logical_plan,
                step_for_query,
                scope,
                state.objective.time_window if state.objective else "",
                query_id=item.query_id,
                limit=limit,
                operation=operation,
                retrieval_stage=item.stage_id,
                removed_retrieval_keys=set(item.removed_retrieval_keys),
            )
            query_plan.parameters["bound_values"] = {
                name: list(values) for name, values in item.inputs.items()
            }
            if operation is not None:
                query_plan.parameters["expected_fields"] = list(operation.output_fields)
            # Keep the provider-page audit attached to the logical query.  A
            # single logical step can consist of multiple native SPL calls;
            # the final report must not imply that one 800-row result was an
            # EOF-complete query.
            query_plan.parameters["page_trace"] = [
                dict(page)
                for page in getattr(execution, "page_trace", [])
                if page.get("step_id") == item.step_id
                and page.get("operation_id") == item.operation_id
            ]
            query_plan.parameters["continuation"] = dict(
                getattr(execution, "continuations", {}).get(item.step_id, {})
            )
            self.controller.record_query_execution(state, query_plan, item.result)

            for row_index, row in enumerate(item.result.rows or ()):
                observation_id = f"obs-{item.query_id}-{row_index}"
                observation = Observation(
                    id=observation_id,
                    provider_scope=scope,
                    cell_id=state.objective.time_window if state.objective else scope.scope_id,
                    timestamp=str(row.get("_time", row.get("timestamp", ""))) or "1970-01-01T00:00:00Z",
                    epistemic_type=EpistemicType.OBSERVED,
                    native_type=str(row.get("sourcetype", row.get("native_type", ""))),
                    fields=dict(row),
                    raw_event=dict(row.get("raw_event") or row),
                    query_id=item.query_id,
                )
                ledger.add_observation(observation)
                self.controller.add_observation(state, observation)
                observations_by_query.setdefault(item.query_id, []).append(observation)

        state.semantic_route_assessments = list(execution.route_assessments)

        # Intermediate grounding steps are necessary for planning but are not
        # answer evidence by themselves.  Only observations from steps that
        # advance a declared semantic goal may become EvidenceCards; this
        # prevents identity-enrichment/process rows from contaminating a final
        # email/domain/version answer.
        # Only complete, correctly-grounded goal steps become proof evidence.
        # Partial discovery rows remain in the immutable ledger and query
        # diagnostics, but must not contaminate the answer evidence graph.
        goal_query_ids = {
            item.query_id
            for item in execution.executions
            if any(
                step.id == item.step_id and step.advances_goal_ids
                for step in logical_plan.steps
            ) and item.result.executed_ok and item.result.complete and bool(item.outputs)
        }
        goal_observations = [
            observation
            for query_id in goal_query_ids
            for observation in observations_by_query.get(query_id, [])
        ]
        if goal_observations:
            self.group_builder.ingest_delta(goal_observations)
            self.controller.set_evidence_cards(state, self.group_builder.build_cards())

        goal_verdicts: list[dict[str, Any]] = []
        operation_by_id = {
            operation.id: operation
            for operation in operations
        }
        executed_by_goal = {
            goal_id: [item for item in execution.executions if goal_id in next(
                step for step in logical_plan.steps if step.id == item.step_id
            ).advances_goal_ids]
            for goal_id in (goal.id for goal in goal_graph.relations)
        }
        for goal in goal_graph.relations:
            executions = executed_by_goal.get(goal.id, [])
            base_relation_proven = any(
                item.result.executed_ok and bool(item.result.rows)
                and item.result.complete and bool(item.outputs)
                and getattr(operation_by_id.get(item.operation_id), "proof_mode", "retrieval_only")
                == "relation_observable"
                for item in executions
            )
            target = next(variable for variable in goal_graph.variables if variable.id == goal.object)
            # Subject restrictions are obligations of the step that grounded
            # the subject.  They are not silently re-applied to a downstream
            # relation; doing so caused device/platform clues to distort file
            # and network queries.  The target restrictions and relation
            # qualifiers are evaluated against this goal only.
            required_restrictions = [item.text() for item in target.constraints]
            required_restrictions.extend(
                qualifier.qualifier if qualifier.expected_value is None
                else f"{qualifier.qualifier}={qualifier.value_text()}"
                for qualifier in goal_graph.qualifiers
                if qualifier.target_goal_id == goal.id and qualifier.required
            )
            proof_keys = {
                str(key).strip().casefold()
                for item in executions
                for key in getattr(operation_by_id.get(item.operation_id), "supported_constraints", ())
            }
            unverified_restrictions = [
                restriction for restriction in required_restrictions
                if restriction.split("=", 1)[0].split(":", 1)[0].strip().casefold() not in proof_keys
            ]
            # A provider may retrieve a candidate with a searchable hint, but
            # only an explicitly proof-capable operation can satisfy the
            # corresponding restriction.
            supported = base_relation_proven and not unverified_restrictions
            partial = any(item.result.executed_ok and not item.result.complete for item in executions)
            status = (
                "SUPPORTED" if supported
                else "INCONCLUSIVE_RESTRICTIONS_UNVERIFIED" if base_relation_proven and required_restrictions
                else "PARTIAL" if partial
                else "INCONCLUSIVE"
            )
            goal_verdicts.append({
                "goal_id": goal.id,
                "relation": goal.relation,
                "status": status,
                "query_ids": [item.query_id for item in executions],
                "proof_method_id": getattr(logical_plan, "selected_method_ids", {}).get(goal.id),
                "unverified_restrictions": unverified_restrictions if base_relation_proven else [],
            })
        self.controller.set_semantic_analysis(state, {
            # This is an audit of the structured compiler exchange, not hidden
            # chain-of-thought.  It lets the report distinguish a valid LLM
            # graph from a rejected or fallback compilation.
            "compiler_trace": dict(getattr(state, "compiler_trace", {}) or {}),
            "goal_verdicts": goal_verdicts,
            "proof_state": {item["goal_id"]: item["status"] for item in goal_verdicts},
            "executed_steps": [item.step_id for item in execution.executions],
            "unresolved_steps": list(execution.unresolved_step_ids),
            "unresolved_goals": list(getattr(logical_plan, "unresolved_goal_ids", [])),
            "unresolved_reasons": dict(execution.unresolved_reasons),
            "candidate_input_warnings": dict(getattr(execution, "candidate_input_warnings", {})),
            "needs_user_decision": execution.needs_user_decision,
            "binding_provenance": dict(execution.binding_provenance),
            "page_trace": [dict(page) for page in getattr(execution, "page_trace", [])],
            "continuations": {
                key: dict(value)
                for key, value in getattr(execution, "continuations", {}).items()
            },
            "unverified_restrictions": {
                item["goal_id"]: item["unverified_restrictions"]
                for item in goal_verdicts if item["unverified_restrictions"]
            },
            "binding_events": [
                {
                    "step_id": event.step_id,
                    "variable_ids": list(event.variable_ids),
                    "values": {key: list(values) for key, values in event.values.items()},
                    "source": event.source,
                }
                for event in execution.binding_events
            ],
            "route_assessments": [
                assessment.to_dict() for assessment in execution.route_assessments
            ],
        })
        required_verdicts = [item for item, goal in zip(goal_verdicts, goal_graph.relations) if goal.required]
        if required_verdicts and all(item["status"] == "SUPPORTED" for item in required_verdicts):
            for hypothesis in state.hypotheses:
                hypothesis.status = HypothesisStatus.SUPPORTED
            self.controller.set_stopping_decision(state, StoppingDecision.STOP_RESOLVED)
        elif execution.needs_user_decision:
            self.controller.set_stopping_decision(state, StoppingDecision.STOP_NEEDS_USER_DECISION)
        elif execution.unresolved_step_ids:
            # A missing typed binding is an explicit execution boundary.  It
            # must be visible in the account and cannot be mistaken for a
            # successful negative search or silently dropped plan steps.
            # A provider result that was executed but did not reach EOF is a
            # coverage problem, not proof that the relation is false or that
            # the graph itself is invalid.  The continuation details are
            # persisted above so a future controller action can resume/refine
            # the step without trusting partial rows as proof.
            if getattr(execution, "continuations", {}):
                self.controller.set_stopping_decision(state, StoppingDecision.STOP_INCONCLUSIVE_COVERAGE_GAP)
            else:
                self.controller.set_stopping_decision(state, StoppingDecision.STOP_INCONCLUSIVE_RELATION_UNPROVEN)
        else:
            self.controller.set_stopping_decision(state, StoppingDecision.STOP_INCONCLUSIVE_RELATION_UNPROVEN)

        state.semantic_plan_executed = True
        return execution

    def _run_semantic_discovery(
        self,
        state: HuntState,
        active_adapter: Any,
        scope: ProviderScope,
        ledger: ObservationLedger,
        step_callback: Callable[[str, dict[str, Any]], None] | None,
    ) -> None:
        """Run bounded provider-neutral content discovery before graph pivots."""
        spec = state.hunt_spec
        if spec is None or not spec.search_terms:
            return
        if getattr(active_adapter, "provider_id", "") != "splunk":
            return
        try:
            descriptor = active_adapter.get_capability_descriptor()
            operation_ids = {op.id for op in getattr(descriptor, "operations", ())}
        except Exception:
            operation_ids = set()
        if "search_text" not in operation_ids:
            return

        import inspect

        # Progressive query relaxation across levels 1, 2, and 3
        qr = None
        plan = None
        terms = [term.value for term in spec.search_terms[:24]]

        for relaxation_level in (1, 2, 3):
            search_groups = spec.discovery_groups(relaxation_level=relaxation_level)
            if not search_groups:
                continue

            query_id = f"qp-discovery-{state.turn or 0}" if relaxation_level == 1 else f"qp-discovery-{state.turn or 0}-rel{relaxation_level}"
            plan = QueryPlan(
                id=query_id,
                requirement_id="discovery",
                provider_id=scope.provider_id,
                scope_id=scope.scope_id,
                operation_id="search_text",
                parameters={
                    "window": state.objective.time_window if state.objective else "",
                    "limit": 500,
                    "terms": terms,
                    "term_groups": search_groups,
                    "relaxation_level": relaxation_level,
                    "purpose": "provider-neutral content discovery" if relaxation_level == 1 else f"provider-neutral content discovery (relaxation level {relaxation_level})",
                },
                is_targeted=False,
            )
            if step_callback:
                step_callback("TURN_ACTION", {
                    "turn": state.turn,
                    "action": "DISCOVER (content)" if relaxation_level == 1 else f"DISCOVER (relaxation level {relaxation_level})",
                    "operation": "search_text",
                    "terms": terms,
                    "relaxation_level": relaxation_level,
                    "target": "provider scope",
                })

            kwargs: dict[str, Any] = {
                "operation_id": "search_text",
                "entity": AnyEntity(),
                "window": state.objective.time_window if state.objective else "",
                "limit": 500,
                "query_id": query_id,
            }
            if "search_terms" in inspect.signature(active_adapter.execute_query).parameters:
                kwargs["search_terms"] = terms
            if "search_groups" in inspect.signature(active_adapter.execute_query).parameters:
                kwargs["search_groups"] = search_groups
            qr = active_adapter.execute_query(**kwargs)
            self.controller.record_query_execution(state, plan, qr)

            if qr.rows:
                break

        state.discovery_completed = True

        if qr is None or not qr.rows:
            return

        candidates: list[str] = []
        host_candidates: list[str] = []
        new_observations: list[Observation] = []
        for row in qr.rows:
            host_value = str(row.get("host", "") or "").strip()
            if host_value and host_value not in host_candidates and len(host_candidates) < 8:
                host_candidates.append(host_value)
            for key in ("host", "user", "Image", "image", "Path", "path", "TargetFilename"):
                value = str(row.get(key, "") or "").strip()
                if value and value not in candidates and len(candidates) < 50:
                    candidates.append(value)
            obs_id = f"obs-discovery-{len(ledger.observations) + 1}"
            obs = Observation(
                id=obs_id,
                provider_scope=scope,
                cell_id=f"discovery:{scope.scope_id}",
                timestamp=str(row.get("timestamp", "")),
                epistemic_type=EpistemicType.OBSERVED,
                native_type=row.get("native_type"),
                fields=dict(row),
                entities=[],
                raw_event=dict(row.get("raw_event") or row),
                query_id=query_id,
            )
            ledger.add_observation(obs)
            self.controller.add_observation(state, obs)
            new_observations.append(obs)

        state.discovery_anchor_values = candidates
        # Discovery is a control phase.  Its rows are retained in the
        # append-only ledger for later pivots, but are not evidence for the
        # user's answer until a targeted goal query verifies them.

        # A bounded adaptive pivot handles Splunk's explicit truncation signal.
        # It searches the observed host(s) with the same semantic evidence
        # group, instead of launching the legacy file/process sweep.
        if not qr.complete and host_candidates and len(search_groups) >= 2:
            followup_id = f"qp-discovery-followup-{state.turn or 0}"
            followup_groups = [host_candidates[:4], search_groups[-1]]
            followup_terms = [term for group in followup_groups for term in group]
            followup_plan = QueryPlan(
                id=followup_id,
                requirement_id="discovery-followup",
                provider_id=scope.provider_id,
                scope_id=scope.scope_id,
                operation_id="search_text",
                parameters={
                    "window": state.objective.time_window if state.objective else "",
                    "limit": 500,
                    "terms": followup_terms,
                    "term_groups": followup_groups,
                    "purpose": "bounded observed-anchor refinement",
                },
                is_targeted=True,
            )
            if step_callback:
                step_callback("TURN_ACTION", {
                    "turn": state.turn,
                    "action": "REFINE (observed anchor)",
                    "operation": "search_text",
                    "terms": followup_terms,
                    "target": ", ".join(host_candidates[:4]),
                })
            import inspect
            followup_kwargs: dict[str, Any] = {
                "operation_id": "search_text",
                "entity": AnyEntity(),
                "window": state.objective.time_window if state.objective else "",
                "limit": 500,
                "query_id": followup_id,
            }
            if "search_terms" in inspect.signature(active_adapter.execute_query).parameters:
                followup_kwargs["search_terms"] = followup_terms
            if "search_groups" in inspect.signature(active_adapter.execute_query).parameters:
                followup_kwargs["search_groups"] = followup_groups
            followup_qr = active_adapter.execute_query(**followup_kwargs)
            self.controller.record_query_execution(state, followup_plan, followup_qr)
            followup_observations: list[Observation] = []
            for row in followup_qr.rows:
                obs_id = f"obs-discovery-{len(ledger.observations) + 1}"
                obs = Observation(
                    id=obs_id,
                    provider_scope=scope,
                    cell_id=f"discovery:{scope.scope_id}",
                    timestamp=str(row.get("timestamp", "")),
                    epistemic_type=EpistemicType.OBSERVED,
                    native_type=row.get("native_type"),
                    fields=dict(row),
                    entities=[],
                    raw_event=dict(row.get("raw_event") or row),
                    query_id=followup_id,
                )
                ledger.add_observation(obs)
                self.controller.add_observation(state, obs)
                followup_observations.append(obs)
            # The observed-anchor refinement is still discovery/control data;
            # do not mint answer evidence from it.

        self._update_evidence_state(state, ledger)

    def _update_evidence_state(self, state: HuntState, ledger: ObservationLedger) -> None:
        """Derive structured EvidenceState tracking artifact and attribute observations.

        v6: artifact_name is extracted from HuntSpec/semantic_intent, not from keyword
        scanning of the question text. This removes hardcoded "Tor Browser" detection.
        """
        answer_spec = (state.objective.answer_spec or {}) if state.objective else {}
        answer_type = str(answer_spec.get("answer_type") or "software_version").lower()

        # v6: Derive target artifact name from structured spec, NOT from "tor" keyword.
        # Priority order:
        # 1. HuntSpec search_terms (LLM-derived, high confidence)
        # 2. semantic_intent.behavior (LLM proposed)
        # 3. answer_spec object name
        # 4. Empty string (artifact name unknown — do not assume)
        target_artifact_name = ""
        hunt_spec = getattr(getattr(state.objective, "semantic_intent", None) or {}, "hunt_spec", None) \
            or getattr(state.objective, "hunt_spec", None)
        if hunt_spec is None:
            # Try to get from semantic_intent directly
            sem_intent = getattr(state.objective, "semantic_intent", None)
            behavior = str(getattr(sem_intent, "behavior", "") or "").strip()
            if behavior and behavior.lower() not in {"unknown", ""}:
                target_artifact_name = behavior
            req_obj = getattr(sem_intent, "requested_object", None)
            if not target_artifact_name and req_obj:
                rv = str(getattr(req_obj, "value", "") or "").strip()
                if rv and rv.lower() not in {"unknown", "", "?"}:
                    target_artifact_name = rv
        else:
            # Use HuntSpec search_terms filtered by confidence
            high_conf = [t.value for t in getattr(hunt_spec, "search_terms", [])
                         if getattr(t, "confidence", 0) >= 0.8 and t.value.strip()]
            if high_conf:
                target_artifact_name = high_conf[0]

        artifact_host = ""
        artifact_path = None
        artifact_proc = None
        artifact_obs_ids: list[str] = []
        is_detected = False

        # --- Detect artifact from evidence cards ---
        # v6: detection is based on card.fact_type and field content, not "tor" keyword
        for card in state.evidence_cards:
            fps = [str(x) for x in card.field_summary.get("file_paths", [])]
            imgs = [str(x) for x in card.field_summary.get("process_names", []) or card.field_summary.get("images", [])]
            hosts = [str(x) for x in card.entity_summary.get("hosts", []) if str(x).strip()]
            c_sum = str(getattr(card, "summary", ""))
            # Match against known artifact names (from spec) or fact_type
            name_lower = target_artifact_name.lower() if target_artifact_name else ""
            has_artifact = (
                card.fact_type in ("process_execution", "software_artifact", "file_modification")
                or (name_lower and any(name_lower in s.lower() for s in (fps + imgs + [c_sum])))
            )
            if has_artifact:
                is_detected = True
                if hosts and not artifact_host:
                    artifact_host = hosts[0]
                if fps and not artifact_path:
                    artifact_path = fps[0]
                if imgs and not artifact_proc:
                    artifact_proc = imgs[0]
                # Derive artifact name from card data if still unknown
                if not target_artifact_name and fps:
                    import os
                    target_artifact_name = os.path.basename(fps[0])
                artifact_obs_ids.extend(card.representative_observation_ids)

        # --- Detect artifact from raw observations ---
        for obs in ledger.observations:
            f = obs.fields
            img = str(f.get("Image") or f.get("image") or f.get("process_name") or "")
            path = str(f.get("Path") or f.get("path") or f.get("TargetFilename") or "")
            cmd = str(f.get("CommandLine") or f.get("cmdline") or "")
            h = str(f.get("host") or "")
            name_lower = target_artifact_name.lower() if target_artifact_name else ""
            # Match if we have a known artifact name OR if fact_type signals artifact presence
            has_artifact_obs = name_lower and any(name_lower in s.lower() for s in (img, path, cmd) if s)
            if has_artifact_obs:
                is_detected = True
                if h and not artifact_host:
                    artifact_host = h
                if path and not artifact_path:
                    artifact_path = path
                if img and not artifact_proc:
                    artifact_proc = img
                if obs.id not in artifact_obs_ids:
                    artifact_obs_ids.append(obs.id)


        version_fields = ("ProductVersion", "FileVersion", "Version", "version", "software_version")
        observed_versions: list[str] = []
        version_obs_ids: list[str] = []
        for obs in ledger.observations:
            for vf in version_fields:
                val = obs.fields.get(vf)
                if val is not None and str(val).strip() and str(val).strip() != "-":
                    v_clean = str(val).strip()
                    if v_clean not in observed_versions:
                        observed_versions.append(v_clean)
                    if obs.id not in version_obs_ids:
                        version_obs_ids.append(obs.id)

        if not observed_versions and answer_type == "software_version":
            from hunting.evidence.attribute_extractor import extract_attributes_from_observation
            for obs in ledger.observations:
                ext_list = extract_attributes_from_observation(obs, "software_version")
                for ext in ext_list:
                    if ext.value not in observed_versions:
                        observed_versions.append(ext.value)
                    if obs.id not in version_obs_ids:
                        version_obs_ids.append(obs.id)

        ev_state = EvidenceState()
        if is_detected:
            ev_state.artifact = ArtifactEvidence(
                type="software",
                name=target_artifact_name or "Target Artifact",
                host=artifact_host,
                path=artifact_path,
                process_name=artifact_proc,
                detected=True,
                observation_ids=artifact_obs_ids,
            )

        if observed_versions:
            ev_state.set_attribute(
                answer_type,
                AnswerAttributeState.OBSERVED,
                values=observed_versions,
                obs_ids=version_obs_ids,
            )
        elif is_detected:
            ev_state.set_attribute(
                answer_type,
                AnswerAttributeState.NOT_OBSERVED,
                values=[],
                obs_ids=[],
            )
        else:
            ev_state.set_attribute(
                answer_type,
                AnswerAttributeState.UNKNOWN,
                values=[],
                obs_ids=[],
            )

        state.evidence_state = ev_state

    def _evaluate_identity_linkage(
        self,
        state: HuntState,
        rows: list[dict[str, Any]],
        ledger: ObservationLedger | None = None,
        query_id: str | None = None,
    ) -> None:
        """Evaluate and update identity mapping for person subjects, avoiding web server false bindings."""
        obj = state.objective
        if not obj or not getattr(obj, "semantic_intent", None):
            return
        intent = obj.semantic_intent
        if not intent or getattr(intent.subject, "type", "") != "person":
            return

        subj_val = intent.subject.value.lower()
        candidate_edges: list[GraphEdge] = []
        graph = state.relation_graph
        # v5 relation-first hunts use InvestigationCase.graph and the
        # RelationVerifier. This legacy helper operates on the older
        # RelationGraph API and must not mutate the canonical case graph.
        if graph is None or not hasattr(graph, "get_node_by_value"):
            state.identity_mapping.setdefault("reason", "IDENTITY_UNRESOLVED")
            return

        for row in rows:
            user = str(row.get("user", "")).strip()
            host = str(row.get("host", "")).strip()
            if not user or not host:
                continue
            u_clean = user.lower().replace(".", " ")
            if subj_val in u_clean or any(part in u_clean.split() for part in subj_val.split() if len(part) > 2):
                state.identity_resolved = True
                state.identity_mapping["endpoint"] = host
                state.identity_mapping["user"] = user
                for ip_key in ("client_ip", "src_ip", "source_ip", "c_ip"):
                    if row.get(ip_key):
                        state.identity_mapping["client_ip"] = str(row[ip_key])
                        break

                if graph:
                    subj_node = graph.get_node_by_value(intent.subject.value, "person")
                    endpoint_node = graph.get_node("node-endpoint")
                    if not endpoint_node:
                        endpoint_node = GraphNode(id=f"node-{host}", type=NodeType.ENDPOINT.value, value=host, status=NodeStatus.UNKNOWN)
                        graph.add_node(endpoint_node)
                    else:
                        endpoint_node.value = host

                    if subj_node and endpoint_node:
                        obs_ids = []
                        if ledger:
                            obs_ids = [o.id for o in ledger.observations if str(o.fields.get("host", "")).lower() == host.lower()]
                        edge = GraphEdge(
                            id=f"edge-auth-{user}-{host}",
                            source_id=subj_node.id,
                            target_id=endpoint_node.id,
                            relation_type=RelationType.LOGGED_ON_TO.value,
                            status=NodeStatus.UNKNOWN,
                            origin_query_id=query_id,
                            metadata={"observation_ids": obs_ids, "client_ip": state.identity_mapping.get("client_ip", "")},
                        )
                        candidate_edges.append(edge)

                        if state.identity_mapping.get("client_ip"):
                            cip = state.identity_mapping["client_ip"]
                            ip_node = graph.get_node("node-client-ip")
                            if not ip_node:
                                ip_node = GraphNode(id=f"node-{cip}", type=NodeType.IP.value, value=cip, status=NodeStatus.UNKNOWN)
                                graph.add_node(ip_node)
                            else:
                                ip_node.value = cip
                            ip_edge = GraphEdge(
                                id=f"edge-ip-{host}-{cip}",
                                source_id=endpoint_node.id,
                                target_id=ip_node.id,
                                relation_type=RelationType.ORIGINATED_FROM.value,
                                status=NodeStatus.UNKNOWN,
                                origin_query_id=query_id,
                                metadata={"observation_ids": obs_ids},
                            )
                            candidate_edges.append(ip_edge)
                break

        if not state.identity_resolved:
            state.identity_mapping.setdefault("reason", "IDENTITY_UNRESOLVED")

        # Adjudicate candidate edges
        if candidate_edges and ledger:
            self.adjudicator.adjudicate_and_apply(candidate_edges, ledger, state)
            if state.investigation_model:
                for unk in state.investigation_model.unknowns:
                    if unk.entity_type in ("endpoint", "host") and state.identity_resolved:
                        unk.status = "RESOLVED"
                    if unk.entity_type == "ip" and state.identity_mapping.get("client_ip"):
                        unk.status = "RESOLVED"

        # Check for web / DNS traffic correlation if client_ip is known
        if graph and state.identity_mapping.get("client_ip"):
            cip = state.identity_mapping["client_ip"]
            ip_node = graph.get_node("node-client-ip") or graph.get_node(f"node-{cip}")
            target_node = graph.get_node("node-target-object")
            traffic_edges: list[GraphEdge] = []
            for row in rows:
                row_ip = str(row.get("client_ip", row.get("source_ip", row.get("src_ip", row.get("c_ip", ""))))).strip()
                row_dom = str(row.get("site", row.get("domain", row.get("query", "")))).strip()
                if row_dom and (not row_ip or row_ip == cip):
                    if target_node:
                        target_node.value = row_dom
                    if ip_node and target_node:
                        obs_ids = []
                        if ledger:
                            obs_ids = [
                                o.id for o in ledger.observations
                                if str(o.fields.get("site", o.fields.get("domain", o.fields.get("query", "")))).strip() == row_dom
                            ]
                        t_edge = GraphEdge(
                            id=f"edge-traffic-{cip}-{row_dom}",
                            source_id=ip_node.id,
                            target_id=target_node.id,
                            relation_type=RelationType.REQUESTED.value,
                            status=NodeStatus.UNKNOWN,
                            origin_query_id=query_id,
                            metadata={"observation_ids": obs_ids},
                        )
                        traffic_edges.append(t_edge)
            if traffic_edges and ledger:
                self.adjudicator.adjudicate_and_apply(traffic_edges, ledger, state)

    def _record_semantic_analysis(self, state: HuntState, analysis: dict[str, Any]) -> None:
        """Persist validated LLM evidence interpretation through the controller."""
        # The evaluator adds narrative fields, but must not erase the
        # semantic executor's proof state, binding provenance, page audit, or
        # continuations.  Losing those fields made a successful identity step
        # look unresolved in the final report.
        merged_analysis = {
            **dict(getattr(state, "semantic_analysis", {}) or {}),
            **dict(analysis),
        }
        if getattr(state, "compiler_trace", None):
            merged_analysis.setdefault("compiler_trace", dict(state.compiler_trace))
        self.controller.set_semantic_analysis(state, merged_analysis)
        for item in analysis.get("evaluations", []):
            if not isinstance(item, dict) or not item.get("card_id"):
                continue
            assessment = EvidenceAssessment(
                card_id=str(item["card_id"]),
                compatible_hypotheses=list(item.get("supporting_hypotheses", [])),
                confidence=float(item.get("confidence", 0.0)),
                reason=str(item.get("interpretation", "")),
                missing_evidence=list(item.get("missing_evidence", [])),
                source_refs=list(item.get("observation_ids", [])),
                interpretation=str(item.get("interpretation", "")),
                answer_candidates=list(item.get("answer_candidates", [])),
                contradicting_hypotheses=list(item.get("contradicting_hypotheses", [])),
            )
            self.controller.add_evidence_assessment(state, assessment)

    def execute_hunt(
        self,
        request: HuntRequest,
        adapter: Any | None = None,
        adapters: list[Any] | tuple[Any, ...] | None = None,
        time_window: str = "2026-02-01T00:00:00Z/P1D",
        step_callback: Callable[[str, dict[str, Any]], None] | None = None,
        analyst_confirm_callback: Callable[[str, dict[str, Any]], bool] | None = None,
        initial_bindings: dict[str, str | list[str]] | None = None,
    ) -> HuntExecutionResult:
        """Execute complete hypothesis-only hunt vertical slice without alert or PoC."""
        explicit_adapter = adapter is not None
        if adapter is not None and adapters is not None:
            raise ValueError("Pass either adapter or adapters, not both")
        if adapters is not None:
            configured_adapters = list(adapters)
        elif adapter is not None:
            configured_adapters = [adapter]
        elif self.configured_adapters:
            configured_adapters = list(self.configured_adapters)
        else:
            configured_adapters = [self.cdb_adapter]
        if not configured_adapters:
            raise ValueError("At least one configured provider adapter is required")

        ledger = ObservationLedger()

        # 1. Capture provider capabilities before semantic planning. The
        # census is retained for later relation-scoped retrieval; the semantic
        # compiler receives only the request and never receives this catalog.
        preplan_capability_graph = self.census_service.census(
            configured_adapters,
            claim_graph=None,
            provider_hints=request.provider_hints,
        )
        # The semantic compiler must not receive the full provider census.
        # Source/field selection is a later, relation-scoped retrieval stage.
        # Keeping this boundary explicit prevents schema size from becoming an
        # accidental LLM prompt multiplier.

        # 2. Compile HuntRequest deterministically (0 LLM calls for known
        # CVE/TTP); unstructured requests produce one validated graph.  A
        # candidate-selection retry reuses the exact validated result from
        # the first pass instead of calling the compiler again.
        cached_compilation = self._semantic_compilation_cache.get(request.id)
        if (
            initial_bindings
            and cached_compilation is not None
            and cached_compilation[0] == request.content
        ):
            _, objective, hypotheses, requirements = cached_compilation
        else:
            objective, hypotheses, requirements = self.compiler.compile(request)
            self._semantic_compilation_cache[request.id] = (
                request.content,
                objective,
                hypotheses,
                requirements,
            )
        if request.time_policy and request.time_policy.start and request.time_policy.end:
            objective.time_window = f"{request.time_policy.start}/{request.time_policy.end}"
        elif time_window and (not objective.time_window or objective.time_window.startswith("NOW")):
            objective.time_window = time_window

        inv_model = getattr(objective, "investigation_model", None)
        if inv_model is None and getattr(objective, "semantic_intent", None):
            inv_model = build_investigation_model_from_intent(objective.semantic_intent, hypotheses, requirements)

        inv_case = getattr(objective, "case", None)
        if inv_case is None and getattr(objective, "claim_graph", None):
            inv_case = build_investigation_case_from_intent(objective.claim_graph)

        state = HuntState(
            objective=objective,
            hypotheses=hypotheses,
            requirements=requirements,
            investigation_model=inv_model,
            # InvestigationCase.graph is the canonical relation state for v5.
            # Persisting the older model graph allowed legacy linkage code to
            # inject an IP/web chain into artifact-only investigations.
            relation_graph=inv_case.graph if inv_case else (inv_model.graph if inv_model else None),
            case=inv_case,
        )
        state.compiler_trace = dict(getattr(self.compiler, "last_compile_trace", {}) or {})

        claim_graph = getattr(objective, "claim_graph", None)
        native_semantic_graph = getattr(objective, "semantic_goal_graph", None) is not None
        if native_semantic_graph:
            state.semantic_goal_graph = objective.semantic_goal_graph
        elif claim_graph is not None:
            # Transitional boundary: expose the generic goal graph while the
            # legacy ClaimGraph executor is still active.  No provider fields
            # or operation-name heuristics are introduced here.
            state.semantic_goal_graph = goal_graph_from_claim_graph(claim_graph)
        # Reuse the captured census and apply claim-specific selection without
        # rediscovering providers or changing the capability snapshot supplied
        # to the semantic planner.
        capability_graph = self.census_service.select_claim_graph(
            preplan_capability_graph,
            claim_graph=claim_graph,
            provider_hints=request.provider_hints,
        )
        state.capability_graph = capability_graph

        # Source profiling is completed after provider selection below. Keep
        # the proposals local until a selected adapter has validated them.
        accepted_source_proposals: list[Any] = []
        source_profile_audit: dict[str, Any] = {}
        # The current run's declared capabilities are the primary source for
        # claim-to-operation binding. Legacy edge mapping remains available
        # only when no runtime capability graph is attached.
        self.capability_binder.set_capability_graph(capability_graph)

        selected_provider_ids = set(capability_graph.selected_providers())
        selected_adapters = [
            candidate
            for candidate, catalog in zip(configured_adapters, capability_graph.providers)
            if catalog.provider_id in selected_provider_ids
        ]
        active_adapter = selected_adapters[0] if selected_adapters else configured_adapters[0]
        active_index = configured_adapters.index(active_adapter)
        active_catalog = capability_graph.providers[active_index]
        active_provider_id = active_catalog.provider_id
        if active_catalog is not None:
            state.capability_catalog = active_catalog
            graph = getattr(state, "semantic_goal_graph", None)
            variables = {
                item.id: item.entity_type
                for item in graph.variables
            } if graph is not None else {}
            active_profiles = {
                profile.source_id: profile
                for profile in getattr(active_catalog, "source_profiles", [])
            }
            profile_requirements = [
                {
                    "goal_id": relation.id,
                    "relation": relation.relation,
                    "subject_type": variables.get(relation.subject, "entity"),
                    "object_type": variables.get(relation.object, "entity"),
                    "description": relation.description,
                    "constraint_terms": [
                        qualifier.qualifier
                        for qualifier in graph.qualifiers
                        if qualifier.target_goal_id == relation.id
                    ] + [
                        str(qualifier.expected_value)
                        for qualifier in graph.qualifiers
                        if qualifier.target_goal_id == relation.id
                        and qualifier.expected_value not in (None, "")
                    ] if graph is not None else [],
                }
                for relation in (graph.relations if graph is not None else ())
            ]
            requirements_by_relation = {
                item["relation"]: item for item in profile_requirements
            }
            # The adapter's typed descriptor is already a validated capability
            # contract.  It is the deterministic baseline for planning; the
            # LLM source profiler is an augmentation path for relations that
            # the descriptor cannot cover.  Requiring the profiler before
            # using these contracts made a normal hunt spend its entire LLM
            # budget describing sources, then execute zero queries.
            canonical_descriptor_operations = [
                operation
                for operation in active_catalog.operations
                if not getattr(operation, "legacy_alias", False)
                and operation.query_builder != "runtime.source_profile.v1"
                and operation.guaranteed_relations
            ]
            static_semantic_plan = None
            static_assessments = []
            proof_ready_goal_ids: set[str] = set()
            profiling_goal_ids: set[str] = set()
            if graph is not None:
                if canonical_descriptor_operations:
                    static_semantic_plan = SemanticGoalPlanner(
                        canonical_descriptor_operations,
                        active_provider_id,
                    ).compose(
                        graph,
                        plan_id=f"logical-{graph.id}-descriptor",
                    )
                else:
                    from hunting.contracts.semantic_graph import LogicalPlan
                    static_semantic_plan = LogicalPlan(
                        id=f"logical-{graph.id}-descriptor",
                        goal_graph_id=graph.id,
                        provider_id=active_provider_id,
                        unresolved_goal_ids=[goal.id for goal in graph.relations],
                    )
                static_assessments = assess_semantic_readiness(
                    graph,
                    static_semantic_plan,
                    canonical_descriptor_operations,
                    prior_assessments=tuple(getattr(state, "semantic_route_assessments", ()) or ()),
                )
                proof_ready_goal_ids = {
                    assessment.goal_id
                    for assessment in static_assessments
                    if assessment.readiness.value == "PROOF_CAPABLE"
                }
                required_goal_ids = {goal.id for goal in graph.relations if goal.required}
                profiling_goal_ids = {
                    assessment.goal_id
                    for assessment in static_assessments
                    if assessment.goal_id in required_goal_ids
                    and assessment.readiness.value in {"CAPABILITY_GAP", "RETRIEVAL_CAPABLE"}
                }
                state.semantic_route_assessments = static_assessments
            static_plan_ready = bool(
                graph is not None
                and all(
                    not goal.required or goal.id in proof_ready_goal_ids
                    for goal in graph.relations
                )
            )
            profiling_requirements = [
                requirement for requirement in profile_requirements
                if requirement["goal_id"] in profiling_goal_ids
            ]
            cache_keys: dict[tuple[str, str], str] = {}
            cached_capabilities: dict[tuple[str, str], tuple[Any, ...]] = {}
            cached_proposals: list[Any] = []
            uncached = False
            cache_hit_count = 0
            for profile in active_profiles.values():
                for requirement in profiling_requirements:
                    signature = json.dumps(requirement, sort_keys=True, ensure_ascii=True)
                    cache_key = self.runtime_capability_cache.key(
                        active_provider_id,
                        profile.partition_id,
                        profile.schema_fingerprint,
                        signature,
                    )
                    cache_keys[(profile.source_id, requirement["relation"])] = cache_key
                    cached = self.runtime_capability_cache.get(cache_key)
                    if cached:
                        cached_capabilities[(profile.source_id, requirement["relation"])] = cached
                        cache_hit_count += 1
                        from hunting.contracts.source_profile import SourceCapabilityProposal
                        cached_proposals.extend(
                            SourceCapabilityProposal(
                                source_id=capability.source_id,
                                relation=capability.relation,
                                input_roles=capability.input_roles,
                                output_roles=capability.output_roles,
                                proof_mode=capability.proof_mode,
                                supported_constraints=capability.supported_constraints,
                                searchable_constraints=capability.searchable_constraints,
                                temporal_roles=capability.temporal_roles,
                                action_roles=capability.action_roles,
                                state_roles=capability.state_roles,
                                artifact_identity_roles=capability.artifact_identity_roles,
                                correlation_roles=capability.correlation_roles,
                                relaxable_constraint_keys=capability.relaxable_constraint_keys,
                            )
                            for capability in cached
                            if capability.status == "VALIDATED"
                        )
                    else:
                        uncached = True
            # Retrieve a compact source set per relation before invoking the
            # profiler. The full census remains available for validation, but
            # never enters the compiler or a single all-goals profiler prompt.
            retrieval = CapabilityBatcher().batch(
                active_profiles.values(),
                profiling_requirements,
            )
            source_profile_audit = {
                "status": "STATIC_TYPED_CAPABILITIES" if static_plan_ready else "RETRIEVAL_COMPLETE",
                "readiness": [assessment.to_dict() for assessment in static_assessments],
                "profiling_goal_ids": sorted(profiling_goal_ids),
                "retrieval": list(retrieval.audit),
                "census_profile_discovery": dict(
                    getattr(active_catalog, "details", {}).get("profile_discovery", {})
                    if active_catalog is not None else {}
                ),
                "proposals": [],
                "rejected": [],
                "relation_calls": [],
            }

            # The profiler is invoked once per unresolved relation. Its output
            # is still untrusted until the selected adapter executes a bounded
            # source-side probe.
            accepted_source_proposals = cached_proposals
            if (
                self.source_profiler_caller is not None
                and not self.llm_tracker.is_exhausted
                and active_profiles
                and profiling_requirements
                and uncached
            ):
                profiler = SourceProfiler(self.source_profiler_caller)
                for requirement in profiling_requirements:
                    relation = requirement["relation"]
                    batches = retrieval.batches_by_relation.get(relation, ())
                    if not batches:
                        source_profile_audit["relation_calls"].append({
                            "relation": relation,
                            "status": "NO_PROFILE_BATCHES",
                        })
                        continue
                    for batch_index, compact_profiles in enumerate(batches, start=1):
                        if self.llm_tracker.is_exhausted:
                            source_profile_audit["relation_calls"].append({
                                "relation": relation,
                                "batch_index": batch_index,
                                "batch_count": len(batches),
                                "status": "LLM_BUDGET_EXHAUSTED_BEFORE_BATCH",
                            })
                            continue
                        try:
                            proposals, audit = profiler.propose(
                                compact_profiles,
                                [requirement],
                                validation_profiles=tuple(active_profiles.values()),
                            )
                            accepted_source_proposals.extend(proposals)
                            source_profile_audit["relation_calls"].append({
                                "relation": relation,
                                "batch_index": batch_index,
                                "batch_count": len(batches),
                                "profile_count": len(compact_profiles),
                                **audit,
                            })
                            source_profile_audit["proposals"].extend(
                                proposal.to_dict() for proposal in proposals
                            )
                            source_profile_audit["rejected"].extend(audit.get("rejected", []))
                        except Exception as error:
                            error_text = str(error)
                            budget_error = "budget" in error_text.lower()
                            source_profile_audit["relation_calls"].append({
                                "relation": relation,
                                "batch_index": batch_index,
                                "batch_count": len(batches),
                                "status": (
                                    "LLM_BUDGET_EXHAUSTED_BEFORE_BATCH"
                                    if budget_error else "PROFILING_FAILED"
                                ),
                                "error": error_text,
                            })
                if source_profile_audit["relation_calls"]:
                    partial = any(
                        item.get("status") == "LLM_BUDGET_EXHAUSTED_BEFORE_BATCH"
                        for item in source_profile_audit["relation_calls"]
                    )
                    source_profile_audit["status"] = (
                        "PARTIAL_RELATION_SCOPED_PROFILING"
                        if partial else "RELATION_SCOPED_PROFILING"
                    )
            elif cache_hit_count and not uncached:
                source_profile_audit = {
                    "status": "CACHE_HIT",
                    "proposals": [proposal.to_dict() for proposal in cached_proposals],
                    "rejected": [],
                    "cache_hits": cache_hit_count,
                    "retrieval": list(retrieval.audit),
                }
            elif self.source_profiler_caller is None:
                source_profile_audit["status"] = "NO_LLM_CALLER"
            elif self.llm_tracker.is_exhausted:
                source_profile_audit["status"] = "LLM_BUDGET_EXHAUSTED_BEFORE_PROFILING"
            elif static_plan_ready:
                source_profile_audit["status"] = "STATIC_TYPED_CAPABILITIES"

            validator = SourceMappingValidator()
            probe_executor = BoundedProbeExecutor()
            materialized: list[dict[str, Any]] = []
            runtime_operations = []
            for proposal in accepted_source_proposals:
                profile = active_profiles.get(proposal.source_id)
                requirement = requirements_by_relation.get(proposal.relation)
                if profile is None or requirement is None:
                    materialized.append({
                        "source_id": proposal.source_id,
                        "relation": proposal.relation,
                        "status": "REJECTED",
                        "reasons": ["proposal is not for the selected provider or graph"],
                    })
                    continue
                cached_for_proposal = cached_capabilities.get((proposal.source_id, proposal.relation))
                if cached_for_proposal:
                    for cached_capability in cached_for_proposal:
                        operation = materialize_runtime_operation(
                            proposal,
                            profile,
                            requirement,
                            cached_capability,
                        )
                        if operation is not None:
                            runtime_operations.append(operation)
                            state.runtime_capabilities.append(cached_capability.to_dict())
                    materialized.append({
                        "source_id": proposal.source_id,
                        "relation": proposal.relation,
                        "status": "CACHE_HIT",
                        "probe_query_id": getattr(cached_for_proposal[0], "probe_query_id", None),
                        "probe_succeeded": True,
                        "probe_reasons": [],
                    })
                    continue
                valid, reasons, probe = validator.validate(proposal, [profile])
                if not valid or probe is None:
                    materialized.append({
                        "source_id": proposal.source_id,
                        "relation": proposal.relation,
                        "status": "REJECTED",
                        "reasons": list(reasons),
                    })
                    continue
                probe_id = f"probe-{objective.request_id}-{len(materialized) + 1}"
                probe_run = probe_executor.run(
                    active_adapter,
                    profile,
                    probe,
                    query_id=probe_id,
                    time_window=objective.time_window,
                )
                runtime_capability = validator.materialize(
                    proposal,
                    profile,
                    probe_query_id=probe_id,
                    probe_succeeded=probe_run.succeeded,
                    diagnostics=probe_run.reasons,
                )
                audit_item = {
                    "source_id": proposal.source_id,
                    "relation": proposal.relation,
                    "status": runtime_capability.status,
                    "probe_query_id": probe_id,
                    "probe_succeeded": probe_run.succeeded,
                    "probe_reasons": list(probe_run.reasons),
                }
                materialized.append(audit_item)
                if not probe_run.succeeded:
                    continue
                operation = materialize_runtime_operation(
                    proposal,
                    profile,
                    requirement,
                    runtime_capability,
                )
                if operation is not None:
                    runtime_operations.append(operation)
                    state.runtime_capabilities.append(runtime_capability.to_dict())
                    cache_key = cache_keys.get((proposal.source_id, proposal.relation))
                    if cache_key:
                        self.runtime_capability_cache.put(cache_key, (runtime_capability,))

            if runtime_operations:
                existing_ids = {operation.id for operation in active_catalog.operations}
                active_catalog.operations.extend(
                    operation for operation in runtime_operations
                    if operation.id not in existing_ids
                )
                operations_by_id = {
                    operation.id: operation
                    for operation in [*capability_graph.operations, *runtime_operations]
                }
                capability_graph.operations = list(operations_by_id.values())
            if source_profile_audit:
                source_profile_audit["runtime_capabilities"] = materialized
                source_profile_audit["runtime_operation_ids"] = [
                    operation.id for operation in runtime_operations
                ]
                state.source_profile_audit = source_profile_audit
                state.semantic_analysis.setdefault("source_profile", source_profile_audit)
            if state.semantic_goal_graph is not None:
                # Runtime capabilities supplement, rather than replace, the
                # provider's canonical typed contracts.  Legacy cdb_* aliases
                # remain excluded; they cannot silently route a semantic goal
                # by event-family or sourcetype name.
                planner_operations = [
                    operation
                    for operation in active_catalog.operations
                    if (
                        not getattr(operation, "legacy_alias", False)
                        and (
                            operation.query_builder != "runtime.source_profile.v1"
                            or operation.id in {item.id for item in runtime_operations}
                        )
                    )
                ]
                state.semantic_logical_plan = SemanticGoalPlanner(
                    planner_operations,
                    active_provider_id,
                ).compose(
                    state.semantic_goal_graph,
                    plan_id=f"logical-{state.semantic_goal_graph.id}",
                )
                # New semantic plans are executable directly only when the
                # compiler has emitted the new contract without a legacy
                # ClaimGraph.  Legacy claims remain on their existing
                # verifier path until their proof model is migrated.
        # Bind only against the operations of the adapter that will execute
        # the plan.  CapabilityGraph may contain several providers; selecting
        # an operation from provider B and executing it on adapter A would be
        # an invisible but serious provenance error.
        self.capability_binder.set_capability_graph(
            capability_graph,
            provider_id=active_provider_id,
        )

        # Explicit test doubles/custom adapters may not publish a capability
        # descriptor yet. Keep the strict census gate for auto/configured
        # provider lists, but preserve direct-adapter compatibility so unit
        # tests can exercise execution and evidence logic independently of a
        # provider catalog. This path is never used for provider auto-selection.
        legacy_explicit_adapter = bool(
            explicit_adapter
            and not selected_adapters
            and active_catalog is not None
            and active_catalog.status == "ONLINE"
            and active_catalog.details.get("descriptor_status") == "LEGACY_UNTYPED"
        )
        use_claim_graph = bool(
            claim_graph is not None
            and not legacy_explicit_adapter
            and not bool(getattr(claim_graph, "metadata", {}).get("legacy_fixture_projection"))
        )
        if claim_graph is not None and not selected_adapters and not legacy_explicit_adapter:
            online_providers = [
                provider
                for provider in capability_graph.providers
                if provider.status == "ONLINE"
            ]
            self.controller.set_stopping_decision(
                state,
                StoppingDecision.STOP_UNSUPPORTED_CAPABILITY
                if online_providers
                else StoppingDecision.STOP_UNREACHABLE,
            )
        elif active_catalog is not None and active_catalog.status != "ONLINE":
            self.controller.set_stopping_decision(state, StoppingDecision.STOP_UNREACHABLE)

        if getattr(objective, "semantic_intent", None):
            state.hunt_spec = HuntSpec.from_semantic(
                objective.semantic_intent,
                requirements,
                time_window=objective.time_window,
                answer_spec=objective.answer_spec,
            )
            objective.hunt_spec = state.hunt_spec

        if inv_model:
            val_res = self.inv_validator.validate_investigation_model(inv_model)
            if not val_res.valid:
                self.controller.set_stopping_decision(state, StoppingDecision.STOP_INSUFFICIENT)

        # 2. Apply fast guards after the Provider Census. Capability discovery
        # has already run exactly once for every configured adapter, and its
        # reachable, unreachable and irrelevant outcomes remain in the graph.
        if any(h.status == HypothesisStatus.INSUFFICIENTLY_SPECIFIED for h in state.hypotheses):
            self.controller.set_stopping_decision(state, StoppingDecision.STOP_INSUFFICIENT)

        # 3. Register Scope and Cells
        scope = getattr(active_adapter, "scope", None)
        if scope is None:
            scope = ProviderScope(
                provider_id="cdb_sqlite",
                native_partition={"table": "events"},
                scope_id="cdb_native_scope",
            )

        if step_callback:
            step_callback("PHASE_START", {
                "phase": 1,
                "title": "Environment & Scope Alignment",
                "details": f"Provider: {scope.provider_id} (Scope: {scope.scope_id}), Window: {objective.time_window}",
            })
            step_callback("PHASE_START", {
                "phase": 2,
                "title": "Hypothesis Decomposition & Behavioral Requirements",
                "hypotheses": [h.statement for h in hypotheses],
                "requirements": [r.description for r in requirements],
            })

        if hasattr(active_adapter, "get_versioned_descriptor"):
            desc = active_adapter.get_versioned_descriptor()
            if isinstance(desc, VersionedCapabilityDescriptor):
                self.registry[scope.provider_id] = desc
                if hasattr(self.planner, "registry"):
                    self.planner.registry = self.registry
                if hasattr(self.planner, "validator") and hasattr(self.planner.validator, "descriptors"):
                    self.planner.validator.descriptors = self.registry

        # Wildcard BroadSweep cell
        wc_cell = Cell(
            provider_scope=scope,
            entity=AnyEntity(),
            time_bucket=objective.time_window,
            state=CellState.UNEXPLORED,
        )
        self.controller.add_cell(state, wc_cell)

        if (
            native_semantic_graph
            and state.semantic_logical_plan is not None
            and state.semantic_logical_plan.steps
            and not state.stopping_decision
        ):
            # Execute every runnable prefix of the graph.  An unresolved
            # downstream goal is not a reason to discard a valid upstream
            # identity query; the semantic executor records the boundary and
            # the final verdict remains inconclusive where required.
            self.execute_semantic_plan(
                state,
                active_adapter,
                scope,
                ledger,
                initial_bindings=initial_bindings,
            )

        if (
            native_semantic_graph
            and state.semantic_logical_plan is not None
            and state.semantic_logical_plan.unresolved_goal_ids
            and not state.semantic_logical_plan.steps
            and not state.stopping_decision
        ):
            # An unresolved semantic goal is not permission to scan the whole
            # provider.  Stop with an explicit capability boundary instead of
            # promoting unrelated scope rows to evidence.
            self.controller.set_stopping_decision(
                state,
                StoppingDecision.STOP_UNSUPPORTED_CAPABILITY,
            )

        # A validated ClaimGraph already contains the semantic observation
        # contract.  It must go directly through capability binding and claim
        # verification; the older adaptive discovery loop would re-interpret
        # the request from answer-type heuristics and could add unrelated
        # queries.  Discovery remains the compatibility path for requests
        # compiled without a ClaimGraph.
        if not state.stopping_decision and not use_claim_graph and not native_semantic_graph:
            self._run_semantic_discovery(
                state=state,
                active_adapter=active_adapter,
                scope=scope,
                ledger=ledger,
                step_callback=step_callback,
            )

        descriptor = getattr(active_adapter, "get_versioned_descriptor", lambda: None)()
        if (
            not state.stopping_decision
            and not use_claim_graph
            and state.hunt_spec is not None
            and descriptor is not None
        ):
            schema_fields: set[str] = set()
            descriptor_operations = {
                str(getattr(operation, "id", ""))
                for operation in getattr(descriptor, "operations", ()) or ()
            }
            if "discover_schema" in descriptor_operations:
                schema_query_id = f"qp-schema-{state.turn or 0}"
                schema_plan = QueryPlan(
                    id=schema_query_id,
                    requirement_id="schema-discovery",
                    provider_id=scope.provider_id,
                    scope_id=scope.scope_id,
                    operation_id="discover_schema",
                    parameters={
                        "window": objective.time_window,
                        "limit": 500,
                        "purpose": "runtime schema discovery",
                    },
                    is_targeted=False,
                )
                try:
                    schema_result = active_adapter.execute_query(
                        operation_id="discover_schema",
                        entity=AnyEntity(),
                        window=objective.time_window,
                        limit=500,
                        query_id=schema_query_id,
                    )
                except (TypeError, ValueError):
                    schema_result = None
                if schema_result is not None:
                    self.controller.record_query_execution(state, schema_plan, schema_result)
                    for row in schema_result.rows or []:
                        field_name = row.get("field") or row.get("field_name")
                        if field_name:
                            schema_fields.add(str(field_name))
                        schema_fields.update(
                            str(key) for key, value in row.items()
                            if value not in (None, "", [], {}) and str(key) not in {"_raw", "_time"}
                        )
            # Adaptive query execution loop bounded to at most 2 iterations
            MAX_ADAPTIVE_LOOPS = 2
            attempted_adaptive_operations: list[str] = []

            for adaptive_iter in range(1, MAX_ADAPTIVE_LOOPS + 1):
                observed_fields = {
                    str(field)
                    for observation in ledger.observations
                    for field, value in observation.fields.items()
                    if value not in (None, "", [], {})
                }
                # Schema discovery only tells us which fields the provider can
                # expose.  It is not an observation and must never satisfy an
                # answer contract by itself.  Readiness is based exclusively
                # on non-empty values present in actual ledger observations.
                decision = self.adaptive_planner.choose(
                    state.hunt_spec,
                    descriptor,
                    observed_fields=observed_fields,
                    attempted_operations=attempted_adaptive_operations,
                    iteration=adaptive_iter,
                )
                state.adaptive_decision = {
                    "operation": decision.operation,
                    "operation_id": decision.operation_id,
                    "reason": decision.reason,
                    "required_fields": list(decision.required_fields),
                    "ready_for_answer": decision.ready_for_answer,
                    "search_terms": list(decision.search_terms),
                    "prompt_hash": decision.prompt_hash,
                    "validation_result": decision.validation_result,
                    "iteration": adaptive_iter,
                    # Diagnostic capability metadata; deliberately not used
                    # to mark the answer contract as satisfied.
                    "available_schema_fields": sorted(schema_fields),
                }

                if decision.ready_for_answer:
                    # Sufficient evidence observed for answering the question
                    break

                if not decision.operation_id or decision.operation_id in attempted_adaptive_operations:
                    break

                attempted_adaptive_operations.append(decision.operation_id)

                # Determine target entity and discovered artifacts for adaptive query
                target_host = ""
                discovered_paths: list[str] = []
                discovered_processes: list[str] = []
                for card in state.evidence_cards:
                    for h in card.field_summary.get("host", []) + card.field_summary.get("ComputerName", []):
                        if h and not target_host and "." not in str(h) and " " not in str(h):
                            target_host = str(h).strip()
                    for p in card.field_summary.get("Path", []) + card.field_summary.get("TargetFilename", []) + card.field_summary.get("file_paths", []):
                        p_str = str(p).strip()
                        if p_str and p_str not in discovered_paths:
                            discovered_paths.append(p_str)
                    for pr in card.field_summary.get("Image", []) + card.field_summary.get("process_name", []):
                        pr_str = str(pr).strip()
                        if pr_str and pr_str not in discovered_processes:
                            discovered_processes.append(pr_str)

                if not target_host and state.discovery_anchor_values:
                    target_host = next(
                        (str(value) for value in state.discovery_anchor_values if str(value).strip() and "." not in str(value)),
                        "",
                    )
                if not target_host and state.hunt_spec and state.hunt_spec.anchors:
                    target_host = next(
                        (str(a.value) for a in state.hunt_spec.anchors if getattr(a, "kind", "") in ("host", "endpoint") or ("." not in str(a.value) and " " not in str(a.value))),
                        "",
                    )

                target_entity: EntityRef = Host(name=target_host) if target_host else AnyEntity()

                adaptive_query_id = f"qp-adaptive-{state.turn or 0}-{adaptive_iter}"
                adaptive_plan = self.adaptive_planner.make_plan(
                    decision,
                    provider_id=scope.provider_id,
                    scope_id=scope.scope_id,
                    query_id=adaptive_query_id,
                    requirement_id="adaptive-answer",
                    window=objective.time_window,
                    anchors=[target_host] if target_host else [],
                )
                if adaptive_plan is not None:
                    if step_callback:
                        step_callback("TURN_ACTION", {
                            "turn": state.turn,
                            "action": f"TEST (adaptive capability loop {adaptive_iter})",
                            "operation": decision.operation_id,
                            "target": target_host or "ANY",
                            "requirement": decision.reason,
                        })

                    exec_kwargs: dict[str, Any] = {
                        "operation_id": decision.operation_id,
                        "entity": target_entity,
                        "window": objective.time_window,
                        "limit": 500,
                        "query_id": adaptive_query_id,
                    }
                    # Pass search_terms for all adaptive operations so the adapter
                    # can use them as content filters (e.g., file name, software name).
                    refinement_terms = list(decision.search_terms or ())
                    for pr in discovered_processes:
                        pr_name = pr.replace("/", "\\").split("\\")[-1]
                        if pr_name and pr_name not in refinement_terms:
                            refinement_terms.append(pr_name)
                    for path_val in discovered_paths:
                        file_name = path_val.replace("/", "\\").split("\\")[-1]
                        if file_name and file_name not in refinement_terms:
                            refinement_terms.append(file_name)

                    if refinement_terms:
                        sig = inspect.signature(active_adapter.execute_query)
                        if "search_terms" in sig.parameters:
                            exec_kwargs["search_terms"] = refinement_terms
                        if "search_groups" in sig.parameters and state.hunt_spec:
                            # Preserve semantic OR groups.  Flattening these
                            # terms would turn every alias into an AND clause
                            # and can eliminate valid events.
                            groups = state.hunt_spec.discovery_groups(relaxation_level=2)
                            if target_host:
                                groups = [[target_host], *groups]
                            exec_kwargs["search_groups"] = groups

                    try:
                        adaptive_result = active_adapter.execute_query(**exec_kwargs)
                    except (TypeError, ValueError):
                        adaptive_result = None
                    if adaptive_result is not None:
                        self.controller.record_query_execution(state, adaptive_plan, adaptive_result)
                        adaptive_observations: list[Observation] = []
                        for row in adaptive_result.rows or []:
                            obs_id = f"obs-adaptive-{len(ledger.observations) + 1}"
                            observation = Observation(
                                id=obs_id,
                                provider_scope=scope,
                                cell_id=f"adaptive:{scope.scope_id}",
                                timestamp=str(row.get("timestamp", row.get("_time", ""))),
                                epistemic_type=EpistemicType.OBSERVED,
                                native_type=row.get("native_type"),
                                fields=dict(row),
                                entities=[target_entity] if not isinstance(target_entity, AnyEntity) else [],
                                raw_event=dict(row.get("raw_event") or row),
                                query_id=adaptive_query_id,
                            )
                            ledger.add_observation(observation)
                            self.controller.add_observation(state, observation)
                            adaptive_observations.append(observation)
                        if adaptive_observations:
                            self.group_builder.ingest_delta(adaptive_observations)
                            self.controller.set_evidence_cards(state, self.group_builder.build_cards())
                            self._update_evidence_state(state, ledger)

            # Re-check readiness after loop completion
            observed_fields = {
                str(field)
                for observation in ledger.observations
                for field, value in observation.fields.items()
                if value not in (None, "", [], {})
            }
            # Keep provider schema metadata separate from observed answer
            # values.  A field name in fieldsummary/schema output is a
            # capability signal, not evidence for the requested answer.
            final_decision = self.adaptive_planner.choose(
                state.hunt_spec,
                descriptor,
                observed_fields=observed_fields,
            )
            state.adaptive_decision["ready_for_answer"] = final_decision.ready_for_answer

        # A free-text discovery result is already a valid bounded execution
        # epoch. Do not fall through into the legacy broad-sweep controller,
        # which would invent a file/process path and pivot to unrelated hosts.
        # The final semantic evaluator still runs below over the discovery
        # cards and explains what the observed rows do and do not prove.
        if state.discovery_completed and getattr(objective, "semantic_intent", None):
            self.controller.set_stopping_decision(state, StoppingDecision.STOP_BOUNDED)

        # Discovered or targeted instance cells
        if request.entities:
            for ent in request.entities:
                inst_cell = Cell(
                    provider_scope=scope,
                    entity=ent,
                    time_bucket=objective.time_window,
                    state=CellState.UNEXPLORED,
                )
                self.controller.add_cell(state, inst_cell)

        # 3. Instantiate initial Expectations for targeted entities
        if request.entities:
            for ent in request.entities:
                for hyp in state.hypotheses:
                    for req in state.requirements:
                        is_bound = (
                            req.id in hyp.requirements
                            or hyp.id in req.supports
                            or (not hyp.requirements
                                and hyp.hypothesis_class != "benign_baseline"
                                and req.semantic_intent != "operational_baseline")
                        )
                        if is_bound:
                            try:
                                ev_enum = EvidenceRequirement(req.evidence_type)
                            except ValueError:
                                ev_enum = EvidenceRequirement.PROCESS_ANCESTRY

                            if not is_entity_compatible_with_requirement(ent, ev_enum):
                                continue

                            ent_label = getattr(ent, "name", getattr(ent, "username", getattr(ent, "address", "ent")))
                            exp_id = f"exp-{hyp.id}-{req.id}-{ent_label}"
                            self.controller.add_expectation(
                                state,
                                Expectation(
                                    id=exp_id,
                                    owner_explanation_id=hyp.id,
                                    evidence_requirement=ev_enum,
                                    predicted_observation=req.description,
                                    entity_ref=ent,
                                    field_predicate=req.predicate,
                                    provider_scope_id=scope.scope_id,
                                    time_window=objective.time_window,
                                    falsification_condition=req.falsification_condition,
                                    test_status=TestStatus.UNTESTED,
                                ),
                            )

        # 4. Central Action Loop governed by CanonicalActionController
        MAX_PIVOTS_PER_HUNT = 3
        pivots_executed = 0
        pending_controls: list[tuple[Expectation, QueryResult]] = []
        expand_candidates: list[EntityRef] = []
        pivot_candidates: list[EntityRef] = []
        pivot_reasons: dict[EntityRef, str] = {}
        discovered_entities: set[str] = set()

        # 4. Action Loop:
        # A validated ClaimGraph is the primary execution plan.  Discovery may
        # have produced initial observations already, but it must not bypass
        # claim-edge execution: each unresolved edge still needs its declared
        # capability binding and deterministic verification.  The older
        # relation/model gate remains only for requests compiled without a
        # ClaimGraph.
        subj_is_person = bool(
            state.objective
            and getattr(state.objective, "semantic_intent", None)
            and getattr(state.objective.semantic_intent.subject, "type", "") in ("person", "user")
        )
        has_identity_relations = bool(
            state.case
            and getattr(state.case, "graph", None)
            and any(
                (e.relation_type in (RelationType.OWNS, RelationType.LOGGED_ON_TO, RelationType.ASSIGNED_IP)
                 or str(getattr(e.relation_type, "value", e.relation_type)) in ("owns", "logged_on_to", "assigned_ip"))
                for e in state.case.graph.edges.values()
            )
        )

        claim_graph_active = bool(
            use_claim_graph
            and state.case
            and getattr(state.case, "graph", None)
            and state.case.graph.edges
        )
        legacy_graph_active = bool(
            not use_claim_graph
            and not native_semantic_graph
            and not state.discovery_completed
            and (subj_is_person or has_identity_relations)
            and state.case
            and getattr(state.case, "graph", None)
            and state.case.graph.edges
        )

        if claim_graph_active or legacy_graph_active:
            while not state.stopping_decision:
                self.budget_ledger.record_turn()
                self.controller.advance_turn(state)

                if self.budget_ledger.is_exhausted:
                    self.controller.set_stopping_decision(state, StoppingDecision.STOP_EXHAUSTED_BY_BUDGET)
                    break

                decision = self.action_planner.select_action(
                    state=state,
                    case=state.case,
                    budget_exhausted=self.budget_ledger.is_exhausted,
                )

                if decision.action == InvestigationAction.STOP:
                    self.controller.evaluate_stopping(state)
                    break

                elif decision.action in (InvestigationAction.RESOLVE_ENTITY, InvestigationAction.TEST):
                    edge_id = decision.metadata.get("edge_id")
                    op_name = decision.metadata.get("operation_name")
                    edge = state.case.graph.get_edge(edge_id) if edge_id else None
                    if not edge or not op_name:
                        self.controller.set_stopping_decision(state, StoppingDecision.STOP_INCONCLUSIVE_RELATION_UNPROVEN)
                        break

                    src_node = state.case.graph.get_node(edge.source_id)
                    tgt_node = state.case.graph.get_node(edge.target_id)
                    if not src_node or not tgt_node:
                        self.controller.set_stopping_decision(state, StoppingDecision.STOP_INCONCLUSIVE_RELATION_UNPROVEN)
                        break

                    rel_label = edge.relation_type if isinstance(edge.relation_type, str) else edge.relation_type.value
                    if step_callback:
                        step_callback("TURN_ACTION", {
                            "turn": state.turn,
                            "action": f"{decision.action.value} ({rel_label})",
                            "target": f"{src_node.value} -> {tgt_node.id}",
                            "operation": op_name,
                            "requirement": decision.reason,
                        })

                    plan_id = f"qp-v5-{state.turn}-{op_name}"
                    query_plan = QueryPlan(
                        id=plan_id,
                        requirement_id=edge.id,
                        provider_id=scope.provider_id,
                        scope_id=scope.scope_id,
                        operation_id=op_name,
                        parameters={"window": objective.time_window, "limit": 100},
                    )

                    qr = active_adapter.execute_query(
                        operation_id=op_name,
                        entity=src_node.value,
                        window=objective.time_window,
                        limit=100,
                        query_id=plan_id,
                    )
                    self.controller.record_query_execution(state, query_plan, qr)

                    # Update instance Cell coverage corresponding to source entity
                    if getattr(qr, "executed_ok", True):
                        cell_state = CellState.EXPLORED if getattr(qr, "complete", True) else CellState.PARTIAL
                    else:
                        diag = str(getattr(qr, "diagnostic", "")).lower()
                        if "unreachable" in diag or "timeout" in diag or "connection" in diag:
                            cell_state = CellState.UNREACHABLE
                        else:
                            cell_state = CellState.UNQUERYABLE

                    src_t_str = str(src_node.type.value if hasattr(src_node.type, "value") else src_node.type).lower()
                    if src_t_str in ("person", "user", "account"):
                        src_ent = Account(username=src_node.value)
                    elif src_t_str in ("endpoint", "host"):
                        src_ent = Host(name=src_node.value)
                    elif src_t_str in ("ip", "client_ip", "ipaddress"):
                        src_ent = IPAddress(address=src_node.value)
                    elif src_t_str in ("domain", "fqdn", "website"):
                        src_ent = Domain(name=src_node.value)
                    else:
                        src_ent = Host(name=src_node.value)

                    inst_cell = Cell(
                        provider_scope=scope,
                        entity=src_ent,
                        time_bucket=objective.time_window,
                        state=cell_state,
                    )
                    self.controller.add_cell(state, inst_cell)
                    # Route state transition through Controller (single-authority invariant).
                    for c in state.cells:
                        if not c.is_wildcard and c.entity == src_ent and c.time_bucket == objective.time_window:
                            self.controller.transition_cell_state(state, c, cell_state)

                    # Map execution results back to requirements using the
                    # validated ClaimGraph contract.  Operation names and
                    # natural-language keywords are intentionally not used:
                    # they are provider/scenario details and can silently
                    # attribute evidence to the wrong claim.
                    turn_req_ids = set()
                    if hasattr(edge, "metadata"):
                        turn_req_ids.update(
                            str(value).strip()
                            for value in edge.metadata.get("evidence_requirements", [])
                            if str(value).strip()
                        )
                        requirement_id = str(edge.metadata.get("requirement_id", "")).strip()
                        if requirement_id:
                            turn_req_ids.add(requirement_id)
                    turn_req_ids.add(edge.id)
                    turn_reqs = [req for req in state.requirements if req.id in turn_req_ids]

                    # No positional fallback is allowed here.  An edge that
                    # has no explicit requirement mapping must not confirm an
                    # arbitrary requirement merely because its query returned
                    # rows.  The edge itself remains the authoritative proof
                    # target in that case.

                    for req in turn_reqs:
                        if req.status in (RequirementStatus.DEFINED, RequirementStatus.PLANNED):
                            self.controller.update_requirement_status(state, req, RequirementStatus.EXECUTED)

                    new_obs_list = []
                    for row in qr.rows:
                        obs_id = f"obs-{row.get('id', row.get('event_id', len(ledger.observations) + 1))}"
                        if any(o.id == obs_id for o in ledger.observations):
                            continue
                        obs = Observation(
                            id=obs_id,
                            provider_scope=scope,
                            cell_id=objective.time_window,
                            timestamp=str(row.get("_time", row.get("timestamp", "2017-08-01T00:00:00Z"))),
                            epistemic_type=EpistemicType.OBSERVED,
                            native_type=str(row.get("sourcetype", row.get("native_type", ""))),
                            fields=dict(row),
                            raw_event=dict(row.get("raw_event") or row),
                            query_id=plan_id,
                        )
                        ledger.add_observation(obs)
                        self.controller.add_observation(state, obs)
                        new_obs_list.append(obs)

                    # Assign explicit citations from real attempt observations
                    edge.citations = [obs.id for obs in new_obs_list]

                    # Query completeness is part of the claim acceptance rule;
                    # a row count alone cannot establish it.
                    edge.acceptance_predicate["query_complete"] = bool(
                        getattr(qr, "complete", False)
                    )
                    executed_op = None
                    if hasattr(active_adapter, "get_operation"):
                        try:
                            executed_op = active_adapter.get_operation(op_name)
                        except Exception:
                            executed_op = None
                    elif hasattr(active_adapter, "operations") and isinstance(active_adapter.operations, dict):
                        executed_op = active_adapter.operations.get(op_name)

                    v_res = self.relation_verifier.verify_candidate_edge(
                        edge, src_node, tgt_node, ledger, new_obs_list,
                        query_results=state.query_results,
                        operation=executed_op,
                    )
                    if v_res.verified:
                        if claim_graph is not None:
                            claim_id = str(edge.metadata.get("claim_id", "")).strip()
                            claim = claim_graph.get_claim(claim_id) if claim_id else None
                            if claim is not None:
                                claim.status = ClaimStatus.SUPPORTED
                                for observation_id in v_res.cited_observation_ids:
                                    claim.cite(observation_id)
                        self.relation_verifier.apply_verification_to_graph(v_res, edge, tgt_node, state.case.graph)
                        tgt_type_str = tgt_node.type if isinstance(tgt_node.type, str) else tgt_node.type.value
                        if tgt_type_str in ("account", "user"):
                            state.identity_mapping["account"] = tgt_node.value
                        elif tgt_type_str in ("endpoint", "host"):
                            state.identity_mapping["endpoint"] = tgt_node.value
                        elif tgt_type_str in ("ip", "client_ip"):
                            state.identity_mapping["client_ip"] = tgt_node.value
                            state.identity_resolved = True
                        elif tgt_type_str in ("email_address", "email"):
                            state.identity_mapping["email"] = tgt_node.value
                            state.identity_resolved = True
                        elif tgt_type_str in ("message", "msg"):
                            state.identity_mapping["message_id"] = tgt_node.value
                        elif tgt_type_str in ("recipient", "role"):
                            state.identity_mapping[tgt_type_str] = tgt_node.value

                        # Raw relation-resolution rows are retained in the
                        # ledger, but their broad host-level groups are not
                        # promoted to report evidence.  Only a verified edge
                        # gets a case-specific evidence card below; this keeps
                        # unrelated mail/web/server rows out of the answer.
                        self.group_builder.ingest_delta(new_obs_list)

                        card_id = f"card-{edge.id}"
                        card = EvidenceCard(
                            id=card_id,
                            fingerprint=f"fp-{edge.id}-{tgt_node.value}",
                            summary=f"Verified relation {src_node.value} -[{edge.relation_type}]-> {tgt_node.value}",
                            why_it_matters=f"Proves causal provenance step for {edge.id}",
                            fact_type=str(edge.relation_type.value if hasattr(edge.relation_type, "value") else edge.relation_type),
                            requirements=[edge.id] + [r.id for r in turn_reqs],
                            hypotheses=[h.id for h in state.hypotheses if getattr(h, "hypothesis_class", "") != "benign_baseline"],
                            query_ids=[plan_id],
                            representative_observation_ids=v_res.cited_observation_ids[:5],
                            count=len(v_res.cited_observation_ids),
                            field_summary=v_res.field_matches,
                            confidence="HIGH",
                        )
                        self.controller.add_evidence_card(state, card)
                        # Promote requirement status to CONFIRMED on verified relation.
                        for req in turn_reqs:
                            self.controller.update_requirement_status(state, req, RequirementStatus.CONFIRMED)
                        if step_callback:
                            step_callback("EVIDENCE_CONFIRMED", {
                                "turn": state.turn,
                                "card_id": card.id,
                                "count": card.count,
                                "entity": f"{src_node.value} -> {tgt_node.value}",
                            })
                    else:
                        if claim_graph is not None:
                            claim_id = str(edge.metadata.get("claim_id", "")).strip()
                            claim = claim_graph.get_claim(claim_id) if claim_id else None
                            if claim is not None:
                                claim.status = (
                                    ClaimStatus.UNKNOWN
                                    if getattr(qr, "complete", False)
                                    else ClaimStatus.INCONCLUSIVE
                                )
                        if step_callback:
                            step_callback("EVIDENCE_REFUTED", {
                                "turn": state.turn,
                                "requirement": decision.reason,
                                "entity": str(src_node.value),
                            })
                        tgt_type_str = tgt_node.type if isinstance(tgt_node.type, str) else tgt_node.type.value
                        if tgt_type_str == "role" or "role" in edge.id:
                            # The recipient may be known, but the claim that the
                            # recipient holds an executive role remains unproven.
                            # This is an epistemic blocker, not a successful stop.
                            logger.info(f"Recipient role '{src_node.value}' -> Role remains UNKNOWN (telemetry limitation).")
                            for req in turn_reqs:
                                if req.status in (RequirementStatus.DEFINED, RequirementStatus.PLANNED, RequirementStatus.EXECUTED):
                                    self.controller.update_requirement_status(state, req, RequirementStatus.INCONCLUSIVE)
                            self.controller.set_stopping_decision(state, StoppingDecision.STOP_INCONCLUSIVE_RELATION_UNPROVEN)
                            break
                        elif tgt_type_str in (
                            "software", "software_version", "application", "version",
                            "file", "file_artifact", "process", "process_name",
                        ) or (
                            tgt_type_str == "event"
                            and str(edge.metadata.get("evidence_type", "")).lower()
                            in ("web_request", "web_activity", "web_request_activity")
                        ):
                            # Query completion proves only that this bounded
                            # provider attempt ended. Rows that fail deterministic
                            # verification are a proof gap, and a complete-empty
                            # result is not a semantic refutation without explicit
                            # negative authority plus exhausted alternatives.
                            edge.metadata["verification_diagnostic"] = (
                                v_res.diagnostic or "Relation proof is missing."
                            )
                            for req in turn_reqs:
                                if req.status in (
                                    RequirementStatus.DEFINED,
                                    RequirementStatus.PLANNED,
                                    RequirementStatus.EXECUTED,
                                ):
                                    self.controller.update_requirement_status(
                                        state,
                                        req,
                                        RequirementStatus.INCONCLUSIVE,
                                    )
                            self.controller.set_stopping_decision(
                                state,
                                StoppingDecision.STOP_INCONCLUSIVE_RELATION_UNPROVEN,
                            )
                            break
                        elif tgt_type_str in ("account", "user", "endpoint", "host"):
                            self.controller.set_stopping_decision(state, StoppingDecision.STOP_INCONCLUSIVE_IDENTITY_UNRESOLVED)
                        else:
                            self.controller.set_stopping_decision(state, StoppingDecision.STOP_INCONCLUSIVE_RELATION_UNPROVEN)
                        break

            if not state.stopping_decision:
                self.controller.evaluate_stopping(state)

        while not state.stopping_decision:
            self.budget_ledger.record_turn()
            self.controller.advance_turn(state)

            if self.budget_ledger.is_exhausted:
                self.controller.set_stopping_decision(state, StoppingDecision.STOP_EXHAUSTED_BY_BUDGET)
                break

            untested_exps = [e for e in state.expectations if e.test_status == TestStatus.UNTESTED]
            has_untested = len(untested_exps) > 0
            has_pending_controls = len(pending_controls) > 0

            # If any instance cell is UNEXPLORED and has no active expectations, ensure it is added to expand_candidates
            for c in state.cells:
                if not c.is_wildcard and c.state == CellState.UNEXPLORED:
                    has_active = any(
                        e.entity_ref == c.entity and e.test_status == TestStatus.UNTESTED
                        for e in state.expectations
                    )
                    if not has_active and c.entity not in expand_candidates:
                        expand_candidates.append(c.entity)

            has_expand = len(expand_candidates) > 0
            has_discover = any(c.is_wildcard and c.state == CellState.UNEXPLORED for c in state.cells)
            has_pivot = len(pivot_candidates) > 0 and (pivots_executed < MAX_PIVOTS_PER_HUNT)

            # Detect ambiguous cards (cards not matching any expectation)
            ambiguous_cards = [
                c for c in state.evidence_cards
                if not any(
                    self.evaluator.evaluate_card_against_expectation(c, exp)
                    for exp in state.expectations
                )
            ]
            has_ambiguous = len(ambiguous_cards) > 0 and not self.llm_tracker.is_exhausted and self.evaluator.llm_caller is not None

            action = self.controller.select_action(
                state,
                has_untested_expectations=has_untested,
                has_pending_controls=has_pending_controls,
                has_expand_candidates=has_expand,
                has_discover_candidates=has_discover,
                has_pivot_candidates=has_pivot,
                has_ambiguous_evidence=has_ambiguous,
            )

            if action == HuntAction.STOP:
                self.controller.evaluate_stopping(state)
                break

            elif action == HuntAction.TEST:
                exp = untested_exps[0]
                # Find matching requirement
                req = next((r for r in state.requirements if r.id in exp.id or r.evidence_type == exp.evidence_requirement.value), None)
                if req is None:
                    req = state.requirements[0] if state.requirements else None

                if req is None:
                    self.controller.update_expectation_status(state, exp, TestStatus.UNTESTABLE)
                    continue

                # Plan query first to know if LLM fallback or custom parameters are produced
                plan, diag = self.planner.plan_query(
                    requirement=req,
                    entity=exp.entity_ref,
                    scope=scope,
                    time_window=exp.time_window,
                    query_id=f"qp-{exp.id}",
                )

                if plan is None:
                    self.controller.update_expectation_status(state, exp, TestStatus.UNTESTABLE)
                    self.controller.update_requirement_status(state, req, RequirementStatus.UNSUPPORTED)
                    continue

                # Pass custom query constraint if generated by LLM fallback
                custom_constraints: dict[str, Any] | None = None
                custom_q = plan.parameters.get("query") or plan.parameters.get("custom_field")
                if custom_q or "extracted_fields" in plan.parameters or "field" in plan.parameters:
                    custom_constraints = {k: v for k, v in plan.parameters.items() if k != "window"}
                    if custom_q:
                        custom_constraints["custom_query"] = custom_q

                # Plan logical query and compile native query
                lqp, _ = self.planner.plan_logical_query(
                    requirement=req,
                    entity=exp.entity_ref,
                    scope=scope,
                    time_window=exp.time_window,
                    catalog=state.capability_catalog,
                    query_id=f"lqp-{exp.id}",
                    custom_constraints=custom_constraints,
                )
                nqp = None
                if lqp:
                    self.controller.add_logical_query_plan(state, lqp)
                    nqp, _ = self.planner.compile_native_query(lqp, catalog=state.capability_catalog)
                    if nqp:
                        self.controller.add_native_query_plan(state, nqp)

                ent_label = getattr(exp.entity_ref, "name", getattr(exp.entity_ref, "username", getattr(exp.entity_ref, "address", "ALL")))
                if step_callback:
                    step_callback("TURN_ACTION", {
                        "turn": state.turn,
                        "action": f"TEST ({exp.evidence_requirement.value})",
                        "target": ent_label,
                        "operation": plan.operation_id,
                        "requirement": exp.predicted_observation,
                    })

                exec_kwargs = {
                    "operation_id": plan.operation_id,
                    "entity": exp.entity_ref,
                    "window": plan.parameters.get("window", exp.time_window),
                    "predicate": exp.field_predicate,
                    "limit": plan.parameters.get("limit", 100),
                    "query_id": plan.id,
                }
                if nqp and hasattr(active_adapter, "execute_query"):
                    sig = inspect.signature(active_adapter.execute_query)
                    if "native_query" in sig.parameters:
                        exec_kwargs["native_query"] = nqp.native_query
                    # LLM-produced native syntax is quarantined at the
                    # adapter boundary. Deterministic native compiler output
                    # remains a normal provider operation.
                    if (
                        custom_q
                        and "native_query_candidate" in sig.parameters
                        and scope.provider_id == "splunk"
                    ):
                        index_name = str(
                            getattr(active_adapter, "index", "")
                            or getattr(scope, "native_partition", {}).get("index", "")
                        ).strip()
                        expected_fields = tuple(
                            str(field)
                            for field in getattr(state.capability_catalog, "observable_fields", ())
                        )
                        exec_kwargs["native_query_candidate"] = NativeQueryCandidate(
                            provider=scope.provider_id,
                            query_text=nqp.native_query,
                            source_ids=(index_name,) if index_name else (),
                            time_window=exp.time_window,
                            expected_fields=expected_fields,
                            max_rows=nqp.limit,
                            reason="LLM fallback; no QueryIntent expression available",
                        )

                qr: QueryResult = active_adapter.execute_query(**exec_kwargs)
                if lqp:
                    qr.logical_plan_id = lqp.id
                self.controller.record_query_execution(state, plan, qr)
                self.controller.update_requirement_status(state, req, RequirementStatus.EXECUTED)

                # Update cell coverage
                matching_cell = wc_cell
                if plan.is_targeted and exp.entity_ref and not isinstance(exp.entity_ref, AnyEntity):
                    for c in state.cells:
                        if not c.is_wildcard and c.entity == exp.entity_ref:
                            matching_cell = c
                            break

                if qr.executed_ok and qr.complete:
                    self.controller.transition_cell_state(state, matching_cell, CellState.EXPLORED)
                elif qr.executed_ok and not qr.complete:
                    self.controller.transition_cell_state(state, matching_cell, CellState.PARTIAL)
                elif not qr.executed_ok:
                    self.controller.transition_cell_state(state, matching_cell, CellState.UNQUERYABLE)

                # Mint observations into ledger
                new_observations: list[Observation] = []
                if qr.rows:
                    for row in qr.rows:
                        ent_list = []
                        if "host" in row and row["host"]:
                            ent_list.append(Host(name=str(row["host"])))
                        if "user" in row and row["user"]:
                            ent_list.append(Account(username=str(row["user"])))
                        if "domain" in row and row["domain"]:
                            ent_list.append(Domain(name=str(row["domain"])))
                        if "site" in row and row["site"]:
                            ent_list.append(Domain(name=str(row["site"])))
                        if "destination_ip" in row and row["destination_ip"]:
                            ent_list.append(IPAddress(address=str(row["destination_ip"])))
                        if "s_ip" in row and row["s_ip"]:
                            ent_list.append(IPAddress(address=str(row["s_ip"])))

                        obs_id = f"obs-{row.get('id', row.get('event_id', len(ledger.observations) + 1))}"
                        if any(o.id == obs_id for o in ledger.observations):
                            continue

                        obs = Observation(
                            id=obs_id,
                            provider_scope=scope,
                            cell_id=matching_cell.time_bucket,
                            timestamp=str(row.get("timestamp", "2026-02-01T00:00:00Z")),
                            epistemic_type=EpistemicType.OBSERVED,
                            native_type=row.get("native_type"),
                            fields=dict(row),
                            entities=ent_list,
                            raw_event=dict(row.get("raw_event") or row),
                            query_id=plan.id,
                        )
                        ledger.add_observation(obs)
                        self.controller.add_observation(state, obs)
                        new_observations.append(obs)

                    self._evaluate_identity_linkage(state, qr.rows, ledger=ledger, query_id=plan.id)

                    # Incremental delta grouping for this targeted expansion.
                    delta_cards = self.group_builder.ingest_delta(new_observations)
                    self.controller.set_evidence_cards(state, self.group_builder.build_cards())
                    # Only cards minted from this query may be associated with
                    # its requirement.  Mutating every historical card here
                    # makes an unrelated web/email row appear to satisfy a
                    # file/process requirement.
                    for c in delta_cards:
                        if exp.owner_explanation_id not in c.hypotheses:
                            c.hypotheses.append(exp.owner_explanation_id)
                        if req.id not in c.requirements:
                            c.requirements.append(req.id)
                        if plan.id not in c.query_ids:
                            c.query_ids.append(plan.id)
                        if hasattr(ledger, "store"):
                            ledger.store.link_card(c.id, c.representative_observation_ids)
                        advisory = self.evaluator.evaluate_evidence_advisory(c, state.hypotheses, state.expectations)
                        self.controller.add_evidence_assessment(state, advisory)

                    # Discover hosts serving this domain / endpoint
                    candidate_ips: set[str] = set()
                    for row in qr.rows:
                        h_val = row.get("host")
                        if h_val:
                            h_str = str(h_val).strip()
                            if h_str and h_str not in discovered_entities:
                                discovered_entities.add(h_str)
                                new_host = Host(name=h_str)
                                if new_host not in expand_candidates and not any(
                                    not c.is_wildcard and c.entity == new_host for c in state.cells
                                ):
                                    expand_candidates.append(new_host)
                                    self.controller.add_cell(
                                        state,
                                        Cell(
                                            provider_scope=scope,
                                            entity=new_host,
                                            time_bucket=objective.time_window,
                                            state=CellState.UNEXPLORED,
                                        ),
                                    )
                        for ip_key in ("destination_ip", "server_ip", "s_ip", "dest_ip"):
                            ip_val = row.get(ip_key)
                            if ip_val:
                                ip_s = str(ip_val).strip()
                                if ip_s.startswith("192.168.") or ip_s.startswith("10.") or ip_s.startswith("172."):
                                    candidate_ips.add(ip_s)

                    if hasattr(active_adapter, "resolve_ip_to_host") and candidate_ips:
                        for ip_s in candidate_ips:
                            resolved_h = active_adapter.resolve_ip_to_host(ip_s)
                            if resolved_h and resolved_h not in discovered_entities:
                                discovered_entities.add(resolved_h)
                                new_host = Host(name=resolved_h)
                                if new_host not in expand_candidates and not any(
                                    not c.is_wildcard and c.entity == new_host for c in state.cells
                                ):
                                    expand_candidates.append(new_host)
                                    self.controller.add_cell(
                                        state,
                                        Cell(
                                            provider_scope=scope,
                                            entity=new_host,
                                            time_bucket=objective.time_window,
                                            state=CellState.UNEXPLORED,
                                        ),
                                    )

                    # Evaluate whether any delta or existing card satisfies this expectation
                    matched_card = next(
                        (c for c in delta_cards if self.evaluator.evaluate_card_against_expectation(c, exp)),
                        None,
                    )
                    if matched_card is not None:
                        self.controller.update_expectation_status(state, exp, TestStatus.CONFIRMED)
                        self.controller.update_requirement_status(state, req, RequirementStatus.CONFIRMED)
                        if exp.entity_ref not in expand_candidates and not isinstance(exp.entity_ref, Domain):
                            expand_candidates.append(exp.entity_ref)

                        # Extract pivot candidates strictly from confirmed expectations
                        if len(pivot_candidates) < MAX_PIVOTS_PER_HUNT:
                            target_domains = {
                                e.name.lower()
                                for e in state.objective.entities
                                if isinstance(e, Domain)
                            }
                            for row in qr.rows:
                                if len(pivot_candidates) >= MAX_PIVOTS_PER_HUNT:
                                    break
                                u_val = row.get("user")
                                if u_val:
                                    u_str = str(u_val).strip()
                                    if u_str and u_str.lower() not in SYSTEM_USERS and not u_str.endswith("$"):
                                        u_ent = Account(username=u_str)
                                        if (
                                            u_ent not in pivot_candidates
                                            and not any(not c.is_wildcard and c.entity == u_ent for c in state.cells)
                                        ):
                                            pivot_candidates.append(u_ent)
                                            pivot_reasons[u_ent] = f"User '{u_str}' running confirmed process in {exp.id}"

                                for ip_key in ("destination_ip", "dest_ip", "s_ip", "remote_ip", "server_ip"):
                                    if len(pivot_candidates) >= MAX_PIVOTS_PER_HUNT:
                                        break
                                    ip_val = row.get(ip_key)
                                    if ip_val:
                                        ip_s = str(ip_val).strip()
                                        if (
                                            ip_s
                                            and not ip_s.startswith("127.")
                                            and not ip_s.startswith("0.")
                                            and not ip_s.startswith("224.")
                                            and ip_s != "255.255.255.255"
                                        ):
                                            ip_ent = IPAddress(address=ip_s)
                                            if (
                                                ip_ent not in pivot_candidates
                                                and not any(not c.is_wildcard and c.entity == ip_ent for c in state.cells)
                                            ):
                                                pivot_candidates.append(ip_ent)
                                                pivot_reasons[ip_ent] = f"Contacted IP '{ip_s}' during confirmed activity in {exp.id}"

                                for dom_key in ("domain", "query", "site", "cs_host"):
                                    if len(pivot_candidates) >= MAX_PIVOTS_PER_HUNT:
                                        break
                                    d_val = row.get(dom_key)
                                    if d_val:
                                        d_str = str(d_val).strip().lower()
                                        if (
                                            d_str
                                            and "." in d_str
                                            and not d_str.endswith(".local")
                                            and not d_str.endswith(".internal")
                                            and not d_str.endswith(".arpa")
                                            and d_str != "localhost"
                                            and not any(td in d_str for td in target_domains)
                                        ):
                                            d_ent = Domain(name=d_str)
                                            if (
                                                d_ent not in pivot_candidates
                                                and not any(not c.is_wildcard and c.entity == d_ent for c in state.cells)
                                            ):
                                                pivot_candidates.append(d_ent)
                                                pivot_reasons[d_ent] = f"External domain '{d_str}' referenced in confirmed activity in {exp.id}"

                        if step_callback:
                            cmd_sample = matched_card.field_summary.get("cmdlines", ["N/A"])[0] if matched_card.field_summary else "N/A"
                            parent_sample = matched_card.field_summary.get("parent_images", ["N/A"])[0] if matched_card.field_summary else "N/A"
                            step_callback("EVIDENCE_CONFIRMED", {
                                "turn": state.turn,
                                "card_id": matched_card.id,
                                "count": matched_card.count,
                                "parent": parent_sample,
                                "cmdline": cmd_sample,
                                "entity": ent_label,
                            })
                    else:
                        # Rows returned and sensor active, but none satisfied the expectation predicate!
                        if qr.complete:
                            self.controller.update_expectation_status(state, exp, TestStatus.REFUTED)
                        else:
                            self.controller.update_expectation_status(state, exp, TestStatus.INCONCLUSIVE)
                        if step_callback and qr.complete:
                            step_callback("EVIDENCE_REFUTED", {
                                "turn": state.turn,
                                "requirement": exp.predicted_observation,
                                "entity": ent_label,
                            })
                else:
                    # 0 rows returned
                    if qr.complete and hasattr(active_adapter, "control_health") and hasattr(active_adapter, "control_any_record"):
                        self.controller.update_expectation_status(state, exp, TestStatus.INCONCLUSIVE)
                        pending_controls.append((exp, qr))
                    else:
                        # 0 rows without negative license verification is a telemetry gap: INCONCLUSIVE
                        self.controller.update_expectation_status(state, exp, TestStatus.INCONCLUSIVE)
                        if step_callback:
                            step_callback("EVIDENCE_INCONCLUSIVE", {
                                "turn": state.turn,
                                "requirement": exp.predicted_observation,
                                "entity": ent_label,
                            })

                # Update hypothesis statuses based on updated expectations
                self.reasoner.evaluate_hypothesis_network(
                    hypotheses=state.hypotheses,
                    expectations=state.expectations,
                    evidence_cards=state.evidence_cards,
                )

            elif action == HuntAction.CONTROL:
                exp, qr = pending_controls.pop(0)
                _, end_dt = validate_time_window_format(exp.time_window)
                as_of = max(datetime.now(timezone.utc), end_dt + timedelta(hours=1))
                ctrl_health = active_adapter.control_health(exp.time_window, as_of=as_of)
                try:
                    ctrl_any = active_adapter.control_any_record(
                        exp.time_window,
                        entity=exp.entity_ref,
                        requirement=exp.evidence_requirement,
                    )
                except TypeError:
                    ctrl_any = active_adapter.control_any_record(exp.time_window)
                ctrl_pred = active_adapter.control_observability(exp.evidence_requirement, exp.field_predicate)
                ledger.record_control_result(ctrl_health)
                ledger.record_control_result(ctrl_any)
                ledger.record_control_result(ctrl_pred)

                if license_valid_negative(qr, ctrl_health, ctrl_any, ctrl_pred):
                    self.controller.update_expectation_status(state, exp, TestStatus.REFUTED)
                else:
                    self.controller.update_expectation_status(state, exp, TestStatus.INCONCLUSIVE)

                self.reasoner.evaluate_hypothesis_network(
                    hypotheses=state.hypotheses,
                    expectations=state.expectations,
                    evidence_cards=state.evidence_cards,
                )

            elif action == HuntAction.EXPAND:
                ent = expand_candidates.pop(0)
                existing_descs = {
                    e.predicted_observation for e in state.expectations if e.entity_ref == ent
                }
                for req in state.requirements:
                    if req.description not in existing_descs:
                        try:
                            ev_enum = EvidenceRequirement(req.evidence_type)
                        except ValueError:
                            ev_enum = EvidenceRequirement.PROCESS_ANCESTRY
                        if not is_entity_compatible_with_requirement(ent, ev_enum):
                            continue
                        owner_id = req.supports[0] if req.supports else next(
                            (h.id for h in state.hypotheses if req.id in h.requirements),
                            state.hypotheses[0].id,
                        )
                        ent_label = getattr(ent, "name", getattr(ent, "username", getattr(ent, "address", "ent")))
                        self.controller.add_expectation(
                            state,
                            Expectation(
                                id=f"exp-expand-{req.id}-{ent_label}",
                                owner_explanation_id=owner_id,
                                evidence_requirement=ev_enum,
                                predicted_observation=req.description,
                                entity_ref=ent,
                                field_predicate=req.predicate,
                                provider_scope_id=scope.scope_id,
                                time_window=objective.time_window,
                                falsification_condition=req.falsification_condition,
                                test_status=TestStatus.UNTESTED,
                            ),
                        )

            elif action == HuntAction.DISCOVER:
                # Broad sweep on unexplored wildcard cell
                unexplored_wc = next(c for c in state.cells if c.is_wildcard and c.state == CellState.UNEXPLORED)
                self.budget_ledger.record_scan_cell()

                # Focus the broad sweep on the hypothesis's primary behavioral requirement
                primary_req = next(
                    (r for r in state.requirements if r.semantic_intent != "operational_baseline"),
                    state.requirements[0] if state.requirements else None,
                )
                sweep_op = "cdb_scope_scan"
                sweep_pred = None
                sweep_lqp = None
                sweep_nqp = None
                if primary_req:
                    sweep_lqp, _ = self.planner.plan_logical_query(
                        requirement=primary_req,
                        entity=AnyEntity(),
                        scope=scope,
                        time_window=objective.time_window,
                        catalog=state.capability_catalog,
                        query_id=f"lqp-sweep-{state.turn}",
                    )
                    if sweep_lqp:
                        self.controller.add_logical_query_plan(state, sweep_lqp)
                        sweep_nqp, _ = self.planner.compile_native_query(sweep_lqp, catalog=state.capability_catalog)
                        if sweep_nqp:
                            self.controller.add_native_query_plan(state, sweep_nqp)

                    sweep_plan_cand, _ = self.planner.plan_query(
                        requirement=primary_req,
                        entity=AnyEntity(),
                        scope=scope,
                        time_window=objective.time_window,
                        query_id=f"qp-sweep-{state.turn}",
                    )
                    if sweep_plan_cand:
                        sweep_op = sweep_plan_cand.operation_id
                        sweep_pred = primary_req.predicate

                sweep_plan = QueryPlan(
                    id=f"qp-sweep-{state.turn}",
                    requirement_id=primary_req.id if primary_req else "req-broad-sweep",
                    provider_id=scope.provider_id,
                    scope_id=scope.scope_id,
                    operation_id=sweep_op,
                    parameters={"window": objective.time_window, "limit": 100},
                )

                if step_callback:
                    step_callback("TURN_ACTION", {
                        "turn": state.turn,
                        "action": "DISCOVER",
                        "operation": sweep_op,
                        "predicate": str(sweep_pred) if sweep_pred else "Scope Baseline",
                        "target": "POPULATION (Wildcard ANY)",
                    })

                exec_kwargs = {
                    "operation_id": sweep_plan.operation_id,
                    "entity": AnyEntity(),
                    "window": objective.time_window,
                    "predicate": sweep_pred,
                    "limit": 100,
                    "query_id": sweep_plan.id,
                }
                if sweep_nqp and hasattr(active_adapter, "execute_query"):
                    sig = inspect.signature(active_adapter.execute_query)
                    if "native_query" in sig.parameters:
                        exec_kwargs["native_query"] = sweep_nqp.native_query

                qr = active_adapter.execute_query(**exec_kwargs)
                if not qr.rows and sweep_op != "cdb_scope_scan":
                    qr = active_adapter.execute_query(
                        operation_id="cdb_scope_scan",
                        entity=AnyEntity(),
                        window=objective.time_window,
                        limit=100,
                        query_id=sweep_plan.id,
                    )
                if sweep_lqp:
                    qr.logical_plan_id = sweep_lqp.id
                self.controller.record_query_execution(state, sweep_plan, qr)
                if primary_req:
                    self.controller.update_requirement_status(state, primary_req, RequirementStatus.EXECUTED)

                # Post-execution cell state transition
                if qr.executed_ok and qr.complete:
                    self.controller.transition_cell_state(state, unexplored_wc, CellState.EXPLORED)
                elif qr.executed_ok and not qr.complete:
                    self.controller.transition_cell_state(state, unexplored_wc, CellState.PARTIAL)
                elif not qr.executed_ok:
                    self.controller.transition_cell_state(state, unexplored_wc, CellState.UNQUERYABLE)

                new_observations = []
                if qr.rows:
                    host_counts: dict[str, int] = {}
                    discovered_ips: set[str] = set()
                    for row in qr.rows:
                        if "host" in row and row["host"]:
                            h_str = str(row["host"])
                            host_counts[h_str] = host_counts.get(h_str, 0) + 1

                        for ip_key in ("destination_ip", "server_ip", "s_ip", "dest_ip"):
                            ip_val = row.get(ip_key)
                            if ip_val:
                                ip_s = str(ip_val).strip()
                                if ip_s.startswith("192.168.") or ip_s.startswith("10.") or ip_s.startswith("172."):
                                    discovered_ips.add(ip_s)

                        ent_list = []
                        if "host" in row and row["host"]:
                            h = Host(name=str(row["host"]))
                            ent_list.append(h)
                        if "user" in row and row["user"]:
                            ent_list.append(Account(username=str(row["user"])))
                        if "domain" in row and row["domain"]:
                            ent_list.append(Domain(name=str(row["domain"])))
                        if "site" in row and row["site"]:
                            ent_list.append(Domain(name=str(row["site"])))
                        if "destination_ip" in row and row["destination_ip"]:
                            ent_list.append(IPAddress(address=str(row["destination_ip"])))
                        if "s_ip" in row and row["s_ip"]:
                            ent_list.append(IPAddress(address=str(row["s_ip"])))

                        obs_id = f"obs-sweep-{row.get('id', row.get('event_id', len(ledger.observations) + 1))}"
                        if any(o.id == obs_id for o in ledger.observations):
                            continue

                        obs = Observation(
                            id=obs_id,
                            provider_scope=scope,
                            cell_id=objective.time_window,
                            timestamp=str(row.get("timestamp", "2026-02-01T00:00:00Z")),
                            epistemic_type=EpistemicType.OBSERVED,
                            native_type=row.get("native_type"),
                            fields=dict(row),
                            entities=ent_list,
                            raw_event=dict(row.get("raw_event") or row),
                            query_id=sweep_plan.id,
                        )
                        ledger.add_observation(obs)
                        self.controller.add_observation(state, obs)
                        new_observations.append(obs)

                    self._evaluate_identity_linkage(state, qr.rows, ledger=ledger, query_id=sweep_plan.id)

                    # Resolve internal server IPs to actual target hosts
                    if hasattr(active_adapter, "resolve_ip_to_host") and discovered_ips:
                        for ip_s in discovered_ips:
                            resolved_h = active_adapter.resolve_ip_to_host(ip_s)
                            if resolved_h:
                                host_counts[resolved_h] = host_counts.get(resolved_h, 0) + 100

                    # Wildcard sweep rows are discovery/control telemetry.
                    # They remain in the ledger for pivots, but cannot become
                    # evidence for the primary requirement without a targeted
                    # query and a verifier-backed relation.

                    # Extract pivot candidates from sweep results
                    for row in qr.rows:
                        u_val = row.get("user")
                        if u_val:
                            u_str = str(u_val).strip()
                            if u_str and u_str.lower() not in SYSTEM_USERS and not u_str.endswith("$"):
                                u_ent = Account(username=u_str)
                                if (
                                    u_ent not in pivot_candidates
                                    and not any(not c.is_wildcard and c.entity == u_ent for c in state.cells)
                                ):
                                    pivot_candidates.append(u_ent)

                        for ip_key in ("destination_ip", "dest_ip", "s_ip", "remote_ip", "server_ip"):
                            ip_val = row.get(ip_key)
                            if ip_val:
                                ip_s = str(ip_val).strip()
                                if ip_s and not ip_s.startswith("127.") and not ip_s.startswith("0.") and ip_s != "255.255.255.255":
                                    ip_ent = IPAddress(address=ip_s)
                                    if (
                                        ip_ent not in pivot_candidates
                                        and not any(not c.is_wildcard and c.entity == ip_ent for c in state.cells)
                                    ):
                                        pivot_candidates.append(ip_ent)

                        for dom_key in ("domain", "query", "site", "cs_host"):
                            d_val = row.get(dom_key)
                            if d_val:
                                d_str = str(d_val).strip().lower()
                                if d_str and "." in d_str and not d_str.endswith(".local") and not d_str.endswith(".internal"):
                                    d_ent = Domain(name=d_str)
                                    if (
                                        d_ent not in pivot_candidates
                                        and not any(not c.is_wildcard and c.entity == d_ent for c in state.cells)
                                    ):
                                        pivot_candidates.append(d_ent)

                    # Record top candidate hosts discovered by the population sweep
                    sorted_hosts = sorted(host_counts.keys(), key=lambda h: host_counts[h], reverse=True)[:5]
                    for h_str in sorted_hosts:
                        discovered_entities.add(h_str)

                    if step_callback:
                        step_callback("DISCOVERY_HIT", {
                            "turn": state.turn,
                            "discovered_hosts": sorted_hosts,
                            "event_count": len(new_observations),
                        })

                    if analyst_confirm_callback and sorted_hosts:
                        proceed = analyst_confirm_callback("CONFIRM_DISCOVERED_TARGETS", {
                            "hosts": sorted_hosts,
                            "count": len(new_observations),
                        })
                        if not proceed:
                            raise PermissionError(f"Analyst declined investigation into discovered targets: {sorted_hosts}")

                    # Promote discovered entities to instance cells and concrete Expectations
                    for h_name in discovered_entities:
                        ent = Host(name=h_name)
                        if not any(not c.is_wildcard and c.entity == ent for c in state.cells):
                            self.controller.add_cell(
                                state,
                                Cell(provider_scope=scope, entity=ent, time_bucket=objective.time_window, state=CellState.UNEXPLORED),
                            )
                        for hyp in state.hypotheses:
                            for req in state.requirements:
                                is_bound = (
                                    req.id in hyp.requirements
                                    or hyp.id in req.supports
                                    or (not hyp.requirements
                                        and hyp.hypothesis_class != "benign_baseline"
                                        and req.semantic_intent != "operational_baseline")
                                )
                                if is_bound:
                                    try:
                                        ev_enum = EvidenceRequirement(req.evidence_type)
                                    except ValueError:
                                        ev_enum = EvidenceRequirement.PROCESS_ANCESTRY
                                    if not is_entity_compatible_with_requirement(ent, ev_enum):
                                        continue
                                    exp_id = f"exp-{hyp.id}-{req.id}-{h_name}"
                                    self.controller.add_expectation(
                                        state,
                                        Expectation(
                                            id=exp_id,
                                            owner_explanation_id=hyp.id,
                                            evidence_requirement=ev_enum,
                                            predicted_observation=req.description,
                                            entity_ref=ent,
                                            field_predicate=req.predicate,
                                            provider_scope_id=scope.scope_id,
                                            time_window=objective.time_window,
                                            falsification_condition=req.falsification_condition,
                                            test_status=TestStatus.UNTESTED,
                                        ),
                                    )

            elif action == HuntAction.PIVOT:
                pivot_ent = pivot_candidates.pop(0)
                pivots_executed += 1
                ent_name = getattr(pivot_ent, "name", getattr(pivot_ent, "username", getattr(pivot_ent, "address", str(pivot_ent))))
                reason = pivot_reasons.get(pivot_ent, f"Investigate pivoted entity {ent_name}")
                if step_callback:
                    step_callback("TURN_ACTION", {
                        "turn": state.turn,
                        "action": f"PIVOT ({type(pivot_ent).__name__})",
                        "target": ent_name,
                        "operation": "pivot_expansion",
                        "requirement": f"Investigate pivoted entity {ent_name}",
                        "reason": reason,
                    })
                # Add cell for pivoted entity
                self.controller.add_cell(
                    state,
                    Cell(
                        provider_scope=scope,
                        entity=pivot_ent,
                        time_bucket=objective.time_window,
                        state=CellState.UNEXPLORED,
                    ),
                )
                # Mint expectations for this pivoted entity
                for hyp in state.hypotheses:
                    for req in state.requirements:
                        is_bound = (
                            req.id in hyp.requirements
                            or hyp.id in req.supports
                            or (not hyp.requirements
                                and hyp.hypothesis_class != "benign_baseline"
                                and req.semantic_intent != "operational_baseline")
                        )
                        if is_bound:
                            try:
                                ev_enum = EvidenceRequirement(req.evidence_type)
                            except ValueError:
                                ev_enum = EvidenceRequirement.PROCESS_ANCESTRY
                            if not is_entity_compatible_with_requirement(pivot_ent, ev_enum):
                                continue
                            exp_id = f"exp-pivot-{hyp.id}-{req.id}-{ent_name}"
                            self.controller.add_expectation(
                                state,
                                Expectation(
                                    id=exp_id,
                                    owner_explanation_id=hyp.id,
                                    evidence_requirement=ev_enum,
                                    predicted_observation=req.description,
                                    entity_ref=pivot_ent,
                                    field_predicate=req.predicate,
                                    provider_scope_id=scope.scope_id,
                                    time_window=objective.time_window,
                                    falsification_condition=req.falsification_condition,
                                    test_status=TestStatus.UNTESTED,
                                ),
                            )

            elif action == HuntAction.REFINE:
                calls_before = len(self.llm_tracker.calls)
                ident_req = bool(objective.semantic_intent and getattr(objective.semantic_intent.subject, "type", "") == "person")
                q_complete = all(getattr(qr, "complete", True) for qr in state.query_results) if state.query_results else True
                analysis = self.evaluator.analyze_batch(
                    ambiguous_cards,
                    state.hypotheses,
                    question=objective.statement or request.content,
                    answer_spec=objective.answer_spec,
                    identity_resolved=state.identity_resolved,
                    queries_complete=q_complete,
                    identity_required=ident_req,
                )
                self._record_semantic_analysis(state, analysis)
                compat_map = analysis.get("compatibility", {})
                if self.evaluator.llm_calls_made and len(self.llm_tracker.calls) == calls_before:
                    self.budget_ledger.record_llm_call()
                if len(self.llm_tracker.calls) == calls_before and not self.llm_tracker.is_exhausted:
                    self.llm_tracker.record_call(
                        component="evaluator_refine",
                        prompt=f"Cards: {len(ambiguous_cards)}, Hypotheses: {len(state.hypotheses)}",
                        response=str(analysis),
                    )
                valid = all(
                    all(any(h.id == hid for h in state.hypotheses) for hid in hids)
                    for hids in compat_map.values()
                )
                self.controller.apply_advisory_llm_proposal(
                    state,
                    {"action": "REFINE", "compatibility": compat_map},
                    m3_validator_passed=valid,
                )

        # 5. Conclude stopping decision if not set
        if not state.stopping_decision:
            self.controller.evaluate_stopping(state)

        # Give the semantic analyst one bounded batch even when all cards had
        # deterministic expectation matches. This is where the agent explains
        # evidence and answers the original question; it does not alter state.
        if (
            state.evidence_cards
            and self.evaluator.llm_caller is not None
            and self.evaluator.llm_calls_made == 0
            and not self.llm_tracker.is_exhausted
        ):
            ident_req = bool(objective.semantic_intent and getattr(objective.semantic_intent.subject, "type", "") == "person")
            q_complete = all(getattr(qr, "complete", True) for qr in state.query_results) if state.query_results else True
            subgraph = None
            if state.case and getattr(state.case, "graph", None):
                graph = state.case.graph
                subgraph = EvidenceSubgraph(
                    claim_id=state.hypotheses[0].id if state.hypotheses else "claim-1",
                    nodes=[n for n in graph.nodes.values() if n.status == NodeStatus.KNOWN],
                    edges=[e for e in graph.edges.values() if getattr(e, "status", None) == RelationStatus.VERIFIED],
                    proofs=list(graph.proofs.values()),
                    cited_observation_ids=[
                        cid for p in graph.proofs.values() for cid in p.citations
                    ],
                )
            analysis = self.evaluator.analyze_batch(
                state.evidence_cards,
                state.hypotheses,
                question=objective.statement or request.content,
                answer_spec=objective.answer_spec,
                identity_resolved=state.identity_resolved,
                queries_complete=q_complete,
                identity_required=ident_req,
                subgraph=subgraph,
                max_cards=20,
            )
            self._record_semantic_analysis(state, analysis)
            self.budget_ledger.record_llm_call()

        if step_callback:
            step_callback("HUNT_CONCLUDED", {
                "decision": state.stopping_decision.value,
                "supported": [h.statement for h in state.hypotheses if h.status == HypothesisStatus.SUPPORTED],
                "cards_count": len(state.evidence_cards),
            })

        if analyst_confirm_callback:
            confirmed = analyst_confirm_callback("AUTHORIZE_FINAL_REPORT", {
                "decision": state.stopping_decision.value,
                "supported": [h.statement for h in state.hypotheses if h.status == HypothesisStatus.SUPPORTED],
                "cards_count": len(state.evidence_cards),
            })
            if not confirmed:
                raise PermissionError(f"Mandatory analyst confirmation declined for final hunt disposition {state.stopping_decision.value}")

        # 6. Build Final Account & Render Markdown Report
        if hasattr(self.compiler, "llm_calls_made") and self.compiler.llm_calls_made > 0:
            while self.llm_tracker.call_count < self.compiler.llm_calls_made:
                self.llm_tracker.record_call(
                    component="compiler",
                    prompt="compiler_unstructured_request",
                    response="compiler_unstructured_response",
                )
        state.llm_usage = self.llm_tracker.to_dict()
        self.budget_ledger.llm_calls = self.llm_tracker.call_count
        self._update_evidence_state(state, ledger)

        # Preserve compilation observability even when planning stops before
        # the semantic executor (for example, invalid graph/capability or
        # provider failure).  Otherwise the report falsely looks as if the
        # LLM was never called.
        if getattr(state, "compiler_trace", None):
            final_analysis = dict(getattr(state, "semantic_analysis", {}) or {})
            final_analysis.setdefault("compiler_trace", dict(state.compiler_trace))
            self.controller.set_semantic_analysis(state, final_analysis)

        account = build_final_hunt_account(state, ledger=ledger)
        # The CLI report is intentionally concise. Full observations, raw
        # references and diagnostics remain available in persisted artifacts.
        report = render_analyst_report(account)

        # Persist isolated hunt artifacts into artifacts/<hunt_id>/
        hunt_id = account.request_id or f"hunt-{int(datetime.now(timezone.utc).timestamp())}"
        persist_hunt_artifacts(Path("artifacts") / hunt_id, request, state, ledger, account, report)

        return HuntExecutionResult(
            account=account,
            report=report,
            state=state,
            ledger=ledger,
            budget=self.budget_ledger,
        )


def persist_hunt_artifacts(
    artifact_dir: Path,
    request: HuntRequest,
    state: HuntState,
    ledger: ObservationLedger,
    account: FinalHuntAccount,
    report: str,
) -> None:
    """Persist complete hunt execution artifacts into isolated directory with strict UTF-8."""
    artifact_dir.mkdir(parents=True, exist_ok=True)

    # 1. request.json
    req_dict = {
        "id": request.id,
        "kind": request.kind.value if hasattr(request.kind, "value") else str(request.kind),
        "content": request.content,
        "entities": [str(e) for e in request.entities],
        "time_window": getattr(state.objective, "time_window", "") if state.objective else "",
        "answer_spec": getattr(state.objective, "answer_spec", {}) if state.objective else {},
    }
    with open(artifact_dir / "request.json", "w", encoding="utf-8") as f:
        json.dump(req_dict, f, indent=2, ensure_ascii=False)

    # 1b. Persist the semantic and capability planning boundaries used before
    # any provider operation or evidence graph pivot.
    claim_graph = getattr(state.objective, "claim_graph", None) if state.objective else None
    if claim_graph is not None:
        with open(artifact_dir / "claim_graph.json", "w", encoding="utf-8") as f:
            json.dump(claim_graph.to_dict(), f, indent=2, ensure_ascii=False)
    if getattr(state, "capability_graph", None) is not None:
        with open(artifact_dir / "capability_graph.json", "w", encoding="utf-8") as f:
            json.dump(state.capability_graph.to_dict(), f, indent=2, ensure_ascii=False)
    if getattr(state, "source_profile_audit", None):
        with open(artifact_dir / "source_profile_audit.json", "w", encoding="utf-8") as f:
            json.dump(state.source_profile_audit, f, indent=2, ensure_ascii=False, default=str)
    if getattr(state, "hunt_spec", None) is not None:
        with open(artifact_dir / "hunt_spec.json", "w", encoding="utf-8") as f:
            json.dump(state.hunt_spec.to_dict(), f, indent=2, ensure_ascii=False)
    if getattr(state, "semantic_goal_graph", None) is not None:
        with open(artifact_dir / "semantic_goal_graph.json", "w", encoding="utf-8") as f:
            json.dump(state.semantic_goal_graph.to_dict(), f, indent=2, ensure_ascii=False, default=str)
    if getattr(state, "compiler_trace", None):
        with open(artifact_dir / "compiler_trace.json", "w", encoding="utf-8") as f:
            json.dump(state.compiler_trace, f, indent=2, ensure_ascii=False, default=str)
    if getattr(state, "semantic_logical_plan", None) is not None:
        with open(artifact_dir / "proof_plan.json", "w", encoding="utf-8") as f:
            json.dump(state.semantic_logical_plan.to_dict(), f, indent=2, ensure_ascii=False, default=str)
    with open(artifact_dir / "adaptive_decision.json", "w", encoding="utf-8") as f:
        json.dump(getattr(state, "adaptive_decision", {}), f, indent=2, ensure_ascii=False)

    # 2. hypotheses.json
    hyps_data = [
        {
            "id": h.id,
            "statement": h.statement,
            "status": h.status.value if hasattr(h.status, "value") else str(h.status),
            "hypothesis_class": getattr(h, "hypothesis_class", ""),
            "requirements": list(getattr(h, "requirements", [])),
        }
        for h in state.hypotheses
    ]
    with open(artifact_dir / "hypotheses.json", "w", encoding="utf-8") as f:
        json.dump(hyps_data, f, indent=2, ensure_ascii=False)

    # 3. requirements.json
    reqs_data = [
        {
            "id": r.id,
            "description": r.description,
            "evidence_type": r.evidence_type,
            "status": r.status.value if hasattr(r.status, "value") else str(r.status),
            "necessity": getattr(r, "necessity", "CRITICAL"),
        }
        for r in state.requirements
    ]
    with open(artifact_dir / "requirements.json", "w", encoding="utf-8") as f:
        json.dump(reqs_data, f, indent=2, ensure_ascii=False)

    # 4. queries.json
    queries_data = []
    for q in account.queries:
        if isinstance(q, dict):
            queries_data.append(dict(q))
        else:
            qid = getattr(q, "id", None)
            queries_data.append({
                "query_id": qid,
                "requirement_id": getattr(q, "requirement_id", None),
                "provider_id": getattr(q, "provider_id", None),
                "operation_id": getattr(q, "operation_id", None),
                "parameters": getattr(q, "parameters", {}),
                "native_query": getattr(q, "native_query", None),
            })
    with open(artifact_dir / "queries.json", "w", encoding="utf-8") as f:
        json.dump(queries_data, f, indent=2, ensure_ascii=False, default=str)

    # 5. query_results.jsonl
    with open(artifact_dir / "query_results.jsonl", "w", encoding="utf-8") as f:
        for qr in state.query_results:
            row_res = {
                "query_id": getattr(qr, "query_id", None),
                "logical_plan_id": getattr(qr, "logical_plan_id", None),
                "executed_ok": qr.executed_ok,
                "complete": qr.complete,
                "rows_count": len(getattr(qr, "rows", [])),
                "native_query": getattr(qr, "native_query", None),
            }
            f.write(json.dumps(row_res, ensure_ascii=False, default=str) + "\n")

    # 6. observations.jsonl
    ledger.export_observations_jsonl(str(artifact_dir / "observations.jsonl"))

    # 7. evidence_cards.json
    cards_data = [
        {
            "id": c.id,
            "summary": c.summary,
            "why_it_matters": c.why_it_matters,
            "fact_type": c.fact_type,
            "count": c.count,
            "confidence": c.confidence,
            "hypotheses": c.hypotheses,
            "requirements": c.requirements,
            "query_ids": c.query_ids,
            "replay": c.replay,
            "entity_summary": c.entity_summary,
            "time_summary": c.time_summary,
            "field_summary": c.field_summary,
            "representative_observation_ids": c.representative_observation_ids,
        }
        for c in state.evidence_cards
    ]
    with open(artifact_dir / "evidence_cards.json", "w", encoding="utf-8") as f:
        json.dump(cards_data, f, indent=2, ensure_ascii=False, default=str)

    # 8. semantic evidence analysis (LLM advisory output after validation)
    analysis_data = {
        "analysis": account.semantic_analysis,
        "assessments": [
            {
                "card_id": assessment.card_id,
                "compatible_hypotheses": assessment.compatible_hypotheses,
                "contradicting_hypotheses": assessment.contradicting_hypotheses,
                "confidence": assessment.confidence,
                "interpretation": assessment.interpretation,
                "answer_candidates": assessment.answer_candidates,
                "missing_evidence": assessment.missing_evidence,
                "source_refs": assessment.source_refs,
            }
            for assessment in account.evidence_assessments
        ],
    }
    analysis_data["semantic_route_assessments"] = [
        route.to_dict() if hasattr(route, "to_dict") else route
        for route in account.semantic_route_assessments
    ]
    with open(artifact_dir / "semantic_evidence_analysis.json", "w", encoding="utf-8") as f:
        json.dump(analysis_data, f, indent=2, ensure_ascii=False, default=str)

    # 9. final_report.md
    with open(artifact_dir / "final_report.md", "w", encoding="utf-8") as f:
        f.write(report)

    # 10. audit_summary.json
    audit_data = {
        "hunt_id": artifact_dir.name,
        "outcome": account.outcome.value,
        "stopping_decision": account.stopping_decision.value,
        "answer": account.answer,
        "llm_usage": account.llm_usage,
        "total_observations": len(ledger.observations),
        "total_cards": len(state.evidence_cards),
        "total_queries": len(state.queries),
        "semantic_graph_id": getattr(getattr(state, "semantic_goal_graph", None), "id", None),
        "proof_plan_id": getattr(getattr(state, "semantic_logical_plan", None), "id", None),
        "semantic_analysis": getattr(state, "semantic_analysis", {}),
        "source_profile_audit": getattr(state, "source_profile_audit", {}),
        "runtime_capabilities": getattr(state, "runtime_capabilities", []),
        "semantic_route_assessments": [
            route.to_dict() if hasattr(route, "to_dict") else route
            for route in account.semantic_route_assessments
        ],
    }
    with open(artifact_dir / "audit_summary.json", "w", encoding="utf-8") as f:
        json.dump(audit_data, f, indent=2, ensure_ascii=False, default=str)

    # 11. investigation_model.json
    if state.investigation_model:
        with open(artifact_dir / "investigation_model.json", "w", encoding="utf-8") as f:
            json.dump(state.investigation_model.to_dict(), f, indent=2, ensure_ascii=False, default=str)

    # 12. relation_graph.json
    if state.relation_graph:
        with open(artifact_dir / "relation_graph.json", "w", encoding="utf-8") as f:
            json.dump(state.relation_graph.to_dict(), f, indent=2, ensure_ascii=False, default=str)


__all__ = ["HypothesisHuntEngine", "HuntExecutionResult"]
