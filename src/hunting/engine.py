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

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from hunting.capabilities.registry import build_default_capability_registry
from hunting.compiler.compiler import KnowledgeBehaviorCompiler
from hunting.contracts.cells import Cell, CellState, ProviderScope
from hunting.contracts.entities import AnyEntity, EntityRef, Host
from hunting.contracts.expectations import (
    EvidenceRequirement,
    Expectation,
    TestStatus,
)
from hunting.contracts.hunt import (
    FinalHuntAccount,
    HuntRequest,
    HuntState,
    QueryPlan,
    RequirementStatus,
    StoppingDecision,
)
from hunting.contracts.observations import EpistemicType, Observation
from hunting.contracts.queries import QueryResult
from hunting.controller.controller import CanonicalActionController
from hunting.controller.models import HuntAction, HuntBudgetLedger
from hunting.controller.reasoning import HypothesisReasoningEngine
from hunting.evidence.evaluator import EvidenceEvaluator
from hunting.evidence.grouping import EvidenceGroupBuilder
from hunting.m1_ledger.ledger import ObservationLedger
from hunting.m5_adapter.allowlist import validate_time_window_format
from hunting.m5_adapter.cdb_adapter import CdbAdapter
from hunting.m5_adapter.controls import license_valid_negative
from hunting.planner.planner import CanonicalQueryPlanner
from hunting.reporter.builder import build_final_hunt_account
from hunting.reporter.renderer import render_final_hunt_account


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
        cdb_adapter: CdbAdapter | None = None,
        budget_ledger: HuntBudgetLedger | None = None,
        evaluator: EvidenceEvaluator | None = None,
    ) -> None:
        self.compiler = compiler if compiler is not None else KnowledgeBehaviorCompiler()
        self.registry = registry if registry is not None else build_default_capability_registry()
        self.planner = planner if planner is not None else CanonicalQueryPlanner(self.registry)
        self.cdb_adapter = cdb_adapter if cdb_adapter is not None else CdbAdapter()
        self.budget_ledger = budget_ledger if budget_ledger is not None else HuntBudgetLedger()
        self.group_builder = EvidenceGroupBuilder()
        self.reasoner = HypothesisReasoningEngine()
        self.evaluator = evaluator if evaluator is not None else EvidenceEvaluator()
        self.controller = CanonicalActionController(budget_ledger=self.budget_ledger)

    def execute_hunt(
        self,
        request: HuntRequest,
        adapter: Any | None = None,
        time_window: str = "2026-02-01T00:00:00Z/P1D",
    ) -> HuntExecutionResult:
        """Execute complete hypothesis-only hunt vertical slice without alert or PoC."""
        active_adapter = adapter if adapter is not None else self.cdb_adapter
        ledger = ObservationLedger()

        # 1. Compile HuntRequest deterministically (0 LLM calls for known CVE/TTP)
        objective, hypotheses, requirements = self.compiler.compile(request)
        if request.time_policy and request.time_policy.start and request.time_policy.end:
            objective.time_window = f"{request.time_policy.start}/{request.time_policy.end}"
        elif time_window and (not objective.time_window or objective.time_window.startswith("NOW")):
            objective.time_window = time_window

        state = HuntState(
            objective=objective,
            hypotheses=hypotheses,
            requirements=requirements,
        )

        # 2. Register Scope and Cells
        scope = getattr(active_adapter, "scope", None)
        if scope is None:
            scope = ProviderScope(
                provider_id="cdb_sqlite",
                native_partition={"table": "events"},
                scope_id="cdb_native_scope",
            )

        # Wildcard BroadSweep cell
        wc_cell = Cell(
            provider_scope=scope,
            entity=AnyEntity(),
            time_bucket=objective.time_window,
            state=CellState.UNEXPLORED,
        )
        state.cells.append(wc_cell)

        # Discovered or targeted instance cells
        if request.entities:
            for ent in request.entities:
                inst_cell = Cell(
                    provider_scope=scope,
                    entity=ent,
                    time_bucket=objective.time_window,
                    state=CellState.UNEXPLORED,
                )
                state.cells.append(inst_cell)

        # 3. Instantiate initial Expectations for targeted entities
        if request.entities:
            for ent in request.entities:
                for hyp in state.hypotheses:
                    for req in state.requirements:
                        is_bound = (
                            req.id in hyp.requirements
                            or hyp.id in req.supports
                            or (not hyp.requirements and "benign" not in hyp.id and "baseline" not in req.id)
                            or ("benign" in hyp.id and "baseline" in req.id)
                        )
                        if is_bound:
                            try:
                                ev_enum = EvidenceRequirement(req.evidence_type)
                            except ValueError:
                                ev_enum = EvidenceRequirement.PROCESS_ANCESTRY

                            ent_label = getattr(ent, "name", getattr(ent, "username", getattr(ent, "address", "ent")))
                            exp_id = f"exp-{hyp.id}-{req.id}-{ent_label}"
                            if not any(e.id == exp_id for e in state.expectations):
                                state.expectations.append(
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
                                    )
                                )

        # 4. Central Action Loop governed by CanonicalActionController
        pending_controls: list[tuple[Expectation, QueryResult]] = []
        expand_candidates: list[EntityRef] = []
        discovered_entities: set[str] = set()

        while not state.stopping_decision:
            self.budget_ledger.record_turn()
            state.turn += 1

            if self.budget_ledger.is_exhausted:
                state.stopping_decision = StoppingDecision.STOP_EXHAUSTED_BY_BUDGET
                break

            untested_exps = [e for e in state.expectations if e.test_status == TestStatus.UNTESTED]
            has_untested = len(untested_exps) > 0
            has_pending_controls = len(pending_controls) > 0
            has_expand = len(expand_candidates) > 0
            has_discover = any(c.is_wildcard and c.state == CellState.UNEXPLORED for c in state.cells)

            # Detect ambiguous cards (cards not matching any expectation)
            ambiguous_cards = [
                c for c in state.evidence_cards
                if not any(
                    self.evaluator.evaluate_card_against_expectation(c, exp)
                    for exp in state.expectations
                )
            ]
            has_ambiguous = len(ambiguous_cards) > 0 and not self.budget_ledger.is_llm_exhausted and self.evaluator.llm_caller is not None

            action = self.controller.select_action(
                state,
                has_untested_expectations=has_untested,
                has_pending_controls=has_pending_controls,
                has_expand_candidates=has_expand,
                has_discover_candidates=has_discover,
                has_pivot_candidates=False,
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
                    exp.test_status = TestStatus.UNTESTABLE
                    continue

                plan, diag = self.planner.plan_query(
                    requirement=req,
                    entity=exp.entity_ref,
                    scope=scope,
                    time_window=exp.time_window,
                    query_id=f"qp-{exp.id}",
                )

                if plan is None:
                    exp.test_status = TestStatus.UNTESTABLE
                    req.status = RequirementStatus.UNSUPPORTED
                    continue

                state.queries.append(plan)

                qr: QueryResult = active_adapter.execute_query(
                    operation_id=plan.operation_id,
                    entity=exp.entity_ref,
                    window=plan.parameters.get("window", exp.time_window),
                    limit=plan.parameters.get("limit", 100),
                    query_id=plan.id,
                )
                state.query_results.append(qr)
                self.budget_ledger.record_query()
                state.query_count += 1

                # Update cell coverage
                matching_cell = wc_cell
                if plan.is_targeted and exp.entity_ref:
                    for c in state.cells:
                        if not c.is_wildcard and c.entity == exp.entity_ref:
                            matching_cell = c
                            break

                if qr.complete:
                    matching_cell.state = CellState.EXPLORED
                else:
                    matching_cell.state = CellState.PARTIAL

                # Mint observations into ledger
                new_observations: list[Observation] = []
                if qr.rows:
                    for row in qr.rows:
                        ent_list = []
                        if "host" in row and row["host"]:
                            ent_list.append(Host(name=str(row["host"])))

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
                        )
                        ledger.add_observation(obs)
                        state.observations.append(obs)
                        new_observations.append(obs)

                    # Incremental delta grouping
                    delta_cards = self.group_builder.ingest_delta(new_observations)
                    state.evidence_cards = self.group_builder.build_cards()

                    # Evaluate whether any delta or existing card satisfies this expectation
                    matched_card = next(
                        (c for c in (delta_cards or state.evidence_cards) if self.evaluator.evaluate_card_against_expectation(c, exp)),
                        None,
                    )
                    if matched_card is not None:
                        exp.test_status = TestStatus.CONFIRMED
                        req.status = RequirementStatus.VALIDATED
                        if exp.entity_ref not in expand_candidates:
                            expand_candidates.append(exp.entity_ref)
                    else:
                        # Rows returned, but none satisfied the expectation predicate!
                        if qr.complete:
                            exp.test_status = TestStatus.REFUTED
                        else:
                            exp.test_status = TestStatus.INCONCLUSIVE
                else:
                    # 0 rows returned
                    if qr.complete:
                        if hasattr(active_adapter, "control_health") and hasattr(active_adapter, "control_any_record"):
                            exp.test_status = TestStatus.INCONCLUSIVE
                            pending_controls.append((exp, qr))
                        else:
                            exp.test_status = TestStatus.REFUTED
                    else:
                        exp.test_status = TestStatus.INCONCLUSIVE

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
                ctrl_any = active_adapter.control_any_record(exp.time_window)
                ctrl_pred = active_adapter.control_observability(exp.evidence_requirement, exp.field_predicate)
                ledger.record_control_result(ctrl_health)
                ledger.record_control_result(ctrl_any)
                ledger.record_control_result(ctrl_pred)

                if license_valid_negative(qr, ctrl_health, ctrl_any, ctrl_pred):
                    exp.test_status = TestStatus.REFUTED
                else:
                    exp.test_status = TestStatus.INCONCLUSIVE

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
                        owner_id = req.supports[0] if req.supports else state.hypotheses[0].id
                        ent_label = getattr(ent, "name", getattr(ent, "username", getattr(ent, "address", "ent")))
                        state.expectations.append(
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
                            )
                        )

            elif action == HuntAction.DISCOVER:
                # Broad sweep on unexplored wildcard cell
                unexplored_wc = next(c for c in state.cells if c.is_wildcard and c.state == CellState.UNEXPLORED)
                unexplored_wc.state = CellState.EXPLORED
                self.budget_ledger.record_scan_cell()

                sweep_plan = QueryPlan(
                    id=f"qp-sweep-{state.turn}",
                    requirement_id="req-broad-sweep",
                    provider_id=scope.provider_id,
                    scope_id=scope.scope_id,
                    operation_id="cdb_scope_scan",
                    parameters={"window": objective.time_window, "limit": 100},
                )
                state.queries.append(sweep_plan)
                qr = active_adapter.execute_query(
                    operation_id=sweep_plan.operation_id,
                    entity=AnyEntity(),
                    window=objective.time_window,
                    limit=100,
                    query_id=sweep_plan.id,
                )
                state.query_results.append(qr)
                self.budget_ledger.record_query()
                state.query_count += 1

                new_observations = []
                if qr.rows:
                    for row in qr.rows:
                        ent_list = []
                        if "host" in row and row["host"]:
                            h = Host(name=str(row["host"]))
                            ent_list.append(h)
                            discovered_entities.add(str(row["host"]))

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
                        )
                        ledger.add_observation(obs)
                        state.observations.append(obs)
                        new_observations.append(obs)

                    self.group_builder.ingest_delta(new_observations)
                    state.evidence_cards = self.group_builder.build_cards()

                    # Promote discovered entities to instance cells and concrete Expectations
                    for h_name in discovered_entities:
                        ent = Host(name=h_name)
                        if not any(not c.is_wildcard and c.entity == ent for c in state.cells):
                            state.cells.append(
                                Cell(provider_scope=scope, entity=ent, time_bucket=objective.time_window, state=CellState.UNEXPLORED)
                            )
                        for hyp in state.hypotheses:
                            for req in state.requirements:
                                is_bound = (
                                    req.id in hyp.requirements
                                    or hyp.id in req.supports
                                    or (not hyp.requirements and "benign" not in hyp.id and "baseline" not in req.id)
                                    or ("benign" in hyp.id and "baseline" in req.id)
                                )
                                if is_bound:
                                    try:
                                        ev_enum = EvidenceRequirement(req.evidence_type)
                                    except ValueError:
                                        ev_enum = EvidenceRequirement.PROCESS_ANCESTRY
                                    exp_id = f"exp-{hyp.id}-{req.id}-{h_name}"
                                    if not any(e.id == exp_id for e in state.expectations):
                                        state.expectations.append(
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
                                            )
                                        )

            elif action == HuntAction.REFINE:
                compat_map = self.evaluator._batch_llm_evaluate(ambiguous_cards, state.hypotheses)
                self.budget_ledger.record_llm_call()
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
            state.stopping_decision = self.controller.evaluate_stopping(state)

        # 6. Build Final Account & Render Markdown Report
        account = build_final_hunt_account(state, ledger=ledger)
        report = render_final_hunt_account(account)

        return HuntExecutionResult(
            account=account,
            report=report,
            state=state,
            ledger=ledger,
            budget=self.budget_ledger,
        )


__all__ = ["HypothesisHuntEngine", "HuntExecutionResult"]
