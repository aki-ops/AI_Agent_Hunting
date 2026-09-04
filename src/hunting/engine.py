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
from typing import Any

from hunting.capabilities.registry import build_default_capability_registry
from hunting.compiler.compiler import KnowledgeBehaviorCompiler
from hunting.contracts.cells import Cell, CellState, ProviderScope
from hunting.contracts.entities import AnyEntity, Host
from hunting.contracts.hunt import (
    FinalHuntAccount,
    HuntRequest,
    HuntState,
    RequirementStatus,
    StoppingDecision,
)
from hunting.contracts.observations import EpistemicType, Observation
from hunting.contracts.queries import QueryResult
from hunting.controller.controller import CanonicalActionController
from hunting.controller.models import HuntAction, HuntBudgetLedger
from hunting.controller.reasoning import HypothesisReasoningEngine
from hunting.evidence.grouping import EvidenceGroupBuilder
from hunting.m1_ledger.ledger import ObservationLedger
from hunting.m5_adapter.cdb_adapter import CdbAdapter
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
    ) -> None:
        self.compiler = compiler if compiler is not None else KnowledgeBehaviorCompiler()
        self.registry = registry if registry is not None else build_default_capability_registry()
        self.planner = planner if planner is not None else CanonicalQueryPlanner(self.registry)
        self.cdb_adapter = cdb_adapter if cdb_adapter is not None else CdbAdapter()
        self.budget_ledger = budget_ledger if budget_ledger is not None else HuntBudgetLedger()
        self.group_builder = EvidenceGroupBuilder()
        self.reasoner = HypothesisReasoningEngine()
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

        # 3. Action Execution Loop (TEST -> CONTROL -> EXPAND -> STOP)
        for req in state.requirements:
            if self.budget_ledger.is_exhausted:
                state.stopping_decision = StoppingDecision.STOP_EXHAUSTED_BY_BUDGET
                break

            action = self.controller.select_action(state, has_untested_expectations=True)
            if action == HuntAction.STOP:
                break

            # Plan safe query
            target_entity = request.entities[0] if request.entities else None
            plan, diag = self.planner.plan_query(
                requirement=req,
                entity=target_entity,
                scope=scope,
                time_window=objective.time_window,
                query_id=f"qp-{req.id}",
            )

            if plan is None:
                req.status = RequirementStatus.UNSUPPORTED
                continue

            state.queries.append(plan)

            # Execute query on adapter
            qr: QueryResult = active_adapter.execute_query(
                operation_id=plan.operation_id,
                entity=target_entity,
                window=plan.parameters.get("window", objective.time_window),
                limit=plan.parameters.get("limit", 100),
                query_id=plan.id,
            )
            state.query_results.append(qr)
            self.budget_ledger.record_query()

            # Coverage update
            matching_cell = wc_cell
            if plan.is_targeted and request.entities:
                for c in state.cells:
                    if not c.is_wildcard:
                        matching_cell = c
                        break

            if qr.complete:
                matching_cell.state = CellState.EXPLORED
            else:
                matching_cell.state = CellState.PARTIAL

            # Mint observations
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
                        timestamp=row.get("timestamp", "2026-02-01T00:00:00Z"),
                        epistemic_type=EpistemicType.OBSERVED,
                        native_type=row.get("native_type"),
                        fields=dict(row),
                        entities=ent_list,
                    )
                    ledger.add_observation(obs)
                    state.observations.append(obs)
                    new_observations.append(obs)

                req.status = RequirementStatus.VALIDATED
            else:
                if qr.complete:
                    req.status = RequirementStatus.VALIDATED

            # Build EvidenceCards from ledger observations
            if ledger.observations:
                cards = self.group_builder.build_cards(ledger.observations)
                state.evidence_cards = cards

            # Reason over hypotheses
            for hyp in state.hypotheses:
                compat = any(
                    self.reasoner.evaluate_compatibility(c, [hyp]).get(hyp.id, False)
                    for c in state.evidence_cards
                )
                if compat:
                    self.reasoner.update_hypothesis_status(
                        hyp,
                        has_confirming_evidence=True,
                        has_refuting_evidence=False,
                    )
                elif qr.complete and not state.evidence_cards and "benign" not in hyp.statement.lower():
                    # Observable negative evidence: 0 hits under complete query
                    # Refute adversary hypothesis if fully observable
                    self.reasoner.update_hypothesis_status(
                        hyp,
                        has_confirming_evidence=False,
                        has_refuting_evidence=True,
                    )

        # 4. Evaluate stopping decision
        stopping_dec = self.controller.evaluate_stopping(state)
        state.stopping_decision = stopping_dec

        # 5. Build Final Account & Render Markdown Report
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
