"""Investigation Orchestrator — Unified coordination engine for threat hunting.

Executes the complete investigation lifecycle:
  ALERT
    -> DISCOVER: Load configured scopes and operations from Registry
    -> BOOTSTRAP: Extract entities and time window, register wildcard & instance cells
    -> M4 ACTION LOOP (TEST -> EXPAND -> SAMPLE):
         TEST: compile query, execute on adapter, ingest rows, evaluate predicate, update contradictions
         EXPAND: select instance candidate, query provider, discover new entities, update frontier
         SAMPLE: select wildcard cell via stratified sampling, BroadSweep, discover entities
         ABDUCE: generate diverse hypotheses & expectations from observations via LLM provider
    -> TERMINATE: evaluate stopping rules (STOP_RESOLVED vs STOP_BOUNDED)
    -> CONFIRM: enforce analyst confirmation requirements on sensitive dispositions
    -> REPORT: render final Markdown investigation account and coverage bounds
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Sequence

from hunting.bootstrap import bootstrap_investigation
from hunting.contracts.capabilities import CapabilityMatcher
from hunting.contracts.cells import CellState
from hunting.contracts.entities import ANY
from hunting.contracts.expectations import EvidenceRequirement, FieldOp, FieldPredicate, TestStatus
from hunting.contracts.explanations import Attribution
from hunting.contracts.queries import Diagnostic
from hunting.contracts.state import (
    Alert,
    FinalAccount,
    InvestigationState,
    TerminalState,
)
from hunting.m1_ledger import ObservationLedger
from hunting.m1_ledger.extraction import build_observation
from hunting.m1_ledger.raw_storage import ProtectedRawStore
from hunting.m2_abduction import (
    LLMProvider,
    StubAbductionProvider,
    build_llm_prompt_context,
    validate_m2_response,
)
from hunting.m3_constraints import (
    update_explanation_contradictions,
    validate_citation_integrity,
)
from hunting.m4_controller import (
    BudgetLedger,
    FrontierManager,
    compile_query_plan,
    emit_final_account,
    evaluate_stopping,
    sample_wildcard_cells,
    select_next_action,
)
from hunting.m5_adapter import license_valid_negative
from hunting.m5_reporter import render_investigation_report
from hunting.registry.schema import Registry


def evaluate_field_predicate(predicate: FieldPredicate | None, rows: Sequence[dict[str, Any]]) -> bool:
    """Deterministically evaluate if any row matches the expectation's field predicate."""
    if not predicate:
        return len(rows) > 0

    for row in rows:
        val = str(row.get(predicate.field, ""))
        target = predicate.value

        if predicate.op == FieldOp.EQUALS:
            if val.lower() == target.lower():
                return True
        elif predicate.op == FieldOp.CONTAINS:
            if target.lower() in val.lower():
                return True
        elif predicate.op == FieldOp.EXISTS:
            if predicate.field in row and row[predicate.field] is not None:
                return True
        elif predicate.op == FieldOp.ABSENT:
            if predicate.field not in row or row[predicate.field] is None:
                return True

    return False


@dataclass(frozen=True)
class InvestigationResult:
    """The complete result of an orchestrated threat hunting investigation."""
    account: FinalAccount
    report: str
    state: InvestigationState
    ledger: ObservationLedger
    frontier: FrontierManager
    budgets: BudgetLedger


class InvestigationOrchestrator:
    """Unified coordinator executing the full autonomous hunting lifecycle."""

    def __init__(
        self,
        registry: Registry,
        adapters: dict[str, Any] | Any,
        matcher: CapabilityMatcher | None = None,
        llm_provider: LLMProvider | None = None,
        budgets: BudgetLedger | None = None,
        raw_store: ProtectedRawStore | None = None,
        auto_confirm_analyst: bool = True,
        seed: int = 42,
    ) -> None:

        self.registry = registry

        # Normalize adapters mapping
        if isinstance(adapters, dict):
            self.adapters = adapters
            self._default_adapter = next(iter(adapters.values())) if adapters else None
        else:
            self._default_adapter = adapters
            scope_id = getattr(getattr(adapters, "scope", None), "scope_id", "default")
            self.adapters = {scope_id: adapters}

        # Capability Matcher
        if matcher is not None:
            self.matcher = matcher
        else:
            descriptors = []
            for ad in self.adapters.values():
                if hasattr(ad, "get_capability_descriptor"):
                    descriptors.append(ad.get_capability_descriptor())
            self.matcher = CapabilityMatcher(descriptors)

        self.llm_provider = llm_provider or StubAbductionProvider()
        self.budgets_factory = budgets or BudgetLedger()
        self.raw_store = raw_store or ProtectedRawStore()
        self.auto_confirm_analyst = auto_confirm_analyst
        self.seed = seed


    def _get_adapter(self, scope_id: str | None) -> Any:
        """Find matching adapter for a given scope ID."""
        if not scope_id:
            return self._default_adapter
        if scope_id in self.adapters:
            return self.adapters[scope_id]
        for ad in self.adapters.values():
            if getattr(getattr(ad, "scope", None), "scope_id", None) == scope_id:
                return ad
            if getattr(getattr(ad, "scope", None), "provider_id", None) == scope_id:
                return ad
        return self._default_adapter

    def investigate(
        self,
        alert: Alert,
        as_of: datetime | None = None,
        analyst_confirmed: bool | None = None,
        seed_radius_seconds: int = 7200,
    ) -> InvestigationResult:
        """Execute complete investigation from alert to final account and report."""
        # -------------------------------------------------------------------
        # 1. BOOTSTRAP: Seed, window, wildcard cells, instance cells
        # -------------------------------------------------------------------
        boot = bootstrap_investigation(
            alert=alert,
            registry=self.registry,
            seed_radius_seconds=seed_radius_seconds,
            as_of=as_of,
        )

        state = InvestigationState(registry=self.registry, seed=boot.seed)
        ledger = ObservationLedger()
        budgets = BudgetLedger(
            t_max=self.budgets_factory.t_max,
            q_max=self.budgets_factory.q_max,
            n_taint=self.budgets_factory.n_taint,
        )

        seen_scopes: dict[str, Any] = {}
        for c in boot.all_cells:
            if c.provider_scope.scope_id not in seen_scopes:
                seen_scopes[c.provider_scope.scope_id] = c.provider_scope
        all_scopes = list(seen_scopes.values())
        frontier = FrontierManager(all_scopes)


        window_str = str(boot.seed.window)

        # Register cells in ledger and frontier
        for cell in boot.wildcard_cells:

            ledger.register_cell(cell)
            frontier.wildcard_cells.append(cell)
            frontier._registered_wildcard_windows.add(cell.time_bucket)

        for cell in boot.instance_cells:
            ledger.register_cell(cell)
            frontier.instance_cells.append(cell)
            frontier._registered_instance_pairs.add((cell.entity, cell.time_bucket))


        # -------------------------------------------------------------------
        # 2. M4 FINITE ACTION LOOP (TEST -> EXPAND -> SAMPLE)
        # -------------------------------------------------------------------
        unsupported_reqs: list[str] = []

        while not budgets.is_budget_exhausted:
            # Check stopping condition
            term_state, disp, blockers = evaluate_stopping(state, budgets)
            if term_state == TerminalState.STOP_RESOLVED:
                break

            untested_expectations = [
                exp for exp in state.expectations
                if exp.test_status == TestStatus.UNTESTED
            ]
            has_untested = len(untested_expectations) > 0
            expand_candidates = frontier.select_expand_candidates()
            sample_candidates = frontier.select_sample_candidates()
            has_expand = len(expand_candidates) > 0
            has_sample = len(sample_candidates) > 0

            action = select_next_action(
                has_untested_expectations=has_untested,
                has_expand_candidates=has_expand,
                has_sample_candidates=has_sample,
            )
            if not action:
                break

            if action == "TEST":
                exp = untested_expectations[0]
                query_id = f"q-{len(state.queries) + 1:03d}"

                query, diag = compile_query_plan(
                    exp.evidence_requirement,
                    self.matcher,
                    exp.entity_ref,
                    exp.time_window,
                    query_id=query_id,
                )

                if not query or diag:
                    exp.test_status = TestStatus.REFUTED
                    update_explanation_contradictions(state.explanations, [exp])
                    if diag == Diagnostic.UNSUPPORTED_REQUIREMENT:
                        if exp.evidence_requirement.value not in unsupported_reqs:
                            unsupported_reqs.append(exp.evidence_requirement.value)
                else:
                    adapter = self._get_adapter(exp.provider_scope_id or query.scope_id)
                    if not adapter:
                        exp.test_status = TestStatus.REFUTED
                        update_explanation_contradictions(state.explanations, [exp])
                    else:
                        res = adapter.execute_query(query.operation_id, exp.entity_ref, exp.time_window)
                        budgets.query_count += 1
                        state.queries.append(query)
                        state.query_results.append(res)
                        state.query_count = len(state.queries)

                        target_cell = ledger.get_cell(adapter.scope.scope_id, exp.entity_ref, exp.time_window)
                        if target_cell:
                            ledger.record_query_outcome(query.intent, target_cell, res)

                        if res.rows:
                            for row in res.rows:
                                raw_ref = self.raw_store.store(json.dumps(row, sort_keys=True)).ref_id
                                obs = build_observation(
                                    record=row,
                                    provider_scope=adapter.scope,
                                    cell_id=target_cell.time_bucket if target_cell else exp.time_window,
                                    raw_ref=raw_ref,
                                    query_id=query.id,
                                    collector=adapter.scope.provider_id,
                                    ingest_time=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                )
                                ledger.add_observation(obs)
                                state.observations.append(obs)
                                if obs.id not in state.unattributed:
                                    state.unattributed.append(obs.id)

                            is_confirmed = evaluate_field_predicate(exp.field_predicate, res.rows)
                            exp.test_status = TestStatus.CONFIRMED if is_confirmed else TestStatus.REFUTED
                            update_explanation_contradictions(state.explanations, [exp])
                        else:
                            # 0 rows: verify with negative controls
                            c_health = adapter.control_health(exp.time_window, as_of=as_of)
                            c_any = adapter.control_any_record(exp.time_window)
                            c_obs = adapter.control_observability(exp.evidence_requirement, exp.field_predicate)

                            if license_valid_negative(res, c_health, c_any, c_obs):
                                exp.test_status = TestStatus.REFUTED
                                update_explanation_contradictions(state.explanations, [exp])
                            else:
                                exp.test_status = TestStatus.INCONCLUSIVE

            elif action == "EXPAND":
                expand_candidates = frontier.select_expand_candidates()
                if not expand_candidates:
                    break
                target_cell = expand_candidates[0]

                # Select best evidence requirement for the entity
                reqs = (
                    EvidenceRequirement.PROCESS_ANCESTRY,
                    EvidenceRequirement.AUTHENTICATION_ACTIVITY,
                    EvidenceRequirement.NETWORK_CONNECTION,
                    EvidenceRequirement.SCOPE_RECORDS,
                )
                query = None
                query_id = f"q-{len(state.queries) + 1:03d}"
                for r in reqs:
                    q, d = compile_query_plan(r, self.matcher, target_cell.entity, target_cell.time_bucket, query_id=query_id)
                    if q and not d:
                        query = q
                        break

                if query:
                    adapter = self._get_adapter(target_cell.provider_scope.scope_id)
                    if adapter:
                        res = adapter.execute_query(query.operation_id, target_cell.entity, target_cell.time_bucket)
                        budgets.query_count += 1
                        state.queries.append(query)
                        state.query_results.append(res)
                        state.query_count = len(state.queries)
                        ledger.record_query_outcome(query.intent, target_cell, res)

                        if res.rows:
                            for row in res.rows:
                                raw_ref = self.raw_store.store(json.dumps(row, sort_keys=True)).ref_id
                                obs = build_observation(
                                    record=row,
                                    provider_scope=adapter.scope,
                                    cell_id=target_cell.time_bucket,
                                    raw_ref=raw_ref,
                                    query_id=query.id,
                                    collector=adapter.scope.provider_id,
                                    ingest_time=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                )
                                ledger.add_observation(obs)
                                state.observations.append(obs)
                                if obs.id not in state.unattributed:
                                    state.unattributed.append(obs.id)

                                # Feed newly discovered entities to frontier
                                for ent in obs.entities:
                                    for ic in frontier.add_instance_entity(ent, target_cell.time_bucket):
                                        ledger.register_cell(ic)
                        else:
                            target_cell.state = CellState.EXPLORED
                    else:
                        target_cell.state = CellState.EXPLORED
                else:
                    target_cell.state = CellState.EXPLORED

            elif action == "SAMPLE":
                sample_candidates = frontier.select_sample_candidates()
                sampled_cells = sample_wildcard_cells(sample_candidates, budget=1, seed=self.seed)
                if not sampled_cells:
                    break
                w_cell = sampled_cells[0]

                query_id = f"q-{len(state.queries) + 1:03d}"
                query, diag = compile_query_plan(
                    EvidenceRequirement.SCOPE_RECORDS,
                    self.matcher,
                    ANY,
                    w_cell.time_bucket,
                    query_id=query_id,
                )

                if query and not diag:
                    adapter = self._get_adapter(w_cell.provider_scope.scope_id)
                    if adapter:
                        res = adapter.execute_query(query.operation_id, ANY, w_cell.time_bucket)
                        budgets.query_count += 1
                        state.queries.append(query)
                        state.query_results.append(res)
                        state.query_count = len(state.queries)
                        ledger.record_query_outcome(query.intent, w_cell, res)

                        if res.rows:
                            for row in res.rows:
                                raw_ref = self.raw_store.store(json.dumps(row, sort_keys=True)).ref_id
                                obs = build_observation(
                                    record=row,
                                    provider_scope=adapter.scope,
                                    cell_id=w_cell.time_bucket,
                                    raw_ref=raw_ref,
                                    query_id=query.id,
                                    collector=adapter.scope.provider_id,
                                    ingest_time=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                )
                                ledger.add_observation(obs)
                                state.observations.append(obs)
                                if obs.id not in state.unattributed:
                                    state.unattributed.append(obs.id)

                                for ent in obs.entities:
                                    for ic in frontier.add_instance_entity(ent, w_cell.time_bucket):
                                        ledger.register_cell(ic)

                        else:
                            w_cell.state = CellState.EXPLORED
                    else:
                        w_cell.state = CellState.EXPLORED
                else:
                    w_cell.state = CellState.EXPLORED

            # ---------------------------------------------------------------
            # M2 Abduction step: Propose hypotheses for unmapped/unattributed obs
            # ---------------------------------------------------------------
            if ledger.unattributed_observations:
                prompt_ctx = build_llm_prompt_context(state, ledger, window_str)
                llm_response = self.llm_provider.generate(prompt_ctx)
                cand_exps, cand_exps_expectations = validate_m2_response(
                    llm_response,
                    default_window=window_str,
                )


                for cand_exp in cand_exps:
                    # Link attribution if not already present
                    if not cand_exp.attributions:
                        for o in ledger.unattributed_observations:
                            cand_exp.attributions.append(
                                Attribution(observation_id=o.id, cause="abduced from telemetry observation")
                            )
                    validate_citation_integrity(cand_exp, ledger)

                    if not any(e.label == cand_exp.label for e in state.explanations):
                        state.explanations.append(cand_exp)

                    # Mark attributions in ledger and state so M2 is NOT invoked repeatedly
                    for attr in cand_exp.attributions:
                        ledger.mark_attributed(attr.observation_id, cand_exp.id)
                        if attr.observation_id not in state.abduced_over:
                            state.abduced_over.append(attr.observation_id)
                        if attr.observation_id in state.unattributed:
                            state.unattributed.remove(attr.observation_id)

                for cand_expectation in cand_exps_expectations:
                    if not any(e.id == cand_expectation.id for e in state.expectations):
                        state.expectations.append(cand_expectation)

            budgets.current_turn += 1


        # -------------------------------------------------------------------
        # 3. TERMINATION & ACCOUNT EMISSION
        # -------------------------------------------------------------------
        term_state, disp, blockers = evaluate_stopping(state, budgets)

        # Build coverage bound
        cb = ledger.build_coverage_bound()
        attempted_reqs: list[str] = []
        satisfied_reqs: list[str] = []
        partial_reqs: list[str] = []

        for q, res in zip(state.queries, state.query_results):
            req_name = q.evidence_requirement.value if q.evidence_requirement else q.intent.value
            attempted_reqs.append(req_name)
            if res.executed_ok and res.complete and res.rows and len(res.rows) > 0:
                if req_name not in satisfied_reqs:
                    satisfied_reqs.append(req_name)
            elif not res.complete:
                if req_name not in partial_reqs:
                    partial_reqs.append(req_name)

        cb.requirement_coverage.attempted_requirements = attempted_reqs
        cb.requirement_coverage.satisfied_requirements = satisfied_reqs
        cb.requirement_coverage.partial_requirements = partial_reqs
        cb.requirement_coverage.unsupported_requirements = unsupported_reqs


        # Determine confirmation
        if analyst_confirmed is not None:
            confirmed = analyst_confirmed
        else:
            confirmed = self.auto_confirm_analyst

        account = emit_final_account(
            disposition=disp,
            terminal_state=term_state,
            coverage_bound=cb,
            residuals=blockers,
            human_confirmed=confirmed,
        )


        # -------------------------------------------------------------------
        # 4. REPORTING
        # -------------------------------------------------------------------
        report_markdown = render_investigation_report(account, state, ledger)

        return InvestigationResult(
            account=account,
            report=report_markdown,
            state=state,
            ledger=ledger,
            frontier=frontier,
            budgets=budgets,
        )


__all__ = [
    "InvestigationResult",
    "InvestigationOrchestrator",
    "evaluate_field_predicate",
]
