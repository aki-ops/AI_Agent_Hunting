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
from typing import Any, Callable

from hunting.capabilities.models import VersionedCapabilityDescriptor
from hunting.capabilities.registry import build_default_capability_registry
from hunting.compiler.compiler import KnowledgeBehaviorCompiler
from hunting.contracts.capabilities import ProviderCapabilityCatalog
from hunting.contracts.cells import Cell, CellState, ProviderScope
from hunting.contracts.entities import Account, AnyEntity, Domain, EntityRef, Host, IPAddress
from hunting.contracts.expectations import (
    EvidenceRequirement,
    Expectation,
    TestStatus,
    is_entity_compatible_with_requirement,
)
from hunting.contracts.hunt import (
    FinalHuntAccount,
    HuntRequest,
    HuntState,
    HypothesisStatus,
    QueryPlan,
    RequirementStatus,
    StoppingDecision,
)
from hunting.contracts.observations import EpistemicType, Observation
from hunting.contracts.queries import QueryResult
from hunting.controller.controller import CanonicalActionController
from hunting.controller.cost import LLMUsageTracker
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
        cdb_adapter: CdbAdapter | None = None,
        budget_ledger: HuntBudgetLedger | None = None,
        evaluator: EvidenceEvaluator | None = None,
        llm_tracker: LLMUsageTracker | None = None,
    ) -> None:
        self.compiler = compiler if compiler is not None else KnowledgeBehaviorCompiler()
        self.registry = registry if registry is not None else build_default_capability_registry()
        self.planner = planner if planner is not None else CanonicalQueryPlanner(self.registry)
        self.cdb_adapter = cdb_adapter if cdb_adapter is not None else CdbAdapter()
        self.budget_ledger = budget_ledger if budget_ledger is not None else HuntBudgetLedger()
        self.llm_tracker = llm_tracker if llm_tracker is not None else LLMUsageTracker()
        self.group_builder = EvidenceGroupBuilder()
        self.reasoner = HypothesisReasoningEngine()
        self.evaluator = evaluator if evaluator is not None else EvidenceEvaluator()
        self.controller = CanonicalActionController(budget_ledger=self.budget_ledger)

    def execute_hunt(
        self,
        request: HuntRequest,
        adapter: Any | None = None,
        time_window: str = "2026-02-01T00:00:00Z/P1D",
        step_callback: Callable[[str, dict[str, Any]], None] | None = None,
        analyst_confirm_callback: Callable[[str, dict[str, Any]], bool] | None = None,
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

        # 2. Discover Provider Capabilities & Fast Guards
        if hasattr(active_adapter, "discover_full_capabilities"):
            cat = active_adapter.discover_full_capabilities()
            if isinstance(cat, ProviderCapabilityCatalog):
                state.capability_catalog = cat
                if cat.status == "UNREACHABLE":
                    self.controller.set_stopping_decision(state, StoppingDecision.STOP_UNREACHABLE)

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
            has_ambiguous = len(ambiguous_cards) > 0 and not self.budget_ledger.is_llm_exhausted and self.evaluator.llm_caller is not None

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
                    import inspect
                    sig = inspect.signature(active_adapter.execute_query)
                    if "native_query" in sig.parameters:
                        exec_kwargs["native_query"] = nqp.native_query

                qr: QueryResult = active_adapter.execute_query(**exec_kwargs)
                if lqp:
                    qr.logical_plan_id = lqp.id
                if nqp:
                    qr.native_query = nqp.native_query
                if hasattr(active_adapter, "last_query_text"):
                    plan.parameters["query_text"] = active_adapter.last_query_text
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
                        )
                        ledger.add_observation(obs)
                        self.controller.add_observation(state, obs)
                        new_observations.append(obs)

                    # Incremental delta grouping
                    delta_cards = self.group_builder.ingest_delta(new_observations)
                    self.controller.set_evidence_cards(state, self.group_builder.build_cards())
                    for c in state.evidence_cards:
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
                        (c for c in (delta_cards or state.evidence_cards) if self.evaluator.evaluate_card_against_expectation(c, exp)),
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
                    import inspect
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
                if sweep_nqp:
                    qr.native_query = sweep_nqp.native_query
                if hasattr(active_adapter, "last_query_text") and isinstance(active_adapter.last_query_text, str):
                    sweep_plan.parameters["query_text"] = active_adapter.last_query_text
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
                        )
                        ledger.add_observation(obs)
                        self.controller.add_observation(state, obs)
                        new_observations.append(obs)

                    # Resolve internal server IPs to actual target hosts
                    if hasattr(active_adapter, "resolve_ip_to_host") and discovered_ips:
                        for ip_s in discovered_ips:
                            resolved_h = active_adapter.resolve_ip_to_host(ip_s)
                            if resolved_h:
                                host_counts[resolved_h] = host_counts.get(resolved_h, 0) + 100

                    self.group_builder.ingest_delta(new_observations)
                    self.controller.set_evidence_cards(state, self.group_builder.build_cards())
                    for c in state.evidence_cards:
                        advisory = self.evaluator.evaluate_evidence_advisory(c, state.hypotheses, state.expectations)
                        self.controller.add_evidence_assessment(state, advisory)

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
                compat_map = self.evaluator._batch_llm_evaluate(ambiguous_cards, state.hypotheses)
                self.budget_ledger.record_llm_call()
                if len(self.llm_tracker.calls) == calls_before and not self.llm_tracker.is_exhausted:
                    self.llm_tracker.record_call(
                        component="evaluator_refine",
                        prompt=f"Cards: {len(ambiguous_cards)}, Hypotheses: {len(state.hypotheses)}",
                        response=str(compat_map),
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
