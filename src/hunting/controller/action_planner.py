"""Graph-Driven Action Planner.

Component 4 of the General Cyclical Investigation Loop.
Selects the next investigation action based on unresolved unknowns, missing graph edges,
and acceptance criteria rather than hardcoded heuristics.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from hunting.capabilities.binder import CapabilityBinder
from hunting.contracts.case_graph import (
    InvestigationCase,
    InvestigationGraph,
)
from hunting.contracts.expectations import TestStatus
from hunting.contracts.hunt import HuntState
from hunting.contracts.investigation_model import (
    InvestigationModel,
    InvestigationUnknown,
    NodeStatus,
    RelationGraph,
)


class InvestigationAction(str, Enum):
    """The set of permitted actions in the cyclical investigation loop."""
    RESOLVE_ENTITY = "RESOLVE_ENTITY"
    DISCOVER = "DISCOVER"
    TEST = "TEST"
    CORRELATE = "CORRELATE"
    EXPAND = "EXPAND"
    PIVOT = "PIVOT"
    REFINE = "REFINE"
    STOP = "STOP"


@dataclass
class ActionDecision:
    """Action decision produced by the InvestigationActionPlanner."""
    action: InvestigationAction
    reason: str
    target_unknown: InvestigationUnknown | None = None
    target_entity: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class InvestigationActionPlanner:
    """Selects next action dynamically by analyzing graph gaps and acceptance criteria."""

    def __init__(self, binder: CapabilityBinder | None = None) -> None:
        self.binder = binder if binder is not None else CapabilityBinder()

    def select_action(
        self,
        model: InvestigationModel | None = None,
        graph: RelationGraph | None = None,
        state: HuntState | None = None,
        budget_exhausted: bool = False,
        case: InvestigationCase | None = None,
    ) -> ActionDecision:
        """Select next optimal action to advance the investigation."""
        # 1. Budget exhaustion check
        if budget_exhausted or (state and getattr(state, "stopping_decision", None) is not None and "EXHAUSTED" in str(state.stopping_decision)):
            return ActionDecision(
                action=InvestigationAction.STOP,
                reason="Investigation budgets exhausted.",
            )

        # 2. v5 Case Graph Dependency-Driven Edge Selection (Priority 1)
        active_case = case or (state.case if state is not None else None)
        if active_case is not None and getattr(active_case, "graph", None) is not None:
            case_graph: InvestigationGraph = active_case.graph
            actionable_edges = case_graph.get_unproven_edges(only_known_source=True)

            if actionable_edges:
                candidates: list[tuple[Any, Any, Any]] = []
                for edge in actionable_edges:
                    src_node = case_graph.get_node(edge.source_id)
                    tgt_node = case_graph.get_node(edge.target_id)
                    if not src_node or not tgt_node:
                        continue
                    candidate = self.binder.create_candidate(edge, src_node, tgt_node)
                    if candidate:
                        candidates.append((candidate, edge, tgt_node))
                if candidates:
                    candidate, edge, tgt_node = min(
                        candidates,
                        key=lambda item: (
                            item[0].priority,
                            item[0].expected_cost is None,
                            item[0].expected_cost or 0,
                            -item[0].relevance,
                            item[1].id,
                        ),
                    )
                    action = (
                        InvestigationAction.RESOLVE_ENTITY
                        if candidate.priority == 1
                        else InvestigationAction.TEST
                    )
                    return ActionDecision(
                        action=action,
                        reason=candidate.reason,
                        target_entity=str(getattr(tgt_node, "type", "")),
                        metadata={
                            "candidate": candidate.to_dict(),
                            "edge_id": edge.id,
                            "operation_name": candidate.operation_name,
                        },
                    )

            # Check if all edges are proven
            all_unproven = case_graph.get_unproven_edges(only_known_source=False)
            if not all_unproven and case_graph.edges:
                return ActionDecision(
                    action=InvestigationAction.STOP,
                    reason="All mandatory causal relations in case graph verified.",
                )

            # If unproven edges remain but none have KNOWN source, the claim
            # dependencies are not executable yet.  Do not invent an
            # identity/endpoint step from the fact that a subject happens to
            # be a person; the validated ClaimGraph and capability contract
            # must define that prerequisite explicitly.  The old identity
            # shortcut is retained only for legacy model-only tests.
            if all_unproven:
                if self.binder.capability_graph is None:
                    subj_person = any(
                        str(getattr(n, "type", "")).lower() in ("person", "user")
                        for n in case_graph.nodes.values()
                    )
                else:
                    subj_person = False
                if subj_person and state is not None and not state.identity_resolved:
                    return ActionDecision(
                        action=InvestigationAction.RESOLVE_ENTITY,
                        reason="Legacy model requires an unresolved subject identity prefix.",
                        target_entity="endpoint",
                    )
                return ActionDecision(
                    action=InvestigationAction.STOP,
                    reason="Unproven claim dependencies remain without an executable known-source edge.",
                )

        if model is None:
            return ActionDecision(
                action=InvestigationAction.STOP,
                reason="No active investigation model or case graph provided.",
            )

        # 3. Check for unresolved mandatory unknowns (Legacy InvestigationModel fallback)
        unresolved_unknowns = [
            u for u in model.unknowns
            if u.mandatory and u.status == "UNRESOLVED"
        ]

        for unk in unresolved_unknowns:
            if unk.entity_type in ("endpoint", "host", "account", "user"):
                if not state.identity_resolved:
                    return ActionDecision(
                        action=InvestigationAction.RESOLVE_ENTITY,
                        reason=f"Mandatory prerequisite unresolved: {unk.description}",
                        target_unknown=unk,
                        target_entity=unk.entity_type,
                    )

        # 3. Check for untested concrete expectations (Priority 2: Testing Hypotheses)
        untested_exps = [e for e in state.expectations if e.test_status == TestStatus.UNTESTED]
        if untested_exps:
            # Guard: If untested expectation relates to web navigation or outbound traffic,
            # ensure subject identity was resolved first if required.
            first_exp = untested_exps[0]
            is_traffic_test = first_exp.evidence_requirement.value in (
                "web_request", "dns_activity", "network_connection"
            )
            subj_is_person = any(s.type in ("person", "user") for s in model.subjects)

            if is_traffic_test and subj_is_person and not state.identity_resolved:
                # Must resolve entity first!
                unk = unresolved_unknowns[0] if unresolved_unknowns else None
                return ActionDecision(
                    action=InvestigationAction.RESOLVE_ENTITY,
                    reason="Cannot test network traffic before subject endpoint identity is established.",
                    target_unknown=unk,
                    target_entity="endpoint",
                )

            return ActionDecision(
                action=InvestigationAction.TEST,
                reason=f"Test concrete expectation: {first_exp.predicted_observation}",
                metadata={"expectation_id": first_exp.id},
            )

        # 4. Check for ambiguous evidence needing LLM refinement
        ambiguous_cards = [
            c for c in state.evidence_cards
            if not c.hypotheses or c.confidence == "LOW"
        ]
        if ambiguous_cards and not state.semantic_analysis:
            return ActionDecision(
                action=InvestigationAction.REFINE,
                reason=f"Analyze {len(ambiguous_cards)} ambiguous evidence cards with bounded LLM evaluator.",
                metadata={"card_count": len(ambiguous_cards)},
            )

        # 5. Check if acceptance criteria are satisfied
        all_criteria_met = True
        for crit in model.acceptance_criteria:
            if crit.required_path and len(crit.required_path) >= 2:
                # Verify path in graph
                start_type, end_type = crit.required_path[0], crit.required_path[-1]
                start_node = next((n for n in graph.nodes.values() if n.type == start_type and n.status == NodeStatus.KNOWN), None)
                end_node = next((n for n in graph.nodes.values() if n.type == end_type and n.status == NodeStatus.KNOWN), None)
                if not start_node or not end_node:
                    all_criteria_met = False
                    break
                path = graph.find_path(start_node.id, end_node.id)
                if not path:
                    all_criteria_met = False
                    break

        if all_criteria_met and model.acceptance_criteria:
            return ActionDecision(
                action=InvestigationAction.STOP,
                reason="All acceptance criteria satisfied with proven graph paths.",
            )

        # 6. Default: Stop once active tests, resolutions, and refinements conclude
        return ActionDecision(
            action=InvestigationAction.STOP,
            reason="No further actions available within current scope and criteria.",
        )


__all__ = ["InvestigationAction", "ActionDecision", "InvestigationActionPlanner"]
