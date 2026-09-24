"""Bounded execution of a provider-neutral multi-step logical plan."""
from __future__ import annotations

import inspect
from dataclasses import dataclass, field, replace
from typing import Any

from hunting.contracts.agenda import AgendaItem, BoundedAgenda
from hunting.contracts.cells import ProviderScope
from hunting.contracts.entities import Account, Domain, File, Host, IPAddress, Process
from hunting.contracts.observations import EpistemicType, Observation
from hunting.contracts.ontology import (
    native_field_compatible_with_kind,
    roles_are_compatible,
    types_are_compatible,
)
from hunting.contracts.proof_contract import ProofResult
from hunting.contracts.queries import (
    Diagnostic,
    ProviderOperation,
    QueryAttempt,
    QueryOutcome,
    QueryResult,
    RetrievalStage,
)
from hunting.contracts.semantic_graph import LogicalPlan
from hunting.contracts.semantic_route import (
    CapabilityReadiness,
    SemanticAttempt,
    SemanticRouteAssessment,
    SemanticRouteStatus,
)
from hunting.contracts.transforms import (
    evaluate_constraint_against_row,
    get_transform_for_constraint,
    is_literal_telemetry_token,
)
from hunting.planner.semantic_query_compiler import query_plan_from_step, split_time_window


def _constraint_pairs(step: Any) -> tuple[tuple[str, Any], ...]:
    pairs: list[tuple[str, Any]] = []
    for text in getattr(step, "constraints", ()) or ():
        raw = str(text)
        if "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        pairs.append((key.strip(), value.strip()))
    for item in getattr(step, "constraint_metadata", ()) or ():
        if not isinstance(item, dict):
            continue
        key = str(item.get("key") or "").strip()
        if key:
            pairs.append((key, item.get("value")))
    return tuple(pairs)


def _rows_matching_transform_constraints(
    rows: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None,
    step: Any,
    removed_keys: set[str] | frozenset[str] | None = None,
) -> list[dict[str, Any]]:
    """Apply registered transforms before treating multiple values as ambiguous."""
    skipped = {str(key).strip().casefold() for key in (removed_keys or ()) if str(key).strip()}
    filtered = [dict(row) for row in (rows or ())]
    for key, value in _constraint_pairs(step):
        if str(key).strip().casefold() in skipped:
            continue
        if get_transform_for_constraint(key, value) is None:
            continue
        filtered = [
            row for row in filtered
            if evaluate_constraint_against_row(
                {str(field): str(item) for field, item in row.items() if item not in (None, "")},
                key,
                value,
            )
        ]
    return filtered


@dataclass(frozen=True)
class BindingEvent:
    """A non-provider binding event used to resume an existing graph."""

    step_id: str
    variable_ids: tuple[str, ...]
    values: dict[str, list[str]]
    source: str = "user_selection"


@dataclass
class StepExecution:
    step_id: str
    query_id: str
    result: QueryResult
    # A step can try more than one declared proof method.  Keep the actual
    # operation for this attempt rather than attributing every query to the
    # planner's first choice.
    operation_id: str = ""
    outputs: dict[str, list[str]] = field(default_factory=dict)
    inputs: dict[str, list[str]] = field(default_factory=dict)
    status: str = "EXECUTED"
    blocked_reason: str | None = None
    stage_id: str = "narrow"
    removed_retrieval_keys: tuple[str, ...] = ()
    goal_id: str = ""
    observation_class: str = ""
    next_action_reason: str = ""
    proof_result: Any | None = None
    observations: list[Any] = field(default_factory=list)


@dataclass
class SemanticExecutionResult:
    executions: list[StepExecution] = field(default_factory=list)
    query_attempts: list[QueryAttempt] = field(default_factory=list)
    binding_events: list[BindingEvent] = field(default_factory=list)

    variables: dict[str, list[str]] = field(default_factory=dict)
    route_assessments: list[SemanticRouteAssessment] = field(default_factory=list)
    attempts: list[SemanticAttempt] = field(default_factory=list)
    route_exhausted: set[str] = field(default_factory=set)
    unresolved_step_ids: list[str] = field(default_factory=list)
    unresolved_reasons: dict[str, str] = field(default_factory=dict)
    needs_user_decision: bool = False
    # Page-level telemetry is part of the execution audit.  A logical query
    # may contain several native provider requests; collapsing them into one
    # QueryResult hides whether the executor actually reached EOF.
    page_trace: list[dict[str, Any]] = field(default_factory=list)
    continuations: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Every value passed to a later step must retain where it came from.  This
    # makes it impossible for a reporter or provider adapter to silently
    # substitute an unrelated host/account.
    binding_provenance: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    # Candidate bindings may be used for exploratory retrieval, but they are
    # never upgraded to proof.  Keep the warning separate from unresolved
    # steps so a valid downstream search is not silently skipped.
    candidate_input_warnings: dict[str, str] = field(default_factory=dict)
    ambiguous_candidates: dict[str, list[str]] = field(default_factory=dict)
    candidate_groups: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    candidate_census: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    winning_facets: dict[str, str] = field(default_factory=dict)
    agenda: dict[str, Any] = field(default_factory=dict)


class SemanticPlanExecutor:
    """Execute only declared operations in dependency order.

    Native query generation stays in ``adapter.execute_query``.  This class
    supplies logical bindings and extracts only fields declared by the
    operation contract, so output values cannot be invented by the executor.
    """

    def __init__(
        self,
        adapter: Any,
        operations: tuple[ProviderOperation, ...] | list[ProviderOperation],
        proof_engine: Any | None = None,
    ) -> None:
        self.adapter = adapter
        self.operations = {operation.id: operation for operation in operations}
        self.proof_engine = proof_engine

    @staticmethod
    def _typed_entity(value: str, entity_type: str | None) -> Any:
        """Preserve the semantic type at the provider boundary."""
        kind = str(entity_type or "").casefold()
        if kind == "account":
            return Account(username=str(value))
        if kind == "host":
            return Host(name=str(value))
        if kind in {"ip", "ip_address"}:
            return IPAddress(address=str(value))
        if kind == "domain":
            return Domain(name=str(value))
        if kind == "file":
            return File(path=str(value))
        if kind == "process":
            if str(value).isdigit():
                return Process(pid=int(value))
            return value
        # Person and opaque semantic values must remain strings because they
        # are not provider entities until a declared operation resolves them.
        return value

    def execute(
        self,
        plan: LogicalPlan,
        scope: ProviderScope,
        time_window: str,
        initial_variables: dict[str, str | list[str]] | None = None,
        *,
        limit: int = 100,
        variable_types: dict[str, str] | None = None,
        max_pages: int = 8,
        max_bindings: int = 32,
        allow_candidate_inputs: bool = False,
        initial_variable_sources: dict[str, str] | None = None,
        target_cardinality: dict[str, str] | None = None,
        proof_engine: Any | None = None,
        goal_graph: Any | None = None,
    ) -> SemanticExecutionResult:
        var_types = dict(variable_types or {})
        if goal_graph and getattr(goal_graph, "variables", None):
            for v in goal_graph.variables:
                if v.id not in var_types and getattr(v, "entity_type", None):
                    var_types[v.id] = v.entity_type
        variable_types = var_types
        variables: dict[str, list[str]] = {
            key: ([value] if isinstance(value, str) else list(value))
            for key, value in (initial_variables or {}).items()
        }
        trusted_initial_sources = {"request", "user_selection"}
        binding_provenance: dict[str, list[dict[str, str]]] = {
            key: [
                {
                    "value": str(value),
                    "source": (initial_variable_sources or {}).get(key, "request" if initial_variable_sources is None else "caller"),
                    "query_id": "",
                    "status": (
                        "VERIFIED"
                        if (initial_variable_sources or {}).get(key, "request" if initial_variable_sources is None else "caller") in trusted_initial_sources
                        else "CANDIDATE"
                    ),
                }
                for value in values
            ]
            for key, values in variables.items()
        }
        executions: list[StepExecution] = []
        query_attempts: list[QueryAttempt] = []
        binding_events: list[BindingEvent] = []
        semantic_attempts: list[SemanticAttempt] = []
        route_assessments: dict[str, SemanticRouteAssessment] = {}
        route_exhausted: set[str] = set()
        no_progress_signatures: set[str] = set()
        agenda = BoundedAgenda()
        selected_methods = dict(getattr(plan, "selected_method_ids", {}) or {})
        agenda.extend(
            AgendaItem(
                goal_id=(step.advances_goal_ids[0] if step.advances_goal_ids else step.id),
                step_id=step.id,
                operation_id=step.operation_id,
                mode=step.mode,
                depends_on=tuple(step.depends_on),
                cost=float(step.expected_cost or 1),
                proof_method_id=str(selected_methods.get(step.advances_goal_ids[0] if step.advances_goal_ids else "", "")),
                route_id=f"route:{(step.advances_goal_ids[0] if step.advances_goal_ids else step.id)}:{step.operation_id}",
                bindings=tuple(sorted((str(role), str(var)) for role, var in step.input_bindings.items())),
            )
            for step in plan.steps
        )
        remaining = [
            next(step for step in plan.steps if step.id == item.step_id)
            for item in agenda.ordered()
        ]
        unresolved_reasons: dict[str, str] = {}
        candidate_input_warnings: dict[str, str] = {}
        ambiguous_candidates: dict[str, list[str]] = {}
        needs_user_decision = False
        page_trace: list[dict[str, Any]] = []
        continuations: dict[str, dict[str, Any]] = {}
        active_proof_engine = proof_engine if proof_engine is not None else self.proof_engine
        if active_proof_engine is None and goal_graph is not None:
            try:
                from hunting.evidence.proof_engine import ProofEngine
                active_proof_engine = ProofEngine()
            except Exception:
                active_proof_engine = None

        while remaining:
            progress = False
            for step in list(remaining):
                prior = {item.step_id: item for item in executions}
                prebound_outputs = [
                    variable_id
                    for variable_id in step.output_bindings.values()
                    if variables.get(variable_id)
                ]
                if prebound_outputs and len(prebound_outputs) == len(step.output_bindings) and all(
                    all(item.get("status") == "VERIFIED" for item in binding_provenance.get(variable_id, []))
                    for variable_id in prebound_outputs
                ):
                    # A user-selected binding satisfies the value needed by
                    # this step, but it is not provider proof and must not enter
                    # provider query accounting or inherit mutable adapter state.
                    selected_values = {
                        variable_id: list(variables.get(variable_id, []))
                        for variable_id in prebound_outputs
                    }
                    binding_events.append(BindingEvent(
                        step_id=step.id,
                        variable_ids=tuple(prebound_outputs),
                        values=selected_values,
                    ))
                    # Compatibility trace only: engine/controller code excludes
                    # this explicit non-provider event from query accounting.
                    pr = ProofResult(
                        contract_id=f"proof-user-selection-{step.id}",
                        contract_version="1.0.0",
                        evaluator_id="user_selection",
                        evaluator_version="1.0",
                        verified=False,
                        verdict="RETRIEVAL_ONLY",
                        reason_codes=("user_selection_binding",),
                        bindings=tuple((k, str(v[0] if isinstance(v, list) and v else v)) for k, v in selected_values.items()),
                        satisfied_obligations=(),
                        missing_obligations=tuple(step.advances_goal_ids),
                        completeness_satisfied=False,
                        coverage_satisfied=False,
                        diagnostic="Analyst selected a binding to continue; this is not relation proof.",
                    )
                    executions.append(StepExecution(
                        step_id=step.id,
                        query_id=f"user-selection-{step.id}",
                        result=QueryResult(
                            query_id=f"user-selection-{step.id}",
                            outcome=QueryOutcome.UNKNOWN,
                            executed_ok=True,
                            complete=True,
                            rows=[],
                            diagnostic=Diagnostic.UNSUPPORTED_REQUIREMENT,
                        ),
                        operation_id=step.operation_id,
                        outputs=selected_values,
                        status="USER_SELECTED",
                        proof_result=pr,
                        goal_id=next(iter(step.advances_goal_ids), ""),
                    ))
                    agenda.dispatch(step.id)
                    remaining.remove(step)
                    progress = True
                    continue
                completed_binding_steps = {event.step_id for event in binding_events}
                if any(
                    dependency not in prior and dependency not in completed_binding_steps
                    for dependency in step.depends_on
                ):
                    continue
                if getattr(step, "dependency_operator", "AND") == "GATE" and getattr(step, "gate_condition", None):
                    from hunting.planner.gate_evaluator import GateEvaluator
                    runtime_goal_states: dict[str, Any] = {}
                    for prev_step in plan.steps:
                        if prev_step.id in prior:
                            p_exec = prior[prev_step.id]
                            step_verified = (
                                p_exec.status == "EXECUTED"
                                and bool(prev_step.output_bindings)
                                and all(
                                    any(b.get("status") == "VERIFIED" for b in binding_provenance.get(var, []))
                                    for var in prev_step.output_bindings.values()
                                )
                                and not (p_exec.proof_result and p_exec.proof_result.verdict in ("UNPROVEN", "PROOF_GAP"))
                            )
                            is_proved = bool((p_exec.proof_result and p_exec.proof_result.proved) or step_verified)
                            is_executed = p_exec.status in ("EXECUTED", "USER_SELECTED", "COMPLETE_EMPTY")
                            for g_id in prev_step.advances_goal_ids:
                                runtime_goal_states[g_id] = {
                                    "execution_status": "COMPLETED" if is_executed else "FAILED",
                                    "proof_status": "PROVEN" if is_proved else "UNPROVEN",
                                    "coverage_status": "COMPLETE" if (p_exec.result and p_exec.result.complete) else "PARTIAL",
                                }

                    gate_res = GateEvaluator.evaluate(step.gate_condition, runtime_goal_states)
                    if not gate_res.passed:
                        unresolved_reasons[step.id] = f"GATE blocked: {gate_res.reason}"
                        continue
                if step.requires_complete_inputs and any(
                    dependency not in completed_binding_steps
                    and prior[dependency].status != "EXECUTED"
                    for dependency in step.depends_on
                ):
                    unresolved_reasons[step.id] = (
                        "required upstream proof is incomplete: "
                        + ", ".join(
                            dependency for dependency in step.depends_on
                            if dependency not in completed_binding_steps
                            and prior[dependency].status != "EXECUTED"
                        )
                    )
                    continue
                unverified_inputs = [
                    variable_id
                    for variable_id in step.input_bindings.values()
                    if any(
                        item.get("status") != "VERIFIED"
                        for item in binding_provenance.get(variable_id, [])
                    )
                ]
                if unverified_inputs and step.mode == "PROVE":
                    unresolved_reasons[step.id] = (
                        "proof-required downstream step requires verified bindings: "
                        + ", ".join(unverified_inputs)
                    )
                    continue
                if step.requires_complete_inputs and unverified_inputs:
                    warning = (
                        "upstream candidate binding requires explicit user "
                        "selection before this downstream step: "
                        + ", ".join(unverified_inputs)
                    )
                    candidate_input_warnings[step.id] = warning
                    if not allow_candidate_inputs:
                        needs_user_decision = True
                        unresolved_reasons[step.id] = warning
                        continue
                primary_operation = self.operations.get(step.operation_id)
                if primary_operation is None:
                    agenda.dispatch(step.id)
                    remaining.remove(step)
                    unresolved_reasons[step.id] = f"operation '{step.operation_id}' is not declared by the provider"
                    continue
                if step.mode == "DISCRIMINATE" and not tuple(
                    getattr(primary_operation, "discriminator_fields", ()) or ()
                ):
                    unresolved_reasons[step.id] = (
                        "DISCRIMINATE requires declared differentiating evidence on the operation"
                    )
                    remaining.remove(step)
                    continue
                # Restrictions do not block retrieval of the base relation.
                # The adapter may use explicitly declared searchable keys as
                # hints; the engine later checks proof-capable keys before a
                # relation can become SUPPORTED.  This lets valid upstream
                # identity steps run without pretending that a broad result
                # proves device/state/role restrictions.
                bound_values = {
                    parameter: variables.get(variable_id, [])
                    for parameter, variable_id in step.input_bindings.items()
                }
                has_empty_bindings = any(not values for values in bound_values.values())
                is_constraint_grounded = bool(
                    has_empty_bindings
                    and (
                        step.constraints
                        or getattr(step, "constraint_metadata", ())
                        or getattr(step, "constraint_retrieval_terms", ())
                    )
                )
                if has_empty_bindings and not is_constraint_grounded:
                    continue
                accepted = inspect.signature(self.adapter.execute_query).parameters
                input_parameter = next(iter(bound_values), None)
                input_variable_id = step.input_bindings.get(input_parameter, "") if input_parameter else ""
                raw_input_values = list(bound_values.get(input_parameter, [])) if input_parameter else []
                if raw_input_values:
                    entity_values = [
                        self._typed_entity(value, variable_types.get(input_variable_id))
                        for value in raw_input_values
                    ]
                else:
                    entity_values = [None]
                if len(entity_values) > max_bindings:
                    needs_user_decision = True
                    unresolved_reasons[step.id] = (
                        f"ambiguous binding '{input_parameter}' has {len(entity_values)} candidates; "
                        f"fan-out limit is {max_bindings}"
                    )
                    continue

                agenda.dispatch(step.id)
                operation_ids = (primary_operation.id, *step.alternative_operation_ids)
                for operation_index, operation_id in enumerate(operation_ids):
                    operation = self.operations.get(operation_id)
                    if operation is None:
                        continue
                    attempt_step = step if operation_id == step.operation_id else replace(step, operation_id=operation_id)
                    policy_stages = (
                        operation.retrieval_policy.stages
                        if operation.retrieval_policy is not None and operation.retrieval_policy.stages
                        else (RetrievalStage("narrow"),)
                    )
                    max_stage_attempts = (
                        min(len(policy_stages), operation.retrieval_policy.max_attempts)
                        if operation.retrieval_policy is not None
                        else 1
                    )
                    for stage_index, stage in enumerate(policy_stages[:max_stage_attempts]):
                        removed_keys = set(stage.remove_constraint_keys)
                        query_id = f"{plan.id}-{step.id}"
                        if operation_index:
                            query_id += f"-alternative-{operation_index}"
                        if stage_index:
                            query_id += f"-stage-{stage_index + 1}"
                        query = query_plan_from_step(
                            plan,
                            attempt_step,
                            scope,
                            time_window,
                            query_id=query_id,
                            limit=limit,
                            operation=operation,
                            retrieval_stage=stage.stage_id,
                            removed_retrieval_keys=removed_keys,
                        )
                        searchable = {
                            str(key).strip().casefold()
                            for key in operation.searchable_constraints
                        } - removed_keys
                        constraint_terms = [
                            text.split("=", 1)[1].strip()
                            for text in step.constraints
                            if "=" in text
                            and text.split("=", 1)[0].strip().casefold() in searchable
                            and is_literal_telemetry_token(text.split("=", 1)[1].strip())
                        ]
                        retrieval_terms = query.parameters.get("constraint_retrieval_terms", [])
                        if isinstance(retrieval_terms, (list, tuple)):
                            constraint_terms.extend(
                                str(item.get("term", "")).strip()
                                for item in retrieval_terms
                                if isinstance(item, dict)
                                and str(item.get("key", "")).strip().casefold() in searchable
                                and is_literal_telemetry_token(item.get("term", ""))
                            )
                        if constraint_terms:
                            query.parameters["constraint_search_terms"] = list(dict.fromkeys(constraint_terms))
                        else:
                            query.parameters.pop("constraint_search_terms", None)

                        binding_signature = tuple(
                            (key, tuple(str(value) for value in values))
                            for key, values in sorted(bound_values.items())
                        )
                        no_progress_signature = repr((
                            operation.id,
                            operation.runtime_source_id or scope.scope_id,
                            binding_signature,
                            time_window,
                            stage.stage_id,
                        ))
                        if no_progress_signature in no_progress_signatures:
                            continue
                        no_progress_signatures.add(no_progress_signature)

                        candidate_results: list[QueryResult] = []
                        for candidate_index, entity_value in enumerate(entity_values or [None]):
                            page_results: list[QueryResult] = []
                            offset = 0
                            seen_page_signatures: set[tuple[str, ...]] = set()
                            pending_windows: list[str] = [time_window]
                            window_index = 0
                            for page in range(max(1, max_pages)):
                                current_window = pending_windows[min(window_index, len(pending_windows) - 1)]
                                suffix = "" if candidate_index == 0 and page == 0 else f"-binding-{candidate_index + 1}-page-{page + 1}"
                                logical_payload = query.parameters.get("logical_query_plan")
                                if isinstance(logical_payload, dict):
                                    logical_payload["cursor"] = str(offset) if operation.pagination in {"offset", "cursor"} else str(logical_payload.get("cursor") or "")
                                    logical_payload["time_window"] = current_window
                                replay_payload = query.parameters.get("query_replay")
                                if isinstance(replay_payload, dict):
                                    replay_payload["cursor"] = str(offset) if operation.pagination in {"offset", "cursor"} else replay_payload.get("cursor")
                                    replay_payload["time_window"] = current_window
                                kwargs: dict[str, Any] = {
                                    "operation_id": query.operation_id,
                                    "entity": entity_value,
                                    "window": current_window,
                                    "limit": limit,
                                    "query_id": f"{query.id}{suffix}",
                                }
                                if "parameters" in accepted:
                                    kwargs["parameters"] = dict(query.parameters)
                                if "query_intent" in accepted:
                                    kwargs["query_intent"] = dict(query.parameters.get("query_intent", {}))
                                if "offset" in accepted:
                                    kwargs["offset"] = offset
                                if "cursor" in accepted and operation.pagination == "cursor":
                                    kwargs["cursor"] = str(offset)
                                candidate_raw = query.parameters.get("native_query_candidate")
                                if candidate_raw:
                                    from hunting.contracts.hunt import LogicalQueryPlan as _LogicalQueryPlan
                                    from hunting.contracts.native_query import NativeQueryCandidate
                                    from hunting.query_safety.c3_admission import admit_c3_candidate

                                    if isinstance(candidate_raw, NativeQueryCandidate):
                                        candidate = candidate_raw
                                    else:
                                        payload = dict(candidate_raw)
                                        candidate = NativeQueryCandidate(
                                            provider=str(payload.get("provider", plan.provider_id)),
                                            query_text=str(payload.get("query_text", "")),
                                            source_ids=tuple(payload.get("source_ids", ())),
                                            time_window=str(payload.get("time_window", current_window)),
                                            expected_fields=tuple(payload.get("expected_fields", ())),
                                            max_rows=int(payload.get("max_rows", limit) or limit),
                                        )
                                    blocked_plan = (
                                        _LogicalQueryPlan(
                                            id="c3-blocked",
                                            requirement_id="c3-blocked",
                                            provider=plan.provider_id,
                                            scope=scope.scope_id,
                                        )
                                        if query.parameters.get("logical_query_plan")
                                        else None
                                    )
                                    gate = admit_c3_candidate(
                                        candidate,
                                        admitted=True,
                                        deterministic_plan=blocked_plan,
                                        known_sources=(getattr(scope, "scope_id", ""),),
                                        known_fields=tuple(
                                            (query.parameters.get("query_intent") or {}).get("projection_roles") or ()
                                        ),
                                    )
                                    if not gate.accepted:
                                        result_page = QueryResult(
                                            query_id=kwargs["query_id"],
                                            outcome=QueryOutcome.UNKNOWN,
                                            executed_ok=False,
                                            complete=False,
                                            diagnostic=Diagnostic.PARSE_FAILED,
                                            truncation_reason=";".join(gate.reasons),
                                        )
                                        page_results.append(result_page)
                                        page_trace.append({
                                            "step_id": step.id,
                                            "operation_id": operation_id,
                                            "query_id": result_page.query_id,
                                            "c3_rejected": True,
                                            "reasons": list(gate.reasons),
                                        })
                                        break
                                result_page = self.adapter.execute_query(**kwargs)
                                page_results.append(result_page)
                                page_trace.append({
                                    "step_id": step.id,
                                    "operation_id": operation_id,
                                    "stage_id": stage.stage_id,
                                    "removed_retrieval_keys": sorted(removed_keys),
                                    "relaxation": (
                                        "removed_searchable_constraints"
                                        if removed_keys else None
                                    ),
                                    "query_id": result_page.query_id,
                                    "candidate_index": candidate_index,
                                    "page": page + 1,
                                    "offset": offset,
                                    "window": current_window,
                                    "cursor": (
                                        str(offset)
                                        if operation.pagination in {"offset", "cursor"}
                                        else result_page.cursor
                                    ),
                                    "rows": len(result_page.rows or []),
                                    "complete": bool(result_page.complete),
                                    "executed_ok": bool(result_page.executed_ok),
                                    "diagnostic": getattr(result_page.diagnostic, "value", result_page.diagnostic),
                                    "time_split": current_window != time_window,
                                })
                                if not result_page.executed_ok:
                                    break
                                if result_page.complete:
                                    if current_window != time_window and window_index + 1 < len(pending_windows):
                                        window_index += 1
                                        continue
                                    break
                                signature = tuple(str(row) for row in (result_page.rows or ()))
                                if signature and signature in seen_page_signatures:
                                    break
                                seen_page_signatures.add(signature)
                                if operation.pagination in {"offset", "cursor"}:
                                    try:
                                        next_offset = int(result_page.cursor or (offset + len(result_page.rows or [])))
                                    except (TypeError, ValueError):
                                        next_offset = offset + len(result_page.rows or [])
                                    if next_offset <= offset or not result_page.rows:
                                        break
                                    offset = next_offset
                                    continue
                                if current_window == time_window:
                                    halves = split_time_window(current_window)
                                    if halves is None:
                                        break
                                    pending_windows = list(halves)
                                    window_index = 0
                                    continue
                                if window_index + 1 < len(pending_windows):
                                    window_index += 1
                                    continue
                                break

                            if page_results and not page_results[-1].complete and page_results[-1].executed_ok:
                                next_offset = page_results[-1].cursor
                                if next_offset is None:
                                    next_offset = offset + len(page_results[-1].rows or [])
                                try:
                                    safe_offset = int(next_offset)
                                except (TypeError, ValueError):
                                    safe_offset = next_offset
                                continuations[step.id] = {
                                    "operation_id": operation_id,
                                    "stage_id": stage.stage_id,
                                    "candidate_index": candidate_index,
                                    "next_offset": safe_offset,
                                    "pages_attempted": len(page_results),
                                    "reason": "max_pages_or_provider_page_limit_reached",
                                }

                            first_page = page_results[0]
                            candidate_results.append(first_page if len(page_results) == 1 else replace(
                                first_page,
                                query_id=first_page.query_id,
                                rows=[row for item in page_results for row in (item.rows or [])],
                                complete=page_results[-1].complete,
                                cursor=page_results[-1].cursor,
                                row_count=sum(item.row_count for item in page_results),
                            ))

                        first = candidate_results[0]
                        result = first if len(candidate_results) == 1 else replace(
                            first,
                            query_id=query.id,
                            rows=[row for item in candidate_results for row in (item.rows or [])],
                            complete=all(item.complete for item in candidate_results),
                            cursor=None if all(item.complete for item in candidate_results) else first.cursor,
                            row_count=sum(item.row_count for item in candidate_results),
                        )
                        advances_goal = step.advances_goal_ids[0] if step.advances_goal_ids else step.id
                        step_observations = [
                            Observation(
                                id=f"obs-{result.query_id}-{row_index}",
                                provider_scope=scope,
                                cell_id=time_window or getattr(scope, "scope_id", ""),
                                timestamp=str(row.get("_time", row.get("timestamp", ""))) or "1970-01-01T00:00:00Z",
                                epistemic_type=EpistemicType.OBSERVED,
                                native_type=str(row.get("sourcetype", row.get("native_type", ""))),
                                fields=dict(row),
                                raw_event=dict(row.get("raw_event") or row),
                                query_id=result.query_id,
                            )
                            for row_index, row in enumerate(result.rows or ())
                        ]
                        step_goal = None
                        if goal_graph and getattr(goal_graph, "relations", None):
                            for rel in goal_graph.relations:
                                if rel.id in step.advances_goal_ids or rel.id == advances_goal:
                                    step_goal = rel
                                    break
                        if step_goal is None and (step.advances_goal_ids or (active_proof_engine is not None and not step.id.startswith("orphan"))):
                            rel_name = operation.guaranteed_relations[0] if getattr(operation, "guaranteed_relations", None) else (step.relation if step.relation != "observed" else "associated_with")
                            from hunting.contracts.semantic_graph import SemanticRelationGoal
                            step_goal = SemanticRelationGoal(
                                id=step.advances_goal_ids[0] if step.advances_goal_ids else step.id,
                                subject=step.input_bindings.get("subject", "subject"),
                                relation=rel_name,
                                object=step.output_bindings.get("object", "object"),
                            )
                        step_bindings = {k: v[0] if isinstance(v, list) else str(v) for k, v in variables.items() if v}
                        for param, vals in bound_values.items():
                            if vals:
                                step_bindings[param] = vals[0] if isinstance(vals, list) else str(vals)

                        step_pr = None
                        if step_goal is None:
                            if goal_graph is not None or step.id.startswith("orphan"):
                                # Only penalise steps that fail to advance a known goal
                                # when we ARE running under a SemanticGoalGraph or the step
                                # is explicitly an orphan step. For standalone plans
                                # (goal_graph=None) without an explicit proof engine,
                                # step_goal will be None; there is no semantic relation
                                # to prove, so step_pr remains None and binding_status is
                                # determined by the simple proof_mode / constraint-subset rule.
                                step_pr = ProofResult(
                                    evaluator_id="no_graph_goal",
                                    verified=False,
                                    verdict="PROOF_GAP",
                                    reason_codes=("step_not_bound_to_accepted_graph_goal",),
                                    missing_obligations=("accepted_graph_goal",),
                                    diagnostic=(
                                        f"Plan step '{step.id}' does not advance a relation "
                                        "present in the accepted SemanticGoalGraph. Provider "
                                        "operation metadata cannot supply proof semantics."
                                    ),
                                )
                        elif active_proof_engine is not None:
                            try:
                                try:
                                    step_pr = active_proof_engine.evaluate(
                                        goal=step_goal,
                                        operation=operation,
                                        query_result=result,
                                        observations=step_observations,
                                        bindings=step_bindings,
                                        goal_graph=goal_graph,
                                    )
                                except TypeError:
                                    step_pr = active_proof_engine.evaluate(
                                        goal=step_goal,
                                        operation=operation,
                                        query_result=result,
                                        observations=step_observations,
                                        bindings=step_bindings,
                                    )
                            except Exception as exc:
                                step_pr = ProofResult(
                                    evaluator_id="proof_engine_error",
                                    verified=False,
                                    verdict="PROOF_GAP",
                                    reason_codes=("proof_evaluator_error",),
                                    missing_obligations=("successful_proof_evaluation",),
                                    diagnostic=f"proof_evaluator_error:{type(exc).__name__}:{exc}",
                                )

                        semantic_attempts.append(SemanticAttempt(
                            attempt_id=f"attempt-{len(semantic_attempts) + 1}",
                            goal_id=advances_goal,
                            operation_id=operation.id,
                            source_id=operation.runtime_source_id or scope.scope_id,
                            schema_fingerprint=operation.schema_fingerprint,
                            stage_id=stage.stage_id,
                            query_id=result.query_id,
                            result_complete=bool(result.complete),
                            row_count=len(result.rows or []),
                            trigger_reason=(
                                "initial_route"
                                if operation_index == 0 and stage_index == 0
                                else "complete_empty_next_stage"
                                if stage_index > 0
                                else "declared_alternative"
                            ),
                            no_progress_signature=no_progress_signature,
                            alternatives_considered=tuple(step.alternative_operation_ids),
                            negative_evidence_capable=operation.negative_evidence_capable,
                        ))

                        is_empty = not bool(result.rows)
                        attempt_status = (
                            "EXECUTED" if result.executed_ok and result.complete and not is_empty
                            else "COMPLETE_EMPTY" if result.executed_ok and result.complete and is_empty
                            else "PARTIAL" if result.executed_ok and not result.complete
                            else "FAILED"
                        )
                        query_attempts.append(QueryAttempt(
                            query_id=result.query_id,
                            goal_id=advances_goal,
                            step_id=step.id,
                            operation_id=operation.id,
                            input_bindings=dict(bound_values),
                            result=result,
                            status=attempt_status,
                            evidence_eligible=bool(result.executed_ok and not is_empty),
                            proof_eligible=bool(
                                result.executed_ok
                                and result.complete
                                and not is_empty
                                and step_pr is not None
                                and step_pr.proved
                            ),
                            stage_id=stage.stage_id,
                            removed_retrieval_keys=tuple(sorted(removed_keys)),
                        ))

                        if not result.executed_ok or not result.complete or result.rows:
                            break
                    else:
                        # Complete-empty advances only after all declared stages.
                        # Record the executed attempt so audit, queries.json, and reports include it.
                        executions.append(StepExecution(
                            step_id=step.id,
                            query_id=result.query_id,
                            result=result,
                            operation_id=operation_id,
                            outputs={},
                            inputs=bound_values,
                            status="COMPLETE_EMPTY",
                            stage_id=stage.stage_id,
                            removed_retrieval_keys=tuple(sorted(removed_keys)),
                            goal_id=advances_goal,
                            proof_result=step_pr,
                            observations=step_observations,
                        ))
                        continue
                    # A partial result requires continuation. A candidate or a
                    # verified result must be evaluated before another route.
                    if not result.complete or result.rows:
                        pass
                    outputs: dict[str, list[str]] = {}
                    outputs_verified = True
                    ambiguous_output = False
                    incomplete_output = False
                    proven_values: set[str] = set()
                    binding_status = "CANDIDATE"
                    for binding_name, variable_id in step.output_bindings.items():
                        expected_type = variable_types.get(variable_id)
                        declared_type = operation.output_binding_entity_kinds.get(binding_name)
                        if not declared_type:
                            continue
                        if expected_type and not types_are_compatible(expected_type, declared_type):
                            continue
                        fields = tuple(
                            field_name
                            for field_name in operation.output_value_bindings.get(binding_name, ())
                            if native_field_compatible_with_kind(str(field_name), declared_type)
                        )
                        binding_rows = _rows_matching_transform_constraints(result.rows, step, removed_keys)
                        values = []
                        for row in binding_rows:
                            for field_name in fields:
                                value = row.get(field_name)
                                if value not in (None, "", [], {}):
                                    values.append(str(value))
                                    break
                        deduped = list(dict.fromkeys(values))
                        if not deduped:
                            continue
                        # A query can legitimately return many rows, but a
                        # multi-valued entity binding is not a safe decision
                        # for the next graph edge.  Fan-out here used to turn
                        # one broad process result into hundreds of PID
                        # candidates, then launch downstream work for all of
                        # them.  Preserve the rows for audit, but require an
                        var_cardinality = (target_cardinality or {}).get(variable_id, "plural").casefold()
                        is_ambiguous_binding = (
                            (var_cardinality == "singular" and len(deduped) > 1)
                            or (len(deduped) > max_bindings)
                        )
                        if is_ambiguous_binding:
                            if not result.complete:
                                incomplete_output = True
                                needs_user_decision = True
                                reason = (
                                    f"incomplete retrieval for '{variable_id}' has "
                                    f"{len(deduped)} values; census groups from this bag; pagination remains open"
                                )
                                unresolved_reasons[step.id] = reason
                                ambiguous_candidates[variable_id] = list(deduped)
                                binding_provenance.setdefault(variable_id, [])
                                for value in deduped:
                                    binding_provenance[variable_id].append({
                                        "value": str(value),
                                        "source": "query",
                                        "query_id": query.id,
                                        "status": "CANDIDATE",
                                    })
                                executions.append(StepExecution(
                                    step_id=step.id,
                                    query_id=query.id,
                                    result=result,
                                    operation_id=operation_id,
                                    outputs={},
                                    inputs=bound_values,
                                    status="PARTIAL",
                                    blocked_reason=reason,
                                    stage_id=stage.stage_id,
                                    removed_retrieval_keys=tuple(sorted(removed_keys)),
                                    goal_id=advances_goal,
                                    proof_result=step_pr,
                                    observations=step_observations,
                                ))
                                break
                            ambiguous_output = True
                            needs_user_decision = True
                            reason = (
                                f"ambiguous output binding '{variable_id}' has "
                                f"{len(deduped)} candidates for singular slot; auto-binding prohibited"
                                if var_cardinality == "singular" and len(deduped) > 1
                                else (
                                    f"ambiguous output binding '{variable_id}' has "
                                    f"{len(deduped)} candidates; fan-out limit is "
                                    f"{max_bindings}"
                                )
                            )
                            unresolved_reasons[step.id] = reason
                            ambiguous_candidates[variable_id] = list(deduped)
                            binding_provenance.setdefault(variable_id, [])
                            for value in deduped:
                                binding_provenance[variable_id].append({
                                    "value": str(value),
                                    "source": "query",
                                    "query_id": query.id,
                                    "status": "CANDIDATE",
                                })
                            attempted = StepExecution(
                                step_id=step.id,
                                query_id=query.id,
                                result=result,
                                operation_id=operation_id,
                                outputs={},
                                inputs=bound_values,
                                status="AMBIGUOUS",
                                blocked_reason=reason,
                                stage_id=stage.stage_id,
                                removed_retrieval_keys=tuple(sorted(removed_keys)),
                                goal_id=advances_goal,
                                proof_result=step_pr,
                                observations=step_observations,
                            )
                            executions.append(attempted)
                            # Do not run another OR method for the same
                            # ambiguous result.  Alternatives are for a
                            # failed/empty method, not a license to multiply
                            # an already ambiguous candidate set.
                            break
                        variables[variable_id] = deduped
                        outputs[variable_id] = deduped
                        required_constraint_keys = {
                            str(constraint).split("=", 1)[0].split(":", 1)[0].strip().casefold()
                            for constraint in step.constraints
                        }
                        supported_constraint_keys = {
                            str(constraint).strip().casefold()
                            for constraint in operation.supported_constraints
                        }
                        # Proof authority is exclusively the executable
                        # ProofContract evaluator. Provider metadata, complete
                        # retrieval, and returned rows can never substitute for
                        # an affirmative ProofResult.
                        is_proven = bool(step_pr is not None and step_pr.proved)

                        def _constraint_key_supported(req_key: str, supported: set[str]) -> bool:
                            if req_key in supported:
                                return True
                            if any(roles_are_compatible(req_key, s) for s in supported):
                                return True
                            cmd_synonyms = {"cmdline", "command_line", "command", "command_type", "encoding", "encoding_state", "process_name", "image"}
                            if req_key in cmd_synonyms and any(s in cmd_synonyms for s in supported):
                                return True
                            return False

                        all_constraints_supported = all(_constraint_key_supported(k, supported_constraint_keys) for k in required_constraint_keys)

                        proven_values: set[str] = set()
                        if is_proven and step_pr is not None:
                            if step_pr.subject_binding:
                                proven_values.add(step_pr.subject_binding.strip().casefold())
                            if step_pr.object_binding:
                                proven_values.add(step_pr.object_binding.strip().casefold())
                            for b_k, b_v in dict(step_pr.bindings).items():
                                if b_v:
                                    proven_values.add(str(b_v).strip().casefold())

                        # Prioritize proven values in variables output ordering
                        if proven_values:
                            deduped = sorted(deduped, key=lambda v: 0 if str(v).strip().casefold() in proven_values else 1)
                            variables[variable_id] = deduped
                            outputs[variable_id] = deduped

                        # Decouple retrieval from proof: An entity binding is VERIFIED
                        # for downstream query input when the base relation is observed from provider rows
                        # and unambiguous. ProofEngine evaluates constraint restrictions separately
                        # and withholds SUPPORTED.
                        #
                        # Phase 5 rule: When running under a SemanticGoalGraph, secondary constraints
                        # on the target variable (e.g. hardware_form_factor=MacBook) must NOT be
                        # required to be supported by the provider in order to grant a VERIFIED binding
                        # for downstream retrieval. The executor passes allow_candidate_inputs=True
                        # so CANDIDATE bindings can still propagate downstream; ProofEngine later
                        # withholds SUPPORTED if restrictions remain unproven.
                        has_unsatisfied_constraints = bool(step_pr and step_pr.unsatisfied_constraints)
                        all_constraints_satisfied = bool(
                            not required_constraint_keys
                            or goal_graph is not None
                            or (
                                not has_unsatisfied_constraints
                                and (
                                    all_constraints_supported
                                    or (step_pr and any(k in step_pr.satisfied_constraints for k in required_constraint_keys))
                                )
                            )
                        )
                        # Binding status for downstream retrieval gate.
                        # relation_observable + constraints all supported → VERIFIED.
                        # Proof failure (explicit PROOF_GAP from a proof evaluator) → CANDIDATE.
                        # When allow_candidate_inputs=True (goal_graph context), CANDIDATE inputs
                        # are still accepted for downstream steps so retrieval is not blocked.
                        binding_status = (
                            "VERIFIED"
                            if (
                                # EXPLORE and DISCRIMINATE are retrieval
                                # permissions, not proof permissions.  A
                                # provider's relation_observable declaration
                                # cannot silently upgrade either mode.
                                step.mode == "PROVE"
                                and result.complete
                                and (operation.proof_mode == "relation_observable" or is_proven)
                                and all_constraints_satisfied
                                and (
                                    is_proven
                                    or (
                                        step_pr is not None
                                        and not step_pr.missing_obligations
                                        and not has_unsatisfied_constraints
                                        and step_pr.verdict not in ("UNPROVEN", "PROOF_GAP")
                                    )
                                    or (
                                        goal_graph is None
                                        and step.relation == "observed"
                                        and not step.constraints
                                        and not step.id.startswith("orphan")
                                        and not (step_pr and step_pr.verdict in ("UNPROVEN", "PROOF_GAP"))
                                    )
                                )
                            )
                            else "CANDIDATE"
                        )

                        outputs_verified = outputs_verified and binding_status == "VERIFIED"
                        binding_provenance[variable_id] = [
                            {
                                "value": value,
                                "source": step.id,
                                "query_id": query.id,
                                "status": (
                                    "VERIFIED"
                                    if (
                                        binding_status == "VERIFIED"
                                        and (not proven_values or str(value).strip().casefold() in proven_values)
                                    )
                                    else "CANDIDATE"
                                ),
                            }
                            for value in deduped
                        ]

                    if ambiguous_output or incomplete_output:
                        break

                    if input_variable_id and not variables.get(input_variable_id):
                        in_fields: list[str] = []
                        for role_name, field_names in getattr(operation, "native_field_bindings", {}).items():
                            if isinstance(field_names, (list, tuple)):
                                in_fields.extend(str(f) for f in field_names)
                        if not in_fields:
                            raw_input_roles = getattr(operation, "input_roles", ())
                            if isinstance(raw_input_roles, dict):
                                in_fields.extend(str(field_id) for field_id in raw_input_roles.values())
                            else:
                                in_fields.extend(str(field_id) for field_id in raw_input_roles or ())
                        in_values = []
                        for row in result.rows or []:
                            for fn in in_fields:
                                v = row.get(fn)
                                if v not in (None, "", [], {}):
                                    in_values.append(str(v))
                                    break
                        in_deduped = list(dict.fromkeys(in_values))
                        if in_deduped:
                            if proven_values:
                                in_deduped = sorted(in_deduped, key=lambda v: 0 if str(v).strip().casefold() in proven_values else 1)
                            variables[input_variable_id] = in_deduped
                            outputs[input_variable_id] = in_deduped
                            binding_provenance[input_variable_id] = [
                                {
                                    "value": value,
                                    "source": step.id,
                                    "query_id": query.id,
                                    "status": (
                                        "VERIFIED"
                                        if (
                                            binding_status == "VERIFIED"
                                            and (not proven_values or str(value).strip().casefold() in proven_values)
                                        )
                                        else "CANDIDATE"
                                    ),
                                }
                                for value in in_deduped
                            ]

                    status = "EXECUTED" if result.complete else "PARTIAL"
                    attempted = StepExecution(
                        step_id=step.id,
                        query_id=query.id,
                        result=result,
                        operation_id=operation_id,
                        outputs=outputs,
                        inputs=bound_values,
                        status=status,
                        stage_id=stage.stage_id,
                        removed_retrieval_keys=tuple(sorted(removed_keys)),
                        goal_id=advances_goal,
                        proof_result=step_pr,
                        observations=step_observations,
                    )
                    executions.append(attempted)
                    # A complete attempt that produces declared, typed
                    # output proves this OR branch.  A partial result
                    # with rows is also not an invitation to execute a
                    # broader alternative; it needs continuation or
                    # explicit refinement first.
                    if result.executed_ok and (
                        (step.mode in {"EXPLORE", "DISCRIMINATE"} and result.rows)
                        or
                        (result.complete and outputs and outputs_verified)
                        or (not result.complete and result.rows)
                        or (result.complete and not outputs and result.rows)
                    ):
                        break
                    if ambiguous_output or incomplete_output:
                        # The ``break`` above exits the output-binding loop;
                        # this one exits the alternative-operation loop.
                        break
                remaining.remove(step)
                progress = True
            if not progress:
                break

        for step in remaining:
            if step.id not in unresolved_reasons:
                missing = [variable for variable in step.input_bindings.values() if not variables.get(variable)]
                unresolved_reasons[step.id] = (
                    "required typed binding is unavailable: " + ", ".join(missing)
                    if missing else "dependency did not complete"
                )

        attempts_by_goal: dict[str, list[SemanticAttempt]] = {}
        for attempt in semantic_attempts:
            attempts_by_goal.setdefault(attempt.goal_id, []).append(attempt)
        for step in plan.steps:
            goal_ids = (
                step.advances_goal_ids
                or (tuple(plan.unresolved_goal_ids[:1]) if plan.unresolved_goal_ids else ())
                or (step.id,)
            )
            for goal_id in goal_ids:
                attempts = attempts_by_goal.get(goal_id, [])
                proof_complete = any(
                    execution.step_id == step.id
                    and execution.status == "EXECUTED"
                    and bool(
                        execution.proof_result
                        and execution.proof_result.proved
                    )
                    for execution in executions
                )
                execution_complete = False
                user_selected = any(
                    execution.step_id == step.id and execution.status == "USER_SELECTED"
                    for execution in executions
                )
                if user_selected:
                    execution_complete = True
                    status = SemanticRouteStatus.CANDIDATE_OBSERVED
                    readiness = CapabilityReadiness.RETRIEVAL_CAPABLE
                    route_assessments[goal_id] = SemanticRouteAssessment(
                        goal_id=goal_id,
                        relation=step.relation,
                        status=status,
                        execution_complete=True,
                        proof_complete=False,
                        route_exhausted=False,
                        readiness=readiness,
                        attempts=list(attempts),
                        proof_gaps=["relation_or_constraint_proof_missing"],
                        capability_gaps=[],
                    )
                    continue
                if proof_complete:
                    execution_complete = True
                    status = SemanticRouteStatus.VERIFIED
                    readiness = CapabilityReadiness.PROOF_CAPABLE
                elif attempts and any(attempt.row_count for attempt in attempts):
                    execution_complete = all(attempt.result_complete for attempt in attempts)
                    status = (
                        SemanticRouteStatus.CANDIDATE_OBSERVED
                        if execution_complete
                        else SemanticRouteStatus.ATTEMPTED_PARTIAL
                    )
                    readiness = CapabilityReadiness.RETRIEVAL_CAPABLE
                elif attempts:
                    execution_complete = all(attempt.result_complete for attempt in attempts)
                    status = (
                        SemanticRouteStatus.ATTEMPTED_EMPTY
                        if execution_complete
                        else SemanticRouteStatus.ATTEMPTED_PARTIAL
                    )
                    readiness = CapabilityReadiness.RETRIEVAL_CAPABLE
                    # Exhaustion describes the finite declared retrieval route:
                    # - all attempts must be execution_complete (no partials)
                    # - no pending continuations for this step
                    # - all declared alternative operations must have been evaluated
                    # - all stages of the retrieval policy must have been evaluated
                    has_continuation = step.id in continuations
                    declared_ops = [step.operation_id, *step.alternative_operation_ids]
                    attempted_ops = {a.operation_id for a in attempts}
                    has_untried_alternatives = any(
                        op_id not in attempted_ops for op_id in declared_ops if op_id in self.operations
                    )
                    last_op_id = attempts[-1].operation_id if attempts else step.operation_id
                    last_op = self.operations.get(last_op_id)
                    policy_stages = (
                        last_op.retrieval_policy.stages
                        if last_op and last_op.retrieval_policy and last_op.retrieval_policy.stages
                        else ()
                    )
                    attempted_stage_ids = {a.stage_id for a in attempts if a.operation_id == last_op_id}
                    has_untried_stages = any(s.stage_id not in attempted_stage_ids for s in policy_stages)

                    if execution_complete and not has_continuation and not has_untried_alternatives and not has_untried_stages:
                        route_exhausted.add(goal_id)
                else:
                    status = SemanticRouteStatus.CAPABILITY_GAP
                    readiness = CapabilityReadiness.CAPABILITY_GAP
                route_assessments[goal_id] = SemanticRouteAssessment(
                    goal_id=goal_id,
                    relation=step.relation,
                    status=status,
                    execution_complete=execution_complete,
                    proof_complete=proof_complete,
                    route_exhausted=goal_id in route_exhausted,
                    readiness=readiness,
                    attempts=list(attempts),
                    proof_gaps=[] if proof_complete else ["relation_or_constraint_proof_missing"],
                    capability_gaps=[] if attempts else ["no_provider_attempt"],
                )

        for unresolved_goal_id in plan.unresolved_goal_ids:
            if unresolved_goal_id not in route_assessments:
                reason = str((getattr(plan, "unresolved_reasons", {}) or {}).get(unresolved_goal_id, ""))
                if reason == "blocked_on_dependency":
                    route_assessments[unresolved_goal_id] = SemanticRouteAssessment(
                        goal_id=unresolved_goal_id,
                        relation="unresolved",
                        status=SemanticRouteStatus.UNPLANNED,
                        execution_complete=False,
                        proof_complete=False,
                        route_exhausted=False,
                        readiness=CapabilityReadiness.RETRIEVAL_CAPABLE,
                        attempts=[],
                        proof_gaps=["relation_or_constraint_proof_missing"],
                        capability_gaps=["blocked_on_dependency"],
                    )
                    continue
                route_assessments[unresolved_goal_id] = SemanticRouteAssessment(
                    goal_id=unresolved_goal_id,
                    relation="unresolved",
                    status=SemanticRouteStatus.CAPABILITY_GAP,
                    execution_complete=False,
                    proof_complete=False,
                    route_exhausted=False,
                    readiness=CapabilityReadiness.CAPABILITY_GAP,
                    attempts=[],
                    proof_gaps=["relation_or_constraint_proof_missing"],
                    capability_gaps=["no_typed_reachable_route" if reason == "no_typed_reachable_route" else "no_provider_attempt"],
                )

        return SemanticExecutionResult(
            executions=executions,
            query_attempts=query_attempts,
            binding_events=binding_events,
            variables=variables,
            route_assessments=list(route_assessments.values()),
            attempts=semantic_attempts,
            route_exhausted=route_exhausted,
            unresolved_step_ids=[step.id for step in remaining],
            unresolved_reasons=unresolved_reasons,
            needs_user_decision=needs_user_decision,
            binding_provenance=binding_provenance,
            page_trace=page_trace,
            continuations=continuations,
            candidate_input_warnings=candidate_input_warnings,
            ambiguous_candidates=ambiguous_candidates,
            agenda=agenda.to_dict(),
        )


__all__ = ["BindingEvent", "QueryAttempt", "SemanticExecutionResult", "SemanticPlanExecutor", "StepExecution"]
