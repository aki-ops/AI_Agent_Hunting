"""Central ProofEngine and Executable Proof Authority (v9).

Replaces legacy metadata heuristics and ad-hoc verifiers with a single
deterministic authority. Telemetry rows and query results must be evaluated
against approved ProofContracts.

LLM proposals, operation metadata, or query counts alone NEVER grant proof authority.
"""
from __future__ import annotations

from typing import Any

from hunting.contracts.observations import Observation
from hunting.contracts.ontology import canonicalize_relation, proof_contract_id_for_relation
from hunting.contracts.proof_contract import (
    ROLE_INCOMPATIBLE_FIELDS,
    ProofContract,
    ProofResult,
)
from hunting.contracts.queries import ProviderOperation, QueryResult
from hunting.contracts.transforms import evaluate_constraint_against_row
from hunting.evidence.relation_verifier import RelationVerifier
from hunting.registry.proof_contract_registry import (
    ProofContractRegistry,
    get_default_proof_contract_registry,
)


class ProofEngine:
    """Deterministic authority evaluating query results and observations against ProofContracts."""

    def __init__(self, registry: ProofContractRegistry | None = None) -> None:
        self.registry = registry or get_default_proof_contract_registry()

    def evaluate(
        self,
        goal: Any,
        method: Any = None,
        operation: ProviderOperation | None = None,
        observations: list[Observation] | None = None,
        query_result: QueryResult | None = None,
        contract: ProofContract | None = None,
        bindings: dict[str, str] | None = None,
        goal_graph: Any = None,
        **kwargs: Any,
    ) -> ProofResult:
        """Central evaluation function dispatching to approved evaluators.

        Signature:
        evaluate(goal, method, operation, observations, query_result, contract) -> ProofResult
        """
        # 1. Resolve ProofContract only from the accepted semantic graph goal or
        # an explicitly supplied contract. Provider declarations are retrieval
        # metadata and cannot invent a semantic relation or proof contract.
        resolved_contract = contract
        raw_relation = str(getattr(goal, "relation", "") or "").strip()
        graph_relation = canonicalize_relation(raw_relation)
        graph_contract_id = proof_contract_id_for_relation(graph_relation)

        def _contract_matches_graph(candidate: ProofContract | None) -> bool:
            if candidate is None or not graph_relation:
                return candidate is not None
            # A directional ontology alias or canonical relation alias can share
            # the same reviewed proof contract as its canonical relation.
            return (
                candidate.relation == graph_relation
                or candidate.relation == raw_relation.casefold()
                or (graph_contract_id is not None and candidate.contract_id == graph_contract_id)
            )

        if resolved_contract is not None and graph_relation:
            if not _contract_matches_graph(resolved_contract):
                return ProofResult(
                    contract_id=resolved_contract.contract_id,
                    contract_version=resolved_contract.version,
                    evaluator_id="contract_relation_mismatch",
                    evaluator_version=resolved_contract.evaluator_version,
                    verified=False,
                    verdict="PROOF_GAP",
                    reason_codes=("contract_relation_mismatch",),
                    diagnostic=(
                        f"Explicit proof contract relation '{resolved_contract.relation}' "
                        f"does not match accepted graph relation '{graph_relation}'."
                    ),
                    missing_obligations=("accepted_semantic_relation",),
                )
        if resolved_contract is None and graph_relation:
            for candidate in self.registry.list_approved():
                if _contract_matches_graph(candidate):
                    resolved_contract = candidate
                    break

        # If no accepted graph relation or approved contract exists, rows and
        # operation metadata remain retrieval-only.
        if resolved_contract is None:
            rel_name = graph_relation or "unknown"
            return ProofResult(
                contract_id=None,
                contract_version=None,
                evaluator_id="no_contract",
                evaluator_version="1.0",
                verified=False,
                verdict="PROOF_GAP",
                reason_codes=("no_approved_proof_contract",),
                diagnostic=f"no_approved_proof_contract_for_relation:{rel_name}",
                missing_obligations=("accepted_semantic_relation", "approved_proof_contract"),
            )

        if not _contract_matches_graph(resolved_contract):
            return ProofResult(
                contract_id=resolved_contract.contract_id,
                contract_version=resolved_contract.version,
                evaluator_id="contract_relation_mismatch",
                evaluator_version=resolved_contract.evaluator_version,
                verified=False,
                verdict="PROOF_GAP",
                reason_codes=("contract_relation_mismatch",),
                diagnostic=(
                    f"Proof contract relation '{resolved_contract.relation}' does not match "
                    f"accepted graph relation '{graph_relation}'."
                ),
                missing_obligations=("accepted_semantic_relation",),
            )

        if not resolved_contract.is_approved:
            return ProofResult(
                contract_id=resolved_contract.contract_id,
                contract_version=resolved_contract.version,
                evaluator_id="unapproved_contract",
                evaluator_version=resolved_contract.evaluator_version,
                verified=False,
                verdict="PROOF_GAP",
                reason_codes=("contract_not_approved",),
                diagnostic=f"contract_{resolved_contract.contract_id}_is_{resolved_contract.status.value}",
                missing_obligations=("approved_contract_status",),
            )

        # 2. Check Operation proof_mode: retrieval_only cannot grant proof authority
        if operation is not None:
            op_mode = getattr(operation, "proof_mode", "retrieval_only")
            if str(op_mode).strip().casefold() == "retrieval_only":
                return ProofResult(
                    contract_id=resolved_contract.contract_id,
                    contract_version=resolved_contract.version,
                    evaluator_id=resolved_contract.evaluator_id,
                    evaluator_version=resolved_contract.evaluator_version,
                    verified=False,
                    verdict="RETRIEVAL_ONLY",
                    reason_codes=("operation_retrieval_only",),
                    diagnostic=(
                        f"Operation '{getattr(operation, 'id', '')}' declared proof_mode='retrieval_only'. "
                        "Co-occurrence without directional proof capability remains retrieval-only."
                    ),
                    missing_obligations=("proof_capable_operation",),
                )

        # 3. Check QueryResult execution status and completeness
        if query_result is not None:
            if not getattr(query_result, "executed_ok", False):
                return ProofResult(
                    contract_id=resolved_contract.contract_id,
                    contract_version=resolved_contract.version,
                    evaluator_id=resolved_contract.evaluator_id,
                    evaluator_version=resolved_contract.evaluator_version,
                    verified=False,
                    verdict="PROOF_GAP",
                    reason_codes=("query_execution_failed",),
                    diagnostic="Query execution failed; cannot evaluate proof.",
                    missing_obligations=("successful_query_execution",),
                )
            is_complete = bool(getattr(query_result, "complete", False))
            if resolved_contract.min_completeness_required and not is_complete:
                return ProofResult(
                    contract_id=resolved_contract.contract_id,
                    contract_version=resolved_contract.version,
                    evaluator_id=resolved_contract.evaluator_id,
                    evaluator_version=resolved_contract.evaluator_version,
                    verified=False,
                    verdict="PROOF_GAP",
                    reason_codes=("incomplete_query_result",),
                    diagnostic=f"Proof contract '{resolved_contract.contract_id}' requires complete query results.",
                    missing_obligations=("query_completeness",),
                )

        # 4. Extract standardized event rows
        events = self._extract_events(observations=observations, query_result=query_result)

        # If zero events/rows found
        if not events:
            if (
                resolved_contract.negative_evidence_licensed
                and query_result is not None
                and getattr(query_result, "complete", False)
            ):
                return ProofResult(
                    contract_id=resolved_contract.contract_id,
                    contract_version=resolved_contract.version,
                    evaluator_id="evaluate_negative_evidence",
                    evaluator_version=resolved_contract.evaluator_version,
                    verified=True,
                    verdict="REFUTED",
                    reason_codes=("negative_evidence_licensed_absence",),
                    completeness_satisfied=True,
                    coverage_satisfied=True,
                    citations=(query_result.query_id,) if query_result and query_result.query_id else (),
                    diagnostic="Complete query with licensed negative evidence proves absence.",
                )
            return ProofResult(
                contract_id=resolved_contract.contract_id,
                contract_version=resolved_contract.version,
                evaluator_id=resolved_contract.evaluator_id,
                evaluator_version=resolved_contract.evaluator_version,
                verified=False,
                verdict="PROOF_GAP",
                reason_codes=("no_observations_or_rows",),
                diagnostic="Zero events or rows provided to verify proof contract.",
                missing_obligations=("observed_events",),
            )

        # 5. Dispatch to Evaluators
        eval_id = resolved_contract.evaluator_id
        if eval_id == "evaluate_artifact_transition" or resolved_contract.relation in (
            "observed_transition",
            "ransomware_encrypted_file",
            "file_encrypted",
            "encrypted_file",
        ):
            return self._evaluate_artifact_transition(
                goal=goal,
                operation=operation,
                events=events,
                contract=resolved_contract,
                bindings=bindings,
                query_result=query_result,
                goal_graph=goal_graph,
            )
        if eval_id == "evaluate_attribute_lookup" or hasattr(goal, "attribute"):
            return self._evaluate_attribute_lookup(
                goal=goal,
                operation=operation,
                events=events,
                contract=resolved_contract,
                bindings=bindings,
                query_result=query_result,
                goal_graph=goal_graph,
            )

        # Default evaluator: evaluate_observed_relation
        return self._evaluate_observed_relation(
            goal=goal,
            operation=operation,
            events=events,
            contract=resolved_contract,
            bindings=bindings,
            query_result=query_result,
            goal_graph=goal_graph,
        )

    def _extract_events(
        self,
        observations: list[Observation] | None,
        query_result: QueryResult | None,
    ) -> list[dict[str, Any]]:
        """Normalize observations and query rows into a uniform list of event dicts."""
        events: list[dict[str, Any]] = []

        if observations:
            for obs in observations:
                fields: dict[str, str] = {}
                raw = getattr(obs, "raw_event", {}) or {}
                if isinstance(raw, dict):
                    for k, v in raw.items():
                        if v not in (None, "", [], {}):
                            fields[str(k).casefold()] = str(v[0] if isinstance(v, list) else v).strip()
                obs_f = getattr(obs, "fields", {}) or {}
                if isinstance(obs_f, dict):
                    for k, v in obs_f.items():
                        if v not in (None, "", [], {}):
                            fields[str(k).casefold()] = str(v[0] if isinstance(v, list) else v).strip()
                events.append({
                    "citation": obs.id,
                    "fields": fields,
                    "raw_event": raw,
                })

        if not events and query_result and query_result.rows:
            q_id = getattr(query_result, "query_id", "query-result")
            for idx, row in enumerate(query_result.rows):
                if not isinstance(row, dict):
                    continue
                fields = {
                    str(k).casefold(): str(v[0] if isinstance(v, list) else v).strip()
                    for k, v in row.items()
                    if v not in (None, "", [], {})
                }
                events.append({
                    "citation": f"{q_id}-row-{idx}",
                    "fields": fields,
                    "raw_event": row,
                })

        return events

    def _evaluate_observed_relation(
        self,
        goal: Any,
        operation: ProviderOperation | None,
        events: list[dict[str, Any]],
        contract: ProofContract,
        bindings: dict[str, str] | None,
        query_result: QueryResult | None,
        goal_graph: Any = None,
    ) -> ProofResult:
        """Deterministic evaluator for observed relations (visited, logged_on_to, etc.)."""
        # Invariant 1: DNS lookup does not prove web visit
        if contract.relation in ("visited", "person_visited_domain", "visited_domain", "user_accessed_web", "domain_visit"):
            is_dns_only = all(
                "dns" in str(ev["fields"].get("sourcetype", "")).lower()
                or ("query" in ev["fields"] and not any(k in ev["fields"] for k in ("http_method", "uri", "url", "site", "dest_domain")))
                for ev in events
            )
            if is_dns_only:
                return ProofResult(
                    contract_id=contract.contract_id,
                    contract_version=contract.version,
                    evaluator_id="evaluate_observed_relation",
                    evaluator_version=contract.evaluator_version,
                    verified=False,
                    verdict="PROOF_GAP",
                    reason_codes=("dns_only_not_web_visit",),
                    diagnostic="DNS lookup demonstrates domain resolution only; does not prove web visit.",
                    missing_obligations=("web_request_event",),
                )

        # Invariant 2: Generic file creation does not prove ransomware encryption
        if contract.relation in ("ransomware_encrypted_file", "encrypted_file", "file_encrypted"):
            is_generic_creation = all(
                str(ev["fields"].get("eventcode", "")) in ("11", "1", "")
                and not any(k in ev["fields"] for k in ("ransom_note", "encryption_key", "cipher", "original_file_path", "state_transition", "ransom_extension"))
                and not str(ev["fields"].get("action", "")).lower().startswith("encrypt")
                for ev in events
            )
            if is_generic_creation:
                return ProofResult(
                    contract_id=contract.contract_id,
                    contract_version=contract.version,
                    evaluator_id="evaluate_observed_relation",
                    evaluator_version=contract.evaluator_version,
                    verified=False,
                    verdict="PROOF_GAP",
                    reason_codes=("generic_file_creation_not_encryption",),
                    diagnostic="Generic file creation does not prove ransomware encryption without cryptographic proof.",
                    missing_obligations=("encryption_state_transition",),
                )

        # Invariant 3: Domain traffic or resolution does not prove ownership
        if contract.relation in ("owns_domain", "domain_ownership", "registered_domain"):
            is_traffic_only = any(
                any(k in ev["fields"] for k in ("url", "uri", "http_method", "site", "dest_port", "query"))
                and not any(k in ev["fields"] for k in ("registrar", "whois", "registrant", "zone_admin"))
                for ev in events
            )
            if is_traffic_only:
                return ProofResult(
                    contract_id=contract.contract_id,
                    contract_version=contract.version,
                    evaluator_id="evaluate_observed_relation",
                    evaluator_version=contract.evaluator_version,
                    verified=False,
                    verdict="PROOF_GAP",
                    reason_codes=("traffic_only_not_domain_ownership",),
                    diagnostic="Domain traffic does not prove domain ownership without registrar/whois record.",
                    missing_obligations=("registrar_whois_record",),
                )

        # Invariant 4: Email transaction does not prove executive title
        if contract.relation in ("holds_title", "is_role", "organization_title", "is_ceo"):
            is_mail_only = any(
                any(k in ev["fields"] for k in ("sender", "recipient", "subject", "message_id"))
                and not any(k in ev["fields"] for k in ("hr_title", "job_role", "employment_title", "directory_role"))
                for ev in events
            )
            if is_mail_only:
                return ProofResult(
                    contract_id=contract.contract_id,
                    contract_version=contract.version,
                    evaluator_id="evaluate_observed_relation",
                    evaluator_version=contract.evaluator_version,
                    verified=False,
                    verdict="PROOF_GAP",
                    reason_codes=("email_traffic_not_executive_title",),
                    diagnostic="Email transaction does not prove executive title without directory/HR record.",
                    missing_obligations=("directory_title_record",),
                )

        expected_subject = None
        expected_object = None
        if bindings:
            subj_var = getattr(goal, "subject", None)
            obj_var = getattr(goal, "object", None)
            if subj_var and subj_var in bindings:
                expected_subject = bindings[subj_var]
            if obj_var and obj_var in bindings:
                expected_object = bindings[obj_var]

        # Collect required variable constraints from goal_graph or goal
        target_var = None
        subject_var = None
        if goal_graph is not None and hasattr(goal_graph, "variables"):
            subj_id = getattr(goal, "subject", None)
            obj_id = getattr(goal, "object", None)
            for v in goal_graph.variables:
                if v.id == subj_id:
                    subject_var = v
                elif v.id == obj_id:
                    target_var = v

        required_constraints: list[Any] = []
        if subject_var and getattr(subject_var, "constraints", None):
            # Subject restrictions are obligations of this relation only when the subject
            # was not already grounded by an upstream relation in the goal graph.
            is_upstream_grounded = False
            if goal_graph is not None and hasattr(goal_graph, "relations"):
                is_upstream_grounded = any(
                    r.object == subject_var.id and getattr(r, "id", None) != getattr(goal, "id", None)
                    for r in goal_graph.relations
                )
            if not is_upstream_grounded:
                required_constraints.extend(subject_var.constraints)
        if target_var and getattr(target_var, "constraints", None):
            required_constraints.extend(target_var.constraints)
        if hasattr(goal, "constraints") and goal.constraints:
            for c in goal.constraints:
                if c not in required_constraints:
                    required_constraints.append(c)

        all_unsatisfied_constraints: set[str] = set()

        # Scan events for a row that satisfies all required roles and constraints
        all_required_roles = (
            *contract.required_entity_roles,
            *contract.required_value_roles,
            *contract.required_action_roles,
            *contract.required_state_roles,
            *contract.artifact_identity_roles,
        )

        all_missing_obligations: set[str] = set()
        violations: list[str] = []
        conforming_events: list[dict[str, Any]] = []

        for ev in events:
            fields = ev["fields"]
            matched_roles: dict[str, str] = {}
            matched_field_names: dict[str, str] = {}
            event_missing: list[str] = []
            role_swapped_or_incompatible = False

            for role in all_required_roles:
                aliases = RelationVerifier._contract_role_aliases(role)
                incompatible_field_names = ROLE_INCOMPATIBLE_FIELDS.get(role, set())

                matched_k = None
                matched_v = None
                for k, v in fields.items():
                    if k in incompatible_field_names:
                        continue
                    if k in aliases and v:
                        matched_k = k
                        matched_v = v
                        break

                if not matched_k:
                    # Check if scoped subject binding fulfills entity role for targeted queries
                    if role in contract.required_entity_roles and expected_subject:
                        matched_roles[role] = expected_subject
                        matched_field_names[role] = "scoped_subject_binding"
                    else:
                        # Check if there is an incompatible field present that would indicate role swapping
                        for k in fields:
                            if k in incompatible_field_names and k in aliases:
                                role_swapped_or_incompatible = True
                        event_missing.append(role)
                else:
                    matched_roles[role] = matched_v
                    matched_field_names[role] = matched_k

            if role_swapped_or_incompatible:
                violations.append("role_swapped_or_semantically_incompatible")
                continue

            if event_missing:
                all_missing_obligations.update(event_missing)
                continue

            # Check expected subject/object bindings if specified
            entity_val = (
                matched_roles.get(contract.required_entity_roles[0])
                if contract.required_entity_roles
                else None
            )
            value_val = (
                matched_roles.get(contract.required_value_roles[0])
                if contract.required_value_roles
                else None
            )

            if expected_subject is not None and entity_val:
                exp_norm = expected_subject.strip().casefold()
                ent_norm = entity_val.strip().casefold()
                if exp_norm != "?" and exp_norm != ent_norm:
                    violations.append(f"subject_binding_mismatch:expected_{expected_subject}_got_{entity_val}")
                    continue

            if expected_object is not None and value_val:
                exp_norm = expected_object.strip().casefold()
                val_norm = value_val.strip().casefold()
                if exp_norm != "?" and exp_norm != val_norm:
                    violations.append(f"object_binding_mismatch:expected_{expected_object}_got_{value_val}")
                    continue

            # Evaluate required semantic constraints against this event row
            row_satisfied_constraints: list[str] = []
            row_unsatisfied_constraints: list[str] = []
            for c in required_constraints:
                c_key = getattr(c, "key", None) or getattr(c, "type", None)
                if not c_key and isinstance(c, str):
                    if "=" in c:
                        c_key, c_val = c.split("=", 1)
                        c_op = "equals"
                    elif ":" in c:
                        c_key, c_val = c.split(":", 1)
                        c_op = "exists"
                    else:
                        c_key = c
                        c_val = None
                        c_op = "exists"
                    c_terms = ()
                    c_text = c
                else:
                    c_val = getattr(c, "value", None)
                    c_op = getattr(c, "operator", "equals")
                    c_terms = getattr(c, "retrieval_terms", ())
                    c_text = c.text() if hasattr(c, "text") else f"{c_key}={c_val}"

                c_key_str = str(c_key).strip().casefold()
                if evaluate_constraint_against_row(
                    row_fields=fields,
                    constraint_key=c_key_str,
                    constraint_value=c_val,
                    operator=c_op,
                    retrieval_terms=c_terms,
                ):
                    row_satisfied_constraints.append(c_text)
                else:
                    row_unsatisfied_constraints.append(c_text)

            if row_unsatisfied_constraints:
                all_unsatisfied_constraints.update(row_unsatisfied_constraints)
                violations.append(f"unsatisfied_constraints:{','.join(row_unsatisfied_constraints)}")
                continue

            conforming_events.append({
                "citation": ev["citation"],
                "subject": entity_val,
                "object": value_val,
                "roles": matched_roles,
                "field_names": matched_field_names,
                "satisfied_constraints": row_satisfied_constraints,
            })

        if conforming_events:
            primary = conforming_events[0]
            all_citations = tuple(item["citation"] for item in conforming_events)
            all_bindings_dict: dict[str, str] = {}
            for item in conforming_events:
                all_bindings_dict.update(item["roles"])
            for idx, item in enumerate(conforming_events):
                if item["object"]:
                    all_bindings_dict[f"proved_object_{idx}"] = item["object"]
                if item["subject"]:
                    all_bindings_dict[f"proved_subject_{idx}"] = item["subject"]

            all_satisfied_constraints = tuple(dict.fromkeys(
                sc for item in conforming_events for sc in item["satisfied_constraints"]
            ))

            # Found conforming proof rows!
            return ProofResult(
                contract_id=contract.contract_id,
                contract_version=contract.version,
                evaluator_id="evaluate_observed_relation",
                evaluator_version=contract.evaluator_version,
                verified=True,
                verdict="PROVEN",
                reason_codes=("contract_requirements_satisfied",),
                subject_binding=primary["subject"],
                object_binding=primary["object"],
                bindings=tuple(sorted(all_bindings_dict.items())),
                satisfied_obligations=all_required_roles,
                satisfied_constraints=all_satisfied_constraints,
                missing_obligations=(),
                unsatisfied_constraints=(),
                citations=all_citations,
                cited_fields=tuple(sorted(primary["field_names"].items())),
                completeness_satisfied=True,
                coverage_satisfied=True,
                diagnostic=f"Proof established for relation '{contract.relation}' via contract '{contract.contract_id}'.",
            )

        # No event satisfied all obligations and constraints
        reasons = ("non_conforming_rows",)
        if violations:
            reasons = (*reasons, *tuple(violations[:3]))

        return ProofResult(
            contract_id=contract.contract_id,
            contract_version=contract.version,
            evaluator_id="evaluate_observed_relation",
            evaluator_version=contract.evaluator_version,
            verified=False,
            verdict="PROOF_GAP",
            reason_codes=reasons,
            satisfied_obligations=(),
            missing_obligations=tuple(sorted(all_missing_obligations)),
            satisfied_constraints=(),
            unsatisfied_constraints=tuple(sorted(all_unsatisfied_constraints)),
            diagnostic=(
                f"No event conformed to proof contract '{contract.contract_id}'. "
                f"Missing roles: {', '.join(sorted(all_missing_obligations)) or 'none'}; "
                f"Unsatisfied constraints: {', '.join(sorted(all_unsatisfied_constraints)) or 'none'}; "
                f"violations: {violations}"
            ),
        )

    def _evaluate_artifact_transition(
        self,
        goal: Any,
        operation: ProviderOperation | None,
        events: list[dict[str, Any]],
        contract: ProofContract,
        bindings: dict[str, str] | None,
        query_result: QueryResult | None,
        goal_graph: Any = None,
    ) -> ProofResult:
        """Evaluator for state transitions (encryption, rename, file overwrite)."""
        required_actions = contract.required_action_roles or ("action",)
        required_states = contract.required_state_roles or ("before_state", "after_state")

        for ev in events:
            fields = ev["fields"]
            # Reject generic file creation or process execution without state change
            if str(fields.get("eventcode", "")) in ("11", "1") and not any(
                k in fields for k in ("action", "before_state", "after_state", "cipher", "ransom_note")
            ):
                continue

            has_action = any(a in fields for a in required_actions) or "action" in fields
            has_states = any(s in fields for s in required_states) or (
                "original_file_path" in fields and "target_file_path" in fields
            )

            if has_action and (has_states or "cipher" in fields or "ransom_note" in fields):
                return ProofResult(
                    contract_id=contract.contract_id,
                    contract_version=contract.version,
                    evaluator_id="evaluate_artifact_transition",
                    evaluator_version=contract.evaluator_version,
                    verified=True,
                    verdict="PROVEN",
                    reason_codes=("artifact_transition_satisfied",),
                    satisfied_obligations=(*required_actions, *required_states),
                    citations=(ev["citation"],),
                    cited_fields=tuple(sorted(fields.items())),
                    completeness_satisfied=True,
                    coverage_satisfied=True,
                    diagnostic="Artifact state transition verified.",
                )

        has_generic_file_events = any(
            str(ev["fields"].get("eventcode", "")) in ("11", "1") for ev in events
        )
        reasons = (
            ("generic_file_creation_not_encryption", "generic_events_lack_transition_proof")
            if has_generic_file_events
            else ("generic_events_lack_transition_proof",)
        )

        return ProofResult(
            contract_id=contract.contract_id,
            contract_version=contract.version,
            evaluator_id="evaluate_artifact_transition",
            evaluator_version=contract.evaluator_version,
            verified=False,
            verdict="PROOF_GAP",
            reason_codes=reasons,
            missing_obligations=(*required_actions, *required_states),
            diagnostic="Telemetry events lack required action/state transition proof.",
        )

    def _evaluate_attribute_lookup(
        self,
        goal: Any,
        operation: ProviderOperation | None,
        events: list[dict[str, Any]],
        contract: ProofContract,
        bindings: dict[str, str] | None,
        query_result: QueryResult | None,
        goal_graph: Any = None,
    ) -> ProofResult:
        """Evaluator for direct attribute lookup (software version, host IP, user email)."""
        attr_name = getattr(goal, "attribute", None) or "value"
        attr_aliases = RelationVerifier._contract_role_aliases(attr_name)

        for ev in events:
            fields = ev["fields"]
            for k, v in fields.items():
                if (k == attr_name.casefold() or k in attr_aliases) and v:
                    return ProofResult(
                        contract_id=contract.contract_id,
                        contract_version=contract.version,
                        evaluator_id="evaluate_attribute_lookup",
                        evaluator_version=contract.evaluator_version,
                        verified=True,
                        verdict="PROVEN",
                        reason_codes=("attribute_found",),
                        object_binding=v,
                        citations=(ev["citation"],),
                        cited_fields=((k, v),),
                        completeness_satisfied=True,
                        coverage_satisfied=True,
                        diagnostic=f"Attribute '{attr_name}' verified with value '{v}'.",
                    )

        return ProofResult(
            contract_id=contract.contract_id,
            contract_version=contract.version,
            evaluator_id="evaluate_attribute_lookup",
            evaluator_version=contract.evaluator_version,
            verified=False,
            verdict="PROOF_GAP",
            reason_codes=("attribute_not_found",),
            missing_obligations=(attr_name,),
            diagnostic=f"Attribute '{attr_name}' was not found in returned events.",
        )


__all__ = ["ProofEngine"]
