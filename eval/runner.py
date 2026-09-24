"""Benchmark Evaluation Runner executing evaluations across canonical scenarios S01–S15."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from eval.baselines import BaselineRunAccount, BaselineSpec
from eval.layers import LayeredHuntMetrics, layered_metrics_from_execution
from eval.metrics import (
    AnswerMetrics,
    CorrelationMetrics,
    OperationalMetrics,
    PlanningMetrics,
    RetrievalMetrics,
    ScenarioEvaluationResult,
)


class EvaluationRunner:
    """Benchmark runner executing evaluations across canonical scenarios S01–S15."""

    def __init__(
        self,
        scenarios_path: Path | str = "eval/corpus/scenarios.jsonl",
        splits_path: Path | str = "eval/splits.json",
        baseline_specs_path: Path | str = "eval/corpus/baseline_specs.jsonl",
    ) -> None:
        self.scenarios_path = Path(scenarios_path)
        self.splits_path = Path(splits_path)
        self.baseline_specs_path = Path(baseline_specs_path)

    def load_scenarios(self, split: str | None = None) -> list[dict[str, Any]]:
        """Load scenarios from corpus, optionally filtering by split partition."""
        if not self.scenarios_path.exists():
            return []
        scenarios: list[dict[str, Any]] = []
        for line in self.scenarios_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                sc = json.loads(line)
                if split is None or sc.get("split") == split:
                    scenarios.append(sc)
        return scenarios

    def evaluation_envelope(self, scenario: dict[str, Any], adapter: Any | None) -> dict[str, Any]:
        specs = {
            (item.scenario_id, item.mode): item
            for item in self.load_baseline_specs()
        }
        scenario_id = str(scenario.get("scenario_id") or "")
        spec = specs.get((scenario_id, "B0_BASELINE")) or specs.get((scenario_id, "B1_DIRECT_QUERY"))
        temporal = dict(scenario.get("temporal_policy") or {})
        window = ""
        if spec is not None:
            window = spec.time_window
        elif temporal.get("earliest") or temporal.get("latest"):
            window = f"{temporal.get('earliest') or ''}/{temporal.get('latest') or ''}"
        elif temporal.get("relative"):
            window = str(temporal.get("relative"))
        return {
            "request_id": scenario_id,
            "request_text": scenario.get("request_text", ""),
            "time_window": window,
            "provider_id": str(getattr(adapter, "provider_id", "") or (spec.provider_id if spec else "")),
            "budget": dict(scenario.get("budget") or {}),
            "permission_digest": str(getattr(getattr(adapter, "scope", None), "scope_id", "") or ""),
        }

    def execute_candidate_pipeline(
        self,
        scenario: dict[str, Any],
        adapter: Any | None = None,
        configured_adapters: list[Any] | tuple[Any, ...] | None = None,
        content_registry: Any | None = None,
    ) -> Any:
        """Invoke the live candidate HypothesisHuntEngine pipeline directly.

        Enforces Workstream K1: eval/runner.py invokes the actual candidate
        pipeline instead of simulating expected outcomes.
        """
        from hunting.contracts.hunt import HuntRequest, HuntRequestKind, TimePolicy
        from hunting.engine import HypothesisHuntEngine

        kind_str = str(scenario.get("kind", "QUESTION")).upper()
        try:
            kind_enum = HuntRequestKind(kind_str)
        except Exception:
            kind_enum = HuntRequestKind.QUESTION

        temporal = dict(scenario.get("temporal_policy") or {})
        time_policy = None
        if temporal.get("earliest") or temporal.get("latest"):
            time_policy = TimePolicy(start=temporal.get("earliest"), end=temporal.get("latest"))
        hints = list(scenario.get("provider_hints") or [])
        if adapter is not None and getattr(adapter, "provider_id", None):
            hints = hints or [str(adapter.provider_id)]
        request = HuntRequest(
            id=scenario["scenario_id"],
            kind=kind_enum,
            content=scenario.get("request_text", ""),
            time_policy=time_policy,
            provider_hints=hints,
        )
        adapters_list = list(configured_adapters) if configured_adapters else ([adapter] if adapter else [])
        engine = HypothesisHuntEngine(
            configured_adapters=adapters_list,
            content_registry=content_registry,
        )
        return engine.execute_hunt(request, adapter=adapter)

    def load_baseline_specs(self) -> list[BaselineSpec]:
        if not self.baseline_specs_path.exists():
            return []
        specs: list[BaselineSpec] = []
        for line in self.baseline_specs_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                specs.append(BaselineSpec.from_dict(json.loads(line)))
        return specs

    @staticmethod
    def _empty_metrics() -> tuple[PlanningMetrics, RetrievalMetrics, CorrelationMetrics, AnswerMetrics, OperationalMetrics]:
        return (
            PlanningMetrics(claim_precision=0.0, claim_recall=0.0, claim_f1=0.0, unsupported_expansion_rate=1.0),
            RetrievalMetrics(evidence_precision=0.0, evidence_recall_at_k=0.0, completeness_accuracy=0.0),
            CorrelationMetrics(edge_precision=0.0, edge_recall=0.0, edge_f1=0.0, transition_validity=0.0),
            AnswerMetrics(exact_match=0.0, value_f1=0.0, citation_grounding_rate=0.0),
            OperationalMetrics(decision_coverage=0.0, waste_ratio=1.0, mean_time_to_verdict_ms=0.0),
        )

    def execute_baseline(
        self,
        scenario: dict[str, Any],
        mode: str,
        adapter: Any | None,
    ) -> tuple[BaselineRunAccount, Any | None]:
        specs = {
            (item.scenario_id, item.mode): item
            for item in self.load_baseline_specs()
        }
        scenario_id = str(scenario["scenario_id"])
        spec = specs.get((scenario_id, mode))
        query_id = f"baseline-{mode.casefold()}-{scenario_id}"
        if spec is None:
            return BaselineRunAccount(
                scenario_id, mode, "NOT_CONFIGURED", "", "", query_id, "",
                diagnostic="no reviewed baseline spec",
            ), None
        if adapter is None:
            return BaselineRunAccount(
                scenario_id, mode, "NOT_EXECUTED", spec.provider_id, spec.operation_id,
                query_id, spec.time_window, diagnostic="adapter not supplied",
            ), None
        provider_id = str(getattr(adapter, "provider_id", ""))
        if provider_id != spec.provider_id:
            return BaselineRunAccount(
                scenario_id, mode, "NOT_EXECUTED", spec.provider_id, spec.operation_id,
                query_id, spec.time_window,
                diagnostic=f"provider mismatch: expected {spec.provider_id}, got {provider_id}",
            ), None
        operations = getattr(getattr(adapter, "get_capability_descriptor", lambda: None)(), "operations", ())
        if not any(getattr(operation, "id", None) == spec.operation_id for operation in operations):
            return BaselineRunAccount(
                scenario_id, mode, "NOT_EXECUTED", spec.provider_id, spec.operation_id,
                query_id, spec.time_window, diagnostic="operation is not declared by provider",
            ), None
        start = time.perf_counter()
        try:
            result = adapter.execute_query(
                operation_id=spec.operation_id,
                entity=None,
                window=spec.time_window,
                limit=100,
                offset=0,
                query_id=query_id,
                search_terms=list(spec.search_terms),
                parameters={"baseline_mode": mode, "review_status": spec.review_status},
                query_intent={"mode": "EXPLORE", "goal_id": scenario_id},
            )
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            account = BaselineRunAccount(
                scenario_id, mode, "EXECUTED", spec.provider_id, spec.operation_id,
                query_id, spec.time_window,
                row_count=int(getattr(result, "row_count", 0) or len(getattr(result, "rows", None) or [])),
                complete=bool(getattr(result, "complete", False)), elapsed_ms=elapsed_ms,
            )
            return account, result
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return BaselineRunAccount(
                scenario_id, mode, "EXECUTION_FAILED", spec.provider_id, spec.operation_id,
                query_id, spec.time_window, elapsed_ms=elapsed_ms, diagnostic=f"{type(exc).__name__}: {exc}",
            ), None

    def evaluate_scenario(
        self,
        scenario: dict[str, Any],
        mode: str = "CANDIDATE",
        ablation: str | None = None,
        adapter: Any | None = None,
        configured_adapters: list[Any] | tuple[Any, ...] | None = None,
        content_registry: Any | None = None,
    ) -> ScenarioEvaluationResult:
        """Evaluate an individual scenario under the specified architecture mode or ablation."""
        scenario_id = scenario["scenario_id"]
        split = scenario.get("split", "train")
        expected_stop = scenario.get("expected_stopping_decision", "ANSWER_PROVED")
        answer_contract = scenario.get("answer_contract", {})
        gold_values = answer_contract.get("gold_values", [])
        envelope = self.evaluation_envelope(scenario, adapter)
        layers = LayeredHuntMetrics()
        run_account_dict: dict[str, Any] | None = None

        if mode == "CANDIDATE" and adapter is None and not configured_adapters:
            # Candidate metrics require an execution artifact or configured provider.
            # Synthetic predictions are strictly disabled when no provider/fixture is supplied.
            pred_stop = "NOT_EXECUTED"
            pred_answer = None
            planning = PlanningMetrics(claim_precision=0.0, claim_recall=0.0, claim_f1=0.0, unsupported_expansion_rate=1.0)
            retrieval = RetrievalMetrics(evidence_precision=0.0, evidence_recall_at_k=0.0, completeness_accuracy=0.0)
            correlation = CorrelationMetrics(edge_precision=0.0, edge_recall=0.0, edge_f1=0.0, transition_validity=0.0)
            answer = AnswerMetrics(exact_match=0.0, value_f1=0.0, citation_grounding_rate=0.0)
            operations = OperationalMetrics(decision_coverage=0.0, waste_ratio=1.0, mean_time_to_verdict_ms=0.0)
            cost_usd = 0.0
            stop_correct = False
            ans_correct = False
            run_account_dict = {"status": "NOT_EXECUTED", "envelope": dict(envelope)}
            layers = LayeredHuntMetrics(zero_query=True)

        elif mode == "CANDIDATE":
            exec_res = None
            execution_error: str | None = None
            start_t = time.perf_counter()
            try:
                exec_res = self.execute_candidate_pipeline(
                    scenario,
                    adapter=adapter,
                    configured_adapters=configured_adapters,
                    content_registry=content_registry,
                )
            except Exception as exc:
                execution_error = f"{type(exc).__name__}: {exc}"
                exec_res = None
            elapsed_ms = (time.perf_counter() - start_t) * 1000.0

            if exec_res is not None:
                account = getattr(exec_res, "account", exec_res)
                state = getattr(exec_res, "state", None)
                budget = getattr(exec_res, "budget", None)
                if hasattr(account, "account"):
                    account = account.account

                from hunting.contracts.hunt import StoppingDecision

                tax_state = getattr(account, "stopping_taxonomy_state", None) or getattr(account, "taxonomy_state", None)
                if tax_state:
                    pred_stop = tax_state.value if hasattr(tax_state, "value") else str(tax_state)
                else:
                    stop_dec = getattr(account, "stopping_decision", None)
                    if hasattr(stop_dec, "to_taxonomy_state"):
                        pred_stop = stop_dec.to_taxonomy_state().value
                    elif isinstance(stop_dec, str):
                        try:
                            pred_stop = StoppingDecision(stop_dec).to_taxonomy_state().value
                        except ValueError:
                            pred_stop = stop_dec
                    else:
                        pred_stop = str(stop_dec or "")

                raw_val = None
                if hasattr(account, "answer") and isinstance(account.answer, dict):
                    raw_val = account.answer.get("value")
                    if raw_val is None and account.answer.get("candidates"):
                        cand0 = account.answer["candidates"][0]
                        raw_val = cand0.get("value") if isinstance(cand0, dict) else str(cand0)
                if raw_val is None and hasattr(account, "candidate_sets") and account.candidate_sets:
                    for cset in account.candidate_sets.values():
                        valid_cands = getattr(cset, "valid_candidates", ())
                        if valid_cands:
                            raw_val = valid_cands[0].value
                            break
                pred_answer = raw_val

                em = 1.0 if (gold_values and pred_answer in gold_values) or (not gold_values and pred_answer is None) else 0.0
                grounded = 1.0 if bool(getattr(account, "observation_citations", [])) else 0.0
                dec_cov = 1.0 if getattr(account, "stopping_decision", None) is not None else 0.0

                # Real metrics from execution trace & gold annotations
                required_goals = scenario.get("required_goals", []) or []
                query_results = getattr(state, "query_results", []) or []
                cards = getattr(state, "evidence_cards", []) or []
                observations = getattr(state, "observations", []) or []
                cited_obs_ids = set(getattr(account, "observation_citations", []) or [])
                cov = getattr(account, "coverage_bound", None)
                req_cov = getattr(cov, "requirement_coverage", None) if cov else None

                # 1. Planning metrics: evaluated against scenario required_goals
                planned_goals = []
                goal_graph = getattr(account, "semantic_goal_graph", None) or getattr(state, "semantic_goal_graph", None)
                if goal_graph and getattr(goal_graph, "relations", None):
                    planned_goals = list(goal_graph.relations)
                elif account.hypotheses:
                    planned_goals = list(account.hypotheses)

                matched_gold = 0
                matched_plan = 0
                if required_goals and planned_goals:
                    for g in required_goals:
                        g_rel = (g.get("relation") or g.get("attribute") or "").lower()
                        if any(
                            g_rel in str(getattr(p, "relation", getattr(p, "statement", ""))).lower()
                            or str(getattr(p, "relation", getattr(p, "statement", ""))).lower() in g_rel
                            for p in planned_goals
                        ):
                            matched_gold += 1
                    for p in planned_goals:
                        p_rel = str(getattr(p, "relation", getattr(p, "statement", ""))).lower()
                        if any(
                            (g.get("relation") or g.get("attribute") or "").lower() in p_rel
                            or p_rel in (g.get("relation") or g.get("attribute") or "").lower()
                            for g in required_goals
                        ):
                            matched_plan += 1

                if planned_goals:
                    claim_precision = (matched_plan / len(planned_goals)) if required_goals else 1.0
                    unsupported_expansion = ((len(planned_goals) - matched_plan) / len(planned_goals)) if required_goals else 0.0
                else:
                    claim_precision = 1.0 if not required_goals else 0.0
                    unsupported_expansion = 0.0 if not required_goals else 1.0

                if required_goals:
                    claim_recall = matched_gold / len(required_goals)
                else:
                    claim_recall = 1.0

                claim_f1 = (
                    (2 * claim_precision * claim_recall / (claim_precision + claim_recall))
                    if (claim_precision + claim_recall) > 0 else 0.0
                )

                planning = PlanningMetrics(
                    claim_precision=claim_precision,
                    claim_recall=claim_recall,
                    claim_f1=claim_f1,
                    unsupported_expansion_rate=unsupported_expansion,
                )

                # 2. Retrieval metrics: evaluated against cited observations and gold answers
                relevant_obs_ids = set(scenario.get("relevant_observation_ids", []) or [])
                if relevant_obs_ids:
                    # Precision is a labelled retrieval metric: citations that
                    # are not in the independently adjudicated relevant set
                    # must count as noise.  Citation count alone is not a
                    # relevance label.
                    evidence_prec = (
                        len(cited_obs_ids & relevant_obs_ids) / len(cited_obs_ids)
                        if cited_obs_ids else 0.0
                    )
                    evidence_precision_labelled = True
                elif cards:
                    # No independent relevance labels: expose the metric as
                    # unlabelled instead of pretending that selected cards are
                    # relevant merely because they were selected.
                    evidence_prec = 0.0
                    evidence_precision_labelled = False
                else:
                    evidence_prec = 0.0
                    evidence_precision_labelled = bool(relevant_obs_ids)

                found_gold_evidence = False
                if gold_values:
                    for gv in gold_values:
                        gv_str = str(gv).lower()
                        if pred_answer is not None and gv_str in str(pred_answer).lower():
                            found_gold_evidence = True
                            break
                        for c in cards:
                            if any(gv_str in str(v).lower() for v in getattr(c, "field_summary", {}).values()):
                                found_gold_evidence = True
                                break
                        if found_gold_evidence:
                            break
                        for obs in observations:
                            if any(gv_str in str(v).lower() for v in getattr(obs, "fields", {}).values()):
                                found_gold_evidence = True
                                break
                        if found_gold_evidence:
                            break
                    evidence_rec = 1.0 if found_gold_evidence else 0.0
                else:
                    evidence_rec = 1.0 if (pred_answer is None or pred_answer is False or pred_answer == []) else 0.0

                if query_results:
                    comp_queries = sum(
                        1 for qr in query_results
                        if getattr(qr, "executed_ok", False)
                        and getattr(qr, "completeness_contract", "") not in ("TRUNCATED", "FAILED")
                    )
                    completeness = comp_queries / len(query_results)
                    completeness_labelled = True
                elif req_cov:
                    sat_reqs = len(getattr(req_cov, "satisfied_requirements", ()))
                    att_reqs = len(getattr(req_cov, "attempted_requirements", ()))
                    completeness = (sat_reqs / att_reqs) if att_reqs > 0 else 0.0
                    completeness_labelled = True
                else:
                    # A zero-query execution has not demonstrated complete
                    # coverage.  Only an explicit scenario contract may mark
                    # a no-query task as complete.
                    completeness = 1.0 if answer_contract.get("no_query_required") is True else 0.0
                    completeness_labelled = answer_contract.get("no_query_required") is True

                retrieval = RetrievalMetrics(
                    evidence_precision=evidence_prec,
                    evidence_recall_at_k=evidence_rec,
                    completeness_accuracy=completeness,
                    evidence_precision_labelled=evidence_precision_labelled,
                    completeness_labelled=completeness_labelled,
                )

                # 3. Correlation metrics: evaluated against verified causal edges and provenance
                verified_edges = getattr(cov, "causal_path_verified_edges", 0) if cov else 0
                total_edges = getattr(cov, "causal_path_total_edges", 0) if cov else 0
                provenance = getattr(account, "provenance_chain", []) or []
                if not verified_edges and provenance:
                    verified_edges = len(provenance)
                    total_edges = len(provenance)

                gold_req_count = len(required_goals)
                if total_edges > 0:
                    edge_prec = verified_edges / total_edges
                else:
                    edge_prec = 1.0 if gold_req_count == 0 else 0.0

                if gold_req_count > 0:
                    edge_rec = min(1.0, verified_edges / gold_req_count)
                else:
                    edge_rec = 1.0 if verified_edges == 0 else 0.0

                edge_f1 = (
                    (2 * edge_prec * edge_rec / (edge_prec + edge_rec))
                    if (edge_prec + edge_rec) > 0 else 0.0
                )

                if provenance:
                    valid_trans = sum(1 for p in provenance if bool(getattr(p, "citations", None)))
                    trans_val = valid_trans / len(provenance)
                elif verified_edges > 0:
                    trans_val = 1.0
                else:
                    trans_val = 1.0 if gold_req_count == 0 else 0.0

                correlation = CorrelationMetrics(
                    edge_precision=edge_prec,
                    edge_recall=edge_rec,
                    edge_f1=edge_f1,
                    transition_validity=trans_val,
                )

                # 4. Answer metrics
                if em == 1.0:
                    vf1 = 1.0
                elif gold_values and pred_answer is not None:
                    pred_toks = set(str(pred_answer).lower().split())
                    gold_toks = set(str(gold_values[0]).lower().split())
                    ov = len(pred_toks.intersection(gold_toks))
                    if ov > 0:
                        p = ov / len(pred_toks)
                        r = ov / len(gold_toks)
                        vf1 = 2 * p * r / (p + r)
                    else:
                        vf1 = 0.0
                else:
                    vf1 = 0.0

                min_citations = scenario.get("answer_contract", {}).get("min_citations", 0)
                if min_citations > 0:
                    citation_grounding = min(1.0, len(cited_obs_ids) / min_citations)
                else:
                    # No-citation contracts must say so explicitly.  A missing
                    # citation is otherwise a failed grounding measurement,
                    # not a perfect score.
                    citation_grounding = (
                        1.0
                        if answer_contract.get("citation_policy") == "not_required"
                        else grounded
                    )

                answer = AnswerMetrics(
                    exact_match=em,
                    value_f1=vf1,
                    citation_grounding_rate=citation_grounding,
                )

                # 5. Operational metrics & timing from step_trace / elapsed time
                irrelevant_obs_ids = set(scenario.get("irrelevant_observation_ids", []) or [])
                if irrelevant_obs_ids:
                    returned_obs_ids = {
                        str(getattr(obs, "id", "")) for obs in observations
                    }
                    waste = (
                        len(returned_obs_ids & irrelevant_obs_ids) / len(returned_obs_ids)
                        if returned_obs_ids else 0.0
                    )
                    waste_labelled = True
                else:
                    # Empty results are not waste by themselves; they may be a
                    # legitimate negative/branching result.  Without an
                    # independent irrelevant-row label, leave waste at zero
                    # and mark it unlabelled.
                    waste = 0.0
                    waste_labelled = False

                step_trace = getattr(account, "step_trace", None) or getattr(state, "step_trace", None)
                steps = getattr(step_trace, "steps", []) if step_trace else []
                if steps:
                    time_ms = sum(float(getattr(s, "duration_ms", 0.0) or 0.0) for s in steps)
                elif elapsed_ms > 0:
                    time_ms = elapsed_ms
                else:
                    time_ms = 0.0

                operations = OperationalMetrics(
                    decision_coverage=dec_cov,
                    waste_ratio=waste,
                    waste_labelled=waste_labelled,
                    mean_time_to_verdict_ms=time_ms,
                )

                # Cost from budget ledger or actual LLM usage
                if budget and getattr(budget, "total_cost_usd", None) is not None:
                    cost_usd = float(budget.total_cost_usd)
                else:
                    cost_acc = getattr(account, "cost_accounting", {})
                    if isinstance(cost_acc, dict) and "total_cost_usd" in cost_acc:
                        cost_usd = float(cost_acc["total_cost_usd"])
                    elif getattr(account, "llm_usage", None):
                        cost_usd = float(account.llm_usage.get("estimated_cost_usd", 0.0) or 0.0)
                    else:
                        cost_usd = 0.0

                layers = layered_metrics_from_execution(
                    scenario=scenario,
                    account=account,
                    state=state,
                    pred_answer=pred_answer,
                    gold_values=gold_values,
                    pred_stop=pred_stop,
                    elapsed_ms=elapsed_ms,
                    cost_usd=cost_usd,
                    evidence_precision=retrieval.evidence_precision,
                    evidence_precision_labelled=retrieval.evidence_precision_labelled,
                )
                if hasattr(account, "to_dict"):
                    run_account_dict = dict(account.to_dict())
                else:
                    run_account_dict = {
                        "status": "EXECUTED",
                        "stopping_decision": pred_stop,
                        "predicted_answer": pred_answer,
                        "query_count": layers.query_count,
                        "observation_citations": list(getattr(account, "observation_citations", []) or []),
                    }
                run_account_dict["envelope"] = dict(envelope)
                run_account_dict["elapsed_ms"] = elapsed_ms
            else:
                pred_stop = "EXECUTION_ERROR"
                pred_answer = None
                planning = PlanningMetrics(claim_precision=0.0, claim_recall=0.0, claim_f1=0.0, unsupported_expansion_rate=1.0)
                retrieval = RetrievalMetrics(evidence_precision=0.0, evidence_recall_at_k=0.0, completeness_accuracy=0.0)
                correlation = CorrelationMetrics(edge_precision=0.0, edge_recall=0.0, edge_f1=0.0, transition_validity=0.0)
                answer = AnswerMetrics(exact_match=0.0, value_f1=0.0, citation_grounding_rate=0.0)
                operations = OperationalMetrics(decision_coverage=0.0, waste_ratio=1.0, mean_time_to_verdict_ms=0.0)
                # Preserve the failed attempt in the serialized evaluation
                # record.  Unknown provider billing is not silently reported as
                # zero; callers can reconcile it from transport/provider logs.
                cost_usd = 0.0
                run_account_dict = {
                    "status": "EXECUTION_FAILED",
                    "diagnostic": execution_error or "candidate returned no execution account",
                    "elapsed_ms": elapsed_ms,
                    "cost_status": "UNKNOWN",
                    "envelope": dict(envelope),
                }
                layers = LayeredHuntMetrics(cost_usd=0.0, zero_query=True)

            if ablation in {"oracle_graph", "dynamic_mapping_only", "single_shot_query"}:
                raise NotImplementedError(
                    f"Ablation '{ablation}' requires an independent executable replay fixture; "
                    "synthetic metric adjustment is disabled."
                )

            stop_correct = (pred_stop == expected_stop)
            if gold_values:
                ans_correct = (pred_answer in gold_values)
            else:
                ans_correct = (pred_answer is None or pred_answer == gold_values)

        elif mode in {"B0_BASELINE", "B1_DIRECT_QUERY"}:
            run_account, result = self.execute_baseline(scenario, mode, adapter)
            pred_stop = run_account.status
            pred_answer = None
            planning, retrieval, correlation, answer, operations = self._empty_metrics()
            operations = OperationalMetrics(
                decision_coverage=1.0 if run_account.status in {"EXECUTED", "EXECUTION_FAILED"} else 0.0,
                waste_ratio=(1.0 if run_account.status == "EXECUTED" and run_account.row_count == 0 else 0.0),
                mean_time_to_verdict_ms=run_account.elapsed_ms,
            )
            cost_usd = 0.0
            stop_correct = False
            ans_correct = False
            run_account_dict = run_account.to_dict()
            run_account_dict["envelope"] = dict(envelope)
            layers = LayeredHuntMetrics(
                query=1.0 if run_account.status == "EXECUTED" else 0.0,
                query_count=1 if run_account.status == "EXECUTED" else 0,
                zero_query=run_account.status != "EXECUTED",
                time_to_first_query_ms=run_account.elapsed_ms,
                cost_usd=0.0,
                labelled={"proof": False, "retrieve": False, "binding": False, "answer": False},
            )

        else:
            raise ValueError(f"Unknown architecture mode: {mode}")

        return ScenarioEvaluationResult(
            scenario_id=scenario_id,
            split=split,
            architecture_mode=mode,
            predicted_stopping_state=pred_stop,
            expected_stopping_state=expected_stop,
            stopping_state_correct=stop_correct,
            predicted_answer=pred_answer,
            answer_correct=ans_correct,
            planning=planning,
            retrieval=retrieval,
            correlation=correlation,
            answer=answer,
            operations=operations,
            cost_usd=cost_usd,
            run_account=run_account_dict,
            layers=layers,
            envelope=envelope,
        )

    def run_suite(
        self,
        split: str | None = None,
        mode: str = "CANDIDATE",
        ablation: str | None = None,
        adapter: Any | None = None,
        configured_adapters: list[Any] | tuple[Any, ...] | None = None,
        content_registry: Any | None = None,
    ) -> list[ScenarioEvaluationResult]:
        """Execute evaluation suite across loaded scenarios."""
        scenarios = self.load_scenarios(split=split)
        return [
            self.evaluate_scenario(
                sc,
                mode=mode,
                ablation=ablation,
                adapter=adapter,
                configured_adapters=configured_adapters,
                content_registry=content_registry,
            )
            for sc in scenarios
        ]

    def evaluate_matched(
        self,
        scenario: dict[str, Any],
        adapter: Any | None,
        configured_adapters: list[Any] | tuple[Any, ...] | None = None,
        content_registry: Any | None = None,
    ) -> dict[str, Any]:
        """Run B0, B1 and candidate under the same request/permission/window envelope."""
        envelope = self.evaluation_envelope(scenario, adapter)
        candidate = self.evaluate_scenario(
            scenario, mode="CANDIDATE", adapter=adapter,
            configured_adapters=configured_adapters, content_registry=content_registry,
        )
        b0 = self.evaluate_scenario(scenario, mode="B0_BASELINE", adapter=adapter)
        b1 = self.evaluate_scenario(scenario, mode="B1_DIRECT_QUERY", adapter=adapter)
        return {
            "envelope": envelope,
            "CANDIDATE": candidate,
            "B0_BASELINE": b0,
            "B1_DIRECT_QUERY": b1,
        }

    def compute_aggregate_metrics(
        self,
        results: list[ScenarioEvaluationResult],
    ) -> dict[str, Any]:
        """Aggregate layer metrics across evaluation scenario results."""
        if not results:
            return {}
        n = len(results)
        failed_or_abstained = [
            item for item in results
            if str(item.predicted_stopping_state) in {
                "NOT_EXECUTED", "EXECUTION_ERROR", "EXECUTION_FAILED", "NOT_CONFIGURED",
            } or item.layers.abstention >= 1.0 or item.layers.zero_query
        ]
        return {
            "total_scenarios": n,
            "stopping_accuracy": sum(1 for r in results if r.stopping_state_correct) / n,
            "answer_accuracy": sum(1 for r in results if r.answer_correct) / n,
            "wrong_path_rate": sum(1 for r in results if r.layers.wrong_path) / n,
            "zero_query_terminal_rate": sum(1 for r in results if r.layers.zero_query) / n,
            "query_execution_rate": sum(1 for r in results if r.layers.query_count > 0) / n,
            "mean_time_to_first_query_ms": sum(r.layers.time_to_first_query_ms for r in results) / n,
            "mean_time_to_first_evidence_ms": sum(r.layers.time_to_first_evidence_ms for r in results) / n,
            "wrong_binding_rate": sum(1 for r in results if r.layers.wrong_binding) / n,
            "proof_gap_rate": sum(1 for r in results if r.layers.proof_gap) / n,
            "false_proof_rate": sum(1 for r in results if r.layers.false_proof) / n,
            "failed_or_abstained": len(failed_or_abstained),
            "cohort_n": n,
            "planning": {
                "claim_precision": sum(r.planning.claim_precision for r in results) / n,
                "claim_recall": sum(r.planning.claim_recall for r in results) / n,
                "claim_f1": sum(r.planning.claim_f1 for r in results) / n,
                "unsupported_expansion_rate": sum(r.planning.unsupported_expansion_rate for r in results) / n,
            },
            "retrieval": {
                "evidence_precision": sum(r.retrieval.evidence_precision for r in results) / n,
                "evidence_recall_at_k": sum(r.retrieval.evidence_recall_at_k for r in results) / n,
                "completeness_accuracy": sum(r.retrieval.completeness_accuracy for r in results) / n,
                "evidence_precision_labelled_rate": sum(bool(r.retrieval.evidence_precision_labelled) for r in results) / n,
                "completeness_labelled_rate": sum(bool(r.retrieval.completeness_labelled) for r in results) / n,
            },
            "correlation": {
                "edge_precision": sum(r.correlation.edge_precision for r in results) / n,
                "edge_recall": sum(r.correlation.edge_recall for r in results) / n,
                "edge_f1": sum(r.correlation.edge_f1 for r in results) / n,
                "transition_validity": sum(r.correlation.transition_validity for r in results) / n,
            },
            "answer": {
                "exact_match": sum(r.answer.exact_match for r in results) / n,
                "value_f1": sum(r.answer.value_f1 for r in results) / n,
                "citation_grounding_rate": sum(r.answer.citation_grounding_rate for r in results) / n,
            },
            "operations": {
                "decision_coverage": sum(r.operations.decision_coverage for r in results) / n,
                "waste_ratio": sum(r.operations.waste_ratio for r in results) / n,
                "waste_labelled_rate": sum(bool(r.operations.waste_labelled) for r in results) / n,
                "mean_time_to_verdict_ms": sum(r.operations.mean_time_to_verdict_ms for r in results) / n,
            },
            "layers": {
                "request_to_graph": sum(r.layers.request_to_graph for r in results) / n,
                "retrieve": sum(r.layers.retrieve for r in results) / n,
                "query": sum(r.layers.query for r in results) / n,
                "proof": sum(r.layers.proof for r in results) / n,
                "binding": sum(r.layers.binding for r in results) / n,
                "outcome": sum(r.layers.outcome for r in results) / n,
                "abstention": sum(r.layers.abstention for r in results) / n,
            },
            "total_cost_usd": sum(r.cost_usd for r in results),
            "cohort_cost_usd": sum(r.cost_usd for r in results),
        }


__all__ = ["EvaluationRunner"]
