# 10 — THREAT-HUNTING EVOLUTION CHECKLIST

**Date:** 2026-09-20
**Status:** execution tracker; never architecture authority
**Plan:** `09-THREAT-HUNTING-EVOLUTION-PLAN.md`
**Normative architecture:** `01_FINAL-ARCHITECTURE.md`
**Existing migration plan:** `08-EVIDENCE-BASED-REARCHITECTURE-PLAN.md`
**Existing evidence checklist:** `04-IMPLEMENTATION-CHECKLIST.md`

---

## 0. How to execute the complete plan

This file is the single implementation tracker for the evolution defined by `09`. Together, `09` and `10` are sufficient to drive all planned changes; canonical documents are consulted and updated as authority/evidence dependencies, not used as separate competing backlogs.

### 0.1 Required loop for every item

1. Select the first unchecked item whose dependencies are satisfied, following Section 14.
2. Read the named canonical authority and inspect the current production path.
3. If behavior or authority changes, add the failing counterexample before production changes.
4. Implement the smallest default-path vertical slice; do not add scenario/vendor/known-answer branches.
5. Run the tests named by the item plus unit/static and the applicable v9 counterexample suite.
6. For a live claim, run the required non-skipped live acceptance test.
7. Add production, test and run-account evidence to the evidence register or the corresponding `04` entry.
8. Update `01`, `02`, `03` or `08` in the same change when normative architecture, runtime method, scientific basis or migration order changes.
9. Update `04` only when production integration evidence justifies the status.
10. Change the item status here, evaluate the workstream gate, then move to the next dependency-ready item.

If new work is discovered, add it to the appropriate M0–M8 section and dependency position before implementing it. Do not maintain a hidden side plan.

### 0.2 Gate and status authority

- A workstream advances only when its gate passes; isolated lower-section progress does not bypass an earlier dependency.
- `[x]` means implementation completion only, except explicitly labelled document-review `PASS` results in Section 16.
- A blocked item remains `[ ]` or `[~]` and records the blocker; it is never silently skipped.
- A failed test, unavailable live provider or deferred decision remains visible in the evidence record.
- Final completion requires every applicable item in Sections 3–13, all gates M0–M8, Section 15, and the definition of done in `09`.

### 0.3 Dependency matrix

| Workstream | Hard prerequisites | May proceed in parallel | Blocks |
|---|---|---|---|
| Minimum M0 | none | documentation review | M1 production change |
| M1 | minimum M0; contract authority decision where required | broader M0 labels/metrics | M2, M3, optimization/providers |
| M2 | M1 gate | M8 fixtures/measurements for M2 | M3 |
| M3 | M2 gate | M8 controller fixtures | M4–M7 default-path integration |
| M4 | M3 gate | M8 execution/evidence fixtures | M5, M6, M7 |
| M5 | M4 canonical execution/evidence boundary | M6 after its M4 dependencies | M7 reusable promotion, M8 package evaluation |
| M6 | relevant M4 evidence/run-account contracts | M5 | M7 mixed-initiative lifecycle |
| M7 | M4 plus applicable M5/M6 gates | M8 operational metrics | final M8 gate |
| M8 final | M1–M7 applicable gates | fixtures and metrics are continuous | final release |

---

## 1. Status and evidence rules

Use exactly these markers:

- `[ ]` missing, untested or only proposed;
- `[~]` partially implemented, isolated, compatibility-only, shadow mode or lacking production evidence;
- `[x]` integrated into the default production path and proved by automated execution evidence; live claims additionally require non-skipped live tests.

A checklist item is not complete because:

- a class, enum, schema or report section exists;
- a unit test constructs the expected value directly;
- a generated artifact says the feature exists;
- an LLM/provider declaration asserts support;
- an evaluation assigns metrics without executing the candidate and baseline;
- a live test is skipped;
- the feature works only on a legacy/non-default path.

Every `[x]` item must link or name:

1. production integration location;
2. automated counterexample/acceptance test;
3. execution artifact or recomputable run account where applicable;
4. live evidence when the item makes a live-provider claim.

### Evidence register template

This document records gates and current status; detailed production evidence remains in `04`. Any new `[x]` entry must add a row here or a direct pointer to the corresponding `04` evidence entry.

| Item ID | Status | Production evidence | Test/replay evidence | Run artifact | Owner | Blocker/notes |
|---|---|---|---|---|---|---|
| M3.1 agenda contract | `[x]` | `src/hunting/contracts/agenda.py`, `src/hunting/planner/semantic_executor.py` | `tests/unit/test_v9_bounded_agenda.py` | semantic run account records `agenda` | engineering | full hunt resume is still `resume_hunt`/cache, not agenda replay |
| M4.3 EvidenceGraph | `[x]` | `src/hunting/evidence/evidence_graph.py`, `src/hunting/engine.py` semantic analysis | `tests/unit/test_evidence_graph.py`, `tests/unit/test_v9_typed_execution.py` | run account stores `observations` + `evidence_graph` | engineering | identity-reconciliation alternatives remain `[~]` |
| M4 Gate mock/live | `[x]` | `SemanticPlanExecutor` + `query_plan_from_step` | `tests/unit/test_v9_m4_gate.py` | contract parity, not a live Splunk session | engineering | remaining M4 `[~]` items are not gate blockers |
| M6 backend views/RBAC/resume | `[x]` | `InvestigationWorkspace`, `reconstruct_from_run_account`, engine `apply_binding_review` | `tests/unit/test_v9_m6_workspace.py` | `FinalHuntAccount.workspace_snapshot` | engineering | no hunt-workspace UI; usability pilot open; Gate M6 stays open |
| M7 Act/Knowledge | `[x]` | `ActEmitter`, `KnowledgePromotionGate`, registry `promote_knowledge` | `tests/unit/test_v9_m7_act_knowledge.py` | hunt `action_items` / pending candidates | engineering | no auto-promote; reuse-time and analyst-effort metrics remain open |
| M8 layered eval | `[x]` | `eval/layers.py`, `eval/runner.py` `evaluate_matched` | `tests/unit/test_v9_m8_evaluation.py` | S01 CDB B0/B1 + candidate run accounts | engineering | live BOTS v2 unreachable; Gate M8 open |

---

## 2. Current baseline summary

These entries reconcile current documentation and inspected production code. They do not replace `04`.

- `[x]` Core v9 target architecture and authority boundaries are documented. Evidence: `01_FINAL-ARCHITECTURE.md`, `context.md`, and documentation consistency checks recorded in `04` Phase 0.
- `[x]` `SemanticGoalGraph`, `OutcomeContract`, candidate, proof and runtime-state contracts exist. Evidence: production contract modules and tests recorded in `04` Phase 1.
- `[x]` Approved executable ProofEngine is present on the semantic execution path. Evidence: `src/hunting/evidence/proof_engine.py`, semantic executor/engine integration, and tests recorded in `04` Phase 5.
- `[x]` AND/OR/GATE behavior has production integration evidence. Evidence: semantic planner/executor plus `tests/unit/test_v9_graph_semantics.py` and `tests/unit/test_v9_executable_planner_and_gate.py`, as recorded in `04` Phase 3.
- `[x]` `CapabilityQuery` exists and excludes free relation wording from its structural key. Evidence: `src/hunting/contracts/capability_query.py` and `tests/unit/test_v9_capability_query.py`.
- `[x]` F1 retrieves operation, source and field documents with a hashed n-gram dense score plus typed overlap; rank is not relevance. Evidence: `src/hunting/capabilities/semantic_index.py`, `tests/unit/test_v9_capability_matching.py`.
- `[x]` Capability admission can yield an executable admitted route from an F1 typed operation hit without C2. Evidence: `tests/unit/test_v9_open_vocabulary_production.py::test_f1_executable_typed_route_reaches_engine_query_without_c2`.
- `[x]` Production planning is independent of exact/canonical `guaranteed_relations` equality. Evidence: production engine calls `SemanticGoalPlanner.compose(..., legacy_relation_matching=False)`, census `_audit_goal_graph` uses F0/F1 routes, and `tests/unit/test_candidate_routes.py::test_production_planner_does_not_fallback_to_relation_string_matching`.
- `[x]` F1 executable hit reliably creates `QueryIntent` and a recorded query without C2. Evidence: `tests/unit/test_v9_open_vocabulary_production.py::test_f1_executable_typed_route_reaches_engine_query_without_c2`.
- `[x]` C2 is at most one call per unresolved goal over one shortlist in production profiling. Evidence: engine profiles `batches[:1]` and skips C2 when an executable F0/F1 route exists.
- `[x]` Requirements/cache/frontier identity is keyed by `goal_id` rather than relation string on the production cache-put and coverage-manifest paths. Evidence: `_run_pre_routing_source_profiling` cache keys and `coverage_manifests[goal_id]`.
- `[x]` EXPLORE/DISCRIMINATE/PROVE change runtime behavior on the production triad. Evidence: `RecoveryController.choose_next_action` is mode-aware; `tests/unit/test_v9_mode_aware_control.py`.
- `[x]` One bounded production agenda has replaced legacy loops. Evidence: default `execute_semantic_plan` uses `BoundedAgenda`; ClaimGraph/cell/adaptive loops require `enable_legacy_execution=True`. Tests: `tests/unit/test_v9_bounded_agenda.py`.
- `[x]` Production terminal assignments go through `controller.set_stopping_decision` after `evaluate_stop`. Evidence: `test_engine_has_no_direct_stopping_decision_assignment`. Explicit resume may still `clear_stopping_decision`.
- `[x]` Default `QueryIntent` compiles to a recorded `LogicalQueryPlan` and operation-envelope `NativeQueryPlan` without C3. Evidence: `query_plan_from_step`; `tests/unit/test_v9_typed_execution.py`.
- `[x]` EvidenceGraph reconstructs from run-account observations; proximity and multi-provider co-presence stay `NOT_PROOF`. Evidence: `tests/unit/test_v9_typed_execution.py`.
- `[x]` Mock and declared-live adapters share the same planner/graph contracts. Evidence: `tests/unit/test_v9_m4_gate.py::test_mock_and_declared_live_share_planner_and_graph_contracts`.
- `[x]` Approved+fixtured packages compile to F0 routes on the default path without C2/C3; metadata is not proof. Evidence: `tests/unit/test_v9_m5_package_f0.py`.
- `[~]` Executable B0/B1 baseline slice is available for the reviewed S01 CDB fixture; full frozen-corpus coverage remains open. Evidence: `eval/baselines.py`, `eval/corpus/baseline_specs.jsonl`, `tests/unit/test_baseline_runner.py`.
- `[x]` Time-to-first-query/evidence, query-execution and zero-query-stop rates are computed from executed run accounts. Knowledge-reuse operational time remains open. Evidence: `eval/runner.py` `compute_aggregate_metrics`; `tests/unit/test_v9_m8_evaluation.py`.
- `[~]` Analyst investigation workspace backend is on the production run account, including timeline/pivot/native/proof-obligation views, RBAC, binding review and reconstruct-from-account. UI and usability pilot remain open. Evidence: `tests/unit/test_v9_m6_workspace.py`.
- `[x]` Act and durable Knowledge promotion lifecycle is implemented on the control plane. Evidence: hunt emits `no_action` or a cited Act; `promote_knowledge` requires reviewer+tests; LLM/single-run cannot approve. Tests: `tests/unit/test_v9_m7_act_knowledge.py`.

**Current P0 gate:** Gates M1–M5 and M7 remain closed. Gate M6 stays open (no hunt-workspace UI / no usability pilot). Gate M8 is not closed: layered metrics, matched B0/B1/candidate envelope and a non-skipped live probe exist, but Splunk/BOTS v2 is unreachable (`https://localhost:8089` connection refused; `SPLUNK_*` unset) so live readiness is not claimed. Do not optimize SPL or add providers.

**Documentation status:** B1 and the executable portions of B0 are covered by `eval/runner.py` and `tests/unit/test_baseline_runner.py`; B0 analyst review and the independent evaluation gate remain open.

---

## 3. M0 — Objectives, baselines and truth conditions

### M0.1 Scope and workload

- `[ ]` Define primary project objective: research contribution, operational product, or both with separate gates.
- `[ ]` Name the initial analyst/user role and representative tasks.
- `[ ]` Freeze one initial provider and replay workload.
- `[ ]` Define eligible request population and severity/difficulty strata.
- `[ ]` Define correctness, false-proof, decision-coverage, latency, cost and analyst-effort constraints.
- `[ ]` Record explicit stop/rollback thresholds before implementation tuning.

### M0.2 Independent corpus

- `[ ]` Split replay by campaign/tenant/time/schema family, not random event rows.
- `[ ]` Independently label allowed and forbidden semantic goals.
- `[ ]` Independently label relevant observations and admissible proofs.
- `[ ]` Record adjudicator disagreement rather than forcing silent consensus.
- `[ ]` Keep production prompts/code free of gold answers and scenario routes.
- `[ ]` Freeze holdout before additional prompt/rule tuning.

### M0.3 Executable baselines

- `[~]` Implement B0 approved curated query/package plus analyst review. The reviewed CDB baseline spec executes and serializes a run account; independent analyst-review workflow is still open.
- `[x]` Implement B1 simple guarded typed-intent/direct-query path. Evidence: `eval/runner.py`, `eval/corpus/baseline_specs.jsonl`, `tests/unit/test_baseline_runner.py`.
- `[x]` Candidate path invokes the live engine when an adapter is supplied. Evidence: `execute_candidate_pipeline`; `tests/unit/test_v9_m8_evaluation.py`.
- `[ ]` Implement oracle graph replay as a diagnostic ablation.
- `[ ]` Implement oracle mapping replay as a diagnostic ablation.
- `[x]` Ensure candidate and baselines receive the same request, permissions, data, time range and budget. Evidence: `EvaluationRunner.evaluate_matched`; `test_b0_b1_candidate_share_matched_envelope`.
- `[x]` Preserve baseline exceptions, timeouts and failed runs in results instead of collapsing them into silent zeros. Evidence: `tests/unit/test_baseline_runner.py::test_baseline_provider_failure_is_not_collapsed_to_zero_score`.

### M0.4 Metric correctness

- `[x]` Zero-query runs cannot receive perfect completeness by default. Evidence: `tests/unit/test_evaluation_metric_correctness.py::test_zero_query_execution_is_not_complete_by_default`.
- `[x]` Citation grounding cannot default to 1.0 without citations unless the contract explicitly requires none. Evidence: `tests/unit/test_evaluation_metric_correctness.py::test_zero_query_execution_is_not_complete_by_default`.
- `[x]` Evidence precision uses independently labelled relevance, not citation count alone. Evidence: `tests/unit/test_evaluation_metric_correctness.py::test_labelled_evidence_precision_counts_only_relevant_citations`.
- `[x]` Empty-query rate is not used as a proxy for waste. Evidence: candidate evaluation sets waste to unlabelled/zero when no independent irrelevant-row labels exist.
- `[x]` Non-empty irrelevant results count as waste/noise. Evidence: optional `irrelevant_observation_ids` evaluation labels in `eval/runner.py`.
- `[x]` Cohort cost includes failed, abstained and retried runs. Evidence: `compute_aggregate_metrics` `cohort_n` / `failed_or_abstained` / `cohort_cost_usd`; `test_failed_and_abstained_remain_in_cohort_cost`.

### Gate M0

- `[ ]` **Pre-M1 minimum:** capture current candidate behavior on the frozen replay slice before M1 production changes.
- `[ ]` **Pre-M1 minimum:** at least one simple executable baseline emits a serialized run account; do not wait for all M0 metrics or ablations before starting M1.
- `[ ]` At least one simple baseline and the candidate execute on identical replay cases.
- `[ ]` Metrics can be recomputed from serialized run accounts.
- `[ ]` Broader corpus, label and metric work proceeds in parallel with M1 without changing the frozen pre-M1 evidence.

---

## 4. M1 — Executable open-vocabulary capability matching

### M1.1 Counterexamples first

- `[x]` Add failure: vocabulary mismatch + typed executable descriptor currently yields zero query. Evidence: `tests/unit/test_candidate_routes.py::test_goal_bound_executable_route_bypasses_relation_string_matching`.
- `[x]` Add failure: F1 source-only lexical hit incorrectly appears executable. Evidence: `tests/unit/test_v9_capability_matching.py::test_source_identifier_does_not_create_semantic_relevance` and route-class admission tests.
- `[x]` Add failure: zero-score top-k item is treated as relevant. Evidence: `tests/unit/test_v9_capability_matching.py::test_zero_score_shortlist_hit_is_rejected_not_relevant`.
- `[x]` Add failure: deferred C2 incorrectly permits unsupported census completion. Evidence: `tests/unit/test_v9_open_vocabulary_production.py::test_deferred_c2_cannot_complete_unsupported_census`.
- `[x]` Add failure: `NO_LLM_CALLER` incorrectly permits unsupported census completion. Evidence: `tests/unit/test_v9_open_vocabulary_production.py::test_no_llm_caller_cannot_complete_unsupported_census`.
- `[x]` Add failure: two goals sharing relation text collide in requirement/cache state. Evidence: `tests/unit/test_candidate_routes.py::test_route_identity_keeps_same_relation_goals_separate`.
- `[x]` Add failure: runtime proposal grants relation guarantee authority. Evidence: `tests/unit/test_v9_open_vocabulary_production.py::test_runtime_proposal_does_not_grant_relation_guarantee`.
- `[~]` Add failure: semantically equivalent typed answer role is rejected lexically. Entity-typed answer compatibility is covered; synonym and nested-field cases remain open.
- `[x]` Add failure: unrelated nested field passes answer-role admission. Evidence: `tests/unit/test_v9_capability_admission.py::test_admission_rejects_unrelated_nested_answer_field`.

### M1.2 Route identity and contracts

- `[x]` Approve `CandidateRoute` through an architecture decision and update `01`, `02` and `08` as applicable before production code treats it as canonical. Evidence: ADR-20260920-01 in `01_FINAL-ARCHITECTURE.md`.
- `[x]` Add provider-neutral `CandidateRoute` contract after that authority gate. Evidence: `src/hunting/contracts/candidate_route.py` and `tests/unit/test_candidate_routes.py`.
- `[x]` Include `goal_id`, provider/source/operation identity, mappings, mode, frontier stage and provenance.
- `[x]` Add route class: `EXECUTABLE`, `MAPPING_REQUIRED`, `DISCOVERY_ONLY`.
- `[x]` Key the migrated production planner route map by `goal_id`, not relation text. Evidence: `SemanticGoalPlanner.compose(..., candidate_routes=...)`.
- `[x]` Key capability cache by goal signature (`goal_id`-scoped requirement) + provider + source + schema/permission version. Evidence: `_run_pre_routing_source_profiling` cache keys and `tests/unit/test_candidate_routes.py` goal isolation coverage.
- `[x]` Keep relation wording as retrieval context, not identity or proof authority. Evidence: `CapabilityQuery.key` excludes free wording; F1 uses it only as a retrieve feature; planner keys routes by `goal_id`.

### M1.3 F0 and F1

- `[x]` Index approved operations separately from source and field documents. Evidence: `SemanticCapabilityIndex` emits `operation_hits`, source `hits` and `field_hits`. Approved package artifacts remain an M5 F0 path.
- `[x]` F0 emits executable routes only from exact approved-operation / contract labels. Evidence: `tests/unit/test_v9_capability_matching.py::test_f0_exact_label_match_is_executable_without_c2_context`.
- `[x]` F1 retrieves operation, source and field candidates without LLM. Evidence: `SemanticCapabilityIndex.retrieve` and matching tests.
- `[x]` F1 records scores, features, index version and unexamined remainder. Evidence: `CapabilityRetrieval.to_dict()` includes `index_version`, `unexamined_ids` and per-hit features.
- `[x]` F1 applies an explicit relevance/defer policy; top-k alone is not relevance. Evidence: `CapabilityHit.relevant` requires score > 0; `test_zero_score_shortlist_hit_is_rejected_not_relevant`.
- `[x]` F1 executable operation hit can bypass C2. Evidence: `test_f1_executable_typed_route_reaches_engine_query_without_c2`.
- `[x]` F1 source/field-only hit remains mapping-required or discovery-only. Evidence: `test_f1_source_or_field_only_hit_is_not_executable`.
- `[x]` Retrieval rank never changes proof status or licenses negative evidence. Evidence: retrieval `proof` is always false; routes default to `EXPLORE`.

### M1.4 F2 and admission

- `[x]` At most one C2 call is scheduled per unresolved goal over one compact shortlist. Evidence: engine consumes `batches[:1]` and skips C2 after an executable F0/F1 route.
- `[x]` C2 proposal remains untrusted and cannot execute or complete coverage. Evidence: deferred/no-caller census tests; materializer cannot write `guaranteed_relations`.
- `[x]` Deferred, malformed, unavailable and budget-denied C2 states remain explicit. Evidence: `_INCOMPLETE_C2_STATUSES` and `test_deferred_c2_cannot_complete_unsupported_census`.
- `[x]` Admission validates reachable input type and current graph bindings. Evidence: `CapabilityAdmissionGate.evaluate_operation` and `test_operation_admission_requires_reachable_types_and_mapping`.
- `[ ]` Admission validates provider/source reachability, permissions, retention and time overlap.
- `[x]` Admission validates census-backed native fields and declared mappings. Evidence: proposal census-field tests plus `evaluate_operation` mapping/census checks.
- `[x]` Admission validates typed answer/output roles without arbitrary nested-field bypass. Evidence: `test_admission_rejects_unrelated_nested_answer_field`.
- `[x]` Admission assigns EXPLORE unless approved proof contract/evaluator compatibility is present. Evidence: `test_prove_route_requires_an_approved_proof_contract_id`.
- `[~]` Rejected route emits reasons and keeps proof `NOT_ASSESSED`/retrieval-only. Rejection reasons are stored on `CandidateRoute`; a dedicated proof-status counterexample for rejected F1 routes remains thin.

### M1.5 Planner, materialization and execution

- `[x]` `SemanticGoalPlanner` consumes admitted routes by `goal_id`. Evidence: engine integration at the descriptor, active and resumed plan paths plus `tests/unit/test_candidate_routes.py`.
- `[x]` Remove exact/canonical relation equality as the production capability matcher. Evidence: production engine disables the compatibility fallback; the fallback remains opt-in for legacy unit fixtures only.
- `[x]` Runtime materialization carries goal-scoped route identity and keeps mode `EXPLORE`; a C2 proposal no longer writes `guaranteed_relations`. Evidence: `test_runtime_proposal_does_not_grant_relation_guarantee`.
- `[x]` Executable F1 hit emits `QueryIntent(EXPLORE)` without C2. Evidence: production engine test `test_f1_executable_typed_route_reaches_engine_query_without_c2` plus `test_admitted_route_mode_reaches_query_intent`.
- `[x]` Every emitted QueryIntent creates a recorded controller attempt and query audit entry. Evidence: semantic execution records `QueryAttempt`; engine routes each non-user-selected execution through `record_query_execution`, covered by the production F1 engine test and `test_goal_bound_route_reaches_provider_query_without_c2`.
- `[x]` Unknown relations remain retrieval-only until an approved ProofContract exists. Evidence: F1 routes default to `EXPLORE`; runtime ops keep `guaranteed_relations=()` and cannot self-authorize proof.

### M1.6 Coverage and stopping

- `[~]` Goal frontier state records F0/F1/F2 completion independently when profiling runs (`f0_complete` / `f1_complete` / `f2_status`). The executable-F1 early-exit path may skip writing that audit.
- `[~]` `examined` differs from listed, shortlisted, sampled and admitted in coverage manifests; a dedicated metric test is still missing.
- `[x]` C2 deferred cannot set frontier complete. Evidence: `_capability_census_incomplete` and deferred-C2 production test.
- `[x]` F1 skipped/empty-with-unexamined cannot set frontier complete. Evidence: empty-audit and `NO_LLM_CALLER` incomplete-census handling.
- `[~]` Admission failure records rejected routes without claiming unexamined routes absent. Rejection reasons exist on the route; census-complete claims are not asserted from rejected-only state.
- `[x]` `STOP_UNSUPPORTED` requires reachable provider, complete eligible frontier and zero admitted routes. Evidence: engine empty-adapter stop orders UNREACHABLE, then incomplete census, then unsupported.
- `[x]` Deferred/unexamined paths stop inconclusive or budget, never unsupported. Evidence: `test_no_llm_caller_cannot_complete_unsupported_census` and `test_deferred_c2_cannot_complete_unsupported_census`.

### Gate M1

- `[x]` Vocabulary mismatch with executable typed route runs at least one mock-provider query. Evidence: `tests/unit/test_v9_open_vocabulary_production.py::test_f1_executable_typed_route_reaches_engine_query_without_c2`.
- `[x]` F1 executable route works with C2 disabled. Evidence: the same production engine test forbids the C2 caller.
- `[x]` C2 cannot replace F1 or act as proof authority. Evidence: C2 is skipped after an executable F1 route; deferred/no-caller C2 cannot complete an unsupported census; proposals cannot write relation guarantees.
- `[x]` No scenario/vendor alias was added to reasoning code. Evidence: F0/F1 use types, roles, fields and hashed n-grams; no email/Tor/BOTS/scenario branch was added.
- `[x]` Unit, static, v9 counterexample and relevant acceptance tests pass. Evidence: ruff on touched files; 134 v9/engine-related tests including `tests/acceptance/test_v9_acceptance_suite.py`. Live BOTS v2 remains open.

---

## 5. M2 — Runtime EXPLORE, DISCRIMINATE and PROVE

### M2.1 Mode authority

- `[x]` Every QueryIntent mode is explicit; unsafe defaults now resolve to `EXPLORE`, and `PROVE` must be explicitly declared and admitted. Evidence: `src/hunting/contracts/query_intent.py`, `src/hunting/contracts/semantic_graph.py`, `src/hunting/planner/semantic_goal_planner.py`, `tests/unit/test_phase5_typed_query_and_quarantine.py`.
- `[x]` Route admission, not an LLM narrative, selects allowed mode. Evidence: `CapabilityRouteResolver` derives mode from admitted operation metadata.
- `[x]` PROVE requires an approved compatible ProofContract/evaluator. Evidence: routes without `proof_contract_id` are downgraded to `EXPLORE`; `tests/unit/test_candidate_routes.py::test_prove_route_requires_an_approved_proof_contract_id`.
- `[x]` EXPLORE cannot create verified bindings or negative licences. Evidence: `SemanticPlanExecutor` gates binding promotion on `PlanStep.mode == PROVE`; `tests/unit/test_candidate_routes.py::test_goal_bound_route_reaches_provider_query_without_c2`.
- `[x]` DISCRIMINATE can only evaluate declared differentiating evidence. Evidence: resolver downgrades DISCRIMINATE without `discriminator_fields`; executor refuses the step; controller emits `NEEDS_DISAMBIGUATION` unless `declared_discriminator=True`. Tests: `test_discriminate_requires_declared_differentiating_evidence`, `test_discriminate_step_without_declared_fields_does_not_run`.

### M2.2 Controller actions

- `[x]` Candidate + EXPLORE is recorded as candidate evidence (`RECORD_CANDIDATE`) and does not `SEEK_PROOF`. Evidence: `test_explore_candidates_do_not_seek_proof`, `test_explore_attempt_records_candidate_action_on_engine_path`.
- `[x]` Singular ambiguity uses a declared discriminator while budget remains, then user clarification. Evidence: `test_discriminate_requires_declared_differentiating_evidence`, `test_recovery_controller_next_actions`.
- `[x]` Plural candidate outcomes preserve valid candidates within budget. Evidence: `test_plural_candidates_are_not_ambiguous`, `test_population_vertical_slice_preserves_plural_prevalence`.
- `[x]` Candidate + PROVE seeks an approved proof-capable route. Evidence: `test_prove_candidates_seek_approved_proof_route`.
- `[x]` Missing proof contract preserves candidate evidence and explicit limitation. Evidence: `test_missing_proof_contract_preserves_candidates`.
- `[x]` Adjacent exploration does not silently mutate accepted semantic obligations. Evidence: `execute_semantic_plan` snapshots accepted relation obligations; `test_adjacent_explore_does_not_mutate_accepted_obligations`.
- `[x]` Material semantic changes pass graph revision and acceptance. Evidence: `accept_graph_revision` rejects dropped/demoted required relations; `test_material_graph_change_requires_accept_graph_revision`.

### M2.3 Binding safety

- `[x]` Candidate-only input can feed only declared exploration actions. Evidence: `test_candidate_input_can_feed_explore_step`.
- `[x]` Proof-required downstream steps require verified bindings. Evidence: `test_candidate_input_cannot_feed_prove_step`.
- `[x]` Row order, substring, provider order and score cannot bind a singular slot. Evidence: `test_row_order_score_and_substring_cannot_bind_singular`, `test_first_row_is_not_a_verified_singular_bind`. Unique proof may bind one value; ranking may not.
- `[x]` User selection resumes the same accepted graph with immutable provenance. Evidence: `test_user_selection_resumes_same_graph_with_immutable_provenance`.

### Gate M2

- `[x]` Factual vertical slice proves one cited value. Evidence: `test_factual_vertical_slice_proves_one_cited_value` (`execute_semantic_plan` + ProofEngine + `STOP_ANSWERED`).
- `[x]` Hypothesis vertical slice preserves support/refutation/inconclusive distinctions. Evidence: `test_hypothesis_vertical_slice_preserves_verdicts`.
- `[x]` Population vertical slice returns plural candidates, prevalence and coverage without singular coercion. Evidence: `test_population_vertical_slice_preserves_plural_prevalence`; `OutcomeVerifier` population slot includes `prevalence` and `coverage`.
- `[x]` Discovery result remains operationally useful when proof is unavailable. Evidence: `test_discovery_remains_useful_without_proof`.

---

## 6. M3 — One bounded agenda and one stop authority

### M3.1 Agenda contract

- `[x]` Define one agenda item: goal, proof method, route, mode, bindings, envelope, cursor and priority. Evidence: `AgendaItem` plus production `SemanticPlanExecutor` population; `test_agenda_item_carries_route_method_bindings_and_mode`.
- `[x]` Priority uses mandatory status, outcome utility, information gain and bounded cost. Evidence: `AgendaItem.priority_key`; `tests/unit/test_candidate_routes.py` agenda order. Production utility/gain still default to 0 unless populated.
- `[x]` Ranking changes order only; it cannot create authority. Evidence: agenda docstring and executor; proof/stop remain outside the scheduler.
- `[~]` Agenda state is serializable and recorded on the semantic run account; resume of a full hunt solely from that snapshot is still resume_hunt/cache, not agenda replay.

### M3.2 Controller integration

- `[x]` Every production semantic attempt passes `classify()`. Evidence: `execute_semantic_plan` triad; `test_semantic_attempts_pass_classify_and_next_action`.
- `[x]` Every production semantic attempt passes `choose_next_action()`. Evidence: same.
- `[x]` Every terminal decision on the default path passes `evaluate_stop()`. Evidence: `execute_semantic_plan` and engine default early-stops call `RecoveryController.evaluate_stop` then `controller.set_stopping_decision`.
- `[x]` Outcome verifier runs before answered/refuted success. Evidence: `execute_semantic_plan` OutcomeVerifier block; M2 factual/hypothesis slices.
- `[x]` ActionSignature contains goal, method, provider, source, mode, bindings, window, hints and cursor. Evidence: `test_action_signature_includes_method_provider_mode_and_cursor`; production classify loop passes mode/method/provider.
- `[x]` Repetition requires material delta or exhausts the route. Evidence: `test_no_progress_replay_exhausts_route`.

### M3.3 Legacy removal

- `[x]` Isolate ClaimGraph execution from default production. Evidence: `enable_legacy_execution` gate; `test_default_path_does_not_execute_claimgraph_operations`.
- `[x]` Isolate cell/expectation loop from default production. Evidence: cell `while` requires `enable_legacy_execution`.
- `[x]` Isolate adaptive legacy query loop from default production. Evidence: adaptive block requires `enable_legacy_execution`; `test_adaptive_loop.py` sets the flag.
- `[x]` Remove direct `state.stopping_decision` assignments from production engine branches. Evidence: `test_engine_has_no_direct_stopping_decision_assignment`.
- `[~]` `CanonicalActionController.clear_stopping_decision` remains for explicit resume; default hunt does not call legacy `evaluate_stopping`. Evidence: `test_semantic_hunt_does_not_call_legacy_evaluate_stopping`.
- `[x]` Maintain explicit legacy flag only until parity evidence permits deletion. Evidence: `HypothesisHuntEngine(enable_legacy_execution=False)` default.

### Gate M3

- `[x]` Code search finds one default production agenda loop. Evidence: `test_legacy_while_loops_require_explicit_flag`; default work is `SemanticPlanExecutor` `BoundedAgenda`.
- `[x]` Code search finds one terminal-state mutation authority. Evidence: engine assigns stops only via `controller.set_stopping_decision`.
- `[x]` Partial, empty, ambiguous, proof-gap, failure, budget and unreachable cases take distinct tested actions/stops. Evidence: `test_distinct_attempt_classes_keep_distinct_stops` plus existing controller suite.
- `[x]` No-progress replay terminates deterministically. Evidence: `test_no_progress_replay_exhausts_route`.

---

## 7. M4 — Typed execution and EvidenceGraph

### M4.1 Query planning

- `[x]` Stabilize `QueryIntent -> LogicalQueryPlan -> ProviderCompiler -> NativeQuery` on the default semantic path. Evidence: `query_plan_from_step` records intent, `logical_query_plan`, and `compile_operation_envelope` native plan; `test_query_intent_compiles_to_logical_and_native_without_c3`. This is an operation envelope, not invented SPL.
- `[~]` Source/partition and retention are recorded on `LogicalQueryPlan`; no planner yet selects or excludes sources by retention.
- `[~]` Predicates and projection roles are recorded as filters/fields; they are not pushed into provider-native syntax on the default path.
- `[x]` Add join/adjacency planning where provider contracts declare it. Evidence: `adjacency_plan_from_operation` uses only `correlation_roles`; undeclared field names are not joins; adjacency stays `NOT_PROOF`. Tests: `test_declared_correlation_is_adjacency_not_proof`, `test_undeclared_fields_are_not_join_plans`.
- `[x]` Cursor pagination and bounded time splitting on the default semantic path. Evidence: `SemanticPlanExecutor` writes `logical_query_plan.cursor` and splits incomplete windows via `split_time_window`; `test_default_path_paginates_from_logical_cursor`, `test_default_path_time_splits_partial_window`.
- `[x]` Explicit unknown-cost status on the default path. Evidence: `cost_status="unknown"`; `test_query_intent_compiles_to_logical_and_native_without_c3`. No backend estimator was added.
- `[~]` `cancellation_cap` equals the intent row bound and is recorded on replay; live cancellation verification is not claimed.
- `[x]` Preserve native envelope, scope, time and job-id slot on the plan. Evidence: `parameters["query_replay"]`; `test_query_replay_preserves_scope_provider_and_time`. Job ID stays empty until an adapter fills it.

### M4.2 Native proposal quarantine

- `[x]` C3 runs only when deterministic compile cannot produce a plan. Evidence: `should_invoke_c3`; production `c3_invoked` is false after `query_plan_from_step`; `test_query_intent_compiles_to_logical_and_native_without_c3`.
- `[x]` Parse provider syntax before C3 execution. Evidence: `admit_c3_candidate` → `NativeQueryGate`; Splunk live candidate path and semantic executor C3 entry; `test_c3_parse_allowlist_and_bounds_before_mutation`.
- `[x]` Enforce read-only allowlist on C3 SPL. Evidence: forbidden commands such as `delete` are rejected; same test.
- `[x]` Enforce census source, time, row/head and scan-proxy bounds on C3. Evidence: `NativeQueryGate` plus `source_not_in_census`; same test. Tenant/runtime cancellation remains adapter-specific `[~]` below.
- `[x]` Validate output fields/roles against QueryIntent. Evidence: `output_roles_match_intent` + `NativeQueryGate(intent=...)`; `test_c3_gate_rejects_output_roles_outside_intent`.
- `[x]` Reject truncated/malformed model output before state mutation. Evidence: `truncated_model_output` / unbalanced quotes; `test_c3_parse_allowlist_and_bounds_before_mutation`. Default hunts still do not invoke C3 when a logical plan exists.
- `[~]` Tenant isolation and live job cancellation remain adapter-specific; they are not claimed as kernel-verified.

### M4.3 Evidence graph

- `[x]` Define append-only EvidenceGraph nodes/edges from Observation and FieldFact, including run-account reconstruction. Evidence: `EvidenceGraph.from_run_account`; engine writes `observations` + `evidence_graph`; `test_from_run_account_rebuilds_from_observations_not_extra_projection`.
- `[x]` Preserve native field/value, query, provider, timestamp and transformation provenance on the observation node. Evidence: `Observation.to_dict`/`from_dict`; payload now includes `provider_id`; `test_evidence_graph_preserves_native_observation_and_provenance`.
- `[x]` Distinguish observed transition, provenance dependency and causal attribution. Evidence: `EvidenceEdgeClass`; `test_contains_fact_is_provenance_not_transition`; `test_causal_attribution_requires_cited_contract_and_stays_not_proof`.
- `[~]` Preserve contradictory facts and identity alternatives. Observation/fact nodes stay append-only and collision-checked; explicit identity-reconciliation alternatives remain open.
- `[x]` Prevent graph proximity/co-occurrence from granting semantic proof. Every graph edge is `NOT_PROOF`; `test_proximity_does_not_create_causal_attribution` plus `tests/unit/test_evidence_graph.py`.
- `[~]` One graph can hold multi-provider observations under one hunt without treating multiplicity as proof. Evidence: `test_multi_provider_observations_share_graph_without_proof`. Planner multi-provider route selection is still open.

### Gate M4

- `[x]` Same semantic graph executes through mock and declared live provider boundary without reasoning changes. Evidence: `test_mock_and_declared_live_share_planner_and_graph_contracts` runs the same `QueryIntent`/`LogicalQueryPlan`/`EvidenceGraph`/`step_actions` contracts on mock vs declared-live adapters. Not a live Splunk session.
- `[x]` Query replay reproduces scope and provider metadata. Evidence: `test_query_replay_preserves_scope_provider_and_time`.
- `[x]` EvidenceGraph can be reconstructed from immutable run account. Evidence: `test_from_run_account_rebuilds_from_observations_not_extra_projection`.
- `[x]` Cross-source relation proof requires approved correlation/identity obligations. Evidence: causal edges require a contract id and cited observations; proximity/multi-provider tests stay `NOT_PROOF`.

---

## 8. M5 — Reusable content and deterministic fast paths

### M5.1 Registries and lifecycle

- `[x]` Define `CapabilityArtifact` schema. Evidence: `src/hunting/contracts/lifecycle.py`, `tests/unit/test_lifecycle_contracts.py`, and production F0 compile in `src/hunting/registry/package_f0.py`.
- `[x]` Define `HuntPackage` schema. Evidence: lifecycle contract plus `compile_hunt_package` / `test_hunt_package_f0_requires_tests_and_does_not_alias_scenarios`.
- `[x]` Define `AnalyticPackage` schema. Evidence: lifecycle contract plus `compile_analytic_ir` / `test_analytic_ir_applies_named_transform_stages`.
- `[x]` Version all packages and ownership metadata. Evidence: registry identity keys and `package_versions` on `HuntState`/`FinalHuntAccount`.
- `[x]` Define draft, validated, approved, deprecated and revoked states. Evidence: `LifecycleStatus`; draft cannot compile (`test_draft_package_is_not_an_f0_asset`).
- `[x]` Add compatibility and deprecation policy. Evidence: `invalidate_for_drift` for schema/parser/permission and `test_schema_parser_permission_drift_removes_f0_route`.
- `[x]` Keep package registries provider-neutral at the reasoning boundary. Evidence: compiler emits `ProviderOperation` envelopes; native syntax stays behind adapters.

### M5.2 Compilation pipeline

- `[x]` Define provider-neutral analytic internal representation. Evidence: `AnalyticIR` in `src/hunting/registry/package_f0.py`.
- `[x]` Define deterministic data-model/field transformation stages. Evidence: `normalize_roles` / `project_fields` / `apply_constraints`; unknown stages fail closed.
- `[x]` Define backend compiler interface. Evidence: `PackageBackendCompiler.compile` / `compile_intent` emit operation envelopes, not SPL.
- `[x]` Record compiler, schema, parser and package versions in run accounts. Evidence: `state.package_versions` / `account.package_versions` in `test_approved_package_is_f0_route_without_c2_or_c3`.
- `[x]` Make approved packages first-class F0 routes. Evidence: engine merges registry F0 ops into resolver/planner/executor; `frontier_stage == F0_CERTIFIED`.
- `[x]` Ensure package output enters standard Observation/Proof paths. Evidence: F0 hunt mints observations; ProofEngine still requires a contract (`test_package_metadata_cannot_verify_unrelated_or_role_swapped_rows`).

### M5.3 Tests and feedback

- `[x]` Every approved artifact has positive and negative fixtures. Evidence: `VersionedContentRegistry.transition` to APPROVED requires named fixtures.
- `[x]` Every proof-capable artifact has unrelated-row and role-swap fixtures. Evidence: `test_proof_capable_artifact_requires_unrelated_row_and_role_swap`.
- `[x]` Every artifact declares completeness and known limitations. Evidence: approve rejects missing completeness/limitations.
- `[x]` Schema/permission/parser drift invalidates or re-reviews affected artifacts. Evidence: `test_schema_parser_permission_drift_removes_f0_route`.
- `[x]` Analyst false-positive/content-defect feedback is retained and triaged. Evidence: `test_false_positive_feedback_is_retained_and_not_auto_revoking`.

### Gate M5

- `[x]` Approved fast path runs with zero C2/C3 calls. Evidence: `test_approved_package_is_f0_route_without_c2_or_c3`.
- `[x]` Fast path is measurably faster or cheaper without violating quality/coverage constraints. Evidence: `test_f0_package_path_is_cheaper_than_c2_mapping_path` (C2 LLM-call count, not SPL).
- `[x]` Package metadata alone cannot verify an incident relation. Evidence: `test_package_metadata_cannot_verify_unrelated_or_role_swapped_rows`; LLM/single-run cannot approve (`test_llm_cannot_approve_content`, `test_hunt_does_not_auto_approve_draft_package`).

---

## 9. M6 — Analyst investigation workspace

### M6.1 Evidence experience

- `[x]` Timeline view over native observations. Evidence: production `WorkspaceSnapshot.timeline` plus `reconstruct_from_run_account`; `tests/unit/test_v9_m6_workspace.py`. No analyst UI.
- `[x]` Entity/event pivot with provenance. Evidence: `WorkspaceSnapshot.entity_pivot` rebuilt from observations; `test_reconstruct_builds_timeline_pivot_native_and_proof_without_hand_edited_json`.
- `[x]` SemanticGoalGraph and EvidenceGraph shown separately. Evidence: workspace snapshot keeps `goal_graph` and `evidence_graph` distinct; `tests/unit/test_v9_m6_workspace.py`.
- `[x]` Native event and transformation viewer. Evidence: `WorkspaceSnapshot.native_events` on the production account; reconstruct test. No analyst UI.
- `[x]` Query, completeness and coverage view. Evidence: `query_audit` + `coverage_view` on the production snapshot; `test_reconstruct_and_resume_preserve_workspace_without_second_c1`. No analyst UI.
- `[x]` Proof obligations, satisfied/missing conditions and limitations view. Evidence: `WorkspaceSnapshot.proof_obligations` and `limitations`; reconstruct test. No analyst UI.
- `[x]` Unexamined routes/sources are visible. Evidence: `WorkspaceSnapshot.unexamined_routes` on the production account.

### M6.2 Collaboration and decisions

- `[x]` Tags, annotations, comments and saved searches. Evidence: allowed workspace kinds plus production snapshot fields; `test_workspace_annotations_do_not_mutate_goal_evidence_proof_budget_or_stop`.
- `[x]` Candidate/binding review action. Evidence: typed `BindingReview` + engine `apply_binding_review`; never auto-selects an empty/ambiguous singular set; `test_viewer_cannot_write_and_binding_review_is_explicit`.
- `[x]` Analyst decisions are immutable, timestamped and cited. Evidence: `append_decision` uniqueness/citation checks; snapshot on `FinalHuntAccount`.
- `[x]` Resume uses the same accepted graph/run state. Evidence: `apply_binding_review` calls `resume_hunt` without a second C1; observations/graph id preserved; `test_reconstruct_and_resume_preserve_workspace_without_second_c1`.
- `[x]` Role-based permissions protect evidence and decisions. Evidence: `WorkspaceRole` viewer/analyst/reviewer + `WORKSPACE_PERMISSIONS`; viewers cannot annotate; machine actors cannot receive analyst/reviewer roles or record decisions.
- `[x]` Workspace text is treated as untrusted data, not agent instructions. Evidence: prompt-injection annotation does not mutate goal/proof/stop/budget.

### Gate M6

- `[~]` Analyst can explain why every query ran and why the system stopped. Backend `query_audit` and `stop_explanation` are on the run account; there is no analyst UI.
- `[x]` Analyst can resolve an allowed ambiguity without a second C1 compile. Evidence: `test_reconstruct_and_resume_preserve_workspace_without_second_c1`.
- `[x]` Resumed hunt preserves evidence, bindings, scope, budgets and decision provenance. Evidence: same test; workspace events survive resume via matching `run_id`.
- `[ ]` Usability pilot measures correction time and total analyst effort.

Gate M6 remains **open**: production-path contracts and tests exist, but this repo has no hunt-workspace UI and no usability pilot.

---

## 10. M7 — Act and Knowledge

### M7.1 Act outputs

- `[x]` Detection candidate action. Evidence: `ACT_KINDS` + `ActEmitter`; `tests/unit/test_v9_m7_act_knowledge.py`.
- `[x]` Response recommendation action. Evidence: same contract/test coverage of `response_recommendation`.
- `[x]` Telemetry/access/retention gap action. Evidence: `telemetry_gap` emit test.
- `[x]` Follow-up hunt action. Evidence: `follow_up_hunt` in `ACT_KINDS` and emit test.
- `[x]` Content defect action. Evidence: `content_defect` in `ACT_KINDS` and emit test.
- `[x]` Explicit no-action decision. Evidence: production `_ensure_act_output` writes `no_action` when the hunt emits nothing else; `test_hunt_emits_no_action_and_reviewed_candidate_can_become_artifact`.
- `[x]` Every action cites the run outcome, evidence and limitations. Evidence: `ActionItem` rejects missing evidence (except `no_action`) and missing limitations; LLM cannot own an Act.

### M7.2 Knowledge candidates

- `[x]` Define `KnowledgeCandidate` contract. Evidence: `src/hunting/contracts/lifecycle.py`.
- `[x]` Candidate kinds include mapping, query, package, baseline and limitation. Evidence: `KNOWLEDGE_KINDS`; unknown kinds rejected.
- `[x]` Store source run, scope, temporal validity and review status. Evidence: `KnowledgeCandidate` fields; promotion requires scope+temporal validity.
- `[x]` Require human review and tests before promotion. Evidence: `KnowledgePromotionGate` and `tests/unit/test_lifecycle_contracts.py::test_knowledge_promotion_requires_human_reviewer_and_tests`.
- `[x]` Never promote an incident conclusion or negative result as universal knowledge. Evidence: `INCIDENT_KNOWLEDGE_CLASSES` rejected; `execute_hunt` does not create knowledge candidates.
- `[x]` Track revocation/invalidation on semantic, schema, permission or contract drift. Evidence: `invalidate_for_drift` revokes pending/approved knowledge; `test_hunt_emits_no_action_and_reviewed_candidate_can_become_artifact`.

### M7.3 Reuse metrics

- `[x]` Knowledge candidate approval rate. Evidence: `KnowledgeReuseLedger.approval_rate` recorded on `register_knowledge`/`promote_knowledge`.
- `[~]` Approved artifact reuse rate. Ledger formula exists; production hunts do not yet record `reused` events.
- `[ ]` Time from hunt to detection/telemetry improvement.
- `[x]` Regression/rollback rate after reuse. Evidence: drift invalidation records `rolled_back`; `regression_rate` asserted in `tests/unit/test_v9_m7_act_knowledge.py`.
- `[ ]` Analyst effort saved on repeated hunt classes.

### Gate M7

- `[x]` A hunt creates at least one auditable Act output or explicit no-action result. Evidence: `FinalHuntAccount.action_items`; `test_hunt_emits_no_action_and_reviewed_candidate_can_become_artifact`.
- `[x]` A reviewed knowledge candidate can become an approved artifact through tests. Evidence: `VersionedContentRegistry.promote_knowledge` sets `APPROVED` only after reviewer+tests; does not compile an F0 package from one run.
- `[x]` No model or single run can auto-promote durable knowledge. Evidence: LLM proposal/promotion refused; hunts leave `knowledge_candidates` empty until a human `propose_knowledge`.

Gate M7 is **closed** on the default production path. Control-plane only; metadata is not proof. Reuse-time and analyst-effort operational metrics remain open and are not Gate M7 blockers.

---

## 11. M8 — Validation and evaluation

### M8.1 Counterexample suite

- `[x]` Unrelated non-empty row. Evidence: `tests/unit/test_v9_proof_engine.py::test_unrelated_row_execution_remains_proof_gap`; `tests/unit/test_v9_m5_package_f0.py`.
- `[x]` Subject/object role swap. Evidence: `tests/unit/test_v9_proof_engine.py::test_role_swapped_account_host_evidence_rejected`.
- `[x]` Co-occurrence without direction/action. Evidence: `tests/unit/test_v9_proof_engine.py::test_cooccurrence_without_directional_action_is_retrieval_only`.
- `[x]` Complete-empty without negative licence. Evidence: unlicensed empty scan stays `PROOF_GAP` in `test_negative_evidence_licensed_absence`.
- `[x]` Partial-empty and truncated results. Evidence: `tests/acceptance/test_v9_acceptance_suite.py::test_scenario_08_partial_empty_query_remains_inconclusive`; `tests/unit/test_v9_controller_integration.py`.
- `[x]` Multiple singular candidates. Evidence: `tests/unit/test_v9_mode_aware_control.py`; `tests/unit/test_v9_candidate_control_and_discriminator.py`.
- `[~]` Conflicting observations. Compiler constraint conflicts trigger clarification; labelled conflicting native observations are not a full eval fixture.
- `[x]` Permission revoked after cache creation. Evidence: `tests/unit/test_proof_contract_registry.py::test_runtime_capability_cache_invalidation_dimensions`.
- `[x]` Schema unchanged but semantic/parser drifted. Evidence: `tests/unit/test_v9_m5_package_f0.py::test_schema_parser_permission_drift_removes_f0_route`.
- `[x]` Misleading source name and field-role spoofing. Evidence: `tests/unit/test_v9_capability_matching.py::test_source_identifier_does_not_create_semantic_relevance`.
- `[x]` Log/CTI/comment indirect prompt injection. Evidence: `tests/unit/test_v9_m6_workspace.py`; acceptance prompt-injection scenario.
- `[x]` Backend timeout with unverified cancellation. Evidence: `tests/acceptance/test_v9_acceptance_suite.py::test_scenario_14_budget_timeout_exhaustion_with_resumable_state`.
- `[x]` Vocabulary mismatch with executable route. Evidence: `tests/unit/test_v9_open_vocabulary_production.py::test_f1_executable_typed_route_reaches_engine_query_without_c2`.
- `[x]` Unknown relation exploration without proof. Evidence: `tests/acceptance/test_v9_acceptance_suite.py::test_scenario_09_unknown_relation_exploration_without_proof`.

### M8.2 Vertical slices

- `[~]` Factual lookup: minimal goal, cited verified value. Default-path QUESTION hunts execute; independent cited-value labels are only on the S01 CDB slice.
- `[~]` Hypothesis hunt: support/refutation obligations and explicit inconclusive state. Default-path HYPOTHESIS hunts execute; labelled support/refute fixtures remain thin.
- `[~]` Population hunt: plural candidates, prevalence and bounded coverage. Default-path population slice executes; prevalence labels remain open.
- `[ ]` Causal reconstruction: temporal/directional obligations and provenance.
- `[ ]` Scheduled/repeated hunt: reuse without stale conclusion reuse.

### M8.3 Operational metrics

- `[x]` Query execution rate. Evidence: `compute_aggregate_metrics` `query_execution_rate`.
- `[x]` Zero-query terminal rate. Evidence: `zero_query_terminal_rate`.
- `[x]` Time to first query. Evidence: `mean_time_to_first_query_ms` from executed elapsed/query count.
- `[x]` Time to first useful cited evidence. Evidence: `mean_time_to_first_evidence_ms` when citations exist.
- `[ ]` Capability and executable-route recall@k.
- `[ ]` Admitted-route precision/recall.
- `[x]` Evidence yield and irrelevant-row rate. Evidence: labelled waste in `eval/runner.py`.
- `[x]` Wrong-binding rate. Evidence: `LayeredHuntMetrics.wrong_binding`.
- `[x]` False-proof/false-refutation/proof-gap rates. Evidence: `false_proof_rate` / `proof_gap_rate`; wrong-path when answer is correct without admissible proof.
- `[~]` Decision coverage and risk–coverage curve. Decision coverage is scored; a risk–coverage curve is not.
- `[ ]` Candidate-to-finding and finding-to-action conversion.
- `[~]` LLM, backend, runtime and analyst cost. LLM/runtime cost is taken from the run account; analyst-effort-saved is not invented.
- `[ ]` Total cost per correctly resolved case, stratified by severity/difficulty.

### M8.4 Content and telemetry validation

- `[ ]` Replay fixtures validate each approved capability/proof package.
- `[ ]` Authorized Atomic/CALDERA-equivalent validation covers selected behaviors.
- `[ ]` Telemetry generation, collection and parser path are verified end to end.
- `[ ]` Missing telemetry creates a telemetry-gap action, not more speculative reasoning.

### M8.5 Live readiness

- `[ ]` Non-skipped BOTS v2 test executes through actual CLI/API/provider path. Probe ran; Splunk `https://localhost:8089` refused and `SPLUNK_*` unset. Evidence: `eval/live_probe.py`, `test_bots_v2_live_probe_never_skips_and_does_not_claim_readiness`.
- `[ ]` Live report includes native query, completeness, evidence, proof, coverage and cost.
- `[x]` Live failures and unreachable backend states remain visible. Evidence: non-skipped probe records the exact blocker and `live_claim_allowed=False`.
- `[x]` Claims are limited to the tested deployment/provider/workload. Evidence: this checklist does not claim live BOTS v2 readiness.

### Gate M8

- `[~]` B0, B1 and candidate results come from actual executions. True for the reviewed S01 CDB slice and mock-adapter candidate hunts; full corpus/holdout labelled comparison remains open.
- `[~]` Independent labels and holdout remain uncontaminated. Holdout split exists in `eval/splits.json`; gold stays out of production prompts; full independent adjudication is incomplete.
- `[ ]` Candidate meets predefined quality/coverage/safety thresholds.
- `[ ]` Added complexity shows measurable benefit or is removed.
- `[~]` Unit, static, v9 counterexample and relevant live suites pass. Unit/static/v9 pass; live BOTS v2 did not run.

Gate M8 remains **open**. Live BOTS v2 is not claimed.

---

## 12. Cross-cutting security and tenancy

- `[ ]` Authorization enforced at source discovery.
- `[ ]` Authorization rechecked at query dispatch.
- `[ ]` Authorization enforced at evidence read/export.
- `[ ]` Cache isolation includes tenant/principal/authorization digest.
- `[ ]` Permission revocation invalidates affected routes/cache.
- `[ ]` Secrets and unnecessary native data are redacted before model calls.
- `[ ]` External telemetry, CTI, comments and artifacts are treated as untrusted data.
- `[ ]` Models cannot mutate hard scope, budget, proof, binding or stop authority.
- `[ ]` Provider query subsets are read-only unless separately authorized.
- `[ ]` Cancellation verification and retry budgets are enforced.
- `[ ]` Audit retention and deletion policies are documented and tested.

---

## 13. Documentation consistency

- `[ ]` `01` remains the sole normative architecture.
- `[ ]` Accepted new contracts are added to `01` before being called normative.
- `[ ]` Runtime method changes update `02`.
- `[ ]` New external evidence and transfer limits update `03`.
- `[ ]` `04` is corrected when inspected code contradicts a completion claim, and items are advanced to `[x]` only after default-path production evidence exists.
- `[ ]` Migration ordering changes update `08`.
- `[ ]` `09` and this checklist remain subordinate planning/tracking documents.
- `[ ]` Generated reports/artifacts never define intended behavior.
- `[ ]` Documentation and CLI/runtime read shared budget/configuration sources.
- `[ ]` Claims distinguish design, isolated implementation, production integration and empirical validation.

---

## 14. Pull-request sequence

Keep changes reviewable and preserve the existing migration priority.

1. `[ ]` **PR12.0 — prerequisite truth patch:** capture the frozen pre-L candidate run, add the minimum executable baseline/run-account support, and expose the `04`/runner discrepancy. This is a prerequisite to Workstream L, not a replacement or renumbering of canonical PR12.
2. `[ ]` **PR12.1 — Workstream L counterexamples plus CandidateRoute architecture decision and contract (only after authority approval).**
3. `[ ]` **PR12.2 — F0/F1 route retrieval and goal-scoped identity.**
4. `[ ]` **PR12.3 — F2 one-call mapping, deterministic admission and materialization cleanup.**
5. `[ ]` **PR12.4 — planner/QueryIntent/stop integration and canonical PR12 acceptance gate L.**
6. `[ ]` **PR13 — mode-aware EXPLORE/DISCRIMINATE/PROVE plus remaining M0 corpus/metric work in parallel.**
7. `[ ]` **PR14 — one bounded agenda and legacy isolation.**
8. `[ ]` **PR15 — typed physical planning and EvidenceGraph.**
9. `[ ]` **PR16 — reusable package registries and deterministic F0 fast path.**
10. `[ ]` **PR17 — analyst investigation workspace.**
11. `[ ]` **PR18 — Act and Knowledge promotion.**
12. `[ ]` **PR19 — full baselines, ablations, authorized validation and final live gate.**

Each PR must:

- start with failing counterexamples;
- avoid scenario/provider branches in the kernel;
- preserve native evidence and authority boundaries;
- report tests actually run and any skipped live checks;
- update completion status only after production integration evidence.

### 14.1 Required deliverables for every PR

Every implementation PR/checkpoint must leave all of the following:

1. counterexample or executable acceptance test;
2. production change on the default path;
3. compatibility/migration handling where an existing public contract changes;
4. machine-readable run-account evidence where execution behavior changes;
5. tests actually run, failures and skips;
6. relevant `09`/`10` status updates;
7. relevant canonical-document updates;
8. explicit rollback trigger and rollback boundary;
9. no unrelated generated-artifact churn presented as implementation evidence.

### 14.2 Stop-and-escalate conditions

Stop the current implementation slice and correct the plan/checklist before continuing when:

- a required change conflicts with `01` or changes authority without an architecture decision;
- the only apparent fix needs a scenario, provider or known-answer branch in the kernel;
- an LLM/provider proposal would gain proof, binding, hard-scope or stop authority;
- independent replay labels or a truthful baseline are unavailable for the claim being optimized;
- a failed live dependency is being converted into synthetic success;
- complexity grows without a measurable gate or a simpler baseline comparison;
- the change would overwrite unrelated user work or generated evidence needed for audit.

---

## 15. Final release gate

The evolved system is ready only when all statements below are true:

- `[ ]` One SemanticGoalGraph/OutcomeContract production path handles supported request kinds.
- `[ ]` Open-vocabulary matching forms executable admitted routes without aliases.
- `[ ]` Unknown relations can explore but cannot self-authorize proof.
- `[x]` EXPLORE, DISCRIMINATE and PROVE have distinct tested runtime behavior. Evidence: `tests/unit/test_v9_mode_aware_control.py`.
- `[x]` One deterministic agenda/controller owns recovery and stopping. Evidence: `tests/unit/test_v9_bounded_agenda.py`.
- `[ ]` EvidenceGraph is reconstructable from immutable native evidence.
- `[ ]` Every verified relation names approved evaluator version and exact citations.
- `[x]` Approved packages run through the same evidence/proof kernel. Evidence: `tests/unit/test_v9_m5_package_f0.py`.
- `[~]` Analyst decisions are visible, resumable and auditable. Decisions are cited on the workspace snapshot; `reconstruct_from_run_account` rebuilds views from the machine account without a hand-edited JSON dump. No hunt-workspace UI.
- `[x]` Act and Knowledge promotion require review and tests. Evidence: `tests/unit/test_v9_m7_act_knowledge.py`.
- `[~]` B0/B1/candidate comparisons use actual execution and independent labels. Matched S01 CDB envelope executes; full labelled holdout comparison remains open.
- `[ ]` Operational utility, abstention, analyst effort and total cost are reported together.
- `[ ]` Required unit/static/counterexample suites pass.
- `[ ]` Required live tests are non-skipped and pass for the declared readiness scope.
- `[ ]` No checklist item is completed solely by class existence, generated output or simulated assignment.

---

## 16. Consolidated review record — 2026-09-20

**Verdict:** accept the plan/checklist pair as a subordinate implementation proposal, with the revisions below already incorporated. This verdict approves the documents for planning; it does not approve the proposed contracts as normative architecture and does not claim implementation completion.

### Revisions incorporated

The following are review conclusions about these two documents, not implementation-completion statuses:

- Reaffirmed `01` as the sole normative architecture and kept proposed contracts plan-level until architecture review.
- Preserved `08` Workstream L as the immediate code-migration priority.
- Limited pre-M1 work to the minimum trustworthy candidate/baseline capture; broader M0 work continues in parallel.
- Recorded the contradiction between `04` Phase 10 and the B0/B1 `NotImplementedError` in `eval/runner.py`.
- Added concrete evidence pointers for existing `[x]` baseline claims.
- Kept F1 retrieval, route admission, proof authority and coverage completion distinct.
- Kept unknown relations exploratory until an approved executable ProofContract exists.
- Prevented compatibility flags from preserving a known authority defect as the validated default path.
- Kept provider/scenario names and native query logic outside the reasoning kernel.

### Residual implementation blockers

- `[~]` B0/B1 support is executable for one reviewed CDB slice with serialized run accounts; full corpus coverage and denominator audit remain open.
- `[x]` End-to-end F1 hit → admitted goal-scoped route → QueryIntent → recorded query. Evidence: `test_f1_executable_typed_route_reaches_engine_query_without_c2`.
- `[x]` Removal of production relation-equality matching and proposal-as-guarantee materialization. Evidence: census `_audit_goal_graph` uses F0/F1; planner `legacy_relation_matching=False`; runtime `guaranteed_relations=()`.
- `[x]` Mode-aware controller behavior for EXPLORE, DISCRIMINATE and PROVE. Evidence: `tests/unit/test_v9_mode_aware_control.py` and production `RecoveryController`/`execute_semantic_plan` wiring.
- `[x]` One bounded agenda and one terminal mutation authority. Evidence: `tests/unit/test_v9_bounded_agenda.py`.
- `[x]` Gate M4 typed planning, EvidenceGraph reconstruction, C3 quarantine and mock/declared-live contract parity. Evidence: `tests/unit/test_v9_m4_gate.py`.
- `[ ]` Non-skipped live BOTS v2 readiness evidence for the declared provider scope.

### Review acceptance criteria

These document-review results do not use implementation status markers:

- **PASS:** the documents preserve v9 proof and stop authority rather than weakening it for recall.
- **PASS:** external technologies contribute bounded principles, not copied architectures or effectiveness claims.
- **PASS:** the migration begins with counterexamples and the smallest executable vertical slice.
- **PASS:** measurement includes utility, abstention, coverage, cost and analyst effort.
- **PASS:** the plan contains rollback/removal conditions when added complexity fails to beat a simpler baseline.
- **PENDING:** automated documentation/static checks have not yet executed successfully against the final files.
