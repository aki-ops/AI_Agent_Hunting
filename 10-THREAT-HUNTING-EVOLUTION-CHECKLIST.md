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
| Example | `[ ]` | — | — | — | unassigned | not started |

---

## 2. Current baseline summary

These entries reconcile current documentation and inspected production code. They do not replace `04`.

- `[x]` Core v9 target architecture and authority boundaries are documented. Evidence: `01_FINAL-ARCHITECTURE.md`, `context.md`, and documentation consistency checks recorded in `04` Phase 0.
- `[x]` `SemanticGoalGraph`, `OutcomeContract`, candidate, proof and runtime-state contracts exist. Evidence: production contract modules and tests recorded in `04` Phase 1.
- `[x]` Approved executable ProofEngine is present on the semantic execution path. Evidence: `src/hunting/evidence/proof_engine.py`, semantic executor/engine integration, and tests recorded in `04` Phase 5.
- `[x]` AND/OR/GATE behavior has production integration evidence. Evidence: semantic planner/executor plus `tests/unit/test_v9_graph_semantics.py` and `tests/unit/test_v9_executable_planner_and_gate.py`, as recorded in `04` Phase 3.
- `[x]` `CapabilityQuery` exists and excludes free relation wording from its structural key. Evidence: `src/hunting/contracts/capability_query.py` and `tests/unit/test_v9_capability_query.py`.
- `[~]` F1 deterministic capability retrieval exists, but current scoring is token/ontology overlap rather than the dense operation/source/field retrieval required by `01` §4.10 and `04` Phase 3.
- `[~]` Capability admission and runtime materialization exist, but F1 does not independently yield an executable admitted route.
- `[x]` Production planning is independent of exact/canonical `guaranteed_relations` equality. Evidence: production engine calls `SemanticGoalPlanner.compose(..., legacy_relation_matching=False)` and `tests/unit/test_candidate_routes.py::test_production_planner_does_not_fallback_to_relation_string_matching`.
- `[ ]` F1 executable hit reliably creates `QueryIntent` and a recorded query without C2.
- `[ ]` C2 is at most one call per unresolved goal over one shortlist in all production cases.
- `[ ]` Requirements/cache/frontier identity is consistently keyed by `goal_id` rather than relation string.
- `[~]` EXPLORE/DISCRIMINATE/PROVE contracts exist, but controller progression is not fully mode-aware.
- `[ ]` One bounded production agenda has replaced legacy loops.
- `[~]` Controller APIs own most stops, but direct terminal mutation/reset sites remain.
- `[~]` Executable B0/B1 baseline slice is available for the reviewed S01 CDB fixture; full frozen-corpus coverage remains open. Evidence: `eval/baselines.py`, `eval/corpus/baseline_specs.jsonl`, `tests/unit/test_baseline_runner.py`.
- `[ ]` Time-to-first-evidence, query-execution, zero-query-stop and knowledge-reuse metrics are implemented.
- `[ ]` Analyst investigation workspace is implemented.
- `[ ]` Act and durable Knowledge promotion lifecycle is implemented.

**Current P0 gate:** `08` Workstream L / M1 remains the immediate code-migration priority. Before changing it, perform only the minimum M0 truth repair needed to capture current candidate behavior and one executable baseline; continue the broader M0 corpus/evaluation work in parallel. Do not begin query optimization, UI expansion, additional providers or autonomy work before M1 passes.

**Documentation discrepancy:** `04` Phase 10 currently marks B0/B1 execution complete, but `eval/runner.py` still raises `NotImplementedError` for `B0_BASELINE` and `B1_DIRECT_QUERY`. Until this is reconciled with executable evidence, this tracker keeps those baseline items open.

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

- `[ ]` Implement B0 approved curated query/package plus analyst review.
- `[ ]` Implement B1 simple guarded typed-intent/direct-query path.
- `[~]` Candidate path invokes the live engine when an adapter is supplied.
- `[ ]` Implement oracle graph replay as a diagnostic ablation.
- `[ ]` Implement oracle mapping replay as a diagnostic ablation.
- `[ ]` Ensure candidate and baselines receive the same request, permissions, data, time range and budget.
- `[ ]` Preserve exceptions, timeouts and failed runs in results instead of collapsing them into silent zeros.

### M0.4 Metric correctness

- `[ ]` Zero-query runs cannot receive perfect completeness by default.
- `[ ]` Citation grounding cannot default to 1.0 without citations unless the contract explicitly requires none.
- `[ ]` Evidence precision uses independently labelled relevance, not citation count alone.
- `[ ]` Empty-query rate is not used as a proxy for waste.
- `[ ]` Non-empty irrelevant results count as waste/noise.
- `[ ]` Cohort cost includes failed, abstained and retried runs.

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
- `[ ]` Add failure: F1 source-only lexical hit incorrectly appears executable.
- `[ ]` Add failure: zero-score top-k item is treated as relevant.
- `[ ]` Add failure: deferred C2 incorrectly permits unsupported census completion.
- `[ ]` Add failure: `NO_LLM_CALLER` incorrectly permits unsupported census completion.
- `[x]` Add failure: two goals sharing relation text collide in requirement/cache state. Evidence: `tests/unit/test_candidate_routes.py::test_route_identity_keeps_same_relation_goals_separate`.
- `[ ]` Add failure: runtime proposal grants relation guarantee authority.
- `[~]` Add failure: semantically equivalent typed answer role is rejected lexically. Entity-typed answer compatibility is covered; synonym and nested-field cases remain open.
- `[ ]` Add failure: unrelated nested field passes answer-role admission.

### M1.2 Route identity and contracts

- `[x]` Approve `CandidateRoute` through an architecture decision and update `01`, `02` and `08` as applicable before production code treats it as canonical. Evidence: ADR-20260920-01 in `01_FINAL-ARCHITECTURE.md`.
- `[x]` Add provider-neutral `CandidateRoute` contract after that authority gate. Evidence: `src/hunting/contracts/candidate_route.py` and `tests/unit/test_candidate_routes.py`.
- `[x]` Include `goal_id`, provider/source/operation identity, mappings, mode, frontier stage and provenance.
- `[x]` Add route class: `EXECUTABLE`, `MAPPING_REQUIRED`, `DISCOVERY_ONLY`.
- `[x]` Key the migrated production planner route map by `goal_id`, not relation text. Evidence: `SemanticGoalPlanner.compose(..., candidate_routes=...)`.
- `[x]` Key capability cache by goal signature (`goal_id`-scoped requirement) + provider + source + schema/permission version. Evidence: `_run_pre_routing_source_profiling` cache keys and `tests/unit/test_candidate_routes.py` goal isolation coverage.
- `[ ]` Keep relation wording as retrieval context, not identity or proof authority.

### M1.3 F0 and F1

- `[ ]` Index approved operations/artifacts separately from source and field documents.
- `[ ]` F0 emits executable routes only from approved contracts/artifacts.
- `[ ]` F1 retrieves operation, source and field candidates without LLM.
- `[ ]` F1 records scores, features, index version and unexamined remainder.
- `[ ]` F1 applies an explicit relevance/defer policy; top-k alone is not relevance.
- `[ ]` F1 executable operation hit can bypass C2.
- `[ ]` F1 source/field-only hit remains mapping-required or discovery-only.
- `[ ]` Retrieval rank never changes proof status or licenses negative evidence.

### M1.4 F2 and admission

- `[ ]` At most one C2 call is scheduled per unresolved goal over one compact shortlist.
- `[ ]` C2 proposal remains untrusted and cannot execute or complete coverage.
- `[ ]` Deferred, malformed, unavailable and budget-denied C2 states remain explicit.
- `[ ]` Admission validates reachable input type and current graph bindings.
- `[ ]` Admission validates provider/source reachability, permissions, retention and time overlap.
- `[ ]` Admission validates census-backed native fields and declared mappings.
- `[ ]` Admission validates typed answer/output roles without arbitrary nested-field bypass.
- `[ ]` Admission assigns EXPLORE unless approved proof contract/evaluator compatibility is present.
- `[ ]` Rejected route emits reasons and keeps proof `NOT_ASSESSED`/retrieval-only.

### M1.5 Planner, materialization and execution

- `[x]` `SemanticGoalPlanner` consumes admitted routes by `goal_id`. Evidence: engine integration at the descriptor, active and resumed plan paths plus `tests/unit/test_candidate_routes.py`.
- `[x]` Remove exact/canonical relation equality as the production capability matcher. Evidence: production engine disables the compatibility fallback; the fallback remains opt-in for legacy unit fixtures only.
- `[~]` Runtime materialization carries goal-scoped route identity and keeps mode `EXPLORE`; the legacy `guaranteed_relations` field remains for provider compatibility and still needs removal from the authority path.
- `[x]` Executable F1 hit emits `QueryIntent(EXPLORE)` without C2. Evidence: `tests/unit/test_candidate_routes.py::test_admitted_route_mode_reaches_query_intent`.
- `[ ]` Every emitted QueryIntent creates a recorded controller attempt and query audit entry.
- `[ ]` Unknown relations remain retrieval-only until an approved ProofContract exists.

### M1.6 Coverage and stopping

- `[ ]` Goal frontier state records F0/F1/F2 completion independently.
- `[ ]` `examined` differs from listed, shortlisted, sampled and admitted.
- `[ ]` C2 deferred cannot set frontier complete.
- `[ ]` F1 skipped/empty-with-unexamined cannot set frontier complete.
- `[ ]` Admission failure records rejected routes without claiming unexamined routes absent.
- `[ ]` `STOP_UNSUPPORTED` requires reachable provider, complete eligible frontier and zero admitted routes.
- `[ ]` Deferred/unexamined paths stop inconclusive or budget, never unsupported.

### Gate M1

- `[x]` Vocabulary mismatch with executable typed route runs at least one mock-provider query. Evidence: `tests/unit/test_candidate_routes.py::test_goal_bound_route_reaches_provider_query_without_c2`.
- `[x]` F1 executable route works with C2 disabled. Evidence: `tests/unit/test_candidate_routes.py::test_goal_bound_route_reaches_provider_query_without_c2`.
- `[ ]` C2 cannot replace F1 or act as proof authority.
- `[ ]` No scenario/vendor alias was added to reasoning code.
- `[ ]` Unit, static, v9 counterexample and relevant acceptance tests pass.

---

## 5. M2 — Runtime EXPLORE, DISCRIMINATE and PROVE

### M2.1 Mode authority

- `[ ]` Every QueryIntent mode is explicit; unsafe defaults do not silently become PROVE.
- `[ ]` Route admission, not an LLM narrative, selects allowed mode.
- `[ ]` PROVE requires an approved compatible ProofContract/evaluator.
- `[ ]` EXPLORE cannot create verified bindings or negative licences.
- `[ ]` DISCRIMINATE can only evaluate declared differentiating evidence.

### M2.2 Controller actions

- `[ ]` Candidate + EXPLORE yields record/expand/enrich action, not default SEEK_PROOF.
- `[ ]` Singular ambiguity uses discriminator budget then user clarification.
- `[ ]` Plural candidate outcomes preserve valid candidates within budget.
- `[ ]` Candidate + PROVE seeks an approved proof-capable route.
- `[ ]` Missing proof contract preserves candidate evidence and explicit limitation.
- `[ ]` Adjacent exploration does not silently mutate accepted semantic obligations.
- `[ ]` Material semantic changes pass graph revision and acceptance.

### M2.3 Binding safety

- `[ ]` Candidate-only input can feed only declared exploration actions.
- `[ ]` Proof-required downstream steps require verified bindings.
- `[ ]` Row order, substring, provider order and score cannot bind a singular slot.
- `[ ]` User selection resumes the same accepted graph with immutable provenance.

### Gate M2

- `[ ]` Factual vertical slice proves one cited value.
- `[ ]` Hypothesis vertical slice preserves support/refutation/inconclusive distinctions.
- `[ ]` Population vertical slice returns plural candidates, prevalence and coverage without singular coercion.
- `[ ]` Discovery result remains operationally useful when proof is unavailable.

---

## 6. M3 — One bounded agenda and one stop authority

### M3.1 Agenda contract

- `[ ]` Define one agenda item: goal, proof method, route, mode, bindings, envelope, cursor and priority.
- `[ ]` Priority uses mandatory status, outcome utility, information gain and bounded cost.
- `[ ]` Ranking changes order only; it cannot create authority.
- `[ ]` Agenda state is serializable and resumable.

### M3.2 Controller integration

- `[ ]` Every production attempt passes `classify()`.
- `[ ]` Every production attempt passes `choose_next_action()`.
- `[ ]` Every terminal decision passes `evaluate_stop()`.
- `[ ]` Outcome verifier runs before answered/refuted success.
- `[ ]` ActionSignature contains goal, method, provider, source, mode, bindings, window, hints and cursor.
- `[ ]` Repetition requires material delta or exhausts the route.

### M3.3 Legacy removal

- `[ ]` Isolate ClaimGraph execution from default production.
- `[ ]` Isolate cell/expectation loop from default production.
- `[ ]` Isolate adaptive legacy query loop from default production.
- `[ ]` Remove direct `state.stopping_decision` assignments from production branches.
- `[ ]` Remove uncontrolled stop reset/mutation sites.
- `[ ]` Maintain explicit legacy flag only until parity evidence permits deletion.

### Gate M3

- `[ ]` Code search finds one default production agenda loop.
- `[ ]` Code search finds one terminal-state mutation authority.
- `[ ]` Partial, empty, ambiguous, proof-gap, failure, budget and unreachable cases take distinct tested actions/stops.
- `[ ]` No-progress replay terminates deterministically.

---

## 7. M4 — Typed execution and EvidenceGraph

### M4.1 Query planning

- `[ ]` Stabilize `QueryIntent -> LogicalQueryPlan -> ProviderCompiler -> NativeQuery`.
- `[ ]` Add source/partition and retention planning.
- `[ ]` Add predicate pushdown and projection planning.
- `[ ]` Add join/adjacency planning where provider contracts declare it.
- `[ ]` Add cursor pagination and bounded time splitting.
- `[ ]` Add backend cost estimator or explicit unknown-cost status.
- `[ ]` Add hard cap/cancellation declarations and verification.
- `[ ]` Preserve exact native query, scope, time, job ID and diagnostics.

### M4.2 Native proposal quarantine

- `[ ]` C3 runs only when deterministic compiler cannot handle an admitted intent.
- `[ ]` Parse provider syntax before execution.
- `[ ]` Enforce read-only allowlist.
- `[ ]` Enforce tenant, scope, time, row, scan and runtime bounds.
- `[ ]` Validate output fields/roles against QueryIntent.
- `[ ]` Reject malformed/truncated model output before state mutation.

### M4.3 Evidence graph

- `[ ]` Define append-only EvidenceGraph nodes/edges from Observation and FieldFact.
- `[ ]` Preserve native field/value, query, provider, timestamp and transformation provenance.
- `[ ]` Distinguish observed transition, provenance dependency and causal attribution.
- `[ ]` Preserve contradictory facts and identity alternatives.
- `[ ]` Prevent graph proximity/co-occurrence from granting semantic proof.
- `[ ]` Support multi-provider evidence routes under one goal.

### Gate M4

- `[ ]` Same semantic graph executes through mock and declared live provider boundary without reasoning changes.
- `[ ]` Query replay reproduces scope and provider metadata.
- `[ ]` EvidenceGraph can be reconstructed from immutable run account.
- `[ ]` Cross-source relation proof requires approved correlation/identity obligations.

---

## 8. M5 — Reusable content and deterministic fast paths

### M5.1 Registries and lifecycle

- `[ ]` Define `CapabilityArtifact` schema.
- `[ ]` Define `HuntPackage` schema.
- `[ ]` Define `AnalyticPackage` schema.
- `[ ]` Version all packages and ownership metadata.
- `[ ]` Define draft, validated, approved, deprecated and revoked states.
- `[ ]` Add compatibility and deprecation policy.
- `[ ]` Keep package registries provider-neutral at the reasoning boundary.

### M5.2 Compilation pipeline

- `[ ]` Define provider-neutral analytic internal representation.
- `[ ]` Define deterministic data-model/field transformation stages.
- `[ ]` Define backend compiler interface.
- `[ ]` Record compiler, schema, parser and package versions in run accounts.
- `[ ]` Make approved packages first-class F0 routes.
- `[ ]` Ensure package output enters standard Observation/Proof paths.

### M5.3 Tests and feedback

- `[ ]` Every approved artifact has positive and negative fixtures.
- `[ ]` Every proof-capable artifact has unrelated-row and role-swap fixtures.
- `[ ]` Every artifact declares completeness and known limitations.
- `[ ]` Schema/permission/parser drift invalidates or re-reviews affected artifacts.
- `[ ]` Analyst false-positive/content-defect feedback is retained and triaged.

### Gate M5

- `[ ]` Approved fast path runs with zero C2/C3 calls.
- `[ ]` Fast path is measurably faster or cheaper without violating quality/coverage constraints.
- `[ ]` Package metadata alone cannot verify an incident relation.

---

## 9. M6 — Analyst investigation workspace

### M6.1 Evidence experience

- `[ ]` Timeline view over native observations.
- `[ ]` Entity/event pivot with provenance.
- `[ ]` SemanticGoalGraph and EvidenceGraph shown separately.
- `[ ]` Native event and transformation viewer.
- `[ ]` Query, completeness and coverage view.
- `[ ]` Proof obligations, satisfied/missing conditions and limitations view.
- `[ ]` Unexamined routes/sources are visible.

### M6.2 Collaboration and decisions

- `[ ]` Tags, annotations, comments and saved searches.
- `[ ]` Candidate/binding review action.
- `[ ]` Analyst decisions are immutable, timestamped and cited.
- `[ ]` Resume uses the same accepted graph/run state.
- `[ ]` Role-based permissions protect evidence and decisions.
- `[ ]` Workspace text is treated as untrusted data, not agent instructions.

### Gate M6

- `[ ]` Analyst can explain why every query ran and why the system stopped.
- `[ ]` Analyst can resolve an allowed ambiguity without a second C1 compile.
- `[ ]` Resumed hunt preserves evidence, bindings, scope, budgets and decision provenance.
- `[ ]` Usability pilot measures correction time and total analyst effort.

---

## 10. M7 — Act and Knowledge

### M7.1 Act outputs

- `[ ]` Detection candidate action.
- `[ ]` Response recommendation action.
- `[ ]` Telemetry/access/retention gap action.
- `[ ]` Follow-up hunt action.
- `[ ]` Content defect action.
- `[ ]` Explicit no-action decision.
- `[ ]` Every action cites the run outcome, evidence and limitations.

### M7.2 Knowledge candidates

- `[ ]` Define `KnowledgeCandidate` contract.
- `[ ]` Candidate kinds include mapping, query, package, baseline and limitation.
- `[ ]` Store source run, scope, temporal validity and review status.
- `[ ]` Require human review and tests before promotion.
- `[ ]` Never promote an incident conclusion or negative result as universal knowledge.
- `[ ]` Track revocation/invalidation on semantic, schema, permission or contract drift.

### M7.3 Reuse metrics

- `[ ]` Knowledge candidate approval rate.
- `[ ]` Approved artifact reuse rate.
- `[ ]` Time from hunt to detection/telemetry improvement.
- `[ ]` Regression/rollback rate after reuse.
- `[ ]` Analyst effort saved on repeated hunt classes.

### Gate M7

- `[ ]` A hunt creates at least one auditable Act output or explicit no-action result.
- `[ ]` A reviewed knowledge candidate can become an approved artifact through tests.
- `[ ]` No model or single run can auto-promote durable knowledge.

---

## 11. M8 — Validation and evaluation

### M8.1 Counterexample suite

- `[ ]` Unrelated non-empty row.
- `[ ]` Subject/object role swap.
- `[ ]` Co-occurrence without direction/action.
- `[ ]` Complete-empty without negative licence.
- `[ ]` Partial-empty and truncated results.
- `[ ]` Multiple singular candidates.
- `[ ]` Conflicting observations.
- `[ ]` Permission revoked after cache creation.
- `[ ]` Schema unchanged but semantic/parser drifted.
- `[ ]` Misleading source name and field-role spoofing.
- `[ ]` Log/CTI/comment indirect prompt injection.
- `[ ]` Backend timeout with unverified cancellation.
- `[ ]` Vocabulary mismatch with executable route.
- `[ ]` Unknown relation exploration without proof.

### M8.2 Vertical slices

- `[ ]` Factual lookup: minimal goal, cited verified value.
- `[ ]` Hypothesis hunt: support/refutation obligations and explicit inconclusive state.
- `[ ]` Population hunt: plural candidates, prevalence and bounded coverage.
- `[ ]` Causal reconstruction: temporal/directional obligations and provenance.
- `[ ]` Scheduled/repeated hunt: reuse without stale conclusion reuse.

### M8.3 Operational metrics

- `[ ]` Query execution rate.
- `[ ]` Zero-query terminal rate.
- `[ ]` Time to first query.
- `[ ]` Time to first useful cited evidence.
- `[ ]` Capability and executable-route recall@k.
- `[ ]` Admitted-route precision/recall.
- `[ ]` Evidence yield and irrelevant-row rate.
- `[ ]` Wrong-binding rate.
- `[ ]` False-proof/false-refutation/proof-gap rates.
- `[ ]` Decision coverage and risk–coverage curve.
- `[ ]` Candidate-to-finding and finding-to-action conversion.
- `[ ]` LLM, backend, runtime and analyst cost.
- `[ ]` Total cost per correctly resolved case, stratified by severity/difficulty.

### M8.4 Content and telemetry validation

- `[ ]` Replay fixtures validate each approved capability/proof package.
- `[ ]` Authorized Atomic/CALDERA-equivalent validation covers selected behaviors.
- `[ ]` Telemetry generation, collection and parser path are verified end to end.
- `[ ]` Missing telemetry creates a telemetry-gap action, not more speculative reasoning.

### M8.5 Live readiness

- `[ ]` Non-skipped BOTS v2 test executes through actual CLI/API/provider path.
- `[ ]` Live report includes native query, completeness, evidence, proof, coverage and cost.
- `[ ]` Live failures and unreachable backend states remain visible.
- `[ ]` Claims are limited to the tested deployment/provider/workload.

### Gate M8

- `[ ]` B0, B1 and candidate results come from actual executions.
- `[ ]` Independent labels and holdout remain uncontaminated.
- `[ ]` Candidate meets predefined quality/coverage/safety thresholds.
- `[ ]` Added complexity shows measurable benefit or is removed.
- `[ ]` Unit, static, v9 counterexample and relevant live suites pass.

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
- `[ ]` EXPLORE, DISCRIMINATE and PROVE have distinct tested runtime behavior.
- `[ ]` One deterministic agenda/controller owns recovery and stopping.
- `[ ]` EvidenceGraph is reconstructable from immutable native evidence.
- `[ ]` Every verified relation names approved evaluator version and exact citations.
- `[ ]` Approved packages run through the same evidence/proof kernel.
- `[ ]` Analyst decisions are visible, resumable and auditable.
- `[ ]` Act and Knowledge promotion require review and tests.
- `[ ]` B0/B1/candidate comparisons use actual execution and independent labels.
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
- `[ ]` End-to-end F1 hit → admitted goal-scoped route → QueryIntent → recorded query.
- `[ ]` Removal of production relation-equality matching and proposal-as-guarantee materialization.
- `[ ]` Mode-aware controller behavior for EXPLORE, DISCRIMINATE and PROVE.
- `[ ]` One bounded agenda and one terminal mutation authority.
- `[ ]` Non-skipped live BOTS v2 readiness evidence for the declared provider scope.

### Review acceptance criteria

These document-review results do not use implementation status markers:

- **PASS:** the documents preserve v9 proof and stop authority rather than weakening it for recall.
- **PASS:** external technologies contribute bounded principles, not copied architectures or effectiveness claims.
- **PASS:** the migration begins with counterexamples and the smallest executable vertical slice.
- **PASS:** measurement includes utility, abstention, coverage, cost and analyst effort.
- **PASS:** the plan contains rollback/removal conditions when added complexity fails to beat a simpler baseline.
- **PENDING:** automated documentation/static checks have not yet executed successfully against the final files.
