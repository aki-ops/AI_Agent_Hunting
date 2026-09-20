# 04 — IMPLEMENTATION CHECKLIST (v9)

`01` is the architecture source of truth. An item is `[x]` only when the production path uses it and an automated test/replay proves the stated behavior. Standalone classes, simulated metrics and skipped live tests do not qualify.

Status legend:

- `[x]` implemented, integrated and tested;
- `[~]` partially implemented or tested in isolation;
- `[ ]` missing or not demonstrated.

## Phase 0 — Documentation and evidence truth

- [x] Define v9 target architecture and scientific claim boundary.
- [x] Separate generated reports/baselines from normative documentation.
- [x] Correct AutoLink and MDB-Link references.
- [x] Replace universal `AnswerContract` with target `OutcomeContract` design.
- [x] Add automated documentation consistency checks for versions, taxonomy and budgets.
- [x] Capture a new post-v9 implementation baseline before code migration.

## Phase 1 — Canonical contracts

- [x] `SemanticGoalGraph`, query, observation and budget contracts exist.
- [x] Implement `OutcomeContract = FactualAnswer | HypothesisVerdict | PopulationDiscovery`.
- [x] Define one canonical `GoalRuntimeState` with execution, coverage, proof and route axes.
- [x] Define cardinality-aware `CandidateSet` and `VerifiedBinding`.
- [x] `ProofContract` and registry exist, and executable evaluator authority is integrated (`ProofEngine`).
- [x] Canonicalize the runtime stopping enum to the v9 taxonomy (`StoppingDecision`, `StoppingTaxonomyState`).
- [x] Map legacy enums only at serialization/compatibility boundaries.

## Phase 2 — Semantic compilation and acceptance

- [x] API free text can produce a `SemanticGoalGraph` with validation.
- [ ] Route question, hypothesis, alert, PoC, CVE, TTP, IOC, CTI and scheduled requests into the same graph contract. CTI/scheduled semantic fallback is implemented; alert/PoC and legacy isolation still require integration tests.
- [x] Remove default production fallback to `ClaimGraph`, `InvestigationModel` and `InvestigationCase`.
- [x] Remove scenario/entity examples from the C1 production prompt.
- [x] Preserve explicit literals and provenance spans.
- [x] Validate graph/outcome consistency and explicit scope preservation.
- [x] Mark novel relations `PROPOSED_UNREGISTERED` rather than silently proving or rejecting them.
- [x] Implement C1V/selective clarification for ambiguous semantic interpretation.
- [x] Add independent request-to-graph gold labels and forbidden-expansion tests.

## Phase 3 — Obligation planning

- [x] Typed operation composition and logical plans exist.
- [x] Execute declared `AND` dependencies exactly.
- [x] Execute declared `OR` proof methods exactly.
- [x] Evaluate `GATE` predicates from verified runtime state before downstream execution.
- [x] Require accepted graph revision before inserting an intermediate goal.
- [x] Ensure a simple lookup may remain one atomic goal.
- [x] Prevent operation IDs, source names, field names and scenario keywords from defining graph shape.
- [x] Add tests where changing AND/OR/GATE changes the executed plan.
- [ ] Match unresolved goals with a `CapabilityQuery` (types, constraint keys, relation text), not exact `guaranteed_relations` equality.
- [ ] F1 dense retrieve of operations/sources/fields with no LLM; C2 at most one call on that shortlist.
- [ ] Admission gate before execute; C2 deferred must not set `examined=100` or `STOP_UNSUPPORTED`.

## Phase 4 — Candidate binding and human control

- [x] Binding provenance and user selection events exist.
- [x] Read fanout/cardinality policy from the `SearchEnvelope`; remove executor-local default 32.
- [x] For singular slots, never propagate multiple candidates as verified bindings.
- [x] Implement discriminator actions with explicit information-gain purpose.
- [x] Ask the user when discrimination cannot resolve ambiguity within budget.
- [x] Preserve plural candidate answers when the OutcomeContract permits them.
- [x] Prove zero first-row, substring, provider-order or host-name auto-selection.

## Phase 5 — Evidence and ProofContract authority

- [x] Query results expose execution success, completeness, rows and diagnostics.
- [x] Raw observations are append-only and retain native values.
- [x] FieldFact extraction and evidence grouping exist, including legacy heuristics.
- [x] Add `evaluator_id`, evaluator version, scope and negative licence to proof contracts.
- [x] Invoke the approved evaluator for every semantic goal on the production path.
- [x] Remove `rows + complete + relation_observable => SUPPORTED` shortcut.
- [x] Keep operation metadata as route eligibility, never incident proof.
- [x] Require exact role direction, bindings, qualifiers, identity, time and citations.
- [x] Make unknown relations retrieval-only until a contract or human decision exists.
- [x] Add the unrelated-row, role-swap, cooccurrence and false-transition rejection tests.

## Phase 6 — Controller and stopping

- [x] `RecoveryController`, observation classes and `LoopGuard` exist and pass isolated tests.
- [x] Normalize `QueryResult.complete` across the controller; remove `completed` mismatch.
- [x] Integrate `classify()` into every production query attempt.
- [x] Integrate `choose_next_action()` as the only recovery authority across the default runtime and legacy boundary.
- [x] Integrate `evaluate_stop()` as the only stopping authority across the default runtime and legacy boundary.
- [x] Remove direct stopping assignments from engine branches.
- [ ] Replace multiple legacy while-loops with one bounded agenda loop.
- [x] Run the OutcomeContract verifier before `STOP_ANSWERED`.
- [x] Prove `PARTIAL + 0 rows != STOP_NOT_FOUND_BOUNDED` end to end.
- [x] Prove action repetition without material delta cannot loop indefinitely.

## Phase 7 — LLM budget and calls

- [x] LLM usage records calls, tokens and estimated cost.
- [x] Use one shared configuration for documentation, CLI and runtime budgets.
- [x] Reconcile documented max 5 calls with the current CLI max 4 calls.
- [x] Implement global reservations across C1/C1V/C2/C3/C4/C5; component ceilings cannot overcommit the global budget.
- [x] Keep C6 disabled unless verified facts already exist.
- [x] Reject truncated/malformed model output before state mutation.
- [x] Demonstrate that optional profiling cannot starve proof/recovery calls.

## Phase 8 — Legacy and hard-code removal

- [x] Disable legacy graph execution by default and prove the boundary with a live route test.
- [x] Remove production person-to-endpoint-to-IP-to-domain route injection.
- [x] Remove case-specific email, Tor, PowerPoint, ransomware, Mallory, Amber and BOTS decision branches/prompts.
- [x] Replace fixed device-word handling with typed semantic role plus uncertainty/clarification.
- [x] Remove implicit CDB fallback when no provider is configured.
- [x] Remove first-provider fallback when no eligible route is selected.
- [x] Keep provider-native mappings in manifests/adapters, not reasoning policy.

## Phase 9 — Reporting and observability

- [x] Human report, structured compiler trace, query audit and cost sections exist.
- [x] Show proposed graph versus accepted graph.
- [x] Show every action's bindings, returned summary, candidate delta and next-action reason.
- [x] Show ProofContract/evaluator decision and missing obligations per goal.
- [x] Show OutcomeContract verification before final answer.
- [x] Show unexamined sources/routes and coverage limitations. The human report now renders compact per-relation coverage counts; the full source/stage audit remains in `source_profile_audit.json`.
- [x] Ensure every report assertion cites query and observation IDs.
- [x] Do not expose hidden chain-of-thought; persist structured proposals and decisions only.

## Phase 10 — Executable evaluation

- [x] Candidate prediction comes from actual pipeline execution when a provider/fixture is supplied, but some layer metrics still need independent replay-derived labels; synthetic ablations are now rejected instead of scored.
- [x] Keep expected graphs, answers, forbidden inferences and evidence labels independent of candidate code.
- [~] Execute B0, B1 and v9 candidate baselines with independent replay fixtures rather than assign fixed scores. A reviewed S01 CDB B0/B1 slice is executable; the full corpus is not yet configured in the current runner.
- [x] Evaluate factual, hypothesis and population OutcomeContracts.
- [x] Evaluate semantic graph accuracy separately from evidence/proof accuracy using execution artifacts.
- [x] Run mock-provider tests without provider/query optimization confounds.
- [ ] Run non-skipped BOTS v2 Splunk acceptance tests when the live provider is reachable.
- [x] Remove or archive the stale BOTS v1 live test.
- [x] Measure answer quality, abstention risk/coverage, wrong-binding rate, query/runtime cost and LLM cost from real run accounts.

Current implementation gate: reasoning contracts and the semantic default path exist, but open-vocabulary capability matching (Phase 3 F0–F2) is not done. Exact relation-name misses plus deferred C2 still emit `STOP_UNSUPPORTED` with zero queries. That is not a completed capability census.

## Status correction — 2026-09-20

The broad completion claims in this legacy checklist are superseded by
`10-THREAT-HUNTING-EVOLUTION-CHECKLIST.md`. The current implementation has a
goal-scoped route/mode slice and one executable reviewed S01 CDB baseline, but
does not yet have full B0/B1 corpus coverage or non-skipped live BOTS v2
evidence. The remaining M2–M8 gates therefore stay open until execution
artifacts exist.

## Definition of done

v9 is complete with all P0 items in Phases 1–6 and Phase 10 passing through the default production path. A green unit suite and non-skipped BOTS v2 live acceptance tests confirm end-to-end correctness.
