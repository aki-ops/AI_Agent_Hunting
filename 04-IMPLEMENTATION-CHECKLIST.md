# 04 — IMPLEMENTATION CHECKLIST (v8)

`[x]` is allowed only with an automated test, replay, or captured execution
artifact. The architecture source is `01`; the executable method is `02`; the
source/claim boundary is `03`; the strategic decision records are `06`, `07`,
and the candidate master plan `08-EVIDENCE-BASED-REARCHITECTURE-PLAN.md`.
The target architecture is the **Contract-Grounded Progressive Hunt Graph**
spanning Control Plane and Hunt Plane (Steps A–J).

---

## Phase 0 — Baseline and Scope Freeze (P0)

- [x] Freeze current tests/reports as historical baseline; do not call them v8 evidence. (`baseline_tests.json`, `baseline_reports/`, `baseline_keyword_branches.txt`; 356 passed / 3 failed / 1 skipped on 2026-09-09. Failures are legacy v5 keyword/email-graph tests, not v8 evidence.)
- [x] Establish `SemanticGoalGraph`, `LogicalPlan`, `CapabilityGraph` and compatibility `ClaimGraph` contracts. (`src/hunting/contracts/semantic_graph.py`, `claim.py`, `capabilities.py`.)
- [x] Keep `Cell(provider_scope, entity|ANY, time_bucket)` strictly as a coverage/execution coordinate, never an ontology.
- [x] Establish evaluation corpus directory and schemas (`eval/corpus/scenarios.jsonl`, `eval/splits.json` with 15 canonical scenarios across train/dev/test_holdout partitions).
- [ ] Define baseline B0 (current pipeline) and baseline B1 (direct LLM-to-read-only-query with safety gate) run accounts.
- [ ] Confirm no `event_family`, `event_code`, keyword or answer-type field controls reasoning path. (`build_investigation_case_from_intent()` is compatibility-only; remaining legacy branches outside semantic compilation are catalogued for retirement.)

---

## Phase 1 — Lock Semantic Authority (P0)

- [x] Create `src/hunting/contracts/proof_contract.py` defining `ProofContract`, `ProofMode`, and the 3 capability levels (`STRUCTURALLY_VALID`, `RETRIEVAL_CAPABLE`, `PROOF_CAPABLE`).
- [x] Create `src/hunting/registry/proof_contract_registry.py` managing human-reviewed, approved, versioned proof contracts.
- [x] Update `contracts/source_profile.py`, `capabilities/source_mapping_validator.py`, and `capabilities/runtime_materializer.py` to enforce that dynamic LLM mappings default to `RETRIEVAL_CAPABLE`.
- [x] Adapter-compiled bounded probes distinguish observable capability from claim evidence. (`BoundedProbeExecutor`, Splunk/CDB probe implementations and probe contract tests.)
- [x] Only successful probes materialize versioned `RuntimeCapability` records; failed/empty/incomplete probes remain auditable diagnostics. (`test_successful_probe_is_required_for_validated_capability` and materializer tests.)
- [x] Enforce that only registry `APPROVED` contracts with passing conformance tests can materialize `PROOF_CAPABLE` runtime capabilities.
- [x] Capability cache keys include provider, scope, permission state, schema fingerprint and requirement signature; schema changes invalidate cache. (`RuntimeCapabilityCache` schema invalidation test; engine uses cache-hit path.)
- [x] Expand capability cache invalidation key to include tenant/provider, principal digest, scope, schema fingerprint, proof contract ID, parser version, model/prompt version, and freshness check.
- [x] Gate verification: DNS mapping `query -> person` or `host -> domain` even with matching rows cannot become `PROOF_CAPABLE`; role swap / cooccurrence tests fail closed. (`tests/unit/test_proof_contract_registry.py`.)


---

## Phase 2 — Semantic Compiler and GoalGraph (P0)

- [x] LLM semantic compiler receives the request without provider catalog/schema context and emits only provider-neutral semantic graph JSON. (Compiler contract test.)
- [x] Semantic compiler cannot emit SPL/KQL/SQL, native event IDs, evidence or final verdicts. (`parse_and_validate_claim_graph()` validates the full raw response; prompt and rejection tests pass.)
- [x] No `is_email`, `is_tor`, `is_cve` or equivalent branch creates graph edges in the free-text compiler path. (`SemanticGoalGraph` is generated dynamically; compatibility case graph is projection-only.)
- [x] Claim-plan provenance and objective-preservation tests pass. (`source_request_id`, dependency, missing-acceptance and same-keyword/different-objective tests.)
- [x] Counterfactual requests demonstrate that claims follow the request, not keywords. (no `EmailClaim`/`TorClaim`; same keyword yields different claim sets.)
- [x] Refactor C1 prompt to emit `GoalGraph` and `AnswerContract` with atomic obligations, exact provenance spans, AND/OR/GATE dependencies, typed variables, explicit qualifiers, non-binding assumptions, and clarification triggers. (`tests/unit/test_phase2_semantic_compiler_goal_graph.py::test_answer_contract_and_goal_graph_contracts`.)
- [x] Deterministic validator rejects invented proper nouns, prevents entity mutation (Mallory cannot become Alice), keeps `MacBook` as device qualifier (not host), and verifies every downstream goal reduces an answer slot. (`tests/unit/test_phase2_semantic_compiler_goal_graph.py`.)
- [x] Persist `llm_raw_proposal`, `validated_graph`, and `validation_diagnostics` into machine run account. (`tests/unit/test_phase2_semantic_compiler_goal_graph.py::test_compiler_end_to_end_emits_goal_graph_and_persists_to_account`.)

---

## Phase 3 — Source Catalog and Progressive Frontier (P0)

- [x] `TelemetryCensus` records source IDs, field coverage/types, bounded safe field sketches, query primitives and `schema_fingerprint` without assigning semantic labels from source names. (`TelemetrySourceProfile`; dynamic profile and schema-fingerprint tests.)
- [x] Provider profile limits are explicit coverage gaps; an unprofiled native source cannot be reported as complete discovery. (Splunk profile-discovery audit.)
- [x] Implement `capabilities/source_card_store.py` providing incremental, compact `SourceCard` structures (fields, sketches, time span, cardinality, parser version, provenance). (`tests/unit/test_phase3_source_catalog_frontier.py::test_source_card_and_store_serialization`.)
- [x] Implement `capabilities/frontier.py` executing the 5-stage progressive expansion (F0 Certified -> F1 Metadata -> F2 Adjacent -> F3 Bounded LLM Profiling -> F4 Approved Exhaustive). (`tests/unit/test_phase3_source_catalog_frontier.py::test_progressive_frontier_stages_and_coverage_manifest`.)
- [x] Implement `capabilities/catalog_index.py` for lexical + embedding retrieval of SourceCards (ordering only, threshold logged, no hard Top-K truncation). (`tests/unit/test_phase3_source_catalog_frontier.py`.)
- [x] Relation-scoped batching schedules discovered sources and fields per unresolved relation; scores affect ordering only and never discard candidates. (`CapabilityBatcher` tests.)
- [x] Track `unexamined_source_ids` in coverage manifest; shortlist never proves absence. (`tests/unit/test_phase3_source_catalog_frontier.py::test_progressive_frontier_stages_and_coverage_manifest`.)
- [x] Gate verification: Misleading source name with correct fields is selected; deceptive source name with wrong fields is rejected; 25 sources / 617 fields never appear in a single prompt. (`tests/unit/test_phase3_source_catalog_frontier.py`.)

---

## Phase 4 — Controlled Binding and Mixed-Initiative Control (P0)

- [x] Binder matches claim requirements to operations using typed inputs/outputs. (`test_binder_uses_declared_fact_contract_for_unseen_operation`.)
- [x] Semantic planner composes typed AND dependencies and declared OR alternatives without operation-name heuristics.
- [x] Identity grounding supports both `person -> endpoint` and `person -> account -> endpoint`; neither route assumes an account directory.
- [x] Downstream steps require complete upstream results and preserve runtime binding provenance; candidate bindings may be used for bounded exploratory retrieval but never for proof.
- [x] Complete-but-restricted outputs remain `CANDIDATE` until the operation proves every restriction; downstream retrieval keeps the warning and verdict gate. (`test_executor_uses_candidate_binding_for_retrieval_but_keeps_warning`.)
- [x] Ambiguous output bindings do not fan out automatically; rows remain auditable and the controller requests narrowing. (`test_executor_does_not_fan_out_ambiguous_output_bindings`.)
- [ ] Implement `contracts/bindings.py` defining `CandidateBinding` and `CandidateSet` (values, supporting facts, contract ID, directness, contradictions, confidence class).
- [ ] Auto-bind only when exactly one candidate satisfies proof contract with zero contradictions.
- [ ] Implement `human_loop/clarification.py`: synthesize `DISCRIMINATOR` query when multiple candidates exist; if ambiguity persists, trigger interactive clarification or non-interactive `NEEDS_DISAMBIGUATION` halt with checkpoint.
- [ ] Gate verification: 1 valid host auto-binds; 2 matching hosts trigger discriminator or clarification; host containing `air` does not win by substring heuristic.

---

## Phase 5 — Typed Query and Native-Query Quarantine (P0)

- [x] Planner emits graph-bound `QueryIntent` with validated role IDs, trusted bindings, narrow projection, explicit scope and expected output shape. (`QueryIntentSpec` and runtime operation compiler tests.)
- [x] Adapter compiles `QueryIntent` to parameterized native syntax without scenario/source-name routes. (Runtime Splunk/CDB operation execution tests.)
- [ ] Implement query intent modes: `EXPLORE` (bounded discovery, no proof license), `DISCRIMINATE` (narrow candidate differentiation), `PROVE` (strict role projection, proof-capable).
- [ ] Implement Quarantined SPL Gate (`query_safety/native_query_gate.py`):
  - Read-only AST parser allowlist (no write/output/delete/script/network commands).
  - Identifier check against active `ProviderManifest`.
  - Escaped literals from trusted bindings only.
  - Mandatory earliest/latest bounds.
- [ ] Adapter execution enforcement: `dispatch.max_time`, scan/result limits, client-side timeout cancels backend SID, performance telemetry capture (`scanCount`, `runDuration`, `resultCount`).
- [ ] Gate verification: Broad `index=* | head` rejected; unknown fields/sources rejected; backend SID cancellation verified on timeout; query with identical semantic signature blocked from looping.

---

## Phase 6 — Evidence, Verification and Stopping Taxonomy (P0)

- [x] Facts preserve native field provenance, field roles, and direction; native rows remain immutable.
- [x] Semantic goal status distinguishes relation proof from unverified request restrictions; unsupported restrictions remain inconclusive.
- [x] Generic state-transition verification accepts only ledger-backed cited observations in one provider/scope with compatible typed entities, parseable ordered timestamps inside the declared bound, exact validated-operation `action_roles`/`state_roles`/`temporal_roles`, and a stable `artifact_identity_roles` or `correlation_roles` value; suffixes and source names prove neither transition nor ransomware causality.
- [x] LLM-proposed variable values are not query bindings until marked request-grounded or provider-observed; MacBook/device labels cannot become hosts by default.
- [x] Execution completion, relation proof and route exhaustion are separate per-goal states; complete-empty is never route exhaustion by itself.
- [x] Proof-aware readiness triggers profiling for static retrieval/proof/qualifier gaps and skips it only for a validated proof-capable route.
- [x] Progressive retrieval removes only declared retrieval predicates while retaining identity, scope, time, projection, row/page and proof bounds.
- [ ] Implement deterministic relation verifier evaluating ledger-backed cited observations against approved `ProofContract`.
- [ ] Implement answer verifier checking exact cited values, value types, required qualifiers, and mandatory gates.
- [ ] Implement the 9-state stopping taxonomy:
  `ANSWER_PROVED`, `BOUNDED_NOT_FOUND`, `NEEDS_DISAMBIGUATION`, `COVERAGE_EXHAUSTED`, `BUDGET_EXHAUSTED`, `BACKEND_DEGRADED`, `SAFETY_QUARANTINE`, `VALIDATION_FAILED`, `ABORTED_BY_USER`.
- [ ] Two-iteration no-progress detection triggers replan at most once; halts if stalled.
- [ ] Gate verification: DNS lookup does not prove person visited; file creation does not prove ransomware encryption; correct answer value with false evidence citation fails verification.

---

## Phase 7 — Report, Tracing and Cost Accounting (P1)

- [x] Report contains request, semantic decomposition, proof plan/state, runtime bindings, evidence/explanation, queries, answer/limits and cost.
- [x] Analyst report shows execution trace, compact returned sample fields and readable evidence values; raw payload remains omitted.
- [x] Incomplete/unobservable telemetry never renders `BENIGN` or definitive absence.
- [x] LLM prompt budget is preflighted before network dispatch; oversized prompts are rejected without consuming a call. (`test_create_llm_caller_preflights_before_call`.)
- [ ] Implement unified `StepTrace` recording every step from Freeze Request (Step A) through Stop (Step J).
- [ ] Implement 6-part human report structure matching `01` / `08`:
  1. Executive Verdict & Answer Contract
  2. Investigation Plan & Obligation Graph
  3. Evidence Ledger & Proof Chain
  4. Executed Queries & Execution Telemetry
  5. Coverage & Uncertainty Manifest
  6. Resource & Financial Cost Accounting
- [ ] Implement machine `run_account.json` capturing complete telemetry, LLM token metrics, query performance metrics, and deterministic ledger.
- [ ] Implement cost formula: $C_{run} = C_{llm} + C_{splunk} + C_{control} + C_{analyst}$.
- [ ] Aborted runs emit failure artifact specifically tied to the active request ID.

---

## Phase 8 — Evaluation, Holdout and Ablation (P0/P1/P2)

- [x] Run counterfactual, partial-telemetry, provider-failure and prompt-injection tests.
- [ ] Run 15-scenario counterfactual matrix (Section 8 of `08-EVIDENCE-BASED-REARCHITECTURE-PLAN.md`):
  1. S01: Tor Browser Version (exact attribute)
  2. S02: Tor Browser Artifact Identity (device qualifier)
  3. S03: Amber Competitor Domain (web proxy/DNS proof)
  4. S04: Amber External Email Exfiltration (mail proof)
  5. S05: Amber Workstation Identity (person -> endpoint)
  6. S06: Amber Account Logon (person -> account -> host)
  7. S07: Frothly Campaign Q317 File Encryption (ransomware transition proof)
  8. S08: Mallory Air13 Hostname Disambiguation (multi-candidate host)
  9. S09: PowerPoint File Download without Encryption (counterfactual benign file)
  10. S10: Deceptive Sourcetype with Incompatible Fields (adversarial schema)
  11. S11: Correct Sourcetype with Deceptive Name (unusual naming)
  12. S12: Missing Telemetry Absence Query (explicit absence bounded stop)
  13. S13: Splunk Backend Timeout & Search Job Cancel (backend degradation)
  14. S14: Prompt Injection in Log Payload (quarantine defense)
  15. S15: Cross-Tenant Multi-Provider Isolation (scope/permission defense)
- [ ] Compare B0 (current baseline), B1 (direct query), and Candidate (Contract-Grounded Progressive Hunt Graph).
- [ ] Report separate layer metrics:
  - Planning: Claim Precision, Recall, F1; Unsupported Expansion Rate
  - Retrieval: Evidence Precision, Recall@k; Completeness Accuracy
  - Correlation: Edge Precision, Recall, F1; Transition Validity
  - Answer: Exact Match, Value F1, Citation Grounding Rate
  - Operations: Decision Coverage, Waste Ratio ($C_{waste}/C_{run}$), Mean Time to Verdict
- [ ] Run ablations: actual graph vs oracle graph; dynamic mapping vs approved mapping; single-shot query vs progressive frontier.

---

## Definition of Done (v8)

The v8 Contract-Grounded Progressive Hunt Graph is complete only when:
1. Every semantic claim is verified through a human-reviewed, approved `ProofContract` or explicitly marked `RETRIEVAL_ONLY` / `UNVERIFIED`.
2. No broad full-schema prompts or arbitrary Top-K truncations occur; the progressive frontier F0–F4 operates with an audited unexamined coverage manifest.
3. Multi-candidate bindings are never resolved by substring heuristics or arbitrary selection; they trigger discriminator queries, clarification, or `NEEDS_DISAMBIGUATION`.
4. All executed native queries pass through typed `QueryIntent` compilation or the quarantined AST gate with active SID cancellation on timeout.
5. Every reported answer value cites ledger-backed observations with valid proof contracts.
6. The 15-scenario evaluation matrix passes with documented layer metrics, baseline comparisons (B0/B1/Candidate), and full financial cost accounting.

