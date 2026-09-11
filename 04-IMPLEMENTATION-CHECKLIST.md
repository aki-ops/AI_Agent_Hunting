# 04 — IMPLEMENTATION CHECKLIST (v7)

`[x]` is allowed only with an automated test, replay, or captured execution
artifact. The architecture source is `01`; the executable method is `02`; the
source/claim boundary is `03`; the detailed decision record is `06`.
The current executable semantic contract is `SemanticGoalGraph` plus
`LogicalPlan`; dynamic source profiling and `QueryIntent` are the v7 query
boundary. The older `ClaimGraph` remains a compatibility projection.

## Phase 0 — Baseline and repository alignment

- [x] Freeze current tests/reports as historical baseline; do not call them v6 evidence. (`baseline_tests.json`, `baseline_reports/`, `baseline_keyword_branches.txt`; 356 passed / 3 failed / 1 skipped on 2026-09-09. Failures are v5 keyword/email-graph tests, not v6 evidence.)
- [ ] Remove any remaining relation-first/template implementation language from code and ancillary docs. (catalogued in `baseline_keyword_branches.txt`; removal is Phase 2+.)
- [x] Establish `SemanticGoalGraph`, `LogicalPlan`, `CapabilityGraph` and the compatibility `ClaimGraph` contracts. (`src/hunting/contracts/semantic_graph.py`, `claim.py`, `capabilities.py`.)
- [x] Keep `Cell(provider_scope, entity|ANY, time_bucket)` only as coverage/execution coordinate.
- [ ] Confirm no `event_family`, `event_code`, keyword or answer-type field controls reasoning path. (`build_investigation_case_from_intent()` is compatibility-only; remaining legacy branches outside semantic compilation are tracked for Phases 4–7.)

## Phase 1 — Request and SemanticGoalGraph contracts

- [x] `HuntRequest` preserves raw content, kind, time policy, entities and provider hints. (`QUESTION` added; `NL_QUESTION` kept for compatibility.)
- [x] `Claim` supports attribute, relation, behaviour and controlled-absence predicates.
- [x] Every claim records provenance, dependencies, evidence requirements and acceptance rule.
- [x] Refutation, partial, unknown and unsupported states are distinct.
- [x] Invalid semantic-compiler output is rejected; validation never repairs it with a scenario template. (Native SPL/KQL/SQL is forbidden in this component; missing acceptance and mismatched `source_request_id` are rejected.)
- [x] Counterfactual requests demonstrate that claims follow the request, not keywords. (no `EmailClaim`/`TorClaim`; same keyword yields different claim sets.)

## Phase 2 — Provider Census and CapabilityGraph

- [x] Census records reachable providers, partitions, schemas, aliases, retention and permissions. (`ProviderCensusService`, provider census tests.)
- [x] `ProviderOperation` declares input kinds, output facts, pagination and completeness. (CDB/Splunk descriptors and capability contract tests.)
- [x] Provider selection is auditable: selected sources, rejected sources and reasons are stored. (`CapabilityGraph.audit` and provider census tests.)
- [x] Constraint contracts distinguish `supported_constraints` (provider can prove) from `searchable_constraints` (provider can narrow retrieval only); neither is inferred from field names.
- [x] A reachable provider that cannot satisfy a claim is not accepted as fallback. (Irrelevant-provider engine test.)
- [x] Unknown native event types and fields survive census/execution without being discarded. (Append-only observation and unknown-native regression tests.)

## Phase 2A — Dynamic source capability discovery

- [x] `TelemetryCensus` records source IDs, field coverage/types, bounded safe field sketches, query primitives and `schema_fingerprint` without assigning semantic labels from source names. (`TelemetrySourceProfile`; dynamic profile and schema-fingerprint tests.)
- [x] LLM `source_profiler` emits only census-referenced source/field-role/relation/probe proposals; it cannot invent source IDs, fields, entity values, selectors or evidence. (`test_profiler_accepts_only_census_referenced_mapping`.)
- [x] Proposal validator rejects invalid IDs, incompatible roles, untrusted values, policy-violating scope and injected instructions. (Census ID/field binding validation tests.)
- [x] Adapter-compiled bounded probes distinguish observable capability from claim evidence. (`BoundedProbeExecutor`, Splunk/CDB probe implementations and probe contract tests.)
- [x] Only successful probes materialize versioned `RuntimeCapability` records; failed/empty/incomplete probes remain auditable diagnostics. (`test_successful_probe_is_required_for_validated_capability` and materializer tests.)
- [x] Capability cache keys include provider, scope, permission state, schema fingerprint and requirement signature; schema changes invalidate cache. (`RuntimeCapabilityCache` schema invalidation test; engine uses cache-hit path.)
- [x] Relation-scoped batching schedules every discovered source and field per unresolved relation; scores affect ordering only and never discard candidates. (`CapabilityBatcher` tests.)
- [x] Source-profiler prompts contain compact relation candidates only; complete census profiles remain the deterministic validation authority. (Profiler context and engine integration tests.)
- [x] Provider profile limits are explicit coverage gaps; an unprofiled native source cannot be reported as complete discovery. (Splunk profile-discovery audit.)
- [ ] Static source-role maps are bootstrap hints only and cannot be selected as semantic truth without validated runtime provenance.

## Phase 3 — Semantic compilation and validation

- [x] LLM semantic compiler receives the request without provider catalog/schema context and emits only provider-neutral semantic graph JSON. (Compiler contract test.)
- [x] Semantic compiler cannot emit SPL/KQL/SQL, native event IDs, evidence or final verdicts. (`parse_and_validate_claim_graph()` validates the full raw response; prompt and rejection tests pass.)
- [x] No `is_email`, `is_tor`, `is_cve` or equivalent branch creates graph edges in the free-text compiler path. (The semantic compiler creates `SemanticGoalGraph`; the compatibility case graph is projection-only.)
- [ ] Technical prerequisites come only from operation contracts and are labelled as such. (Semantic projection no longer invents prerequisites; binder migration remains Phase 4.)
- [x] Claim-plan provenance and objective-preservation tests pass. (`source_request_id`, dependency, missing-acceptance and same-keyword/different-objective tests.)
- [ ] Prompt injection in request/telemetry cannot mutate objective, scope or disposition. (Request injection guard passes; telemetry-to-replan boundary remains Phase 6.)

Verified regression evidence: semantic compiler/planner/executor/adapter tests
pass; full-suite evidence remains a separate regression gate because live
provider and labelled evaluation are not yet production evidence.

## Phase 4 — Binding, action selection and native execution

- [x] Binder matches claim requirements to operations using typed inputs/outputs. (`test_binder_uses_declared_fact_contract_for_unseen_operation`.)
- [x] Semantic planner composes typed AND dependencies and declared OR alternatives without operation-name heuristics.
- [x] Identity grounding supports both `person -> endpoint` and `person -> account -> endpoint`; neither route assumes an account directory.
- [x] Downstream steps require complete upstream results and preserve runtime binding provenance; candidate bindings may be used for bounded exploratory retrieval but never for proof.
- [x] Complete-but-restricted outputs remain `CANDIDATE` until the operation proves every restriction; downstream retrieval keeps the warning and verdict gate. (`test_executor_uses_candidate_binding_for_retrieval_but_keeps_warning`.)
- [x] Ambiguous output bindings do not fan out automatically; rows remain auditable and the controller requests narrowing. (`test_executor_does_not_fan_out_ambiguous_output_bindings`.)
- [x] A relation row cannot satisfy required semantic restrictions unless the selected operation declares proof support; searchable restrictions remain explicitly unverified.
- [x] Action candidates contain relevance, completeness and cost diagnostics. (Capability-bound candidate regression test.)
- [ ] Controller never selects an action without an unresolved claim it can reduce.
- [ ] LLM ranking is optional and restricted to valid candidate IDs.
- [ ] Adapters compile only validated logical operations to native queries.
- [ ] Query allowlist, parameterization, pagination and bounded time split pass tests.
- [ ] `QueryResult.complete` is explicit; row count never implies EOF.
- [x] Planner emits graph-bound `QueryIntent` with validated role IDs, trusted bindings, narrow projection, explicit scope and expected output shape. (`QueryIntentSpec` and runtime operation compiler tests.)
- [x] Adapter compiles `QueryIntent` to parameterized native syntax without scenario/source-name routes. (Runtime Splunk/CDB operation execution tests.)
- [ ] Raw native-query fallback is reachable only when intent compilation explicitly cannot express the selected operation.
- [ ] Native candidate query is parsed to AST and rejected unless read-only, census-bound, explicitly time/result/scan bounded and dry-run validated.
- [ ] At most one validator-guided native-query repair occurs; repeated failure stops truthfully.

## Phase 5 — Observation and EvidenceGraph

- [ ] Raw observations are append-only with native type, fields, query ID and completeness.
- [ ] Normalized facts preserve field roles and never replace native data.
- [ ] Evidence cards retain representative observation IDs and held-out malicious-event recall.
- [ ] Candidate edges cannot become verified without cited observations.
- [ ] Schema-only fields cannot be rendered as observed values.
- [ ] Client/server/sensor and account/display-name role confusion is rejected.

## Phase 6 — Claim verification and bounded replanning

- [x] Semantic goal status distinguishes relation proof from unverified request restrictions; unsupported restrictions remain inconclusive.
- [x] LLM-proposed variable values are not query bindings until marked request-grounded or provider-observed; MacBook/device labels cannot become hosts by default.
- [ ] Claim acceptance checks citations, identity, fields, time, completeness and observability for every legacy compatibility path. (The semantic path now blocks unverified restrictions; legacy migration remains.)
- [ ] `SUPPORTED`, `REFUTED`, `PARTIAL`, `UNKNOWN` and `INCONCLUSIVE` are claim-level states.
- [ ] Replanning is triggered only by ambiguity, new evidence, or a coverage/capability gap.
- [ ] Replanning receives deltas/cards, not the full raw ledger.
- [ ] Every newly proposed claim returns through validation and capability binding.
- [ ] No-progress loops and repeated partial attribution are bounded.
- [x] Execution completion, relation proof and route exhaustion are separate per-goal states; complete-empty is never route exhaustion by itself.
- [x] Proof-aware readiness triggers profiling for static retrieval/proof/qualifier gaps and skips it only for a validated proof-capable route.
- [x] Progressive retrieval removes only declared retrieval predicates while retaining identity, scope, time, projection, row/page and proof bounds.
- [x] Generic state-transition verification accepts only ledger-backed cited observations in one provider/scope with compatible typed entities, parseable ordered timestamps inside the declared bound, exact validated-operation `action_roles`/`state_roles`/`temporal_roles`, and a stable `artifact_identity_roles` or `correlation_roles` value; suffixes and source names prove neither transition nor ransomware causality.

## Phase 7 — Reporting and cost

- [x] Report contains request, semantic decomposition, proof plan/state, runtime bindings, evidence/explanation, queries, answer/limits and cost.
- [x] Analyst report shows execution trace, compact returned sample fields and readable evidence values; raw payload remains omitted.
- [ ] Every final value cites a fact/observation ID.
- [ ] Query rationale states which claim it attempted to reduce.
- [ ] Coverage separates claim, scope, query-completeness and evidence coverage.
- [x] Incomplete/unobservable telemetry never renders `BENIGN` or definitive absence.
- [ ] LLM calls, tokens, latency, retries, query count and runtime are recorded.
- [x] LLM prompt budget is preflighted before network dispatch; oversized prompts are rejected without consuming a call. (`test_create_llm_caller_preflights_before_call`.)
- [ ] Report links each runtime capability to profiler proposal, validator decision, probe query, `QueryIntent` and native-query gate decision when used.
- [ ] Explanation failure degrades to deterministic verified facts with parse status.

## Phase 8 — Evaluation and F1 gate

- [ ] Label factual lookup questions and acceptable answer values.
- [ ] Label required/forbidden claims for plan evaluation.
- [ ] Label evidence observation IDs and causal edges for multistep cases.
- [ ] Label malicious campaigns/TTPs and scope for hunt detection cases.
- [ ] Report claim precision/recall/F1, evidence precision/recall, edge F1 and answer F1 separately.
- [ ] Report citation-grounding rate, unsupported-expansion rate and false-verdict rate.
- [ ] Report cost/latency/query-volume/budget-stop metrics per dataset and model.
- [ ] Report source-role mapping precision/recall, probe precision and hallucinated-source/field rate separately from answer F1.
- [x] Run counterfactual, partial-telemetry, provider-failure and prompt-injection tests.
- [ ] Run cross-dataset replay; do not claim generality from one BotSv2 scenario.

## Phase 9 — Production gate

- [ ] Splunk adapter passes the full v6 contract/replay suite.
- [x] CDB adapter passes the same semantic contract without changing `SemanticGoalGraph` (role mapping is fixed; full semantic replay remains).
- [ ] EDR/IDS/mail providers are added only as adapters with capability tests.
- [ ] Provider expansion does not introduce provider-specific semantic branches.
- [ ] Live runs produce reproducible artifacts containing plan, capabilities, queries, observations, evidence, verdict, coverage and cost.

## Definition of done

The v6 MVP is complete only when a labelled hypothesis/question vertical slice
can create a request-derived SemanticGoalGraph without scenario templates, discover and
audit the capabilities it uses, bind claims to safe operations, preserve and
verify evidence, replan within bounded state, produce a concise cited report,
and report F1/grounding/cost metrics on labelled data.

Production readiness remains separate until live provider, scale, cost and
security gates pass.
