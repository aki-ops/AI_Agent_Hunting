# 04 — IMPLEMENTATION CHECKLIST (v6)

`[x]` is allowed only with an automated test, replay, or captured execution
artifact. The architecture source is `01`; the executable method is `02`; the
source/claim boundary is `03`; the detailed decision record is `06`.

## Phase 0 — Baseline and repository alignment

- [x] Freeze current tests/reports as historical baseline; do not call them v6 evidence. (`baseline_tests.json`, `baseline_reports/`, `baseline_keyword_branches.txt`; 356 passed / 3 failed / 1 skipped on 2026-09-09. Failures are v5 keyword/email-graph tests, not v6 evidence.)
- [ ] Remove any remaining relation-first/template implementation language from code and ancillary docs. (catalogued in `baseline_keyword_branches.txt`; removal is Phase 2+.)
- [x] Establish `ClaimGraph` and `CapabilityGraph` as v6 contracts. (`src/hunting/contracts/claim.py`, `capabilities.py`; `EvidenceGraph` deferred to Phase 6.)
- [x] Keep `Cell(provider_scope, entity|ANY, time_bucket)` only as coverage/execution coordinate.
- [ ] Confirm no `event_family`, `event_code`, keyword or answer-type field controls reasoning path. (`build_investigation_case_from_intent()` is now ClaimGraph-only; remaining legacy branches outside semantic compilation are tracked for Phases 4–7.)

## Phase 1 — Request and ClaimGraph contracts

- [x] `HuntRequest` preserves raw content, kind, time policy, entities and provider hints. (`QUESTION` added; `NL_QUESTION` kept for compatibility.)
- [x] `Claim` supports attribute, relation, behaviour and controlled-absence predicates.
- [x] Every claim records provenance, dependencies, evidence requirements and acceptance rule.
- [x] Refutation, partial, unknown and unsupported states are distinct.
- [x] Invalid LLM output is rejected; validation never repairs it with a scenario template. (raw SPL/KQL/SQL, missing acceptance, mismatched `source_request_id`.)
- [x] Counterfactual requests demonstrate that claims follow the request, not keywords. (no `EmailClaim`/`TorClaim`; same keyword yields different claim sets.)

## Phase 2 — Provider Census and CapabilityGraph

- [ ] Census records reachable providers, partitions, schemas, aliases, retention and permissions.
- [ ] `ProviderOperation` declares input kinds, output facts, pagination and completeness.
- [ ] Provider selection is auditable: selected sources, rejected sources and reasons are stored.
- [ ] A reachable provider that cannot satisfy a claim is not accepted as fallback.
- [ ] Unknown native event types and fields survive census/execution without being discarded.

## Phase 3 — Semantic compilation and validation

- [ ] LLM receives request plus compact capability context and emits only ClaimGraph JSON. (ClaimGraph-only output is implemented; compact runtime census context awaits Phase 2.)
- [x] LLM cannot emit SPL/KQL/SQL, native event IDs, evidence or final verdicts. (`parse_and_validate_claim_graph()` validates the full raw response; prompt and rejection tests pass.)
- [x] No `is_email`, `is_tor`, `is_cve` or equivalent branch creates graph edges in the free-text compiler path. (`build_investigation_case_from_intent()` accepts only `ClaimGraph`; counterfactual email/artifact/unseen-request tests pass.)
- [ ] Technical prerequisites come only from operation contracts and are labelled as such. (Semantic projection no longer invents prerequisites; binder migration remains Phase 4.)
- [x] Claim-plan provenance and objective-preservation tests pass. (`source_request_id`, dependency, missing-acceptance and same-keyword/different-objective tests.)
- [ ] Prompt injection in request/telemetry cannot mutate objective, scope or disposition. (Request injection guard passes; telemetry-to-replan boundary remains Phase 6.)

Verified regression evidence on 2026-09-09: focused compiler/ClaimGraph suite 69 passed; full unit suite 369 passed with 25 TLS warnings.

## Phase 4 — Binding, action selection and native execution

- [ ] Binder matches claim requirements to operations using typed inputs/outputs.
- [ ] Action candidates contain relevance, completeness and cost diagnostics.
- [ ] Controller never selects an action without an unresolved claim it can reduce.
- [ ] LLM ranking is optional and restricted to valid candidate IDs.
- [ ] Adapters compile only validated logical operations to native queries.
- [ ] Query allowlist, parameterization, pagination and bounded time split pass tests.
- [ ] `QueryResult.complete` is explicit; row count never implies EOF.

## Phase 5 — Observation and EvidenceGraph

- [ ] Raw observations are append-only with native type, fields, query ID and completeness.
- [ ] Normalized facts preserve field roles and never replace native data.
- [ ] Evidence cards retain representative observation IDs and held-out malicious-event recall.
- [ ] Candidate edges cannot become verified without cited observations.
- [ ] Schema-only fields cannot be rendered as observed values.
- [ ] Client/server/sensor and account/display-name role confusion is rejected.

## Phase 6 — Claim verification and bounded replanning

- [ ] Claim acceptance checks citations, identity, fields, time, completeness and observability.
- [ ] `SUPPORTED`, `REFUTED`, `PARTIAL`, `UNKNOWN` and `INCONCLUSIVE` are claim-level states.
- [ ] Replanning is triggered only by ambiguity, new evidence, or a coverage/capability gap.
- [ ] Replanning receives deltas/cards, not the full raw ledger.
- [ ] Every newly proposed claim returns through validation and capability binding.
- [ ] No-progress loops and repeated partial attribution are bounded.

## Phase 7 — Reporting and cost

- [ ] Report contains request, claim analysis, evidence/explanation, queries, answer/limits and cost.
- [ ] Every final value cites a fact/observation ID.
- [ ] Query rationale states which claim it attempted to reduce.
- [ ] Coverage separates claim, scope, query-completeness and evidence coverage.
- [ ] Incomplete/unobservable telemetry never renders `BENIGN` or definitive absence.
- [ ] LLM calls, tokens, latency, retries, query count and runtime are recorded.
- [ ] Explanation failure degrades to deterministic verified facts with parse status.

## Phase 8 — Evaluation and F1 gate

- [ ] Label factual lookup questions and acceptable answer values.
- [ ] Label required/forbidden claims for plan evaluation.
- [ ] Label evidence observation IDs and causal edges for multistep cases.
- [ ] Label malicious campaigns/TTPs and scope for hunt detection cases.
- [ ] Report claim precision/recall/F1, evidence precision/recall, edge F1 and answer F1 separately.
- [ ] Report citation-grounding rate, unsupported-expansion rate and false-verdict rate.
- [ ] Report cost/latency/query-volume/budget-stop metrics per dataset and model.
- [ ] Run counterfactual, partial-telemetry, provider-failure and prompt-injection tests.
- [ ] Run cross-dataset replay; do not claim generality from one BotSv2 scenario.

## Phase 9 — Production gate

- [ ] Splunk adapter passes the full v6 contract/replay suite.
- [ ] CDB adapter passes the same semantic contract without changing ClaimGraph.
- [ ] EDR/IDS/mail providers are added only as adapters with capability tests.
- [ ] Provider expansion does not introduce provider-specific semantic branches.
- [ ] Live runs produce reproducible artifacts containing plan, capabilities, queries, observations, evidence, verdict, coverage and cost.

## Definition of done

The v6 MVP is complete only when a labelled hypothesis/question vertical slice
can create a request-derived ClaimGraph without scenario templates, discover and
audit the capabilities it uses, bind claims to safe operations, preserve and
verify evidence, replan within bounded state, produce a concise cited report,
and report F1/grounding/cost metrics on labelled data.

Production readiness remains separate until live provider, scale, cost and
security gates pass.
