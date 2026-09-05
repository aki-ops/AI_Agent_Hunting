# 04 — IMPLEMENTATION CHECKLIST (v4.1)

An item is complete only when a test, replay or captured execution artifact
supports it. `01` is the architecture contract, `02` is the method and `03`
is the traceability record. The checkboxes below describe the current repo,
not an unverified production claim.

## Phase 0 — contracts

- [x] `HuntRequest` accepts hypothesis/TTP/IOC/CVE/CTI/NL question without alert.
- [x] `HuntObjective`, `Hypothesis`, `EvidenceRequirement`, `Expectation` and `QueryPlan` are distinct.
- [x] `Cell(provider_scope, entity|ANY, time_bucket)` has no `event_family`.
- [x] `ProviderScope` preserves native partition, retention and gaps.
- [x] `ProviderOperation` declares schema, pagination and completeness.
- [x] `Observation` preserves native type and nullable semantic type.
- [x] `QueryResult.complete` is explicit; row count never implies EOF.
- [x] `UNKNOWN`, `INCONCLUSIVE`, `UNREACHABLE` and `UNSUPPORTED` are distinct.
- [x] `CoverageBound` separates scope, requirement and unknown boundaries.
- [x] Public state transitions are exercised through Action Controller methods.
- [ ] Remove remaining direct initialization/final-account assignments from the engine if strict controller-only mutation is required.

## Phase 1 — knowledge and semantic compilation

- [x] Version CVE/TTP/IOC/behavior records with source citations.
- [x] Behavior templates exist for process, remote authentication, network, file, persistence and web request.
- [x] Known CVE/TTP/IOC/template paths compile without LLM.
- [x] Unstructured free text uses one schema-validated semantic LLM call when `--llm api` is configured.
- [x] Free text without API fails safely with `STOP_INSUFFICIENT`.
- [x] No natural-language keyword fallback or statement/ID keyword attribution remains.
- [x] Require source references, assumptions, falsification and required fields.
- [x] Separate CVE exposure, preconditions, exploitation and post-exploitation.
- [x] Keep semantic entities and `search_hints` separate from confirmed evidence and Cells.

## Phase 2 — capabilities and queries

- [x] Version deployment-specific capability descriptors for CDB and Splunk.
- [x] Validate entity, time, fields, permissions and completeness.
- [x] Try query templates before LLM fallback.
- [x] Parse, allowlist, dry-run and validate generated native queries.
- [x] Cache validated plans by requirement/provider.
- [x] Missing capability becomes `UNSUPPORTED_REQUIREMENT` or `UNREACHABLE`.
- [x] Splunk manifest mode and dynamic discovery mode are both covered by tests.
- [ ] Add live EDR and IDS capability descriptors/adapters.

## Phase 3 — execution and evidence

- [x] CDB and Splunk adapters return complete `QueryResult` envelopes.
- [x] Splunk REST/oneshot execution and L+1 completeness are tested live.
- [x] Cursor/time-bounded continuation behavior is covered by adapter tests.
- [x] Raw observations are append-only and auditable.
- [x] Deterministic fact extraction handles fields and relationships.
- [x] Repeated observations form `EvidenceCard`s with representative IDs/counts.
- [x] Grouping preserves held-out malicious-event recall in tests.
- [x] LLM contexts receive cards/deltas, never the full raw ledger.
- [x] Ambiguous groups are batched; no per-event LLM call.

## Phase 4 — reasoning and control

- [x] Exact predicates and temporal/entity correlations are deterministic.
- [x] Evidence may be compatible with multiple hypotheses through typed expectations.
- [x] Semantic LLM output is advisory and schema/M3 validated.
- [x] Competing hypotheses remain until genuinely refuted.
- [x] Controller owns TEST/CONTROL/EXPAND/DISCOVER/PIVOT/REFINE/STOP selection.
- [x] Query, turn, runtime, scan and LLM budgets are enforced.
- [x] `STOP_RESOLVED`, `STOP_BOUNDED`, `STOP_EXHAUSTED_BY_BUDGET`,
  `STOP_INSUFFICIENT`, `STOP_UNSUPPORTED` and `STOP_UNREACHABLE` are distinct.
- [x] Web-chain support requires typed web/process/artifact correlation, not text matching.

## Phase 5 — reporting and coverage

- [x] Scope coverage is separate from requirement coverage.
- [x] Targeted query never implies full scope coverage.
- [x] `NO_EVIDENCE_FOUND` is never rendered as `BENIGN`.
- [x] Final account cites request, hypotheses, cards, observations, queries,
  diagnostics, residuals and coverage.
- [x] Report distinguishes not found, not observable, unqueryable and unknown source.
- [x] LLM usage/cost metadata is included in the state and report path.

## Phase 6 — experiments and gates

- [x] Hypothesis-only hunt runs without alert or PoC.
- [x] Unknown native event survives ingestion and evaluation.
- [x] Partial query cannot license negative evidence.
- [x] Evidence grouping does not reduce malicious-event recall beyond the test threshold.
- [x] LLM calls, tokens, latency and retries stay within the configured hard budget in tests.
- [x] Prompt injection cannot alter objective, state, scope or disposition.
- [x] CDB and mock SIEM/EDR/IDS adapter contract tests pass.
- [x] Live Splunk BOTSv1 adapter and web-hypothesis replay pass.
- [ ] Real LLM API compilation/query-fallback/evidence-refinement run with captured usage.
- [ ] Live EDR execution tests pass.
- [ ] Live IDS execution tests pass.

## Current verification evidence

The latest local run produced:

```text
216 passed, 8 warnings
2 representative CLI tests passed
compileall: PASS
ruff check: PASS
Splunk BOTSv1 entity-free replay:
  8 queries, 400 observations, 7 evidence cards,
  STOP_EXHAUSTED_BY_BUDGET, outcome UNKNOWN
```

The live run used the explicit offline semantic fixture, so its LLM cost was
`$0`. This validates the control flow and provider integration, not the quality
or price of a real external model.

## Definition of done

The current MVP is complete for a replayable CDB/Splunk vertical slice when a
structured request or explicit semantic test fixture produces validated
requirements, provider-neutral Cells, safe query plans, evidence grouping,
typed reasoning, bounded actions, auditable stopping and a coverage-aware
`FinalHuntAccount`.

Production readiness additionally requires a real LLM API capture, strict
controller-only mutation cleanup, and live EDR/IDS adapter gates.
