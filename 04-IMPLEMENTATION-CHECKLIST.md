# 04 — IMPLEMENTATION CHECKLIST (v4)

An item is complete only with a test, replay or captured execution artifact.
`01` is the architecture source of truth; `02` is the method; `03` is the
traceability record.

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
- [x] Only the Action Controller changes HuntState.


## Phase 1 — knowledge and hypothesis

- [x] Version CVE/TTP/IOC/behavior records with source citations.
- [x] Add behavior templates for process, remote authentication, network, file and persistence.
- [x] Compile structured hypotheses without LLM.
- [x] Use LLM only for unstructured/novel input with schema validation.
- [x] Require source references, falsification and required fields.
- [x] Reject unsupported or injection-distorted requirements.
- [x] Separate CVE exposure, preconditions, exploitation and post-exploitation.


## Phase 2 — capabilities and queries

- [x] Version deployment-specific capability descriptors.
- [x] Validate entity, time, fields, permissions and completeness.
- [x] Try query templates before LLM fallback.
- [x] Parse, allowlist, dry-run and validate generated queries.
- [x] Cache validated plans by requirement/provider/schema.
- [x] Missing capability becomes `UNSUPPORTED` or `UNREACHABLE`.


## Phase 3 — execution and evidence

- [x] Adapters return complete QueryResult envelopes.
- [x] Cursor pagination and bounded time-split fallback work.
- [x] Raw observations are append-only and auditable.
- [x] Deterministic fact extraction handles fields and relationships.
- [x] Repeated observations form EvidenceGroups with representative IDs/counts.
- [x] Grouping preserves held-out malicious-event recall.
- [x] LLM receives cards/deltas, never the full raw ledger.
- [x] Ambiguous groups are batched; no per-event LLM call.


## Phase 4 — reasoning and control

- [x] Exact predicates and temporal/entity correlations are deterministic.
- [x] Evidence may be compatible with multiple hypotheses.
- [x] Semantic LLM output is advisory and M3-validated.
- [x] Competing hypotheses remain until genuinely refuted.
- [x] Controller owns TEST/EXPAND/DISCOVER/PIVOT/REFINE/STOP.
- [x] Query, turn, runtime, scan and LLM budgets are enforced.
- [x] `STOP_RESOLVED`, `STOP_BOUNDED` and `STOP_EXHAUSTED_BY_BUDGET` are distinct.


## Phase 5 — reporting and coverage

- [ ] Scope coverage is separate from requirement coverage.
- [ ] Targeted query never implies full scope coverage.
- [ ] `NO_EVIDENCE_FOUND` is never rendered as `BENIGN`.
- [ ] Final account cites request, hypothesis, cards, observations, queries,
  diagnostics, residuals and coverage.
- [ ] Report distinguishes not found, not observable, unqueryable and unknown source.

## Phase 6 — experiments and production gate

- [ ] Hypothesis-only hunt runs without alert or PoC.
- [ ] Unknown native event survives ingestion and evaluation.
- [ ] Partial query cannot license negative evidence.
- [ ] Evidence grouping does not reduce malicious-event recall beyond threshold.
- [ ] LLM calls, tokens, latency and retries stay within hard budget.
- [ ] Prompt injection cannot alter objective, state, scope or disposition.
- [ ] CDB/mock SIEM, EDR and IDS adapter contract tests pass.
- [ ] Live SIEM, EDR and IDS execution tests pass before production claims.

## Definition of done

The MVP is complete when a hypothesis-only CDB vertical slice completes with
validated requirements, provider-neutral Cells, evidence grouping, bounded LLM
gates, competing-hypothesis evaluation, auditable state transitions and a
coverage-aware FinalHuntAccount. Production readiness remains a separate live
provider gate.
