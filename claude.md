# Repository Working Rules

Read `context.md` first, then use `01_FINAL-ARCHITECTURE.md` as the canonical
architecture, `02_METHOD-AND-IMPLEMENTATION-PLAN.md` as the method, `03` for
source traceability and `04` for implementation status.

## Architecture rules

- `Cell` is exactly `(ProviderScope, entity | ANY, time_bucket)`.
- Never add `event_family`, `event_code` or operation as a Cell axis.
- `ProviderScope` and `ProviderOperation` are separate contracts.
- `EvidenceRequirement` describes the question; adapters answer it.
- Preserve native types and unknown native records.
- `search_hints` are query constraints, never evidence, confirmed entities or
  coverage addresses.
- Scope coverage and requirement coverage are separate.
- A complete targeted query does not establish full scope coverage.

## Determinism and LLM boundary

- Known CVE/TTP/IOC/template inputs compile deterministically.
- Free-text semantic compilation requires the configured API LLM or stops as
  `STOP_INSUFFICIENT`.
- No natural-language keyword fallback or statement/ID keyword attribution.
- Query templates and allowlists run before any planner fallback.
- Fact extraction, predicates, correlation, controls, action selection,
  stopping and final disposition are deterministic.
- LLM output is schema-validated and advisory. It cannot execute a query,
  mutate state, select an action or determine final disposition.
- Group evidence before LLM refinement; never call once per raw observation.

## Security and provenance

- Raw log content is untrusted and must not be placed in repeated LLM context.
- Incomplete, stale, unsupported or unreachable results cannot license a
  negative conclusion.
- Every report claim cites query/observation/card IDs and a coverage bound.
- Keep literature-derived principles separate from thesis engineering choices
  and measured implementation results.
- Audit records are append-only.

## Testing rules

- Every contract and state transition needs a known-answer test.
- Test sparse and entity-bearing hypotheses, unknown native records, partial
  results, stale scopes, unsupported requirements and prompt-injection payloads.
- CDB and Splunk are the current executable providers.
- Real LLM API, EDR and IDS execution evidence is required before production
  claims for those paths.
