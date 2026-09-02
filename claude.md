# CLAUDE.md

Working rules for AI agents in this repository. Read `context.md` first, then
use `01` for architecture, `02` for implementation contracts, and `04` for
the checklist.

## Think before coding

- State assumptions when they affect scope or correctness.
- Treat `01`/`02` as the active v3 contracts; report conflicts instead of
  silently inventing a fourth design.
- Keep parameters provisional unless an experiment establishes them.
- Prefer the smallest change that closes a tested gap.

## Project-specific architecture rules

- Five modules only: M1 ledger, M2 abduction, M3 constraints, M4 controller,
  M5 adapter/reporter.
- `Cell` is `(ProviderScope, entity/ANY, time_bucket)`. Never add
  `event_family` to Cell or use it as the coverage denominator.
- `ProviderScope` (native data partition) and `ProviderOperation` (query
  function) are separate contracts.
- `EvidenceRequirement` describes the question; provider operations answer it.
  Unsupported requirements are explicit, not fabricated.
- Preserve `native_type`; `semantic_type=None` is valid. Never drop an unknown
  event or force it into `OTHER`.
- `UNQUERYABLE` is counted in coverage; `UNKNOWN_SOURCE` is reported outside
  the denominator. Scope and requirement coverage are separate.
- A complete targeted query does not mean the whole scope is explored.

## Determinism and security

- Field/entity extraction, taint, retrieval, coverage, controls, action
  selection, stopping and disposition are deterministic.
- LLM input contains structured extracted fields and taint only; raw log
  content never enters a prompt.
- M2 cannot mutate observations, attribution or statuses. No LLM output can
  select a control, stop the run, or compute disposition.
- Tainted entities may generate leads within a budget; deferred entities are
  counted, never silently discarded.
- Queries are template/allowlist-first. Validate provider, scope, fields,
  predicates, time bounds, pagination and limits before execution.

## Evidence and provenance

- Every claim cites observation/query IDs and a coverage bound.
- Keep `INHERITED`, `ADAPTED`, `COMPOSED`, `ORIGINAL`, `ENGINEERING` and
  experimental status labels honest.
- Do not cite `UNVERIFIED` references as established evidence.
- Do not use null-baseline results or benchmark outcomes beyond their measured
  scope.
- Audit logs are append-only.

## Testing standards

- Every contract and state transition has a known-answer unit test.
- Integration tests cover entity-bearing and entity-free alerts, unknown native
  records, partial results, stale scopes, unqueryable scopes and unsupported
  requirements.
- Security tests cover command lines, URLs, DNS names, usernames and filenames;
  assert raw-content isolation, hidden-target blocking and LLM mutation guards.
- MVP means a replayable CDB/mock vertical slice with zero LLM calls. Real
  SIEM/EDR/IDS production claims require real adapter execution evidence.
