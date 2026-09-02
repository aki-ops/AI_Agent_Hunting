# AI Agent Hunting

Evidence-grounded, human-in-the-loop threat investigation agent.

## Documentation

- [`01_FINAL-ARCHITECTURE.md`](01_FINAL-ARCHITECTURE.md) — frozen system architecture and module boundaries.
- [`02_METHOD-AND-IMPLEMENTATION-PLAN.md`](02_METHOD-AND-IMPLEMENTATION-PLAN.md) — algorithms, data contracts, state machine, experiments and implementation plan.
- [`03_LITERATURE-AND-TRACEABILITY.md`](03_LITERATURE-AND-TRACEABILITY.md) — literature and provenance mapping.
- [`04-IMPLEMENTATION-CHECKLIST.md`](04-IMPLEMENTATION-CHECKLIST.md) — executable implementation checklist and MVP definition of done.
- [`context.md`](context.md) — concise operational context for coding agents.
- [`CONTRADICTION-RESOLUTION.md`](CONTRADICTION-RESOLUTION.md) — historical record of the P0 contract merge.

## Current MVP target

The MVP must run the deterministic loop with zero LLM calls, using a stubbed
abduction engine, a provider-scope manifest and a CDB/mock backend. A Cell is
`(ProviderScope, entity/ANY, time_bucket)`; it has no `event_family` axis.
Unknown native records remain observations with nullable `semantic_type`, and
known scopes without an adapter are explicit `UNQUERYABLE` coverage gaps. The
MVP supports both entity-bearing and entity-free alerts through wildcard Cells
and `BroadSweep`. The core is provider-neutral: future SIEM, EDR, IDS, cloud or
audit backends add adapters and capability bindings, not new Cell axes.
