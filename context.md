# AI Agent Hunting — Project Context (v6)

Read the canonical documentation in this order:

1. `01_FINAL-ARCHITECTURE.md` — ClaimGraph, CapabilityGraph and EvidenceGraph;
2. `02_METHOD-AND-IMPLEMENTATION-PLAN.md` — executable evidence-seeking lifecycle;
3. `03_LITERATURE-AND-TRACEABILITY.md` — source grounding and claim boundaries;
4. `04-IMPLEMENTATION-CHECKLIST.md` — evidence-gated implementation plan;
5. `06-REFERENCE-ARCHITECTURE-DECISION.md` — detailed architecture decision;
6. `docs/01-REAL-PROVIDER-SPECIFICATIONS.md` — provider capabilities and operations.

## Core invariants

1. The LLM proposes a request-derived ClaimGraph; it does not create evidence.
2. Providers are selected through a CapabilityGraph with typed inputs/outputs.
3. Native queries are compiled and executed by adapters, not emitted by the LLM.
4. Raw observations are append-only; normalized facts are additive views.
5. EvidenceGraph claims require citations, field roles and sufficient completeness.
6. `Cell = (ProviderScope, entity | ANY, time_bucket)` is coverage only.
7. No keyword, event family or scenario branch controls the reasoning path.
8. Coverage gaps and incomplete queries cannot become negative or benign results.
9. LLM calls, query count, latency and cost are bounded and auditable.
