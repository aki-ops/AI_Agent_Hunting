# AI Agent Hunting — Project Context (v5.0)

Read the canonical documentation in this order:
1. `01_FINAL-ARCHITECTURE.md` — Canonical system boundaries and Case Graph model;
2. `02_METHOD-AND-IMPLEMENTATION-PLAN.md` — Executable relation-first lifecycle;
3. `03_LITERATURE-AND-TRACEABILITY.md` — 26-source literature grounding and decision matrix;
4. `04-IMPLEMENTATION-CHECKLIST.md` — Active v5 implementation checklist;
5. `docs/01-REAL-PROVIDER-SPECIFICATIONS.md` — Field roles and provider operations.

---

## Core Objectives & Invariants

1. **Investigation Case Graph as Center of State**: The reasoning unit of the agent is the Case Graph.
2. **Cell is Purely Coverage/Execution Address**: `Cell = (ProviderScope, entity | ANY, time_bucket)` tracks physical execution partitions, not the agent's mental model.
3. **Relation-First Execution**: Queries are triggered strictly to prove an unresolved edge in the graph for a known source node. Broad sweeps are never the default starting point.
4. **Strict Field Role Isolation**: `client_ip` ≠ `server_ip`, `sensor_host` ≠ `endpoint_host`, `account_name` ≠ `person`.
5. **Truthful Stopping Taxonomy**: If identity or causal paths cannot be proven, stop as `STOP_INCONCLUSIVE_*`. Never report `NOT_FOUND` or benign behavior due to coverage gaps or unproven identity.
6. **Bounded LLM Boundary**: Free text compilation is at most 1 call; LLM explainer receives only the verified `EvidenceSubgraph`. Zero raw SPL generation.
