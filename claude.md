# Repository Working Rules (v8.0)

Read `context.md` first, then follow canonical documents in priority order:
1. `08-EVIDENCE-BASED-REARCHITECTURE-PLAN.md` — candidate master plan and execution roadmap;
2. `01_FINAL-ARCHITECTURE.md` — canonical architecture (Control & Hunt Planes);
3. `02_METHOD-AND-IMPLEMENTATION-PLAN.md` — executable Steps A–J, C1–C6 call table, and cost accounting;
4. `03_LITERATURE-AND-TRACEABILITY.md` — literature grounding and architectural traceability;
5. `04-IMPLEMENTATION-CHECKLIST.md` — evidence-gated implementation checklist (Phases 0–8);
6. `06-REFERENCE-ARCHITECTURE-DECISION.md` — reference architecture decision record;
7. `07-STRATEGIC-RESEARCH-REVIEW.md` — strategic research critique.

---

## Three Non-Negotiable Invariants

1. **LLM is a semantic planner, not a semantic oracle.** The LLM may propose goals, candidate sources, field mappings, queries, and explanations. Only deterministic validators, adapters, and human-approved `ProofContract` evaluators may promote a claim or answer to verified status.
2. **No full-schema prompt, no fixed Top-K cutoff.** The catalog of sources and fields remains outside the hot LLM prompt. The agent expands a progressive frontier (F0–F4) per unresolved goal. Unexamined sources are explicitly recorded as coverage gaps; shortlists never license negative claims.
3. **Never auto-bind ambiguous candidates without proof.** If multiple entities (hosts, accounts, IPs, artifacts) match, the agent must execute a `DISCRIMINATOR` query or halt for human clarification (`NEEDS_DISAMBIGUATION`). It never selects candidates by substring heuristic or arbitrary ranking.

---

## Core Architectural Invariants

- The reasoning unit is the **Contract-Grounded Progressive Hunt Graph** spanning Control Plane and Hunt Plane (Steps A–J).
- `Cell` is strictly `(ProviderScope, entity | ANY, time_bucket)` for execution coverage, never an ontology or thinking graph.
- Strict field role isolation: `client_ip` ≠ `server_ip`, `endpoint_host` ≠ `server_host`, `account_name` ≠ `person`.
- Never bind web servers (`jabbah`, `we1149srv`, IIS) as client workstations.
- C1 Semantic Compilation context is isolated: receives **only** request text, vocabulary schemas, and time policy (zero provider schema, zero raw SPL).
- Dynamic LLM source mappings default to `RETRIEVAL_CAPABLE`; only approved `ProofContract` records can materialize `PROOF_CAPABLE`.
- Queries are compiled from typed `QueryIntent` (`EXPLORE`, `DISCRIMINATE`, `PROVE`). Quarantined SPL fallback must pass AST allowlist and manifest binding, with backend SID cancellation on client timeout.
- 9-state stopping taxonomy: `ANSWER_PROVED`, `BOUNDED_NOT_FOUND`, `NEEDS_DISAMBIGUATION`, `COVERAGE_EXHAUSTED`, `BUDGET_EXHAUSTED`, `BACKEND_DEGRADED`, `SAFETY_QUARANTINE`, `VALIDATION_FAILED`, `ABORTED_BY_USER`.
- Total investigation cost is tracked and reported: $C_{run} = C_{llm} + C_{splunk} + C_{control} + C_{analyst}$.

---

## Documentation Integrity

- `report.md` is an ephemeral per-hunt output artifact, **not** an architecture document.
- All canonical documents (`01`–`08`, `CLAUDE.md`, `README.md`, `context.md`, `docs/01`) must remain synchronized with the v8 Contract-Grounded Progressive Hunt Graph.
- `[x]` in `04-IMPLEMENTATION-CHECKLIST.md` is strictly forbidden without automated test, replay, or captured execution evidence.

---

## Agent Autonomy & Execution Directive

- **Autonomous Proactivity**: Decide the optimal implementation adhering to v8 invariants and execute directly to completion.
- **Evidence-Based Rigor**: Never manufacture proof, never bypass verification contracts, and fail closed when telemetry or contracts are missing.


