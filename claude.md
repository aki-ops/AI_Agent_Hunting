# Repository Working Rules (v5.0)

Read `context.md` first, then use `01_FINAL-ARCHITECTURE.md` as canonical
architecture, `02` for executable method, `03` for literature traceability,
and `04` for verified checklist gates.

---

## Core Architectural Invariants

- The reasoning unit is the **Investigation Case Graph**.
- `Cell` is strictly `(ProviderScope, entity | ANY, time_bucket)` for execution coverage, never an ontology or thinking graph.
- **Relation-First Rule**: Unresolved edge with known source entity $\rightarrow$ valid provider operation $\rightarrow$ verified relation $\rightarrow$ pivot.
- Never execute broad/wildcard network queries before human subject identity is verified.
- Strict field role isolation: `client_ip` ≠ `server_ip`, `endpoint_host` ≠ `server_host`, `account_name` ≠ `person`.
- Never bind web servers (`jabbah`, `we1149srv`, IIS) as client workstations.

---

## LLM & Verification Boundary

- Free-text semantic compilation: at most 1 call. Must emit schema-strict `InvestigationCase`. Zero raw SPL.
- Known CVE/TTP/IOC inputs compile deterministically (zero LLM calls).
- Grounded explanation receives **only** the verified `EvidenceSubgraph`.
- Relation verification is 100% deterministic (citations, field roles, temporal checks).
- Incomplete telemetry, timeouts, or unproven edges stop as `STOP_INCONCLUSIVE_*`, never `NOT_FOUND`.

---

## Documentation Integrity

- `report.md` is an ephemeral per-hunt output artifact, **not** an architecture document.
- Every architectural change must update `01`, `02`, `03`, `04`, and `docs/01` first.

---

## Agent Autonomy & Execution Directive

- **Autonomous Proactivity**: Do not ask the user for permission, clarification, or confirmation. Always decide the optimal implementation and execute directly to completion.

