# AI Agent Hunting — Project Context (v8)

Read the canonical documentation in this order:

1. `08-EVIDENCE-BASED-REARCHITECTURE-PLAN.md` — candidate master plan, scientific critique resolution, and execution roadmap;
2. `01_FINAL-ARCHITECTURE.md` — Contract-Grounded Progressive Hunt Graph (Control & Hunt Planes);
3. `02_METHOD-AND-IMPLEMENTATION-PLAN.md` — executable Steps A–J, C1–C6 LLM calls, and cost accounting;
4. `03_LITERATURE-AND-TRACEABILITY.md` — external literature grounding and architectural traceability;
5. `04-IMPLEMENTATION-CHECKLIST.md` — evidence-gated implementation checklist (Phases 0–8);
6. `06-REFERENCE-ARCHITECTURE-DECISION.md` — reference architecture decision record;
7. `07-STRATEGIC-RESEARCH-REVIEW.md` — strategic critique on science, cost, and scalability;
8. `docs/01-REAL-PROVIDER-SPECIFICATIONS.md` — provider capabilities, operations, and field roles.

## Three Non-Negotiable Invariants

1. **LLM is a semantic planner, not a semantic oracle.** The LLM may propose goals, candidate sources, field mappings, queries, and explanations. Only deterministic validators, adapters, and human-approved `ProofContract` evaluators may promote a claim or answer to verified status.
2. **No full-schema prompt, no fixed Top-K cutoff.** The catalog of sources and fields remains outside the hot LLM prompt. The agent expands a progressive frontier (F0–F4) per unresolved goal. Unexamined sources are explicitly recorded as coverage gaps; shortlists never license negative claims.
3. **Never auto-bind ambiguous candidates without proof.** If multiple entities match, the agent must execute a `DISCRIMINATOR` query or halt for human clarification (`NEEDS_DISAMBIGUATION`). It never selects candidates by substring heuristic or arbitrary ranking.

## Core Architectural Invariants

1. The reasoning model is a **Contract-Grounded Progressive Hunt Graph** operating across a Control Plane (manifests, catalog, proof contracts) and a Hunt Plane (Steps A–J).
2. The semantic compilation (Call C1) emits `GoalGraph` and `AnswerContract` without provider catalog or raw SPL context.
3. Providers and sources are explored through a 5-stage progressive frontier F0–F4 (Certified $\rightarrow$ Metadata $\rightarrow$ Adjacent $\rightarrow$ Profiling $\rightarrow$ Exhaustive).
4. Entities are tracked in a `CandidateSet`. Auto-binding requires a unique proof-supported candidate; ambiguities trigger `DISCRIMINATOR` or `NEEDS_DISAMBIGUATION`.
5. Queries are expressed as typed `QueryIntent` (`EXPLORE`, `DISCRIMINATE`, `PROVE`). Unregistered queries pass through a quarantined AST gate with SID cancellation on timeout.
6. Raw observations are immutable and append-only; normalized `FieldFact` entries retain native provenance.
7. Verification requires an approved `ProofContract` (`STRUCTURALLY_VALID`, `RETRIEVAL_CAPABLE`, `PROOF_CAPABLE`). Co-occurrence defaults to `retrieval_only`.
8. Execution terminates deterministically under the 9-state stopping taxonomy and outputs a 6-part human report and a machine `run_account.json`.
9. All runs track comprehensive financial and operational cost: $C_{run} = C_{llm} + C_{splunk} + C_{control} + C_{analyst}$.

