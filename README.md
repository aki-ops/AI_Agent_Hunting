# AI Agent Hunting (v8)

This repository implements an evidence-grounded threat hunting and cyber investigation agent based on a **Contract-Grounded Progressive Hunt Graph**.

The architecture operates across two planes:
1. **Control Plane**: Provider manifests, source catalog, semantic vocabulary, human-approved proof contracts, query compilers, and ground-truth evaluation corpus.
2. **Hunt Plane**: A deterministic, progressive 10-step lifecycle (Steps A–J) with bounded LLM semantic planning, quarantined query synthesis, and strict evidence verification.

```text
Request
  -> Freeze Request & Budget (Step A)
  -> LLM Semantic Compilation C1: GoalGraph + AnswerContract (Step B)
  -> Deterministic Validation (Step C)
  -> AND/OR/GATE Graph Planning (Step D)
  -> Progressive Frontier F0–F4 Discovery (Step E)
  -> Controlled Entity Binding & CandidateSet (Step F)
  -> Typed QueryIntent (EXPLORE/DISCRIMINATE/PROVE) & Quarantined Native Gate (Step G)
  -> Evidence Pipeline: Row -> Observation -> Fact -> CandidateRelation (Step H)
  -> ProofContract Evaluation & Verification (Step I)
  -> 9-State Stopping Taxonomy & 6-Part Report + Machine Run Account (Step J)
```

## Three Non-Negotiable Invariants

1. **LLM is a semantic planner, not a semantic oracle.** The LLM may propose goals, candidate sources, field mappings, queries, and explanations. Only deterministic validators, adapters, and human-approved `ProofContract` evaluators may promote a claim or answer to verified status.
2. **No full-schema prompt, no fixed Top-K cutoff.** The catalog of sources and fields remains outside the hot LLM prompt. The agent expands a progressive frontier (F0–F4) per unresolved goal. Unexamined sources are explicitly recorded as coverage gaps; shortlists never license negative claims.
3. **Never auto-bind ambiguous candidates without proof.** If multiple entities match, the agent must execute a `DISCRIMINATOR` query or halt for human clarification (`NEEDS_DISAMBIGUATION`). It never selects candidates by substring heuristic or arbitrary ranking.

## Canonical Documents

1. [08-EVIDENCE-BASED-REARCHITECTURE-PLAN.md](08-EVIDENCE-BASED-REARCHITECTURE-PLAN.md) — Candidate master plan, scientific critique resolution, and execution roadmap.
2. [01_FINAL-ARCHITECTURE.md](01_FINAL-ARCHITECTURE.md) — Architectural boundaries, Two Planes, and data contracts.
3. [02_METHOD-AND-IMPLEMENTATION-PLAN.md](02_METHOD-AND-IMPLEMENTATION-PLAN.md) — Executable Steps A–J, C1–C6 LLM call table, and financial cost accounting.
4. [03_LITERATURE-AND-TRACEABILITY.md](03_LITERATURE-AND-TRACEABILITY.md) — Peer-reviewed literature grounding and decision traceability.
5. [04-IMPLEMENTATION-CHECKLIST.md](04-IMPLEMENTATION-CHECKLIST.md) — Evidence-gated implementation checklist (Phases 0–8).
6. [05-SCIENTIFIC-ARCHITECTURE-REVIEW.md](05-SCIENTIFIC-ARCHITECTURE-REVIEW.md) — Scientific principles and local contribution boundaries.
7. [06-REFERENCE-ARCHITECTURE-DECISION.md](06-REFERENCE-ARCHITECTURE-DECISION.md) — Reference architecture decision record and operational loop.
8. [07-STRATEGIC-RESEARCH-REVIEW.md](07-STRATEGIC-RESEARCH-REVIEW.md) — Strategic critique on science, cost, and scalability.
9. [docs/01-REAL-PROVIDER-SPECIFICATIONS.md](docs/01-REAL-PROVIDER-SPECIFICATIONS.md) — Real provider contracts, capabilities, and field roles.

## Installation

```bash
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

## Running

```bash
python main.py --hypothesis "Amber Turing visited a competitor website. What domain was it?"
```

## Tests

```bash
python -m pytest tests/unit -q
python -m compileall -q src main.py
ruff check .
```

