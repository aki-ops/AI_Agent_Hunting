# AI Agent Hunting — Project Context (v9)

## Document priority

1. `01_FINAL-ARCHITECTURE.md` — sole normative architecture.
2. `02_METHOD-AND-IMPLEMENTATION-PLAN.md` — executable method.
3. `03_LITERATURE-AND-TRACEABILITY.md` — external basis and claim boundary.
4. `04-IMPLEMENTATION-CHECKLIST.md` — implementation evidence and open work.
5. `08-EVIDENCE-BASED-REARCHITECTURE-PLAN.md` — ordered code migration plan.
6. `06-REFERENCE-ARCHITECTURE-DECISION.md` — accepted v9 decision.
7. `05-SCIENTIFIC-ARCHITECTURE-REVIEW.md` and `07-STRATEGIC-RESEARCH-REVIEW.md` — review records.
8. `docs/01-REAL-PROVIDER-SPECIFICATIONS.md` — provider boundary.

`report.md`, `baseline_reports/` and `artifacts/` are generated/historical and never override the documents above.

## Current status

The v9 Evidence-Grounded Progressive Hunt Graph is the accepted target. The repository is under migration. Existing classes and passing unit tests do not imply that proof, graph planning, controller or evaluation are integrated.

## Core invariants

1. Every input kind reaches one `SemanticGoalGraph` and one `OutcomeContract`.
2. `OutcomeContract` supports factual answers, hypothesis verdicts and population discovery.
3. LLM output is a proposal. It cannot establish proof, binding, scope mutation or stopping.
4. A Semantic Acceptance Gate checks structure, provenance, scope, outcome utility and semantic uncertainty before execution.
5. AND/OR/GATE are executable graph semantics.
6. Candidate ambiguity is cardinality-aware; singular ambiguity triggers discrimination or user clarification.
7. Provider operation metadata grants route eligibility only. An approved executable ProofContract verifies cited observations.
8. Execution, coverage, proof and route states are independent.
9. A single deterministic controller owns classify, recovery and stop decisions.
10. `PARTIAL + 0 rows` is never bounded absence.
11. Provider-native fields, sources and queries stay behind provider contracts.
12. Evaluation metrics must come from actual pipeline runs with independent labels.

## Immediate P0 work

Follow `08` in order:

1. authority-gap tests;
2. canonical OutcomeContract/state/taxonomy;
3. unified semantic entry point and acceptance gate;
4. executable graph semantics;
5. CandidateSet and clarification;
6. ProofEngine;
7. one controller loop;
8. actual evaluation runner.

Do not prioritize source ranking or SPL optimization before these reasoning gates pass.

