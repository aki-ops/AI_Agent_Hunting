# Repository Working Rules (v9)

Read `context.md` and then the canonical documents in the order declared there.

## Architecture authority

- `01_FINAL-ARCHITECTURE.md` is the sole normative architecture.
- `02` defines runtime method; `08` defines migration work; `04` records evidence.
- Generated reports and artifacts never define intended behavior.
- Do not mark a checklist item complete because a class exists or a simulated test assigns expected values.

## Implementation rules

1. All request kinds use one SemanticGoalGraph production path.
2. Use `OutcomeContract` for factual, hypothesis and population outcomes.
3. Treat LLM outputs as untrusted proposals requiring validation.
4. Do not implement case branches for email, web, Tor, ransomware, PowerPoint, Mallory, Amber, BOTS or known answers.
5. Provider operation declarations are not evidence proof.
6. Only an approved executable ProofContract may verify a relation.
7. Implement declared AND/OR/GATE semantics exactly.
8. Never auto-select an ambiguous singular binding.
9. The deterministic controller is the only stop authority.
10. Preserve native evidence, citations, completeness, coverage and cost.
11. Keep provider names, fields and native query logic outside the reasoning kernel.
12. Add a failing counterexample before fixing an authority or reasoning defect.

## Current migration priority

Follow the pull-request sequence in `08-EVIDENCE-BASED-REARCHITECTURE-PLAN.md`. Core reasoning correctness precedes source ranking, query optimization and additional providers.

## Required verification

Run unit/static checks and the v9 counterexample suite. Live readiness requires non-skipped BOTS v2 tests. A green legacy suite alone is insufficient.

