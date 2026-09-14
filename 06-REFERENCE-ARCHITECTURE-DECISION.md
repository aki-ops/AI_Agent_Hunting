# 06 — ARCHITECTURE DECISION RECORD: Evidence-Grounded Progressive Hunt Graph (v9)

## Status

Accepted as the target architecture on 2026-09-14. Production implementation and empirical validation remain pending under `08` and `04`.

## Context

Previous versions repeatedly failed in general ways:

- natural-language intent was reduced by keywords or scenario examples;
- fixed person/account/host/IP/domain paths distorted unrelated questions;
- provider metadata and returned rows were promoted to semantic proof;
- ambiguous entities were ranked or selected without sufficient evidence;
- multiple legacy and new execution paths produced different behavior;
- LLM calls competed for budget without preserving later reasoning capacity;
- green tests included a simulated evaluation runner rather than actual executions.

The project needs flexibility without allowing an LLM to invent proof.

## Decision

Adopt one provider-neutral reasoning kernel based on:

1. immutable `RequestContract` and `SearchEnvelope`;
2. one `SemanticGoalGraph` for all input kinds;
3. a typed `OutcomeContract` union;
4. a selective `Semantic Acceptance Gate`;
5. explicit AND/OR/GATE obligation planning;
6. progressive capability discovery;
7. cardinality-aware candidate binding and mixed-initiative clarification;
8. typed EvidenceAction/QueryIntent before provider-native queries;
9. immutable observation/fact provenance;
10. independently approved executable ProofContracts;
11. one deterministic recovery/stopping controller;
12. executable, independently labelled evaluation.

## Outcome contract decision

Threat hunting is not always a factual question. The architecture therefore uses:

```text
FactualAnswerContract
HypothesisVerdictContract
PopulationDiscoveryContract
```

This prevents proactive hunts from being forced into a scalar answer and prevents factual lookups from being forced into a multi-stage attack playbook.

## Semantic authority decision

The LLM proposal is not accepted merely because it is valid JSON or references text in the request. Structural/provenance checks are mandatory, and semantically uncertain or novel interpretations are selectively reviewed or presented to the user. A review model supplies advisory findings; deterministic policy or the user makes the acceptance decision.

There is no claim that deterministic code can validate the meaning of arbitrary natural language without an ontology, independent model or human input.

## Proof authority decision

Provider capabilities answer “can this source retrieve potentially relevant data?” A ProofContract evaluator answers “do these exact cited observations establish this relation under this scope?” These authorities are separate.

The following shortcut is forbidden:

```text
complete query + non-empty rows + operation proof_mode
    => verified relation
```

## Graph decision

The GoalGraph is an obligation DAG. It may be minimal for a simple lookup or multi-hop for reconstruction. It does not prescribe person → endpoint → IP unless those obligations are present in the accepted graph or are introduced through an audited graph revision.

AND/OR/GATE fields are executable semantics, not report metadata.

## Candidate decision

Ambiguity is relative to the target contract:

- a singular answer cannot accept several unranked viable values;
- a plural answer may preserve several values;
- a discriminator is preferred when it can reduce ambiguity within budget;
- otherwise the controller asks the user or stops for clarification.

## LLM decision

Calls are isolated, demand-driven and globally scheduled. Optional capability profiling, query synthesis or narrative cannot consume reservations required by semantic compilation, proof recovery or clarification.

The LLM never controls proof, scope mutation, candidate binding or stopping.

## Consequences

Positive:

- removes dependence on case-specific routes;
- makes semantic and evidential errors observable;
- supports both investigation and proactive hunting;
- allows new providers behind stable contracts;
- supports honest abstention and cost accounting.

Costs:

- requires a maintained proof-contract/evaluator registry;
- some novel relations cannot receive automatic definitive verdicts;
- clarification may be required;
- real evaluation and gold labelling are substantially more expensive than unit tests;
- legacy removal may temporarily break tests that encode old behavior.

## Rejected alternatives

### Unconstrained LLM agent

Rejected because generated queries, interpretations and verdicts are not independently enforceable.

### Fixed scenario playbooks

Rejected as the universal architecture because they do not generalize. Reviewed playbooks may still be optional proof methods, never mandatory routes.

### Full-schema prompt

Rejected as the default due to cost, noise and scaling. Approved exhaustive discovery remains a bounded fallback.

### Fixed Top-K source cutoff

Rejected as proof/coverage authority because a relevant source can be omitted. Ranking may order progressive exploration only.

### Pure deterministic parser

Rejected for arbitrary natural language. Deterministic compilation remains appropriate for validated structured inputs, but must emit the same graph contract.

## Acceptance criteria

This decision is considered implemented only when the P0 items in `04` pass and the actual pipeline demonstrates:

- incompatible rows cannot prove a relation;
- graph operators change runtime execution;
- ambiguous singular bindings never auto-select;
- outcome verification precedes success stopping;
- all input types use one reasoning path;
- actual B0/B1/candidate evaluation replaces assigned metrics;
- live BOTS v2 tests are not skipped.
