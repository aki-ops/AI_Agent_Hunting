# 02 — METHOD AND IMPLEMENTATION PLAN (v9)

`01_FINAL-ARCHITECTURE.md` is normative. This file defines the executable method for the v9 reasoning kernel. `08` contains the code migration plan and acceptance order.

## 1. Runtime method

### Step A — Freeze the run

Create immutable `RequestContract`, `SearchEnvelope E0`, `BudgetEnvelope` and run identifiers. Preserve the original text and explicit entities exactly. Provider discovery may occur here for availability, but provider schema is not supplied to C1.

Output: frozen request, scope and budget.

### Step B — C1 semantic proposal

C1 converts the request into:

- one `SemanticGoalGraph`;
- one typed `OutcomeContract`;
- provenance spans;
- assumptions, uncertainties and forbidden inferences.

C1 does not select indexes, sourcetypes, provider operations or native query text. All request kinds must reach this canonical contract, whether compiled by LLM, deterministic CTI adapter or a hybrid compiler.

Output status: `PROPOSED`, never `VERIFIED`.

### Step C — Semantic Acceptance Gate

Perform deterministic structural checks:

- graph references and DAG validity;
- entity/literal preservation;
- provenance span validity;
- hard-scope preservation;
- outcome-slot reachability;
- explicit dependencies and gate predicates;
- absence of provider-native syntax;
- registered versus novel relations.

Then apply selective semantic review. If an interpretation is novel, conflicting, low-confidence or changes the user's objective, run C1V or ask the user. C1V cannot prove the interpretation; it can approve execution risk, request clarification or reject malformed expansion.

Output: `ACCEPTED`, `NEEDS_CLARIFICATION` or `REJECTED` graph.

### Step D — Build the obligation agenda

The planner reads the accepted graph directly.

- A goal is ready when its `AND` dependencies are verified.
- An `OR` goal exposes admissible proof methods and succeeds when one method proves it.
- A `GATE` goal remains blocked until its deterministic predicate over runtime state evaluates true.
- The planner may propose intermediate typed goals required by a capability path, but the graph revision must pass Step C and be recorded.

Select actions by mandatory status, answer utility, information gain and bounded cost. Ranking affects order only.

### Step E — Discover capabilities progressively

For the current unresolved goal only:

1. F0: approved proof-capable operations;
2. F1: catalog metadata and semantic index;
3. F2: adjacent sources through declared joins/field relations;
4. F3: bounded dynamic profiling;
5. F4: approved exhaustive discovery.

Unexamined sources remain explicit coverage gaps. Retrieval scores cannot create proof authority or license a negative conclusion.

### Step F — Manage candidate bindings

Store every value in a `CandidateSet` with provenance. Apply answer/variable cardinality:

- singular + one proof-supported candidate: bind;
- singular + multiple candidates: execute discriminator, otherwise ask user;
- plural: preserve all admissible candidates within budget;
- candidate-only evidence may support exploration but not downstream proof that requires a verified input.

No selection by first row, substring, provider order or fixed hostname rules.

### Step G — Compile and execute EvidenceAction

The planner emits provider-neutral `QueryIntent` in one mode:

- `EXPLORE`: find candidate values;
- `DISCRIMINATE`: distinguish candidates;
- `PROVE`: retrieve evidence required by an approved contract.

Prefer a deterministic provider compiler. C3 may propose a native query only when no compiler supports the intent. The query must pass parsing, read-only allowlist, scope binding, field/role checks, time/row/scan/runtime limits and cancellation support.

Output: a `QueryResult` whose `executed_ok`, `complete`, rows, cursor, diagnostics, scan and runtime are explicit.

### Step H — Build evidence without semantic promotion

Append raw rows as immutable `Observation` records. Extract `FieldFact` records while preserving native provenance. Group repeated evidence for LLM context, but retain raw observation IDs.

Rows and extracted values are candidates. They are not verified relations.

### Step I — Evaluate executable ProofContracts

For each goal attempt:

1. locate the approved contract and exact evaluator version;
2. validate subject/object direction and native role mappings;
3. evaluate action, state, temporal, identity, correlation and qualifier obligations;
4. verify completeness requirements;
5. emit `ProofResult` with exact citations and missing obligations.

An operation declaration can make a route eligible. Only the evaluator can change `ProofStatus` to `VERIFIED` or `REFUTED`.

### Step J — Recover, verify outcome and stop

The single controller loop executes:

```text
ObservationClass = classify(QueryResult, CandidateSet, ProofResult, SearchEnvelope)
NextAction       = choose_next_action(ObservationClass, routes, budget, LoopGuard)
StopDecision     = evaluate_stop(OutcomeContract, GoalRuntimeState, coverage, budget)
```

Before `STOP_ANSWERED`, run the appropriate outcome verifier. The verified value must be present in cited evidence and every mandatory gate must be complete.

## 2. Observation classification

Use one canonical precedence order:

1. `QUERY_INVALID`
2. `QUERY_FAILURE`
3. `PARTIAL`
4. `EMPTY`
5. `CONTRADICTORY`
6. `AMBIGUOUS`
7. `PROOF_GAP`
8. `VERIFIED`

`CANDIDATES` is a proof state/detail, not a ninth outcome that can bypass ambiguity handling.

## 3. Controller recovery rules

| Class | Default action |
|---|---|
| QUERY_INVALID | deterministic repair or alternate route |
| QUERY_FAILURE | retry within policy, alternate route or unreachable |
| PARTIAL | cursor pagination or bounded time split |
| EMPTY | relax declared hint, alternate route or exhaust route |
| CONTRADICTORY | quarantine conflict and run one bounded re-check |
| AMBIGUOUS | discriminator or clarification |
| PROOF_GAP | seek a proof-capable route or stop unsupported/inconclusive |
| VERIFIED | update goal and outcome state |

Every recovery action derives a new envelope without changing immutable constraints.

## 4. LLM policy and cost

Mandatory budget reservation order:

1. C1 semantic compile;
2. one repair or C1V review if required;
3. reserve at least one proof/recovery decision opportunity;
4. optional C2/C3/C4/C5 calls compete for the remaining budget;
5. C6 remains disabled by default.

Do not assign independent component quotas whose sum exceeds the global budget without a scheduler. Record prompt/completion tokens, model, latency, retries, validation result and estimated cost for every call.

Default ceilings remain configuration candidates, not architecture constants. The documentation and CLI must read the same configuration object.

## 5. Implementation boundaries

### Reasoning kernel

Provider-independent:

- request/outcome/graph contracts;
- semantic acceptance;
- obligation planner;
- candidate state;
- proof state;
- recovery controller;
- stopping and reporting.

### Provider boundary

Provider-specific:

- manifests and native partitions;
- source/field discovery;
- query compilation and execution;
- pagination, cancellation and completeness semantics.

Provider code cannot define a semantic investigation path.

### Knowledge boundary

CVE/TTP/IOC/CTI records may contain cited behavior knowledge, but adapters convert that knowledge into the same graph contracts. They do not execute a separate legacy architecture.

## 6. Implementation sequence

1. Make documentation and status claims truthful.
2. Add failing authority-gap and graph-semantics tests.
3. Canonicalize contracts and stop taxonomy.
4. Route every input type into one graph.
5. implement explicit AND/OR/GATE planning.
6. Integrate executable proof evaluation.
7. Integrate the deterministic triad and one agenda loop.
8. Remove production legacy routes and scenario branches.
9. Replace simulated evaluation with executable evaluation.
10. Run mock-provider, API and BOTS v2 live acceptance suites.

## 7. Definition of done

The reasoning kernel is complete only when:

- a row with incompatible semantics cannot prove a relation despite operation metadata;
- all declared graph dependencies and gates affect execution;
- all terminal states originate from the canonical controller;
- ambiguous singular bindings never auto-select;
- every output contract type completes on mock data;
- all input kinds use the same production graph path;
- evaluation metrics are computed from actual executions;
- reports show structured decisions, returned evidence, proof outcomes and cost;
- live-provider claims are based on non-skipped BOTS v2 runs.
