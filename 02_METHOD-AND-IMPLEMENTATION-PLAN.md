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

For the current unresolved goal only, build a `CapabilityQuery` from types, constraint keys, relation text and answer role. Do not require `goal.relation == operation.guaranteed_relations`. Do not add scenario aliases.

1. F0: exact approved proof-capable operations when labels already coincide.
2. F1: retrieve top-k operation, source and field documents from the provider semantic index (no LLM). The in-repo index uses hashed n-gram dense similarity plus typed overlap; rank is not relevance. Record unretrieved items as unexamined.
3. F2: at most one C2 call over that shortlist to propose mappings. Compact cards only. A deferred or failed C2 is a coverage gap, not `STOP_UNSUPPORTED`.
4. F3: adjacent sources through declared joins/field relations on admitted candidates.
5. F4: approved exhaustive discovery.

Admission gate before `QueryIntent`: reachable input types, census-backed fields, declared native mapping. Admitted routes may `EXPLORE`. `PROVE` still requires an approved ProofContract.

Unexamined sources remain explicit coverage gaps. Retrieval scores cannot create proof authority or license a negative conclusion. Enumerating 100 sources without F1/F2 admission must not set `examined=100`.

### Step F — Manage candidate bindings

Store every value in a `CandidateSet` with provenance. Apply answer/variable cardinality:

- singular + one proof-supported candidate: bind;
- singular + multiple candidates: execute a declared discriminator, otherwise ask user;
- plural: preserve all admissible candidates within budget;
- candidate-only evidence may support exploration but not downstream proof that requires a verified input;
- EXPLORE records candidates and cannot `SEEK_PROOF`; PROVE without an approved route preserves the limitation.

No selection by first row, substring, provider order or fixed hostname rules.

### Step G — Compile and execute EvidenceAction

The planner emits provider-neutral `QueryIntent` in one mode:

- `EXPLORE`: find candidate values;
- `DISCRIMINATE`: distinguish candidates;
- `PROVE`: retrieve evidence required by an approved contract.

Prefer a deterministic provider compiler. The default path records `QueryIntent -> LogicalQueryPlan -> NativeQuery` as an operation envelope and an explicit `unknown` cost when no backend estimator exists. Incomplete results paginate from the logical cursor or split the time window when the operation has no cursor pagination. Declared `correlation_roles` become adjacency plans and stay `NOT_PROOF`. C3 may propose a native query only when no compiler supports the intent. The query must pass `admit_c3_candidate`: parsing, read-only allowlist, scope binding, field/role checks, time/row/scan/runtime limits and rejection of truncated output.

Output: a `QueryResult` whose `executed_ok`, `complete`, rows, cursor, diagnostics, scan and runtime are explicit.

### Step H — Build evidence without semantic promotion

Append raw rows as immutable `Observation` records. Extract `FieldFact` records while preserving native provenance. Project them into an append-only `EvidenceGraph` whose edge classes are observed transition, provenance dependency or declared causal attribution. Graph proximity is `NOT_PROOF`. Group repeated evidence for LLM context, but retain raw observation IDs.

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

### 6.1 Goal-scoped route formation

Before semantic planning, the runtime resolves each `CapabilityQuery` into a
goal-scoped `CandidateRoute`. F1/F2 may rank typed operation/source/field
documents, but only an admitted `EXECUTABLE` route is passed to the planner.
The route carries provider/source/schema provenance and an explicit execution
mode. A missing or deferred route remains an unexamined capability gap; it is
not converted into `STOP_UNSUPPORTED`.

The planner therefore receives `candidate_routes[goal_id]` and does not infer
that a relation is supported merely because its text equals an operation
label. Compatibility matching remains only for callers that have not yet
migrated to route formation and is covered by the removal gate in `09`/`10`.

### 6.2 Lifecycle and analyst boundary

The runtime may emit a `HuntLifecycleRecord` containing preparation, the actual
run account, cited analyst decisions, Act items and pending knowledge
candidates. `CapabilityArtifact`, `HuntPackage` and `AnalyticPackage` are
versioned control-plane inputs; only approved, tested packages may be used as
F0 routes. The default engine compiles those packages into the same
`ProviderOperation` / Observation / ProofContract path and records package
versions on the run account. An LLM, a single hunt, or package metadata cannot
approve content or verify a relation. Workspace annotations and decisions are
append-only views over the run and never change semantic obligations, proof,
budget or stop state directly. The default hunt attaches a `WorkspaceSnapshot`
reconstructed from the machine account (query audit, timeline, entity pivot,
native events, proof obligations, stop explanation, coverage) and emits an Act
or explicit `no_action`. Binding review is a typed analyst action; it never
auto-selects an ambiguous singular binding. Knowledge promotion is a separate
reviewed registry operation with scope, temporal validity and conformance tests.

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
