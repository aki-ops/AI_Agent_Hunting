# 08 — V9 CODE REARCHITECTURE PLAN

**Date:** 2026-09-14
**Status:** approved migration plan; not implementation evidence
**Architecture:** `01_FINAL-ARCHITECTURE.md`
**Method:** `02_METHOD-AND-IMPLEMENTATION-PLAN.md`
**Progress:** `04-IMPLEMENTATION-CHECKLIST.md`

## 1. Objective

Migrate the current repository to the v9 Evidence-Grounded Progressive Hunt Graph without introducing case-specific routes. The first milestone isolates core reasoning from source ranking and query optimization. Splunk/BOTS v2 remains the live acceptance provider, but provider logic must remain behind contracts.

The plan fixes six root causes:

1. operation metadata is incorrectly acting as proof;
2. graph AND/OR/GATE declarations are not executed;
3. recovery/stopping classes exist but do not own the production loop;
4. several incompatible graph architectures remain active;
5. candidate ambiguity and LLM budgets do not follow the documented policy;
6. the evaluation runner assigns ideal results instead of running the agent;
7. the planner treats exact `guaranteed_relations` equality as a completed census, so a vocabulary mismatch plus deferred C2 yields zero queries and false `STOP_UNSUPPORTED`.

## 2. Rules for implementation

- Start each phase with failing counterexample tests.
- Do not preserve a legacy behavior merely to keep an old test green; classify the test as compatibility or obsolete.
- Do not add branches for email, web, Tor, ransomware, PowerPoint, Mallory, Amber, BOTS or a known answer.
- Provider-native source names and fields belong in manifests/adapters, not the reasoning kernel.
- A class counts as implemented only after the default production path invokes it.
- Do not optimize SPL/source retrieval until reasoning authority tests pass.
- Every state transition must be visible in the machine run account.

## 3. Workstream A — establish an honest baseline

### A1. Add failing regression tests

Create tests that currently fail:

1. `visited(endpoint, domain)` receives only a `file_path` row and must not verify.
2. A complete non-empty query with `relation_observable` metadata but no conforming proof remains `PROOF_GAP`.
3. A goal with unmet `GATE` dependency must not execute.
4. Changing a dependency from `AND` to `OR` changes readiness.
5. A singular slot with two candidates must not bind or execute proof downstream.
6. `QueryResult(complete=False, rows=[])` is `PARTIAL`.
7. `STOP_ANSWERED` is impossible before outcome verification.
8. A novel relation can be explored but not proven.

Target files:

- `tests/unit/test_v9_authority_boundaries.py`
- `tests/unit/test_v9_graph_semantics.py`
- `tests/unit/test_v9_controller_integration.py`

### A2. Record current behavior

Capture test result, the in-memory unrelated-row counterexample and one mock semantic run. Do not call them v9 success artifacts.

Acceptance gate A: counterexample tests exist and demonstrate the current defects before production changes.

## 4. Workstream B — canonical contracts

### B1. Implement OutcomeContract

Add a tagged union under `src/hunting/contracts/outcome.py`:

```text
FactualAnswerContract
  slots, types, cardinality, qualifiers, citations

HypothesisVerdictContract
  support obligations, refutation obligations, falsification, scope

PopulationDiscoveryContract
  population unit, candidate schema, prevalence/aggregation, coverage
```

The graph references one outcome contract. Existing answer contracts receive a compatibility converter.

### B2. Implement canonical runtime state

Create one `GoalRuntimeState` containing:

- execution status;
- coverage status;
- proof status;
- route status;
- candidate set;
- proof results;
- active/exhausted methods;
- last material delta.

### B3. Canonical stopping enum

Use exactly the v9 terminal names in runtime. Map `STOP_RESOLVED`, `STOP_BOUNDED` and other legacy names only during old artifact deserialization.

### B4. Normalize result contracts

Use `QueryResult.complete` everywhere. Remove or adapt callers expecting `completed`. Derive row count consistently from returned rows and provider declarations.

Acceptance gate B:

- all OutcomeContract variants serialize/deserialize;
- one goal cannot hold contradictory state axes;
- legacy stop aliases never appear in new run accounts;
- partial-empty classification test passes.

## 5. Workstream C — one semantic entry point

### C1. Refactor input adapters

Refactor `KnowledgeBehaviorCompiler` into:

```text
RequestAdapter
  -> structured knowledge adapter (CVE/TTP/IOC/CTI/PoC/alert)
  -> natural-language C1 adapter
  -> shared SemanticProposal
```

Both paths output the same `SemanticGoalGraph + OutcomeContract`. They may use different evidence sources, but cannot invoke separate execution engines.

### C2. Remove C1 scenario bias

Replace case examples in the production prompt with:

- schema definitions;
- neutral graph rules;
- provenance requirements;
- explicit uncertainty rules;
- a diverse, external versioned example set used only when experimentally enabled.

Remove values such as Mallory, Amber and personal email from the production prompt.

### C3. Implement Semantic Acceptance Gate

Refactor `SemanticGoalGraphValidator` into structural and semantic-risk stages:

1. deterministic schema/DAG/reference validation;
2. literal and provenance validation;
3. scope/outcome utility validation;
4. relation registry status;
5. semantic-risk classification;
6. C1V or user clarification when required.

Device descriptions must be represented as typed qualifiers. Do not determine them solely through a production word list. If the role is uncertain, preserve uncertainty and clarify rather than treating the text as a hostname.

### C4. Remove production graph fallback

Default API, structured and CLI routes must use the accepted semantic graph. Legacy ClaimGraph/InvestigationModel paths remain behind `--legacy-engine` temporarily, then are removed after parity.

Acceptance gate C:

- question, hypothesis, CVE, TTP, IOC and alert fixtures emit the same contract types;
- changing entity names does not change graph structure except grounded values;
- invented proper nouns are rejected/unbound;
- ambiguous semantics request clarification;
- no legacy executor runs by default.

## 6. Workstream D — execute graph semantics

### D1. Replace inferred dependency behavior

`SemanticGoalPlanner.compose()` must read `goal.dependencies`, `dependency_operator` and `gate_condition`. Variable flow may validate a dependency but cannot replace the declared dependency graph.

### D2. Implement proof methods

Represent each OR route as a `ProofMethod` with prerequisites, capability requirements, expected cost and status. Do not execute an alternate merely because another method returned ambiguous candidates.

### D3. Implement deterministic GATE evaluator

Gate predicates may inspect only verified runtime state and declared coverage/proof fields. Native query text and LLM prose are not executable gate expressions.

### D4. Audited graph expansion

If no typed path reaches a goal, the planner may propose an intermediate goal. The proposal returns to the Semantic Acceptance Gate and is versioned as graph revision `G0 -> G1`; it is not silently inserted.

Acceptance gate D:

- AND/OR/GATE tests execute different expected step sets;
- blocked gates issue zero provider queries;
- intermediate goals are visible in graph history;
- a one-goal factual lookup stays one goal when no intermediate binding is needed.

## 7. Workstream E — candidate control

### E1. Replace list variables with CandidateSet

Each candidate records value, type, provenance, status, supporting observations, competing values and discrimination history.

### E2. Enforce OutcomeContract cardinality

- singular target: more than one viable candidate is ambiguous, regardless of whether the count is below 32 or 5;
- plural target: propagate all allowed candidates within budget;
- only `VERIFIED_BINDING` satisfies proof-required downstream input.

### E3. Implement discriminator lifecycle

The planner creates a discriminator only if it has a declared differentiating field/relation and expected information gain. If no such action is available, return `STOP_NEEDS_CLARIFICATION` with candidates and evidence summaries.

Acceptance gate E:

- two singular host candidates never fan out into the proof goal;
- user selection resumes the same accepted graph without a second C1 call;
- selection provenance appears in the run account;
- plural outcomes retain legitimate multiple results.

## 8. Workstream F — executable proof authority

### F1. Upgrade ProofContract

Add:

- `evaluator_id` and evaluator version;
- supported subject/object type signatures;
- directional role bindings;
- action/state/temporal/correlation requirements;
- constraint evaluators;
- completeness requirement;
- negative-evidence licence;
- scope and limitation text.

### F2. Separate capability from evidence

`SourceMappingValidator` may approve an operation as a candidate proof route when its schema conforms. This does not make an execution proof-conforming.

### F3. Central ProofEngine

Create `src/hunting/evidence/proof_engine.py`:

```text
evaluate(goal, method, operation, observations, query_result, contract)
  -> ProofResult
```

It dispatches to approved evaluator functions. Every successful result cites exact observations and fields.

### F4. Remove semantic shortcut and legacy case verifier

Replace `base_relation_proven` in `engine.py` with ProofEngine output. Split generic reusable evaluators from legacy scenario branches; legacy branches cannot be called by v9.

Acceptance gate F:

- unrelated-row counterexample remains `PROOF_GAP`;
- role-swapped account/host evidence is rejected;
- co-occurrence without directional action is retrieval-only;
- generic file creation does not prove encryption;
- verified goals contain contract/evaluator/query/observation citations.

## 9. Workstream G — one controller loop

### G1. Define canonical attempt adapter

Convert `QueryResult`, candidate delta and ProofResult into one controller input. This prevents field-name mismatches between isolated classes and runtime objects.

### G2. Integrate the deterministic triad

Every attempt passes through:

```text
classify
choose_next_action
evaluate_stop
```

No engine branch directly sets a terminal state.

### G3. Replace legacy loops

Create one agenda queue over ready goals/methods. Delete or isolate the ClaimGraph loop and generic expectation/cell loop from the default path.

### G4. Outcome verification before stop

Dispatch to the appropriate factual/hypothesis/population verifier. `STOP_ANSWERED` or resolved hypothesis status is emitted only after this verifier passes.

### G5. LoopGuard integration

Fingerprint each action using goal, method, provider, source, bindings, window, hints, cursor and mode. Require material delta before repeating. Persist exhausted routes.

Acceptance gate G:

- code search finds one production agenda loop and one stop authority;
- all query attempts have an ObservationClass and next-action reason;
- repeated no-delta actions terminate deterministically;
- partial, ambiguity, proof gap, budget and backend failure reach distinct stops.

## 10. Workstream H — LLM scheduling

### H1. Shared configuration

CLI, tracker, SearchEnvelope and documentation read one `LLMBudgetPolicy`. Remove max-call drift between 4 and 5.

### H2. Global reservation scheduler

Reserve mandatory semantic and recovery capacity before optional calls. A possible initial policy for experiment, not a scientific constant:

```text
C1: 1 mandatory + at most 1 repair
C1V: at most 1, ambiguity only
C2: cache miss only, bounded batches
C3: deterministic compiler unsupported only
C4: grouped ambiguity only
C5: one material-deadlock replan
C6: disabled
```

When the global budget cannot cover an optional call, record a deferred action and coverage gap rather than silently continuing as if validation succeeded.

Acceptance gate H:

- every call has phase, reason, payload size, tokens, latency and validation status;
- optional source profiling cannot consume reserved proof/recovery capacity;
- malformed or truncated output cannot mutate graph/state;
- reports use actual provider usage when available and label estimates.

## 11. Workstream I — provider boundary cleanup

This workstream follows the reasoning milestone.

- Remove implicit CDB fallback when no provider is configured.
- Do not select `configured_adapters[0]` when no eligible provider route exists.
- Keep source and field semantics in provider descriptors/manifests.
- Keep deterministic provider compilers for approved operations.
- Keep LLM native query generation quarantined and optional.
- Archive BOTS v1 configuration/tests if the dataset is no longer supported.

Acceptance gate I: provider absence, ambiguity, unsupported relation and backend degradation produce explicit states without switching to an unrelated backend.

## 12. Workstream J — reporting

Update report construction after canonical state is available.

Required human sections:

1. request and outcome;
2. proposed/accepted graph and assumptions;
3. step trace with reasons and binding changes;
4. evidence and proof decisions;
5. native queries, result summaries and completeness;
6. coverage and complete cost.

The report must show what each query returned in human-readable form. `obs-*` identifiers are citations, not the explanation itself.

Acceptance gate J: an analyst can reconstruct why each query ran, what changed and why the controller stopped without reading raw JSON or hidden model reasoning.

## 13. Workstream K — real evaluation

### K1. Replace simulated runner

`eval/runner.py` must invoke the real candidate pipeline. It must not copy expected stop/answer or assign metric constants.

### K2. Independent corpus

For each scenario store independently reviewed:

- request and explicit scope;
- allowed/forbidden graph obligations;
- answer/verdict/discovery gold;
- admissible evidence/proof labels;
- expected ambiguity and stopping class.

Do not store known answers or entity routes in production prompts/code.

### K3. Layer metrics

Measure request-to-graph, retrieval, query, proof, binding, outcome, abstention and cost independently. A pipeline can have a correct final answer while using an invalid proof path; both must be reported.

### K4. Baselines and ablations

Execute:

- B0 legacy behavior;
- B1 direct LLM-to-read-only-query;
- v9 candidate;
- oracle graph;
- oracle capability mapping;
- no progressive frontier;
- no proof contract;
- no clarification.

### K5. Live gate

Run BOTS v2 through the actual CLI/API/provider path. A skipped test is not a pass. Provider/query optimization may follow only after reasoning correctness is demonstrated.

Acceptance gate K: metrics derive from serialized actual run accounts and can be recomputed independently.

## 13b. Workstream L — open-vocabulary capability matching

Normative refs: `01` §4.10, `02` Step E, `03` Progressive Capability Frontier.

**Defect to fix:** production compose matches `goal.relation` to `guaranteed_relations` by string. A C1 name miss plus deferred C2 yields 0 steps, `examined=100`, `STOP_UNSUPPORTED`. That is a false census, not a missing SMTP alias.

**Forbidden:** relation/scenario/vendor aliases; branches for email, SMTP, zip, attachment, Taedonggang, Frothly, Mallory, Amber, BOTS; SPL ranking; treating F1 rank as proof.

**Complete runtime (one unresolved goal):**

```text
accepted goal
  -> CapabilityQuery (types, answer role, constraint keys, relation text)
  -> F0 exact contract if labels already coincide
  -> F1 retrieve top-k ops/sources/fields from provider index (no LLM)
       remainder := unexamined
  -> if budget: F2 one C2 call on that shortlist only
       else: record C2 deferred coverage gap
  -> admission gate (reachable inputs, census fields, declared native mapping)
  -> admitted -> QueryIntent EXPLORE (PROVE only with ProofContract)
  -> execute -> Observation -> ProofEngine
  -> stop:
       admitted/explored, still open     -> continue agenda
       F1 done, F2 done or not budgeted,
         0 admitted                      -> STOP_UNSUPPORTED
       F1 skipped or C2 deferred         -> STOP_INCONCLUSIVE / STOP_BUDGET
```

### L1. CapabilityQuery

File: `src/hunting/contracts/capability_query.py` + builder in planner.

Fields: `goal_id`, `subject_type`, `object_type`, `answer_role`, `constraint_keys`, `relation_text`, `canonical_relation` (optional), `proposed_unregistered`.

Tests (`tests/unit/test_v9_capability_query.py`):

- two graphs with different relation strings and the same types/roles produce equal query keys except `relation_text`;
- grep kernel has no scenario tokens.

### L2. F1 retrieve (no LLM)

Files: `src/hunting/capabilities/semantic_index.py`, wire before `SemanticGoalPlanner.compose`.

Index documents from provider descriptors only (operation id, input/output kinds, roles, field names, fact kinds, relation strings if present). k is config (start 8). Return `hits` + `unexamined_ids`.

Tests:

- exact-name miss still returns k>0 when types/fields overlap;
- k bounded;
- unexamined IDs persist on `GoalRuntimeState.coverage`.

### L3. F2 one C2 call

Files: `src/hunting/engine.py` C2 loop, `CapabilityBatcher`, `SourceProfiler`.

One goal → one shortlist card set → at most one C2 call. Deferred/fail writes `RELATION_DEFERRED_BY_BUDGET` without flipping census to complete.

Tests:

- 100 sources do not create 100+ C2 batches;
- deferred C2 cannot set `examined=100`;
- C2 cannot run if F1 shortlist is empty (gap, not unsupported).

### L4. Admission gate

File: `src/hunting/capabilities/admission.py`. Called after F0/F1/F2 before `QueryIntent`.

Admit iff: input types reachable in the graph/catalog, cited fields exist in census, native mapping declared on the operation/source card. Mode `EXPLORE` until ProofContract exists.

Tests:

- admitted → ≥1 `QueryIntent` and ≥1 recorded query on a mock adapter;
- rejected → 0 queries, proof stays `NOT_ASSESSED`;
- LLM mapping that cites a missing field is rejected.

### L5. Planner + stop

Files: `semantic_goal_planner.py` (F1 hits as candidates, not equality-only), `engine.py` unresolved-goal stop, `recovery_controller.py`.

`STOP_UNSUPPORTED` only after F1 completed and F2 ran or was explicitly not budgeted, with zero admitted candidates. Else `STOP_INCONCLUSIVE` or `STOP_BUDGET`.

Tests (`tests/unit/test_v9_capability_matching.py`):

- exact-name miss + deferred C2 is not `STOP_UNSUPPORTED`;
- 0 queries with unexamined routes is not `COVERAGE_EXHAUSTED`;
- F1 hit + admission → mock query runs without C2.

Acceptance gate L: production matcher is not exact relation equality; C2 cannot replace F1; unknown-relation live hunts explore an admitted route or abstain with unexamined coverage; no new scenario/vendor string in the kernel.

## 14. Pull-request sequence

Keep changes reviewable in this order:

1. PR1 — authority-gap tests and truthful evaluation baseline;
2. PR2 — OutcomeContract, GoalRuntimeState and stop taxonomy;
3. PR3 — unified semantic compiler and acceptance gate;
4. PR4 — executable AND/OR/GATE planner;
5. PR5 — CandidateSet and clarification;
6. PR6 — ProofEngine and removal of metadata shortcut;
7. PR7 — integrated controller agenda loop;
8. PR8 — LLM scheduler and budget policy;
9. PR9 — legacy/provider cleanup;
10. PR10 — report and executable evaluation;
11. PR11 — non-skipped BOTS v2 acceptance run;
12. PR12 — Workstream L capability matching (F0–F2 + admission + stop).

Each PR updates `04` only after its acceptance tests pass.

## 15. Final acceptance scenarios

At minimum, the finished reasoning kernel must pass:

1. direct attribute lookup with one verified value;
2. multi-hop relation with exact prerequisite gates;
3. OR route fallback after complete failure;
4. multiple singular candidates requiring discrimination;
5. plural population result;
6. contradictory evidence quarantine;
7. complete bounded negative with licence;
8. partial-empty query remaining inconclusive;
9. unknown relation exploration without proof;
10. semantic ambiguity requiring user input;
11. prompt/provider content unable to change scope or stop;
12. hypothesis support/refutation with competing obligations;
13. population hunt with prevalence and explicit coverage;
14. API timeout/budget exhaustion with resumable state;
15. live BOTS v2 run with auditable graph, evidence, proof and cost;
16. vocabulary-mismatch goal (relation string absent from `guaranteed_relations`) either explores via F1/F2 admission or stops inconclusive with unexamined routes, never silent zero-query `STOP_UNSUPPORTED`.

## 16. Completion statement

The migration is complete only when the default production path—not a standalone class or simulated evaluator—implements the v9 flow. Until then, documentation must describe the repository as an evidence-informed architecture under implementation.

### Route migration decision

Workstream L now introduces an accepted, provider-neutral `CandidateRoute`
keyed by `goal_id`. F1/F2 output is route metadata; only an admitted
executable route reaches `SemanticGoalPlanner`, and it starts in `EXPLORE`
unless an approved proof contract permits `PROVE`. Relation-string matching
remains only at an explicit compatibility boundary while remaining callers
migrate; it is not evidence of route support and remains tracked for removal.
