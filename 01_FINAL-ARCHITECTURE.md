# 01 — FINAL ARCHITECTURE (v9)

## 1. Source of truth and implementation status

This file is the sole normative architecture source for the project.

- `02_METHOD-AND-IMPLEMENTATION-PLAN.md` defines the executable method.
- `03_LITERATURE-AND-TRACEABILITY.md` separates external support from local claims.
- `04-IMPLEMENTATION-CHECKLIST.md` records implementation evidence; a design statement is not completion evidence.
- `05`–`07` are review and decision records.
- `08-EVIDENCE-BASED-REARCHITECTURE-PLAN.md` is the migration plan from the current code to this architecture.
- `report.md`, `baseline_reports/` and `artifacts/` are generated or historical evidence, not specifications.

Status: **accepted target architecture; implementation and empirical validation are incomplete**.

## 2. Objective and boundary

The system is an **Evidence-Grounded Progressive Hunt Graph** agent. It accepts:

- a factual cyber-investigation question;
- a threat hypothesis;
- an alert or PoC description;
- CTI, TTP, IOC or CVE material;
- a scheduled or population-level hunt request.

It produces one of three typed outcomes:

1. a grounded factual answer;
2. a supported, refuted or inconclusive hypothesis assessment;
3. a bounded population-discovery result with prevalence, candidates and coverage.

The architecture is a general reasoning kernel. It is not a catalogue of scenario playbooks, not an unconstrained LLM, and not a claim that all telemetry relations can be proved.

## 3. Canonical runtime flow

```text
Input
  -> RequestAdapter
  -> immutable RequestContract + SearchEnvelope + BudgetEnvelope
  -> C1 Semantic Graph Proposal
       GoalGraph + OutcomeContract + provenance + uncertainty
  -> Semantic Acceptance Gate
       structure + provenance + scope + independent semantic checks
       -> proceed | clarify | reject
  -> Obligation Planner
       explicit AND / OR / GATE semantics
  -> Progressive Capability Frontier
        CapabilityQuery from the accepted graph
        F0 exact contract -> F1 semantic retrieve (no LLM)
        -> F2 budgeted C2 rerank of the shortlist
        -> F3 adjacent/probe -> F4 approved exhaustive
        admission gate before any query
        deferred/unexamined is not unsupported
  -> Controlled Candidate Binding
       unique proof -> bind
       ambiguous -> discriminate or ask the user
  -> EvidenceAction / QueryIntent
       EXPLORE | DISCRIMINATE | PROVE
  -> provider compiler or quarantined native-query proposal
  -> bounded execution
  -> QueryResult -> Observation -> FieldFact -> CandidateRelation
  -> executable ProofContract evaluation
  -> combined attempt classification
  -> deterministic RecoveryController
       choose_next_action -> update GoalRuntimeState -> evaluate_stop
  -> OutcomeContract verification
  -> auditable report + machine run account
```

## 4. Non-negotiable invariants

### 4.1 LLM is a proposer, never a proof authority

An LLM may propose interpretation, goals, relations, source mappings, query intents, native queries and narrative. It cannot:

- mark a relation `VERIFIED`;
- bind an ambiguous entity;
- broaden hard scope;
- license negative evidence;
- choose a terminal state;
- introduce an answer not bound to cited observations.

`complete query + rows + relation_observable metadata` is never sufficient proof.

### 4.2 One production reasoning graph

All input kinds compile into one `SemanticGoalGraph`. `ClaimGraph`, `InvestigationModel` and `InvestigationCase` may exist only behind an explicit legacy compatibility boundary until removed. They cannot control the default production route.

### 4.3 OutcomeContract, not universal AnswerContract

```text
OutcomeContract =
    FactualAnswerContract
  | HypothesisVerdictContract
  | PopulationDiscoveryContract
```

- `FactualAnswerContract` specifies slots, type, cardinality, required qualifiers and citations.
- `HypothesisVerdictContract` specifies support, refutation and falsification obligations.
- `PopulationDiscoveryContract` specifies population, candidate unit, prevalence/aggregation, ranking semantics and coverage requirements.

### 4.4 Graph semantics are explicit

- `AND`: every mandatory dependency must be proved.
- `OR`: one admissible proof method may satisfy the goal; failed alternatives remain auditable.
- `GATE`: the downstream goal is not runnable until a deterministic predicate over verified state is true.
- A typed capability path may propose intermediate goals, but cannot silently change the accepted graph.

The graph is an obligation DAG, not necessarily a causal graph. Causal claims require stronger temporal and directional proof contracts.

### 4.5 Semantic acceptance is selective

Structural validation cannot prove that an arbitrary natural-language request was understood correctly. Before execution, the system validates:

- exact preservation of user-named entities and literals;
- provenance spans for goals, qualifiers and outcome slots;
- no provider/query syntax in the semantic graph;
- no unsupported objective expansion;
- graph/outcome consistency;
- known relation semantics or explicit `PROPOSED_UNREGISTERED` status;
- declared assumptions and uncertainty.

Novel, conflicting or low-confidence interpretations trigger clarification or bounded exploration without proof authority.

### 4.6 Ambiguity is cardinality-aware

Candidate handling is determined by the target slot cardinality, not a global list-size heuristic.

- A singular slot with multiple viable candidates requires a discriminator or user decision.
- A plural slot may preserve multiple candidates.
- Candidate ranking is exploration metadata, never proof.
- Substring similarity, row order and provider order cannot select a candidate.

### 4.7 ProofContract is executable authority

A proof contract is approved, versioned and independently reviewed. It contains:

```text
relation / attribute semantics
subject and object roles
direction
native role requirements
action/state/temporal requirements
correlation identity
constraint evaluators
completeness requirements
negative-evidence licence
executable evaluator_id
scope and known limitations
```

An operation may be:

- `STRUCTURALLY_VALID`;
- `RETRIEVAL_CAPABLE`;
- `PROOF_CAPABLE` only when an approved contract evaluator passes on cited observations.

Unknown relations remain queryable for discovery, but cannot receive a definitive semantic verdict until a contract is approved or a human accepts a bounded interpretation.

### 4.8 Execution, coverage, proof and route are independent

Each goal carries four orthogonal states:

```text
ExecutionStatus: NOT_STARTED | EXECUTED | PARTIAL | FAILED | CANCELLED
CoverageStatus:  UNKNOWN | PARTIAL | COMPLETE | UNREACHABLE
ProofStatus:     NOT_ASSESSED | RETRIEVAL_ONLY | PROOF_GAP | VERIFIED | REFUTED
RouteStatus:     UNPLANNED | ACTIVE | EXHAUSTED | NO_PROGRESS
```

`PARTIAL + 0 rows` is not `NOT_FOUND`. A complete-empty query covers only its declared bounded attempt.

### 4.9 One deterministic controller loop

The controller alone mutates runtime state and stopping decisions:

```text
select ready obligation
  -> choose admissible action
  -> execute bounded action
  -> build evidence and evaluate proof
  -> classify the combined attempt
  -> record material delta and update runtime state
  -> choose next action
  -> verify outcome / evaluate stop
```

Every action has an `ActionSignature`. Repetition without material delta exhausts or blocks the route. LLM calls occur only at declared transition points and cannot form an open-ended loop.

### 4.10 Open-vocabulary capability matching

Exact string equality between a C1 relation name and `ProviderOperation.guaranteed_relations` is not the production matcher. Vocabulary mismatch between a proposed goal and a provider catalog is expected (schema linking / tool retrieval). The kernel must not close that gap with case aliases, scenario keywords or provider-native names.

A ready unresolved goal yields one `CapabilityQuery`:

```text
subject_type, object_type or answer_role
constraint keys (not vendor fields)
relation text + canonical name if registered
PROPOSED_UNREGISTERED flag
```

Matching is retrieve-then-admit:

1. F0: exact approved contract / operation identity when labels already coincide.
2. F1: dense retrieval over operation, source and field documents built from provider descriptors. No LLM. Top-k only.
3. F2: at most one C2 call over that shortlist. C2 proposes mappings; it cannot execute, prove or mark coverage complete.
4. F3/F4: adjacent joins then approved exhaustive discovery, still budgeted.

Admission (deterministic, after any LLM proposal): input types are reachable, cited fields exist in census, a native mapping is declared, and the intent mode is `EXPLORE` until a ProofContract exists. Failed admission does not run a query.

Coverage rules:

- Listing sources is not examining them.
- C2 deferred, F1 empty, or admission failure leaves `CoverageStatus.PARTIAL` / unexamined routes.
- `STOP_UNSUPPORTED` requires completed F1 and, if budget allowed, F2, with zero admitted candidates. It is forbidden while C2 is deferred or while F1 was skipped.
- Retrieval rank never proves a relation and never licenses `STOP_NOT_FOUND_BOUNDED`.

## 5. Canonical contracts

### 5.1 RequestContract

Preserves original content, request kind, explicit entities, temporal expression, requested scope, user constraints and immutable request hash.

### 5.2 SearchEnvelope

Contains:

- immutable hard constraints: allowed providers, outer time window, pinned and user-confirmed bindings, tenant boundaries and proof obligations;
- expandable retrieval hints: aliases, lexical variants and approved alternative routes;
- versioned derivation history;
- query, runtime, scan, candidate, retry and LLM budgets.

### 5.3 SemanticGoalGraph

Contains typed variables, relation/attribute goals, qualifiers, dependencies, methods, gates, provenance spans, assumptions, uncertainties and forbidden inferences.

### 5.4 CandidateSet

Each candidate records value, semantic type, source query, observation IDs, derivation, confidence class and status. `CANDIDATE` and `VERIFIED_BINDING` are distinct.

### 5.5 EvidenceAction and QueryIntent

The reasoning layer asks for evidence independently of provider syntax. A `QueryIntent` contains goal ID, mode, typed input bindings, desired output roles, constraints, scope and completeness requirement. Provider-native code remains at the adapter boundary.

### 5.6 Observation and FieldFact

Raw observations are append-only. A normalized fact retains native field, native value, semantic role proposal, query ID, provider scope, timestamp and transformation provenance. Unknown native fields survive ingestion.

### 5.7 ProofResult

A verifier returns:

- contract and evaluator version;
- verdict and reason codes;
- exact subject/object bindings;
- satisfied and missing obligations;
- observation/query citations;
- completeness and coverage dependencies;
- limitations.

## 6. LLM call architecture

LLM roles are isolated and demand-driven:

| Call | Purpose | Authority |
|---|---|---|
| C1 semantic compile | Propose graph and outcome contract | Proposal only |
| C1V semantic review | Optional independent review on ambiguity/novelty | Advisory input to the deterministic acceptance gate |
| C2 capability profile | Propose mapping for a small unresolved-goal batch | Retrieval only |
| C3 native query | Propose provider query when deterministic compiler cannot | Quarantined candidate |
| C4 evidence interpretation | Interpret grouped ambiguous evidence | Advisory |
| C5 replan | Propose graph revision from a material delta | Requires acceptance gate |
| C6 narrative | Render verified facts | No new facts; disabled by default |

The global scheduler reserves budget for mandatory calls before optional calls. Per-call limits do not imply every call will run. Exact ceilings are configuration and experimental parameters, not scientific constants.

## 7. Stopping taxonomy

Canonical terminal decisions:

- `STOP_ANSWERED`
- `STOP_REFUTED`
- `STOP_NOT_FOUND_BOUNDED`
- `STOP_NEEDS_CLARIFICATION`
- `STOP_UNSUPPORTED`
- `STOP_UNREACHABLE`
- `STOP_INCONCLUSIVE`
- `STOP_BUDGET`
- `STOP_ERROR`
- `STOP_ABORTED_BY_USER`

Aliases from older versions must be mapped only at serialization boundaries. The runtime uses one enum.

`STOP_ANSWERED` requires the `OutcomeContract` verifier to pass before termination. `STOP_NOT_FOUND_BOUNDED` additionally requires complete coverage of every mandatory admissible route and an explicit negative-evidence licence. `STOP_UNSUPPORTED` requires a completed capability census in the sense of §4.10, not a deferred profiler or an exact-name miss. Incomplete matching stops `STOP_INCONCLUSIVE` or `STOP_BUDGET`.

## 8. Threat-hunting semantics

The same kernel supports distinct hunt shapes without scenario branches:

- factual lookup: minimal attribute/relation obligation;
- causal reconstruction: temporal, directional multi-hop obligations;
- hypothesis hunt: competing support/refutation obligations;
- population hunt: candidate discovery, prevalence, ranking and coverage obligations;
- CTI/TTP/IOC/CVE hunt: input adapters compile source knowledge into the same graph and retain citations.

The graph shape, not keywords such as email, web, Tor or ransomware, determines execution.

## 9. Reporting

The human report contains:

1. request and verified outcome or precise abstention;
2. proposed and accepted graph, including assumptions and clarification decisions;
3. action trace and state changes;
4. grounded evidence and proof-contract decisions;
5. queries, returned summaries, completeness and coverage;
6. LLM/provider/runtime/analyst cost.

The machine run account stores complete contracts, observations, query results, proof results, state transitions, hashes and version identifiers. It does not expose hidden model chain-of-thought; it records structured proposals and decisions.

## 10. Scientific claim boundary

Prior work supports graph-based investigation, typed query layers, progressive schema discovery, evidence-driven hunting and selective abstention. No cited work proves this exact composition, its budgets, relation registry, prompts, stopping taxonomy or cross-provider generality. Those are thesis hypotheses and require independent labelled evaluation.

## 11. Accepted architecture decision — goal-scoped candidate routes (ADR-20260920-01)

The capability boundary uses a provider-neutral `CandidateRoute` between a
semantic goal and a provider operation. The route is keyed by `goal_id`,
provider, source and operation identity; relation wording is retrieval context,
not the production identity or proof authority.

Route classes are explicit: `EXECUTABLE`, `MAPPING_REQUIRED` and
`DISCOVERY_ONLY`. Only an admitted executable route may emit an `EXPLORE`
`QueryIntent`. Routes default to `EXPLORE`; `PROVE` requires compatibility
with an approved `ProofContract`. A route or LLM proposal never creates proof
authority. The planner consumes admitted routes by `goal_id`; the old relation
matching path is only a migration compatibility boundary and is not the
authority path.

This decision solves goal identity collision and open-vocabulary route
formation. It does not claim retrieval or provider coverage is complete;
frontier, execution, proof and unexamined state remain separately measured.

### Control-plane lifecycle decision (ADR-20260920-02)

Reusable capability, hunt and analytic packages, analyst workspace records and
knowledge candidates are control-plane records around the same v9 kernel. They
are versioned and scoped, but they are never incident evidence and their
metadata cannot grant proof authority. A package is an F0 execution asset only
after explicit approval and conformance fixtures. A run may emit an Act or
`KnowledgeCandidate`, but promotion requires human review, cited run evidence
and passing tests; an LLM or one run cannot auto-promote durable knowledge.
Workspace annotations are append-only and cannot mutate goal, evidence, proof,
budget or stop state.
