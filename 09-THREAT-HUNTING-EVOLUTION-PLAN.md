# 09 — THREAT-HUNTING SYSTEM EVOLUTION PLAN

**Date:** 2026-09-20  
**Status:** proposed evolution plan; not architecture authority or implementation evidence  
**Normative authority:** `01_FINAL-ARCHITECTURE.md`  
**Runtime method:** `02_METHOD-AND-IMPLEMENTATION-PLAN.md`  
**Scientific basis:** `03_LITERATURE-AND-TRACEABILITY.md`  
**Current evidence:** `04-IMPLEMENTATION-CHECKLIST.md`  
**Existing migration order:** `08-EVIDENCE-BASED-REARCHITECTURE-PLAN.md`  
**Execution tracker:** `10-THREAT-HUNTING-EVOLUTION-CHECKLIST.md`

---

## 1. Purpose and authority

This plan evolves the repository from a rigorous but operationally incomplete reasoning kernel into a complete threat-hunting system. It does not replace the v9 architecture. Any conflict is resolved in favor of `01_FINAL-ARCHITECTURE.md`; changes to normative behavior require an explicit architecture decision and corresponding updates to `01`, `02`, `03`, `04` and `08`.

The plan applies one rule to external systems and research:

> Extract a transferable principle, state its assumptions and limits, map it to a measured local defect, express it through provider-neutral contracts, add a failing counterexample, implement the smallest vertical slice, and retain it only if executable evaluation shows benefit over a simpler baseline.

The target is not a collection of copied products. It is one coherent system with v9 retained as the deterministic evidence, proof and stopping kernel.

### 1.1 Two-file execution contract

This document and `10-THREAT-HUNTING-EVOLUTION-CHECKLIST.md` form the complete operational package for this evolution:

- `09` defines the diagnosis, target composition, proposed contracts, dependency order, workstream boundaries, acceptance gates, measurements, rollback rules and final definition of done.
- `10` decomposes that plan into executable tasks, status, blockers, tests, evidence requirements, pull-request slices and the final release gate.
- No third migration plan or competing checklist is required. A newly discovered requirement must first be placed into the appropriate workstream in `09` and tracked in `10` before production code relies on it.
- Canonical documents remain authority references, not an alternative execution backlog. When a proposed change alters normative behavior, the corresponding checklist item includes the required update to `01`, `02`, `03`, `04` or `08` before the change is called canonical or complete.
- If these two files conflict with a canonical document, the canonical document wins and both `09` and `10` must be corrected in the same change before implementation continues.

The implementation loop is fixed:

```text
first open, dependency-ready checklist item
  -> verify its authority and baseline
  -> add a failing counterexample or executable acceptance test
  -> implement the smallest default-path vertical slice
  -> run required unit/static/counterexample/live checks
  -> record production, test and run-account evidence
  -> update canonical documents when authority or runtime method changed
  -> update item status in 10
  -> proceed to the next dependency-ready item
```

A workstream is not complete because its code exists. Its gate in `09` and every required item in `10` must have execution evidence. The entire evolution is complete only when the final release gate in `10` and the definition of done in `09` are both satisfied.

### 1.2 Dependency order

The controlling dependency graph is:

```text
minimum M0 truth capture
  -> M1 executable open-vocabulary routes
  -> M2 mode-aware exploration/discrimination/proof
  -> M3 one agenda and stop authority
  -> M4 typed execution and EvidenceGraph
       -> M5 reusable content and deterministic fast paths
       -> M6 analyst investigation workspace
  -> M7 Act and reviewed Knowledge promotion
  -> M8 final comparative, authorized and live validation
```

M8 fixtures and measurements are developed continuously with the workstream they validate, but its final gate runs only after M1–M7 dependencies are satisfied. Broader M0 corpus and metric work may proceed in parallel after the frozen pre-M1 baseline, but it cannot rewrite that baseline or delay the immediate Workstream L fix.

---

## 2. Executive diagnosis

The current repository has strong authority boundaries but weak operational reach. It is better at preventing unsupported conclusions than at reaching useful evidence quickly.

The principal failure path **was**:

```text
accepted request
  -> SemanticGoalGraph
  -> CapabilityQuery
  -> F1 source shortlist
  -> no executable route unless cache/C2 yields a proposal
  -> admission/validation/probe may yield no RuntimeCapability
  -> SemanticGoalPlanner / census still filter guaranteed_relations by name
  -> zero logical steps
  -> zero production queries
  -> unsupported or inconclusive outcome
```

Workstream M1 now forms F0/F1 typed `CandidateRoute`s, admits them by `goal_id`, and records an `EXPLORE` query without C2 when a typed executable operation exists. Workstream M2 now makes EXPLORE/DISCRIMINATE/PROVE change controller, binding and outcome behavior on the default path. Workstream M3 now runs one `BoundedAgenda` on the default path and isolates ClaimGraph/cell/adaptive loops behind `enable_legacy_execution`. Workstream M4 now records `QueryIntent -> LogicalQueryPlan -> operation-envelope NativeQuery`, reconstructs `EvidenceGraph` from run-account observations, paginates or time-splits incomplete results, plans declared adjacency without treating it as proof, and quarantines C3 behind parse/allowlist/bounds. Gate M4 is closed on contract-level mock/declared-live parity. Gate M5 is closed on approved+fixtured F0 packages. Gate M7 is closed on the control-plane Act/Knowledge path. Gate M6 remains open because there is no hunt-workspace UI or usability pilot. Gate M8 remains open: layered metrics and a matched S01 envelope exist, but live BOTS v2 is unreachable and the labelled corpus/oracle/quality-threshold claims are incomplete. Remaining operational gaps are M4 `[~]` leftovers, M6 UI/pilot, M7 reuse-time/effort metrics, and M8 live/corpus work. This remains a route-to-controller completeness program, not a reason to weaken ProofContract authority.

### 2.1 Current strengths to preserve

- one `SemanticGoalGraph` and typed `OutcomeContract` target;
- explicit AND/OR/GATE semantics;
- cardinality-aware candidate binding;
- native observation and citation preservation;
- executable, approved ProofContracts;
- LLM output as untrusted proposal only;
- separate execution, coverage, proof and route state;
- deterministic recovery and stopping;
- `PARTIAL + 0 rows` never becoming bounded absence;
- provider-native logic behind provider contracts;
- cost and coverage accounting.

### 2.2 Confirmed implementation gaps

1. Closed on the default path: planner and census no longer use production `guaranteed_relations` equality; F0/F1 typed retrieve can admit an executable route without C2.
2. Closed on the default path: an F1 executable operation hit creates a goal-scoped `CandidateRoute` and a recorded query.
3. Remaining: mapping-required / source-only hits still need F2 or analyst mapping before execution.
4. Closed on the default path: runtime materialization no longer writes the proposed relation into `guaranteed_relations`.
5. Mostly closed: cache put and coverage manifests are `goal_id`-keyed; some audit records still carry relation text as display context.
6. Closed on the default path: F1 indexes operation, source and field documents with hashed n-gram dense scoring; zero-score top-k items are not relevant.
7. Remaining: synonym answer-role admission is only partially covered; nested-field over-accept is rejected.
8. Remaining: native graph execution still lacks a robust exploration route when planning yields no steps (M4/M3 residual).
9. Closed on the default path: controller actions are mode-aware — EXPLORE records candidates, DISCRIMINATE requires declared differentiating evidence, PROVE seeks a proof-capable route or preserves a limitation (M2).
10. Closed on the default path: ClaimGraph, cell and adaptive loops require `enable_legacy_execution` and cannot mutate default-path stop/state (M3).
11. Closed on the default path: engine terminal assignments go through `controller.set_stopping_decision` after `evaluate_stop` (M3).
12. Closed on the default path: `QueryIntent` compiles to a recorded `LogicalQueryPlan` and operation-envelope `NativeQuery` without C3 (M4).
13. Closed on the default path: `EvidenceGraph` reconstructs from run-account observations; proximity and undeclared cross-source links stay `NOT_PROOF` (M4).
14. Remaining: source/retention selection, native pushdown, live cancel, identity alternatives, and multi-provider route planning (M4 `[~]`, not Gate M4 blockers).
15. Remaining: evaluation has layered metrics and a matched S01 B0/B1/candidate envelope, but lacks a full independently labelled corpus, oracle ablations, and live BOTS v2 (M0/M8). Gate M8 stays open.
16. Closed on the default path: a hunt emits an auditable Act or explicit `no_action`; reviewed `KnowledgeCandidate` promotion requires a human reviewer, cited evidence and tests; LLM/single-run cannot auto-promote (M7). Reuse-time and analyst-effort metrics remain open.
17. Remaining: no hunt-workspace UI or usability pilot (M6). Backend timeline/pivot/native/proof-obligation views, RBAC, binding review and reconstruct-from-run-account are on the production account.

---

## 3. Technology synthesis and transfer decisions

External evidence supports design hypotheses; it does not prove this composition. Vendor documentation verifies described features, not comparative effectiveness.

| Source family | Transferable principle | Local adoption | What is not transferred |
|---|---|---|---|
| Splunk PEAK | Prepare–Execute–Act lifecycle with reusable Knowledge across hunts | Add lifecycle records, action outputs and controlled knowledge promotion around the v9 runtime | Splunk-specific data, content, workflow assumptions or effectiveness claims |
| TaHiTI | Hypothesis, data requirements, scope and falsification form a reusable hunt package | Versioned `HuntPackage` compiled into the canonical graph and outcome contracts | A second execution architecture or a rigid universal workflow |
| Sqrrl reference model | Hunting is iterative: hypothesize, investigate, uncover, inform and enrich | Permit evidence-driven frontier expansion through accepted graph revisions and agenda actions | Unbounded graph mutation or implicit scenario paths |
| SANS maturity model | Hunting maturity depends on telemetry, process, people, automation and reuse | Measure readiness across telemetry, capability, execution, evidence, analyst and knowledge dimensions | Treating a maturity label as proof of detection effectiveness |
| ATT&CK and CAR | Machine-readable behavior knowledge, data requirements and reusable analytics | Versioned hypothesis/analytic templates and telemetry expectations with provenance | ATT&CK mapping as incident proof |
| SLEUTH, HOLMES, OmegaLog | Provenance, directional information flow, multi-stage correlation and cross-source reconciliation | Separate observed `EvidenceGraph` from desired `SemanticGoalGraph`; prove relations over cited observations | Causal claims from co-occurrence or generic graph proximity |
| AIQL | Typed domain query primitives and semantics-aware physical planning | Strengthen `QueryIntent -> LogicalQueryPlan -> ProviderCompiler` with pushdown, partition, join and completeness planning | AIQL workload results as proof of local performance |
| ThreatRaptor | Inspectable behavior-graph intermediate representation compiled into queries | Keep semantic intent provider-neutral and compilation auditable | Natural-language extraction as proof authority |
| Kestrel | Find relevant subgraphs iteratively in incomplete telemetry | Make `EXPLORE -> DISCRIMINATE -> PROVE` real runtime modes | Assuming a complete global graph |
| ECTH and ATHAFI | Knowledge–hypothesis–action separation and adaptive evidence collection | Add hypothesis updates, information-gain actions and knowledge candidates without granting proof authority | Unvalidated automatic hypothesis promotion |
| Practitioner research | Real hunting is heterogeneous and mixed-initiative | Ship analyst-guided copilot checkpoints before full autonomy | One rigid process encoded as universal behavior |
| Timesketch | Timeline, annotation, collaboration and evidence organization are core investigation functions | Add an evidence/timeline workspace over immutable observations and decisions | A UI that mutates proof or runtime truth directly |
| Velociraptor | Versioned reusable collection artifacts | Add `CapabilityArtifact` packages with tests, parameters, completeness and limitations | Treating artifact presence as evidence |
| osquery/Fleet | Stable typed primitives and scheduled/distributed collection | Prefer deterministic approved primitives and scheduled population hunts | SQL table presence as completeness or semantic proof |
| Sigma/pySigma | Semantic content, internal representation, transformations and backend compilation are separate | Build versioned analytic/hunt packages and deterministic transformation pipelines | Provider fields in the reasoning kernel |
| Elastic/Splunk content repos | Detection/hunt content is software with schemas, reviews, tests and feedback | Content lifecycle, ownership, validation, deprecation and replay tests | Copying vendor rules as universally valid proof contracts |
| OCSF/ECS/CIM | Normalized schemas reduce backend coupling | Use normalized roles for planning while retaining native values and transformation provenance | Normalization as collection, coverage or proof guarantee |
| OpenCTI/MISP/STIX/TAXII | Threat knowledge needs relationships, confidence, temporal validity, versioning and connectors | Durable `HuntKnowledgeStore` with provenance and promotion state | CTI inference as observed incident evidence |
| CALDERA/Atomic Red Team | Behavior and telemetry claims need executable validation | Positive, negative, role-swap, unrelated-row, partial and ambiguity fixtures plus authorized emulation | Emulation success as universal production coverage |
| DARPA TC/Mordor/OTRF | Reproducible provenance datasets support investigation evaluation | Independent replay corpus and causal/evidence labels | Dataset coverage as production generality |
| ExCyTIn/Cyber Defense benchmarks | Evaluate intermediate actions and actual execution, not only final answers | Layer metrics, actual run accounts, baselines and ablations | Benchmark-specific thresholds as universal acceptance criteria |

---

## 4. Target system model

The target has an outer threat-hunting lifecycle and an inner v9 reasoning kernel.

```text
Prepare
  -> HuntPackage / RequestContract / scope / success criteria
  -> SemanticGoalGraph + OutcomeContract
  -> Progressive Capability Frontier
       F0 approved artifacts/contracts
       F1 deterministic typed retrieval
       F2 bounded semantic mapping
       F3 adjacent expansion/probes
       F4 approved exhaustive discovery
  -> CandidateRoute admission
  -> one bounded agenda
       EXPLORE -> DISCRIMINATE -> PROVE
  -> QueryIntent -> LogicalQueryPlan -> ProviderCompiler -> NativeQuery
  -> QueryResult -> Observation -> FieldFact -> EvidenceGraph
  -> ProofEngine -> Outcome verifier -> deterministic stop
  -> Act
       detection / response / telemetry improvement / follow-up
  -> Knowledge
       reviewed package, mapping, query, baseline, limitation or lesson
```

### 4.1 Graph separation

- `SemanticGoalGraph`: accepted obligations—what the system needs to establish.
- `EvidenceGraph`: observed entities, events, facts and candidate relations—what telemetry actually contains.
- `ProofEngine`: the only automatic authority that may establish an approved semantic relation from cited evidence.
- `KnowledgeGraph` or knowledge store: reusable reviewed knowledge—not current-run proof.

### 4.2 Lifecycle separation

- **Prepare:** freeze request, scope, hypothesis, outcome, data expectations and budgets.
- **Execute:** explore, discriminate and prove through one agenda.
- **Act:** create reviewed defensive outputs.
- **Knowledge:** promote reusable, versioned artifacts after review and tests.

---

## 5. Proposed new and revised contracts

`CandidateRoute` is no longer a plan-level proposal. `01` §11 ADR-20260920-01 accepted it as the provider-neutral capability boundary. The remaining items in this section stay plan-level until an architecture decision accepts them.

### 5.1 `CandidateRoute` (accepted in `01` ADR-20260920-01)

A route candidate must be keyed by goal identity rather than pretending a retrieved source guarantees the goal relation.

```text
CandidateRoute
  route_id
  goal_id
  provider_id
  source_id
  operation_id?                 # present for executable descriptor/artifact routes
  subject_type
  object_type
  input_role_bindings
  output_role_bindings
  supported_constraint_keys
  mode                          # EXPLORE | DISCRIMINATE | PROVE
  frontier_stage                # F0 ... F4
  route_class                   # EXECUTABLE | MAPPING_REQUIRED | DISCOVERY_ONLY
  discovery_provenance
  admission_status
  rejection_reasons
  proof_contract_id?
  schema_fingerprint
```

Rules:

- F1 rank can propose a route but cannot prove it.
- `EXECUTABLE` requires a declared native operation or approved artifact with typed mappings.
- `MAPPING_REQUIRED` requires F2 or analyst mapping before execution.
- `DISCOVERY_ONLY` remains coverage/frontier state and cannot silently become executable.
- `PROVE` requires an approved ProofContract and compatible evaluator; otherwise mode is `EXPLORE`.

### 5.2 `CapabilityArtifact`

```text
CapabilityArtifact
  id, version, owner, status
  semantic input/output roles
  supported entity types and constraints
  provider compiler/template reference
  source/permission/retention requirements
  pagination/cancellation/completeness contract
  known limitations and failure modes
  schema and parser versions
  positive/negative/conformance fixtures
```

An approved artifact is an F0 execution asset. It is not incident evidence.

### 5.3 `HuntPackage` and `AnalyticPackage`

```text
HuntPackage
  id, version, provenance
  hypotheses and falsification conditions
  expected data/fact kinds
  graph/outcome template
  admissible actions and analyst checkpoints
  known limitations
  tests

AnalyticPackage
  provider-neutral semantic expression
  normalized internal representation
  transformation pipeline
  supported backends
  investigation guidance
  tests, ownership and lifecycle state
```

Packages compile into the same `SemanticGoalGraph`, `OutcomeContract` and `QueryIntent`; they do not define parallel execution paths.

### 5.4 `HuntLifecycleRecord`

```text
HuntLifecycleRecord
  preparation
  execution_run_account
  action_items[]
  knowledge_candidates[]
  analyst_decisions[]
  promotion_events[]
```

### 5.5 `KnowledgeCandidate`

A run may propose reusable knowledge but cannot auto-promote it.

```text
KnowledgeCandidate
  kind                           # mapping, query, package, baseline, limitation
  source_run_id
  evidence/proof references
  scope and temporal validity
  confidence class
  review status
  test requirements
```

---

## 6. Ordered implementation program

**Sequencing constraint:** `08` Workstream L remains the immediate code-migration priority. M0 is split operationally: perform only the minimum truth repair needed to capture a trustworthy pre-L baseline before changing Workstream L, then continue the broader corpus and evaluation work in parallel. M0 must not become a reason to defer the M1 counterexamples and route-formation fix.

### Workstream M0 — Freeze objectives, baselines and truth conditions

**Purpose:** prevent architecture work from outrunning evidence while preserving Workstream L as the immediate implementation priority.

1. Define the first representative workload, user role, provider and acceptance constraints.
2. Freeze independent replay splits by campaign/tenant/time/schema family.
3. Implement executable baselines:
   - B0 approved curated query/package plus analyst review;
   - B1 simple typed-intent/direct read-only query with the same safety envelope;
   - current candidate;
   - oracle graph and oracle mapping only as diagnostic ablations.
4. Correct misleading evaluation defaults and preserve execution exceptions in run artifacts.
5. Record current query execution rate, zero-query stop rate, time to first evidence, correctness, decision coverage, analyst time and total cost.

**Pre-M1 baseline gate:** record the current candidate behavior on the frozen replay slice and make at least one simple executable baseline produce a serialized run account. The broader M0 gate remains: the same cases, permissions and budgets execute through candidate and baseline; metrics are recomputable from serialized run accounts.

### Workstream M1 — Complete Workstream L: executable open-vocabulary capability matching

**Purpose:** make valid vocabulary mismatches reach bounded evidence collection.

1. Add failing counterexamples before production changes.
2. Key requirements, caches and route state by `goal_id` plus provider/source/schema identity, not relation string alone.
3. Split F1 retrieval into operation, artifact, source and field documents.
4. Label F1 results `EXECUTABLE`, `MAPPING_REQUIRED` or `DISCOVERY_ONLY`.
5. Reject or explicitly defer zero-evidence candidates; top-k membership alone is not relevance.
6. Produce `CandidateRoute` objects from F0/F1/F2.
7. Run F2 at most once per unresolved goal over the compact shortlist, with explicit deferred/failure coverage.
8. Replace proposal-as-`guaranteed_relations` materialization with goal-scoped route eligibility.
9. Admit a route only after deterministic type, field, permission, retention, mapping and mode checks.
10. Feed admitted routes to `SemanticGoalPlanner` by `goal_id`; remove relation-equality as the production matcher.
11. Emit a real `QueryIntent(EXPLORE)` and recorded query for executable F1 routes without requiring C2.
12. Make `STOP_UNSUPPORTED` depend on a completed frontier, not an empty plan.

**Gate M1:** vocabulary-mismatch tests execute at least one mock-provider query when an executable typed route exists; deferred C2 or unexamined routes cannot produce `STOP_UNSUPPORTED`; no scenario/vendor aliases enter the kernel.

### Workstream M2 — Make EXPLORE, DISCRIMINATE and PROVE executable semantics

**Purpose:** allow useful discovery without weakening proof.

1. Remove default `PROVE` behavior when intent authority is unknown; route admission sets mode explicitly.
2. Make controller classification/action mode-aware:
   - candidate + EXPLORE -> expand/enrich/record candidate;
   - ambiguity + singular target -> discriminate or ask user;
   - candidate + PROVE -> seek proof-capable route;
   - no contract -> preserve retrieval-only result and limitation.
3. Keep candidate evidence available for analyst and adjacent exploration.
4. Require verified bindings for proof-required downstream steps; permit bounded candidate inputs only for declared exploration actions.
5. Make frontier expansion and graph revision distinct: evidence may open adjacent routes; new semantic obligations require accepted graph revision.

**Gate M2:** closed on the default path. Discovery-oriented hunts can return cited candidate populations without false verification; factual claims still require approved proof; singular ambiguity never auto-selects. See `10` Gate M2 evidence.

### Workstream M3 — Consolidate one bounded agenda and stop authority

**Purpose:** remove behavioral divergence between architectural generations.

1. Define one agenda item over goal, method, route, mode, bindings, envelope and cursor.
2. Adapt every production query attempt into the canonical controller input.
3. Route pagination, retry, alternate route, adjacent exploration, discrimination, proof seeking and stop through one deterministic controller.
4. Remove or isolate ClaimGraph, cell/expectation and adaptive loops from the default path.
5. Remove direct terminal-state assignments and unrestricted state resets.
6. Extend `ActionSignature` to mode, source, bindings, window, hints and cursor.
7. Require material delta before repeating an action.
8. Preserve legacy compatibility only behind an explicit non-default boundary until deletion.

**Gate M3:** closed on the default path. Code inspection and tests show one default production agenda and one stop authority; all semantic attempts have classification and next-action reason; no-delta loops terminate. See `10` Gate M3 evidence.

### Workstream M4 — Build the typed execution and evidence-graph layer

**Purpose:** make execution efficient, inspectable and provider-neutral.

1. Stabilize `QueryIntent -> LogicalQueryPlan -> ProviderCompiler -> NativeQuery`.
2. Add deterministic planning for source/partition selection, predicate pushdown, projection, pagination, time splitting, cancellation and completeness.
3. Quarantine C3 native query proposals behind parser, read-only, permission, scope, cost and output-role checks.
4. Build `EvidenceGraph` from immutable Observation and FieldFact records.
5. Represent observed transition, provenance dependency and causal attribution as distinct relation classes.
6. Support multi-provider routes without treating provider multiplicity as singular answer ambiguity.
7. Reconcile identities only through cited mapping events/contracts; preserve conflicts.

**Gate M4:** closed on the default path. The same accepted semantic graph runs through mock and declared-live adapter boundaries without reasoning changes; native evidence and transformation provenance are reproducible from the run account; provider limits stay explicit. Remaining `[~]` items (source/retention selection, native pushdown, live cancel, identity alternatives, multi-provider route planning) are not gate blockers. See `10` Gate M4 evidence. Not a live Splunk/BOTS claim.

### Workstream M5 — Add reusable content and deterministic fast paths

**Purpose:** stop rediscovering known capabilities and analytics on every hunt.

1. Implement versioned registries for `CapabilityArtifact`, `HuntPackage`, `AnalyticPackage` and ProofContracts.
2. Define review states: draft, validated, approved, deprecated and revoked.
3. Add schema, permission, parser and contract freshness checks.
4. Compile approved packages through a Sigma/pySigma-style internal representation and backend pipeline.
5. Make F0 the preferred route for approved content.
6. Keep open-vocabulary discovery as fallback, not the only route.
7. Add content ownership, false-positive feedback, compatibility tests and deprecation policy.

**Gate M5:** closed on the default path. An approved, fixtured package compiles to an F0 route with zero C2/C3, enters the same Observation/ProofContract path, and cannot verify a relation by metadata. Draft packages and LLM/single-run actors cannot auto-promote. See `10` Gate M5 evidence.

### Workstream M6 — Implement the analyst investigation workspace

**Purpose:** support real mixed-initiative hunting rather than report-only automation.

Minimum capabilities:

- timeline and entity/event pivot;
- native observation viewer;
- evidence graph and goal graph side by side;
- annotations, tags, comments and saved searches;
- candidate and binding review;
- route, completeness and unexamined-source display;
- proof obligations, missing evidence and limitations;
- analyst decisions as immutable, cited events;
- resumable hunt state and collaborative ownership.

The workspace may propose commands but cannot mutate verified state outside canonical controller/analyst-decision contracts.

**Gate M6:** still open. Production-path contracts now include append-only annotations, timeline/pivot/native/proof-obligation views, query/coverage audit, RBAC (viewer/analyst/reviewer), typed `BindingReview` (no auto-bind), resume on the same graph without a second C1, and `reconstruct_from_run_account` from the machine account. This repo has no hunt-workspace UI and no usability pilot, so the gate stays open.

### Workstream M7 — Add Act and Knowledge promotion

**Purpose:** turn individual hunts into improving defensive capability.

1. Represent action items:
   - detection candidate;
   - response recommendation;
   - telemetry/access/retention gap;
   - follow-up hunt;
   - content defect;
   - no-action decision.
2. Generate `KnowledgeCandidate` objects from reviewed results.
3. Require human review, scope, temporal validity and tests before promotion.
4. Never reuse incident conclusions or negative evidence across new windows.
5. Invalidate or re-review mappings on schema, permission, parser, contract or semantic drift.
6. Track reuse and downstream operational outcome.

**Gate M7:** closed on the default production path. A completed hunt creates an auditable Act or explicit `no_action`; a reviewed knowledge candidate can be approved through tests; no LLM output or single run auto-promotes knowledge. Control-plane only; metadata is not proof. Reuse-time and analyst-effort operational metrics remain open.

### Workstream M8 — Executable validation and scientific evaluation

**Purpose:** determine which complexity earns its place.

1. Add positive, negative, unrelated-row, role-swap, co-occurrence, partial, ambiguity, permission-revocation, schema-drift and prompt-injection fixtures.
2. Add authorized Atomic/CALDERA or equivalent telemetry validation for selected packages.
3. Execute factual, hypothesis and population vertical slices.
4. Compare at matched permissions, model, budget and workload:
   - B0 curated package/analyst;
   - B1 simple guarded query path;
   - evolved candidate;
   - oracle graph/mapping ablations.
5. Report risk–coverage and cost–quality curves, not a single accuracy number.
6. Keep the simplest design meeting correctness, coverage, latency, cost and analyst-effort constraints.
7. Run non-skipped BOTS v2 only as one live gate, not universal generalization evidence.

**Gate M8:** still open. Layered metrics (request→graph, retrieve, query, proof, binding, outcome, abstention, cost) come from executed accounts; a correct answer with an unverified/inadmissible proof path is `wrong_path`. B0/B1/candidate share one envelope on the reviewed S01 CDB slice. Live BOTS v2 did not run: Splunk `https://localhost:8089` connection refused and `SPLUNK_*` unset. Failed/abstained runs remain in the cohort. Full labelled corpus, oracle ablations, Atomic/CALDERA and quality-threshold claims remain open.

---

## 7. Counterexample-first test program

The following tests precede their corresponding implementation changes:

1. vocabulary mismatch plus typed executable operation runs without C2;
2. source-only lexical hit does not become executable;
3. zero-score top-k item is not a relevant admitted route;
4. deferred C2 and `NO_LLM_CALLER` cannot complete the capability census;
5. two goals sharing a relation label retain independent requirements and route state;
6. runtime proposal cannot grant relation proof/guarantee authority;
7. semantic answer-role synonym with a typed declared mapping passes admission;
8. unrelated nested field fails answer-role admission;
9. candidate evidence in EXPLORE does not force `SEEK_PROOF`;
10. retrieval-only evidence remains visible without becoming a verified binding;
11. multiple providers can be scheduled as evidence routes without provider-order selection;
12. direct terminal assignment outside the controller fails an authority test;
13. all default runtime attempts pass through the controller triad;
14. approved package fast path runs with zero C2/C3 calls;
15. package or ATT&CK mapping alone cannot verify an incident relation;
16. promoted knowledge is invalidated by incompatible schema/permission/contract version;
17. partial-empty, cancelled and backend-still-running cases never license bounded absence;
18. baseline and candidate exceptions remain visible and charged to cohort cost.

No test may contain a production route branch for email, web, Tor, ransomware, PowerPoint, Mallory, Amber, BOTS or a known answer.

---

## 8. Measurement framework

### 8.1 Semantic layer

- graph goal precision/recall;
- forbidden expansion rate;
- literal/provenance preservation;
- clarification accuracy and rate.

### 8.2 Capability and routing

- F0 hit rate;
- operation/source/field retrieval recall@k;
- executable-route recall;
- admitted-route precision/recall;
- unexamined-route rate;
- C2 calls per unresolved goal;
- false unsupported rate;
- zero-query terminal rate.

### 8.3 Execution and evidence

- query execution rate;
- time to first executed query;
- time to first useful cited evidence;
- evidence yield per query;
- independently labelled irrelevant-row rate;
- completion-class accuracy;
- provider scan/runtime/cancellation cost;
- cross-source identity error.

### 8.4 Binding, proof and outcome

- wrong-binding rate;
- discriminator success and analyst escalation rate;
- false-proof and false-refutation rate;
- proof-gap rate;
- relation precision/recall by contract;
- outcome exactness/verdict/population quality;
- citation grounding;
- risk–coverage curve;
- correctly resolved/all eligible requests.

### 8.5 Operations and learning

- analyst minutes per case, including correction and follow-up;
- candidate-to-finding conversion;
- finding-to-action conversion;
- knowledge-candidate approval rate;
- approved artifact reuse rate;
- time from hunt to detection/telemetry improvement;
- regression rate after schema/content change;
- total cost per correctly resolved case, stratified by difficulty/severity.

A complete-empty query is not automatically waste. A non-empty irrelevant query is not automatically useful. Metric denominators and independent labels must be explicit.

---

## 9. Migration and compatibility strategy

1. Preserve current public contracts through adapters while the default path migrates.
2. Add compatibility adapters and shadow instrumentation before cutover; do not label an authority fix as optional or permit a known-unsound legacy path to remain the validated default after its counterexamples pass.
3. Shadow-run `CandidateRoute` planning beside current planning and compare route decisions without executing twice where provider cost is material.
4. Enable the evolved path first on mock replay, then selected live hunts.
5. Keep run-account schema versioned and support old artifact deserialization at compatibility boundaries.
6. Roll back by feature flag to the last validated default path; never roll back evidence or audit records.
7. Remove legacy code only after parity tests prove no supported input depends on it.
8. Do not update completion checkboxes until the default production route and automated/live evidence satisfy the gate.

---

## 10. Security, safety and tenancy requirements

- enforce tenant/principal authorization at discovery, dispatch and evidence read;
- isolate caches by deployment, tenant, principal/authorization digest, scope and schema version;
- treat log, CTI, comments and payload fields as untrusted content and never as instructions;
- minimize model-visible native data and redact secrets before LLM calls;
- allow only read-only bounded query subsets unless explicitly authorized otherwise;
- verify backend cancellation instead of assuming client timeout stopped work;
- record permission revocation and schema drift as route invalidation;
- prevent models from changing hard scope, budget, proof authority, binding or stop state;
- preserve contradictory evidence rather than averaging or deleting it.

---

## 11. Explicit non-goals

This program does not:

- copy all features from every surveyed system;
- create a second reasoning graph or request-specific engine;
- add provider/scenario aliases to close semantic gaps;
- treat normalized schemas, ATT&CK mappings, source names or returned rows as proof;
- require a graph database or microservice for each logical graph;
- build many providers before one provider and replay path are measured;
- require LLM-generated native queries for MVP;
- automatically promote model proposals into durable knowledge;
- claim universal soundness, completeness, superiority or cross-provider generality;
- optimize SPL/native queries before Workstream M1 can reliably form executable routes.

---

## 12. Decision and stop conditions

Complexity is retained only when evidence justifies it.

| Observation | Decision |
|---|---|
| Curated/simple baseline meets requirements with lower cost and equivalent safety | Prefer the simpler baseline or a thin verifier layer |
| Semantic graph errors dominate | Improve independent semantic labels/acceptance before capability optimization |
| Telemetry lacks required information | Fix instrumentation, permissions or retention rather than adding reasoning |
| F1/C2 dominates latency or causes zero-query stops | Complete M1 and compare approved artifacts, retrieval and exhaustive alternatives |
| Exhaustive discovery is cheap and meets coverage for the target catalog | Keep exhaustive mode; do not force adaptive retrieval |
| Dynamic discovery recovers important unknown-schema cases at acceptable cost | Retain it with unexamined coverage and audit fallback |
| Oracle mapping still cannot recover evidence | Revisit telemetry, goal semantics or workload; do not add more profiling |
| Analyst review dominates total effort | Improve evidence presentation and reusable content before autonomy |
| False-proof ceiling is violated | Stop rollout and repair authority/evaluator defects before feature work |

---

## 13. Definition of done

The evolution is complete only when the default production path demonstrates all of the following:

1. every supported request uses one SemanticGoalGraph/OutcomeContract path;
2. valid open-vocabulary capability matches form executable admitted routes without relation aliases;
3. unknown relations may explore but cannot receive unsupported proof authority;
4. EXPLORE, DISCRIMINATE and PROVE alter runtime behavior as declared;
5. one deterministic agenda/controller owns recovery and stop;
6. immutable native evidence feeds a distinct EvidenceGraph and approved ProofEngine;
7. approved reusable packages provide a deterministic fast path through the same kernel;
8. an analyst can inspect, correct, resume and audit the hunt;
9. Act and Knowledge outputs are versioned, reviewed and non-automatic;
10. factual, hypothesis and population vertical slices pass counterexamples and replay;
11. B0/B1/candidate metrics come from actual runs and include abstention, failures, analyst effort and cost;
12. non-skipped live readiness tests pass for the declared provider scope;
13. no generated report, class existence, simulated metric or skipped test is used as completion evidence.
