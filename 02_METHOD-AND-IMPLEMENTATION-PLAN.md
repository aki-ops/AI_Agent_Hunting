# 02 — METHOD AND IMPLEMENTATION PLAN (v8 / Evidence-Based Implementation Plan)

`01_FINAL-ARCHITECTURE.md` defines the architecture. `08-EVIDENCE-BASED-REARCHITECTURE-PLAN.md`
is the master evidence-based rearchitecture and execution blueprint. This document defines
the operational execution method, component boundaries, LLM call contracts, and phased migration.
`03` records the research basis; `04` is the evidence-gated implementation checklist.

## 1. Decision and boundary

The agent operates across unfamiliar provider telemetry without hardcoding scenario logic,
keywords, or entity names. It enforces a **Contract-Grounded Progressive Hunt Graph**:

```text
Yêu cầu tự nhiên
  -> LLM biên dịch GoalGraph + AnswerContract (C1)
  -> Kiểm tra graph và provenance (deterministic validation)
  -> Chọn goal đang sẵn sàng (AND / OR / GATE planner)
  -> Tìm capability theo progressive frontier (F0 -> F4)
  -> Bind entity/value hoặc hỏi người dùng nếu còn mơ hồ (CandidateSet / Discriminator)
  -> QueryIntent (EXPLORE | DISCRIMINATE | PROVE)
       -> Compiler xác định (preferred)
       -> Quarantined SPL candidate (C3 trong sandbox)
  -> Kiểm tra an toàn (Native SPL Gate: AST, read-only, bounds, cancel SID)
  -> Observation -> FieldFact -> Candidate Evidence
  -> ProofContract xác minh quan hệ và answer slot (STRUCTURALLY_VALID / RETRIEVAL_CAPABLE / PROOF_CAPABLE)
  -> Tiếp tục / mở rộng / hỏi / dừng theo 9 trạng thái kiểm tra được
  -> Báo cáo 6 phần + Machine Run Account JSON
```

Three non-negotiable principles govern every execution:
1. **LLM is a semantic planner, not a semantic oracle.** It proposes; only deterministic validators and approved `ProofContract` instances establish proof.
2. **No full-schema prompt, no fixed Top-K cutoff.** Progressive frontier (`F0` to `F4`) incrementally explores sources. Unexamined sources are explicit coverage gaps.
3. **Never auto-bind ambiguous candidates without proof.** Ambiguous bindings trigger a `DISCRIMINATOR` query or halt for human clarification / `NEEDS_DISAMBIGUATION`.

## 2. Runtime method (Steps A–J)

### Step A — Freeze request and budget

Construct an immutable `HuntRunContext`:
- `request_id`, request text hash, user-supplied entities and seed facts;
- time policy and permitted provider scopes;
- hard ceilings: max 5 LLM calls, max 15,000 tokens, provider scan/runtime/query caps;
- prompt, model, and registry versions.

Input text and telemetry rows are untrusted data: prompt injection must never alter scope,
provider selection, budget, or verdict.

### Step B — LLM Semantic Compilation (Call C1)

C1 receives only the request, small vocabulary/JSON schema, and time policy.
**It does not receive the provider catalog and does not emit SPL.**
It compiles a schema-strict `GoalGraph` and `AnswerContract`:
- `answer_slots`: required variable, expected type, acceptance condition;
- `goals`: atomic obligations with request text span provenance;
- `dependencies`: AND / OR / GATE relationships;
- `variables`: typed entities/values;
- `qualifiers`: time, action, state, mechanism restrictions;
- `assumptions`: explicit, non-binding;
- `forbidden_inferences` and `clarification_triggers`.

### Step C — Deterministic Graph Validation

The validator checks:
- provenance spans exist for all proposed goals;
- no invented proper nouns or entity mutations (e.g. changing Mallory to Alice, MacBook to hostname);
- acyclic dependencies and valid GATE semantics;
- no acceptance rules demanding specific field names invented by the LLM.

### Step D — AND / OR / GATE Planning

A deterministic planner (not a prompt) maintains:
- `AND`: all predecessor goals must be verified;
- `OR`: any verified branch satisfies the parent obligation;
- `GATE`: downstream execution is blocked until required input bindings are proven;
- `DISCRIMINATOR`: automated low-cost queries specifically targeting candidate ambiguity.

### Step E — Capability Discovery via Progressive Frontier (F0–F4)

Rather than fixed Top-K or full-catalog prompting, search expands iteratively:
- **`F0` Certified frontier:** Operations with approved `ProofContract` matching relation and roles.
- **`F1` Metadata frontier:** Retrieve `SourceCard` candidates via lexical + embedding score without hard cutoffs.
- **`F2` Adjacent expansion:** Open related sources sharing partition, field alias, or join keys upon gaps.
- **`F3` Bounded semantic profiling:** Bounded LLM batching for a single goal; mappings default strictly to `retrieval_only`.
- **`F4` Approved exhaustive:** Run only under explicit escalation or offline audit.

Unexamined sources are recorded in the coverage manifest (`unexamined_source_ids`).

### Step F — Controlled Entity Binding

Variables maintain a `CandidateSet` of `CandidateBinding` records (supporting facts, directness, contradictions, confidence class).
- If exactly 1 candidate is proven by contract without contradiction: bind.
- If multiple candidates exist: dispatch a `DISCRIMINATOR` query.
- If ambiguity persists: halt for user clarification or output structured `NEEDS_DISAMBIGUATION`. Never pick by heuristic, string matching, or first row.

### Step G — QueryIntent before Native SPL

Query synthesis operates in two tiers:
1. **Normal tier (Typed `QueryIntent`):** Declares `mode` (`EXPLORE` | `DISCRIMINATE` | `PROVE`), bound inputs, projected roles, predicates, and budget. Compiled deterministically by the adapter.
2. **Quarantined Native Candidate (C3 fallback):** When intent cannot express needed syntax, isolated C3 proposes SPL. It must pass the `NativeQueryGate`:
   - AST validation against read-only command allowlist;
   - only census-known sources and fields;
   - explicit time bounds, scan/result caps;
   - cancellation SID tracking and backend job telemetry (`scanCount`, `runDuration`).

### Step H — Evidence Pipeline

Raw rows are transformed strictly via:
```text
native row
  -> immutable Observation (append-only ledger)
  -> deterministic FieldFact
  -> CandidateRelation
  -> ProofContract evaluation
  -> EvidenceItem / AnswerCandidate
```

### Step I — ProofContract Evaluation

Authority rests solely in human-reviewed, test-verified contracts:
- `STRUCTURALLY_VALID`: Schema fields exist.
- `RETRIEVAL_CAPABLE`: Rows retrieved, but relation semantics unproven.
- `PROOF_CAPABLE`: Conforms to approved contract; cited observations satisfy all required roles, temporal order, and state transitions.

Cooccurrence defaults to `RETRIEVAL_CAPABLE`. LLM proposals cannot upgrade to `PROOF_CAPABLE`.

### Step J — Controller and Stopping Taxonomy

Halt only via 9 verifiable execution states:
`STOP_ANSWERED`, `STOP_REFUTED`, `STOP_NOT_FOUND_BOUNDED`, `STOP_NEEDS_CLARIFICATION`,
`STOP_UNSUPPORTED`, `STOP_UNREACHABLE`, `STOP_INCONCLUSIVE`, `STOP_BUDGET`, `STOP_ERROR`.

## 3. LLM Call Architecture and Budgets (C1–C6)

Context is strictly isolated per call; no call receives the entire schema catalog or raw ledger.

| Call | Trigger | Allowed Context | Output | Default Budget Ceilings |
|---|---|---|---|---:|
| **C1: `semantic_compile`** | Every free-text request | Request text, small vocabulary/schema, time policy | `GoalGraph` + `AnswerContract` | 2,500 in / 1,200 out |
| **C2: `capability_profile`** | Cache miss & F0/F1 insufficient | Single goal + compact `SourceCard` batch | `retrieval_only` candidate mappings | 2 × (1,800 in / 700 out) |
| **C3: `native_query_proposal`** | Intent compiler unsupported | Single goal + selected source + verified bindings | Sandboxed candidate SPL | 1,800 in / 700 out |
| **C4: `evidence_interpret`** | Ambiguous evidence semantics | Grouped delta cards (no raw ledger) | Candidate interpretation & gaps | 2,500 in / 800 out |
| **C5: `replan`** | Deadlock with material new delta | Unresolved goal graph + compact delta | Revised goals (no verdict) | 2,000 in / 900 out |
| **C6: `narrative`** | Optional human report polish | Verified account facts only | Narrative prose (no new facts) | 1,500 in / 600 out |

**Execution Ceilings:** Hard limit of max 5 calls and 15,000 total tokens per hunt run (excluding C6).

### Cost Accounting

Cost accounting reports total real-world expenditure, not just estimated LLM USD:

```text
C_run = C_llm + C_splunk + C_cache/control + C_analyst

C_llm = Σ(input_uncached * rate_in + input_cached * rate_cached + output * rate_out)
Splunk work = Σ(scanCount, runDuration, queue_time, resultCount, cancelled_state)
Human work = clarification_time + review_minutes
```

## 4. Phased Implementation Roadmap (Phases 0–8)

### Phase 0 — Baseline & Scope Freeze
- Freeze 20–30 representative requests (`eval/corpus/*.jsonl`, `eval/splits.json`).
- Establish B0 (current execution) and B1 (direct LLM-to-query) baselines.
- Isolate BOTS v2 as integration fixture; do not hardcode entities or answers.

### Phase 1 — Lock Semantic Authority
- Create `contracts/proof_contract.py` and `registry/proof_contract_registry.py`.
- Enforce three capability levels: `STRUCTURALLY_VALID`, `RETRIEVAL_CAPABLE`, `PROOF_CAPABLE`.
- LLM mappings default strictly to `retrieval_only`.
- Materialize proof capability only via `APPROVED` registry contracts and conformance tests.

### Phase 2 — Semantic Compiler and Real Graph
- Upgrade C1 compiler to output `GoalGraph` and `AnswerContract` with request text provenance spans.
- Enforce AND / OR / GATE dependency graph.
- Validator preserves request entities (Mallory cannot mutate into Alice; MacBook cannot become hostname).

### Phase 3 — Source Catalog and Progressive Frontier (F0–F4)
- Create `SourceCardStore`, `frontier.py`, and `catalog_index.py`.
- Replace per-hunt exhaustive prompt batching with progressive frontier expansion:
  `F0` (Certified) -> `F1` (Metadata) -> `F2` (Adjacent) -> `F3` (Bounded profiling) -> `F4` (Approved exhaustive).
- Record unexamined sources as explicit coverage gaps (`unexamined_source_ids`).

### Phase 4 — Controlled Binding & Mixed-Initiative Control
- Create `contracts/bindings.py` with `CandidateSet` and `CandidateBinding`.
- Implement automated `DISCRIMINATOR` queries for candidate ambiguity.
- Halt for human clarification or output structured `NEEDS_DISAMBIGUATION`. Never auto-bind by heuristic.

### Phase 5 — Typed Query & Native-Query Quarantine
- Implement `QueryIntent` modes: `EXPLORE`, `DISCRIMINATE`, `PROVE`.
- Deterministic compiler handles approved mappings; quarantined C3 fallback runs in AST sandbox.
- Capture Splunk backend execution telemetry (`scanCount`, `runDuration`, cancellation SID).

### Phase 6 — Evidence, Verification & Stopping Taxonomy
- Evidence pipeline preserves native field roles, timestamps, and causal transitions.
- Evaluates proof solely against `ProofContract`.
- Enforce 9-state stopping taxonomy (`STOP_ANSWERED` through `STOP_ERROR`).

### Phase 7 — Report, Tracing & Cost
- Build unified `StepTrace` from C1 through stop.
- Generate 6-part Markdown `report.md` and machine `run_account.json`.

### Phase 8 — Evaluation & Ablation
- Execute benchmark across B0, B1, and candidate architecture.
- Run ablation studies (graph oracle, mapping oracle, frontier vs. exhaustive).
- Report layer metrics: goal F1, candidate recall, binding precision, citation grounding, false support rate, wrong auto-binding rate.

## 5. End-to-End Required Test Matrix

| Category | Scenario | Mandatory Expectation |
|---|---|---|
| Factual single-hop | Single attribute lookup | 1 goal, narrow query, cited answer |
| Multi-hop | person -> account/host -> artifact | GATE enforced; no artifact query before verified host binding |
| OR path | person->host OR person->account->host | One verified path opens gate; alternative not forced |
| Ambiguity | Multiple candidate hosts | `DISCRIMINATOR` or user clarification; no auto-selection |
| Missing source | Required relation lacks source | `UNSUPPORTED`/coverage gap, never routes to irrelevant source |
| Permission/retention | Source unreachable | `UNREACHABLE`, never `NOT_FOUND` |
| Partial result | Result limit or timeout | No negative license; reports partial coverage |
| Unknown native event | Schema outside vocabulary | Native observation preserved; exploratory candidate |
| Misleading schema | Source named "email" lacking roles | Proposal rejected; name never implies proof |
| Role swap | Inverted client/server or sender/rcpt | Contract rejects or detects contradiction |
| Prompt injection in logs | Row contains instructions | Zero change to graph, budget, or tool policy |
| LLM compiler failure | Empty/invalid JSON | Max 1 repair, then graceful stop; no fake graph |
| LLM query failure | Malformed or unsafe SPL | AST gate blocks execution; zero dispatch |
| Provider failure | Splunk disconnects mid-run | Job cancelled; error reported with clean checkpoint |
| No progress | Repeated identical queries | Bounded recovery exhausts; halts with no-progress signature |

## 6. Definition of Done and Priorities

### P0 (Mandatory before further optimization):
- LLM cannot materialize proof-capable capability.
- GoalGraph carries AnswerContract, provenance spans, and AND/OR/GATE semantics.
- Ambiguous candidate bindings never auto-bind.
- Progressive frontier replaces full-catalog prompting; coverage retains unexamined sources.
- Stop rules strictly enforce proof obligations.
- Report displays graph, actions, queries, evidence, and cost.

### P1 (Required for evaluable prototype):
- Native SPL quarantine with AST parser, scanCount, and cancellation telemetry.
- SourceCard cache invalidation on schema/permission/contract changes.
- Evaluation corpus, baseline B0/B1 comparison, and layer metrics.
- Live Splunk replay with failure/partial/ambiguity cases.

### P2 (Post-measurement enhancements):
- Secondary providers, graph databases, online contract promotion, or multi-agent reflection.
