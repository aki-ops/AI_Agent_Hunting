# 01 — FINAL ARCHITECTURE (v8 / Contract-Grounded Progressive Hunt Graph)

## Source of truth

This document defines the architecture. `08-EVIDENCE-BASED-REARCHITECTURE-PLAN.md`
is the authoritative, evidence-based rearchitecture plan and implementation master.
`02_METHOD-AND-IMPLEMENTATION-PLAN.md` defines execution and migration.
`03_LITERATURE-AND-TRACEABILITY.md` records scientific grounding and thesis limits.
`04-IMPLEMENTATION-CHECKLIST.md` is the evidence-gated implementation checklist.
`06-REFERENCE-ARCHITECTURE-DECISION.md` and `07-STRATEGIC-RESEARCH-REVIEW.md` record
the strategic and architectural critique leading to this specification.

The system is a **Contract-Grounded Progressive Hunt Graph** agent. It accepts a
natural-language question, hypothesis, CTI/TTP/IOC/CVE or scheduled hunt and produces an
auditable answer or an explicit inconclusive result. It is neither an unconstrained LLM
nor a collection of pre-baked scenario playbooks.

## 1. Core architecture

```text
Natural-language Request
  -> LLM compiles GoalGraph + AnswerContract (C1)
  -> Deterministic Graph & Provenance Validation
  -> Ready Goal Selection (AND / OR / GATE Planner)
  -> Capability Discovery via Progressive Frontier (F0 -> F4)
  -> Controlled Entity Binding (CandidateSet, Discriminator, Disambiguation)
  -> QueryIntent Synthesis (EXPLORE | DISCRIMINATE | PROVE)
       -> Deterministic Compiler (preferred)
       -> Quarantined Native SPL Candidate (isolated C3 fallback)
  -> Native SPL Gate (AST Parser, Read-only, Bounds, Cancellation SID)
  -> Observation -> FieldFact -> Candidate Evidence Pipeline
  -> ProofContract Evaluation (STRUCTURALLY_VALID | RETRIEVAL_CAPABLE | PROOF_CAPABLE)
  -> State-based Stopping Taxonomy (9 verifiable states)
  -> 6-Part Auditable Report + Machine Run Account JSON
```

### Three Non-Negotiable Invariants

1. **LLM is a semantic planner, not a semantic oracle.** The model may propose goals,
   sources, fields, queries and explanations. Only deterministic validators, adapters
   and human-reviewed `ProofContract` instances can alter proof state.
2. **No full-schema prompt and no fixed Top-K cutoff.** Hot-path prompts never receive
   the entire provider catalog. Discovery operates across a progressive frontier
   (`F0` certified -> `F1` metadata -> `F2` adjacent -> `F3` bounded profiling -> `F4` approved exhaustive).
   Unexamined sources are recorded as coverage gaps; a shortlist never proves absence.
3. **Never auto-bind ambiguous candidates without proof.** If multiple entities
   (accounts, hosts, IPs, artifacts) match and an automated `DISCRIMINATOR` cannot
   distinguish them within budget, the agent must ask the user or halt as
   `STOP_NEEDS_CLARIFICATION` / `NEEDS_DISAMBIGUATION`. It must never pick by string heuristics,
   first row, or LLM preference.

## 2. Scientific grounding and limits

| Architectural principle | External grounding | Boundary of the claim |
|---|---|---|
| Evidence/provenance graph | SLEUTH, HOLMES, OmegaLog | Supports multi-hop reconstruction and context preservation; does not require every question to use a fixed attack graph. |
| Typed logical query before native syntax | AIQL, ThreatRaptor | Supports an intermediate query/behaviour representation; does not prove this repository's exact schema. |
| Hypothesis/evidence/action loop | Evidential Cyber Threat Hunting, ATHAFI, TaHiTI | Supports explicit uncertainty and adaptive collection; thresholds and stopping enums are local choices. |
| Schema/capability-aware execution | OCSF, MITRE Data Components, Microsoft Threat Hunting Assistant | Supports provider-aware binding and extensible semantics; no taxonomy covers every native event. |
| LLM bounded by deterministic execution and verification | ExCyTIn-Bench and safe tool-use research | Supports measuring and constraining the LLM; does not make a model reliable by itself. |
| Flexible threat-hunting process | Maxam et al. field study | Supports avoiding one prescriptive workflow; does not specify our implementation. |

Full links and source tiers are in `03`. External papers support principles,
not the exact budgets, prompts, class names, or F1 thresholds in this project.

## 3. Two-Plane Architecture

The system operates across two distinct operational planes:

### 3.1 Control Plane (Out-of-Hunt Preparation & Registry)

Manages reusable, long-lived artifacts across hunts:
- **ProviderManifest:** Configured providers, credentials, scope partitions, retention, permissions, rate limits, and job cancellation interfaces.
- **SourceCard Catalog:** Compact, auditable descriptors for each source/sourcetype: native fields, primitive types, cardinality estimates, time spans, schema fingerprints, and privacy-filtered sketches.
- **SemanticVocabulary:** Shared entity, value, and relation types (referencing OCSF, ATT&CK, Sigma taxonomy), supporting `native_unknown`.
- **ProofContractRegistry:** Human-reviewed and test-verified semantic contracts defining what evidence constitutes proof for a relation.
- **QueryCompilerRegistry:** Deterministic compilers transforming typed `QueryIntent` into provider-native syntax.
- **CapabilityIndex:** Lexical + embedding index over `SourceCard` metadata for efficient candidate ordering (discovery only, never proof authority).
- **EvaluationCorpus:** Benchmark requests, valid graph paths, gold answers, and holdout splits.

### 3.2 Hunt Plane (Single Execution Lifecycle, Steps A–J)

- **Step A — Freeze Request & Budget:** Construct immutable `HuntRunContext` (request hash, time policy, provider scopes, LLM token ceilings, Splunk scan/runtime limits).
- **Step B — LLM Semantic Compilation:** C1 compiles `GoalGraph` and `AnswerContract` from request text without seeing the provider schema.
- **Step C — Deterministic Graph Validation:** Check provenance spans, acyclicity, and reject invented entities (e.g. changing Mallory to Alice, MacBook to hostname).
- **Step D — AND/OR/GATE Planning:** Planner determines dependency resolution order, requiring all AND predecessors, accepting any OR path, and enforcing GATE input prerequisites.
- **Step E — Progressive Capability Frontier:** Search capability space incrementally (`F0` certified -> `F1` metadata -> `F2` adjacent -> `F3` bounded profiling -> `F4` approved exhaustive) per unresolved goal.
- **Step F — Controlled Entity Binding:** Maintain `CandidateSet`; execute `DISCRIMINATOR` queries or request clarification upon ambiguity.
- **Step G — QueryIntent before SPL:** Emit typed intent with mode `EXPLORE`, `DISCRIMINATE`, or `PROVE`. Compile deterministically or quarantine LLM-generated SPL through AST and safety gates.
- **Step H — Evidence Pipeline:** Raw native row -> append-only `Observation` -> deterministic `FieldFact` -> `CandidateRelation` -> `ProofContract` evaluation -> `EvidenceItem`.
- **Step I — ProofContract Evaluation:** Authority rests solely in the contract. Cooccurrence is restricted to `RETRIEVAL_CAPABLE`; only approved contracts grant `PROOF_CAPABLE`.
- **Step J — State-based Stopping:** Halt only via verifiable state enums, never by asking the LLM if it is satisfied.

## 4. Universal data contracts

### 4.1 Request & Run Context

```python
HuntRequest = {
    "id": str,
    "kind": "QUESTION" | "HYPOTHESIS" | "TTP" | "IOC" |
            "CVE" | "CTI_REPORT" | "SCHEDULED",
    "content": str,
    "entities": list[EntityRef],
    "time_policy": TimePolicy | None,
    "provider_hints": list[str],
}
```

The request is an objective, not evidence. An explicit entity is an unverified
seed until a provider observation establishes the required relation.

### 4.2 GoalGraph and AnswerContract

The provider-neutral semantic contract proposed by the LLM and accepted only
after validation is `SemanticGoalGraph`. It contains typed variables,
relations, qualifiers, answer variables, assumptions and uncertainties.
`ClaimGraph` remains a compatibility representation for the older execution
path; it is mechanically projected into the semantic graph and is not allowed
to bypass typed capability binding.

```text
SemanticGoalGraph {
  id,
  variables: typed entities/values and constraints,
  relations: subject -> relation -> object,
  qualifiers: required restrictions on relations,
  answers: variables requested by the user,
  assumptions, uncertainties,
}
```

There is no universal `event_family` axis and no automatic semantic branch.
Technical prerequisites may be added only when an operation explicitly
requires them; they are recorded as prerequisites, not as extra conclusions.

Every relation must be traceable to the request or a declared prerequisite;
unsupported story expansion is rejected. The runtime planner composes typed AND
dependencies and declared OR alternatives. It does not infer account, endpoint,
IP, message, recipient, role or web paths from request keywords. Operation-
required prerequisites belong to capability binding.

The graph is not required to pass through a particular identity type. If the
request has a person and the provider can discover endpoint keys directly,
`person -> host` is a valid route; `person -> account -> host` is only another
typed route when an account relation is actually observable. This keeps the
account/host anchor region flexible without selecting a host by name or order.

### 3.3 Telemetry census and CapabilityGraph

The Provider Census first creates a versioned, provider-neutral
`TelemetryCensus`. It records native partitions, schemas, field coverage,
retention, permissions, query primitives and bounded privacy-filtered field
sketches. It does **not** conclude that a sourcetype is mail, process, file or
any other semantic category merely from its name.

For an unresolved graph requirement, the LLM may propose a source capability
using only census IDs: a source, source fields as typed roles, relation/fact
kind and a bounded `ProbeSpec`. A deterministic validator checks every ID and
policy constraint; the adapter compiles and executes the probe. Only a
successful probe materializes a versioned `RuntimeCapability`.

The resulting `CapabilityGraph` contains bootstrap and validated runtime
operations:

```text
ProviderScope
  -> native partitions / index or table
  -> schema and field aliases
  -> logical operations
  -> input entity kinds
  -> output fact kinds
  -> permissions / retention / time limits
  -> pagination / completeness semantics
```

`ProviderOperation` is provider-neutral at the contract boundary. Its normal
execution form is a typed `QueryIntent`; the adapter owns binding validated
roles and compiling SPL, KQL, SQL or API syntax. It must declare which semantic
constraint keys it can prove and which it can use only as retrieval hints. A
searchable restriction narrows candidate retrieval but never upgrades the
relation verdict; only a proof-supported restriction can do that. A provider is
not selected merely because it is reachable: it must satisfy an outstanding
relation and expose the relevant contract.

The census is not sent wholesale to one LLM call. After the semantic graph is
validated, a deterministic batcher orders native source profiles separately
for each unresolved relation, but schedules every discovered source and every
field. It splits that complete set into context-sized batches; ordering is only
an execution optimization and never an admission decision. The LLM source
profiler sees one relation-specific batch at a time, while the complete census
remains the authoritative validation set. An incomplete batch run is a
coverage gap, never an implicit "no source" result.

When a `QueryIntent` cannot express a needed provider feature, a separately
gated LLM may submit one native-query candidate. It is not executed directly:
the provider parser converts it to an AST, then the policy requires read-only
operators, census-known identifiers, trusted values, explicit time/result/scan
bounds and a dry-run. This preserves novel-query expressiveness without making
raw SPL an unrestricted LLM tool.

Runtime bindings follow the same epistemic rule. A complete query may produce a
usable row while still leaving a requested restriction unproven; that output is
`CANDIDATE`, not `VERIFIED`. It may be consumed by a downstream exploratory
retrieval step so the system can collect discriminating evidence across the
whole candidate set, but it can never license a positive claim until the
restriction is proven. The executor must preserve every candidate and never
select the first value.
When a step returns more distinct output bindings than the configured fan-out
bound, the executor preserves all rows for audit but pauses for explicit
narrowing rather than launching unbounded downstream queries. Declared
alternative methods are tried only for an empty/failed method, not to multiply
an already ambiguous result.

A semantic route has three independent states that must never be collapsed:

1. **execution complete** — one bounded provider attempt finished;
2. **proof complete** — cited observations satisfy the relation and every
   required proof-supported restriction; and
3. **route exhausted** — every valid bounded retrieval stage, continuation,
   declared alternative and eligible capability-discovery action was either
   attempted or rejected with an audited reason.

A complete-empty query establishes only the first state. It normally creates an
`ATTEMPTED_EMPTY` relation assessment and a material delta for bounded recovery;
it does not establish semantic absence. Per-goal assessment states are
`UNPLANNED`, `PLANNED`, `ATTEMPTED_EMPTY`, `ATTEMPTED_PARTIAL`,
`CANDIDATE_OBSERVED`, `PROOF_GAP`, `CAPABILITY_GAP`, `VERIFIED` and
`ROUTE_EXHAUSTED`, with separate terminal causes for user decision, unsupported,
unreachable and budget exhaustion.

Provider operations declare an ordered, bounded retrieval policy. A recovery
stage may remove only predicates classified as retrieval hints. Verified entity
bindings, provider scope, time window, projection, row/page limits and proof
obligations remain invariant across stages. The controller records each attempt
and rejects a repeated no-progress signature. This is progressive retrieval,
not an unbounded fallback sweep.

Static typed reachability is not capability readiness. Readiness is evaluated
per required relation from typed reachability, input grounding, source/runtime
provenance, retrieval support, proof-supported restrictions, qualifier
observability and prior route state. A reachable retrieval-only operation may
collect candidates, but it cannot suppress runtime capability discovery when a
proof or observability gap remains.

### 3.4 Observation and EvidenceGraph

Raw observations are append-only and retain provider-native fields, native type,
query ID, cursor/completeness, timestamps and integrity metadata. Normalized
facts are additive aliases and never replace native data.

The EvidenceGraph contains observations and citations, normalized facts and
field roles, candidate and verified relations, claim status
(`UNPROVEN`, `SUPPORTED`, `REFUTED`, `PARTIAL`, `UNKNOWN`) and coverage/diagnostic
records.

Only deterministic verification may promote a claim. LLM prose cannot create an
observation, value, relation or final verdict.

## 5. Component responsibilities and LLM call boundaries (C1–C6)

The LLM is partitioned into six single-responsibility calls. No single prompt receives the entire catalog or full raw ledger.

| Call | Responsibility | Allowed Context | Output | Token Ceilings |
|---|---|---|---|---:|
| **C1: `semantic_compile`** | Convert request into GoalGraph + AnswerContract | Request text, small vocabulary, time policy | `GoalGraph` + `AnswerContract` | 2,500 in / 1,200 out |
| **C2: `capability_profile`** | Propose candidate mappings on cache miss | Single goal + compact `SourceCard` batch | `retrieval_only` candidate mappings | 2 × (1,800 in / 700 out) |
| **C3: `native_query_proposal`** | Suggest SPL when intent compiler unsupported | Single goal + selected source + verified bindings | Sandboxed candidate SPL | 1,800 in / 700 out |
| **C4: `evidence_interpret`** | Disambiguate evidence card semantics | Grouped delta evidence cards (no raw ledger) | Candidate interpretation & gaps | 2,500 in / 800 out |
| **C5: `replan`** | Revise goals upon deadlock with new evidence delta | Unresolved goal graph + compact delta | Revised goals (no verdict) | 2,000 in / 900 out |
| **C6: `narrative`** | Optional human-readable final summary | Verified account facts only | Narrative prose (no new facts) | 1,500 in / 600 out |

Deterministic system components (Zero LLM authority):
- **Plan Validator:** Preserves objective, rejects invented entities and validates provenance spans.
- **ProofContract Registry & Validator:** Verifies schema, enforces required roles, and materializes only `PROOF_CAPABLE` operations for approved contracts.
- **Planner:** Composes AND / OR / GATE dependencies and emits `DISCRIMINATOR` queries for ambiguous candidates.
- **Native Query Gate:** AST parsing, read-only allowlist, and job cancellation hooks.
- **Claim & Transition Verifier:** Evaluates exact ledger citations, timestamps, roles, and completeness.

## 6. Coverage coordinate

```text
Cell = (ProviderScope, entity | ANY, time_bucket)
```

`Cell` is an execution and coverage coordinate. It has no `event_family`,
`event_code`, semantic-intent or reasoning role. It records queried scope,
entity, time, cursor state and completeness.

Coverage is reported independently: claim coverage, scope coverage, query
completeness and evidence coverage. No targeted query implies full scope
coverage. An incomplete or unobservable query cannot support a negative
conclusion.

## 7. State-based stopping taxonomy

The controller terminates strictly through 9 verifiable execution states:
- `STOP_ANSWERED`: All required answer slots have grounded, contract-verified values with completed gate dependencies.
- `STOP_REFUTED`: Refutation condition proven by contract-compliant evidence.
- `STOP_NOT_FOUND_BOUNDED`: All required routes exhausted with complete-empty results under explicit negative evidence licensing.
- `STOP_NEEDS_CLARIFICATION`: Multiple competing candidates or missing user-provided facts require human disambiguation.
- `STOP_UNSUPPORTED`: No provider capability or approved proof contract exists for required relations.
- `STOP_UNREACHABLE`: Configured provider, permissions, or retention periods are inaccessible.
- `STOP_INCONCLUSIVE`: Execution completed but proof obligations remain unsatisfied or unlicensed.
- `STOP_BUDGET`: LLM token, call, query, or runtime ceiling reached; frontier checkpoint persisted.
- `STOP_ERROR`: Infrastructure, validator, or backend failure; never serves stale cached reports.

## 8. Resource and security policy

Budgets are configuration values to be measured, not scientific constants:
LLM calls (max 5), total tokens (max 15,000), queries, scan cells, runtime, retries and result volume.
The controller stops when a budget is exhausted and records why.

User text, CTI, and native log content are untrusted data. Prompt injection
must not change objective, claims, provider policy, scope, state, disposition
or budgets.

## 9. Final output

The system produces two strictly separated artifacts:
1. **Human Report (`report.md`):** Six auditable sections:
   - Section 1: Request and verified answer (or precise reason for abstention).
   - Section 2: Analyzed `GoalGraph` (goals, dependencies, GATEs, validation diagnostics).
   - Section 3: Execution trace (actions, input bindings, state updates).
   - Section 4: Grounded evidence table (human-readable values, cited observation IDs).
   - Section 5: Audited queries (purpose, mode, SPL, rows, completeness, scan/runtime).
   - Section 6: Coverage and cost accounting (obligations satisfied, unexamined frontier sources, full cost).
2. **Machine Run Account (`run_account.json`):** Complete, serialized, verifiable ledger containing raw observations, query results, execution telemetry, and cryptographic hashes for reproduction.
