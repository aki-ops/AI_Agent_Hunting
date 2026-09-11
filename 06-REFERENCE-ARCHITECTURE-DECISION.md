# 06 — Reference Architecture for Evidence-Grounded Threat Hunting (v8)

## Decision

The system shall be a **Contract-Grounded Progressive Hunt Graph** agent, not a
fixed playbook engine, not a relation-first keyword template, and not an
unconstrained LLM agent. Its universal unit of reasoning is an obligation graph
of testable goals, candidate bindings, and human-approved proof contracts whose
truth must be established from verified telemetry.

The target architecture spans two operational planes:

```text
================================================================================
CONTROL PLANE (Bootstrap / Catalog / Knowledge Management)
--------------------------------------------------------------------------------
ProviderManifest + SourceCard Catalog + SemanticVocabulary
  + ProofContractRegistry + QueryCompilerRegistry + CapabilityIndex
  + EvaluationCorpus
================================================================================
HUNT PLANE (Execution Lifecycle: Steps A–J)
--------------------------------------------------------------------------------
[Step A] Freeze Request & Budget (HuntRunContext: ceilings, hashes, seeds)
    │
[Step B] Semantic Compilation C1 (GoalGraph + AnswerContract; NO catalog/SPL)
    │
[Step C] Deterministic Validation (rejection of hallucinated entities/sources)
    │
[Step D] AND/OR/GATE Graph Planning (HTN-inspired reduction & discriminators)
    │
[Step E] Progressive Frontier F0–F4 (Certified -> Metadata -> Adjacent -> Profiling -> Exhaustive)
    │
[Step F] Controlled Binding (CandidateSet; auto-bind ONLY on unique proof; else DISCRIMINATE / ask)
    │
[Step G] Typed QueryIntent (EXPLORE / DISCRIMINATE / PROVE)
            ├── Deterministic Compiler (preferred)
            └── Quarantined Native SPL Gate (AST check, manifest-bound, SID cancel on timeout)
    │
[Step H] Evidence Pipeline (Row -> Observation -> FieldFact -> CandidateRelation)
    │
[Step I] ProofContract Evaluation (structural / retrieval_only / proof_capable)
    │
[Step J] 9-State Stopping Taxonomy & 6-Part Report + Machine Run Account JSON
================================================================================
```

This is a thesis engineering composition. Its individual components inherit from
peer-reviewed literature; the end-to-end integration, data contracts, progressive
frontier, and verifier policies constitute the local scientific contribution and
must be empirically evaluated via ablation and replay.

### Three Non-Negotiable Architectural Invariants

1. **LLM is a semantic planner, not a semantic oracle.** The LLM may propose
   goals, candidate sources, field mappings, queries, and explanations. Only
   deterministic validators, adapters, and human-approved `ProofContract`
   evaluators may promote a claim or answer to verified status.
2. **No full-schema prompt, no fixed Top-K cutoff.** The catalog of sources and
   fields remains outside the hot LLM prompt. The agent expands a progressive
   frontier (F0–F4) per unresolved goal. Unexamined sources are explicitly
   recorded as coverage gaps; shortlists never license negative claims.
3. **Never auto-bind ambiguous candidates without proof.** If multiple entities
   (hosts, accounts, IPs, artifacts) match, the agent must execute a
   `DISCRIMINATOR` query or halt for human clarification (`NEEDS_DISAMBIGUATION`).
   It never selects candidates by substring heuristic or arbitrary ranking.

---

## Scope and Non-Goals

The agent accepts a natural-language question, threat hypothesis, CTI/TTP/IOC/CVE,
or structured hunt request. It outputs a verified factual answer, a supported or
refuted hypothesis assessment, or an explicit inconclusive verdict detailing
unexamined coverage gaps.

It is **not** an autonomous incident-response remediation tool, an exploit
payload generator, or an omniscient detector. It cannot assert absence from
incomplete telemetry. It distinguishes factual lookup, causal reconstruction,
hypothesis verification, and population discovery through declared goal
contracts—never through keyword routing.

---

## Two Operational Planes

### 1. Control Plane (Offline / Governance)

The Control Plane manages durable, reusable assets independently of individual
hunt runs:

- **`ProviderManifest`**: Declares configured providers, partition scopes (index,
  sourcetype), retention, credentials, health check endpoints, query limits, and
  cancellation semantics.
- **`SourceCard` Catalog**: Compact descriptors per source/sourcetype containing
  exact field names/types, sample sketches, time spans, cardinality estimates,
  schema versions, and data provenance. Excludes unverified semantic assumptions.
- **`SemanticVocabulary`**: Standardized entity, value, and relation types (aligned
  with OCSF, MITRE ATT&CK, and Sigma taxonomy), with explicit support for
  `native_unknown`.
- **`ProofContractRegistry`**: Authoritative registry of versioned, peer-reviewed,
  and tested proof contracts defining the exact conditions under which telemetry
  proves a semantic relation.
- **`QueryCompilerRegistry`**: Parameterized native query compilation pipelines
  mapping typed `QueryIntent` to native backend queries (e.g., Splunk SPL).
- **`CapabilityIndex`**: Lexical (BM25) and dense embedding index over `SourceCard`
  catalog to prioritize retrieval candidates without granting proof authority.
- **`EvaluationCorpus`**: Curated ground truth cases, gold answer contracts,
  forbidden inferences, and split definitions.

### 2. Hunt Plane (Online Lifecycle: Steps A–J)

#### Step A — Freeze Request and Budget
Constructs an immutable `HuntRunContext` containing: `request_id`, content hash,
explicit user-provided entities, temporal constraints, permitted providers, LLM
call/token limits, provider scan/runtime limits, and model/registry versions.
Provider selection is based on health and capability manifest, never on arbitrary
local fallbacks (e.g., falling back to CDB/SQLite when Splunk is configured).

#### Step B — LLM Semantic Compilation (Call C1)
Compiles the request into a `GoalGraph` and `AnswerContract`. Context is isolated:
receives **only** the request text, compact vocabulary schemas, and time policy.
**Zero provider schema, zero source catalog, and zero SPL** are provided.
- Emits atomic goals with exact character spans tracing back to request text.
- Formulates AND/OR/GATE dependencies and typed variables.
- Flags explicit non-binding assumptions and clarification triggers.
- Prevents narrative expansion (e.g., ransomware does not automatically invoke
  SMTP, DNS, or PowerShell without direct request relevance).

#### Step C — Deterministic Graph Validation
Validates C1 output against deterministic policy:
- Rejects entity drift (e.g., user specifies Mallory $\rightarrow$ cannot mutate to Alice).
- Enforces qualifier distinction (e.g., `MacBook` is a device qualifier, not a hostname).
- Validates goal dependencies, prevents cyclic graphs, and rejects invented sources.
- Novel relations are tagged `NOVEL_RELATION` and restricted to exploration paths.

#### Step D — AND/OR/GATE Graph Planning
Constructs an executable logical plan using explicit dependency types:
- `AND`: All predecessor goals must succeed.
- `OR`: Any alternative proving the required output binding satisfies the gate.
- `GATE`: Blocks downstream goals until required prerequisite bindings are proved.
- `OPTIONAL`: Gathers supporting confidence without blocking answer derivation.
- `DISCRIMINATOR`: Queries specifically synthesized to reduce candidate ambiguity.

#### Step E — Progressive Frontier Capability Discovery
Replaces exhaustive per-hunt catalog dumping with a 5-stage progressive expansion:
- **F0 (Certified)**: Operations backed by registry-approved `ProofContract`.
- **F1 (Metadata Retrieval)**: `SourceCard` candidates retrieved via lexical/embedding match (threshold-gated, no arbitrary Top-K truncation).
- **F2 (Adjacent Expansion)**: Broadens search to sources sharing partitions, join keys, or field aliases if F0/F1 indicate missing fields.
- **F3 (Bounded LLM Profiling)**: Compact LLM prompt (Call C2) evaluating a small batch of `SourceCard` items for an unresolved goal; proposals default strictly to `RETRIEVAL_CAPABLE`.
- **F4 (Approved Exhaustive)**: Offline audit or user-approved escalation only.
Tracks `unexamined_source_ids` in coverage manifest; shortlist never proves absence.

#### Step F — Controlled Entity Binding
Entities are tracked via `CandidateSet` containing `CandidateBinding` records:
- Auto-binding is permitted **if and only if** exactly one candidate satisfies an
  approved proof contract with zero contradictions.
- If multiple candidates exist:
  1. Planner synthesizes a cheap `DISCRIMINATOR` query.
  2. If ambiguity persists, requests user clarification or halts with `NEEDS_DISAMBIGUATION`.
  3. Prohibits substring matching (e.g., host containing `air`), first-row selection, or arbitrary LLM choice.

#### Step G — Typed QueryIntent & Quarantined Native SPL Gate
Queries are formulated first as typed `QueryIntent` specifying intent mode:
- `EXPLORE`: Bounded sampling to discover schema or existence (no proof license).
- `DISCRIMINATE`: Narrow query designed to separate conflicting candidate entities.
- `PROVE`: Strict role projection targeting exact proof contract requirements.

Execution paths:
1. **Deterministic Compiler**: Preferred path using registered templates.
2. **Quarantined SPL Fallback (Call C3)**: Used only when compiler cannot express
   the operation. Evaluated by strict AST gate:
   - Read-only AST command allowlist.
   - Identifier check against active `ProviderManifest`.
   - Escaped literals from trusted bindings only.
   - Explicit `earliest`/`latest` time bounds.
   - Execution management: `dispatch.max_time`, scan/result caps, client-side timeout triggers backend SID cancellation.

#### Step H — Evidence Pipeline
Strict transformation stages:
$$\text{Native Row} \rightarrow \text{Observation} \rightarrow \text{FieldFact} \rightarrow \text{CandidateRelation} \rightarrow \text{ProofContract Evaluation} \rightarrow \text{EvidenceItem}$$
- Raw rows and observations are append-only and immutable.
- LLM reads compact evidence cards (Call C4) to synthesize explanations; cannot
  invent values, flip subject/object roles, or promote co-occurrence to proof.

#### Step I — ProofContract Evaluation
Differentiates 3 capability levels:
1. `STRUCTURALLY_VALID`: Fields match primitive types and shapes.
2. `RETRIEVAL_CAPABLE`: Operation can filter or narrow candidates (default for dynamic mappings).
3. `PROOF_CAPABLE`: Operation satisfies approved proof contract; authorized to assert facts.

#### Step J — 9-State Stopping Taxonomy & Reporting
Halts deterministically under one of 9 mutually exclusive states:
1. `ANSWER_PROVED`: Answer slots verified with complete evidence citations.
2. `BOUNDED_NOT_FOUND`: Legitimate absence confirmed over complete, observable scope.
3. `NEEDS_DISAMBIGUATION`: Multiple candidate entities remain unresolved; requires user input.
4. `COVERAGE_EXHAUSTED`: All reachable frontiers evaluated without satisfying proof contract.
5. `BUDGET_EXHAUSTED`: Call, token, query, scan volume, or wall-time ceilings reached.
6. `BACKEND_DEGRADED`: Provider unreachable, queries timeout, or connection lost.
7. `SAFETY_QUARANTINE`: AST gate violation, injection attempt, or unauthorized scope access.
8. `VALIDATION_FAILED`: Graph, binding, or contract validation failure.
9. `ABORTED_BY_USER`: Explicit cancellation by analyst.

Emits a **6-Part Human Report** (`report.md`) and a **Machine Run Account** (`run_account.json`).

---

## LLM Call Ceilings and Context Isolation

| Call ID | Phase / Purpose | Allowed Input Context | Output Contract | Call Ceiling |
|---|---|---|---|---:|
| **C1** | Semantic Goal Compilation | Request text, vocabulary JSON schemas, time policy | `GoalGraph` + `AnswerContract` JSON | 1 call (+ 1 repair) |
| **C2** | Progressive Source Profiling | Target goal obligation, compact `SourceCard` batch | Candidate role proposals (`RETRIEVAL_CAPABLE`) | $\le 3$ calls/goal |
| **C3** | Quarantined SPL Synthesis | Single goal, selected `SourceCard`, trusted bindings | Raw candidate SPL (sent to AST gate) | $\le 2$ calls/goal |
| **C4** | Evidence Card Synthesis | Formatted `FieldFact` cards, target goal | Summary explanation, candidate observations | $\le 5$ calls/run |
| **C5** | Bounded Replanning | Unresolved goal delta, new evidence cards, coverage | Revised goal graph or stop signal | $\le 2$ calls/run |
| **C6** | Grounded Final Narrative | Verified evidence cards, answer values, audit manifest | Human-readable Markdown report | 1 call |

---

## Financial and Operational Cost Accounting

Total investigation cost is formally tracked and bounded:

$$C_{run} = C_{llm} + C_{splunk} + C_{control} + C_{analyst}$$

Where:
- $C_{llm} = \sum (\text{input\_tokens} \times r_{in} + \text{output\_tokens} \times r_{out})$
- $C_{splunk} = \sum (\text{scanCount} \times r_{scan} + \text{runDuration} \times r_{compute})$
- $C_{control} = \text{local embedding / index lookup compute costs}$
- $C_{analyst} = \text{analyst interaction minutes} \times r_{human}$

Cost waste ratio is tracked for optimization:
$$\text{Waste Ratio} = \frac{C_{\text{unproductive\_queries}} + C_{\text{rejected\_spl}} + C_{\text{discarded\_calls}}}{C_{run}}$$

---

## Evaluation Gate: 15-Scenario Counterfactual Matrix

No architectural claim is accepted without verification across the full 15-scenario
matrix (Section 8 of `08-EVIDENCE-BASED-REARCHITECTURE-PLAN.md`):

1. **S01**: Tor Browser Version (exact attribute lookup)
2. **S02**: Tor Browser Artifact Identity (device qualifier isolation)
3. **S03**: Amber Competitor Domain (web proxy / DNS proof)
4. **S04**: Amber External Email Exfiltration (mail proof)
5. **S05**: Amber Workstation Identity (person $\rightarrow$ endpoint)
6. **S06**: Amber Account Logon (person $\rightarrow$ account $\rightarrow$ host)
7. **S07**: Frothly Campaign Q317 File Encryption (ransomware transition proof)
8. **S08**: Mallory Air13 Hostname Disambiguation (multi-candidate host)
9. **S09**: PowerPoint File Download without Encryption (counterfactual benign file)
10. **S10**: Deceptive Sourcetype with Incompatible Fields (adversarial schema)
11. **S11**: Correct Sourcetype with Deceptive Name (unusual naming)
12. **S12**: Missing Telemetry Absence Query (explicit absence bounded stop)
13. **S13**: Splunk Backend Timeout & Search Job Cancel (backend degradation)
14. **S14**: Prompt Injection in Log Payload (quarantine defense)
15. **S15**: Cross-Tenant Multi-Provider Isolation (scope/permission defense)

Layer-separated evaluation metrics:
- **Planning**: Claim Precision, Recall, F1; Unsupported Expansion Rate.
- **Retrieval**: Evidence Precision, Recall@k; Query Completeness Accuracy.
- **Correlation**: Edge Precision, Recall, F1; Transition Validity.
- **Answer**: Exact Match, Value F1, Citation Grounding Rate.
- **Operations**: Decision Coverage, Waste Ratio, Mean Time to Verdict.

---

## Literature Grounding & Sources

1. **Wu, Y. et al.** “ExCyTIn-Bench: Evaluating LLM Agents on Cyber Threat Investigation.” *Microsoft Research / ICML*, 2026.
2. **Cyber Defense Benchmark.** “Evaluating LLMs on Direct Telemetry Hunting.” *Technical Report*, 2026.
3. **AutoLink.** “Iterative Schema Linking via Progressive Exploration.” *AAAI*, 2026.
4. **MDB-Link.** “Global Column Index and Shortlist Selection for Text-to-SQL.” *Preprint*, 2026.
5. **PMLR.** “Toward Autonomous SOC Operations with Constrained Query Generation.” *PMLR*, 2026.
6. **Kestrel Threat Hunting Language.** *OASIS Open Repository*, 2023.
7. **Gao, P. et al.** “AIQL: Enabling Efficient Attack Investigation through Dataset-Aware Querying.” *USENIX ATC*, 2018.
8. **Open Cybersecurity Schema Framework (OCSF).** *Linux Foundation*, 2024.
9. **Sigma / pySigma Specification.** *SigmaHQ*, 2024.
10. **Hossain, M. et al.** “SLEUTH: Real-time Attack Scenario Reconstruction from COTS Audit Data.” *USENIX Security*, 2017.
11. **Selective Classification.** “Risk-Coverage Tradeoffs in Abstaining Classifiers.” *JMLR*, 2010.
12. **Chen, X. et al.** “Towards Verifiably Safe Tool Use for LLM Agents.” *ICSE-NIER*, 2026.
13. **Splunk Enterprise REST API & Search Job Reference.** *Splunk Documentation*, 2026.
14. **DARPA I2O.** “Transparent Computing Dataset.” *DARPA*, 2019.
15. **Erol, K. et al.** “UMCP: A Sound and Complete Procedure for Hierarchical Task Network Planning.” *AIPS*, 1994.
16. **Maxam, A. et al.** “An Interview Study on Third-Party Cyber Threat Hunting Processes.” *USENIX Security*, 2024.

