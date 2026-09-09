# 01 — FINAL ARCHITECTURE (v6)

## Source of truth

This document defines the architecture. `02_METHOD-AND-IMPLEMENTATION-PLAN.md`
defines execution and migration. `03_LITERATURE-AND-TRACEABILITY.md` records
what external sources support and what remains a thesis engineering choice.
`04-IMPLEMENTATION-CHECKLIST.md` is the evidence-gated implementation plan.
`06-REFERENCE-ARCHITECTURE-DECISION.md` contains the detailed decision record
and research sources behind this revision.

The system is an **evidence-seeking investigation agent**. It accepts a
question, hypothesis, CTI/TTP/IOC/CVE or scheduled hunt and produces an
auditable answer or an explicit inconclusive result. It is neither an
unconstrained LLM nor a collection of scenario templates.

## 1. Core architecture

```text
Request
  -> Provider Census
  -> LLM Claim-Plan Proposal
  -> Deterministic Plan Validation
  -> Capability Binding and Action Selection
  -> Safe Native Query Execution
  -> Observation / Fact / Evidence Graph Update
  -> Claim Verification and Bounded Replanning
  -> Grounded Answer, Coverage and Cost Report
```

The same contracts are used for every request. The runtime must not branch on
`email`, `Tor`, `CVE`, `web`, `process`, `event_family`, or `request_mode` to
select a prewritten investigation story.

The investigation path is produced from:

1. the user's declared objective;
2. claims proposed by the semantic compiler;
3. provider capabilities and required inputs/outputs;
4. observations acquired during the current run; and
5. explicit acceptance, refutation, coverage and budget rules.

This gives a general contract without pretending that every hunt has the same
behavioural path.

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

## 3. Universal data contracts

### 3.1 Request

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

### 3.2 ClaimGraph

The ClaimGraph is the semantic contract proposed by the LLM and accepted only
after validation. It contains claims, dependencies, required observations,
acceptance/refutation rules and provenance.

```text
Claim {
  id,
  subject: typed entity or variable,
  predicate: attribute | relation | behaviour | controlled_absence,
  object_or_value_type,
  provenance: request | cti_source | verified_observation,
  dependencies: claim IDs,
  evidence_requirements,
  acceptance_rule,
  refutation_rule,
  optional: bool,
}
```

There is no universal `event_family` axis and no automatic semantic branch.
Technical prerequisites may be added only when an operation explicitly
requires them; they are recorded as prerequisites, not as extra conclusions.

Every non-prerequisite claim must be traceable to the request, a cited CTI
source or an already verified observation. Unsupported story expansion is
rejected. The runtime projection is mechanical: `build_investigation_case_from_intent()`
accepts only a validated `ClaimGraph` and emits one candidate relation per claim;
it does not infer account, endpoint, IP, message, recipient, role or web paths
from request keywords. Operation-required prerequisites belong to later binding.

### 3.3 CapabilityGraph

The Provider Census creates a versioned CapabilityGraph:

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

`ProviderOperation` is provider-neutral at the contract boundary; the adapter
owns SPL, KQL, SQL or API syntax. A provider is not selected merely because it
is reachable: it must be able to satisfy an outstanding claim.

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

## 4. Component responsibilities and LLM boundary

| Component | Responsibility | LLM boundary |
|---|---|---|
| Provider Census | Discover reachable sources, partitions, schemas, permissions and completeness. | None. |
| Semantic Compiler | Convert request into claims, dependencies, evidence requirements and acceptance rules. | One schema-strict proposal; no native query and no evidence assertion. |
| Plan Validator | Preserve objective, reject unsupported expansion and validate provenance. | None. |
| Capability Binder | Match claim requirements to operations with compatible inputs/outputs. | Optional ranking only among already valid candidates. |
| Action Controller | Select bounded actions from unresolved claims and available capabilities. | None for safety, state and budget. |
| Provider Adapter | Compile and execute parameterized native queries; expose completeness. | None. |
| Observation Ledger | Preserve raw rows and audit metadata. | None. |
| Fact/Evidence Builder | Extract facts, roles and evidence cards; update graph. | None for admission and identity of facts. |
| Claim Verifier | Check citations, roles, time, completeness and acceptance rules. | None. |
| Grounded Explainer | Explain verified evidence and limitations. | At most one bounded call; citations are checked and no new values allowed. |
| Final Reporter | Render answer, evidence, queries, coverage, stopping decision and cost. | LLM text is advisory only. |

## 5. Coverage coordinate

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

## 6. Action and stopping policy

An action is valid only if it reduces at least one unresolved claim and its
operation contract is satisfiable. Discovery, resolution, testing,
correlation, expansion and refinement are action labels—not a fixed universal
sequence.

```text
unresolved claims
  -> candidate operations
  -> completeness/cost/relevance score
  -> bounded action
  -> new observations
  -> verification or bounded replanning
```

Terminal decisions include `STOP_RESOLVED`, `STOP_REFUTED`,
`STOP_INCONCLUSIVE`, `STOP_COVERAGE_GAP`, `STOP_UNSUPPORTED_CAPABILITY`,
`STOP_UNREACHABLE` and `STOP_BUDGET_EXHAUSTED`. `NO_EVIDENCE_FOUND` is not
equivalent to `BENIGN`.

## 7. Resource and security policy

Budgets are configuration values to be measured, not scientific constants:
LLM calls, tokens, queries, scan cells, runtime, retries and result volume.
The controller stops when a budget is exhausted and records why.

User text, CTI, and native log content are untrusted data. Prompt injection
must not change objective, claims, provider policy, scope, state, disposition
or budgets.

## 8. Final output

The analyst-facing report contains request and answer contract, claim plan and
reason, cited evidence and explanation, queries and completeness, answer/claim
states, coverage, limitations and LLM/query/runtime cost. The raw ledger
remains available as an auditable artifact rather than an unstructured report
dump.
