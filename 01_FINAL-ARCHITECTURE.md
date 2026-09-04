# 01 — FINAL ARCHITECTURE (v4)

**CANONICAL SOURCE OF TRUTH.** This document defines a pure hypothesis-driven
threat-hunting engine. `02` defines algorithms, `03` records evidence and
sources, and `04` is the implementation gate.

## 1. Goal

Start from a short hunt hypothesis or hunt question and produce an auditable
account of supporting, contradicting, unknown and unreachable evidence. The
engine is not alert-triage and does not require a CVE PoC.

It must:

- turn a hypothesis into testable evidence requirements;
- discover configured provider capabilities and execute bounded queries;
- work across heterogeneous SIEM, EDR, IDS, identity and cloud telemetry;
- discover entities without a predeclared event taxonomy;
- evaluate evidence against competing hypotheses;
- keep raw observations out of repeated LLM contexts;
- stop with explicit coverage and uncertainty bounds.

## 2. Scope

```text
HYPOTHESIS / TTP / IOC / CVE / CTI / NL QUESTION
→ evidence-driven hunting
```

An alert can be converted by an external integration into a hypothesis, but the
core engine has no alert-investigation mode. Active exploitation/pentesting is
out of scope.

## 3. Architecture

```text
HuntRequest
    ↓
Knowledge / Behavior Compiler
    ↓
Hypothesis + EvidenceRequirements
    ↓
Capability Registry + Runtime Validation
    ↓
Query Planner + Query Validator
    ↓
Provider Adapters / Query Execution
    ↓
Observation Ledger
    ↓
Evidence Fact + Evidence Group Builder
    ↓
Compatibility / Evidence Evaluator
    ↓
HuntState
    ↓
Deterministic Action Controller
    ├── TEST / EXPAND / DISCOVER / PIVOT / REFINE
    └── STOP
    ↓
Final Hunt Account
```

`HuntState` is data, not a second controller.

| Component | Responsibility | LLM |
|---|---|---|
| Knowledge/Behavior Compiler | Normalize request and derive behavior candidates | optional, bounded |
| Capability/Adapter Layer | Describe and execute provider operations | no state authority |
| Query Planner/Validator | Bind evidence to safe queries | templates first; fallback only |
| Observation/Evidence Layer | Preserve, compress and evaluate evidence | semantic fallback only |
| Hunt Controller | Own transitions, budgets, coverage and stopping | forbidden |
| Account Renderer | Produce structured account and optional prose | optional |

## 4. Input and output

```python
HuntRequest = {
    "id": str,
    "kind": "HYPOTHESIS" | "TTP" | "IOC" | "CVE" | "CTI_REPORT" |
            "NL_QUESTION" | "SCHEDULED",
    "content": str,
    "entities": list[EntityRef],
    "time_policy": TimePolicy | None,
    "provider_hints": list[str],
}
```

Entities, time and provider hints are optional. Missing values use an explicit
deployment policy and are never silently treated as facts.

```python
FinalHuntAccount = {
    "request_id": str,
    "objective": HuntObjective,
    "hypotheses": list[Hypothesis],
    "evidence_cards": list[EvidenceCard],
    "queries": list[QueryRecord],
    "supporting": list[str],
    "contradicting": list[str],
    "unknown": list[str],
    "unreachable": list[str],
    "residuals": list[str],
    "coverage_bound": CoverageBound,
    "stopping_decision": StoppingDecision,
}
```

## 5. Core contracts

```python
Hypothesis = {
    "id": str,
    "statement": str,
    "origin": "INPUT" | "LLM_PROPOSAL" | "RULE" | "HUMAN",
    "status": "LIVE" | "SUPPORTED" | "WEAKENED" | "REFUTED" | "UNTESTABLE",
    "source_refs": list[str],
    "requirements": list[str],
}

EvidenceRequirement = {
    "id": str,
    "description": str,
    "evidence_type": str,
    "entity_scope": EntityRef | "ANY" | "POPULATION",
    "time_scope": TimeWindow,
    "predicate": Predicate | None,
    "supports": list[str],
    "contradicts": list[str],
    "falsification_condition": str,
    "source_refs": list[str],
    "status": "PROPOSED" | "VALIDATED" | "UNSUPPORTED" | "REJECTED",
}
```

`EvidenceRequirement` is reusable. `Expectation` instantiates it for a
particular entity/time/predicate. `QueryPlan` is provider-specific:

```text
EvidenceRequirement → Expectation → QueryPlan → QueryResult
```

```python
ProviderScope = {
    "provider_id": str,
    "scope_id": str,
    "native_partition": dict[str, str],
    "coverage_start": datetime,
    "coverage_end": datetime | None,
    "retention_days": int | None,
    "known_gaps": list[Gap],
}

Cell = {
    "provider_scope": ProviderScope,
    "entity": EntityRef | ANY,
    "time_bucket": TimeBucket,
}
```

`Cell` is a coverage address only. It has no `event_family`, `event_code`,
intent or operation axis. Native types remain in observations; semantic mapping
is optional.

```python
EvidenceCard = {
    "id": str,
    "fingerprint": str,
    "representative_observation_ids": list[str],
    "count": int,
    "entity_summary": dict,
    "time_summary": dict,
    "field_summary": dict,
    "fact_type": str,
    "completeness": str,
    "relations": list[EvidenceRelation],
}
```

The ledger stores every observation. The LLM receives bounded cards and deltas,
not every raw row.

## 6. LLM boundary and cost policy

LLM calls are conditional gates:

| Gate | Trigger | MVP limit |
|---|---|---:|
| Objective compilation | Unstructured or novel input | 1 |
| Query fallback | No validated template | 1 per requirement/provider/schema |
| Ambiguous evidence | Rules cannot discriminate hypotheses | 1 per epoch |
| Narrative | Explicit analyst request | 1, optional |

```python
max_llm_calls_per_hunt = 3
max_llm_calls_per_epoch = 1
max_retries = 1
max_dynamic_requirements = 5
```

Known predicates, grouping, correlation, capability selection, coverage, state
and stopping are deterministic. A known or duplicate observation never triggers
an LLM call.

## 7. Outcomes and stopping

```text
SUPPORTED       — evidence satisfies the hypothesis requirements
CONTRADICTED    — complete and observable evidence refutes it
INCONCLUSIVE    — evidence is insufficient or ambiguous
UNKNOWN         — required meaning/data cannot be established
UNREACHABLE     — provider/scope/telemetry cannot be queried
```

```text
STOP_RESOLVED | STOP_BOUNDED | STOP_EXHAUSTED_BY_BUDGET
```

`NO_EVIDENCE_FOUND` is a report result, not `BENIGN`. The account must state the
searched frame, incomplete regions and unobservable requirements.

## 8. Basis and limitations

The architecture adapts the knowledge–hypothesis–action model from *Evidential
Cyber Threat Hunting*, adaptive targeted collection and hypothesis testing from
ATHAFI, and behavior-to-query synthesis from ThreatRaptor. MITRE’s methodology
separates hypothesis development, data requirements and collection gaps.

The exact Cell model, EvidenceCard compression, compatibility semantics,
bounded LLM gates and coverage-aware stopping are thesis engineering decisions,
not claims that a paper proved the exact implementation. See `03` and `02`.
