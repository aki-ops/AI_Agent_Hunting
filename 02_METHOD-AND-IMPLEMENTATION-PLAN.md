# 02 — METHOD AND IMPLEMENTATION PLAN (v4)

**Source of truth for algorithms and acceptance criteria.** Architecture is in
`01`; references are in `03`; executable work is in `04`.

## 1. Canonical lifecycle

```text
HuntRequest
→ HuntObjective
→ Hypothesis + EvidenceRequirements
→ CapabilityBinding
→ Cell/search frame
→ QueryPlan
→ validated QueryResult
→ Observation
→ EvidenceFact/EvidenceGroup
→ hypothesis compatibility update
→ TEST/EXPAND/DISCOVER/PIVOT/REFINE
→ coverage-aware FinalHuntAccount
```

## 2. Input and behavior compilation

Use this order:

```text
structured input/template
→ trusted knowledge retrieval
→ LLM normalization only when needed
→ deterministic source/schema validation
```

Trusted knowledge includes CVE/NVD, vendor advisory, CISA KEV, MITRE
techniques/data components/detection strategies, CTI and versioned internal
behavior templates. A PoC may improve specificity but is never required.

For CVE input, separate:

```text
exposure → preconditions → exploitation indicators → post-exploitation → gaps
```

Unsupported behavior is reported as unsupported; the system never invents an
exploit path.

## 3. Requirement and expectation generation

Requirements are question-side concepts such as:

```text
process_execution, remote_authentication, destination_activity,
network_connection, software_version, vulnerability_exposure,
post_exploitation_behavior
```

Runtime observations first use existing predicates and behavior fingerprints.
Only an unmatched, high-value, batched behavior may trigger one LLM proposal for
a new requirement. The proposal requires source references, rationale,
predicate, falsification condition and required fields, then M3 validates it.

## 4. Capability binding and query planning

```text
EvidenceRequirement
→ CapabilityDescriptor
→ CapabilityBinding
→ QueryTemplate or validated LLM fallback
→ QueryPlan
```

Hard filters:

- requirement, entity and time are supported;
- required fields are observable or explicitly unknown;
- scope and permission are valid;
- pagination and completeness semantics exist;
- budget permits execution.

Rank remaining plans lexicographically:

```text
EXACT > PARTIAL
template > generated fallback
targeted > broad
strong completeness contract > weak contract
lower estimated cost > higher cost
```

No event-family or event-code catalogue is required for querying.

## 5. Execution and completeness

Adapters validate scope, parameters, time and provider syntax before execution.
`complete=False` is never a negative result. Prefer cursor pagination; use time
splitting as fallback. A truncated parent is audit-only and never subsumes child
cells.

An empty result can license negative evidence only after scope health, record
existence and predicate observability controls pass.

## 6. Evidence compression and evaluation

```text
QueryResult
→ normalized fact
→ fingerprint/group
→ EvidenceCard
→ compatibility matrix
```

The ledger is append-only storage, not prompt context. Deterministic evaluation
handles predicates, versions, entity links, time relations, completeness and
coverage. LLM semantic evaluation is only for unmapped/ambiguous groups and
receives the current hypothesis set plus the new delta.

The same evidence may be compatible with multiple hypotheses. “Consistent with
H1” is not “proves H1”.

## 7. State and controller

`HuntState` stores hypotheses, requirements, expectations, facts, evidence cards,
queries, Cells, coverage, unresolved groups, pivots and budgets. Only the Action
Controller changes state.

Default action order:

```text
TEST → CONTROL → EXPAND → DISCOVER → PIVOT → REFINE → STOP
```

The order and thresholds are provisional engineering parameters and must be
measured rather than presented as scientific facts.

## 8. Cost control

```python
if matches_known_rule(observation) or is_duplicate_group(observation):
    no_llm()
elif unresolved_batch_is_small_and_low_value():
    defer()
elif epoch_has_llm_call:
    defer()
else:
    call_bounded_llm()
```

Record calls, tokens, latency, retries, query count and groups per call. When
the LLM budget is exhausted, return `STOP_EXHAUSTED_BY_BUDGET` safely.

## 9. Experiments

| ID | Question | Metric |
|---|---|---|
| EXP-01 | sparse hypothesis compiles | valid objective rate |
| EXP-02 | capability matching is executable | bind/execution success |
| EXP-03 | templates reduce LLM use | calls, tokens and cost |
| EXP-04 | grouping preserves recall | grouped-vs-row recall |
| EXP-05 | escalation targets hard cases | escalation precision/recall |
| EXP-06 | unknown records survive | retention rate |
| EXP-07 | incomplete results never become negative | critical error rate |
| EXP-08 | competing hypotheses are retained | premature rejection rate |
| EXP-09 | controller avoids loops | turn/query compliance |
| EXP-10 | hunt works without PoC | useful evidence discovery |
| EXP-11 | provider extension is adapter-only | cross-provider contract pass |
| EXP-12 | cost-quality trade-off is acceptable | recall, calls, tokens, latency |
| EXP-13 | prompt injection is contained | attack success rate |
