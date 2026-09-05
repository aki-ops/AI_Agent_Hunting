# 01 — FINAL ARCHITECTURE (v4.1)

**Canonical architecture source of truth.** `02` describes the executable
method, `03` records literature and implementation traceability, and `04` is
the verified implementation gate.

## 1. Purpose and boundary

The system is a hypothesis-driven threat-hunting engine. It accepts a short
hypothesis, TTP, IOC, CVE, CTI question or natural-language hunt request and
returns an auditable account of evidence, uncertainty and coverage.

It is not an alert-triage workflow and does not require an alert or a CVE PoC.
An external alert integration may convert an alert into a hypothesis, but the
core engine does not depend on that conversion.

```text
HuntRequest
  → semantic / knowledge compilation
  → typed hypotheses and evidence requirements
  → provider capability validation
  → safe logical and native query plans
  → bounded provider execution
  → observations and evidence cards
  → deterministic testing and controller actions
  → coverage-aware FinalHuntAccount
```

## 2. Components

| Component | Responsibility | LLM boundary |
|---|---|---|
| Knowledge/Behavior Compiler | Converts typed knowledge or free text into hypotheses and requirements | Known CVE/TTP/IOC/templates: none; unstructured free text: at most one semantic call |
| Capability and Adapter Layer | Discovers scopes, fields, operations, retention and provider health; executes queries | None |
| Query Planner and Validator | Binds requirements to templates/capabilities and compiles safe native queries | Only fallback when no template exists and a caller is configured |
| Observation and Evidence Layer | Preserves native records, extracts facts, groups evidence and evaluates typed expectations | Only bounded batch refinement for unresolved groups |
| Action Controller | Owns TEST/CONTROL/EXPAND/DISCOVER/PIVOT/REFINE/STOP, budgets and stopping | None |
| Account Builder/Renderer | Builds the final structured account and Markdown report | Narrative LLM is not used by the current runtime |

`HuntState` is the data container. The controller API is the intended state
transition boundary; engine initialization/final usage attachment remains an
implementation detail covered by the current tests.

## 3. Input and output

```python
HuntRequest = {
    "id": str,
    "kind": "HYPOTHESIS" | "TTP" | "IOC" | "CVE" | "CTI_REPORT" |
            "NL_QUESTION" | "SCHEDULED",
    "content": str,
    "entities": list[EntityRef],       # optional explicit targets
    "time_policy": TimePolicy | None,
    "provider_hints": list[str],
}
```

The request may contain only `content`. An absent entity means a wildcard
population hunt, not a fabricated entity. Entities returned by semantic
compilation are hints for interpretation/query filtering; they are not
automatically confirmed Cells.

```python
FinalHuntAccount = {
    "request_id": str,
    "objective": HuntObjective,
    "hypotheses": list[Hypothesis],
    "evidence_cards": list[EvidenceCard],
    "queries": list[dict],
    "supporting": list[str],
    "contradicting": list[str],
    "unknown": list[str],
    "unreachable": list[str],
    "residuals": list[str],
    "coverage_bound": CoverageBound,
    "stopping_decision": StoppingDecision,
}
```

## 4. Semantic model

The compiler has two safe paths:

1. Versioned CVE/TTP/IOC/behavior templates compile deterministically.
2. Unstructured `HYPOTHESIS`/`NL_QUESTION` input is sent to the bounded
   semantic compiler when `--llm api` is configured. The result is validated by
   `validate_compiler_llm_output`. If the API is unavailable, not configured or
   returns an invalid schema, the hunt stops as `STOP_INSUFFICIENT`.

The semantic schema contains:

```python
SemanticCompilationResult = {
    "normalized_claim": {"text": str, "status": "UNVERIFIED"},
    "entities": [{"type": str, "value": str, "role": str}],
    "mechanism_status": "KNOWN" | "UNKNOWN",
    "hypotheses": [{
        "id": str, "statement": str, "class": str,
        "assumptions": list[str], "requirements": list[str]
    }],
    "requirements": [{
        "id": str, "semantic_intent": str,
        "necessity": "CRITICAL" | "SUPPORTING",
        "search_hints": list[str],
        "falsification_condition": str,
        "description": str, "source_refs": list[str]
    }]
}
```

There is no natural-language keyword classifier. Evidence attribution cannot
be triggered by words in a hypothesis statement. It requires a typed
`Expectation`, or a single bounded LLM batch when the card is genuinely
ambiguous. `search_hints` are query constraints only; they are not evidence,
Cells or confirmed entities.

## 5. Provider-neutral coverage model

```text
Cell = (ProviderScope, entity | ANY, time_bucket)
```

`Cell` has no `event_family`, `event_code`, semantic intent or operation axis.
Provider-native event types are retained in `Observation.native_type`; an
unknown native record may have `semantic_type=None` and must not be dropped.

```text
EvidenceRequirement
    → Expectation(entity, time, predicate)
    → QueryPlan(provider operation)
    → QueryResult(complete/partial/diagnostic)
```

`ProviderScope` retains the native partition, coverage interval, retention and
known gaps. `ProviderOperation` declares provider behavior, fields,
pagination and completeness. Scope coverage and requirement coverage are
reported separately.

## 6. Query and execution boundary

The planner uses a validated template first. If no template exists, a
configured planner LLM may propose structured parameters or custom query text;
the parser, provider allowlist, dry-run validation and native compiler must
accept it before execution. The semantic compiler never emits raw SPL/SQL.

The current live adapter is Splunk (`SplunkLiveAdapter`) and the local replay
adapter is CDB (`CdbAdapter`). EDR and IDS contracts are designed as extension
points, but no live EDR/IDS adapter is part of the current implementation.

## 7. Evidence and epistemic rules

- Raw observations are append-only and auditable.
- Fact extraction and temporal/entity correlation are deterministic.
- Repeated records become compressed `EvidenceCard` groups.
- A card may be compatible with multiple hypotheses.
- No expectation means no deterministic attribution; the result remains
  unknown or goes to one bounded ambiguity batch.
- `complete=False`, `UNREACHABLE`, `UNSUPPORTED`, `INCONCLUSIVE` and
  `UNKNOWN` never become a benign conclusion.
- Negative evidence is licensed only after scope health, any-record and
  predicate-observability controls pass.

## 8. LLM and resource policy

The current CLI/API wiring shares an `LLMUsageTracker` with a hard default of
three calls and 12,000 total tokens per hunt. The controller also enforces:

```text
max_turns = 15
max_queries = 60
max_llm_calls = 3
max_scan_cells = 100
max_runtime_seconds = 300
```

The semantic compiler is at most one call per free-text compilation. Query
fallback is used only when a template is absent. Evidence refinement is one
batch per evaluator instance/epoch and receives cards, not the raw ledger.
The offline `StubSemanticCompiler` is a test fixture selected explicitly by
scenario; it is not evidence of model quality or API cost.

## 9. Actions and stopping

The controller selects actions in this order when their preconditions exist:

```text
TEST → CONTROL → EXPAND → DISCOVER → PIVOT → REFINE → STOP
```

Terminal decisions include:

```text
STOP_RESOLVED
STOP_BOUNDED
STOP_EXHAUSTED_BY_BUDGET
STOP_INSUFFICIENT
STOP_UNSUPPORTED
STOP_UNREACHABLE
```

`STOP_RESOLVED` requires concluded expectations, resolved hypotheses and no
unexplored targeted instance Cell. `STOP_BOUNDED` means the controller has no
safe next action but the evidence is not a complete resolution.

## 10. Implementation and research boundary

The knowledge–hypothesis–action loop is adapted from evidential cyber threat
hunting and adaptive hypothesis testing. Behavior-to-query compilation,
provider capability validation, evidence grouping and bounded LLM escalation
are thesis engineering compositions. They require replay and live-provider
experiments; they are not claimed to be directly proven by any single paper.
See `03_LITERATURE-AND-TRACEABILITY.md`.
