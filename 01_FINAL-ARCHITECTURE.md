# 01 — FINAL ARCHITECTURE (v5.1)

## Current source of truth: discovery-first hunting

The current implementation uses a **discovery-first** contract for free-text
hunting. The request is not forced into a fixed attack chain or a predefined
relation graph before telemetry is inspected.

1. The LLM converts the hypothesis into a validated `HuntSpec`: intent,
   answer contract, anchors, evidence requirements and provider-neutral search
   terms. It must not emit SPL, event codes or a hard-coded attack path.
2. The provider is inspected for capabilities and schema, then the generic
   `search_text` primitive searches native content. Terms are grouped as
   alternatives within a group and intersected across groups; this prevents
   one guessed alias from suppressing valid evidence.
3. Returned native rows are preserved as observations and evidence cards. The
   next query is chosen from observed anchors, capability metadata and the
   answer contract—not from a fixed list of event families.
4. Deterministic checks validate exact fields, relationships, time order and
   query completeness. The LLM explains ambiguous evidence and proposes the
   next bounded search, but it cannot invent evidence or silently change the
   objective.
5. The former Investigation Case Graph is a post-discovery correlation and
   verification mechanism. It is not allowed to preempt content discovery.

When capability metadata is insufficient, the LLM may select a semantic
operation and literal search terms from the discovered metadata. It may not
emit native SPL, SQL or KQL; provider adapters own native query generation.

The relation-first sections below describe the compatibility path for already
structured cases; where they conflict with this section, this section wins.

**Canonical architecture source of truth.** `02` describes the executable
method, `03` records external literature and traceability, and `04` is
the verified implementation gate.

---

## 1. Purpose and Boundary [Tags: REF-ECTH, REF-TAHITI, REF-PEAK, REF-SLEUTH]

The system is a hypothesis-driven, evidential threat-hunting engine. It accepts
a natural-language question, CTI report, TTP, IOC, or CVE and produces an
auditable, citation-grounded forensic graph of evidence, uncertainty, and coverage.

It is not an alert-triage script and does not require a prior security alert or
a CVE proof-of-concept. The engine establishes a fundamental architectural shift in v5.0:

- **v4 Legacy Model**: `requirement → broad query → host/IP discovered → pivot`.
  (The `Cell` served as both coverage address and the agent's implicit thinking unit,
  causing severe failure modes where server hosts like `jabbah` or destination IPs
  were conflated with client endpoints).
- **v5.0 Relation-First Model**: `known entity → unresolved relation → valid operation → verified relation → pivot`.
  The central reasoning and state tracking unit is the **Investigation Case Graph**.
  `Cell` is retained strictly as a physical execution and coverage coordinate
  (`Cell = (ProviderScope, entity | ANY, time_bucket)`), **not** the agent's mental graph.

```text
HuntRequest / CTI / CVE / TTP / NL Question
    │
    ▼ [REF-HUNTERAGENT, REF-THREATRAPTOR]
Semantic Case Compiler (Emits typed InvestigationCase, zero raw SPL)
    │
    ▼ [REF-SLEUTH, REF-HOLMES, REF-MITRE-DC]
Investigation Case Graph (Nodes, directed Edges, mandatory Unknowns, Acceptance Criteria)
    │
    ▼ [REF-AIQL, REF-MITRE-ANALYTICS]
Capability Binder (Binds unresolved relations to logical provider operations)
    │
    ▼ [REF-PROVSEEK, REF-HOLMES]
Relation-Aware Action Planner (Backward/forward chaining on verified source nodes)
    │
    ▼ [REF-OCSF, REF-MICROSOFT]
Provider Query Execution (Splunk / CDB / EDR; parameterized, bounded, native type preserved)
    │
    ▼ [REF-HUNTERAGENT, REF-FOR508, REF-FOR572]
Deterministic Relation Verifier (Enforces citations & strict field roles: client_ip ≠ server_ip)
    │
    ▼ [REF-SLEUTH, REF-RAG-SEC]
Evidence / Provenance Graph (Verified RelationProofs & citation-backed EvidenceSubgraph)
    │
    ▼ [REF-EXCYTIN, REF-RAG-SEC]
LLM-Grounded Explanation (Advisory narrative bounded strictly to EvidenceSubgraph)
    │
    ▼ [REF-ECTH, REF-TAHITI]
Final Hunt Result & Epistemic Verdict (Proven causal chain or truthful INCONCLUSIVE_* stop)
```

---

## 2. Architectural Components & LLM Boundary [Tags: REF-HUNTERAGENT, REF-PROVSEEK, REF-CASCADE]

| Component | Responsibility | LLM Boundary | Source Grounding |
|---|---|---|---|
| **Semantic Case Compiler** | Compiles free text or CTI/CVE input into an `InvestigationCase` and `InvestigationGraph` with claims, unknowns, and required relation paths. | Free text: at most 1 schema-strict call. Known CVE/TTP: 0 calls (deterministic templates). Emits **no** raw SPL or vendor terms. | `REF-HUNTERAGENT`, `REF-THREATRAPTOR` |
| **Investigation Case Graph** | Central epistemic state holding nodes, edges, unproven relations, and mandatory unknowns. | None (Deterministic data structure). | `REF-SLEUTH`, `REF-HOLMES`, `REF-EXCYTIN` |
| **Capability Binder** | Maps each unresolved typed relation to a provider-neutral operation. The path is evidence-driven: web/DNS claims may require an IP hop, while process/file/software claims can query directly from a resolved endpoint. | None (Deterministic capability schema). | `REF-AIQL`, `REF-MITRE-ANALYTICS` |
| **Relation-Aware Action Planner** | Selects next action using backward/forward dependency chaining; enforces identity resolution before activity queries. | Advisory ranking only when multiple valid operations tie. Final selection is deterministic. | `REF-PROVSEEK`, `REF-FOR508` |
| **Provider Adapter Layer** | Discovers partitions, compiles native queries (SPL/SQL), manages L+1 completeness pagination. | None (Zero LLM query synthesis in normal path). | `REF-OCSF`, `REF-MICROSOFT` |
| **Observation Ledger** | Append-only store of raw provider rows preserving `native_type` and native fields. | None. | `REF-OMEGALOG`, `REF-OCSF` |
| **Deterministic Relation Verifier** | Verifies observation citations, field role constraints, temporal order, and blocks server/client conflation. | None (Strict deterministic rule engine). | `REF-HUNTERAGENT`, `REF-FOR572` |
| **Evidence / Provenance Graph** | Maintains verified `RelationProof`s and projects minimal `EvidenceSubgraph`s for specific claims. | None. | `REF-SLEUTH`, `REF-AIQL` |
| **LLM Grounded Explainer** | Generates analyst explanations and synthesizes lookup answers. | Receives **only** the verified `EvidenceSubgraph` (never raw ledger). Output is advisory and citation-checked. | `REF-RAG-SEC`, `REF-EXCYTIN` |
| **Controller & Stopping Engine** | Enforces budgets (queries, turns, tokens) and terminal stopping taxonomy. | None (Deterministic finite state controller). | `REF-ECTH`, `REF-TAHITI` |

---

## 3. Input and Output Contracts [Tags: REF-MITRE-HUNT, REF-EXCYTIN, REF-FOR578]

```python
HuntRequest = {
    "id": str,
    "kind": "HYPOTHESIS" | "TTP" | "IOC" | "CVE" | "CTI_REPORT" |
            "NL_QUESTION" | "SCHEDULED",
    "content": str,
    "entities": list[EntityRef],       # explicit targets (if provided)
    "time_policy": TimePolicy | None,
    "provider_hints": list[str],
}
```

The request may consist solely of natural language `content`. Entities provided in the
request are treated as unverified subject seeds; they do not bypass the identity
verification graph.

```python
FinalHuntAccount = {
    "request_id": str,
    "objective": HuntObjective,
    "case": InvestigationCase,
    "provenance_graph": InvestigationGraph,
    "evidence_subgraph": EvidenceSubgraph,
    "provenance_chain": list[RelationProof],
    "queries": list[dict],
    "stopping_decision": StoppingDecision,
    "answer": dict,                    # typed answer contract (e.g. domain, IP)
    "unresolved_unknowns": list[InvestigationUnknown],
    "coverage_bound": CoverageBound,
    "llm_usage": dict,                 # calls, tokens, latency, USD cost
}
```

---

## 4. Investigation Case Graph & Epistemic Invariants [Tags: REF-SLEUTH, REF-HOLMES, REF-FOR508, REF-FOR572]

### 4.1 Epistemic Graph Primitives
- **GraphNode**: Represents entities typed by `NodeType` (`PERSON`, `ACCOUNT`, `ENDPOINT`, `IP`, `DOMAIN`, `PROCESS`, `FILE`).
- **GraphEdge**: Directed relation between nodes typed by `RelationType` (`OWNS`, `LOGGED_ON_TO`, `ASSIGNED_IP`, `ORIGINATED_FROM`, `REQUESTED`, `RESOLVED_TO`, `EXECUTED`).
  - Requires explicit `field_roles` mappings.
  - Requires acceptable provider logical operations.
  - Tracks status: `UNPROVEN` → `VERIFIED` or `REFUTED`.
- **InvestigationUnknown**: Explicit gap in the causal chain (e.g. `endpoint_for_person(Amber)`).
- **RelationProof**: Immutable proof record citing ledger `observation_id`s, timestamp, and field matches.

### 4.2 Strict Field Role Typing [Tags: REF-FOR572, REF-OMEGALOG]
To prevent server-client conflation and spurious attribution, fields carry strict roles:
- `client_ip` ≠ `server_ip` (and `source_ip` ≠ `destination_ip`)
- `endpoint_host` ≠ `server_host` ≠ `sensor_host`
- `account_name` ≠ `display_name` / `person_name`

**Invariant**: A pivot or relation can NEVER be minted merely because a row contains a
generic `host` or `destination_ip` field.

### 4.3 Dependency-First, Evidence-Driven Paths [Tags: REF-FOR508, REF-FOR572]
When an investigation targets a human actor (`person`), identity resolution is a
prerequisite, but it is not a universal suffix. The compiler derives downstream
edges from the evidence requirements:

```text
Web/DNS objective:   Person -> Account -> Endpoint -> Client IP -> Web/DNS -> Domain
Artifact objective:  Person -> Account -> Endpoint -> Process/File -> Answer
Email objective:     Person -> Account -> Email -> Message -> Recipient/Role
```

These are examples of typed paths, not hard-coded scenarios. An artifact hunt
must not manufacture an IP/web edge, and a web hunt must not manufacture a
process/file edge. Global web/DNS sweeps remain forbidden while the required
identity prefix is unproven. Web servers (`jabbah`, `we1149srv`, IIS) are
permanently prohibited from being bound as user endpoints.

---

## 5. Provider-Neutral Coverage Coordinate (Cell) [Tags: REF-OCSF, REF-OTEL, REF-TAHITI]

```text
Cell = (ProviderScope, entity | ANY, time_bucket)
```

In v5.0, `Cell` is strictly an execution and coverage accounting coordinate:
1. It records which provider partitions, target entities, and temporal windows have been queried.
2. It tracks pagination cursors, row bounds, and scope completeness.
3. It has **no** `event_family`, `event_code`, or semantic intent axis.
4. **It is NOT the reasoning unit of the agent.** The agent reasons over the `InvestigationCaseGraph`.

### 5.1 Triple Coverage Accounting
To avoid false impressions of exhaustive telemetry sweeps while verifying targeted investigations, v5.0 decouples coverage into three independent orthogonal metrics:
- **Causal Path Coverage**: $$\frac{\text{verified\_causal\_edges}}{\text{total\_required\_causal\_edges}} \times 100\%$$
  Measures completeness of the proven forensic relation chain (100% when the causal path is fully established).
- **Wildcard Scope Coverage**: $$\frac{\text{explored\_wildcard\_cells}}{\text{total\_wildcard\_cells}} \times 100\%$$
  Measures broad telemetry population sweeps across entire scopes (remains 0% during targeted entity hunts, preventing false claims of total environmental scanning).
- **Instance Cell Coverage**: $$\frac{\text{explored\_instance\_cells}}{\text{total\_instance\_cells}} \times 100\%$$
  Measures completeness of queries executed against concrete, resolved entity coordinates.

---

## 6. Capability Binding & Logical Operations [Tags: REF-AIQL, REF-MITRE-ANALYTICS, REF-MICROSOFT]

Instead of mapping requirements directly to raw SPL or broad sweeps, providers declare
support for typed, relation-oriented **Logical Provider Operations**:

```text
resolve_person_to_account(person_name) → account_name
resolve_account_to_endpoint(account_name, time_window) → endpoint_host
resolve_endpoint_to_client_ip(endpoint_host, time_window) → client_ip
find_web_activity_from_client_ip(client_ip, time_window, predicates) → web_requests
find_dns_activity_from_client_ip(client_ip, time_window, predicates) → dns_queries
find_process_from_endpoint(endpoint_host, time_window, predicates) → process_events
find_file_change_from_process(endpoint_host, process_id, time_window) → file_events
```

Each provider adapter (Splunk, CDB, EDR, IDS) independently maps these operations
to its native indexes, sourcetypes, fields, and query syntax.

---

## 7. Deterministic Relation Verifier & Adjudication [Tags: REF-HUNTERAGENT, REF-SLEUTH, REF-PROVSEEK]

The `Deterministic Relation Verifier` serves as the sole epistemic gatekeeper:
1. **Citation Audit**: Every asserted edge must cite valid, existing `observation_id`s from the ledger.
2. **Field-Specific Matching**: Matches must satisfy field roles (e.g. `user` in `Account_Name`, `host` in `ComputerName`).
3. **Temporal Ordering**: Cause must precede effect in multi-hop chains.
4. **Server Isolation**: Rejects assertions assigning server hostnames to client roles.
5. **Truthful Promotion**: Only when all predicate checks pass is an edge promoted to `VERIFIED` and recorded in a `RelationProof`.

### 7.1 Fine-Grained Hypothesis Adjudication
Answering a specific inquiry or proving a causal chain does not automatically validate all competing attack hypotheses:
- Proving user web navigation (e.g., Amber Turing visited `www.berkbeer.com`) promotes the browsing hypothesis to `SUPPORTED`.
- Competing hypotheses alleging credential theft, unauthorized data access, or lateral movement without specific corroborating evidence cards remain `UNKNOWN` or `WEAKENED`.
- The controller audits each hypothesis against its specific required edges and required evidence types before updating status.

### 7.2 Two-Layer Evidence & Evaluator LLM Scoping
To decouple raw audit fidelity from advisory reasoning cost and context size:
- **Audit Layer**: The `ObservationLedger` retains complete raw events and fields for tamper-proof forensics.
- **Reasoning Layer**: The LLM Evaluator receives strictly the minimal `EvidenceSubgraph` (max 20 cards), with noisy third-party telemetry (CDN, trackers, ads) filtered out.
- **Parse Status Tracking**: Evaluator parsing is tracked with explicit `ParseStatus` (`SUCCESS`, `INVALID_JSON`, `SCHEMA_REJECTED`, `TIMEOUT`, `PROVIDER_ERROR`). Markdown code fences (` ```json `) are robustly stripped.
- **Graceful Degradation**: If LLM explanation is unavailable or invalid, deterministic graph answers (e.g., target node values) are rendered unconditionally, reporting `LLM Explanation: Unavailable (status: ...)`.

---

## 8. Resource Policy & Budgets [Tags: REF-CASCADE, REF-CDB]

The controller strictly enforces bounded resource consumption across every hunt:
```text
max_turns = 15
max_queries = 60
max_llm_calls = 3
max_scan_cells = 100
max_runtime_seconds = 300
max_total_tokens = 12,000
```

- Free-text semantic compilation: at most 1 call.
- Grounded explanation: at most 1 call over `EvidenceSubgraph`.
- Query planning: zero LLM calls when provider capability templates exist.
- LLM API failures/timeouts trigger immediate abort (`LLMTimeoutError`); fabrication of reports or conclusions is strictly blocked.

---

## 9. Action Selection & Stopping Rules [Tags: REF-ECTH, REF-PROVSEEK, REF-TAHITI]

### 9.1 Action Precedence
The Action Planner selects actions via dependency graph analysis:
```text
RESOLVE_ENTITY → TEST → CORRELATE → EXPAND → DISCOVER → PIVOT → REFINE → STOP
```
- `RESOLVE_ENTITY`: Proves an unresolved mandatory edge for a known node (e.g. Person → Endpoint).
- `TEST`: Executes an operation to verify an edge whose source entity is confirmed.
- `CORRELATE`: Evaluates multi-source convergence on an existing subgraph.
- `DISCOVER`: Restricted strictly to population discovery or baseline anomaly hunts. **Never** used as a blind fallback for entity hunting.
- `STOP`: Terminal evaluation against acceptance criteria.

### 9.2 Terminal Stopping Taxonomy
The engine emits one of eight explicit stopping decisions:
1. `STOP_RESOLVED`: All mandatory relation paths proven; acceptance criteria satisfied.
2. `STOP_REFUTED`: Competing hypothesis definitively proven or falsification condition met.
3. `STOP_INCONCLUSIVE_IDENTITY_UNRESOLVED`: Subject identity could not be linked to an endpoint/IP.
4. `STOP_INCONCLUSIVE_RELATION_UNPROVEN`: Causal path broken at an intermediate edge.
5. `STOP_INCONCLUSIVE_COVERAGE_GAP`: Telemetry missing, unobservable, or query incomplete.
6. `STOP_UNSUPPORTED_CAPABILITY`: Provider catalog lacks required logical operations.
7. `STOP_UNREACHABLE`: Telemetry scope offline or credentials invalid.
8. `STOP_BUDGET_EXHAUSTED`: Turn, query, or token limits reached before path resolution.

**Strict Epistemic Rule**: `NOT_FOUND` or `BENIGN` is NEVER asserted when the stopping
decision is `STOP_INCONCLUSIVE_*`, `STOP_UNSUPPORTED_*`, or `STOP_BUDGET_EXHAUSTED`.

---

## 10. Research Grounding & Intellectual Boundaries [Tags: REF-SLEUTH, REF-HUNTERAGENT, REF-USENIX-TH]

The v5.0 architecture synthesizes graph provenance (`REF-SLEUTH`, `REF-AIQL`), dual-layer
verifiers (`REF-HUNTERAGENT`, `REF-PROVSEEK`), and professional DFIR methodology (`REF-FOR508`, `REF-FOR572`).
It claims novel thesis compositions in relation-first capability binding, strict field role isolation,
and coverage-decoupled case graph reasoning. Full source citations and evidence levels are
maintained in `03_LITERATURE-AND-TRACEABILITY.md`.
