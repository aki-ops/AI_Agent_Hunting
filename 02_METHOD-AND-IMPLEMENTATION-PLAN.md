# 02 — METHOD AND IMPLEMENTATION PLAN (v5.0)

`01_FINAL-ARCHITECTURE.md` defines WHAT the system is. This file defines the
executable HOW. `03` contains literature sources and traceability; `04` records
the active implementation checklist and test gates.

---

## 1. End-to-End Execution Flow [Tags: REF-ECTH, REF-TAHITI, REF-PEAK, REF-SLEUTH]

```text
HuntRequest (NL Question, CTI, CVE, TTP, IOC)
    │
    ▼ Step 1: Compilation
SemanticCaseCompiler
    │  ├─ Free-text input: Bounded LLM API generates InvestigationCase schema
    │  └─ CVE/TTP/IOC input: Deterministic knowledge templates generate Behavior Graph
    ▼
InvestigationCase (Nodes, Directed Edges, Mandatory Unknowns, Acceptance Criteria)
    │
    ▼ Step 2: Dependency Analysis & Action Selection [REF-PROVSEEK, REF-HOLMES]
Relation-Aware Action Planner
    │  ├─ Scans unproven mandatory edges whose source node is KNOWN
    │  └─ Prioritizes entity/identity resolution over traffic testing
    ▼
ActionCandidate (e.g. resolve_person_to_account, resolve_account_to_endpoint)
    │
    ▼ Step 3: Capability Binding [REF-AIQL, REF-MITRE-ANALYTICS]
CapabilityBinder
    │  ├─ Matches logical operation to provider capability catalog
    │  └─ Validates observable fields, scope partitions, and permissions
    ▼
LogicalQueryPlan → NativeQueryPlan (SPL, SQL, API request)
    │
    ▼ Step 4: Parameterized Execution [REF-OCSF, REF-MICROSOFT]
Provider Adapter (SplunkLiveAdapter / CdbAdapter)
    │  ├─ Executes search with L+1 limit for completeness detection
    │  └─ Records QueryResult envelope (status, rows, cursor, complete)
    ▼
ObservationLedger (Append-only storage; preserves native_type and raw fields) [REF-OMEGALOG]
    │
    ▼ Step 5: Deterministic Relation Verification [REF-HUNTERAGENT, REF-FOR508, REF-FOR572]
RelationVerifier
    │  ├─ Audits observation citations
    │  ├─ Enforces strict field roles (client_ip ≠ server_ip; rejects web servers as endpoints)
    │  └─ Mints verified RelationProof; promotes target node to KNOWN
    ▼
Updated InvestigationGraph (Graph state transitions; cycle repeats if edges remain)
    │
    ▼ Step 6: Evidence Subgraph Extraction & Narrative Reporting [REF-RAG-SEC, REF-EXCYTIN]
Grounded Report Generator
    │  ├─ Extracts minimal EvidenceSubgraph for proven causal path
    │  ├─ Generates grounded LLM explanation bounded strictly to subgraph
    │  └─ Emits FinalHuntAccount and Section 2 Provenance Chain
    ▼
StoppingDecision & Detection/Knowledge Feedback [REF-TAHITI]
```

---

## 2. Compilation and Graph Synthesis [Tags: REF-HUNTERAGENT, REF-THREATRAPTOR, REF-MITRE-DC]

### 2.1 Deterministic Paths
Known CVE records use versioned knowledge templates separating exposure, preconditions,
exploitation indicators, post-exploitation, and coverage gaps. Known TTPs and IOCs
compile directly into typed behavior graphs. These paths do not call an LLM.

### 2.2 Free-Text Semantic Path
For unstructured `HYPOTHESIS` and `NL_QUESTION` requests:
1. The request text is dispatched to the semantic compiler with a strict JSON schema.
2. The schema enforces:
   - `known_entities`: Seed nodes extracted from input (e.g. `Person: "Amber Turing"`).
   - `claims`: Core behaviors asserted in the request.
   - `mandatory_unknowns`: Required missing nodes (e.g. endpoint host, client IP).
   - `required_relation_paths`: Sequence of typed edges required to prove the claim.
   - `acceptance_criteria`: Logical criteria required to resolve or refute the hunt.
3. `InvestigationValidator` deterministically audits the compiled model:
   - Blocks raw SPL, index names, or provider-specific keywords.
   - Mandates that any `Person` subject without a pre-linked workstation produces a mandatory `unknown` for `endpoint` and sets state to `READY_FOR_DISCOVERY`.
   - If the API times out, fails, or violates schema, the engine raises `LLMTimeoutError` or stops with `STOP_INSUFFICIENT`; fabrication is strictly barred.

---

## 3. Case Graph Dependency Analysis & Edge Selection [Tags: REF-SLEUTH, REF-HOLMES, REF-PROVSEEK]

The action planner evaluates the `InvestigationGraph` using backward and forward dependency chaining:

1. **Find Actionable Edges**: Identify directed edges where:
   - `status == UNPROVEN`
   - `source_node.status == KNOWN`
   - Edge is marked `MANDATORY`
2. **The Amber Turing Invariant** (`REF-FOR508`, `REF-FOR572`):
   - Path: $	ext{Person(Amber)} ightarrow 	ext{Account} ightarrow 	ext{Endpoint} ightarrow 	ext{Client IP} ightarrow 	ext{Web Activity} ightarrow 	ext{Domain}$.
   - While $	ext{Person} ightarrow 	ext{Account}$ or $	ext{Account} ightarrow 	ext{Endpoint}$ is unproven:
     The planner **only** permits `RESOLVE_ENTITY` actions targeting identity.
   - Global or wildcard web queries (`sourcetype="stream:http"`, `sourcetype="iis"`) are **prohibited**.

---

## 4. Capability Binding & Logical Operations [Tags: REF-AIQL, REF-MITRE-ANALYTICS, REF-MICROSOFT]

Logical operations express provider-neutral forensic intents:
- `resolve_person_to_account`: Queries directory or authentication services.
- `resolve_account_to_endpoint`: Queries endpoint logon events (e.g. Windows Event ID 4624).
- `resolve_endpoint_to_client_ip`: Queries DHCP, network interface, or local IP bindings.
- `find_web_activity_from_client_ip`: Queries web proxy or HTTP stream logs for requests originating from the client IP.
- `find_dns_activity_from_client_ip`: Queries DNS resolver logs for queries originating from the client IP.
- `find_process_from_endpoint`: Queries process creation telemetry (Sysmon Event ID 1, EDR).
- `find_file_change_from_process`: Queries file creation/modification telemetry.

The `CapabilityBinder` matches an actionable edge to the provider's registered operations based on
target entity type, observable field roles, and required time window.

---

## 5. Execution, Completeness & Negative Controls [Tags: REF-OCSF, REF-MICROSOFT, REF-TAHITI]

Providers return a `QueryResult` envelope with native records, execution status, and explicit `complete: bool`.

### 5.1 The L+1 Completeness Rule
The adapter queries for $L + 1$ records where $L$ is the configured row limit (e.g. 100).
- If $> L$ rows are returned: Adapter returns $L$ rows, sets `complete = False`, and provides a continuation cursor.
- If $\le L$ rows are returned: Adapter sets `complete = True`.
- **Epistemic Rule**: A partial query (`complete = False`) can **never** license negative evidence or refute a hypothesis.

### 5.2 Negative Controls
To conclude absence of activity, three deterministic controls must pass:
1. `ScopeHealthControl`: Provider and scope are online and reachable.
2. `AnyRecordInScope`: Baseline telemetry confirms the scope was actively logging during the target window.
3. `PredicateObservabilityControl`: The queried field exists and is observable in the provider catalog.

### 5.3 Cell Lifecycle & Triple Coverage Accounting
Each query execution updates or instantiates a concrete `Cell(scope, entity, time_bucket)`:
- `complete == True` $\rightarrow$ `CellState.EXPLORED`.
- `complete == False` $\rightarrow$ `CellState.PARTIAL`.
- Query execution error $\rightarrow$ `CellState.UNQUERYABLE` or `UNREACHABLE`.
- Wildcard scope cells (`entity == ANY`) remain unsearched during targeted instance resolution.

Coverage is computed and reported via three independent dimensions:
1. **Causal Path Coverage**: Verified causal edges / total required causal edges.
2. **Wildcard Scope Coverage**: Explored wildcard cells / total wildcard cells (remains 0.0% during targeted resolution).
3. **Instance Cell Coverage**: Explored instance cells / total instance cells (100.0% when all targeted entity coordinates are completed).

---

## 6. Observation Ledger & Fact Extraction [Tags: REF-OMEGALOG, REF-OCSF]

Every raw provider row is stored immutably in the `ObservationLedger`:
- Assigns unique `observation_id` (e.g. `obs-splunk-104`).
- Preserves native provider fields and original `native_type`.
- Extracts normalized facts with explicit field roles:
  - `client_ip`: Originating client IP address.
  - `server_ip`: Target server IP address.
  - `endpoint_host`: Host machine executing the action or hosting the session.
  - `account_name`: Authenticated username.
  - `uri_stem`, `domain_name`, `process_name`, `command_line`.

---

## 7. Deterministic Relation Verification & Provenance Graph [Tags: REF-HUNTERAGENT, REF-SLEUTH, REF-FOR572]

The `RelationVerifier` audits candidate edges against ledger observations before state transitions occur:

1. **Citation Integrity**: Each asserted edge must cite valid `observation_id`s in the ledger.
2. **Field Role Isolation**:
   - Matches for `person` or `account` must occur strictly in user identity fields (`user`, `Account_Name`).
   - Matches for `endpoint` must occur in computer name fields (`host`, `ComputerName`).
   - Rejects web servers: Server hostnames (`jabbah`, `we1149srv`, IIS instances) are permanently prohibited from being bound as user endpoints.
   - Rejects destination IPs: `destination_ip` and `server_ip` cannot satisfy a `client_ip` requirement.
3. **Promotion**: Upon successful verification, the verifier mints an immutable `RelationProof`, marks the edge as `VERIFIED`, and transitions the target node to `KNOWN`.

---

## 8. Action Controller & Epistemic State Loop [Tags: REF-PROVSEEK, REF-CASCADE, REF-CDB]

The controller drives the iterative investigation loop under strict budget limits:
```text
max_turns = 15
max_queries = 60
max_llm_calls = 3
max_scan_cells = 100
max_runtime_seconds = 300
```

Action precedence:
$$\text{RESOLVE\_ENTITY} \rightarrow \text{TEST} \rightarrow \text{CORRELATE} \rightarrow \text{EXPAND} \rightarrow \text{DISCOVER} \rightarrow \text{PIVOT} \rightarrow \text{REFINE} \rightarrow \text{STOP}$$

If the controller runs out of actions or exhausts budget:
- If mandatory identity edge is unproven $\rightarrow$ `STOP_INCONCLUSIVE_IDENTITY_UNRESOLVED`.
- If intermediate causal edge is unproven $\rightarrow$ `STOP_INCONCLUSIVE_RELATION_UNPROVEN`.
- If coverage was incomplete or scope missing $\rightarrow$ `STOP_INCONCLUSIVE_COVERAGE_GAP`.
- If all acceptance criteria satisfied $\rightarrow$ `STOP_RESOLVED`.

---

## 9. Grounded Reporting & Feedback [Tags: REF-RAG-SEC, REF-EXCYTIN, REF-TAHITI]

The analyst-facing report (`report.md`) is structured into five concise sections:
1. **Hypothesis / Question**: Seed request, subject, requested object, triple coverage metrics (Causal Path, Wildcard Scope, Instance Cell), and deterministic verdict.
2. **Hypothesis Analysis & Provenance Graph**:
   - Competing hypotheses adjudicated individually (supported vs unknown/weakened).
   - Proven Relation Chain: Causal path $\text{Person} \rightarrow \text{Account} \rightarrow \text{Endpoint} \rightarrow \text{Client IP} \rightarrow \text{Request} \rightarrow \text{Domain}$ with citations.
   - Unresolved Mandatory Unknowns: Explicit listing of unproven variables if inconclusive.
3. **Evidence and Explanation**:
   - Two-Layer Separation: Raw forensic records preserved in `ObservationLedger` (audit layer); LLM evaluator receives bounded `EvidenceSubgraph` (max 20 cards) with noise domains (CDNs, ads, telemetry trackers) stripped.
   - Robust Parser & Graceful Degradation: Markdown code fences stripped, `{...}` JSON substring extracted, with explicit `ParseStatus` tracking (`SUCCESS`, `INVALID_JSON`, `SCHEMA_REJECTED`, `TIMEOUT`, `PROVIDER_ERROR`).
   - If LLM narrative is unavailable, deterministic graph resolution (`target_node.value`) is reported directly.
4. **Queries Used**: Parameterized queries, semantic reasons, and completeness status.
5. **Resource & Cost Accounting**: Calls, tokens, latency, and estimated USD cost.

---

## 10. Verification Plan & Benchmark Strategy [Tags: REF-CDB, REF-EXCYTIN]

1. **Unit Test Suite**: Known-answer tests for contracts, verifier, capability binder, and action planner.
2. **Amber Vertical Slice**: Proves the complete causal path on Splunk BOTSv2 without global web traffic sweeps or server host confusion.
3. **Multi-Dataset Replay**:
   - Splunk BOTSv2 (Enterprise SIEM & network stream logs; live-validated against Amber Turing scenario).
   - OTRF Security-Datasets (Sysmon, Windows Security, Active Directory).
   - DARPA Transparent Computing / Provenance datasets (System-level causal graphs).
