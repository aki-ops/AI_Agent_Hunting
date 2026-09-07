# 04 — IMPLEMENTATION CHECKLIST (v5.0)

An item is marked complete `[x]` only when an automated test, replay script,
or captured execution artifact directly verifies it. `01` is the architecture
contract, `02` is the executable method, and `03` is the literature traceability record.

---

## Active Checklist: Migration v5.0 (Investigation Case Graph)

### Phase 0 — Re-baseline & Invariants [Tags: REF-SLEUTH, REF-OCSF, REF-TAHITI]
- [x] Freeze v4 test baseline and maintain historical auditability.
- [x] Establish strict migration boundary: demote `Cell` to coverage coordinate only; promote `InvestigationCaseGraph` to agent reasoning unit.
- [x] Enforce field role separation invariant: `client_ip` ≠ `server_ip`, `sensor_host` ≠ `endpoint_host`.
- [x] Enforce identity-first invariant: `Person → Account → Endpoint → Client IP` before network traffic testing.

### Phase 1 — Documentation v5.0 Source of Truth [Tags: REF-USENIX-TH, REF-FOR578]
- [x] Rewrite `01_FINAL-ARCHITECTURE.md` to v5.0 with embedded literature tags.
- [x] Rewrite `02_METHOD-AND-IMPLEMENTATION-PLAN.md` to v5.0 with executable edge-dependency lifecycle.
- [x] Expand `03_LITERATURE-AND-TRACEABILITY.md` with full 26-source register, tiers, and traceability matrix.
- [x] Reset `04-IMPLEMENTATION-CHECKLIST.md` to active v5 gates; archive v4 legacy evidence.
- [x] Update `docs/01-REAL-PROVIDER-SPECIFICATIONS.md` with field roles and relation-oriented provider operations.
- [x] Update `README.md`, `context.md`, `claude.md` to reflect relation-first epistemic architecture.

### Phase 2 — Data Contracts (`InvestigationCase`, `InvestigationGraph`, `FieldRole`) [Tags: REF-SLEUTH, REF-AIQL, REF-FOR572]
- [x] Implement `FieldRole` enum with explicit client, server, endpoint, sensor, and identity roles.
- [x] Implement `NodeType` and `RelationType` enums.
- [x] Implement `GraphNode`, `GraphEdge`, `InvestigationUnknown`, and `RelationProof` contracts.
- [x] Implement `EvidenceSubgraph` contract for bounded LLM context extraction.
- [x] Implement `InvestigationCase` and `InvestigationGraph` containers with topological query methods.
- [x] Extend `StoppingDecision` enum with v5 terminal taxonomy (`STOP_INCONCLUSIVE_IDENTITY_UNRESOLVED`, `STOP_INCONCLUSIVE_RELATION_UNPROVEN`, `STOP_INCONCLUSIVE_COVERAGE_GAP`, `STOP_UNSUPPORTED_CAPABILITY`).

#### Phase 3 — Semantic Case Compiler & Behavior Templates [Tags: REF-HUNTERAGENT, REF-THREATRAPTOR, REF-MITRE-DC]
- [x] Implement free-text LLM compiler schema emitting `InvestigationCase` (entities, claims, unknowns, relation paths). (`src/hunting/compiler/compiler.py`)
- [x] Implement deterministic behavior templates for known CVE/TTP/IOC inputs (zero LLM calls). (`_build_cve_case`, `_build_ttp_case`)
- [x] Implement compiler output validator: strictly prohibit raw SPL, vendor terms, or fabricated bindings. (`validate_compiler_output_integrity`)
- [x] Enforce mandatory `endpoint` unknown insertion when subject is `Person` without proven host.

### Phase 4 — Capability Binder & Logical Provider Operations [Tags: REF-AIQL, REF-MITRE-ANALYTICS, REF-MICROSOFT]
- [x] Implement `CapabilityBinder` mapping relation goals to logical provider operations (`resolve_person_to_account`, `resolve_account_to_endpoint`, etc.).
- [x] Update Splunk adapter to register relation-first operations and validate field roles against sourcetypes.
- [x] Update CDB adapter to register relation-first operations for replay testing.
- [x] Ensure provider query compiler produces parameterized, bounded native queries.

### Phase 5 — Relation-Aware Action Planner & Dependency Graph [Tags: REF-PROVSEEK, REF-HOLMES, REF-FOR508]
- [x] Implement dependency-driven edge selection: pick unproven mandatory edge whose source node is `KNOWN`.
- [x] Enforce Amber invariant in planner: select `RESOLVE_ENTITY` until identity prefix is proven; block global web sweeps.
- [x] Restrict `DISCOVER` strictly to population discovery and baseline anomaly hunts.
- [x] Implement controller state transitions and budget enforcement (`STOP_INCONCLUSIVE_RELATION_UNPROVEN`).

### Phase 6 — Deterministic Relation Verifier & Provenance Graph [Tags: REF-HUNTERAGENT, REF-FOR508, REF-FOR572]
- [x] Implement `RelationVerifier` auditing observation citations.
- [x] Enforce strict field-specific matching (user fields for accounts, host fields for endpoints).
- [x] Enforce web server isolation (reject `jabbah`, `we1149srv`, IIS as client workstations).
- [x] Enforce IP role isolation (reject `destination_ip` or `server_ip` as client IP).
- [x] Mint immutable `RelationProof` and promote target nodes to `KNOWN`.

### Phase 7 — Grounded Reporting & Subgraph Extraction [Tags: REF-RAG-SEC, REF-EXCYTIN, REF-TAHITI]
- [x] Extract minimal `EvidenceSubgraph` corresponding to verified causal chain.
- [x] Restrict narrative LLM explainer strictly to `EvidenceSubgraph`.
- [x] Render Section 2 with Proven Relation Chain and Unresolved Mandatory Unknowns.
- [x] Enforce truthful inconclusive outcomes: never render `NOT_FOUND` when causal path is broken.

### Phase 8 — Verification Suites & Benchmarks [Tags: REF-CDB, REF-EXCYTIN]
- [x] Unit tests for case graph contracts (`test_v5_case_graph.py`).
- [x] Unit tests for relation verifier (`test_v5_relation_verifier.py`).
- [x] Unit tests for capability binder (`test_v5_capability_binder.py`).
- [x] Unit tests for semantic case compiler (`test_v5_case_compiler.py`).
- [x] Unit tests for relation-aware action planner (`test_v5_action_planner.py`).
- [x] Unit tests for provider adapters (`test_v5_adapters.py`).
- [x] Amber Turing vertical slice test: proves full causal chain without broad web sweeps or server host confusion (`test_v5_amber_vertical_slice.py`).
- [x] Regression test suite passes 100% with zero regressions (286 passed).

### Phase 9 — Production Refinements & Rigor Gated Verification [Tags: REF-TAHITI, REF-PEAK, REF-RAG-SEC, REF-ECTH]
- [x] Fine-Grained Hypothesis Adjudication: Each hypothesis audited against required edge IDs and corroborating evidence cards; unproven attack mechanisms remain `UNKNOWN` rather than blanket `SUPPORTED` (verified on Amber Turing hunt).
- [x] Decoupled Triple Coverage Accounting: Independent computation of Causal Path Coverage (100.0%), Wildcard Scope Coverage (0.0%), and Instance Cell Coverage (100.0%) on v5 execution.
- [x] Evaluator LLM Scoping & Parse Status: LLM analysis bounded strictly to verified `EvidenceSubgraph` (max 20 cards), noise domain exclusions (CDNs, ads, trackers), markdown code fence stripping, and explicit `ParseStatus` tracking.
- [x] Two-Layer Evidence Separation: Full audit fidelity preserved in `ObservationLedger` without bloating reasoning context or token cost.
- [x] Complete BOTSv1 Decoupling: Zero default fallbacks to `botsv1` across production `src/` codebase; native partition dynamically configured to `botsv2`.
- [x] Zero Lint Errors: Strict `ruff check src tests` compliance (0 errors).
- [x] Full Regression & Live Verification: 286 unit/integration tests passing; live Splunk BOTSv2 Amber Turing hunt resolves deterministic answer `www.berkbeer.com` with `STOP_RESOLVED`.

---

## Legacy Baseline: v4 Prototype Verification Evidence

The items below record verified capabilities of the v4.1 prototype before the v5 migration.
They are preserved as a historical engineering baseline and do not substitute for v5 gates.

- [x] `HuntRequest` accepts hypothesis/TTP/IOC/CVE/CTI/NL question without alert.
- [x] `Cell(provider_scope, entity|ANY, time_bucket)` has no `event_family`.
- [x] `ProviderScope` preserves native partition, retention and gaps.
- [x] `Observation` preserves native type and nullable semantic type.
- [x] `QueryResult.complete` is explicit; row count never implies EOF.
- [x] Version CVE/TTP/IOC/behavior records with source citations.
- [x] Free text without API fails safely with `STOP_INSUFFICIENT`.
- [x] No natural-language keyword fallback or statement/ID keyword attribution remains.
- [x] Splunk REST/oneshot execution and L+1 completeness tested live on BOTSv2.
- [x] Raw observations are append-only and auditable in `artifacts/<hunt_id>/`.
- [x] Repeated observations form `EvidenceCard`s with representative IDs/counts.
- [x] Query, turn, runtime, scan and LLM budgets are strictly enforced.
- [x] LLM API timeout fail-fast and anti-fabrication enforcement verified.
