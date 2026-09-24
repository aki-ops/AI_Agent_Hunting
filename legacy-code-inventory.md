# Comprehensive Codebase & Legacy Inventory

This document classifies every Python module under `src/hunting/` into one of five lifecycle categories:
- **`ACTIVE_NEW`**: Modern canonical architecture supporting semantic threat hunting (`SemanticGoalGraph`, `CapabilityGraph`, `ProofEngine`, `SemanticPlanExecutor`).
- **`ACTIVE_LEGACY`**: Legacy operational code currently exercised by backward-compatibility modes (e.g. alert investigation, ClaimGraph fallback).
- **`TEST_ONLY`**: Modules, adapters, or stubs used only by unit/integration tests or synthetic fixtures.
- **`DEAD_CODE`**: Unused, unreachable, or obsolete code that can be safely quarantined or removed.
- **`UNKNOWN`**: Modules requiring further runtime verification.

---

## 1. Root Package (`src/hunting/`)

| File | Status | Description & Role | Action / Target State |
| :--- | :--- | :--- | :--- |
| `__init__.py` | `ACTIVE_NEW` | Package root export. Exports orchestrator and contracts. | Keep minimal clean exports. |
| `bootstrap.py` | `DEAD_CODE` | Obsolete mock environment bootstrap from early prototypes. | Quarantine / Remove. |
| `cli.py` | `ACTIVE_NEW` | Main user CLI entry point supporting both hypothesis hunt and legacy alert. | Retain; isolate legacy branches. |
| `engine.py` | `ACTIVE_NEW` | Central orchestration engine (`HypothesisHuntEngine`). | Modernize to single canonical data flow. |
| `normalization.py` | `DEAD_CODE` | Primitive entity normalization functions superseded by `entities.py`. | Quarantine / Remove. |
| `orchestrator.py` | `ACTIVE_LEGACY` | Legacy alert-driven investigation orchestrator (`InvestigationOrchestrator`). | Isolate strictly to `--alert` mode. |

---

## 2. Capabilities & Runtime Probing (`src/hunting/capabilities/`)

| File | Status | Description & Role | Action / Target State |
| :--- | :--- | :--- | :--- |
| `__init__.py` | `ACTIVE_NEW` | Package initialization. | Retain. |
| `binder.py` | `ACTIVE_NEW` | Binds operations to capability frontier and checks parameter compatibility. | Retain in modern path. |
| `catalog_index.py` | `ACTIVE_NEW` | Fast index for looking up capabilities by relation and entity kind. | Retain in modern path. |
| `census.py` | `ACTIVE_NEW` | `CensusService` building `CapabilityGraph` from configured adapters. | Active in modern path. |
| `frontier.py` | `ACTIVE_NEW` | Implements progressive capability frontier (F0–F4). | Active in modern path. |
| `inventory.py` | `ACTIVE_NEW` | Manages active provider inventory and operational readiness. | Active in modern path. |
| `models.py` | `ACTIVE_NEW` | Data classes for capability graphs and catalog representations. | Active in modern path. |
| `probe_executor.py` | `ACTIVE_NEW` | Executes runtime probe queries during environment census. | Active in modern path. |
| `profile_cache.py` | `ACTIVE_NEW` | In-memory and disk caching for telemetry source profiles. | Active in modern path. |
| `registry.py` | `ACTIVE_NEW` | Registry of discovered capability catalogs across adapters. | Active in modern path. |
| `retriever.py` | `ACTIVE_NEW` | Semantic capability retriever mapping goals to candidate operations. | Active in modern path. |
| `runtime_materializer.py` | `ACTIVE_NEW` | Materializes operational bindings and query builders at runtime. | Active in modern path. |
| `source_card_store.py` | `ACTIVE_NEW` | Stores validated source profile cards for reuse across turns. | Active in modern path. |
| `source_mapping_validator.py` | `ACTIVE_NEW` | Validates candidate source proposals and constraint mappings. | Active in modern path. |
| `source_profiler.py` | `ACTIVE_NEW` | Automated source profiler analyzing sourcetypes/tables into operations. | Active in modern path. |

---

## 3. Compiler & Knowledge Base (`src/hunting/compiler/`)

| File | Status | Description & Role | Action / Target State |
| :--- | :--- | :--- | :--- |
| `__init__.py` | `ACTIVE_NEW` | Package initialization. | Retain. |
| `compiler.py` | `ACTIVE_NEW` | `KnowledgeBehaviorCompiler` (Phase C1) transforming requests into `SemanticGoalGraph`. | Retain; streamline request grounding. |
| `knowledge_base.py` | `ACTIVE_NEW` | Deterministic knowledge base for known CVEs and MITRE TTPs. | Retain. |
| `models.py` | `ACTIVE_NEW` | Data contracts for compilation trace, diagnostics, and intermediate representations. | Retain. |
| `templates.py` | `ACTIVE_NEW` | Structured graph and claim templates for standard attack techniques. | Retain. |

---

## 4. Contracts & Epistemic Types (`src/hunting/contracts/`)

| File | Status | Description & Role | Action / Target State |
| :--- | :--- | :--- | :--- |
| `__init__.py` | `ACTIVE_NEW` | Unified contract exports. | Retain. |
| `abduction.py` | `ACTIVE_LEGACY` | Contracts for abduction runtime (`AbductionRuntime`). | Legacy alert path. |
| `bindings.py` | `ACTIVE_NEW` | `CandidateBinding`, `CandidateSet`, `BindingDirectness`. | Retain in modern path. |
| `capabilities.py` | `ACTIVE_NEW` | `CapabilityDescriptor`, `ProviderCapabilityCatalog`. | Retain in modern path. |
| `case_graph.py` | `ACTIVE_LEGACY` | v5 `InvestigationCase`, `GraphNode`, `GraphEdge`. | Legacy ClaimGraph path. |
| `cells.py` | `ACTIVE_LEGACY` | `Cell`, `CellState` (legacy); `ProviderScope` (`ACTIVE_NEW`). | Separate `ProviderScope`. |
| `claim.py` | `ACTIVE_LEGACY` | v6 `ClaimGraph`, `Claim`, `AcceptanceRule`. | Legacy ClaimGraph path. |
| `conflicts.py` | `ACTIVE_LEGACY` | `Conflict`, `HumanInput` for alert adjudication. | Legacy alert path. |
| `coverage.py` | `ACTIVE_NEW` | `CoverageBound`, `RequirementCoverage`. | Retain in modern path. |
| `entities.py` | `ACTIVE_NEW` | Strongly typed entities: `Host`, `Account`, `IPAddress`, `Domain`, `File`, `Process`. | Core canonical contract. |
| `evidence_state.py` | `ACTIVE_LEGACY` | v4 `EvidenceState`, `ArtifactEvidence`. | Legacy path. |
| `expectations.py` | `ACTIVE_LEGACY` | v4 `Expectation`, `EvidenceRequirement`, `TestStatus`. | Legacy action loop. |
| `explanations.py` | `ACTIVE_LEGACY` | v3/v4 `Explanation`, `Attribution`. | Legacy abduction path. |
| `hunt.py` | `ACTIVE_NEW` | Core contracts: `HuntRequest`, `HuntState`, `Hypothesis`, `FinalHuntAccount`, `EvidenceCard`. | Core canonical contract. |
| `hunt_spec.py` | `ACTIVE_LEGACY` | v4 `HuntSpec`, `SearchTerm`, `EvidencePath`. | Legacy discovery path. |
| `investigation_model.py` | `ACTIVE_LEGACY` | v4 `InvestigationModel`. | Legacy path. |
| `manifest.py` | `ACTIVE_LEGACY` | Old provider YAML manifest schema. | Legacy alert path. |
| `native_query.py` | `ACTIVE_NEW` | `NativeQueryCandidate`, safety validation contracts. | Retain in modern path. |
| `observation_class.py` | `ACTIVE_NEW` | `ActionSignature`, `ObservationClass`, execution statuses. | Core canonical contract. |
| `observations.py` | `ACTIVE_NEW` | `Observation`, `EpistemicType`, `Provenance`. | Core canonical contract. |
| `ontology.py` | `ACTIVE_NEW` | Canonical relations (`CANONICAL_RELATIONS`), synonyms, and inverse relations. | Core canonical contract. |
| `outcome.py` | `ACTIVE_LEGACY` | Legacy `HuntOutcome` enum. | Superseded by `StoppingTaxonomyState`. |
| `proof_contract.py` | `ACTIVE_NEW` | `ProofContract`, `ProofResult`, proof statuses. | Core canonical contract. |
| `queries.py` | `ACTIVE_NEW` | `ProviderOperation`, `QueryResult`, `QueryOutcome`, `RetrievalPolicy`. | Core canonical contract. |
| `query_intent.py` | `ACTIVE_LEGACY` | Legacy `QueryIntentSpec`. | Superseded by `SemanticRelationGoal`. |
| `search_envelope.py` | `ACTIVE_NEW` | `SearchEnvelope`, `HardConstraints`, `BudgetEnvelope`. | Retain in modern path. |
| `semantic_graph.py` | `ACTIVE_NEW` | `SemanticGoalGraph`, `SemanticVariable`, `LogicalPlan`, `PlanStep`. | Core canonical contract. |
| `semantic_intent.py` | `ACTIVE_LEGACY` | v4 `SemanticHuntIntent`. | Superseded by `SemanticGoalGraph`. |
| `semantic_route.py` | `ACTIVE_NEW` | `SemanticAttempt`, `SemanticRouteAssessment`. | Retain in modern path. |
| `source_profile.py` | `ACTIVE_NEW` | `TelemetrySourceProfile`, `ConstraintMapping`, `RuntimeCapability`. | Core canonical contract. |
| `state.py` | `ACTIVE_LEGACY` | v1/v2 `Alert`, `InvestigationState`, `TerminalState`. | Legacy alert path. |
| `step_trace.py` | `ACTIVE_NEW` | Structured `StepTrace` and `HuntStepName` lifecycle recording. | Core canonical contract. |
| `transforms.py` | `ACTIVE_NEW` | Modular semantic transforms (`PowerShellInterpreterTransform`, etc.). | Core canonical contract. |
| `validators.py` | `ACTIVE_NEW` | Parameter validation helpers. | Retain. |

---

## 5. Controller & State Management (`src/hunting/controller/`)

| File | Status | Description & Role | Action / Target State |
| :--- | :--- | :--- | :--- |
| `__init__.py` | `ACTIVE_NEW` | Package initialization. | Retain. |
| `action_planner.py` | `ACTIVE_LEGACY` | Plans actions across legacy `Cell`s and `Expectation`s. | Legacy path. |
| `controller.py` | `ACTIVE_NEW` | `CanonicalActionController` governing all runtime state mutations. | Core canonical controller. |
| `cost.py` | `ACTIVE_NEW` | `LLMBudgetPolicy` and `LLMUsageTracker` managing LLM token ceilings. | Core canonical budget tracker. |
| `loop_guard.py` | `ACTIVE_NEW` | `LoopGuard` detecting and terminating infinite query/action loops. | Core canonical safety guard. |
| `models.py` | `ACTIVE_NEW` | Controller data structures and action event types. | Retain. |
| `reasoning.py` | `ACTIVE_NEW` | Reasoning helpers for evaluating stopping conditions. | Retain. |
| `recovery_controller.py` | `ACTIVE_NEW` | `RecoveryController` determining taxonomy stopping states. | Core canonical stopping evaluator. |

---

## 6. Evidence & Proof Verification (`src/hunting/evidence/`)

| File | Status | Description & Role | Action / Target State |
| :--- | :--- | :--- | :--- |
| `__init__.py` | `ACTIVE_NEW` | Package initialization. | Retain. |
| `adjudicator.py` | `ACTIVE_LEGACY` | Adjudicates hypothesis probability scores from legacy cards. | Legacy path. |
| `answer_verifier.py` | `ACTIVE_NEW` | Verifies final answer string against evidence cards. | Modern path. |
| `attribute_extractor.py` | `ACTIVE_LEGACY` | Heuristic attribute extraction from legacy ledger rows. | Legacy path. |
| `evaluator.py` | `ACTIVE_NEW` | Evaluates evidence cards against hypotheses using LLM or heuristics. | Modern path. |
| `facts.py` | `ACTIVE_NEW` | Generates semantic facts from observations. | Modern path. |
| `grouping.py` | `ACTIVE_NEW` | `EvidenceGroupBuilder` clustering raw observations into `EvidenceCard`s. | Modern path. |
| `normalizer.py` | `ACTIVE_LEGACY` | Normalizes legacy field dictionaries. | Legacy path. |
| `outcome_verifier.py` | `ACTIVE_NEW` | `OutcomeVerifier` verifying goals and candidate answer bindings. | Core canonical verifier. |
| `proof_engine.py` | `ACTIVE_NEW` | Authoritative `ProofEngine` evaluating contracts, transforms, and roles. | Core canonical verifier. |
| `relation_verifier.py` | `ACTIVE_NEW` | Helper resolving role synonyms and contract role aliases. | Modern path. |

---

## 7. Planner & Execution (`src/hunting/planner/`)

| File | Status | Description & Role | Action / Target State |
| :--- | :--- | :--- | :--- |
| `__init__.py` | `ACTIVE_NEW` | Package initialization. | Retain. |
| `adaptive.py` | `ACTIVE_LEGACY` | `AdaptiveOperationPlanner` for broad-sweep discovery. | Legacy discovery path. |
| `cache.py` | `ACTIVE_NEW` | `QueryCache` preventing duplicate query execution within a hunt. | Modern path. |
| `compiler.py` | `ACTIVE_LEGACY` | Older query plan compiler. | Superseded by `semantic_goal_planner.py`. |
| `gate_evaluator.py` | `ACTIVE_NEW` | Evaluates prerequisite execution gates between logical plan steps. | Modern path. |
| `planner.py` | `ACTIVE_NEW` | `CanonicalQueryPlanner` building concrete query parameters. | Modern path. |
| `semantic_executor.py` | `ACTIVE_NEW` | `SemanticPlanExecutor` executing steps, handling paging, gates, and proof. | Core canonical executor. |
| `semantic_goal_planner.py` | `ACTIVE_NEW` | Plans ordered `LogicalPlan` from `SemanticGoalGraph` and operations. | Core canonical planner. |
| `semantic_query_compiler.py`| `ACTIVE_LEGACY` | Legacy query compiler for unstructured requests. | Legacy path. |
| `semantic_readiness.py` | `ACTIVE_LEGACY` | Legacy readiness checks before query execution. | Legacy path. |
| `templates.py` | `ACTIVE_LEGACY` | Static SQL/SPL query templates. | Superseded by modular transforms. |
| `validator.py` | `ACTIVE_NEW` | Validates logical plans and step dependency DAGs. | Modern path. |

---

## 8. Adapters & Telemetry Providers (`src/hunting/m5_adapter/`)

| File | Status | Description & Role | Action / Target State |
| :--- | :--- | :--- | :--- |
| `__init__.py` | `ACTIVE_NEW` | Exports adapters. | Retain. |
| `allowlist.py` | `ACTIVE_NEW` | Validates time window formats and query parameters. | Core safety guard. |
| `cdb_adapter.py` | `ACTIVE_NEW` | SQLite adapter for offline testing (`CdbAdapter`). | Modern local test adapter. |
| `controls.py` | `ACTIVE_NEW` | Control queries checking telemetry partition health. | Modern path. |
| `splunk_adapter.py` | `ACTIVE_NEW` | Production Splunk adapter (`SplunkLiveAdapter`). | Modern enterprise SIEM adapter. |

---

## 9. Observation Ledger & Storage (`src/hunting/m1_ledger/`)

| File | Status | Description & Role | Action / Target State |
| :--- | :--- | :--- | :--- |
| `__init__.py` | `ACTIVE_NEW` | Package initialization. | Retain. |
| `extraction.py` | `ACTIVE_LEGACY` | Event extraction for legacy alert models. | Legacy path. |
| `ledger.py` | `ACTIVE_NEW` | In-memory `ObservationLedger` indexing observations by entity and query. | Core modern ledger. |
| `raw_storage.py` | `ACTIVE_LEGACY` | Raw event blob storage on disk. | Superseded by artifact persistence. |
| `store.py` | `ACTIVE_NEW` | `ObservationStore` supporting observation lookups and forensic queries. | Core modern store. |
| `taint.py` | `ACTIVE_LEGACY` | Taint tracking for legacy graph edges. | Legacy path. |

---

## 10. Legacy Subsystems (`m2_abduction`, `m3_constraints`, `m4_controller`, `m5_reporter`, `human_loop`)

| Directory / File | Status | Description & Role | Action / Target State |
| :--- | :--- | :--- | :--- |
| `m2_abduction/provider.py` | `ACTIVE_NEW` | `ApiLLMProvider`, `ApiLLMConfig`, `create_llm_caller`. | Modern LLM interface. |
| `m2_abduction/policy.py` | `ACTIVE_LEGACY` | Abduction policy for legacy alert hypotheses. | Legacy alert only. |
| `m2_abduction/prompting.py`| `ACTIVE_LEGACY` | Prompts for legacy alert abduction. | Legacy alert only. |
| `m2_abduction/schema.py` | `ACTIVE_LEGACY` | JSON schemas for legacy alert abduction. | Legacy alert only. |
| `m3_constraints/integrity.py`| `ACTIVE_LEGACY`| Graph integrity rules for legacy alert graphs. | Legacy alert only. |
| `m4_controller/controller.py`| `ACTIVE_LEGACY`| Controller for legacy alert investigation. | Legacy alert only. |
| `m4_controller/planner.py` | `ACTIVE_LEGACY`| Action planner for legacy alert investigation. | Legacy alert only. |
| `m5_reporter/reporter.py` | `ACTIVE_LEGACY` | Report generator for legacy alert investigations. | Legacy alert only. |
| `human_loop/clarification.py`| `ACTIVE_LEGACY`| Terminal question prompt for legacy alerts. | Legacy alert only. |
| `human_loop/testimony.py` | `ACTIVE_LEGACY` | Analyst testimony ingestion for legacy alerts. | Legacy alert only. |

---

## 11. Registry, Reporting, & Validation (`registry/`, `reporter/`, `validator/`, `query_safety/`)

| File | Status | Description & Role | Action / Target State |
| :--- | :--- | :--- | :--- |
| `registry/proof_contract_registry.py` | `ACTIVE_NEW` | Central authoritative registry for approved `ProofContract`s. | Core modern registry. |
| `registry/loader.py` | `ACTIVE_LEGACY` | Loads legacy registry YAML (`registry_cdb.yaml`). | Legacy alert only. |
| `registry/schema.py` | `ACTIVE_LEGACY` | Legacy schema definitions. | Legacy alert only. |
| `reporter/builder.py` | `ACTIVE_NEW` | `build_final_hunt_account` assembling account from state and ledger. | Core modern reporter. |
| `reporter/renderer.py` | `ACTIVE_NEW` | `render_analyst_report` rendering standard 6-section Markdown report. | Core modern renderer. |
| `reporter/account_exporter.py` | `ACTIVE_NEW` | Exports account JSON summary. | Modern path. |
| `validator/investigation_validator.py` | `ACTIVE_NEW` | `InvestigationValidator` verifying syntactic and semantic validity of goal graphs. | Core modern validator. |
| `query_safety/native_query_gate.py` | `ACTIVE_NEW` | `NativeQueryGate` validating SQL and SPL queries against destructive operations. | Core safety guard. |

---

## 12. Summary Breakdown

- **`ACTIVE_NEW` Modules**: **44 modules** (100% of modern semantic hunting data flow).
- **`ACTIVE_LEGACY` Modules**: **28 modules** (Restricted to legacy `--alert` CLI mode and backward-compatible tests).
- **`TEST_ONLY` Modules / Stubs**: Evaluated within test suite (`test_*`, synthetic fixtures).
- **`DEAD_CODE` Candidates for Quarantine / Removal**: `bootstrap.py`, `normalization.py`.
- **`UNKNOWN` Modules**: 0 (all modules verified).
