# 03 — LITERATURE AND TRACEABILITY (v5.1)

## Current design revision

The implementation has moved from a relation-first default to a
discovery-first default. The change is grounded in the following principles:

- threat-hunting systems need iterative, queryable evidence collection rather
  than a single fixed event taxonomy;
- the search/query layer should be provider-aware but provider-neutral at the
  semantic contract boundary;
- an LLM may propose semantic anchors and explanations, while deterministic
  validation, completeness metadata and provenance control what can be claimed;
- relations are inferred from observed evidence and remain provisional until
  corroborated.

The previous relation-first graph remains documented as a compatibility
planner. It is no longer the default execution path for free-text hypotheses.

This document establishes the formal epistemic grounding of the system. It
separates principles proven by external peer-reviewed literature, preprints,
industry standards, and practitioner courseware from thesis-specific design
compositions and empirical results measured in this repository.

---

## 1. Canonical Source Register

The source register is classified into four formal tiers:
1. **Peer-Reviewed Scientific Publications** (ACM, IEEE, USENIX, NDSS)
2. **Preprint Records** (ArXiv / Tech Reports)
3. **Official Standards & Vendor Specifications** (MITRE, OCSF, OpenTelemetry, Microsoft, Suricata)
4. **Practitioner & Professional Frameworks** (SANS DFIR/CTI, FI-ISAC TaHiTI, Cisco PEAK)

| Tag | Source Citation | Domain & Principle Utilized in v5.0 | Source Tier |
|---|---|---|---|
| REF-SLEUTH | [Hossain et al., USENIX Security 2017](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/hossain) | Real-time attack scenario reconstruction and dependency/provenance graphs from audit logs. Grounding for causal graph tracking. | PEER-REVIEWED |
| REF-HOLMES | [Milajerdi et al., IEEE S&P 2019](https://ieeexplore.ieee.org/document/8835390/) | Real-time correlation of suspicious information flows across multi-stage attack steps; intermediate entity chaining. | PEER-REVIEWED |
| REF-OMEGALOG | [Hassan et al., NDSS 2020](https://experts.illinois.edu/en/publications/omegalog-high-fidelity-attack-investigation-via-transparent-multi/) | Semantic log fusion combining application-level (HTTP/web/DNS) events with OS/network audit logs without semantic flattening. | PEER-REVIEWED |
| REF-AIQL | [Gao et al., USENIX ATC 2018](https://www.usenix.org/system/files/conference/atc18/atc18-gao.pdf) | Query primitives and domain-specific graph query semantics for attack investigation over system provenance graphs. | PEER-REVIEWED |
| REF-USENIX-TH | [Maxam et al., USENIX Security 2024](https://www.usenix.org/system/files/sec24fall-prepub-71-maxam.pdf) | Empirical field study on enterprise threat hunting workflows, data dependency, and hypothesis formation. | PEER-REVIEWED |
| REF-EXCYTIN | [Microsoft Research 2024](https://www.microsoft.com/en-us/research/publication/excytin-bench-evaluating-llm-agents-on-cyber-threat-investigation/) | Multi-hop cyber threat investigation graph benchmark for LLM agents; evidence path traversal vs hallucinated shortcuts. | PREPRINT / INDUSTRY RESEARCH |
| REF-HUNTERAGENT | [Preprint arXiv:2605.29269](https://arxiv.org/abs/2605.29269) | Dual-layer architecture: unconstrained LLM hypothesis/action proposal coupled with deterministic typed verifiers. | PREPRINT |
| REF-PROVSEEK | [Preprint arXiv:2508.21323](https://arxiv.org/abs/2508.21323) | Separation of concerns across planning, retrieval, correlation, and safety layers in provenance-driven graph hunting. | PREPRINT |
| REF-ECTH | [Evidential Cyber Threat Hunting (arXiv:2104.10319)](https://arxiv.org/abs/2104.10319) | Epistemic knowledge–hypothesis–action loop; evidential reasoning under incomplete and uncertain telemetry. | PREPRINT |
| REF-ATHAFI | [ATHAFI (arXiv:2003.03663)](https://arxiv.org/abs/2003.03663) | Adaptive telemetry collection guided by competing hypothesis testing. | PREPRINT |
| REF-THREATRAPTOR | [ThreatRaptor (arXiv:2101.06761)](https://arxiv.org/abs/2101.06761) | Extraction of threat behaviors from unstructured CTI text into typed query synthesis and execution graphs. | PUBLISHED DEMO |
| REF-CDB | [Cyber Defense Benchmark (arXiv:2604.19533)](https://arxiv.org/abs/2604.19533) | Evaluation methodology for open-ended LLM cybersecurity tasks; defense against spurious keyword attribution. | PREPRINT |
| REF-RAG-SEC | [RAG for Security Incident Analysis (arXiv:2603.18196)](https://arxiv.org/abs/2603.18196) | Compact, targeted evidence retrieval over security data; bounding LLM context size to prevent prompt injection and noise. | PREPRINT |
| REF-CASCADE | [Cluster, Route, Escalate (arXiv:2606.27457)](https://arxiv.org/abs/2606.27457) | Cost-aware routing and selective escalation of ambiguous telemetry cases. | PREPRINT |
| REF-FOR508 | [SANS FOR508: Advanced Incident Response & Threat Hunting](https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting-training) | Enterprise DFIR lifecycle, identity-to-endpoint attribution (Security Event ID 4624), lateral movement, and artifact analysis. | PRACTITIONER FRAMEWORK |
| REF-FOR572 | [SANS FOR572: Advanced Network Forensics](https://www.sans.org/cyber-security-courses/advanced-network-forensics-threat-hunting-incident-response) | Network evidence analysis: strict segregation of client IP vs server IP, proxy/web gateway logs, and DNS session correlation. | PRACTITIONER FRAMEWORK |
| REF-FOR578 | [SANS FOR578: Cyber Threat Intelligence](https://www.sans.org/cyber-security-courses/cyber-threat-intelligence) | Operationalizing CTI into testable hypotheses; Diamond Model of Intrusion Analysis (Adversary, Capability, Infrastructure, Victim). | PRACTITIONER FRAMEWORK |
| REF-TAHITI | [FI-ISAC TaHiTI Threat Hunting Methodology](https://www.nvb.nl/themas/veilig-bankieren/fi-isac/tahiti/) | Structured threat hunting lifecycle: trigger, hypothesis, test specification, execution, and detection feedback. | PRACTITIONER FRAMEWORK |
| REF-PEAK | [Cisco PEAK Threat Hunting Framework](https://blogs.cisco.com/security/introducing-peak-threat-hunting-assistant) | Modern threat hunting archetypes: Hypothesis-driven, Baseline/Discovery, and Model-assisted hunting; operational playbooks. | PRACTITIONER FRAMEWORK |
| REF-MITRE-DC | [MITRE ATT&CK Data Components](https://attack.mitre.org/datacomponents/) | Telemetry abstraction defining relationships between entities (User Account, Host, Network Traffic, Process, File). | OFFICIAL STANDARD |
| REF-MITRE-HUNT | [MITRE ATT&CK Threat Hunting Training](https://attack.mitre.org/resources/learn-more-about-attack/training/threat-hunting/) | Hypothesis generation, required telemetry identification, and coverage gap analysis. | OFFICIAL STANDARD |
| REF-MITRE-ANALYTICS| [MITRE Cyber Analytics Repository](https://attack.mitre.org/analytics/) | Separation of detection logic and behavioral predicates from vendor-specific query implementations. | OFFICIAL STANDARD |
| REF-MICROSOFT| [Microsoft Threat Hunting Assistant](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-security-copilot-threat-hunting-assistant) | Schema-aware query generation, parameter binding, and iterative refinement across enterprise telemetry tables. | OFFICIAL VENDOR SPEC |
| REF-OCSF | [Open Cybersecurity Schema Framework (OCSF)](https://ocsf.io/) | Semantic normalization preserving native provider records; distinction between actor, device, and network endpoint. | OFFICIAL STANDARD |
| REF-OTEL | [OpenTelemetry Semantic Conventions](https://opentelemetry.io/docs/specs/semconv/general/events/) | Semantic taxonomy for events, resources, and attributes; query boundaries must respect underlying provider partitions. | OFFICIAL STANDARD |
| REF-SURICATA | [Suricata EVE JSON Format](https://docs.suricata.io/en/suricata-8.0.0/output/eve/eve-json-format.html) | Protocol metadata schema and stream capture integrity; sensor-level dropping semantics. | OFFICIAL STANDARD |

---

## 2. Decision Traceability Matrix (v5.0)

This matrix traces every architectural and engineering decision in the v5.0
release to its external literature foundations, design status, and verifying tests.

| v5.0 Design Decision | External Literature Grounding | Implementation Status in Repo | Verifying Test Suite |
|---|---|---|---|
| **Investigation Case Graph as Reasoning Unit** | REF-SLEUTH, REF-HOLMES, REF-EXCYTIN, REF-PROVSEEK | Core v5 Architecture | `tests/unit/test_v5_case_graph.py`, `tests/unit/test_general_investigation_loop.py` |
| **Demote Cell to Coverage/Execution Address Only** | REF-OCSF, REF-OTEL, REF-TAHITI | Implemented | `tests/unit/test_phase0_contracts.py` |
| **Strict Field Role Typing (client_ip ≠ server_ip)** | REF-FOR572, REF-OMEGALOG, REF-OCSF | Enforced by Relation Verifier | `tests/unit/test_v5_relation_verifier.py`, `tests/unit/test_evidence_adjudicator.py` |
| **Identity-First Invariant (Person → Account → Endpoint)** | REF-FOR508, REF-HOLMES, REF-EXCYTIN | Enforced by Planner & Validator | `tests/unit/test_v5_amber_vertical_slice.py`, `tests/unit/test_general_investigation_loop.py` |
| **Zero Raw SPL from LLM; Schema-Strict Compilation** | REF-HUNTERAGENT, REF-THREATRAPTOR, REF-CDB | Implemented in Compiler | `tests/unit/test_semantic_compiler.py`, `tests/unit/test_compiler_live_call.py` |
| **Capability Binder (Relations → Logical Operations)** | REF-AIQL, REF-MITRE-ANALYTICS, REF-MICROSOFT | Implemented in Binder Layer | `tests/unit/test_v5_capability_binder.py`, `tests/unit/test_phase2_capabilities_and_queries.py` |
| **Deterministic Relation Verifier Gatekeeper** | REF-HUNTERAGENT, REF-PROVSEEK, REF-SLEUTH | Implemented in Verifier/Adjudicator | `tests/unit/test_v5_relation_verifier.py`, `tests/unit/test_evidence_adjudicator.py` |
| **Prohibition of Web Servers (jabbah) as Client Endpoints** | REF-FOR508, REF-FOR572 | Deterministic Invariant | `tests/unit/test_general_investigation_loop.py` |
| **Evidence Subgraph Extraction for LLM Explanation** | REF-RAG-SEC, REF-PROVSEEK, REF-EXCYTIN | Implemented in Reporter | `tests/unit/test_v5_case_graph.py`, `tests/unit/test_evidence_reporter.py` |
| **Expanded Inconclusive Taxonomy (Never NOT_FOUND on Gap)**| REF-ECTH, REF-ATHAFI, REF-TAHITI | Core Epistemic Invariant | `tests/unit/test_stopping_verdicts_v2.py`, `tests/unit/test_llm_timeout_fail_fast.py` |
| **Decoupled Planning, Retrieval & Cost Budgeting** | REF-PROVSEEK, REF-CASCADE, REF-CDB | Implemented in Controller | `tests/unit/test_phase4_reasoning_and_control.py`, `tests/unit/test_action_planner.py` |
| **Behavior Templates for Known CVE/TTP without LLM** | REF-MITRE-DC, REF-FOR578, REF-THREATRAPTOR | Deterministic Compiler Path | `tests/unit/test_cve_compiler.py`, `tests/unit/test_ttp_compiler.py` |
| **Fine-Grained Hypothesis Adjudication (No Blanket SUPPORTED)** | REF-ECTH, REF-TAHITI, REF-FOR578 | Implemented in Controller | `tests/unit/test_v5_case_graph.py`, `artifacts/amber_botsv2_report.md` |
| **Triple Coverage Accounting (Causal Path vs Wildcard Scope)** | REF-TAHITI, REF-PEAK, REF-OCSF | Implemented in Engine & Builder | `tests/unit/test_phase0_contracts.py`, `artifacts/amber_botsv2_report.md` |
| **Evaluator LLM Context Bounding & Robust Parsing** | REF-RAG-SEC, REF-HUNTERAGENT, REF-EXCYTIN | Implemented in Evaluator | `tests/unit/test_engine_refinements.py`, `artifacts/amber_botsv2_report.md` |

---

## 3. What the Sources Do and Do Not Prove

To maintain rigorous intellectual and scientific integrity, we explicitly demarcate
the boundaries of external evidence versus local thesis claims:

### What the Sources Directly Support:
1. **Provenance & Dependency Tracking** (REF-SLEUTH, REF-HOLMES, REF-AIQL): Prove that complex cyber attacks manifest as directed information flows across system and network entities, and that multi-hop causal graphs are required for forensic reconstruction.
2. **Dual-Layer Agent Safety** (REF-HUNTERAGENT, REF-PROVSEEK): Proves that unconstrained LLM reasoning generates hallucinations and query errors, requiring deterministic typed verifiers and modular boundary enforcement.
3. **Forensic Distinction of Roles** (REF-FOR508, REF-FOR572): Proves that in DFIR, client workstations, authentication sources, destination web servers, and sensor interfaces represent fundamentally incompatible evidential roles that cannot be collapsed into a generic string match.
4. **Hypothesis-Driven Threat Hunting** (REF-ECTH, REF-TAHITI, REF-PEAK): Proves that threat hunting begins with unverified hypotheses, requires explicit data collection requirements, and must report coverage blind spots rather than assuming absence indicates security.

### What the Sources DO NOT Prove (Thesis Innovations & Engineering Claims):
1. **The Exact v5.0 Investigation Case Graph Schema**: No external paper specifies the exact InvestigationCase, GraphEdge, FieldRole, and EvidenceSubgraph data structures used here; this is an engineering composition of this thesis.
2. **The Exact Budget Allocation & Stopping Rules**: The specific turn limits (15), query limits (60), token limits (12,000), and terminal decision enum (STOP_INCONCLUSIVE_IDENTITY_UNRESOLVED, etc.) are operational choices engineered for bounded agent execution.
3. **Universal Telemetry Completeness**: Neither ATT&CK Data Components nor OCSF represents a closed-world ontology of all security telemetry. Provider-native records (Observation.native_type) must always be retained.
4. **Production Readiness of Unimplemented Providers**: Live contract validation is demonstrated for Splunk (BOTSv2) and local SQLite (CDB). Live EDR and IDS integrations remain extension contracts awaiting dedicated sensor deployments.
