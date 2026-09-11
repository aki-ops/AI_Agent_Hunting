# 03 — LITERATURE AND TRACEABILITY (v7)

This file separates external support from thesis engineering. “Supports” does
not mean “proves our exact implementation”. Exact class names, prompts,
budgets, stopping enums and F1 thresholds remain local decisions until tested.

## 1. Canonical source register

| ID | Source | Supports | Does not establish |
|---|---|---|---|
| REF-SLEUTH | [USENIX Security 2017](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-hossain.pdf) | Provenance/dependency graph reconstruction from audit logs. | A universal path for every question. |
| REF-HOLMES | [IEEE S&P 2019](https://ieeexplore.ieee.org/document/8835390/) | Correlation of suspicious information flows in multi-stage attacks. | A mandatory relation graph for factual lookup. |
| REF-OMEGALOG | [NDSS 2020](https://experts.illinois.edu/en/publications/omegalog-high-fidelity-attack-investigation-via-transparent-multi/) | Reconciliation of application/system/network context. | A closed event taxonomy. |
| REF-AIQL | [USENIX ATC 2018](https://www.usenix.org/system/files/conference/atc18/atc18-gao.pdf) | Typed logical query semantics and execution planning. | Our exact SemanticGoalGraph or scoring formula. |
| REF-THREATRAPTOR | [ICDE 2021 / implementation](https://github.com/peng-gao-lab/threatraptor) | Structured behaviour extraction before typed query synthesis. | That all NL questions are attack-behaviour graphs. |
| REF-USENIX-TH | [Maxam et al., USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/maxam) | Empirical diversity of threat-hunting processes. | Our controller or query policy. |
| REF-ECTH | [Evidential Cyber Threat Hunting](https://arxiv.org/abs/2104.10319) | Explicit knowledge/hypothesis/action and uncertainty concepts. Preprint. | Production effectiveness of our state machine. |
| REF-ATHAFI | [ATHAFI](https://arxiv.org/abs/2003.03663) | Adaptive telemetry collection and hypothesis testing. Preprint. | Our action score or budget. |
| REF-EXCYTIN | [ExCyTIn-Bench](https://www.microsoft.com/en-us/research/publication/excytin-bench-evaluating-llm-agents-on-cyber-threat-investigation/) | Graph-grounded benchmark for multistep investigation and evidence paths. | General reliability of LLMs. |
| REF-MITRE-DC | [ATT&CK Data Components](https://attack.mitre.org/datacomponents/) | Properties observable for techniques/sub-techniques. | Complete telemetry coverage. |
| REF-MITRE-ANALYTICS | [ATT&CK Detection Strategies](https://attack.mitre.org/detectionstrategies/) | High-level detection strategies and analytics. | Provider-specific query availability. |
| REF-OCSF | [OCSF](https://ocsf.io/) | Extensible vendor-neutral event normalization. | A replacement for native records. |
| REF-SCHEMA-LLM | [Schema Matching with Large Language Models](https://arxiv.org/abs/2407.11852) | LLM-assisted generation of semantic schema-match candidates; context size/selection materially affects match quality. | That a candidate mapping is correct without validation. |
| REF-REMATCH | [ReMatch](https://arxiv.org/abs/2403.01567) | Retrieval-enhanced LLM schema matching over heterogeneous real-world schemas. | A cybersecurity-specific source mapping or query-safety policy. |
| REF-CHESS | [CHESS](https://arxiv.org/abs/2405.16755) | Retrieval, schema selection, query generation and validation as separate stages; reducing the context sent to the model. | That its database setting or component budgets transfer unchanged to telemetry. |
| REF-RAT-SQL | [RAT-SQL](https://arxiv.org/abs/1911.04942) | Relation-aware schema linking instead of treating schema items as an unordered list. | Our source-score formula or security semantics. |
| REF-ADAPTIVE-K | [Adaptive-K](https://arxiv.org/abs/2506.08479) | A documented alternative for dynamic context sizing; evaluated but not adopted as the source-selection policy here because it can discard low-scoring telemetry. | A universal cutoff or a guarantee that lexical scores find every relevant source. |
| REF-TOOLSHED | [ToolShed](https://arxiv.org/abs/2410.14594) | Tool/capability retrieval under a recall--context-size trade-off. | Correctness of a telemetry mapping without validation. |
| REF-MDB-LINK | [MDB-Link](https://arxiv.org/abs/2608.09588) | Field-level retrieval, aggregation by source, shortlist construction and budget-aware reranking. | A cybersecurity-specific field ontology or proof of our thresholds. |
| REF-OTEL | [OpenTelemetry events](https://opentelemetry.io/docs/specs/semconv/general/events/) | Extensible semantic events and attributes. | Security-specific coverage. |
| REF-MICROSOFT | [Microsoft Threat Hunting Assistant](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-security-copilot) | Schema/table-aware query assistance and review. | Correctness without verification. |
| REF-SAFE-TOOLS | [Verifiably Safe Tool Use for LLM Agents](https://doi.org/10.1145/3786582.3786839) | Separation of intent/planning from verified tool execution. | Hunting-specific metrics. |
| REF-RPG | [Retrieve-Plan-Generation, EMNLP 2024](https://aclanthology.org/2024.emnlp-main.270/) | Iterative planning and retrieval conditioned on evidence. | Our controller's optimality. |
| REF-TAHITI | [FI-ISAC TaHiTI](https://www.nvb.nl/themas/veilig-bankieren/fi-isac/tahiti/) | Practitioner hypothesis-driven hunting lifecycle. | A universal industrial standard. |
| REF-PEAK | [Cisco PEAK](https://blogs.cisco.com/security/introducing-peak-threat-hunting-assistant) | Practical hunting archetypes/playbook thinking. | Scientific validity of our architecture. |
| REF-DARPA-TC | [DARPA Transparent Computing](https://github.com/darpa-i2o/Transparent-Computing/blob/master/README.md) | Provenance data and attack engagements for evaluation. | Dataset completeness/perfection. |

## 2. Traceability matrix

| v7 decision | Source basis | Local engineering | Required evidence |
|---|---|---|---|
| SemanticGoalGraph is semantic planning contract | REF-THREATRAPTOR, REF-AIQL | Typed variables, relations, qualifiers, provenance and dependencies | Claim precision/recall/F1; unsupported-expansion rate |
| CapabilityGraph precedes query | REF-AIQL, REF-OCSF, REF-MICROSOFT | Census and fallback policy | Provider-selection and capability tests |
| Relation-scoped exhaustive batching precedes source profiling | REF-CHESS, REF-RAT-SQL, REF-TOOLSHED, REF-MDB-LINK | Deterministic per-relation ordering, exhaustive source/field batches, compact prompts and full-census validation | Source/field coverage, token reduction per call, source-role precision/recall and partial-batch gap rate |
| LLM source proposal becomes runtime capability only after validation/probe | REF-SCHEMA-LLM, REF-REMATCH, REF-OCSF | Census sketch, proposal schema, probe protocol and cache | Source-role precision/recall; probe precision; hallucinated-ID rate |
| QueryIntent is compiled; raw native candidate is quarantined | REF-AIQL, REF-SAFE-TOOLS | AST policy, allowlist, parameterization, dry-run and cost gate | Query safety/replay artifacts |
| Raw observations append-only | REF-SLEUTH, REF-OMEGALOG, REF-OCSF | Ledger/envelope/card format | Citation integrity and unknown-field tests |
| EvidenceGraph built from observations | REF-SLEUTH, REF-HOLMES | Fact roles and edge promotion | Edge precision/recall/F1 |
| No universal scenario branch | REF-USENIX-TH | Remove keyword/template routing | Counterfactual plan-faithfulness tests; Phase-B regression suite verifies request-derived case edges |
| LLM bounded to proposal/explanation | REF-EXCYTIN, REF-SAFE-TOOLS | Parser, graph schema, citation gate | One-call semantic compiler, injection, invalid-output and cost/grounding tests |
| Gaps differ from negative results | REF-ECTH, REF-TAHITI | Separate execution completion, proof completion and route exhaustion in controller state | Complete-empty, partial, unreachable and unsupported replays; false-negative rate |
| Proof-aware capability readiness | REF-AIQL, REF-OCSF, REF-MITRE-DC, REF-SCHEMA-LLM | Per-relation reachability/retrieval/proof/qualifier readiness and profiling trigger | Readiness classification accuracy; unnecessary/missed profiling rate |
| Declarative progressive retrieval | REF-RPG, REF-CHESS, REF-TOOLSHED | Ordered bounded predicate stages with invariant scope/time/binding/projection limits and no-progress detection | False-miss reduction; query/scan/latency cost; repeated-query count |
| Contract-driven transition verification | REF-SLEUTH, REF-HOLMES, REF-OMEGALOG | Cited ledger observations from one provider/scope and compatible typed entity; exact validated-operation `temporal_roles`, `action_roles`, `state_roles`, `artifact_identity_roles`/`correlation_roles`; parseable ordered timestamps within a declared bound; causality remains a separate obligation | Transition edge precision/recall/F1; uncited/cross-scope/cross-entity/time-bound/suffix/source-name counterfactuals |
| Coverage and cost are outputs | REF-EXCYTIN, REF-DARPA-TC | Metrics/artifact format | Reproducible labelled benchmark |

## 3. Claims that remain thesis hypotheses

The following are not externally proven: exact graph classes; action scoring;
budgets; optimal LLM call count; minimum evidence thresholds; generalization
from one Splunk dataset to all SIEM/EDR/IDS; and any F1 result without labelled
ground truth.

Peer-reviewed papers and official standards support principles. Preprints and
vendor/practitioner material inform design with weaker evidentiary weight. A
local replay supports only the exact repository behaviour measured in that
replay.
