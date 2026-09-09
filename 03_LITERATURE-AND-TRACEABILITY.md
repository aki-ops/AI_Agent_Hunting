# 03 — LITERATURE AND TRACEABILITY (v6)

This file separates external support from thesis engineering. “Supports” does
not mean “proves our exact implementation”. Exact class names, prompts,
budgets, stopping enums and F1 thresholds remain local decisions until tested.

## 1. Canonical source register

| ID | Source | Supports | Does not establish |
|---|---|---|---|
| REF-SLEUTH | [USENIX Security 2017](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-hossain.pdf) | Provenance/dependency graph reconstruction from audit logs. | A universal path for every question. |
| REF-HOLMES | [IEEE S&P 2019](https://ieeexplore.ieee.org/document/8835390/) | Correlation of suspicious information flows in multi-stage attacks. | A mandatory relation graph for factual lookup. |
| REF-OMEGALOG | [NDSS 2020](https://experts.illinois.edu/en/publications/omegalog-high-fidelity-attack-investigation-via-transparent-multi/) | Reconciliation of application/system/network context. | A closed event taxonomy. |
| REF-AIQL | [USENIX ATC 2018](https://www.usenix.org/system/files/conference/atc18/atc18-gao.pdf) | Typed logical query semantics and execution planning. | Our exact ClaimGraph or scoring formula. |
| REF-THREATRAPTOR | [ICDE 2021 / implementation](https://github.com/peng-gao-lab/threatraptor) | Structured behaviour extraction before typed query synthesis. | That all NL questions are attack-behaviour graphs. |
| REF-USENIX-TH | [Maxam et al., USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/maxam) | Empirical diversity of threat-hunting processes. | Our controller or query policy. |
| REF-ECTH | [Evidential Cyber Threat Hunting](https://arxiv.org/abs/2104.10319) | Explicit knowledge/hypothesis/action and uncertainty concepts. Preprint. | Production effectiveness of our state machine. |
| REF-ATHAFI | [ATHAFI](https://arxiv.org/abs/2003.03663) | Adaptive telemetry collection and hypothesis testing. Preprint. | Our action score or budget. |
| REF-EXCYTIN | [ExCyTIn-Bench](https://www.microsoft.com/en-us/research/publication/excytin-bench-evaluating-llm-agents-on-cyber-threat-investigation/) | Graph-grounded benchmark for multistep investigation and evidence paths. | General reliability of LLMs. |
| REF-MITRE-DC | [ATT&CK Data Components](https://attack.mitre.org/datacomponents/) | Properties observable for techniques/sub-techniques. | Complete telemetry coverage. |
| REF-MITRE-ANALYTICS | [ATT&CK Detection Strategies](https://attack.mitre.org/detectionstrategies/) | High-level detection strategies and analytics. | Provider-specific query availability. |
| REF-OCSF | [OCSF](https://ocsf.io/) | Extensible vendor-neutral event normalization. | A replacement for native records. |
| REF-OTEL | [OpenTelemetry events](https://opentelemetry.io/docs/specs/semconv/general/events/) | Extensible semantic events and attributes. | Security-specific coverage. |
| REF-MICROSOFT | [Microsoft Threat Hunting Assistant](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-security-copilot) | Schema/table-aware query assistance and review. | Correctness without verification. |
| REF-SAFE-TOOLS | [Verifiably Safe Tool Use for LLM Agents](https://doi.org/10.1145/3786582.3786839) | Separation of intent/planning from verified tool execution. | Hunting-specific metrics. |
| REF-RPG | [Retrieve-Plan-Generation, EMNLP 2024](https://aclanthology.org/2024.emnlp-main.270/) | Iterative planning and retrieval conditioned on evidence. | Our controller's optimality. |
| REF-TAHITI | [FI-ISAC TaHiTI](https://www.nvb.nl/themas/veilig-bankieren/fi-isac/tahiti/) | Practitioner hypothesis-driven hunting lifecycle. | A universal industrial standard. |
| REF-PEAK | [Cisco PEAK](https://blogs.cisco.com/security/introducing-peak-threat-hunting-assistant) | Practical hunting archetypes/playbook thinking. | Scientific validity of our architecture. |
| REF-DARPA-TC | [DARPA Transparent Computing](https://github.com/darpa-i2o/Transparent-Computing/blob/master/README.md) | Provenance data and attack engagements for evaluation. | Dataset completeness/perfection. |

## 2. Traceability matrix

| v6 decision | Source basis | Local engineering | Required evidence |
|---|---|---|---|
| ClaimGraph is semantic planning contract | REF-THREATRAPTOR, REF-AIQL | Schema, provenance, dependencies | Claim precision/recall/F1; unsupported-expansion rate |
| CapabilityGraph precedes query | REF-AIQL, REF-OCSF, REF-MICROSOFT | Census and fallback policy | Provider-selection and capability tests |
| Native query is adapter-owned | REF-AIQL, REF-MITRE-ANALYTICS | Allowlist, parameterization, dry-run | Query safety/replay artifacts |
| Raw observations append-only | REF-SLEUTH, REF-OMEGALOG, REF-OCSF | Ledger/envelope/card format | Citation integrity and unknown-field tests |
| EvidenceGraph built from observations | REF-SLEUTH, REF-HOLMES | Fact roles and edge promotion | Edge precision/recall/F1 |
| No universal scenario branch | REF-USENIX-TH | Remove keyword/template routing | Counterfactual plan-faithfulness tests; Phase-B regression suite verifies request-derived case edges |
| LLM bounded to proposal/explanation | REF-EXCYTIN, REF-SAFE-TOOLS | Parser, prompt schema, citation gate | One-call ClaimGraph compiler, injection, invalid-output and cost/grounding tests |
| Gaps differ from negative results | REF-ECTH, REF-TAHITI | Stop enum/controller policy | Partial/unreachable/unsupported replays |
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
