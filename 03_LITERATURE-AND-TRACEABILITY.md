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
| REF-AUTOLINK | [AutoLink, AAAI 2026](https://ojs.aaai.org/index.php/AAAI/article/view/40672) | Autonomous iterative schema exploration, progressive expansion without full-schema prompts. | Exact parameters transfer to threat hunting without calibration. |
| REF-CYBER-BENCH | [Cyber Defense Benchmark, 2026](https://arxiv.org/abs/2604.19533) | Real-world threat hunting evaluation over 75k-135k raw events; models struggle without structural constraints. | That all agentic hunting is infeasible; refutes assumption that unguided LLMs succeed. |
| REF-SOC-OPS | [Autonomous SOC Operations, PMLR 2026](https://proceedings.mlr.press/v318/saju26a.html) | Constrained query generation with syntax constraints and documentation-grounded prompts. | BLEU/ROUGE overlap proves query denotation or execution semantics. |
| REF-SELECTIVE-CLS | [Selective Classification](https://arxiv.org/abs/1805.08206) | Abstention models evaluated on risk-coverage curves rather than precision on answered cases only. | Statistical classifier guarantees transfer unchanged to adaptive agents. |
| REF-KESTREL | [Kestrel Threat Hunting](https://kestrel.readthedocs.io/en/stable/theory.html) | Threat hunting as iterative subgraph pattern matching over incomplete telemetry. | LLM-generated graph is valid without independent proof contracts. |
| REF-UMCP-HTN | [UMCP / HTN Planning, AIPS 1994](https://www.cs.umd.edu/~nau/papers/erol1994umcp.pdf) | Task-network decomposition, AND/OR/GATE dependency graphs. | Soundness/completeness of our local planning heuristic. |
| REF-SPLUNK-REST | [Splunk Search Job API](https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-reference/10.2/search-endpoints/search-endpoint-descriptions) | Search dispatch with `max_time`, cancellation, `scanCount`, `runDuration`, and `resultCount`. | `head 100` limits backend scanning work. |
| REF-OTEL | [OpenTelemetry events](https://opentelemetry.io/docs/specs/semconv/general/events/) | Extensible semantic events and attributes. | Security-specific coverage. |
| REF-MICROSOFT | [Microsoft Threat Hunting Assistant](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-security-copilot) | Schema/table-aware query assistance and review. | Correctness without verification. |
| REF-SAFE-TOOLS | [Verifiably Safe Tool Use, ICSE-NIER 2026](https://doi.org/10.1145/3786582.3786839) | External specification enforcement for tool capability and action sequences. | Hunting-specific verifier completeness. |
| REF-RPG | [Retrieve-Plan-Generation, EMNLP 2024](https://aclanthology.org/2024.emnlp-main.270/) | Iterative planning and retrieval conditioned on evidence. | Our controller's optimality. |
| REF-TAHITI | [FI-ISAC TaHiTI](https://www.nvb.nl/themas/veilig-bankieren/fi-isac/tahiti/) | Practitioner hypothesis-driven hunting lifecycle. | A universal industrial standard. |
| REF-PEAK | [Cisco PEAK](https://blogs.cisco.com/security/introducing-peak-threat-hunting-assistant) | Practical hunting archetypes/playbook thinking. | Scientific validity of our architecture. |
| REF-DARPA-TC | [DARPA Transparent Computing](https://github.com/darpa-i2o/Transparent-Computing/blob/master/README.md) | Provenance data and attack engagements for evaluation. | Dataset completeness/perfection. |

## 2. Traceability matrix

| Architecture Decision (v8 / 08 Plan) | Source basis | Local engineering | Required evidence |
|---|---|---|---|
| GoalGraph carries AnswerContract & request spans | REF-THREATRAPTOR, REF-AIQL, REF-EXCYTIN | Typed variables, relations, qualifiers, provenance spans, AND/OR/GATE | Goal precision/recall/F1; forbidden-expansion rate |
| ProofContract independent of LLM proposal | REF-SLEUTH, REF-SCHEMA-LLM, REF-SAFE-TOOLS | Three levels: STRUCTURALLY_VALID, RETRIEVAL_CAPABLE, PROOF_CAPABLE | Role-swap & cooccurrence reject tests; probe precision |
| Progressive Frontier (F0–F4) replaces fixed Top-K | REF-AUTOLINK, REF-MDB-LINK, REF-TOOLSHED | Incremental expansion (certified -> metadata -> adjacent -> profiling -> exhaustive) | Unexamined source coverage; token reduction per hunt |
| Controlled CandidateSet & Discriminator queries | REF-UMCP-HTN, REF-SAFE-TOOLS | Multi-candidate sets; automated discriminator before user prompt | Zero wrong auto-binding; disambiguation rate |
| QueryIntent modes (EXPLORE/DISCRIMINATE/PROVE) | REF-AIQL, REF-SOC-OPS, REF-SAFE-TOOLS | Provider-neutral intent; adapter parameterization | Execution success; denotation accuracy; zero injection |
| Quarantined Native SPL Gate & AST telemetry | REF-SAFE-TOOLS, REF-SPLUNK-REST | AST parser allowlist, time bounds, scan/runtime tracking, cancel SID | Unsafe query rejection; backend scan monitoring |
| Raw observations append-only in ledger | REF-SLEUTH, REF-OMEGALOG, REF-OCSF | Ledger/envelope/card format | Citation integrity and unknown-field tests |
| EvidenceGraph built from verified facts | REF-SLEUTH, REF-HOLMES | Role direction, state transition, and ProofContract evaluation | Transition edge precision/recall/F1 |
| No universal scenario branch | REF-USENIX-TH, REF-CYBER-BENCH | Pure contract flow; no keyword playbooks | Counterfactual matrix 8/8 passing |
| LLM bounded to C1–C6 isolated calls | REF-EXCYTIN, REF-SAFE-TOOLS | Token budgets, max 5 calls, schema validation | Call & token ceilings; zero prompt leakage |
| 9-state stopping taxonomy & selective abstention | REF-SELECTIVE-CLS, REF-ECTH, REF-TAHITI | Explicit stopping enums; complete-empty without license is INCONCLUSIVE | Risk-coverage curve; false-negative rate |
| Full cost accounting (LLM + Splunk + Analyst) | REF-EXCYTIN, REF-SPLUNK-REST | $C_{run} = C_{llm} + C_{splunk} + C_{control} + C_{analyst}$ | Cost per solved case; scanCount and latency tracking |

## 3. Claims that remain thesis hypotheses

The following are not externally proven: exact graph classes; action scoring;
budgets; optimal LLM call count; minimum evidence thresholds; generalization
from one Splunk dataset to all SIEM/EDR/IDS; and any F1 result without labelled
ground truth.

Peer-reviewed papers and official standards support principles. Preprints and
vendor/practitioner material inform design with weaker evidentiary weight. A
local replay supports only the exact repository behaviour measured in that
replay.
