# 03 — LITERATURE AND TRACEABILITY (v9)

This record distinguishes external evidence, engineering transfer and thesis hypotheses. “Supports” never means that a source proves the exact local architecture.

## 1. Source register

| ID | Primary source | Supported principle | Transfer limit |
|---|---|---|---|
| REF-SLEUTH | [SLEUTH, USENIX Security 2017](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-hossain.pdf) | Provenance/dependency reconstruction from audit logs | Does not provide a universal path for arbitrary questions |
| REF-HOLMES | [HOLMES, IEEE S&P 2019](https://ieeexplore.ieee.org/document/8835390/) | Correlation of suspicious information flows in multi-stage attacks | Does not prove arbitrary factual relations |
| REF-OMEGALOG | [OmegaLog, NDSS 2020](https://experts.illinois.edu/en/publications/omegalog-high-fidelity-attack-investigation-via-transparent-multi/) | Reconciliation across application, system and network context | Does not define a closed event ontology |
| REF-AIQL | [AIQL, USENIX ATC 2018](https://www.usenix.org/conference/atc18/presentation/gao) | Typed domain query primitives and semantics-aware planning | Does not prove the local GoalGraph or planner |
| REF-THREATRAPTOR | [ThreatRaptor, ICDE 2021 implementation](https://github.com/peng-gao-lab/threatraptor) | Natural-language attack description to behavior graph and query | Focuses on described attack behavior and system audit data, not arbitrary QA |
| REF-KESTREL | [Kestrel theory](https://kestrel.readthedocs.io/en/latest/theory.html) | Iterative graph/subset identification over incomplete real telemetry | Does not validate LLM-generated graph semantics |
| REF-ECTH | [Evidential Cyber Threat Hunting](https://arxiv.org/abs/2104.10319) | Knowledge, hypothesis and action subspaces; human-machine investigation | Preprint; no proof of this controller or its budgets |
| REF-ATHAFI | [ATHAFI](https://arxiv.org/abs/2003.03663) | Adaptive collection and hypothesis testing | Does not establish local action scoring |
| REF-USENIX-TH | [Maxam and Davis, USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/maxam) | Practitioner processes are diverse; hunting uses hypothesis-driven and data-driven work | Qualitative study of 11 DHS-associated hunters, not an optimal agent design |
| REF-EXCYTIN | [ExCyTIn-Bench, ICML 2026](https://www.microsoft.com/en-us/research/publication/excytin-bench-evaluating-llm-agents-on-cyber-threat-investigation/) | Multi-step investigation graphs, intermediate actions and executable evaluation | Controlled Azure/Sentinel SQL benchmark; not unknown-provider semantic proof |
| REF-CYBER-BENCH | [Cyber Defense Benchmark](https://arxiv.org/abs/2604.19533) | Raw-event cyber hunting remains difficult for general LLMs | 2026 preprint; does not prove all agentic hunting is infeasible |
| REF-UMCP | [UMCP / HTN Planning, AIPS 1994](https://www.cs.umd.edu/~nau/papers/erol1994umcp.pdf) | Formal task-network decomposition | Soundness/completeness does not transfer to the local heuristic |
| REF-RPG | [Retrieve-Plan-Generation, EMNLP 2024](https://aclanthology.org/2024.emnlp-main.270/) | Iterative retrieval and planning conditioned on observations | Does not establish the local recovery policy |
| REF-AUTOLINK | [AutoLink, AAAI 2026](https://ojs.aaai.org/index.php/AAAI/article/view/40672) | Progressive schema exploration without full-schema prompts | Text-to-SQL; reported thresholds and actions do not transfer unchanged |
| REF-MDB-LINK | [MDB-Link](https://arxiv.org/abs/2608.09588) | Hierarchical multi-database schema retrieval and budget-aware reranking | 2026 preprint; ranking does not guarantee telemetry recall or proof |
| REF-REMATCH | [ReMatch](https://arxiv.org/abs/2403.01567) | Retrieval-enhanced matching over heterogeneous schemas | Candidate mappings still require independent validation |
| REF-CHESS | [CHESS](https://arxiv.org/abs/2405.16755) | Separate retrieval, schema selection, generation and validation | Database assumptions and budgets do not transfer directly |
| REF-RATSQL | [RAT-SQL](https://arxiv.org/abs/1911.04942) | Relation-aware schema linking | Does not define cybersecurity semantics |
| REF-TOOLSHED | [ToolShed](https://arxiv.org/abs/2410.14594) | Tool retrieval has recall/context/cost trade-offs | Does not license a fixed cutoff for telemetry |
| REF-SELECTIVE | [Selective Classification](https://arxiv.org/abs/1805.08206) | Evaluate abstention using risk-coverage, not answered accuracy alone | Classifier guarantees do not transfer automatically to agents |
| REF-SAFE-TOOLS | [Verifiably Safe Tool Use, ICSE-NIER 2026](https://doi.org/10.1145/3786582.3786839) | External specifications can constrain agent tool actions | Does not provide hunting-specific proof contracts |
| REF-MITRE | [MITRE ATT&CK Data Components](https://attack.mitre.org/datacomponents/) | Observable properties for ATT&CK behavior | Does not guarantee local telemetry availability |
| REF-OCSF | [OCSF](https://ocsf.io/) | Extensible vendor-neutral event normalization | Must not replace native evidence provenance |
| REF-SPLUNK | [Splunk Search Job API](https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-reference/10.2/search-endpoints/search-endpoint-descriptions) | Job bounds, cancellation and execution telemetry | `head` does not imply bounded backend scan or completeness |
| REF-TAHITI | [FI-ISAC TaHiTI](https://www.nvb.nl/themas/veilig-bankieren/fi-isac/tahiti/) | Practitioner hypothesis-driven hunt lifecycle | Practitioner guidance, not universal scientific proof |
| REF-DARPA-TC | [DARPA Transparent Computing](https://github.com/darpa-i2o/Transparent-Computing) | Provenance datasets and attack engagements | Dataset coverage is not complete or provider-universal |

## 2. Architecture traceability

| v9 decision | Basis | Local contribution requiring evaluation |
|---|---|---|
| SemanticGoalGraph as obligation DAG | REF-AIQL, REF-THREATRAPTOR, REF-EXCYTIN, REF-UMCP | Generic factual/hypothesis/population graph and explicit AND/OR/GATE semantics |
| OutcomeContract union | REF-EXCYTIN, REF-ECTH, REF-USENIX-TH, REF-SELECTIVE | Unifying factual answers, hypothesis verdicts and population discovery |
| Semantic Acceptance Gate | REF-SAFE-TOOLS, REF-SELECTIVE, schema-matching sources | Provenance checks plus selective clarification for semantic uncertainty |
| Progressive Capability Frontier | REF-AUTOLINK, REF-MDB-LINK, REF-CHESS, REF-TOOLSHED, REF-REMATCH, REF-RATSQL | F0–F4 retrieve-then-admit matching; no exact-name or case-alias matcher; C2 only on a budgeted shortlist |
| Controlled CandidateSet | REF-UMCP, REF-SAFE-TOOLS | Cardinality-aware discriminator and human checkpoint |
| Typed EvidenceAction / QueryIntent | REF-AIQL, REF-THREATRAPTOR | Provider-neutral EXPLORE/DISCRIMINATE/PROVE contract |
| Immutable observations and evidence graph | REF-SLEUTH, REF-HOLMES, REF-OMEGALOG, REF-OCSF | Native-preserving FieldFacts and cited CandidateRelations |
| Executable ProofContracts | REF-SAFE-TOOLS, provenance systems | Approved relation-specific evaluators and negative licences |
| Deterministic recovery and stopping | REF-ECTH, REF-RPG, REF-SELECTIVE | Observation ladder, orthogonal state axes and terminal taxonomy |
| Population-discovery hunt | REF-USENIX-TH, REF-KESTREL, REF-MITRE | DiscoveryContract, prevalence and bounded population coverage |
| End-to-end evaluation | REF-EXCYTIN, REF-CYBER-BENCH | Independent gold graphs/answers/evidence and executable baselines |

## 3. Scientific claims permitted now

The project may claim that its design is informed by established work on graph-based investigation, typed query languages, evidence-centric hunting, progressive schema discovery, constrained tool use and selective abstention.

It may not yet claim:

- that v9 is optimal or universally sound/complete;
- that its semantic compiler understands arbitrary requests reliably;
- that its ProofContract registry covers every relation;
- that F0–F4 retrieve-then-admit matching is better than exhaustive or simpler baselines;
- that an exact `guaranteed_relations` string match is a completed capability census;
- a cross-provider generalization result;
- F1, answer accuracy or cost superiority from the current simulated runner;
- production readiness from skipped live tests.

These remain thesis hypotheses until measured using independent labels and actual pipeline execution.
