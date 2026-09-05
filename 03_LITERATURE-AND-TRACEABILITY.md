# 03 — LITERATURE AND TRACEABILITY (v4.1)

This document separates principles supported by external sources from design
decisions made in this thesis and results measured in this repository.

## 1. Source register

| Tag | Source | Principle used here | Evidence level |
|---|---|---|---|
| REF-ECTH | [Evidential Cyber Threat Hunting](https://arxiv.org/abs/2104.10319) | knowledge–hypothesis–action loop and evidential reasoning | published/preprint record |
| REF-ATHAFI | [ATHAFI](https://arxiv.org/abs/2003.03663) | adaptive collection guided by hypotheses | preprint record |
| REF-THREATRAPTOR | [ThreatRaptor](https://arxiv.org/abs/2101.06761) | behavior-to-query synthesis and execution | published demo record |
| REF-MITRE-HUNT | [MITRE threat hunting training](https://attack.mitre.org/resources/learn-more-about-attack/training/threat-hunting/) | hypothesis, data requirement and collection-gap workflow | official documentation |
| REF-MITRE-DC | [MITRE Data Components](https://attack.mitre.org/datacomponents/) | behavior-oriented evidence vocabulary | official documentation |
| REF-MITRE-ANALYTICS | [MITRE Analytics](https://attack.mitre.org/analytics/) | detection behavior separated from platform syntax | official documentation |
| REF-MICROSOFT | [Microsoft Threat Hunting Assistant](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-security-copilot-threat-hunting-assistant) | schema-aware query generation and refinement | official documentation |
| REF-USENIX-TH | [Threat Hunting Teams and Organizations](https://www.usenix.org/system/files/sec24fall-prepub-71-maxam.pdf) | evidence about real-world hypothesis/data-driven practice | USENIX Security 2024 |
| REF-CDB | [Cyber Defense Benchmark](https://arxiv.org/abs/2604.19533) | open-ended LLM cyber defense remains difficult to benchmark | preprint record |
| REF-RAG-SEC | [RAG for Security Incident Analysis](https://arxiv.org/abs/2603.18196) | targeted retrieval and compact context | preprint record |
| REF-CASCADE | [Cluster, Route, Escalate](https://arxiv.org/abs/2606.27457) | cost-aware escalation of hard cases | preprint record |
| REF-OCSF | [OCSF](https://ocsf.io/) | semantic normalization while retaining native records | official project |
| REF-OTEL | [OpenTelemetry Events](https://opentelemetry.io/docs/specs/semconv/general/events/) | semantic conventions are not a complete query universe | official specification |
| REF-SURICATA | [Suricata EVE JSON](https://docs.suricata.io/en/suricata-8.0.0/output/eve/eve-json-format.html) | evolving native event schemas must be preserved | official documentation |

## 2. Decision traceability

| Implementation decision | Literature basis | Status in this repo | Evidence/tests |
|---|---|---|---|
| Start from hypothesis/question, not alert | REF-ECTH, REF-ATHAFI, REF-MITRE-HUNT | adapted | `tests/unit/test_semantic_compiler.py` |
| Convert behavior into typed requirements | REF-MITRE-DC, REF-THREATRAPTOR | adapted | compiler and phase-1 tests |
| Capability validation before query | REF-THREATRAPTOR, REF-MICROSOFT | adapted | phase-2 and provider tests |
| `Cell` excludes `EventFamily` | REF-OCSF, REF-OTEL, REF-SURICATA | composed thesis decision | phase-0 contract tests |
| Preserve native records and unknown fields | REF-OCSF, REF-OTEL, REF-SURICATA | adapted | phase-3/phase-6 tests |
| Query templates before LLM fallback | REF-THREATRAPTOR, REF-MICROSOFT, REF-RAG-SEC | adapted | planner tests |
| Evidence cards instead of raw-ledger prompts | REF-RAG-SEC plus engineering need | proposed/implemented | grouping and prompt-boundary tests |
| Competing hypotheses and typed compatibility | REF-ECTH, REF-ATHAFI | adapted | phase-4 tests |
| Bounded escalation and cost ledger | REF-CASCADE, REF-CDB | adapted | cost and engine-refinement tests |
| Incomplete result cannot become negative evidence | provider completeness contracts and incomplete-information reasoning | composed | negative-control tests |
| Coverage-aware stopping | literature motivates uncertainty; exact rule is ours | proposed/implemented | controller and live replay tests |
| Semantic compilation instead of request keyword guessing | REF-THREATRAPTOR, REF-MICROSOFT, REF-CDB | engineering decision | semantic compiler tests; no production keyword classifier |
| Search hints isolated from evidence/Cells | epistemic separation required by this design | proposed/implemented | `test_6_search_hints_never_become_evidence` |
| Explicit hypothesis classes instead of ID/text classification | anti-bias implementation refinement | implemented | reasoning, CLI and compiler tests |

## 3. What the sources do and do not prove

The cited work motivates hypothesis-driven collection, behavior-oriented data
requirements, query synthesis, adaptive escalation and evidence-aware
reasoning. No source proves this repository’s exact Cell, EvidenceCard,
provider contract, LLM budget or stopping rule.

The following claims are explicitly not made:

- ATT&CK, OCSF or OpenTelemetry is a complete telemetry ontology.
- A PoC is required for threat hunting.
- A vulnerable asset proves exploitation.
- A successful query proves complete visibility.
- Sampling proves absence outside its frame.
- LLM confidence is ground truth.
- A benchmark proves production readiness.
- The current requirement vocabulary covers every attack.
- The current repository has live EDR or IDS adapters; those remain extension
  work beyond the current CDB/Splunk implementation.

## 4. Evidence labels

```text
OFFICIAL-DOC — vendor/standards/project documentation
PUBLISHED    — peer-reviewed publication or published demo
PREPRINT     — not independently peer-reviewed here
ADAPTED      — external principle transferred to this design
COMPOSED     — multiple principles combined into a thesis mechanism
PROPOSED     — mechanism requiring further experiment
MEASURED-HERE — result from this implementation/test run only
```
