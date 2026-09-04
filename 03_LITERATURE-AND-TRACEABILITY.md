# 03 — LITERATURE AND TRACEABILITY (v4)

This file separates literature-supported principles from thesis design choices.

## 1. Source register

| Tag | Source | Supports | Evidence level |
|---|---|---|---|
| REF-ECTH | [Evidential Cyber Threat Hunting](https://arxiv.org/abs/2104.10319) | knowledge–hypothesis–action and human-machine reasoning | abstract/HTML verified; workshop paper |
| REF-ATHAFI | [ATHAFI](https://arxiv.org/abs/2003.03663) | adaptive data collection and hypothesis testing | abstract/HTML verified; preprint |
| REF-THREATRAPTOR | [ThreatRaptor](https://arxiv.org/abs/2101.06761) | threat behavior → structured query → execution | abstract/HTML verified; ICDE demo |
| REF-MITRE-HUNT | [MITRE hunting training](https://attack.mitre.org/resources/learn-more-about-attack/training/threat-hunting/) | hypotheses, data requirements and collection gaps | official documentation |
| REF-MITRE-DC | [MITRE Data Components](https://attack.mitre.org/datacomponents/) | behavior-relevant evidence concepts | official documentation |
| REF-MITRE-ANALYTICS | [MITRE Analytics](https://attack.mitre.org/analytics/) | behavior strategy separated from platform logic | official documentation |
| REF-MICROSOFT | [Microsoft Threat Hunting Assistant](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-security-copilot-threat-hunting-assistant) | schema discovery, query generation and iterative refinement | official documentation |
| REF-USENIX-TH | [Threat Hunting Teams and Organizations](https://www.usenix.org/system/files/sec24fall-prepub-71-maxam.pdf) | real teams use hypothesis- and data-driven hunting | USENIX Security 2024 |
| REF-CDB | [Cyber Defense Benchmark](https://arxiv.org/abs/2604.19533) | open-ended LLM hunting remains difficult | abstract/HTML verified; preprint |
| REF-RAG-SEC | [RAG for Security Incident Analysis](https://arxiv.org/abs/2603.18196) | targeted retrieval and compact context | abstract/HTML verified; preprint |
| REF-CASCADE | [Cluster, Route, Escalate](https://arxiv.org/abs/2606.27457) | cost-aware cascade for hard cases | abstract verified; preprint |
| REF-OCSF | [OCSF](https://ocsf.io/) | semantic normalization with native records | official project |
| REF-OTEL | [OpenTelemetry Events](https://opentelemetry.io/docs/specs/semconv/general/events/) | semantic conventions are not query universe | official specification |
| REF-SURICATA | [Suricata EVE JSON](https://docs.suricata.io/en/suricata-8.0.0/output/eve/eve-json-format.html) | evolving native event records | official documentation |

## 2. Decision traceability

| Decision | Basis | Relationship | Must be measured |
|---|---|---|---|
| hypothesis-driven input | REF-ECTH, REF-ATHAFI, REF-MITRE-HUNT | inherited/adapted | sparse-input quality |
| behavior → EvidenceRequirement | REF-MITRE-DC, REF-THREATRAPTOR | adapted | requirement completeness |
| capability before query | REF-THREATRAPTOR, REF-MICROSOFT | adapted | binding/execution success |
| Cell excludes EventFamily | REF-OCSF, REF-OTEL, REF-SURICATA | composed engineering decision | unknown-source boundary |
| native observation preservation | REF-OCSF, REF-OTEL, REF-SURICATA | adapted | unknown-record retention |
| templates before LLM | REF-THREATRAPTOR, REF-MICROSOFT, REF-RAG-SEC | adapted | cost and recall |
| EvidenceCard grouping | REF-RAG-SEC plus thesis need | proposed | grouped-vs-row recall |
| competing hypothesis compatibility | REF-ECTH, REF-ATHAFI | adapted | premature rejection |
| bounded LLM escalation | REF-CASCADE, REF-CDB | adapted | calibration and cost |
| incomplete ≠ negative | incomplete-information theory/provider contracts | composed | false-negative rate |
| coverage-aware stopping | literature motivates uncertainty; exact mechanism is ours | proposed | stopping correctness |

## 3. Claims explicitly not made

- ATT&CK is not a complete telemetry ontology.
- A PoC is not required for hunting.
- Vulnerable asset does not prove exploitation.
- Successful query does not prove complete visibility.
- Sampling does not prove absence outside its frame.
- LLM confidence is not ground truth.
- A benchmark does not prove production readiness.
- The requirement vocabulary covers every attack.

## 4. Evidence levels

```text
OFFICIAL-DOC — vendor/standards/project documentation
PUBLISHED — reviewed publication
PREPRINT — not independently peer-reviewed here
ADAPTED — principle transferred to our design
PROPOSED — thesis mechanism requiring experiment
MEASURED-HERE — result from our implementation only
```
