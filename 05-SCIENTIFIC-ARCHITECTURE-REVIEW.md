# 05 — SCIENTIFIC ARCHITECTURE REVIEW (v9)

## Review conclusion

The v9 **Evidence-Grounded Progressive Hunt Graph** is a defensible thesis architecture, not a scientifically proven optimum and not yet a completed implementation.

Its strongest property is separation of authority:

```text
LLM interpretation proposal
  != accepted semantic contract
  != provider retrieval capability
  != observed row
  != verified semantic relation
  != verified final outcome
```

The architecture should be retained if evaluation tests these boundaries independently. It should be rejected or simplified if an executable direct-query baseline achieves comparable quality and safety at lower total cost.

## Supported design principles

| Principle | Evidence | Valid conclusion |
|---|---|---|
| Graph-based, multi-step investigation | [SLEUTH](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-hossain.pdf), [HOLMES](https://ieeexplore.ieee.org/document/8835390/), [Kestrel](https://kestrel.readthedocs.io/en/latest/theory.html), [ExCyTIn-Bench](https://www.microsoft.com/en-us/research/publication/excytin-bench-evaluating-llm-agents-on-cyber-threat-investigation/) | Relations and intermediate evidence should be explicit and auditable |
| Typed semantic query layer | [AIQL](https://www.usenix.org/conference/atc18/presentation/gao), [ThreatRaptor](https://github.com/peng-gao-lab/threatraptor) | Separate investigation intent from provider-native query syntax |
| Progressive source/schema discovery | [AutoLink](https://ojs.aaai.org/index.php/AAAI/article/view/40672), [MDB-Link](https://arxiv.org/abs/2608.09588), [CHESS](https://arxiv.org/abs/2405.16755) | Full-schema prompting is avoidable; incremental discovery is a credible candidate |
| Hypothesis/action/evidence cycle | [Evidential CTH](https://arxiv.org/abs/2104.10319), [ATHAFI](https://arxiv.org/abs/2003.03663) | Hypotheses and actions should update from evidence, not only keywords |
| Diverse human hunting processes | [Maxam and Davis, USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/maxam) | Do not encode one universal scenario path; support hypothesis and data-driven discovery |
| Safe bounded tool use | [Verifiably Safe Tool Use](https://doi.org/10.1145/3786582.3786839) | External validators should constrain model-proposed actions |
| Selective abstention | [Selective Classification](https://arxiv.org/abs/1805.08206) | Measure error versus coverage; abstention is not automatically success |

## What the literature does not prove

The sources do not establish:

- that arbitrary natural language can be converted into the correct graph without independent review;
- that a finite relation registry covers all future hunts;
- that AND/OR/GATE planning is optimal for telemetry investigation;
- that F0–F4 beats exhaustive discovery or a simpler baseline;
- that five LLM calls or 15,000 tokens is an optimal budget;
- that a design validated on one Splunk dataset generalizes to SIEM, EDR and IDS providers;
- that a cited row semantically proves the user's intended claim.

## Architecture corrections adopted in v9

1. `OutcomeContract` replaces universal `AnswerContract` so the kernel supports factual answers, hypothesis verdicts and population discovery.
2. `Semantic Acceptance Gate` addresses the gap between a structurally valid graph and a semantically faithful interpretation.
3. Proof authority moves from operation metadata to an executable, approved ProofContract evaluator.
4. Candidate ambiguity is evaluated against slot cardinality rather than a fixed global fanout.
5. Graph dependencies must execute their declared AND/OR/GATE semantics.
6. One deterministic controller owns recovery and stopping.
7. Evaluation must run the real pipeline; assigned metrics are not evidence.

## Required empirical evidence

Evaluation must separate:

- request-to-graph precision, recall and forbidden expansion;
- source/capability retrieval recall and unexamined coverage;
- query denotation and execution completeness;
- relation/transition proof precision and recall;
- candidate binding error;
- answer exactness and citation grounding;
- abstention risk-coverage;
- LLM, backend, controller and analyst cost;
- performance against executable B0/B1 baselines.

Until these are measured, the correct description is “evidence-informed target architecture under implementation.”

