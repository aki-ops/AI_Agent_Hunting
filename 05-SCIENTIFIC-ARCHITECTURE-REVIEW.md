# 05 — SCIENTIFIC ARCHITECTURE REVIEW (v8)

## Review conclusion

No single external paper validates the exact architecture in this repository.
The defensible approach is to compose established principles and explicitly
test the local composition:

```text
Request -> Semantic Compilation C1 (GoalGraph + AnswerContract)
        -> Progressive Frontier F0–F4 -> Controlled Binding & CandidateSet
        -> QueryIntent (EXPLORE / DISCRIMINATE / PROVE) & Native Gate
        -> Evidence Pipeline -> ProofContract Evaluation -> 9-State Stopping
```

This is a general contract, not a universal attack path. It must not contain
branches such as `if email`, `if Tor`, `if CVE`, `event_family` or
`request_mode` that manufacture a scenario.
For the comprehensive strategic critiques on science, cost, and scalability,
see [07-STRATEGIC-RESEARCH-REVIEW.md](07-STRATEGIC-RESEARCH-REVIEW.md).
For the candidate master plan and proof-grounded execution specifications,
see [08-EVIDENCE-BASED-REARCHITECTURE-PLAN.md](08-EVIDENCE-BASED-REARCHITECTURE-PLAN.md).

## What external work supports

| Principle used in v8 | Evidence | Limit |
|---|---|---|
| Provenance and multi-hop evidence | [SLEUTH](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-hossain.pdf), [HOLMES](https://ieeexplore.ieee.org/document/8835390/), [OmegaLog](https://experts.illinois.edu/en/publications/omegalog-high-fidelity-attack-investigation-via-transparent-multi/) | Supports causal reconstruction, not a mandatory path for every question. |
| Typed logical query layer | [AIQL](https://www.usenix.org/system/files/conference/atc18/atc18-gao.pdf), [ThreatRaptor](https://github.com/peng-gao-lab/threatraptor) | Supports an intermediate representation, not our exact SemanticGoalGraph. |
| Hypothesis/evidence/action loop | [Evidential Cyber Threat Hunting](https://arxiv.org/abs/2104.10319), [ATHAFI](https://arxiv.org/abs/2003.03663), [TaHiTI](https://www.nvb.nl/themas/veilig-bankieren/tahiti/) | Supports uncertainty and adaptive collection; budgets/stopping are local. |
| Heterogeneous schema/capability binding | [OCSF](https://ocsf.io/), [MITRE Data Components](https://attack.mitre.org/datacomponents/), [Microsoft Threat Hunting Assistant](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-security-copilot) | No standard covers every provider-native field. |
| Bounded LLM/tool execution | [ExCyTIn-Bench](https://www.microsoft.com/en-us/research/publication/excytin-bench-evaluating-llm-agents-on-cyber-threat-investigation/), [Verifiably Safe Tool Use](https://doi.org/10.1145/3786582.3786839) | Current LLMs remain unreliable on multistep cyber investigation. |
| Progressive schema discovery | [AutoLink](https://arxiv.org/abs/2402.13204), [MDB-Link](https://arxiv.org/abs/2403.01567) | Explores schema incrementally without full context exposure. |
| Flexible hunting workflow | [Maxam et al., USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/maxam) | Shows process diversity; does not specify our implementation. |

## What is our engineering contribution

The following are not externally proven and must be evaluated in this repo:

- `GoalGraph`, `AnswerContract`, `SourceCard`, `ProofContract`, and `CandidateSet` schemas;
- The 5-stage progressive frontier F0–F4 and unexamined coverage manifest;
- Controlled entity binding and ambiguity resolution via `DISCRIMINATOR`;
- Quarantined AST-gated native query synthesis and SID lifecycle enforcement;
- Bounded replanning, card limits, and the 9-state stopping taxonomy;
- Claim, evidence-edge, answer F1, and financial cost results ($C_{run}$);
- Generalization from Splunk/BotSv2 to other providers.

## Review of the former design

The former design was unsafe when it let an answer keyword create a fixed graph,
for example a mail question automatically becoming a message/recipient/role
investigation. It also treated identity-to-endpoint as universally mandatory
and could fall back to an unrelated provider. These are route-selection and
source-selection errors, not merely query syntax errors.

The v8 design corrects this by making the LLM propose claims, deterministic
code validate them, adapters bind them to real capabilities, and evidence
verification decide what can be asserted.

## Evidence required before architectural claims

- Plan faithfulness: required claims are covered without unsupported expansion.
- Provider correctness: only sources whose outputs satisfy the claim are used.
- Evidence grounding: every final value has an observation/fact citation.
- Causal correctness: evidence-edge precision/recall/F1 on labelled graphs.
- Hunt effectiveness: campaign/TTP precision/recall/F1 on labelled scope.
- Operational quality: latency, query count, tokens, cost and budget-stop rate.

F1 cannot be reported honestly on unlabeled production telemetry. Use labelled
question-answer cases, evidence-graph cases, and campaign/provenance replays.
The [DARPA Transparent Computing dataset](https://github.com/darpa-i2o/Transparent-Computing)
is suitable for provenance-oriented replay; provider-specific labelled data is
still required for SIEM/EDR/IDS claims.

