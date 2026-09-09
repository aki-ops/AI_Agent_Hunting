# Reference Architecture for Evidence-Grounded Threat Hunting

## Decision

The system shall be an **evidence-seeking investigation agent**, not a fixed
playbook engine and not an unconstrained LLM agent. Its universal unit of
reasoning is a graph of claims whose truth must be established from telemetry.

The universal architecture is:

```text
Request
  -> Provider Census
  -> Semantic Claim-Plan Proposal
  -> Plan Validation
  -> Capability Binding and Action Selection
  -> Safe Native Query Execution
  -> Observation / Fact / Evidence Graph Update
  -> Claim Verification and Bounded Replanning
  -> Grounded Answer, Coverage and Cost Report
```

The pipeline is universal because every request follows the same contracts.
It is not template-driven because neither the request words nor an answer type
can select a prewritten path such as “email -> message -> recipient”, “Tor ->
process”, or “CVE -> web logs”. The plan is constructed from the request,
live capabilities, and evidence acquired during the current run.

This is a thesis engineering composition. Its individual principles are
supported by research and standards; the exact contracts, policies and
thresholds must be empirically evaluated, not presented as externally proven.

---

## Scope and non-goals

The agent accepts a natural-language question, hypothesis, CTI/TTP/IOC/CVE,
or scheduled hunt. It may return a factual answer, supported/refuted hypothesis
assessment, or an explicit inconclusive result with coverage gaps.

It is not an autonomous incident-response system, a malware exploit generator,
or an omniscient detector. It cannot prove absence from incomplete telemetry.
It must distinguish a factual lookup, causal reconstruction, threat hypothesis,
and population discovery through their declared claims—not by a keyword router.

The distinction matters: threat hunting practice is diverse rather than a
single mandated workflow.^1 Provenance systems demonstrate the value of causal
graphs for attack reconstruction, but they do not prescribe an attack graph for
every security question.^2 ^3

---

## Universal data model

### 1. Request

**Input:** user content, optional entities, time policy and provider hints.  
**Output:** immutable `HuntRequest`.

The request is treated as an objective, not as evidence. User text and all
retrieved log text are untrusted instructions; neither can mutate scope,
provider policy, budget or final verdict.

### 2. Claim graph

**Input:** `HuntRequest`, compact provider census.  
**Output:** `ClaimGraph` proposed by the LLM, then schema-validated.

A claim is a testable statement, not a scenario label:

```text
Claim {
  subject: typed entity or variable,
  predicate: attribute | relation | behaviour | absence-with-controls,
  object/value type: typed entity, value or event condition,
  provenance: user_request | CTI_source | verified_observation,
  acceptance_rule: required facts/relations and completeness conditions,
  refutation_rule: optional explicit contradiction,
  dependencies: other claim IDs,
  expansion_policy: allowed only on ambiguity, missing anchor, or coverage gap
}
```

Examples are deliberately written in one grammar:

```text
attribute(person: Amber, personal_email, value: ?)
attribute(artifact: Tor Browser, version, value: ?)
relation(person: Amber, visited, domain: ?)
behaviour(scope: organisation, matches, CVE-X observable condition)
```

There is no `is_email`, `is_tor`, `is_cve`, `request_mode`, event-family or
scenario-template branch. Labels may be retained solely for reporting and
experimental stratification, never for action selection.

**Scientific basis:** ThreatRaptor demonstrates a structured intermediate
behaviour graph from unstructured CTI before query synthesis; AIQL demonstrates
typed investigation query semantics.^4 ^5 Neither source proves this exact
claim schema or that free-text LLM compilation is reliable; those are local
design hypotheses.

### 3. Capability graph

**Input:** live provider census and versioned adapter descriptors.  
**Output:** `CapabilityGraph`.

Each provider operation declares:

```text
Operation {
  operation_id, provider, native partitions,
  required input entity/value kinds,
  output fact kinds and fields,
  time/retention limits, permission requirements,
  pagination and completeness semantics,
  upper-bound cost/scan behaviour
}
```

The provider census always runs first and produces a signed/audited snapshot:
reachable providers, permitted partitions, schemas, fields, retention,
timestamps, completeness support, operation catalogue and exclusions. A
fallback provider is usable only when it can satisfy at least one outstanding
claim. Otherwise the outcome is `UNSUPPORTED_CAPABILITY` or `UNREACHABLE`, not
a misleading search over unrelated records.

**Scientific basis:** AIQL separates logical investigation operations from
execution optimisation; OCSF provides a vendor-neutral extensible schema model;
Microsoft's hunting assistant describes schema/table-aware assistance.^5 ^6 ^7
The precise census protocol and fallback policy are thesis implementation
choices.

### 4. Evidence graph

**Input:** immutable native observations returned by an adapter.  
**Output:** `EvidenceGraph` containing observation citations, normalized facts,
candidate relations and verified claim status.

Every observation retains provider ID, native type, raw fields, query ID,
timestamp, cursor/completeness and integrity metadata. Normalized facts are
additive aliases—not replacements for native fields. Unknown source types and
fields remain stored and queryable.

Only a claim verifier may promote a candidate to `SUPPORTED`, `REFUTED`, or
`PARTIAL`. It checks cited observation IDs, subject/value field roles, temporal
constraints, query completeness and the claim's acceptance rule. A declared
schema column is not a fact value. A row returned by a query against the wrong
source is not evidence for the claim.

**Scientific basis:** SLEUTH and HOLMES support provenance/dependency evidence
for multistage reconstruction; OmegaLog argues for preserving/reconciling
multiple contexts; OCSF supports semantic normalization with extensibility.^2
^3 ^8 ^6 The repository's exact fact roles and verifier are local engineering.

---

## Reference execution loop

| Step | Input → output | Who decides | Invariant | Foundation / status |
|---|---|---|---|---|
| A. Provider census | configured environment → capability graph | Adapter, deterministic | No content query before source/schema state is recorded. | Supported by schema-aware hunting practice; exact method is local.^7 |
| B. Claim-plan proposal | request + compact capability graph → claims/dependencies/acceptance rules | LLM | No raw SPL/KQL/SQL, no asserted evidence, every claim records provenance. | Structured intermediate representation is supported; exact prompt/schema is local.^4 ^5 |
| C. Plan validation | proposed graph → accepted/rejected/reduced graph | Deterministic policy | Each non-prerequisite claim must trace to request, CTI, or verified evidence. | Defence-in-depth is supported; rules are local.^9 |
| D. Capability binding | outstanding claim + capabilities → candidate operations | Deterministic binder | Candidate operation must accept known inputs and be able to output required facts. | Supported by typed query/capability principles.^5 ^6 |
| E. Action selection | candidates + cost/coverage/evidence state → one bounded action | Deterministic scorer; LLM may rank ties only | Never route on a scenario label; no query without a claim it can reduce. | Adaptive evidence collection is supported; scoring function is local.^10 |
| F. Native execution | operation + parameters → `QueryResult` envelope | Adapter, deterministic | Parameterized/allowlisted query, pagination, explicit `complete`; row count is not EOF. | Query safety/completeness policy is local, necessary for valid negative claims. |
| G. Evidence update | raw rows → facts/cards/candidate edges | Deterministic extractor | Native rows append-only; card is a view, never a replacement. | Supported by provenance/semantic fusion principles.^2 ^8 |
| H. Claim verification | evidence graph + acceptance rule → claim status | Deterministic verifier | No conclusion without citations and required completeness/observability controls. | Evidence-grounding principle; exact logic is local.^9 |
| I. Bounded replan | unresolved claims + delta cards → revised claims or next action | LLM only at a decision boundary | New claim needs provenance; repeated non-progress is blocked. | Plan–retrieve–generate supports iterative evidence-conditioned planning; gating is local.^11 |
| J. Stop and report | claim states + coverage + budgets → final account | Deterministic controller; LLM explains only verified evidence | `NO_EVIDENCE_FOUND` is never rendered as benign when coverage is inadequate. | Hypothesis/evidential hunting supports explicit uncertainty; stop taxonomy is local.^10 ^12 |

### Selection rule

At each loop, the controller considers only operations bound to an unresolved
claim. It prefers an action with the greatest expected reduction of unresolved
claim uncertainty per bounded cost, subject to input availability,
completeness and provider health.

```text
score(action) = expected_claim_reduction
                * completeness_confidence
                * source_relevance
                / bounded_cost
```

This is a transparent engineering heuristic, not a scientifically validated
optimal formula. It is included so that future experiments can compare it with
LLM ranking and ablations, rather than hiding policy inside a prompt.

---

## LLM boundary and dependence

The architecture deliberately makes LLM intelligence valuable but not
authoritative.

| Responsibility | LLM allowed? | Deterministic control |
|---|---:|---|
| Interpret unfamiliar natural language and propose claims | Yes | Schema, provenance and objective validator |
| See source capabilities and suggest a semantic operation | Yes, only among filtered candidates | Capability binder accepts/rejects |
| Generate native provider query syntax | No | Adapter owns compilation and query safety |
| Admit telemetry into the ledger | No | Adapter/envelope checks |
| Determine whether a fact is observed | No | Fact extractor + claim verifier |
| Promote/refute a claim | No | Acceptance/refutation rule + citations |
| Explain a verified result and uncertainty | Yes | Citation check; explanation cannot introduce a value |
| Stop for coverage/budget/safety | No | Controller |

This is the strongest practical compromise currently available: free-form
language requires a semantic model, while tool use and factual adjudication
need deterministic boundaries. Recent work on safe LLM tool use similarly
separates non-deterministic intent/planning from verified execution.^9 The
ExCyTIn benchmark confirms that end-to-end cyber investigation remains a hard
task for current models, so model narrative alone is not a valid verdict.^13

The implementation must record model/version, prompt version, tokens, latency,
retries and parse failures. A model upgrade is a new experimental condition,
not an invisible quality improvement.

---

## Required report contract

The analyst report contains only:

1. Request and answer contract.
2. Claim plan: each required claim, provenance and reason it was necessary.
3. Evidence: cited observations/facts, explanation and explicit gaps.
4. Queries: logical purpose, provider operation, native query, completeness and
   result cardinality.
5. Final answer/claim states, coverage and limitations.
6. Cost: LLM calls/tokens/latency/USD estimate and query/runtime cost.

Raw observations remain accessible through IDs and stored artifacts, but do not
overwhelm the main report.

---

## Evaluation and acceptance gate

No architecture claim is accepted solely because one scenario returns a
plausible answer. The following metrics are mandatory.

| Layer | Ground truth | Metric |
|---|---|---|
| Claim planning | Annotated required/forbidden claims; allow multiple valid plans | obligation precision, recall and F1; unsupported-expansion rate |
| Retrieval | Relevant observation IDs/rows | evidence precision, recall@k, query completeness accuracy |
| Correlation | Annotated evidence graph | node/edge precision, recall and F1 |
| Final factual answer | Canonical answer values and acceptable aliases | exact match, value precision/recall/F1, citation-grounding rate |
| Hunt detection | Campaign/TTP labels and scope ground truth | TP/FP/FN precision, recall, F1; time-to-evidence |
| Cost/liveness | Per-run telemetry | tokens, LLM calls, latency, retries, queries, scan volume, budget-stop rate |

F1 is invalid where no ground truth exists. In live production telemetry, the
system can report verified facts and coverage, but cannot truthfully claim a
global false-negative rate. Use labelled question-answer cases for factual
lookup, labelled evidence graphs for multihop investigation (the ExCyTIn design
is a useful model), and labelled campaign/provenance datasets for hunting.^13
DARPA Transparent Computing is appropriate for provenance/campaign replay;
provider-specific scenario data is needed for Splunk/EDR/IDS adapters.^14

Minimum acceptance tests:

- Counterfactual requests with overlapping words must yield only the claims
  actually required, with no keyword/template route.
- Every final answer value must point to an observation/fact ID and a complete
  enough query.
- Provider failure/fallback cannot substitute unrelated source records.
- Missing value fields cannot be inferred from schema metadata.
- Partial telemetry cannot support a negative conclusion.
- Claim, evidence-edge and answer F1 are reported separately by dataset and
  request family, together with cost.

---

## Migration decision for this repository

The current relation-first compatibility code and especially any
`is_email`/keyword-derived graph construction conflict with this reference
architecture. They should be removed only as part of a controlled migration:

1. Introduce `Claim`, `ClaimGraph`, plan provenance and acceptance rules.
2. Make the existing case graph a projection of validated claims and observed
   evidence, not the input-specific planner.
3. Extend capability descriptors with typed inputs/outputs and source
   relevance; preserve adapter-owned query compilation.
4. Replace keyword/template routing with semantic-plan validation.
5. Add the acceptance tests and a labelled evaluation corpus before claiming
   generality or reporting F1.
6. Once tests pass, reconcile `01`–`04` against this document and retire
   relation-first compatibility prose.

No live provider expansion should precede these invariants. A provider is an
adapter implementation; it must not force a new architecture.

---

## Sources

1. Maxam, A. et al. “An Interview Study on Third-Party Cyber Threat Hunting
   Processes in the U.S. Department of Homeland Security.” *USENIX Security*,
   2024. [Paper](https://www.usenix.org/system/files/sec24fall-prepub-71-maxam.pdf).
2. Hossain, M. et al. “SLEUTH: Real-time Attack Scenario Reconstruction from
   COTS Audit Data.” *USENIX Security*, 2017.
   [Paper](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-hossain.pdf).
3. Milajerdi, S. M. et al. “HOLMES: Real-time APT Detection through Correlation
   of Suspicious Information Flows.” *IEEE S&P*, 2019.
   [Record](https://ieeexplore.ieee.org/document/8835390/).
4. Gao, P. et al. “Enabling Efficient Cyber Threat Hunting with Cyber Threat
   Intelligence.” *IEEE ICDE*, 2021.
   [DOI](https://doi.org/10.1109/ICDE51399.2021.00024),
   [implementation](https://github.com/peng-gao-lab/threatraptor).
5. Gao, P. et al. “AIQL: Enabling Efficient Attack Investigation through
   Dataset-Aware Querying.” *USENIX ATC*, 2018.
   [Paper](https://www.usenix.org/system/files/conference/atc18/atc18-gao.pdf).
6. Open Cybersecurity Schema Framework. [OCSF documentation](https://ocsf.io/).
7. Microsoft. “Threat Hunting Assistant in Microsoft Defender.”
   [Documentation](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-security-copilot).
8. Hassan, W. U. et al. “OmegaLog: High-Fidelity Attack Investigation via
   Transparent Multi-layer Log Analysis.” *NDSS*, 2020.
   [Record](https://experts.illinois.edu/en/publications/omegalog-high-fidelity-attack-investigation-via-transparent-multi/).
9. Chen, X. et al. “Towards Verifiably Safe Tool Use for LLM Agents.”
   *ICSE*, 2026. [DOI](https://doi.org/10.1145/3786582.3786839).
10. Marín, G. et al. “ATHAFI: An Adaptive Threat Hunting Framework for
   Information Security.” 2020. **Preprint.**
   [arXiv](https://arxiv.org/abs/2003.03663).
11. Lyu, D. et al. “Retrieve-Plan-Generation: An Iterative Planning and
   Answering Framework for Knowledge-Intensive LLM Generation.” *EMNLP*,
   2024. [Paper](https://aclanthology.org/2024.emnlp-main.270/).
12. Schlette, D. et al. “Evidential Cyber Threat Hunting.” 2021.
   **Preprint.** [arXiv](https://arxiv.org/abs/2104.10319).
13. Wu, Y. et al. “ExCyTIn-Bench: Evaluating LLM Agents on Cyber Threat
   Investigation.” Microsoft Research / ICML 2026.
   [Publication](https://www.microsoft.com/en-us/research/publication/excytin-bench-evaluating-llm-agents-on-cyber-threat-investigation/).
14. DARPA I2O. “Transparent Computing Dataset.”
   [Repository](https://github.com/darpa-i2o/Transparent-Computing/blob/master/README.md).
