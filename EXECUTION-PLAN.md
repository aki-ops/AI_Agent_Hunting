# Evidence-Grounded Human-in-the-Loop Threat Investigation Agent
## Implementation, Experiment and Literature-Traceability Plan

**Architecture status: FROZEN.** This document does not redesign it. Every section turns the frozen five-module design into executable, testable, traceable work.

**Citation verification scheme used throughout §22 and all traceability tables:**

| Level | Meaning |
|---|---|
| **FULL-TEXT** | I read the paper body or the released repository in this project |
| **INDEX-VERIFIED** | Title, authors, year and venue confirmed via an academic index; body **not** read |
| **UNVERIFIED** | Cited from secondary description; **must be checked before thesis submission** |

Nothing below is labelled higher than the evidence supports. Any row marked UNVERIFIED is a task in §3, not a reference you may cite yet.

---

# 1. Executive Summary

The project builds a threat-investigation agent in which an LLM proposes explanations and translates queries, and **everything else is deterministic**: evidence storage, field extraction, taint labelling, constraint checking, action ordering, negative-evidence semantics, stopping, and escalation. Target LLM usage is 8–16 calls per investigation.

Five experiments were already run. Three findings shape the entire plan:

1. **DiagChain MAIN-69 cannot be used to select retrieval policies.** A content-free mean-IDF ranking scored 0.662 there, beating every designed policy; the same null gives 0.68–1.08× on CDB. Retrieval work goes on CDB; MAIN-69 is for evidence-*use* scoring only.
2. **Reachability, not policy, is the binding constraint.** Held-out evidence reachable by entity pivot: mean 0.272, per-chain 0.006/0.239/0.571 (n=3). The gap between best and worst policy (0.046) is a quarter of the gap to the ceiling (0.165).
3. **The coverage alarm is dead.** Fires in 85% of cases at median precision 0.050. Replaced by *coverage-bound reporting*, which is honesty rather than a solution.

The largest single risk to the thesis is that **EXP-02 confirms the 0.272 reachability ceiling at scale**, in which case the contribution is a measured negative result about evidence acquisition plus a defensible epistemic layer — still publishable, but a different thesis than "we built a better hunting agent." Plan for that outcome explicitly (§25, R-05).

---

# 2. Frozen Architecture

```
ALERT → SCOPE FRONTIER
          ↓
        [M1] OBSERVATION LEDGER      deterministic
          ↓ unattributed observations      ↑ observations
        [M2] ABDUCTION ENGINE        LLM
          ↓ proposed explanations
        [M3] CONSTRAINT CHECKER      deterministic (C1,C2,C5 in v1)
          ↓ validated state
        [M4] CONTROLLER              deterministic
          ↓ action                        ↕ human
        [M5] ADAPTER / REPORTER      templates + LLM fallback
          ↓
        TELEMETRY ──────────────────────↺
```

Controller ordering: **STOP → ASK_HUMAN → TEST expectation → CONTROL_QUERY → ABDUCE → EXPAND_SCOPE.**
Terminal states: `STOP_RESOLVED`, `STOP_BOUNDED`.
Query outcomes: `ROWS`, `VALID_NEGATIVE`, `UNKNOWN` (+ diagnostic reason).

---

# 3. Complete Implementation Checklist

Task format: **ID | Component | Purpose | In → Out | Deps | DoD | Tests | Source | Provenance class | Priority**

Provenance classes: `INHERITED` · `ADAPTED` · `COMPOSED` · `ORIGINAL` · `EXPERIMENTALLY-DERIVED` · `ENGINEERING`

## A. Repository / environment

| ID | Purpose | In → Out | Deps | DoD | Tests | Source | Class | Pri |
|---|---|---|---|---|---|---|---|---|
| A-01 | Repo, CI, lint, typed Python 3.10+ | — → skeleton | — | CI green on empty suite | — | — | ENGINEERING | P0 |
| A-02 | Clone + pin CDB; unpack sample | — → 155,350 events | A-01 | `sample.json` + `sample_flags.json` load | smoke | [REF-DATA-01] | INHERITED | P0 |
| A-03 | Clone + pin DiagChain; run `verify_package.py` | — → MAIN-69 | A-01 | SHA-256 manifest verifies | smoke | [REF-EVID-01] | INHERITED | P0 |
| A-04 | ExCyTIn access (needs HuggingFace; **blocked in some environments**) | — → 8 incidents | A-01 | DB container up | smoke | [REF-EVID-02] | INHERITED | P2 |
| A-05 | Deterministic seeding + run manifest (git SHA, config hash, seed) | config → manifest | A-01 | two runs byte-identical | unit | — | ENGINEERING | P0 |
| A-06 | LLM client with cache + call/token counter | prompt → response | A-01 | counter matches provider | unit | — | ENGINEERING | P0 |

## B. Data ingestion

| ID | Purpose | In → Out | Deps | DoD | Tests | Source | Class | Pri |
|---|---|---|---|---|---|---|---|---|
| B-01 | CDB loader → internal event stream | JSON → `RawEvent[]` | A-02 | all 155,350 parse | unit | [REF-DATA-01] | INHERITED | P0 |
| B-02 | CDB flag loader → per-(chain,step) ground truth | flags → labels | B-01 | 8,658 malicious mapped | unit | [REF-DATA-01] | INHERITED | P0 |
| B-03 | DiagChain loader (cards, gt, docs, graphs) | JSON → objects | A-03 | 69 cases load | unit | [REF-EVID-01] | INHERITED | P1 |
| B-04 | **Hidden-target guard**: hard-block `attack_step`, `step_description`, tactic/technique labels, `causal_edges`, support mapping from ever reaching a query or prompt | field access → allow/deny | B-03 | attempted access raises | unit + **security** | E1b | EXPERIMENTALLY-DERIVED | **P0** |

> B-04 is non-negotiable. E1b showed gold prose is 8.5× more similar to its own supporting evidence than to other evidence, and the benchmark's own `input_policy.hidden_targets` lists it as withheld. Enforce in code, not by discipline.

## C. Normalization

| ID | Purpose | In → Out | Deps | DoD | Tests | Source | Class | Pri |
|---|---|---|---|---|---|---|---|---|
| C-01 | Field extractor (Windows EVTX / Sentinel / generic) | `RawEvent` → `fields{}` | B-01 | ≥95% events yield ≥3 typed fields | unit | [REF-EVID-01] | ADAPTED | P0 |
| C-02 | Entity extractor (host, account, process, IP, domain, file, session) | fields → entities | C-01 | precision ≥0.9 on 100 hand-labelled | unit | [REF-RET-04] | ADAPTED | P0 |
| C-03 | **Taint labeller**: per-field `ATTACKER_INFLUENCED` vs `STRUCTURAL` | fields → taint map | C-01 | labels all fields in the fixed field registry | unit + **security** | [REF-INJECT-01] | ADAPTED | P0 |
| C-04 | Timestamp normalizer (UTC, source-local ordering only) | fields → ts | C-01 | monotonic within source | unit | [REF-EVID-01] | INHERITED | P1 |

## D. M1 Observation Ledger

| ID | Purpose | In → Out | Deps | DoD | Tests | Source | Class | Pri |
|---|---|---|---|---|---|---|---|---|
| D-01 | `Observation` store, append-only, provenance | rows → `Observation[]` | C-01..04 | nothing deletable mid-investigation | unit | [REF-EVID-01] | ADAPTED | P0 |
| D-02 | Epistemic typing `OBSERVED` / `TESTIMONY` | source → type | D-01 | testimony never typed OBSERVED | unit | [REF-ARG-01] | ADAPTED | P0 |
| D-03 | Attribution bookkeeping `attributed_by[]` | explanations → status | D-01, F-01 | set ops only, no LLM | unit | [REF-EVID-01] | ADAPTED | P0 |
| D-04 | **Reachability accounting**: sources queried/not, windows covered/not, entity-connected fraction | state → `coverage_bound` | D-01 | recomputed each turn | unit | E6 | **ORIGINAL** | P0 |
| D-05 | Outcome typing `ROWS`/`VALID_NEGATIVE`/`UNKNOWN` + diagnostic | result → outcome | H-03 | `UNKNOWN` unless all LCWA conditions hold | unit | [REF-INCOMP-01],[REF-INCOMP-02] | ADAPTED | P0 |

## E. M2 Abduction Engine

| ID | Purpose | In → Out | Deps | DoD | Tests | Source | Class | Pri |
|---|---|---|---|---|---|---|---|---|
| E-01 | Abduction prompt (always *"what accounts for these?"*, never *"does X hold?"*) | unattributed obs → explanations | D-01 | schema-valid JSON ≥95% | unit | [REF-ABD-01],[REF-ABD-02] | ADAPTED | P0 |
| E-02 | **Prompt input filter**: extracted fields + taint labels only, never raw log text | obs → prompt | C-03, E-01 | raw `content` never in prompt | unit + **security** | [REF-INJECT-01] | ORIGINAL | P0 |
| E-03 | Expectation generation per explanation | explanation → expectations | E-01 | ≥1 testable expectation each | unit | [REF-ABD-04] | ADAPTED | P0 |
| E-04 | Diversity constraint: ≥1 BENIGN, ≥1 MALICIOUS where possible; UNKNOWN permitted | proposals → validated set | E-01 | rejected if violated | unit | [REF-ARG-02] | ADAPTED | P1 |
| E-05 | Explosion control: cap 7 live, merge >80% attribution overlap, drop highest arbitrariness | set → set | E-01, F-06 | cap never exceeded | unit | [REF-ABD-03] | ADAPTED | P1 |

## F. M3 Constraint Checker

| ID | Purpose | Deps | DoD | Tests | Source | Class | Pri |
|---|---|---|---|---|---|---|---|
| F-01 | **C1** schema well-formedness | E-01 | malformed rejected, no state change | unit | [REF-EVID-01] | INHERITED | P0 |
| F-02 | **C2** cited observation exists | D-01 | dangling ref rejected | unit | [REF-EVID-01] | INHERITED | P0 |
| F-03 | **C5** contradiction vs expectations → `WEAKENED` + conflict | E-03 | both explanations stay live | unit | [REF-ABD-04] | ADAPTED | P0 |
| F-04 | **C3** relation re-derivation *(v2)* | C-01 | mismatch → `MISATTRIBUTED` | unit | — | **ORIGINAL, UNSUPPORTED** | P2 |
| F-05 | **C4** taint enforcement *(v2; label in v1)* | C-03 | taint-only attribution can't carry disposition | unit + security | [REF-INJECT-01] | ADAPTED | P2 |
| F-06 | **C6** arbitrariness count *(v2)* | E-01 | count = assumptions with no observational support | unit | [REF-ABD-03] | ADAPTED | P2 |

## G. M4 Controller

| ID | Purpose | Deps | DoD | Tests | Source | Class | Pri |
|---|---|---|---|---|---|---|---|
| G-01 | Action ordering (6 steps, exactly as frozen) | F-* | order deterministic and logged | unit | — | COMPOSED | P0 |
| G-02 | Stop predicate `STOP_RESOLVED` (5 conditions) | D-04, F-03 | blocked while any condition fails | unit | [REF-STOP-01] | ADAPTED | P0 |
| G-03 | Stop predicate `STOP_BOUNDED` + mandatory coverage-bound emission | D-04 | never emitted without bound | unit | [REF-STOP-02], E6 | EXPERIMENTALLY-DERIVED | P0 |
| G-04 | Scope expansion, **adaptive on alert entity-richness** | C-02 | entity-poor path takes broad sampling | unit | E6 | EXPERIMENTALLY-DERIVED | P1 |
| G-05 | Six escalation triggers incl. low entity-connected fraction | D-04 | each independently unit-tested | unit | [REF-HUMAN-01], E6 | COMPOSED | P1 |
| G-06 | Budget accounting (turns, queries, tokens) | A-06 | hard cap enforced | unit | [REF-EVID-01] | INHERITED | P0 |

## H. M5 Adapter / Reporter

| ID | Purpose | Deps | DoD | Tests | Source | Class | Pri |
|---|---|---|---|---|---|---|---|
| H-01 | Intent templates ×7 per backend (`ProcessLineage`, `LogonHistory`, `NetworkConnections`, `PersistenceArtifacts`, `FileWrites`, `DNSQueries`, `AnyEventControl`) | B-01 | all 7 execute on CDB | unit + integration | [REF-RET-05] | ADAPTED | P0 |
| H-02 | LLM fallback for novel intents | A-06 | used <30% of queries | unit | — | ENGINEERING | P1 |
| H-03 | **Control query** executor (`AnyEventControl` on same source/window/host) | H-01 | licenses `VALID_NEGATIVE` iff rows returned | unit | E4/E5 rationale, [REF-INCOMP-02] | **ORIGINAL** | P0 |
| H-04 | Reporter: fixed schema from observation IDs, prose generated from schema, never from raw logs | D-01 | raw log text absent from prompt | unit + **security** | [REF-INJECT-01] | ORIGINAL | P1 |

## I–O (condensed)

| ID | Purpose | DoD | Source | Class | Pri |
|---|---|---|---|---|---|
| I-01 | Human input as `TESTIMONY`, identical constraints, no privilege | testimony never `OBSERVED` | [REF-ARG-01] | ADAPTED | P1 |
| I-02 | Human may force CONTINUE / `STOP_BOUNDED`, **never** `STOP_RESOLVED` while blocked | attempt rejected + logged | [REF-ARG-03] | ADAPTED | P1 |
| I-03 | Conflict record on disagreement (no overwrite) | both retained | [REF-ARG-02] | ADAPTED | P1 |
| J-01 | Append-only audit log of every state transition (actor, precondition, delta) | full replay from log | — | ENGINEERING | P0 |
| J-02 | LLM call log (prompt hash, tokens, purpose, call site) | count matches A-06 | — | ENGINEERING | P0 |
| K-01 | Metric library (§13), all formulas unit-tested on synthetic fixtures | each metric has a known-answer test | — | ENGINEERING | P0 |
| K-02 | Null-baseline library: random, mean-IDF, doc-length, chronological | mandatory in every retrieval run | E4 | **EXPERIMENTALLY-DERIVED** | **P0** |
| L-01 | Experiment runner: paired design, seeds, bootstrap CI, per-case W/L/T | reproduces E4/E6 exactly | E1–E6 | ENGINEERING | P0 |
| L-02 | Held-out-step generator (suffix + random, multiple seeds) | deterministic per seed | E1 | ENGINEERING | P0 |
| M-01 | Injection corpus: adversarial command lines, URLs, DNS, usernames, filenames | ≥100 payloads across S1–S4 taxonomy | [REF-INJECT-01] | ADAPTED | P1 |
| M-02 | Assert LLM never receives raw `content` field | static + runtime check | [REF-INJECT-01] | ORIGINAL | P0 |
| N-01 | Data-contract docs auto-generated from schemas | matches §5 | — | ENGINEERING | P1 |
| O-01 | Thesis artifact generator (tables, figures, claim register) | regenerates §20 from run logs | — | ENGINEERING | P2 |

---

# 4. Technical Dependency Graph

```
A-01 ─┬─ A-02 ─ B-01 ─ B-02 ─┐
      ├─ A-03 ─ B-03 ─ B-04  │
      ├─ A-05                │
      └─ A-06 ────────────┐  │
                          │  ▼
        C-01 ─┬─ C-02 ────┼─ D-01 ─┬─ D-02
              ├─ C-03 ────┤        ├─ D-03 ─── F-01,F-02,F-03
              └─ C-04     │        ├─ D-04 ─── G-02,G-03,G-05
                          │        └─ D-05 ◄── H-03
              E-01 ◄──────┴─ E-02
                │
                ├─ E-03 ─ H-01 ─┬─ H-02
                ├─ E-04         └─ H-03
                └─ E-05
                          G-01 ◄── F-*, E-*, H-*
                          G-04, G-06
        K-01, K-02 ─ L-01, L-02 ─── EXPERIMENTS
```

**Critical path:** A-01 → A-02 → B-01 → C-01 → D-01 → E-01 → F-01 → G-01 → H-01 → first end-to-end run.

---

# 5. Data Contracts

```python
Alert          = {id*, raw*, source*, received_at*, fields?, free_text?}
Seed           = {entities*[], windows*[], source*, raw_ref*}
Scope          = {entities*[], windows*[], sources_queried*[],
                  sources_known*[], frontier*[]}

Observation    = {id*, source*, scope_id*, timestamp*,
                  epistemic_type*: OBSERVED|TESTIMONY,
                  fields*{}, taint*{field: STRUCTURAL|ATTACKER_INFLUENCED},
                  provenance*{query_id, collector, ingest_time},
                  attributed_by*[], demanding?: bool}

Explanation    = {id*, label*, class*: BENIGN|MALICIOUS|UNKNOWN,
                  status*: LIVE|WEAKENED|REJECTED,
                  origin*: LLM|HUMAN,
                  attributions*[{observation_id*, cause*,
                                 status*: SUPPORTED|MISATTRIBUTED|TAINTED}],
                  expectations*[Expectation],
                  arbitrariness?: int, rejection_reason?}

Expectation    = {id*, description*, scope*,
                  test_status*: UNTESTED|CONFIRMED|REFUTED|UNTESTABLE}

Query          = {id*, intent*, scope*, backend*, generated_by*: TEMPLATE|LLM,
                  cost*}
QueryResult    = {query_id*, outcome*: ROWS|VALID_NEGATIVE|UNKNOWN,
                  diagnostic?: SOURCE_UNAVAILABLE|RETENTION_EXPIRED|
                               QUERY_FAILED|OUT_OF_WINDOW|PARTIAL_RESULT|
                               SOURCE_UNHEALTHY|PARSE_FAILED,
                  control_query_id?, rows?}

HumanInput     = {id*, content*, type*: CONTEXT|HYPOTHESIS|CHALLENGE|
                                        RESOLUTION|CONFIRMATION,
                  analyst*, timestamp*}
Conflict       = {id*, observation_ids*[], explanation_ids*[], resolved*: bool}

InvestigationState = {scope*, observations*[], explanations*[], queries*[],
                      conflicts*[], dark_sources*[], coverage_bound*,
                      human*[], stop*}

FinalAccount   = {disposition*: MALICIOUS|BENIGN|UNKNOWN|
                                INSUFFICIENT_EVIDENCE|CONFLICTED,
                  terminal_state*: STOP_RESOLVED|STOP_BOUNDED,
                  chain*[{claim*, observation_ids*[]}],
                  coverage_bound*, residual*, human_confirmed*: bool}
```

**Validation rules.** `VALID_NEGATIVE` requires a non-null `control_query_id` whose outcome is `ROWS`. `TESTIMONY` may never be assigned `OBSERVED`. `attributed_by` is derived, never written by M2. `FinalAccount.coverage_bound` is mandatory in both terminal states.

---

# 6. State Machine

| # | State | Precondition | Action | Trigger | LLM | May change | May NOT change |
|---|---|---|---|---|---|---|---|
| 1 | INIT | alert received | build Seed | M1 | optional | scope | — |
| 2 | SCOPING | frontier non-empty | EXPAND_SCOPE | M4 | no | scope, observations | explanations |
| 3 | OBSERVING | rows returned | mint observations | M1 | **forbidden** | observations, coverage_bound | explanations |
| 4 | ABDUCING | unattributed ≠ ∅ | ABDUCE | M4→M2 | **yes** | *proposals only* | observation state, status |
| 5 | VALIDATING | proposals exist | C1,C2 | M3 | no | explanation status | observations |
| 6 | EXPECTING | explanation LIVE | derive expectations | M2 | yes | expectations | observations |
| 7 | QUERYING | expectation UNTESTED | QUERY | M4→M5 | template/fallback | queries | explanations |
| 8 | CONTROLLING | empty result pending | CONTROL_QUERY | M4→M5 | no | outcome typing | explanations |
| 9 | CONTRADICTING | observation vs expectation | C5 | M3 | no | status→WEAKENED, conflicts | observations |
| 10 | REJECTING | all expectations REFUTED | mark REJECTED + reason | M3 | no | status | delete the record |
| 11 | EXPANDING | unattributed persists | ABDUCE (narrow prompt) | M4→M2 | yes | proposals | status |
| 12 | ESCALATING | any of 6 triggers | ASK_HUMAN | M4 | phrasing only | human[] | observations |
| 13 | STOP_RESOLVED | all 5 conditions | emit FinalAccount | M4 | report only | terminal | — |
| 14 | STOP_BOUNDED | relaxed + bound | emit FinalAccount + bound | M4 | report only | terminal | — |

**Invariant, enforced in code:** transitions 5, 9, 10, 13, 14 are the only ones that change explanation *status*, and none of them involves an LLM.

---

# 7. Module-by-Module Implementation Plan

**M1** — build first, it is the injection boundary and every other module depends on it. Order: C-01 → C-02 → C-03 → D-01 → D-05 → D-04.
**M3** — build second, before any LLM code exists, so the gates are in place the first time a model output arrives. Order: F-01 → F-02 → F-03.
**M4** — build third against a stubbed abduction engine returning fixed explanations. This lets the whole loop be tested with zero LLM calls. Order: G-01 → G-06 → G-02 → G-03.
**M5** — templates before LLM fallback. H-01 → H-03 → H-02 → H-04.
**M2** — build last. By then the gates, controller and adapters constrain it, which is the point.

---

# 8. LLM Boundary

| Stage | Classification | Calls/investigation |
|---|---|---|
| Field extraction, taint, entity extraction | **FORBIDDEN** | 0 |
| Retrieval, scope expansion | **FORBIDDEN** | 0 |
| Attribution bookkeeping, outcome typing | **FORBIDDEN** | 0 |
| All constraints C1–C6 | **FORBIDDEN** | 0 |
| Action ordering, control query, stop predicate | **FORBIDDEN** | 0 |
| Abduction / expansion | **REQUIRED** | 3–6 |
| Expectation generation | **REQUIRED** (with abduction) | included above |
| Query generation — templated intents | **FORBIDDEN** | 0 |
| Query generation — novel intents | **REQUIRED** | 3–8 |
| Escalation phrasing | OPTIONAL | 0–1 |
| Final account | **REQUIRED** | 1 |
| **Total** | | **8–16** |

**Hard prohibitions (enforced by M-02 static + runtime checks):** the LLM must not decide truth, mutate observation state, override a constraint, declare `STOP_RESOLVED`, or reinterpret a structural field as an observation.

**Cost levers.** Cache by (intent, backend) — intents repeat across investigations while scopes vary. Batch abduction over the whole unattributed set rather than per-turn. Templates cover the 7 common intents; measure fallback rate and drive it below 30% (EXP-06).

---

# 9. Human-in-the-Loop Plan

Six triggers: (1) unattributed observations persist after one expansion; (2) source dark for a window a live expectation requires; (3) two `OBSERVED` sources conflict irreconcilably; (4) `STOP_BOUNDED` reached; (5) disposition would rest on `TAINTED` attributions alone; (6) `entity_connected_fraction` below threshold.

Trigger 6 exists because of E6 and is the only one that tells the analyst *what the agent could not see*. Threshold is **provisional** — calibrate in EXP-09.

Human input enters as `TESTIMONY` with full provenance, passes identical constraints, and never overwrites an observation. Mandatory confirmation: any `MALICIOUS` disposition, any `STOP_BOUNDED`, any unresolved conflict.

---

# 10. Retrieval / Action Policy — **PROVISIONAL**

Current candidate, to be locked by EXP-01/02:

| Situation | Policy |
|---|---|
| Entity-rich alert | entity-neighbourhood retrieval around alert entities |
| Entity-poor alert | **broad sampling; do NOT rank by brief similarity** |
| After confirmed evidence | hybrid: ~50% entity pivot, ~50% unconditioned |
| After new explanation | test its expectations first |
| Frontier saturated (k=2 expansions, no new demanding observations) | route to `STOP_BOUNDED` |

**Justification and its limits.** E6 measured observation-first *below uniform random* on CDB's entity-free briefing (0.019/0.029/0.061 vs 0.023/0.054/0.099) and hybrid best at k=10% (0.122). **n=3 chains.** Per the freeze rules this is PROVISIONAL and the word "adaptive" is used only because a regime *difference* was observed, not because a regime *effect* is established. EXP-02 must reproduce it at n≥100 before this is written up as a finding.

---

# 11. Experiment Campaign

Priority = (architectural impact × uncertainty × decision value) / cost.

| ID | Question | Baseline | Intervention | Benchmark | n target | Metric | Stats | Kill criterion | Architectural consequence | Priority |
|---|---|---|---|---|---|---|---|---|---|---|
| **EXP-02** | Does the retrieval-policy ranking survive at scale, and does the 0.272 reachability ceiling hold? | random, mean-IDF, doc-length, chronological (**all mandatory**) | HF pivot, OF, hybrid, adaptive | CDB, all 106 procedures | ≥100 chains | held-out recall; **reachable fraction** | paired bootstrap CI, per-case W/L/T | if no policy beats the strongest null → drop policy selection entirely, report reachability only | Locks or kills §10 | **1** |
| **EXP-01** | Does a *real LLM* hypothesis change the ranking? | entity-pivot proxy | LLM-generated partial hypothesis | CDB subset | ≥30 chains × 3 seeds | held-out recall; hypothesis diagnosticity ratio | paired, report diagnosticity as covariate | if LLM hypothesis diagnosticity < entity proxy → HF has no headroom | Resolves the E1/E1c confound | **2** |
| **EXP-04** | Does the control query correctly separate `VALID_NEGATIVE` from `UNKNOWN`? | naive "empty ⇒ negative" | control query | CDB + 5 injected conditions | 5 × 50 | 5×3 confusion matrix; **any UNKNOWN→VALID_NEGATIVE is critical** | exact counts | >2% critical errors → mark all empties UNKNOWN | Locks H-03 / D-05 | **3** |
| **EXP-07** | Does abduction recover when the true explanation is withheld? | no expansion | expansion on unattributed | DiagChain MAIN-69 (evidence-use is valid here) | 69 × 3 seeds | recovery rate, turn-to-recovery | McNemar | <20% recovery → M2 expansion is decorative | Validates or kills E-01/E-03 | **4** |
| **EXP-05** | Does C5 contradiction detection improve attribution? | C5 off | C5 on | MAIN-69 | 69 | attribution gap, grounding F1 | paired | no improvement → C5 to v2 | Locks F-03 | 5 |
| **EXP-08** | Do the stop predicates route correctly? | fixed budget | 5-condition predicate | CDB scenarios | 5 × 40 | premature-stop, unnecessary-continuation, routing accuracy | exact counts | >10% premature → add blocking condition | Locks G-02/G-03 | 6 |
| **EXP-10** | Injection resistance with taint gate on/off | naive prompt | filtered prompt + C4 | injection corpus M-01 | 100 payloads × 4 defenses | injection success rate by S1–S4 | exact | no reduction → C4 unsupported | Locks E-02/F-05 | 7 |
| **EXP-06** | Template-only vs template+LLM fallback | templates only | + fallback | CDB | 200 queries | success rate, LLM calls | paired | fallback <5% gain → drop H-02 | Cost reduction | 8 |
| **EXP-03** | Expectation-driven vs random action ordering | random ordering | expectation-driven | CDB | ≥50 | queries-to-resolution | paired | **run only if EXP-02 shows policy headroom** | Locks G-01 | 9 |
| **EXP-09** | Human escalation configurations | no human | conflict / exhaustion / reachability / combined | simulated oracle analyst | 4 × 40 | escalation precision & recall, workload | paired | no config improves recovery → simplify to 3 triggers | Locks G-05 | 10 |

**Stopping rule for the campaign:** after each experiment ask whether the result changes a load-bearing decision. EXP-03, EXP-06, EXP-09 are conditional and should be skipped if the earlier results already settle their decision.

---

# 12. Dataset → Experiment Matrix

| Dataset | Event-level GT | Benign labels | Cross-host | Cross-source | Missing-telemetry simulable | Valid for | **Invalid for** |
|---|---|---|---|---|---|---|---|
| **CDB** [REF-DATA-01] | yes (timestamps) | no | yes | partial | yes (drop tables) | EXP-01,02,04,06,08 | benign-attribution claims |
| **DiagChain MAIN-69** [REF-EVID-01] | yes (evidence IDs) | **no** | yes | yes (median 5 sources) | partial | EXP-05,07; evidence-use, grounding, ordering, attribution | **retrieval-policy selection (E4: IDF null 0.662, 2.23× lift)** |
| **ExCyTIn** [REF-EVID-02] | partial (QA pairs) | no | yes | yes | yes | end-to-end reward, EXP-07 alt | fine-grained stage attribution |
| OTRF/Mordor | yes (Sigma-derived) | no | yes | yes | yes | EXP-02 extension | anything needing benign GT |
| DARPA provenance | yes | no | yes | yes | partial | future provenance work | out of v1 scope |

**No public benchmark has benign ground truth.** This blocks any direct test of whether benign explanations absorb routine telemetry, which is the open confound on the E3 trigger-precision result. Building such labels is itself a contribution (§21).

---

# 13. Evaluation Metrics

| Group | Metric | Formula | Detects |
|---|---|---|---|
| Hypothesis | coverage | \|true causes ∈ live set\| / \|true causes\| | missing explanations |
| | alternative retention | mean live explanations at stop | premature collapse |
| | false hypothesis rate | REJECTED-but-true / total true | over-aggressive elimination |
| | expansion recovery | recovered / (cases where true cause withheld) | M2 expansion value |
| Retrieval | evidence recall@k | \|retrieved ∩ gold\| / \|gold\| | acquisition quality |
| | **reachable fraction** | \|pivot-pool ∩ held-out\| / \|held-out\| | **the ceiling; E6's key metric** |
| | redundancy | 1 − \|unique\| / \|retrieved\| | wasted budget |
| | null lift | policy recall / strongest-null recall | **benchmark artifact detection (mandatory)** |
| Reasoning | attribution gap | \|observed\| − \|cited\| over gold | evidence-not-used failure |
| | grounding F1 | vs gold support sets | unsupported claims |
| | ordering accuracy | pairwise concordance | temporal errors |
| Epistemic | outcome accuracy | 5×3 confusion matrix | false exoneration |
| | **critical error rate** | UNKNOWN classified VALID_NEGATIVE / all | the dangerous one |
| Stopping | premature stop | stops with unmet condition / stops | false completeness |
| | unnecessary continuation | turns after all conditions met | wasted budget |
| | routing accuracy | correct RESOLVED/BOUNDED/ASK | terminal-state logic |
| Human | escalation precision / recall | needed∩fired / fired, / needed | over- and under-asking |
| | recovery after intervention | Δ correctness post-input | human value |
| LLM | calls, tokens, cost per investigation | count | budget |
| | **non-LLM fraction** | deterministic steps / total steps | LLM-minimization goal |

---

# 14. Test Plan

**Unit** — every deterministic component; known-answer fixtures for all metrics; state-machine transitions 1–14 each individually.

**Integration** — full loop on a synthetic 20-event incident with a planted answer; full loop on one CDB chain; loop with abduction stubbed (zero LLM calls) proving the deterministic core runs standalone.

**Security (mandatory before any LLM run touches real logs)**
- S1–S4 injection payloads from [REF-INJECT-01]'s taxonomy in command lines, URLs, DNS names, usernames, filenames.
- Assert raw `content` never appears in any prompt (M-02, static + runtime).
- Assert `attributed_by` is never writable by M2 output.
- Assert `STOP_RESOLVED` unreachable via any LLM output path.
- Assert B-04 hidden-target guard raises on every withheld field.

**Regression** — one test per historical failure: gold-prose leakage (E1b), IDF-null contamination (E4), OF-below-random on entity-poor alerts (E6), trigger precision collapse (E3). Each becomes a permanent guard.

---

# 15. Failure / Recovery Matrix

| Failure | Detection | Recovery | Human? | Residual risk |
|---|---|---|---|---|
| Wrong leading hypothesis | C5 vs expectations | weaken; rivals live | no | low |
| **Absent hypothesis** | unattributed obs — **precision 0.050 (E3)** | expansion | trigger 1 | **HIGH — see §27** |
| **Unreachable evidence** | coverage_bound only | none | trigger 6 | **HIGH — 0.272 ceiling (E6)** |
| Sparse alert | entity count = 0 | broad sampling path | no | medium (policy provisional) |
| Misleading alert | contradiction on expectations | weaken | no | medium |
| Missing source | control query empty | `UNKNOWN` + dark_sources | trigger 2 | low |
| Retention expiry | control query empty | `UNKNOWN` | trigger 2 | low |
| Malformed query | execution status | `UNKNOWN`, retry | no | low |
| Delayed evidence | window recheck | re-query | no | medium |
| Contradictory sources | C5 | both live + conflict | trigger 3 | medium |
| Hallucinated relation | C3 *(v2)* | `MISATTRIBUTED` | no | **medium — C3 UNSUPPORTED** |
| Prompt injection | C4 + prompt filter | taint gate | trigger 5 | **medium — residual injection remains** |
| Query translation error | outcome typing | retry, `UNKNOWN` | no | low |
| **Baseline poisoning** | **none** | none | none | **FUNDAMENTALLY UNRESOLVED** |
| **Log deletion** | **none** (control passes) | none | none | **FUNDAMENTALLY UNRESOLVED** |
| Premature stopping | stop conditions 2,4,5 | blocked | no | low |

---

# 16. Architecture → Literature Traceability

| Component | Our mechanism | Source | What the source actually did | We adopt | We change | Why | Evidence level | Thesis role |
|---|---|---|---|---|---|---|---|---|
| M1 evidence cards | Observation with provenance, fields, clues | [REF-EVID-01] | Evidence cards + retrieval docs + evidence-entity graph + working chain, for chain-reconstruction scoring | card schema, ID-based citation | replace *chain* with *attribution* so benign explanations are first-class | chain structure is malicious-shaped; goal requires symmetry | **DIRECT-CYBER** | IMPLEMENTATION INHERITED |
| M1 grounded submission | `eᵢ ← eᵢ ∩ Ids(O)`, drop unsupported | [REF-EVID-01] | Same operation at finalization; reported attribution gap 0.306→0.054 | verbatim | none | — | **DIRECT-CYBER** | ARCHITECTURAL FOUNDATION |
| M1 taint labelling | Per-field ATTACKER_INFLUENCED / STRUCTURAL | [REF-INJECT-01] | Defined log-substrate prompt injection; 4-class taxonomy S1–S4; 48 strategy×defense×task combinations with gpt-4o-mini | the threat model and the attacker-controlled field list | field-level labels propagated into constraint logic | paper characterizes the attack, proposes no ledger-level mitigation | **DIRECT-CYBER** (threat) / **UNSUPPORTED-DESIGN** (mitigation) | ADAPTATION |
| M1 outcome typing | ROWS / VALID_NEGATIVE / UNKNOWN | [REF-INCOMP-01] | Distinguished *external* interpretation (queries about the world) from *internal* (queries about the system's information) | the distinction itself | applied to SIEM query results | logs are an incomplete database | **FOUNDATIONAL-THEORY** | ARCHITECTURAL FOUNDATION |
| M1 outcome typing | three-valued with certainty | [REF-INCOMP-02] | Classify answers certainly-true / certainly-false / unknown; modest modification of 3-valued evaluation gives certainty guarantees | the classification | scoped LCWA over (source × window × event-type) | telemetry coverage is per-source, not global | **FOUNDATIONAL-THEORY** | ARCHITECTURAL FOUNDATION |
| M1 reachability accounting | coverage_bound | **E6 (this project)** | — | — | — | E3 killed the coverage alarm; a bound is what remains honest | **EMPIRICALLY-VALIDATED-HERE** (need) / **UNSUPPORTED-DESIGN** (mechanism) | ORIGINAL DESIGN |
| M2 abduction framing | "what accounts for these?" | [REF-ABD-01] | Taxonomy of abduction patterns; distinguishes *selective* (choose among given candidates) from *creative* (introduce new models), noting creative abduction is rarely treated | the selective/creative distinction as the name for our limit | none — used as framing | — | **FOUNDATIONAL-THEORY** | LIMITATION |
| M2 incremental accounts | alternative explanations maintained incrementally | [REF-ABD-02] | Architecture generating alternative accounts over incoming observations; definitions elaborate, constraints detect and repair inconsistency | the definitions/constraints split → M2/M3 | LLM replaces the symbolic generator | no system model available for an enterprise estate | **CROSS-DOMAIN-TRANSFER** | ARCHITECTURAL FOUNDATION |
| M2/M3 ranking | arbitrariness count | [REF-ABD-03] | Degree of arbitrariness (count of arbitrary assumptions) as explanation quality; zero-arbitrariness preferred | the measure | count = attributions with no observational support | operationalized for evidence | **CROSS-DOMAIN-TRANSFER** | ADAPTATION |
| M3 contradiction | C5 conflict → WEAKENED | [REF-ABD-04] | Consistency-based diagnosis: diagnoses are minimal hitting sets of conflict sets; sound and complete **relative to a system description** | conflict-driven weakening | no hitting-set computation, no completeness claim | we have no system description | **FOUNDATIONAL-THEORY** | ADAPTATION |
| M3/M4 no probability | symbolic support/defeat | [REF-ARG-01] | Argues defeasible argumentation as an alternative to probability for evidential reasoning; models direct vs ancillary evidence, witness/expert appeals, generalizations | argument status + evidence typing | no full argumentation framework | complexity not justified in v1 | **CROSS-DOMAIN-TRANSFER** | ARCHITECTURAL FOUNDATION |
| Explanation classes | BENIGN / MALICIOUS / UNKNOWN symmetric | [REF-ARG-02] | Hybrid theory combining arguments and stories for criminal evidence, with graphical representation | competing-scenario symmetry | typed classes instead of stories | attack chains are one class among several | **CROSS-DOMAIN-TRANSFER** | ADAPTATION |
| Conflict handling | both live, human resolves | [REF-ARG-03] | Legal idioms: qualitative graphical structures for witness reliability and its interaction with hypotheses | reliability-as-structure, not as a number | ordinal source preference only | no calibrated reliabilities available | **CROSS-DOMAIN-TRANSFER** | ADAPTATION |
| G-02 stopping | action-relevance, no confidence | [REF-STOP-01] | Threshold model: testing threshold and test-treatment threshold; test only between them | the action-relevance criterion | qualitative, no probabilities | no calibrated posterior exists | **CROSS-DOMAIN-TRANSFER** | ARCHITECTURAL FOUNDATION |
| G-03 STOP_BOUNDED | terminal state with residual | [REF-STOP-02] | Therapeutic threshold: equipoise when diagnostic options are exhausted | the exhausted-but-must-decide state | renamed BOUNDED; emits coverage bound | E6 showed agents hit *reachability* limits, not exhaustion | **CROSS-DOMAIN-TRANSFER** + **EMPIRICALLY-VALIDATED-HERE** | EXPERIMENTALLY VALIDATED DESIGN CHOICE |
| G-05 escalation | VoI-style ask-vs-act | [REF-HUMAN-01] | Parameter-free VoI weighing expected utility gain against user cognitive cost; matches/exceeds tuned thresholds across four domains | the cost-vs-value framing | fixed triggers in v1, VoI deferred | no calibration data | **CROSS-DOMAIN-TRANSFER** | ADAPTATION |
| Anti-confirmation | intent from *all* live explanations | [REF-BIAS-01] | Experimental finding that clinicians preferentially seek confirmatory information after forming a hypothesis | the failure mode as motivation | structural prevention rather than debiasing training | — | **CROSS-DOMAIN-TRANSFER** | MOTIVATION |
| Entity pivot | scope expansion over entities | [REF-RET-04] | Threat hunting as inexact graph pattern matching of a CTI query graph against a provenance graph | entity-adjacency pivoting | no CTI query graph required | open-world constraint forbids CTI-defined hypotheses | **DIRECT-CYBER** | ADAPTATION |
| H-01 intent templates | semantic intent → backend query | [REF-RET-05] | Graph query language with constrained traversal, edge weighting, value propagation over heterogeneous backends | backend-abstraction layer | 7 fixed intents, no DSL | DSL unjustified at this scale | **DIRECT-CYBER** | ADAPTATION |
| H-03 control query | probe before licensing negative | — | — | — | — | replaces a metadata requirement most SOCs cannot meet | **UNSUPPORTED-DESIGN** | ORIGINAL DESIGN |
| K-02 null baselines | mandatory IDF/length/random nulls | **E4/E5 (this project)** | — | — | — | MAIN-69 IDF null 0.662 vs CDB lift 0.68–1.08× | **EMPIRICALLY-VALIDATED-HERE** | EXPERIMENTALLY VALIDATED DESIGN CHOICE |
| No POMDP/RL/EIG | expectation-generated actions | [REF-RET-01],[REF-RET-02],[REF-RET-03] + **E6** | Active probing reduced probes 60–75%; greedy most-informative test shown intractable, needing approximation; query-selection measures compared by discrimination power | discrimination as the ordering idea | ordinal only, no EIG computation | E6: policy spread 0.046 ≪ reachability gap 0.165 | **CROSS-DOMAIN-TRANSFER** + **EMPIRICALLY-VALIDATED-HERE** | EXPERIMENTALLY VALIDATED DESIGN CHOICE |

---

# 17. Source → Architecture Reverse Map

| Paper | Concept taken | Used in | Direct/Transfer | What we change |
|---|---|---|---|---|
| [REF-EVID-01] DiagChain | evidence cards; grounded submission; stage-wise eval; budget defaults | M1, M3, §13 | Direct | chain → attribution ledger |
| [REF-EVID-02] ExCyTIn | environment, 25-step protocol, partial credit | EXP-07 alt | Direct | not primary |
| [REF-DATA-01] CDB | Gymnasium env, verifiable rewards, context morphing | EXP-01/02/04/06/08 | Direct | used as retrieval testbed |
| [REF-INJECT-01] Watchtower | log-substrate injection; attacker-controlled field list; S1–S4 | C-03, E-02, F-05, M-01 | Direct | field-level ledger labels |
| [REF-INCOMP-01] Lipski | internal vs external interpretation | D-05 | Transfer | applied to SIEM |
| [REF-INCOMP-02] Libkin | certainly-true/false/unknown | D-05, H-03 | Transfer | scoped LCWA |
| [REF-INCOMP-03] Imieliński & Lipski | marked nulls, safe representation | D-05 (theory) | Transfer | background only |
| [REF-ABD-01] Schurz | selective vs creative abduction | §27 limitation | Transfer | naming our limit |
| [REF-ABD-02] Langley | incremental alternative accounts; definitions vs constraints | M2/M3 split | Transfer | LLM generator |
| [REF-ABD-03] Caroprese | arbitrariness | F-06, E-05 | Transfer | evidence-based count |
| [REF-ABD-04] Reiter-line MBD | conflict-driven diagnosis | F-03 | Transfer | no completeness claim |
| [REF-ARG-01] Prakken | argumentation over probability; evidence typing | D-02, M3 | Transfer | simplified |
| [REF-ARG-02] Bex et al. | arguments + stories hybrid | E-04, I-03 | Transfer | typed classes |
| [REF-ARG-03] Lagnado et al. | legal idioms, reliability structure | I-03 | Transfer | ordinal only |
| [REF-STOP-01] Pauker & Kassirer | testing / test-treatment thresholds | G-02 | Transfer | qualitative |
| [REF-STOP-02] Boyles et al. | therapeutic threshold | G-03 | Transfer | renamed BOUNDED |
| [REF-HUMAN-01] Dong et al. | parameter-free VoI | G-05 | Transfer | deferred to v2 |
| [REF-RET-01] Rish et al. | active probing | §10 rationale | Transfer | not implemented |
| [REF-RET-02] Zheng et al. | intractability of greedy EIG | §10 rationale | Transfer | justifies omission |
| [REF-RET-03] Rodler | query discrimination power | G-01 | Transfer | ordinal count |
| [REF-RET-04] POIROT | provenance graph alignment | C-02, G-04 | Direct | no CTI graph |
| [REF-RET-05] ProGQL | backend-abstracted graph queries | H-01 | Direct | fixed intents |
| [REF-BIAS-01] confirmation-bias study | diagnostic confirmation bias | motivation | Transfer | structural fix |
| [REF-CYB-01] AUTOMA | KB-driven hypothesis generation + variants | §21 alternatives | Direct | rejected (closed world) |
| [REF-CYB-02] Ramkumar et al. | anomaly + ASP abduction for unknown attacks | §21 alternatives | Direct | rejected (needs system model) |

---

# 18. Cross-Domain Transfer Matrix

| Domain | Original assumption | Holds in cyber? | Adaptation | Classification | Residual risk |
|---|---|---|---|---|---|
| Incomplete databases | closed schema, known nulls | **Partly** — schema known, coverage not | scoped LCWA + control query | **PARTIALLY TRANSFERABLE** | control query can't detect deletion |
| Model-based diagnosis | a system description of correct behaviour exists | **No** | conflict-driven weakening only; no completeness claim | **ANALOGOUS ONLY** | no completeness guarantee |
| Medical thresholds | calibrated posterior probability exists | **No** | action-relevance criterion, qualitative | **PARTIALLY TRANSFERABLE** | no principled threshold value |
| Legal/forensic argumentation | closed evidence set, adversarial presentation by two parties | **Partly** — evidence set is open, no opposing counsel | agent must generate its own rival explanations | **PARTIALLY TRANSFERABLE** | no adversary forcing alternatives ⇒ §27 |
| Active diagnosis / BED | probabilistic model over hypotheses | **No** | ordinal discrimination count | **ANALOGOUS ONLY** | may leave value on the table (EXP-03) |
| HCI / mixed-initiative | measurable human cost model | **Not yet** | fixed triggers in v1 | **PARTIALLY TRANSFERABLE** | thresholds uncalibrated |
| Conformal prediction | exchangeability between calibration and test | **No** — novel attacks break it | **not used** | **NON-TRANSFERABLE** | must be stated; it looks applicable and is not |

---

# 19. Experiment → Architecture Traceability

| Experiment | Component | Claim tested | Evidence status | Decision |
|---|---|---|---|---|
| E1/E1b | benchmark hygiene | gold-prose baselines are valid | **refuted** — 8.5× leakage, field is in `hidden_targets` | B-04 guard mandatory |
| E4 | benchmark validity | MAIN-69 measures retrieval strategy | **refuted** — IDF null 0.662 beats all designed policies | K-02 nulls mandatory; MAIN-69 barred from EXP-01/02 |
| E5 | generality of E4 | the artifact is universal | **refuted** — 2.23× vs 0.68–1.08× | CDB primary for retrieval |
| E6 | §10 retrieval policy | OF beats HF universally | **refuted; regime-dependent** | adaptive policy, PROVISIONAL |
| E6 | G-01 action selection | action selection is the bottleneck | **refuted** — spread 0.046 vs gap 0.165 | no EIG/VoI/POMDP |
| E6 | D-04, G-03 | evidence for unconceived causes is reachable | **refuted** — 0.272 mean, 0.006 worst | coverage_bound + STOP_BOUNDED |
| E3 | coverage alarm | unattributed observations signal incompleteness | **refuted** — precision 0.050 | alarm demoted, not load-bearing |
| EXP-02 | §10 | *pending* | — | locks or kills retrieval policy |
| EXP-01 | §10, M2 | *pending* | — | resolves LLM-hypothesis confound |
| EXP-04 | H-03, D-05 | *pending* | — | locks control query |
| EXP-07 | E-01, E-03 | *pending* | — | validates M2 expansion |

---

# 20. Claim Evidence Register

| Claim | Source | Exact location | Type | Status |
|---|---|---|---|---|
| Grounded submission reduces attribution errors | [REF-EVID-01] | RQ3 scaffold ablation, 0.306→0.054 | DIRECT-CYBER | **ESTABLISHED** (in source; not yet replicated by us) |
| More turns/budget does not monotonically help | [REF-EVID-01] | RQ4 budget sensitivity, R24 | DIRECT-CYBER | **ESTABLISHED** (in source) |
| Gold-prose baselines leak | this project | E1b, 8.5× ratio | EMPIRICAL | **MEASURED HERE** |
| MAIN-69 evidence-recall is IDF-confounded | this project | E4, 0.662 vs 0.297 | EMPIRICAL | **MEASURED HERE** |
| The confound is construction-specific | this project | E5, 2.23× vs 0.68–1.08× | EMPIRICAL | **MEASURED HERE** |
| Observation-first is below random on entity-poor alerts | this project | E6, n=3 | EMPIRICAL | **PROVISIONAL (n=3)** |
| Hybrid retrieval is best | this project | E6, k=10%, n=3 | EMPIRICAL | **PROVISIONAL — do not claim** |
| Entity pivot reaches ~27% of held-out evidence | this project | E6, mean 0.272 | EMPIRICAL | **PROVISIONAL (n=3)** — EXP-02 decides |
| Unattributed-observation alarm is uninformative | this project | E3, precision 0.050 | EMPIRICAL | **MEASURED HERE**, confounded by absent benign labels |
| Defeasible reasoning can replace calibrated probability | [REF-ARG-01] | argued, not measured | FOUNDATIONAL | **ESTABLISHED as an argument**, untested here |
| Action selection is not the bottleneck | this project | E6 | EMPIRICAL | **PROVISIONAL** |
| Control query licenses VALID_NEGATIVE | — | — | DESIGN | **UNSUPPORTED** until EXP-04 |
| C3 relation re-derivation catches misattribution | — | — | DESIGN | **UNSUPPORTED** |
| Complete hypothesis coverage in an open world | — | — | — | **FUNDAMENTALLY UNRESOLVED** |
| Baseline poisoning detectable in-band | — | — | — | **FUNDAMENTALLY UNRESOLVED** |
| Deleted-evidence detection without tamper-evident logs | — | — | — | **FUNDAMENTALLY UNRESOLVED** |

---

# 21. Our Actual Contributions

**Contribution 1 — Benchmark-validity finding (strongest; benchmark/evaluation contribution).**
*Before:* DiagChain-style evidence-recall was used to compare retrieval approaches. *We establish:* a content-free mean-IDF ranking scores 0.662 on MAIN-69, beating every designed policy, with 2.23× lift over random, versus 0.68–1.08× on CDB; gold cards are 1.32× longer than noise. *Consequence:* retrieval experiments on such benchmarks are uninterpretable without null baselines. This is **experimentally derived** and independent of whether the agent works.

**Contribution 2 — Reachability ceiling (experimentally derived, pending EXP-02).**
Held-out evidence reachable by entity pivot: mean 0.272, per-chain 0.006/0.239/0.571. If it holds at n≥100, it reframes evidence acquisition for hunting agents: the constraint is what is *reachable*, not what is *chosen*. **n=3 today. Do not overclaim.**

**Contribution 3 — Epistemic layer for negative evidence (composition + one original mechanism).**
*Inherited:* Lipski's internal/external distinction, Libkin's three-valued certainty classification. *Original:* the control query, which converts an unavailable-metadata requirement into an executable probe. *Unproven* until EXP-04.

**Contribution 4 — Coverage-bound reporting instead of a completeness alarm (original, negative-result-driven).**
We measured our own proposed alarm at precision 0.050 and replaced it with an honest bound. The contribution is the *demotion*, documented, not a fix.

**Contribution 5 — Architecture composition (composition, not novelty).**
Five modules composing DiagChain grounding, incomplete-database semantics, medical threshold stopping, argumentation-based evidence typing, and injection-aware field taint. **No component is new.** The composition is not claimed as novel; it is claimed as *defensible*, with each part traced in §16.

**Explicitly not contributions:** hypothesis completeness (unsolved), a better retrieval policy (unestablished), LLM abduction quality (untested), multi-agent or probabilistic machinery (rejected).

---

# 22. Verified Bibliography

| Tag | Citation | Verification |
|---|---|---|
| [REF-EVID-01] | *DiagChain: A Diagnostic Benchmark for Evaluating LLM Agents on Evidence-Grounded Attack Chain Reconstruction.* arXiv:2608.03591. Repo: github.com/abrahaamm/DiagChain | **FULL-TEXT** — HTML read; repo cloned; `PACKAGE_MANIFEST.json` verified. **Author list not confirmed** (anonymized package) |
| [REF-EVID-02] | Wu, Y., Velazco, M., Zhao, A., Meléndez Luján, M.R., Movva, S., Roy, Y.K., Nguyen, Q., Rodriguez, R., Wu, Q., Albada, M., et al. *ExCyTIn-Bench: Evaluating LLM Agents on Cyber Threat Investigation.* arXiv:2507.14201 (2025). Accepted ICML 2026. github.com/microsoft/SecRL | **FULL-TEXT (repo)** — BibTeX taken verbatim from repo README |
| [REF-DATA-01] | Chona, A., Kozlov, I., Kumar, A. *Cyber Defense Benchmark: Agentic Threat Hunting Evaluation for LLMs in SecOps.* arXiv:2604.19533, cs.CR (2026). github.com/simbianai/cyber_defense_benchmark | **FULL-TEXT (repo)** — BibTeX verbatim from repo README |
| [REF-INJECT-01] | Pandey, R., et al. *Poisoning the Watchtower: Prompt Injection Attacks Against LLM-Augmented Security Operations Through Adversarial Log Content.* arXiv:2605.24421 (May 2026) | **INDEX-VERIFIED** — title/ID/abstract confirmed. ⚠ **Numbers used in earlier drafts (96% / 38% / 26.6%→11.8%) are NOT confirmed at page level.** Abstract confirms: S1 classification 0% suppression; persona hijack 68% under naive classifier; summarization highest-risk; gpt-4o-mini, 200 logs/condition, 48 combinations. **Re-derive all figures from the PDF before citing** |
| [REF-INCOMP-01] | Lipski, W. *On Semantic Issues Connected with Incomplete Information Databases.* ACM TODS (1979) | INDEX-VERIFIED |
| [REF-INCOMP-02] | Libkin, L. *SQL's Three-Valued Logic and Certain Answers.* ACM TODS (2016) | INDEX-VERIFIED |
| [REF-INCOMP-03] | Imieliński, T., Lipski, W. *Incomplete Information in Relational Databases.* JACM (1984) | INDEX-VERIFIED |
| [REF-ABD-01] | Schurz, G. *Patterns of Abduction.* Synthese (2008) | INDEX-VERIFIED |
| [REF-ABD-02] | Langley, P. *Generating, Managing, and Evaluating Explanations* (PENUMBRA) (2020) | **UNVERIFIED** — exact title/venue to confirm |
| [REF-ABD-03] | Caroprese, L., et al. — abductive explanation quality via degree of arbitrariness (2022) | **UNVERIFIED** — exact title/venue/authors to confirm |
| [REF-ABD-04] | Reiter, R. *A Theory of Diagnosis from First Principles.* Artificial Intelligence 32(1), 57–95 (1987) | INDEX-VERIFIED (foundational; confirm page range) |
| [REF-ARG-01] | Prakken, H. — formal argumentation models for reasoning about evidence (2004) | **UNVERIFIED** — exact title/venue to confirm |
| [REF-ARG-02] | Bex, F., van Koppen, P., Prakken, H., Verheij, B. *A hybrid formal theory of arguments, stories and criminal evidence.* AI & Law (2010) | INDEX-VERIFIED |
| [REF-ARG-03] | Lagnado, D., Fenton, N., Neil, M. *Legal idioms: a framework for evidential reasoning.* Argument & Computation (2013) | INDEX-VERIFIED |
| [REF-STOP-01] | Pauker, S.G., Kassirer, J.P. *The Threshold Approach to Clinical Decision Making.* NEJM 302(20):1109–17 (1980) | INDEX-VERIFIED |
| [REF-STOP-02] | Boyles, T.H., et al. — therapeutic threshold (2016) | **UNVERIFIED** — exact title/venue to confirm |
| [REF-HUMAN-01] | Dong, et al. — Value of Information framework for human-agent communication (2026) | **UNVERIFIED** |
| [REF-RET-01] | Rish, I., et al. *Adaptive diagnosis in distributed systems.* IEEE TNN (2005) | INDEX-VERIFIED |
| [REF-RET-02] | Zheng, A.X., Rish, I., Beygelzimer, A. *Efficient Test Selection in Active Diagnosis via Entropy Approximation.* UAI (2005) | INDEX-VERIFIED |
| [REF-RET-03] | Rodler, P. *On Active Learning Strategies for Sequential Diagnosis* (2018) | INDEX-VERIFIED |
| [REF-RET-04] | Milajerdi, S.M., Eshete, B., Gjomemo, R., Venkatakrishnan, V.N. *POIROT: Aligning Attack Behavior with Kernel Audit Records for Cyber Threat Hunting.* ACM CCS (2019) | INDEX-VERIFIED |
| [REF-RET-05] | ProGQL — graph query language for security investigation, ICDE (2026) | **UNVERIFIED** — authors/venue to confirm |
| [REF-BIAS-01] | Confirmation-bias-in-clinical-hypothesis-testing study (Devine et al., 1990) | **UNVERIFIED** — ⚠ the 92%/90%/84%/77% figures must be re-derived from the paper |
| [REF-CYB-01] | Nour, B., et al. — AUTOMA, threat-hunting hypothesis generation, IEEE TNSM (2024) | **UNVERIFIED** |
| [REF-CYB-02] | Ramkumar, et al. — ASP abduction for unknown attack diagnosis, IEEE TSE (2024) | **UNVERIFIED** |

**11 of 25 references are UNVERIFIED or carry unverified figures.** Task N-02 (§23, Week 1) is to resolve every one before any thesis text is written. Do not cite an UNVERIFIED row.

---

# 23. Week-by-Week Plan (one student, 24 weeks)

| Wk | Milestone | Deliverable | Acceptance | Risk |
|---|---|---|---|---|
| 1 | **M0** env + **N-02 reference verification** | repos pinned, CDB loads, all 25 refs resolved to FULL-TEXT/INDEX-VERIFIED | zero UNVERIFIED rows | refs unavailable → substitute or drop the claim |
| 2 | M1 contracts | §5 schemas + validators | round-trip tests pass | — |
| 3–4 | M2 deterministic core | C-01..04, B-04 guard | 95% extraction; guard raises | parser coverage |
| 5–6 | M3 ledger | D-01..05 | outcome typing unit-complete | — |
| 7 | M4 constraints | F-01,02,03 | transitions 5,9,10 tested | — |
| 8–9 | M5 controller | G-01..06, stubbed abduction | **full loop runs with 0 LLM calls** | — |
| 10 | M6 adapter | H-01,03 | 7 intents execute on CDB | backend quirks |
| 11–12 | M7 abduction | E-01..05 | schema-valid ≥95% | LLM output instability |
| 13 | M8 human loop | I-01..03, J-01,02 | audit replay works | — |
| 14 | M9 harness | K-01,02, L-01,02 | **reproduces E4 and E6 exactly** | — |
| 15–16 | **EXP-02** | scale retrieval study | n≥100, nulls included | *the pivotal week* |
| 17 | **EXP-01** | LLM-hypothesis study | n≥30×3 | API budget |
| 18 | **EXP-04** + **EXP-07** | epistemic + recovery | matrices complete | — |
| 19 | EXP-05, EXP-08 | ablations | — | — |
| 20 | EXP-10 + security | injection suite | all security tests pass | — |
| 21 | Conditional (EXP-03/06/09) | only if load-bearing | — | skip if settled |
| 22 | Analysis | claim register regenerated from logs | every claim has a status | — |
| 23–24 | Thesis | methodology, results, limitations chapters | §16–21 tables exported | — |

---

# 24. MVP / V1 / V2

**MVP (week 9).** Alert → observation → *stubbed* abduction → expectation → query → observation → update → stop. Zero LLM calls. Proves the deterministic core is a standalone system.

**V1 (thesis).** MVP + real abduction (E-01..05) + templates + control query + human loop + audit + EXP-01/02/04/07.

**V2 (deferred).** C3 re-derivation, C4 enforcement, C6 arbitrariness, VoI escalation, ExCyTIn integration, LLM fallback tuning, additional backends.

---

# 25. Risk Register

| ID | Risk | P | Impact | Detection | Mitigation | Residual |
|---|---|---|---|---|---|---|
| R-01 | HuggingFace blocked → no ExCyTIn | High | Low | week 1 | CDB + DiagChain suffice | low |
| R-02 | No benign ground truth anywhere | **Certain** | **High** | known | state as limitation; propose labels as future work | **high — E3 confound unresolvable** |
| R-03 | Benchmark artifacts recur | Medium | High | K-02 nulls mandatory | nulls in every run | low |
| R-04 | LLM abduction quality poor | Medium | High | EXP-07 recovery rate | narrow prompts, schema validation | medium |
| R-05 | **EXP-02 confirms 0.272 ceiling** | **Medium-High** | **High** | week 16 | **pre-plan the pivot: thesis becomes a measured negative result + epistemic layer** | medium |
| R-06 | Retrieval policy stays unresolved | Medium | Medium | EXP-01/02 | report as PROVISIONAL, do not claim | low |
| R-07 | Prompt injection succeeds | Medium | High | EXP-10 | filter + taint + templates | **medium — residual, unavoidable** |
| R-08 | LLM cost overrun | Low | Medium | J-02 counters | caching, templates, batching | low |
| R-09 | Query translation errors | Medium | Low | outcome typing | templates first | low |
| R-10 | Stopping false confidence | Medium | **High** | EXP-08 | 5 blocking conditions | medium |
| R-11 | Escalation burden too high | Medium | Medium | EXP-09 | tune trigger 6 threshold | medium |
| R-12 | Sample size insufficient | Medium | High | pre-registration | n≥100 target; report CI always | medium |

---

# 26. Definition of Done

Architecture implemented (M1–M5); all 14 state transitions unit-tested; LLM boundary enforced by static **and** runtime checks; audit log supports full replay; all security tests pass including the four assertions in §14; EXP-01/02/04/07 completed with nulls and CIs; every §20 claim carries a status; **zero UNVERIFIED references remain**; §16–21 tables regenerate from run logs; MVP demonstrable with zero LLM calls.

---

# 27. Final Architecture Freeze Check

**LOCKED** — five modules; observation ledger; LLM abduction; C1/C2/C5; deterministic controller; template-first queries; escalation structure; two terminal states; three-valued outcome typing; no probabilistic core; no RL/POMDP/MCTS; no multi-agent.

**PROVISIONAL** — entity-driven scope expansion; expectation-driven ordering; control query; C4; C6; saturation parameter *k*=2; retrieval policy details; LLM call counts; trigger-6 threshold.

**REJECTED (may not re-enter without new evidence)** — gold-prose baselines; pure observation-first as universal default; the unattributed-observation coverage alarm as a primary signal; POMDP/RL/MCTS/multi-agent machinery; conformal prediction for hypothesis-set coverage.

**UNSUPPORTED (must not be claimed as validated)** — control query; C3; coverage-bound *mechanism*; taint-gate *effectiveness*; every escalation trigger.

**FUNDAMENTALLY UNRESOLVED (thesis must state explicitly)** — complete hypothesis coverage in an open world; evidence outside reachable scope; baseline poisoning; deleted-evidence detection without tamper-evident infrastructure; LLM creative-abduction reliability.

Nothing has been promoted. Two items were *demoted* this cycle: the coverage alarm (LOCKED → REJECTED, by E3) and the retrieval policy (was heading to LOCKED → PROVISIONAL, by E4/E5/E6).

---

# MASTER CHECKLIST — chronological

```
WEEK 1
[ ] A-01 repo, CI, typed Python
[ ] A-02 clone + pin CDB; unpack sample
[ ] A-03 clone + pin DiagChain; verify_package.py
[ ] A-05 deterministic seeding + run manifest
[ ] A-06 LLM client with cache + counters
[ ] N-02 VERIFY ALL 25 REFERENCES  <-- 11 currently UNVERIFIED
[ ] N-02a re-derive Watchtower figures from PDF
[ ] N-02b re-derive confirmation-bias figures from source
WEEK 2
[ ] Data contracts (§5) + validators + round-trip tests
WEEKS 3-4
[ ] C-01 field extractor    [ ] C-02 entity extractor
[ ] C-03 taint labeller     [ ] C-04 timestamp normalizer
[ ] B-01/B-02 CDB loaders   [ ] B-03 DiagChain loader
[ ] B-04 HIDDEN-TARGET GUARD (blocks gold prose)  <-- P0, from E1b
WEEKS 5-6
[ ] D-01 observation store  [ ] D-02 epistemic typing
[ ] D-03 attribution bookkeeping
[ ] D-04 reachability accounting / coverage_bound
[ ] D-05 outcome typing ROWS/VALID_NEGATIVE/UNKNOWN
WEEK 7
[ ] F-01 C1 schema  [ ] F-02 C2 integrity  [ ] F-03 C5 contradiction
WEEKS 8-9
[ ] G-01 action ordering    [ ] G-06 budget accounting
[ ] G-02 STOP_RESOLVED      [ ] G-03 STOP_BOUNDED + bound emission
[ ] G-04 adaptive scope expansion  [ ] G-05 six escalation triggers
[ ] MVP GATE: full loop runs end-to-end with ZERO LLM calls
WEEK 10
[ ] H-01 seven intent templates   [ ] H-03 control query executor
WEEKS 11-12
[ ] E-01 abduction prompt   [ ] E-02 prompt input filter (no raw logs)
[ ] E-03 expectations       [ ] E-04 diversity  [ ] E-05 explosion control
[ ] H-02 LLM fallback
WEEK 13
[ ] I-01/02/03 human loop   [ ] J-01/J-02 audit + LLM call logs
WEEK 14
[ ] K-01 metric library     [ ] K-02 NULL BASELINE LIBRARY (mandatory)
[ ] L-01 experiment runner  [ ] L-02 held-out generator
[ ] GATE: harness reproduces E4 and E6 exactly
WEEKS 15-16
[ ] EXP-02 retrieval at scale, n>=100, all nulls   <-- PIVOTAL
[ ] Decision: lock or kill §10 retrieval policy
WEEK 17
[ ] EXP-01 real-LLM hypothesis comparison
WEEK 18
[ ] EXP-04 control query / epistemic matrix
[ ] EXP-07 hypothesis recovery
WEEK 19
[ ] EXP-05 contradiction ablation   [ ] EXP-08 stopping scenarios
WEEK 20
[ ] M-01 injection corpus   [ ] EXP-10 injection resistance
[ ] All four §14 security assertions pass
WEEK 21
[ ] Conditional only: EXP-03 / EXP-06 / EXP-09
WEEK 22
[ ] Regenerate claim register (§20) from run logs
[ ] Update freeze check (§27); demote anything unsupported
WEEKS 23-24
[ ] Export §16-21 traceability tables
[ ] Write methodology, results, limitations
[ ] Definition of Done audit (§26)
```
