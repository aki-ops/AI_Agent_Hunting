# Threat Investigation Agent — Final Architecture
## After five experiments, three of which killed proposed mechanisms

**Status of evidence.** Everything below is marked: **[MEASURED]** tested here with numbers · **[LIT]** literature-supported, untested here · **[UNTESTED]** my design, no evidence · **[KILLED]** proposed earlier, contradicted by experiment.

---

# 0. What the experimental loop found

Five experiments were run. **Two prior conclusions were retracted and two proposed mechanisms were killed.**

| # | Experiment | Result | Consequence |
|---|---|---|---|
| E1 | Observation-first vs hypothesis-first on DiagChain MAIN-69 | HF won (−0.128, CI excl. 0) | Provisional |
| E1b | Baseline validity check | HF query used `gold attack step names` + `gold step descriptions`, both in the benchmark's own `hidden_targets`; **8.5× vocabulary leakage** | E1 retracted |
| E1c | Corrected comparison | OF +0.186 [+0.038, +0.338] | Provisional |
| **E4** | **Null baselines** | **Content-free mean-IDF ranking scores 0.662 — beats every designed policy. Both policies LOSE to it (OF −0.159 [−0.267,−0.063])** | **E1b retracted too** |
| **E5** | **Cross-benchmark check** | **IDF-null lift: DiagChain 2.23× vs CDB 0.68–1.08×.** Artifact is construction-specific | **MAIN-69 invalid for this question; CDB valid** |
| **E6** | **Real comparison on CDB** | See below | **Architecture changed** |
| **E3** | **Coverage-trigger precision** | **Fires in 85% of cases, precision median 0.050** | **Coverage mechanism killed** |

## E6 — the decisive numbers

155,350 real Windows events, 3 attack chains, last 40% of steps held out. Budget-matched, no gold text in any query. **n=3 chains: a pilot, reported for direction and magnitude, not inference.**

| policy | k=2% | k=5% | k=10% |
|---|---|---|---|
| uniform random | 0.023 | 0.054 | 0.099 |
| observation-first (brief similarity) | 0.019 | 0.029 | 0.061 |
| hypothesis-first (entity pivot) | 0.028 | **0.107** | 0.107 |
| hybrid half/half | 0.043 | 0.060 | **0.122** |

Three findings, in increasing order of importance:

1. **Observation-first is at or below random at every budget.** CDB's alert briefing contains no entities, so there is nothing to seed on. This is a **regime effect**: observation-first requires an entity anchor in the alert. Where the alert is sparse, it degenerates below chance.
2. **Hypothesis-first plateaus.** Identical at k=5% and k=10% because the entity-pivot pool is exhausted at 14.8% of corpus. More budget buys nothing.
3. **The ceiling.** *Held-out evidence reachable via entity pivot at any budget:* **mean 0.272**, per-chain **0.006 / 0.239 / 0.571**. For one of three chains, **99.4% of the evidence for the unconceived part of the attack was entity-disconnected from the confirmed part.**

Finding 3 is the one that changes the architecture.

---

# 1. Final Architecture

Four modules. Two call an LLM. Smaller than every previous version, because two components were removed by evidence rather than by taste.

```
   ALERT ──►┌───────────────────────────────────────────────┐
            │  [M1] EVIDENCE LEDGER        (deterministic)  │
            │  extract · taint · epistemic-type ·           │
            │  outcome-type · reachability accounting       │
            └────────┬─────────────────────────▲────────────┘
                     │                          │
                     ▼                          │
            ┌────────────────────┐     ┌────────┴───────────┐
            │ [M2] ABDUCTION     │────►│ [M3] CONSTRAINTS   │
            │      (LLM)         │     │   (deterministic)  │
            └────────────────────┘     └────────┬───────────┘
                                                 │
                     ┌───────────────────────────▼───────────┐
                     │ [M4] CONTROLLER    (deterministic)    │
                     │ retrieve · control-query · stop ·      │
                     │ COVERAGE-BOUND REPORTING              │
                     └───────┬───────────────────▲───────────┘
                             ▼                    │
                    ┌──────────────────┐          │
                    │ [M5] TRANSLATE / │          │
                    │  REPORT (LLM)    │──query───┘
                    └────────┬─────────┘
                             ▼
                    ANALYST  ◄── escalation + coverage bound
```

**Removed by experiment, not by preference:**
- **Entity-graph BFS expansion** — E4 voided the DiagChain measurement that appeared to condemn it, and E6 shows entity pivoting caps at 0.272 reachability. It is neither the harmful thing E1c suggested nor a solution. **[KILLED as a completeness mechanism; retained only as one retrieval heuristic among several]**
- **Coverage-check as the completeness alarm** — E3: fires in 85% of cases at median precision 0.050. It is a constant alarm carrying roughly prevalence-level information. **[KILLED]**
- **Pure observation-first scope expansion** — E6: below random on entity-free alerts. **[KILLED as a default; conditionally retained, see §8]**

---

# 2. Modules

## M1 — Evidence Ledger *(deterministic, no LLM — this is the injection boundary)*

**Purpose.** Turn rows into typed, provenance-carrying observations, and — new — maintain the **reachability accounting** that replaces the dead coverage check.

**In:** rows, query scope, execution status, control-query status.
**Out:** observations + a running coverage bound.

**Decision rules.**
- Field extraction is deterministic parsing. Never an LLM. **[LIT — log-substrate prompt injection: summarization reaches 96% injection success undefended, 38% under constrained output; strongest defense only reduces average success 26.6% → 11.8%]**
- Per-field taint: `ATTACKER_INFLUENCED` if an adversary chooses the content before storage (command lines, paths, URIs, user agents, DNS names, attempted usernames); `STRUCTURAL` if the collector generates it (PIDs, kernel timestamps, event IDs, collector host).
- **Reachability accounting (new, replaces coverage):** track (a) which sources have been queried at all, (b) what fraction of in-scope events are entity-connected to confirmed evidence, (c) time windows never covered. **[UNTESTED as a mechanism; the need for it is [MEASURED] by E6]**

**Failure.** Parse failure → `PARSE_FAILED` → contributes to the coverage bound, never silently dropped.

## M2 — Abduction Engine *(LLM — REQUIRED)*

**Purpose.** Generate candidate causes. The only open-world component and the only irreducible LLM dependency.

**In:** extracted fields + taint labels (never raw log text), plus existing explanation labels for dedup.
**Out:** `Explanation{id, label, class ∈ {BENIGN, MALICIOUS, UNKNOWN}, attributions[], expectations[], assumptions[]}`.

**Decision rule.** Prompt shape is always *"what could account for these observations?"* — never *"does explanation X hold?"* Each explanation must carry **expectations**: observations it predicts should exist. Expectations are what generate queries, and because they come from *all* live explanations including weak ones, testing is discriminating rather than confirmatory by construction. **[LIT — the human failure mode is severe: 92% of licensed psychologists sought confirmatory over disconfirmatory information after forming an initial hypothesis, persisting across three sequential opportunities (90%/84%/77%)]**

**Mandatory diversity:** at least one `BENIGN` and one `MALICIOUS` candidate where both are logically possible; `UNKNOWN` always permitted.

**Failure.** Cannot be detected when the true cause is absent — see §12.

## M3 — Constraint Checker *(deterministic)*

The only module permitted to change status.

| | Constraint | On failure |
|---|---|---|
| C1 | Schema well-formedness | reject |
| C2 | Cited observation exists | reject attribution |
| C3 | **Relation re-derivation** — recompute any asserted structural relation from the cited observation's fields | `MISATTRIBUTED` **[UNTESTED]** |
| C4 | **Taint gate** — attribution resting solely on attacker-influenced fields | `TAINTED`; cannot alone carry a disposition |
| C5 | Contradiction against an explanation's expectations | `WEAKENED` + conflict recorded |
| C6 | **Arbitrariness** — count of assumptions with no observational support | ranking input **[LIT — degree of arbitrariness as the quality measure for abductive explanations, zero-arbitrariness preferred]** |

C6 replaces every place earlier designs reached for plausibility scoring. It needs no probability.

## M4 — Controller *(deterministic)*

**Decision order per turn:**
1. Stop predicate holds → terminal (§11).
2. Unconditional escalation trigger → `ASK_HUMAN`.
3. Untested expectation exists → `QUERY(expectation)`.
4. Pending negative result → `CONTROL_QUERY`.
5. Unattributed observations exist → `ABDUCE`.
6. Else → `EXPAND_SCOPE` under the **adaptive rule** in §8.

No EIG, no VoI arithmetic, no learned policy. **[MEASURED — E6: the spread between the best and worst retrieval policy (0.107 vs 0.061 at k=10%) is smaller than the gap between the best policy and its own reachability ceiling (0.107 vs 0.272). Action-selection sophistication cannot be the bottleneck when the reachable set is the constraint.]**

## M5 — Translate / Report *(LLM — REQUIRED, highest risk)*

Common intents (`ProcessLineage`, `LogonHistory`, `NetworkConnections`, `PersistenceArtifacts`, `FileWrites`, `DNSQueries`, `AnyEventControl`) resolve through **hand-written per-backend templates**, not the LLM — cheaper, deterministic, and it removes the injection surface on the common path. The reporter receives extracted fields and observation IDs, never raw log text, and emits a fixed schema from which prose is generated.

---

# 3. Investigation State

```python
State = {
  "scope": {"entities":[...], "windows":[...], "sources_queried":[...],
            "sources_known":[...], "frontier":[...]},

  "observations": [{"id","source","scope_id","timestamp",
      "epistemic_type": OBSERVED | TESTIMONY,
      "fields":{...}, "taint":{field: STRUCTURAL|ATTACKER_INFLUENCED},
      "provenance":{query_id,collector,ingest_time},
      "attributed_by":[explanation_id]}],

  "explanations": [{"id","label","class","status","origin",
      "attributions":[{"observation_id","cause","status"}],
      "expectations":[{"description","scope",
                       "test_status": UNTESTED|CONFIRMED|REFUTED|UNTESTABLE}],
      "arbitrariness": int, "rejection_reason"}],

  "queries": [{"id","intent","scope","backend",
               "outcome": ROWS|VALID_NEGATIVE|UNKNOWN,
               "diagnostic","control_query_id","cost"}],

  "conflicts":   [{"observation_ids","explanation_ids","resolved"}],
  "dark_sources":[{"source","window","demanded_by":[expectation_id]}],

  "coverage_bound": {                       # NEW — replaces the killed check
      "sources_never_queried":[...],
      "windows_never_covered":[...],
      "entity_connected_fraction": float,   # E6 measured this at 0.272 mean
      "pivot_pool_exhausted": bool},

  "human": [{"content","type","analyst","timestamp"}],
  "stop": {"state","blocking":[]}
}
```

**Two epistemic types only.** `OBSERVED` and `TESTIMONY`. `INFERRED` is not an observation type — an inference is an attribution inside an explanation. `UNKNOWN` is a query outcome, not an evidence type.

**Removed:** belief vectors, probabilities, reliability scores, raw transcript, cost models beyond a counter.

---

# 4. Action Space

| Action | Generated by | LLM |
|---|---|---|
| `QUERY(expectation)` | an explanation's untested expectation | template, LLM fallback |
| `CONTROL_QUERY(source, scope)` | any pending negative | template only |
| `EXPAND_SCOPE` | adaptive rule (§8) | no |
| `ABDUCE(unattributed[])` | unattributed set non-empty | yes |
| `ASK_HUMAN(question)` | triggers in §7 | phrasing only |
| `STOP_RESOLVED` / `STOP_BOUNDED` | stop predicate | no |

No `CHALLENGE` action — anti-confirmation is structural (§2, M2).

---

# 5. Hypothesis Lifecycle

**PROPOSE** (LLM, ≥1 benign) → **VALIDATE** (C1–C2) → **TEST** (expectations from *all* live explanations) → **UPDATE** (C3–C5) → **EXPAND** (LLM, triggered by unattributed observations) → **REJECT** (all expectations refuted; reason retained, never deleted) → **STOP**.

Explosion control, all deterministic: cap 7 live; merge on >80% attribution overlap; drop highest-arbitrariness when over cap.

---

# 6. Evidence Lifecycle

**OBSERVE** → **VALIDATE** (parse; failure → `PARSE_FAILED`) → **EXTRACT + TAINT** → **LINK** → **CONTRADICT** → **UNAVAILABLE** (`UNKNOWN` + `dark_sources`) → **ARCHIVE** (nothing deleted mid-investigation).

---

# 7. Human Interaction

**Unconditional escalation:**
1. Unattributed observations persist after one abduction round.
2. A source is dark for a window some expectation requires.
3. Two `OBSERVED` sources conflict irreconcilably.
4. `STOP_BOUNDED` reached.
5. A disposition would rest on `TAINTED` attributions alone.
6. **`entity_connected_fraction` below threshold** — i.e. the agent knows most of the scope was unreachable from what it confirmed. **[new, driven by E6]**

**Rules.** Human input is `TESTIMONY`, never `OBSERVED`, never overwrites a machine observation. Human explanations pass identical constraints — no privilege. Disagreement becomes a conflict, not an overwrite. A human may force `CONTINUE` or `STOP_BOUNDED` but **may not force `STOP_RESOLVED` while blocking conditions hold**. Mandatory confirmation: any `MALICIOUS` disposition, any `STOP_BOUNDED`, any unresolved conflict.

The value-of-information formulation for cost-gating escalation exists **[LIT — parameter-free, weighs expected utility gain against cognitive cost, matches or exceeds manually-tuned thresholds across four domains including medical diagnosis]** but should not be built in v1; the six triggers need no calibration.

---

# 8. Initial Context Strategy — **changed by E6**

**Adaptive, conditioned on alert richness.** This is the regime effect E6 exposed.

```
if alert contains ≥1 concrete entity (host, user, process, IP, domain):
    seed = entity-neighbourhood retrieval around alert entities
else:                                    # sparse / entity-free alert
    seed = broad sampling; do NOT use brief-similarity ranking
```

**[MEASURED]** E6: on CDB's entity-free briefing, brief-similarity observation-first scored *below uniform random* at every budget (0.019/0.029/0.061 vs 0.023/0.054/0.099). Ranking on a generic alert text is worse than not ranking at all. Where an entity anchor exists (DiagChain's richer inputs), hypothesis-independent retrieval is competitive — but E4 showed that measurement was confounded, so the honest position is: **entity anchor present → either policy is defensible; absent → use broad sampling and say so.**

Once confirmed evidence exists, retrieval becomes entity-pivot driven, with the **hybrid** allocation: half the budget on entity pivot, half on unconditioned sampling. **[MEASURED]** E6: hybrid was best at k=10% (0.122 vs 0.107 HF, 0.061 OF), though at n=3 chains this is direction only.

---

# 9. Query / Action Selection

Actions are **generated by explanations' own expectations**, ordered by: expectations discriminating the most live explanations first; then lowest cost. No probabilistic policy.

**[MEASURED]** justification: E6 shows the between-policy spread (0.046 at k=10%) is dwarfed by the distance to the reachability ceiling (0.165). Optimising *which* action to take cannot help much when the reachable set itself is the binding constraint. This also retires the action-selection question the earlier audits kept deferring — it is not the bottleneck.

---

# 10. Hypothesis Update

Symbolic support/defeat plus ordinal arbitrariness ranking. **No Bayesian update.** P(E|H) has no honest source: expert elicitation doesn't scale, fitting from historical attacks violates the no-incident-training constraint, and reading it from LLM confidence is an assumption, not a posterior. **[LIT — defeasible argumentation as a worthwhile alternative to probability for evidential reasoning, with explicit modelling of direct vs ancillary evidence and of distinct argument types]**

Dempster-Shafer remains a documented fallback if ordinal ranking proves too coarse, with the caveat that it needs a stated combination rule.

---

# 11. Stopping

Two terminal states. **Renamed from the previous design because the evidence changed what the second one means.**

**`STOP_RESOLVED`** — all of:
1. every demanding observation attributed by a `LIVE` explanation;
2. every expectation `CONFIRMED` or `REFUTED` (none `UNTESTED`/`UNTESTABLE`);
3. no surviving cross-class rival;
4. `dark_sources` empty for any source a live expectation requires;
5. **`coverage_bound` shows no unqueried source and no uncovered window.**

**`STOP_BOUNDED`** *(was `STOP_EXHAUSTED`)* — conditions relaxed, plus any of: dark required source; budget exhausted; pivot pool exhausted; no executable action remains. **Must emit the coverage bound**: which sources were never queried, which windows never covered, what fraction of scope was entity-connected.

The rename is substantive. E6 showed that in the common case the agent has not exhausted the investigation — it has hit a **reachability boundary** and cannot tell the difference from the inside. Naming the state honestly is what makes the residual reportable.

**Confidence and probability appear nowhere in this predicate.** Structure borrowed from the medical threshold model — keep testing while a live rival would change the action **[LIT — testing threshold / test-treatment threshold, plus the therapeutic threshold for equipoise when diagnostic options are exhausted]** — using the action-relevance criterion, not the numbers.

---

# 12. Unknown-Attack Handling — **honest version**

The completeness mechanism proposed in the previous architecture is dead. Both of its legs failed measurement:

- **Retrieval leg.** Evidence for the unconceived part of a chain is reachable via entity pivot at **mean 0.272**, per-chain as low as **0.006**. **[MEASURED, E6]**
- **Detection leg.** The unattributed-observation trigger fires in 85% of cases at **median precision 0.050**. **[MEASURED, E3]** It carries roughly prevalence-level information: a constant alarm that means nothing.

*Caveat on the detection leg:* DiagChain has no benign ground truth, so "noise" cards are unattributable by construction. In deployment, benign explanations would absorb routine telemetry and precision could be higher. This is **untestable on any current benchmark** and should be stated as such rather than assumed either way.

**What replaces it.** The agent cannot detect its own blindness, so it must **bound and report** it instead:

1. `UNKNOWN` remains a first-class explanation class; ATT&CK/Sigma/CTI appear only as optional labels and as sources of expectations to test — never defining the hypothesis space.
2. Unattributed observations still trigger abduction — cheap, occasionally useful, no longer load-bearing.
3. **Every terminal state emits a coverage bound.** Not "the investigation is complete" but "these sources were queried, these were not; this fraction of scope was entity-connected to confirmed evidence; these windows were never covered."
4. Escalation trigger 6 fires when the connected fraction is low.

This converts an undetectable failure into a **stated limitation on the output**. It does not solve the problem. Nothing available solves the problem.

---

# 13. LLM Boundary

| Stage | Verdict | Calls |
|---|---|---|
| Field extraction, taint | **FORBIDDEN** | 0 |
| Retrieval, scope expansion | NOT NEEDED | 0 |
| Abduction | **REQUIRED** | 3–6 |
| All constraints | NOT NEEDED | 0 |
| Action selection, control queries, stop | NOT NEEDED | 0 |
| Query generation (templated) | NOT NEEDED | 0 |
| Query generation (novel) | REQUIRED | 3–8 |
| Final account | REQUIRED (highest risk) | 1 |

**≈ 8–16 calls per investigation.**

**Against "give the logs to one big model":** ExCyTIn spans 57 Sentinel tables, CDB's sample alone is 155,350 events — they do not fit. And the monolithic design is the exact configuration measured at 96% injection success on summarization with tool access over attacker-authored text. **[LIT]** Every deterministic module here that touches raw logs *instead of* the model is a reduction in that surface. That is the architecture's justification for existing.

---

# 14. Evaluation Plan

**Do not use DiagChain MAIN-69 for retrieval-strategy questions.** **[MEASURED, E4/E5]** Content-free IDF ranking beats every designed policy there (2.23× lift over random); the same null gives 0.68–1.08× on CDB. Gold cards are 1.32× longer than noise cards on MAIN-69; malicious events are 1.12× longer than benign on CDB. **Any retrieval experiment must report an IDF null and a length null, or its result is uninterpretable.** This applies to anyone reproducing DiagChain-style work, not just to us.

**Use MAIN-69 for what it was built for:** stage-wise chain-reconstruction scoring given evidence — retrieval coverage, grouping (B³), ordering, grounding F1, attribution gap, and the first-failure funnel.

**Use CDB for evidence-acquisition and unseen-distribution questions:** Gymnasium env, binary verifiable rewards, seeded entity substitution and GUID re-anonymization.

**Next experiments, in priority order:**
1. **E6 at scale.** n=3 chains is a pilot. Run all 106 CDB procedures. This is the only cheap way to firm up the reachability ceiling, which is now the single most important number in the design.
2. **The LLM-hypothesis confound.** Both retrieval policies with a real model generating the partial hypothesis, rather than my entity/gold proxies. One run decides whether hypothesis-first has more headroom than entity pivoting showed.
3. **Trigger precision with benign labels.** Requires a benchmark with benign ground truth. None exists. Building one is a contribution in itself.

---

# 15. Known Limitations

1. **Hypothesis completeness is unsolved and now measured.** Reachability ceiling 0.272 mean, 0.006 worst case. Reiter-style consistency-based diagnosis gives completeness only *relative to a system description* you do not have; conformal prediction's coverage guarantee rests on exchangeability and voids precisely on novel attacks.
2. **The coverage alarm does not work.** Median precision 0.050.
3. **Baseline poisoning has no in-band detection.** If the attacker was resident during baselining, their activity never registers as demanding attribution.
4. **`VALID_NEGATIVE` is defeated by log deletion.** Control query passes, target returns empty, system concludes correctly about a false world. Unsolvable without tamper-evident logging.
5. **Injection is reduced, not eliminated.** 11.8% residual under the strongest tested defense, on a system simpler than this one.
6. **n=3 on the decisive experiment.** Direction and magnitude only.

---

# 16. Evidence Table

| Decision | Chosen | Alternatives tested | Evidence | Confidence |
|---|---|---|---|---|
| Adaptive initial context | Entity-anchored if available, else broad sampling | pure OF; pure HF; hybrid | **[MEASURED]** E6: OF below random on entity-free alerts | Medium (n=3) |
| Retrieval after confirmation | Hybrid pivot + unconditioned | HF only; OF only | **[MEASURED]** E6: hybrid best at k=10% | Low (n=3) |
| No formal action-selection policy | Expectation-generated, ordinal ordering | EIG, VoI, POMDP, MCTS | **[MEASURED]** E6: policy spread ≪ reachability gap | Medium |
| No Bayesian update | Symbolic + arbitrariness | Bayes, D-S, ordinal | **[LIT]** no honest likelihood source | High |
| Three query outcomes + control query | `ROWS`/`VALID_NEGATIVE`/`UNKNOWN` | metadata-based LCWA | **[LIT]** internal vs external interpretation; certainly-true/false/unknown classification | High |
| Coverage bound replaces coverage check | Report the bound | unattributed-observation alarm | **[MEASURED]** E3: precision 0.050 → **[KILLED]** | High |
| Two terminal states | `STOP_RESOLVED` / `STOP_BOUNDED` | single stop; confidence threshold | **[LIT]** threshold model + **[MEASURED]** E6 reachability | Medium |
| Deterministic extraction | Forbidden to LLM | LLM extraction | **[LIT]** injection surface | High |
| Taint gate | Field-level labelling | none | **[LIT]** for the risk, **[UNTESTED]** for the mitigation | Low |
| Relation re-derivation (C3) | Recompute from cited fields | LLM judge | **[UNTESTED]** | Low |
| Benchmark choice | CDB for retrieval, MAIN-69 for chain scoring | MAIN-69 for both | **[MEASURED]** E4/E5 | High |

---

# 17. Self-Critique

**Based on one experiment only:** the adaptive context rule (E6, n=3); the hybrid allocation (E6, n=3); the claim that action selection is not the bottleneck (E6, n=3). All three need E6 at scale before they are load-bearing.

**Replicated / multiply supported:** the coverage-alarm failure (E3 precision + E6 reachability ceiling, two independent measurements pointing the same way); the DiagChain metric invalidity (E4 null result + E5 cross-benchmark contrast + the benchmark's own `hidden_targets` documentation).

**Changed after experimentation:** the observation-first reframe (from central thesis → conditional, regime-dependent, and below random in one regime); the coverage mechanism (from the answer to RED 1 → killed, replaced by bound reporting); `STOP_EXHAUSTED` → `STOP_BOUNDED`; entity-graph traversal (from load-bearing → one heuristic among several); the previous two turns' retrieval conclusions (both retracted).

**Still unsupported:** C3 relation re-derivation, the taint gate's effectiveness, the arbitrariness ranking in practice, and every human-in-the-loop trigger.

**Strongest counterexample to the final architecture.** An attacker whose later stages share no entities with the alerted stage — a separate host, separate account, separate credential path. E6 chain 0 is exactly this case: 0.6% of held-out evidence entity-reachable. The agent confirms the alerted portion, grounds every claim, exhausts its pivot pool, reaches `STOP_BOUNDED`, and reports a coverage bound the analyst may not act on. Every mechanism in this design works correctly and the investigation is still substantially wrong. **The coverage bound is the only thing standing between that outcome and a confident false negative, and its usefulness depends entirely on an analyst reading it.**
