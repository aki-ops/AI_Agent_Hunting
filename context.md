# AI Agent Hunting — Project Context

> File này tổng hợp toàn bộ context của project từ FINAL-ARCHITECTURE.md và EXECUTION-PLAN.md, giúp bất kỳ AI agent nào (Claude, GPT, Gemini...) hiểu rõ project để hỗ trợ coding và research.

---

## 1. Project là gì?

Xây dựng một **Threat Investigation Agent** — agent AI điều tra mối đe dọa an ninh mạng, trong đó:
- **LLM chỉ đề xuất giải thích (abduction) và dịch truy vấn** — tất cả phần còn lại là **deterministic**
- Mọi bằng chứng, trích xuất field, gán nhãn taint, constraint checking, action ordering, stopping, escalation — đều **không dùng LLM**
- Mục tiêu: **8–16 LLM calls mỗi cuộc điều tra**
- Agent hỗ trợ **Human-in-the-Loop**: analyst con người luôn có quyền can thiệp

---

## 2. Kiến trúc 5 Module (FROZEN)

```
ALERT → SCOPE FRONTIER
          ↓
        [M1] OBSERVATION LEDGER      deterministic
          ↓ unattributed observations
        [M2] ABDUCTION ENGINE        LLM (REQUIRED)
          ↓ proposed explanations
        [M3] CONSTRAINT CHECKER      deterministic (C1,C2,C5 in v1)
          ↓ validated state
        [M4] CONTROLLER              deterministic
          ↓ action
        [M5] ADAPTER / REPORTER      templates + LLM fallback
          ↓
        ANALYST ← escalation + coverage bound
```

### M1 — Evidence Ledger (deterministic, injection boundary)
- Trích xuất fields từ raw logs (parser, không LLM)
- Gán nhãn taint: `ATTACKER_INFLUENCED` vs `STRUCTURAL` per-field
- Epistemic typing: `OBSERVED` vs `TESTIMONY`
- Outcome typing: `ROWS` / `VALID_NEGATIVE` / `UNKNOWN`
- **Reachability accounting**: theo dõi sources đã/chưa query, entity-connected fraction, windows chưa covered
- Parse failure → `PARSE_FAILED`, không bao giờ drop silently

### M2 — Abduction Engine (LLM — REQUIRED)
- Prompt luôn là *"what could account for these observations?"* — không bao giờ *"does X hold?"*
- Input: extracted fields + taint labels — **KHÔNG BAO GIỜ raw log text**
- Output: `Explanation{id, label, class: BENIGN|MALICIOUS|UNKNOWN, attributions[], expectations[], assumptions[]}`
- Bắt buộc diversity: ≥1 BENIGN + ≥1 MALICIOUS nếu cả hai đều hợp lý
- Explosion control: cap 7 live explanations, merge nếu >80% overlap

### M3 — Constraint Checker (deterministic)
- C1: Schema well-formedness → reject
- C2: Cited observation phải tồn tại → reject attribution
- C3: Relation re-derivation (v2) → `MISATTRIBUTED`
- C4: Taint gate (v2; label in v1) → `TAINTED`, không đủ carry disposition
- C5: Contradiction vs expectations → `WEAKENED` + conflict
- C6: Arbitrariness count (v2) → ranking input

### M4 — Controller (deterministic)
Thứ tự mỗi turn:
1. Stop predicate → terminal
2. Escalation trigger → `ASK_HUMAN`
3. Untested expectation → `QUERY(expectation)`
4. Pending negative → `CONTROL_QUERY`
5. Unattributed observations → `ABDUCE`
6. Else → `EXPAND_SCOPE` (adaptive rule)

### M5 — Translate / Report (LLM fallback)
- 7 intent templates: `ProcessLineage`, `LogonHistory`, `NetworkConnections`, `PersistenceArtifacts`, `FileWrites`, `DNSQueries`, `AnyEventControl`
- Templates là deterministic, LLM chỉ dùng cho novel intents (<30%)
- Reporter nhận extracted fields + observation IDs, **không bao giờ raw log text**

---

## 3. Data Contracts (Key Types)

```python
Observation    = {id, source, scope_id, timestamp,
                  epistemic_type: OBSERVED|TESTIMONY,
                  fields{}, taint{field: STRUCTURAL|ATTACKER_INFLUENCED},
                  provenance{query_id, collector, ingest_time},
                  attributed_by[], demanding?: bool}

Explanation    = {id, label, class: BENIGN|MALICIOUS|UNKNOWN,
                  status: LIVE|WEAKENED|REJECTED,
                  origin: LLM|HUMAN,
                  attributions[{observation_id, cause, status}],
                  expectations[Expectation],
                  arbitrariness?: int, rejection_reason?}

Expectation    = {id, description, scope,
                  test_status: UNTESTED|CONFIRMED|REFUTED|UNTESTABLE}

QueryResult    = {query_id, outcome: ROWS|VALID_NEGATIVE|UNKNOWN,
                  diagnostic?, control_query_id?, rows?}

FinalAccount   = {disposition: MALICIOUS|BENIGN|UNKNOWN|
                                INSUFFICIENT_EVIDENCE|CONFLICTED,
                  terminal_state: STOP_RESOLVED|STOP_BOUNDED,
                  chain[{claim, observation_ids[]}],
                  coverage_bound, residual, human_confirmed: bool}
```

---

## 4. Kết quả thực nghiệm quan trọng (Đã đo)

| Thí nghiệm | Kết quả | Hệ quả |
|---|---|---|
| **E1b** | Gold-prose baselines leak (8.5× vocabulary leakage) | B-04 hidden-target guard bắt buộc |
| **E3** | Coverage alarm: precision 0.050, fires 85% cases | **KILLED** — thay bằng coverage-bound reporting |
| **E4** | Content-free mean-IDF ranking 0.662 trên MAIN-69 | MAIN-69 INVALID cho retrieval-policy questions |
| **E5** | IDF-null lift: DiagChain 2.23× vs CDB 0.68–1.08× | Artifact là construction-specific |
| **E6** | Entity pivot reachability: mean **0.272**, worst **0.006** | Ceiling là reachable set, không phải policy |
| **E6** | Policy spread 0.046 ≪ reachability gap 0.165 | Action-selection KHÔNG phải bottleneck |
| **E6** | OF dưới random trên entity-free alerts | Pure observation-first **KILLED** as default |

---

## 5. Stopping Rules

**`STOP_RESOLVED`** — tất cả 5 điều kiện:
1. Mọi demanding observation được attributed bởi LIVE explanation
2. Mọi expectation đã CONFIRMED hoặc REFUTED (không UNTESTED)
3. Không có cross-class rival sống sót
4. dark_sources empty cho mọi source mà live expectation cần
5. coverage_bound không có unqueried source hay uncovered window

**`STOP_BOUNDED`** — điều kiện nới lỏng + dark required source / budget exhausted / pivot pool exhausted / no executable action. **Bắt buộc emit coverage bound.**

---

## 6. Human-in-the-Loop (6 Escalation Triggers)

1. Unattributed observations persist sau một round abduction
2. Source dark cho window mà expectation cần
3. Hai OBSERVED sources conflict không hòa giải được
4. `STOP_BOUNDED` reached
5. Disposition chỉ dựa trên TAINTED attributions
6. `entity_connected_fraction` dưới threshold (từ E6)

**Rules:** Human input = TESTIMONY, không overwrite observation. Human explanations qua cùng constraints. Disagreement = conflict, không phải overwrite. Human KHÔNG THỂ force `STOP_RESOLVED` khi blocking conditions còn.

---

## 7. LLM Boundary (Nghiêm ngặt)

| Stage | Verdict | Calls |
|---|---|---|
| Field extraction, taint | **FORBIDDEN** | 0 |
| Retrieval, scope expansion | **FORBIDDEN** | 0 |
| Abduction | **REQUIRED** | 3–6 |
| All constraints | **FORBIDDEN** | 0 |
| Action selection, control queries, stop | **FORBIDDEN** | 0 |
| Query generation (templated) | **FORBIDDEN** | 0 |
| Query generation (novel) | REQUIRED | 3–8 |
| Final account | REQUIRED | 1 |
| **Total** | | **8–16** |

---

## 8. Security Constraints

- **B-04**: Hard-block gold prose (`attack_step`, `step_description`, tactic/technique labels, `causal_edges`, support mapping) khỏi query/prompt
- **E-02**: Prompt input filter — extracted fields + taint labels only, NEVER raw log text
- **M-02**: Assert LLM never receives raw `content` field (static + runtime check)
- **C-03/C-04**: Taint gate — attribution dựa solely trên attacker-influenced fields → TAINTED
- Injection corpus S1–S4 từ [REF-INJECT-01]

---

## 9. Datasets & Benchmarks

| Dataset | Valid for | Invalid for |
|---|---|---|
| **CDB** (155,350 events) | Retrieval, evidence-acquisition, EXP-01/02/04/06/08 | Benign-attribution claims |
| **DiagChain MAIN-69** | Evidence-use, grounding, attribution, EXP-05/07 | **Retrieval-policy selection** (IDF null 0.662) |
| **ExCyTIn** | End-to-end reward, EXP-07 alt | Fine-grained stage attribution |

---

## 10. Implementation Priority & Timeline

### Critical Path
`A-01 → A-02 → B-01 → C-01 → D-01 → E-01 → F-01 → G-01 → H-01 → first end-to-end run`

### Build Order
1. **M1** (Evidence Ledger) — injection boundary, mọi module phụ thuộc
2. **M3** (Constraints) — gates trước khi LLM code tồn tại
3. **M4** (Controller) — test full loop với stubbed abduction, ZERO LLM calls
4. **M5** (Adapter) — templates trước LLM fallback
5. **M2** (Abduction) — build cuối cùng, vì gates/controller/adapters đã constrain nó

### MVP (Week 9)
Alert → observation → stubbed abduction → expectation → query → observation → update → stop. **Zero LLM calls.** Chứng minh deterministic core chạy standalone.

### Key Experiments
1. **EXP-02** (P1): Retrieval tại scale, n≥100 — xác nhận/kill §10
2. **EXP-01** (P2): LLM-hypothesis confound — n≥30×3
3. **EXP-04** (P3): Control query epistemic matrix
4. **EXP-07** (P4): Abduction recovery

---

## 11. Known Limitations (MUST STATE)

1. **Hypothesis completeness unsolved**: reachability ceiling 0.272 mean, 0.006 worst
2. **Coverage alarm doesn't work**: precision 0.050
3. **Baseline poisoning**: no in-band detection
4. **VALID_NEGATIVE defeated by log deletion**: control query passes on tampered data
5. **Injection reduced, not eliminated**: 11.8% residual under strongest defense
6. **n=3 on decisive experiment**: direction and magnitude only

---

## 12. Architecture Status Tags

- **LOCKED**: 5 modules, observation ledger, LLM abduction, C1/C2/C5, deterministic controller, template-first queries, escalation, 2 terminal states, 3-valued outcome typing, no probabilistic core, no RL/POMDP
- **PROVISIONAL**: entity-driven scope expansion, expectation-driven ordering, control query, C4, C6, retrieval policy details
- **REJECTED** (cần evidence mới để re-enter): gold-prose baselines, pure observation-first as default, coverage alarm as primary signal, POMDP/RL/MCTS/multi-agent
- **UNSUPPORTED** (không được claim validated): control query, C3, coverage-bound mechanism, taint-gate effectiveness, escalation triggers
- **FUNDAMENTALLY UNRESOLVED**: complete hypothesis coverage, evidence outside reachable scope, baseline poisoning, deleted-evidence detection, LLM creative-abduction reliability

---

## 13. Tech Stack & Environment

- **Language**: Python 3.10+, typed, CI, lint
- **Deterministic seeding**: git SHA, config hash, seed → run manifest
- **LLM client**: cache + call/token counter
- **Benchmarks**: CDB (Gymnasium), DiagChain (evidence cards), ExCyTIn (HuggingFace)
- **Testing**: unit (every deterministic component) + integration (full loop) + security (S1–S4 injection)

---

## 14. Contributions (Thực sự)

1. **Benchmark-validity finding**: IDF null 0.662 trên MAIN-69 — retrieval experiments cần null baselines
2. **Reachability ceiling**: mean 0.272 — constraint là reachable set, không phải policy (pending EXP-02)
3. **Epistemic layer cho negative evidence**: control query (original, unproven until EXP-04)
4. **Coverage-bound reporting**: thay thế coverage alarm precision 0.050 (negative-result-driven)
5. **Architecture composition**: 5 modules từ DiagChain + incomplete-DB + medical thresholds + argumentation + taint (defensible, not novel)
