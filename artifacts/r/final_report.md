# Hunt Report

## 1. Request and Outcome
<!-- ## 1. Hypothesis / Question -->

> r

- **Request ID:** `r`
- **Hunt Kind:** `HUNT`
**Result:** `SUPPORTED`  
**Stopping:** `STOP_INCONCLUSIVE`
**Stopping Taxonomy:** `COVERAGE_EXHAUSTED`

**Answer Status:** `FULLY_ANSWERED`

**Answer (file):** `sensitive_doc.pdf`

**Answer explanation:** Variable 'var_file' proved as 'sensitive_doc.pdf'.

- **Candidate Host(s) — not proof:** `MACLORY-AIR13`
- **User Context(s):** `mallory`

## 2. Proposed/Accepted Graph and Assumptions
<!-- ## 2. Hypothesis analysis -->

- `SUPPORTED` — content

### Semantic decomposition

- `var_user`: `account` = `mallory`; origin=`request`, verification=`UNVERIFIED`
- `var_endpoint`: `endpoint`; constraints: hardware_form_factor=MacBook; origin=`llm_proposal`, verification=`UNVERIFIED`
- `var_file`: `file`; origin=`llm_proposal`, verification=`UNVERIFIED`
- Claim `rel_user_host`: `var_user` — `associated_with` → `var_endpoint`
- Claim `rel_host_file`: `var_endpoint` — `modified` → `var_file`
- Answer: `var_file` as `file`

### Proof plan

- `selected` `rel_user_host` via `resolve-user-host` (cost=1)
- `selected` `rel_host_file` via `find-files-on-host` (cost=1; requires `rel_user_host`)

### Unverified restrictions

The retrieved rows prove only the declared relation. These request restrictions were not proven by a declared provider capability:
- `rel_user_host`: `hardware_form_factor=MacBook`

## 3. Step Trace and Binding Changes

### Lifecycle step trace

| Step | Lifecycle Phase | Duration (ms) | Status | Key Inputs / Outputs |
|---|---|---|---|---|
| 1 | `STEP_A_FREEZE_REQUEST` | 0.0 | `SUCCESS` | in: request_id=r; content=content |
| 2 | `STEP_B_COMPILE_GOAL_GRAPH` | 0.0 | `SUCCESS` | in: request_id=r; out: has_semantic_goal_graph=True |
| 3 | `STEP_D_BIND_CANDIDATES` | 0.0 | `SUCCESS` | in: initial_variables=var_user; out: bound_variable_count=1 |
| 4 | `STEP_E_COMPILE_QUERY_INTENT` | 0.0 | `SUCCESS` | in: plan_steps=2; out: planned_attempts=2 |
| 5 | `STEP_F_EXECUTE_NATIVE_QUERY` | 0.0 | `SUCCESS` | in: executions=2; out: total_rows=2; statuses=EXECUTED, EXECUTED |
| 6 | `STEP_G_RECORD_OBSERVATIONS` | 0.0 | `SUCCESS` | in: total_observations=2; out: evidence_cards=1 |
| 7 | `STEP_H_VERIFY_PROOF` | 0.0 | `SUCCESS` | in: goal_count=2; out: verdicts=INCONCLUSIVE_RESTRICTIONS_UNVERIFIED, INCONCLUSI... |
| 8 | `STEP_I_CHECK_STOPPING` | 0.0 | `SUCCESS` | in: stopping_decision=StoppingDecision.STOP_INCONCLUSIVE; out: route_exhausted=; unresolved_steps=0 |

### Execution trace

1. `step-1` gọi `resolve-user-host` (candidate #1, page 1): 1 row(s), complete=True, executed_ok=True; goal `rel_user_host` => `INCONCLUSIVE_RESTRICTIONS_UNVERIFIED`.
2. `step-2` gọi `find-files-on-host` (candidate #1, page 1): 1 row(s), complete=True, executed_ok=True; goal `rel_host_file` => `INCONCLUSIVE`.

### Runtime bindings

- `var_user`: `mallory` (VERIFIED) from `request`
- `var_endpoint`: `MACLORY-AIR13` (VERIFIED) from `logical-g-step-1`
- `var_file`: `sensitive_doc.pdf` (VERIFIED) from `logical-g-step-2`

## 4. Evidence and Proof Decisions
<!-- ## 3. Evidence and explanation -->

| Evidence | Why it matters | Observed values | Source |
|---|---|---|---|
| Telemetry observations (2 events on MACLORY-AIR13) | Observed operational telemetry within the monitored scope. | no readable fields summarized | 2 event(s); query: `logical-g-step-1`, `logical-g-step-2`; observations: `obs-logical-g-step-1-0`, `obs-logical-g-step-2-0` |

### Evidence details

- `card-3cb7db88e48b` — fact=`generic_telemetry`, count=`2`, completeness=`complete`; observed: no readable fields summarized

### Explanation

- **Deterministic Graph Resolution:** The target object `sensitive_doc.pdf` was proven through 0 verified claim relation(s).
- **Deterministic Explanation:** Variable 'var_file' proved as 'sensitive_doc.pdf'.
- Observed operational telemetry within the monitored scope.
- Limitation: No definitive adversary presence or refutation established in searched frame.

### Semantic route assessments

- Goal `rel_user_host` (`associated_with`): status=`CANDIDATE_OBSERVED`, execution_complete=`True`, proof_complete=`False`, route_exhausted=`False`, readiness=`RETRIEVAL_CAPABLE`, terminal=`none`
  - Proof gaps: `relation_or_constraint_proof_missing`
  - Attempt `attempt-1`: operation=`resolve-user-host`, source=`scope-1`, schema=`unknown`, stage=`narrow`, query=`logical-g-step-1`, complete=`True`, rows=`1`, trigger=`initial_route`, negative_license=`False`, alternatives=`[]`
- Goal `rel_host_file` (`modified`): status=`CANDIDATE_OBSERVED`, execution_complete=`True`, proof_complete=`False`, route_exhausted=`False`, readiness=`RETRIEVAL_CAPABLE`, terminal=`none`
  - Proof gaps: `relation_or_constraint_proof_missing`
  - Attempt `attempt-2`: operation=`find-files-on-host`, source=`scope-1`, schema=`unknown`, stage=`narrow`, query=`logical-g-step-2`, complete=`True`, rows=`1`, trigger=`initial_route`, negative_license=`False`, alternatives=`[]`

### Proof state

- `rel_user_host`: `INCONCLUSIVE_RESTRICTIONS_UNVERIFIED`
- `rel_host_file`: `INCONCLUSIVE`

## 5. Native Queries, Result Summaries and Completeness
<!-- ## 4. Queries used -->

### `logical-g-step-1` — `rel_user_host`
- **Purpose:** resolve-user-host

- **Input binding:** `subject=mallory`
- **Expected output fields:** `host`, `timestamp`
- **Result:** 1 rows returned; complete=True
- **Observed fields:** none
- **Execution:** executed_ok=`True`, diagnostic=`none`
- **Hypothesis Impact:** Targets `h1`
Provider: `mock-edr`; completeness: `provider-declared`

- **Provider pages:** `1`; continuation=`False`
```text
search user=mallory | table host, user
```

**Returned sample rows (raw payload omitted):**

- Row 1: host=MACLORY-AIR13; user=mallory

### `logical-g-step-2` — `rel_host_file`
- **Purpose:** find-files-on-host

- **Input binding:** `subject=MACLORY-AIR13`
- **Expected output fields:** `host`, `timestamp`
- **Result:** 1 rows returned; complete=True
- **Observed fields:** none
- **Execution:** executed_ok=`True`, diagnostic=`none`
- **Hypothesis Impact:** Targets `h1`
Provider: `mock-edr`; completeness: `provider-declared`

- **Provider pages:** `1`; continuation=`False`
```text
search host=MACLORY-AIR13 | table file, host, action
```

**Returned sample rows (raw payload omitted):**

- Row 1: host=MACLORY-AIR13; file=sensitive_doc.pdf; action=modified


## 6. Coverage and Cost
<!-- ## 5. Cost -->

### Scope and Requirement Coverage

- **Causal Path Coverage:** `0.0%` (0/2 relations verified)
- **Wildcard Scope Coverage:** `100.0%` (1/1 broadsweep cells)
- **Instance Cell Coverage:** `100.0%` (1/1 concrete entity cells)

### Cost Accounting

- Model: `stub`
- Calls: `0`
- Physical API attempts: `0`
- Failed calls: `0`
- Tokens: `0` (estimated)
- Token accounting mode: `ESTIMATED`
- Estimated cost: `$0.000000`
