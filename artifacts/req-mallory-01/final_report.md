# Hunt Report

## 1. Request and Outcome
<!-- ## 1. Hypothesis / Question -->

> Find confidential files on Mallory's endpoint

- **Request ID:** `req-mallory-01`
- **Hunt Kind:** `HUNT`
**Result:** `INCONCLUSIVE`  
**Stopping:** `STOP_NEEDS_USER_DECISION`
**Stopping Taxonomy:** `NEEDS_DISAMBIGUATION`

**Answer Status:** `INCONCLUSIVE`

**Answer:** Inconclusive (USER_DECISION_REQUIRED)

**Answer explanation:** Candidate bindings were discovered, but no downstream query was executed because an analyst must select the intended binding.

**Candidates:**
- `var_user`: `mallory` (VERIFIED)
- `var_endpoint`: `WORKSTATION-01` (CANDIDATE)
- `var_endpoint`: `WORKSTATION-02` (CANDIDATE)
- `var_endpoint`: `WORKSTATION-03` (CANDIDATE)
- `var_endpoint`: `WORKSTATION-04` (CANDIDATE)
- `var_endpoint`: `WORKSTATION-05` (CANDIDATE)
- `var_endpoint`: `MACLORY-AIR13` (CANDIDATE)

## 2. Proposed/Accepted Graph and Assumptions
<!-- ## 2. Hypothesis analysis -->

- `LIVE` — Find confidential files on Mallory's endpoint

### Semantic decomposition

- `var_user`: `account` = `mallory`; origin=`request`, verification=`UNVERIFIED`
- `var_endpoint`: `endpoint`; origin=`llm_proposal`, verification=`UNVERIFIED`
- `var_file`: `file`; origin=`llm_proposal`, verification=`UNVERIFIED`
- Claim `rel_user_host`: `var_user` — `associated_with` → `var_endpoint`
- Claim `rel_host_file`: `var_endpoint` — `modified` → `var_file`
- Answer: `var_file` as `file`

### Proof plan

- `selected` `rel_user_host` via `resolve-user-host` (cost=1)
- `alternative` `rel_user_host` via `logged-on-to-host` (cost=1)
- `selected` `rel_host_file` via `find-files-on-host` (cost=1; requires `rel_user_host`)

## 3. Step Trace and Binding Changes

### Lifecycle step trace

| Step | Lifecycle Phase | Duration (ms) | Status | Key Inputs / Outputs |
|---|---|---|---|---|
| 1 | `STEP_A_FREEZE_REQUEST` | 0.0 | `SUCCESS` | in: request_id=req-mallory-01; content=Find confidential file... |
| 2 | `STEP_B_COMPILE_GOAL_GRAPH` | 0.0 | `SUCCESS` | in: request_id=req-mallory-01; out: has_semantic_goal_graph=True |
| 3 | `STEP_D_BIND_CANDIDATES` | 0.0 | `SUCCESS` | in: initial_variables=var_user; out: bound_variable_count=1 |
| 4 | `STEP_E_COMPILE_QUERY_INTENT` | 0.0 | `SUCCESS` | in: plan_steps=2; out: planned_attempts=1 |
| 5 | `STEP_F_EXECUTE_NATIVE_QUERY` | 0.0 | `SUCCESS` | in: executions=1; out: total_rows=6; statuses=AMBIGUOUS |
| 6 | `STEP_G_RECORD_OBSERVATIONS` | 0.0 | `SUCCESS` | in: total_observations=6; out: evidence_cards=0 |
| 7 | `STEP_H_VERIFY_PROOF` | 0.0 | `SUCCESS` | in: goal_count=2; out: verdicts=SUPPORTED, INCONCLUSIVE; verified_goals=1 |
| 8 | `STEP_I_CHECK_STOPPING` | 0.0 | `SUCCESS` | in: stopping_decision=StoppingDecision.STOP_NEEDS_USER_DECISION; out: route_exhausted=; unresolved_steps=1 |

### Execution trace

1. `step-1` gọi `resolve-user-host` (candidate #1, page 1): 6 row(s), complete=True, executed_ok=True; goal `rel_user_host` => `SUPPORTED`.
- `step-1` chưa chạy/hoàn tất: ambiguous output binding 'var_endpoint' has 6 candidates for singular slot; auto-binding prohibited
- `step-2` chưa chạy/hoàn tất: required upstream proof is incomplete: step-1

### Runtime bindings

- `var_user`: 1 candidate(s); see candidate groups
- `var_endpoint`: 6 candidate(s); see candidate groups

## 4. Evidence and Proof Decisions
<!-- ## 3. Evidence and explanation -->

No evidence cards were produced.

### Explanation

- **Deterministic Explanation:** Candidate bindings were discovered, but no downstream query was executed because an analyst must select the intended binding.
- Limitation: No definitive adversary presence or refutation established in searched frame.

### Semantic route assessments

- Goal `rel_user_host` (`associated_with`): status=`CANDIDATE_OBSERVED`, execution_complete=`True`, proof_complete=`False`, route_exhausted=`False`, readiness=`RETRIEVAL_CAPABLE`, terminal=`none`
  - Proof gaps: `relation_or_constraint_proof_missing`
  - Attempt `attempt-1`: operation=`resolve-user-host`, source=`scope-1`, schema=`unknown`, stage=`narrow`, query=`logical-graph-mallory-files-step-1`, complete=`True`, rows=`6`, trigger=`initial_route`, negative_license=`False`, alternatives=`['logged-on-to-host']`
- Goal `rel_host_file` (`modified`): status=`CAPABILITY_GAP`, execution_complete=`False`, proof_complete=`False`, route_exhausted=`False`, readiness=`CAPABILITY_GAP`, terminal=`none`
  - Proof gaps: `relation_or_constraint_proof_missing`
  - Capability gaps: `no_provider_attempt`

### Proof state

- `rel_user_host`: `SUPPORTED`
- `rel_host_file`: `INCONCLUSIVE`

## 5. Native Queries, Result Summaries and Completeness
<!-- ## 4. Queries used -->

### `logical-graph-mallory-files-step-1` — `rel_user_host`
- **Purpose:** resolve-user-host

- **Input binding:** `subject=mallory`
- **Expected output fields:** `host`, `timestamp`
- **Result:** 6 rows returned; complete=True
- **Observed fields:** none
- **Execution:** executed_ok=`True`, diagnostic=`none`
- **Hypothesis Impact:** Targets `h1`
Provider: `mock-edr`; completeness: `provider-declared`

- **Provider pages:** `1`; continuation=`False`
```text
search user=mallory | table host, user
```

**Returned sample rows (raw payload omitted):**

- Row 1: host=WORKSTATION-01; user=mallory
- Row 2: host=WORKSTATION-02; user=mallory
- Row 3: host=WORKSTATION-03; user=mallory
- Row 4: host=WORKSTATION-04; user=mallory
- Row 5: host=WORKSTATION-05; user=mallory


## 6. Coverage and Cost
<!-- ## 5. Cost -->

### Scope and Requirement Coverage

- **Causal Path Coverage:** `0.0%` (0/2 relations verified)
- **Wildcard Scope Coverage:** `100.0%` (1/1 broadsweep cells)
- **Instance Cell Coverage:** `100.0%` (1/1 concrete entity cells)

### Route and Frontier Coverage

- **Examined routes:**
  - `rel_user_host` (`associated_with`): operation=`resolve-user-host`, source=`scope-1`, query=`logical-graph-mallory-files-step-1`, rows=`6`, complete=`True`
- **Unexamined routes & frontier sources:**
  - Unattempted candidate method: `method-rel_user_host-2` (`rel_user_host` via `logged-on-to-host`)
  - Unattempted candidate method: `method-rel_host_file-1` (`rel_host_file` via `find-files-on-host`)
- **Route Exhaustion Rationale:** Execution halted before exhaustion with unexamined frontier elements remaining. Stopping decision: `STOP_NEEDS_USER_DECISION`.

### Cost Accounting

- Model: `stub`
- Configured model(s): `stub`
- Actual model(s): `not reported by gateway`
- Calls: `0`
- Physical API attempts: `0`
- Failed calls: `0`
- Tokens: `0` (estimated)
- Token accounting mode: `ESTIMATED`
- Estimated cost: `$0.000000`
