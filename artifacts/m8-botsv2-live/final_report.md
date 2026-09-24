# Hunt Report

## 1. Request and Outcome
<!-- ## 1. Hypothesis / Question -->

> Which process ran on an observed host?

- **Request ID:** `m8-botsv2-live`
- **Hunt Kind:** `QUESTION`
**Result:** `INSUFFICIENTLY_SPECIFIED`  
**Stopping:** `STOP_INSUFFICIENT`
**Stopping Taxonomy:** `COVERAGE_EXHAUSTED`

**Answer Status:** `INCONCLUSIVE`

**Answer:** Inconclusive (UNRESOLVED_REASON_UNAVAILABLE)

## 2. Proposed/Accepted Graph and Assumptions
<!-- ## 2. Hypothesis analysis -->

- `INSUFFICIENTLY_SPECIFIED` — Free-text hypothesis requires semantic compilation via LLM (--llm api): 'Which process ran on an observed host?'

## 3. Step Trace and Binding Changes

### Lifecycle step trace

| Step | Lifecycle Phase | Duration (ms) | Status | Key Inputs / Outputs |
|---|---|---|---|---|
| 1 | `STEP_A_FREEZE_REQUEST` | 0.0 | `SUCCESS` | in: request_id=m8-botsv2-live; content=Which process ran on a... |
| 2 | `STEP_B_COMPILE_GOAL_GRAPH` | 0.0 | `SUCCESS` | in: request_id=m8-botsv2-live; out: has_semantic_goal_graph=False |

## 4. Evidence and Proof Decisions
<!-- ## 3. Evidence and explanation -->

No evidence cards were produced.

### Explanation

- Limitation: No definitive adversary presence or refutation established in searched frame.

## 5. Native Queries, Result Summaries and Completeness
<!-- ## 4. Queries used -->

No query was executed.

## 6. Coverage and Cost
<!-- ## 5. Cost -->

### Scope and Requirement Coverage

- **Causal Path Coverage:** `0.0%` (0/0 relations verified)
- **Wildcard Scope Coverage:** `0.0%` (0/1 broadsweep cells)
- **Instance Cell Coverage:** `0.0%` (0/0 concrete entity cells)

### Route and Frontier Coverage

- **Examined routes:** None
- **Unexamined routes & frontier sources:**
  - None (frontier and candidate proof methods exhausted)
- **Route Exhaustion Rationale:** Stopping decision: `STOP_INSUFFICIENT`.

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
