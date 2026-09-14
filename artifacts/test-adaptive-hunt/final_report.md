# Hunt Report

## 1. Request and Outcome
<!-- ## 1. Hypothesis / Question -->

> What version of Tor was installed on wrk-amber?

- **Request ID:** `test-adaptive-hunt`
- **Hunt Kind:** `HUNT`
- **Subject:** `host`: `wrk-amber`
- **Requested Object:** `software_version` (role: `answer`)
- **Behavior:** installed Tor

**Result:** `PARTIALLY_SUPPORTED`  
**Stopping:** `STOP_NOT_FOUND_BOUNDED`
**Stopping Taxonomy:** `BOUNDED_NOT_FOUND`

**Answer Status:** `PARTIALLY_SUPPORTED`

**Answer:** wrk-amber was observed on wrk-amber. Requested version: Not available in the retrieved telemetry.

**Evidence Citation:** wrk-amber executed on wrk-amber Evidence: obs-adaptive-2, obs-adaptive-3 Query: qp-adaptive-0-1, qp-adaptive-0-2 Fields: Path, Image

- **Impacted Host(s):** `wrk-amber`

## 2. Proposed/Accepted Graph and Assumptions
<!-- ## 2. Hypothesis analysis -->

- `PARTIALLY_SUPPORTED` — Tor installed

### Source capability profiling

- Status: `NO_LLM_CALLER`; accepted proposals: `0`; rejected: `0`
- Proposals are candidates only; a provider probe is required before they become executable capabilities.

## 3. Step Trace and Binding Changes

### Lifecycle step trace

| Step | Lifecycle Phase | Duration (ms) | Status | Key Inputs / Outputs |
|---|---|---|---|---|
| 1 | `STEP_A_FREEZE_REQUEST` | 0.0 | `SUCCESS` | in: request_id=test-adaptive-hunt; content=What version of To... |
| 2 | `STEP_B_COMPILE_GOAL_GRAPH` | 0.0 | `SUCCESS` | in: request_id=test-adaptive-hunt; out: has_semantic_goal_graph=False |
| 3 | `STEP_C_RESOLVE_FRONTIER` | 0.0 | `SUCCESS` | in: profiling_requirements=0; out: coverage_manifests=0 |

## 4. Evidence and Proof Decisions
<!-- ## 3. Evidence and explanation -->

| Evidence | Why it matters | Observed values | Source |
|---|---|---|---|
| Process artifact observed on wrk-amber: C:\Tor\firefox.exe | Observed process execution providing evidence of code execution on endpoint. | file_paths=C:\Tor\firefox.exe | 1 event(s); query: `qp-adaptive-0-1`; observations: `obs-adaptive-2` |
| Process: firefox.exe Host: wrk-amber | Observed process execution providing evidence of code execution on endpoint. | images=firefox.exe; process_names=firefox.exe | 1 event(s); query: `qp-adaptive-0-2`; observations: `obs-adaptive-3` |

### Evidence details

- `card-e5d92fdeb056` — fact=`process_execution`, count=`1`, completeness=`complete`; observed: file_paths=C:\Tor\firefox.exe
- `card-eef7b0502355` — fact=`process_execution`, count=`1`, completeness=`complete`; observed: images=firefox.exe; process_names=firefox.exe

### Explanation

- **Deterministic Explanation:** wrk-amber was observed on wrk-amber. Requested version: Not available in the retrieved telemetry.
- Observed process execution providing evidence of code execution on endpoint.
- Limitation: No definitive adversary presence or refutation established in searched frame.

**Unresolved Mandatory Unknowns:**
- `host(wrk-amber) -> connected_to -> software_version`: Activity connecting wrk-amber to software_version

## 5. Native Queries, Result Summaries and Completeness
<!-- ## 4. Queries used -->

### `qp-discovery-0` — `discovery`
- **Purpose:** search_text

- **Input binding:** `None`
- **Expected output fields:** `host`, `timestamp`
- **Result:** 1 rows returned; complete=True
- **Observed fields:** none
- **Execution:** executed_ok=`True`, diagnostic=`none`
- **Hypothesis Impact:** Targets `h1`
Provider: `mock_splunk`; completeness: `complete`


```text
(native query text not captured)
```

**Returned sample rows (raw payload omitted):**

- Row 1: host=wrk-amber; timestamp=2026-09-02T10:00:00Z; user=amber

### `qp-adaptive-0-1` — `adaptive-answer`
- **Purpose:** find_file_version

- **Input binding:** `None`
- **Expected output fields:** `host`, `timestamp`
- **Result:** 1 rows returned; complete=True
- **Observed fields:** none
- **Execution:** executed_ok=`True`, diagnostic=`none`
- **Hypothesis Impact:** Targets `h1`
Provider: `mock_splunk`; completeness: `complete`


```text
(native query text not captured)
```

**Returned sample rows (raw payload omitted):**

- Row 1: host=wrk-amber; timestamp=2026-09-02T10:05:00Z; Path=C:\Tor\firefox.exe

### `qp-adaptive-0-2` — `adaptive-answer`
- **Purpose:** find_process_version

- **Input binding:** `None`
- **Expected output fields:** `host`, `timestamp`
- **Result:** 1 rows returned; complete=True
- **Observed fields:** none
- **Execution:** executed_ok=`True`, diagnostic=`none`
- **Hypothesis Impact:** Targets `h1`
Provider: `mock_splunk`; completeness: `complete`


```text
(native query text not captured)
```

**Returned sample rows (raw payload omitted):**

- Row 1: host=wrk-amber; timestamp=2026-09-02T10:10:00Z; Image=firefox.exe


## 6. Coverage and Cost
<!-- ## 5. Cost -->

### Scope and Requirement Coverage

- **Causal Path Coverage:** `0.0%` (0/0 relations verified)
- **Wildcard Scope Coverage:** `0.0%` (0/1 broadsweep cells)
- **Instance Cell Coverage:** `0.0%` (0/0 concrete entity cells)

### Visibility and Gap Breakdown

- **Not Found:** 1 gap(s)
  - Requirement r1: Searched with complete coverage; zero matching adversary records detected

### Cost Accounting

- Model: `stub`
- Calls: `0`
- Physical API attempts: `0`
- Failed calls: `0`
- Tokens: `0` (estimated)
- Token accounting mode: `ESTIMATED`
- Estimated cost: `$0.000000`
