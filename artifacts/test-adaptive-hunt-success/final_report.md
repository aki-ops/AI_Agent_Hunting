# Hunt Report

## 1. Hypothesis / Question

> What version of Tor was installed on wrk-amber?

- **Subject:** `host`: `wrk-amber`
- **Requested Object:** `software_version` (role: `answer`)
- **Behavior:** installed Tor

**Result:** `SUPPORTED`  
**Stopping:** `STOP_BOUNDED`

- **Causal Path Coverage:** `0.0%` (0/0 relations verified)
- **Wildcard Scope Coverage:** `0.0%` (0/1 broadsweep cells)
- **Instance Cell Coverage:** `0.0%` (0/0 concrete entity cells)

**Answer Status:** `FULLY_ANSWERED`

**Answer (software_version):** `13.5.2`

## 2. Hypothesis analysis

- `SUPPORTED` — Tor installed

### Source capability profiling

- Status: `NO_LLM_CALLER`; accepted proposals: `0`; rejected: `0`
- Proposals are candidates only; a provider probe is required before they become executable capabilities.

**Unresolved Mandatory Unknowns:**
- `host(wrk-amber) -> connected_to -> software_version`: Activity connecting wrk-amber to software_version

## 3. Evidence and explanation

| Evidence | Why it matters | Observed values | Source |
|---|---|---|---|
| Process artifact observed on wrk-amber: C:\Tor\firefox.exe | Observed process execution providing evidence of code execution on endpoint. | file_paths=C:\Tor\firefox.exe; software_versions=13.5.2; software_version=13.5.2 | 1 event(s); query: `qp-adaptive-0-1`; observations: `obs-adaptive-2` |

### Evidence details

- `card-e5d92fdeb056` — fact=`process_execution`, count=`1`, completeness=`complete`; observed: file_paths=C:\Tor\firefox.exe; software_versions=13.5.2; software_version=13.5.2

### Explanation

- **Deterministic Graph Resolution:** The target object `13.5.2` was proven through 0 verified claim relation(s).
- Observed process execution providing evidence of code execution on endpoint.
- Limitation: No definitive adversary presence or refutation established in searched frame.

## 4. Queries used

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

- Row 1: host=wrk-amber; timestamp=2026-09-02T10:05:00Z; ProductVersion=13.5.2; Path=C:\Tor\firefox.exe

## 5. Cost

- Model: `stub`
- Calls: `0`
- Physical API attempts: `0`
- Failed calls: `0`
- Tokens: `0`
- Estimated cost: `$0.000000`
