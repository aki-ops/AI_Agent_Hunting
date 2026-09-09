# Hunt Report

## 1. Hypothesis / Question

> What version of Tor was installed on wrk-amber?

- **Subject:** `host`: `wrk-amber`
- **Requested Object:** `software_version` (role: `answer`)
- **Behavior:** installed Tor

**Result:** `PARTIALLY_SUPPORTED`  
**Stopping:** `STOP_BOUNDED`

- **Causal Path Coverage:** `0.0%` (0/1 relations verified)
- **Wildcard Scope Coverage:** `0.0%` (0/1 broadsweep cells)
- **Instance Cell Coverage:** `0.0%` (0/0 concrete entity cells)

**Answer Status:** `PARTIALLY_SUPPORTED`

**Answer:** wrk-amber was observed on wrk-amber. Requested version: Not available in the retrieved telemetry.

**Evidence Citation:** wrk-amber executed on wrk-amber Evidence: obs-adaptive-2, obs-adaptive-3, obs-discovery-1 Query: qp-adaptive-0-1, qp-adaptive-0-2 Fields: Path, Image

## 2. Hypothesis analysis

- `PARTIALLY_SUPPORTED` — Tor installed

**Unresolved Mandatory Unknowns:**
- `host(wrk-amber) -> connected_to -> software_version`: Activity connecting wrk-amber to software_version

## 3. Evidence and explanation

| Evidence | Why it matters | Source |
|---|---|---|
| Process: firefox.exe Host: wrk-amber | Observed process execution providing evidence of code execution on endpoint. | 2 event(s); representative observations: `obs-discovery-1`, `obs-adaptive-3` |
| Process artifact observed on wrk-amber: C:\Tor\firefox.exe | Observed process execution providing evidence of code execution on endpoint. | 1 event(s); representative observations: `obs-adaptive-2` |

### Explanation

- **Deterministic Explanation:** wrk-amber was observed on wrk-amber. Requested version: Not available in the retrieved telemetry.
- **LLM Narrative Analysis:** Not requested / offline deterministic mode.
- Observed process execution providing evidence of code execution on endpoint.
- Limitation: No definitive adversary presence or refutation established in searched frame.

## 4. Queries used

### `qp-discovery-0` — `discovery`
- **Purpose:** search_text

- **Result:** 1 rows returned; complete=True
- **Hypothesis Impact:** Targets `h1`
Provider: `mock_splunk`; completeness: `complete`

```spl
<MagicMock name='mock.last_query_text' id='2020391090512'>
```

### `qp-adaptive-0-1` — `adaptive-answer`
- **Purpose:** find_file_version

- **Result:** 1 rows returned; complete=True
- **Hypothesis Impact:** Targets `h1`
Provider: `mock_splunk`; completeness: `complete`

```spl
<MagicMock name='mock.last_query_text' id='2020391090512'>
```

### `qp-adaptive-0-2` — `adaptive-answer`
- **Purpose:** find_process_version

- **Result:** 1 rows returned; complete=True
- **Hypothesis Impact:** Targets `h1`
Provider: `mock_splunk`; completeness: `complete`

```spl
<MagicMock name='mock.last_query_text' id='2020391090512'>
```

## 5. Cost

- Model: `stub`
- Calls: `0`
- Tokens: `0`
- Estimated cost: `$0.000000`
