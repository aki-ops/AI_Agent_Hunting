# Hunt Report

## 1. Hypothesis / Question

> What version of Tor was installed on wrk-amber?

- **Subject:** `host`: `wrk-amber`
- **Requested Object:** `software_version` (role: `answer`)
- **Behavior:** installed Tor

**Result:** `INCONCLUSIVE`  
**Stopping:** `STOP_BOUNDED`

- **Causal Path Coverage:** `0.0%` (0/1 relations verified)
- **Wildcard Scope Coverage:** `0.0%` (0/1 broadsweep cells)
- **Instance Cell Coverage:** `0.0%` (0/0 concrete entity cells)

**Answer Status:** `FULLY_ANSWERED`

**Answer (software_version):** `13.5.2`

## 2. Hypothesis analysis

- `LIVE` — Tor installed

**Unresolved Mandatory Unknowns:**
- `host(wrk-amber) -> connected_to -> software_version`: Activity connecting wrk-amber to software_version

## 3. Evidence and explanation

| Evidence | Why it matters | Source |
|---|---|---|
| Telemetry observations (2 events on wrk-amber) | Observed operational telemetry within the monitored scope. | 2 event(s); representative observations: `obs-discovery-1`, `obs-adaptive-2` |

### Explanation

- **Deterministic Graph Resolution:** The target object `13.5.2` was proven through the verified 4-step causal provenance chain.
- **LLM Explanation:** Not requested / offline deterministic mode.
- Observed operational telemetry within the monitored scope.
- Limitation: No definitive adversary presence or refutation established in searched frame.

## 4. Queries used

### `qp-discovery-0` — `discovery`
- **Purpose:** search_text

- **Result:** 1 rows returned; complete=True
- **Hypothesis Impact:** Targets `h1`
Provider: `mock_splunk`; completeness: `complete`

```spl
<MagicMock name='mock.last_query_text' id='2533600387600'>
```

### `qp-adaptive-0-1` — `adaptive-answer`
- **Purpose:** find_file_version

- **Result:** 1 rows returned; complete=True
- **Hypothesis Impact:** Targets `h1`
Provider: `mock_splunk`; completeness: `complete`

```spl
<MagicMock name='mock.last_query_text' id='2533600387600'>
```

## 5. Cost

- Model: `stub`
- Calls: `0`
- Tokens: `0`
- Estimated cost: `$0.000000`
