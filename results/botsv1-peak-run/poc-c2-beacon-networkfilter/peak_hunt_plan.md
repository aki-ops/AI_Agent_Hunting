# Hunt Plan: C2 Beaconing to ad.networkfilter.co

## Hypothesis
C2 beacon to `ad.networkfilter.co` (BOTS v1 known IOC). Outbound HTTP request to `ad.networkfilter.co`, the ad-fraud beacon seen in BOTS v1. Expected observable chain: `web_request`, `process_creation`. MITRE ATT&CK T1071.001 - Application Layer Protocol: Web.

## Recommended Time Frame
Full local dataset window: **2016-08-01T00:00:00Z through 2016-08-28T23:59:00Z**.  
No shorter window recommended because beaconing cadence and baseline comparison are best assessed across the full available period. DNS telemetry is only available for **2016-08-24T10:25:02Z through 2016-08-24T16:34:35Z**, so any DNS-dependent check outside that interval cannot be answered.

## ABLE Table
| ABLE Element | Local Mapping |
|---|---|
| Actor | No specific named threat group in supplied material. Associated with the BOTS v1 ad-fraud beacon and known IOC `ad.networkfilter.co`. |
| Behavior | Outbound HTTP command-and-control beaconing to `ad.networkfilter.co`; likely GET requests, possibly `/banner/` path. MITRE ATT&CK T1071.001. |
| Location | Internal hosts making outbound HTTP to the internet and network perimeter/egress web traffic. Primary local source: CDB SQLite table `events` with `native_type` = `web_request`. Supporting endpoint source: `process_creation`. |
| Evidence | Primary: `native_type EQUALS web_request` and (`domain EQUALS ad.networkfilter.co` OR `cmdline CONTAINS ad.networkfilter.co` OR `cmdline CONTAINS /banner/` OR `cmdline CONTAINS site=ad.networkfilter.co`). Supporting: `native_type EQUALS process_creation` and `cmdline CONTAINS ad.networkfilter.co`. Pivot on `host`, `user`, and time primarily. `web_request.ip` and `web_request.port` semantics are undefined in the local data document and must be verified before use. DNS: `native_type EQUALS dns` and `domain EQUALS ad.networkfilter.co` only within the limited DNS window. |

## Data
No Splunk index/sourcetype is provided in the local data discovery. The data source is the CDB SQLite table `events`; `native_type` is the sourcetype-equivalent. If exported to Splunk, adjust `index=cdb_events` placeholder accordingly. SPL shown below is an equivalent detection draft only; the deterministic executor uses single literal predicates.

| Data Source | native_type / event_id | Key Fields | Relevance |
|---|---|---|---|
| CDB table `events` | `web_request` / - | `timestamp`, `host`, `user`, `ip`, `port`, `domain`, `cmdline` | Primary detection. Web requests store site in `domain` and `site=<host> uri=<path>` in `cmdline`. `ip` and `port` semantics (client/source vs server/destination) are undefined in the local data document. |
| CDB table `events` | `process_creation` / `4688`, `1` | `timestamp`, `host`, `user`, `image`, `pid`, `ppid`, `cmdline` | Supporting. Useful only if the URL or host appears in a process command line; cannot independently prove outbound HTTP beaconing. |
| CDB table `events` | `dns` / - | `timestamp`, `host`, `ip`, `domain`, `cmdline` | Limited to 2016-08-24T10:25:02Z–2016-08-24T16:34:35Z. Can confirm resolution only in that interval. |
| CDB table `events` | `authentication` / `4624` | `timestamp`, `host`, `user`, `ip`, `action`, `cmdline` | Pivot to scope account/host context. Local document notes auth rows keep text such as `Logon Success user=.. ip=..` in `cmdline`; auth IP may be in `cmdline` rather than the `ip` field. |

SPL-equivalent detection draft only:  
`index=cdb_events earliest=2016-08-01T00:00:00Z latest=2016-08-28T23:59:00Z native_type=web_request (domain="ad.networkfilter.co" OR cmdline="*ad.networkfilter.co*" OR cmdline="*/banner/*")`

## Hunt Procedure

**Executor note:** The deterministic executor accepts one literal predicate per step: `field operator value`. Compound predicates, nested ORs, and SPL joins are not executed by the deterministic executor. Where a hunt requires combining predicates, run each predicate as its own step and intersect the result sets manually by row identity (`timestamp`, `host`, `user`, `cmdline`) or by the fields needed for the next pivot. SPL shown below is an equivalent detection draft only and includes `earliest`/`latest` for Splunk export efficiency.

### Phase A: Direct IOC Predicates

1. **Executor predicate:** `native_type EQUALS web_request`  
   SPL draft: `index=cdb_events earliest=2016-08-01T00:00:00Z latest=2016-08-28T23:59:00Z native_type=web_request | table timestamp host user ip port domain cmdline | sort timestamp`  
   Action: Store as result set A. This is the population of all web requests to intersect against the IOC predicates.

2. **Executor predicate:** `domain EQUALS ad.networkfilter.co`  
   SPL draft: `index=cdb_events earliest=2016-08-01T00:00:00Z latest=2016-08-28T23:59:00Z domain="ad.networkfilter.co" | table timestamp native_type host user ip port domain cmdline | sort timestamp`  
   Action: Store as result set B.

3. **Manual intersection:** Intersect result set A (`native_type EQUALS web_request`) with result set B (`domain EQUALS ad.networkfilter.co`) by row identity. These are primary direct IOC hits. Record `timestamp`, `host`, `user`, `ip`, `port`, `domain`, and `cmdline`.

4. **Executor predicate:** `cmdline CONTAINS ad.networkfilter.co`  
   SPL draft: `index=cdb_events earliest=2016-08-01T00:00:00Z latest=2016-08-28T23:59:00Z cmdline="*ad.networkfilter.co*" | table timestamp native_type host user ip port domain cmdline | sort timestamp`  
   Action: Store as result set C. This captures the IOC if embedded in `cmdline` and not in `domain`.

5. **Manual intersection:** Intersect result set A (`native_type EQUALS web_request`) with result set C (`cmdline CONTAINS ad.networkfilter.co`) by row identity. These are primary direct IOC hits in web_request `cmdline`. Record all fields.

6. **Executor predicate:** `cmdline CONTAINS site=ad.networkfilter.co`  
   SPL draft: `index=cdb_events earliest=2016-08-01T00:00:00Z latest=2016-08-28T23:59:00Z cmdline="*site=ad.networkfilter.co*" | table timestamp native_type host user ip port domain cmdline | sort timestamp`  
   Action: Store as result set D. Intersect manually with result set A for web_request rows. This is the explicit local `site=<host>` marker. Record all fields.

7. **Executor predicate:** `cmdline CONTAINS /banner/`  
   SPL draft: `index=cdb_events earliest=2016-08-01T00:00:00Z latest=2016-08-28T23:59:00Z cmdline="*/banner/*" | table timestamp native_type host user ip port domain cmdline | sort timestamp`  
   Action: Store as result set E. `/banner/` alone is weak and may match benign ad banners. It is strong primary evidence only when correlated with `ad.networkfilter.co` or another repeating suspicious domain.

8. **Manual correlation:** Intersect result set E (`/banner/`) with result set B (`domain EQUALS ad.networkfilter.co`) or result set C (`cmdline CONTAINS ad.networkfilter.co`) by `host`, `user`, and time proximity. If `/banner/` co-occurs with `ad.networkfilter.co`, treat as strong supporting evidence. If `/banner/` appears only without `ad.networkfilter.co`, treat as weak/investigative only.

9. **Executor predicate:** `native_type EQUALS process_creation`  
   SPL draft: `index=cdb_events earliest=2016-08-01T00:00:00Z latest=2016-08-28T23:59:00Z native_type=process_creation | table timestamp host user image pid ppid cmdline | sort timestamp`  
   Action: Store as result set F. Used for supporting process_creation intersections.

10. **Manual intersection:** Intersect result set F (`native_type EQUALS process_creation`) with result set C (`cmdline CONTAINS ad.networkfilter.co`) by row identity. These are supporting process_creation hits. They cannot independently prove outbound HTTP beaconing.

11. **Manual intersection:** Intersect result set F (`native_type EQUALS process_creation`) with result set E (`cmdline CONTAINS /banner/`) by row identity. These are supporting process_creation `/banner/` hits. Treat as weak unless correlated with `ad.networkfilter.co`.

### Phase B: Pivots on Affected Entities

From primary hits in steps 3, 5, and 6, collect unique `host`, `user`, and observed `ip`/`port` values. Use `host`, `user`, and time as the primary pivots.

12. **Executor predicate:** `host EQUALS <host from primary hits>`  
    SPL draft: `index=cdb_events earliest=2016-08-01T00:00:00Z latest=2016-08-28T23:59:00Z host="<host>" | table timestamp native_type user ip port domain cmdline | sort timestamp`  
    Action: Store as result set H. Manually intersect with result set A to view web_request activity for that host. This scopes all activity for the affected host.

13. **Executor predicate:** `user EQUALS <user from primary hits>`  
    SPL draft: `index=cdb_events earliest=2016-08-01T00:00:00Z latest=2016-08-28T23:59:00Z user="<user>" | table timestamp native_type host ip port domain cmdline | sort timestamp`  
    Action: Store as result set U. Manually intersect with result set A for web_request activity. This scopes the affected identity.

14. **Executor predicate:** `ip EQUALS <ip from primary hits>`  
    SPL draft: `index=cdb_events earliest=2016-08-01T00:00:00Z latest=2016-08-28T23:59:00Z ip="<ip>" | table timestamp native_type host user port domain cmdline | sort timestamp`  
    Action: Store as result set I. **Field semantics caveat:** the local data document does not state whether `web_request.ip` is client/source or server/destination. Do not assume this is the external C2 destination or the internal source without corroboration. Use only as an observed pivot field, and verify by inspecting `cmdline` and related rows. If `ip` is external destination, do not use it to pivot authentication.

15. **Executor predicate:** `port EQUALS <port from primary hits>`  
    SPL draft: `index=cdb_events earliest=2016-08-01T00:00:00Z latest=2016-08-28T23:59:00Z port="<port>" | table timestamp native_type host user ip domain cmdline | sort timestamp`  
    Action: Store as result set P. Same field-semantics caveat as step 14.

16. **Executor predicate:** `native_type EQUALS authentication`  
    SPL draft: `index=cdb_events earliest=2016-08-01T00:00:00Z latest=2016-08-28T23:59:00Z native_type=authentication | table timestamp host user ip action cmdline | sort timestamp`  
    Action: Store as result set Auth. Use for authentication context.

17. **Manual authentication pivot:** Intersect result set Auth with affected `host` and/or `user` values from primary hits, and optionally with time proximity. Do not pivot on `ip` from web_request unless you have verified that `web_request.ip` is an internal/source IP. The local data document says authentication rows keep text such as `Logon Success user=.. ip=..` in `cmdline`; if an authentication IP pivot is required, run step 18 and intersect manually. This avoids invalid nested OR/AND logic.

18. **Executor predicate (conditional):** `cmdline CONTAINS ip=<ip from primary hits>`  
    SPL draft: `index=cdb_events earliest=2016-08-01T00:00:00Z latest=2016-08-28T23:59:00Z native_type=authentication cmdline="*ip=<ip>*" | table timestamp host user ip action cmdline | sort timestamp`  
    Action: Use only if authentication IP pivot is required and field semantics are verified. Intersect manually with result set Auth. Otherwise skip.

### Phase C: Manual Cadence and Baseline Analysis

The deterministic executor only returns matching rows; it cannot run `timechart`, `stats`, or joins. Perform the following manually after exporting or copying the relevant result sets.

19. **Manual cadence analysis for primary hits:**
    - Export rows from steps 3, 5, and 6 (web_request to `ad.networkfilter.co`).
    - Sort by `host`, `user`, `domain`, then `timestamp`.
    - Compute inter-arrival deltas between consecutive timestamps for the same `host`/`user`/`domain`.
    - Look for repeated periodic requests with low jitter. Heuristic: at least 5 requests with delta standard deviation / mean < 0.30, or visibly consistent intervals such as every 30s, 1m, 5m, 15m, or 1h.
    - Record whether requests are machine-like or match human browsing.

20. **Manual baseline comparison:**
    - For each affected `host`, export normal web_request rows from result set A filtered manually to that host.
    - Compare the `ad.networkfilter.co` cadence against that host's normal domains.
    - Beaconing is more suspicious when the same domain is contacted at regular intervals and is not part of normal user browsing or known software update patterns.

21. **Manual `/banner/` correlation analysis:**
    - From step 8, list `/banner/` rows that co-occur with `ad.networkfilter.co` by `host`, `user`, and time proximity, such as same host/user within the same hour.
    - If `/banner/` appears only without `ad.networkfilter.co`, treat as weak and do not escalate solely on this predicate.
    - If `/banner/` appears with `ad.networkfilter.co` or another domain that also shows regular periodic cadence, escalate as strong supporting evidence.

22. **Manual documentation of findings and limitations:**
    - Record all matching `timestamp`, `host`, `user`, `ip`, `port`, `domain`, `cmdline`, and `native_type`.
    - State explicitly: `web_request` can show matching HTTP requests but cannot alone prove malicious intent, actor attribution, or beaconing cadence without time-based aggregation and baseline comparison.
    - `process_creation` cannot independently prove outbound HTTP beaconing.
    - `dns` telemetry is limited to 2016-08-24T10:25:02Z–2016-08-24T16:34:35Z and cannot confirm resolution across the full dataset.
    - `web_request.ip` and `web_request.port` field semantics (client/source vs server/destination) are undefined in the local data document and must be verified before using them for pivots.
    - If no hits occur, the hunt cannot rule out the behavior due to possible telemetry gaps; it can only state that the known IOC and `/banner/` pattern were not observed in the available local data.

### Optional Exploration

23. **Optional executor predicate:** `domain EQUALS <other domain from /banner/ hits>`  
    SPL draft: `index=cdb_events earliest=2016-08-01T00:00:00Z latest=2016-08-28T23:59:00Z domain="<other domain>" | table timestamp native_type host user ip port domain cmdline | sort timestamp`  
    Action: Optional. For any repeating domain from `/banner/` analysis that is not `ad.networkfilter.co`, pivot to determine whether other ad-fraud or beaconing domains are present. This is exploratory and not required for the core hypothesis.

24. **Optional DNS check within available window:**
    - **Executor predicate:** `native_type EQUALS dns`
    - **Executor predicate:** `domain EQUALS ad.networkfilter.co`
    - **Manual intersection:** Intersect by row identity.
    - SPL draft: `index=cdb_events earliest=2016-08-24T10:25:02Z latest=2016-08-24T16:34:35Z native_type=dns domain="ad.networkfilter.co" | table timestamp host ip domain cmdline | sort timestamp`  
    - Action: Confirms resolution only if it occurred within the available DNS telemetry window. Absence outside that interval cannot be interpreted.
