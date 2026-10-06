# PEAK ABLE Table: Command and Control Beaconing

*Hypothesis: C2 beacon to ad.networkfilter.co (BOTS v1 known IOC). Outbound HTTP request to ad.networkfilter.co, the ad-fraud beacon seen in BOTS v1.*

| ABLE Element | |
|---|---|
| Actor | Not a specific named threat group in the supplied material; associated with the BOTS v1 ad-fraud beacon and known IOC ad.networkfilter.co. |
| Behavior | Outbound HTTP command-and-control beaconing to ad.networkfilter.co, likely GET requests and possibly a /banner/ path. MITRE ATT&CK T1071.001 - Application Layer Protocol: Web. |
| Location | Internal hosts making outbound HTTP to the internet and the network perimeter/egress web traffic. In local telemetry, primary source is the CDB SQLite table `events` with `native_type` = `web_request`; related endpoint telemetry is `process_creation`. |
| Evidence | Primary: `native_type EQUALS web_request` and (`domain EQUALS ad.networkfilter.co` OR `cmdline CONTAINS ad.networkfilter.co` OR `cmdline CONTAINS /banner/` OR `cmdline CONTAINS site=ad.networkfilter.co`). Supporting: `native_type EQUALS process_creation` and `cmdline CONTAINS ad.networkfilter.co`. Pivot on `host`, `user`, `ip`, `port`, and `timestamp` to scope affected hosts and frequency. |

Notes:
- Local `web_request` schema has no dedicated URI column; the URI is embedded in `cmdline` as `site=<host> uri=<path>`.
- The strongest local predicates are `domain EQUALS ad.networkfilter.co`, `cmdline CONTAINS ad.networkfilter.co`, and `cmdline CONTAINS /banner/` on `web_request` rows.
- `process_creation` only helps if the URL or host appears in a process command line; it cannot independently prove outbound HTTP beaconing.
- `dns` telemetry exists but is limited to 2016-08-24 10:25:02–16:34:35 in the local table, so it cannot confirm resolution across the full 2016-08-01–2016-08-28 dataset.
- SPL-equivalent detection draft only: `index=... native_type=web_request (domain="ad.networkfilter.co" OR cmdline="*ad.networkfilter.co*" OR cmdline="*/banner/*")`; the deterministic executor should use literal field/operator/value predicates, not SPL.
- The available data can show matching HTTP requests, but it cannot by itself prove malicious intent, actor attribution, or beaconing cadence without time-based aggregation and baseline comparison.
