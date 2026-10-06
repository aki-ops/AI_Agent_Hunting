# PEAK ABLE Table: command-and-control beaconing
*Hypothesis: C2 beacon to ad.networkfilter.co (BOTS v1 known IOC). Outbound HTTP request to ad.networkfilter.co, the ad-fraud beacon seen in BOTS v1.*
| ABLE Element |  |
|---|---|
| Actor | Unspecified ad-fraud / opportunistic operator behind ad.networkfilter.co (BOTS v1 known IOC); no named APT in hypothesis or research document |
| Behavior | Outbound command-and-control beacon via Application Layer Protocol: Web (MITRE ATT&CK T1071.001) - HTTP request to known C2 host ad.networkfilter.co, specifically GET to /banner/ ad-fraud beacon pattern |
| Location | Internal endpoints initiating outbound web traffic to the internet / egress perimeter; in CDB terms the `host` values with `native_type` EQUALS `web_request` from 2016-08-01 to 2016-08-28 |
| Evidence | CDB SQLite table `events`, `native_type` EQUALS `web_request` where `domain` stores site and `cmdline` stores `site=<host> uri=<path>`: `domain` CONTAINS `ad.networkfilter.co`, `cmdline` CONTAINS `ad.networkfilter.co`, `cmdline` CONTAINS `/banner/`; pivot on `host`, `ip`, `timestamp` for beacon cadence and on `host`, `pid`, `ppid`, `image` with `native_type` EQUALS `process_creation` for sourcing process chain `web_request, process_creation`; SPL only as equivalent detection draft, each hunt step executed as one literal field/operator/value predicate (EQUALS/CONTAINS/STARTS_WITH/ENDS_WITH/MATCHES/EXISTS, case-insensitive) |
## Notes
- Executor limitation: hunts run through deterministic executor, not by LLM; plan steps must be literal predicates over `timestamp, event_id, native_type, host, user, pid, ppid, cmdline, image, ip, port, domain, file_path, action, status, raw_ref` plus pivots on `host, user, ip, time`; LLM never creates or edits evidence
- Available data cannot confirm HTTP method/headers/body/volume: `web_request` retains only `domain` and `site=<host> uri=<path>` in `cmdline` with no dedicated method, header, or bytes fields
- Available data cannot answer pre-infection DNS resolution outside 2016-08-24T10:25:02Z to 2016-08-24T16:34:35Z `dns` coverage; `web_request` coverage is 2016-08-01T00:01:01Z to 2016-08-28T23:54:58Z
- Available data cannot attribute to named actor or distinguish ad-fraud from other C2 without `process_creation` join on `host, pid, ppid, image, timestamp` and without firewall/proxy/TLS logs for encrypted sessions
