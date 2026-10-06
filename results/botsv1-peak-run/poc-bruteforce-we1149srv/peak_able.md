# PEAK ABLE Table: Password Guessing Against a Server
*Hypothesis: Brute force login against public-facing server. Repeated failed authentication events targeting user accounts on a host. The encoded cmdline row carries 'Logon Failed' for failed attempts.*
| ABLE Element |  |
| --- | --- |
| Actor | Unspecified external opportunistic attacker. No specific group is named in hypothesis or research; hunt for any source attempting password guessing, MITRE ATT&CK T1110 - Brute Force. |
| Behavior | T1110 Brute Force - password guessing: repeated failed authentication events targeting user accounts on a single host in a short window, forming an authentication_failure_burst. Per BOTS v1 brute-force phase, focus on burst rate and repeat targeting, not a full lifecycle. |
| Location | Public-facing server(s). In CDB terms this is host values in SQLite table events where authentication activity concentrates. Pivot and scope by host, with ip for source and target context and timestamp for burst windowing. Available data cannot by itself prove which host is public-facing versus internal without asset inventory or zone mapping; hunt hosts with concentrated bursts then validate exposure separately. |
| Evidence | Data source: CDB SQLite table events, native_type EQUALS authentication. Primary indicator per research: cmdline CONTAINS Logon Failed, with outcome also reflected in action and detail text such as Logon Success user=.. ip=.. pattern in cmdline. Privileged targeting check: user EQUALS admin. Burst proof requires grouping by host, user, ip and timestamp to show many failed logons to same host and user in a short time. Detection draft equivalent: filter native_type authentication where cmdline contains Logon Failed, aggregate count by host, user, ip over time. |
## Notes
- Executor constraint: Each PoC step must be one literal predicate field, operator, value over fields timestamp, event_id, native_type, host, user, pid, ppid, cmdline, image, ip, port, domain, file_path, action, status, raw_ref, plus pivots on host, user, ip and time. EQUALS, CONTAINS, STARTS_WITH and ENDS_WITH are case-insensitive.
- Burst threshold is not defined in research; repeated means multiple Logon Failed rows for same host and user and ip in a compressed timestamp window and must be quantified during hunting.
- user EQUALS admin is an analyst-authored example of privileged targeting, not a requirement for all brute force; also hunt bursts against other user values.
- Available data cannot answer public-facing status, cleartext passwords tried, or attacker attribution from telemetry alone; source attribution is limited to ip, host, user and timestamp pivots.
- Local telemetry shows 579580 rows of native_type authentication event_id 4624 from 2016-08-01 to 2016-08-28, providing coverage for this hunt; dns coverage is limited to 2016-08-24 and web_request stores site in domain with site=<host> uri=<path> in cmdline, neither of which replaces auth evidence for this behavior.

