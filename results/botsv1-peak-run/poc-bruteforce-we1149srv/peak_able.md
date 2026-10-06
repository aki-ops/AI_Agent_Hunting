# PEAK ABLE Table: Brute Force

*Hypothesis: Brute force login against public-facing server. Repeated failed authentication events targeting user accounts on a host. The encoded cmdline row carries 'Logon Failed' for failed attempts.*

| ABLE Element | |
| --- | --- |
| Actor | Not specified in the hypothesis. Treat as an external attacker or automated bot attempting brute-force login against a public-facing server. No named threat actor or tooling is provided. |
| Behavior | Repeated failed authentication events targeting user accounts on a host; brute-force login attempt (MITRE ATT&CK T1110). Detection focus is an authentication failure burst. Candidate predicates: cmdline CONTAINS "Logon Failed"; user EQUALS "admin". |
| Location | Public-facing or internet-facing server and its authentication telemetry. If the server is web-facing, correlate with web_request rows for the same host, domain, IP, and time window. Pivot on host, user, ip, and timestamp. |
| Evidence | CDB events table. Primary source: native_type EQUALS authentication (event_id 4624). Search for cmdline CONTAINS "Logon Failed"; optionally user EQUALS "admin"; inspect action/status for failure outcome. Aggregate or count by host, user, and ip over short time windows to find bursts. Secondary source: web_request rows use domain and cmdline text such as site=<host> uri=<path> to identify public-facing server traffic, but those rows do not show logon failures. |

Notes:
- The local telemetry does not include Windows event ID 4625 for failed logon; authentication rows are event_id 4624. Failed authentication must therefore be inferred from cmdline text or action/status, not from event_id.
- Literal executor predicates available: native_type EQUALS authentication; cmdline CONTAINS Logon Failed; user EQUALS admin. Use time, host, user, and ip pivots to detect repeated attempts.
- If action/status does not encode failure and cmdline lacks "Logon Failed", the available CDB data cannot confirm failed authentication.
- Equivalent SPL detection draft, for reference only and not executed by ABLE: index=cdb native_type=authentication cmdline="*Logon Failed*" user=admin | bin _time span=5m | stats count by _time host user ip | where count > 10. The threshold must be tuned.
- This hunt can identify failed-logon bursts but may not distinguish brute force from password spraying or user error without additional context.
