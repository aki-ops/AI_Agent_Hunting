# PEAK ABLE Table: Brute Force

*Hypothesis: Brute force login against public-facing server. Repeated failed authentication events targeting user accounts on a host. The encoded cmdline row carries 'Logon Failed' for failed attempts.*

| ABLE Element | |
|---|---|
| Actor | Unknown or opportunistic brute-force actor. No specific actor is named in the hypothesis or research, so actor context is not derivable from the local telemetry. If actor-specific intelligence is available, use it to refine likely source IPs, targeted accounts, password-spray patterns, and timing. |
| Behavior | Password guessing / brute force against a login service, mapped to MITRE ATT&CK T1110. Repeated failed authentication events target user accounts on a host. Candidate detection predicates include `cmdline CONTAINS Logon Failed` for failed attempts and `user EQUALS admin` when a privileged account is targeted. The observable chain is an authentication failure burst. |
| Location | Public-facing / internet-facing server and its authentication service. The relevant part of the network is the perimeter or internet-facing server zone where login attempts arrive. Local telemetry host, user, and ip fields can identify the target host and source addresses, but confirming that the server is public-facing requires asset exposure or inventory context not present in the local data document. |
| Evidence | Data source: local CDB SQLite table `events`, especially `native_type = authentication`. Look for rows where `cmdline CONTAINS Logon Failed`, and inspect `action`, `host`, `user`, `ip`, `timestamp`, and `status`. Repetition or burst behavior must be derived by grouping/counting failed events by `host`, `user`, and `ip` over a short time window. If targeting a privileged account, also pivot on `user EQUALS admin`. A detection draft equivalent would be: `native_type=authentication cmdline CONTAINS "Logon Failed" | stats count by host user ip | where count > threshold`. Public-facing exposure cannot be proven from the available columns alone. |

Notes:
- The local authentication `native_type` uses `event_id 4624`; do not assume Windows event ID `4625` is present. In this dataset, the failure signal is encoded in `cmdline` as `Logon Failed`, with outcome context in `action`.
- A burst or repeated-failure condition is not a single literal event predicate. The deterministic executor should first match `cmdline CONTAINS "Logon Failed"`, then pivot and aggregate on `host`, `user`, `ip`, and `timestamp`.
- The hypothesis mentions a public-facing server, but the available fields do not directly encode internet exposure. Confirming public-facing status requires external asset inventory, exposure data, or correlation with web-facing telemetry such as `web_request`.
- Actor attribution is not supported by the provided local telemetry. Treat the Actor element as contextual only unless external intelligence is supplied.
- Candidate predicates from the research document that fit the local data model are `cmdline CONTAINS Logon Failed` and `user EQUALS admin`. Additional targeted users can be discovered by pivoting from matching authentication rows.
