# PEAK ABLE Table: Brute Force
*Hypothesis: Brute force login against public-facing server. Repeated failed authentication events targeting user accounts on a host. The encoded cmdline row carries 'Logon Failed' for failed attempts.*

| ABLE Element | Content |
|--------------|---------|
| Actor | Unspecified / generic threat actor (no specific group named in hypothesis) |
| Behavior | Brute force login – repeated failed authentication attempts against user accounts |
| Location | Public‑facing server (internet‑exposed host) |
| Evidence | Authentication event logs (native_type = `authentication`, event_id = 4624) where `cmdline` contains the string `Logon Failed`; can be further refined by host, user, and temporal bursts (e.g., multiple failures from same host/user within a short time window) |

- Local telemetry provides the needed authentication events (`authentication` event_id 4624) and the `cmdline` field that records `Logon Failed` for failed logons, allowing the evidence condition to be expressed as a literal predicate: `cmdline CONTAINS Logon Failed`.  
- The location element (public‑facing server) may require additional context (e.g., tagging hosts as external or examining IP addresses not in internal ranges); if such tagging is absent in the available fields, the hunt may need to rely on external knowledge of which hosts are internet‑exposed.  
- Pivots on `host`, `user`, `ip`, and `time` can be used to correlate bursts of failed logins and isolate suspicious activity.
