# PEAK ABLE Table: C2 Beaconing via HTTP

*Hypothesis: C2 beacon to ad.networkfilter.co (BOTS v1 known IOC). Outbound HTTP request to ad.networkfilter.co, the ad-fraud beacon seen in BOTS v1.*

| ABLE Element | Details |
|--------------|---------|
| Actor | Threat actor using the ad.networkfilter.co C2 infrastructure (associated with BOTS v1 ad‑fraud campaign); specific actor not identified in the hypothesis. |
| Behavior | Outbound HTTP request to the domain **ad.networkfilter.co** (C2 beaconing), observable as a web request with the site in the `domain` field or the string `ad.networkfilter.co` appearing in the `cmdline` of a web request event. |
| Location | Internal hosts that have outbound internet access (e.g., workstations, servers) within the monitored network; the beacon originates from inside and travels to the external C2 host. |
| Evidence | - `web_request` events where `domain` CONTAINS `ad.networkfilter.co` (or `cmdline` CONTAINS `ad.networkfilter.co`).<br>- Corresponding `process_creation` events that spawned the process making the web request (to link beacon to a specific executable).<br>- Optional: `cmdline` CONTAINS `/banner/` to capture the known ad‑fraud beacon pattern. |

**Notes**
- The local telemetry includes a `web_request` native type with a `domain` field that stores the target host, making the primary detection predicate straightforward.
- If only `cmdline` is available (e.g., for non‑web request logs), use `cmdline CONTAINS ad.networkfilter.co` as a fallback.
- No direct DNS or authentication events are required for this specific beacon detection, but they can be used for additional context (e.g., prior DNS lookup of ad.networkfilter.co).
