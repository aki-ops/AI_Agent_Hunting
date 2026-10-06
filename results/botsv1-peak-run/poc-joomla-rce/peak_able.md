# PEAK ABLE Table: Joomla Search/Mailto RCE (T1190)

*Hypothesis: Joomla RCE web compromise (BOTS v1 real attack). Attacker scans and exploits Joomla search/mailto components on imreallynotbatman.com.*

| ABLE Element | |
|---|---|
| Actor | External attacker in the BOTS v1 real-attack scenario. No named threat group attribution is provided in the research, so treat this as an opportunistic web application exploitation actor targeting an internet-facing Joomla site. |
| Behavior | Scanning and exploitation of Joomla search/mailto components on imreallynotbatman.com, leading to remote code execution. Expected observable chain: web_request, exploitation. MITRE ATT&CK T1190 (Exploit Public-Facing Application). Candidate detection predicates include web requests to `domain EQUALS imreallynotbatman.com` and Joomla component paths where `cmdline CONTAINS /joomla/`. |
| Location | Internet-facing web server hosting imreallynotbatman.com, typically in the perimeter or DMZ web tier. Focus first on web request telemetry for the site, then on process activity on the web server host. If exploitation succeeds, also inspect the web server host and adjacent internal network for follow-on activity. |
| Evidence | Relevant data sources: `web_request` events (`domain`, `cmdline`), `process_creation` events (`image`, `cmdline`, `pid`, `ppid`, `host`), `authentication` (`user`, `ip`, `action`), `dns`, and `smb`. Expected evidence: `web_request` rows where `domain EQUALS imreallynotbatman.com` and `cmdline CONTAINS /joomla/`; web request `cmdline` stores text such as `site=<host> uri=<path>`, so Joomla paths are embedded there. Corroborate with `process_creation` on the web server showing unexpected child processes, shell commands, or downloaded payloads after the web requests. Use pivots on `host`, `user`, `ip`, and time. The available data cannot directly prove successful RCE or reveal exploit payload content; it can show the web request pattern and any subsequent process/authentication/network behavior. |

## Notes
- Actor attribution is not provided in the research. The hypothesis is technique-focused, primarily T1190.
- Local telemetry does not expose a dedicated URI field. Joomla path strings are embedded in `cmdline` as `site=<host> uri=<path>`, so preferred predicates are `cmdline CONTAINS /joomla/` and optionally `cmdline CONTAINS com_search` or `cmdline CONTAINS com_mailto` if those strings are present.
- The data can show web requests and process creation, but cannot directly confirm exploit success or payload content. Corroborate with `process_creation`, `authentication`, `dns`, and `smb` activity after the suspicious web request timestamp.
- Plan steps must be single literal predicates over fields listed in the local data document. Pivots on `host`, `user`, `ip`, or time should be separate steps.
- MITRE ATT&CK reference: T1190, Exploit Public-Facing Application.
