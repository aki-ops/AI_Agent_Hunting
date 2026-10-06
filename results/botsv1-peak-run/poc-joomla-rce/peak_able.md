# PEAK ABLE Table: Exploit Public-Facing Application (Joomla RCE)

*Hypothesis: Joomla RCE web compromise (BOTS v1 real attack). Attacker scans and exploits Joomla search/mailto components on imreallynotbatman.com.*

| ABLE Element | |
|---|---|
| **Actor** | Unspecified external attacker. The research document does not attribute the activity to a named threat group; it describes a BOTS v1 real attack scenario against a public Joomla site. |
| **Behavior** | Scanning and exploitation of Joomla search/mailto components on imreallynotbatman.com, consistent with MITRE ATT&CK T1190 (Exploit Public-Facing Application). Expected observable chain: web_request followed by exploitation, potentially leading to remote code execution. Candidate detections: web requests where domain EQUALS imreallynotbatman.com; Joomla component path where cmdline CONTAINS /joomla/. |
| **Location** | Internet-facing web server hosting imreallynotbatman.com; web application/DMZ perimeter. Successful exploitation would be expected to generate subsequent host-level activity on the same web server. |
| **Evidence** | Consult web_request telemetry (native_type = web_request) using fields timestamp, host, ip, port, domain, cmdline, action, status. Look for domain EQUALS imreallynotbatman.com, cmdline CONTAINS /joomla/, and focused terms such as search or mailto where present in cmdline. Correlate by host and time with process_creation (event_id 4688 or 1) on the web host, looking for unexpected process creation, command-line execution, or web-shell activity that may indicate successful RCE. The available data can show web exploitation attempts and possible process creation, but it cannot by itself prove exact Joomla exploit success, data exfiltration, or all request details without additional web server, WAF, or EDR context. |

Notes:
- The local web_request table stores the site in domain and request text such as site=<host> uri=<path> in cmdline; exact HTTP method, URI, status, and user-agent may not be directly filterable unless present in cmdline or other fields.
- Detection draft SPL: index=cdb native_type=web_request (domain="imreallynotbatman.com" OR cmdline="*/joomla/*") — adapt field/operator syntax to the deterministic executor; executor PoC steps should be literal predicates such as domain EQUALS imreallynotbatman.com and cmdline CONTAINS /joomla/.
- Pitfall: cmdline CONTAINS /joomla/ may match benign Joomla paths; tune with search, mailto, HTTP method/POST indicators, response status, request volume, and time correlation to the exploitation window.
- If the question is whether RCE actually occurred, pivot to process_creation on the web host (host from web_request) and inspect image, cmdline, pid, ppid, and user; absence of process telemetry may mean the exploit failed or telemetry does not capture the child process.
