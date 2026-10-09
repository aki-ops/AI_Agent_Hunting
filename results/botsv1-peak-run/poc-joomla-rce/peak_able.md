# PEAK ABLE Table: Joomla RCE via Search/Mailto
*Hypothesis: Joomla RCE web compromise (BOTS v1 real attack). Attacker scans and exploits Joomla search/mailto components on imreallynotbatman.com.*
| ABLE Element | Content |
|---|---|
| Actor | Unspecified / generic web application attacker |
| Behavior | Scan and exploit Joomla search/mailto components to achieve remote code execution (RCE) |
| Location | Internet‑facing web server hosting imreallynotbatman.com (the Joomla web application) |
| Evidence | Web request logs where `domain EQUALS imreallynotbatman.com` and `cmdline CONTAINS` Joomla search/mailto paths (e.g., `/index.php?option=com_search…`, `/index.php?option=com_mailto…`). This can be expressed as the predicate: `domain EQUALS imreallynotbatman.com AND cmdline CONTAINS /joomla/` (or more specific strings) indicating attempted exploitation. |
- Note: Host‑level process or authentication data confirming post‑exploitation is not available in the provided telemetry; detection must rely on web request logs. The `cmdline` field stores `site=<host> uri=<path>`, allowing filtering on the URI component. |
