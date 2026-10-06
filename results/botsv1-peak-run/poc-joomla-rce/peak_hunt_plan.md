# Hunt Plan: Joomla RCE Web Compromise on imreallynotbatman.com

## Hypothesis

Joomla RCE web compromise (BOTS v1 real attack). An attacker scans and exploits Joomla `search`/`mailto` components on `imreallynotbatman.com`, consistent with MITRE ATT&CK T1190 (Exploit Public-Facing Application). Expected observable chain: `web_request`, then exploitation, potentially leading to remote code execution on the Internet-facing web server.

## Recommended Time Frame

Primary window: **2016-08-24 10:00:00Z to 2016-08-24 17:00:00Z UTC**, based on the available DNS activity window and the BOTS v1 web-compromise scenario. If no conclusive activity is found, expand to the full local telemetry range: **2016-08-01T00:00:00Z through 2016-08-28T23:59:00Z**.

## ABLE Table

| ABLE Element | Description |
|---|---|
| **Actor** | Unspecified external attacker. No named threat group is attributed in the research document; it describes a BOTS v1 real attack against a public Joomla site. |
| **Behavior** | Scanning and exploitation of Joomla `search`/`mailto` components on `imreallynotbatman.com`, consistent with MITRE ATT&CK T1190. Expected chain: `web_request` followed by exploitation, potentially leading to remote code execution. |
| **Location** | Internet-facing web server hosting `imreallynotbatman.com`; web application/DMZ perimeter. Successful exploitation would generate subsequent host-level activity on the same web server. |
| **Evidence** | `web_request` telemetry using `timestamp`, `host`, `ip`, `port`, `domain`, `cmdline`, `action`, `status`. Look for `domain EQUALS imreallynotbatman.com`, `cmdline CONTAINS /joomla/`, and terms such as `search` or `mailto`. Correlate by `host` and time with `process_creation` (`event_id 4688` or `1`) on the web host for unexpected process creation, command-line execution, or web-shell activity. The available data can show web exploitation attempts and possible process creation, but it cannot by itself prove exact Joomla exploit success, data exfiltration, or all request details without additional web server, WAF, or EDR context. |

## Data

The local telemetry is a CDB SQLite table named `events`. In Splunk terms, use `index=cdb` where mapped and filter by `native_type` as the sourcetype-equivalent. The deterministic executor should apply literal predicates over the fields below.

| Data Source / native_type | Key Fields | Relevance |
|---|---|---|
| `web_request` | `timestamp`, `host`, `ip`, `port`, `domain`, `cmdline`, `action`, `status`, `raw_ref` | Identify requests to `imreallynotbatman.com` and Joomla component paths. Web requests store the site in `domain` and request text such as `site=<host> uri=<path>` in `cmdline`. |
| `process_creation` (`event_id 4688` or `1`) | `timestamp`, `host`, `user`, `pid`, `ppid`, `cmdline`, `image`, `file_path` | Detect post-exploit RCE child processes on the web host. `event_id 1` has only 66 rows, so `4688` is the main process telemetry. |
| `authentication` (`event_id 4624`) | `timestamp`, `host`, `user`, `ip`, `action`, `cmdline` | Detect lateral movement or post-exploit logons. Auth rows keep text such as `Logon Success user=.. ip=..` in `cmdline` and outcome in `action`. |
| `dns` | `timestamp`, `host`, `domain`, `ip`, `cmdline` | Detect possible C2 or outbound resolution from the web host after exploitation. |
| `smb` (`event_id 5140`, `5145`, `4648`) | `timestamp`, `host`, `user`, `ip`, `port`, `cmdline`, `action`, `file_path` | Detect lateral movement, file access, or credential use after compromise. |

## Hunt Procedure

SPL shown below is an equivalent detection draft only. The deterministic executor should run the literal field/operator/value predicates against the CDB `events` table.

1. **Confirm web request telemetry for the target domain.**  
   Table: `native_type=web_request`. Predicate: `domain EQUALS imreallynotbatman.com`.  
   SPL draft: `index=cdb native_type=web_request domain="imreallynotbatman.com" | stats count by host, ip, port, action, status | sort -count`  
   Interpretation: establish baseline volume, source IPs, destination ports, and response statuses. Note any single source IP with unusually high request counts.

2. **Enumerate Joomla component paths on the target.**  
   Table: `native_type=web_request`, `domain EQUALS imreallynotbatman.com`. Predicate: `cmdline CONTAINS /joomla/`.  
   SPL draft: `index=cdb native_type=web_request domain="imreallynotbatman.com" cmdline="*/joomla/*" | stats count by host, ip, cmdline, action, status | sort -count`  
   Interpretation: identify accessed Joomla paths. Many benign Joomla paths may match; prioritize high-volume or unusual paths.

3. **Focus on the Joomla `search` component.**  
   Table: `native_type=web_request`, `domain EQUALS imreallynotbatman.com`. Predicate: `cmdline CONTAINS search`.  
   SPL draft: `index=cdb native_type=web_request domain="imreallynotbatman.com" cmdline="*search*" | stats count by host, ip, cmdline, action, status | sort -count`  
   Interpretation: highlight requests involving `search`, which may indicate scanning or exploitation of the vulnerable component.

4. **Focus on the Joomla `mailto` component.**  
   Table: `native_type=web_request`, `domain EQUALS imreallynotbatman.com`. Predicate: `cmdline CONTAINS mailto`.  
   SPL draft: `index=cdb native_type=web_request domain="imreallynotbatman.com" cmdline="*mailto*" | stats count by host, ip, cmdline, action, status | sort -count`  
   Interpretation: highlight requests involving `mailto`, another component named in the hypothesis.

5. **Identify high-volume scanning by source IP.**  
   Table: `native_type=web_request`, `domain EQUALS imreallynotbatman.com`. Predicate: `ip EXISTS`.  
   SPL draft: `index=cdb native_type=web_request domain="imreallynotbatman.com" ip=* | stats count by ip, host, cmdline | sort -count`  
   Interpretation: repeated requests from one IP to many Joomla paths suggest automated scanning.

6. **Look for POST or exploit-like request indicators if present in `cmdline`.**  
   Table: `native_type=web_request`, `domain EQUALS imreallynotbatman.com`. Predicate: `cmdline CONTAINS POST`.  
   SPL draft: `index=cdb native_type=web_request domain="imreallynotbatman.com" cmdline="*POST*" | stats count by host, ip, cmdline, action, status | sort -count`  
   Interpretation: if HTTP method is stored in `cmdline`, POST requests to Joomla components are more suspicious than GET requests. If the method is not present, clearly note that the available data cannot filter on HTTP method.

7. **Extract suspicious source IPs and web hosts for pivoting.**  
   Analysis step using results from steps 1–6. Select IPs with repeated Joomla access, `search`/`mailto` requests, or high request volume. Select the `host` values associated with `imreallynotbatman.com`.  
   SPL draft: `index=cdb native_type=web_request domain="imreallynotbatman.com" | stats count by ip, host | sort -count`

8. **Pivot to process creation on the web host.**  
   Table: `native_type=process_creation`. Predicate: `host EQUALS <suspicious_web_host>`.  
   SPL draft: `index=cdb native_type=process_creation host="<suspicious_web_host>" (event_id=4688 OR event_id=1) | table timestamp, host, user, pid, ppid, image, cmdline, file_path | sort timestamp`  
   Interpretation: inspect for unexpected child processes on the web server, especially around the time of suspicious Joomla requests.

9. **Look for suspicious process images on the web host.**  
   Table: `native_type=process_creation`, `host EQUALS <suspicious_web_host>`. Predicate: `image ENDS_WITH cmd.exe`.  
   SPL draft: `index=cdb native_type=process_creation host="<suspicious_web_host>" image="*cmd.exe" | table timestamp, host, user, pid, ppid, image, cmdline | sort timestamp`  
   Interpretation: `cmd.exe` spawned by a web server process may indicate RCE or web-shell activity.

10. **Look for suspicious PowerShell execution on the web host.**  
    Table: `native_type=process_creation`, `host EQUALS <suspicious_web_host>`. Predicate: `image CONTAINS powershell`.  
    SPL draft: `index=cdb native_type=process_creation host="<suspicious_web_host>" image="*powershell*" | table timestamp, host, user, pid, ppid, image, cmdline | sort timestamp`  
    Interpretation: PowerShell execution on a web server may indicate post-exploitation activity.

11. **Search for common reconnaissance commands in process command lines.**  
    Table: `native_type=process_creation`, `host EQUALS <suspicious_web_host>`. Predicate: `cmdline CONTAINS whoami`.  
    SPL draft: `index=cdb native_type=process_creation host="<suspicious_web_host>" cmdline="*whoami*" | table timestamp, host, user, pid, ppid, image, cmdline`  
    Interpretation: repeat with other indicators such as `ipconfig`, `net user`, `certutil`, `bitsadmin`, and `wget`/`curl`. These are common post-exploitation commands.

12. **Correlate process creation time with suspicious web requests.**  
    Pivot on `host` and `timestamp`. Compare the timestamp of Joomla `search`/`mailto` requests from steps 3–4 with process creation events from steps 8–11.  
    SPL draft: `index=cdb (native_type=web_request domain="imreallynotbatman.com" cmdline="*search*") OR (native_type=process_creation host="<suspicious_web_host>") | eval t=timestamp | table t, native_type, host, ip, user, image, cmdline | sort t`  
    Interpretation: process creation within seconds or minutes after a suspicious Joomla request strongly suggests exploitation. If no process telemetry exists, the available data cannot confirm RCE.

13. **Check authentication events from the suspicious source IP.**  
    Table: `native_type=authentication`. Predicate: `ip EQUALS <suspicious_attacker_ip>`.  
    SPL draft: `index=cdb native_type=authentication ip="<suspicious_attacker_ip>" | table timestamp, host, user, ip, action, cmdline | sort timestamp`  
    Interpretation: successful logons from the attacking IP after the web exploitation attempt may indicate lateral movement.

14. **Check authentication events on the web host after exploitation.**  
    Table: `native_type=authentication`. Predicate: `host EQUALS <suspicious_web_host>`.  
    SPL draft: `index=cdb native_type=authentication host="<suspicious_web_host>" | table timestamp, host, user, ip, action, cmdline | sort timestamp`  
    Interpretation: look for unusual users, `Logon Success`, or service account activity shortly after the exploitation window.

15. **Check DNS activity from the web host.**  
    Table: `native_type=dns`. Predicate: `host EQUALS <suspicious_web_host>`.  
    SPL draft: `index=cdb native_type=dns host="<suspicious_web_host>" | table timestamp, host, domain, ip, cmdline | sort timestamp`  
    Interpretation: outbound DNS resolution from the web server after exploitation may indicate C2, payload download, or beaconing.

16. **Check SMB activity involving the web host or attacker IP.**  
    Table: `native_type=smb`. Predicate: `host EQUALS <suspicious_web_host>`.  
    SPL draft: `index=cdb native_type=smb host="<suspicious_web_host>" | table timestamp, host, user, ip, port, action, file_path, cmdline | sort timestamp`  
    Interpretation: SMB access to or from the web host may indicate lateral movement, file staging, or credential use. Repeat with `ip EQUALS <suspicious_attacker_ip>`.

17. **Tune false positives and validate against baseline.**  
    Compare suspicious Joomla requests and process creation against normal activity before the exploitation window. Consider benign Joomla administration, update checks, vulnerability scanners, and monitoring tools.  
    SPL draft: `index=cdb native_type=web_request domain="imreallynotbatman.com" | timechart span=1h count by cmdline`  
    Interpretation: repeated low-volume access to common Joomla paths is likely benign; a spike plus post-exploit process creation is suspicious.

18. **Document findings and gaps.**  
    State whether the available data shows scanning, exploitation attempts, and/or successful RCE. The local telemetry can show `web_request` activity and possible `process_creation`, but it cannot prove exact Joomla exploit success, data exfiltration, or all HTTP request details unless the method, URI, status, or user-agent are present in `cmdline` or another field. Additional web server, WAF, or EDR context would be required for definitive confirmation.
