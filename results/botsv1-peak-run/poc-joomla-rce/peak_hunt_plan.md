**Hypothesis**  
Joomla RCE web compromise (BOTS v1 real attack). Attacker scans and exploits Joomla search/mailto components on imreallynotbatman.com.

**Recommended Time Frame**  
Full available time range for web request telemetry: **2016‑08‑01T00:00:00Z → 2016‑08‑28T23:59:58Z** (the span of the `web_request` native_type). No narrower window is indicated by the hypothesis.

**ABLE Table**

| ABLE Element | Content |
|---|---|
| Actor | Unspecified / generic web application attacker |
| Behavior | Scan and exploit Joomla search/mailto components to achieve remote code execution (RCE) |
| Location | Internet‑facing web server hosting imreallynotbatman.com (the Joomla web application) |
| Evidence | Web request logs where `native_type EQUALS web_request` **AND** `domain EQUALS imreallynotbatman.com` **AND** `cmdline` contains a Joomla search/mailto URI. In the local SQLite `events` table this is expressed as:<br>`native_type EQUALS web_request AND domain EQUALS imreallynotbatman.com AND ( cmdline CONTAINS "/joomla/" OR cmdline CONTAINS "uri=/index.php?option=com_search" OR cmdline CONTAINS "uri=/index.php?option=com_mailto" )` |
| Note | Host‑level process or authentication data confirming post‑exploitation is not available; detection must rely solely on web request logs. The `cmdline` field stores `site=<host> uri=<path>`, allowing filtering on the URI component. |

**Data**

| Table | Sourcetype (native_type) | Key Fields | Relevance to Hunt |
|---|---|---|---|
| `events` | `web_request` | `timestamp`, `domain`, `cmdline`, `host`, `ip`, `port` | Contains the web request logs needed to test for Joomla search/mailto component access. |
| `events` | `process_creation` (4688, 1) | `timestamp`, `host`, `user`, `cmdline`, `image` | Not directly useful for this hunt (no post‑exploitation telemetry). |
| `events` | `authentication` (4624) | `timestamp`, `host`, `user`, `cmdline`, `action` | Not directly useful for this hunt. |
| `events` | `smb` (5140, 5145, 4648) | `timestamp`, `host`, `user`, `cmdline`, `ip`, `port` | Not directly useful for this hunt. |
| `events` | `dns` | `timestamp`, `host`, `domain`, `cmdline` | Not directly useful for this hunt. |

**Hunt Procedure**  
All steps are expressed as literal predicates over the fields in the `events` table, plus allowed pivots on `host`, `user`, `ip`, and `time`. After each step a detection‑draft SPL is shown for reference only; the executor will execute the predicate chain directly.

1. **Isolate web request events**  
   - Predicate: `native_type EQUALS web_request`  
   - Detection draft: `FROM events WHERE native_type='web_request'`

2. **Restrict to the target domain**  
   - Predicate: `domain EQUALS imreallynotbatman.com`  
   - Detection draft: `| where domain="imreallynotbatman.com"`

3. **Filter for Joomla search/mailto URIs** (broad catch‑all plus two specific strings)  
   - Predicate: `cmdline CONTAINS "/joomla/" OR cmdline CONTAINS "uri=/index.php?option=com_search" OR cmdline CONTAINS "uri=/index.php?option=com_mailto"`  
   - Detection draft: `| where match(cmdline, "(?i)/joomla/") OR match(cmdline, "(?i)uri=/index.php?option=com_search") OR match(cmdline, "(?i)uri=/index.php?option=com_mailto")`  
   - *(Note: The executor treats `CONTAINS` as case‑insensitive, so the plain `CONTAINS` operators are sufficient.)*

4. **Return relevant fields for initial inspection**  
   - Fields: `timestamp`, `host`, `ip`, `port`, `cmdline`  
   - Detection draft: `| table timestamp host ip port cmdline`

5. **Pivot to identify repeating sources (optional but recommended)**  
   - Pivot on `host` and `ip` with a time bucket of 1 hour to distinguish bursty scanning from low‑and‑slow activity.  
   - Predicate after step 4: `stats count, earliest(timestamp) as first_seen, latest(timestamp) as last_seen by host ip bin(timestamp, 1h)`  
   - Detection draft: `| stats count, earliest(timestamp) as first_seen, latest(timestamp) as last_seen by host ip, bin(timestamp, 1h)`

6. **Interpret results**  
   - Any row returned after step 3 indicates a request to a Joomla search/mailto endpoint on the target domain.  
   - A high count from a single `host`/`IP` (especially with a short time span) suggests scanning or attempted exploitation.  
   - Examine the `cmdline` value for suspicious payloads that might appear in the URI (e.g., presence of `cmd=`, `id=`, `eval(`, `base64_decode`, long encoded strings).  
   - Because the telemetry logs only the URI (`site=<host> uri=<path>`), any POST‑body obfuscation or multipart data is invisible; therefore we cannot see the exact exploit string unless it is placed in the query string.

7. **Limitations / What the data cannot answer**  
   - **Post‑exploitation confirmation**: No host‑level process creation, authentication, or SMB logs are available to verify that a successful RCE led to command execution, file writes, or lateral movement.  
   - **Payload details**: The `cmdline` field records only the URI; any data sent in the request body, headers, or encoded within cookies is not captured.  
   - **Request outcome**: The `action` and `status` fields are not populated for `web_request` in this dataset, so HTTP response codes (200, 404, 500, etc.) cannot be inferred from this table alone.  

**Summary**  
Execute the combined predicate chain  

```
native_type EQUALS web_request
AND domain EQUALS imreallynotbatman.com
AND ( cmdline CONTAINS "/joomla/"
      OR cmdline CONTAINS "uri=/index.php?option=com_search"
      OR cmdline CONTAINS "uri=/index.php?option=com_mailto" )
```

over the `events` table for the full date range. Review the returned `timestamp`, `host`, `ip`, `port`, and `cmdline` values to identify scanning or exploitation attempts. Optionally pivot on `host`, `ip`, and hourly time bins to spot frequent sources. Acknowledge that without additional telemetry (process, auth, SMB) you cannot confirm successful compromise or subsequent malicious behavior.
