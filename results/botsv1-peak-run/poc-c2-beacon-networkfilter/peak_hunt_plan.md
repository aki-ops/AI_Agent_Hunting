**Hypothesis**  
C2 beacon to ad.networkfilter.co (BOTS v1 known IOC). An internal host will generate an outbound HTTP request to the domain **ad.networkfilter.co**, observable as a web_request event where the domain field (or the cmdline field) contains that string.

**Recommended Time Frame**  
No specific time window is required; the hypothesis can be tested over the entire available dataset (2016‑08‑01 00:00:00Z to 2016‑08‑28 23:59:59Z). If a narrower window is desired for performance, a reasonable default is the **previous 30 days** relative to the latest timestamp in the data.

**ABLE Table**

| ABLE Element | Details |
|--------------|---------|
| **Actor** | Threat actor leveraging the ad.networkfilter.co C2 infrastructure (associated with the BOTS v1 ad‑fraud campaign). Specific actor not identified in the hypothesis. |
| **Behavior** | Outbound HTTP request to the domain **ad.networkfilter.co** (C2 beaconing). Observed as a `web_request` event where `domain` CONTAINS `ad.networkfilter.co` (or `cmdline` CONTAINS `ad.networkfilter.co`). |
| **Location** | Internal hosts with outbound Internet access (workstations, servers) inside the monitored network. The beacon originates internally and travels to the external C2 host. |
| **Evidence** | - `web_request` rows where `domain` CONTAINS `ad.networkfilter.co` (or `cmdline` CONTAINS `ad.networkfilter.co`).<br>- Corresponding `process_creation` rows (event_id = 4688 or 1) that share the same `host`, `user`, and a temporal proximity to the web request (to link the beacon to a specific executable).<br>- Optional: `cmdline` CONTAINS `/banner/` to capture the known ad‑fraud beacon pattern. |

**Data**

| Index / Table | Native Type | Key Fields | Relevance to Hunt |
|---------------|-------------|------------|-------------------|
| `events` (SQLite) | `web_request` (no event_id) | `timestamp`, `host`, `user`, `domain`, `cmdline` | Primary source for detecting the C2 beacon; `domain` holds the target host, `cmdline` contains `site=<host> uri=<path>`. |
| `events` (SQLite) | `process_creation` (event_id = 4688) | `timestamp`, `host`, `user`, `pid`, `ppid`, `image`, `cmdline` | Provides the process that issued the web request; allows linking beacon to an executable via host/user/time pivot. |
| `events` (SQLite) | `process_creation` (event_id = 1) | same as above | Fallback for process creation events captured via a different channel (if present). |
| `events` (SQLite) | `dns` (no event_id) | `timestamp`, `host`, `user`, `domain` | Optional context: prior DNS lookup of ad.networkfilter.co. |
| `events` (SQLite) | `authentication` (event_id = 4624) | `timestamp`, `host`, `user`, `cmdline`, `action` | Optional context: logon activity around the beacon time. |

**Hunt Procedure**  
All steps are expressed as literal predicates (field / operator / value) over the columns listed above, plus pivots on `host`, `user`, `ip`, and `time`. Where the available data cannot answer a question, it is noted explicitly.

1. **Identify candidate web‑request events matching the C2 domain**  
   - Predicate: `native_type EQUALS 'web_request' AND domain CONTAINS 'ad.networkfilter.co'`  
   - (Case‑insensitive CONTAINS per executor rules.)  
   - Return fields: `timestamp`, `host`, `user`, `domain`, `cmdline`.  
   - *If no rows are returned, the hypothesis is not supported in the data set.*

2. **Optional refinement – look for the known ad‑fraud URI pattern**  
   - Predicate: `native_type EQUALS 'web_request' AND cmdline CONTAINS '/banner/'`  
   - This can be combined with step 1 (AND) if you want to require both the domain and the `/banner/` string, or run separately to see how many beacon‑like requests also contain the pattern.  

3. **Collect context from each candidate web request**  
   - For each row returned in step 1 (or step 2 if refined), note the values of `host`, `user`, and `timestamp`.  
   - These three fields will be used as pivot values to locate the responsible process.

4. **Find process creation events that could have generated the web request**  
   - Predicate: `native_type EQUALS 'process_creation' AND (event_id EQUALS '4688' OR event_id EQUALS '1') AND host = <host_from_step3> AND user = <user_from_step3> AND timestamp >= <timestamp_from_step3 - 5 minutes> AND timestamp <= <timestamp_from_step3 + 5 minutes>`  
   - The executor does not support arithmetic directly; therefore the time window is expressed as a pair of explicit predicates using the **time pivot** capability:  
     - `timestamp >= <earliest_time>` (where `<earliest_time>` is the candidate timestamp minus 5 minutes)  
     - `timestamp <= <latest_time>` (candidate timestamp plus 5 minutes)  
   - Return fields: `timestamp`, `host`, `user`, `pid`, `ppid`, `image`, `cmdline`.  
   - *If no process_creation rows are found within the window, note that the executor cannot definitively link the web request to a specific executable; the beacon may have originated from a script, a service, or a process not captured in the process_creation telemetry.*

5. **Correlate and enrich**  
   - For each matching process_creation row, examine the `image` (executable path) and `cmdline` to assess legitimacy.  
   - Optionally, add a DNS lookup step:  
     - Predicate: `native_type EQUALS 'dns' AND host = <host_from_step3> AND domain CONTAINS 'ad.networkfilter.co' AND timestamp < <timestamp_from_step3>`  
     - This shows whether the host performed a DNS query for the C2 domain prior to the HTTP request.  
   - Optionally, add authentication context:  
     - Predicate: `native_type EQUALS 'authentication' AND host = <host_from_step3> AND user = <user_from_step3> AND timestamp BETWEEN <timestamp_from_step3 - 1 hour> AND <timestamp_from_step3 + 1 hour>`  
     - Look for unusual logon types or failed attempts that might indicate credential compromise.

6. **Output and assessment**  
   - Produce a table containing: web_request timestamp, host, user, domain, cmdline; linked process_creation timestamp, pid, ppid, image, cmdline; and any DNS/auth rows if collected.  
   - Flag rows where:  
     - The `image` is not a known legitimate browser or updater (e.g., unexpected executables, scripts, or unsigned binaries).  
     - The `cmdline` of the process contains suspicious parameters (e.g., `--proxy`, `--no-sandbox`, or known malicious frameworks).  
   - If the web request includes `/banner/` in `cmdline`, raise higher confidence that the traffic matches the BOTS v1 ad‑fraud beacon pattern.

**Limitations / Where Data Cannot Answer**  
- The telemetry does not contain the actual HTTP payload (e.g., POST data, response body), so we cannot confirm whether the request carried malicious commands or exfiltrated data.  
- If the beacon was generated by a non‑standard process that does not generate a process_creation event (e.g., a DLL loaded into a trusted browser, a script executed via `wscript.exe` without a distinct creation event), step 4 may fail to link the request to an executable.  
- The executor’s literal‑predicate model cannot express complex calculations (e.g., dynamic time windows based on each row’s timestamp); we must pre‑compute or approximate windows, which may miss very short‑lived processes.  
- No TLS/SSL certificate information is available, so we cannot verify whether the connection was encrypted or inspect SNI values beyond the domain field.  

By following the above steps, a hunter can systematically search the available SQLite `events` table for the specific C2 beacon described in the hypothesis, gather supporting process and contextual evidence, and make an informed judgment about the likelihood of malicious activity.
