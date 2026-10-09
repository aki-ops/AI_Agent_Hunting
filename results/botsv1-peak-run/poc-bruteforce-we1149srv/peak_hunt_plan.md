**Hypothesis**  
Brute force login against a public‑facing server. Repeated failed authentication events target user accounts on a host, and the `cmdline` field contains the string **“Logon Failed”** for each failed attempt.

**Recommended Time Frame**  
No specific time window is prescribed in the hypothesis. The available telemetry spans **2016‑08‑01 00:00:00 Z to 2016‑08‑28 23:59:00 Z**; the hunt can be run over the full dataset or any sub‑range of interest (e.g., the previous 7 days if a more recent window is desired).

**ABLE Table**

| ABLE Element | Content |
|--------------|---------|
| **Actor** | Unspecified / generic threat actor (no specific group named) |
| **Behavior** | Brute force login – repeated failed authentication attempts against user accounts |
| **Location** | Public‑facing server (internet‑exposed host) |
| **Evidence** | Authentication events (`native_type = authentication`, `event_id = 4624`) where `cmdline` **CONTAINS** `Logon Failed`. Evidence can be refined by `host`, `user`, `ip`, and temporal bursts (multiple failures from the same host/user within a short time window). |

**Data**

| Data Source (Table) | native_type | event_id | Key Fields Relevant to Hunt | Relevance |
|---------------------|-------------|----------|-----------------------------|-----------|
| `events` (SQLite)   | authentication | 4624 | `timestamp`, `host`, `user`, `cmdline`, `ip`, `action`, `status` | Contains the authentication logs needed to detect failed logons (`cmdline CONTAINS Logon Failed`). |
| `events` (SQLite)   | authentication | 4624 (success) | `timestamp`, `host`, `user`, `cmdline`, `ip` | Optional pivot to see if any successful logon followed a burst of failures (`cmdline CONTAINS Logon Success`). |
| `events` (SQLite)   | any (for context) | — | `host`, `ip`, `domain` | May help infer whether a host is public‑facing if external tagging or IP reputation data were present (not available in the current schema). |

**Hunt Procedure**

1. **Select failed authentication events**  
   - Predicate: `native_type EQUALS authentication AND event_id EQUALS 4624 AND cmdline CONTAINS Logon Failed`  
   - Return fields: `timestamp`, `host`, `user`, `ip`, `cmdline`.

2. **(Optional) Restrict to known public‑facing hosts**  
   - If the environment provides a tag or list of external hosts, apply: `host EQUALS <external‑host‑list>` or `ip NOT IN <internal‑ranges>`.  
   - *Note:* The current schema does **not** contain an explicit field marking a host as public‑facing; this step can only be performed if external context is added elsewhere. If unavailable, proceed with all hosts and acknowledge the limitation.

3. **Aggregate failures by host and user over a short time window**  
   - Use a time‑bucketed count (e.g., 5‑minute intervals) to spot bursts:  
     ```
     | tstats count WHERE native_type=authentication event_id=4624 cmdline="*Logon Failed*" 
       BY host user _time span=5m
     ```
   - In pure predicate terms, this step can be approximated by:  
     - Filter as in Step 1.  
     - Sort results by `timestamp`.  
     - For each `host`/`user` pair, count events where the difference between successive timestamps ≤ 300 seconds (5 min).  
   - Flag pairs where the count ≥ threshold (e.g., **≥ 10 failures** within the window).

4. **Extract candidate brute‑force incidents**  
   - For each flagged `host`/`user` pair, return the earliest and latest `timestamp` in the burst, the list of `ip` addresses observed, and the raw `cmdline` values.

5. **Check for subsequent successful logon (optional pivot)**  
   - Predicate: `native_type EQUALS authentication AND event_id EQUALS 4624 AND cmdline CONTAINS Logon Success AND host EQUALS <candidate host> AND user EQUALS <candidate user> AND timestamp > <burst end time>`  
   - If a success follows a burst, note it as a potential compromise; if none, the activity remains a failed brute‑force attempt.

6. **Enrich with network context (if available)**  
   - Join on `ip` to see if the source address belongs to known malicious IP lists, geo‑locations, or ASNs.  
   - *Limitation:* The provided `events` table does not contain reputation fields; this enrichment would require external look‑ups not present in the current data.

7. **Report findings**  
   - Produce a table with columns: `detected_at` (burst start), `host`, `user`, `failure_count`, `source_ip_list`, `time_window_minutes`, `followed_by_success (yes/no)`, and any relevant notes (e.g., “no external‑host tag available”).  
   - Highlight any bursts that exceed the threshold and involve hosts suspected of being public‑facing.

**Where the Available Data Cannot Answer a Question**

- **Public‑facing server identification:** The schema lacks a field or tag that explicitly marks a host as internet‑exposed. Without external context (e.g., asset inventory, IP reputation, or DMZ labeling), the hunt cannot definitively restrict to public‑facing servers; it must either rely on administrator‑supplied host lists or accept that some detected bursts may occur on internal systems.  
- **Reputation / threat‑intel on source IPs:** No columns for IP reputation, geo‑location, or ASN are present, so determining whether the source addresses are known malicious or originate from unexpected geographic regions requires external look‑ups outside the provided SQLite table.  

---  

*All steps above are expressed as literal predicates (`EQUALS`, `CONTAINS`, etc.) or as equivalent SPL `tstats` drafts that can be executed against the `events` table.*
