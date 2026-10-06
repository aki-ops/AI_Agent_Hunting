# Hypothesis
Brute force login against a public-facing server. Repeated failed authentication events target user accounts on a host. The encoded `cmdline` row carries `Logon Failed` for failed attempts. Candidate detection predicates: `cmdline CONTAINS "Logon Failed"` and optionally `user EQUALS "admin"`.

# Recommended Time Frame
Full available CDB telemetry window: **2016-08-01T00:00:00Z through 2016-08-28T23:59:00Z**. Use the full 28-day range to establish baseline authentication failure volume, then focus on **5-minute buckets** for burst detection. If a burst is identified, pivot **±1 hour** around the burst for surrounding authentication, web, process, and SMB context.

# ABLE Table
| Element | Details |
| --- | --- |
| Actor | Not specified. Treat as an external attacker or automated bot attempting brute-force login against a public-facing server. No named actor or tooling is provided. |
| Behavior | Repeated failed authentication events targeting user accounts on a host; brute-force login attempt (MITRE ATT&CK T1110). Detection focus is an authentication failure burst. Candidate predicates: `cmdline CONTAINS "Logon Failed"`; `user EQUALS "admin"`. |
| Location | Public-facing or internet-facing server and its authentication telemetry. Pivot on `host`, `user`, `ip`, and `timestamp`. If web-facing, correlate with `web_request` rows for the same host, domain, IP, and time window. |
| Evidence | CDB events table. Primary source: `native_type EQUALS authentication` (`event_id 4624`). Search for `cmdline CONTAINS "Logon Failed"`; optionally `user EQUALS "admin"`; inspect `action`/`status` for failure outcome. Aggregate or count by `host`, `user`, and `ip` over short time windows to find bursts. Secondary source: `web_request` rows use `domain` and `cmdline` text such as `site=<host> uri=<path>` to identify public-facing server traffic, but those rows do not show logon failures. The local telemetry does not include Windows event ID 4625; failed authentication must be inferred from `cmdline` text or `action`/`status`, not from `event_id`. |

# Data
| Data Source | Native Type / Event ID | Key Fields | Relevance |
| --- | --- | --- | --- |
| CDB events table (equivalent `index=cdb`) | `authentication` / `4624` | `timestamp`, `event_id`, `native_type`, `host`, `user`, `ip`, `cmdline`, `action`, `status` | Primary source for failed-logon burst detection. Use `cmdline CONTAINS "Logon Failed"` and optionally `user EQUALS "admin"`. |
| CDB events table | `web_request` / `-` | `timestamp`, `native_type`, `host`, `domain`, `ip`, `port`, `cmdline` | Secondary source to identify public-facing server traffic and correlate attack timing. Cannot confirm authentication failure. |
| CDB events table | `process_creation` / `4688`, `1` | `timestamp`, `event_id`, `native_type`, `host`, `user`, `pid`, `ppid`, `image`, `cmdline` | Post-burst follow-up if a successful logon or compromise is suspected. |
| CDB events table | `smb` / `5140`, `5145`, `4648` | `timestamp`, `event_id`, `native_type`, `host`, `user`, `ip`, `file_path`, `cmdline` | Post-burst follow-up for lateral movement or file share access after possible successful authentication. |

# Hunt Procedure
All SPL below is an **equivalent detection draft only**. The deterministic executor uses the literal predicates listed in each step; SPL is provided for analyst reference and tuning.

1. **Identify failed authentication candidates.**
   - Predicates: `native_type EQUALS authentication`; `event_id EQUALS 4624`; `cmdline CONTAINS "Logon Failed"`.
   - Optional high-priority filter: `user EQUALS admin`.
   - Equivalent SPL:
     ```spl
     index=cdb native_type=authentication event_id=4624 cmdline="*Logon Failed*"
     | stats count by host user ip
     | sort -count
     ```
   - Interpretation: Lists hosts, users, and source IPs with failed-logon text. If no rows contain `cmdline CONTAINS "Logon Failed"`, the available CDB data cannot confirm failed authentication from `cmdline`. Inspect `action` and `status` for failure outcome.

2. **Establish baseline failed-authentication volume.**
   - Predicates: same as step 1.
   - Aggregation: count failed rows by `host`, `user`, `ip`, and 5-minute `_time` buckets over the full 28-day range.
   - Equivalent SPL:
     ```spl
     index=cdb native_type=authentication event_id=4624 cmdline="*Logon Failed*"
     | bin _time span=5m
     | stats count by _time host user ip
     | stats max(count) as max_5m avg(count) as avg_5m by host user ip
     | sort -max_5m
     ```
   - Interpretation: Use `max_5m` and `avg_5m` to tune the burst threshold. A starting threshold is `count > 10` per 5-minute window, but it must be adjusted to the observed baseline.

3. **Detect authentication failure bursts.**
   - Predicates: same as step 1.
   - Aggregation: count failed rows in 5-minute buckets by `host`, `user`, and `ip`.
   - Equivalent SPL:
     ```spl
     index=cdb native_type=authentication event_id=4624 cmdline="*Logon Failed*"
     | bin _time span=5m
     | stats count by _time host user ip
     | where count > 10
     | sort -_time
     ```
   - Interpretation: Any returned row is a burst candidate. If the burst includes `user=admin`, prioritize it. Tune the `count > 10` threshold based on step 2.

4. **Determine whether the burst targets a privileged account.**
   - Predicates: from step 3 results, filter `user EQUALS admin`.
   - Also compare against all users:
     ```spl
     index=cdb native_type=authentication event_id=4624 cmdline="*Logon Failed*"
     | bin _time span=5m
     | stats count by _time host user ip
     | where count > 10
     | sort -count
     ```
   - Interpretation: Bursts targeting `admin` are higher severity. Non-admin failures may also be brute force, user error, or spraying; do not ignore them without checking step 5.

5. **Distinguish brute force from password spraying.**
   - Predicates: same as step 1.
   - Pivot: count distinct users and total failures by `_time`, `host`, and `ip`.
   - Equivalent SPL:
     ```spl
     index=cdb native_type=authentication event_id=4624 cmdline="*Logon Failed*"
     | bin _time span=5m
     | stats dc(user) as users count by _time host ip
     | where users > 1 and count > 10
     ```
   - Interpretation: Many users from one IP suggests password spraying. Many failures against one user from one IP suggests brute force. Many source IPs targeting one user suggests distributed brute force. If `user=admin` is the only targeted account, treat as focused brute force.

6. **Correlate with public-facing web traffic.**
   - Predicates: `native_type EQUALS web_request`; `host EQUALS <flagged_host>` or `ip EQUALS <flagged_ip>`; time window around the burst.
   - Use `domain` and `cmdline` text such as `site=<host> uri=<path>`.
   - Equivalent SPL:
     ```spl
     index=cdb native_type=web_request (host=<flagged_host> OR cmdline="*site=<flagged_host>*")
     | bin _time span=5m
     | stats count by _time host domain ip cmdline
     | sort -_time
     ```
   - Interpretation: Helps confirm the server is web-facing and may show scanning or attack traffic. It **cannot** confirm failed authentication. If no `web_request` rows exist for the host, public-facing status is not proven by this telemetry.

7. **Check for successful authentication after the burst.**
   - Predicates: `native_type EQUALS authentication`; `event_id EQUALS 4624`; `cmdline CONTAINS "Logon Success"`; `host EQUALS <flagged_host>`; `user EQUALS <target_user>`; `ip EQUALS <source_ip>`; timestamp within the window after the burst.
   - Equivalent SPL:
     ```spl
     index=cdb native_type=authentication event_id=4624 cmdline="*Logon Success*" host=<flagged_host> user=<target_user> ip=<source_ip>
     | bin _time span=5m
     | stats count by _time host user ip action status
     ```
   - Interpretation: A successful logon after many failures indicates possible compromise. Use `action` or `status` if they encode success. If no success rows exist, the burst may have been unsuccessful or the available data may be incomplete.

8. **If success is found, hunt post-compromise activity.**
   - Process predicates: `native_type EQUALS process_creation`; `host EQUALS <flagged_host>`; `user EQUALS <target_user>`; `event_id EQUALS 4688 or 1`; time window after success.
   - SMB predicates: `native_type EQUALS smb`; `event_id EQUALS 5140 or 5145 or 4648`; `host EQUALS <flagged_host>`; `user EQUALS <target_user>`; time window after success.
   - Equivalent SPL:
     ```spl
     index=cdb native_type=process_creation host=<flagged_host> user=<target_user> event_id IN (4688,1)
     | stats count by _time pid ppid image cmdline
     | sort _time
     ```
     ```spl
     index=cdb native_type=smb host=<flagged_host> user=<target_user> event_id IN (5140,5145,4648)
     | stats count by _time event_id file_path cmdline ip
     | sort _time
     ```
   - Interpretation: Look for suspicious child processes, credential access tooling, lateral movement, or unexpected file share access shortly after the suspected successful authentication.

9. **Document limitations and gaps.**
   - Local telemetry lacks Windows event ID `4625`; failed authentication is inferred from `cmdline CONTAINS "Logon Failed"` or from `action`/`status`. If `action`/`status` does not encode failure and `cmdline` lacks `"Logon Failed"`, failed authentication cannot be confirmed from the available CDB data.
   - `web_request` rows do not record logon failures; they can only support public-facing server correlation.
   - The starting threshold `count > 10` per 5-minute window is a baseline hypothesis and must be tuned to the environment.
   - The data may identify a failed-logon burst but may not definitively distinguish brute force from password spraying, user error, or vulnerability scanning without additional context.
   - No named actor or tooling is provided; attribution is not possible from this telemetry alone.
