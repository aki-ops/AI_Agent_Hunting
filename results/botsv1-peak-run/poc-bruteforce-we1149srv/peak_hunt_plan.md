# Hunt Plan: Brute Force Login Against Public-Facing Server

## Hypothesis
Brute force login against public-facing server. Repeated failed authentication events targeting user accounts on a host. The encoded cmdline row carries `Logon Failed` for failed attempts.

## Recommended Time Frame
Full available CDB window: **2016-08-01T00:00:00Z through 2016-08-28T23:59:00Z** (28 days). Use **5-minute** and **1-hour** aggregation bins to detect authentication-failure bursts. If run against a live Splunk instance with newer data, use **previous 30 days** and compare against this 28-day baseline.

## ABLE Table
| ABLE Element | Hunt-Relevant Details |
|---|---|
| Actor | Unknown or opportunistic brute-force actor. No actor-specific telemetry is available in the local CDB data. Actor attribution cannot be confirmed from the provided fields. |
| Behavior | Password guessing / brute force against a login service, mapped to MITRE ATT&CK **T1110**. Repeated failed authentication events target user accounts on a host. Local failure signal is encoded in `cmdline` as `Logon Failed`; outcome context is in `action`. Privileged targeting is tested with `user EQUALS admin`. Observable chain is an authentication-failure burst. |
| Location | Public-facing / internet-facing server and its authentication service. Local telemetry can identify target `host`, `user`, and source `ip`, but **cannot prove internet exposure**. Confirming public-facing status requires external asset inventory, exposure data, or correlation with web-facing telemetry. |
| Evidence | Primary data source: local CDB SQLite table `events`, especially `native_type = authentication` / `event_id = 4624`. Look for rows where `cmdline CONTAINS "Logon Failed"`. Pivot and aggregate by `host`, `user`, `ip`, and `timestamp` to derive burst behavior. Check privileged targeting with `user EQUALS admin`. Check for success after failure with `cmdline CONTAINS "Logon Success"`. Public-facing exposure is not directly encoded in the available columns. |

## Data
| Data Source | Native Type / Event ID | Key Fields | Relevance to Hunt |
|---|---|---|---|
| CDB table `events` | `authentication` / `4624` | `timestamp`, `host`, `user`, `ip`, `cmdline`, `action`, `status`, `raw_ref` | Primary failed and successful authentication events. Failure text is in `cmdline` as `Logon Failed`; success text is in `cmdline` as `Logon Success`. `event_id 4624` is authentication telemetry in this dataset and **must not** be treated as a Windows failure event ID. |
| CDB table `events` | `web_request` / `-` | `timestamp`, `host`, `domain`, `ip`, `port`, `cmdline` | Possible public-facing exposure correlation. Web requests store site in `domain` and `site=<host> uri=<path>` in `cmdline`. Matching an auth `host` to web telemetry supports, but does not prove, internet exposure. |
| CDB table `events` | `process_creation` / `4688`, `1` | `timestamp`, `host`, `user`, `pid`, `ppid`, `image`, `cmdline` | Post-compromise process activity if a brute-force attempt succeeds. |
| CDB table `events` | `smb` / `5140`, `5145`, `4648` | `timestamp`, `host`, `user`, `ip`, `cmdline`, `action`, `status` | Lateral movement or remote access after successful authentication. |
| CDB table `events` | `dns` / `-` | `timestamp`, `host`, `domain`, `cmdline` | Limited relevance to primary authentication hunt; useful only for enrichment if a source or target domain appears. |

No Splunk index or sourcetype mapping is provided in the local data document. Treat CDB table `events` as the source and map fields accordingly if imported into Splunk. SPL below is an equivalent detection draft only; the deterministic executor should use the literal predicates and pivots described in each step. If `timestamp` is imported as a string, convert it to Splunk `_time` before binning.

## Hunt Procedure

1. **Select authentication telemetry.**
   - Predicate: `native_type EQUALS authentication`
   - Optional narrowing: `event_id EQUALS 4624`
   - Pivot: by `host`, `user`, `ip`, `timestamp`
   - SPL draft:
     ```spl
     native_type=authentication event_id=4624
     | stats count min(timestamp) as first max(timestamp) as last by host user ip
     | sort - count
     ```
   - Interpretation: Establishes overall authentication volume and identifies hosts/users/IPs with high activity. This is the baseline before filtering for failures. **Note:** in this dataset `event_id=4624` is authentication telemetry, not a Windows failure indicator; do not treat `4624` alone as evidence of failed logon.

2. **Validate the failure/outcome signal against `action` and `status`.**
   - Predicate: `native_type EQUALS authentication`
   - Pivot: by `action`, `status`
   - SPL draft:
     ```spl
     native_type=authentication
     | stats count by action
     | sort - count
     ```
     ```spl
     native_type=authentication
     | stats count by status
     | sort - count
     ```
   - Interpretation: Confirm that `cmdline CONTAINS "Logon Failed"` aligns with the expected failure outcome in `action` and/or `status`. If failures are encoded differently in `action` or `status`, adjust the hunt filters accordingly. This prevents missing failures that may not use the `Logon Failed` text or that use a different outcome value.

3. **Identify failed authentication events.**
   - Predicate: `cmdline CONTAINS "Logon Failed"`
   - Combined with: `native_type EQUALS authentication`
   - Pivot: by `host`, `user`, `ip`, `timestamp`
   - SPL draft:
     ```spl
     native_type=authentication cmdline="*Logon Failed*"
     | stats count min(timestamp) as first max(timestamp) as last values(action) as actions values(status) as statuses by host user ip
     | sort - count
     ```
   - Interpretation: Rows with high counts are candidate brute-force targets. Inspect `action`, `status`, and `raw_ref` for outcome details.

4. **Detect authentication-failure bursts.**
   - Predicate: `cmdline CONTAINS "Logon Failed"`
   - Combined with: `native_type EQUALS authentication`
   - Pivot: by `host`, `user`, `ip`, and 5-minute / 1-hour time bins
   - SPL draft for 5-minute bursts:
     ```spl
     native_type=authentication cmdline="*Logon Failed*"
     | eval _time=strptime(timestamp,"%Y-%m-%dT%H:%M:%SZ")
     | bin _time span=5m
     | stats count by host user ip _time
     | where count > 10
     | sort - count
     ```
   - SPL draft for 1-hour bursts:
     ```spl
     native_type=authentication cmdline="*Logon Failed*"
     | eval _time=strptime(timestamp,"%Y-%m-%dT%H:%M:%SZ")
     | bin _time span=1h
     | stats count by host user ip _time
     | where count > 50
     | sort - count
     ```
   - If `timestamp` is already mapped to Splunk `_time`, use `| bin _time span=5m` or `| bin _time span=1h` without the `strptime` conversion.
   - Interpretation: Bursts above threshold indicate password guessing. Start with `>10` failures in 5 minutes or `>50` in 1 hour, then adjust based on normal authentication baseline. Repeated failures from one `ip` to one `user` suggests targeted brute force; failures from one `ip` to many `user`s suggests password spraying.

5. **Check for privileged account targeting.**
   - Predicate: `user EQUALS admin`
   - Combined with: `native_type EQUALS authentication` AND `cmdline CONTAINS "Logon Failed"`
   - Pivot: by `host`, `ip`, `timestamp`
   - SPL draft:
     ```spl
     native_type=authentication cmdline="*Logon Failed*" user=admin
     | stats count min(timestamp) as first max(timestamp) as last by host ip
     | sort - count
     ```
   - Also pivot `user` over all failed rows to discover other targeted accounts:
     ```spl
     native_type=authentication cmdline="*Logon Failed*"
     | stats count by user
     | sort - count
     ```
   - Interpretation: Failure bursts against `admin` are higher severity. Other high-count users may also be targeted accounts.

6. **Identify source IPs and targets.**
   - Predicate: `ip EXISTS`
   - Combined with: `native_type EQUALS authentication` AND `cmdline CONTAINS "Logon Failed"`
   - Pivot: by `ip` over `host`, `user`, `timestamp`
   - SPL draft:
     ```spl
     native_type=authentication cmdline="*Logon Failed*"
     | stats count dc(host) as hosts dc(user) as users min(timestamp) as first max(timestamp) as last by ip
     | sort - count
     ```
   - Interpretation: Source IPs with many failures and many targeted users are likely password-spray sources. Source IPs with failures against one host and one user are likely focused brute force.

7. **Inverse aggregation: users targeted by many source IPs.**
   - Predicate: `native_type EQUALS authentication` AND `cmdline CONTAINS "Logon Failed"`
   - Pivot: by `user` over `ip`, `host`, `timestamp`
   - SPL draft:
     ```spl
     native_type=authentication cmdline="*Logon Failed*"
     | stats count dc(ip) as source_ips dc(host) as hosts min(timestamp) as first max(timestamp) as last by user
     | sort - count
     ```
   - Interpretation: A user targeted from many distinct IPs may indicate distributed brute force or credential spraying against that account. Compare with Step 6 to distinguish single-source brute force from distributed attempts.

8. **Check for successful authentication after failures.**
   - Explicit predicates for the deterministic executor, for each burst candidate:
     - `native_type EQUALS authentication`
     - `host EQUALS <host>`
     - `user EQUALS <user>`
     - `ip EQUALS <ip>`
     - Then inspect rows where `cmdline CONTAINS "Logon Failed"` OR `cmdline CONTAINS "Logon Success"`
   - Pivot: by `timestamp`, `cmdline`, `action`, `status`, `raw_ref`
   - SPL draft:
     ```spl
     native_type=authentication host=<host> user=<user> ip=<ip>
     | where match(cmdline, "Logon Failed") OR match(cmdline, "Logon Success")
     | sort timestamp
     | table timestamp cmdline action status raw_ref
     ```
   - Interpretation: A `Logon Success` immediately after a failure burst indicates likely successful brute force. If no success appears, the attack may have failed, but continue checking for lockout, password spray success on another account, or delayed success.

9. **If success is found, inspect post-compromise process creation.**
   - Explicit predicates for the deterministic executor:
     - `native_type EQUALS process_creation`
     - `host EQUALS <host>`
     - Pivot on `timestamp` and retain events after `<first_success>`
   - SPL draft:
     ```spl
     native_type=process_creation host=<host>
     | eval _time=strptime(timestamp,"%Y-%m-%dT%H:%M:%SZ")
     | where _time >= strptime("<first_success>","%Y-%m-%dT%H:%M:%SZ")
     | table timestamp user pid ppid image cmdline
     | sort timestamp
     ```
   - Interpretation: Look for suspicious command lines, unusual parent/child process relationships, or binaries inconsistent with the server role. This step requires a confirmed successful authentication from Step 8.

10. **If success is found, inspect SMB activity for lateral movement.**
    - Explicit predicates for the deterministic executor:
      - `native_type EQUALS smb`
      - `host EQUALS <host>`
      - `user EQUALS <user>`
      - Pivot on `timestamp` and retain events after `<first_success>`
    - SPL draft:
      ```spl
      native_type=smb host=<host> user=<user>
      | eval _time=strptime(timestamp,"%Y-%m-%dT%H:%M:%SZ")
      | where _time >= strptime("<first_success>","%Y-%m-%dT%H:%M:%SZ")
      | table timestamp event_id user ip cmdline action status
      | sort timestamp
      ```
    - Interpretation: Event IDs `5140`, `5145`, and `4648` may indicate file share access, share enumeration, or explicit credential use. Unexpected SMB activity after a brute-force success increases severity.

11. **Correlate public-facing exposure using web telemetry.**
    - Explicit predicates for the deterministic executor:
      - `native_type EQUALS web_request`
      - Then for target host `<host>`, test: `host EQUALS <host>` OR `domain EQUALS <host>` OR `cmdline CONTAINS "site=<host>"`
    - Pivot: by `domain`, `host`, `cmdline`, `timestamp`
    - SPL draft:
      ```spl
      native_type=web_request (host=<host> OR domain=<host> OR cmdline="*site=<host>*")
      | stats count min(timestamp) as first max(timestamp) as last by domain host cmdline
      | sort - count
      ```
    - Interpretation: If the brute-force target host also appears in web request telemetry, the public-facing hypothesis is supported. **Important limitation:** the local authentication columns do not encode internet exposure. Confirming true public-facing status requires external asset inventory or exposure data.

12. **Triage and escalation.**
    - Escalate if any of the following are true:
      - Failure burst against `user EQUALS admin`.
      - Failure burst from a single `ip` across many users or hosts.
      - A user targeted from many distinct source IPs.
      - `Logon Success` follows a failure burst for the same `host`, `user`, and `ip`.
      - Post-success `process_creation` or `smb` activity is suspicious.
      - Web telemetry confirms the target host is internet-facing.
    - If only repeated failures occur with no success, classify as attempted brute force and continue monitoring the source IPs.
    - **Data limitations:** actor attribution is not supported by local telemetry; public-facing exposure cannot be proven from authentication fields alone; password policy, account lockout, and geolocation enrichment are not available in the provided columns.
