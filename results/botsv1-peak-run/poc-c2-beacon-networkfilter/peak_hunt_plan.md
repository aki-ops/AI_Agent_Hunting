# Hypothesis
C2 beacon to `ad.networkfilter.co` (BOTS v1 known IOC). Outbound HTTP request to `ad.networkfilter.co`, the ad-fraud beacon seen in BOTS v1. Expected observable chain: `web_request`, `process_creation`. Candidate behavior mapping: MITRE ATT&CK T1071.001 - Application Layer Protocol: Web.

# Recommended Time Frame
Full available dataset: `2016-08-01T00:00:00Z` through `2016-08-28T23:59:00Z` (28 days). This supports baseline and time-series analysis for beaconing, not just single-request matching. If a narrower focus is needed, prioritize `2016-08-24T10:25:02Z` through `2016-08-24T16:34:35Z` for optional DNS pivots, but `web_request` and `process_creation` cover the full range.

# ABLE Table
| ABLE Element | Details |
|---|---|
| Actor | Ad-fraud/C2 operator associated with the BOTS v1 known IOC `ad.networkfilter.co`. No named APT or individual actor is specified. |
| Behavior | Outbound HTTP command-and-control beaconing to `ad.networkfilter.co`. Expected behavior includes a web request to the known C2 host and potentially a GET request to the `/banner/` path. Expected observable chain: `web_request`, `process_creation`. |
| Location | Network perimeter/egress web traffic and internal endpoints that generate outbound HTTP requests. Local telemetry tables: `web_request` and `process_creation`. Optional DNS pivot in `dns`. |
| Evidence | Table `web_request`: `domain EQUALS ad.networkfilter.co`; `cmdline CONTAINS ad.networkfilter.co`; `cmdline CONTAINS /banner/`. Table `process_creation`: `cmdline CONTAINS ad.networkfilter.co`; `cmdline CONTAINS /banner/`. Pivot on `host`, `user`, `ip`, and `timestamp`. Optional: `dns.domain EQUALS ad.networkfilter.co`. |

# Data
| Telemetry Table / native_type | Key Fields | Relevance |
|---|---|---|
| `web_request` | `timestamp`, `host`, `user`, `ip`, `port`, `domain`, `cmdline`, `action`, `status`, `raw_ref` | Primary evidence. `domain` stores the site; `cmdline` stores text such as `site=<host> uri=<path>`. Use to find `ad.networkfilter.co` and `/banner/` requests. |
| `process_creation` (`event_id` 4688 and 1) | `timestamp`, `host`, `user`, `pid`, `ppid`, `cmdline`, `image`, `file_path`, `raw_ref` | Secondary evidence in expected chain. May show a script, browser, or utility launching/containing the beacon destination or path. |
| `dns` | `timestamp`, `host`, `user`, `ip`, `domain`, `cmdline`, `raw_ref` | Optional pivot for DNS lookup of `ad.networkfilter.co`. Coverage is limited to `2016-08-24T10:25:02Z` through `2016-08-24T16:34:35Z`. |
| `authentication` (`event_id` 4624) | `timestamp`, `host`, `user`, `ip`, `action`, `cmdline`, `raw_ref` | Context only. Helps scope users and hosts around IOC hits; not a primary detection. |
| `smb` (`event_id` 5140, 5145, 4648) | `timestamp`, `host`, `user`, `ip`, `cmdline`, `file_path`, `action`, `raw_ref` | Optional impact/lateral-movement context if a beaconing host is compromised; not part of the expected observable chain. |

Note: local execution is against the CDB SQLite table `events`; `native_type` acts as the table/sourcetype selector. Field matching is literal and case-insensitive for `EQUALS`, `CONTAINS`, `STARTS_WITH`, and `ENDS_WITH`. All SPL below is illustrative only and assumes a Splunk mirror where `native_type` is mapped to `sourcetype` and local `timestamp` is mapped to `_time` for `earliest`/`latest`. The deterministic executor runs predicates, not SPL.

# Hunt Procedure

1. Table: `web_request`; Predicate: `domain EQUALS ad.networkfilter.co`
   - Purpose: primary high-signal detection for the BOTS v1 IOC.
   - Record all hits by `host`, `user`, `ip`, `port`, `timestamp`, and `cmdline`.
   - Illustrative SPL only: `sourcetype=web_request domain="ad.networkfilter.co"`

2. Table: `web_request`; Predicate: `cmdline CONTAINS ad.networkfilter.co`
   - Purpose: catch cases where `domain` is not populated but `cmdline` contains `site=ad.networkfilter.co uri=...`.
   - Merge and de-duplicate with step 1 by `host`, `user`, `ip`, `timestamp`, and `cmdline`.
   - Illustrative SPL only: `sourcetype=web_request cmdline="*ad.networkfilter.co*"`

3. Table: `web_request`; Predicate: `cmdline CONTAINS /banner/`
   - Purpose: detect the ad-fraud beacon URI pattern even when the domain is not present in the indexed fields.
   - This predicate is broad and will produce benign hits. Do not treat `/banner/` alone as high priority unless it correlates with `ad.networkfilter.co`, repeated behavior from the same `host`/`user`/`ip`, or close timing to IOC hits from steps 1–2.
   - Illustrative SPL only: `sourcetype=web_request cmdline="*/banner/*"`

4. Table: `process_creation`; Predicate: `cmdline CONTAINS ad.networkfilter.co`
   - Purpose: identify scripts, browsers, or utilities that may have launched the beacon.
   - Illustrative SPL only: `sourcetype=process_creation cmdline="*ad.networkfilter.co*"`

5. Table: `process_creation`; Predicate: `cmdline CONTAINS /banner/`
   - Purpose: detect process command lines referencing the `/banner/` path.
   - Browser-driven beaconing may not appear here; absence does not rule out `web_request` evidence.
   - Illustrative SPL only: `sourcetype=process_creation cmdline="*/banner/*"`

6. Post-processing/SPL-only: Correlate and de-duplicate `web_request` hits from steps 1–3.
   - The deterministic executor cannot perform multi-predicate correlation or grouping. This step requires post-processing or SPL.
   - Group by `host`, `user`, `ip`, `domain`, `cmdline`, and `timestamp`; count requests.
   - For `/banner/` alone, require correlation with `ad.networkfilter.co`, repeated host behavior, or close timing to IOC hits before escalating.
   - Illustrative SPL only: `sourcetype=web_request (domain="ad.networkfilter.co" OR cmdline="*ad.networkfilter.co*" OR cmdline="*/banner/*") | stats count min(timestamp) as first max(timestamp) as last values(cmdline) as cmds by host user ip domain | sort -count`
   - Limitation: this cannot prove periodicity by itself.

7. Post-processing/SPL-only: Time-series/periodicity analysis.
   - The deterministic executor cannot extract URI paths or bin time.
   - Extract URI path from `cmdline` where possible; group hits by `host`, `user`, `ip`, `domain`, and extracted path; bin time at `1m`, `5m`, `10m`, or `1h`.
   - Fixed intervals, repeated counts, or clustered requests at regular periods indicate beaconing. Irregular one-off traffic is lower confidence.
   - Illustrative SPL only: `sourcetype=web_request (domain="ad.networkfilter.co" OR cmdline="*ad.networkfilter.co*" OR cmdline="*/banner/*") | bin _time span=5m | stats count by host user ip domain cmdline _time | sort _time`
   - Limitation: `web_request` cannot prove “beaconing” periodicity by itself without this time-series analysis. If local `timestamp` is not mapped to `_time`, convert it before using `bin _time`.

8. Post-processing/SPL-only: Pivot from `web_request` IOC hits to nearby `process_creation` activity.
   - Use the `host` and timestamp from step 1–3 findings. Bound the search to a short window, e.g. ±10 minutes.
   - Put filters in the base search and avoid a post-pipe `search`.
   - Illustrative SPL only: `sourcetype=process_creation host=<host> earliest=<web_hit-10m> latest=<web_hit+10m> (cmdline="*ad.networkfilter.co*" OR cmdline="*/banner/*" OR image="*powershell.exe" OR image="*cmd.exe" OR image="*wscript.exe" OR image="*cscript.exe" OR image="*curl.exe" OR image="*wget.exe" OR image="*bitsadmin.exe" OR image="*rundll32.exe" OR image="*regsvr32.exe" OR image="*mshta.exe")`
   - If decomposed into executor predicates, use separate table-scoped steps with more precise `ENDS_WITH` matching, for example:
     - Table: `process_creation`; Predicate: `image ENDS_WITH powershell.exe`
     - Table: `process_creation`; Predicate: `image ENDS_WITH cmd.exe`
     - Table: `process_creation`; Predicate: `image ENDS_WITH wscript.exe`
     - Table: `process_creation`; Predicate: `image ENDS_WITH cscript.exe`
     - Table: `process_creation`; Predicate: `image ENDS_WITH curl.exe`
     - Table: `process_creation`; Predicate: `image ENDS_WITH wget.exe`
     - Table: `process_creation`; Predicate: `image ENDS_WITH bitsadmin.exe`
     - Table: `process_creation`; Predicate: `image ENDS_WITH rundll32.exe`
     - Table: `process_creation`; Predicate: `image ENDS_WITH regsvr32.exe`
     - Table: `process_creation`; Predicate: `image ENDS_WITH mshta.exe`
   - Interpretation: process context strengthens attribution and helps distinguish user browsing from scripted beaconing.

9. Optional: Table: `dns`; Predicate: `domain EQUALS ad.networkfilter.co`
   - Purpose: confirm DNS resolution of the C2 domain if available.
   - Illustrative SPL only: `sourcetype=dns domain="ad.networkfilter.co"`
   - Limitation: DNS coverage is limited to `2016-08-24T10:25:02Z` through `2016-08-24T16:34:35Z`. Absence outside that window is not meaningful.

10. Optional: Table: `dns`; Predicate: `cmdline CONTAINS ad.networkfilter.co`
    - Purpose: catch cases where the DNS query name is stored in `cmdline` rather than `domain`.
    - Illustrative SPL only: `sourcetype=dns cmdline="*ad.networkfilter.co*"`

11. Post-processing/context pivot: Correlate with `authentication` and `smb` for user/host context.
    - After a suspicious `host` is identified, use single table-scoped predicates for that host if executor steps are needed:
      - Table: `authentication`; Predicate: `host EQUALS <confirmed_host>`
      - Table: `smb`; Predicate: `host EQUALS <confirmed_host>`
    - Purpose: identify which users were active, whether the host had logon activity, and whether SMB activity suggests lateral movement. This is context only, not primary detection.

12. Scope and report findings.
    - For each confirmed or suspected host, report: `host`, `user`, `ip`, `port`, `domain`, `cmdline`/URI path, first seen, last seen, count, time interval pattern, and any related `process_creation` events.
    - Classification guidance:
      - Confirmed C2 beacon: recurring `web_request` to `ad.networkfilter.co` and/or `/banner/` with a regular interval and corroborating process or DNS evidence.
      - Suspicious: one or few IOC hits without clear periodicity.
      - No finding: no matching `web_request` or `process_creation` IOC evidence.
    - If no hits are found, state that the available data cannot prove absence of C2 if traffic was encrypted, non-HTTP, DNS-only, outside the collected window, or mediated entirely through a browser process not visible in `process_creation`.

## Data Limitations / Unanswerable Questions
- The available `web_request` data cannot show full HTTP headers, request method beyond text in `cmdline`, response codes, or complete URI beyond what is stored in `cmdline`.
- The available data cannot prove periodic beaconing without time-series analysis across `host`, `ip`, and `timestamp`. This must be repeated when interpreting Step 7.
- `process_creation` may not capture browser-driven or purely script-driven beaconing; absence in `process_creation` does not rule out `web_request` evidence.
- The `dns` table exists but has very limited coverage; DNS findings outside `2016-08-24T10:25:02Z` through `2016-08-24T16:34:35Z` cannot be assessed.
- No named threat actor attribution is possible from this IOC alone; `ad.networkfilter.co` is a known BOTS v1 IOC and should be treated as high-signal but verified with host, user, and timing context.
