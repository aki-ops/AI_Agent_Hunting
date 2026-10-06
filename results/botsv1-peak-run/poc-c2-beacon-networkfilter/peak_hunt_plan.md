# Hypothesis
## Hypothesis
C2 beacon to ad.networkfilter.co (BOTS v1 known IOC). Outbound HTTP request to ad.networkfilter.co, the ad-fraud beacon seen in BOTS v1 via Application Layer Protocol: Web, specifically GET to `/banner/` path.

# Recommended Time Frame
## Recommended Time Frame
2016-08-01T00:00:00Z to 2016-08-28T23:59:59Z inclusive - full coverage window of `native_type = web_request` (2016-08-01T00:01:01Z to 2016-08-28T23:54:58Z, 39,010 rows). No sampling; beaconing requires full-window review to assess periodicity and enumerate all affected hosts. DNS corroboration if attempted is limited to 2016-08-24T10:25:02Z to 2016-08-24T16:34:35Z.

# ABLE Table
## ABLE Table
| Element | Description |
|---|---|
| **A - Actor** | Unspecified ad-fraud operator associated with BOTS v1 known IOC; no specific APT named |
| **B - Behavior** | Command-and-control beaconing via T1071.001 Application Layer Protocol: Web - periodic outbound HTTP GET to ad.networkfilter.co with ad-fraud beacon pattern `GET /banner/`. Expected chain: `web_request` -> `process_creation` for host process attribution |
| **L - Location** | Internal endpoints with internet egress as represented in CDB SQLite table `events`. Scope is `native_type = web_request`. Pivots on `host`, `user`, `ip`, `timestamp` to locate affected endpoint(s) |
| **E - Evidence** | CDB `events`: `native_type` EQUALS `web_request`. Web requests store site in `domain` and `site=<host> uri=<path>` in `cmdline`. Predicates (case-insensitive literal): `domain` EQUALS `ad.networkfilter.co`, `domain` CONTAINS `ad.networkfilter.co`, `cmdline` CONTAINS `ad.networkfilter.co`, `cmdline` CONTAINS `site=ad.networkfilter.co`, `cmdline` CONTAINS `/banner/`. Attribution via `native_type` EQUALS `process_creation` pivoted on `host` + `timestamp` (+ `user`, `ip` where present) to recover `image`, `cmdline`, `pid`, `ppid`. Equivalent detection draft only: `native_type=web_request AND (domain=ad.networkfilter.co OR cmdline CONTAINS ad.networkfilter.co OR cmdline CONTAINS /banner/)` |

# Data
## Data
| Table / Index | native_type / event_id | Key Fields for Hunt | Relevance to Hunt |
|---|---|---|---|
| CDB `events` | `web_request` / - (39,010 rows) | `timestamp`, `host`, `user`, `ip`, `domain`, `cmdline` | Primary evidence. `domain` holds egress site; `cmdline` holds `site=<host> uri=<path>`. Direct IOC and `/banner/` beacon pattern match |
| CDB `events` | `process_creation` / 4688 (3,642,895 rows, 2016-08-01 to 2016-08-28) | `timestamp`, `host`, `user`, `pid`, `ppid`, `image`, `cmdline`, `file_path` | Attribution. Pivot on `host` + `timestamp` (+ `user`) from web_request hit to find originating process. No direct join key in web_request rows |
| CDB `events` | `process_creation` / 1 (66 rows, 2016-08-10 to 2016-08-24) | `timestamp`, `host`, `user`, `pid`, `ppid`, `image`, `cmdline` | Supplemental attribution, very sparse. Check only if 4688 pivot inconclusive |
| CDB `events` | `dns` / - (35,904 rows, 2016-08-24 only) | `timestamp`, `host`, `domain`, `cmdline`, `ip` | Limited corroboration only. Cannot answer full-window DNS for beaconing due to single-day coverage |
| CDB `events` | `authentication` / 4624 | `timestamp`, `host`, `user`, `cmdline`, `action`, `ip` | Context only for `user` seen in beacon. Not primary evidence |

Field matching is literal EQUALS / CONTAINS / STARTS_WITH / ENDS_WITH / MATCHES / EXISTS; EQUALS, CONTAINS, STARTS_WITH, ENDS_WITH are case-insensitive. All SPL below is equivalent detection draft only; executor runs one literal predicate per step plus pivots on `host`, `user`, `ip` and time.

# Hunt Procedure
## Hunt Procedure
**Data that cannot answer:** CDB provides only `domain` and `cmdline` (`site=<host> uri=<path>`) for web_request. It cannot answer payload content, HTTP method/headers/body beyond inferred GET to `/banner/`, response status/bytes, exfiltration volume, or full-window DNS resolution / beacon interval modeling with headers. Attribution requires time-proximate pivot, not direct process linkage.

**Step 1 - Scope to web egress telemetry**
- Predicate: `native_type` EQUALS `web_request`
- Equivalent SPL draft only: `index=cdb native_type=web_request | tstats count where index=cdb native_type=web_request by host domain cmdline | head 100`
- Interpretation: Confirms ~39k row working set. If 0 rows, stop - no egress data to test. Record distinct `host` count and time bounds for baseline.

**Step 2 - Direct IOC match on structured domain field**
- Predicate: `domain` EQUALS `ad.networkfilter.co`
- Equivalent SPL draft only: `index=cdb native_type=web_request domain="ad.networkfilter.co" | tstats count where index=cdb native_type=web_request domain="ad.networkfilter.co" by _time host user ip domain cmdline`
- Interpretation: Highest fidelity. Any hit = BOTS v1 IOC present. Preserve `timestamp`, `host`, `user`, `ip`, full `cmdline` (`site=` and `uri=`). If 0 hits, continue to broader variants before declaring negative - do not close.

**Step 3 - Broad IOC variant to catch subdomain / formatting variance**
- Predicate: `domain` CONTAINS `ad.networkfilter.co`
- Equivalent SPL draft only: `index=cdb native_type=web_request domain="*ad.networkfilter.co*" | tstats count where index=cdb native_type=web_request by host user ip domain cmdline`
- Interpretation: Catches `www.ad.networkfilter.co`, case variance, trailing dot. Compare to Step 2. If new domains appear, they are candidate evasion / related infrastructure. If still 0, continue.

**Step 4 - Unstructured IOC match in request text**
- Predicate: `cmdline` CONTAINS `ad.networkfilter.co`
- Equivalent SPL draft only: `index=cdb native_type=web_request cmdline="*ad.networkfilter.co*" | tstats count where index=cdb native_type=web_request by host domain cmdline`
- Interpretation: Catches cases where `domain` parsing missed but `site=` text retains IOC. Expected to match Step 2 hits. If `cmdline` hits > `domain` hits, inspect `domain` values for parser gaps / alternate sites.

**Step 5 - Confirm canonical site formatting**
- Predicate: `cmdline` CONTAINS `site=ad.networkfilter.co`
- Equivalent SPL draft only: `index=cdb native_type=web_request cmdline="*site=ad.networkfilter.co*" | table _time host user ip domain cmdline`
- Interpretation: Validates expected CDB encoding `site=<host> uri=<path>`. Strong true-positive marker. Extract `uri=` portion after this for Step 6.

**Step 6 - Beacon URI pattern**
- Predicate: `cmdline` CONTAINS `/banner/`
- Equivalent SPL draft only: `index=cdb native_type=web_request cmdline="*/banner/*" | tstats count where index=cdb native_type=web_request by host domain cmdline`
- Interpretation: Ad-fraud beacon pattern from research. Critical correlation: hits that satisfy BOTH Step 4/5 AND this step (`site=ad.networkfilter.co` + `/banner/`) = confirmed BOTS v1 beacon per hypothesis. `/banner/` alone on other domains = possible similar adware - note but do not conflate; pivot those hosts separately. Review full `cmdline` for query strings, IDs, repeated URIs.

**Step 7 - Enumerate scope via pivots**
- Pivot on `host` EQUALS `<host from Steps 2-6>`, then `user` and `ip` from same rows. No new predicate needed beyond pivot; if re-querying use `host` EQUALS `<value>`.
- Equivalent SPL draft only: `index=cdb native_type=web_request host="<compromised-host>" | tstats count where index=cdb native_type=web_request by _time user ip domain cmdline | sort _time`
- Interpretation: List all affected hosts, users, source IPs. Single host + single user + repeated identical URI at regular intervals = classic beacon. Multiple hosts = broader infection. Group by `timestamp` to assess periodicity / regularity. CDB has no byte counts so cannot prove exfiltration volume - state this as limitation.

**Step 8 - Attribute to endpoint process**
- Predicate: `native_type` EQUALS `process_creation`
- Then pivot: `host` EQUALS `<compromised-host>` with time window +/- 1-5 minutes around each beacon `timestamp`, plus `user` EQUALS `<beacon-user>` where available.
- Equivalent SPL draft only: `index=cdb native_type=process_creation host="<compromised-host>" earliest=<beacon_time-5m> latest=<beacon_time+5m> | table _time host user pid ppid image cmdline file_path`
- Interpretation: Look for browser (iexplore.exe, chrome.exe, firefox.exe), script host (powershell.exe, wscript.exe, cscript.exe), or unknown binary / temp path launching around beacon time. Record `image`, `cmdline`, `pid`, `ppid`, `file_path`. Repeat for event_id 4688 first (full coverage); check event_id 1 only if needed - 66 rows total. If no proximate process, record as gap: web_request rows carry no pid/ppid join key so attribution is temporal only, not definitive.

**Step 9 - Limited DNS corroboration attempt with explicit caveat**
- Predicate: `native_type` EQUALS `dns`
- Then predicate: `domain` CONTAINS `ad.networkfilter.co` OR `cmdline` CONTAINS `ad.networkfilter.co`, constrained to 2016-08-24.
- Equivalent SPL draft only: `index=cdb native_type=dns domain="*ad.networkfilter.co*" | table _time host domain cmdline`
- Interpretation: If hit on 2016-08-24, supports resolution prior to HTTP. If 0 hits, make no negative conclusion - available data cannot answer full-window DNS because dns coverage is 2016-08-24T10:25:02Z to 2016-08-24T16:34:35Z only versus web 2016-08-01 to 2016-08-28. Do not use absence as exoneration.

**Step 10 - Disposition**
- Positive: any `web_request` with `domain` EQUALS/CONTAINS `ad.networkfilter.co` especially with `cmdline` CONTAINS `/banner/` = hypothesis confirmed. Escalate with host, user, ip, first/last `timestamp`, full `site=`/`uri=` strings, inter-beacon intervals, and attributed process if found.
- Negative: only after Steps 2-6 all return 0 across full 2016-08-01 to 2016-08-28 web_request window. Report as no evidence of IOC in available egress telemetry, noting payload/headers/volume and full DNS cannot be answered with CDB fields.
