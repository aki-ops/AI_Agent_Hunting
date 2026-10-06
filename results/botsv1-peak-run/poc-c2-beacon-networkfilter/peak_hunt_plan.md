## Hypothesis
C2 beacon to ad.networkfilter.co (BOTS v1 known IOC). Outbound HTTP request to ad.networkfilter.co, the ad-fraud beacon seen in BOTS v1, via Application Layer Protocol: Web (MITRE ATT&CK T1071.001), specifically GET to /banner/ pattern.

## Recommended Time Frame
2016-08-01T00:01:01Z to 2016-08-28T23:54:58Z — full `web_request` coverage in CDB (39,010 rows). No narrower window recommended; beaconing requires full-window review for cadence.
Human-readable bounds for all SPL drafts: earliest="08/01/2016:00:00:00" latest="08/28/2016:23:59:00" (ISO 2016-08-01 to 2016-08-28). Exception: DNS corroboration only valid earliest="08/24/2016:10:25:02" latest="08/24/2016:16:34:35" (ISO 2016-08-24T10:25:02Z to 2016-08-24T16:34:35Z).

## ABLE Table
| Element | Restatement |
|---|---|
| **Actor** | Unspecified ad-fraud / opportunistic operator behind ad.networkfilter.co (BOTS v1 known IOC); no named APT |
| **Behavior** | Outbound C2 beacon via Web (T1071.001): HTTP request to `ad.networkfilter.co`, specifically `/banner/` ad-fraud beacon pattern |
| **Location** | Internal endpoints initiating outbound web traffic to internet / egress; in CDB terms `host` values with `native_type` EQUALS `web_request` from 2016-08-01 to 2016-08-28 |
| **Evidence** | CDB SQLite table `events`: `native_type` EQUALS `web_request` where `domain` stores site and `cmdline` stores `site=<host> uri=<path>`. Hunt predicates: `domain` CONTAINS `ad.networkfilter.co`, `cmdline` CONTAINS `ad.networkfilter.co`, `cmdline` CONTAINS `/banner/`. Pivot on `host`, `ip`, `timestamp` for cadence and `host`, `pid`, `ppid`, `image` with `native_type` EQUALS `process_creation` for sourcing process chain `web_request, process_creation`. SPL shown only as equivalent detection draft; execution is via single literal predicates (EQUALS/CONTAINS/STARTS_WITH/ENDS_WITH/MATCHES/EXISTS, case-insensitive) |

## Data
| Table / Index | native_type / event_id (sourcetype equivalent) | Key Fields | Relevance to Hunt |
|---|---|---|---|
| `events` | `web_request` / `-` (39,010 rows, 2016-08-01T00:01:01Z to 2016-08-28T23:54:58Z) | `timestamp`, `host`, `user`, `ip`, `port`, `domain`, `cmdline` | Primary evidence: `domain` holds site, `cmdline` holds `site=<host> uri=<path>`. Directly tests `ad.networkfilter.co` and `/banner/` predicates. `host`, `ip`, `timestamp` enable beacon cadence analysis |
| `events` | `process_creation` / `4688` (3,642,895 rows, 2016-08-01 to 2016-08-28) + `1` (66 rows, 2016-08-10 to 2016-08-24) | `timestamp`, `host`, `user`, `pid`, `ppid`, `image`, `cmdline`, `file_path` | Expected observable chain second step: identify sourcing process on beaconing `host` near beacon `timestamp` via `host`, `pid`, `ppid`, `image` pivot |
| `events` | `dns` / `-` (35,904 rows, 2016-08-24T10:25:02Z to 2016-08-24T16:34:35Z only) | `timestamp`, `host`, `domain`, `cmdline`, `ip` | Corroborating resolution of `ad.networkfilter.co` if beacon falls in 2016-08-24 window; **cannot answer** resolution outside that window |
| `events` | `authentication` / `4624`, `smb` / `5140, 5145, 4648` | `host`, `user`, `ip`, `timestamp`, `action`, `cmdline` | Context only for compromised user/host triage; not direct beacon evidence |

Available data limitations that must be stated to hunter:
- No dedicated HTTP method, header, body, bytes, user-agent fields. `web_request` retains only `domain` and `site=<host> uri=<path>` in `cmdline`. HTTP GET, headers, volume **cannot be confirmed** from available data.
- Encrypted sessions, proxy/firewall logs, TLS SNI not available. C2 vs ad-fraud distinction **cannot be confirmed** without those plus process join.
- Named actor attribution **cannot be answered** from available data.
- `dns` coverage is limited to 2016-08-24T10:25:02Z to 2016-08-24T16:34:35Z and **cannot answer** pre-infection resolution outside that window.

## Hunt Procedure
**Executor rule:** Each numbered step executes as ONE literal predicate (field, operator, value) over `timestamp, event_id, native_type, host, user, pid, ppid, cmdline, image, ip, port, domain, file_path, action, status, raw_ref` plus pivots on `host, user, ip, time`. SPL is equivalent detection draft only; LLM never creates evidence. Field matching is literal (EQUALS / CONTAINS / STARTS_WITH / ENDS_WITH / MATCHES / EXISTS); EQUALS, CONTAINS, STARTS_WITH and ENDS_WITH are case-insensitive.

**1. Scope to web telemetry**
- Predicate: `native_type` / EQUALS / `web_request`
- SPL draft (equivalent only): `index=* sourcetype=web_request earliest="08/01/2016:00:00:00" latest="08/28/2016:23:59:00" | table _time host user ip domain cmdline | sort _time`
- Interpretation: Establishes baseline of 39,010 events 2016-08-01 to 2016-08-28. If zero results, stop — no web data to test. Record distinct `host` count for scope.

**2. Hunt for known C2 host in site field**
- Predicate: `domain` / CONTAINS / `ad.networkfilter.co`
- SPL draft: `index=* sourcetype=web_request earliest="08/01/2016:00:00:00" latest="08/28/2016:23:59:00" domain="*ad.networkfilter.co*" | table _time host user ip port domain cmdline`
- Interpretation: Direct positive for hypothesis. Any hit is high-fidelity BOTS v1 IOC match. Preserve `host`, `ip`, `timestamp`, `cmdline` for next steps. If no hits, do NOT stop here — proceed to Step 3 before declaring negative due to possible `domain` vs `cmdline` encoding variance.

**3. Hunt for known C2 host in request text**
- Predicate: `cmdline` / CONTAINS / `ad.networkfilter.co`
- SPL draft: `index=* sourcetype=web_request earliest="08/01/2016:00:00:00" latest="08/28/2016:23:59:00" cmdline="*ad.networkfilter.co*" | table _time host user ip domain cmdline`
- Interpretation: Corroborates Step 2 and catches cases where `domain` is empty/truncated but `site=<host>` in `cmdline` retains IOC. Per local doc, web rows store `site=<host> uri=<path>` in `cmdline`. If Steps 2 AND 3 both zero, hypothesis has no IOC evidence in full window — document as negative and skip to Step 7 for near-miss review.

**4. Hunt for ad-fraud beacon path pattern**
- Predicate: `cmdline` / CONTAINS / `/banner/`
- SPL draft: `index=* sourcetype=web_request earliest="08/01/2016:00:00:00" latest="08/28/2016:23:59:00" cmdline="*/banner/*" | table _time host user ip domain cmdline`
- Interpretation: Tests second analyst predicate (GET to /banner/). Intersection of Step 2/3 hits with this step = strongest BOTS v1 ad-fraud beacon pattern (`site=ad.networkfilter.co uri=/banner/...`). `cmdline` CONTAINS `/banner/` alone without IOC must NOT escalate — many ad networks use /banner/, so require IOC match to escalate. Available data **cannot confirm** HTTP method was GET; treat as path-pattern match only.

**5a. Pivot on beaconing endpoint to assess cadence**
- Pivot: `host` / EQUALS / `<value from Steps 2-4>`
- SPL draft component: `index=* sourcetype=web_request earliest="08/01/2016:00:00:00" latest="08/28/2016:23:59:00" domain="*ad.networkfilter.co*" | stats count earliest(_time) AS earliest latest(_time) AS latest values(cmdline) AS uris dc(cmdline) AS uri_count by host | eval duration=latest-earliest`
- Interpretation: Single isolated hit = possible one-off ad load or single beacon. Multiple hits from same `host` at regular intervals over 2016-08-01 to 2016-08-28, same `/banner/` URI = beaconing behavior supporting C2 hypothesis. Irregular diverse URIs/domains from same host = likely user browsing/adware. Document inter-beacon deltas manually from `timestamp` ordering.

**5b. Pivot on egress destination IP to assess cadence**
- Pivot: `ip` / EQUALS / `<destination ip value from Steps 2-4>`
- SPL draft component: `index=* sourcetype=web_request earliest="08/01/2016:00:00:00" latest="08/28/2016:23:59:00" domain="*ad.networkfilter.co*" | stats count earliest(_time) AS earliest latest(_time) AS latest values(cmdline) AS uris by host, ip | eval duration=latest-earliest`
- Interpretation: Same `ip` across beacons strengthens infrastructure persistence. `values(cmdline) AS uris` unbounded over 39k rows — use `uri_count` for triage to avoid overload. Diverse `host` values to same `ip` = wider infection; single `host` = isolated.

**6a. Scope to process creation for sourcing process**
- Predicate: `native_type` / EQUALS / `process_creation`
- SPL draft base: `index=* sourcetype=process_creation earliest="08/01/2016:00:00:00" latest="08/28/2016:23:59:00" | table _time host user pid ppid image cmdline file_path`
- Interpretation: Establishes process dataset (3,642,895 x 4688 + 66 x 1) for host-temporal correlation. No disposition on this step alone.

**6b. Pivot to beaconing host**
- Pivot: `host` / EQUALS / `<beaconing host from Step 5a>`
- Interpretation: Restricts process_creation to endpoint that beaconed. Look for suspicious parent-child: browser (iexplore.exe, chrome.exe, firefox.exe), script host (powershell.exe, wscript.exe, cscript.exe), or unknown binary in temp/appdata.

**6c. Pivot to beacon time window**
- Pivot: `time` / ±300 seconds around / `<beacon timestamp from Steps 2-4>`
- SPL draft for 6a+6b+6c combined (equivalent only, hunter must substitute absolute times): `index=* sourcetype=process_creation host="<beacon_host>" earliest="<beacon_time-300>" latest="<beacon_time+300>" | table _time host user pid ppid image cmdline file_path`
- Interpretation: If `image` is standard browser with interactive `user`, favor adware/browsing. If `image` is script/system process, no user interaction, or high `ppid` chaining, escalate. **Limitation:** CDB requires join on `host, pid, ppid, image, timestamp`; `web_request` has no `pid` link, so attribution is temporal + host correlation only, not definitive process-to-request linkage — state this explicitly in findings. Expected chain is `web_request, process_creation`.

**7. Near-miss and typo-squat review**
- Predicate: `domain` / CONTAINS / `networkfilter`
- SPL draft: `index=* sourcetype=web_request earliest="08/01/2016:00:00:00" latest="08/28/2016:23:59:00" domain="*networkfilter*" | stats count by domain, cmdline`
- Then if needed as separate atomic follow-up — Predicate: `cmdline` / CONTAINS / `networkfilter`
- Interpretation: Catches evasion variants (subdomains, http vs https encoding). If only `ad.networkfilter.co` exact hits exist, no evasion. If similar domains appear, treat as new leads. If Steps 2-4 were negative, this step confirms true negative vs encoding miss.

**8a. Scope to DNS telemetry (conditional)**
- Predicate: `native_type` / EQUALS / `dns`
- SPL draft base: `index=* sourcetype=dns earliest="08/24/2016:10:25:02" latest="08/24/2016:16:34:35" | table _time host domain cmdline ip`
- Interpretation: Establishes limited DNS window (2016-08-24T10:25:02Z to 2016-08-24T16:34:35Z, 35,904 rows). No disposition alone.

**8b. Hunt for IOC resolution within DNS scope**
- Predicate: `domain` / CONTAINS / `ad.networkfilter.co` [applied within dns scope from 8a; only meaningful for `timestamp` in 2016-08-24T10:25:02Z to 2016-08-24T16:34:35Z]
- SPL draft: `index=* sourcetype=dns earliest="08/24/2016:10:25:02" latest="08/24/2016:16:34:35" domain="*ad.networkfilter.co*" | table _time host domain cmdline ip`
- Interpretation: Hit confirms host attempted resolution. No hit outside that window means nothing — available `dns` data **cannot answer** pre-infection resolution. Do not declare negative based on missing DNS.

**9. Disposition criteria**
- Positive (likely C2/ad-fraud beacon): Steps 2 or 3 positive AND Step 4 positive on same `host` + repeat cadence in Steps 5a/5b + suspicious/non-browser `process_creation` in Steps 6a-6c.
- Suspect (requires triage): IOC hit but single event or browser-sourced — possible adware vs beacon; recommend proxy/firewall review (not in CDB), full host timeline, and `authentication` (`native_type` EQUALS `authentication`) review for that `host, user`.
- Negative: No hits in Steps 2, 3, 4, 7 across full 2016-08-01 to 2016-08-28 `web_request` window.
- Explicitly document what CDB cannot answer: HTTP method/headers/body/volume, encrypted C2 content, named actor identity, and DNS before/after 2016-08-24 window.
