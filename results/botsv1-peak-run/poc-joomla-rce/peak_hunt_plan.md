# Hypothesis
Attacker scans and exploits Joomla search/mailto components on imreallynotbatman.com to achieve web compromise / Remote Code Execution, consistent with MITRE ATT&CK T1190 Exploit Public-Facing Application (BOTS v1 real attack).

# Recommended Time Frame
2016-08-01T00:00:00Z to 2016-08-28T23:59:58Z - full available coverage of CDB `events` web_request telemetry (39010 rows, 2016-08-01T00:01:01Z to 2016-08-28T23:54:58Z). No down-selection. Hunt scan-to-exploit chaining requires full window to establish baseline and detect tight-time progression from same host/ip. If triage requires focus, prioritize 2016-08-10 to 2016-08-24 where process_creation event_id 1 and dns telemetry overlap, but do not exclude other dates.

# ABLE Table
| ABLE Element | Restatement |
|---|---|
| **A - Actor** | Unspecified external attacker. BOTS v1 real attack, no named group. Behavior-based hunt for opportunistic Joomla scanning and exploitation, not actor IOCs. |
| **B - Behavior** | T1190 Exploit Public-Facing Application: probing/scanning of Joomla URIs followed by exploitation of `search` and `mailto` components for web compromise / RCE. Expected observable chain: `web_request` -> `exploitation`. Hunt one piece at a time: find scan URIs first, then exploitation attempts from same host/ip in tight time window. |
| **L - Location** | Perimeter egress as seen from internal requesters to external site `imreallynotbatman.com`. In CDB terms: `host` values generating `web_request` telemetry where `domain` points to target, with `ip`, `port`, `timestamp` for egress pivot. No internal Joomla server logs available; server-side execution cannot be observed. |
| **E - Evidence** | Single relevant source: CDB SQLite table `events` filtered to `native_type EQUALS web_request`. Relevant fields: `domain` holds site, `cmdline` holds `site=<host> uri=<path>`, plus `timestamp`, `host`, `ip`, `port` for pivots. Deterministic predicates (case-insensitive, one per step): `domain EQUALS imreallynotbatman.com`, `cmdline CONTAINS /joomla/`, `cmdline CONTAINS search`, `cmdline CONTAINS mailto`, plus additional `cmdline CONTAINS` for exploit-string separation. Pivot on `host`, `ip`, `timestamp` to chain scan to exploit. `authentication` (4624), `process_creation` (4688, 1), `smb` (5140, 5145, 4648), `dns` usable only for post-exploit pivot by `host`, `user`, `ip`, time. Coverage gap: no HTTP method, headers, user-agent, response status/body, or server-side Joomla logs; scanning can be proven, RCE success cannot be confirmed from available data alone. |

# Data
| Table / Index Equivalent | Sourcetype / native_type (event_id) | Key Fields Used in Hunt | Relevance |
|---|---|---|---|
| `events` | `web_request` (event_id `-` / null, 39010 rows) | `timestamp`, `native_type`, `domain`, `cmdline`, `host`, `ip`, `port` | Primary evidence. `domain` isolates target site. `cmdline` contains `site=<host> uri=<path>` for Joomla path and component detection. `host`, `ip`, `timestamp` chain scan to exploit. |
| `events` | `authentication` (4624, 579580 rows) | `timestamp`, `host`, `user`, `ip`, `cmdline`, `action` | Post-exploit pivot only. `cmdline` contains `Logon Success user=.. ip=..`, `action` holds outcome. Detect anomalous logons from suspect web-requesting `host` in tight time window after exploit. |
| `events` | `process_creation` (4688, 3642895 rows; 1, 66 rows) | `timestamp`, `host`, `user`, `cmdline`, `image`, `pid`, `ppid` | Post-exploit pivot only. Detect suspicious child processes / command execution on suspect `host` after web exploit time. |
| `events` | `smb` (5140, 5145, 4648) | `timestamp`, `host`, `user`, `ip`, `action`, `file_path` | Post-exploit lateral movement pivot only. Not direct evidence of web exploitation. |
| `events` | `dns` (`-`, 35904 rows, 2016-08-24 only) | `timestamp`, `host`, `domain`, `cmdline`, `ip` | Supporting pivot: resolution of `imreallynotbatman.com` prior to web_request. Limited to 2016-08-24T10:25:02Z to 2016-08-24T16:34:35Z; absence outside that window is expected and not negative evidence. |

All matching is literal: `EQUALS`, `CONTAINS`, `STARTS_WITH`, `ENDS_WITH` are case-insensitive. `MATCHES`, `EXISTS` as defined. Web `cmdline` format must be searched via `CONTAINS`, not parsed as URL fields.

# Hunt Procedure
> Execution note: Hunts run through deterministic executor, not by LLM. Each PoC step is one literal predicate (field, operator, value) over `timestamp, event_id, native_type, host, user, pid, ppid, cmdline, image, ip, port, domain, file_path, action, status, raw_ref` plus pivots on `host, user, ip` and time. SPL below is equivalent detection draft only. LLM never creates evidence.

**Step 1 - Establish web_request baseline and validate data availability**
- Data source: `events` where `native_type EQUALS web_request`
- Predicate 1a: `native_type EQUALS web_request`
- SPL draft equivalent (efficient indexed search):
  `| tstats count WHERE index=events AND native_type="web_request" BY domain | sort -count | head 20`
- Interpret: Confirms 39010-row population. Lists top domains to show rarity/volume of `imreallynotbatman.com` vs benign web traffic. If target domain is absent, stop - hypothesis not testable in this window. Record total count, distinct `host` count, time bounds via `| tstats min(_time) max(_time) WHERE index=events AND native_type="web_request"`.

**Step 2 - Isolate requests to compromised site**
- Data source: `events` `web_request`
- Predicate 2a: `domain EQUALS imreallynotbatman.com`
- Must be combined with Step 1 via pivot/intersection: `native_type=web_request AND domain=imreallynotbatman.com`
- SPL draft equivalent:
  `| tstats count WHERE index=events AND native_type="web_request" AND domain="imreallynotbatman.com" BY host, ip | sort -count`
  `index=events native_type="web_request" domain="imreallynotbatman.com" | stats count min(timestamp) max(timestamp) BY host, ip | sort -count`
- Interpret: This is the suspect population. Small count from 1-few `host`/`ip` values in tight burst suggests scanning/exploitation vs broad user browsing. Large distributed count suggests benign popularity - then proceed to Step 3 to filter for Joomla. Pivot values to carry forward: `host`, `ip`, `timestamp` list.

**Step 3 - Isolate Joomla component paths**
- Data source: filtered result from Step 2
- Predicate 3a: `cmdline CONTAINS /joomla/`
- SPL draft equivalent:
  `| tstats count WHERE index=events AND native_type="web_request" AND domain="imreallynotbatman.com" AND cmdline="/joomla/*" BY host, ip, cmdline | sort -count`
  Traditional equivalent: `index=events native_type="web_request" domain="imreallynotbatman.com" cmdline="*/joomla/*" | table timestamp, host, ip, port, domain, cmdline`
- Interpret: Positive hits are Joomla-specific access, per candidate predicate. `cmdline` will show `site=imreallynotbatman.com uri=/joomla/...`. If Step 2 has hits but Step 3 has zero, there is non-Joomla access to the site but no hypothesis-relevant Joomla probing in `cmdline`. Document as negative for T1190 Joomla vector. If hits present, extract full `uri` strings from `cmdline` for analyst review and carry `host`/`ip` forward.

**Step 4 - Separate search component probing**
- Data source: Step 2+3 intersection
- Predicate 4a: `cmdline CONTAINS search`
- SPL draft equivalent:
  `index=events native_type="web_request" domain="imreallynotbatman.com" cmdline="*search*" | stats count min(timestamp) max(timestamp) values(cmdline) BY host, ip`
- Interpret: Hits indicate `search` component access (e.g., `uri` containing `/joomla/` + `search`, `option=com_search`, `view=search`). Multiple distinct `search` URIs from same `host`/`ip` in seconds/minutes = scanning behavior. Single isolated hit may be benign. Compare timestamp spread: scan shows burst enumeration; exploit shows repeat with added strings.

**Step 5 - Separate mailto component probing**
- Data source: Step 2+3 intersection
- Predicate 5a: `cmdline CONTAINS mailto`
- SPL draft equivalent:
  `index=events native_type="web_request" domain="imreallynotbatman.com" cmdline="*mailto*" | stats count min(timestamp) max(timestamp) values(cmdline) BY host, ip`
- Interpret: Same logic as Step 4 for `mailto` component (e.g., `option=com_mailto`, `link=`, `mailto` form paths). BOTS v1 real attack is expected to touch both `search` and `mailto`. Finding both components from same `host`/`ip` in tight window strongly supports hypothesis of systematic Joomla scan. Finding only one still relevant - do not dismiss.

**Step 6 - Chain scan to exploitation by host/ip/time**
- Data source: `events` `web_request`
- Method: pivot, not new content predicate. Take `host` and `ip` values that hit Steps 3-5, examine all their `web_request` to same `domain` ordered by `timestamp` within +/- 60 minutes, then +/- 24 hours.
- SPL draft equivalent:
  `index=events native_type="web_request" domain="imreallynotbatman.com" host="<suspect_host_from_Step3>" | sort timestamp | table timestamp, host, ip, port, cmdline`
  `index=events native_type="web_request" ip="<suspect_ip>" | sort timestamp | table timestamp, host, ip, domain, cmdline`
- Interpret: Look for progression: 1) broad `/joomla/` + `search`/`mailto` enumeration, 2) repeated requests to same URI with longer `cmdline` / added query, encoding, or command-like substrings indicating exploit attempt. Available data has no response code or server log, so success cannot be determined here - only attempt and sequencing. Document time delta between first scan and subsequent exploit-like request. If only uniform repeated URIs with no variation, classify as scan only, not confirmed exploitation. This step answers behavior sequencing; where available data cannot answer exploit success must be stated explicitly.

**Step 7 - Characterize exploit-string candidates within suspect host timeline (one predicate at a time)**
- Data source: suspect `host`/`ip` timeline from Step 6
- Use single-predicate probes intersected by pivot; do not assume these strings exist - negative result is informative:
  - Predicate 7a: `cmdline CONTAINS option=`
  - Predicate 7b: `cmdline CONTAINS view=`
  - Predicate 7c: `cmdline CONTAINS com_`
- SPL draft equivalent per probe, e.g.:
  `index=events native_type="web_request" domain="imreallynotbatman.com" host="<suspect_host>" cmdline="*option=*" | table timestamp, ip, cmdline`
- Interpret: Helps separate generic `/joomla/` page fetches from component-parameterized requests typical of Joomla T1190 probing. Presence of `option=com_search`, `option=com_mailto` with additional parameters, long query strings, or encoded characters increases suspicion of exploit attempt vs simple GET. Absence does not clear host if Steps 3-5 already show targeted Joomla component URIs. Do not invent exploit payload syntax beyond what `cmdline` literally contains; report verbatim `cmdline` values.

**Step 8 - Post-exploit pivot to authentication, process, smb, dns by host/user/ip/time**
- Data sources: `events` `authentication`, `process_creation`, `smb`, `dns`
- Predicates (one per PoC step, then intersect by pivot):
  - Predicate 8a: `native_type EQUALS authentication`
  - Predicate 8b: `native_type EQUALS process_creation`
  - Predicate 8c: `native_type EQUALS smb`
  - Predicate 8d: `native_type EQUALS dns`
  Combined via pivot: `host EQUALS <suspect_host>` and time window after web exploit timestamp.
- SPL draft equivalents:
  `index=events native_type="authentication" host="<suspect_host>" | sort timestamp | table timestamp, user, ip, action, cmdline`
  `index=events native_type="process_creation" host="<suspect_host>" | sort timestamp | table timestamp, user, image, cmdline, pid, ppid`
  `index=events native_type="smb" host="<suspect_host>" | sort timestamp | table timestamp, user, ip, action, file_path`
  `index=events domain="imreallynotbatman.com" native_type="dns" | table timestamp, host, domain, cmdline, ip`
- Interpret: These sources do not directly evidence web exploitation. Use only to assess follow-on activity: new logons (`action` = success/failure, `cmdline` contains `Logon Success user=.. ip=..`), unusual processes, SMB access shortly after web exploit from same `host` suggests potential compromise requiring incident review. No correlation = web-only activity with no visible internal follow-on in CDB. DNS hits only possible on 2016-08-24; lack of DNS hits outside that date is a collection gap, not exoneration. Where available data cannot answer server-side RCE, state so and recommend server-side Joomla access/error logs, WAF logs, and filesystem timeline review out-of-band.

**Step 9 - Rule out benign and adjudicate**
- Compare suspect `host`/`ip` request rate and URI diversity against baseline from Step 1 and against other `host` values accessing same `domain` without `/joomla/`/`search`/`mailto`.
- Benign indicators: distributed hosts, single `/joomla/` fetch, normal browsing URIs, no burst, no component parameters.
- Malicious-leaning indicators: single/few internal `host`(s) generating most/all `domain EQUALS imreallynotbatman.com` + `cmdline CONTAINS /joomla/` hits, both `search` and `mailto` touched, burst enumeration then parameterized repeats in tight window, followed by anomalous auth/process activity.
- Decision: Report as (a) Confirmed scanning/exploitation attempt if Steps 2-6 show Joomla component scan + sequenced exploit-like requests from same host/ip, (b) Scan only if enumeration without progression, (c) No evidence if Step 2 or 3 empty. Never claim confirmed RCE/web compromise success from CDB `web_request` alone - explicitly document as unanswerable without server-side response, Joomla execution logs, or payload output.
