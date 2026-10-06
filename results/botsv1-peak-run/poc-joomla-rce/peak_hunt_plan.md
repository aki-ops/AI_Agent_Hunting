# Hypothesis
## Hypothesis
Joomla RCE web compromise (BOTS v1 real attack). An unspecified external opportunistic attacker scanned and then exploited Joomla search and mailto components on the public site imreallynotbatman.com, consistent with MITRE ATT&CK T1190 Exploit Public-Facing Application, observable as clustered `web_request` rows to that domain with Joomla URIs in `cmdline`.

# Recommended Time Frame
## Recommended Time Frame
2016-08-01T00:00:00Z to 2016-08-28T23:59:59Z — full coverage of available `web_request` telemetry (39,010 rows, 2016-08-01T00:01:01Z to 2016-08-28T23:54:58Z). No narrower attack window is provided in research; do not sub-sample. Use `timestamp` filtering only to contain volume and to order scan-burst vs focused exploit.

# ABLE Table
## ABLE Table
| Element | Restatement |
|---|---|
| **A - Actor** | Unspecified external opportunistic attacker. No named APT. Treat as generic internet scanner/exploiter targeting public Joomla. |
| **B - Behavior** | T1190 Exploit Public-Facing Application: 1) anomalous URI access / scanning of Joomla component paths, 2) exploitation / RCE-pattern requests via `search` and `mailto` components. |
| **L - Location** | Internet-facing web tier hosting imreallynotbatman.com. In local telemetry: CDB SQLite table `events` where `native_type` is `web_request`. Scope to `domain` = imreallynotbatman.com, pivot by `ip`, `host`, `timestamp`. No initial scope to internal SMB/auth/process. |
| **E - Evidence** | Only `events` `native_type`=`web_request`: site in `domain`, request detail as text `site=<host> uri=<path>` in `cmdline`, plus `ip`, `timestamp`, `host`, `raw_ref`. Deterministic predicates: `domain EQUALS imreallynotbatman.com`, `cmdline CONTAINS /joomla/`, refined as `cmdline CONTAINS site=imreallynotbatman.com`, `cmdline CONTAINS search`, `cmdline CONTAINS mailto`. Positive = clustered rows to that domain with Joomla URIs, scan burst from single `ip` followed by focused search/mailto URIs. **Limitation:** no method/status/body/user-agent fields; scanning vs successful RCE cannot be distinguished from this source alone. Server-side execution linkage requires validated `host` mapping and is out of scope for initial confirmation. |

# Data
## Data
| Table / Source | Native_Type / Filter | Key Fields Used | Relevance to Hunt | Volume / Coverage |
|---|---|---|---|---|
| CDB SQLite `events` | `native_type` = `web_request` | `timestamp`, `domain`, `cmdline`, `ip`, `host`, `raw_ref` | Primary evidence: `domain` holds site, `cmdline` holds `site=<host> uri=<path>`. All Joomla predicates applied here. `ip` for attacker clustering, `timestamp` for burst ordering. | 39,010 rows, 2016-08-01 to 2016-08-28 |
| CDB SQLite `events` | `native_type` = `process_creation` (event_id 4688, 1), `authentication` (4624), `smb`, `dns` | `host`, `ip`, `timestamp`, `user` | NOT used for initial web compromise confirmation. Only for post-web pivot if `host`/`ip`/`time` correlation to imreallynotbatman.com server is validated. | 4688: 3,642,895 rows; 4624: 579,580 rows; dns only 2016-08-24 |
| Unavailable in schema | HTTP method, status code, response size, POST body, user-agent, WAF logs, web server process logs | N/A | Cannot answer RCE success, payload decoding, or exploit outcome. Must state as gap. | No rows |

Field matching is literal and case-insensitive for EQUALS / CONTAINS / STARTS_WITH / ENDS_WITH. Web `cmdline` example: `site=imreallynotbatman.com uri=/joomla/...`.

# Hunt Procedure
## Hunt Procedure
All steps execute as single literal predicates (field/operator/value) on `events` plus pivots on `host`, `user`, `ip`, `time`. SPL shown is equivalent detection draft only — executor runs predicates, LLM creates no evidence.

**1. Isolate web telemetry to bound search**
- Predicate: `native_type EQUALS web_request`
- SPL draft: `| tstats count FROM events WHERE native_type="web_request" BY _time, host, ip, domain, cmdline`
- Interpretation: Establishes 39k-row baseline 2016-08-01 to 2016-08-28. If count is zero, stop — data missing. Otherwise proceed. Pivot baseline by `host` to see which logging host(s) record web data.

**2. Scope to compromised site**
- Predicate: `domain EQUALS imreallynotbatman.com`
- SPL draft: `| tstats count FROM events WHERE native_type="web_request" AND domain="imreallynotbatman.com" BY ip, cmdline, timestamp`
- Interpretation: Positive = non-zero cluster. This is candidate detection predicate 1. Record total count, distinct `ip` count, `timestamp` min/max. If zero, hypothesis has no support in this telemetry. Preserve `ip` list and `timestamp` range for next steps. Also cross-check text form:
- Alternate predicate for same scope: `cmdline CONTAINS site=imreallynotbatman.com`
- If `domain` and `cmdline` site disagree, prefer `domain EQUALS` for scoping and use `cmdline` form for validation; note discrepancy.

**3. Test Joomla component path**
- Predicate: `cmdline CONTAINS /joomla/`
- To be run intersected with Step 2 (executor: two sequential predicates: `domain EQUALS imreallynotbatman.com` then `cmdline CONTAINS /joomla/`).
- SPL draft: `| tstats count FROM events WHERE native_type="web_request" AND domain="imreallynotbatman.com" AND cmdline="*/joomla/*" BY ip, cmdline, timestamp | sort timestamp`
- Interpretation: This is candidate detection predicate 2. Positive = rows where `cmdline` contains e.g. `site=imreallynotbatman.com uri=/joomla/...`. Negative (Step 2 positive but this zero) means site traffic exists but no Joomla URI evidence — weakens hypothesis, consider case variation or alternate encoding, but do not invent new values. Capture full `cmdline` and `raw_ref` for manual URI review.

**4. Test search-component exploitation**
- Predicate: `cmdline CONTAINS search`
- Run intersected with Steps 2-3.
- SPL draft: `| tstats count FROM events WHERE native_type="web_request" AND domain="imreallynotbatman.com" AND cmdline="*/joomla/*" AND cmdline="*search*" BY ip, cmdline, timestamp`
- Interpretation: Positive = focused exploit-pattern URIs for Joomla search component. Review `cmdline` strings for repeated access, query strings, traversal or injection-like text. Note: available data has only URI text, no payload decoding or response — cannot confirm RCE, only access attempt. Record `ip`(s) and `timestamp`(s).

**5. Test mailto-component exploitation**
- Predicate: `cmdline CONTAINS mailto`
- Run intersected with Steps 2-3.
- SPL draft: `| tstats count FROM events WHERE native_type="web_request" AND domain="imreallynotbatman.com" AND cmdline="*/joomla/*" AND cmdline="*mailto*" BY ip, cmdline, timestamp`
- Interpretation: Positive = focused exploit-pattern URIs for mailto component. Same limitation as Step 4: access ≠ confirmed exploitation. If both Steps 4 and 5 positive from same `ip` in tight `timestamp` window, stronger support for scan-then-exploit chain (expected observable chain: web_request -> exploitation).

**6. Pivot by attacker IP to identify scan burst vs focused exploit**
- Pivot, not new predicate: group Steps 2-5 results by `ip`, then order by `timestamp`.
- Predicates to enumerate: `ip EXISTS` (to exclude null-ip rows), then per-candidate `ip EQUALS <candidate-ip>` for top 1-3 ips.
- SPL draft: `| tstats count, values(cmdline), earliest(timestamp), latest(timestamp) FROM events WHERE native_type="web_request" AND domain="imreallynotbatman.com" BY ip | sort -count`
- Interpretation: Opportunistic scanner pattern = one `ip` with high count in short window (many Joomla URIs), followed by fewer targeted `search`/`mailto` URIs. Distributed low-count across many `ip`s = background internet noise or crawler. Single `ip` doing both broad `/joomla/` and `search`+`mailto` = highest fidelity. Document top `ip`(s), counts, time deltas. Pivot also by `host` to confirm which web logging host observed it.

**7. Pivot by time to order the chain**
- Pivot: sort filtered rows by `timestamp` ascending, review `cmdline` sequence.
- No new value predicate; use `timestamp` range narrowing if needed.
- SPL draft: `| tstats values(cmdline) FROM events WHERE native_type="web_request" AND domain="imreallynotbatman.com" AND ip="<candidate-ip>" BY _time | sort _time`
- Interpretation: Expected: early burst of diverse `/joomla/` URIs (scan) -> later repeated `search`/`mailto` URIs (exploit attempt). Out-of-order or single isolated hit weakens RCE narrative; note as scan-only. Use `raw_ref` to preserve original reference for each row in sequence.

**8. Disposition and explicit gaps — do not overclaim**
- If Steps 2+3+ (4 or 5) positive with single-`ip` burst + focused sequence: report as **Hypothesis Supported (web access attempt)** — attacker IP(s), timestamps, example `cmdline` URIs, `host`, `raw_ref`.
- If Step 2 positive but Steps 3-5 zero: report as **No Joomla evidence** — site traffic only.
- If Step 2 zero: report as **No evidence in available web_request**.
- Explicitly state where data cannot answer: (a) exploitation vs scanning cannot be distinguished — no HTTP status/method/body/user-agent in schema, only `domain`+`cmdline` URI text; (b) RCE success cannot be confirmed without response or server-side execution; (c) pivot to `process_creation` (4688/1) or `authentication` (4624) requires validated `host` mapping for imreallynotbatman.com and correlated `host`/`ip`/`time` — out of scope for initial confirmation, recommend follow-on only if web pivot yields validated server `host`/`ip` and time window.
