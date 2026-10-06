# Hypothesis
## Hypothesis
Brute force login against public-facing server. Repeated failed authentication events targeting user accounts on a host. The encoded cmdline row carries 'Logon Failed' for failed attempts.

# Recommended Time Frame
## Recommended Time Frame
2016-08-01T00:00:00Z to 2016-08-28T23:59:00Z - full available coverage of `events` table for `native_type EQUALS authentication` (event_id 4624, 579,580 rows). No narrower window is pre-defined in hypothesis/research; hunt by scanning full 28 days then drilling into short burst windows (5-min, 15-min, 60-min) to identify `authentication_failure_burst` clusters. If data volume requires triage, prioritize 5-minute to 1-hour sliding windows with high failure counts.

# ABLE Table
## ABLE Table
| Element | Restatement |
|---|---|
| **A - Actor** | Unspecified external attacker. No named actor. Consistent with opportunistic external password-guessing per MITRE ATT&CK T1110 - Brute Force. |
| **B - Behavior** | T1110 Brute Force as `authentication_failure_burst`: repeated failed authentications targeting user account(s) on a single host in a short time. Analyst predicates: `cmdline CONTAINS Logon Failed` + `user EQUALS admin` as privileged-target example. Must pivot by `user` to distinguish focused brute force (one user, many attempts) vs password spray (many users, few attempts each). |
| **L - Location** | Target = host receiving attempts (internal target, hypothesized public-facing / internet-facing server) and ingress source `ip`. Scope via `host` pivot, then `ip`, `user`, `timestamp` to isolate source-to-target relationship. **Limitation: public-facing / internet-exposed status cannot be answered from `events` table alone - no zone tag or asset inventory; `host`, `ip`, `domain` show target/source only.** |
| **E - Evidence** | Local telemetry CDB SQLite table `events`: `native_type EQUALS authentication`, `event_id EQUALS 4624` (579,580 rows, 2016-08-01 to 2016-08-28). Examine `cmdline`, `user`, `host`, `ip`, `timestamp`, `action`. Positive = burst/cluster on same `host` in short time of `cmdline CONTAINS Logon Failed` with `user EQUALS admin` and repeated `timestamp`s, potentially single `ip`. Auth rows encode outcome as text e.g. `Logon Success user=.. ip=..` in `cmdline` and outcome in `action`. **Constraint: all hunt steps must be single literal predicates (EQUALS / CONTAINS / STARTS_WITH / ENDS_WITH / MATCHES / EXISTS, case-insensitive for EQUALS/CONTAINS/STARTS_WITH/ENDS_WITH) over `timestamp, event_id, native_type, host, user, pid, ppid, cmdline, image, ip, port, domain, file_path, action, status, raw_ref` plus pivots on `host, user, ip, time`; any SPL below is detection-draft equivalent only. Tooling / plaintext passwords not visible in available fields. Success requires correlation to follow-on `Logon Success` on same host+user+ip in time order.** |

# Data
## Data
Source is CDB SQLite table `events`, not Splunk indexes. All queries filter this single table. `native_type` + `event_id` act as sourcetype equivalent.

| Table / native_type / event_id | Sourcetype Equivalent | Key Fields for This Hunt | Relevance |
|---|---|---|---|
| `events` where `native_type EQUALS authentication` and `event_id EQUALS 4624` | Windows Security Log 4624 ingested as authentication rows; 579,580 rows 2016-08-01T00:00:03Z to 2016-08-28T23:59:00Z | `timestamp`, `cmdline`, `user`, `host`, `ip`, `action`, `status` | Primary evidence. `cmdline CONTAINS Logon Failed` = failed attempt per research. `cmdline CONTAINS Logon Success` = potential success. `host` = targeted server. `user` = targeted account (start with `admin`). `ip` = attacker source. `timestamp` = burst clustering. `action` = outcome field to cross-check `cmdline` encoding. |
| `events` where `native_type EQUALS authentication` (any `action`) | Same as above, broader | `action`, `status`, `raw_ref` | Needed to validate encoding: auth rows keep `Logon Success user=.. ip=..` in `cmdline` and outcome in `action`. Use to confirm `Logon Failed` vs `Logon Success` handling and to find success-after-burst. |
| `events` where `native_type EQUALS smb` (`5140`, `5145`, `4648`) | SMB access logs | `host`, `user`, `ip`, `timestamp` | Context only if brute-forced creds reused for SMB lateral movement. Not primary; do not use for initial burst detection. |
| `events` where `native_type EQUALS process_creation` (`4688`, `1`) / `web_request` / `dns` | Endpoint / network | `host`, `user`, `ip`, `domain`, `cmdline` | Out of scope for burst detection. Use only for limited follow-on validation if success found. Cannot answer public-facing status; `domain` and `web_request cmdline site=<host> uri=<path>` do not tag internet exposure. |

Field notes:
- Literal matching only. `EQUALS, CONTAINS, STARTS_WITH, ENDS_WITH` are case-insensitive.
- `cmdline` carries encoded auth text - must use `CONTAINS` not `EQUALS`.
- `user`, `host`, `ip` are pivot fields for aggregation after filtering.
- `port`, `pid`, `ppid`, `image`, `domain`, `file_path` are low relevance for this behavior; `password` value / tool name not present.

# Hunt Procedure
## Hunt Procedure
> Note: Executor runs deterministic single-predicate searches. Each step below is one literal `field / operator / value` predicate plus pivot on `host, user, ip, time`. SPL is provided as equivalent detection draft only, not executed directly.

**Step 1 - Isolate authentication telemetry:**
Predicate: `native_type EQUALS authentication`
Draft SPL: `| tstats count where events.native_type="authentication" by events.host events.user events.ip _time | head 100`
Interpretation: Confirms working set (~579k rows). If zero results, stop - telemetry missing. Record distinct `host` count to scope next steps.

**Step 2 - Isolate failed logons via encoded cmdline:**
Predicate: `cmdline CONTAINS Logon Failed`
Combine as: `native_type EQUALS authentication` AND then `cmdline CONTAINS Logon Failed` as sequential filters.
Draft SPL: `| tstats count where events.native_type="authentication" AND events.cmdline="*Logon Failed*" by events.host events.user events.ip | sort -count`
Interpretation: This is the core behavior predicate from research. Large result set expected; do not alert on single events. Proceed to aggregation. If no `Logon Failed` rows, hypothesis not testable in this window. Also check variant: `action CONTAINS Failed` to validate encoding consistency, but `cmdline` remains authoritative per research.

**Step 3 - Focus privileged-target example:**
Predicate: `user EQUALS admin`
Applied after Step 2 (failed + admin).
Draft SPL: `| tstats count where events.native_type="authentication" AND events.cmdline="*Logon Failed*" AND events.user="admin" by events.host events.ip _time span=5m | where count>20`
Interpretation: Tests analyst-authored `user EQUALS admin` predicate. Burst on same `host` = candidate brute force against privileged account. Note limitation: hunting only `admin` will miss bursts against other accounts - must also run Step 6 without this filter.

**Step 4 - Pivot by host to find targeted server(s):**
Using Step 2 (+ Step 3) result set, pivot / group-count by `host`, then by `timestamp` bucket.
Predicates to enumerate: no new predicate; aggregate prior predicates by `host`.
Draft SPL: `| tstats count where events.native_type="authentication" AND events.cmdline="*Logon Failed*" AND events.user="admin" by events.host | sort -count | head 20`
Follow with: `| tstats count where events.native_type="authentication" AND events.cmdline="*Logon Failed*" by events.host _time span=10m | eventstats max(count) as peak by events.host`
Interpretation: Top `host`(s) with hundreds-thousands of failures = public-facing server candidate. Single host dominating failures in short window supports `authentication_failure_burst`. Evenly distributed failures across many hosts suggests spray or noisy baseline, not focused server brute force. Record top 3 `host` values for deep dive. **Cannot confirm public-facing status from `host` alone - flag need for external asset inventory / firewall zone data.**

**Step 5 - Pivot by ip to isolate source(s) per targeted host:**
For each candidate `host` from Step 4, pivot by `ip`.
Predicate for drill-down example (replace <HOST> with literal found): `host EQUALS <HOST>` + prior `cmdline CONTAINS Logon Failed`
Draft SPL: `| tstats count dc(events.user) as users where events.native_type="authentication" AND events.cmdline="*Logon Failed*" AND events.host="<HOST>" by events.ip | sort -count`
Interpretation: 1-3 `ip`s contributing >80% of failures to one `host` in minutes-hours = classic brute force source. Many `ip`s with few failures each = distributed guessing or NAT / false positive. Single `ip` with single failure = benign. Record top `ip`(s), failure count, time range.

**Step 6 - Pivot by user to distinguish brute force vs spray:**
Predicate set: remove `user EQUALS admin` filter; keep `cmdline CONTAINS Logon Failed` + `host EQUALS <HOST>` + time bounds from Step 5, then group by `user`.
Draft SPL: `| tstats count where events.native_type="authentication" AND events.cmdline="*Logon Failed*" AND events.host="<HOST>" by events.user | sort -count | head 50`
And per-source: `| tstats count where events.native_type="authentication" AND events.cmdline="*Logon Failed*" AND events.host="<HOST>" AND events.ip="<IP>" by events.user | sort -count`
Interpretation: One `user` (e.g., `admin`) with high count + one `ip` = password guessing / brute force - supports hypothesis. Many distinct `user`s with low counts each from same `ip` = password spray - different T1110 sub-technique, note and do not conflate. Single `user` across many `ip`s = possible distributed brute force. Check `user EXISTS` to catch blank/malformed user rows.

**Step 7 - Confirm burst / time clustering:**
Using `host EQUALS <HOST>` + `cmdline CONTAINS Logon Failed` (+ `ip EQUALS <IP>` and/or `user EQUALS admin`), examine `timestamp` ordering and rate.
Draft SPL: `| tstats count where events.native_type="authentication" AND events.cmdline="*Logon Failed*" AND events.host="<HOST>" AND events.ip="<IP>" by _time span=5m | sort _time | streamstats avg(count) as baseline | where count>5*baseline AND count>20`
Interpretation: Sustained high-rate cluster (e.g., >20-50 failures per 5-10 min, gaps of seconds between `timestamp`s) = burst. Isolated single failures spaced hours apart = likely mistyped passwords, not brute force. Document start-end `timestamp`, total count, rate (events/min), duration. Require repeated `timestamp`s in short window before declaring positive.

**Step 8 - Check for success-after-burst (compromise determination):**
Predicate: `cmdline CONTAINS Logon Success`
Correlate on same `host EQUALS <HOST>` + `user EQUALS <USER>` (+ `ip EQUALS <IP>`) with `timestamp` AFTER burst end.
Draft SPL: `| tstats count where events.native_type="authentication" AND (events.cmdline="*Logon Failed*" OR events.cmdline="*Logon Success*") AND events.host="<HOST>" AND events.user="admin" by events.cmdline _time events.ip | sort _time`
Interpretation: `Logon Failed` burst followed within minutes-hours by `Logon Success` for same `host`+`user` (+ same `ip` = strong success signal; different `ip` = possible legitimate logon, weaker) suggests guessed credential used. Burst with no success = attempted but failed brute force - still valid attempt finding. Check `action` field change in same window to corroborate outcome encoding. **Tooling / password values not visible - cannot confirm method from fields.**

**Step 9 - Rule out benign / baseline causes:**
Re-apply `host EQUALS <HOST>` + `user EQUALS admin` without `cmdline` filter to view baseline ratio of `Logon Failed` vs `Logon Success` over 28 days.
Draft SPL: `| tstats count where events.native_type="authentication" AND events.host="<HOST>" AND events.user="admin" by events.cmdline | head 20`
Interpretation: If `Logon Failed` rate is constant low background across all days/hosts/users, candidate burst must clearly exceed baseline to be malicious. Service account misconfiguration typically shows regular interval failures from internal `ip` over full 28 days, not sharp burst. Document baseline vs burst ratio.

**Step 10 - Disposition:**
- Positive (attempt): Same `host` + short `timestamp` burst of `cmdline CONTAINS Logon Failed` (+ `user EQUALS admin` for privileged case), high count, tight interval, 1-few `ip`s.
- Positive (likely success): Above plus time-ordered `cmdline CONTAINS Logon Success` on same `host`+`user` (+same `ip`) - escalate for incident review with `host, user, ip, timestamp` start/end, counts, rate.
- Negative: No burst; only sparse failures or no `Logon Failed` rows.
- Explicit gaps to record: (a) cannot prove target is public-facing from `events` alone - need firewall / asset exposure data; (b) cannot see passwords/tools; (c) `admin`-only scope misses other accounts - report full `user` distribution from Step 6.
