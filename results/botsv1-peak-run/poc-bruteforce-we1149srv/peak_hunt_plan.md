## Hypothesis
Brute force login against public-facing server. Repeated failed authentication events targeting user accounts on a host. The encoded cmdline row carries 'Logon Failed' for failed attempts, forming an authentication_failure_burst consistent with MITRE ATT&CK T1110 - Brute Force.

## Recommended Time Frame
2016-08-01T00:00:00Z to 2016-08-28T23:59:00Z inclusive - full coverage of available CDB `events` authentication data (579,580 rows, event_id 4624). No narrower window is defined in research; hunt the full 28 days then window down into compressed intervals (5-minute, 1-hour) using CDB `timestamp` to quantify repeated failures to the same host and user.

## ABLE Table
| Element | Restatement |
|---|---|
| **Actor** | Unspecified external opportunistic attacker. No named group. Hunt any source IP attempting password guessing (T1110). Attribution limited to `ip`, `host`, `user`, `timestamp` pivots; telemetry alone cannot attribute. |
| **Behavior** | T1110 Brute Force - password guessing: many `Logon Failed` authentication rows to same `host` + `user` + `ip` in compressed `timestamp` window (authentication_failure_burst). Focus on burst rate and repeat targeting per BOTS v1 brute-force phase. Burst threshold not defined in research; must be quantified. |
| **Location** | Concentrated `host` values in CDB table `events` where authentication bursts occur. Assumed public-facing server(s) per hypothesis, but available data cannot prove public-facing vs internal without asset inventory / zone mapping. Pivot and scope by `host`, with `ip` for source/target context and `timestamp` for windowing. |
| **Evidence** | CDB SQLite table `events`, `native_type` EQUALS `authentication`, `event_id` EQUALS `4624`. Primary indicator: `cmdline` CONTAINS `Logon Failed`, with outcome also in `action` / `status` and detail text like `Logon Success user=.. ip=..` in `cmdline`. Privileged targeting example: `user` EQUALS `admin` (also hunt other `user` values). Burst proof requires aggregation by `host`, `user`, `ip` over `timestamp`. Equivalent detection draft: filter `native_type` authentication + `event_id` 4624 where `cmdline` contains `Logon Failed`, aggregate count by `host`, `user`, `ip` over time. |

## Data
All hunting executes against CDB SQLite table `events`. No Splunk index or sourcetype is given in local telemetry; SPL below are equivalent detection drafts only, not executed. Drafts assume a scoped auth index (shown as `index=auth_index` placeholder). SPL `_time` maps to CDB `timestamp`. In every failure query, scope first to indexed-equivalent fields `native_type` + `event_id` before `search` on `cmdline` content, because `tstats` cannot search wildcard raw `cmdline`. Executor constraint: each PoC step is one literal predicate (field, operator, value) over fields `timestamp, event_id, native_type, host, user, pid, ppid, cmdline, image, ip, port, domain, file_path, action, status, raw_ref`, plus pivots on `host, user, ip` and time. EQUALS, CONTAINS, STARTS_WITH, ENDS_WITH are case-insensitive.

| Source / Filter | Key Fields | Relevance to Hunt |
|---|---|---|
| `events` where `native_type` EQUALS `authentication` + `event_id` EQUALS `4624` (579,580 rows, 2016-08-01 to 2016-08-28) | `timestamp, event_id, native_type, host, user, ip, cmdline, action, status` | Base dataset. All logon rows. `event_id` 4624 narrows to logon telemetry; excludes 3.6M `process_creation` 4688 rows. Use in all predicates. |
| `cmdline` CONTAINS `Logon Failed` | `cmdline, action, status` | Primary failure indicator per research. Isolate failures, then pivot distinct `action`, `status` to verify outcome encoding. |
| `cmdline` CONTAINS `Logon Success` | `cmdline, host, user, ip, timestamp, action` | Compromise check: success for same `host`/`user`/`ip` after burst. Pattern `Logon Success user=.. ip=..` in `cmdline`. |
| `user` EQUALS `admin` | `user` | Analyst-authored privileged targeting example. Test separately; do not limit full hunt to admin. |
| Pivots: `host`, `user`, `ip`, `timestamp` (`_time span` in SPL = `timestamp` windowing in CDB) | `host` = targeted server, `ip` = source, `user` = targeted account, `timestamp` = burst windowing | Required to prove burst: many failures to same host+user+ip in compressed window. Report actual counts/rate/duration; no fixed threshold. |
| Out-of-scope: `native_type` EQUALS `process_creation`, `smb`, `web_request`, `dns` | — | Not evidence for this behavior. `web_request` stores site in `domain` and `site=<host> uri=<path>` in `cmdline`; `dns` only 2016-08-24. Neither replaces auth evidence. Available data cannot answer public-facing status, cleartext passwords tried, or attacker identity beyond IP. |

## Hunt Procedure
1. **Establish authentication baseline and scope to logon telemetry:**
   - Executor predicates in sequence:
     - Predicate 1: `native_type` EQUALS `authentication`
     - Predicate 2: `event_id` EQUALS `4624`
     - Pivot on `host` (group/count), pivot on `user`, pivot on `ip`, pivot on time (`timestamp` binned by hour)
   - Equivalent detection draft:
     `index=auth_index native_type=authentication event_id=4624 | bin _time span=1h | stats count BY _time host user ip | sort - count | head 20`
   - Interpretation: Confirms coverage (expect ~579k rows). Identifies which `host` values carry high authentication volume for later burst-vs-baseline comparison. Do not group by raw `_time`; always `bin _time` first to avoid high-cardinality explosion, then `sort - count` before `head`. If a single `host` dominates, prioritize as candidate target. This step cannot prove public-facing status.

2. **Isolate failed authentications and verify outcome encoding:**
   - Executor predicates in sequence:
     - Predicate 1: `native_type` EQUALS `authentication`
     - Predicate 2: `event_id` EQUALS `4624`
     - Predicate 3: `cmdline` CONTAINS `Logon Failed`
     - Pivot on `host`, `user`, `ip` to count; pivot distinct values of `action` and `status` to verify encoding
   - Equivalent detection drafts:
     `index=auth_index native_type=authentication event_id=4624 | search cmdline="*Logon Failed*" | stats count BY host user ip action`
     `index=auth_index native_type=authentication event_id=4624 | search cmdline="*Logon Failed*" | stats count BY action status`
     `index=auth_index native_type=authentication event_id=4624 | search cmdline="*Logon Success*" | stats count BY action status`
   - Interpretation: This is the core true-positive pool. Do not assume `action`/`status` values; list what is observed where `cmdline` contains `Logon Failed` vs `Logon Success` and record distinct values. If zero `Logon Failed` rows, hypothesis has no support. If large volume, proceed to burst analysis. Document total failure count and failure rate vs Step 1 baseline.

3. **Find targeted hosts (Location pivot):**
   - Executor predicates in sequence:
     - Predicate 1: `native_type` EQUALS `authentication`
     - Predicate 2: `event_id` EQUALS `4624`
     - Predicate 3: `cmdline` CONTAINS `Logon Failed`
     - Pivot on `host` (group/count, sort descending)
   - Equivalent detection draft:
     `index=auth_index native_type=authentication event_id=4624 | search cmdline="*Logon Failed*" | stats count BY host | sort - count`
   - Interpretation: Brute force predicts concentration on 1-few `host`s, not even spread. Keep `native_type` + `event_id` + `cmdline` filter in all failure queries for consistency and efficiency. A host with hundreds-thousands of failures vs others with tens is a candidate target server. Select top 3-5 `host`s for deep dive. Available data cannot confirm which is internet-facing; note candidates for separate asset/zone validation.

4. **Find targeted users and check privileged targeting:**
   - Executor predicates in sequence for each candidate from Step 3:
     - Predicate 1: `host` EQUALS `<candidate>`
     - Predicate 2: `cmdline` CONTAINS `Logon Failed`
     - Pivot on `user` (group/count, sort descending)
     - Predicate 3 (test separately, not as combined filter): `user` EQUALS `admin`
     - Predicate 4 (test separately for full scope): pivot on `user` without `admin` restriction to enumerate other targeted users
   - Note: Predicates 1-2 assume prior scope `native_type` EQUALS `authentication` and `event_id` EQUALS `4624` already applied.
   - Equivalent detection drafts:
     `index=auth_index native_type=authentication event_id=4624 | search cmdline="*Logon Failed*" host="<candidate>" | stats count BY user | sort - count`
     `index=auth_index native_type=authentication event_id=4624 | search cmdline="*Logon Failed*" host="<candidate>" user=admin | stats count BY ip | sort - count`
   - Interpretation: If `admin` dominates, matches privileged-targeting example. If single non-admin `user` dominates, classic directed guessing against that account. If many distinct `user` values each with few failures to same host, consider password-spray variant - still in scope but note distinction. Record top targeted `user`s per host. Do not filter exclusively to `admin`.

5. **Prove burst behavior by source IP and compressed time window:**
   - Executor predicates in sequence for each candidate host/user:
     - Predicate 1: `host` EQUALS `<candidate>`
     - Predicate 2: `user` EQUALS `<targeted-user>`
     - Predicate 3: `cmdline` CONTAINS `Logon Failed`
     - Pivot on `ip` (group/count)
     - Predicate 4: `ip` EQUALS `<burst-ip-candidate>`
     - Pivot on time (`timestamp` binned to 5-min and 1-hour windows, count per window)
   - Equivalent detection drafts (`_time span` = CDB `timestamp` windowing):
     `index=auth_index native_type=authentication event_id=4624 | search cmdline="*Logon Failed*" host="<candidate>" | bin _time span=5m | stats count BY _time host user ip | sort - count | head 100`
     `index=auth_index native_type=authentication event_id=4624 | search cmdline="*Logon Failed*" host="<candidate>" user="<targeted>" ip="<burst-ip>" | bin _time span=1h | stats count BY _time host user ip | sort - count`
   - Interpretation: True brute force = multiple `Logon Failed` rows for same host+user+ip in compressed window. Research defines no threshold, so report actual counts/rate/duration per `host`/`user`/`ip` (e.g., count per 5-min, per 1-hour, burst duration). Values such as >10 in 5 min or >100 in 1 hour are illustrative starting points to quantify, not decision rules. Single isolated failures or 1-2 per hour per IP are not a burst - mark as benign/policy noise. One IP hammering one account = directed brute force; one IP hitting many users = spray; many IPs hitting same account = distributed.

6. **Check for success-after-burst (potential compromise):**
   - Executor predicates in sequence:
     - Predicate 1: `host` EQUALS `<candidate>`
     - Predicate 2: `user` EQUALS `<targeted-user>`
     - Predicate 3: `ip` EQUALS `<burst-ip>`
     - Predicate 4: `cmdline` CONTAINS `Logon Success`
     - Pivot on time: require `timestamp` later than burst `timestamp` from Step 5
   - Note: Assumes prior scope `native_type` EQUALS `authentication` and `event_id` EQUALS `4624`.
   - Equivalent detection draft:
     `index=auth_index native_type=authentication event_id=4624 host="<candidate>" user="<targeted>" ip="<burst-ip>" | search cmdline="*Logon Failed*" OR cmdline="*Logon Success*" | bin _time span=5m | stats count BY _time cmdline action | sort _time`
   - Interpretation: `Logon Success` for same host/user/IP within minutes-hours after burst is high-priority follow-up - possible successful guessing. No success = attempted but failed brute force (still valid finding). Success from different `ip` with same user/host shortly after may indicate credential reuse. This step cannot show passwords tried or post-logon activity.

7. **Rule out benign mass-failure causes and close:**
   - Executor predicates in sequence:
     - Predicate 1: `host` EQUALS `<candidate>`
     - Predicate 2: `cmdline` CONTAINS `Logon Failed`
     - Pivot on time (`timestamp` binned hourly), then pivot on `user`, pivot on `ip` per window
   - Equivalent detection draft:
     `index=auth_index native_type=authentication event_id=4624 | search cmdline="*Logon Failed*" host="<candidate>" | bin _time span=1h | stats count values(user) AS users values(ip) AS ips BY _time | sort _time`
   - Interpretation: Benign explanations: misconfigured service/script retrying same account at regular intervals from internal `ip`, expired service account, single-user typo (low count, spread over days). Malicious-leaning: high-velocity burst from unusual `ip`, targeting `admin` or multiple accounts, off-hours, followed by success. If burst maps to single internal host/service account at fixed cadence, mark likely benign but recommend credential/service review. Explicitly state limitations in finding: available data cannot answer public-facing status, cleartext passwords, or attribution beyond IP/host/user/time; recommend asset exposure check, firewall/VPN logs, and EDR process context as separate follow-on, not proof for this hypothesis.
