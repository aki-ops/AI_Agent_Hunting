# Hunt Report

## 1. Hypothesis / Question

> Amber Turing visited a competitor website to find executive contact info. What website did she visit?

- **Subject:** `user`: `Amber Turing`
- **Requested Object:** `fully_qualified_domain_name` (role: `answer`)
- **Behavior:** User Amber Turing navigated to a competitor website to retrieve executive contact information.

**Result:** `SUPPORTED`  
**Stopping:** `STOP_RESOLVED`

- **Causal Path Coverage:** `100.0%` (4/4 relations verified)
- **Wildcard Scope Coverage:** `0.0%` (0/1 broadsweep cells)
- **Instance Cell Coverage:** `100.0%` (4/4 concrete entity cells)

**Answer (fully_qualified_domain_name):** `www.berkbeer.com`

## 2. Hypothesis analysis

- `SUPPORTED` — Amber Turing conducted standard interactive web browsing from an enterprise endpoint to an external competitor domain for competitive research.
- `UNKNOWN` — The user session or credentials attributed to Amber Turing were leveraged to access competitor web infrastructure or unauthorized third-party directories outside of sanctioned business activities.

### Proven Relation Chain (Causal Provenance)

| Edge ID | Relation Path | Citations | Verified At |
|---|---|---|---|
| `edge-person-owns-account` | `Amber Turing` **-[owns]->** `amber.turing` | `obs-1` | `2026-09-07T12:27:51.007164` |
| `edge-account-logon-endpoint` | `amber.turing` **-[logged_on_to]->** `WRK-ATURING` | `obs-102` | `2026-09-07T12:27:53.929741` |
| `edge-endpoint-assigned-ip` | `WRK-ATURING` **-[assigned_ip]->** `10.0.2.101` | `obs-201` | `2026-09-07T12:27:55.767567` |
| `edge-client-ip-requested-target` | `10.0.2.101` **-[requested]->** `www.berkbeer.com` | `obs-373` | `2026-09-07T12:28:37.269687` |

**Unresolved Mandatory Unknowns:** None (all causal relations verified).

## 3. Evidence and explanation

| Evidence | Why it matters | Source |
|---|---|---|
| Verified relation 10.0.2.101 -[RelationType.REQUESTED]-> www.berkbeer.com | Proves causal provenance step for edge-client-ip-requested-target | 1 event(s); representative observations: `obs-373` |
| Web request to www.berkbeer.com | Represents incoming HTTP activity targeting web application services, potentially correlating with exploitation attempts or web access. | 1 event(s); representative observations: `obs-373` |
| Telemetry observations (132 events on venus) | Observed operational telemetry within the monitored scope. | 132 event(s); representative observations: `obs-1`, `obs-3`, `obs-5` |
| Telemetry observations (91 events on mercury) | Observed operational telemetry within the monitored scope. | 91 event(s); representative observations: `obs-201`, `obs-202`, `obs-203` |
| Telemetry observations (68 events on wrk-aturing) | Observed operational telemetry within the monitored scope. | 68 event(s); representative observations: `obs-2`, `obs-4`, `obs-9` |
| Web request to wrk-aturing.frothly.local | Represents incoming HTTP activity targeting web application services, potentially correlating with exploitation attempts or web access. | 6 event(s); representative observations: `obs-292`, `obs-293`, `obs-294` |
| Web request to wrk-aturing | Represents incoming HTTP activity targeting web application services, potentially correlating with exploitation attempts or web access. | 3 event(s); representative observations: `obs-298`, `obs-299`, `obs-300` |
| Web request to ping.chartbeat.net | Represents incoming HTTP activity targeting web application services, potentially correlating with exploitation attempts or web access. | 1 event(s); representative observations: `obs-324` |
| Web request to ad.afy11.net | Represents incoming HTTP activity targeting web application services, potentially correlating with exploitation attempts or web access. | 1 event(s); representative observations: `obs-308` |
| Web request to go.microsoft.com | Represents incoming HTTP activity targeting web application services, potentially correlating with exploitation attempts or web access. | 1 event(s); representative observations: `obs-387` |
| Web request to ss.symcd.com | Represents incoming HTTP activity targeting web application services, potentially correlating with exploitation attempts or web access. | 1 event(s); representative observations: `obs-383` |
| Web request to tapestry.tapad.com | Represents incoming HTTP activity targeting web application services, potentially correlating with exploitation attempts or web access. | 1 event(s); representative observations: `obs-368` |

### Explanation

- **Deterministic Graph Resolution:** The target object `www.berkbeer.com` was proven through the verified 4-step causal provenance chain.
- Proves causal provenance step for edge-client-ip-requested-target
- Represents incoming HTTP activity targeting web application services, potentially correlating with exploitation attempts or web access.
- Observed operational telemetry within the monitored scope.

## 4. Queries used

### `qp-v5-1-resolve_person_to_account` — `edge-person-owns-account`
- **Purpose:** resolve_person_to_account

- **Result:** 100 rows returned; complete=True
- **Hypothesis Impact:** Targets `hypo-1`
Provider: `splunk`; completeness: `complete`

```spl
search index="botsv2" (sourcetype="WinEventLog:Security" OR sourcetype="wineventlog:security") (EventCode=4624 OR EventCode=4625) ("Amber Turing" OR "Amber" OR TargetUserName="*Amber*") | rex field=_raw "New Logon:[\s\S]*?Account Name:\s*(?<TargetUserName>[^\r\n\s]+)" | rex field=_raw "Account Name:\s*(?<user>[^\r\n\s]+)" | head 101 | table _time, host, ComputerName, TargetUserName, user, IpAddress, WorkstationName, LogonType, _raw
```

### `qp-v5-2-resolve_account_to_endpoint` — `edge-account-logon-endpoint`
- **Purpose:** resolve_account_to_endpoint

- **Result:** 100 rows returned; complete=True
- **Hypothesis Impact:** Targets `hypo-1`
Provider: `splunk`; completeness: `complete`

```spl
search index="botsv2" (sourcetype="WinEventLog:Security" OR sourcetype="wineventlog:security") (EventCode=4624 OR EventCode=4625) ("amber.turing" OR TargetUserName="*amber.turing*" OR TargetUserName="*amber.turing*" OR user="*amber.turing*") | rex field=_raw "Workstation Name:\s*(?<WorkstationName>[^\r\n\s]+)" | rex field=_raw "New Logon:[\s\S]*?Account Name:\s*(?<TargetUserName>[^\r\n\s]+)" | head 101 | table _time, host, ComputerName, TargetUserName, user, IpAddress, WorkstationName, LogonType, _raw
```

### `qp-v5-3-resolve_endpoint_to_client_ip` — `edge-endpoint-assigned-ip`
- **Purpose:** resolve_endpoint_to_client_ip

- **Result:** 100 rows returned; complete=True
- **Hypothesis Impact:** Targets `hypo-1`
Provider: `splunk`; completeness: `complete`

```spl
search index="botsv2" ((sourcetype="stream:dns" ("WRK-ATURING" OR hostname="*WRK-ATURING*" OR name="*WRK-ATURING*")) OR ((sourcetype="WinEventLog:Security" OR sourcetype="wineventlog:security") ("WRK-ATURING" OR host="*WRK-ATURING*" OR ComputerName="*WRK-ATURING*") EventCode=4624) OR (sourcetype="*sysmon*" (host="*WRK-ATURING*" OR ComputerName="*WRK-ATURING*") "*EventID>3<*") OR (sourcetype="stream:dhcp" host="*WRK-ATURING*")) | rex field=_raw "\"host_addr\":\[\"(?<IpAddress>[^\"]+)\"" | rex field=_raw "\"src_ip\":\"(?<src_ip>[^\"]+)\"" | rex field=_raw "Source Network Address:\s*(?<IpAddress>[^\r\n\s]+)" | rex field=_raw "New Logon:[\s\S]*?Account Name:\s*(?<TargetUserName>[^\r\n\s]+)" | rex field=_raw "Workstation Name:\s*(?<WorkstationName>[^\r\n\s]+)" | where (isnotnull(IpAddress) AND IpAddress!="-" AND IpAddress!="127.0.0.1" AND IpAddress!="0.0.0.0") OR (isnotnull(src_ip) AND src_ip!="-" AND src_ip!="127.0.0.1" AND src_ip!="0.0.0.0") | head 101 | table _time, host, ComputerName, WorkstationName, TargetUserName, IpAddress, src_ip, client_ip, c_ip, hostname, name, _raw
```

### `qp-v5-4-find_web_activity_from_client_ip` — `edge-client-ip-requested-target`
- **Purpose:** find_web_activity_from_client_ip

- **Result:** 100 rows returned; complete=True
- **Hypothesis Impact:** Targets `hypo-1`
Provider: `splunk`; completeness: `complete`

```spl
search index="botsv2" (sourcetype="stream:http" OR sourcetype="pan:traffic") (src_ip="10.0.2.101" OR client_ip="10.0.2.101" OR c_ip="10.0.2.101" OR src="10.0.2.101") | eval site=coalesce(site, cs_host) | where isnotnull(site) AND site!="" AND NOT (site like "%:8014%") | search NOT (site="*cnn.com*" OR site="*scorecardresearch*" OR site="*doubleclick*" OR site="*rubiconproject*" OR site="*outbrain*" OR site="*adnxs*" OR site="*fwmrm.net*" OR site="*krxd.net*" OR site="*gigya.com*" OR site="*doubleverify*" OR site="*sharethrough*" OR site="*akamai*")  | dedup site | head 101 | table _time, host, sourcetype, src_ip, dest_ip, site, cs_host, uri, cs_uri_stem, cs_method, status, _raw
```

## 5. Cost

- Model: `1/gemini-flash-3.8-high-omni`
- Calls: `2`
- Tokens: `6220`
- Estimated cost: `$0.000754`
