# Joomla Search/Mailto RCE (T1190) Hunt Plan

## Hypothesis
Joomla RCE web compromise (BOTS v1 real attack). An external attacker scans and exploits Joomla search/mailto components on `imreallynotbatman.com`, potentially achieving remote code execution. Expected observable chain: `web_request`, exploitation. MITRE ATT&CK T1190 (Exploit Public-Facing Application).

## Recommended Time Frame
Use the full available data range: **2016-08-01T00:00:00Z to 2016-08-28T23:59:00Z**. Focus drill-down on **2016-08-10 to 2016-08-24**, which contains the sparse `process_creation` event_id `1` telemetry and `dns` activity. No narrower time window is recommended because the local telemetry must first establish a baseline for `imreallynotbatman.com` web traffic.

## ABLE Table
| Element | Detail |
|---|---|
| Actor | External attacker in the BOTS v1 real-attack scenario. No named threat group attribution. Treat as an opportunistic web application exploitation actor targeting an internet-facing Joomla site. |
| Behavior | Scanning and exploitation of Joomla search/mailto components on `imreallynotbatman.com`, leading to remote code execution. Expected observable chain: `web_request`, exploitation. MITRE ATT&CK T1190. Candidate predicates: `domain EQUALS imreallynotbatman.com`; `cmdline CONTAINS /joomla/`. |
| Location | Internet-facing web server hosting `imreallynotbatman.com`, typically in the perimeter/DMZ web tier. Start with web request telemetry for the site, then pivot to process activity on the web server host. If exploitation succeeds, inspect the web server host and adjacent internal network for follow-on activity. |
| Evidence | Relevant local telemetry: `web_request` (`domain`, `cmdline`, `host`, `ip`, `port`, `timestamp`), `process_creation` (`image`, `cmdline`, `pid`, `ppid`, `host`, `user`, `timestamp`), `authentication` (`user`, `ip`, `action`, `host`, `timestamp`), `dns` (`domain`, `host`, `timestamp`), and `smb` (`host`, `user`, `ip`, `file_path`, `action`, `status`, `timestamp`). Expected evidence: `web_request` rows where `domain EQUALS imreallynotbatman.com` and `cmdline CONTAINS /joomla/`; web request `cmdline` stores `site=<host> uri=<path>`, so Joomla paths are embedded there. Corroborate with `process_creation` on the web server showing unexpected child processes, shell commands, or downloaded payloads after the web requests. The available data cannot directly prove successful RCE or reveal exploit payload content. |

## Data
| Source | Native Type / Event ID | Key Fields | Relevance to Hunt |
|---|---|---|---|
| Web requests | `web_request` / `-` | `timestamp`, `host`, `user`, `ip`, `port`, `domain`, `cmdline`, `action`, `status` | Initial Joomla scan/exploit entry point; `domain` identifies `imreallynotbatman.com`; `cmdline` embeds `site=<host> uri=<path>` and should contain `/joomla/`, `com_search`, or `com_mailto`. |
| Process creation | `process_creation` / `4688`, `1` | `timestamp`, `host`, `user`, `pid`, `ppid`, `cmdline`, `image` | RCE, payload execution, child shells, and post-exploitation commands on the web server. |
| Authentication | `authentication` / `4624` | `timestamp`, `host`, `user`, `ip`, `action`, `cmdline` | Post-exploit logons, credential use, and lateral movement. |
| DNS | `dns` / `-` | `timestamp`, `host`, `domain`, `ip` | C2, payload download domains, or beaconing after exploitation. |
| SMB | `smb` / `5140`, `5145`, `4648` | `timestamp`, `host`, `user`, `ip`, `file_path`, `action`, `status` | Lateral movement, file access, or staging after web compromise. |

**Execution model note:** Each numbered PoC step below is a **single literal predicate** (`field`, `operator`, `value`) that the deterministic executor will evaluate. Steps that are labeled **PIVOT** or **CORRELATION** are not predicates; they consume the output of previous steps and must be performed manually by the hunter (using the field values returned by the predicate steps).

**Splunk mapping note:** The local telemetry is described as CDB SQLite table `events`; no Splunk index is named. If ingested into Splunk, scope to that CDB telemetry index (avoid `index=*`). The `native_type` column is a field in the CDB schema, not a native Splunk `sourcetype`; the SPL drafts below treat it as a field filter for consistency. All SPL is presented as an **equivalent detection draft only** — the executor must use the literal predicates, not the SPL.

## Hunt Procedure

### Phase A — Establish the web request baseline for `imreallynotbatman.com`

**Step 1 (predicate):** `domain EQUALS imreallynotbatman.com`
- SPL draft: `index=<cdb_events> domain="imreallynotbatman.com" | timechart span=1h count`
- Purpose: find all web request rows answering for the site. Web requests store `site=<host> uri=<path>` in `cmdline` and the site in `domain`.

**Step 2 (predicate):** `native_type EQUALS web_request`
- SPL draft: `index=<cdb_events> native_type="web_request" | stats count min(_time) max(_time) by host, domain | sort -count`
- Purpose: enumerate the host(s) serving the site and the time range of web activity. Record the returned `host` value(s) — this grounds the `<web_server_host>` pivot used in Phase D.

**PIVOT (Phase A):** Intersect the result sets of Step 1 and Step 2 to obtain the `host` and `ip` values of web requests to `imreallynotbatman.com`. Record every distinct `host` returned; these become the literal `host` values used in Phase D.

### Phase B — Identify Joomla component targeting (scan vs exploit)

**Step 3 (predicate):** `cmdline CONTAINS /joomla/`
- SPL draft: `index=<cdb_events> native_type="web_request" domain="imreallynotbatman.com" cmdline="*/joomla/*" | stats count dc(cmdline) min(_time) max(_time) by host, ip, port | sort -count`
- Purpose: research-provided primary predicate for Joomla component paths. If this returns rows, proceed to Step 6 to slice by component. If this returns **zero rows**, proceed to Steps 4 and 5 as fallbacks in that order, then Step 6b.

**Step 4 (predicate, fallback):** `cmdline CONTAINS com_search`
- SPL draft: `index=<cdb_events> native_type="web_request" domain="imreallynotbatman.com" cmdline="*com_search*" | stats count min(_time) max(_time) by host, ip, cmdline | sort -count`
- Purpose: fallback if Step 3 returns no rows; the real BOTS attack targets the `com_search` component.

**Step 5 (predicate, fallback):** `cmdline CONTAINS com_mailto`
- SPL draft: `index=<cdb_events> native_type="web_request" domain="imreallynotbatman.com" cmdline="*com_mailto*" | stats count min(_time) max(_time) by host, ip, cmdline | sort -count`
- Purpose: fallback if Steps 3 and 4 return no rows; the real BOTS attack also targets the `com_mailto` component.

**Step 6 (predicate, drill-down):** `cmdline CONTAINS com_search`
- Note: this is a separate run of the Step 4 predicate **scoped** to the `host`/`ip` values from Step 3 or 4 (use a `| search` clause to add that scope in the SPL draft). If Step 3 found `/joomla/` paths, re-run this on the specific host/ip returned by Step 3.
- SPL draft: `index=<cdb_events> native_type="web_request" cmdline="*com_search*" | stats count min(_time) max(_time) by host, ip, cmdline | sort -count`
- Purpose: identify the search-component request(s) that typically precede exploitation.

**PIVOT (Phase B — scan vs exploit discrimination):**
- **Scan indicator:** a single `ip` returning a **high count of distinct `/joomla/` paths** (`dc(cmdline)` high) over a **short interval** (minutes to a few hours), with only `2xx`/`3xx`/`404` mixed statuses. This is reconnaissance.
- **Exploit indicator:** the same `ip` then issuing a request whose `cmdline` includes `com_search` or `com_mailto`, tightly followed (typically **within seconds to low minutes**) by a `process_creation` event on the same `host` (Phase D). The tight web-request → process-creation proximity is the primary exploit signal in this telemetry.

### Phase C — Source IP and request-pattern pivot

**Step 7 (predicate):** `ip EXISTS`
- **Scoped execution required.** Do NOT run this globally; run it as a scoped filter over the outputs of Steps 1–6 (i.e., only `native_type=web_request` + `domain=imreallynotbatman.com` + `/joomla/` / `com_search` / `com_mailto` rows). Bare `ip EXISTS` over the full table is trivially true and produces no signal.
- SPL draft: `index=<cdb_events> native_type="web_request" domain="imreallynotbatman.com" cmdline="*/joomla/*" | stats count dc(cmdline) min(_time) max(_time) by ip, port, host | sort -count`
- Purpose: rank candidate attacker IPs by Joomla-path breadth and request volume. The top IPs by `dc(cmdline)` are the most likely scanners; the IP that also appears in `com_search`/`com_mailto` rows (Phase B) is the most likely exploiter.

**PIVOT (Phase C):** Record the top candidate `ip`(s) and the `host`(s) they hit. These become the literal `ip` and `host` values used in Phases D and E below.

### Phase D — Post-exploitation process activity on the web server host

The placeholder `<web_server_host>` is **defined as the literal `host` value(s) returned by the Phase A and Phase B pivot steps** (the host serving `imreallynotbatman.com` web requests). Do not run Phase D until that value has been read out of Phases A/B.

**Step 8 (predicate):** `native_type EQUALS process_creation`
- SPL draft (scoped to the resolved host): `index=<cdb_events> native_type="process_creation" host="<web_server_host>" | table _time, user, image, cmdline, pid, ppid | sort _time`
- Purpose: enumerate every process created on the web server host across the full window. This is the base set for the exploit-confirmation drill-downs below.

**Step 9 (predicate):** `image CONTAINS cmd.exe`
- SPL draft: `index=<cdb_events> native_type="process_creation" host="<web_server_host>" image="*cmd.exe*" | table _time, user, image, cmdline, pid, ppid | sort _time`
- Purpose: a web-server process spawning `cmd.exe` is a strong RCE indicator.

**Step 10 (predicate):** `image CONTAINS powershell.exe`
- SPL draft: `index=<cdb_events> native_type="process_creation" host="<web_server_host>" image="*powershell.exe*" | table _time, user, image, cmdline, pid, ppid | sort _time`
- Purpose: PowerShell spawned on the web server is a strong post-exploitation indicator.

**Step 11 (predicate):** `cmdline CONTAINS http`
- SPL draft: `index=<cdb_events> native_type="process_creation" host="<web_server_host>" cmdline="*http*" | table _time, user, image, cmdline, pid, ppid | sort _time`
- Purpose: download/staging command lines (e.g., `certutil -urlcache`, `curl`, `wget`, `Invoke-WebRequest`).

**Step 12 (predicate):** `cmdline CONTAINS powershell`
- SPL draft: `index=<cdb_events> native_type="process_creation" host="<web_server_host>" cmdline="*powershell*" | table _time, user, image, cmdline, pid, ppid | sort _time`
- Purpose: PowerShell command-line flags (e.g., `-enc`, `-nop`, `-w hidden`) indicative of malicious execution.

**Step 13 (predicate):** `cmdline CONTAINS certutil`
- SPL draft: `index=<cdb_events> native_type="process_creation" host="<web_server_host>" cmdline="*certutil*" | table _time, user, image, cmdline, pid, ppid | sort _time`
- Purpose: common LOLBin download/decode pattern after web exploitation.

**Step 14 (predicate):** `cmdline CONTAINS bitsadmin`
- SPL draft: `index=<cdb_events> native_type="process_creation" host="<web_server_host>" cmdline="*bitsadmin*" | table _time, user, image, cmdline, pid, ppid | sort _time`
- Purpose: alternative LOLBin download utility.

**PIVOT (Phase D — exploit confirmation):** Any `process_creation` row on `<web_server_host>` whose `timestamp` falls **after** the last suspicious `web_request` (Steps 3–7) and **within a tight window (≤ a few minutes)** is strong corroborating evidence of successful exploitation. Note the `user`, `image`, `pid`, `ppid`, and `cmdline` for the report.

### Phase E — Follow-on network, authentication, and lateral-movement checks

**Step 15 (predicate):** `native_type EQUALS authentication`
- SPL draft: `index=<cdb_events> native_type="authentication" host="<web_server_host>" | stats count min(_time) max(_time) by user, ip, action | sort -count`
- Purpose: surface logons on the web server after the exploitation window.

**Step 16 (predicate):** `action CONTAINS Success`
- SPL draft: `index=<cdb_events> native_type="authentication" host="<web_server_host>" action="*Success*" | stats count min(_time) max(_time) by user, ip | sort -count`
- Purpose: successful logons after exploitation may indicate credential use or lateral movement.

**Step 17 (predicate):** `native_type EQUALS dns`
- SPL draft: `index=<cdb_events> native_type="dns" host="<web_server_host>" | stats count min(_time) max(_time) by domain, ip | sort -count`
- Purpose: DNS lookups from the web server after exploitation may reveal C2 or payload retrieval domains.

**Step 18 (predicate):** `native_type EQUALS smb`
- SPL draft: `index=<cdb_events> native_type="smb" host="<web_server_host>" | stats count min(_time) max(_time) by host, user, ip, file_path, action, status | sort -count`
- Purpose: SMB activity from the web server after exploitation may indicate lateral movement or staging.

### Phase F — Correlation and limitations (not a predicate step)

**Step 19 (CORRELATION — not a predicate):** Build a single host-scoped timeline using the resolved `<web_server_host>` value.
- SPL draft: `index=<cdb_events> host="<web_server_host>" (native_type="web_request" OR native_type="process_creation" OR native_type="authentication" OR native_type="dns" OR native_type="smb") | sort _time | table _time, native_type, user, ip, image, cmdline, file_path, action, status`
- This step is **explicitly a correlation-only step**, not a predicate. It must not be run as a bare `timestamp EXISTS` (which would match every row). Its purpose is to reconstruct the ordered sequence from the first Joomla web request through any subsequent process/authentication/DNS/SMB activity, so the hunter can distinguish the scan phase from the exploitation phase and from post-exploitation movement.

**Limitations:**
- The available telemetry can show the web request pattern (including Joomla `/joomla/`, `com_search`, `com_mailto` targeting), source IPs, and subsequent host/network activity.
- The available telemetry **cannot directly prove successful RCE or reveal exploit payload content**. Confirmation requires process-creation evidence, command-line artifacts, or downstream network/authentication behavior consistent with code execution following the web request.
- If neither Step 3 nor its fallbacks (Steps 4, 5) return rows, fall back to a broad review of **Step 1** results (all `domain EQUALS imreallynotbatman.com` web requests) and look for unusual paths, request spikes, unusual status codes, or an IP with a very high distinct-path count — that remains the reconnaissance signal even when the specific component strings are absent.
