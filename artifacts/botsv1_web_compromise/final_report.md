# Threat Hunting Investigation Final Account

**Investigation Outcome:** `SUPPORTED` (Adversary Activity Detected)
- **Request ID:** `hunt-botsv1-web-01`
- **Stopping Decision:** `STOP_EXHAUSTED_BY_BUDGET`
- **Hunt Kind:** `HUNT`
- **Objective Statement:** Investigate hypo-hunt-botsv1-web-01-active, hypo-hunt-botsv1-web-01-benign
- **Searched Time Window:** `2016-08-01T00:00:00Z/2016-08-29T23:59:59Z`
- **Target Entities:** `POPULATION / ANY`
- **Impacted Hosts Identified:** `splunk-02`, `we1149srv`
- **Impacted Accounts Identified:** `IIS APPPOOL\DefaultAppPool`, `IIS APPPOOL\joomla`, `NT AUTHORITY\IUSR`, `NT AUTHORITY\NETWORK SERVICE`, `NT AUTHORITY\SYSTEM`, `Window Manager\DWM-3`

---
## Executive Threat Brief

> [!CAUTION]
> **CRITICAL FINDING: Adversary Activity Confirmed.**
> Telemetry verification across observed security logs confirmed the active threat hypothesis:
> *"Attacker compromised web www.imreallynotbatman.com"*.
> Suspicious behavior and anomalous command line executions were detected on impacted host(s): **`splunk-02`, `we1149srv`**
> involving user security context(s): **`IIS APPPOOL\DefaultAppPool`, `IIS APPPOOL\joomla`, `NT AUTHORITY\IUSR`, `NT AUTHORITY\NETWORK SERVICE`, `NT AUTHORITY\SYSTEM`, `Window Manager\DWM-3`**.

**Key Incident Characteristics:**
- **Attack Surface / Vector:** Web application / unauthorized remote command execution.
- **Compromised Target Host(s):** `splunk-02`, `we1149srv`
- **Executed Telemetry Queries:** 9 query executions across provider scopes.
- **Evidence Groups Validated:** 118 distinct evidence cards with verified telemetry falsification criteria.

---
## Investigation Storyline & Execution Timeline

| Phase | Stage Description | Actions & Telemetry Operations | Result / Status |
|---|---|---|---|
| **Phase 1** | **Telemetry Environment Discovery** | Autonomous audit discovered live providers (splunk) and scopes (splunk_botsv1) | Active telemetry indexed |
| **Phase 2** | **Hypothesis Decomposition** | Decomposed hypothesis into testable behavioral requirements (web_request, process_ancestry, file_modification, baseline) | Requirements validated |
| **Phase 3** | **Population Discovery Sweep** | Executed wildcard sweep (`ANY` entity) across telemetry partition to discover candidate hosts | Candidate hosts: `splunk-02`, `we1149srv` |
| **Phase 4** | **Target Host Verification** | Promoted discovered hosts to instance cells; tested falsification predicates | 118 cards verified |
| **Phase 5** | **Termination & Final Accounting** | Reconciled scope coverage, requirement satisfaction, and epistemic disposition | Decision: `STOP_EXHAUSTED_BY_BUDGET` |

---
## 1. Coverage Accounting

> Scope coverage (spatial-temporal telemetry partition cells) is strictly accounted separately
> from requirement coverage (behavioral TTPs). Targeted queries on specific entities do NOT
> mark wildcard broadsweep cells as explored.

### Scope Coverage (Spatial-Temporal Partition Cells)

#### Wildcard Cells (BroadSweep / Population):
- Known: 1
- Explored: 1
- Partial (truncated / split): 0
- Unexplored: 0
- Unqueryable (syntax / permissions / unsupported adapter): 0
- Unreachable (retention expired / missing telemetry): 0

#### Instance Cells (Discovered Concrete Entities):
- Known: 2
- Explored: 2
- Partial: 0
- Unexplored: 0
- Unqueryable: 0
- Unreachable: 0

**Active Scope Coverage Ratio:** 3 / 3 active cells (100.0%)

### Requirement Coverage (Behavioral TTPs)
- **Attempted Requirements (4):** ['req-hunt-botsv1-web-01-web_request', 'req-hunt-botsv1-web-01-process_ancestry', 'req-hunt-botsv1-web-01-file_modification', 'req-hunt-botsv1-web-01-baseline']
- **Satisfied Requirements (4):** ['req-hunt-botsv1-web-01-web_request', 'req-hunt-botsv1-web-01-process_ancestry', 'req-hunt-botsv1-web-01-file_modification', 'req-hunt-botsv1-web-01-baseline']
- **Partial Requirements (0):** []
- **Unsupported Requirements (0):** []
- **Requirement Satisfaction Ratio:** 4 / 4 attempted requirements (100.0%)

- **Unmapped Observations:** 0
- **Unknown Sources (excluded from coverage denominator):** []

---
## 2. Hypotheses Evaluation

| Hypothesis ID | Statement | Origin | Status | Requirements | Source Refs |
|---|---|---|---|---|---|
| `hypo-hunt-botsv1-web-01-active` | Attacker compromised web www.imreallynotbatman.com | `INPUT` | **`SUPPORTED`** | req-hunt-botsv1-web-01-web_request, req-hunt-botsv1-web-01-process_ancestry, req-hunt-botsv1-web-01-file_modification | None |
| `hypo-hunt-botsv1-web-01-benign` | Telemetry reflects normal operational baseline; refuted hypothesis: 'Attacker compromised web www.imreallynotbatman.com' | `RULE` | **`REFUTED`** | req-hunt-botsv1-web-01-baseline | None |

- **Supported Hypotheses:** ['hypo-hunt-botsv1-web-01-active']
- **Competing Viable (Live) Hypotheses:** []
- **Refuted Hypotheses:** ['hypo-hunt-botsv1-web-01-benign']

---
## 3. Key Technical Evidence & Forensic Artifacts

### Evidence Cards Summary
| Host | User Context | Fact Type | Parent Process | Executable / Command / Artifact | Events | Card ID |
|---|---|---|---|---|---|---|
| `splunk-02` | `N/A` | `web_request` | `N/A` | `imreallynotbatman.com` | 196 | `card-be13cd255f96` |
| `we1149srv` | `N/A` | `generic_telemetry` | `N/A` | `N/A` | 92 | `card-85047dc2a924` |
| `we1149srv` | `NT AUTHORITY\IUSR`, `NT AUTHORITY\SYSTEM` | `process_execution` | `sc.exe`, `cmd.exe` | `\??\C:\Windows\system32\conhost.exe 0xffffffff` | 20 | `card-cfbbc54b5383` |
| `we1149srv` | `NT AUTHORITY\NETWORK SERVICE` | `process_execution` | `svchost.exe` | `C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding` | 18 | `card-f40f054614e7` |
| `we1149srv` | `NT AUTHORITY\SYSTEM` | `process_execution` | `svchost.exe` | `C:\Windows\system32\wbem\wmiprvse.exe -Embedding` | 17 | `card-7eaa1c065b10` |
| `splunk-02` | `N/A` | `dns_activity` | `N/A` | `N/A` | 15 | `card-2c573061ec31` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 10 | `card-1bc5eed50fd1` |
| `we1149srv` | `NT AUTHORITY\IUSR` | `process_execution` | `php-cgi.exe` | `cmd.exe /c "dir 2&gt;&amp;1"` | 8 | `card-7670bbd751dd` |
| `we1149srv` | `N/A` | `generic_telemetry` | `N/A` | `N/A` | 5 | `card-89a1580f9ac4` |
| `splunk-02` | `N/A` | `web_request` | `N/A` | `imreallynotbatman.com` | 4 | `card-c7c92b3ea5ed` |
| `we1149srv` | `N/A` | `generic_telemetry` | `N/A` | `N/A` | 3 | `card-0fbe0069c41e` |
| `we1149srv` | `IIS APPPOOL\joomla` | `process_execution` | `w3wp.exe` | `"C:\Program Files (x86)\PHP\v5.5\php-cgi.exe"` | 3 | `card-b778a65522eb` |
| `we1149srv` | `NT AUTHORITY\IUSR` | `process_execution` | `3791.exe` | `C:\Windows\system32\cmd.exe` | 2 | `card-3480760978fe` |
| `splunk-02` | `N/A` | `dns_activity` | `N/A` | `N/A` | 2 | `card-4fd38c42dce4` |
| `we1149srv` | `NT AUTHORITY\IUSR` | `process_execution` | `php-cgi.exe` | `cmd.exe /c "exit 2&gt;&amp;1"` | 2 | `card-a650c09aee42` |
| `we1149srv` | `NT AUTHORITY\IUSR` | `process_execution` | `php-cgi.exe` | `cmd.exe /c "ifconfig 2&gt;&amp;1"` | 1 | `card-008e225a3e48` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-00c5a66b74c4` |
| `we1149srv` | `NT AUTHORITY\IUSR` | `process_execution` | `php-cgi.exe` | `cmd.exe /c "move 2.jpeg imnotbatman.jpg 2&gt;&amp;1"` | 1 | `card-08c6fd6fe656` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-0e6ca2744eee` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-11672dcfcf76` |
| `splunk-02` | `N/A` | `dns_activity` | `N/A` | `N/A` | 1 | `card-145bdd2e2d4d` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-149542736987` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-151c178814dc` |
| `we1149srv` | `NT AUTHORITY\IUSR` | `process_execution` | `php-cgi.exe` | `cmd.exe /c "echo 63059"` | 1 | `card-154dcb7a89f5` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-158b07f6d593` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-16f17947f1e5` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-1700b5c64a1d` |
| `we1149srv` | `NT AUTHORITY\IUSR` | `process_execution` | `cmd.exe` | `3791.exe  ` | 1 | `card-172255cf27f0` |
| `we1149srv` | `NT AUTHORITY\IUSR` | `process_execution` | `cmd.exe` | `net  share` | 1 | `card-180d638595cc` |
| `splunk-02` | `N/A` | `dns_activity` | `N/A` | `N/A` | 1 | `card-1c68c944d17b` |
| `splunk-02` | `N/A` | `dns_activity` | `N/A` | `N/A` | 1 | `card-2187d90060b4` |
| `we1149srv` | `NT AUTHORITY\IUSR` | `process_execution` | `cmd.exe` | `ping  http://prankglassinebracket.jumpingcrab.com:` | 1 | `card-21c919d86902` |
| `we1149srv` | `NT AUTHORITY\IUSR` | `process_execution` | `php-cgi.exe` | `cmd.exe /c "echo 24365"` | 1 | `card-2439c18bc457` |
| `splunk-02` | `N/A` | `dns_activity` | `N/A` | `N/A` | 1 | `card-243b32829f96` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-249acdaba203` |
| `we1149srv` | `NT AUTHORITY\IUSR` | `process_execution` | `php-cgi.exe` | `cmd.exe /c "3791.exe 2&gt;&amp;1"` | 1 | `card-28f16c4a86be` |
| `we1149srv` | `NT AUTHORITY\IUSR` | `process_execution` | `cmd.exe` | `tasklist  ` | 1 | `card-29476e042e06` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-2afbf9ff8b55` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-2d60837e96d0` |
| `we1149srv` | `NT AUTHORITY\SYSTEM` | `process_execution` | `winlogon.exe` | `"LogonUI.exe" /flags:0x0` | 1 | `card-304cc9e714bf` |
| `we1149srv` | `NT AUTHORITY\IUSR` | `process_execution` | `cmd.exe` | `net  use c:\share` | 1 | `card-326e20661ffa` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-334997c04e41` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-33c81ac5ffd6` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-34da3d18fc0d` |
| `splunk-02` | `N/A` | `dns_activity` | `N/A` | `N/A` | 1 | `card-36d84f64c1e7` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-3738d342446a` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-375cb6866a27` |
| `we1149srv` | `NT AUTHORITY\IUSR` | `process_execution` | `cmd.exe` | `whoami` | 1 | `card-378320697d5d` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-3bc382f867cf` |
| `we1149srv` | `NT AUTHORITY\IUSR` | `process_execution` | `cmd.exe` | `help` | 1 | `card-3c79fafebcd4` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-3ca6a10e41b9` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-3dda693aa90d` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-3fbb780a90d5` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-413fa4dafcde` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-48e9ab3d491b` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-4a1b77182701` |
| `we1149srv` | `NT AUTHORITY\IUSR` | `process_execution` | `net.exe` | `C:\Windows\system32\net1  user` | 1 | `card-4a6f5358e285` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-546d56f0ec9f` |
| `we1149srv` | `Window Manager\DWM-3` | `process_execution` | `winlogon.exe` | `"dwm.exe"` | 1 | `card-548921630078` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-5561a836b1fe` |
| `we1149srv` | `NT AUTHORITY\IUSR` | `process_execution` | `cmd.exe` | `nslookup  http://prankglassinebracket.jumpingcrab.` | 1 | `card-55a476288abf` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-5684cac650d8` |
| `splunk-02` | `N/A` | `dns_activity` | `N/A` | `N/A` | 1 | `card-57002323d8f3` |
| `we1149srv` | `NT AUTHORITY\IUSR` | `process_execution` | `cmd.exe` | `find  / "\\"` | 1 | `card-64d596b7d7dc` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-66deac0cc5a8` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-6eba719dcbc6` |
| `we1149srv` | `NT AUTHORITY\IUSR` | `process_execution` | `php-cgi.exe` | `cmd.exe /c "ls 2&gt;&amp;1"` | 1 | `card-768c63505960` |
| `we1149srv` | `NT AUTHORITY\SYSTEM` | `process_execution` | `svchost.exe` | `C:\Windows\system32\sc.exe start wuauserv` | 1 | `card-7c96c36fb430` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-7e12ebd6dfd5` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-82284f1b49fa` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-849824739ba8` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-849e8cbff924` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-856be90f682b` |
| `we1149srv` | `NT AUTHORITY\IUSR` | `process_execution` | `php-cgi.exe` | `cmd.exe /c "move ..\1.jpeg 2.jpeg 2&gt;&amp;1"` | 1 | `card-886e430ccbd2` |
| `we1149srv` | `NT AUTHORITY\IUSR` | `process_execution` | `net.exe` | `C:\Windows\system32\net1  session ` | 1 | `card-8dcd41b28cf1` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-8f6b3f6c8acc` |
| `we1149srv` | `NT AUTHORITY\SYSTEM` | `process_execution` | `smss.exe` | `%SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows Sha...` | 1 | `card-9057a4e27ef3` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-90952a928ec7` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-90b5460ed904` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-99b801a44247` |
| `splunk-02` | `N/A` | `dns_activity` | `N/A` | `N/A` | 1 | `card-9a58ee923f24` |
| `we1149srv` | `NT AUTHORITY\IUSR` | `process_execution` | `cmd.exe` | `net  view /domain` | 1 | `card-9ac5d18b31aa` |
| `splunk-02` | `N/A` | `dns_activity` | `N/A` | `N/A` | 1 | `card-9da9e03dfc9d` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-a08bd2570019` |
| `we1149srv` | `NT AUTHORITY\SYSTEM` | `process_execution` | `smss.exe` | `winlogon.exe` | 1 | `card-a33316bd82ed` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-a8b3934cb3cf` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-b18a3fff8ec6` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-b44c854918a5` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-b5b3588b0535` |
| `we1149srv` | `NT AUTHORITY\IUSR` | `process_execution` | `net.exe` | `C:\Windows\system32\net1  share` | 1 | `card-bef3b6c2091a` |
| `splunk-02` | `N/A` | `dns_activity` | `N/A` | `N/A` | 1 | `card-c150069548b4` |
| `we1149srv` | `NT AUTHORITY\IUSR` | `process_execution` | `cmd.exe` | `net  session ` | 1 | `card-c4722ccd97b7` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-c4e3162dc0f9` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-c6c7a453f0a0` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-c7c8b4d663bb` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-ced92212ac8b` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-d124e591e718` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-e09e91842d89` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-e49155291671` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-e6ea83262176` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-e9ba349dc95f` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-ea1b6113b96b` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-eb51ba17bc89` |
| `we1149srv` | `IIS APPPOOL\DefaultAppPool` | `process_execution` | `svchost.exe` | `c:\windows\system32\inetsrv\w3wp.exe -ap "DefaultAppPool" -v...` | 1 | `card-ebd6304b7fbe` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-ebfe5228e741` |
| `we1149srv` | `NT AUTHORITY\IUSR` | `process_execution` | `cmd.exe` | `net  user` | 1 | `card-ecff65ad3e50` |
| `we1149srv` | `NT AUTHORITY\IUSR` | `process_execution` | `cmd.exe` | `nslookup  prankglassinebracket.jumpingcrab.com` | 1 | `card-ed3631c3c307` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-ed9e3a02724e` |
| `splunk-02` | `N/A` | `dns_activity` | `N/A` | `N/A` | 1 | `card-eddf35f4aa5a` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-f16cadf1d19c` |
| `splunk-02` | `N/A` | `dns_activity` | `N/A` | `N/A` | 1 | `card-f59b76aecff9` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-f70a8198f28b` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-f8b9d90f9f1f` |
| `we1149srv` | `NT AUTHORITY\SYSTEM` | `process_execution` | `smss.exe` | `\SystemRoot\System32\smss.exe 00000000 00000050 ` | 1 | `card-fbe7e7601b6c` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-fcbfe3b58429` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-fe66df7f1ff1` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-fe798d8a8803` |
| `splunk-02` | `N/A` | `network_connection` | `N/A` | `N/A` | 1 | `card-ff2402dacce4` |

### Detailed Evidence Breakdown

#### Evidence Card: `card-be13cd255f96` (web_request)
- **Fingerprint:** `be13cd255f960f330a9f8fff...`
- **Event Count:** 196 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T22:22:12.403+00:00` to `2016-08-10T22:22:27.612+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.250.70`; **domains:** `imreallynotbatman.com`
- **Observed Domains/Queries:** `imreallynotbatman.com`

#### Evidence Card: `card-85047dc2a924` (generic_telemetry)
- **Fingerprint:** `85047dc2a924e33596ad0c54...`
- **Event Count:** 92 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-24T18:27:01.000+00:00` to `2016-08-24T18:27:03.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`

#### Evidence Card: `card-cfbbc54b5383` (process_execution)
- **Fingerprint:** `cfbbc54b53837e1e0ca882c4...`
- **Event Count:** 20 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T21:55:22.000+00:00` to `2016-08-24T18:16:49.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\IUSR`, `NT AUTHORITY\SYSTEM`
- **Parent Process(es):** `C:\Windows\System32\sc.exe`, `C:\Windows\SysWOW64\cmd.exe`
- **Image/Process Executable(s):** `C:\Windows\System32\conhost.exe`
- **Observed Command Lines:**
  ```shell
  \??\C:\Windows\system32\conhost.exe 0xffffffff
  ```

#### Evidence Card: `card-f40f054614e7` (process_execution)
- **Fingerprint:** `f40f054614e7ad2add6e24c1...`
- **Event Count:** 18 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T21:55:50.000+00:00` to `2016-08-24T18:25:15.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\NETWORK SERVICE`
- **Parent Process(es):** `C:\Windows\System32\svchost.exe`
- **Image/Process Executable(s):** `C:\Windows\System32\wbem\WmiPrvSE.exe`
- **Observed Command Lines:**
  ```shell
  C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding
  ```

#### Evidence Card: `card-7eaa1c065b10` (process_execution)
- **Fingerprint:** `7eaa1c065b10d65a6fa7c8fd...`
- **Event Count:** 17 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T21:55:51.000+00:00` to `2016-08-24T18:25:17.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\SYSTEM`
- **Parent Process(es):** `C:\Windows\System32\svchost.exe`
- **Image/Process Executable(s):** `C:\Windows\System32\wbem\WmiPrvSE.exe`
- **Observed Command Lines:**
  ```shell
  C:\Windows\system32\wbem\wmiprvse.exe -Embedding
  ```

#### Evidence Card: `card-2c573061ec31` (dns_activity)
- **Fingerprint:** `2c573061ec316facbdc76d1d...`
- **Event Count:** 15 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:20.003+00:00` to `2016-08-28T23:58:58.693+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `8.8.8.8`

#### Evidence Card: `card-1bc5eed50fd1` (network_connection)
- **Fingerprint:** `1bc5eed50fd1b86b4dfbeaca...`
- **Event Count:** 10 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:32.706+00:00` to `2016-08-28T23:59:00.318+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `8.8.8.8`

#### Evidence Card: `card-7670bbd751dd` (process_execution)
- **Fingerprint:** `7670bbd751ddf9cad1a8c919...`
- **Event Count:** 8 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T21:55:24.000+00:00` to `2016-08-10T22:20:13.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\IUSR`
- **Parent Process(es):** `C:\Program Files (x86)\PHP\v5.5\php-cgi.exe`
- **Image/Process Executable(s):** `C:\Windows\SysWOW64\cmd.exe`
- **Observed Command Lines:**
  ```shell
  cmd.exe /c "dir 2&gt;&amp;1"
  ```

#### Evidence Card: `card-89a1580f9ac4` (generic_telemetry)
- **Fingerprint:** `89a1580f9ac4780e7412a2c7...`
- **Event Count:** 5 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-24T18:27:02.000+00:00` to `2016-08-24T18:27:30.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`

#### Evidence Card: `card-c7c92b3ea5ed` (web_request)
- **Fingerprint:** `c7c92b3ea5ed7e9eae7f9cc8...`
- **Event Count:** 4 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T22:22:20.271+00:00` to `2016-08-10T22:22:22.857+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.250.70`; **domains:** `imreallynotbatman.com`
- **Observed Domains/Queries:** `imreallynotbatman.com`

#### Evidence Card: `card-0fbe0069c41e` (generic_telemetry)
- **Fingerprint:** `0fbe0069c41e157586d2a1af...`
- **Event Count:** 3 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-24T18:27:30.000+00:00` to `2016-08-24T18:27:30.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`

#### Evidence Card: `card-b778a65522eb` (process_execution)
- **Fingerprint:** `b778a65522eba3431137ce78...`
- **Event Count:** 3 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T21:46:28.000+00:00` to `2016-08-10T22:16:27.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `IIS APPPOOL\joomla`
- **Parent Process(es):** `C:\Windows\System32\inetsrv\w3wp.exe`
- **Image/Process Executable(s):** `C:\Program Files (x86)\PHP\v5.5\php-cgi.exe`
- **Observed Command Lines:**
  ```shell
  "C:\Program Files (x86)\PHP\v5.5\php-cgi.exe"
  ```

#### Evidence Card: `card-3480760978fe` (process_execution)
- **Fingerprint:** `3480760978fe813fc87b5282...`
- **Event Count:** 2 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T21:58:23.000+00:00` to `2016-08-10T22:08:13.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\IUSR`
- **Parent Process(es):** `C:\inetpub\wwwroot\joomla\3791.exe`
- **Image/Process Executable(s):** `C:\Windows\SysWOW64\cmd.exe`
- **Observed Command Lines:**
  ```shell
  C:\Windows\system32\cmd.exe
  ```

#### Evidence Card: `card-4fd38c42dce4` (dns_activity)
- **Fingerprint:** `4fd38c42dce41ae943338525...`
- **Event Count:** 2 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:34.227+00:00` to `2016-08-28T23:58:39.566+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `224.0.0.252`

#### Evidence Card: `card-a650c09aee42` (process_execution)
- **Fingerprint:** `a650c09aee425e1d0507ac7d...`
- **Event Count:** 2 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T22:21:31.000+00:00` to `2016-08-10T22:21:34.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\IUSR`
- **Parent Process(es):** `C:\Program Files (x86)\PHP\v5.5\php-cgi.exe`
- **Image/Process Executable(s):** `C:\Windows\SysWOW64\cmd.exe`
- **Observed Command Lines:**
  ```shell
  cmd.exe /c "exit 2&gt;&amp;1"
  ```

#### Evidence Card: `card-008e225a3e48` (process_execution)
- **Fingerprint:** `008e225a3e485335a66b0df5...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T21:55:33.000+00:00` to `2016-08-10T21:55:33.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\IUSR`
- **Parent Process(es):** `C:\Program Files (x86)\PHP\v5.5\php-cgi.exe`
- **Image/Process Executable(s):** `C:\Windows\SysWOW64\cmd.exe`
- **Observed Command Lines:**
  ```shell
  cmd.exe /c "ifconfig 2&gt;&amp;1"
  ```

#### Evidence Card: `card-00c5a66b74c4` (network_connection)
- **Fingerprint:** `00c5a66b74c4a42eafd9d90b...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:22.129+00:00` to `2016-08-28T23:58:22.129+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.228.6`

#### Evidence Card: `card-08c6fd6fe656` (process_execution)
- **Fingerprint:** `08c6fd6fe656bd0a84440db3...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T22:20:33.000+00:00` to `2016-08-10T22:20:33.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\IUSR`
- **Parent Process(es):** `C:\Program Files (x86)\PHP\v5.5\php-cgi.exe`
- **Image/Process Executable(s):** `C:\Windows\SysWOW64\cmd.exe`
- **Observed Command Lines:**
  ```shell
  cmd.exe /c "move 2.jpeg imnotbatman.jpg 2&gt;&amp;1"
  ```

#### Evidence Card: `card-0e6ca2744eee` (network_connection)
- **Fingerprint:** `0e6ca2744eee337cd720f2ca...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:54.429+00:00` to `2016-08-28T23:58:54.429+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.225.156`

#### Evidence Card: `card-11672dcfcf76` (network_connection)
- **Fingerprint:** `11672dcfcf761de56d07b770...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:30.546+00:00` to `2016-08-28T23:58:30.546+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.224.58`

#### Evidence Card: `card-145bdd2e2d4d` (dns_activity)
- **Fingerprint:** `145bdd2e2d4d9b1c8dbfa596...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:57.452+00:00` to `2016-08-28T23:58:57.452+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.227.133`

#### Evidence Card: `card-149542736987` (network_connection)
- **Fingerprint:** `1495427369879f9d52aed408...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:37.273+00:00` to `2016-08-28T23:58:37.273+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.230.177`

#### Evidence Card: `card-151c178814dc` (network_connection)
- **Fingerprint:** `151c178814dcf8090bf7cca5...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:28.795+00:00` to `2016-08-28T23:58:28.795+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.226.224`

#### Evidence Card: `card-154dcb7a89f5` (process_execution)
- **Fingerprint:** `154dcb7a89f544125acdf732...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T22:05:42.000+00:00` to `2016-08-10T22:05:42.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\IUSR`
- **Parent Process(es):** `C:\Program Files (x86)\PHP\v5.5\php-cgi.exe`
- **Image/Process Executable(s):** `C:\Windows\SysWOW64\cmd.exe`
- **Observed Command Lines:**
  ```shell
  cmd.exe /c "echo 63059"
  ```

#### Evidence Card: `card-158b07f6d593` (network_connection)
- **Fingerprint:** `158b07f6d5930f512d58e6f7...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:38.917+00:00` to `2016-08-28T23:58:38.917+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.228.206`

#### Evidence Card: `card-16f17947f1e5` (network_connection)
- **Fingerprint:** `16f17947f1e5d550f5b1ac72...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:52.503+00:00` to `2016-08-28T23:58:52.503+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `23.203.184.161`

#### Evidence Card: `card-1700b5c64a1d` (network_connection)
- **Fingerprint:** `1700b5c64a1d13fa87a66332...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:47.413+00:00` to `2016-08-28T23:58:47.413+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.231.50`

#### Evidence Card: `card-172255cf27f0` (process_execution)
- **Fingerprint:** `172255cf27f0105bfbb6886d...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T21:56:18.000+00:00` to `2016-08-10T21:56:18.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\IUSR`
- **Parent Process(es):** `C:\Windows\SysWOW64\cmd.exe`
- **Image/Process Executable(s):** `C:\inetpub\wwwroot\joomla\3791.exe`
- **Observed Command Lines:**
  ```shell
  3791.exe  
  ```

#### Evidence Card: `card-180d638595cc` (process_execution)
- **Fingerprint:** `180d638595cc0f52fbc0dc58...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T21:58:37.000+00:00` to `2016-08-10T21:58:37.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\IUSR`
- **Parent Process(es):** `C:\Windows\SysWOW64\cmd.exe`
- **Image/Process Executable(s):** `C:\Windows\SysWOW64\net.exe`
- **Observed Command Lines:**
  ```shell
  net  share
  ```

#### Evidence Card: `card-1c68c944d17b` (dns_activity)
- **Fingerprint:** `1c68c944d17bf18ff6a14bf0...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:49.197+00:00` to `2016-08-28T23:58:49.197+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.225.193`

#### Evidence Card: `card-2187d90060b4` (dns_activity)
- **Fingerprint:** `2187d90060b4a9f0281ed98e...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:46.011+00:00` to `2016-08-28T23:58:46.011+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.228.152`

#### Evidence Card: `card-21c919d86902` (process_execution)
- **Fingerprint:** `21c919d86902458d6ccefe3b...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T22:11:06.000+00:00` to `2016-08-10T22:11:06.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\IUSR`
- **Parent Process(es):** `C:\Windows\SysWOW64\cmd.exe`
- **Image/Process Executable(s):** `C:\Windows\SysWOW64\PING.EXE`
- **Observed Command Lines:**
  ```shell
  ping  http://prankglassinebracket.jumpingcrab.com:
  ```

#### Evidence Card: `card-2439c18bc457` (process_execution)
- **Fingerprint:** `2439c18bc457f6ed5d0e19c7...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T21:55:22.000+00:00` to `2016-08-10T21:55:22.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\IUSR`
- **Parent Process(es):** `C:\Program Files (x86)\PHP\v5.5\php-cgi.exe`
- **Image/Process Executable(s):** `C:\Windows\SysWOW64\cmd.exe`
- **Observed Command Lines:**
  ```shell
  cmd.exe /c "echo 24365"
  ```

#### Evidence Card: `card-243b32829f96` (dns_activity)
- **Fingerprint:** `243b32829f96842aca509ce9...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:34.330+00:00` to `2016-08-28T23:58:34.330+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.227.144`

#### Evidence Card: `card-249acdaba203` (network_connection)
- **Fingerprint:** `249acdaba2035a35c566329b...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:51.631+00:00` to `2016-08-28T23:58:51.631+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.229.165`

#### Evidence Card: `card-28f16c4a86be` (process_execution)
- **Fingerprint:** `28f16c4a86be4880e316820a...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T21:56:18.000+00:00` to `2016-08-10T21:56:18.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\IUSR`
- **Parent Process(es):** `C:\Program Files (x86)\PHP\v5.5\php-cgi.exe`
- **Image/Process Executable(s):** `C:\Windows\SysWOW64\cmd.exe`
- **Observed Command Lines:**
  ```shell
  cmd.exe /c "3791.exe 2&gt;&amp;1"
  ```

#### Evidence Card: `card-29476e042e06` (process_execution)
- **Fingerprint:** `29476e042e06b9c8589c8cb2...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T22:17:22.000+00:00` to `2016-08-10T22:17:22.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\IUSR`
- **Parent Process(es):** `C:\Windows\SysWOW64\cmd.exe`
- **Image/Process Executable(s):** `C:\Windows\SysWOW64\tasklist.exe`
- **Observed Command Lines:**
  ```shell
  tasklist  
  ```

#### Evidence Card: `card-2afbf9ff8b55` (network_connection)
- **Fingerprint:** `2afbf9ff8b55fe3877b54ad5...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:38.273+00:00` to `2016-08-28T23:58:38.273+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.224.44`

#### Evidence Card: `card-2d60837e96d0` (network_connection)
- **Fingerprint:** `2d60837e96d0777fab27ecfd...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:55.278+00:00` to `2016-08-28T23:58:55.278+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.224.23`

#### Evidence Card: `card-304cc9e714bf` (process_execution)
- **Fingerprint:** `304cc9e714bfbfd547b51a37...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-24T16:36:25.000+00:00` to `2016-08-24T16:36:25.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\SYSTEM`
- **Parent Process(es):** `C:\Windows\System32\winlogon.exe`
- **Image/Process Executable(s):** `C:\Windows\System32\LogonUI.exe`
- **Observed Command Lines:**
  ```shell
  "LogonUI.exe" /flags:0x0
  ```

#### Evidence Card: `card-326e20661ffa` (process_execution)
- **Fingerprint:** `326e20661ffaed4ea131e14e...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T21:59:12.000+00:00` to `2016-08-10T21:59:12.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\IUSR`
- **Parent Process(es):** `C:\Windows\SysWOW64\cmd.exe`
- **Image/Process Executable(s):** `C:\Windows\SysWOW64\net.exe`
- **Observed Command Lines:**
  ```shell
  net  use c:\share
  ```

#### Evidence Card: `card-334997c04e41` (network_connection)
- **Fingerprint:** `334997c04e4195535797ce9d...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:38.753+00:00` to `2016-08-28T23:58:38.753+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `191.232.139.214`

#### Evidence Card: `card-33c81ac5ffd6` (network_connection)
- **Fingerprint:** `33c81ac5ffd625599a16f676...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:44.849+00:00` to `2016-08-28T23:58:44.849+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.224.35`

#### Evidence Card: `card-34da3d18fc0d` (network_connection)
- **Fingerprint:** `34da3d18fc0d0feb38e61e42...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:19.916+00:00` to `2016-08-28T23:58:19.916+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.228.179`

#### Evidence Card: `card-36d84f64c1e7` (dns_activity)
- **Fingerprint:** `36d84f64c1e77f81030fe86e...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:25.105+00:00` to `2016-08-28T23:58:25.105+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.230.212`

#### Evidence Card: `card-3738d342446a` (network_connection)
- **Fingerprint:** `3738d342446ab42ad006a6cb...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:43.253+00:00` to `2016-08-28T23:58:43.253+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.230.214`

#### Evidence Card: `card-375cb6866a27` (network_connection)
- **Fingerprint:** `375cb6866a27bef7415514d7...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:22.716+00:00` to `2016-08-28T23:58:22.716+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.228.236`

#### Evidence Card: `card-378320697d5d` (process_execution)
- **Fingerprint:** `378320697d5d518f8ea82de5...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T21:58:30.000+00:00` to `2016-08-10T21:58:30.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\IUSR`
- **Parent Process(es):** `C:\Windows\SysWOW64\cmd.exe`
- **Image/Process Executable(s):** `C:\Windows\SysWOW64\whoami.exe`
- **Observed Command Lines:**
  ```shell
  whoami
  ```

#### Evidence Card: `card-3bc382f867cf` (network_connection)
- **Fingerprint:** `3bc382f867cfbce310771936...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:51.052+00:00` to `2016-08-28T23:58:51.052+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.227.176`

#### Evidence Card: `card-3c79fafebcd4` (process_execution)
- **Fingerprint:** `3c79fafebcd4a98566fdc53d...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T22:17:17.000+00:00` to `2016-08-10T22:17:17.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\IUSR`
- **Parent Process(es):** `C:\Windows\SysWOW64\cmd.exe`
- **Image/Process Executable(s):** `C:\Windows\SysWOW64\help.exe`
- **Observed Command Lines:**
  ```shell
  help
  ```

#### Evidence Card: `card-3ca6a10e41b9` (network_connection)
- **Fingerprint:** `3ca6a10e41b96bf93b3e02f2...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:47.239+00:00` to `2016-08-28T23:58:47.239+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.230.30`

#### Evidence Card: `card-3dda693aa90d` (network_connection)
- **Fingerprint:** `3dda693aa90d8049d4567d8e...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:45.980+00:00` to `2016-08-28T23:58:45.980+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.228.234`

#### Evidence Card: `card-3fbb780a90d5` (network_connection)
- **Fingerprint:** `3fbb780a90d5f9c566002e72...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:32.921+00:00` to `2016-08-28T23:58:32.921+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.224.49`

#### Evidence Card: `card-413fa4dafcde` (network_connection)
- **Fingerprint:** `413fa4dafcdeb85f45a39071...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:52.840+00:00` to `2016-08-28T23:58:52.840+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.226.220`

#### Evidence Card: `card-48e9ab3d491b` (network_connection)
- **Fingerprint:** `48e9ab3d491b07a1a9361094...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:39.465+00:00` to `2016-08-28T23:58:39.465+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.229.0`

#### Evidence Card: `card-4a1b77182701` (network_connection)
- **Fingerprint:** `4a1b771827018a58ce887c19...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:20.475+00:00` to `2016-08-28T23:58:20.475+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.226.191`

#### Evidence Card: `card-4a6f5358e285` (process_execution)
- **Fingerprint:** `4a6f5358e2856219ccf7515a...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T21:58:59.000+00:00` to `2016-08-10T21:58:59.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\IUSR`
- **Parent Process(es):** `C:\Windows\SysWOW64\net.exe`
- **Image/Process Executable(s):** `C:\Windows\SysWOW64\net1.exe`
- **Observed Command Lines:**
  ```shell
  C:\Windows\system32\net1  user
  ```

#### Evidence Card: `card-546d56f0ec9f` (network_connection)
- **Fingerprint:** `546d56f0ec9f590cd29b8f4d...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:57.669+00:00` to `2016-08-28T23:58:57.669+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.224.78`

#### Evidence Card: `card-548921630078` (process_execution)
- **Fingerprint:** `5489216300787352c12b6b95...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-24T16:36:26.000+00:00` to `2016-08-24T16:36:26.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `Window Manager\DWM-3`
- **Parent Process(es):** `C:\Windows\System32\winlogon.exe`
- **Image/Process Executable(s):** `C:\Windows\System32\dwm.exe`
- **Observed Command Lines:**
  ```shell
  "dwm.exe"
  ```

#### Evidence Card: `card-5561a836b1fe` (network_connection)
- **Fingerprint:** `5561a836b1fe044b5cf3fe05...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:16.832+00:00` to `2016-08-28T23:58:16.832+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.228.73`

#### Evidence Card: `card-55a476288abf` (process_execution)
- **Fingerprint:** `55a476288abff4a71c180736...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T22:11:23.000+00:00` to `2016-08-10T22:11:23.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\IUSR`
- **Parent Process(es):** `C:\Windows\SysWOW64\cmd.exe`
- **Image/Process Executable(s):** `C:\Windows\SysWOW64\nslookup.exe`
- **Observed Command Lines:**
  ```shell
  nslookup  http://prankglassinebracket.jumpingcrab.
  ```

#### Evidence Card: `card-5684cac650d8` (network_connection)
- **Fingerprint:** `5684cac650d8a031265c2d78...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:19.714+00:00` to `2016-08-28T23:58:19.714+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.230.171`

#### Evidence Card: `card-57002323d8f3` (dns_activity)
- **Fingerprint:** `57002323d8f393b1317b8af8...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:59:00.105+00:00` to `2016-08-28T23:59:00.105+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.225.44`

#### Evidence Card: `card-64d596b7d7dc` (process_execution)
- **Fingerprint:** `64d596b7d7dc8842383cf395...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T21:58:50.000+00:00` to `2016-08-10T21:58:50.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\IUSR`
- **Parent Process(es):** `C:\Windows\SysWOW64\cmd.exe`
- **Image/Process Executable(s):** `C:\Windows\SysWOW64\find.exe`
- **Observed Command Lines:**
  ```shell
  find  / "\\"
  ```

#### Evidence Card: `card-66deac0cc5a8` (network_connection)
- **Fingerprint:** `66deac0cc5a8cda15f177722...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:49.145+00:00` to `2016-08-28T23:58:49.145+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.230.162`

#### Evidence Card: `card-6eba719dcbc6` (network_connection)
- **Fingerprint:** `6eba719dcbc669fa3ed9b237...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:27.510+00:00` to `2016-08-28T23:58:27.510+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.226.68`

#### Evidence Card: `card-768c63505960` (process_execution)
- **Fingerprint:** `768c63505960c02843ba31c2...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T21:55:26.000+00:00` to `2016-08-10T21:55:26.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\IUSR`
- **Parent Process(es):** `C:\Program Files (x86)\PHP\v5.5\php-cgi.exe`
- **Image/Process Executable(s):** `C:\Windows\SysWOW64\cmd.exe`
- **Observed Command Lines:**
  ```shell
  cmd.exe /c "ls 2&gt;&amp;1"
  ```

#### Evidence Card: `card-7c96c36fb430` (process_execution)
- **Fingerprint:** `7c96c36fb430b321f6b6befa...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-24T18:16:49.000+00:00` to `2016-08-24T18:16:49.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\SYSTEM`
- **Parent Process(es):** `C:\Windows\System32\svchost.exe`
- **Image/Process Executable(s):** `C:\Windows\System32\sc.exe`
- **Observed Command Lines:**
  ```shell
  C:\Windows\system32\sc.exe start wuauserv
  ```

#### Evidence Card: `card-7e12ebd6dfd5` (network_connection)
- **Fingerprint:** `7e12ebd6dfd5f67f07fd4626...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:54.479+00:00` to `2016-08-28T23:58:54.479+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.228.88`

#### Evidence Card: `card-82284f1b49fa` (network_connection)
- **Fingerprint:** `82284f1b49fa1f01cd303a3a...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:32.543+00:00` to `2016-08-28T23:58:32.543+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.229.165`

#### Evidence Card: `card-849824739ba8` (network_connection)
- **Fingerprint:** `849824739ba84f846ffbf3cb...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:37.754+00:00` to `2016-08-28T23:58:37.754+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.230.164`

#### Evidence Card: `card-849e8cbff924` (network_connection)
- **Fingerprint:** `849e8cbff924e70843921a92...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:18.057+00:00` to `2016-08-28T23:58:18.057+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.227.232`

#### Evidence Card: `card-856be90f682b` (network_connection)
- **Fingerprint:** `856be90f682bf4d9adee75d7...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:36.009+00:00` to `2016-08-28T23:58:36.009+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.230.7`

#### Evidence Card: `card-886e430ccbd2` (process_execution)
- **Fingerprint:** `886e430ccbd2053b5e485db4...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T22:20:10.000+00:00` to `2016-08-10T22:20:10.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\IUSR`
- **Parent Process(es):** `C:\Program Files (x86)\PHP\v5.5\php-cgi.exe`
- **Image/Process Executable(s):** `C:\Windows\SysWOW64\cmd.exe`
- **Observed Command Lines:**
  ```shell
  cmd.exe /c "move ..\1.jpeg 2.jpeg 2&gt;&amp;1"
  ```

#### Evidence Card: `card-8dcd41b28cf1` (process_execution)
- **Fingerprint:** `8dcd41b28cf14d2d9d528b4b...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T21:58:50.000+00:00` to `2016-08-10T21:58:50.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\IUSR`
- **Parent Process(es):** `C:\Windows\SysWOW64\net.exe`
- **Image/Process Executable(s):** `C:\Windows\SysWOW64\net1.exe`
- **Observed Command Lines:**
  ```shell
  C:\Windows\system32\net1  session 
  ```

#### Evidence Card: `card-8f6b3f6c8acc` (network_connection)
- **Fingerprint:** `8f6b3f6c8acc9d56489b103c...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:44.157+00:00` to `2016-08-28T23:58:44.157+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.230.151`

#### Evidence Card: `card-9057a4e27ef3` (process_execution)
- **Fingerprint:** `9057a4e27ef326232d3b770c...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-24T16:36:24.000+00:00` to `2016-08-24T16:36:24.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\SYSTEM`
- **Parent Process(es):** `C:\Windows\System32\smss.exe`
- **Image/Process Executable(s):** `C:\Windows\System32\csrss.exe`
- **Observed Command Lines:**
  ```shell
  %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16
  ```

#### Evidence Card: `card-90952a928ec7` (network_connection)
- **Fingerprint:** `90952a928ec7de359bea0f45...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:53.611+00:00` to `2016-08-28T23:58:53.611+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.226.95`

#### Evidence Card: `card-90b5460ed904` (network_connection)
- **Fingerprint:** `90b5460ed904e43ea2b55e3e...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:30.296+00:00` to `2016-08-28T23:58:30.296+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.229.229`

#### Evidence Card: `card-99b801a44247` (network_connection)
- **Fingerprint:** `99b801a442475ea73d49c10b...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:45.429+00:00` to `2016-08-28T23:58:45.429+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.229.207`

#### Evidence Card: `card-9a58ee923f24` (dns_activity)
- **Fingerprint:** `9a58ee923f240a47b40b9816...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:44.351+00:00` to `2016-08-28T23:58:44.351+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.229.241`

#### Evidence Card: `card-9ac5d18b31aa` (process_execution)
- **Fingerprint:** `9ac5d18b31aaaa1576427e75...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T21:58:28.000+00:00` to `2016-08-10T21:58:28.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\IUSR`
- **Parent Process(es):** `C:\Windows\SysWOW64\cmd.exe`
- **Image/Process Executable(s):** `C:\Windows\SysWOW64\net.exe`
- **Observed Command Lines:**
  ```shell
  net  view /domain
  ```

#### Evidence Card: `card-9da9e03dfc9d` (dns_activity)
- **Fingerprint:** `9da9e03dfc9d00ec36efddab...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:26.691+00:00` to `2016-08-28T23:58:26.691+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.230.40`

#### Evidence Card: `card-a08bd2570019` (network_connection)
- **Fingerprint:** `a08bd25700191330782d3e8d...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:21.929+00:00` to `2016-08-28T23:58:21.929+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.226.123`

#### Evidence Card: `card-a33316bd82ed` (process_execution)
- **Fingerprint:** `a33316bd82ed8b433cd084dc...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-24T16:36:24.000+00:00` to `2016-08-24T16:36:24.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\SYSTEM`
- **Parent Process(es):** `C:\Windows\System32\smss.exe`
- **Image/Process Executable(s):** `C:\Windows\System32\winlogon.exe`
- **Observed Command Lines:**
  ```shell
  winlogon.exe
  ```

#### Evidence Card: `card-a8b3934cb3cf` (network_connection)
- **Fingerprint:** `a8b3934cb3cfac54bb89540c...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:23.677+00:00` to `2016-08-28T23:58:23.677+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.225.36`

#### Evidence Card: `card-b18a3fff8ec6` (network_connection)
- **Fingerprint:** `b18a3fff8ec6f15f884b5e24...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:37.256+00:00` to `2016-08-28T23:58:37.256+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.231.37`

#### Evidence Card: `card-b44c854918a5` (network_connection)
- **Fingerprint:** `b44c854918a5e56b910f9a65...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:43.266+00:00` to `2016-08-28T23:58:43.266+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.225.80`

#### Evidence Card: `card-b5b3588b0535` (network_connection)
- **Fingerprint:** `b5b3588b0535736ecc7a368e...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:32.819+00:00` to `2016-08-28T23:58:32.819+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.228.36`

#### Evidence Card: `card-bef3b6c2091a` (process_execution)
- **Fingerprint:** `bef3b6c2091ad05f0c71ad8a...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T21:58:37.000+00:00` to `2016-08-10T21:58:37.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\IUSR`
- **Parent Process(es):** `C:\Windows\SysWOW64\net.exe`
- **Image/Process Executable(s):** `C:\Windows\SysWOW64\net1.exe`
- **Observed Command Lines:**
  ```shell
  C:\Windows\system32\net1  share
  ```

#### Evidence Card: `card-c150069548b4` (dns_activity)
- **Fingerprint:** `c150069548b4035bff6f196e...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:23.745+00:00` to `2016-08-28T23:58:23.745+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.227.232`

#### Evidence Card: `card-c4722ccd97b7` (process_execution)
- **Fingerprint:** `c4722ccd97b72a37d51e2ab7...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T21:58:50.000+00:00` to `2016-08-10T21:58:50.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\IUSR`
- **Parent Process(es):** `C:\Windows\SysWOW64\cmd.exe`
- **Image/Process Executable(s):** `C:\Windows\SysWOW64\net.exe`
- **Observed Command Lines:**
  ```shell
  net  session 
  ```

#### Evidence Card: `card-c4e3162dc0f9` (network_connection)
- **Fingerprint:** `c4e3162dc0f98ad6bf39df42...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:51.792+00:00` to `2016-08-28T23:58:51.792+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.227.198`

#### Evidence Card: `card-c6c7a453f0a0` (network_connection)
- **Fingerprint:** `c6c7a453f0a0495a9e2dd6af...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:44.350+00:00` to `2016-08-28T23:58:44.350+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.230.27`

#### Evidence Card: `card-c7c8b4d663bb` (network_connection)
- **Fingerprint:** `c7c8b4d663bb212950fc848d...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:32.908+00:00` to `2016-08-28T23:58:32.908+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.227.112`

#### Evidence Card: `card-ced92212ac8b` (network_connection)
- **Fingerprint:** `ced92212ac8bfe2bba1a7bd3...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:18.806+00:00` to `2016-08-28T23:58:18.806+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.227.24`

#### Evidence Card: `card-d124e591e718` (network_connection)
- **Fingerprint:** `d124e591e718aa7e5ae50d4c...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:49.106+00:00` to `2016-08-28T23:58:49.106+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.224.47`

#### Evidence Card: `card-e09e91842d89` (network_connection)
- **Fingerprint:** `e09e91842d89fdf525018244...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:59:00.611+00:00` to `2016-08-28T23:59:00.611+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.228.189`

#### Evidence Card: `card-e49155291671` (network_connection)
- **Fingerprint:** `e49155291671fcc35a06c7dd...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:43.722+00:00` to `2016-08-28T23:58:43.722+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.226.109`

#### Evidence Card: `card-e6ea83262176` (network_connection)
- **Fingerprint:** `e6ea8326217628d2a301c6da...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:38.624+00:00` to `2016-08-28T23:58:38.624+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.224.23`

#### Evidence Card: `card-e9ba349dc95f` (network_connection)
- **Fingerprint:** `e9ba349dc95f5d4d5e16affc...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:31.353+00:00` to `2016-08-28T23:58:31.353+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.231.10`

#### Evidence Card: `card-ea1b6113b96b` (network_connection)
- **Fingerprint:** `ea1b6113b96b3950c0e60f73...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:42.912+00:00` to `2016-08-28T23:58:42.912+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.228.148`

#### Evidence Card: `card-eb51ba17bc89` (network_connection)
- **Fingerprint:** `eb51ba17bc895a80ad48750e...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:43.028+00:00` to `2016-08-28T23:58:43.028+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.228.219`

#### Evidence Card: `card-ebd6304b7fbe` (process_execution)
- **Fingerprint:** `ebd6304b7fbedf5c4f25491f...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-24T16:33:46.000+00:00` to `2016-08-24T16:33:46.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `IIS APPPOOL\DefaultAppPool`
- **Parent Process(es):** `C:\Windows\System32\svchost.exe`
- **Image/Process Executable(s):** `C:\Windows\System32\inetsrv\w3wp.exe`
- **Observed Command Lines:**
  ```shell
  c:\windows\system32\inetsrv\w3wp.exe -ap "DefaultAppPool" -v "v4.0" -l "webengine4.dll" -a \\.\pipe\iisipm45a13fae-8ca5-408b-a9e4-631fc0631086 -h "C:\inetpub\temp\apppools\DefaultAppPool\DefaultAppPool.config" -w "" -m 0 -t 20 -ta 0
  ```

#### Evidence Card: `card-ebfe5228e741` (network_connection)
- **Fingerprint:** `ebfe5228e741edaff210988f...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:42.794+00:00` to `2016-08-28T23:58:42.794+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `204.79.197.200`

#### Evidence Card: `card-ecff65ad3e50` (process_execution)
- **Fingerprint:** `ecff65ad3e50d8619ec57612...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T21:58:59.000+00:00` to `2016-08-10T21:58:59.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\IUSR`
- **Parent Process(es):** `C:\Windows\SysWOW64\cmd.exe`
- **Image/Process Executable(s):** `C:\Windows\SysWOW64\net.exe`
- **Observed Command Lines:**
  ```shell
  net  user
  ```

#### Evidence Card: `card-ed3631c3c307` (process_execution)
- **Fingerprint:** `ed3631c3c307d9b382c7138b...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-10T22:11:30.000+00:00` to `2016-08-10T22:11:30.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\IUSR`
- **Parent Process(es):** `C:\Windows\SysWOW64\cmd.exe`
- **Image/Process Executable(s):** `C:\Windows\SysWOW64\nslookup.exe`
- **Observed Command Lines:**
  ```shell
  nslookup  prankglassinebracket.jumpingcrab.com
  ```

#### Evidence Card: `card-ed9e3a02724e` (network_connection)
- **Fingerprint:** `ed9e3a02724eddc541ef8e1c...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:41.902+00:00` to `2016-08-28T23:58:41.902+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.227.12`

#### Evidence Card: `card-eddf35f4aa5a` (dns_activity)
- **Fingerprint:** `eddf35f4aa5a9af931312974...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:51.230+00:00` to `2016-08-28T23:58:51.230+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.227.200`

#### Evidence Card: `card-f16cadf1d19c` (network_connection)
- **Fingerprint:** `f16cadf1d19c9456eac47fb8...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:27.933+00:00` to `2016-08-28T23:58:27.933+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.230.170`

#### Evidence Card: `card-f59b76aecff9` (dns_activity)
- **Fingerprint:** `f59b76aecff9d3c56df36952...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:27.332+00:00` to `2016-08-28T23:58:27.332+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.225.111`

#### Evidence Card: `card-f70a8198f28b` (network_connection)
- **Fingerprint:** `f70a8198f28ba7f8084e5132...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:43.334+00:00` to `2016-08-28T23:58:43.334+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.225.33`

#### Evidence Card: `card-f8b9d90f9f1f` (network_connection)
- **Fingerprint:** `f8b9d90f9f1ff8666e717987...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:37.640+00:00` to `2016-08-28T23:58:37.640+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `191.232.139.214`

#### Evidence Card: `card-fbe7e7601b6c` (process_execution)
- **Fingerprint:** `fbe7e7601b6cfd467c24cd67...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-24T16:36:24.000+00:00` to `2016-08-24T16:36:24.000+00:00`
- **Associated Entities:** **hosts:** `we1149srv`; **users:** `NT AUTHORITY\SYSTEM`
- **Parent Process(es):** `C:\Windows\System32\smss.exe`
- **Image/Process Executable(s):** `C:\Windows\System32\smss.exe`
- **Observed Command Lines:**
  ```shell
  \SystemRoot\System32\smss.exe 00000000 00000050 
  ```

#### Evidence Card: `card-fcbfe3b58429` (network_connection)
- **Fingerprint:** `fcbfe3b58429aceb785f0a78...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:33.634+00:00` to `2016-08-28T23:58:33.634+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.229.78`

#### Evidence Card: `card-fe66df7f1ff1` (network_connection)
- **Fingerprint:** `fe66df7f1ff1f67acfc53b27...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:55.724+00:00` to `2016-08-28T23:58:55.724+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.228.70`

#### Evidence Card: `card-fe798d8a8803` (network_connection)
- **Fingerprint:** `fe798d8a8803190d194a5712...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:23.692+00:00` to `2016-08-28T23:58:23.692+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.226.110`

#### Evidence Card: `card-ff2402dacce4` (network_connection)
- **Fingerprint:** `ff2402dacce45b4ac306fdec...`
- **Event Count:** 1 occurrences (`complete` completeness)
- **Observed Time Window:** `2016-08-28T23:58:35.796+00:00` to `2016-08-28T23:58:35.796+00:00`
- **Associated Entities:** **hosts:** `splunk-02`; **destination_ips:** `192.168.228.154`

---
## Actionable Containment & Incident Response Recommendations

> [!CAUTION]
> **Immediate Incident Response Actions Required:**

1. **Endpoint Isolation & Containment:**
   - Immediately disconnect and isolate impacted host(s): `splunk-02`, `we1149srv` from the network to halt potential lateral movement.
2. **Web Server & Webshell Eradication:**
   - Audit web server document root directories (e.g., Joomla/IIS) for newly dropped or modified script files (`.php`, `.asp`, `.aspx`).
   - Terminate suspicious child processes spawned under web server workers (`w3wp.exe`, `httpd.exe`, `php-cgi.exe`).
3. **Account & Credential Security:**
   - Invalidate active sessions and rotate credentials for affected security contexts: `IIS APPPOOL\DefaultAppPool`, `IIS APPPOOL\joomla`, `NT AUTHORITY\IUSR`, `NT AUTHORITY\NETWORK SERVICE`, `NT AUTHORITY\SYSTEM`, `Window Manager\DWM-3`.
   - Audit privilege escalation paths and recent modifications to local administrators / domain groups.
4. **Detection Rule Deployment:**
   - Deploy high-fidelity detection rules alerting on web server worker processes spawning script interpreters or command shells (`cmd.exe`, `powershell.exe`, `php-cgi.exe`).

### Cited Observations (Audit Trail)

> [!NOTE]
> The raw observation IDs below record deterministic telemetry provenance and mathematical auditability.

<details>
<summary><strong>Click to expand Raw Telemetry Observation IDs (500 events)</strong></summary>

- `obs-101`
- `obs-102`
- `obs-103`
- `obs-104`
- `obs-105`
- `obs-106`
- `obs-107`
- `obs-108`
- `obs-109`
- `obs-110`
- `obs-111`
- `obs-112`
- `obs-113`
- `obs-114`
- `obs-115`
- `obs-116`
- `obs-117`
- `obs-118`
- `obs-119`
- `obs-120`
- `obs-121`
- `obs-122`
- `obs-123`
- `obs-124`
- `obs-125`
- `obs-126`
- `obs-127`
- `obs-128`
- `obs-129`
- `obs-130`
- `obs-131`
- `obs-132`
- `obs-133`
- `obs-134`
- `obs-135`
- `obs-136`
- `obs-137`
- `obs-138`
- `obs-139`
- `obs-140`
- `obs-141`
- `obs-142`
- `obs-143`
- `obs-144`
- `obs-145`
- `obs-146`
- `obs-147`
- `obs-148`
- `obs-149`
- `obs-150`
- `obs-151`
- `obs-152`
- `obs-153`
- `obs-154`
- `obs-155`
- `obs-156`
- `obs-157`
- `obs-158`
- `obs-159`
- `obs-160`
- `obs-161`
- `obs-162`
- `obs-163`
- `obs-164`
- `obs-165`
- `obs-166`
- `obs-167`
- `obs-168`
- `obs-169`
- `obs-170`
- `obs-171`
- `obs-172`
- `obs-173`
- `obs-174`
- `obs-175`
- `obs-176`
- `obs-177`
- `obs-178`
- `obs-179`
- `obs-180`
- `obs-181`
- `obs-182`
- `obs-183`
- `obs-184`
- `obs-185`
- `obs-186`
- `obs-187`
- `obs-188`
- `obs-189`
- `obs-190`
- `obs-191`
- `obs-192`
- `obs-193`
- `obs-194`
- `obs-195`
- `obs-196`
- `obs-197`
- `obs-198`
- `obs-199`
- `obs-200`
- `obs-201`
- `obs-202`
- `obs-203`
- `obs-204`
- `obs-205`
- `obs-206`
- `obs-207`
- `obs-208`
- `obs-209`
- `obs-210`
- `obs-211`
- `obs-212`
- `obs-213`
- `obs-214`
- `obs-215`
- `obs-216`
- `obs-217`
- `obs-218`
- `obs-219`
- `obs-220`
- `obs-221`
- `obs-222`
- `obs-223`
- `obs-224`
- `obs-225`
- `obs-226`
- `obs-227`
- `obs-228`
- `obs-229`
- `obs-230`
- `obs-231`
- `obs-232`
- `obs-233`
- `obs-234`
- `obs-235`
- `obs-236`
- `obs-237`
- `obs-238`
- `obs-239`
- `obs-240`
- `obs-241`
- `obs-242`
- `obs-243`
- `obs-244`
- `obs-245`
- `obs-246`
- `obs-247`
- `obs-248`
- `obs-249`
- `obs-250`
- `obs-251`
- `obs-252`
- `obs-253`
- `obs-254`
- `obs-255`
- `obs-256`
- `obs-257`
- `obs-258`
- `obs-259`
- `obs-260`
- `obs-261`
- `obs-262`
- `obs-263`
- `obs-264`
- `obs-265`
- `obs-266`
- `obs-267`
- `obs-268`
- `obs-269`
- `obs-270`
- `obs-271`
- `obs-272`
- `obs-273`
- `obs-274`
- `obs-275`
- `obs-276`
- `obs-277`
- `obs-278`
- `obs-279`
- `obs-280`
- `obs-281`
- `obs-282`
- `obs-283`
- `obs-284`
- `obs-285`
- `obs-286`
- `obs-287`
- `obs-288`
- `obs-289`
- `obs-290`
- `obs-291`
- `obs-292`
- `obs-293`
- `obs-294`
- `obs-295`
- `obs-296`
- `obs-297`
- `obs-298`
- `obs-299`
- `obs-300`
- `obs-301`
- `obs-302`
- `obs-303`
- `obs-304`
- `obs-305`
- `obs-306`
- `obs-307`
- `obs-308`
- `obs-309`
- `obs-310`
- `obs-311`
- `obs-312`
- `obs-313`
- `obs-314`
- `obs-315`
- `obs-316`
- `obs-317`
- `obs-318`
- `obs-319`
- `obs-320`
- `obs-321`
- `obs-322`
- `obs-323`
- `obs-324`
- `obs-325`
- `obs-326`
- `obs-327`
- `obs-328`
- `obs-329`
- `obs-330`
- `obs-331`
- `obs-332`
- `obs-333`
- `obs-334`
- `obs-335`
- `obs-336`
- `obs-337`
- `obs-338`
- `obs-339`
- `obs-340`
- `obs-341`
- `obs-342`
- `obs-343`
- `obs-344`
- `obs-345`
- `obs-346`
- `obs-347`
- `obs-348`
- `obs-349`
- `obs-350`
- `obs-351`
- `obs-352`
- `obs-353`
- `obs-354`
- `obs-355`
- `obs-356`
- `obs-357`
- `obs-358`
- `obs-359`
- `obs-360`
- `obs-361`
- `obs-362`
- `obs-363`
- `obs-364`
- `obs-365`
- `obs-366`
- `obs-367`
- `obs-368`
- `obs-369`
- `obs-370`
- `obs-371`
- `obs-372`
- `obs-373`
- `obs-374`
- `obs-375`
- `obs-376`
- `obs-377`
- `obs-378`
- `obs-379`
- `obs-380`
- `obs-381`
- `obs-382`
- `obs-383`
- `obs-384`
- `obs-385`
- `obs-386`
- `obs-387`
- `obs-388`
- `obs-389`
- `obs-390`
- `obs-391`
- `obs-392`
- `obs-393`
- `obs-394`
- `obs-395`
- `obs-396`
- `obs-397`
- `obs-398`
- `obs-399`
- `obs-400`
- `obs-401`
- `obs-402`
- `obs-403`
- `obs-404`
- `obs-405`
- `obs-406`
- `obs-407`
- `obs-408`
- `obs-409`
- `obs-410`
- `obs-411`
- `obs-412`
- `obs-413`
- `obs-414`
- `obs-415`
- `obs-416`
- `obs-417`
- `obs-418`
- `obs-419`
- `obs-420`
- `obs-421`
- `obs-422`
- `obs-423`
- `obs-424`
- `obs-425`
- `obs-426`
- `obs-427`
- `obs-428`
- `obs-429`
- `obs-430`
- `obs-431`
- `obs-432`
- `obs-433`
- `obs-434`
- `obs-435`
- `obs-436`
- `obs-437`
- `obs-438`
- `obs-439`
- `obs-440`
- `obs-441`
- `obs-442`
- `obs-443`
- `obs-444`
- `obs-445`
- `obs-446`
- `obs-447`
- `obs-448`
- `obs-449`
- `obs-450`
- `obs-451`
- `obs-452`
- `obs-453`
- `obs-454`
- `obs-455`
- `obs-456`
- `obs-457`
- `obs-458`
- `obs-459`
- `obs-460`
- `obs-461`
- `obs-462`
- `obs-463`
- `obs-464`
- `obs-465`
- `obs-466`
- `obs-467`
- `obs-468`
- `obs-469`
- `obs-470`
- `obs-471`
- `obs-472`
- `obs-473`
- `obs-474`
- `obs-475`
- `obs-476`
- `obs-477`
- `obs-478`
- `obs-479`
- `obs-480`
- `obs-481`
- `obs-482`
- `obs-483`
- `obs-484`
- `obs-485`
- `obs-486`
- `obs-487`
- `obs-488`
- `obs-489`
- `obs-490`
- `obs-491`
- `obs-492`
- `obs-493`
- `obs-494`
- `obs-495`
- `obs-496`
- `obs-497`
- `obs-498`
- `obs-499`
- `obs-500`
- `obs-sweep-1`
- `obs-sweep-10`
- `obs-sweep-100`
- `obs-sweep-11`
- `obs-sweep-12`
- `obs-sweep-13`
- `obs-sweep-14`
- `obs-sweep-15`
- `obs-sweep-16`
- `obs-sweep-17`
- `obs-sweep-18`
- `obs-sweep-19`
- `obs-sweep-2`
- `obs-sweep-20`
- `obs-sweep-21`
- `obs-sweep-22`
- `obs-sweep-23`
- `obs-sweep-24`
- `obs-sweep-25`
- `obs-sweep-26`
- `obs-sweep-27`
- `obs-sweep-28`
- `obs-sweep-29`
- `obs-sweep-3`
- `obs-sweep-30`
- `obs-sweep-31`
- `obs-sweep-32`
- `obs-sweep-33`
- `obs-sweep-34`
- `obs-sweep-35`
- `obs-sweep-36`
- `obs-sweep-37`
- `obs-sweep-38`
- `obs-sweep-39`
- `obs-sweep-4`
- `obs-sweep-40`
- `obs-sweep-41`
- `obs-sweep-42`
- `obs-sweep-43`
- `obs-sweep-44`
- `obs-sweep-45`
- `obs-sweep-46`
- `obs-sweep-47`
- `obs-sweep-48`
- `obs-sweep-49`
- `obs-sweep-5`
- `obs-sweep-50`
- `obs-sweep-51`
- `obs-sweep-52`
- `obs-sweep-53`
- `obs-sweep-54`
- `obs-sweep-55`
- `obs-sweep-56`
- `obs-sweep-57`
- `obs-sweep-58`
- `obs-sweep-59`
- `obs-sweep-6`
- `obs-sweep-60`
- `obs-sweep-61`
- `obs-sweep-62`
- `obs-sweep-63`
- `obs-sweep-64`
- `obs-sweep-65`
- `obs-sweep-66`
- `obs-sweep-67`
- `obs-sweep-68`
- `obs-sweep-69`
- `obs-sweep-7`
- `obs-sweep-70`
- `obs-sweep-71`
- `obs-sweep-72`
- `obs-sweep-73`
- `obs-sweep-74`
- `obs-sweep-75`
- `obs-sweep-76`
- `obs-sweep-77`
- `obs-sweep-78`
- `obs-sweep-79`
- `obs-sweep-8`
- `obs-sweep-80`
- `obs-sweep-81`
- `obs-sweep-82`
- `obs-sweep-83`
- `obs-sweep-84`
- `obs-sweep-85`
- `obs-sweep-86`
- `obs-sweep-87`
- `obs-sweep-88`
- `obs-sweep-89`
- `obs-sweep-9`
- `obs-sweep-90`
- `obs-sweep-91`
- `obs-sweep-92`
- `obs-sweep-93`
- `obs-sweep-94`
- `obs-sweep-95`
- `obs-sweep-96`
- `obs-sweep-97`
- `obs-sweep-98`
- `obs-sweep-99`
</details>

---
## 4. Query Audit Trail & Diagnostics

| Query ID | Req ID | Provider | Scope | Operation | Completeness | Targeted? |
|---|---|---|---|---|---|---|
| `qp-sweep-1` | `req-hunt-botsv1-web-01-web_request` | `splunk` | `splunk_botsv1` | `cdb_web_requests` | `complete` | `NO (Broad)` |
| `qp-exp-hypo-hunt-botsv1-web-01-active-req-hunt-botsv1-web-01-web_request-we1149srv` | `req-hunt-botsv1-web-01-web_request` | `splunk` | `splunk_botsv1` | `cdb_web_requests` | `complete` | `YES` |
| `qp-exp-hypo-hunt-botsv1-web-01-active-req-hunt-botsv1-web-01-process_ancestry-we1149srv` | `req-hunt-botsv1-web-01-process_ancestry` | `splunk` | `splunk_botsv1` | `cdb_process_lineage` | `complete` | `YES` |
| `qp-exp-hypo-hunt-botsv1-web-01-active-req-hunt-botsv1-web-01-file_modification-we1149srv` | `req-hunt-botsv1-web-01-file_modification` | `splunk` | `splunk_botsv1` | `cdb_file_writes` | `complete` | `YES` |
| `qp-exp-hypo-hunt-botsv1-web-01-benign-req-hunt-botsv1-web-01-baseline-we1149srv` | `req-hunt-botsv1-web-01-baseline` | `splunk` | `splunk_botsv1` | `cdb_broad_sweep` | `complete` | `NO (Broad)` |
| `qp-exp-hypo-hunt-botsv1-web-01-active-req-hunt-botsv1-web-01-web_request-splunk-02` | `req-hunt-botsv1-web-01-web_request` | `splunk` | `splunk_botsv1` | `cdb_web_requests` | `complete` | `YES` |
| `qp-exp-hypo-hunt-botsv1-web-01-active-req-hunt-botsv1-web-01-process_ancestry-splunk-02` | `req-hunt-botsv1-web-01-process_ancestry` | `splunk` | `splunk_botsv1` | `cdb_process_lineage` | `complete` | `YES` |
| `qp-exp-hypo-hunt-botsv1-web-01-active-req-hunt-botsv1-web-01-file_modification-splunk-02` | `req-hunt-botsv1-web-01-file_modification` | `splunk` | `splunk_botsv1` | `cdb_file_writes` | `complete` | `YES` |
| `qp-exp-hypo-hunt-botsv1-web-01-benign-req-hunt-botsv1-web-01-baseline-splunk-02` | `req-hunt-botsv1-web-01-baseline` | `splunk` | `splunk_botsv1` | `cdb_broad_sweep` | `complete` | `NO (Broad)` |

### Executed Query Statements (SPL / SQL)

> [!TIP]
> Chuyên viên phân tích SOC có thể sao chép trực tiếp các câu lệnh truy vấn dưới đây vào Splunk Web hoặc CDB để tự mình kiểm chứng lại kết quả.

<details>
<summary><strong>Click to expand Executed Query Plans (9 statements)</strong></summary>

#### Query: `qp-sweep-1` (cdb_web_requests)
```spl
search index="botsv1" (sourcetype="stream:http" OR sourcetype="iis") (site="*imreallynotbatman.com*" OR cs_host="*imreallynotbatman.com*" OR "imreallynotbatman.com" OR "imreallynotbatman.com")
| eval site=coalesce(site, cs_host) | where like(lower(site), "%imreallynotbatman.com%")
| head 101
| table _time, host, sourcetype, image, cmdline, parent_image, user, pid, ppid, destination_ip, destination_port, source_ip, source_port, protocol, file_path, domain, query, logon_type, status, hash, uri, cs_uri_stem, cs_method, client_ip, server_ip, c_ip, s_ip, dest_ip, src_ip, dest, http_method, site, cs_host, _raw
```

#### Query: `qp-exp-hypo-hunt-botsv1-web-01-active-req-hunt-botsv1-web-01-web_request-we1149srv` (cdb_web_requests)
```spl
search index="botsv1" (sourcetype="stream:http" OR sourcetype="iis") host="we1149srv" (site="*imreallynotbatman.com*" OR cs_host="*imreallynotbatman.com*" OR "imreallynotbatman.com" OR "imreallynotbatman.com")
| eval site=coalesce(site, cs_host) | where like(lower(site), "%imreallynotbatman.com%")
| head 101
| table _time, host, sourcetype, image, cmdline, parent_image, user, pid, ppid, destination_ip, destination_port, source_ip, source_port, protocol, file_path, domain, query, logon_type, status, hash, uri, cs_uri_stem, cs_method, client_ip, server_ip, c_ip, s_ip, dest_ip, src_ip, dest, http_method, site, cs_host, _raw
```

#### Query: `qp-exp-hypo-hunt-botsv1-web-01-active-req-hunt-botsv1-web-01-process_ancestry-we1149srv` (cdb_process_lineage)
```spl
search index="botsv1" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "*EventID>1<*" host="we1149srv"
| rex field=_raw "<Data Name='Image'>(?<image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<cmdline>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<parent_image>[^<]+)</Data>"
| rex field=_raw "<Data Name='User'>(?<user>[^<]+)</Data>"
| rex field=_raw "<Data Name='ProcessId'>(?<pid>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentProcessId'>(?<ppid>[^<]+)</Data>"
| rex field=_raw "<Data Name='Hashes'>(?<hash>[^<]+)</Data>"
| where isnotnull(cmdline) AND cmdline!=""
| head 101
| table _time, host, sourcetype, image, cmdline, parent_image, user, pid, ppid, destination_ip, destination_port, source_ip, source_port, protocol, file_path, domain, query, logon_type, status, hash, uri, cs_uri_stem, cs_method, client_ip, server_ip, c_ip, s_ip, dest_ip, src_ip, dest, http_method, site, cs_host, _raw
```

#### Query: `qp-exp-hypo-hunt-botsv1-web-01-active-req-hunt-botsv1-web-01-file_modification-we1149srv` (cdb_file_writes)
```spl
search index="botsv1" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "*EventID>11<*" host="we1149srv"
| rex field=_raw "<Data Name='TargetFilename'>(?<file_path>[^<]+)</Data>"
| rex field=_raw "<Data Name='Image'>(?<image>[^<]+)</Data>"
| where isnotnull(file_path) AND file_path!=""
| head 101
| table _time, host, sourcetype, image, cmdline, parent_image, user, pid, ppid, destination_ip, destination_port, source_ip, source_port, protocol, file_path, domain, query, logon_type, status, hash, uri, cs_uri_stem, cs_method, client_ip, server_ip, c_ip, s_ip, dest_ip, src_ip, dest, http_method, site, cs_host, _raw
```

#### Query: `qp-exp-hypo-hunt-botsv1-web-01-benign-req-hunt-botsv1-web-01-baseline-we1149srv` (cdb_broad_sweep)
```spl
search index="botsv1" host="we1149srv"
| head 101
| table _time, host, sourcetype, image, cmdline, parent_image, user, pid, ppid, destination_ip, destination_port, source_ip, source_port, protocol, file_path, domain, query, logon_type, status, hash, uri, cs_uri_stem, cs_method, client_ip, server_ip, c_ip, s_ip, dest_ip, src_ip, dest, http_method, site, cs_host, _raw
```

#### Query: `qp-exp-hypo-hunt-botsv1-web-01-active-req-hunt-botsv1-web-01-web_request-splunk-02` (cdb_web_requests)
```spl
search index="botsv1" (sourcetype="stream:http" OR sourcetype="iis") host="splunk-02" (site="*imreallynotbatman.com*" OR cs_host="*imreallynotbatman.com*" OR "imreallynotbatman.com" OR "imreallynotbatman.com")
| eval site=coalesce(site, cs_host) | where like(lower(site), "%imreallynotbatman.com%")
| head 101
| table _time, host, sourcetype, image, cmdline, parent_image, user, pid, ppid, destination_ip, destination_port, source_ip, source_port, protocol, file_path, domain, query, logon_type, status, hash, uri, cs_uri_stem, cs_method, client_ip, server_ip, c_ip, s_ip, dest_ip, src_ip, dest, http_method, site, cs_host, _raw
```

#### Query: `qp-exp-hypo-hunt-botsv1-web-01-active-req-hunt-botsv1-web-01-process_ancestry-splunk-02` (cdb_process_lineage)
```spl
search index="botsv1" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "*EventID>1<*" host="splunk-02"
| rex field=_raw "<Data Name='Image'>(?<image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<cmdline>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<parent_image>[^<]+)</Data>"
| rex field=_raw "<Data Name='User'>(?<user>[^<]+)</Data>"
| rex field=_raw "<Data Name='ProcessId'>(?<pid>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentProcessId'>(?<ppid>[^<]+)</Data>"
| rex field=_raw "<Data Name='Hashes'>(?<hash>[^<]+)</Data>"
| where isnotnull(cmdline) AND cmdline!=""
| head 101
| table _time, host, sourcetype, image, cmdline, parent_image, user, pid, ppid, destination_ip, destination_port, source_ip, source_port, protocol, file_path, domain, query, logon_type, status, hash, uri, cs_uri_stem, cs_method, client_ip, server_ip, c_ip, s_ip, dest_ip, src_ip, dest, http_method, site, cs_host, _raw
```

#### Query: `qp-exp-hypo-hunt-botsv1-web-01-active-req-hunt-botsv1-web-01-file_modification-splunk-02` (cdb_file_writes)
```spl
search index="botsv1" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "*EventID>11<*" host="splunk-02"
| rex field=_raw "<Data Name='TargetFilename'>(?<file_path>[^<]+)</Data>"
| rex field=_raw "<Data Name='Image'>(?<image>[^<]+)</Data>"
| where isnotnull(file_path) AND file_path!=""
| head 101
| table _time, host, sourcetype, image, cmdline, parent_image, user, pid, ppid, destination_ip, destination_port, source_ip, source_port, protocol, file_path, domain, query, logon_type, status, hash, uri, cs_uri_stem, cs_method, client_ip, server_ip, c_ip, s_ip, dest_ip, src_ip, dest, http_method, site, cs_host, _raw
```

#### Query: `qp-exp-hypo-hunt-botsv1-web-01-benign-req-hunt-botsv1-web-01-baseline-splunk-02` (cdb_broad_sweep)
```spl
search index="botsv1" host="splunk-02"
| head 101
| table _time, host, sourcetype, image, cmdline, parent_image, user, pid, ppid, destination_ip, destination_port, source_ip, source_port, protocol, file_path, domain, query, logon_type, status, hash, uri, cs_uri_stem, cs_method, client_ip, server_ip, c_ip, s_ip, dest_ip, src_ip, dest, http_method, site, cs_host, _raw
```

</details>

### Diagnostics & Warnings
- Clean: No query diagnostics or execution warnings recorded.

---
## 5. Visibility & Gap Breakdown

### 1. Not Found (Queried with Complete Coverage, Zero Findings)
- None

### 2. Not Observable (Telemetry Lacks Required Behavioral Fields)
- None

### 3. Unqueryable (Adapter Unsupported, Permission Denied, or Syntax Error)
- None

### 4. Unknown Source (Unmapped / Unregistered Telemetry, Excluded from Denominator)
- None

---
## 6. Residual Uncertainty & Investigation Boundaries

> - No residual uncertainty documented.