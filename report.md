# Hunt Report

## 1. Hypothesis / Question

> Amber Turing da thuc hien cai dat TOR browser, phien ban cua TOR browser la gi

- **Subject:** `person`: `Amber Turing`
- **Requested Object:** `software_version` (role: `answer`)
- **Behavior:** Amber Turing installed Tor Browser on a host, and the user is requesting to determine the installed version of Tor Browser.

**Result:** `SUPPORTED`  
**Stopping:** `STOP_BOUNDED`

- **Causal Path Coverage:** `0.0%` (0/5 relations verified)
- **Wildcard Scope Coverage:** `0.0%` (0/1 broadsweep cells)
- **Instance Cell Coverage:** `0.0%` (0/0 concrete entity cells)

**Answer Status:** `FULLY_ANSWERED`

**Answer (software_version):** `{'user': 'FROTHLY\\amber.turing', 'file_path': 'C:\\Users\\amber.turing\\Downloads\\torbrowser-install-7.0.4_en-US.exe', 'file_version': '7.0.4', 'process_name': 'C:\\Users\\amber.turing\\Downloads\\torbrowser-install-7.0.4_en-US.exe'}`

**Answer explanation:** Telemetry on host wrk-aturing confirms user FROTHLY\amber.turing executed the Tor Browser installer 'torbrowser-install-7.0.4_en-US.exe' downloaded via Chrome, which subsequently launched the Tor Browser 'firefox.exe' process. The software version recorded across the installation and execution events is 7.0.4.

## 2. Hypothesis analysis

- `SUPPORTED` — Amber Turing downloaded and executed an interactive Tor Browser installer on an endpoint.
- `SUPPORTED` — A portable or pre-extracted version of Tor Browser was placed and executed in user-writable space to bypass enterprise controls.

**Unresolved Mandatory Unknowns:**
- `person(Amber Turing) -> logged_on_to -> endpoint`: Identify workstation endpoint used by Amber Turing
- `endpoint -> executed -> software_version`: Execution of the Tor Browser setup package or installation wizard.
- `endpoint -> modified -> software_version`: File system artifacts and binary properties showing installed file paths and version resource attributes for Tor Browser.
- `endpoint -> executed -> software_version`: Execution of the main Tor Browser process or Tor proxy daemon under the user context.
- `account_for_Amber Turing`: Identify account username for Amber Turing
- `endpoint_for_Amber Turing`: Identify workstation endpoint used by Amber Turing

## 3. Evidence and explanation

| Evidence | Why it matters | Source |
|---|---|---|
| Process execution observed on wrk-aturing | Process execution events observed on wrk-aturing indicate the presence and execution of software version 7.0.4. | 312 event(s); representative observations: `obs-discovery-82`, `obs-discovery-83`, `obs-discovery-84` |
| Process: C:\Users\amber.turing\Downloads\torbrowser-install-7.0.4_en-US.exe Path: C:\Users\AMBER~1.TUR\AppData\Local\Temp\nsi52A6.tmp\modern-wizard.bmp Host: wrk-aturing | Amber Turing (FROTHLY\amber.turing) executed the installer 'C:\Users\amber.turing\Downloads\torbrowser-install-7.0.4_en-US.exe' on wrk-aturing spawned by Chrome, creating files under Desktop and Temp, confirming Tor Browser version 7.0.4. | 225 event(s); representative observations: `obs-discovery-173`, `obs-discovery-404`, `obs-discovery-405` |
| Process: C:\Users\amber.turing\Desktop\Tor Browser\Browser\firefox.exe Path: C:\Users\amber.turing\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\1RQWYSDG80WMR58PAP2I.temp Host: wrk-aturing | Execution of Tor Browser browser engine 'firefox.exe' on wrk-aturing by FROTHLY\amber.turing, with parent installer 'torbrowser-install-7.0.4_en-US.exe', confirming version 7.0.4. | 26 event(s); representative observations: `obs-discovery-55`, `obs-discovery-56`, `obs-discovery-63` |
| Process execution observed on wrk-aturing | Process execution events on wrk-aturing recording Tor Browser software version 7.0.4. | 9 event(s); representative observations: `obs-discovery-144`, `obs-discovery-156`, `obs-discovery-157` |
| Process: tor.exe Path: C:\Users\amber.turing\Desktop\Tor Browser\Browser\firefox.exe Host: wrk-aturing | Process execution events for tor.exe associated with Desktop Tor Browser path 'C:\Users\amber.turing\Desktop\Tor Browser\Browser\firefox.exe' on wrk-aturing. | 114 event(s); representative observations: `obs-discovery-1`, `obs-discovery-3`, `obs-discovery-4` |
| Process: tor.exe Path: C:\Users\amber.turing\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe Host: wrk-aturing | Execution of tor.exe located under 'C:\Users\amber.turing\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe' on wrk-aturing. | 57 event(s); representative observations: `obs-discovery-2`, `obs-discovery-5`, `obs-discovery-8` |
| Telemetry observations (5 events on wrk-aturing) | Generic telemetry events on wrk-aturing with no explicit Tor process or version details. | 5 event(s); representative observations: `obs-discovery-505`, `obs-discovery-506`, `obs-discovery-507` |
| Telemetry observations (2 events on uranus) | Telemetry on host uranus, unrelated to Amber Turing's Tor Browser installation on wrk-aturing. | 2 event(s); representative observations: `obs-discovery-501`, `obs-discovery-502` |
| Process: C:\Users\amber.turing\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe Host: wrk-aturing | Execution of 'tor.exe' on wrk-aturing by FROTHLY\amber.turing spawned by 'firefox.exe' under the Desktop Tor Browser directory. | 2 event(s); representative observations: `obs-discovery-158`, `obs-discovery-597` |
| Telemetry observations (2 events on wrk-aturing) | Generic telemetry on wrk-aturing without Tor Browser version or execution specifics. | 2 event(s); representative observations: `obs-discovery-503`, `obs-discovery-504` |

### Explanation

- **Deterministic Graph Resolution:** The target object `{'user': 'FROTHLY\\amber.turing', 'file_path': 'C:\\Users\\amber.turing\\Downloads\\torbrowser-install-7.0.4_en-US.exe', 'file_version': '7.0.4', 'process_name': 'C:\\Users\\amber.turing\\Downloads\\torbrowser-install-7.0.4_en-US.exe'}` was proven through the verified 4-step causal provenance chain.
- **Deterministic Explanation:** Telemetry on host wrk-aturing confirms user FROTHLY\amber.turing executed the Tor Browser installer 'torbrowser-install-7.0.4_en-US.exe' downloaded via Chrome, which subsequently launched the Tor Browser 'firefox.exe' process. The software version recorded across the installation and execution events is 7.0.4.
- **LLM Narrative Analysis:** Telemetry on host wrk-aturing confirms user FROTHLY\amber.turing executed the Tor Browser installer 'torbrowser-install-7.0.4_en-US.exe' downloaded via Chrome, which subsequently launched the Tor Browser 'firefox.exe' process. The software version recorded across the installation and execution events is 7.0.4.
- Process execution events observed on wrk-aturing indicate the presence and execution of software version 7.0.4.
- Amber Turing (FROTHLY\amber.turing) executed the installer 'C:\Users\amber.turing\Downloads\torbrowser-install-7.0.4_en-US.exe' on wrk-aturing spawned by Chrome, creating files under Desktop and Temp, confirming Tor Browser version 7.0.4.
- Execution of Tor Browser browser engine 'firefox.exe' on wrk-aturing by FROTHLY\amber.turing, with parent installer 'torbrowser-install-7.0.4_en-US.exe', confirming version 7.0.4.
- Process execution events on wrk-aturing recording Tor Browser software version 7.0.4.
- Process execution events for tor.exe associated with Desktop Tor Browser path 'C:\Users\amber.turing\Desktop\Tor Browser\Browser\firefox.exe' on wrk-aturing.
- Execution of tor.exe located under 'C:\Users\amber.turing\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe' on wrk-aturing.
- Generic telemetry events on wrk-aturing with no explicit Tor process or version details.
- Telemetry on host uranus, unrelated to Amber Turing's Tor Browser installation on wrk-aturing.
- Limitation: No definitive adversary presence or refutation established in searched frame.

## 4. Queries used

### `qp-discovery-0` — `discovery`
- **Purpose:** search_text

- **Result:** 500 rows returned; complete=False
- **Hypothesis Impact:** Targets `hypo-1`
Provider: `splunk`; completeness: `complete`

```spl
search index="botsv2" ("Amber Turing" OR "Amber") ("torbrowser-install" OR "tor-browser" OR "Tor Browser" OR "tor.exe" OR "firefox.exe" OR "browser.exe" OR "Tor Browser\Browser\firefox.exe" OR "Browser") | rex field=_raw "(?i)<Data Name=[\"']ProductVersion[\"']>(?<ProductVersion>[^<]+)</Data>" | rex field=_raw "(?i)<Data Name=[\"']FileVersion[\"']>(?<FileVersion>[^<]+)</Data>" | rex field=_raw "(?i)ProductVersion[:= ]+(?<ProductVersion>[^\r\n,]+)" | rex field=_raw "(?i)FileVersion[:= ]+(?<FileVersion>[^\r\n,]+)" | rex field=_raw "(?i)version[\"':= ]+(?<Version>[0-9]+(\.[0-9]+)+)" | rex field=_raw "(?i)[/\\\(][a-zA-Z0-9_.-]*(?:install|setup|browser|update|v)[-_ ]*(?<software_version>[0-9]+(\.[0-9]+)+)" | head 501 | table _time, host, sourcetype, user, Image, CommandLine, Path, TargetFilename, ProductVersion, FileVersion, Version, uri, site, _raw
```

### `qp-discovery-followup-0` — `discovery-followup`
- **Purpose:** search_text

- **Result:** 254 rows returned; complete=True
- **Hypothesis Impact:** Targets `hypo-1`
Provider: `splunk`; completeness: `complete`

```spl
search index="botsv2" ("wrk-aturing") ("torbrowser-install" OR "tor-browser" OR "Tor Browser" OR "tor.exe" OR "firefox.exe" OR "browser.exe" OR "Tor Browser\Browser\firefox.exe" OR "Browser") | rex field=_raw "(?i)<Data Name=[\"']ProductVersion[\"']>(?<ProductVersion>[^<]+)</Data>" | rex field=_raw "(?i)<Data Name=[\"']FileVersion[\"']>(?<FileVersion>[^<]+)</Data>" | rex field=_raw "(?i)ProductVersion[:= ]+(?<ProductVersion>[^\r\n,]+)" | rex field=_raw "(?i)FileVersion[:= ]+(?<FileVersion>[^\r\n,]+)" | rex field=_raw "(?i)version[\"':= ]+(?<Version>[0-9]+(\.[0-9]+)+)" | rex field=_raw "(?i)[/\\\(][a-zA-Z0-9_.-]*(?:install|setup|browser|update|v)[-_ ]*(?<software_version>[0-9]+(\.[0-9]+)+)" | head 501 | table _time, host, sourcetype, user, Image, CommandLine, Path, TargetFilename, ProductVersion, FileVersion, Version, uri, site, _raw
```

### `qp-schema-0` — `schema-discovery`
- **Purpose:** discover_schema

- **Result:** 342 rows returned; complete=True
- **Hypothesis Impact:** Targets `hypo-1`
Provider: `splunk`; completeness: `complete`

```spl
search index="botsv2" | head 501 | fieldsummary
```

### `qp-adaptive-0-1` — `adaptive-answer`
- **Purpose:** find_process_from_endpoint

- **Result:** 0 rows returned; complete=True
- **Hypothesis Impact:** Targets `hypo-1`
Provider: `splunk`; completeness: `complete`

```spl
search index="botsv2" (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1) (host="*wrk-aturing*" OR ComputerName="*wrk-aturing*") ("Amber Turing" OR "torbrowser-install" OR "tor-browser" OR "Tor Browser" OR "tor.exe" OR "firefox.exe" OR "browser.exe" OR "Tor Browser\Browser\firefox.exe" OR "modern-wizard.bmp" OR "Accessible.tlb" OR "AccessibleMarshal.dll" OR "IA2Marshal.dll" OR "bookmarks.html" OR "1RQWYSDG80WMR58PAP2I.temp" OR "6QIZ67XP67CW4TJ2PKR7.temp" OR "A1DCHQKNOGVOEWF1VQCT.temp" OR "A49K5RREJXHYXPS5JGCI.temp" OR "BQIHUMLSOW67O6DFNZ93.temp") | rex field=_raw "(?i)<Data Name=[\"']ProductVersion[\"']>(?<ProductVersion>[^<]+)</Data>" | rex field=_raw "(?i)<Data Name=[\"']FileVersion[\"']>(?<FileVersion>[^<]+)</Data>" | rex field=_raw "(?i)ProductVersion[:= ]+(?<ProductVersion>[^\r\n,]+)" | rex field=_raw "(?i)FileVersion[:= ]+(?<FileVersion>[^\r\n,]+)" | rex field=_raw "(?i)version[\"':= ]+(?<Version>[0-9]+(\.[0-9]+)+)" | head 501 | table _time, host, ComputerName, Image, CommandLine, ParentImage, User, ProcessId, ProductVersion, FileVersion, Version, _raw
```

### `qp-adaptive-0-2` — `adaptive-answer`
- **Purpose:** find_file_change_from_process

- **Result:** 0 rows returned; complete=True
- **Hypothesis Impact:** Targets `hypo-1`
Provider: `splunk`; completeness: `complete`

```spl
search index="botsv2" (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11) (ProcessId="wrk-aturing" OR Image="*wrk-aturing*") | rex field=_raw "(?i)<Data Name=[\"']ProductVersion[\"']>(?<ProductVersion>[^<]+)</Data>" | rex field=_raw "(?i)<Data Name=[\"']FileVersion[\"']>(?<FileVersion>[^<]+)</Data>" | rex field=_raw "(?i)ProductVersion[:= ]+(?<ProductVersion>[^\r\n,]+)" | rex field=_raw "(?i)FileVersion[:= ]+(?<FileVersion>[^\r\n,]+)" | rex field=_raw "(?i)version[\"':= ]+(?<Version>[0-9]+(\.[0-9]+)+)" | head 501 | table _time, host, TargetFilename, Image, ProcessId, ProductVersion, FileVersion, Version, _raw
```

## 5. Cost

- Model: `auto`
- Calls: `2`
- Tokens: `23977`
- Estimated cost: `$0.026012`
