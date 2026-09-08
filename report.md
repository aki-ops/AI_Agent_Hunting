# Hunt Report

## 1. Hypothesis / Question

> Amber Turing da thuc hien cai dat TOR browser, phien ban cua TOR browser la gi

- **Subject:** `person`: `Amber Turing`
- **Requested Object:** `software_version` (role: `answer`)
- **Behavior:** Amber Turing installed Tor Browser on a host, and the user is requesting to determine the installed version of Tor Browser.

**Result:** `PARTIALLY_SUPPORTED`  
**Stopping:** `STOP_BOUNDED`

- **Causal Path Coverage:** `0.0%` (0/5 relations verified)
- **Wildcard Scope Coverage:** `0.0%` (0/1 broadsweep cells)
- **Instance Cell Coverage:** `0.0%` (0/0 concrete entity cells)

**Answer Status:** `PARTIALLY_SUPPORTED`

**Answer:** Tor Browser was observed on wrk-aturing. Requested version: Not available in the retrieved telemetry.

**Evidence Citation:** Tor Browser executed on wrk-aturing Evidence: obs-discovery-1, obs-discovery-10, obs-discovery-11 Query: qp-discovery-0, qp-discovery-followup-0 Fields: Path, raw_event

## 2. Hypothesis analysis

- `PARTIALLY_SUPPORTED` — Amber Turing downloaded and executed an interactive Tor Browser installer on an endpoint.
- `PARTIALLY_SUPPORTED` — A portable or pre-extracted version of Tor Browser was placed and executed in user-writable space to bypass enterprise controls.

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
| Process: tor.exe Path: C:\Users\amber.turing\Desktop\Tor Browser\Browser\firefox.exe Host: wrk-aturing | Shows execution of firefox.exe under 'C:\Users\amber.turing\Desktop\Tor Browser\Browser\firefox.exe' on wrk-aturing, supporting execution of Tor Browser from a user-writable desktop path, but file_version is absent. | 114 event(s); representative observations: `obs-discovery-1`, `obs-discovery-3`, `obs-discovery-4` |
| Process: tor.exe Path: C:\Users\amber.turing\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe Host: wrk-aturing | Shows execution of tor.exe under 'C:\Users\amber.turing\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe' on wrk-aturing, supporting user-writable execution, but file_version is absent. | 57 event(s); representative observations: `obs-discovery-2`, `obs-discovery-5`, `obs-discovery-8` |
| Process execution observed on wrk-aturing | Process execution events on wrk-aturing with no process names, file paths, or version data specified. | 312 event(s); representative observations: `obs-discovery-82`, `obs-discovery-83`, `obs-discovery-84` |
| Process execution observed on wrk-aturing | Process execution events on wrk-aturing without specific process identification or version details. | 253 event(s); representative observations: `obs-discovery-55`, `obs-discovery-56`, `obs-discovery-63` |
| Process execution observed on wrk-aturing | Process execution telemetry on wrk-aturing without process details or version information. | 9 event(s); representative observations: `obs-discovery-144`, `obs-discovery-156`, `obs-discovery-157` |
| Telemetry observations (5 events on wrk-aturing) | Generic telemetry events on wrk-aturing without process names or version details. | 5 event(s); representative observations: `obs-discovery-505`, `obs-discovery-506`, `obs-discovery-507` |
| Telemetry observations (2 events on uranus) | Telemetry on host uranus, unrelated to Amber Turing or Tor Browser execution on wrk-aturing. | 2 event(s); representative observations: `obs-discovery-501`, `obs-discovery-502` |
| Telemetry observations (2 events on wrk-aturing) | Generic telemetry on wrk-aturing without executable path or version data. | 2 event(s); representative observations: `obs-discovery-503`, `obs-discovery-504` |

### Explanation

- **Deterministic Explanation:** Tor Browser was observed on wrk-aturing. Requested version: Not available in the retrieved telemetry.
- **LLM Narrative Analysis:** Cannot conclude NOT_FOUND because subject identity was not resolved to an endpoint or client IP.
- Shows execution of firefox.exe under 'C:\Users\amber.turing\Desktop\Tor Browser\Browser\firefox.exe' on wrk-aturing, supporting execution of Tor Browser from a user-writable desktop path, but file_version is absent.
- Shows execution of tor.exe under 'C:\Users\amber.turing\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe' on wrk-aturing, supporting user-writable execution, but file_version is absent.
- Process execution events on wrk-aturing with no process names, file paths, or version data specified.
- Process execution events on wrk-aturing without specific process identification or version details.
- Process execution telemetry on wrk-aturing without process details or version information.
- Generic telemetry events on wrk-aturing without process names or version details.
- Telemetry on host uranus, unrelated to Amber Turing or Tor Browser execution on wrk-aturing.
- Generic telemetry on wrk-aturing without executable path or version data.
- Missing according to evidence analysis: File version or ProductVersion metadata from PE headers for firefox.exe and tor.exe
- Missing according to evidence analysis: Installer logs, command-line arguments, or download artifacts containing Tor Browser version information
- Limitation: No definitive adversary presence or refutation established in searched frame.

## 4. Queries used

### `qp-discovery-0` — `discovery`
- **Purpose:** search_text

- **Result:** 500 rows returned; complete=False
- **Hypothesis Impact:** Targets `hypo-1`
Provider: `splunk`; completeness: `complete`

```spl
search index="botsv2" ("Amber Turing" OR "Amber") ("torbrowser-install" OR "tor-browser" OR "Tor Browser" OR "tor.exe" OR "firefox.exe" OR "browser.exe" OR "Tor Browser\Browser\firefox.exe" OR "Browser") | rex field=_raw "(?i)<Data Name=[\"']ProductVersion[\"']>(?<ProductVersion>[^<]+)</Data>" | rex field=_raw "(?i)<Data Name=[\"']FileVersion[\"']>(?<FileVersion>[^<]+)</Data>" | rex field=_raw "(?i)ProductVersion[:= ]+(?<ProductVersion>[^\r\n,]+)" | rex field=_raw "(?i)FileVersion[:= ]+(?<FileVersion>[^\r\n,]+)" | rex field=_raw "(?i)version[\"':= ]+(?<Version>[0-9]+(\.[0-9]+)+)" | head 501 | table _time, host, sourcetype, user, Image, CommandLine, Path, TargetFilename, ProductVersion, FileVersion, Version, uri, site, _raw
```

### `qp-discovery-followup-0` — `discovery-followup`
- **Purpose:** search_text

- **Result:** 254 rows returned; complete=True
- **Hypothesis Impact:** Targets `hypo-1`
Provider: `splunk`; completeness: `complete`

```spl
search index="botsv2" ("wrk-aturing") ("torbrowser-install" OR "tor-browser" OR "Tor Browser" OR "tor.exe" OR "firefox.exe" OR "browser.exe" OR "Tor Browser\Browser\firefox.exe" OR "Browser") | rex field=_raw "(?i)<Data Name=[\"']ProductVersion[\"']>(?<ProductVersion>[^<]+)</Data>" | rex field=_raw "(?i)<Data Name=[\"']FileVersion[\"']>(?<FileVersion>[^<]+)</Data>" | rex field=_raw "(?i)ProductVersion[:= ]+(?<ProductVersion>[^\r\n,]+)" | rex field=_raw "(?i)FileVersion[:= ]+(?<FileVersion>[^\r\n,]+)" | rex field=_raw "(?i)version[\"':= ]+(?<Version>[0-9]+(\.[0-9]+)+)" | head 501 | table _time, host, sourcetype, user, Image, CommandLine, Path, TargetFilename, ProductVersion, FileVersion, Version, uri, site, _raw
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
- **Purpose:** cdb_file_search

- **Result:** 0 rows returned; complete=True
- **Hypothesis Impact:** Targets `hypo-1`
Provider: `splunk`; completeness: `complete`

```spl
search index="botsv2" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "*EventID>11<*" host="wrk-aturing"
| rex field=_raw "<Data Name='TargetFilename'>(?<file_path>[^<]+)</Data>"
| rex field=_raw "<Data Name='Image'>(?<image>[^<]+)</Data>"
| rex field=_raw "(?i)<Data Name=[\'\"ProductVersion[\'\">[^<]+</Data>"
| rex field=_raw "(?i)<Data Name=[\'\"FileVersion[\'\">[^<]+</Data>"
| rex field=_raw "(?i)ProductVersion[:= ]+([^\r\n,]+)"
| rex field=_raw "(?i)FileVersion[:= ]+([^\r\n,]+)"
| rex field=_raw "(?i)version[\'\":= ]+([0-9]+(\.[0-9]+)+)"
| head 501
| table _time, host, sourcetype, image, cmdline, parent_image, user, pid, ppid, destination_ip, destination_port, source_ip, source_port, protocol, file_path, domain, query, logon_type, status, hash, uri, cs_uri_stem, cs_method, client_ip, server_ip, c_ip, s_ip, dest_ip, src_ip, dest, http_method, site, cs_host, ProductVersion, FileVersion, Version, TargetFilename, _raw
```

### `qp-adaptive-0-2` — `adaptive-answer`
- **Purpose:** find_process_from_endpoint

- **Result:** 0 rows returned; complete=True
- **Hypothesis Impact:** Targets `hypo-1`
Provider: `splunk`; completeness: `complete`

```spl
search index="botsv2" (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1) (host="*wrk-aturing*" OR ComputerName="*wrk-aturing*") ("Amber Turing" OR "torbrowser-install" OR "tor-browser" OR "Tor Browser" OR "tor.exe" OR "firefox.exe" OR "browser.exe" OR "Tor Browser\Browser\firefox.exe") | rex field=_raw "(?i)<Data Name=[\"']ProductVersion[\"']>(?<ProductVersion>[^<]+)</Data>" | rex field=_raw "(?i)<Data Name=[\"']FileVersion[\"']>(?<FileVersion>[^<]+)</Data>" | rex field=_raw "(?i)ProductVersion[:= ]+(?<ProductVersion>[^\r\n,]+)" | rex field=_raw "(?i)FileVersion[:= ]+(?<FileVersion>[^\r\n,]+)" | rex field=_raw "(?i)version[\"':= ]+(?<Version>[0-9]+(\.[0-9]+)+)" | head 501 | table _time, host, ComputerName, Image, CommandLine, ParentImage, User, ProcessId, ProductVersion, FileVersion, Version, _raw
```

## 5. Cost

- Model: `auto`
- Calls: `2`
- Tokens: `14699`
- Estimated cost: `$0.014496`
