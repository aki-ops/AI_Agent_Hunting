# PoC Hunt Report — `poc-joomla-rce`

**PoC Name:** Joomla RCE web compromise (BOTS v1 real attack)
**Request ID:** `poc-poc-joomla-rce-20260922-025212`
**Window:** 2016-08-10T21:36:00Z/2016-08-10T22:00:00Z
**Started:** 20260922-025212
**Finished:** 20260922-025214
**Runtime:** 1.3241 s

## Hunt Plan (ABLE)

- Topic: web application exploitation
- Actor: (unknown)
- Behavior: Exploit public-facing application (T1190) via Joomla search component
- Location: web traffic to imreallynotbatman.com
- Evidence: web_request telemetry; hit = site imreallynotbatman.com with /joomla/ uri
- Scope: stream:http 2016-08-10 window
- Max duration: 3d
- Plan: search_text over web telemetry for the victim site + joomla path
- Research: BOTS v1 walkthrough - web compromise phase, MITRE ATT&CK T1190

## Verdict: **MATCHED**

Matched 2 PoC step(s) with 199 observation(s).

## LLM Judge: **TRUE_POSITIVE** (confidence 0.87)

199 requests to imreallynotbatman.com in attack window include Acunetix scanner probe, random fuzz paths, and Joomla enumeration consistent with PoC scan stage.

**Notes:**
- uri=/acunetix-wvs-test-for-some-inexistent-file is scanner artifact not normal browsing
- random /PdgdyH6M /OD6xDhbF indicate fuzzing/probing
- joomla component paths show targeted CMS enumeration

_Judge cost: 1 call(s), 4995 token(s)_

## PoC Definition

- Kind: `ttp`
- Summary: Attacker scans and exploits Joomla search/mailto components on imreallynotbatman.com.
- Expected chain: web_request, exploitation
- References: MITRE ATT&CK T1190

### Steps

- `[s1-victim-site]` Request to compromised site → `domain EQUALS imreallynotbatman.com`
- `[s2-joomla-path]` Joomla component path → `cmdline CONTAINS /joomla/`

## Step Results

- ✓ `[s1-victim-site]` Request to compromised site: 99 row(s)
  - `{'id': 4412203, 'timestamp': '2016-08-10T21:36:45Z', 'event_id': None, 'native_type': 'web_request', 'host': 'splunk-02', 'user': None, 'pid': None, 'ppid': None, 'cmdline': 'site=imreallynotbatman.com uri=/acunetix-wvs-test-for-some-inexistent-file', 'image': None, 'ip': '40.80.148.42', 'port': None, 'domain': 'imreallynotbatman.com', 'file_path': None, 'action': None, 'status': None, 'raw_ref': 'botsv1-http'}`
  - `{'id': 4412204, 'timestamp': '2016-08-10T21:36:45Z', 'event_id': None, 'native_type': 'web_request', 'host': 'splunk-02', 'user': None, 'pid': None, 'ppid': None, 'cmdline': 'site=imreallynotbatman.com uri=/', 'image': None, 'ip': '40.80.148.42', 'port': None, 'domain': 'imreallynotbatman.com', 'file_path': None, 'action': None, 'status': None, 'raw_ref': 'botsv1-http'}`
  - `{'id': 4412196, 'timestamp': '2016-08-10T21:36:48Z', 'event_id': None, 'native_type': 'web_request', 'host': 'splunk-02', 'user': None, 'pid': None, 'ppid': None, 'cmdline': 'site=imreallynotbatman.com uri=/PdgdyH6M', 'image': None, 'ip': '40.80.148.42', 'port': None, 'domain': 'imreallynotbatman.com', 'file_path': None, 'action': None, 'status': None, 'raw_ref': 'botsv1-http'}`
  - `{'id': 4412197, 'timestamp': '2016-08-10T21:36:48Z', 'event_id': None, 'native_type': 'web_request', 'host': 'splunk-02', 'user': None, 'pid': None, 'ppid': None, 'cmdline': 'site=imreallynotbatman.com uri=/OD6xDhbF', 'image': None, 'ip': '40.80.148.42', 'port': None, 'domain': 'imreallynotbatman.com', 'file_path': None, 'action': None, 'status': None, 'raw_ref': 'botsv1-http'}`
  - `{'id': 4412198, 'timestamp': '2016-08-10T21:36:48Z', 'event_id': None, 'native_type': 'web_request', 'host': 'splunk-02', 'user': None, 'pid': None, 'ppid': None, 'cmdline': 'site=imreallynotbatman.com uri=/', 'image': None, 'ip': '40.80.148.42', 'port': None, 'domain': 'imreallynotbatman.com', 'file_path': None, 'action': None, 'status': None, 'raw_ref': 'botsv1-http'}`
  - … (+94 more)
- ✓ `[s2-joomla-path]` Joomla component path: 100 row(s)
  - `{'id': 4410725, 'timestamp': '2016-08-10T21:37:55Z', 'event_id': None, 'native_type': 'web_request', 'host': 'splunk-02', 'user': None, 'pid': None, 'ppid': None, 'cmdline': 'site=imreallynotbatman.com uri=/joomla/components/com_jnews/includes/openflashchart/open-flash-chart.swf', 'image': None, 'ip': '40.80.148.42', 'port': None, 'domain': 'imreallynotbatman.com', 'file_path': None, 'action': None, 'status': None, 'raw_ref': 'botsv1-http'}`
  - `{'id': 4409686, 'timestamp': '2016-08-10T21:40:46Z', 'event_id': None, 'native_type': 'web_request', 'host': 'splunk-02', 'user': None, 'pid': None, 'ppid': None, 'cmdline': 'site=imreallynotbatman.com uri=/joomla/', 'image': None, 'ip': '40.80.148.42', 'port': None, 'domain': 'imreallynotbatman.com', 'file_path': None, 'action': None, 'status': None, 'raw_ref': 'botsv1-http'}`
  - `{'id': 4409685, 'timestamp': '2016-08-10T21:40:47Z', 'event_id': None, 'native_type': 'web_request', 'host': 'splunk-02', 'user': None, 'pid': None, 'ppid': None, 'cmdline': 'site=imreallynotbatman.com uri=/joomla/index.php', 'image': None, 'ip': '40.80.148.42', 'port': None, 'domain': 'imreallynotbatman.com', 'file_path': None, 'action': None, 'status': None, 'raw_ref': 'botsv1-http'}`
  - `{'id': 4409671, 'timestamp': '2016-08-10T21:40:48Z', 'event_id': None, 'native_type': 'web_request', 'host': 'splunk-02', 'user': None, 'pid': None, 'ppid': None, 'cmdline': 'site=imreallynotbatman.com uri=/joomla/index.php/about', 'image': None, 'ip': '40.80.148.42', 'port': None, 'domain': 'imreallynotbatman.com', 'file_path': None, 'action': None, 'status': None, 'raw_ref': 'botsv1-http'}`
  - `{'id': 4409672, 'timestamp': '2016-08-10T21:40:48Z', 'event_id': None, 'native_type': 'web_request', 'host': 'splunk-02', 'user': None, 'pid': None, 'ppid': None, 'cmdline': 'site=imreallynotbatman.com uri=/joomla/index.php/6-your-template', 'image': None, 'ip': '40.80.148.42', 'port': None, 'domain': 'imreallynotbatman.com', 'file_path': None, 'action': None, 'status': None, 'raw_ref': 'botsv1-http'}`
  - … (+95 more)

## LLM Cost

- Calls: 1 (match/escalation=0, judge=1)
- Tokens: 4995 (match/escalation=0, judge=4995)
- Cost: $0.000000

## Act (Detection Draft + Backlog)

### Detection Draft (SPL — analyst review required)

```spl
search index="botsv1" domain="imreallynotbatman.com" match(cmdline, "(?i)/joomla/") earliest=-14d latest=now
| table _time, host, user, image, cmdline, domain, file_path, action
```

### Backlog

- Sibling TTP hunt: same behavior `Exploit public-facing application (T1190) via Joomla search component` on other host groups.
- New topic candidate: variations of `web application exploitation` (PEAK Re-Add Topic to Backlog).

### Stakeholder Summary

- PoC `poc-joomla-rce` verdict MATCHED over 199 observations. Judge: TRUE_POSITIVE (0.87).
- Matched steps: s1-victim-site, s2-joomla-path.
- Next: analyst reviews the detection draft before production.

## Ledger

`artifacts\poc_hunts\poc-poc-joomla-rce-20260922-025212.json`
