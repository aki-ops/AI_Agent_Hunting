"""Ingest stream:http rows into the eval DB + write a Joomla PoC.

Ground truth: imreallynotbatman.com joomla attack is real BOTS v1 web
compromise traffic (22k rows). Benign control: windowsupdate/msn/google
rows in the same file must NOT match the Joomla PoC.
"""
import csv
import gzip
import json
import re
import sqlite3

SRC = "data/raw/botsv1.stream-http.csv.gz"
DB = "data/botsv1_eval.sqlite"

conn = sqlite3.connect(DB)
cols = ["timestamp", "event_id", "native_type", "host", "user", "pid",
        "ppid", "cmdline", "image", "ip", "port", "domain",
        "file_path", "action", "status", "raw_ref"]
sql = f"INSERT INTO events ({', '.join(cols)}) VALUES ({', '.join('?' for _ in cols)})"

n = 0
joomla = 0
with gzip.open(SRC, "rt", encoding="utf-8", errors="replace") as f:
    reader = csv.DictReader(f)
    batch = []
    for row in reader:
        raw = row.get("_raw") or ""
        m = re.search(r'"timestamp":"([^"]+)"', raw)
        ts = (m.group(1)[:19] + "Z") if m else (row.get("_time") or "")
        site = (re.search(r'"site":\s*"([^"]+)"', raw) or [None, None])[1]
        uri = (re.search(r'"uri_path":\s*"([^"]+)"', raw) or [None, None])[1]
        cip = (re.search(r'"c_ip":\s*"([^"]+)"', raw) or [None, None])[1]
        if "joomla" in (uri or "").lower():
            joomla += 1
        ev = {
            "timestamp": ts, "event_id": None, "native_type": "web_request",
            "host": row.get("host"), "user": None, "pid": None, "ppid": None,
            "cmdline": f"site={site} uri={uri}" if site or uri else None,
            "image": None, "ip": cip, "port": None, "domain": site,
            "file_path": None, "action": None, "status": None,
            "raw_ref": "botsv1-http",
        }
        batch.append(tuple(ev[c] for c in cols))
        n += 1
        if len(batch) >= 5000:
            conn.executemany(sql, batch)
            batch = []
    if batch:
        conn.executemany(sql, batch)
conn.commit()
total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
conn.close()
print(f"ingested {n} http rows ({joomla} joomla), eval total now {total}", flush=True)

poc = {
    "poc_id": "poc-joomla-rce",
    "name": "Joomla RCE web compromise (BOTS v1 real attack)",
    "kind": "ttp",
    "summary": "Attacker scans and exploits Joomla search/mailto components on imreallynotbatman.com.",
    "topic": "web application exploitation",
    "able": {
        "actor": "",
        "behavior": "Exploit public-facing application (T1190) via Joomla search component",
        "location": "web traffic to imreallynotbatman.com",
        "evidence": "web_request telemetry; hit = site imreallynotbatman.com with /joomla/ uri",
    },
    "research_refs": ["BOTS v1 walkthrough - web compromise phase", "MITRE ATT&CK T1190"],
    "scope": "stream:http 2016-08-10 window",
    "max_duration": "3d",
    "plan": "search_text over web telemetry for the victim site + joomla path",
    "steps": [
        {"step_id": "s1-victim-site", "description": "Request to compromised site",
         "target_field": "domain", "op": "EQUALS", "value": "imreallynotbatman.com",
         "source_kind": "web"},
        {"step_id": "s2-joomla-path", "description": "Joomla component path",
         "target_field": "cmdline", "op": "CONTAINS", "value": "/joomla/",
         "source_kind": "web"},
    ],
    "references": ["MITRE ATT&CK T1190"],
    "expected_chain": ["web_request", "exploitation"],
}
with open("pocs/poc-joomla-rce.json", "w", encoding="utf-8") as f:
    json.dump(poc, f, indent=2)
print("wrote pocs/poc-joomla-rce.json", flush=True)
