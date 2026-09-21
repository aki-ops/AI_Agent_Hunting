"""Ingest BOTS v1 Security CSV + journal sysmon/dns into an eval CDB.

Streaming: never holds the full CSV in RAM. Only keeps rows relevant to
the eval (auth 4624/4625, process 4688, SMB 5140/5145) plus sysmon process
and stream:dns events from the attack-only journals.

Output: data/botsv1_eval.sqlite (gitignored) + data/eval_ingest_stats.json
Ground truth is counted during ingest (see eval labels below).
"""
import csv
import gzip
import json
import re
import sqlite3
import sys
import time
from collections import Counter
from pathlib import Path

CSV_PATH = "data/raw/botsv1.WinEventLog-Security.csv.gz"
OUT_DB = "data/botsv1_eval.sqlite"
STATS_PATH = "data/eval_ingest_stats.json"

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_id TEXT,
    native_type TEXT,
    host TEXT,
    user TEXT,
    pid INTEGER,
    ppid INTEGER,
    cmdline TEXT,
    image TEXT,
    ip TEXT,
    port INTEGER,
    domain TEXT,
    file_path TEXT,
    action TEXT,
    status TEXT,
    raw_ref TEXT
)
"""

RE_EVENTCODE = re.compile(r"EventCode=(\d+)")
RE_COMPUTER = re.compile(r"ComputerName=([A-Za-z0-9_.\-]+)")
RE_ACCOUNT = re.compile(r"Account Name:\s+([^\r\n]+)")
RE_PROC_NAME = re.compile(r"New Process Name:\s+([^\r\n]+)")
RE_CMDLINE = re.compile(r"Process Command Line:\s+([^\r\n]+)")
RE_CREATOR_PID = re.compile(r"Creator Process ID:\s+(0x[0-9a-fA-F]+|\d+)")
RE_NEW_PID = re.compile(r"New Process ID:\s+(0x[0-9a-fA-F]+|\d+)")
RE_SRC_IP = re.compile(r"Source Network Address:\s+([0-9a-fA-F.:]+)")
RE_SHARE = re.compile(r"Share Name:\s+([^\r\n]+)")
RE_LOGON_TYPE = re.compile(r"Logon Type:\s+(\d+)")
RE_STATUS = re.compile(r"Status:\s+(0x[0-9a-fA-F]+)")
RE_TIME = re.compile(r"(\d{2})/(\d{2})/(\d{4})\s+(\d{2}):(\d{2}):(\d{2})\s+(AM|PM)")


def to_iso(raw: str, fallback: str) -> str:
    m = RE_TIME.search(raw)
    if not m:
        return fallback
    mo, d, y, hh, mm, ss, ap = m.groups()
    h = int(hh) % 12 + (12 if ap == "PM" else 0)
    return f"{y}-{mo}-{d}T{h:02d}:{mm}:{ss}Z"


def parse_security_row(raw: str, splunk_time: str, host: str) -> dict | None:
    m = RE_EVENTCODE.search(raw)
    if not m:
        return None
    code = m.group(1)
    if code not in ("4624", "4625", "4688", "4648", "5140", "5145"):
        return None
    comp = RE_COMPUTER.search(raw)
    hostname = comp.group(1).split(".")[0] if comp else host
    ts = to_iso(raw, splunk_time)
    cmdline = ""
    image = None
    user = None
    ip = None
    action = None
    status = None
    file_path = None
    pid = None
    ppid = None
    if code in ("4624", "4625"):
        native = "authentication"
        acct = RE_ACCOUNT.search(raw)
        user = acct.group(1).strip() if acct else None
        ipm = RE_SRC_IP.search(raw)
        ip = ipm.group(1).strip() if ipm else None
        ltm = RE_LOGON_TYPE.search(raw)
        stm = RE_STATUS.search(raw)
        status = stm.group(1) if stm else None
        ok = "Success" if code == "4624" else "Failed"
        cmdline = f"Logon {ok} user={user} ip={ip} type={ltm.group(1) if ltm else '?'} status={status or '?'}"
        action = "logon-success" if code == "4624" else "logon-failed"
    elif code == "4688":
        native = "process_creation"
        pnm = RE_PROC_NAME.search(raw)
        image = (pnm.group(1).strip().split("\\")[-1] if pnm else None)
        clm = RE_CMDLINE.search(raw)
        cmdline = clm.group(1).strip() if clm else (image or "")
        acct = RE_ACCOUNT.search(raw)
        user = acct.group(1).strip() if acct else None
        try:
            pid = int((RE_NEW_PID.search(raw) or [None, None])[1] or 0, 16) if RE_NEW_PID.search(raw) else None
        except Exception:
            pid = None
        try:
            ppid = int((RE_CREATOR_PID.search(raw) or [None, None])[1] or 0, 16) if RE_CREATOR_PID.search(raw) else None
        except Exception:
            ppid = None
    else:
        native = "smb"
        shm = RE_SHARE.search(raw)
        file_path = shm.group(1).strip() if shm else None
        acct = RE_ACCOUNT.search(raw)
        user = acct.group(1).strip() if acct else None
        cmdline = f"Network Share Access file_path={file_path}"
    return {
        "timestamp": ts, "event_id": code, "native_type": native,
        "host": hostname, "user": user, "pid": pid, "ppid": ppid,
        "cmdline": cmdline or None, "image": image, "ip": ip,
        "port": None, "domain": None, "file_path": file_path,
        "action": action, "status": status, "raw_ref": f"botsv1-sec-{code}",
    }


def main() -> None:
    t0 = time.time()
    out = Path(OUT_DB)
    if out.exists():
        out.unlink()
    conn = sqlite3.connect(str(out))
    conn.execute(SCHEMA)
    cols = ["timestamp", "event_id", "native_type", "host", "user", "pid",
            "ppid", "cmdline", "image", "ip", "port", "domain",
            "file_path", "action", "status", "raw_ref"]
    sql = f"INSERT INTO events ({', '.join(cols)}) VALUES ({', '.join('?' for _ in cols)})"

    counts: Counter = Counter()
    kept = 0
    batch: list[tuple] = []
    # Ground truth counters
    gt_failed_4625 = 0
    gt_success_4624 = 0
    gt_ps_4688 = 0
    gt_ps_enc = 0

    with gzip.open(CSV_PATH, "rt", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            ev = parse_security_row(row.get("_raw") or "", row.get("_time") or "", row.get("host") or "")
            if ev is None:
                continue
            counts[ev["event_id"]] += 1
            kept += 1
            if ev["event_id"] == "4625":
                gt_failed_4625 += 1
            elif ev["event_id"] == "4624":
                gt_success_4624 += 1
            elif ev["event_id"] == "4688":
                gt_ps_4688 += 1
                cl = (ev["cmdline"] or "").lower()
                if "powershell" in cl and "-enc" in cl:
                    gt_ps_enc += 1
            batch.append(tuple(ev[c] for c in cols))
            if len(batch) >= 5000:
                conn.executemany(sql, batch)
                batch = []
            if (i + 1) % 1000000 == 0:
                conn.commit()
                print(f"  scanned {i + 1:,} csv rows, kept {kept:,}", flush=True)
    if batch:
        conn.executemany(sql, batch)
    conn.commit()

    # Ingest sysmon process + dns from journals
    sysmon_n = 0
    dns_n = 0
    dns_domains: Counter = Counter()
    import xml.etree.ElementTree as ET
    for name in ("XmlWinEventLog_Microsoft-Windows-Sysmon.jsonl", "stream_dns.jsonl"):
        p = Path("data/raw/events") / name
        if not p.exists():
            continue
        with open(p, encoding="utf-8") as f:
            for line in f:
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                raw = rec.get("raw") or ""
                if name.startswith("XmlWin"):
                    if "<EventID>1</EventID>" not in raw:
                        continue
                    try:
                        # carve first complete <Event>...</Event>
                        s = raw.index("<Event")
                        e = raw.index("</Event>") + len("</Event>")
                        root = ET.fromstring(raw[s:e])
                        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
                        def tx(tag: str) -> str:
                            el = root.find(f".//e:{tag}", ns)
                            return el.text if el is not None and el.text else ""
                        ed = root.find(".//e:EventData", ns)
                        data = {}
                        if ed is not None:
                            for d in ed.findall("e:Data", ns):
                                data[d.get("Name", "")] = d.text or ""
                        img = (data.get("Image") or "").split("\\")[-1] or None
                        ev = {
                            "timestamp": tx("SystemTime") or rec.get("host") or "",
                            "event_id": "1", "native_type": "process_creation",
                            "host": rec.get("host"), "user": data.get("User") or None,
                            "pid": int(data.get("ProcessId") or 0) or None,
                            "ppid": int(data.get("ParentProcessId") or 0) or None,
                            "cmdline": data.get("CommandLine") or img,
                            "image": img, "ip": None, "port": None, "domain": None,
                            "file_path": None, "action": None, "status": None,
                            "raw_ref": "botsv1-sysmon-1",
                        }
                        # fix timestamp from SystemTime attr
                        tc = root.find(".//e:TimeCreated", ns)
                        if tc is not None and tc.get("SystemTime"):
                            ev["timestamp"] = tc.get("SystemTime")[:19] + "Z"
                        conn.execute(sql, tuple(ev[c] for c in cols))
                        sysmon_n += 1
                        cl = (ev["cmdline"] or "").lower()
                        if img and "powershell" in img.lower() and "-enc" in cl:
                            gt_ps_enc += 1
                    except Exception:
                        continue
                else:
                    m = re.search(r'"timestamp":"([^"]+)"', raw)
                    q = re.search(r'"query":\["([^"]+)"', raw)
                    if not m:
                        continue
                    ts = m.group(1)[:19] + "Z"
                    dom = q.group(1) if q else None
                    if dom:
                        dns_domains[dom] += 1
                    ev = {
                        "timestamp": ts, "event_id": None, "native_type": "dns",
                        "host": rec.get("host"), "user": None, "pid": None, "ppid": None,
                        "cmdline": f"query={dom}" if dom else None, "image": None,
                        "ip": None, "port": None, "domain": dom,
                        "file_path": None, "action": None, "status": None,
                        "raw_ref": "botsv1-dns",
                    }
                    conn.execute(sql, tuple(ev[c] for c in cols))
                    dns_n += 1
    conn.commit()
    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    conn.close()
    stats = {
        "csv_event_counts": dict(counts),
        "eval_rows": total,
        "sysmon_process_rows": sysmon_n,
        "dns_rows": dns_n,
        "top_dns_domains": dns_domains.most_common(20),
        "ground_truth": {
            "failed_logons_4625": gt_failed_4625,
            "success_logons_4624": gt_success_4624,
            "process_4688": gt_ps_4688,
            "powershell_enc_total": gt_ps_enc,
            "note": "attack-only + full-Security mix: 4625/4624 counts come from the full 14.2M Security CSV (mostly benign); encoded-PS count mixes 4688 CSV + sysmon Event 1",
        },
        "elapsed_seconds": round(time.time() - t0, 1),
    }
    Path(STATS_PATH).write_text(json.dumps(stats, indent=2), encoding="utf-8")
    print(json.dumps(stats, indent=2), flush=True)


if __name__ == "__main__":
    sys.exit(main())
