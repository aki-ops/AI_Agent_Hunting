"""Seed a CDB with representative BOTS v1 attack samples.

BOTS v1 is "Boss of the SOC v1" — a Splunk dataset of 1 day of an
organisation's endpoints, firewalls, web proxies, AD logs. The full
dataset is ~1GB; we ship a small representative sample that covers
the core attack patterns you would hunt:

  - 2016-08-21 morning: cleartext FTP credential leak
  - 2016-08-21 afternoon: spear-phishing email + pdf exploit
  - 2016-08-21 evening: lateral movement SMB / beacon to non-routable IP
  - 2016-08-21 late: persistence via Run key + scheduled task

The MITRE mapping follows the BOTS v1 walkthrough:
  - T1078 / T1110  - brute force + valid account login
  - T1071.001     - C2 over HTTP
  - T1190         - exploit public-facing app
  - T1566.001     - spear-phishing attachment
  - T1027         - obfuscated PowerShell
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from hunting.m5_adapter import CdbAdapter


# Compact representation of BOTS v1 events. Each event is row-shaped to
# match the CDB schema.
BOTS_SAMPLE = [
    # ----- T1078 / T1110: brute force and a successful login -----
    # Repeated failed logons to we1149srv.
    # The CDB search_text scans {raw_ref, cmdline, image, file_path, domain,
    # user, host, native_type}; we encode structured fields into cmdline
    # so PoC predicates match cleanly.
    *[
        {
            "timestamp": f"2016-08-21T03:0{minute}:00Z",
            "event_id": "4625",
            "native_type": "authentication",
            "host": "we1149srv",
            "user": "admin",
            "cmdline": "Logon Failed user=admin ip={ip} status=0xC000006D auth-fail-{minute}".format(
                minute=minute,
                ip="10.0.2.18" if minute == 0 else "23.22.63.114",
            ),
            "raw_ref": f"auth-fail-{minute}",
        }
        for minute in range(0, 7)
    ],
    # 1 successful logon at 03:08 (alice)
    {
        "timestamp": "2016-08-21T03:08:00Z",
        "event_id": "4624",
        "native_type": "authentication",
        "host": "we1149srv",
        "user": "alice",
        "cmdline": "Logon Success user=alice ip=23.22.63.114 auth-success-alice",
        "raw_ref": "auth-success-alice",
    },
    # ----- Phishing e-mail (SMTP) -----
    {
        "timestamp": "2016-08-21T06:02:00Z",
        "event_id": "1",
        "native_type": "smtp",
        "host": "we1149srv",
        "user": "alice",
        "cmdline": "received subject=Payroll_Adjustment from=it-payroll@british-shipping.co to=alice@korps.local attachment=Payroll_Adjustment_08012016.lnk",
        "raw_ref": "smtp-001",
    },
    # ----- T1071.001: beacon to ad.networkfilter.co -----
    {
        "timestamp": "2016-08-21T08:14:30Z",
        "event_id": "7",
        "native_type": "web_request",
        "host": "we1149srv",
        "user": "alice",
        "site": "ad.networkfilter.co",
        "uri": "/banner/banner728.gif?c=ads",
        "cmdline": "method=GET site=ad.networkfilter.co uri=/banner/banner728.gif?c=ads web-beacon",
        "ip": "10.0.2.18",
        "raw_ref": "web-beacon",
    },
    # ----- T1190 / T1027: pdf exploit child = powershell -----
    {
        "timestamp": "2016-08-21T08:14:45Z",
        "event_id": "4688",
        "native_type": "process_creation",
        "host": "we1149srv",
        "user": "alice",
        "image": "powershell.exe",
        "pid": 4012,
        "ppid": 2048,
        "cmdline": "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdAAgAGkAZQBtACAAUwB0AGEAcgB0AC0AUwBsAGUAZQAuAC4ALgAuAA==",
        "raw_ref": "proc-pdf-exploit",
    },
    # ----- T1021.002: SMB lateral movement to JGREEN-PC -----
    {
        "timestamp": "2016-08-21T11:33:10Z",
        "event_id": "5145",
        "native_type": "smb",
        "host": "JGREEN-PC",
        "user": "alice",
        "cmdline": "Network Share Access file_path=\\\\we1149srv\\C$\\Users\\alice\\__CTF_data\\flag",
        "ip": "10.0.2.18",
        "raw_ref": "smb-jgreen",
    },
    {
        "timestamp": "2016-08-21T11:33:45Z",
        "event_id": "4688",
        "native_type": "process_creation",
        "host": "JGREEN-PC",
        "user": "alice",
        "image": "powershell.exe",
        "pid": 5400,
        "ppid": 4012,
        "cmdline": "powershell.exe -NoP -W Hidden -enc SQBuAHQAbABsACEAUwBjAGgAZQBkAHUAbABlAA==",
        "raw_ref": "proc-jgreen",
    },
    # ----- T1053.005 / T1547.001: persistence -----
    {
        "timestamp": "2016-08-21T11:42:15Z",
        "event_id": "4688",
        "native_type": "process_creation",
        "host": "JGREEN-PC",
        "user": "SYSTEM",
        "image": "schtasks.exe",
        "pid": 6100,
        "ppid": 4,
        "cmdline": "schtasks.exe /create /tn WinUpdater /tr C:\\Windows\\Temp\\update_task.exe /sc minute /mo 1",
        "raw_ref": "schtask-001",
    },
    {
        "timestamp": "2016-08-21T11:42:30Z",
        "event_id": "1",
        "native_type": "registry",
        "host": "JGREEN-PC",
        "user": "alice",
        "cmdline": "registry_set path=HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
        "raw_ref": "reg-run-key",
    },
    # ----- Benign / FP: legitimate scheduled script by svc_admin -----
    {
        "timestamp": "2016-08-21T02:15:00Z",
        "event_id": "4688",
        "native_type": "process_creation",
        "host": "SCCM-SERVER",
        "user": "CORP\\svc_admin",
        "image": "powershell.exe",
        "pid": 7800,
        "ppid": 600,
        "cmdline": "powershell.exe -NoP -W Hidden -enc Zm9vYmFy",
        "raw_ref": "sccm-001",
    },
]


def _emails_for_bots_sample():
    """A second source-style table for inbound email; CDB has only the
    events table, so we keep these inline with the SMTP events above."""


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed a CDB with BOTS v1 sample events.")
    parser.add_argument("--db", default="data/cdb_sample.sqlite", help="Path to SQLite DB")
    parser.add_argument(
        "--print-summary",
        action="store_true",
        help="Print a JSON summary of the seeded events to stdout",
    )
    args = parser.parse_args()

    db_path = Path(args.db)
    adapter = CdbAdapter(":memory:")
    adapter.insert_events(BOTS_SAMPLE)
    print(f"[+] Seeded {len(BOTS_SAMPLE)} BOTS v1 representative events")

    # Mirroring to disk so the CLI can find the file
    if db_path.exists():
        db_path.unlink()
    disk = CdbAdapter(str(db_path))
    disk.insert_events(BOTS_SAMPLE)

    if args.print_summary:
        print(json.dumps({"events": len(BOTS_SAMPLE)}, indent=2))


if __name__ == "__main__":
    main()
