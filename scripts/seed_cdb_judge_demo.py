"""Seed the CDB with three scenarios for the judge demo:
1. Phishing PowerShell-Enc with parent=outlook (TRUE_POSITIVE expected)
2. SCCM admin script with -Enc (FALSE_POSITIVE expected)
3. OUTLOOK.EXE running alone (no -Enc -> no PoC match)
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from hunting.m5_adapter import CdbAdapter

db_path = Path("data") / "cdb_sample.sqlite"

EVENTS = [
    # 1. Phishing PowerShell-Enc (parent=outlook)
    {
        "timestamp": "2026-09-01T09:35:10Z",
        "event_id": "4688",
        "native_type": "process_creation",
        "host": "DESKTOP-VICTIM1",
        "user": "CORP\\alice",
        "pid": 1020,
        "ppid": 800,
        "image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
        "cmdline": '"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"',
        "raw_ref": "outlook-001",
    },
    {
        "timestamp": "2026-09-01T10:14:30Z",
        "event_id": "4688",
        "native_type": "process_creation",
        "host": "DESKTOP-VICTIM1",
        "user": "CORP\\alice",
        "pid": 4820,
        "ppid": 1020,
        "parent_image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "cmdline": "powershell.exe -NoP -NonI -W Hidden -Enc JABhID0A...",
        "raw_ref": "phish-001",
    },

    # 2. SCCM admin script with -Enc (FALSE_POSITIVE expected)
    {
        "timestamp": "2026-09-01T03:00:00Z",
        "event_id": "4688",
        "native_type": "process_creation",
        "host": "SCCM-SERVER",
        "user": "CORP\\svc_admin",
        "pid": 7200,
        "ppid": 600,
        "parent_image": "C:\\Program Files\\Microsoft Configuration Manager\\bin\\CmRcViewer.exe",
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "cmdline": "powershell.exe -NoP -NonI -W Hidden -Enc Zm9vYmFy...",
        "raw_ref": "sccm-001",
    },
]

adapter = CdbAdapter(":memory:")
adapter.insert_events(EVENTS)
print(f"[+] Seeded {len(EVENTS)} events")

# Mirror to disk for the CLI command
import shutil, sqlite3
shutil.copy(Path("data") / "cdb_sample.sqlite", Path("data") / "cdb_sample.sqlite.backup") if (Path("data") / "cdb_sample.sqlite").exists() else None
disk = CdbAdapter(str(db_path) if db_path.exists() else ":memory:")
disk.insert_events(EVENTS)
print(f"[+] Mirrored to {db_path}")
