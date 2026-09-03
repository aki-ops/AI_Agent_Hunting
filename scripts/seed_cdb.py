"""Seed a sample SQLite database (data/cdb_sample.sqlite) with realistic security events."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Add src to sys.path so hunting can be imported
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from hunting.m5_adapter import CdbAdapter

SAMPLE_EVENTS = [
    # 1. Normal user activity prior to incident
    {
        "timestamp": "2026-09-01T09:30:00Z",
        "event_id": "4624",
        "native_type": "authentication",
        "host": "DESKTOP-VICTIM1",
        "user": "CORP\\alice",
        "action": "logon",
        "status": "success",
    },
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
    },
    # 2. Phishing payload execution (PowerShell)
    {
        "timestamp": "2026-09-01T10:14:30Z",
        "event_id": "4688",
        "native_type": "process_creation",
        "host": "DESKTOP-VICTIM1",
        "user": "CORP\\alice",
        "pid": 4820,
        "ppid": 1020,
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "cmdline": "powershell.exe -NoP -NonI -W Hidden -Enc JABhID0A...",
    },
    # 3. Network C2 beaconing
    {
        "timestamp": "2026-09-01T10:14:45Z",
        "event_id": "3",
        "native_type": "net_connect",
        "host": "DESKTOP-VICTIM1",
        "pid": 4820,
        "ip": "192.168.1.50",
        "port": 443,
        "domain": "evil-c2.corp.internal.",
    },
    # 4. Dropped persistence file
    {
        "timestamp": "2026-09-01T10:15:20Z",
        "event_id": "11",
        "native_type": "file_write",
        "host": "DESKTOP-VICTIM1",
        "user": "CORP\\alice",
        "pid": 4820,
        "file_path": "C:\\Users\\alice\\AppData\\Local\\Temp\\update_task.dll",
        "action": "create",
    },
    # 5. Registry Persistence
    {
        "timestamp": "2026-09-01T10:15:30Z",
        "event_id": "13",
        "native_type": "registry_change",
        "host": "DESKTOP-VICTIM1",
        "user": "CORP\\alice",
        "pid": 4820,
        "action": "set_value",
        "cmdline": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
    },
    # 6. Secondary host activity
    {
        "timestamp": "2026-09-01T10:20:00Z",
        "event_id": "4624",
        "native_type": "authentication",
        "host": "DC-SRV01",
        "user": "CORP\\svc_backup",
        "action": "logon",
        "status": "success",
    },
]


def seed_database(db_path: str | Path) -> None:
    """Create and seed SQLite database with sample attack telemetry."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    adapter = CdbAdapter(str(path))
    adapter.insert_events(SAMPLE_EVENTS)
    print(f"[+] Successfully seeded {len(SAMPLE_EVENTS)} events into {path.resolve()}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed CDB sample telemetry database")
    parser.add_argument(
        "--db",
        type=str,
        default="data/cdb_sample.sqlite",
        help="Path to output SQLite database (default: data/cdb_sample.sqlite)",
    )
    args = parser.parse_args()
    seed_database(args.db)


if __name__ == "__main__":
    main()
