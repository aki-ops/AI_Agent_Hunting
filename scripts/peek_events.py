"""Peek at extracted event samples per sourcetype."""
import json
from pathlib import Path

for path in sorted(Path("data/raw/events").glob("*.jsonl")):
    print("=" * 80)
    print(path.name, path.stat().st_size, "bytes")
    with open(path, encoding="utf-8") as f:
        for i in range(2):
            line = f.readline()
            if not line:
                break
            ev = json.loads(line)
            print(f"  host={ev['host']}")
            print("  raw:", ev["raw"][:500].replace("\n", " | "))
