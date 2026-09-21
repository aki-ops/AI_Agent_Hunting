"""Peek at raw content of BOTS Security CSV rows."""
import csv
import gzip
from collections import Counter

path = "data/raw/botsv1.WinEventLog-Security.csv.gz"
with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
    reader = csv.DictReader(f)
    for i, row in enumerate(reader):
        if i < 2:
            print("KEYS:", list(row.keys()))
            print("HOST:", row.get("host"))
            print("TIME:", row.get("_time"))
            print("RAW:", (row.get("_raw") or "")[:800])
            print("-" * 60)
        if i == 2:
            break
    # count event codes inside _raw
    codes: Counter = Counter()
    n = 0
    for row in reader:
        n += 1
        raw = row.get("_raw") or ""
        for code in ("4625", "4624", "4688", "4672", "4648", "5140", "5145"):
            if f"EventCode={code}" in raw or f"EventID>{code}<" in raw:
                codes[code] += 1
        if n >= 200000:
            break
    print("scanned:", n)
    print("codes in first 200k:", dict(codes))
