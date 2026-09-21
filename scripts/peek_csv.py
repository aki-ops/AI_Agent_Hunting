"""Peek at BOTS Security CSV: header, row count, event distribution."""
import csv
import gzip
from collections import Counter

path = "data/raw/botsv1.WinEventLog-Security.csv.gz"
print("opening", path, flush=True)
with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
    reader = csv.DictReader(f)
    print("columns:", reader.fieldnames, flush=True)
    codes: Counter = Counter()
    n = 0
    sample_4625 = None
    sample_4688 = None
    for row in reader:
        n += 1
        code = row.get("EventCode") or row.get("EventID") or row.get("event_id")
        codes[code] += 1
        if code == "4625" and sample_4625 is None:
            sample_4625 = row
        if code == "4688" and sample_4688 is None:
            sample_4688 = row
        if n % 500000 == 0:
            print(f"  ...{n}", flush=True)
    print("total rows:", n, flush=True)
    print("top event codes:", codes.most_common(15), flush=True)
    print("sample 4625:", dict(list((sample_4625 or {}).items())[:12]), flush=True)
    print("sample 4688:", dict(list((sample_4688 or {}).items())[:12]), flush=True)
