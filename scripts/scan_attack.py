"""Full scan of the 14.2M-row Security CSV for attack indicators.

Looks for: 4625 failed logons, encoded/powershell cmdlines, known BOTS
attack hosts (we1149, jgreen), networkfilter IOC, mimikatz-like tokens.
Streams the gzip, keeps only hits + counters. ~10-15 min.
"""
import csv
import gzip
import json
from collections import Counter

path = "data/raw/botsv1.WinEventLog-Security.csv.gz"
tokens = ("4625", "-enc", "powershell", "mimikatz", "networkfilter",
          "banner728", "we1149", "jgreen", "JGREEN", "DownloadString",
          "IEX", "FromBase64String", "schtasks", "Run\\Updater")
counts: Counter = Counter()
hits: list[dict] = []
n = 0
with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
    reader = csv.DictReader(f)
    for row in reader:
        n += 1
        raw = row.get("_raw") or ""
        found = [t for t in tokens if t.lower() in raw.lower()]
        if found:
            for t in found:
                counts[t] += 1
            if len(hits) < 60:
                hits.append({
                    "host": row.get("host"), "time": row.get("_time"),
                    "matched": found,
                    "raw": raw[:600].replace("\n", " | "),
                })
        if n % 2000000 == 0:
            print(f"scanned {n:,} ... hits-so-far={dict(counts)}", flush=True)
print("TOTAL scanned:", n, flush=True)
print("token hits:", dict(counts), flush=True)
with open("data/attack_scan.json", "w", encoding="utf-8") as f:
    json.dump({"scanned": n, "counts": dict(counts), "samples": hits}, f, indent=2)
print("wrote data/attack_scan.json", flush=True)
