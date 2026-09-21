"""Scan stream:http CSV for the BOTS C2 beacon and attack hosts."""
import csv
import gzip
from collections import Counter

path = "data/raw/botsv1.stream-http.csv.gz"
print("opening", path, flush=True)
with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
    reader = csv.DictReader(f)
    print("columns:", reader.fieldnames, flush=True)
    n = 0
    counts: Counter = Counter()
    samples: list[dict] = []
    for row in reader:
        n += 1
        raw = row.get("_raw") or ""
        low = raw.lower()
        hit = []
        if "networkfilter" in low:
            hit.append("networkfilter")
        if "banner" in low:
            hit.append("banner")
        if "we1149" in low:
            hit.append("we1149")
        if "jgreen" in low:
            hit.append("jgreen")
        if hit:
            for h in hit:
                counts[h] += 1
            if len(samples) < 10:
                samples.append({"host": row.get("host"), "time": row.get("_time"),
                                "matched": hit, "raw": raw[:500].replace("\n", " | ")})
        if n % 500000 == 0:
            print(f"  ...{n:,} hits={dict(counts)}", flush=True)
print("TOTAL:", n, flush=True)
print("hits:", dict(counts), flush=True)
for s in samples:
    print("=" * 100)
    print(s["host"], s["time"], s["matched"])
    print(s["raw"][:500])
