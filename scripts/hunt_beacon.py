"""Hunt the real C2 beacon: networkfilter or joomla exploit in stream:http."""
import csv
import gzip
import re
from collections import Counter

path = "data/raw/botsv1.stream-http.csv.gz"
sites: Counter = Counter()
uris: Counter = Counter()
beacon = 0
n = 0
with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
    reader = csv.DictReader(f)
    for row in reader:
        n += 1
        raw = row.get("_raw") or ""
        low = raw.lower()
        if "networkfilter" in low:
            beacon += 1
            if beacon <= 3:
                print("BEACON:", raw[:400].replace("\n", " "))
        m = re.search(r'"site":\s*"([^"]+)"', raw)
        if m:
            sites[m.group(1)] += 1
        u = re.search(r'"uri_path":\s*"([^"]+)"', raw)
        if u:
            uris[u.group(1)[:80]] += 1
print("TOTAL:", n, "networkfilter rows:", beacon, flush=True)
print("top sites:", sites.most_common(15), flush=True)
print("top uri_paths:", uris.most_common(15), flush=True)
