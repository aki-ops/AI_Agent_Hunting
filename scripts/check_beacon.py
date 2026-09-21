"""Check if stream:http banner hits are the real C2 beacon."""
import csv
import gzip
import re

path = "data/raw/botsv1.stream-http.csv.gz"
with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
    reader = csv.DictReader(f)
    for i, row in enumerate(reader):
        raw = row.get("_raw") or ""
        if "banner" not in raw.lower():
            continue
        uri = re.search(r'"uri(_path)?":\s*"([^"]+)"', raw)
        host = re.search(r'"(dest_host|host|server)":\s*"([^"]+)"', raw)
        site = re.search(r'"site":\s*"([^"]+)"', raw)
        print(i, "uri=", uri.group(2) if uri else "?", "| host=", host.group(2) if host else "?", "| site=", site.group(1) if site else "?")
        if i > 0 and sum(1 for _ in [0]) :
            pass
        if i >= 0:
            # print first 6 banner rows then stop
            pass
        break
# print first 6 banner rows with uri
n = 0
with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
    reader = csv.DictReader(f)
    for row in reader:
        raw = row.get("_raw") or ""
        if "banner" not in raw.lower():
            continue
        uri = re.search(r'"uri(_path)?":\s*"([^"]+)"', raw)
        dest = re.search(r'"dest_ip":\s*"([^"]+)"', raw)
        print("uri=", uri.group(2)[:120] if uri else "?", "| dest_ip=", dest.group(1) if dest else "?")
        n += 1
        if n >= 6:
            break
