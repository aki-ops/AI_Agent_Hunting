"""Peek at Splunk journal.gz: list sourcetypes and sample events."""
import gzip
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else (
    "data/raw/attack/botsv1_data_set/var/lib/splunk/botsv1/db/"
    "db_1470868141_1470799731_28/rawdata/journal.gz"
)
print("reading", path, flush=True)
with gzip.open(path, "rb") as f:
    data = f.read()
print("decompressed bytes:", len(data), flush=True)
hits = re.findall(rb"sourcetype::([A-Za-z0-9:_.\-]+)", data)
print("sourcetype event markers:", len(hits), flush=True)
from collections import Counter
for st, n in Counter(hits).most_common(40):
    print(f"  {st.decode()} x{n}", flush=True)
