"""Find real EventCode=4625 rows (not 4656 containing '4625') and IEX rows."""
import csv
import gzip

path = "data/raw/botsv1.WinEventLog-Security.csv.gz"
found_4625 = 0
found_iex = 0
with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
    reader = csv.DictReader(f)
    for row in reader:
        raw = row.get("_raw") or ""
        if "EventCode=4625" in raw:
            found_4625 += 1
            if found_4625 <= 3:
                print("4625 host=", row.get("host"), "time=", row.get("_time"))
                print(raw[:700].replace("\n", " | "))
                print("-" * 80)
        if "IEX" in raw and found_iex < 3:
            found_iex += 1
            print("IEX host=", row.get("host"), "time=", row.get("_time"))
            print(raw[:700].replace("\n", " | "))
            print("-" * 80)
print("real 4625:", found_4625, "iex-shown:", found_iex, flush=True)
