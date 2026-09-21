"""Show only interesting attack samples (4625, IEX, we1149)."""
import json

with open("data/attack_scan.json", encoding="utf-8") as f:
    data = json.load(f)
shown = 0
for s in data["samples"]:
    m = s["matched"]
    if any(t in ("4625", "IEX", "we1149") for t in m):
        print("=" * 100)
        print("host=", s["host"], "time=", s["time"], "matched=", m)
        print(s["raw"][:900])
        shown += 1
        if shown >= 12:
            break
print("counts:", data["counts"])
