"""Show attack samples from the full scan."""
import json

with open("data/attack_scan.json", encoding="utf-8") as f:
    data = json.load(f)
for s in data["samples"]:
    print("=" * 100)
    print("host=", s["host"], "time=", s["time"], "matched=", s["matched"])
    print(s["raw"][:700])
