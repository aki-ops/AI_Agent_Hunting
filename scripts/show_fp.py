"""Show which rows falsely matched the PoCs."""
import json

with open("data/eval_fp_results.json", encoding="utf-8") as f:
    data = json.load(f)
for r in data["results"]:
    print("=" * 80)
    print(r["poc_id"], r.get("verdict"), "obs=", r.get("observations"),
          "matched=", r.get("matched_steps"))
    for s in r.get("samples", []):
        print(f"  [{s['step']}] host={s['host']} user={s['user']} image={s['image']}")
        print(f"    cmdline={s['cmdline']}")
