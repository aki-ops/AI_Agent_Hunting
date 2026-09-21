"""Ground-truth eval: PoC precision/recall on the real BOTS v1 eval DB.

Method (honest, documented limits):
- Eval DB = 4.38M rows from the full BOTS v1 Security CSV (14.2M rows,
  mostly benign enterprise noise) + 66 sysmon Event-1 + 35.9k stream:dns
  from the attack-only journals.
- This dataset has NO labeled attack I can verify (no 4625 bursts, no
  real encoded powershell, no networkfilter beacon found). So recall
  against "known attack" cannot be measured here.
- What IS measurable: FALSE-POSITIVE rate — run the PoCs over real
  enterprise noise and count how many benign rows match. A good PoC
  must stay quiet on 4.38M benign rows.
- Benign controls: splunk-powershell.exe foregoes matching (PoC looks
  for image == powershell.exe exactly); the single real powershell.exe
  row is an admin Get-AppxPackage (benign, must NOT match -enc steps).

Metrics per PoC: rows scanned, rows matched, FP rate, verdict, top
match samples (to judge by eye whether they look malicious).
"""
import json
import sqlite3
import sys
import time

sys.path.insert(0, "src")
from hunting.m5_adapter import CdbAdapter
from hunting.poc import PocAgent

DB = "data/botsv1_eval.sqlite"
WINDOW = "2016-08-10T00:00:00Z/2016-08-28T23:59:59Z"

POIS = [
    ("poc-phishing-powershell-enc", "encoded powershell triple-match"),
    ("poc-c2-beacon", "external C2 beacon (.corp.internal)"),
    ("poc-office-macro", "office parent -> script child"),
    ("poc-credential-phish", "phishing URL POST"),
]


def main() -> None:
    t0 = time.time()
    total = sqlite3.connect(DB).execute("SELECT COUNT(*) FROM events").fetchone()[0]
    print(f"eval rows: {total:,}", flush=True)
    adapter = CdbAdapter(DB)
    results = []
    for poc_id, desc in POIS:
        agent = PocAgent(adapter=adapter, ledger_dir="artifacts/poc_hunts")
        t1 = time.time()
        try:
            r = agent.run(poc_id, time_window=WINDOW)
            status = "ok"
        except Exception as e:  # noqa: BLE001
            status = f"error: {e}"
            r = None
        dt = round(time.time() - t1, 2)
        if r is None:
            print(f"{poc_id}: {status}", flush=True)
            results.append({"poc_id": poc_id, "status": status})
            continue
        fp_rate = r.total_observations / total if total else 0.0
        samples = []
        for step in r.step_results:
            for row in step.rows[:2]:
                samples.append({
                    "step": step.step_id,
                    "host": row.get("host"), "user": row.get("user"),
                    "image": row.get("image"),
                    "cmdline": str(row.get("cmdline"))[:160],
                })
        print(f"{poc_id}: verdict={r.verdict} obs={r.total_observations:,} "
              f"fp_rate={fp_rate:.6f} time={dt}s", flush=True)
        results.append({
            "poc_id": poc_id, "description": desc, "status": status,
            "verdict": r.verdict, "observations": r.total_observations,
            "fp_rate": fp_rate, "runtime_seconds": dt,
            "matched_steps": r.matched_step_ids, "samples": samples,
        })
    out = {
        "db": DB, "window": WINDOW, "total_rows": total,
        "elapsed_seconds": round(time.time() - t0, 1),
        "results": results,
        "limits": [
            "No verified attack labels in this dataset slice: recall not measurable.",
            "FP rate measured against predominantly-benign enterprise noise.",
            "splunk-powershell.exe must not match image==powershell.exe (exact EQUALS).",
        ],
    }
    with open("data/eval_fp_results.json", "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    print("wrote data/eval_fp_results.json", flush=True)


if __name__ == "__main__":
    main()
