"""Check ground-truth signals in the eval DB."""
import sqlite3

conn = sqlite3.connect("data/botsv1_eval.sqlite")
q = conn.execute
print("total:", q("SELECT COUNT(*) FROM events").fetchone()[0], flush=True)
print("4625:", q("SELECT COUNT(*) FROM events WHERE event_id='4625'").fetchone()[0], flush=True)
print("4624:", q("SELECT COUNT(*) FROM events WHERE event_id='4624'").fetchone()[0], flush=True)
print("4688:", q("SELECT COUNT(*) FROM events WHERE event_id='4688'").fetchone()[0], flush=True)
print("powershell:", q("SELECT COUNT(*) FROM events WHERE LOWER(COALESCE(image,'')) LIKE '%powershell%'").fetchone()[0], flush=True)
print("ps+enc:", q("SELECT COUNT(*) FROM events WHERE LOWER(COALESCE(image,'')) LIKE '%powershell%' AND LOWER(COALESCE(cmdline,'')) LIKE '%-enc%'").fetchone()[0], flush=True)
print("hidden:", q("SELECT COUNT(*) FROM events WHERE LOWER(COALESCE(cmdline,'')) LIKE '%hidden%'").fetchone()[0], flush=True)
print("networkfilter:", q("SELECT COUNT(*) FROM events WHERE COALESCE(cmdline,'') LIKE '%networkfilter%' OR COALESCE(domain,'') LIKE '%networkfilter%'").fetchone()[0], flush=True)
print("sysmon rows:", q("SELECT COUNT(*) FROM events WHERE raw_ref='botsv1-sysmon-1'").fetchone()[0], flush=True)
print("--- sample powershell rows:", flush=True)
for r in q("SELECT timestamp,host,user,image,cmdline,raw_ref FROM events WHERE LOWER(COALESCE(image,'')) LIKE '%powershell%' LIMIT 5"):
    print(r, flush=True)
print("--- distinct images top:", flush=True)
for r in q("SELECT image, COUNT(*) c FROM events WHERE image IS NOT NULL GROUP BY image ORDER BY c DESC LIMIT 15"):
    print(r, flush=True)
conn.close()
