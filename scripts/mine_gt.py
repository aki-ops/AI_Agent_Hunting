"""Mine rare-process and DNS ground truth in the eval DB."""
import sqlite3

conn = sqlite3.connect("data/botsv1_eval.sqlite")
q = conn.execute
print("rare non-splunk images:", flush=True)
for r in q(
    "SELECT image, COUNT(*) c FROM events WHERE image IS NOT NULL "
    "AND image NOT LIKE 'splunk-%' GROUP BY image ORDER BY c ASC LIMIT 30"
):
    print(" ", r, flush=True)
print("cmdline with enc (any):", q(
    "SELECT COUNT(*) FROM events WHERE LOWER(COALESCE(cmdline,'')) LIKE '%-enc%'").fetchone()[0], flush=True)
print("cmdline download cradle:", q(
    "SELECT COUNT(*) FROM events WHERE LOWER(COALESCE(cmdline,'')) LIKE '%downloadstring%' OR LOWER(COALESCE(cmdline,'')) LIKE '%iex%'").fetchone()[0], flush=True)
print("sysmon samples:", flush=True)
for r in q("SELECT timestamp,host,user,image,cmdline FROM events WHERE raw_ref='botsv1-sysmon-1' LIMIT 8"):
    print(" ", r, flush=True)
print("we1149 rows:", q(
    "SELECT COUNT(*) FROM events WHERE host LIKE 'we1149%'").fetchone()[0], flush=True)
print("dns rows:", q(
    "SELECT COUNT(*) FROM events WHERE native_type='dns'").fetchone()[0], flush=True)
conn.close()
