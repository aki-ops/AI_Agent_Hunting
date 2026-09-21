"""Zoom into the real powershell.exe row and download-cradle rows."""
import sqlite3

conn = sqlite3.connect("data/botsv1_eval.sqlite")
q = conn.execute
print("real powershell.exe rows:", flush=True)
for r in q("SELECT timestamp,host,user,image,cmdline,event_id,raw_ref FROM events WHERE image='powershell.exe'"):
    print(" ", r, flush=True)
print("cradle rows:", flush=True)
for r in q("SELECT timestamp,host,user,image,cmdline FROM events WHERE LOWER(COALESCE(cmdline,'')) LIKE '%downloadstring%' OR LOWER(COALESCE(cmdline,'')) LIKE '%iex%' LIMIT 8"):
    print(" ", r, flush=True)
print("we1149 breakdown:", flush=True)
for r in q("SELECT native_type, event_id, COUNT(*) FROM events WHERE host LIKE 'we1149%' GROUP BY native_type, event_id"):
    print(" ", r, flush=True)
conn.close()
