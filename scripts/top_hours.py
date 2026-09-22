"""Find peak Joomla attack hours in the eval DB."""
import sqlite3

conn = sqlite3.connect("data/botsv1_eval.sqlite")
print("joomla rows per hour on 2016-08-10:", flush=True)
for r in conn.execute(
    "SELECT SUBSTR(timestamp,1,13) h, COUNT(*) c FROM events "
    "WHERE domain='imreallynotbatman.com' AND timestamp LIKE '2016-08-10%' "
    "GROUP BY h ORDER BY c DESC LIMIT 8"
):
    print(" ", r, flush=True)
print("min/max ts:", conn.execute(
    "SELECT MIN(timestamp), MAX(timestamp) FROM events "
    "WHERE domain='imreallynotbatman.com'").fetchone(), flush=True)
conn.close()
