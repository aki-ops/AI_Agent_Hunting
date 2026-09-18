# BOTS v1 walkthrough — without Splunk

You don't need a Splunk instance. The PoC agent works against any
adapter that implements `execute_query(operation_id="search_text",
search_terms=[...])`. The `CdbAdapter` does this against a local SQLite
file (`data/cdb_sample.sqlite`); the `SplunkLiveAdapter` does it against
real Splunk.

This guide uses the **CDB route** so you can run the demo today.

## 1. Seed the CDB with a representative BOTS v1 sample

```bash
python scripts/seed_botsv1_sample.py
```

This writes 16 representative events to `data/cdb_sample.sqlite`. They
mirror the core BOTS v1 attack chains:

| Time (2016-08-21) | Event | MITRE |
|---|---|---|
| 03:00–03:06 | 7 failed logons to `we1149srv` (brute-force) | T1110 |
| 03:08 | alice successful logon (post-bruteforce pivot) | T1078 |
| 06:02 | phishing email SMTP ingest | T1566.001 |
| 08:14 | beacon to `ad.networkfilter.co` | T1071.001 |
| 08:14 | powershell -enc PDF exploit child | T1059.001 + T1027 |
| 11:33 | SMB lateral movement to JGREEN-PC | T1021.002 |
| 11:42 | scheduled task + Run-key persistence | T1053.005 / T1547.001 |
| 02:15 | benign SCCM admin script (FP candidate) | — |

## 2. Run the built-in PoC library

```bash
python main.py --provider cdb --db data/cdb_sample.sqlite \
  --poc-chain "poc-phishing-powershell-enc,poc-c2-beacon" \
  --time-window "2016-08-21T00:00:00Z/2016-08-22T00:00:00Z"
```

The built-in PoCs use generic IOC / TTP patterns, so against BOTS v1:

- `poc-phishing-powershell-enc` → **MATCHED** (3 encoded PowerShell rows)
- `poc-c2-beacon` → **EMPTY** (built-in looks for `.corp.internal`, but BOTS v1 has `networkfilter.co`)

## 3. Run with a JSON PoC file (analyst-authored)

PoCs under `pocs/` match the real BOTS v1 IOCs:

```bash
# Brute-force phase (T1110)
python main.py --provider cdb --db data/cdb_sample.sqlite \
  --poc-file pocs/poc-bruteforce-we1149srv.json \
  --time-window "2016-08-21T00:00:00Z/2016-08-22T00:00:00Z"
# → MATCHED — 15 obs, 2 matched steps

# C2 beacon to ad.networkfilter.co (T1071.001)
python main.py --provider cdb --db data/cdb_sample.sqlite \
  --poc-file pocs/poc-c2-beacon-networkfilter.json \
  --time-window "2016-08-21T00:00:00Z/2016-08-22T00:00:00Z"
# → MATCHED — 2 obs, 2 matched steps

# PDF exploit encoded PowerShell (T1059.001 + T1566.001)
python main.py --provider cdb --db data/cdb_sample.sqlite \
  --poc-file pocs/poc-pdf-exploit-enc.json \
  --time-window "2016-08-21T00:00:00Z/2016-08-22T00:00:00Z"
# → MATCHED — 3 obs, 3 matched steps
```

## 4. Run the chain end-to-end with the LLM Judge

```bash
python main.py --provider cdb --db data/cdb_sample.sqlite \
  --poc-file pocs/poc-c2-beacon-networkfilter.json \
  --time-window "2016-08-21T00:00:00Z/2016-08-22T00:00:00Z" \
  --poc-judge \
  --llm api \
  --poc-judge-max-tokens 4000
```

The judge will then call your LLM and return TRUE_POSITIVE /
FALSE_POSITIVE / INCONCLUSIVE / NO_SIGNAL. Without `--llm api`,
the analyzer runs in stub mode and no judge fires.

## 5. Running against a real Splunk (when you have one)

The same `--poc-chain` / `--poc-file` switches work against Splunk:

```bash
python main.py --provider splunk \
  --splunk-url https://localhost:8089 \
  --splunk-user admin --splunk-pass changeme \
  --splunk-index botsv1 \
  --poc-file pocs/poc-bruteforce-we1149srv.json \
  --time-window "2016-08-21T00:00:00Z/2016-08-21T23:59:59Z" \
  --poc-judge --llm api
```

The `SplunkLiveAdapter` already exposes `operation_id="search_text"` in
`src/hunting/m5_adapter/splunk_adapter.py` — it issues
`search index="botsv1" "Logon Failed" ...` SPL and parses the standard
search-results JSON. The PoC agent doesn't know it's talking to Splunk.

To set up a local Splunk with BOTS v1:

```bash
# Option A: docker compose (Splunk enterprise is multi-GB, this is the
# minimum that runs locally):
docker pull splunk/splunk:latest
docker run -d -p 8000:8000 -p 8089:8089 \
  -e SPLUNK_START_ARGS="--accept-license" \
  -e SPLUNK_PASSWORD=changeme \
  splunk/splunk:latest

# Then upload botsv1_events.zip from
# https://github.com/splunk/botsv1_data_set via the Splunk UI.
```

Or load via the Splunk Add-On for BOTS v1.

## 6. Format for your own BOTS PoCs

See `pocs/poc-bruteforce-we1149srv.json` for the schema. The two
guaranteed CDB-searched columns are:

```
raw_ref, cmdline, image, file_path, domain, user, host, native_type
```

For BOTS v1 payloads you typically encode structured fields
(`subject=...`, `attachment=...`, `status=...`) into the `cmdline`
column so they're searchable via `LIKE '%...%'`.

## 7. What the matcher does

```
PoC step:        target_field=cmdline, op=CONTAINS, value="Logon Failed"
                              |
                              v
adapter.execute_query(operation_id="search_text", search_terms=["Logon Failed"])
                              |
                              v
CDB: SELECT * FROM events WHERE ... AND cmdline LIKE '%Logon Failed%'
                              |
                              v
rows -> StepResult{row_count, rows}
                              |
                              v
matched step -> report MATCHED -> judge evaluates with LLM
```

No AI is involved in matching. AI is involved only when:

- the matcher returns EMPTY and the PoC has an `escalation_hint`, **or**
- the analyst passes `--poc-judge`, in which case the matched rows
  are passed to the LLM for TP/FP adjudication.
