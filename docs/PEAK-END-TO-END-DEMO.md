# Demo end-to-end: Baseline → M-ATH → PoC + Judge (BOTS v1 sample)

> Chạy ngày 2026-09-19 trên `data/cdb_sample.sqlite` (16 events BOTS v1 thu gọn).
> Mục đích: chứng minh 3 flow PEAK chạy nối nhau trên cùng dữ liệu, không LLM ở 2 bước đầu.

## 0. Chuẩn bị dữ liệu

```bash
.venv/Scripts/python.exe scripts/seed_botsv1_sample.py
# [+] Seeded 16 BOTS v1 representative events
```

16 events bao phủ: brute-force (7 failed logons `we1149srv`), 1 logon thành công,
1 email SMTP, 1 web beacon `ad.networkfilter.co`, 2 PowerShell `-enc` ác tính,
1 PowerShell `-enc` benign (SCCM `foobar`), SMB lateral, scheduled task + Run key.

## 1. Baseline (PEAK Baseline / EDA — không LLM)

```bash
.venv/Scripts/python.exe main.py --provider cdb --db data/cdb_sample.sqlite \
  --baseline cdb:events --time-window "2016-08-21T00:00:00Z/2016-08-22T00:00:00Z"
```

Kết quả: **16 rows, 11 fields, 23 outliers, 4 gaps (0.0002s)**

| Loại | Phát hiện |
|---|---|
| Outliers (stack counting) | `native_type` hiếm: `smtp`, `web_request`, `smb`, `registry` (mỗi thứ ×1); `host=SCCM-SERVER`; `user` hiếm: `CORP\svc_admin`, `SYSTEM`; `image=schtasks.exe`; cmdline hiếm (SCCM + từng Logon Failed riêng lẻ) |
| Gaps | `domain`, `file_path`, `action`, `status` trống hoàn toàn trong window → hunt theo 4 field này không khả thi |
| Relationships | `we1149srv :: authentication` ×10 (brute-force cluster), `JGREEN-PC :: process_creation` |

Ledger: `baselines/baseline-cdb:events-<ts>.json` + report `.md` (kèm `## PEAK Act`:
SPL draft cho outlier, backlog coverage tasks, stakeholder summary).

## 2. M-ATH lite (sinh lead — không LLM)

```bash
.venv/Scripts/python.exe main.py --provider cdb --db data/cdb_sample.sqlite \
  --math cdb:events --time-window "2016-08-21T00:00:00Z/2016-08-22T00:00:00Z"
```

Kết quả: **16 rows → 25 leads (0.0013s)**

| Lead | Kind / Score | Ý nghĩa |
|---|---|---|
| `lead-020/021/022` | lexical / **6.50** | 3 cmdline PowerShell `-enc` + hidden (SCCM foobar, PDF exploit, JGREEN lateral) — encoded + hidden + no-profile cộng dồn |
| `lead-001…007` | rare_value / 5.81 | từng cmdline hiếm (SCCM + 6 Logon Failed mang IP/status khác nhau) |

Lead đúng thứ tự ưu tiên: encoded PowerShell lên trước brute-force rời rạc.
Ledger: `models/math_runs/math-<ts>.json` + report `.md` (kèm `## PEAK Act`).

## 3. PoC + Judge (PEAK Hypothesis-Driven — có LLM)

```bash
.venv/Scripts/python.exe main.py --provider cdb --db data/cdb_sample.sqlite \
  --poc-file pocs/poc-pdf-exploit-enc.json \
  --time-window "2016-08-21T00:00:00Z/2016-08-22T00:00:00Z" \
  --poc-judge --llm api
```

Kết quả: **MATCHED — 9 obs, 3 steps | JUDGE: INCONCLUSIVE (0.88)**

- Match deterministic (không LLM): `image=powershell.exe` + `cmdline ∋ -enc` + `cmdline ∋ -w hidden`.
- Judge (1 LLM call, 5963 tokens, hiển thị `[match=0, judge=1]`):
  - Bóc được SCCM event decode ra `foobar` → nghi operational noise.
  - 2 cmdline alice còn suspicious nhưng thiếu parent image, network, persistence → không dám kết TP.
  - Kết luận INCONCLUSIVE 0.88: đúng chuẩn "absence of evidence ≠ evidence of absence".

Report `artifacts/poc_hunts/*.md` có đủ: `## PEAK Prepare (ABLE)`, verdict,
`## LLM Judge`, `## PEAK Act` (SPL draft bên dưới + backlog + stakeholder).

```spl
search index="botsv1" image="powershell.exe" match(cmdline, "(?i)-enc") match(cmdline, "(?i)-w hidden") earliest=-14d latest=now
| table _time, host, user, image, cmdline, domain, file_path, action
```

## 4. Đọc kết quả theo ngôn ngữ PEAK

1. **Prepare:** PoC mang ABLE (behavior T1566.001→T1059.001, location workstations, evidence process_creation) — không còn hypothesis free-text.
2. **Execute:** Baseline vẽ normal (auth burst ×10 ở `we1149srv` là bất thường số lượng nhưng chưa rõ ác tính) → M-ATH xếp encoded PowerShell lên top → PoC confirm 9 obs → Judge giữ ở INCONCLUSIVE vì thiếu parent/network corroboration.
3. **Act:** mỗi bước đều sinh SPL draft (DRAFT, analyst review), backlog (sibling TTP, coverage tasks, lead follow-up), stakeholder summary.
4. **Knowledge:** ledger 3 tầng (`baselines/`, `models/math_runs/`, `artifacts/poc_hunts/`) tái chạy được.

## 5. Giới hạn đã biết (nói trước với sếp)

- Sample chỉ 16 events / 1 ngày — baseline window thật cần 30–90 ngày.
- CDB thiếu cột `parent_image`, `site`, `uri` tách riêng (phải encode vào `cmdline`) nên judge luôn đòi thêm parent/network evidence.
- Judge LLM non-deterministic: cùng evidence lần trước ra TRUE_POSITIVE 0.97 / INCONCLUSIVE 0.92 — chỉ dùng làm advisory.
- SPL draft là điểm khởi đầu, chưa phải production detection.
