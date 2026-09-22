# Demo end-to-end: Baseline survey → Lead scoring → PoC + Judge (BOTS v1 sample)

> Chạy ngày 2026-09-19 trên `data/cdb_sample.sqlite` (16 events BOTS v1 thu gọn).
> Mục đích: chứng minh baseline, xếp lead, rồi PoC trên cùng dữ liệu.
> Baseline không gọi LLM. `--math` gọi API LLM trong `.env` (không train model tại chỗ);
> nếu API không có thì prefilter stdlib và ghi rõ nguồn. PoC đi qua Prepare có sẵn trong file,
> một vòng refine, IR khi có finding, rồi Act. Judge LLM vẫn chỉ là advisory.

## 0. Chuẩn bị dữ liệu

```bash
.venv/Scripts/python.exe scripts/seed_botsv1_sample.py
# [+] Seeded 16 BOTS v1 representative events
```

16 events bao phủ: brute-force (7 failed logons `we1149srv`), 1 logon thành công,
1 email SMTP, 1 web beacon `ad.networkfilter.co`, 2 PowerShell `-enc` ác tính,
1 PowerShell `-enc` benign (SCCM `foobar`), SMB lateral, scheduled task + Run key.

## 1. Baseline survey (EDA — không LLM)

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

## 2. Xếp lead bằng API LLM (không train model cục bộ)

`--math` gửi mẫu hàng tới model trong `.env`. Không có cuộc train. Lead bịa, không có trong hàng, bị loại.
`--llm stub` chỉ chạy prefilter stdlib và report ghi `heuristic_prefilter`.

```bash
.venv/Scripts/python.exe main.py --provider cdb --db data/cdb_sample.sqlite \
  --math cdb:events --time-window "2016-08-21T00:00:00Z/2016-08-22T00:00:00Z"
```

Lệnh trên, khi `.env` có API, ghi `model_source=api_llm` và chỉ giữ lead mà model copy từ hàng.
Bảng sau là snapshot prefilter ngày demo (16 rows, không gọi API) — dùng để đối chiếu khi `--llm stub`:

Kết quả prefilter: **16 rows → 25 leads (0.0013s)**

| Lead | Kind / Score | Ý nghĩa |
|---|---|---|
| `lead-020/021/022` | lexical / **6.50** | 3 cmdline PowerShell `-enc` + hidden (SCCM foobar, PDF exploit, JGREEN lateral) — encoded + hidden + no-profile cộng dồn |
| `lead-001…007` | rare_value / 5.81 | từng cmdline hiếm (SCCM + 6 Logon Failed mang IP/status khác nhau) |

Lead đúng thứ tự ưu tiên: encoded PowerShell lên trước brute-force rời rạc.
Ledger: `models/math_runs/math-<ts>.json` + report `.md` (kèm `## PEAK Act`).

## 3. PoC + Judge (hypothesis có cấu trúc — LLM chỉ advisory)

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

Report `artifacts/poc_hunts/*.md` có: `## Hunt Plan (ABLE)`, `## Execute (Analyze → Refine)`, `## IR Escalation`, verdict,
`## LLM Judge` khi bật judge, và `## Act` với trạng thái SPL (`VALIDATED` khi parser Splunk chấp nhận, còn lại `DRAFT` hoặc `INVALID`).
Backlog nối vào `artifacts/backlog/backlog.jsonl`. Stakeholder nằm ở `artifacts/act/<request_id>/stakeholder.md`.

```spl
search index="botsv1" image="powershell.exe" match(cmdline, "(?i)-enc") match(cmdline, "(?i)-w hidden") earliest=-14d latest=now
| table _time, host, user, image, cmdline, domain, file_path, action
```

## 4. Đọc kết quả (dùng ngôn ngữ PEAK khi trình bày, giữ bản chất khi làm kỹ thuật)

1. **Prepare:** PoC đã có topic, research, ABLE, scope, `max_duration=3d`, plan. Evidence có `powershell.exe` và `-Enc`, hai token đó được AND vào search. Location là văn xuôi, không thành filter host.
2. **Chạy:** Baseline vẽ normal → `--math` xếp lead bằng API LLM (hoặc prefilter nếu không có API) → PoC analyze rồi refine nếu step đầu chỉ ra một host → Judge giữ INCONCLUSIVE khi thiếu parent/network.
3. **Act:** SPL được kiểm tra tĩnh; parser Splunk chạy khi provider là splunk. Backlog và stakeholder được ghi file.
4. **IR:** lần MATCHED ghi `artifacts/poc_hunts/ir/<request_id>.json`. Lần EMPTY không có LLM thì không mở hồ sơ IR.

## 5. Giới hạn đã biết (nói trước với sếp)

- Sample chỉ 16 events / 1 ngày — baseline window thật cần 30–90 ngày.
- CDB thiếu cột `parent_image`, `site`, `uri` tách riêng (phải encode vào `cmdline`) nên judge luôn đòi thêm parent/network evidence.
- Judge LLM non-deterministic: cùng evidence lần trước ra TRUE_POSITIVE 0.97 / INCONCLUSIVE 0.92 — chỉ dùng làm advisory.
- SPL `VALIDATED` mới chỉ là parser chấp nhận cú pháp. Analyst vẫn duyệt trước khi phát hành detection.
