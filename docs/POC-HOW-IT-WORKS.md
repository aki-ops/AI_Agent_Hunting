# PoC và cách nó tìm dữ liệu — giải thích

## Câu hỏi: PoC biết "tìm cái gì" ở đâu?

PoC **không biết gì cả** — nó chỉ là 1 danh sách predicate `(column, op, value)` đã viết sẵn. Agent chạy mỗi predicate qua adapter. Không có AI trong quá trình match.

## Ví dụ thật: PoC `poc-phishing-powershell-enc`

```python
PoC(
    poc_id="poc-phishing-powershell-enc",
    name="Phishing email led to PowerShell encoded command",
    kind=PocKind.TTP,                          # MITRE T1059.001
    summary="Detect encoded PowerShell execution on a workstation.",
    steps=[
        TestStep(
            step_id="s1-powershell-enc",
            description="Look for powershell.exe",
            target_field="image",                # <-- CỘT nào trong CDB
            op=FieldOp.EQUALS,                   # <-- PHÉP SO SÁNH
            value="powershell.exe",              # <-- GIÁ TRỊ
            source_kind="process",               # <-- định tuyến adapter
        ),
        TestStep(
            step_id="s2-powershell-hidden",
            target_field="cmdline",
            op=FieldOp.CONTAINS,
            value="-W Hidden",
            source_kind="process",
        ),
        TestStep(
            step_id="s3-powershell-encoded",
            target_field="cmdline",
            op=FieldOp.CONTAINS,
            value="-Enc",
            source_kind="process",
        ),
    ],
)
```

Có 3 step. Mỗi step được chạy qua adapter như sau:

```
agent → adapter.execute_query(
    operation_id="search_text",
    entity=None,                         # hoặc Host nếu ABLE location là host cụ thể
    window="2026-09-01/02",
    search_terms=["powershell.exe", "-Enc"],
)
```

`powershell.exe` là value của step. `-Enc` là token cụ thể lấy từ ABLE evidence, được AND thêm. Sau SQL, agent còn lọc đúng operator trên cột đích (`EQUALS` là khớp nguyên tên file, không phải LIKE).

**CDB adapter** (`src/hunting/m5_adapter/cdb_adapter.py`):
```sql
SELECT * FROM events
WHERE timestamp BETWEEN ? AND ?
  AND (raw_ref LIKE '%powershell.exe%' OR
       cmdline LIKE '%powershell.exe%' OR
       image LIKE '%powershell.exe%' OR
       ...  -- tất cả cột text)
```

**Splunk adapter** (cần implement cho POC nếu muốn chạy trên Splunk):
```spl
search "powershell.exe" index=botsv1 earliest=... latest=...
| head 100
```

## Prepare trước khi query

Hunt không chạy nếu thiếu topic, research, behavior, location, evidence, scope, max duration hoặc plan. Actor được trống. Ba cách đưa plan:

1. Trường đó đã nằm trong PoC / file JSON.
2. `--hunt-plan configs/hunt_plan.example.yaml`.
3. `--prepare` hỏi tuần tự trên terminal.

`max_duration: 3d` cắt cửa sổ telemetry dài hơn 3 ngày về 3 ngày cuối, và là hạn của pass refine.

ABLE lái query bằng token cụ thể. Với PoC phishing, evidence chứa `powershell.exe` và `-Enc`, nên mỗi step AND thêm hai token đó. Câu "end-user workstations" không có host dạng `DESKTOP-VICTIM1` nên không thành filter host.

## Execute: analyze, refine, IR

Pass 1 chạy các step. Nếu step khớp đầu chỉ có một host, pass 2 chạy lại các step còn lại trên host đó. Nếu cả pass 1 rỗng, agent chạy fallback rồi chạy lại đúng predicate cũ, không đổi `EQUALS` thành `CONTAINS`.

Có hàng khớp, hoặc có narrative LLM khi rỗng, thì ghi `artifacts/poc_hunts/ir/<request_id>.json` cho IR. Narrative đó không phải evidence.

## Tóm tắt

| Thành phần | Vai trò | AI? |
|---|---|---|
| Prepare (`--prepare`, `--hunt-plan`, trường trên PoC) | Cửa trước query | Không |
| PoC | Predicate field/op/value | Không |
| `compile_poc` | Graph + constraint ABLE | Không |
| `_execute_loop` | Pass 1, analyze, tối đa một pass refine | Không |
| Adapter | LIKE/SPL | Không |
| IR file | Gói bàn giao khi có finding hoặc narrative | Không tạo evidence |
| `judge()` | Chấm TP/FP sau khi đã có rows | LLM, advisory |
| `escalation_hint` | Chỉ khi adapter rỗng và bật escalation | LLM, advisory |

Match = rules. LLM không tạo hàng.

AI chỉ dùng ở 2 chỗ:
- **Escalation** (khi adapter không tìm thấy gì): LLM được hỏi 1 câu bounded để có hay không có signal.
- **Judge** (sau khi có rows): LLM đánh giá rows có phải TP hay FP hay INCONCLUSIVE.

Nếu bạn thích không dùng LLM, dùng `--stub` (default) hoặc đơn giản bỏ `--poc-judge`.

## Bạn muốn tự viết PoC thì sao?

Bạn cần trả lời 4 câu cho mỗi bước:

1. **Tên cột trong database/log** là gì? (`cmdline`, `image`, `dest_ip`, `domain`, `user`, `host`, ...)
2. **So sánh thế nào?** (`EQUALS`, `CONTAINS`, `STARTS_WITH`, `ENDS_WITH`, `MATCHES` regex, `EXISTS`).
3. **Giá trị khớp** là gì? (`powershell.exe`, `evil-c2.com`, `192.168.1.100`).
4. **Loại telemetry** (process / dns / web / file) — để adapter định tuyến.

Ví dụ để tự viết PoC "tìm failed login liên tục trên hệ thống quan trọng":

```json
{
  "poc_id": "poc-bruteforce-ssh",
  "name": "Brute force login detected",
  "kind": "behavior",
  "summary": "Detect repeated failed authentication events (>= 10/min) on a host",
  "steps": [
    {
      "step_id": "s1-failed-auth",
      "target_field": "action",
      "op": "EQUALS",
      "value": "failure",
      "source_kind": "authentication"
    }
  ],
  "references": ["MITRE ATT&CK T1110"]
}
```

Lưu vào `pocs/my-bruteforce.json`, gõ:

```bash
python main.py --poc-file pocs/my-bruteforce.json
```

Đến commit sau tôi sẽ implement `--poc-file` để bạn dùng được.

## Tại sao dùng rule, không dùng AI để "tự tìm"?

| | Rules (PoC) | AI prompt "tìm threat đi" |
|---|---|---|
| Tái lập | 100% — same PoC → same output | Phụ thuộc LLM |
| Phí tổn | $0 (PoC chỉ chạy rules) | $$ per token |
| Tốc độ | Milliseconds | Seconds/minutes |
| Có thể ground-truth | Có — labeled scenarios | Khó |
| Lý giải | Step-by-step có thể audit | Black box |

Cách tốt nhất là **rules bắt signal**, **AI judge giải thích** — đó là dual-layer của repo này.

## Thực tế PoC chạy với data như nào?

Ví dụ, nếu bạn có BOTS v1 dataset (công khai trên GitHub) — nó có nhiều host, nhiều loại attack. PoC agent sẽ:

1. Đọc CDB → nếu có BOTS v1 events đã import → chạy trên đó.
2. Đọc Splunk → nếu BOTS v1 index có sẵn → cần `search_text` (chưa có, sẽ thêm).

3 step "tìm encoded PowerShell":
- `image LIKE '%powershell.exe%'` → trả về rows nào có image = powershell.exe (đúng cả admin hợp lệ lẫn malicious).
- `cmdline LIKE '%-W Hidden%'` → lọc rows có hidden window.
- `cmdline LIKE '%-Enc%'` → lọc rows có encoded command.
- PoC `verdict = MATCHED` khi cả 3 step có rows. Hoặc judge gọi LLM phân biệt TP vs FP.

Không có AI trong lúc match. AI chỉ gọi khi user bật `--poc-judge`.
