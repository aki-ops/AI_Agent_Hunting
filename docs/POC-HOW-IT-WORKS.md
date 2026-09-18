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
    operation_id="search_text",          # adapter chạy full-text search
    entity=None,
    window="2026-09-01/02",
    search_terms=["powershell.exe"],     # value của step
)
```

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

## Tóm tắt

| Thành phần | Vai trò | AI? |
|---|---|---|
| PoC (Python file trong `library.py`) | Định nghĩa predicate | ❌ Thuần Python |
| `compile_poc(poc)` | Bóc tách thành `SemanticGoalGraph` | ❌ Thuần Python |
| `_run_step(step)` | Gửi `search_terms` cho adapter | ❌ Thuần Python |
| Adapter (CDB/Splunk) | LIKE/SPL match trên các cột | ❌ SQL hoặc SPL |
| `judge()` (LLM-as-Judge) | Chỉ gọi LLM **sau** khi có rows | ✅ LLM |
| `escalation_hint` (LLM) | Chỉ gọi LLM **khi adapter rỗng** | ✅ LLM |

PoC-driven match = **rules**. Không có AI trong giai đoạn match.

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
