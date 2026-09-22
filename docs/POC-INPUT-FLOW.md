# Xử lý đầu vào dạng PoC — luồng chi tiết

## 1. Đầu vào: PoC là gì?

PoC (Proof-of-Concept) là **một hypothesis có cấu trúc** — khác với
`--hypothesis` (chuỗi tự do), PoC có:

- Một **id** cố định (`poc-phishing-powershell-enc`, ...).
- Một **kind**: `ttp`, `cve`, `ioc`, hoặc `behavior`.
- Một **danh sách TestStep** có cấu trúc, mỗi step khai báo:
  - `target_field`: cột trong CDB/Splunk (vd. `image`, `cmdline`, `domain`).
  - `op`: phép so sánh (`EQUALS`, `CONTAINS`, `STARTS_WITH`, `ENDS_WITH`, `MATCHES`, `EXISTS`).
  - `value`: giá trị khớp (vd. `powershell.exe`, `-Enc`, `.corp.internal`).
  - `source_kind`: loại telemetry (process/dns/web/file) — để adapter định tuyến.
- **Fallbacks**: các step dự phòng (vd. `pwsh.exe` thay cho `powershell.exe`).
- **References**: tham chiếu khoa học (vd. `MITRE ATT&CK T1059.001`).
- **Escalation hint** (optional): một câu hỏi ngắn cho LLM — **chỉ**
  dùng khi adapter trả về rỗng và user yêu cầu escalation.

Định nghĩa ở `src/hunting/poc/models.py` (PoC, TestStep, FieldOp, PocKind,
EscalationHint). Danh mục có sẵn ở `src/hunting/poc/library.py`:

```
poc-phishing-powershell-enc   (TTP)        Phishing → PowerShell encoded
poc-c2-beacon                 (BEHAVIOR)   Outbound C2 beacon
poc-office-macro              (TTP)        Office macro dropper
poc-credential-phish          (BEHAVIOR)   Credential phish landing page
```

## 2. Đường vào CLI

Argument mới (thêm trong `build_parser`):

```
--poc <id>                  Chạy 1 PoC
--poc-chain <id,id,...>     Chạy chuỗi PoC
--list-pocs                 Liệt kê PoC có sẵn, thoát
--prepare                   Wizard topic → research → ABLE → scope → plan
--hunt-plan <yaml|json>     Nạp plan trước khi chạy
--max-refine N              Số pass refine sau lần analyze đầu (mặc định 1)
--poc-allow-escalation      Cho phép gọi LLM khi adapter rỗng
--poc-report <path>         Ghi Markdown report vào path cụ thể
```

`--prepare` một mình ghi `artifacts/hunt_plans/prepare-<ts>.yaml` rồi thoát. Kèm `--poc`, wizard điền plan rồi mới query. Terminal không tương tác thì dùng `--hunt-plan`. PoC thiếu trường Prepare thì process trả mã 2, không gửi query.

Đoạn dispatch trong `run_cli` (sau khi adapter được setup, trước khi đi
vào nhánh hypothesis/alert cũ):

```python
poc_id = getattr(args, "poc", None)
poc_chain = getattr(args, "poc_chain", None)
if poc_id or poc_chain:
    from hunting.poc import PocAgent, get_poc, render_poc_report
    ...
```

Nếu `--poc` được truyền, `poc_id` được set. Nếu `--poc-chain` được truyền,
`poc_chain` được set. Cả hai cùng xảy ra thì `--poc` thắng (chỉ chạy một).

## 3. Khởi tạo agent (CLI → PocAgent)

```python
agent = PocAgent(
    adapter=adapter,        # CDB / Splunk adapter đã setup
    llm_caller=llm_caller,  # None nếu không --poc-allow-escalation
    llm_tracker=llm_tracker,
    ledger_dir=Path("artifacts") / "poc_hunts",
)
ids = [poc_id] if poc_id else [x.strip() for x in poc_chain.split(",") if x.strip()]
```

`PocAgent` được khởi tạo trong `src/hunting/poc/agent.py`. Nó giữ:

- `adapter`: bất kỳ adapter nào có `execute_query(operation_id="search_text", search_terms=...)`.
- `llm_caller`: callable `(question, max_tokens) -> str` hoặc `None`.
- `llm_tracker`: `LLMUsageTracker` để ghi cost khi escalation xảy ra.
- `ledger_dir`: thư mục lưu JSON ledger (mặc định `artifacts/poc_hunts`).

## 4. Kiểm tra PoC id hợp lệ

```python
for pid in ids:
    try:
        get_poc(pid)
    except KeyError:
        print(f"[-] Unknown PoC id: {pid}", file=sys.stderr)
        return 1
```

`get_poc` tra cứu trong `POC_LIBRARY` dict ở `library.py`. Nếu id không
tồn tại → fail nhanh với message gợi ý dùng `--list-pocs`.

## 5. Chạy chuỗi PoC

```python
chain_results = agent.run_chain(ids, time_window=args.time_window or "NOW-14d/NOW")
```

`agent.run_chain()` gọi `agent.run()` cho từng id trong `ids`, theo thứ tự.
Kết quả trả về là danh sách `PocHuntResult`.

## 6. Luồng bên trong `agent.run()` (chi tiết nhất)

`PocAgent.run(poc_id, time_window, request_id)` thực hiện 6 bước:

```python
def run(self, poc_id, time_window="NOW-14d/NOW", request_id=None):
    poc = get_poc(poc_id)                                    # 1
    request_id = request_id or f"poc-{poc_id}-{_now()}"
    started_at = _now()
    t0 = time.perf_counter()

    graph = compile_poc(poc, request_id, time_window)        # 2

    step_results = []
    for step in poc.steps:                                    # 3
        step_results.append(self._run_step(step, ...))

    if all empty and poc.fallbacks:                          # 4
        for step in poc.fallbacks:
            step_results.append(self._run_step(step, ..., fallback=True))

    all_observations = [...]                                 # 5
    matched_step_ids = [...]
    called, summary, ... = self._maybe_escalate(poc, all_observations)

    # 6. write verdict + ledger
```

### Bước 1 — Tải PoC
`poc = get_poc(poc_id)`: dict lookup trong `POC_LIBRARY`. Trả về đối
tượng `PoC` bất biến (frozen dataclass).

### Bước 2 — Compile thành SemanticGoalGraph

`compile_poc(poc, request_id, time_window)` trong `compiler.py`:

- Lấy step đầu tiên làm anchor (`SemanticVariable`).
- Tạo thêm một biến `target` cho event.
- Mỗi step trong `poc.steps + poc.fallbacks` trở thành:
  - Một `SemanticConstraint` (key=target_field, operator=equals/contains/exists, value=...)
  - Một `SemanticRelationGoal` (subject=anchor, relation=process_execution/dns_resolution/web_request_activity/file_artifact, object=target)
  - Một qualifier ghi lại `field:op` và expected value

Kết quả: một `SemanticGoalGraph` typed, deterministic — không có LLM.

### Bước 3 — Chạy từng step qua adapter

`self._run_step(step, time_window, query_id)`:

```python
def _run_step(self, step, time_window, query_id):
    terms = _compile_terms(step)   # EQUALS → [value]; CONTAINS → [value]; MATCHES → [value]
    result = self.adapter.execute_query(
        operation_id="search_text",
        entity=None,
        window=time_window,
        limit=100,
        query_id=query_id,
        search_terms=terms,        # CDB sẽ LIKE %term% trên nhiều cột text
    )
    rows = [dict(r) for r in result.rows]
    return StepResult(step_id, ..., rows=rows, row_count=len(rows))
```

`adapter.execute_query(operation_id="search_text", search_terms=[...])`
là contract chung của CDB adapter (`m5_adapter/cdb_adapter.py`). Nó
chạy một truy vấn parameterized, scan tất cả các cột text
(`cmdline`, `image`, `domain`, `host`, `user`, ...) với `LIKE '%term%'`,
trả về `QueryResult` có `rows` và `complete`.

### Bước 4 — Chạy fallback nếu primary trống

```python
if all empty and poc.fallbacks:
    for step in poc.fallbacks:
        fb = self._run_step(step, ...)
        fb.used_fallback = True
        step_results.append(fb)
```

Fallback chỉ chạy khi **mọi primary step đều rỗng**. Mỗi fallback được
gắn `used_fallback=True` để report phân biệt được.

### Bước 5 — Quyết định escalation

```python
called, summary, calls, tokens, cost = self._maybe_escalate(poc, all_observations)
```

`_maybe_escalate` chỉ gọi LLM khi **đồng thời**:

- `all_observations` rỗng (không có step nào khớp, cả fallback).
- `poc.escalation_hint` không phải `None`.
- `self.llm_caller` không phải `None` (nghĩa là user đã bật `--poc-allow-escalation`).

Khi đó, nó gọi `llm_caller(question, max_tokens)` và ghi call vào
`LLMUsageTracker`. Đây là **1 LLM call duy nhất**, kèm `max_tokens`
giới hạn (mặc định 2000–4000 trong library).

### Bước 6 — Verdict + ledger

Verdict:

```python
if matched_step_ids:            verdict = "MATCHED"
elif called:                     verdict = "ESCALATED"
else:                            verdict = "EMPTY"
```

Ledger được ghi vào `artifacts/poc_hunts/<request_id>.json`:

```json
{
  "graph": { /* SemanticGoalGraph summary */ },
  "result": { /* PocHuntResult.to_dict() */ }
}
```

## 7. Output cho analyst

CLI in một dòng tóm tắt cho mỗi PoC:

```
PoC poc-phishing-powershell-enc — verdict MATCHED — 3 obs,
3 matched step(s), 0 LLM call(s), 0.0006s
  Rationale: Matched 3 PoC step(s) with 3 observation(s).
  Ledger:    artifacts\poc_hunts\poc-poc-phishing-powershell-enc-...json
  Report:    artifacts\poc_hunts\poc-poc-phishing-powershell-enc-...md
```

Và ghi file `report.md` (qua `render_poc_report`):

```markdown
# PoC Hunt Report — `poc-phishing-powershell-enc`
## Verdict: **MATCHED**
## PoC Definition
- Kind: `ttp`
- Summary: ...
- Steps: `image EQUALS powershell.exe`, `cmdline CONTAINS -W Hidden`, `cmdline CONTAINS -Enc`
## Step Results
- ✓ [s1-powershell-enc] ...: 1 row(s)
- ✓ [s2-powershell-hidden] ...: 1 row(s)
- ✓ [s3-powershell-encoded] ...: 1 row(s)
## LLM Cost
- Calls: 0, Tokens: 0, Cost: $0.000000
```

## 8. Tóm tắt chuỗi xử lý (end-to-end)

```
argv (--poc/--poc-chain/--poc-allow-escalation)
    │
    ▼
argparse (build_parser) — validates args
    │
    ▼
run_cli() — early exit nếu --list-pocs
    │
    ▼
adapter setup (CDB / Splunk) — không phụ thuộc PoC
    │
    ▼
PocAgent(adapter, llm_caller?, llm_tracker?, ledger_dir)
    │
    ▼
PocAgent.run(poc_id)
    │
    ├─► get_poc(poc_id)              — lookup trong POC_LIBRARY
    ├─► compile_poc(poc, ...)         — Deterministic; ra SemanticGoalGraph
    ├─► _run_step(step) × N          — search_text → adapter
    ├─► (optional) fallbacks         — nếu primary trống
    ├─► _maybe_escalate(poc, obs)    — gọi LLM nếu user yêu cầu + obs rỗng
    ├─► verdict                      — MATCHED | ESCALATED | EMPTY
    └─► write ledger JSON + Markdown report
```

Mọi bước ngoài LLM escalation đều **deterministic, reproducible, cost = 0**.
Khi LLM escalation được bật, nó chỉ gọi **tối đa 1 lần** với
`max_tokens ≤ 4000`.
