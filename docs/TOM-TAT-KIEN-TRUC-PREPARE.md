# Tóm tắt kiến trúc: Prepare-only v0.4

## 1. Làm gì, trong một đoạn

Từ một PoC/CVE công khai, hệ thống tạo **kế hoạch săn** dạng "giả sử kẻ tấn công dùng PoC này, hãy kiểm tra hệ thống của ta có dấu hiệu bị khai thác không". Hệ thống **chỉ đề xuất**. Con người duyệt, đội khác chạy truy vấn trên Splunk, rồi hệ thống đọc kết quả và gợi ý bước tiếp. Hệ thống không chạm vào hệ thống nội bộ, không chạy PoC, không tự chạy truy vấn nào.

## 2. Luồng tổng thể

```
 Internet công khai                          NGƯỜI                    Đội Execute (Splunk)
 NVD · CISA KEV · GitHub PoC
        │
        ▼
 [1] gather: thu tình báo, trích dấu vết (UA, đường dẫn, payload, tên miền OAST, tệp, ...)
        │
        ├────────────► [2a] CORE (mã, tất định) ─┐
        │                                         ├─► HuntPlan: plan.json · plan.md · RUNBOOK.md
        └─► [2b] LLM/PEAK (tuỳ chọn) ─► gợi ý ────┘        (core_digest, plan_digest)
              (qua cùng bộ kiểm tra, nhãn origin=llm)
                                                   │
                                   [3] R0: người duyệt kế hoạch ◄──┘
                                                   │
                                   [4] bind: gắn chỉ mục + mốc thời gian tuyệt đối,
                                       lint lần 2, từ chối nếu không an toàn ─► queries.bound.spl
                                                   │
                                                   ▼
                                   [5] chạy tuần tự theo RUNBOOK, mỗi giai đoạn có cổng người ─► results.json
                                       (kèm plan_digest + approved_by + approved_at)
                                                   │
                                   [6] verify (không LLM): ACCEPT / ESCALATE / REFINE / COLLECT_DATA / ...
                                                   │
                                   [7] người quyết định cuối ◄─────────┘   (REFINE → kế hoạch MỚI → quay lại R0)
```

## 3. Ba bảo đảm và cách thực hiện

### A. Kết quả không phụ thuộc model

| Phần | Ai tạo | Phụ thuộc model? | Quyết định? |
|---|---|---|---|
| **core**: S1 ngữ cảnh, S2 nỗ lực khai thác, S3 hậu khai thác; truy vấn, điểm dừng, giới hạn, độ phủ | Mã (`plan/core.py`) từ dấu vết trong PoC/CVE | Không | Có, chỉ phần này |
| **llm**: tối đa 2 giai đoạn × 2 truy vấn (`L1`, `L2`) | LLM qua PEAK | Có | Không; người chấp nhận từng cái, chỉ để tham khảo |

- `core_digest` là băm của riêng phần lõi: cùng tình báo thì cùng giá trị, dù model nào hay không có model.
- Model yếu, hỏng, hết hạn khoá: kế hoạch nhỏ hơn, không bao giờ khác hay mất truy vấn lõi.
- Gợi ý LLM không có điểm dừng `escalate` và bị bỏ qua khi `verify` quyết định hay pivot.

### B. Người quyết định từng bước

- `RUNBOOK.md` do mã sinh (không LLM): R0 duyệt → R1 gắn chỉ mục và thời gian → độ phủ → từng truy vấn (mỗi truy vấn một bước, có "ghi lại" và "dừng nếu") → cổng người sau mỗi giai đoạn → nộp kết quả → quyết định cuối.
- Kết quả nộp lại phải có `plan_digest`, `approved_by`, `approved_at`; thiếu hoặc sai thì `REJECT_RESULTS`.
- Gợi ý LLM chỉ được tính khi liệt kê trong `accepted_llm_stages`.
- Vòng pivot (`REFINE`) sinh kế hoạch mới với digest mới nên phải duyệt lại.
- Phần mã không tự quyết được (ví dụ chưa biết tiến trình cha) ghi vào "Việc con người phải tự làm", không đoán.

### C. SPL và thời gian được kiểm tra hai lần

| Lúc | Công cụ | Chặn |
|---|---|---|
| Lập kế hoạch | `check_spl` | chỉ lệnh trong danh sách cho phép; không `eventstats`/`streamstats`/`mvexpand`/`makemv`; không group/dedup theo `_raw`; không `limit=0`/`sort 0`; bộ lọc phải có chuỗi cụ thể ≥ 3 ký tự; endpoint phải lọc tiến trình cha |
| Gắn (`bind`) | `resolve_window` + `lint_bound` | `index=*` và chỉ mục nội bộ; đúng một chỉ mục thật; mốc thời gian tuyệt đối, cửa sổ ≤ 90 ngày, không ở tương lai; `head N` bắt buộc; placeholder còn sót; từ chối cả lô, không ghi file khi có lỗi |

## 4. Các module

| Module | Vai trò |
|---|---|
| `intel/` | Thu NVD, KEV, GitHub (3 host cho phép, kiểm tra chuyển hướng), trích dấu vết |
| `plan/core.py` | Dựng phần lõi tất định |
| `plan/build.py` | Ghép lõi + gợi ý LLM đã kiểm tra; tính digest |
| `plan/safety.py` | `check_spl`, `lint_bound`, quy tắc tiến trình cha |
| `plan/language.py` | Phát hiện chữ ngoại ngữ lẫn trong văn bản LLM |
| `plan/runbook.py` | Sinh `RUNBOOK.md` |
| `plan/render.py` | `plan.md`, `bind`, `bind_plan`, cửa sổ thời gian |
| `plan/digest.py` | `core_digest`, `plan_digest` |
| `plan/verify.py` | Xác minh kết quả, quyết định, sinh vòng sau (không LLM) |
| `plan_cli.py` | Lệnh `plan`, `bind`, `verify`, `schema` |

## 5. Đã kiểm chứng và chưa kiểm chứng

**Đã kiểm chứng:** lõi giống hệt khi `--offline`, khi khoá hết hạn và khi 3 model bị từ chối (cùng `core_digest`); 5 cấu hình model giả lập cho cùng lõi và cùng quyết định; `bind` từ chối 5 trường hợp không an toàn; `verify` cho đúng 5 quyết định trên kết quả giả lập; 189 test pass.

**Chưa kiểm chứng:**
- Chưa có lần gọi LLM thành công nào với bản 0.4 (model free của nhà cung cấp mới bị giới hạn theo tài khoản), nên chưa đo chất lượng gợi ý của model mạnh so với yếu.
- Chưa có Splunk thật: SPL, `tstats` độ phủ và tên trường CIM chưa chạy thật; `verify` chưa nhận kết quả thật.

## 6. Hạn chế cần nói thẳng

- "Độc lập model" nghĩa là cùng kế hoạch lõi và cùng quyết định, không phải cùng chất lượng gợi ý.
- Lõi hẹp và thận trọng: chỉ tìm chuỗi có trong PoC, không suy luận biến thể; không tạo truy vấn tiến trình khi chưa suy ra được tiến trình cha.
- Bộ kiểm tra bảo đảm an toàn và hình thức, không bảo đảm truy vấn bắt đúng tấn công.
- Cổng duyệt chỉ kiểm tra được tên người duyệt và đúng digest, không kiểm tra được người đó có đọc thật.
- `bind` không thay giới hạn quyền trên Splunk: nên đặt thêm hạn mức tìm kiếm theo vai trò phía Splunk.

## 7. Việc tiếp theo đề xuất

1. Liên kết GitHub trên orcarouter (hoặc dùng khoá khác) rồi chạy `artifacts/compare_models.py` với 2–3 model để đo gợi ý LLM, bổ sung vào mục 7.10.5 của luận văn.
2. Khi có Splunk (hoặc đội Execute), chạy thử một kế hoạch thật để kiểm chứng SPL, `tstats` và vòng `verify`.
3. Đặt hạn mức tìm kiếm theo vai trò phía Splunk cho tài khoản chạy kế hoạch.
