# Kiến trúc v7: PEAK Assistant + hunt tất định + khuyến nghị

## 1. Vì sao đổi

Engine v6 (ClaimGraph → CapabilityGraph → EvidenceGraph, ~35k dòng) giải bài toán trả lời câu hỏi điều tra
tự do. Mục tiêu hiện tại hẹp hơn và thực dụng hơn: với một PoC có sẵn, **chuẩn bị hunt theo PEAK, chạy,
rồi đưa khuyến nghị để người săn quyết định**. PEAK Assistant đã làm tốt phần Prepare (nghiên cứu, ABLE,
kế hoạch), nên v7 dùng nó thay vì tự xây thêm, và giữ lại phần mà PEAK Assistant không có: thực thi
tất định trên telemetry, kiểm tra độ phủ dữ liệu, và khuyến nghị có lý do.

## 2. Các pha

| Pha PEAK | Thành phần | LLM | Ghi chú |
|---|---|---|---|
| Prepare | `prepare.py` gọi `peak_assistant.able_assistant.able_table` và `planning_assistant.plan_hunt` (planner + critic) | có | Đầu vào PEAK được dựng từ PoC và từ `adapter.describe_data()` thay cho bước data discovery qua Splunk MCP. `--research` bật thêm `researcher` (cần MCP server nghiên cứu). Lỗi/timeout → dùng ABLE và plan của chính PoC, ghi rõ lý do. |
| Execute | `poc/agent.py` + `adapters/` | không | Mỗi bước là một predicate literal; EQUALS khớp chính xác (kèm basename), có tối đa một lượt refine, `max_duration` cắt cửa sổ. |
| Act | `recommend.py`, `report.py`, `act/` | judge + advisor (tham khảo) | Luật tất định tính `disposition`; LLM chỉ thêm ngữ cảnh. Kèm bản nháp SPL, backlog, ghi chú stakeholder. |

LLM đi qua một đường duy nhất: `llm.py` sinh `model_config.json` cho PEAK từ `.env` (chỉ chứa placeholder
`${ENV}`, không ghi khoá ra đĩa), và `PeakLlm` dùng chính client đó cho judge và advisor.

## 3. Luật khuyến nghị (`recommend.decide`)

| Điều kiện | Disposition | Tin cậy |
|---|---|---|
| Mọi bước khớp, judge TRUE_POSITIVE ≥ 0.7 | `ESCALATE_TO_IR` | HIGH nếu judge ≥ 0.8 **và** PoC có bước kiểm tra kết quả (`status`/`action`...); còn lại MEDIUM |
| Mọi bước khớp, judge FALSE_POSITIVE ≥ 0.7 | `TUNE_POC_OR_CLOSE` | MEDIUM |
| Mọi bước khớp, judge INCONCLUSIVE/thấp/không có | `INVESTIGATE_FURTHER` | MEDIUM |
| Chỉ một phần bước khớp | `INVESTIGATE_FURTHER` | LOW (không judge) / MEDIUM |
| Không khớp, một nguồn cần thiết có 0 bản ghi trong cửa sổ | `COLLECT_DATA_THEN_RERUN` | HIGH |
| Không khớp, nguồn có dữ liệu | `CLOSE_WITH_CAVEAT` | MEDIUM |
| Không khớp, không kiểm tra được độ phủ | `CLOSE_WITH_CAVEAT` | LOW |

Chuỗi không đầy đủ không bao giờ lên `ESCALATE`, dù judge nói gì. Advisor không đổi disposition. Mọi
khuyến nghị có `decision_required = true`, danh sách lựa chọn xếp hạng, giới hạn của kết luận, câu hỏi cho
người săn và rủi ro nếu quyết định sai.

## 4. Giới hạn đã biết

- Độ phủ chỉ kiểm tra *có nguồn* (số bản ghi theo loại trong cửa sổ), chưa kiểm tra nguồn có *đúng loại sự kiện*
  cần tìm (vd. có đăng nhập thành công nhưng không có 4625). Báo cáo ghi caveat này.
- Judge và các agent PEAK không tất định; kết quả LLM chạy lại có thể khác. Phần tất định (hits, disposition
  khi cùng judge) thì tái lập được.
- Các lần gọi LLM bên trong PEAK (ABLE, planner, critic) chưa được đo token/chi phí vì PEAK tự tạo client.
- Bản nháp SPL chưa được kiểm tra trên Splunk thật; adapter Splunk giữ nguyên từ v6 và không được chạy trong
  lần xác minh này (không có Splunk).
- Cửa sổ thời gian lấy từ `time_window` trong PoC hoặc `--window`; PoC dài hơn `max_duration` bị cắt về phần cuối.
- PEAK Assistant tự nhận là proof-of-concept chưa qua kiểm thử bảo mật; chỉ chạy cục bộ.

## 5. Khôi phục engine cũ

`git checkout v6-engine-final`, hoặc đọc tài liệu trong `docs/archive/v6-engine/`.
